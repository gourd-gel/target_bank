//! Fixed processing fees and a separately encrypted, atomically committed ledger.
//! Only the public encryption key is installed on the ATM. The programmer keeps
//! the private key off the bank's machine; the bank audit still discloses charges.
use crate::audit::{self, Action, Entry};
use crate::error::{AtmError, Result};
use crate::fx::{Conversion, Currency, SumLine};
use crate::money::Cents;
use rand::rngs::OsRng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// 3% of principal, rounded up to a supported unit (one cent or whole yen/won).
pub fn fee(currency: Currency, principal: Cents) -> Result<Cents> {
    currency.check_amount(principal)?;
    let step = i128::from(currency.step());
    let units = (i128::from(principal.as_i64()) * 3 + 100 * step - 1) / (100 * step);
    Cents::new(i64::try_from(units * step).map_err(|_| AtmError::InvalidInput("amount is too large"))?)
}

pub fn public_key_path(db: &Path) -> PathBuf {
    db.with_extension("processing-fees.public.pem")
}
pub fn ledger_path(db: &Path) -> PathBuf {
    db.with_extension("processing-fees.db")
}

pub(crate) fn attach(conn: &Connection, db: Option<&Path>) -> Result<()> {
    let path = db.map(ledger_path);
    let initialized: bool =
        conn.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE key = 'processing_ledger_hash')", [], |r| {
            r.get(0)
        })?;
    if initialized && path.as_ref().is_some_and(|p| !p.is_file()) {
        return Err(AtmError::NotAllowed(
            "the processing fee database is missing; restore the matching backup",
        ));
    }
    conn.execute(
        "ATTACH DATABASE ?1 AS processing",
        [path.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or(":memory:".into())],
    )?;
    if let Some(path) = &path {
        crate::keys::restrict_permissions(path)?;
    }
    // Super-journal commits both files together. WAL does not provide this guarantee.
    conn.execute_batch(
        "PRAGMA main.journal_mode = DELETE; PRAGMA processing.journal_mode = DELETE;
        PRAGMA processing.synchronous = FULL;",
    )?;
    if !initialized {
        conn.execute_batch("CREATE TABLE IF NOT EXISTS processing.records (
            reference INTEGER PRIMARY KEY, ciphertext BLOB NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS processing.recipient (id INTEGER PRIMARY KEY CHECK(id = 1), public_key TEXT NOT NULL) STRICT;")?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM processing.records", [], |r| r.get(0))?;
        if count != 0 {
            return Err(AtmError::DatabaseAltered);
        }
        if let Some(db) = db {
            if let Ok(pem) = std::fs::read_to_string(public_key_path(db)) {
                parse_public(&pem)?;
                conn.execute("INSERT OR IGNORE INTO processing.recipient VALUES (1, ?1)", [pem])?;
            }
        }
        #[cfg(test)]
        if db.is_none() {
            conn.execute("INSERT INTO processing.recipient VALUES (1, ?1)", [test_public_key()])?;
        }
    }
    // Pin both files in one read snapshot while checking their association.
    let view = conn.unchecked_transaction()?;
    check(&view)
}

fn parse_public(pem: &str) -> Result<RsaPublicKey> {
    use rsa::traits::PublicKeyParts;
    let key = RsaPublicKey::from_public_key_pem(pem)
        .map_err(|_| AtmError::NotAllowed("invalid processing fee public key"))?;
    if key.n().bits() < 2048 {
        return Err(AtmError::NotAllowed("processing fee key must be at least 2048 bits"));
    }
    Ok(key)
}

fn digest(conn: &Connection) -> Result<String> {
    let mut hash = Sha256::new();
    let schema: String = conn.query_row("SELECT COALESCE(group_concat(sql, ';'), '') FROM (SELECT sql FROM processing.sqlite_schema ORDER BY type, name)", [], |r| r.get(0))?;
    hash.update(schema.as_bytes());
    let public: Option<String> = conn
        .query_row("SELECT public_key FROM processing.recipient WHERE id = 1", [], |r| r.get(0))
        .optional()?;
    hash.update(public.unwrap_or_default().as_bytes());
    let mut stmt = conn.prepare("SELECT reference, ciphertext FROM processing.records ORDER BY reference")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        hash.update(row.get::<_, i64>(0)?.to_le_bytes());
        let bytes: Vec<u8> = row.get(1)?;
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

pub(crate) fn install_if_available(atm: &mut crate::Atm, db: &Path) -> Result<()> {
    let installed: bool =
        atm.conn.query_row("SELECT EXISTS(SELECT 1 FROM processing.recipient)", [], |r| r.get(0))?;
    if !installed && public_key_path(db).is_file() {
        let pem =
            std::fs::read_to_string(public_key_path(db)).map_err(|e| AtmError::Internal(e.to_string()))?;
        parse_public(&pem)?;
        let tx = atm.begin()?;
        tx.execute("INSERT INTO processing.recipient VALUES (1, ?1)", [pem])?;
        tx.commit()?;
    }
    Ok(())
}

pub(crate) fn check(conn: &Connection) -> Result<()> {
    let expected: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key = 'processing_ledger_hash'", [], |r| r.get(0))
        .optional()?;
    if let Some(expected) = expected {
        if expected != digest(conn)? {
            return Err(AtmError::DatabaseAltered);
        }
    }
    let mismatched: bool = conn.query_row("SELECT EXISTS (
        SELECT seq FROM audit_log WHERE action = 'processing_fee' EXCEPT SELECT reference FROM processing.records
    ) OR EXISTS (
        SELECT reference FROM processing.records EXCEPT SELECT seq FROM audit_log WHERE action = 'processing_fee'
    )", [], |r| r.get(0))?;
    if mismatched {
        return Err(AtmError::DatabaseAltered);
    }
    Ok(())
}

pub(crate) fn seal(conn: &Connection) -> Result<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES ('processing_ledger_hash', ?1)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [digest(conn)?],
    )?;
    Ok(())
}

/// Debit and log separately so transfer recipients get exactly the principal.
/// Called inside the same attached-database transaction as the money movement.
pub(crate) fn charge(
    conn: &Connection,
    actor: &str,
    account: i64,
    reference: i64,
    kind: &str,
    currency: Currency,
    principal: Cents,
) -> Result<Cents> {
    let amount = fee(currency, principal)?;
    let pem: Option<String> = conn
        .query_row("SELECT public_key FROM processing.recipient WHERE id = 1", [], |r| r.get(0))
        .optional()?;
    let key = parse_public(&pem.ok_or(AtmError::NotAllowed(
        "the programmer must provision the processing fee public key before transactions",
    ))?)?;
    // Compact versioned payload fits RSA-2048 OAEP-SHA256's 190-byte limit.
    let payload = serde_json::to_vec(&(
        1,
        reference,
        audit::now_utc(),
        account,
        kind,
        currency.code(),
        principal.as_i64(),
        amount.as_i64(),
    ))
    .map_err(|e| AtmError::Internal(e.to_string()))?;
    let encrypted = key
        .encrypt(&mut OsRng, Oaep::new::<rsa::sha2::Sha256>(), &payload)
        .map_err(|_| AtmError::Internal("processing fee encryption failed".into()))?;
    crate::customer::debit(conn, account, amount)?;
    let fee_reference = audit::append(
        conn,
        &Entry {
            actor,
            action: Action::ProcessingFee,
            account_id: Some(account),
            counterparty_id: None,
            amount: Some(amount),
            usd: None,
            detail: &format!(
                "Processing fee: 3% of {}; transaction #{reference} ({kind})",
                currency.format(principal)
            ),
        },
    )?;
    crate::revenue::credit_fee(conn, fee_reference, currency, amount)?;
    conn.execute(
        "INSERT INTO processing.records(reference, ciphertext) VALUES (?1, ?2)",
        params![fee_reference, encrypted],
    )?;
    Ok(amount)
}

pub(crate) fn apply(mut conversion: Conversion, deposit: bool) -> Result<Conversion> {
    let amount = fee(conversion.currency, conversion.cash_amount)?;
    conversion.processing_fee = amount;
    conversion.account_amount = if deposit {
        conversion.account_amount.checked_sub(amount).filter(|v| !v.is_zero())
    } else {
        conversion.account_amount.checked_add(amount)
    }
    .ok_or(AtmError::NotAllowed("transaction cannot cover its processing fee"))?;
    Ok(conversion)
}

pub fn transfer_summary(currency: Currency, principal: Cents) -> Result<Vec<SumLine>> {
    let fee = fee(currency, principal)?;
    let total = principal.checked_add(fee).ok_or(AtmError::InvalidInput("amount is too large"))?;
    Ok(vec![
        SumLine { label: "Transfer".into(), amount: currency.format(principal), total: false },
        SumLine { label: "+ Processing fee (3%)".into(), amount: currency.format(fee), total: false },
        SumLine { label: "Total charged".into(), amount: currency.format(total), total: true },
    ])
}

#[cfg(test)]
fn test_key() -> &'static rsa::RsaPrivateKey {
    static KEY: std::sync::OnceLock<rsa::RsaPrivateKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap())
}

#[cfg(test)]
fn test_public_key() -> &'static str {
    use rsa::pkcs8::EncodePublicKey;
    static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PEM.get_or_init(|| test_key().to_public_key().to_public_key_pem(Default::default()).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::money::Denomination;
    use crate::{Atm, admin, auth, cash, customer, family};

    #[test]
    fn percentage_rounding_obeys_currency_precision() {
        assert_eq!(fee(Currency::Usd, Cents::new(1).unwrap()).unwrap().as_i64(), 1);
        assert_eq!(fee(Currency::Usd, Cents::new(101).unwrap()).unwrap().as_i64(), 4);
        assert_eq!(fee(Currency::Jpy, Cents::from_dollars(1)).unwrap(), Cents::from_dollars(1));
        assert_eq!(fee(Currency::Usd, Cents::MAX).unwrap().as_i64(), 30_000_000_000_000);
    }

    #[test]
    fn every_money_path_charges_once_and_encrypted_records_reconcile() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, handler) = auth::testing::setup(&mut atm);
        let bill = Denomination::new(20).unwrap();
        cash::restock(&mut atm, &handler, bill, 100).unwrap();
        let parent = admin::create_customer(
            &mut atm,
            &admin,
            "Pat Doe",
            "1980-01-01",
            "1357",
            Cents::from_dollars(500),
        )
        .unwrap();
        let child = admin::open_youth_account(
            &mut atm,
            &admin,
            auth::CardAndPin { card_number: &parent.card_number, pin: "1357" },
            "Kid Doe",
            "2014-01-01",
            "2580",
            Cents::from_dollars(100),
        )
        .unwrap();
        let other =
            admin::create_customer(&mut atm, &admin, "Sam Roe", "1980-01-01", "9512", Cents::ZERO).unwrap();
        let session = auth::login_customer(&mut atm, &parent.card_number, "1357").unwrap();
        let receipt = customer::deposit(&mut atm, &session, &[(bill, 5)]).unwrap();
        assert_eq!(receipt.balance_after, Cents::from_dollars(597));
        let quote = customer::check_withdrawal(&atm, &session, Cents::from_dollars(20)).unwrap();
        let receipt =
            customer::withdraw(&mut atm, &session, Cents::from_dollars(20), crate::dispense::BillChoice::Any)
                .unwrap();
        assert_eq!(receipt.amount, quote.account_amount);
        assert_eq!(receipt.balance_after.as_i64(), 57_640);
        let receipt =
            customer::transfer(&mut atm, &session, &other.account_number, Cents::from_dollars(10)).unwrap();
        assert_eq!(receipt.balance_after.as_i64(), 56_610);
        assert_eq!(
            customer::balance_of(&atm.conn, crate::db::account_id(&atm.conn, &other.account_number).unwrap())
                .unwrap(),
            Cents::from_dollars(10)
        );
        let moved = family::move_money(
            &mut atm,
            &session,
            &child.account_number,
            family::Direction::ToChild,
            Cents::from_dollars(10),
        )
        .unwrap();
        assert_eq!(moved.your_balance.as_i64(), 55_580);
        assert_eq!(moved.child_balance, Cents::from_dollars(110));
        let moved = family::move_money(
            &mut atm,
            &session,
            &child.account_number,
            family::Direction::FromChild,
            Cents::from_dollars(10),
        )
        .unwrap();
        assert_eq!(moved.child_balance.as_i64(), 9_970);
        assert_eq!(moved.your_balance.as_i64(), 56_580);
        let count: i64 =
            atm.conn.query_row("SELECT COUNT(*) FROM processing.records", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 5);
        assert_eq!(
            atm.conn
                .query_row("SELECT balance_cents FROM bank_revenue WHERE currency = 'USD'", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            450
        );
        let encrypted: Vec<u8> = atm
            .conn
            .query_row("SELECT ciphertext FROM processing.records ORDER BY reference LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        let plain =
            test_key().decrypt_blinded(&mut OsRng, Oaep::new::<rsa::sha2::Sha256>(), &encrypted).unwrap();
        let data: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(data[4], "deposit");
        assert_eq!(data[7], 300);
        admin::verify_integrity(&mut atm, &admin).unwrap();
        assert_eq!(
            customer::history(&atm, &session, 0)
                .unwrap()
                .iter()
                .filter(|r| r.action == "processing_fee")
                .count(),
            4
        );
        atm.conn.execute("UPDATE processing.records SET ciphertext = x'00' WHERE reference = (SELECT MIN(reference) FROM processing.records)", []).unwrap();
        assert!(matches!(customer::balance(&atm, &session), Err(AtmError::DatabaseAltered)));
    }

    #[test]
    fn failed_fee_write_rolls_back_cash_balances_and_both_ledgers() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, handler) = auth::testing::setup(&mut atm);
        let bill = Denomination::new(20).unwrap();
        cash::restock(&mut atm, &handler, bill, 100).unwrap();
        let card = admin::create_customer(
            &mut atm,
            &admin,
            "Pat Doe",
            "1980-01-01",
            "1357",
            Cents::from_dollars(20),
        )
        .unwrap();
        let session = auth::login_customer(&mut atm, &card.card_number, "1357").unwrap();
        let before: i64 = atm.conn.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)).unwrap();
        // The balance covers principal but cannot cover principal + fee.
        assert!(matches!(
            customer::withdraw(&mut atm, &session, Cents::from_dollars(20), crate::dispense::BillChoice::Any),
            Err(AtmError::InsufficientFunds)
        ));
        // A storage failure after crediting cash must undo everything as well.
        {
            let tx = atm.begin().unwrap();
            tx.execute("DELETE FROM processing.recipient", []).unwrap();
            tx.commit().unwrap();
        }
        assert!(customer::deposit(&mut atm, &session, &[(bill, 1)]).is_err());
        {
            let tx = atm.begin().unwrap();
            tx.execute("INSERT INTO processing.recipient VALUES (1, ?1)", [test_public_key()]).unwrap();
            tx.execute_batch("CREATE TRIGGER processing.reject_record BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END;").unwrap();
            tx.commit().unwrap();
        }
        assert!(customer::deposit(&mut atm, &session, &[(bill, 1)]).is_err());
        assert_eq!(customer::balance(&atm, &session).unwrap(), Cents::from_dollars(20));
        assert_eq!(
            atm.conn
                .query_row("SELECT balance_cents FROM bank_revenue WHERE currency = 'USD'", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(cash::stock(&atm.conn).unwrap().1, Cents::from_dollars(2000));
        let after: i64 = atm.conn.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)).unwrap();
        assert_eq!(before, after);
        assert_eq!(
            atm.conn
                .query_row("SELECT COUNT(*) FROM processing.records", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
