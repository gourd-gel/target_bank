//! Authorities-only investigation APIs. Bank data inspection is read-only; access is audited separately.
//! Credentials and recovery challenge values are never returned in reports.
//!
//! Teller sessions cannot inspect databases through Authorities APIs:
//! ```compile_fail,E0308
//! fn inspect(bank: &atm::Atm, teller: &atm::auth::AdminSession) {
//!     atm::oversight::databases(bank, teller);
//! }
//! ```
//! Customer sessions cannot request investigation reports:
//! ```compile_fail,E0308
//! fn inspect(bank: &atm::Atm, customer: &atm::auth::CustomerSession) {
//!     atm::oversight::users(bank, customer, None, 0);
//! }
//! ```
use crate::Atm;
use crate::audit::{self, IntegrityReport, Row};
use crate::auth::AuthoritiesSession;
use crate::db::{self, Number};
use crate::error::{AtmError, Result};
use crate::{input, keys};
use rusqlite::{Connection, OptionalExtension, params, types::ValueRef};
use serde::Serialize;
use serde_json::{Value, json};

const PAGE: u32 = 20;

#[derive(Debug, Serialize)]
pub struct Report {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

fn report(conn: &Connection, sql: &str, page: u32) -> Result<Report> {
    let mut stmt = conn.prepare(sql)?;
    let columns = stmt.column_names().iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut query = stmt.query(params![PAGE, i64::from(page) * i64::from(PAGE)])?;
    let mut rows = Vec::new();
    while let Some(row) = query.next()? {
        let mut cells = Vec::new();
        for column in 0..columns.len() {
            cells.push(match row.get_ref(column)? {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(n) => json!(n),
                ValueRef::Real(n) => json!(n),
                ValueRef::Text(s) => json!(String::from_utf8_lossy(s)),
                ValueRef::Blob(b) => json!({"hex": b.iter().map(|b| format!("{b:02x}")).collect::<String>()}),
            });
        }
        rows.push(cells);
    }
    Ok(Report { columns, rows })
}

pub fn databases(atm: &Atm, session: &AuthoritiesSession) -> Result<Vec<Value>> {
    crate::administration::access(atm, session, "database_inventory", "")?;
    let conn = atm.read()?;
    atm.admit(session)?;
    let mut stmt = conn.prepare("PRAGMA database_list")?;
    let mut query = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = query.next()? {
        let name: String = row.get(1)?;
        if name == "main" || name == "processing" || name == "administration" {
            out.push(json!({"database": name, "file": row.get::<_, String>(2)?}));
        }
    }
    Ok(out)
}

pub fn schema(atm: &Atm, session: &AuthoritiesSession, database: &str, page: u32) -> Result<Report> {
    crate::administration::access(
        atm,
        session,
        "database_schema",
        &format!("database={database}, page={page}"),
    )?;
    let conn = atm.read()?;
    atm.admit(session)?;
    let sql = match database {
        "main" => {
            "SELECT name, type, sql FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT ?1 OFFSET ?2"
        }
        "processing" => {
            "SELECT name, type, sql FROM processing.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT ?1 OFFSET ?2"
        }
        "administration" => {
            "SELECT name, type, sql FROM administration.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT ?1 OFFSET ?2"
        }
        _ => return Err(AtmError::NotFound("Database")),
    };
    report(&conn, sql, page)
}

/// Inspect stored tables using a fixed allowlist; no SQL supplied by the caller executes.
pub fn table(
    atm: &Atm,
    session: &AuthoritiesSession,
    database: &str,
    table: &str,
    page: u32,
) -> Result<Report> {
    crate::administration::access(
        atm,
        session,
        "database_table",
        &format!("database={database}, table={table}, page={page}"),
    )?;
    let conn = atm.read()?;
    atm.admit(session)?;
    let sql = match (database, table) {
        ("main", "accounts") => "SELECT * FROM main.accounts ORDER BY id LIMIT ?1 OFFSET ?2",
        ("main", "cards") => {
            "SELECT id, card_lookup, card_enc, card_last4, account_id, holder_role, name_enc, dob_enc, '[protected]' AS pin_hash, failed_attempts, locked FROM main.cards ORDER BY id LIMIT ?1 OFFSET ?2"
        }
        ("main", "staff") => {
            "SELECT id, username, role, '[protected]' AS password_hash, phone_enc, failed_attempts, cooldown_until FROM main.staff ORDER BY id LIMIT ?1 OFFSET ?2"
        }
        ("main", "meta") => {
            "SELECT key, CASE WHEN key IN ('schema_version', 'atm-origin/v1', 'demo') THEN value ELSE '[protected metadata]' END AS value FROM main.meta ORDER BY key LIMIT ?1 OFFSET ?2"
        }
        ("main", "guardians") => {
            "SELECT * FROM main.guardians ORDER BY youth_account_id, guardian_card_id LIMIT ?1 OFFSET ?2"
        }
        ("main", "settings") => "SELECT * FROM main.settings ORDER BY key LIMIT ?1 OFFSET ?2",
        ("main", "exchange_rates") => {
            "SELECT * FROM main.exchange_rates ORDER BY currency LIMIT ?1 OFFSET ?2"
        }
        ("main", "rate_history") => "SELECT * FROM main.rate_history ORDER BY id DESC LIMIT ?1 OFFSET ?2",
        ("main", "cash_inventory") => {
            "SELECT * FROM main.cash_inventory ORDER BY denomination LIMIT ?1 OFFSET ?2"
        }
        ("main", "audit_log") => "SELECT * FROM main.audit_log ORDER BY seq DESC LIMIT ?1 OFFSET ?2",
        ("main", "seal") => "SELECT * FROM main.seal ORDER BY id LIMIT ?1 OFFSET ?2",
        ("main", "bank_revenue") => "SELECT * FROM main.bank_revenue ORDER BY currency LIMIT ?1 OFFSET ?2",
        ("main", "revenue_ledger") => {
            "SELECT * FROM main.revenue_ledger ORDER BY audit_seq DESC LIMIT ?1 OFFSET ?2"
        }
        ("processing", "records") => {
            "SELECT * FROM processing.records ORDER BY reference DESC LIMIT ?1 OFFSET ?2"
        }
        ("processing", "recipient") => "SELECT * FROM processing.recipient ORDER BY id LIMIT ?1 OFFSET ?2",
        ("administration", "events") => {
            "SELECT * FROM administration.events ORDER BY seq DESC LIMIT ?1 OFFSET ?2"
        }
        ("administration", "store_meta") => {
            "SELECT * FROM administration.store_meta ORDER BY key LIMIT ?1 OFFSET ?2"
        }
        _ => return Err(AtmError::NotFound("Database table")),
    };
    report(&conn, sql, page)
}

/// Full customer identification for investigations, with the exact audit actor to trace.
pub fn users(atm: &Atm, session: &AuthoritiesSession, card: Option<&str>, page: u32) -> Result<Vec<Value>> {
    crate::administration::access(
        atm,
        session,
        "user_inspection",
        &format!("card={}, page={page}", card.unwrap_or("all")),
    )?;
    let conn = atm.read()?;
    atm.admit(session)?;
    let lookup = card
        .map(|number| {
            input::validate_number10(number)?;
            db::lookup(Number::Card, number)
        })
        .transpose()?;
    let mut stmt = conn.prepare("SELECT c.id, c.card_lookup, c.card_enc, c.card_last4, c.holder_role, c.name_enc, c.dob_enc,
        c.failed_attempts, c.locked, a.id, a.account_lookup, a.account_enc, a.kind, a.currency, a.balance_cents, a.closed, a.frozen
        FROM cards c JOIN accounts a ON a.id = c.account_id WHERE (?1 IS NULL OR c.card_lookup = ?1)
        ORDER BY c.id LIMIT ?2 OFFSET ?3")?;
    let mut rows = stmt.query(params![lookup, PAGE, i64::from(page) * i64::from(PAGE)])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let lookup: String = r.get(1)?;
        out.push(json!({"card_id": r.get::<_, i64>(0)?, "actor": db::customer_actor(r.get(0)?, &r.get::<_, String>(3)?),
            "card_number": db::open_number(Number::Card, &lookup, &r.get::<_, Vec<u8>>(2)?)?,
            "holder_role": r.get::<_, String>(4)?, "name": db::holder_name(&lookup, &r.get::<_, Vec<u8>>(5)?)?,
            "date_of_birth": db::holder_dob(&lookup, &r.get::<_, Vec<u8>>(6)?)?.to_string(),
            "failed_attempts": r.get::<_, i64>(7)?, "locked": r.get::<_, bool>(8)?, "account_id": r.get::<_, i64>(9)?,
            "account_number": db::open_number(Number::Account, &r.get::<_, String>(10)?, &r.get::<_, Vec<u8>>(11)?)?,
            "account_kind": r.get::<_, String>(12)?, "currency": r.get::<_, String>(13)?,
            "balance_cents": r.get::<_, i64>(14)?, "closed": r.get::<_, bool>(15)?, "bank_frozen": r.get::<_, bool>(16)?}));
    }
    Ok(out)
}

pub fn staff(
    atm: &Atm,
    session: &AuthoritiesSession,
    username: Option<&str>,
    page: u32,
) -> Result<Vec<Value>> {
    crate::administration::access(
        atm,
        session,
        "staff_inspection",
        &format!("username={}, page={page}", username.unwrap_or("all")),
    )?;
    let conn = atm.read()?;
    atm.admit(session)?;
    let mut stmt = conn.prepare(
        "SELECT id, username, role, phone_enc, failed_attempts, cooldown_until FROM staff
        WHERE (?1 IS NULL OR username = ?1) ORDER BY id LIMIT ?2 OFFSET ?3",
    )?;
    let mut rows = stmt.query(params![username, PAGE, i64::from(page) * i64::from(PAGE)])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let name: String = r.get(1)?;
        let role: String = r.get(2)?;
        let phone: Option<Vec<u8>> = r.get(3)?;
        let phone = phone.map(|bytes| keys::unseal("staff.phone", &name, &bytes)).transpose()?;
        let phones = crate::auth::recovery::staff_phones(&conn, &name)?;
        out.push(json!({"staff_id": r.get::<_, i64>(0)?, "username": name, "role": role,
            "actor": format!("{role}:{name}"), "phone": phone, "verified_phone_count": phones.len(), "failed_attempts": r.get::<_, i64>(4)?, "cooldown_until": r.get::<_, Option<String>>(5)?}));
    }
    Ok(out)
}

/// All accounts, including closed accounts retained for tracing.
pub fn accounts(
    atm: &Atm,
    session: &AuthoritiesSession,
    number: Option<&str>,
    page: u32,
) -> Result<Vec<Value>> {
    crate::administration::access(
        atm,
        session,
        "account_inspection",
        &format!("account={}, page={page}", number.unwrap_or("all")),
    )?;
    let conn = atm.read()?;
    atm.admit(session)?;
    let lookup = number
        .map(|number| {
            input::validate_number10(number)?;
            db::lookup(Number::Account, number)
        })
        .transpose()?;
    let mut stmt = conn.prepare("SELECT id, account_lookup, account_enc, kind, currency, balance_cents, closed, frozen, guardian_frozen
        FROM accounts WHERE (?1 IS NULL OR account_lookup = ?1) ORDER BY id LIMIT ?2 OFFSET ?3")?;
    let mut rows = stmt.query(params![lookup, PAGE, i64::from(page) * i64::from(PAGE)])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(json!({"account_id": r.get::<_, i64>(0)?, "account_number": db::open_number(Number::Account, &r.get::<_, String>(1)?, &r.get::<_, Vec<u8>>(2)?)?,
            "kind": r.get::<_, String>(3)?, "currency": r.get::<_, String>(4)?, "balance_cents": r.get::<_, i64>(5)?,
            "closed": r.get::<_, bool>(6)?, "bank_frozen": r.get::<_, bool>(7)?, "guardian_frozen": r.get::<_, bool>(8)?}));
    }
    Ok(out)
}

/// Requested-amount activity, filtered before paging, with optional exact actor and account.
pub fn activity(
    atm: &Atm,
    session: &AuthoritiesSession,
    account: Option<&str>,
    actor: Option<&str>,
    page: u32,
) -> Result<Vec<Row>> {
    crate::administration::access(
        atm,
        session,
        "activity_inspection",
        &format!("account={}, actor={}, page={page}", account.unwrap_or("all"), actor.unwrap_or("all")),
    )?;
    let conn = atm.read()?;
    atm.admit(session)?;
    let account_id = account
        .map(|number| -> Result<i64> {
            input::validate_number10(number)?;
            conn.query_row(
                "SELECT id FROM accounts WHERE account_lookup = ?1",
                [db::lookup(Number::Account, number)?],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(AtmError::NotFound("Account"))
        })
        .transpose()?;
    audit::activity_filtered(&conn, account_id, actor, false, PAGE, page)
}

pub fn verify(atm: &Atm, session: &AuthoritiesSession) -> Result<IntegrityReport> {
    crate::administration::access(atm, session, "integrity_inspection", "")?;
    let conn = atm.read()?;
    atm.admit(session)?;
    let structure: String = conn.query_row("PRAGMA processing.integrity_check(1)", [], |r| r.get(0))?;
    if structure != "ok" {
        return Err(AtmError::DatabaseAltered);
    }
    audit::verify(&conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::money::{Cents, Denomination};
    use crate::{admin, auth, customer};

    fn bank() -> (Atm, AuthoritiesSession, admin::NewCard) {
        let mut bank = Atm::in_memory().unwrap();
        let (admin, _) = auth::testing::setup(&mut bank);
        let card = admin::create_customer(
            &mut bank,
            &admin,
            "Ann Lee",
            "1980-01-01",
            "1357",
            Cents::from_dollars(100),
        )
        .unwrap();
        let session = auth::login_customer(&mut bank, &card.card_number, "1357").unwrap();
        customer::deposit(&mut bank, &session, &[(Denomination::new(5).unwrap(), 1)]).unwrap();
        let authorities = auth::testing::authorities(&bank);
        (bank, authorities, card)
    }

    #[test]
    fn inspection_covers_all_tables_redacts_credentials_and_preserves_the_audit() {
        let (mut bank, authorities, _) = bank();
        let tx = bank.begin().unwrap();
        tx.execute("INSERT INTO meta(key, value) VALUES ('inspection-private', 'secret challenge data')", [])
            .unwrap();
        tx.commit().unwrap();
        let before: (i64, String) = bank
            .conn
            .query_row("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(databases(&bank, &authorities).unwrap().len(), 3);
        for database in ["main", "processing", "administration"] {
            let mut page = 0;
            loop {
                let tables = schema(&bank, &authorities, database, page).unwrap();
                for row in &tables.rows {
                    if row[1] == "table" {
                        table(&bank, &authorities, database, row[0].as_str().unwrap(), 0).unwrap();
                    }
                }
                if tables.rows.len() < PAGE as usize {
                    break;
                }
                page += 1;
            }
        }
        let staff = table(&bank, &authorities, "main", "staff", 0).unwrap();
        let cards = table(&bank, &authorities, "main", "cards", 0).unwrap();
        let meta = table(&bank, &authorities, "main", "meta", 0).unwrap();
        let printed = serde_json::to_string(&(staff, cards, meta)).unwrap();
        assert!(printed.contains("[protected]"));
        assert!(!printed.contains("$argon2id$"));
        assert!(!printed.contains("secret challenge data"));
        assert!(
            table(&bank, &authorities, "processing", "records", 0).unwrap().rows[0][1]["hex"]
                .as_str()
                .is_some()
        );
        verify(&bank, &authorities).unwrap();
        let after: (i64, String) = bank
            .conn
            .query_row("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn investigators_can_identify_and_trace_users_tellers_and_closed_accounts() {
        let (mut bank, authorities, card) = bank();
        let found = users(&bank, &authorities, Some(&card.card_number), 0).unwrap();
        assert_eq!(found[0]["name"], "Ann Lee");
        assert_eq!(found[0]["date_of_birth"], "1980-01-01");
        assert_eq!(found[0]["account_number"], card.account_number);
        let actor = found[0]["actor"].as_str().unwrap();
        let rows = activity(&bank, &authorities, None, Some(actor), 0).unwrap();
        assert!(rows.iter().all(|r| r.actor == actor));
        let deposit = rows.iter().find(|r| r.action == "deposit").unwrap();
        assert_eq!(deposit.amount, Some(Cents::from_dollars(5)));
        let tellers = staff(&bank, &authorities, Some(auth::testing::ADMIN.0), 0).unwrap();
        assert_eq!(tellers[0]["role"], "admin");
        let teller_actor = tellers[0]["actor"].as_str().unwrap();
        assert!(
            activity(&bank, &authorities, None, Some(teller_actor), 0)
                .unwrap()
                .iter()
                .any(|r| r.action == "account_opened")
        );
        let admin = auth::login_admin(&mut bank, auth::testing::ADMIN.0, auth::testing::ADMIN.1).unwrap();
        let closed =
            admin::create_customer(&mut bank, &admin, "Bo Roe", "1980-01-01", "9512", Cents::ZERO).unwrap();
        admin::close_account(&mut bank, &admin, &closed.account_number).unwrap();
        assert_eq!(
            accounts(&bank, &authorities, Some(&closed.account_number), 0).unwrap()[0]["closed"],
            true
        );
        assert!(
            activity(&bank, &authorities, Some(&closed.account_number), None, 0)
                .unwrap()
                .iter()
                .any(|r| r.action == "account_closed")
        );
    }

    #[test]
    fn actor_filtering_happens_before_pagination() {
        let (mut bank, authorities, card) = bank();
        let customer = auth::login_customer(&mut bank, &card.card_number, "1357").unwrap();
        for _ in 0..25 {
            customer::deposit(&mut bank, &customer, &[(Denomination::new(5).unwrap(), 1)]).unwrap();
        }
        let actor = customer.actor();
        let first = activity(&bank, &authorities, None, Some(&actor), 0).unwrap();
        let second = activity(&bank, &authorities, None, Some(&actor), 1).unwrap();
        assert_eq!(first.len(), PAGE as usize);
        assert!(!second.is_empty());
        assert!(first.iter().chain(second.iter()).all(|r| r.actor == actor && r.action != "processing_fee"));
        assert!(first.last().unwrap().seq > second.first().unwrap().seq);
    }

    #[test]
    fn invalid_inspection_targets_and_invalid_sessions_cannot_bypass_checks() {
        let (bank, authorities, _) = bank();
        assert!(table(&bank, &authorities, "main", "accounts; DELETE FROM accounts", 0).is_err());
        assert!(schema(&bank, &authorities, "other", 0).is_err());
        assert!(activity(&bank, &authorities, Some("0000000000"), None, 0).is_err());
        let (other, _, _) = self::bank();
        assert!(matches!(databases(&other, &authorities), Err(AtmError::SessionExpired)));
        let authorities = auth::testing::authorities(&bank);
        authorities.end();
        assert!(matches!(users(&bank, &authorities, None, 0), Err(AtmError::SessionExpired)));
        let authorities = auth::testing::authorities(&bank);
        bank.conn.execute("UPDATE accounts SET balance_cents = balance_cents + 1", []).unwrap();
        assert!(matches!(table(&bank, &authorities, "main", "accounts", 0), Err(AtmError::DatabaseAltered)));
    }
}
