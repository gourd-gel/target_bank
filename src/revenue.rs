//! The bank's processing-fee revenue account. Currency balances never mix.
//! Only an authenticated Bank Authorities session can inspect or adjust it.
//!
//! A teller session cannot adjust bank revenue:
//! ```compile_fail,E0308
//! fn adjust(a: &mut atm::Atm, teller: &atm::auth::AdminSession) {
//!     atm::revenue::adjust(a, teller, atm::fx::Currency::Usd,
//!         atm::revenue::Adjustment::Credit, atm::money::Cents::from_dollars(1), "correction");
//! }
//! ```
//! A customer cannot view the revenue account:
//! ```compile_fail,E0308
//! fn view(a: &atm::Atm, customer: &atm::auth::CustomerSession) {
//!     atm::revenue::balances(a, customer);
//! }
//! ```
use crate::Atm;
use crate::audit::{self, Action, Entry};
use crate::auth::AuthoritiesSession;
use crate::error::{AtmError, Result};
use crate::fx::Currency;
use crate::money::Cents;
use rusqlite::{Connection, params};

const SCHEMA: &str = "
CREATE TABLE bank_revenue (
    currency TEXT PRIMARY KEY,
    balance_cents INTEGER NOT NULL CHECK(balance_cents BETWEEN 0 AND 1000000000000000)
) STRICT;
CREATE TABLE revenue_ledger (
    audit_seq INTEGER PRIMARY KEY REFERENCES audit_log(seq),
    currency TEXT NOT NULL REFERENCES bank_revenue(currency),
    delta_cents INTEGER NOT NULL CHECK(delta_cents BETWEEN -1000000000000000 AND 1000000000000000)
) STRICT;
CREATE TRIGGER revenue_no_update BEFORE UPDATE ON revenue_ledger
BEGIN SELECT RAISE(ABORT, 'revenue ledger is append-only'); END;
CREATE TRIGGER revenue_no_delete BEFORE DELETE ON revenue_ledger
BEGIN SELECT RAISE(ABORT, 'revenue ledger is append-only'); END;";

#[derive(Debug, Clone)]
pub struct RevenueBalance {
    pub currency: Currency,
    pub balance: Cents,
}

#[derive(Debug, Clone)]
pub struct RevenueEntry {
    pub reference: i64,
    pub timestamp: String,
    pub currency: Currency,
    /// Signed: a credit is positive and an authorized debit is negative.
    pub delta_cents: i64,
    pub actor: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Adjustment {
    Credit,
    Debit,
}

/// Authorities may correct the account using new, auditable ledger entries.
pub fn adjust(
    atm: &mut Atm,
    session: &AuthoritiesSession,
    currency: Currency,
    direction: Adjustment,
    amount: Cents,
    reason: &str,
) -> Result<i64> {
    atm.admit(session)?;
    currency.check_amount(amount)?;
    let reason = reason.trim();
    if amount.is_zero()
        || reason.is_empty()
        || reason.chars().count() > 240
        || reason.chars().any(char::is_control)
    {
        return Err(AtmError::InvalidInput("enter a positive amount and a reason of 1 to 240 characters"));
    }
    let tx = atm.begin_for(session)?;
    conn_balance_row(&tx, currency)?;
    let current: i64 =
        tx.query_row("SELECT balance_cents FROM bank_revenue WHERE currency = ?1", [currency.code()], |r| {
            r.get(0)
        })?;
    let (balance, delta, action, label) = match direction {
        Adjustment::Credit => (
            Cents::new(current)?
                .checked_add(amount)
                .ok_or(AtmError::InvalidInput("bank revenue balance is too large"))?,
            amount.as_i64(),
            Action::RevenueCredit,
            "credit",
        ),
        Adjustment::Debit => (
            Cents::new(current)?.checked_sub(amount).ok_or(AtmError::InsufficientFunds)?,
            -amount.as_i64(),
            Action::RevenueDebit,
            "debit",
        ),
    };
    let reference = audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action,
            account_id: None,
            counterparty_id: None,
            amount: Some(amount),
            usd: None,
            detail: &format!("Bank revenue {} {label}: {reason}", currency.code()),
        },
    )?;
    tx.execute(
        "UPDATE bank_revenue SET balance_cents = ?2 WHERE currency = ?1",
        params![currency.code(), balance.as_i64()],
    )?;
    tx.execute(
        "INSERT INTO revenue_ledger(audit_seq, currency, delta_cents) VALUES (?1, ?2, ?3)",
        params![reference, currency.code(), delta],
    )?;
    tx.commit()?;
    Ok(reference)
}

fn conn_balance_row(conn: &Connection, currency: Currency) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO bank_revenue(currency, balance_cents) VALUES (?1, 0)",
        [currency.code()],
    )?;
    Ok(())
}

/// Verify the old seal before creating tables, and recover already collected fees
/// from their signed audit entries without debiting any customer again.
pub(crate) fn migrate(atm: &mut Atm) -> Result<()> {
    let tx = atm.begin()?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'bank_revenue')",
        [],
        |r| r.get(0),
    )?;
    if exists {
        return Ok(());
    }
    tx.execute_batch(SCHEMA)?;
    tx.execute_batch("INSERT INTO bank_revenue(currency, balance_cents) VALUES ('USD', 0);
        INSERT OR IGNORE INTO bank_revenue(currency, balance_cents)
            SELECT a.currency, 0 FROM audit_log l JOIN accounts a ON a.id = l.account_id WHERE l.action = 'processing_fee';
        INSERT INTO revenue_ledger(audit_seq, currency, delta_cents)
            SELECT l.seq, a.currency, l.amount_cents FROM audit_log l JOIN accounts a ON a.id = l.account_id WHERE l.action = 'processing_fee';
        UPDATE bank_revenue SET balance_cents = COALESCE((SELECT SUM(delta_cents) FROM revenue_ledger WHERE currency = bank_revenue.currency), 0);")?;
    let backfilled: i64 = tx.query_row("SELECT COUNT(*) FROM revenue_ledger", [], |r| r.get(0))?;
    if backfilled > 0 {
        audit::append(
            &tx,
            &Entry {
                actor: "system",
                action: Action::ControlsChanged,
                account_id: None,
                counterparty_id: None,
                amount: None,
                usd: None,
                detail: "bank revenue account initialized from existing processing fee records; no customer charged again",
            },
        )?;
    }
    tx.commit()
}

pub(crate) fn credit_fee(conn: &Connection, reference: i64, currency: Currency, amount: Cents) -> Result<()> {
    conn_balance_row(conn, currency)?;
    let current: i64 = conn.query_row(
        "SELECT balance_cents FROM bank_revenue WHERE currency = ?1",
        [currency.code()],
        |r| r.get(0),
    )?;
    let total = Cents::new(current)?
        .checked_add(amount)
        .ok_or(AtmError::InvalidInput("bank revenue balance is too large"))?;
    conn.execute(
        "UPDATE bank_revenue SET balance_cents = ?2 WHERE currency = ?1",
        params![currency.code(), total.as_i64()],
    )?;
    conn.execute(
        "INSERT INTO revenue_ledger(audit_seq, currency, delta_cents) VALUES (?1, ?2, ?3)",
        params![reference, currency.code(), amount.as_i64()],
    )?;
    Ok(())
}

pub fn balances(atm: &Atm, session: &AuthoritiesSession) -> Result<Vec<RevenueBalance>> {
    let conn = atm.read()?;
    atm.admit(session)?;
    let mut stmt = conn.prepare("SELECT currency, balance_cents FROM bank_revenue ORDER BY currency")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    rows.map(|r| {
        let (currency, balance) = r?;
        Ok(RevenueBalance { currency: Currency::parse(&currency)?, balance: Cents::new(balance)? })
    })
    .collect()
}

pub fn history(atm: &Atm, session: &AuthoritiesSession, page: u32) -> Result<Vec<RevenueEntry>> {
    let conn = atm.read()?;
    atm.admit(session)?;
    let mut stmt = conn.prepare(
        "SELECT l.seq, l.ts, r.currency, r.delta_cents, l.actor, l.detail
        FROM revenue_ledger r JOIN audit_log l ON l.seq = r.audit_seq ORDER BY l.seq DESC LIMIT 20 OFFSET ?1",
    )?;
    let mut rows = stmt.query([i64::from(page) * 20])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(RevenueEntry {
            reference: row.get(0)?,
            timestamp: row.get(1)?,
            currency: Currency::parse(&row.get::<_, String>(2)?)?,
            delta_cents: row.get(3)?,
            actor: row.get(4)?,
            detail: row.get(5)?,
        });
    }
    Ok(out)
}

/// Cross-check balances, account credits and all fee references against the signed audit.
pub(crate) fn reconcile(conn: &Connection) -> Result<i64> {
    let bad: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM bank_revenue b WHERE b.balance_cents !=
        COALESCE((SELECT SUM(delta_cents) FROM revenue_ledger r WHERE r.currency = b.currency), 0))
        OR EXISTS(SELECT 1 FROM revenue_ledger r LEFT JOIN audit_log l ON l.seq = r.audit_seq
            LEFT JOIN accounts a ON a.id = l.account_id WHERE l.seq IS NULL
            OR (l.action = 'processing_fee' AND (r.delta_cents != l.amount_cents OR r.currency != a.currency))
            OR (l.action = 'revenue_credit' AND (r.delta_cents != l.amount_cents OR l.actor NOT LIKE 'authorities:%'
                OR l.detail NOT LIKE 'Bank revenue ' || r.currency || ' credit: %'))
            OR (l.action = 'revenue_debit' AND (r.delta_cents != -l.amount_cents OR l.actor NOT LIKE 'authorities:%'
                OR l.detail NOT LIKE 'Bank revenue ' || r.currency || ' debit: %'))
            OR l.action NOT IN ('processing_fee', 'revenue_credit', 'revenue_debit'))
        OR EXISTS(SELECT seq FROM audit_log WHERE action IN ('processing_fee', 'revenue_credit', 'revenue_debit')
            EXCEPT SELECT audit_seq FROM revenue_ledger)", [], |r| r.get(0))?;
    if bad {
        return Err(AtmError::StateMismatch(vec!["bank processing fee revenue account".into()]));
    }
    Ok(conn.query_row("SELECT COUNT(*) FROM bank_revenue", [], |r| r.get(0))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::money::Denomination;
    use crate::{admin, auth, customer};

    fn bank() -> (Atm, auth::AdminSession, auth::AuthoritiesSession) {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = auth::testing::setup(&mut atm);
        let authority = auth::testing::authorities(&atm);
        (atm, admin, authority)
    }

    #[test]
    fn authorities_adjustments_are_signed_reconciled_and_do_not_change_customer_money() {
        let (mut atm, admin, authority) = bank();
        let card = admin::create_customer(
            &mut atm,
            &admin,
            "Pat Doe",
            "1980-01-01",
            "1357",
            Cents::from_dollars(100),
        )
        .unwrap();
        let customer = auth::login_customer(&mut atm, &card.card_number, "1357").unwrap();
        customer::deposit(&mut atm, &customer, &[(Denomination::new(100).unwrap(), 1)]).unwrap();
        assert_eq!(balances(&atm, &authority).unwrap()[0].balance, Cents::from_dollars(3));
        adjust(
            &mut atm,
            &authority,
            Currency::Usd,
            Adjustment::Credit,
            Cents::from_dollars(10),
            "opening correction",
        )
        .unwrap();
        let reference = adjust(
            &mut atm,
            &authority,
            Currency::Usd,
            Adjustment::Debit,
            Cents::from_dollars(2),
            "fee refund allocation",
        )
        .unwrap();
        assert_eq!(balances(&atm, &authority).unwrap()[0].balance, Cents::from_dollars(11));
        assert_eq!(customer::balance(&atm, &customer).unwrap(), Cents::from_dollars(197));
        let rows = history(&atm, &authority, 0).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].reference, reference);
        assert_eq!(rows[0].delta_cents, -200);
        assert_eq!(rows[0].actor, "authorities:bank authorities");
        assert!(rows[0].detail.contains("fee refund allocation"));
        let activity = crate::audit::recent(&atm.conn, 1, 0).unwrap();
        assert_eq!(activity.len(), 1);
        assert_eq!(activity[0].action, "deposit");
        assert_eq!(activity[0].amount, Some(Cents::from_dollars(100)));
        admin::verify_integrity(&mut atm, &admin).unwrap();
        assert!(atm.conn.execute("UPDATE revenue_ledger SET delta_cents = 0", []).is_err());
        assert!(atm.conn.execute("DELETE FROM revenue_ledger", []).is_err());
    }

    #[test]
    fn revenue_never_mixes_currencies_and_rejects_invalid_or_unfunded_edits() {
        let (mut atm, _, authority) = bank();
        adjust(
            &mut atm,
            &authority,
            Currency::Usd,
            Adjustment::Credit,
            Cents::from_dollars(10),
            "USD correction",
        )
        .unwrap();
        adjust(
            &mut atm,
            &authority,
            Currency::Eur,
            Adjustment::Credit,
            Cents::from_dollars(20),
            "EUR correction",
        )
        .unwrap();
        let rows = balances(&atm, &authority).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|r| r.currency == Currency::Usd && r.balance == Cents::from_dollars(10)));
        assert!(rows.iter().any(|r| r.currency == Currency::Eur && r.balance == Cents::from_dollars(20)));
        assert!(matches!(
            adjust(
                &mut atm,
                &authority,
                Currency::Usd,
                Adjustment::Debit,
                Cents::from_dollars(11),
                "overdraft"
            ),
            Err(AtmError::InsufficientFunds)
        ));
        for reason in ["", "   ", "line\nbreak"] {
            assert!(
                adjust(
                    &mut atm,
                    &authority,
                    Currency::Usd,
                    Adjustment::Credit,
                    Cents::from_dollars(1),
                    reason
                )
                .is_err()
            );
        }
        assert!(
            adjust(&mut atm, &authority, Currency::Usd, Adjustment::Credit, Cents::ZERO, "zero").is_err()
        );
        assert!(
            adjust(
                &mut atm,
                &authority,
                Currency::Jpy,
                Adjustment::Credit,
                Cents::new(1).unwrap(),
                "fractional yen"
            )
            .is_err()
        );
        assert_eq!(history(&atm, &authority, 0).unwrap().len(), 2);
        let audit = crate::audit::recent(&atm.conn, 20, 0).unwrap();
        assert!(audit.iter().all(|row| row.action != "revenue_credit" && row.action != "revenue_debit"));
        let entries = history(&atm, &authority, 0).unwrap();
        assert!(entries.iter().any(|entry| entry.currency == Currency::Eur && entry.delta_cents == 2000));
        reconcile(&atm.conn).unwrap();
    }

    #[test]
    fn migration_credits_existing_fees_once_without_charging_customers_again() {
        let (mut atm, admin, authority) = bank();
        let card =
            admin::create_customer(&mut atm, &admin, "Pat Doe", "1980-01-01", "1357", Cents::ZERO).unwrap();
        let session = auth::login_customer(&mut atm, &card.card_number, "1357").unwrap();
        customer::deposit(&mut atm, &session, &[(Denomination::new(100).unwrap(), 1)]).unwrap();
        let tx = atm.begin().unwrap();
        tx.execute_batch("DROP TABLE revenue_ledger; DROP TABLE bank_revenue;").unwrap();
        tx.commit().unwrap();
        migrate(&mut atm).unwrap();
        migrate(&mut atm).unwrap();
        assert_eq!(balances(&atm, &authority).unwrap()[0].balance, Cents::from_dollars(3));
        assert_eq!(customer::balance(&atm, &session).unwrap(), Cents::from_dollars(97));
        assert_eq!(history(&atm, &authority, 0).unwrap().len(), 1);
        admin::verify_integrity(&mut atm, &admin).unwrap();
    }

    #[test]
    fn expired_cross_bank_and_changed_role_sessions_cannot_access_revenue() {
        let (mut atm, _, authority) = bank();
        let (other, _, _) = bank();
        assert!(matches!(balances(&other, &authority), Err(AtmError::SessionExpired)));
        let authority = auth::testing::authorities(&atm);
        authority.end();
        assert!(matches!(balances(&atm, &authority), Err(AtmError::SessionExpired)));
        let authority = auth::testing::authorities(&atm);
        let tx = atm.begin().unwrap();
        tx.execute("DELETE FROM staff WHERE role = 'authorities'", []).unwrap();
        tx.commit().unwrap();
        assert!(matches!(
            adjust(
                &mut atm,
                &authority,
                Currency::Usd,
                Adjustment::Credit,
                Cents::from_dollars(1),
                "rejected"
            ),
            Err(AtmError::SessionExpired)
        ));
    }

    #[test]
    fn altered_revenue_is_detected_by_seal_and_reconciliation() {
        let (atm, _, authority) = bank();
        atm.conn.execute("UPDATE bank_revenue SET balance_cents = 1", []).unwrap();
        assert!(matches!(balances(&atm, &authority), Err(AtmError::DatabaseAltered)));
        assert!(reconcile(&atm.conn).is_err());
    }

    #[test]
    fn a_failed_revenue_credit_rolls_back_the_customer_cash_and_both_ledgers() {
        let (mut atm, admin, authority) = bank();
        adjust(&mut atm, &authority, Currency::Usd, Adjustment::Credit, Cents::MAX, "capacity test").unwrap();
        let card =
            admin::create_customer(&mut atm, &admin, "Pat Doe", "1980-01-01", "1357", Cents::ZERO).unwrap();
        let session = auth::login_customer(&mut atm, &card.card_number, "1357").unwrap();
        let before: i64 = atm.conn.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)).unwrap();
        assert!(customer::deposit(&mut atm, &session, &[(Denomination::new(100).unwrap(), 1)]).is_err());
        assert_eq!(customer::balance(&atm, &session).unwrap(), Cents::ZERO);
        assert_eq!(balances(&atm, &authority).unwrap()[0].balance, Cents::MAX);
        assert_eq!(crate::cash::stock(&atm.conn).unwrap().1, Cents::ZERO);
        assert_eq!(
            atm.conn.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get::<_, i64>(0)).unwrap(),
            before
        );
        assert_eq!(
            atm.conn
                .query_row("SELECT COUNT(*) FROM processing.records", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        admin::verify_integrity(&mut atm, &admin).unwrap();
    }
}
