//! The audit log: one append-only, HMAC-chained ledger.
//!
//! STRIDE (Repudiation): every money movement and security event is logged
//! with a timestamp and who did it, in the SAME SQL transaction as the change.
//! STRIDE (Tampering): each row stores HMAC(key, row + previous MAC). Editing,
//! reordering or deleting a row breaks the chain, and without `atm.key`
//! nobody can recompute it. `verify` also cross-checks every balance.
//!
//! Known limits: someone holding BOTH the DB and the key can rewrite history; deleting the
//! newest rows is caught via sqlite_sequence only if that wasn't edited too. Writing down the
//! head MAC (shown after verify) gives an off-machine anchor.

use crate::db::{self, Number};
use crate::error::{AtmError, Result};
use crate::fx::Currency;
use crate::keys;
use crate::money::Cents;
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use chrono_tz::America::New_York;
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::Sha256;

/// `prev_mac` of the very first row.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Allowed clock skew before we call it a rollback.
const CLOCK_SKEW_SECS: i64 = 120;

/// Everything that can be logged. An enum, so a typo can't invent an action
/// name that the daily-limit query silently misses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Setup,
    AccountOpened,
    HolderAdded,
    LoginOk,
    LoginFailed,
    CardLocked,
    CardUnlocked,
    SessionEnded,
    Deposit,
    Withdrawal,
    Transfer,
    LimitChanged,
    ControlsChanged,
    AccountFrozen,
    AccountUnfrozen,
    AccountClosed,
    PinChanged,
    PasswordChanged,
    CashRestocked,
    CashRemoved,
    AuditVerified,
    RateChanged,
    FeeChanged,
    ExchangePaused,
    ExchangeResumed,
    /// A teller approved more than the daily limit, for today only (`usd` = the extra).
    WithdrawalLimitRaised,
    DepositLimitRaised,
    TransferLimitRaised,
    /// Unusual activity: withdrawals and transfers stopped until a teller releases it.
    HoldPlaced,
    HoldReleased,
    /// A teller's rate check failed (unreachable, untrusted certificate, bad reply).
    RateFeedFailed,
    /// Customer service stopped (failed integrity check, or by hand) / started again.
    ServiceHalted,
    ServiceResumed,
}

impl Action {
    /// The fixed name stored in the log for this action.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Setup => "setup",
            Action::AccountOpened => "account_opened",
            Action::HolderAdded => "holder_added",
            Action::LoginOk => "login_ok",
            Action::LoginFailed => "login_failed",
            Action::CardLocked => "card_locked",
            Action::CardUnlocked => "card_unlocked",
            Action::SessionEnded => "session_ended",
            Action::Deposit => "deposit",
            Action::Withdrawal => "withdrawal",
            Action::Transfer => "transfer",
            Action::LimitChanged => "limit_changed",
            Action::ControlsChanged => "controls_changed",
            Action::AccountFrozen => "account_frozen",
            Action::AccountUnfrozen => "account_unfrozen",
            Action::AccountClosed => "account_closed",
            Action::PinChanged => "pin_changed",
            Action::PasswordChanged => "password_changed",
            Action::CashRestocked => "cash_restocked",
            Action::CashRemoved => "cash_removed",
            Action::AuditVerified => "audit_verified",
            Action::RateChanged => "rate_changed",
            Action::FeeChanged => "fee_changed",
            Action::ExchangePaused => "exchange_paused",
            Action::ExchangeResumed => "exchange_resumed",
            Action::WithdrawalLimitRaised => "withdrawal_limit_raised",
            Action::DepositLimitRaised => "deposit_limit_raised",
            Action::TransferLimitRaised => "transfer_limit_raised",
            Action::HoldPlaced => "hold_placed",
            Action::HoldReleased => "hold_released",
            Action::RateFeedFailed => "rate_feed_failed",
            Action::ServiceHalted => "service_halted",
            Action::ServiceResumed => "service_resumed",
        }
    }
}

/// A new entry to append.
pub(crate) struct Entry<'a> {
    pub actor: &'a str,
    pub action: Action,
    pub account_id: Option<i64>,
    pub counterparty_id: Option<i64>,
    /// In the account's currency.
    pub amount: Option<Cents>,
    /// US-dollar value of a deposit, withdrawal or transfer (counts toward daily limits).
    pub usd: Option<Cents>,
    /// Program-generated text only. Never raw user input.
    pub detail: &'a str,
}

/// A row read back for display.
#[derive(Debug, Clone)]
pub struct Row {
    pub seq: i64,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub account_number: Option<String>,
    pub counterparty_number: Option<String>,
    /// In `currency` (the account's currency).
    pub amount: Option<Cents>,
    pub currency: Currency,
    pub detail: String,
}

/// Result of a full integrity check.
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    pub entries: i64,
    pub accounts_checked: i64,
    /// Cash in the machine, which matches the log's cash in and out.
    pub cash: Cents,
    /// Settings and exchange-rate rows whose MAC was checked.
    pub records_checked: i64,
    /// Limits, rates and account freezes/closures that match the log.
    pub state_checked: i64,
    /// First 16 hex chars of the newest MAC. Write it down: an off-machine anchor.
    pub head: String,
}

/// The current time in UTC, as RFC 3339 text to the second.
pub fn now_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// MAC one row. Fields are length-prefixed so "ab"+"c" != "a"+"bc".
#[allow(clippy::too_many_arguments)]
fn row_mac(
    prev_mac: &str,
    ts: &str,
    actor: &str,
    action: &str,
    account_id: Option<i64>,
    counterparty_id: Option<i64>,
    amount_cents: Option<i64>,
    usd_cents: Option<i64>,
    detail: &str,
) -> Result<String> {
    let opt = |v: Option<i64>| v.map(|n| n.to_string()).unwrap_or_else(|| "-".to_string());
    let fields = [
        prev_mac.to_string(),
        ts.to_string(),
        actor.to_string(),
        action.to_string(),
        opt(account_id),
        opt(counterparty_id),
        opt(amount_cents),
        opt(usd_cents),
        detail.to_string(),
    ];
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(keys::audit_mac_key()?)
        .map_err(|_| AtmError::Internal("bad MAC key".into()))?;
    for field in &fields {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field.as_bytes());
    }
    Ok(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect())
}

/// Append one entry; returns its sequence number (used as receipt reference).
/// Always call on the same open transaction as the change it describes.
pub(crate) fn append(conn: &Connection, entry: &Entry) -> Result<i64> {
    let prev_mac: String = conn
        .query_row("SELECT mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
        .optional()?
        .unwrap_or_else(|| GENESIS.to_string());
    let ts = now_utc();
    let amount = entry.amount.map(Cents::as_i64);
    let usd = entry.usd.map(Cents::as_i64);
    let action = entry.action.as_str();
    let mac = row_mac(
        &prev_mac,
        &ts,
        entry.actor,
        action,
        entry.account_id,
        entry.counterparty_id,
        amount,
        usd,
        entry.detail,
    )?;
    conn.execute(
        "INSERT INTO audit_log
            (ts, actor, action, account_id, counterparty_id, amount_cents, usd_cents, detail, prev_mac, mac)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            ts,
            entry.actor,
            action,
            entry.account_id,
            entry.counterparty_id,
            amount,
            usd,
            entry.detail,
            prev_mac,
            mac
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Walk the chain from the first row. Returns (row count, head MAC).
fn verify_chain(conn: &Connection) -> Result<(i64, String)> {
    let mut stmt = conn.prepare(
        "SELECT seq, ts, actor, action, account_id, counterparty_id, amount_cents, usd_cents, detail,
                prev_mac, mac
         FROM audit_log ORDER BY seq ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut expected_prev = GENESIS.to_string();
    let mut count = 0;
    let mut last_seq = 0;
    while let Some(r) = rows.next()? {
        let seq: i64 = r.get(0)?;
        let prev_mac: String = r.get(9)?;
        let mac: String = r.get(10)?;
        let recomputed = row_mac(
            &prev_mac,
            &r.get::<_, String>(1)?,
            &r.get::<_, String>(2)?,
            &r.get::<_, String>(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
            &r.get::<_, String>(8)?,
        )?;
        // Both compared in full (constant time), so timing can't guide a forger.
        if !keys::same_mac(&prev_mac, &expected_prev) | !keys::same_mac(&mac, &recomputed) {
            return Err(AtmError::AuditTampered(seq));
        }
        expected_prev = mac;
        last_seq = seq;
        count += 1;
    }
    // Tail truncation: AUTOINCREMENT remembers the highest seq ever issued.
    let highest: Option<i64> = conn
        .query_row("SELECT seq FROM sqlite_sequence WHERE name = 'audit_log'", [], |r| r.get(0))
        .optional()?;
    if highest.unwrap_or(0) != last_seq {
        return Err(AtmError::AuditTampered(last_seq + 1));
    }
    Ok((count, expected_prev))
}

/// Recompute every balance from the ledger and compare with the stored one.
/// Catches a balance edited directly in the DB (STRIDE: Tampering).
fn reconcile_balances(conn: &Connection) -> Result<i64> {
    let mut stmt = conn.prepare(
        "SELECT a.account_last4, a.currency, a.balance_cents,
                COALESCE((SELECT SUM(CASE
                    WHEN l.account_id = a.id AND l.action IN ('account_opened', 'deposit')
                        THEN l.amount_cents
                    WHEN l.account_id = a.id AND l.action IN ('withdrawal', 'transfer')
                        THEN -l.amount_cents
                    WHEN l.counterparty_id = a.id AND l.action = 'transfer'
                        THEN l.amount_cents
                    ELSE 0 END)
                  FROM audit_log l
                  WHERE l.account_id = a.id OR l.counterparty_id = a.id), 0)
         FROM accounts a ORDER BY a.id",
    )?;
    let rows: Vec<(String, String, i64, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    // Every account that is off, with both amounts: a new or bigger difference
    // changes the report. Last 4 digits only, since the report goes in the log.
    let mut wrong = Vec::new();
    for (last4, currency, stored, derived) in &rows {
        if stored != derived {
            let c = crate::fx::Currency::parse(currency)?;
            let show = |v: i64| match Cents::new(v.saturating_abs()) {
                Ok(m) if v < 0 => format!("-{}", c.format(m)),
                Ok(m) => c.format(m),
                Err(_) => v.to_string(),
            };
            wrong.push(format!(
                "account ******{last4} (stored {}, the log says {})",
                show(*stored),
                show(*derived)
            ));
        }
    }
    if !wrong.is_empty() {
        return Err(AtmError::BalanceMismatch(wrong));
    }
    Ok(rows.len() as i64)
}

/// The cash in the machine must equal what the log says went in (restocks,
/// deposits) minus what went out (withdrawals, removals). STRIDE (Tampering):
/// bills paid out or added with no log entry (say, one extra bill planted in
/// a withdrawal) show up here, even when the balances all match.
fn reconcile_cash(conn: &Connection) -> Result<Cents> {
    let (counted, logged): (i64, i64) = conn.query_row(
        "SELECT (SELECT COALESCE(SUM(denomination * 100 * bill_count), 0) FROM cash_inventory),
                (SELECT COALESCE(SUM(CASE action
                    WHEN 'cash_restocked' THEN amount_cents
                    WHEN 'deposit' THEN usd_cents
                    WHEN 'withdrawal' THEN -usd_cents
                    WHEN 'cash_removed' THEN -amount_cents
                    ELSE 0 END), 0) FROM audit_log)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let cents = |c: i64| Cents::new(c.max(0)).unwrap_or(Cents::ZERO);
    if counted != logged {
        return Err(AtmError::CashMismatch { counted: cents(counted), logged: cents(logged) });
    }
    Ok(cents(counted))
}

/// Each daily limit, exchange rate (newest history row, one log entry per row) and account
/// freeze or closure must match the log. STRIDE (Tampering): a change made without its log
/// entry shows up here. Returns how many were checked.
fn reconcile_state(conn: &Connection) -> Result<i64> {
    let mut wrong = Vec::new();
    let mut checked = 0;
    for limit in db::Limit::ALL {
        let logged: Option<i64> = conn
            .query_row(
                "SELECT amount_cents FROM audit_log WHERE action = 'limit_changed' AND detail LIKE ?1
                 ORDER BY seq DESC LIMIT 1",
                params![format!("daily {} limit:%", limit.label())],
                |r| r.get(0),
            )
            .optional()?;
        if db::get_limit(conn, limit)?.as_i64() != logged.unwrap_or(limit.default_value().as_i64()) {
            wrong.push(format!("the daily {} limit", limit.label()));
        }
        checked += 1;
    }
    // A rate must equal its newest history row, and every history row
    // (append-only) needs its own "XXX per USD:" log line (one pass over the log).
    let mut stmt = conn.prepare(
        "WITH logged AS (SELECT substr(detail, 1, 3) AS currency, COUNT(*) AS n FROM audit_log
                         WHERE action = 'rate_changed' AND detail LIKE '___ per USD:%' GROUP BY 1),
              history AS (SELECT currency, COUNT(*) AS n FROM rate_history GROUP BY currency)
         SELECT r.currency,
                r.per_usd_micros IS (SELECT h.per_usd_micros FROM rate_history h
                                     WHERE h.currency = r.currency ORDER BY h.id DESC LIMIT 1)
                AND COALESCE(h.n, 0) = COALESCE(l.n, 0)
         FROM exchange_rates r
         LEFT JOIN history h ON h.currency = r.currency
         LEFT JOIN logged l ON l.currency = r.currency
         ORDER BY r.currency",
    )?;
    let rates: Vec<(String, bool)> =
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
    for (currency, matches) in &rates {
        if !matches {
            wrong.push(format!("the {currency} rate"));
        }
    }
    checked += rates.len() as i64;
    // 1 if the newest freeze row of this kind is a freeze, else 0.
    let mut stmt = conn.prepare(
        "SELECT a.account_last4,
                a.frozen IS COALESCE((SELECT l.action = 'account_frozen' FROM audit_log l
                    WHERE l.account_id = a.id AND l.action IN ('account_frozen', 'account_unfrozen')
                      AND l.detail = 'by teller admin' ORDER BY l.seq DESC LIMIT 1), 0),
                a.guardian_frozen IS COALESCE((SELECT l.action = 'account_frozen' FROM audit_log l
                    WHERE l.account_id = a.id AND l.action IN ('account_frozen', 'account_unfrozen')
                      AND l.detail = 'by guardian' ORDER BY l.seq DESC LIMIT 1), 0),
                a.closed IS EXISTS (SELECT 1 FROM audit_log l
                    WHERE l.account_id = a.id AND l.action = 'account_closed')
         FROM accounts a ORDER BY a.id",
    )?;
    let accounts: Vec<(String, [bool; 3])> = stmt
        .query_map([], |r| Ok((r.get(0)?, [r.get(1)?, r.get(2)?, r.get(3)?])))?
        .collect::<rusqlite::Result<_>>()?;
    for (last4, matches) in &accounts {
        for (ok, what) in matches.iter().zip(["bank freeze", "guardian freeze", "closure"]) {
            if !ok {
                wrong.push(format!("the {what} of account ******{last4}"));
            }
        }
    }
    checked += 3 * accounts.len() as i64;
    if !wrong.is_empty() {
        return Err(AtmError::StateMismatch(wrong));
    }
    Ok(checked)
}

/// Full integrity check: chain, truncation, balances, cash, settings, rates,
/// and the limits, rates and account flags against the log.
/// A broken chain stops it (the other checks trust the log). After that every
/// check runs and every failure is reported, so a known one hides nothing.
pub(crate) fn verify(conn: &Connection) -> Result<IntegrityReport> {
    let (entries, head) = verify_chain(conn)?;
    match (
        reconcile_balances(conn),
        reconcile_cash(conn),
        crate::db::verify_settings(conn),
        crate::fx::verify_rates(conn),
        reconcile_state(conn),
    ) {
        (Ok(accounts_checked), Ok(cash), Ok(settings), Ok(rates), Ok(state_checked)) => Ok(IntegrityReport {
            entries,
            accounts_checked,
            cash,
            records_checked: settings + rates,
            state_checked,
            head: head.chars().take(16).collect(),
        }),
        (balances, cash, settings, rates, state) => {
            let mut failed: Vec<AtmError> =
                [balances.err(), cash.err(), settings.err(), rates.err(), state.err()]
                    .into_iter()
                    .flatten()
                    .collect();
            Err(if failed.len() == 1 { failed.remove(0) } else { AtmError::IntegrityFailures(failed) })
        }
    }
}

/// Rows touching one account, newest first, one page at a time.
/// `transactions_only`: deposits/withdrawals/transfers (customer view).
pub(crate) fn for_account(
    conn: &Connection,
    account_id: i64,
    transactions_only: bool,
    page_size: u32,
    page: u32,
) -> Result<Vec<Row>> {
    let offset = i64::from(page) * i64::from(page_size);
    // Fixed SQL; the filter switch is itself a bound parameter.
    let mut stmt = conn.prepare(
        "SELECT l.seq, l.ts, l.actor, l.action, a.account_lookup, a.account_enc,
                c.account_lookup, c.account_enc, l.amount_cents, l.detail, COALESCE(a.currency, 'USD')
         FROM audit_log l
         LEFT JOIN accounts a ON a.id = l.account_id
         LEFT JOIN accounts c ON c.id = l.counterparty_id
         WHERE (l.account_id = ?1 OR l.counterparty_id = ?1)
           AND (?2 = 0 OR l.action IN ('deposit', 'withdrawal', 'transfer'))
         ORDER BY l.seq DESC LIMIT ?3 OFFSET ?4",
    )?;
    let mut rows = stmt.query(params![account_id, transactions_only, page_size, offset])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(read_row(r)?);
    }
    Ok(out)
}

/// One account's transactions as its customer may see them (STRIDE: Info
/// Disclosure). Any other account shows only its last 4 digits, and an action
/// taken from another account (a transfer in) shows "other account holder",
/// not that person's card. Staff screens use `for_account` instead.
pub(crate) fn for_customer(
    conn: &Connection,
    account_id: i64,
    own: &str,
    page_size: u32,
    page: u32,
) -> Result<Vec<Row>> {
    let hide = |n: Option<String>| n.map(|n| if n == own { n } else { crate::customer::mask(&n) });
    Ok(for_account(conn, account_id, true, page_size, page)?
        .into_iter()
        .map(|row| Row {
            actor: if row.account_number.as_deref() == Some(own) {
                row.actor
            } else {
                "other account holder".into()
            },
            account_number: hide(row.account_number),
            counterparty_number: hide(row.counterparty_number),
            ..row
        })
        .collect())
}

/// Every event (all accounts, logins, cash, admin), newest first, one page at a time.
pub(crate) fn recent(conn: &Connection, page_size: u32, page: u32) -> Result<Vec<Row>> {
    let offset = i64::from(page) * i64::from(page_size);
    let mut stmt = conn.prepare(
        "SELECT l.seq, l.ts, l.actor, l.action, a.account_lookup, a.account_enc,
                c.account_lookup, c.account_enc, l.amount_cents, l.detail, COALESCE(a.currency, 'USD')
         FROM audit_log l
         LEFT JOIN accounts a ON a.id = l.account_id
         LEFT JOIN accounts c ON c.id = l.counterparty_id
         ORDER BY l.seq DESC LIMIT ?1 OFFSET ?2",
    )?;
    let mut rows = stmt.query(params![page_size, offset])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(read_row(r)?);
    }
    Ok(out)
}

/// One log row as read by the page queries, with its account numbers decrypted.
fn read_row(r: &rusqlite::Row) -> Result<Row> {
    // An account number, decrypted; None when the row names no account.
    let number = |lookup: usize| -> Result<Option<String>> {
        match (r.get::<_, Option<String>>(lookup)?, r.get::<_, Option<Vec<u8>>>(lookup + 1)?) {
            (Some(found_by), Some(sealed)) => Ok(Some(db::open_number(Number::Account, &found_by, &sealed)?)),
            _ => Ok(None),
        }
    };
    let amount: Option<i64> = r.get(8)?;
    Ok(Row {
        seq: r.get(0)?,
        ts: r.get(1)?,
        actor: r.get(2)?,
        action: r.get(3)?,
        account_number: number(4)?,
        counterparty_number: number(6)?,
        amount: amount.map(Cents::new).transpose()?,
        currency: Currency::parse(&r.get::<_, String>(10)?)?,
        detail: r.get(9)?,
    })
}

/// Start of today's bank day (New York midnight) as a UTC timestamp string.
pub(crate) fn bank_day_start_utc() -> Result<String> {
    let today = Utc::now().with_timezone(&New_York).date_naive();
    let midnight = today
        .and_hms_opt(0, 0, 0)
        .and_then(|naive| New_York.from_local_datetime(&naive).earliest())
        .ok_or_else(|| AtmError::Internal("cannot compute bank day".into()))?;
    Ok(midnight.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// US-dollar amount this account moved today via `action` (all holders combined).
/// STRIDE (Tampering): derived from the ledger every time; there is no
/// "used today" counter to reset, and logging out/restarting changes nothing.
/// Incoming transfers don't count: they're logged on the sender's account_id.
pub(crate) fn total_today(conn: &Connection, account_id: i64, action: Action) -> Result<Cents> {
    let since = bank_day_start_utc()?;
    let total: i64 = conn.query_row(
        "SELECT COALESCE(SUM(usd_cents), 0) FROM audit_log
         WHERE account_id = ?1 AND action = ?2 AND ts >= ?3",
        params![account_id, action.as_str(), since],
        |r| r.get(0),
    )?;
    Cents::new(total)
}

/// US-dollar value of the starting balances one staff login entered this
/// bank day (see admin::STARTING_BALANCES_PER_DAY). From the signed log.
pub(crate) fn opened_today_by(conn: &Connection, actor: &str) -> Result<Cents> {
    let total: i64 = conn.query_row(
        "SELECT COALESCE(SUM(usd_cents), 0) FROM audit_log WHERE actor = ?1 AND action = ?2 AND ts >= ?3",
        params![actor, Action::AccountOpened.as_str(), bank_day_start_utc()?],
        |r| r.get(0),
    )?;
    Cents::new(total)
}

/// Refuse to run if the clock is behind the newest log entry: a rolled-back
/// clock would start a fresh "day" early and reset daily limits.
pub(crate) fn check_clock(conn: &Connection) -> Result<()> {
    let newest: Option<String> =
        conn.query_row("SELECT MAX(ts) FROM audit_log", [], |r| r.get(0)).optional()?.flatten();
    if let Some(ts) = newest {
        let newest = DateTime::parse_from_rfc3339(&ts)
            .map_err(|_| AtmError::Internal("bad audit timestamp".into()))?;
        if Utc::now().timestamp() + CLOCK_SKEW_SECS < newest.timestamp() {
            return Err(AtmError::ClockRollback);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn entry(detail: &str) -> Entry<'_> {
        Entry {
            actor: "test",
            action: Action::Setup,
            account_id: None,
            counterparty_id: None,
            amount: None,
            usd: None,
            detail,
        }
    }

    fn three_rows() -> crate::Atm {
        let conn = crate::Atm::in_memory().unwrap();
        for d in ["one", "two", "three"] {
            append(&conn, &entry(d)).unwrap();
        }
        conn
    }

    #[test]
    fn chain_verifies_and_detects_edits() {
        let conn = three_rows();
        assert_eq!(verify(&conn).unwrap().entries, 3);
        // Attacker with raw file access drops the trigger; the MAC still catches it.
        conn.execute_batch("DROP TRIGGER audit_no_update").unwrap();
        conn.execute("UPDATE audit_log SET detail = 'TWO' WHERE seq = 2", []).unwrap();
        assert!(matches!(verify(&conn), Err(AtmError::AuditTampered(2))));
    }

    #[test]
    fn chain_detects_deletion_in_the_middle_and_at_the_end() {
        let conn = three_rows();
        conn.execute_batch("DROP TRIGGER audit_no_delete").unwrap();
        conn.execute("DELETE FROM audit_log WHERE seq = 3", []).unwrap();
        assert!(matches!(verify(&conn), Err(AtmError::AuditTampered(3))));
        conn.execute("DELETE FROM audit_log WHERE seq = 2", []).unwrap();
        assert!(matches!(verify(&conn), Err(AtmError::AuditTampered(_))));
    }

    #[test]
    fn forger_without_the_key_cannot_rebuild_the_chain() {
        let conn = three_rows();
        conn.execute_batch("DROP TRIGGER audit_no_update").unwrap();
        // Forger edits row 3 and recomputes an unkeyed SHA-256 "chain" value.
        let fake: String = sha2::Sha256::digest(b"forged").iter().map(|b| format!("{b:02x}")).collect();
        conn.execute("UPDATE audit_log SET detail = 'x', mac = ?1 WHERE seq = 3", [fake]).unwrap();
        assert!(matches!(verify(&conn), Err(AtmError::AuditTampered(3))));
    }

    #[test]
    fn application_cannot_edit_or_delete_history() {
        let conn = crate::Atm::in_memory().unwrap();
        append(&conn, &entry("one")).unwrap();
        assert!(conn.execute("UPDATE audit_log SET detail = 'x'", []).is_err());
        assert!(conn.execute("DELETE FROM audit_log", []).is_err());
    }

    #[test]
    fn clock_rollback_is_refused() {
        let conn = crate::Atm::in_memory().unwrap();
        append(&conn, &entry("one")).unwrap();
        assert!(check_clock(&conn).is_ok());
        conn.execute_batch("DROP TRIGGER audit_no_update").unwrap();
        conn.execute("UPDATE audit_log SET ts = '2999-01-01T00:00:00Z'", []).unwrap();
        assert!(matches!(check_clock(&conn), Err(AtmError::ClockRollback)));
    }
}
