//! Database: file, schema, hardening, bank-wide settings.
//!
//! STRIDE (Tampering): every query uses bound parameters (?1, ?2 ...). User
//! text is never pasted into SQL, so no SQL injection. `format!` building SQL
//! anywhere in this codebase would be a bug.
//! CHECK constraints are a second line of defence behind the Rust checks.
//!
//! Data model:
//!   accounts  - the money (individual / joint / youth / guest).
//!               "guest" = a card from another bank (simulated card network):
//!               withdraw and balance only, plus an ATM fee.
//!   cards     - a person's login to one account (card number + own PIN).
//!               Joint accounts have 2 cards; each holder has their own PIN.
//!               Name and DOB are stored encrypted (see keys.rs).
//!   Card and account numbers are never stored in the clear: each row keeps
//!   a keyed lookup (HMAC) to find it, the number AES-GCM encrypted, and the
//!   last 4 digits for display. Logs name a card by its row id + last 4.
//!   guardians - which adult cards manage which youth account
//!   settings  - bank-wide limits and fees, each with a MAC
//!   exchange_rates - teller-set rates for other currencies (see fx.rs)
//!   rate_history   - every rate ever set (change cap + review), append-only
//!   meta      - schema version + key fingerprint
//!   seal      - one HMAC over all of the above (see seal.rs)

use crate::error::{AtmError, Result};
use crate::keys;
use crate::money::{Cents, DENOMINATIONS};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

/// Normal cash maximum. Restocks fill up to this; handler removes anything above.
pub const CASH_MAXIMUM: Cents = Cents::from_dollars(100_000);
/// Physical capacity. Customer deposits can't push the machine past this.
pub const PHYSICAL_CAPACITY: Cents = Cents::from_dollars(150_000);
/// Bump when the schema changes in a way older databases can't use.
const SCHEMA_VERSION: &str = "6";
/// Settings keys for the two fees: (percent in basis points, minimum in US cents).
/// Each fee is the higher of the two. See `fx::Fee`.
pub(crate) const EXCHANGE_FEE_KEYS: (&str, &str) = ("exchange_fee_bp", "exchange_fee_min_cents");
pub(crate) const OTHER_BANK_FEE_KEYS: (&str, &str) = ("other_bank_fee_bp", "other_bank_fee_min_cents");
/// Default for both fees: 3%, but at least $3.00 (typical card and New York ATM fees).
const DEFAULT_FEE_BP: i64 = 300;
const DEFAULT_FEE_MIN_CENTS: i64 = 300;

const SCHEMA: &str = r#"
-- Every table is STRICT: a value of the wrong type (text in a balance) is refused.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS staff (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE,
    role            TEXT    NOT NULL CHECK (role IN ('admin', 'handler')),
    password_hash   TEXT    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    cooldown_until  TEXT                      -- UTC; NULL = no cooldown
) STRICT;

CREATE TABLE IF NOT EXISTS accounts (
    id                    INTEGER PRIMARY KEY,
    account_lookup        TEXT    NOT NULL UNIQUE,  -- HMAC of the number: finds the row
    account_enc           BLOB    NOT NULL,         -- the number, AES-256-GCM
    account_last4         TEXT    NOT NULL CHECK (length(account_last4) = 4),
    kind                  TEXT    NOT NULL CHECK (kind IN ('individual', 'joint', 'youth', 'guest')),
    -- Balance is in this currency's cents. Cash in the machine is always USD.
    currency              TEXT    NOT NULL DEFAULT 'USD'
                                  CHECK (currency IN ('USD', 'BDT', 'BRL', 'CAD', 'CNY', 'COP', 'DOP',
                                                      'EUR', 'GBP', 'GYD', 'HTG', 'INR', 'JMD', 'JPY',
                                                      'KRW', 'MXN')),
    balance_cents         INTEGER NOT NULL CHECK (balance_cents BETWEEN 0 AND 1000000000000000),  -- Cents::MAX
    -- Two separate freezes: each side can only lift its own.
    frozen                INTEGER NOT NULL DEFAULT 0 CHECK (frozen IN (0, 1)),          -- by the bank
    guardian_frozen       INTEGER NOT NULL DEFAULT 0 CHECK (guardian_frozen IN (0, 1)), -- by a guardian
    -- Closed accounts stay in the table (history kept, number never reused).
    closed                INTEGER NOT NULL DEFAULT 0 CHECK (closed IN (0, 1)),
    -- Youth controls (NULL / 0 for adult accounts). Effective limit = min(bank, cap).
    withdraw_cap_cents    INTEGER CHECK (withdraw_cap_cents >= 0),
    transfer_cap_cents    INTEGER CHECK (transfer_cap_cents >= 0),
    family_only_transfers INTEGER NOT NULL DEFAULT 0 CHECK (family_only_transfers IN (0, 1))
) STRICT;

CREATE TABLE IF NOT EXISTS cards (
    id              INTEGER PRIMARY KEY,
    card_lookup     TEXT    NOT NULL UNIQUE,  -- HMAC of the number: finds the row
    card_enc        BLOB    NOT NULL,         -- the number, AES-256-GCM
    card_last4      TEXT    NOT NULL CHECK (length(card_last4) = 4),
    account_id      INTEGER NOT NULL REFERENCES accounts(id),
    holder_role     TEXT    NOT NULL CHECK (holder_role IN ('owner', 'joint', 'minor', 'guest')),
    name_enc        BLOB    NOT NULL,         -- AES-256-GCM (keys::seal)
    dob_enc         BLOB    NOT NULL,         -- AES-256-GCM, YYYY-MM-DD inside
    pin_hash        TEXT    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked          INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1))
) STRICT;
CREATE INDEX IF NOT EXISTS cards_by_account ON cards (account_id);

CREATE TABLE IF NOT EXISTS guardians (
    youth_account_id INTEGER NOT NULL REFERENCES accounts(id),
    guardian_card_id INTEGER NOT NULL REFERENCES cards(id),
    PRIMARY KEY (youth_account_id, guardian_card_id)
) STRICT;

-- STRIDE (Tampering): each row carries an HMAC; an edit in the file is detected.
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT    PRIMARY KEY,
    value INTEGER NOT NULL CHECK (value >= 0),
    mac   TEXT    NOT NULL
) STRICT;

-- Foreign units per US dollar, in millionths (920000 = 0.92 EUR per USD).
CREATE TABLE IF NOT EXISTS exchange_rates (
    currency       TEXT    PRIMARY KEY CHECK (currency IN ('BDT', 'BRL', 'CAD', 'CNY', 'COP', 'DOP',
                                                       'EUR', 'GBP', 'GYD', 'HTG', 'INR', 'JMD',
                                                       'JPY', 'KRW', 'MXN')),
    per_usd_micros INTEGER NOT NULL CHECK (per_usd_micros > 0),
    set_at         TEXT    NOT NULL,   -- UTC
    set_by         TEXT    NOT NULL,   -- admin:<user>
    paused         INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1)),  -- emergency stop
    mac            TEXT    NOT NULL
) STRICT;

-- Every rate a teller has set, oldest first. Used for the change cap and for
-- review. Append-only like the audit log; each row carries a MAC.
CREATE TABLE IF NOT EXISTS rate_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    currency       TEXT    NOT NULL,
    per_usd_micros INTEGER NOT NULL CHECK (per_usd_micros > 0),
    set_at         TEXT    NOT NULL,
    set_by         TEXT    NOT NULL,
    mac            TEXT    NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS rate_history_by_currency ON rate_history (currency, id);
CREATE TRIGGER IF NOT EXISTS rate_history_no_update BEFORE UPDATE ON rate_history
BEGIN SELECT RAISE(ABORT, 'rate history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS rate_history_no_delete BEFORE DELETE ON rate_history
BEGIN SELECT RAISE(ABORT, 'rate history is append-only'); END;

CREATE TABLE IF NOT EXISTS cash_inventory (
    denomination INTEGER PRIMARY KEY CHECK (denomination IN (5, 10, 20, 50, 100)),
    bill_count   INTEGER NOT NULL CHECK (bill_count >= 0)
) STRICT;

-- One append-only ledger: money movements AND security events.
CREATE TABLE IF NOT EXISTS audit_log (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,   -- UTC, YYYY-MM-DDTHH:MM:SSZ
    actor           TEXT    NOT NULL,   -- who: customer:<card>, admin:<user>, ...
    action          TEXT    NOT NULL,   -- what
    account_id      INTEGER,            -- whose account (money left / arrived)
    counterparty_id INTEGER,            -- other side of a transfer
    amount_cents    INTEGER CHECK (amount_cents >= 0),  -- in the account's currency
    usd_cents       INTEGER CHECK (usd_cents >= 0),     -- US-dollar value (daily limits)
    detail          TEXT    NOT NULL DEFAULT '',
    prev_mac        TEXT    NOT NULL,   -- MAC of the previous row
    mac             TEXT    NOT NULL    -- HMAC(key, this row + prev_mac)
) STRICT;
CREATE INDEX IF NOT EXISTS audit_by_account ON audit_log (account_id, seq);
CREATE INDEX IF NOT EXISTS audit_by_counterparty ON audit_log (counterparty_id, seq);

-- STRIDE (Repudiation): the app cannot edit or delete history.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;

-- STRIDE (Tampering): HMAC over every table above, rewritten with each change.
CREATE TABLE IF NOT EXISTS seal (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    counter INTEGER NOT NULL CHECK (counter > 0),
    mac     TEXT    NOT NULL
) STRICT;
"#;

/// Open the DB file (owner-only permissions). A new file gets the tables,
/// defaults and its first seal. An existing one is only checked, never
/// changed here: the seal check that follows must see it as it was.
pub(crate) fn open(path: &Path, fresh: bool) -> Result<Connection> {
    let conn = Connection::open(path)?;
    // STRIDE (Info Disclosure / Tampering): only the owning OS user can read/write.
    keys::restrict_permissions(path)?;
    configure(&conn)?;
    if fresh {
        create(&conn)?;
    } else {
        check_version_and_key(&conn)?;
    }
    Ok(conn)
}

/// Throwaway in-memory DB for tests.
#[cfg(test)]
pub(crate) fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    configure(&conn)?;
    create(&conn)?;
    Ok(conn)
}

/// Turn on SQLite hardening for this connection (defensive mode and safe pragmas).
fn configure(conn: &Connection) -> Result<()> {
    // Defensive mode: SQL can't corrupt the file via writable_schema & co.
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    // trusted_schema OFF: a tampered DB file can't smuggle functions into views/triggers.
    // secure_delete ON: deleted/overwritten data is zeroed, not left in free pages.
    // FULL sync: a committed transaction survives a power cut.
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = ON;
         PRAGMA synchronous = FULL;
         PRAGMA busy_timeout = 5000;",
    )?;
    Ok(())
}

/// A brand-new bank, in one transaction: tables, version + key fingerprint,
/// defaults, first seal.
fn create(conn: &Connection) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(SCHEMA)?;
    tx.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?1)", [SCHEMA_VERSION])?;
    tx.execute("INSERT INTO meta (key, value) VALUES ('key_fingerprint', ?1)", [keys::fingerprint()?])?;
    insert_defaults(&tx)?;
    crate::seal::write(&tx, 1)?;
    tx.commit()?;
    Ok(())
}

/// Defaults for a new bank.
fn insert_defaults(conn: &Connection) -> Result<()> {
    for (key, value) in [
        // Typical US bank defaults. $10,000 is the cash amount above which a
        // bank must file a Currency Transaction Report, so more needs a teller.
        (Limit::Withdrawal.key(), Limit::Withdrawal.default_value().as_i64()),
        (Limit::Deposit.key(), Limit::Deposit.default_value().as_i64()),
        (Limit::Transfer.key(), Limit::Transfer.default_value().as_i64()),
        (EXCHANGE_FEE_KEYS.0, DEFAULT_FEE_BP),
        (EXCHANGE_FEE_KEYS.1, DEFAULT_FEE_MIN_CENTS),
        (OTHER_BANK_FEE_KEYS.0, DEFAULT_FEE_BP),
        (OTHER_BANK_FEE_KEYS.1, DEFAULT_FEE_MIN_CENTS),
    ] {
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value, mac) VALUES (?1, ?2, ?3)",
            params![key, value, setting_mac(key, value)?],
        )?;
    }
    for d in DENOMINATIONS {
        conn.execute(
            "INSERT OR IGNORE INTO cash_inventory (denomination, bill_count) VALUES (?1, 0)",
            params![d],
        )?;
    }
    Ok(())
}

/// One value from the `meta` table, if present.
fn meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| r.get(0)).optional()?)
}

/// Existing DB: version and key fingerprint must match.
fn check_version_and_key(conn: &Connection) -> Result<()> {
    const START_OVER: &str =
        "this database was made by a different version; delete atm.db, atm.key and atm.anchor to start over";
    // No meta table at all: not a database this version made.
    let version = meta(conn, "schema_version").map_err(|_| AtmError::NotAllowed(START_OVER))?;
    if version.as_deref() != Some(SCHEMA_VERSION) {
        return Err(AtmError::NotAllowed(START_OVER));
    }
    let expected = keys::fingerprint()?;
    if !meta(conn, "key_fingerprint")?.is_some_and(|stored| keys::same_mac(&stored, &expected)) {
        return Err(AtmError::NotAllowed("the key file does not belong to this database"));
    }
    Ok(())
}

/// Marks a database as demo data (published passwords). Sealed like
/// everything else, so the mark can't be removed by editing the file.
#[cfg(feature = "demo")]
pub(crate) fn mark_demo(conn: &Connection) -> Result<()> {
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('demo', '1')", [])?;
    Ok(())
}

/// True for a demo database (see `mark_demo`).
pub(crate) fn is_demo(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row("SELECT EXISTS (SELECT 1 FROM meta WHERE key = 'demo')", [], |r| r.get(0))?)
}

/// True once first-run setup has run. Setup writes the first log entry, so a
/// bank with any history counts as set up, even if its staff rows are gone.
pub(crate) fn is_initialized(conn: &Connection) -> Result<bool> {
    let n: i64 =
        conn.query_row("SELECT (SELECT COUNT(*) FROM staff) + (SELECT COUNT(*) FROM audit_log)", [], |r| {
            r.get(0)
        })?;
    Ok(n > 0)
}

/// Bank-wide daily limits a Teller Admin can set.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Limit {
    Withdrawal,
    Deposit,
    Transfer,
}

impl Limit {
    pub const ALL: [Limit; 3] = [Limit::Withdrawal, Limit::Deposit, Limit::Transfer];

    /// The settings key that stores this limit.
    fn key(self) -> &'static str {
        match self {
            Limit::Withdrawal => "daily_withdrawal_limit_cents",
            Limit::Deposit => "daily_deposit_limit_cents",
            Limit::Transfer => "daily_transfer_limit_cents",
        }
    }

    /// The limit's name for messages.
    pub fn label(self) -> &'static str {
        match self {
            Limit::Withdrawal => "withdrawal",
            Limit::Deposit => "deposit",
            Limit::Transfer => "transfer",
        }
    }

    /// The log action for a teller approving more than this limit today.
    pub(crate) fn raised_action(self) -> crate::audit::Action {
        match self {
            Limit::Withdrawal => crate::audit::Action::WithdrawalLimitRaised,
            Limit::Deposit => crate::audit::Action::DepositLimitRaised,
            Limit::Transfer => crate::audit::Action::TransferLimitRaised,
        }
    }

    /// A new bank's limit.
    pub fn default_value(self) -> Cents {
        match self {
            Limit::Withdrawal => Cents::from_dollars(1_000),
            Limit::Deposit => Cents::from_dollars(10_000),
            Limit::Transfer => Cents::from_dollars(5_000),
        }
    }

    /// Highest a teller may set this limit: the default plus one day's
    /// largest raise ($5,000 / $50,000 / $25,000). Stops one teller from
    /// switching a limit off with a huge number (STRIDE: Elevation of Privilege).
    pub fn ceiling(self) -> Cents {
        Cents::new(self.default_value().as_i64() + self.max_raise().as_i64()).unwrap_or(Cents::ZERO)
    }

    /// Most a teller may approve above this limit, per account per day.
    pub fn max_raise(self) -> Cents {
        match self {
            Limit::Withdrawal => Cents::from_dollars(4_000), // up to $5,000 cash that day
            Limit::Deposit => Cents::from_dollars(40_000),
            Limit::Transfer => Cents::from_dollars(20_000),
        }
    }
}

/// The MAC a setting row must carry for this key and value.
fn setting_mac(key: &str, value: i64) -> Result<String> {
    keys::record_mac(&["setting", key, &value.to_string()])
}

/// A bank setting, MAC-checked. Fails closed: missing or edited is an error.
/// STRIDE (Tampering): raising a limit by editing the DB file doesn't work.
pub(crate) fn get_setting(conn: &Connection, key: &str) -> Result<i64> {
    let row: Option<(i64, String)> = conn
        .query_row("SELECT value, mac FROM settings WHERE key = ?1", params![key], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    let (value, mac) = row.ok_or_else(|| AtmError::Internal("setting missing".into()))?;
    if !keys::same_mac(&mac, &setting_mac(key, value)?) {
        return Err(AtmError::RecordTampered("bank settings"));
    }
    Ok(value)
}

/// Only admin functions call this (they hold the AdminSession and log the change).
pub(crate) fn put_setting(conn: &Connection, key: &str, value: i64) -> Result<()> {
    conn.execute(
        "UPDATE settings SET value = ?2, mac = ?3 WHERE key = ?1",
        params![key, value, setting_mac(key, value)?],
    )?;
    Ok(())
}

/// Every setting row, MAC-checked (part of the integrity check). Returns the count.
pub(crate) fn verify_settings(conn: &Connection) -> Result<i64> {
    let mut stmt = conn.prepare("SELECT key FROM settings ORDER BY key")?;
    let keys: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    for key in &keys {
        get_setting(conn, key)?;
    }
    Ok(keys.len() as i64)
}

/// Current bank-wide limit.
pub(crate) fn get_limit(conn: &Connection, limit: Limit) -> Result<Cents> {
    Cents::new(get_setting(conn, limit.key())?)
}

/// Only `admin::set_limit` calls this (it holds the AdminSession).
pub(crate) fn set_limit(conn: &Connection, limit: Limit, value: Cents) -> Result<()> {
    put_setting(conn, limit.key(), value.as_i64())
}

/// The two kinds of 10-digit number. Kept apart in lookups and encryption.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Number {
    Card,
    Account,
}

impl Number {
    /// Lookup-hash label, so card and account lookups never collide.
    fn label(self) -> &'static str {
        match self {
            Number::Card => "card",
            Number::Account => "account",
        }
    }
    /// Column name bound into the encryption, so numbers can't move between tables.
    fn column(self) -> &'static str {
        match self {
            Number::Card => "cards.number",
            Number::Account => "accounts.number",
        }
    }
}

/// Keyed lookup value for a number: what the DB stores and searches by.
pub(crate) fn lookup(kind: Number, number: &str) -> Result<String> {
    keys::lookup_hash(kind.label(), number)
}

/// A new number as stored: (lookup, encrypted number, last 4 digits).
pub(crate) fn seal_number(kind: Number, number: &str) -> Result<(String, Vec<u8>, String)> {
    let found_by = lookup(kind, number)?;
    let sealed = keys::seal(kind.column(), &found_by, number)?;
    Ok((found_by, sealed, last4(number).to_string()))
}

/// Decrypt a stored number. Bound to its own lookup value, so copying one
/// row's encrypted number onto another row is detected.
pub(crate) fn open_number(kind: Number, found_by: &str, sealed: &[u8]) -> Result<String> {
    keys::unseal(kind.column(), found_by, sealed)
}

/// Last 4 characters (the part that may be shown).
pub(crate) fn last4(number: &str) -> &str {
    &number[number.len().saturating_sub(4)..]
}

/// How logs name a card: its row id plus last 4 digits, never the number.
pub(crate) fn card_ref(card_id: i64, last4: &str) -> String {
    format!("card {card_id} ending {last4}")
}

/// The log's actor name for a customer card ("customer:card 7 ending 1234").
pub(crate) fn customer_actor(card_id: i64, last4: &str) -> String {
    format!("customer:{}", card_ref(card_id, last4))
}

/// Look up an OPEN account by its number. Same error for "bad format", "missing" and "closed".
pub(crate) fn account_id(conn: &Connection, account_number: &str) -> Result<i64> {
    crate::input::validate_number10(account_number).map_err(|_| AtmError::NotFound("Account"))?;
    conn.query_row(
        "SELECT id FROM accounts WHERE account_lookup = ?1 AND closed = 0",
        params![lookup(Number::Account, account_number)?],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(AtmError::NotFound("Account"))
}

/// A card holder's name, decrypted. `card_lookup` is the card row's lookup value.
pub(crate) fn holder_name(card_lookup: &str, name_enc: &[u8]) -> Result<String> {
    keys::unseal("cards.name", card_lookup, name_enc)
}

/// A card holder's date of birth, decrypted.
pub(crate) fn holder_dob(card_lookup: &str, dob_enc: &[u8]) -> Result<chrono::NaiveDate> {
    let text = keys::unseal("cards.dob", card_lookup, dob_enc)?;
    chrono::NaiveDate::parse_from_str(&text, "%Y-%m-%d")
        .map_err(|_| AtmError::Internal("bad stored DOB".into()))
}

/// Encrypt name + DOB for a new card row.
pub(crate) fn seal_holder(
    card_lookup: &str,
    name: &str,
    dob: chrono::NaiveDate,
) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((
        keys::seal("cards.name", card_lookup, name)?,
        keys::seal("cards.dob", card_lookup, &dob.to_string())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_pragmas_are_on() {
        let conn = open_in_memory().unwrap();
        let get = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(get("PRAGMA foreign_keys"), 1);
        assert_eq!(get("PRAGMA trusted_schema"), 0);
        assert_eq!(get("PRAGMA secure_delete"), 1);
        assert!(conn.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE).unwrap());
    }

    #[test]
    fn strict_tables_refuse_values_of_the_wrong_type() {
        let conn = open_in_memory().unwrap();
        for sql in [
            "UPDATE cash_inventory SET bill_count = 'lots' WHERE denomination = 20",
            "UPDATE cash_inventory SET bill_count = 2.5 WHERE denomination = 20",
            "UPDATE settings SET value = x'00' WHERE key = 'daily_withdrawal_limit_cents'",
        ] {
            assert!(conn.execute_batch(sql).is_err(), "{sql}");
        }
        let strict: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_list WHERE schema = 'main' AND strict = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(strict, 11);
    }

    #[test]
    fn an_edited_setting_is_detected() {
        let conn = open_in_memory().unwrap();
        assert_eq!(verify_settings(&conn).unwrap(), 7);
        conn.execute("UPDATE settings SET value = 99999999 WHERE key = 'daily_withdrawal_limit_cents'", [])
            .unwrap();
        assert!(matches!(get_limit(&conn, Limit::Withdrawal), Err(AtmError::RecordTampered(_))));
        assert!(matches!(verify_settings(&conn), Err(AtmError::RecordTampered(_))));
    }

    #[test]
    fn a_wrong_key_or_version_is_refused_with_a_clear_error() {
        let conn = open_in_memory().unwrap();
        assert!(check_version_and_key(&conn).is_ok());
        conn.execute("UPDATE meta SET value = 'deadbeef' WHERE key = 'key_fingerprint'", []).unwrap();
        assert!(matches!(check_version_and_key(&conn), Err(AtmError::NotAllowed(_))));
        conn.execute("UPDATE meta SET value = '5' WHERE key = 'schema_version'", []).unwrap();
        assert!(matches!(check_version_and_key(&conn), Err(AtmError::NotAllowed(_))));
        // A file that isn't one of ours at all.
        assert!(check_version_and_key(&Connection::open_in_memory().unwrap()).is_err());
    }
}
