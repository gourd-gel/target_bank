//! Logins, lockout, idle timeout, and the session types.
//!
//! STRIDE (Elevation of Privilege): a session is a *value*. Every privileged
//! function demands one: `customer::withdraw` needs `&CustomerSession`,
//! `admin::unlock` needs `&AdminSession`, `cash::restock` needs
//! `&HandlerSession`. Fields are private, so the only way to get one is a
//! successful `login_*` here. The compiler, not an `if`, blocks a customer
//! from reaching admin code.

use crate::audit::{self, Action, Entry};
use crate::db::{self, Number};
use crate::error::{AtmError, Result};
use crate::{Atm, input, keys};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::cell::Cell;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Spec: 3 consecutive failed PINs lock the card.
pub const MAX_PIN_ATTEMPTS: i64 = 3;
/// Staff: after 3 failures each further failure pauses that login, starting at
/// this many seconds and doubling (locking the only admin would be a DoS).
pub const STAFF_COOLDOWN_SECS: i64 = 60;
/// Longest staff pause: 15 minutes.
pub const STAFF_MAX_COOLDOWN_SECS: i64 = 900;
/// Sessions end after this much inactivity (walk-away protection).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Unknown transfer destinations allowed per session before it is ended.
const MAX_MISSED_LOOKUPS: u8 = 3;

// ---------------------------------------------------------------------------
// Idle timer shared by all session types
// ---------------------------------------------------------------------------

pub(crate) struct IdleClock {
    last_active: Cell<Instant>,
    ended: Cell<bool>,
}

impl IdleClock {
    /// A fresh clock, active from now.
    fn new() -> Self {
        IdleClock { last_active: Cell::new(Instant::now()), ended: Cell::new(false) }
    }

    /// Ok and reset the timer if still live; once expired, stays expired.
    fn touch(&self) -> Result<()> {
        if self.ended.get() || self.last_active.get().elapsed() >= IDLE_TIMEOUT {
            self.ended.set(true);
            return Err(AtmError::SessionExpired);
        }
        self.last_active.set(Instant::now());
        Ok(())
    }

    /// True if ended or idle too long; does not reset the timer.
    fn is_expired(&self) -> bool {
        self.ended.get() || self.last_active.get().elapsed() >= IDLE_TIMEOUT
    }
}

// ---------------------------------------------------------------------------
// Session types. Private fields: only this file can build them.
// Not Clone: a session can't be copied and kept after logout.
// ---------------------------------------------------------------------------

/// Which kind of holder a card belongs to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HolderRole {
    Owner,
    Joint,
    Minor,
    /// A card from another bank: withdraw and balance only.
    Guest,
}

impl HolderRole {
    /// The role stored in the database; anything unknown is an error.
    fn from_db(s: &str) -> Result<HolderRole> {
        match s {
            "owner" => Ok(HolderRole::Owner),
            "joint" => Ok(HolderRole::Joint),
            "minor" => Ok(HolderRole::Minor),
            "guest" => Ok(HolderRole::Guest),
            _ => Err(AtmError::Internal("bad holder role".into())),
        }
    }
}

pub struct CustomerSession {
    bank: u64,
    card_id: i64,
    card_number: String,
    account_id: i64,
    account_number: String,
    role: HolderRole,
    clock: IdleClock,
    missed_lookups: Cell<u8>,
}

impl CustomerSession {
    /// For a GUI timer: true once the session should be closed.
    pub fn is_expired(&self) -> bool {
        self.clock.is_expired()
    }
    /// Log out: the session is useless from here on.
    pub fn end(&self) {
        self.clock.ended.set(true);
    }
    /// The card's row id.
    pub fn card_id(&self) -> i64 {
        self.card_id
    }
    /// The card number used to sign in.
    pub fn card_number(&self) -> &str {
        &self.card_number
    }
    /// The account's row id.
    pub fn account_id(&self) -> i64 {
        self.account_id
    }
    /// The account number this card is on.
    pub fn account_number(&self) -> &str {
        &self.account_number
    }
    /// This card's holder role.
    pub fn role(&self) -> HolderRole {
        self.role
    }
    /// How this person appears in the audit log: card row id + last 4 digits
    /// (joint holders stay distinct; the full card number is never logged).
    pub fn actor(&self) -> String {
        db::customer_actor(self.card_id, db::last4(&self.card_number))
    }
    /// Count an unknown transfer destination; ends the session after too many
    /// (stops account-number hunting). Returns true if the session was ended.
    pub(crate) fn note_missed_lookup(&self) -> bool {
        let n = self.missed_lookups.get().saturating_add(1);
        self.missed_lookups.set(n);
        if n >= MAX_MISSED_LOOKUPS {
            self.end();
            return true;
        }
        false
    }
    /// Tests: pretend the last activity was `secs` seconds ago.
    #[cfg(test)]
    pub(crate) fn backdate(&self, secs: u64) {
        self.clock.last_active.set(Instant::now() - Duration::from_secs(secs));
    }
}

pub struct AdminSession {
    bank: u64,
    username: String,
    clock: IdleClock,
    integrity_problem: Option<String>,
}

impl AdminSession {
    /// What the automatic integrity check at sign-in found wrong (None = all good).
    /// When set, the ATM was taken out of service (see service.rs).
    pub fn integrity_problem(&self) -> Option<&str> {
        self.integrity_problem.as_deref()
    }
    /// For a GUI timer: true once the session should be closed.
    pub fn is_expired(&self) -> bool {
        self.clock.is_expired()
    }
    /// Log out: the session is useless from here on.
    pub fn end(&self) {
        self.clock.ended.set(true);
    }
    /// How this teller appears in the audit log.
    pub fn actor(&self) -> String {
        format!("admin:{}", self.username)
    }
}

pub struct HandlerSession {
    bank: u64,
    username: String,
    clock: IdleClock,
}

impl HandlerSession {
    /// For a GUI timer: true once the session should be closed.
    pub fn is_expired(&self) -> bool {
        self.clock.is_expired()
    }
    /// Log out: the session is useless from here on.
    pub fn end(&self) {
        self.clock.ended.set(true);
    }
    /// How this Cash Handler appears in the audit log.
    pub fn actor(&self) -> String {
        format!("handler:{}", self.username)
    }
}

// ---------------------------------------------------------------------------
// The session gate: every operation's first line is `atm.admit(session)?`.
// ---------------------------------------------------------------------------

/// What every session type has: the bank that issued it, an idle clock, and
/// a check that the database still allows it.
pub(crate) trait Session {
    /// Id of the `Atm` that issued this session.
    fn bank(&self) -> u64;
    /// This session's idle clock.
    fn clock(&self) -> &IdleClock;
    /// Still allowed right now? (card not locked, account open and not frozen
    /// by the bank, staff login still there)
    fn still_allowed(&self, conn: &Connection) -> Result<bool>;
    /// Customers and Cash Handlers stop when the ATM is out of service; only
    /// a Teller Admin keeps working (to review and resume).
    fn stops_when_halted(&self) -> bool {
        false
    }
}

impl Session for CustomerSession {
    /// Id of the issuing `Atm`.
    fn bank(&self) -> u64 {
        self.bank
    }
    /// This session's idle clock.
    fn clock(&self) -> &IdleClock {
        &self.clock
    }
    /// Customers stop when the ATM is out of service.
    fn stops_when_halted(&self) -> bool {
        true
    }
    /// Card unlocked, still on this account, account open and not frozen by the bank.
    fn still_allowed(&self, conn: &Connection) -> Result<bool> {
        Ok(conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM cards c JOIN accounts a ON a.id = c.account_id
                            WHERE c.id = ?1 AND c.card_lookup = ?2 AND c.account_id = ?3
                              AND c.locked = 0 AND a.closed = 0 AND a.frozen = 0)",
            params![self.card_id, db::lookup(Number::Card, &self.card_number)?, self.account_id],
            |r| r.get(0),
        )?)
    }
}

impl Session for AdminSession {
    /// Id of the issuing `Atm`.
    fn bank(&self) -> u64 {
        self.bank
    }
    /// This session's idle clock.
    fn clock(&self) -> &IdleClock {
        &self.clock
    }
    /// The admin login still exists.
    fn still_allowed(&self, conn: &Connection) -> Result<bool> {
        still_staff(conn, &self.username, "admin")
    }
}

impl Session for HandlerSession {
    /// Id of the issuing `Atm`.
    fn bank(&self) -> u64 {
        self.bank
    }
    /// This session's idle clock.
    fn clock(&self) -> &IdleClock {
        &self.clock
    }
    /// The handler login still exists.
    fn still_allowed(&self, conn: &Connection) -> Result<bool> {
        still_staff(conn, &self.username, "handler")
    }
    /// Cash Handlers stop when the ATM is out of service.
    fn stops_when_halted(&self) -> bool {
        true
    }
}

/// True if a staff login with this username and role still exists.
fn still_staff(conn: &Connection, username: &str, role: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM staff WHERE username = ?1 AND role = ?2)",
        params![username, role],
        |r| r.get(0),
    )?)
}

impl Atm {
    /// The gate every operation passes first. Refuses (and ends) a session that is idle, logged
    /// out, from another `Atm`, or whose card was locked or account closed since login.
    /// STRIDE (Spoofing / Elevation of Privilege): stops an "admin" session made on a throwaway
    /// database being used here, and a session outliving a lock or closure.
    pub(crate) fn admit(&self, session: &impl Session) -> Result<()> {
        if session.bank() != self.id || !session.still_allowed(&self.conn)? {
            session.clock().ended.set(true);
            return Err(AtmError::SessionExpired);
        }
        if session.stops_when_halted() && crate::service::halted(&self.conn)?.is_some() {
            session.clock().ended.set(true);
            return Err(AtmError::OutOfService);
        }
        session.clock().touch()
    }

    /// Start a write for this session: `begin`, then the session checks again
    /// inside the write lock. A halt, card lock or closure that another
    /// process committed while this one waited for the lock still stops it.
    pub(crate) fn begin_for(&mut self, session: &impl Session) -> Result<crate::Tx<'_>> {
        let tx = self.begin()?;
        let refused = if !session.still_allowed(&tx)? {
            Some(AtmError::SessionExpired)
        } else if session.stops_when_halted() && crate::service::halted(&tx)?.is_some() {
            Some(AtmError::OutOfService)
        } else {
            None
        };
        match refused {
            Some(e) => {
                session.clock().ended.set(true);
                Err(e)
            }
            None => Ok(tx),
        }
    }
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Who a PIN belongs to: this card (by its lookup value), on this account, in this role.
pub(crate) fn card_identity(card_lookup: &str, account_id: i64, role: &str) -> String {
    format!("card\0{card_lookup}\0{account_id}\0{role}")
}

/// Who a staff password belongs to: this username, in this role.
fn staff_identity(username: &str, role: &str) -> String {
    format!("staff\0{username}\0{role}")
}

/// Argon2id keyed for one identity (see `keys::credential_key`).
fn hasher(key: &[u8]) -> Result<Argon2<'_>> {
    Argon2::new_with_secret(key, Algorithm::Argon2id, Version::V0x13, Params::default())
        .map_err(|_| AtmError::Internal("argon2 setup failed".into()))
}

/// Hash a PIN/password: Argon2id + random salt + a key from `atm.key` for this one identity.
/// STRIDE (Spoofing / Info Disclosure): the PIN is never stored; a stolen DB can't be guessed
/// offline without `atm.key`, and a hash moved to another card, account or role fails.
pub(crate) fn hash_secret(secret: &str, identity: &str) -> Result<String> {
    let key = keys::credential_key(identity)?;
    hasher(&*key)?
        .hash_password(secret.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|_| AtmError::Internal("hashing failed".into()))
}

/// PIN check for other modules (change PIN). Same constant-time verify.
pub(crate) fn check_pin(pin: &str, stored_hash: &str, identity: &str) -> bool {
    verify_secret(pin, stored_hash, identity)
}

/// Constant-time check (inside argon2). A malformed stored hash is just "no".
fn verify_secret(secret: &str, stored_hash: &str, identity: &str) -> bool {
    let Ok(key) = keys::credential_key(identity) else { return false };
    let Ok(argon) = hasher(&*key) else { return false };
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => argon.verify_password(secret.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Do a real-cost check for unknown users, so timing doesn't reveal which
/// card numbers / usernames exist (STRIDE: Info Disclosure). It checks a
/// fixed string, never the caller's input, so a huge "password" can't keep
/// the machine busy (STRIDE: Denial of Service).
fn burn_time_like_a_real_check() {
    let _ = verify_secret("still not a real credential", dummy_hash(), "nobody");
}

/// The stand-in hash those checks run against, made once.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_secret("not a real credential", "nobody").unwrap_or_default())
}

/// Makes the stand-in hash when the bank opens. Otherwise the first failed
/// login after a start would also pay for making it (two Argon2 runs, not
/// one), and that slower answer would show the card number doesn't exist.
pub(crate) fn warm_up() {
    dummy_hash();
}

// ---------------------------------------------------------------------------
// Customer login: card number + PIN
// ---------------------------------------------------------------------------

/// card id, account id, account lookup, encrypted account number, holder role,
/// PIN hash, failures, locked, closed, frozen by the bank.
type CardRow = (i64, i64, String, Vec<u8>, String, String, i64, bool, bool, bool);

/// Log a customer in. The card number stands in for the physical card
/// (something you have); the PIN is something you know.
pub fn login_customer(atm: &mut Atm, card_number: &str, pin: &str) -> Result<CustomerSession> {
    // Malformed input looks exactly like wrong credentials.
    if input::validate_number10(card_number).is_err() || input::validate_pin(pin).is_err() {
        burn_time_like_a_real_check();
        return Err(AtmError::AuthFailed);
    }

    // The DB only holds a keyed lookup of each card number, never the number.
    let found_by = db::lookup(Number::Card, card_number)?;
    // Write lock up front: two racing logins can't both read "2 failures".
    let tx = atm.begin()?;
    // Out of service: refused before any PIN is checked or counted.
    crate::service::refuse_if_halted(&tx)?;
    let found: Option<CardRow> = tx
        .query_row(
            "SELECT c.id, c.account_id, a.account_lookup, a.account_enc, c.holder_role, c.pin_hash,
                    c.failed_attempts, c.locked, a.closed, a.frozen
             FROM cards c JOIN accounts a ON a.id = c.account_id
             WHERE c.card_lookup = ?1",
            params![found_by],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            },
        )
        .optional()?;

    let Some((
        card_id,
        account_id,
        account_lookup,
        account_enc,
        role,
        pin_hash,
        failed,
        locked,
        closed,
        frozen,
    )) = found
    else {
        burn_time_like_a_real_check();
        log(&tx, "anonymous", Action::LoginFailed, None, "unknown card number")?;
        tx.commit()?;
        return Err(like_a_real_card(atm, found_by));
    };
    let actor = db::customer_actor(card_id, db::last4(card_number));

    // Closed account: looks exactly like a wrong PIN from outside.
    if closed {
        burn_time_like_a_real_check();
        log(&tx, &actor, Action::LoginFailed, Some(account_id), "account is closed")?;
        tx.commit()?;
        return Err(like_a_real_card(atm, found_by));
    }

    // Locked: don't even check the PIN, or guessing could continue. Same
    // wait as a check, so timing can't tell a locked card from an unknown one.
    if locked {
        burn_time_like_a_real_check();
        log(&tx, &actor, Action::LoginFailed, Some(account_id), "card is locked")?;
        tx.commit()?;
        return Err(AtmError::CardLocked);
    }

    if verify_secret(pin, &pin_hash, &card_identity(&found_by, account_id, &role)) {
        // "Consecutive": a success resets the count.
        tx.execute("UPDATE cards SET failed_attempts = 0 WHERE id = ?1", params![card_id])?;
        // Frozen by the bank (e.g. a reported stolen card): no card is accepted
        // until a teller lifts it. Said only after the right PIN, so it shows
        // nothing to a guesser.
        if frozen {
            log(&tx, &actor, Action::LoginFailed, Some(account_id), "account is frozen by the bank")?;
            tx.commit()?;
            return Err(AtmError::FrozenByBank);
        }
        log(&tx, &actor, Action::LoginOk, Some(account_id), "")?;
        tx.commit()?;
        return Ok(CustomerSession {
            bank: atm.id,
            card_id,
            card_number: card_number.to_string(),
            account_id,
            account_number: db::open_number(Number::Account, &account_lookup, &account_enc)?,
            role: HolderRole::from_db(&role)?,
            clock: IdleClock::new(),
            missed_lookups: Cell::new(0),
        });
    }

    // Wrong PIN. Counter is in the DB, so restarting the program doesn't reset it.
    let attempts = failed + 1;
    let now_locked = attempts >= MAX_PIN_ATTEMPTS;
    tx.execute(
        "UPDATE cards SET failed_attempts = ?2, locked = ?3 WHERE id = ?1",
        params![card_id, attempts, now_locked],
    )?;
    log(&tx, &actor, Action::LoginFailed, Some(account_id), "wrong PIN")?;
    if now_locked {
        log(&tx, "system", Action::CardLocked, Some(account_id), "3 consecutive failed PINs")?;
    }
    // Commit BEFORE returning the error; dropping tx would roll back the counter.
    tx.commit()?;
    Err(if now_locked { AtmError::CardLocked } else { AtmError::AuthFailed })
}

// ---------------------------------------------------------------------------
// A holder at the teller's counter confirms a change with card + PIN
// ---------------------------------------------------------------------------

/// An existing customer at the teller's counter: their card number, and the
/// PIN they type on the PIN pad. Needed to add a joint holder, open a youth
/// account, or add a guardian, so one teller can't do these alone.
#[derive(Clone, Copy)]
pub struct CardAndPin<'a> {
    pub card_number: &'a str,
    pub pin: &'a str,
}

/// Who confirmed at the counter.
pub(crate) struct Confirmed {
    pub card_id: i64,
    pub account_id: i64,
    pub role: String,
}

/// Check a holder's card and PIN at the counter, in the core. STRIDE (Spoofing / Elevation of
/// Privilege): a teller alone can't add themselves to an account. A wrong PIN is logged and
/// counts toward the 3-strike lock. Outer error: database problem; inner error: refused (the
/// caller commits first so the failed try counts, see `admin::confirmed`).
pub(crate) fn confirm_at_counter(
    tx: &Connection,
    teller: &str,
    who: CardAndPin,
) -> Result<std::result::Result<Confirmed, AtmError>> {
    if input::validate_number10(who.card_number).is_err() || input::validate_pin(who.pin).is_err() {
        burn_time_like_a_real_check();
        return Ok(Err(AtmError::AuthFailed));
    }
    let found_by = db::lookup(Number::Card, who.card_number)?;
    type Row = (i64, i64, String, String, i64, bool, bool, bool);
    let row: Option<Row> = tx
        .query_row(
            "SELECT c.id, c.account_id, c.holder_role, c.pin_hash, c.failed_attempts, c.locked, a.closed, a.frozen
             FROM cards c JOIN accounts a ON a.id = c.account_id WHERE c.card_lookup = ?1",
            params![found_by],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
        )
        .optional()?;
    let Some((card_id, account_id, role, pin_hash, failed, locked, closed, frozen)) = row else {
        burn_time_like_a_real_check();
        return Ok(Err(AtmError::AuthFailed));
    };
    if closed {
        burn_time_like_a_real_check();
        return Ok(Err(AtmError::AuthFailed));
    }
    if locked {
        return Ok(Err(AtmError::CardLocked));
    }
    if verify_secret(who.pin, &pin_hash, &card_identity(&found_by, account_id, &role)) {
        tx.execute("UPDATE cards SET failed_attempts = 0 WHERE id = ?1", params![card_id])?;
        // A card the bank froze can't vouch for anything at the counter either.
        if frozen {
            return Ok(Err(AtmError::FrozenByBank));
        }
        return Ok(Ok(Confirmed { card_id, account_id, role }));
    }
    let attempts = failed + 1;
    let now_locked = attempts >= MAX_PIN_ATTEMPTS;
    tx.execute(
        "UPDATE cards SET failed_attempts = ?2, locked = ?3 WHERE id = ?1",
        params![card_id, attempts, now_locked],
    )?;
    let actor = db::customer_actor(card_id, db::last4(who.card_number));
    log(tx, &actor, Action::LoginFailed, Some(account_id), &format!("wrong PIN at the counter ({teller})"))?;
    if now_locked {
        log(tx, "system", Action::CardLocked, Some(account_id), "3 consecutive failed PINs")?;
    }
    Ok(Err(if now_locked { AtmError::CardLocked } else { AtmError::AuthFailed }))
}

/// The answer for a card number that isn't a live card: the same as a real
/// card's (wrong PIN twice, then "card locked"), so the messages don't show
/// which numbers exist (STRIDE: Info Disclosure). Counted in memory only.
fn like_a_real_card(atm: &mut Atm, found_by: String) -> AtmError {
    if atm.unknown_cards.len() >= 10_000 {
        atm.unknown_cards.clear(); // bounded memory (STRIDE: Denial of Service)
    }
    let tries = atm.unknown_cards.entry(found_by).or_insert(0);
    *tries += 1;
    if *tries >= MAX_PIN_ATTEMPTS { AtmError::CardLocked } else { AtmError::AuthFailed }
}

/// Append one login or session event to the audit log.
fn log(conn: &Connection, actor: &str, action: Action, account: Option<i64>, detail: &str) -> Result<()> {
    audit::append(
        conn,
        &Entry { actor, action, account_id: account, counterparty_id: None, amount: None, usd: None, detail },
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Staff login: username + password, role fixed by the caller
// ---------------------------------------------------------------------------

/// Shared by admin and handler login. The SQL matches on `required_role`, so a
/// handler's password never opens the admin interface (and vice versa).
fn login_staff(atm: &mut Atm, username: &str, password: &str, required_role: &str) -> Result<String> {
    let well_formed =
        input::validate_username(username).is_ok() && input::validate_password(password).is_ok();
    let now = Utc::now();
    let now_s = now.to_rfc3339_opts(SecondsFormat::Secs, true);

    let tx = atm.begin()?;
    // Out of service: only a Teller Admin may sign in (to review and resume).
    if required_role != "admin" {
        crate::service::refuse_if_halted(&tx)?;
    }
    let stored: Option<(i64, String, i64, Option<String>)> = if well_formed {
        tx.query_row(
            "SELECT id, password_hash, failed_attempts, cooldown_until
             FROM staff WHERE username = ?1 AND role = ?2",
            params![username, required_role],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?
    } else {
        None
    };
    // Attacker-controlled text stays out of the log unless it passed validation.
    let actor = if well_formed { format!("{required_role}:{username}") } else { "anonymous".into() };

    let Some((id, hash, failed, cooldown)) = stored else {
        burn_time_like_a_real_check();
        log(&tx, &actor, Action::LoginFailed, None, "staff login rejected")?;
        tx.commit()?;
        return Err(AtmError::AuthFailed);
    };

    // During cooldown: refuse without checking the password (no guessing allowed).
    if cooldown.as_deref().is_some_and(|until| now_s.as_str() < until) {
        burn_time_like_a_real_check();
        log(&tx, &actor, Action::LoginFailed, None, "staff login during cooldown")?;
        tx.commit()?;
        return Err(AtmError::AuthFailed);
    }

    if verify_secret(password, &hash, &staff_identity(username, required_role)) {
        tx.execute("UPDATE staff SET failed_attempts = 0, cooldown_until = NULL WHERE id = ?1", params![id])?;
        log(&tx, &actor, Action::LoginOk, None, "")?;
        tx.commit()?;
        return Ok(username.to_string());
    }

    let attempts = failed + 1;
    if attempts >= MAX_PIN_ATTEMPTS {
        // 60s, 120s, 240s ... up to 15 min. The count only resets on a success,
        // so a guesser gets slower and slower (about 100 guesses a day at most).
        let secs = staff_cooldown_secs(attempts);
        let until = (now + ChronoDuration::seconds(secs)).to_rfc3339_opts(SecondsFormat::Secs, true);
        tx.execute(
            "UPDATE staff SET failed_attempts = ?2, cooldown_until = ?3 WHERE id = ?1",
            params![id, attempts, until],
        )?;
        log(&tx, &actor, Action::LoginFailed, None, &format!("{attempts} failures in a row: {secs}s pause"))?;
    } else {
        tx.execute("UPDATE staff SET failed_attempts = ?2 WHERE id = ?1", params![id, attempts])?;
        log(&tx, &actor, Action::LoginFailed, None, "wrong password")?;
    }
    tx.commit()?;
    Err(AtmError::AuthFailed)
}

/// Pause after `attempts` consecutive staff failures (3 or more).
fn staff_cooldown_secs(attempts: i64) -> i64 {
    let doublings = (attempts - MAX_PIN_ATTEMPTS).clamp(0, 10) as u32;
    (STAFF_COOLDOWN_SECS << doublings).min(STAFF_MAX_COOLDOWN_SECS)
}

/// Teller Admin sign-in. Every sign-in also runs the full integrity check
/// (see service.rs): if it fails, the ATM goes out of service and the session
/// carries what failed, for the red banner.
pub fn login_admin(atm: &mut Atm, username: &str, password: &str) -> Result<AdminSession> {
    let username = login_staff(atm, username, password, "admin")?;
    let integrity_problem = crate::service::check_at_sign_in(atm, &format!("admin:{username}"))?;
    Ok(AdminSession { bank: atm.id, username, clock: IdleClock::new(), integrity_problem })
}

/// Cash Handler sign-in.
pub fn login_handler(atm: &mut Atm, username: &str, password: &str) -> Result<HandlerSession> {
    login_staff(atm, username, password, "handler").map(|username| HandlerSession {
        bank: atm.id,
        username,
        clock: IdleClock::new(),
    })
}

/// Staff change their own password (current one required).
/// A wrong current password counts as a failed login (same pause rules).
fn change_staff_password(atm: &mut Atm, username: &str, role: &str, current: &str, new: &str) -> Result<()> {
    input::validate_password(new)?;
    if current == new {
        return Err(AtmError::InvalidInput("the new password must be different"));
    }
    login_staff(atm, username, current, role)?; // logs the check; counts failures
    let hash = hash_secret(new, &staff_identity(username, role))?;
    let tx = atm.begin()?;
    tx.execute(
        "UPDATE staff SET password_hash = ?3 WHERE username = ?1 AND role = ?2",
        params![username, role, hash],
    )?;
    log(&tx, &format!("{role}:{username}"), Action::PasswordChanged, None, "")?;
    tx.commit()?;
    Ok(())
}

/// Teller Admin changes their own password.
pub fn change_admin_password(atm: &mut Atm, session: &AdminSession, current: &str, new: &str) -> Result<()> {
    atm.admit(session)?;
    change_staff_password(atm, &session.username, "admin", current, new)
}

/// Cash Handler changes their own password.
pub fn change_handler_password(
    atm: &mut Atm,
    session: &HandlerSession,
    current: &str,
    new: &str,
) -> Result<()> {
    atm.admit(session)?;
    change_staff_password(atm, &session.username, "handler", current, new)
}

// ---------------------------------------------------------------------------
// Logout (audited). Takes the session by value: it can't be used afterwards.
// ---------------------------------------------------------------------------

/// Logs the end of a session. A session from another `Atm` writes nothing here.
fn log_logout(atm: &mut Atm, session: &impl Session, actor: &str, account: Option<i64>) -> Result<()> {
    let expired = session.clock().is_expired();
    session.clock().ended.set(true);
    if session.bank() != atm.id {
        return Err(AtmError::SessionExpired);
    }
    let detail = if expired { "idle timeout" } else { "logged out" };
    let tx = atm.begin()?;
    log(&tx, actor, Action::SessionEnded, account, detail)?;
    tx.commit()
}

/// Log a customer out (logged).
pub fn logout_customer(atm: &mut Atm, session: CustomerSession) -> Result<()> {
    log_logout(atm, &session, &session.actor(), Some(session.account_id))
}

/// Log a Teller Admin out (logged).
pub fn logout_admin(atm: &mut Atm, session: AdminSession) -> Result<()> {
    log_logout(atm, &session, &session.actor(), None)
}

/// Log a Cash Handler out (logged).
pub fn logout_handler(atm: &mut Atm, session: HandlerSession) -> Result<()> {
    log_logout(atm, &session, &session.actor(), None)
}

// ---------------------------------------------------------------------------
// First-run setup
// ---------------------------------------------------------------------------

/// Create the first Teller Admin and Cash Handler. STRIDE (Spoofing): no default credentials.
/// STRIDE (Elevation of Privilege): only on a bank with no staff and no history, checked in the
/// same transaction, so no second admin later (emptying staff also breaks the seal).
pub fn first_run_setup(
    atm: &mut Atm,
    admin_username: &str,
    admin_password: &str,
    handler_username: &str,
    handler_password: &str,
) -> Result<()> {
    input::validate_username(admin_username)?;
    input::validate_username(handler_username)?;
    input::validate_password(admin_password)?;
    input::validate_password(handler_password)?;
    if admin_username == handler_username {
        return Err(AtmError::InvalidInput("admin and handler need different usernames"));
    }
    let admin_hash = hash_secret(admin_password, &staff_identity(admin_username, "admin"))?;
    let handler_hash = hash_secret(handler_password, &staff_identity(handler_username, "handler"))?;

    let tx = atm.begin()?;
    if db::is_initialized(&tx)? {
        return Err(AtmError::NotAllowed("this machine has already been set up"));
    }
    tx.execute(
        "INSERT INTO staff (username, role, password_hash) VALUES (?1, 'admin', ?2)",
        params![admin_username, admin_hash],
    )?;
    tx.execute(
        "INSERT INTO staff (username, role, password_hash) VALUES (?1, 'handler', ?2)",
        params![handler_username, handler_hash],
    )?;
    log(&tx, "system", Action::Setup, None, "first-run setup: staff accounts created")?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod testing {
    //! Helpers for other modules' tests.
    use super::*;

    pub const ADMIN: (&str, &str) = ("alice", "correct horse battery");
    pub const HANDLER: (&str, &str) = ("bob", "staple gun orchestra");

    pub fn setup(conn: &mut Atm) -> (AdminSession, HandlerSession) {
        first_run_setup(conn, ADMIN.0, ADMIN.1, HANDLER.0, HANDLER.1).unwrap();
        (login_admin(conn, ADMIN.0, ADMIN.1).unwrap(), login_handler(conn, HANDLER.0, HANDLER.1).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::{admin, money::Cents};

    fn new_customer(conn: &mut Atm, admin: &AdminSession, pin: &str) -> String {
        admin::create_customer(conn, admin, "Test Customer", "1990-01-01", pin, Cents::from_dollars(100))
            .unwrap()
            .card_number
    }

    #[test]
    fn right_pin_logs_in_and_wrong_pin_does_not() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let card = new_customer(&mut conn, &admin, "4821");
        assert!(login_customer(&mut conn, &card, "4821").is_ok());
        assert!(matches!(login_customer(&mut conn, &card, "0000"), Err(AtmError::AuthFailed)));
        assert!(matches!(login_customer(&mut conn, "0000000000", "4821"), Err(AtmError::AuthFailed)));
    }

    #[test]
    fn three_consecutive_failures_lock_even_against_the_right_pin() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let card = new_customer(&mut conn, &admin, "4821");
        assert!(matches!(login_customer(&mut conn, &card, "1111"), Err(AtmError::AuthFailed)));
        assert!(matches!(login_customer(&mut conn, &card, "2222"), Err(AtmError::AuthFailed)));
        assert!(matches!(login_customer(&mut conn, &card, "3333"), Err(AtmError::CardLocked)));
        assert!(matches!(login_customer(&mut conn, &card, "4821"), Err(AtmError::CardLocked)));
        admin::unlock_card(&mut conn, &admin, &card).unwrap();
        assert!(login_customer(&mut conn, &card, "4821").is_ok());
    }

    #[test]
    fn a_success_resets_the_failure_count() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let card = new_customer(&mut conn, &admin, "4821");
        for _ in 0..3 {
            assert!(login_customer(&mut conn, &card, "1111").is_err());
            assert!(login_customer(&mut conn, &card, "2222").is_err());
            assert!(login_customer(&mut conn, &card, "4821").is_ok());
        }
    }

    #[test]
    fn staff_roles_do_not_cross() {
        let mut conn = crate::Atm::in_memory().unwrap();
        setup(&mut conn);
        assert!(login_admin(&mut conn, HANDLER.0, HANDLER.1).is_err());
        assert!(login_handler(&mut conn, ADMIN.0, ADMIN.1).is_err());
    }

    #[test]
    fn staff_cooldown_after_three_failures() {
        let mut conn = crate::Atm::in_memory().unwrap();
        setup(&mut conn);
        for _ in 0..3 {
            assert!(login_admin(&mut conn, ADMIN.0, "wrong password here").is_err());
        }
        // Even the right password is refused during cooldown.
        assert!(login_admin(&mut conn, ADMIN.0, ADMIN.1).is_err());
        // The pause runs out (simulated by the bank itself, so re-sealed).
        conn.execute("UPDATE staff SET cooldown_until = '2000-01-01T00:00:00Z'", []).unwrap();
        conn.reseal();
        assert!(login_admin(&mut conn, ADMIN.0, ADMIN.1).is_ok());
    }

    #[test]
    fn staff_pauses_grow_and_are_capped() {
        assert_eq!(staff_cooldown_secs(3), 60);
        assert_eq!(staff_cooldown_secs(4), 120);
        assert_eq!(staff_cooldown_secs(6), 480);
        assert_eq!(staff_cooldown_secs(50), STAFF_MAX_COOLDOWN_SECS);
    }

    #[test]
    fn staff_can_change_their_own_password() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        assert!(
            change_admin_password(&mut conn, &admin, "wrong current pw", "a brand new password").is_err()
        );
        assert!(change_admin_password(&mut conn, &admin, ADMIN.1, "short").is_err());
        change_admin_password(&mut conn, &admin, ADMIN.1, "a brand new password").unwrap();
        assert!(login_admin(&mut conn, ADMIN.0, ADMIN.1).is_err());
        assert!(login_admin(&mut conn, ADMIN.0, "a brand new password").is_ok());
    }

    #[test]
    fn logout_is_logged_and_ends_the_session() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        logout_admin(&mut conn, admin).unwrap();
        let last: String = conn
            .query_row("SELECT action FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(last, "session_ended");
    }

    #[test]
    fn idle_and_logged_out_sessions_stop_working() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let card = new_customer(&mut conn, &admin, "4821");
        let s = login_customer(&mut conn, &card, "4821").unwrap();
        assert!(conn.admit(&s).is_ok());
        s.backdate(IDLE_TIMEOUT.as_secs() + 1);
        assert!(matches!(conn.admit(&s), Err(AtmError::SessionExpired)));
        let s2 = login_customer(&mut conn, &card, "4821").unwrap();
        s2.end();
        assert!(matches!(crate::customer::balance(&conn, &s2), Err(AtmError::SessionExpired)));
    }

    #[test]
    fn setup_cannot_be_run_twice() {
        let mut conn = crate::Atm::in_memory().unwrap();
        setup(&mut conn);
        assert!(
            first_run_setup(&mut conn, "mallory", "a long password!!", "trudy", "another long one").is_err()
        );
    }

    #[test]
    fn a_hash_only_works_for_its_own_card_and_role() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let a = new_customer(&mut conn, &admin, "4821");
        let b = new_customer(&mut conn, &admin, "5937");
        // Even if the seal were bypassed (re-sealed here), a copied hash fails.
        conn.execute(
            "UPDATE cards SET pin_hash = (SELECT pin_hash FROM cards WHERE card_lookup = ?1)
             WHERE card_lookup = ?2",
            [db::lookup(Number::Card, &a).unwrap(), db::lookup(Number::Card, &b).unwrap()],
        )
        .unwrap();
        conn.execute("UPDATE staff SET role = 'admin' WHERE username = ?1", [HANDLER.0]).unwrap();
        conn.reseal();
        assert!(matches!(login_customer(&mut conn, &b, "4821"), Err(AtmError::AuthFailed)));
        assert!(matches!(login_admin(&mut conn, HANDLER.0, HANDLER.1), Err(AtmError::AuthFailed)));
        assert!(login_customer(&mut conn, &a, "4821").is_ok());
    }

    #[test]
    fn pins_are_not_stored_in_the_clear() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let a = new_customer(&mut conn, &admin, "4821");
        let b = new_customer(&mut conn, &admin, "4821");
        let hash = |n: &str| -> String {
            let found_by = db::lookup(Number::Card, n).unwrap();
            conn.query_row("SELECT pin_hash FROM cards WHERE card_lookup = ?1", [found_by], |r| r.get(0))
                .unwrap()
        };
        assert!(hash(&a).starts_with("$argon2id$"));
        assert!(!hash(&a).contains("4821"));
        assert_ne!(hash(&a), hash(&b), "same PIN must not give the same hash");
    }
}
