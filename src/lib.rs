//! Bank of CCNY ATM: the secure core.
//!
//! The CLI (`main.rs` + `ui.rs`) and the GUI (`gui/`) both call into these
//! modules. Every rule lives here, so no front end can skip a check.
//!
//! Module map:
//!   error    - one error type; what users may see
//!   money    - `Cents` and `Denomination` (no negatives, no floats)
//!   input    - keyboard reading (CLI) + field validators (everyone)
//!   keys     - secret key file: PIN pepper, audit MAC key, field encryption, record MACs
//!   db       - SQLite schema, constraints, hardening, bank-wide limits (MAC'd)
//!   seal     - one HMAC over the whole database, checked before every operation
//!   anchor   - file next to the database: the newest seal (old copies refused)
//!   fx       - currencies: teller-set rates, fees, conversions
//!   rate_feed - daily rate feed: fetch (teller button), check, teller approves
//!   audit    - append-only, HMAC-chained log; daily totals come from it
//!   auth     - logins, lockout, idle timeout, logout, session types
//!   dispense - which bills to pay out (single or mixed)
//!   customer - customer actions        (needs CustomerSession)
//!   family   - guardian controls for youth accounts (needs CustomerSession)
//!   admin    - Teller Admin actions    (needs AdminSession)
//!   cash     - Cash Handler actions    (needs HandlerSession)
//!   review   - holds on unusual activity, released by a teller
//!   service  - out-of-service mode: integrity check at teller sign-in, halt / resume
//!   demo     - sample data for testing (only with `--features demo`)
//!
//! The compiler enforces the trust boundary. Each of these is a compile
//! error in a front end (checked by `cargo test`):
//!
//! A front end can't run its own SQL (the connection is private):
//! ```compile_fail,E0616
//! fn sql(atm: &atm::Atm) {
//!     atm.conn.execute("UPDATE accounts SET balance_cents = 1000000", []).unwrap();
//! }
//! ```
//!
//! A session can't be forged (only a successful login makes one):
//! ```compile_fail,E0451
//! fn forge() -> atm::auth::AdminSession {
//!     atm::auth::AdminSession { username: "mallory".into(), clock: todo!() }
//! }
//! ```
//!
//! A customer session can't be passed where an admin one is required:
//! ```compile_fail,E0308
//! fn escalate(a: &mut atm::Atm, me: &atm::auth::CustomerSession) {
//!     atm::admin::unlock_card(a, me, "1234567890").unwrap();
//! }
//! ```
//!
//! A session can't be used after logout:
//! ```compile_fail,E0382
//! fn reuse(a: &mut atm::Atm, s: atm::auth::CustomerSession) {
//!     atm::auth::logout_customer(a, s).unwrap();
//!     let _ = atm::customer::balance(a, &s);
//! }
//! ```
//!
//! A front end can't make up a rate feed (only `rate_feed::fetch` makes one):
//! ```compile_fail,E0451
//! fn forge() -> atm::rate_feed::Feed {
//!     atm::rate_feed::Feed { published: "today".into(), rates: Vec::new() }
//! }
//! ```

// No `unsafe` code anywhere: rules out memory-safety bugs.
#![forbid(unsafe_code)]

pub mod admin;
mod anchor;
pub mod audit;
pub mod auth;
pub mod cash;
pub mod customer;
pub mod db;
#[cfg(feature = "demo")]
pub mod demo; // sample data; only in `--features demo` builds
pub mod dispense;
pub mod error;
pub mod family;
pub mod fx;
pub mod input;
pub mod keys;
pub mod money;
pub mod rate_feed;
pub mod review;
mod seal;
pub mod service;

use anchor::Anchor;
use error::{AtmError, Result};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::cell::Cell;
use std::collections::HashMap;
use std::path::Path;

/// The open machine: database connection + loaded key.
///
/// STRIDE (Elevation of Privilege / Tampering): the connection is private to this crate, so a
/// front end can't run its own SQL, only the checked functions, each needing the right session.
/// Every operation goes through `begin` (changes) or `read` (views); both check the seal first.
pub struct Atm {
    pub(crate) conn: Connection,
    /// Random per opened bank. Sessions carry it, so a session made on any
    /// other `Atm` (say, a throwaway database with its own passwords) is refused.
    pub(crate) id: u64,
    /// None for the throwaway in-memory test bank.
    anchor: Option<Anchor>,
    /// Newest seal counter seen: the database may never go back below it.
    seen: Cell<i64>,
    /// A change was committed but the anchor couldn't be updated: every
    /// operation tries again first, and refuses until it works.
    anchor_behind: Cell<bool>,
    /// Failed logins per unknown (or closed) card lookup, in memory only,
    /// so after 3 tries they answer "card locked" like a real card would.
    pub(crate) unknown_cards: HashMap<String, i64>,
}

/// A fresh random id for one opened bank.
fn new_id() -> Result<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| AtmError::Internal("no system randomness".into()))?;
    Ok(u64::from_le_bytes(bytes))
}

impl Atm {
    /// Start-up for any front end: load the key, open the DB, run safety checks. A bank is
    /// `atm.db` + `atm.key` + `atm.anchor`, made new only when none exists; a key or anchor with
    /// no database is refused, so deleting the DB can't hand setup to whoever is at the machine.
    /// Demo data (published passwords) is refused, so it can't be copied over a real bank.
    pub fn open(db_path: &Path, key_path: &Path) -> Result<Atm> {
        let atm = Atm::start(db_path, key_path, false)?;
        if db::is_demo(&*atm.read()?)? {
            return Err(AtmError::NotAllowed(
                "this is a demo database with published passwords; it can't run as a real bank",
            ));
        }
        Ok(atm)
    }

    /// Demo mode only: opens demo data, and refuses a real bank's database.
    #[cfg(feature = "demo")]
    pub fn open_demo(db_path: &Path, key_path: &Path) -> Result<Atm> {
        let atm = Atm::start(db_path, key_path, false)?;
        let demo = db::is_demo(&*atm.read()?)?;
        if !demo && !atm.needs_setup()? {
            return Err(AtmError::NotAllowed("this is a real bank's database, not demo data"));
        }
        Ok(atm)
    }

    /// Start a brand-new bank with a key file made in advance (tests use one
    /// key for many banks). Refused if the database or its anchor exists.
    pub fn create(db_path: &Path, key_path: &Path) -> Result<Atm> {
        if db_path.exists() {
            return Err(AtmError::NotAllowed("a bank already exists here"));
        }
        Atm::start(db_path, key_path, true)
    }

    /// Shared start-up: check the files, load the key, open the DB, check seal, anchor, clock.
    fn start(db_path: &Path, key_path: &Path, key_made_in_advance: bool) -> Result<Atm> {
        let anchor = Anchor::for_db(db_path);
        let fresh = !db_path.exists();
        if fresh && (anchor.exists() || (key_path.exists() && !key_made_in_advance)) {
            return Err(AtmError::NotAllowed(
                "the bank's database file is missing; restore it, or delete the key and anchor files to \
                 start a new bank on purpose",
            ));
        }
        keys::load_or_create(key_path, !fresh)?; // fail closed if DB exists but key is gone
        let conn = db::open(db_path, fresh)?; // also checks the key belongs to this DB
        let (counter, mac) = seal::current(&conn)?;
        seal::check(&conn)?; // refuse a database edited outside the ATM
        if fresh {
            anchor.advance(counter, &mac)?;
        } else {
            let (anchored, anchored_mac) = anchor.read()?;
            if counter < anchored || (counter == anchored && !keys::same_mac(&mac, &anchored_mac)) {
                return Err(AtmError::RolledBack);
            }
            anchor.advance(counter, &mac)?; // a crash right after a commit leaves it one behind
        }
        audit::check_clock(&conn)?; // refuse to run if the clock went backwards
        auth::warm_up(); // the first failed login then takes as long as any other
        Ok(Atm {
            conn,
            id: new_id()?,
            anchor: Some(anchor),
            seen: Cell::new(counter),
            anchor_behind: Cell::new(false),
            unknown_cards: HashMap::new(),
        })
    }

    /// True until first-run setup has created the Teller Admin and Cash Handler.
    pub fn needs_setup(&self) -> Result<bool> {
        Ok(!db::is_initialized(&*self.read()?)?)
    }

    /// Open a change. Takes the write lock, then checks the seal and that the
    /// database hasn't gone back to an older copy. Dropped without `commit`,
    /// everything rolls back.
    pub(crate) fn begin(&mut self) -> Result<Tx<'_>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let counter = seal::check(&tx)?;
        if counter < self.seen.get() {
            return Err(AtmError::RolledBack);
        }
        self.seen.set(counter);
        catch_up_anchor(self.anchor.as_ref(), &self.anchor_behind, &tx)?;
        Ok(Tx {
            tx,
            counter,
            anchor: self.anchor.as_ref(),
            seen: &self.seen,
            anchor_behind: &self.anchor_behind,
        })
    }

    /// Open a consistent read-only view, after checking the seal.
    pub(crate) fn read(&self) -> Result<Transaction<'_>> {
        let tx = self.conn.unchecked_transaction()?;
        let counter = seal::check(&tx)?;
        if counter < self.seen.get() {
            return Err(AtmError::RolledBack);
        }
        self.seen.set(counter);
        catch_up_anchor(self.anchor.as_ref(), &self.anchor_behind, &tx)?;
        Ok(tx)
    }

    /// Throwaway in-memory bank (tests).
    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Atm> {
        let conn = db::open_in_memory()?;
        let counter = seal::check(&conn)?;
        Ok(Atm {
            conn,
            id: new_id()?,
            anchor: None,
            seen: Cell::new(counter),
            anchor_behind: Cell::new(false),
            unknown_cards: HashMap::new(),
        })
    }

    /// Tests that set up a situation by editing the database directly (say,
    /// moving an entry to yesterday) re-seal it afterwards, as the bank would.
    #[cfg(test)]
    pub(crate) fn reseal(&self) {
        let (counter, _) = seal::current(&self.conn).unwrap();
        seal::write(&self.conn, counter).unwrap();
    }
}

/// After a commit whose anchor write failed: write it now (the seal was just
/// checked), or refuse the operation. STRIDE (Tampering): blocking the anchor
/// file can't make the ATM run on without it.
fn catch_up_anchor(anchor: Option<&Anchor>, behind: &Cell<bool>, conn: &Connection) -> Result<()> {
    if let (true, Some(anchor)) = (behind.get(), anchor) {
        let (counter, mac) = seal::current(conn)?;
        anchor.advance(counter, &mac)?;
        behind.set(false);
    }
    Ok(())
}

/// A change in progress (from `Atm::begin`). `commit` re-seals the database
/// in the same transaction, then moves the anchor forward.
pub(crate) struct Tx<'a> {
    tx: Transaction<'a>,
    counter: i64,
    anchor: Option<&'a Anchor>,
    seen: &'a Cell<i64>,
    anchor_behind: &'a Cell<bool>,
}

impl<'a> std::ops::Deref for Tx<'a> {
    type Target = Transaction<'a>;
    /// Use the change like the transaction it wraps.
    fn deref(&self) -> &Transaction<'a> {
        &self.tx
    }
}

impl Tx<'_> {
    /// Re-seal with the next counter, commit, then move the anchor forward.
    pub(crate) fn commit(self) -> Result<()> {
        let next = self.counter + 1;
        let mac = seal::write(&self.tx, next)?;
        self.tx.commit()?;
        self.seen.set(next);
        // The change is permanent now, so it is never reported as failed (a
        // customer told "not completed" would get the cash or bills back).
        // If the anchor can't be written, the next operation tries again
        // and refuses until it works (fail closed).
        if let Some(anchor) = self.anchor
            && anchor.advance(next, &mac).is_err()
        {
            self.anchor_behind.set(true);
        }
        Ok(())
    }
}

// Tests may poke the raw database (e.g. to simulate an attacker editing the file).
#[cfg(test)]
impl std::ops::Deref for Atm {
    type Target = Connection;
    /// The raw connection (tests only).
    fn deref(&self) -> &Connection {
        &self.conn
    }
}
#[cfg(test)]
impl std::ops::DerefMut for Atm {
    /// The raw connection, writable (tests only).
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}
