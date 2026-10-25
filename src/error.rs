//! One error type for the whole program.
//!
//! STRIDE (Information Disclosure): users only ever see the `Display` text.
//! DB errors, paths and hash failures collapse into a generic `Internal`.
//! STRIDE (Denial of Service): no `unwrap()` on the runtime path; bad input
//! ends one operation, never the program.

use crate::money::Cents;
use std::fmt;

#[derive(Debug)]
pub enum AtmError {
    /// Rejected input. Our own text, never an echo of what was typed.
    InvalidInput(&'static str),
    /// Wrong credentials. Never says which part was wrong (no account enumeration).
    AuthFailed,
    /// Card locked after 3 bad PINs; a Teller Admin must unlock it.
    CardLocked,
    /// Session idle too long (or ended for safety). Log in again.
    SessionExpired,
    /// Money can't leave this account right now (guardian or admin froze it).
    AccountFrozen,
    /// The bank froze this account: its cards aren't accepted until a teller lifts it.
    FrozenByBank,
    InsufficientFunds,
    /// Unusual activity: money can't leave until a teller confirms it in person.
    OnHold,
    /// A daily limit would be exceeded. Carries what is still allowed today,
    /// and whether a teller can approve more (adult Bank of CCNY accounts).
    LimitExceeded {
        kind: &'static str,
        remaining: Cents,
        see_teller: bool,
    },
    /// Chosen bill can't cover the amount. Lists bills that can (spec 5.1),
    /// and whether a mixed-bill payout would work. Never reveals bill counts.
    DenominationUnavailable {
        available: Vec<u32>,
        mixed_possible: bool,
    },
    /// More bills than one withdrawal pays out (a dispenser limit).
    TooManyBills {
        max: i64,
    },
    NotFound(&'static str),
    /// The action breaks a rule (cash maximum, youth controls, etc.).
    NotAllowed(&'static str),
    /// Audit chain broken at this entry.
    AuditTampered(i64),
    /// Stored balances disagree with the ledger: one line per account, last 4
    /// digits only ("account ******1234 (stored $X, the log says $Y)").
    BalanceMismatch(Vec<String>),
    /// The bill counts disagree with the cash the log says went in and out.
    CashMismatch {
        counted: Cents,
        logged: Cents,
    },
    /// Today's rate feed couldn't be fetched or used; nothing was changed.
    FeedUnavailable(&'static str),
    /// A MAC-protected record (settings, exchange rates) was edited outside the ATM.
    RecordTampered(&'static str),
    /// Limits, rates or account flags that don't match the log (see
    /// `audit::reconcile_state`), one item per line.
    StateMismatch(Vec<String>),
    /// More than one integrity check failed. All are listed, so a failure
    /// that is already known can't hide a new one.
    IntegrityFailures(Vec<AtmError>),
    /// The database seal doesn't match: the file was changed outside the ATM.
    DatabaseAltered,
    /// The database is an older copy than this machine has already used.
    RolledBack,
    /// Customer service is halted until a teller reviews (see service.rs).
    OutOfService,
    /// System clock is earlier than the newest audit entry.
    ClockRollback,
    /// stdin closed; lets the CLI exit cleanly.
    Eof,
    /// Anything unexpected. Detail is for developers (debug builds only).
    #[allow(dead_code)]
    Internal(String),
}

impl fmt::Display for AtmError {
    /// The only text a user sees for each error; no internal detail.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtmError::InvalidInput(msg) => write!(f, "Invalid input: {msg}."),
            AtmError::AuthFailed => write!(f, "Login failed."),
            AtmError::CardLocked => {
                write!(f, "This card is locked. Please see a teller to have it unlocked.")
            }
            AtmError::SessionExpired => write!(f, "Your session has ended. Please log in again."),
            AtmError::AccountFrozen => {
                write!(f, "This account is frozen. Money cannot be taken out right now.")
            }
            AtmError::FrozenByBank => {
                write!(f, "This account is frozen by the bank. Please see a teller inside the branch.")
            }
            AtmError::InsufficientFunds => write!(f, "Insufficient funds."),
            AtmError::OnHold => write!(
                f,
                "For your protection, withdrawals and transfers on this account are paused after unusual \
                 activity. Please see a teller inside the branch to confirm it was you."
            ),
            AtmError::LimitExceeded { kind, remaining, see_teller } => {
                write!(f, "That would exceed the daily {kind} limit. Remaining today: {remaining}.")?;
                if *see_teller {
                    write!(
                        f,
                        " For a larger amount, please see a teller inside the branch, who can approve it."
                    )?;
                }
                Ok(())
            }
            AtmError::DenominationUnavailable { available, mixed_possible } => {
                if available.is_empty() {
                    write!(f, "This machine cannot pay that amount in a single bill type right now.")?;
                } else {
                    let list: Vec<String> = available.iter().map(|d| format!("${d}")).collect();
                    write!(f, "Not enough of that bill. Available for this amount: {}.", list.join(", "))?;
                }
                if *mixed_possible {
                    write!(f, " You can also choose mixed bills.")?;
                }
                Ok(())
            }
            AtmError::TooManyBills { max } => write!(
                f,
                "This machine pays out at most {max} bills at a time. Choose bigger bills, or take the \
                 cash in two withdrawals."
            ),
            AtmError::NotFound(what) => write!(f, "{what} not found."),
            AtmError::NotAllowed(msg) => write!(f, "Not allowed: {msg}."),
            AtmError::FeedUnavailable(msg) => {
                write!(f, "{msg}. Rates are unchanged; you can still type a rate.")
            }
            AtmError::AuditTampered(seq) => {
                write!(f, "AUDIT LOG INTEGRITY FAILURE at entry {seq}. Stop and escalate.")
            }
            AtmError::BalanceMismatch(accounts) => write!(
                f,
                "BALANCE MISMATCH: stored balance disagrees with the ledger on {}. Escalate.",
                accounts.join("; ")
            ),
            AtmError::CashMismatch { counted, logged } => write!(
                f,
                "CASH MISMATCH: the bill counts add up to {counted}, but the log says {logged} should be in \
                 the machine. Escalate."
            ),
            AtmError::StateMismatch(items) => write!(
                f,
                "CHANGED WITH NO LOG ENTRY (doesn't match the audit log): {}. Escalate.",
                items.join("; ")
            ),
            AtmError::IntegrityFailures(all) => {
                write!(f, "{} PROBLEMS FOUND.", all.len())?;
                for (i, e) in all.iter().enumerate() {
                    write!(f, " {}) {e}", i + 1)?;
                }
                Ok(())
            }
            AtmError::RecordTampered(what) => {
                write!(f, "TAMPERING DETECTED: the stored {what} were changed outside the ATM. Escalate.")
            }
            AtmError::DatabaseAltered => write!(
                f,
                "TAMPERING DETECTED: the database was changed outside the ATM. Nothing was done. Stop and \
                 escalate."
            ),
            AtmError::RolledBack => write!(
                f,
                "DATABASE ROLLED BACK: this is an older copy of the bank's records. Nothing was done. Stop \
                 and escalate."
            ),
            AtmError::OutOfService => {
                write!(f, "This ATM is temporarily out of service. Please use another ATM.")
            }
            AtmError::ClockRollback => {
                write!(f, "System clock is behind the audit log. Fix the clock before using this ATM.")
            }
            AtmError::Eof => write!(f, "Input closed."),
            AtmError::Internal(_) => write!(f, "Internal error. Please contact the bank."),
        }
    }
}

impl std::error::Error for AtmError {}

impl From<rusqlite::Error> for AtmError {
    /// Any database error becomes a generic `Internal` (detail hidden from users).
    fn from(e: rusqlite::Error) -> Self {
        AtmError::Internal(format!("sqlite: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, AtmError>;
