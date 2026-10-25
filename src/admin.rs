//! Everything a Teller Admin can do. Every function takes `&AdminSession`.
//!
//! STRIDE (Repudiation): every admin action writes an audit row with the
//! admin's username.
//! Least privilege: NO function here edits a balance, reads/changes a PIN, or
//! touches the audit log. That limits what a stolen admin password is worth.

use crate::audit::{self, Action, Entry, IntegrityReport, Row};
use crate::auth::{self, AdminSession, CardAndPin, Confirmed};
use crate::db::{self, CASH_MAXIMUM, Limit, Number};
use crate::error::{AtmError, Result};
use crate::fx::{self, Currency};
use crate::input::{self, ADULT_AGE};
use crate::money::Cents;
use crate::{Atm, Tx};
use chrono::{NaiveDate, Utc};
use chrono_tz::America::New_York;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// Rows per page in the admin audit view.
pub const AUDIT_PAGE: u32 = 20;
/// Max people on one joint account (couples).
pub const MAX_JOINT_HOLDERS: i64 = 2;
/// Starting youth controls (guardian can change them).
pub const YOUTH_WITHDRAW_CAP: Cents = Cents::from_dollars(100);
pub const YOUTH_TRANSFER_CAP: Cents = Cents::from_dollars(50);

/// Numbers to hand to the customer after an account or card is created.
#[derive(Debug, Clone)]
pub struct NewCard {
    pub account_number: String, // receives transfers
    pub card_number: String,    // logs in (with the PIN)
}

/// A locked card, with what a teller needs to check ID before unlocking.
/// Last 4 digits only: the teller unlocks with the card the customer hands
/// over, and never sees full numbers they could try at the ATM themselves.
#[derive(Debug, Clone)]
pub struct LockedCard {
    pub card_last4: String,
    pub account_last4: String,
    pub full_name: String,
    pub date_of_birth: String,
}

fn today() -> NaiveDate {
    Utc::now().with_timezone(&New_York).date_naive()
}

/// Random 10-digit number from the OS CSPRNG, unused by any account or card.
/// STRIDE (Spoofing / DoS): not sequential, so nobody can list every
/// account and lock them all out with 3 bad PINs each.
fn fresh_number(tx: &Transaction) -> Result<String> {
    const RANGE: u64 = 10_000_000_000;
    const UNBIASED_BELOW: u64 = u64::MAX - (u64::MAX % RANGE); // uniform % RANGE
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| AtmError::Internal("no system randomness".into()))?;
        let n = u64::from_le_bytes(bytes);
        if n >= UNBIASED_BELOW {
            continue;
        }
        let candidate = format!("{:010}", n % RANGE);
        // Never the same digits as any account or card, open or closed.
        let taken: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE account_lookup = ?1)
                 OR EXISTS (SELECT 1 FROM cards WHERE card_lookup = ?2)",
            params![db::lookup(Number::Account, &candidate)?, db::lookup(Number::Card, &candidate)?],
            |r| r.get(0),
        )?;
        if !taken {
            return Ok(candidate);
        }
    }
}

/// Validate a new holder's details; returns (dob, age).
fn check_holder(name: &str, dob_text: &str, pin: &str) -> Result<(NaiveDate, u32)> {
    input::validate_name(name)?;
    let dob = input::validate_dob(dob_text, today())?;
    input::validate_new_pin(pin, dob)?;
    Ok((dob, input::age_on(dob, today())))
}

fn insert_card(
    tx: &Transaction,
    account_id: i64,
    role: &str,
    name: &str,
    dob: NaiveDate,
    pin: &str,
) -> Result<(i64, String)> {
    let card_number = fresh_number(tx)?;
    // STRIDE (Info Disclosure): card number, name and DOB all encrypted;
    // name + DOB are bound to this card's row.
    let (found_by, card_enc, last4) = db::seal_number(Number::Card, &card_number)?;
    let (name_enc, dob_enc) = db::seal_holder(&found_by, name, dob)?;
    // The PIN hash only verifies for this card, account and role.
    let pin_hash = auth::hash_secret(pin, &auth::card_identity(&found_by, account_id, role))?;
    tx.execute(
        "INSERT INTO cards (card_lookup, card_enc, card_last4, account_id, holder_role, name_enc, dob_enc,
                            pin_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![found_by, card_enc, last4, account_id, role, name_enc, dob_enc, pin_hash],
    )?;
    Ok((tx.last_insert_rowid(), card_number))
}

/// All the starting balances one Teller Admin login may enter in a bank day,
/// together (US-dollar value). Fixed: raising a limit doesn't raise it.
pub const STARTING_BALANCES_PER_DAY: Cents = Cents::from_dollars(20_000);

/// Insert a new account row with a fresh, encrypted number. Returns (id,
/// number, US-dollar value of the starting balance, for the log).
/// The starting balance is typed by a teller with no cash counted by the
/// machine, so it is capped twice: each one at the bank's daily deposit
/// limit, and all of one teller's in a bank day at STARTING_BALANCES_PER_DAY
/// (summed from the signed log). So one teller can't create money out of
/// nothing, not even by opening many accounts (STRIDE: Tampering / Elevation
/// of Privilege). More goes in as deposits, which the limits cover.
fn insert_account(
    tx: &Transaction,
    session: &AdminSession,
    kind: &str,
    currency: Currency,
    balance: Cents,
) -> Result<(i64, String, Cents)> {
    let usd = if balance.is_zero() { Cents::ZERO } else { fx::usd_value(tx, currency, balance)? };
    if usd > db::get_limit(tx, Limit::Deposit)? {
        return Err(AtmError::NotAllowed(
            "a starting balance can't be more than the daily deposit limit; deposit the rest at the ATM",
        ));
    }
    let today = audit::opened_today_by(tx, &session.actor())?;
    if today.checked_add(usd).is_none_or(|total| total > STARTING_BALANCES_PER_DAY) {
        return Err(AtmError::NotAllowed(
            "today's starting balances would pass $20,000; open it with less and deposit the rest at the ATM",
        ));
    }
    let account_number = fresh_number(tx)?;
    let (found_by, account_enc, last4) = db::seal_number(Number::Account, &account_number)?;
    tx.execute(
        "INSERT INTO accounts (account_lookup, account_enc, account_last4, kind, currency, balance_cents)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![found_by, account_enc, last4, kind, currency.code(), balance.as_i64()],
    )?;
    Ok((tx.last_insert_rowid(), account_number, usd))
}

/// Logs a new account with its starting balance and that balance's US-dollar
/// value (what the daily cap on starting balances adds up).
fn log_opened(
    tx: &Connection,
    session: &AdminSession,
    opened: (i64, Cents, Cents),
    detail: &str,
) -> Result<()> {
    let (account_id, balance, usd) = opened;
    audit::append(
        tx,
        &Entry {
            actor: &session.actor(),
            action: Action::AccountOpened,
            account_id: Some(account_id),
            counterparty_id: None,
            amount: Some(balance),
            usd: Some(usd),
            detail,
        },
    )?;
    Ok(())
}

fn log(
    tx: &Connection,
    session: &AdminSession,
    action: Action,
    account: Option<i64>,
    amount: Option<Cents>,
    detail: &str,
) -> Result<()> {
    audit::append(
        tx,
        &Entry {
            actor: &session.actor(),
            action,
            account_id: account,
            counterparty_id: None,
            amount,
            usd: None,
            detail,
        },
    )?;
    Ok(())
}

/// Card id, account id, role, DOB for a card on an open account.
/// Same error for bad format, missing and closed.
fn card_ids(conn: &Connection, card_number: &str) -> Result<(i64, i64, String, NaiveDate)> {
    input::validate_number10(card_number).map_err(|_| AtmError::NotFound("Card"))?;
    let found_by = db::lookup(Number::Card, card_number)?;
    let (id, account_id, role, dob_enc): (i64, i64, String, Vec<u8>) = conn
        .query_row(
            "SELECT c.id, c.account_id, c.holder_role, c.dob_enc
             FROM cards c JOIN accounts a ON a.id = c.account_id
             WHERE c.card_lookup = ?1 AND a.closed = 0",
            params![found_by],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?
        .ok_or(AtmError::NotFound("Card"))?;
    Ok((id, account_id, role, db::holder_dob(&found_by, &dob_enc)?))
}

// ---------------------------------------------------------------------------
// Accounts and cards
// ---------------------------------------------------------------------------

/// Spec: create a customer account (full name, DOB, chosen PIN, starting balance).
/// Individual accounts are for adults; minors get a youth account instead.
/// Bank of CCNY accounts are always in US dollars.
pub fn create_customer(
    atm: &mut Atm,
    session: &AdminSession,
    full_name: &str,
    date_of_birth: &str,
    pin: &str,
    starting_balance: Cents,
) -> Result<NewCard> {
    let holder = Holder { full_name, date_of_birth, pin };
    open_adult_account(atm, session, AdultKind::Individual, holder, starting_balance, Currency::Usd)
}

/// Simulates the card network: registers another bank's card so it can be
/// used at this ATM. `balance` is what the card's own bank would approve, in
/// that bank's currency (a foreign visitor's card is converted to dollars).
/// Guest cards can only withdraw (paying the ATM fee) and check the balance.
pub fn register_guest_card(
    atm: &mut Atm,
    session: &AdminSession,
    full_name: &str,
    date_of_birth: &str,
    pin: &str,
    balance: Cents,
    currency: Currency,
) -> Result<NewCard> {
    let holder = Holder { full_name, date_of_birth, pin };
    open_adult_account(atm, session, AdultKind::Guest, holder, balance, currency)
}

/// The person a new adult account is for.
struct Holder<'a> {
    full_name: &'a str,
    date_of_birth: &'a str,
    pin: &'a str,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum AdultKind {
    Individual,
    Guest,
}

/// Individual accounts (USD) and guest cards (any currency): one adult, one card.
fn open_adult_account(
    atm: &mut Atm,
    session: &AdminSession,
    kind: AdultKind,
    holder: Holder,
    starting_balance: Cents,
    currency: Currency,
) -> Result<NewCard> {
    atm.admit(session)?;
    currency.check_amount(starting_balance)?;
    let (dob, age) = check_holder(holder.full_name, holder.date_of_birth, holder.pin)?;
    if age < ADULT_AGE {
        return Err(AtmError::NotAllowed("under 18: open a youth account with a guardian instead"));
    }
    // Fixed strings per kind (no SQL is ever built from input).
    let (account_kind, role, detail) = match kind {
        AdultKind::Individual => ("individual", "owner", "individual account, starting balance"),
        AdultKind::Guest => {
            ("guest", "guest", "guest card from another bank (simulated network), balance there")
        }
    };
    let tx = atm.begin()?;
    let (account_id, account_number, usd) =
        insert_account(&tx, session, account_kind, currency, starting_balance)?;
    let (_, card_number) = insert_card(&tx, account_id, role, holder.full_name, dob, holder.pin)?;
    log_opened(
        &tx,
        session,
        (account_id, starting_balance, usd),
        &format!("{} ({})", detail, currency.code()),
    )?;
    tx.commit()?;
    Ok(NewCard { account_number, card_number })
}

/// Add a second adult to an account, making it joint. They get their own card
/// and PIN, so each person's actions are logged under their own card.
/// The current holder must be at the counter: their card and PIN confirm it.
pub fn add_joint_holder(
    atm: &mut Atm,
    session: &AdminSession,
    account_number: &str,
    holder: CardAndPin,
    full_name: &str,
    date_of_birth: &str,
    pin: &str,
) -> Result<NewCard> {
    atm.admit(session)?;
    let (dob, age) = check_holder(full_name, date_of_birth, pin)?;
    if age < ADULT_AGE {
        return Err(AtmError::NotAllowed("joint account holders must be 18 or older"));
    }
    let tx = atm.begin()?;
    let account_id = db::account_id(&tx, account_number)?;
    let holder_card = holder.card_number;
    let (tx, holder) = confirmed(tx, session, holder)?;
    if holder.account_id != account_id || !matches!(holder.role.as_str(), "owner" | "joint") {
        return Err(AtmError::NotAllowed(
            "the card and PIN must be those of a current holder of this account",
        ));
    }
    let (kind, holders): (String, i64) = tx.query_row(
        "SELECT kind, (SELECT COUNT(*) FROM cards WHERE account_id = ?1) FROM accounts WHERE id = ?1",
        params![account_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if kind == "youth" {
        return Err(AtmError::NotAllowed("youth accounts can't be joint; add a guardian instead"));
    }
    if kind == "guest" {
        return Err(AtmError::NotAllowed("cards from other banks can't have joint holders here"));
    }
    if holders >= MAX_JOINT_HOLDERS {
        return Err(AtmError::NotAllowed("this account already has the maximum number of holders"));
    }
    tx.execute("UPDATE accounts SET kind = 'joint' WHERE id = ?1", params![account_id])?;
    let (card_id, card_number) = insert_card(&tx, account_id, "joint", full_name, dob, pin)?;
    log(
        &tx,
        session,
        Action::HolderAdded,
        Some(account_id),
        None,
        &format!(
            "joint holder, {}; confirmed by {} with PIN",
            db::card_ref(card_id, db::last4(&card_number)),
            db::card_ref(holder.card_id, db::last4(holder_card))
        ),
    )?;
    tx.commit()?;
    Ok(NewCard { account_number: account_number.to_string(), card_number })
}

/// Open a youth account for a child under 18, managed by an adult guardian,
/// who confirms at the counter with their own card and PIN. Starts with safe
/// defaults: $100/day withdrawals, $50/day transfers, transfers only to family.
pub fn open_youth_account(
    atm: &mut Atm,
    session: &AdminSession,
    guardian: CardAndPin,
    child_name: &str,
    child_dob: &str,
    child_pin: &str,
    starting_balance: Cents,
) -> Result<NewCard> {
    atm.admit(session)?;
    let (dob, age) = check_holder(child_name, child_dob, child_pin)?;
    if age >= ADULT_AGE {
        return Err(AtmError::NotAllowed("youth accounts are for customers under 18"));
    }
    let guardian_card_number = guardian.card_number;
    let tx = atm.begin()?;
    let (tx, _) = confirmed(tx, session, guardian)?;
    let guardian_card = adult_card(&tx, guardian_card_number)?;
    let (account_id, account_number, usd) =
        insert_account(&tx, session, "youth", Currency::Usd, starting_balance)?;
    tx.execute(
        "UPDATE accounts SET withdraw_cap_cents = ?2, transfer_cap_cents = ?3, family_only_transfers = 1
         WHERE id = ?1",
        params![account_id, YOUTH_WITHDRAW_CAP.as_i64(), YOUTH_TRANSFER_CAP.as_i64()],
    )?;
    let (_, card_number) = insert_card(&tx, account_id, "minor", child_name, dob, child_pin)?;
    tx.execute(
        "INSERT INTO guardians (youth_account_id, guardian_card_id) VALUES (?1, ?2)",
        params![account_id, guardian_card],
    )?;
    log_opened(
        &tx,
        session,
        (account_id, starting_balance, usd),
        &format!(
            "youth account, guardian {} (confirmed with PIN)",
            db::card_ref(guardian_card, db::last4(guardian_card_number))
        ),
    )?;
    tx.commit()?;
    Ok(NewCard { account_number, card_number })
}

/// Add another guardian (e.g. the second parent) to a youth account.
/// A current guardian must be at the counter and confirm with card and PIN,
/// so a teller can't appoint a guardian (say, to lift a parent's freeze) alone.
pub fn add_guardian(
    atm: &mut Atm,
    session: &AdminSession,
    youth_account_number: &str,
    current_guardian: CardAndPin,
    guardian_card_number: &str,
) -> Result<()> {
    atm.admit(session)?;
    let current_card = current_guardian.card_number;
    let tx = atm.begin()?;
    let account_id = db::account_id(&tx, youth_account_number)?;
    let kind: String =
        tx.query_row("SELECT kind FROM accounts WHERE id = ?1", params![account_id], |r| r.get(0))?;
    if kind != "youth" {
        return Err(AtmError::NotAllowed("guardians can only be added to youth accounts"));
    }
    let (tx, current) = confirmed(tx, session, current_guardian)?;
    let is_guardian: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM guardians WHERE youth_account_id = ?1 AND guardian_card_id = ?2)",
        params![account_id, current.card_id],
        |r| r.get(0),
    )?;
    if !is_guardian {
        return Err(AtmError::NotAllowed(
            "the card and PIN must be those of a current guardian of this account",
        ));
    }
    let guardian_card = adult_card(&tx, guardian_card_number)?;
    let added = tx.execute(
        "INSERT OR IGNORE INTO guardians (youth_account_id, guardian_card_id) VALUES (?1, ?2)",
        params![account_id, guardian_card],
    )?;
    if added == 0 {
        return Err(AtmError::NotAllowed("that card is already a guardian of this account"));
    }
    log(
        &tx,
        session,
        Action::HolderAdded,
        Some(account_id),
        None,
        &format!(
            "guardian {}; confirmed by {} with PIN",
            db::card_ref(guardian_card, db::last4(guardian_card_number)),
            db::card_ref(current.card_id, db::last4(current_card))
        ),
    )?;
    tx.commit()?;
    Ok(())
}

/// A holder confirms at the counter with card + PIN (see `auth::confirm_at_counter`).
/// A refusal is committed first, so a wrong PIN counts toward the lock.
fn confirmed<'a>(tx: Tx<'a>, session: &AdminSession, who: CardAndPin) -> Result<(Tx<'a>, Confirmed)> {
    match auth::confirm_at_counter(&tx, &session.actor(), who)? {
        Ok(holder) => Ok((tx, holder)),
        Err(refused) => {
            tx.commit()?;
            Err(refused)
        }
    }
}

/// A Bank of CCNY card that belongs to an adult (18+), not a youth or guest card.
fn adult_card(conn: &Connection, card_number: &str) -> Result<i64> {
    let (card_id, _, role, dob) = card_ids(conn, card_number)?;
    if role == "guest" {
        return Err(AtmError::NotAllowed("a guardian must be a Bank of CCNY customer"));
    }
    if role == "minor" || input::age_on(dob, today()) < ADULT_AGE {
        return Err(AtmError::NotAllowed("a guardian must be an adult customer"));
    }
    Ok(card_id)
}

// ---------------------------------------------------------------------------
// Oversight
// ---------------------------------------------------------------------------

/// Spec: audit log of all transactions for any account, with timestamps.
/// Also shows logins, lockouts and unlocks (what a dispute investigation needs).
pub fn audit_for_account(
    atm: &Atm,
    session: &AdminSession,
    account_number: &str,
    page: u32,
) -> Result<Vec<Row>> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    let id = db::account_id(conn, account_number)?;
    audit::for_account(conn, id, false, AUDIT_PAGE, page)
}

/// Spec: set daily withdrawal and deposit limits for all customers (+ transfer).
pub fn set_limit(atm: &mut Atm, session: &AdminSession, limit: Limit, new_value: Cents) -> Result<()> {
    atm.admit(session)?;
    if new_value.is_zero() {
        return Err(AtmError::InvalidInput("a limit must be more than zero"));
    }
    if limit == Limit::Withdrawal && new_value > CASH_MAXIMUM {
        return Err(AtmError::InvalidInput("the withdrawal limit cannot exceed what the machine can hold"));
    }
    if new_value > limit.ceiling() {
        return Err(AtmError::NotAllowed(match limit {
            Limit::Withdrawal => "the daily withdrawal limit can be at most $5,000.00",
            Limit::Deposit => "the daily deposit limit can be at most $50,000.00",
            Limit::Transfer => "the daily transfer limit can be at most $25,000.00",
        }));
    }
    let tx = atm.begin()?;
    let old_value = db::get_limit(&tx, limit)?;
    db::set_limit(&tx, limit, new_value)?;
    log(
        &tx,
        session,
        Action::LimitChanged,
        None,
        Some(new_value),
        &format!("daily {} limit: {} -> {}", limit.label(), old_value, new_value),
    )?;
    tx.commit()?;
    Ok(())
}

/// Approve more than a daily limit for one account, for today only (the
/// customer is at the counter and has shown ID). The extra is written to the
/// signed log and the limit check reads it from there, so there is no flag
/// to edit. Adult Bank of CCNY accounts only (a youth account's caps belong
/// to its guardian; another bank's card belongs to that bank). At most
/// `Limit::max_raise` extra per account per day.
pub fn raise_limit_today(
    atm: &mut Atm,
    session: &AdminSession,
    account_number: &str,
    limit: Limit,
    extra: Cents,
) -> Result<()> {
    atm.admit(session)?;
    if extra.is_zero() {
        return Err(AtmError::InvalidInput("enter an amount more than zero"));
    }
    let tx = atm.begin()?;
    let id = db::account_id(&tx, account_number)?;
    let kind: String = tx.query_row("SELECT kind FROM accounts WHERE id = ?1", params![id], |r| r.get(0))?;
    if kind == "youth" {
        return Err(AtmError::NotAllowed("a youth account's limits are set by its parent or guardian"));
    }
    if kind == "guest" {
        return Err(AtmError::NotAllowed("another bank's card follows that bank's limits"));
    }
    let already = audit::total_today(&tx, id, limit.raised_action())?;
    if already.checked_add(extra).is_none_or(|total| total > limit.max_raise()) {
        return Err(AtmError::NotAllowed(
            "that is more than a teller can approve for one account in one day",
        ));
    }
    audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action: limit.raised_action(),
            account_id: Some(id),
            counterparty_id: None,
            amount: None,
            usd: Some(extra),
            detail: &format!(
                "daily {} limit raised by {extra} for today; customer at the counter",
                limit.label()
            ),
        },
    )?;
    tx.commit()?;
    Ok(())
}

/// Cards locked by 3 bad PINs, with name and DOB so the teller can check ID first.
pub fn locked_cards(atm: &Atm, session: &AdminSession) -> Result<Vec<LockedCard>> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    let mut stmt = conn.prepare(
        "SELECT c.card_lookup, c.card_last4, a.account_last4, c.name_enc, c.dob_enc
         FROM cards c JOIN accounts a ON a.id = c.account_id
         WHERE c.locked = 1 AND a.closed = 0 ORDER BY c.id",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let card: String = r.get(0)?;
        out.push(LockedCard {
            card_last4: r.get(1)?,
            account_last4: r.get(2)?,
            full_name: db::holder_name(&card, &r.get::<_, Vec<u8>>(3)?)?,
            date_of_birth: db::holder_dob(&card, &r.get::<_, Vec<u8>>(4)?)?.to_string(),
        });
    }
    Ok(out)
}

/// Spec: unlock a card locked by failed PIN attempts. The customer hands
/// over the card at the counter (its number is typed from it).
/// At most once per card per bank day, counted from the signed log: 3 wrong
/// PINs, unlock, 3 more... would otherwise let a teller (or a friend of the
/// customer) keep guessing (STRIDE: Spoofing).
pub fn unlock_card(atm: &mut Atm, session: &AdminSession, card_number: &str) -> Result<()> {
    atm.admit(session)?;
    let tx = atm.begin()?;
    let (card_id, account_id, _, _) = card_ids(&tx, card_number)?;
    let locked: bool =
        tx.query_row("SELECT locked FROM cards WHERE id = ?1", params![card_id], |r| r.get(0))?;
    if !locked {
        return Err(AtmError::InvalidInput("that card is not locked"));
    }
    let card = db::card_ref(card_id, db::last4(card_number));
    let unlocked_today: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM audit_log
                        WHERE action = ?1 AND account_id = ?2 AND detail = ?3 AND ts >= ?4)",
        params![Action::CardUnlocked.as_str(), account_id, card, audit::bank_day_start_utc()?],
        |r| r.get(0),
    )?;
    if unlocked_today {
        return Err(AtmError::NotAllowed(
            "this card was already unlocked today; it can be unlocked again tomorrow (New York time)",
        ));
    }
    tx.execute("UPDATE cards SET locked = 0, failed_attempts = 0 WHERE id = ?1", params![card_id])?;
    log(&tx, session, Action::CardUnlocked, Some(account_id), None, &card)?;
    tx.commit()?;
    Ok(())
}

/// Freeze/unfreeze an account (fraud response, e.g. a reported stolen card).
/// Frozen by the bank = its cards aren't accepted at all (sign-in refused,
/// live sessions end, no holder consent at the counter) and it takes no
/// transfers in. Only a Teller Admin lifts it. A guardian's freeze on a
/// youth account is separate (no money out; the card still works): a teller
/// can't lift it, and a guardian can't lift this one.
pub fn set_frozen(atm: &mut Atm, session: &AdminSession, account_number: &str, frozen: bool) -> Result<()> {
    atm.admit(session)?;
    let tx = atm.begin()?;
    let id = db::account_id(&tx, account_number)?;
    let (bank, guardian): (bool, bool) =
        tx.query_row("SELECT frozen, guardian_frozen FROM accounts WHERE id = ?1", params![id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    if !frozen && !bank && guardian {
        return Err(AtmError::NotAllowed(
            "this account was frozen by its guardian; only the guardian can unfreeze it",
        ));
    }
    tx.execute("UPDATE accounts SET frozen = ?2 WHERE id = ?1", params![id, frozen])?;
    let action = if frozen { Action::AccountFrozen } else { Action::AccountUnfrozen };
    log(&tx, session, action, Some(id), None, "by teller admin")?;
    tx.commit()?;
    Ok(())
}

/// Close an account (customer leaving). Balance must be $0 first: the teller
/// can't make money vanish. Cards stop working, history is kept, and the
/// number is never reused (fresh_number checks closed accounts too).
pub fn close_account(atm: &mut Atm, session: &AdminSession, account_number: &str) -> Result<()> {
    atm.admit(session)?;
    let tx = atm.begin()?;
    let id = db::account_id(&tx, account_number)?;
    let balance: i64 =
        tx.query_row("SELECT balance_cents FROM accounts WHERE id = ?1", params![id], |r| r.get(0))?;
    if balance != 0 {
        return Err(AtmError::NotAllowed("the balance must be $0.00 before an account can be closed"));
    }
    // A guardian's card can't vanish while it still manages an open youth account alone.
    // Only guardians whose own account is still open count (closing them one
    // by one must not leave a child with no guardian).
    let sole_guardian: bool = tx.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM guardians g JOIN cards c ON c.id = g.guardian_card_id
             JOIN accounts y ON y.id = g.youth_account_id
             WHERE c.account_id = ?1 AND y.closed = 0
               AND (SELECT COUNT(*) FROM guardians g2
                    JOIN cards c2 ON c2.id = g2.guardian_card_id
                    JOIN accounts a2 ON a2.id = c2.account_id
                    WHERE g2.youth_account_id = g.youth_account_id AND a2.closed = 0) = 1)",
        params![id],
        |r| r.get(0),
    )?;
    if sole_guardian {
        return Err(AtmError::NotAllowed("this customer is the only guardian of a youth account"));
    }
    tx.execute("UPDATE accounts SET closed = 1 WHERE id = ?1", params![id])?;
    log(&tx, session, Action::AccountClosed, Some(id), None, "closed by teller admin")?;
    tx.commit()?;
    Ok(())
}

/// One card holder in the teller's account list. Only the card's last 4
/// digits: the teller types the full number from the card itself (unlock).
#[derive(Debug, Clone)]
pub struct HolderSummary {
    pub card_last4: String,
    pub full_name: String,
    pub role: String, // owner / joint / minor
    pub locked: bool,
}

/// One row of the teller's account list. No balance: a teller doesn't need it.
#[derive(Debug, Clone)]
pub struct AccountSummary {
    pub account_number: String,
    pub kind: String, // individual / joint / youth / guest
    pub currency: Currency,
    /// Frozen by the bank (this teller screen can lift it).
    pub frozen: bool,
    /// Frozen by a youth account's guardian (only the guardian can lift it).
    pub guardian_frozen: bool,
    pub closed: bool,
    pub holders: Vec<HolderSummary>,
}

/// Every account with its holders (names decrypted for the teller screen).
pub fn list_accounts(atm: &Atm, session: &AdminSession) -> Result<Vec<AccountSummary>> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    let mut stmt = conn.prepare(
        "SELECT a.id, a.account_lookup, a.account_enc, a.kind, a.frozen, a.closed,
                c.card_lookup, c.card_last4, c.name_enc, c.holder_role, c.locked, a.currency,
                a.guardian_frozen
         FROM accounts a JOIN cards c ON c.account_id = a.id
         ORDER BY a.closed, a.id, c.id",
    )?;
    let mut rows = stmt.query([])?;
    let mut out: Vec<AccountSummary> = Vec::new();
    let mut last_id = None;
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        let card: String = r.get(6)?;
        let holder = HolderSummary {
            card_last4: r.get(7)?,
            full_name: db::holder_name(&card, &r.get::<_, Vec<u8>>(8)?)?,
            role: r.get(9)?,
            locked: r.get(10)?,
        };
        match out.last_mut() {
            Some(last) if last_id == Some(id) => last.holders.push(holder),
            _ => out.push(AccountSummary {
                account_number: db::open_number(
                    Number::Account,
                    &r.get::<_, String>(1)?,
                    &r.get::<_, Vec<u8>>(2)?,
                )?,
                kind: r.get(3)?,
                currency: Currency::parse(&r.get::<_, String>(11)?)?,
                frozen: r.get(4)?,
                guardian_frozen: r.get(12)?,
                closed: r.get(5)?,
                holders: vec![holder],
            }),
        }
        last_id = Some(id);
    }
    Ok(out)
}

/// Every security event and transaction, all accounts, newest first.
pub fn recent_audit(atm: &Atm, session: &AdminSession, page: u32) -> Result<Vec<Row>> {
    atm.admit(session)?;
    audit::recent(&*atm.read()?, AUDIT_PAGE, page)
}

/// Current bank-wide limits (for the "set limits" screen).
pub fn bank_limits(atm: &Atm, session: &AdminSession) -> Result<Vec<(Limit, Cents)>> {
    atm.admit(session)?;
    let conn = &atm.read()?;
    Limit::ALL.into_iter().map(|l| Ok((l, db::get_limit(conn, l)?))).collect()
}

/// Check the audit chain + every balance against the ledger. Logs the check.
/// (The database seal was already checked when the transaction opened.)
pub fn verify_integrity(atm: &mut Atm, session: &AdminSession) -> Result<IntegrityReport> {
    atm.admit(session)?;
    let tx = atm.begin()?;
    let report = audit::verify(&tx)?;
    log(
        &tx,
        session,
        Action::AuditVerified,
        None,
        None,
        &format!(
            "{} entries, {} balances, cash {}, {} limits/rates/flags verified",
            report.entries, report.accounts_checked, report.cash, report.state_checked
        ),
    )?;
    tx.commit()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testing::setup;

    fn usd(n: u32) -> Cents {
        Cents::from_dollars(n)
    }

    #[test]
    fn a_bank_freeze_stops_the_card_entirely_until_a_teller_lifts_it() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let ann = create_customer(&mut conn, &admin, "Ann Lee", "1980-01-01", "4821", usd(100)).unwrap();
        let sam = create_customer(&mut conn, &admin, "Sam Roe", "1981-01-01", "5937", usd(100)).unwrap();
        let open_session = auth::login_customer(&mut conn, &ann.card_number, "4821").unwrap();
        let sender = auth::login_customer(&mut conn, &sam.card_number, "5937").unwrap();
        set_frozen(&mut conn, &admin, &ann.account_number, true).unwrap();

        // A session already open ends at its next step.
        assert!(matches!(crate::customer::balance(&conn, &open_session), Err(AtmError::SessionExpired)));
        // The right PIN gets "see a teller"; a wrong one is just a wrong PIN.
        let login = |conn: &mut Atm, pin: &str| auth::login_customer(conn, &ann.card_number, pin).map(|_| ());
        assert!(matches!(login(&mut conn, "4821"), Err(AtmError::FrozenByBank)));
        assert!(matches!(login(&mut conn, "1111"), Err(AtmError::AuthFailed)));
        // No transfers in: to a sender it looks like an unknown number.
        assert!(matches!(
            crate::customer::recipient_hint(&mut conn, &sender, &ann.account_number),
            Err(AtmError::NotFound(_))
        ));
        // At the counter, the frozen card can't vouch for a new joint holder.
        let holder = CardAndPin { card_number: &ann.card_number, pin: "4821" };
        assert!(matches!(
            add_joint_holder(&mut conn, &admin, &ann.account_number, holder, "Ben Lee", "1983-01-01", "7305"),
            Err(AtmError::FrozenByBank)
        ));
        // Lifted by a Teller Admin: the card works again.
        set_frozen(&mut conn, &admin, &ann.account_number, false).unwrap();
        assert!(login(&mut conn, "4821").is_ok());
    }

    #[test]
    fn joint_and_youth_changes_need_the_holders_card_and_pin() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let ann = create_customer(&mut conn, &admin, "Ann Lee", "1980-01-01", "4821", usd(10)).unwrap();
        let sam = create_customer(&mut conn, &admin, "Sam Roe", "1981-01-01", "5937", usd(10)).unwrap();
        let add = |conn: &mut Atm, card: &str, pin: &str| {
            let holder = CardAndPin { card_number: card, pin };
            add_joint_holder(conn, &admin, &ann.account_number, holder, "Ben Lee", "1983-01-01", "7305")
        };
        // Someone else's card (right PIN) doesn't confirm for Ann's account.
        assert!(matches!(add(&mut conn, &sam.card_number, "5937"), Err(AtmError::NotAllowed(_))));
        // Wrong PINs at the counter count toward Ann's lock, like at the ATM.
        assert!(matches!(add(&mut conn, &ann.card_number, "1111"), Err(AtmError::AuthFailed)));
        assert!(matches!(add(&mut conn, &ann.card_number, "2222"), Err(AtmError::AuthFailed)));
        assert!(matches!(add(&mut conn, &ann.card_number, "3333"), Err(AtmError::CardLocked)));
        assert!(matches!(
            auth::login_customer(&mut conn, &ann.card_number, "4821"),
            Err(AtmError::CardLocked)
        ));
        unlock_card(&mut conn, &admin, &ann.card_number).unwrap();
        assert!(add(&mut conn, &ann.card_number, "4821").is_ok());
        // A youth account needs the guardian's own PIN.
        let sam_guess = CardAndPin { card_number: &sam.card_number, pin: "0000" };
        assert!(
            open_youth_account(&mut conn, &admin, sam_guess, "Kid Roe", "2014-01-01", "2580", usd(5))
                .is_err()
        );
        let sam_here = CardAndPin { card_number: &sam.card_number, pin: "5937" };
        assert!(
            open_youth_account(&mut conn, &admin, sam_here, "Kid Roe", "2014-01-01", "2580", usd(5)).is_ok()
        );
    }

    #[test]
    fn one_teller_cannot_mint_money_or_switch_limits_off() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        // Starting balance: up to the daily deposit limit ($10,000).
        let open =
            |conn: &mut Atm, amount| create_customer(conn, &admin, "Mal Lory", "1975-05-05", "7305", amount);
        assert!(open(&mut conn, usd(10_000)).is_ok());
        assert!(matches!(open(&mut conn, usd(10_001)), Err(AtmError::NotAllowed(_))));
        // Limits: at most the default plus one day's largest raise.
        for limit in Limit::ALL {
            assert!(set_limit(&mut conn, &admin, limit, limit.ceiling()).is_ok());
            let over = limit.ceiling().checked_add(Cents::new(1).unwrap()).unwrap();
            assert!(set_limit(&mut conn, &admin, limit, over).is_err(), "{}", limit.label());
        }
        assert_eq!(Limit::Withdrawal.ceiling(), usd(5_000));
        assert_eq!(Limit::Deposit.ceiling(), usd(50_000));
        assert_eq!(Limit::Transfer.ceiling(), usd(25_000));
    }

    #[test]
    fn create_customer_rejects_bad_fields_and_minors() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        assert!(create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).is_ok());
        assert!(create_customer(&mut conn, &admin, "A\x1b[31m", "1990-01-01", "4821", usd(10)).is_err());
        assert!(create_customer(&mut conn, &admin, "Ann Lee", "2990-01-01", "4821", usd(10)).is_err());
        assert!(create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "48a1", usd(10)).is_err());
        assert!(create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "1234", usd(10)).is_err());
        assert!(create_customer(&mut conn, &admin, "Kid Lee", "2020-01-01", "4821", usd(10)).is_err());
    }

    #[test]
    fn names_and_birth_dates_are_encrypted_at_rest() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).unwrap();
        let (name, dob): (Vec<u8>, Vec<u8>) = conn
            .query_row("SELECT name_enc, dob_enc FROM cards", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert!(!String::from_utf8_lossy(&name).contains("Ann"));
        assert!(!String::from_utf8_lossy(&dob).contains("1990"));
        assert_eq!(list_accounts(&conn, &admin).unwrap()[0].holders[0].full_name, "Ann Lee");
    }

    #[test]
    fn copying_one_customers_encrypted_name_onto_another_is_detected() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).unwrap();
        create_customer(&mut conn, &admin, "Bo Kim", "1990-01-01", "4821", usd(10)).unwrap();
        conn.execute(
            "UPDATE cards SET name_enc = (SELECT name_enc FROM cards WHERE id = 1) WHERE id = 2",
            [],
        )
        .unwrap();
        // The database seal catches it first...
        assert!(matches!(list_accounts(&conn, &admin), Err(AtmError::DatabaseAltered)));
        // ...and the encryption would on its own (the name is bound to its row).
        conn.reseal();
        assert!(matches!(list_accounts(&conn, &admin), Err(AtmError::NotAllowed(_))));
    }

    #[test]
    fn card_and_account_numbers_are_stored_encrypted() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let a = create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).unwrap();
        let b = add_joint_holder(
            &mut conn,
            &admin,
            &a.account_number,
            CardAndPin { card_number: &a.card_number, pin: "4821" },
            "Ben Lee",
            "1990-02-02",
            "7305",
        )
        .unwrap();
        // Every column of both tables, as text: no full number anywhere.
        let dump: String = conn
            .query_row(
                "SELECT group_concat(quote(a.account_lookup) || quote(a.account_enc) || quote(a.account_last4)
                    || quote(c.card_lookup) || quote(c.card_enc) || quote(c.card_last4) || quote(c.name_enc), '|')
                 FROM accounts a JOIN cards c ON c.account_id = a.id",
                [],
                |r| r.get(0),
            )
            .unwrap();
        for number in [&a.account_number, &a.card_number, &b.card_number] {
            assert!(!dump.contains(number.as_str()), "a full number is stored in the clear");
            let hex: String = number.bytes().map(|x| format!("{x:02X}")).collect();
            assert!(!dump.contains(&hex), "a full number is stored as raw bytes");
        }
        // The lookup is keyed: not the plain SHA-256 an attacker could rebuild.
        use sha2::Digest;
        let plain: String =
            sha2::Sha256::digest(a.card_number.as_bytes()).iter().map(|x| format!("{x:02x}")).collect();
        assert_ne!(db::lookup(Number::Card, &a.card_number).unwrap(), plain);
        // Card and account lookups differ even for the same digits.
        assert_ne!(
            db::lookup(Number::Card, "1234567890").unwrap(),
            db::lookup(Number::Account, "1234567890").unwrap()
        );
        // The teller sees the account number, and only the last 4 of each card.
        let list = list_accounts(&conn, &admin).unwrap();
        assert_eq!(list[0].account_number, a.account_number);
        assert_eq!(list[0].holders[1].card_last4, db::last4(&b.card_number));
    }

    #[test]
    fn logs_name_cards_by_id_and_last_four_only() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let pat = create_customer(&mut conn, &admin, "Pat Doe", "1980-03-03", "4821", usd(50)).unwrap();
        let sue = create_customer(&mut conn, &admin, "Sue Doe", "1981-03-03", "5937", usd(50)).unwrap();
        let joint = add_joint_holder(
            &mut conn,
            &admin,
            &pat.account_number,
            CardAndPin { card_number: &pat.card_number, pin: "4821" },
            "Lee Doe",
            "1982-03-03",
            "6048",
        )
        .unwrap();
        let kid = open_youth_account(
            &mut conn,
            &admin,
            CardAndPin { card_number: &pat.card_number, pin: "4821" },
            "Kid Doe",
            "2014-06-06",
            "2580",
            usd(5),
        )
        .unwrap();
        let pat_here = CardAndPin { card_number: &pat.card_number, pin: "4821" };
        add_guardian(&mut conn, &admin, &kid.account_number, pat_here, &sue.card_number).unwrap();
        for _ in 0..3 {
            let _ = auth::login_customer(&mut conn, &kid.card_number, "9999");
        }
        unlock_card(&mut conn, &admin, &kid.card_number).unwrap();
        let s = auth::login_customer(&mut conn, &pat.card_number, "4821").unwrap();
        crate::customer::transfer(&mut conn, &s, &sue.account_number, usd(1)).unwrap();
        let log: String = conn
            .query_row("SELECT group_concat(actor || ' ' || detail, '|') FROM audit_log", [], |r| r.get(0))
            .unwrap();
        for card in [&pat, &sue, &joint, &kid] {
            assert!(!log.contains(card.card_number.as_str()), "a full card number is in the log");
            assert!(!log.contains(card.account_number.as_str()), "a full account number is in the log");
        }
        assert!(log.contains(&s.actor()) && s.actor().ends_with(db::last4(&pat.card_number)));
    }

    #[test]
    fn copying_one_rows_encrypted_number_onto_another_is_detected() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).unwrap();
        create_customer(&mut conn, &admin, "Bo Kim", "1990-01-01", "4821", usd(10)).unwrap();
        conn.execute(
            "UPDATE accounts SET account_enc = (SELECT account_enc FROM accounts WHERE id = 1) WHERE id = 2",
            [],
        )
        .unwrap();
        assert!(matches!(list_accounts(&conn, &admin), Err(AtmError::DatabaseAltered)));
        conn.reseal(); // second layer: the number is bound to its own lookup value
        assert!(matches!(list_accounts(&conn, &admin), Err(AtmError::NotAllowed(_))));
    }

    #[test]
    fn closing_needs_a_zero_balance_and_then_blocks_the_account() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let rich = create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).unwrap();
        let empty = create_customer(&mut conn, &admin, "Bo Kim", "1990-01-01", "5937", Cents::ZERO).unwrap();
        assert!(matches!(
            close_account(&mut conn, &admin, &rich.account_number),
            Err(AtmError::NotAllowed(_))
        ));
        close_account(&mut conn, &admin, &empty.account_number).unwrap();
        assert!(matches!(
            auth::login_customer(&mut conn, &empty.card_number, "5937"),
            Err(AtmError::AuthFailed)
        ));
        assert!(close_account(&mut conn, &admin, &empty.account_number).is_err());
        let ann = auth::login_customer(&mut conn, &rich.card_number, "4821").unwrap();
        let to_closed = crate::customer::transfer(&mut conn, &ann, &empty.account_number, usd(1));
        assert!(matches!(to_closed, Err(AtmError::NotFound(_))));
        assert!(list_accounts(&conn, &admin).unwrap().iter().any(|a| a.closed));
    }

    #[test]
    fn numbers_are_ten_digits_and_distinct() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let a = create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).unwrap();
        assert!(input::validate_number10(&a.account_number).is_ok());
        assert_ne!(a.account_number, a.card_number);
    }

    #[test]
    fn admin_sees_account_events_with_timestamps() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let a = create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).unwrap();
        let _ = auth::login_customer(&mut conn, &a.card_number, "0000");
        let rows = audit_for_account(&conn, &admin, &a.account_number, 0).unwrap();
        assert_eq!(rows.len(), 2); // account_opened + login_failed
        assert!(rows.iter().all(|r| r.ts.ends_with('Z') && r.ts.len() == 20));
        assert!(matches!(audit_for_account(&conn, &admin, "0000000000", 0), Err(AtmError::NotFound(_))));
    }

    #[test]
    fn limit_changes_are_validated_and_logged() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        assert!(set_limit(&mut conn, &admin, Limit::Deposit, Cents::ZERO).is_err());
        assert!(set_limit(&mut conn, &admin, Limit::Withdrawal, usd(100_001)).is_err());
        set_limit(&mut conn, &admin, Limit::Deposit, usd(750)).unwrap();
        assert_eq!(db::get_limit(&conn, Limit::Deposit).unwrap(), usd(750));
        let logged: String = conn
            .query_row("SELECT detail FROM audit_log WHERE action = 'limit_changed'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(logged, "daily deposit limit: $10,000.00 -> $750.00");
    }

    #[test]
    fn locked_cards_are_listed_for_id_check_and_unlock_needs_a_locked_card() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let a = create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).unwrap();
        assert!(unlock_card(&mut conn, &admin, &a.card_number).is_err());
        for _ in 0..3 {
            let _ = auth::login_customer(&mut conn, &a.card_number, "9999");
        }
        let locked = locked_cards(&conn, &admin).unwrap();
        assert_eq!(locked.len(), 1);
        assert_eq!(locked[0].full_name, "Ann Lee");
        assert_eq!(locked[0].card_last4, db::last4(&a.card_number));
        assert!(!format!("{locked:?}").contains(&a.card_number), "the list shows a full card number");
        unlock_card(&mut conn, &admin, &a.card_number).unwrap();
        assert!(locked_cards(&conn, &admin).unwrap().is_empty());
        // Locked again the same day: no second unlock until tomorrow.
        for _ in 0..3 {
            let _ = auth::login_customer(&mut conn, &a.card_number, "9999");
        }
        assert!(matches!(unlock_card(&mut conn, &admin, &a.card_number), Err(AtmError::NotAllowed(_))));
    }

    #[test]
    fn integrity_check_catches_a_balance_edited_in_the_database() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut conn);
        let a = create_customer(&mut conn, &admin, "Ann Lee", "1990-01-01", "4821", usd(10)).unwrap();
        assert_eq!(verify_integrity(&mut conn, &admin).unwrap().accounts_checked, 1);
        conn.execute("UPDATE accounts SET balance_cents = 99999999", []).unwrap();
        assert!(matches!(verify_integrity(&mut conn, &admin), Err(AtmError::DatabaseAltered)));
        conn.reseal(); // second layer: the balance is checked against the ledger
        // Named by its last 4 digits only: the report goes into the log.
        let last4 = &a.account_number[6..];
        assert!(matches!(verify_integrity(&mut conn, &admin), Err(AtmError::BalanceMismatch(lines))
            if lines.len() == 1 && lines[0].contains(last4) && !lines[0].contains(&a.account_number)));
    }
}
