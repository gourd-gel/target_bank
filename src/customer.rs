//! Everything a logged-in customer can do.
//!
//! STRIDE (Info Disclosure / Elevation of Privilege): no function here takes
//! "which account" as input. The account always comes from the
//! `CustomerSession`, so a customer can't name someone else's account.
//! (Only exception: a transfer's destination, which can only receive money.)
//! Least privilege: other banks' cards (guest cards) can only withdraw, check
//! the balance and see limits here; every other operation refuses them.
//! STRIDE (Tampering): each money operation is ONE immediate SQL transaction:
//! check, move money, move bills, write audit row. Any failure (or a power
//! cut) and none of it happened.

use crate::Atm;
use crate::audit::{self, Action, Entry, Row};
use crate::auth::{CustomerSession, HolderRole};
use crate::cash;
use crate::db::{self, Limit, Number, PHYSICAL_CAPACITY};
use crate::dispense::{self, BillChoice, Plan};
use crate::error::{AtmError, Result};
use crate::fx::{self, Conversion, Currency, Fee, FeeRule, SumLine};
use crate::input;
use crate::money::{Cents, Denomination};
use crate::review::{self, Move, Screen};
use rusqlite::{Connection, OptionalExtension, params};

/// Rows per page of "recent transactions".
pub const HISTORY_PAGE: u32 = 10;
/// Max bills of one kind per deposit (like a real deposit slot).
const MAX_BILLS_PER_DEPOSIT: u32 = 200;

/// One daily limit as this customer experiences it.
#[derive(Debug, Clone)]
pub struct LimitStatus {
    pub limit: Limit,
    /// Bank limit, or the guardian's lower cap on a youth account.
    pub per_day: Cents,
    /// Extra a teller approved for today only (usually zero).
    pub approved_today: Cents,
    /// per_day + approved_today - used today.
    pub remaining_today: Cents,
}

/// Printed/shown after every successful transaction (our "receipt" feature).
#[derive(Debug, Clone)]
pub struct Receipt {
    /// Audit-log sequence number: quote this in a dispute.
    pub reference: i64,
    pub timestamp: String,
    pub kind: &'static str,
    /// Masked: last 4 digits only.
    pub account: String,
    pub counterparty: Option<String>,
    /// In the account's currency (what the balance changed by).
    pub amount: Cents,
    pub currency: Currency,
    /// Cash, each fee and the total (empty for transfers).
    pub summary: Vec<SumLine>,
    /// How each fee is worked out and the rate (empty if neither).
    pub fine_print: String,
    /// Bills dispensed or deposited (empty for transfers).
    pub bills: Plan,
    pub balance_after: Cents,
}

/// Basic facts about the logged-in account, for the menu header.
#[derive(Debug, Clone)]
pub struct AccountInfo {
    /// This card holder's own name ("Hello, Ann").
    pub holder_name: String,
    pub account: String, // masked
    pub kind: String,    // individual / joint / youth / guest
    pub frozen: bool,
    /// Withdrawals and transfers paused after unusual activity (see a teller).
    pub on_hold: bool,
    pub holders: i64,
    /// Number of youth accounts this card is a guardian of (shows the Family menu).
    pub youth_accounts: i64,
    /// The account's currency (cash is always US dollars).
    pub currency: Currency,
    /// Today's rate and fee, for an account in another currency with a usable rate.
    pub rate: Option<String>,
    /// ATM fee rule per withdrawal (other banks' cards only).
    pub atm_fee: Option<FeeRule>,
}

/// Show only the last 4 digits (spec masking from the group notes).
pub fn mask(number: &str) -> String {
    let tail: String = number.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("******{tail}")
}

// ---------------------------------------------------------------------------
// Helpers (run inside the caller's transaction)
// ---------------------------------------------------------------------------

pub(crate) fn balance_of(conn: &Connection, account_id: i64) -> Result<Cents> {
    let cents: i64 =
        conn.query_row("SELECT balance_cents FROM accounts WHERE id = ?1", params![account_id], |r| {
            r.get(0)
        })?;
    Cents::new(cents)
}

pub(crate) fn currency_of(conn: &Connection, account_id: i64) -> Result<Currency> {
    let code: String =
        conn.query_row("SELECT currency FROM accounts WHERE id = ?1", params![account_id], |r| r.get(0))?;
    Currency::parse(&code)
}

/// Other banks' cards may only withdraw, check the balance and see limits here.
pub(crate) fn not_guest(session: &CustomerSession) -> Result<()> {
    if session.role() == HolderRole::Guest {
        return Err(AtmError::NotAllowed(
            "cards from other banks can only withdraw cash and check the balance at this ATM",
        ));
    }
    Ok(())
}

/// The ATM fee rule this card pays per withdrawal: other banks' cards only.
fn atm_fee_for(conn: &Connection, session: &CustomerSession) -> Result<Option<FeeRule>> {
    if session.role() != HolderRole::Guest {
        return Ok(None);
    }
    Ok(Some(fx::fee_rule_of(conn, Fee::OtherBank)?))
}

pub(crate) fn is_frozen(conn: &Connection, account_id: i64) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT frozen OR guardian_frozen FROM accounts WHERE id = ?1",
        params![account_id],
        |r| r.get(0),
    )?)
}

/// Guardian cap for this limit on this account (youth accounts only).
fn account_cap(conn: &Connection, account_id: i64, limit: Limit) -> Result<Option<Cents>> {
    // Fixed SQL per limit (no string-built queries anywhere).
    let sql = match limit {
        Limit::Withdrawal => "SELECT withdraw_cap_cents FROM accounts WHERE id = ?1",
        Limit::Transfer => "SELECT transfer_cap_cents FROM accounts WHERE id = ?1",
        Limit::Deposit => return Ok(None),
    };
    let cap: Option<i64> = conn.query_row(sql, params![account_id], |r| r.get(0))?;
    cap.map(Cents::new).transpose()
}

fn limit_action(limit: Limit) -> Action {
    match limit {
        Limit::Withdrawal => Action::Withdrawal,
        Limit::Deposit => Action::Deposit,
        Limit::Transfer => Action::Transfer,
    }
}

/// (per-day limit, extra approved today, remaining today) after any youth cap.
/// Usage and approvals are per ACCOUNT, so joint holders share one limit.
/// Both come from the signed log: there is no counter or flag to edit.
fn limit_status(conn: &Connection, account_id: i64, limit: Limit) -> Result<LimitStatus> {
    let bank = db::get_limit(conn, limit)?;
    let per_day = match account_cap(conn, account_id, limit)? {
        Some(cap) => bank.min(cap),
        None => bank,
    };
    let approved_today = audit::total_today(conn, account_id, limit.raised_action())?;
    let used = audit::total_today(conn, account_id, limit_action(limit))?;
    let allowed = per_day.checked_add(approved_today).ok_or(AtmError::Internal("limit overflow".into()))?;
    Ok(LimitStatus {
        limit,
        per_day,
        approved_today,
        remaining_today: allowed.checked_sub(used).unwrap_or(Cents::ZERO),
    })
}

pub(crate) fn check_daily_limit(
    conn: &Connection,
    account_id: i64,
    limit: Limit,
    amount: Cents,
) -> Result<()> {
    let status = limit_status(conn, account_id, limit)?;
    if amount > status.remaining_today {
        // Only adult Bank of CCNY accounts can have a teller approve more.
        let kind: String =
            conn.query_row("SELECT kind FROM accounts WHERE id = ?1", params![account_id], |r| r.get(0))?;
        return Err(AtmError::LimitExceeded {
            kind: limit.label(),
            remaining: status.remaining_today,
            see_teller: kind == "individual" || kind == "joint",
        });
    }
    Ok(())
}

/// Debit; the `balance_cents >= ?2` makes check-and-debit one atomic statement.
pub(crate) fn debit(conn: &Connection, account_id: i64, amount: Cents) -> Result<()> {
    let changed = conn.execute(
        "UPDATE accounts SET balance_cents = balance_cents - ?2 WHERE id = ?1 AND balance_cents >= ?2",
        params![account_id, amount.as_i64()],
    )?;
    if changed == 1 { Ok(()) } else { Err(AtmError::InsufficientFunds) }
}

pub(crate) fn credit(conn: &Connection, account_id: i64, amount: Cents) -> Result<()> {
    let changed = conn.execute(
        "UPDATE accounts SET balance_cents = balance_cents + ?2 WHERE id = ?1",
        params![account_id, amount.as_i64()],
    )?;
    if changed == 1 { Ok(()) } else { Err(AtmError::Internal("credit hit no row".into())) }
}

// ---------------------------------------------------------------------------
// Customer operations
// ---------------------------------------------------------------------------

/// "View the total balance of their account."
pub fn balance(atm: &Atm, session: &CustomerSession) -> Result<Cents> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    balance_of(conn, session.account_id())
}

/// Holder name, account type, frozen flag, number of holders, guardian status.
pub fn account_info(atm: &Atm, session: &CustomerSession) -> Result<AccountInfo> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    type InfoRow = (String, bool, i64, String, Vec<u8>, i64);
    let (kind, frozen, holders, card_lookup, name_enc, youth_accounts): InfoRow = conn.query_row(
        "SELECT a.kind, a.frozen OR a.guardian_frozen, (SELECT COUNT(*) FROM cards c WHERE c.account_id = a.id),
                me.card_lookup, me.name_enc,
                (SELECT COUNT(*) FROM guardians g WHERE g.guardian_card_id = me.id)
         FROM cards me JOIN accounts a ON a.id = me.account_id WHERE me.id = ?1",
        params![session.card_id()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;
    let currency = currency_of(conn, session.account_id())?;
    Ok(AccountInfo {
        currency,
        rate: fx::rate_note(conn, currency)?,
        atm_fee: atm_fee_for(conn, session)?,
        holder_name: db::holder_name(&card_lookup, &name_enc)?,
        account: mask(session.account_number()),
        kind,
        frozen,
        on_hold: review::hold_reason(conn, session.account_id())?.is_some(),
        holders,
        youth_accounts,
    })
}

/// "View the withdrawal and transfer limit" (deposit shown too).
pub fn limits(atm: &Atm, session: &CustomerSession) -> Result<Vec<LimitStatus>> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    [Limit::Withdrawal, Limit::Transfer, Limit::Deposit]
        .into_iter()
        .map(|l| limit_status(conn, session.account_id(), l))
        .collect()
}

/// Checks that don't depend on bills: amount, frozen, balance, daily limit.
/// `amount` is US-dollar cash; returns what the account will be charged,
/// part by part (cash, rate, other bank's ATM fee, exchange fee).
fn precheck_withdrawal(conn: &Connection, session: &CustomerSession, amount: Cents) -> Result<Conversion> {
    let account_id = session.account_id();
    if amount.is_zero() {
        return Err(AtmError::InvalidInput("amount must be more than zero"));
    }
    if is_frozen(conn, account_id)? {
        return Err(AtmError::AccountFrozen);
    }
    review::check_not_held(conn, account_id)?;
    let other_bank = session.role() == HolderRole::Guest;
    let charge = fx::charge_for(conn, currency_of(conn, account_id)?, amount, other_bank)?;
    if charge.account_amount > balance_of(conn, account_id)? {
        return Err(AtmError::InsufficientFunds);
    }
    check_daily_limit(conn, account_id, Limit::Withdrawal, amount)?;
    Ok(charge)
}

/// Early "can I withdraw this much?" so a front end can refuse before the
/// customer picks bills, and show the charge line by line
/// (`Conversion::summary`). `withdraw` repeats every check; this changes nothing.
pub fn check_withdrawal(atm: &Atm, session: &CustomerSession, amount: Cents) -> Result<Conversion> {
    atm.admit(session)?;
    precheck_withdrawal(&*atm.read()?, session, amount)
}

/// Preview which bills a withdrawal would pay out. Changes nothing.
pub fn quote_withdrawal(
    atm: &Atm,
    session: &CustomerSession,
    amount: Cents,
    choice: BillChoice,
) -> Result<Plan> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    precheck_withdrawal(conn, session, amount)?;
    let (stock, _) = cash::stock(conn)?;
    dispense::plan_withdrawal(&stock, amount, choice)
}

/// Withdraw `amount` paid as `choice` says. Spec checks: balance, daily
/// limit, and the machine must hold the bills (else list what it has), at
/// most 40 of them per withdrawal.
pub fn withdraw(
    atm: &mut Atm,
    session: &CustomerSession,
    amount: Cents,
    choice: BillChoice,
) -> Result<Receipt> {
    atm.admit(session)?;
    let id = session.account_id();
    let tx = atm.begin_for(session)?;
    let charge = precheck_withdrawal(&tx, session, amount)?; // inside the transaction: no race

    let (stock, _) = cash::stock(&tx)?;
    let plan = dispense::plan_withdrawal(&stock, amount, choice)?; // rejects + lists bills if impossible
    // Unusual pattern: refuse, and keep the hold row for the teller.
    if review::screen(&tx, id, Move::Withdrawal, amount, charge.account_amount)? == Screen::Held {
        tx.commit()?;
        return Err(AtmError::OnHold);
    }
    cash::take_plan(&tx, &plan)?;
    debit(&tx, id, charge.account_amount)?;
    let reference = audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action: Action::Withdrawal,
            account_id: Some(id),
            counterparty_id: None,
            amount: Some(charge.account_amount),
            usd: Some(amount),
            detail: &detail_with(cash::describe(&plan), &charge),
        },
    )?;
    let balance_after = balance_of(&tx, id)?;
    tx.commit()?;
    Ok(receipt(reference, "withdrawal", session, None, charge, plan, balance_after))
}

/// What a deposit of `amount` US dollars would add to this account, line by
/// line (conversion and exchange fee for an account in another currency). Changes nothing.
pub fn preview_deposit(atm: &Atm, session: &CustomerSession, amount: Cents) -> Result<Conversion> {
    atm.admit(session)?;
    not_guest(session)?;
    let conn = &atm.read()?;
    fx::credit_for(conn, currency_of(conn, session.account_id())?, amount)
}

/// Deposit cash as (bill, count) pairs, the way a machine counts what you feed it.
pub fn deposit(atm: &mut Atm, session: &CustomerSession, bills: &[(Denomination, u32)]) -> Result<Receipt> {
    atm.admit(session)?;
    not_guest(session)?;
    // Total per kind of bill first: listing $5 four times is still one kind.
    let mut plan: Plan = Vec::new();
    for &(denom, count) in bills {
        match plan.iter_mut().find(|(d, _)| *d == denom) {
            Some((_, n)) => *n += i64::from(count),
            None => plan.push((denom, i64::from(count))),
        }
    }
    plan.retain(|&(_, count)| count > 0);
    let mut amount = Cents::ZERO;
    for &(denom, count) in &plan {
        if count > i64::from(MAX_BILLS_PER_DEPOSIT) {
            return Err(AtmError::InvalidInput("at most 200 bills of each kind per deposit"));
        }
        amount =
            amount.checked_add(denom.times(count)?).ok_or(AtmError::InvalidInput("amount is too large"))?;
    }
    if amount.is_zero() {
        return Err(AtmError::InvalidInput("no bills were entered"));
    }
    let id = session.account_id();
    let tx = atm.begin_for(session)?;

    // Spec: no more than the daily deposit limit (counted in US dollars).
    check_daily_limit(&tx, id, Limit::Deposit, amount)?;
    let (_, total) = cash::stock(&tx)?;
    if total.checked_add(amount).is_none_or(|t| t > PHYSICAL_CAPACITY) {
        return Err(AtmError::NotAllowed("this machine is full; please use another ATM"));
    }
    let credited = fx::credit_for(&tx, currency_of(&tx, id)?, amount)?;
    for &(denom, count) in &plan {
        cash::add_bills(&tx, denom, count)?;
    }
    credit(&tx, id, credited.account_amount)?;
    plan.sort_by_key(|&(d, _)| std::cmp::Reverse(d));
    let reference = audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action: Action::Deposit,
            account_id: Some(id),
            counterparty_id: None,
            amount: Some(credited.account_amount),
            usd: Some(amount),
            detail: &detail_with(cash::describe(&plan), &credited),
        },
    )?;
    let balance_after = balance_of(&tx, id)?;
    tx.commit()?;
    Ok(receipt(reference, "deposit", session, None, credited, plan, balance_after))
}

/// Transfer to another account at this bank.
pub fn transfer(
    atm: &mut Atm,
    session: &CustomerSession,
    to_account_number: &str,
    amount: Cents,
) -> Result<Receipt> {
    atm.admit(session)?;
    not_guest(session)?;
    // Spec: "Target transfer account should be validated."
    input::validate_number10(to_account_number)?;
    if to_account_number == session.account_number() {
        return Err(AtmError::InvalidInput("you cannot transfer to your own account"));
    }
    if amount.is_zero() {
        return Err(AtmError::InvalidInput("amount must be more than zero"));
    }
    let from = session.account_id();
    let tx = atm.begin_for(session)?;

    let Some(to) = destination(&tx, session, to_account_number)? else {
        tx.commit()?; // keep the "session ended" log row, if one was written
        return Err(if session.is_expired() {
            AtmError::SessionExpired
        } else {
            AtmError::NotFound("Destination account")
        });
    };

    if is_frozen(&tx, from)? {
        return Err(AtmError::AccountFrozen);
    }
    review::check_not_held(&tx, from)?;
    // Youth "family only": destination must belong to one of this account's guardians.
    let family_only: bool =
        tx.query_row("SELECT family_only_transfers FROM accounts WHERE id = ?1", params![from], |r| {
            r.get(0)
        })?;
    if family_only {
        let ok: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM guardians g JOIN cards c ON c.id = g.guardian_card_id
                            WHERE g.youth_account_id = ?1 AND c.account_id = ?2)",
            params![from, to],
            |r| r.get(0),
        )?;
        if !ok {
            return Err(AtmError::NotAllowed("this youth account can only transfer to a parent or guardian"));
        }
    }
    // No conversion inside the bank: both accounts must use the same currency.
    let currency = currency_of(&tx, from)?;
    if currency_of(&tx, to)? != currency {
        return Err(AtmError::NotAllowed("transfers must be between accounts in the same currency"));
    }
    currency.check_amount(amount)?; // e.g. no half won
    // Spec: sufficient funds.
    if amount > balance_of(&tx, from)? {
        return Err(AtmError::InsufficientFunds);
    }
    let usd = fx::usd_value(&tx, currency, amount)?;
    check_daily_limit(&tx, from, Limit::Transfer, usd)?;
    // Unusual pattern: refuse, and keep the hold row for the teller.
    if review::screen(&tx, from, Move::Transfer { to }, usd, amount)? == Screen::Held {
        tx.commit()?;
        return Err(AtmError::OnHold);
    }

    // Both halves in one transaction: money is never created or destroyed.
    debit(&tx, from, amount)?;
    credit(&tx, to, amount)?;
    let reference = audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action: Action::Transfer,
            account_id: Some(from),
            counterparty_id: Some(to),
            amount: Some(amount),
            usd: Some(usd),
            detail: "",
        },
    )?;
    let balance_after = balance_of(&tx, from)?;
    tx.commit()?;
    let moved = Conversion::plain(currency, usd, amount);
    Ok(receipt(
        reference,
        "transfer",
        session,
        Some(mask(to_account_number)),
        moved,
        Vec::new(),
        balance_after,
    ))
}

/// Open destination account id, or None. Counts misses: too many unknown
/// numbers ends the session (STRIDE: Info Disclosure, stops number hunting).
/// Guest cards belong to other banks, so they are never a destination here.
/// An account the bank froze takes no transfers and looks like an unknown
/// number (it can't collect moved money, and its state isn't shown).
fn destination(conn: &Connection, session: &CustomerSession, number: &str) -> Result<Option<i64>> {
    let id: Option<i64> = conn
        .query_row(
            "SELECT id FROM accounts
             WHERE account_lookup = ?1 AND closed = 0 AND frozen = 0 AND kind != 'guest'",
            params![db::lookup(Number::Account, number)?],
            |r| r.get(0),
        )
        .optional()?;
    if id.is_none() && session.note_missed_lookup() {
        audit::append(
            conn,
            &Entry {
                actor: &session.actor(),
                action: Action::SessionEnded,
                account_id: Some(session.account_id()),
                counterparty_id: None,
                amount: None,
                usd: None,
                detail: "too many unknown transfer destinations",
            },
        )?;
    }
    Ok(id)
}

/// Before confirming a transfer: check the destination exists and show the
/// holders' initials ("A. L. / B. L."), enough to catch a typo, not enough
/// to harvest names. Misses count toward the 3-strike session end.
pub fn recipient_hint(atm: &mut Atm, session: &CustomerSession, to_account_number: &str) -> Result<String> {
    atm.admit(session)?;
    not_guest(session)?;
    input::validate_number10(to_account_number)?;
    if to_account_number == session.account_number() {
        return Err(AtmError::InvalidInput("you cannot transfer to your own account"));
    }
    let tx = atm.begin_for(session)?;
    let Some(to) = destination(&tx, session, to_account_number)? else {
        tx.commit()?;
        return Err(if session.is_expired() {
            AtmError::SessionExpired
        } else {
            AtmError::NotFound("Destination account")
        });
    };
    holder_initials(&tx, to)
}

/// Holders' initials for an account: "A. L. / B. L.".
fn holder_initials(conn: &Connection, account_id: i64) -> Result<String> {
    let mut stmt =
        conn.prepare("SELECT card_lookup, name_enc FROM cards WHERE account_id = ?1 ORDER BY id")?;
    let mut rows = stmt.query(params![account_id])?;
    let mut hints = Vec::new();
    while let Some(r) = rows.next()? {
        let card: String = r.get(0)?;
        let name = db::holder_name(&card, &r.get::<_, Vec<u8>>(1)?)?;
        let initials: Vec<String> =
            name.split_whitespace().filter_map(|w| w.chars().next()).map(|c| format!("{c}.")).collect();
        hints.push(initials.join(" "));
    }
    Ok(hints.join(" / "))
}

/// Most recent payees `recent_payees` returns.
pub const RECENT_PAYEES: usize = 5;

/// An account this account recently sent money to ("send again").
/// `number` is the full number so a front end can fill in the transfer
/// form; show only `masked` and `initials` on screen.
#[derive(Debug, Clone)]
pub struct RecentPayee {
    pub number: String,
    pub masked: String,
    pub initials: String,
    pub currency: Currency,
    /// The last amount sent there, and the bank day (New York) it was sent.
    pub last_amount: Cents,
    pub last_date: String,
}

/// Up to `RECENT_PAYEES` accounts this account sent money to, newest first.
/// Read from the signed log. Only transfers this account's own card holders
/// made count (not a guardian taking money back); closed accounts are left out.
pub fn recent_payees(atm: &Atm, session: &CustomerSession) -> Result<Vec<RecentPayee>> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    not_guest(session)?;
    let id = session.account_id();
    let mut own = Vec::new();
    let mut stmt = conn.prepare("SELECT id, card_last4 FROM cards WHERE account_id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    while let Some(r) = rows.next()? {
        own.push(db::customer_actor(r.get(0)?, &r.get::<_, String>(1)?));
    }
    let mut stmt = conn.prepare(
        "SELECT l.counterparty_id, l.actor, l.amount_cents, l.ts, a.account_lookup, a.account_enc
         FROM audit_log l JOIN accounts a ON a.id = l.counterparty_id AND a.closed = 0
         WHERE l.account_id = ?1 AND l.action = 'transfer'
         ORDER BY l.seq DESC LIMIT 500",
    )?;
    let mut rows = stmt.query(params![id])?;
    let mut seen = Vec::new();
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let to: i64 = r.get(0)?;
        if seen.contains(&to) || !own.contains(&r.get::<_, String>(1)?) {
            continue;
        }
        seen.push(to);
        let number = db::open_number(Number::Account, &r.get::<_, String>(4)?, &r.get::<_, Vec<u8>>(5)?)?;
        let ts: String = r.get(3)?;
        out.push(RecentPayee {
            masked: mask(&number),
            number,
            initials: holder_initials(conn, to)?,
            currency: currency_of(conn, to)?,
            last_amount: Cents::new(r.get(2)?)?,
            last_date: bank_date(&ts),
        });
        if out.len() == RECENT_PAYEES {
            break;
        }
    }
    Ok(out)
}

/// A log time (UTC) as its New York bank date, "2026-10-12".
fn bank_date(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|t| t.with_timezone(&chrono_tz::America::New_York).date_naive().to_string())
        .unwrap_or_else(|_| ts.chars().take(10).collect())
}

/// Change this card's PIN. The current PIN is required, and a wrong one
/// counts toward the 3-strike lock exactly like a failed login, so an
/// unattended logged-in session can't be used to guess it (STRIDE: Spoofing).
pub fn change_pin(atm: &mut Atm, session: &CustomerSession, current: &str, new: &str) -> Result<()> {
    atm.admit(session)?;
    // A guest card's PIN belongs to its own bank.
    not_guest(session)?;
    input::validate_pin(new)?;
    let tx = atm.begin_for(session)?;
    let (pin_hash, failed, card_lookup, dob_enc, account_id, role): (
        String,
        i64,
        String,
        Vec<u8>,
        i64,
        String,
    ) = tx.query_row(
        "SELECT pin_hash, failed_attempts, card_lookup, dob_enc, account_id, holder_role
             FROM cards WHERE id = ?1",
        params![session.card_id()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;
    let identity = crate::auth::card_identity(&card_lookup, account_id, &role);
    if !crate::auth::check_pin(current, &pin_hash, &identity) {
        let attempts = failed + 1;
        let locked = attempts >= crate::auth::MAX_PIN_ATTEMPTS;
        tx.execute(
            "UPDATE cards SET failed_attempts = ?2, locked = ?3 WHERE id = ?1",
            params![session.card_id(), attempts, locked],
        )?;
        let log = |action, detail| {
            audit::append(
                &tx,
                &Entry {
                    actor: &session.actor(),
                    action,
                    account_id: Some(session.account_id()),
                    counterparty_id: None,
                    amount: None,
                    usd: None,
                    detail,
                },
            )
        };
        log(Action::LoginFailed, "wrong current PIN while changing PIN")?;
        if locked {
            log(Action::CardLocked, "3 consecutive failed PINs")?;
            session.end();
        }
        tx.commit()?;
        return Err(if locked { AtmError::CardLocked } else { AtmError::AuthFailed });
    }
    if current == new {
        return Err(AtmError::InvalidInput("the new PIN must be different from the current one"));
    }
    // Same strength rules as a new card: no 1234, 0000 or birthday.
    input::validate_new_pin(new, db::holder_dob(&card_lookup, &dob_enc)?)?;
    let new_hash = crate::auth::hash_secret(new, &identity)?;
    tx.execute(
        "UPDATE cards SET pin_hash = ?2, failed_attempts = 0 WHERE id = ?1",
        params![session.card_id(), new_hash],
    )?;
    audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action: Action::PinChanged,
            account_id: Some(session.account_id()),
            counterparty_id: None,
            amount: None,
            usd: None,
            detail: "",
        },
    )?;
    tx.commit()?;
    Ok(())
}

/// "View a history of their own recent transactions." Page 0 = newest.
pub fn history(atm: &Atm, session: &CustomerSession, page: u32) -> Result<Vec<Row>> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    // A guest card's statement comes from its own bank.
    not_guest(session)?;
    audit::for_customer(conn, session.account_id(), session.account_number(), HISTORY_PAGE, page)
}

/// Log detail: bills, then the rate and each fee in US dollars
/// ("5 x $20; at 1 USD = 0.86 EUR; exchange fee $3.00").
fn detail_with(bills: String, conversion: &Conversion) -> String {
    let mut text = bills;
    if let Some(rate) = &conversion.rate {
        text.push_str(&format!("; at {rate}"));
    }
    for f in &conversion.fees {
        text.push_str(&format!("; {} {}", f.fee.label().to_lowercase(), f.usd));
    }
    text
}

/// `money`: what moved. Withdrawals and deposits (they have bills) get the
/// cash + fees = total summary.
fn receipt(
    reference: i64,
    kind: &'static str,
    session: &CustomerSession,
    counterparty: Option<String>,
    money: Conversion,
    bills: Plan,
    balance_after: Cents,
) -> Receipt {
    Receipt {
        reference,
        timestamp: audit::now_utc(),
        kind,
        account: mask(session.account_number()),
        counterparty,
        amount: money.account_amount,
        currency: money.currency,
        summary: if bills.is_empty() { Vec::new() } else { money.summary(kind == "deposit") },
        fine_print: if bills.is_empty() { String::new() } else { money.fine_print() },
        bills,
        balance_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin;
    use crate::auth::testing::setup;
    use crate::auth::{self, AdminSession, CardAndPin, HandlerSession};

    fn d(n: u32) -> Denomination {
        Denomination::new(n).unwrap()
    }
    fn usd(n: u32) -> Cents {
        Cents::from_dollars(n)
    }

    /// Machine with 100 x $20 and 10 x $50; Ann has $1,000, Bo has $50.
    fn world() -> (Atm, AdminSession, HandlerSession, CustomerSession, CustomerSession) {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, handler) = setup(&mut conn);
        cash::restock(&mut conn, &handler, d(20), 100).unwrap();
        cash::restock(&mut conn, &handler, d(50), 10).unwrap();
        let a =
            admin::create_customer(&mut conn, &admin, "Ann Rich", "1980-05-05", "4821", usd(1000)).unwrap();
        let b = admin::create_customer(&mut conn, &admin, "Bo Poor", "1999-09-09", "7305", usd(50)).unwrap();
        let ann = auth::login_customer(&mut conn, &a.card_number, "4821").unwrap();
        let bo = auth::login_customer(&mut conn, &b.card_number, "7305").unwrap();
        (conn, admin, handler, ann, bo)
    }

    #[test]
    fn recent_payees_are_newest_first_without_repeats_and_capped_at_five() {
        let (mut conn, admin, _, ann, bo) = world();
        assert!(recent_payees(&conn, &ann).unwrap().is_empty());
        let names = ["Cy Ray", "Di Fox", "Ed Moe", "Flo Yu", "Gus Ng"];
        let pins = ["5937", "3691", "2468", "1593", "8024"];
        let others: Vec<_> = names
            .iter()
            .zip(pins)
            .map(|(n, pin)| admin::create_customer(&mut conn, &admin, n, "1990-01-01", pin, usd(0)).unwrap())
            .collect();
        // Bo, then 5 others, then Bo again. A teller contact before each keeps
        // the activity check (3 new payees a day) out of this test.
        let send = |conn: &mut Atm, to: &str, dollars: u32| {
            admin::raise_limit_today(conn, &admin, ann.account_number(), Limit::Transfer, usd(1)).unwrap();
            transfer(conn, &ann, to, usd(dollars)).unwrap();
        };
        send(&mut conn, bo.account_number(), 7);
        for (i, o) in others.iter().enumerate() {
            send(&mut conn, &o.account_number, 10 + i as u32);
        }
        send(&mut conn, bo.account_number(), 3);
        let list = recent_payees(&conn, &ann).unwrap();
        assert_eq!(list.len(), RECENT_PAYEES);
        assert_eq!(list[0].number, bo.account_number());
        assert_eq!(list[0].masked, mask(bo.account_number()));
        assert_eq!(list[0].initials, "B. P.");
        assert_eq!(list[0].last_amount, usd(3)); // the latest, not the first
        assert_eq!(list[1].initials, "G. N.");
        assert_eq!(list[4].initials, "D. F."); // Cy (oldest) dropped off
        assert_eq!(list[0].last_date.len(), 10);
        // Bo hasn't sent anything.
        assert!(recent_payees(&conn, &bo).unwrap().is_empty());
    }

    #[test]
    fn a_guardian_taking_money_back_is_not_a_payee_of_the_child() {
        let (mut conn, admin, _, _, _) = world();
        let pat =
            admin::create_customer(&mut conn, &admin, "Pat Doe", "1980-01-01", "1593", usd(100)).unwrap();
        let kid = admin::open_youth_account(
            &mut conn,
            &admin,
            CardAndPin { card_number: &pat.card_number, pin: "1593" },
            "Kid Doe",
            "2014-06-06",
            "2580",
            usd(50),
        )
        .unwrap();
        let p = auth::login_customer(&mut conn, &pat.card_number, "1593").unwrap();
        let k = auth::login_customer(&mut conn, &kid.card_number, "2580").unwrap();
        crate::family::move_money(
            &mut conn,
            &p,
            &kid.account_number,
            crate::family::Direction::FromChild,
            usd(5),
        )
        .unwrap();
        assert!(recent_payees(&conn, &k).unwrap().is_empty());
        // The child's own transfer to the parent does count.
        transfer(&mut conn, &k, &pat.account_number, usd(1)).unwrap();
        assert_eq!(recent_payees(&conn, &k).unwrap()[0].initials, "P. D.");
    }

    #[test]
    fn a_teller_can_approve_more_than_the_daily_limit_for_today_only() {
        let (mut conn, admin, _, ann, _) = world();
        deposit(&mut conn, &ann, &[(d(50), 20)]).unwrap(); // balance $2,000
        // Over the $1,000 limit: refused, and told a teller can approve more.
        let err = check_withdrawal(&conn, &ann, usd(1100)).unwrap_err();
        assert!(matches!(err, AtmError::LimitExceeded { see_teller: true, .. }));
        assert!(err.to_string().contains("please see a teller inside the branch"));
        // Teller approves $200 more for today; the customer sees it.
        admin::raise_limit_today(&mut conn, &admin, ann.account_number(), Limit::Withdrawal, usd(200))
            .unwrap();
        let st = limits(&conn, &ann).unwrap().into_iter().find(|s| s.limit == Limit::Withdrawal).unwrap();
        assert_eq!((st.per_day, st.approved_today, st.remaining_today), (usd(1000), usd(200), usd(1200)));
        // $1,100 in $50s (22 bills; in $20s it would be 55, over the 40-bill cap).
        withdraw(&mut conn, &ann, usd(1100), BillChoice::Only(d(50))).unwrap();
        assert!(matches!(
            check_withdrawal(&conn, &ann, usd(120)),
            Err(AtmError::LimitExceeded { remaining, .. }) if remaining == usd(100)
        ));
        // Other limits are untouched by a withdrawal approval.
        let st = limits(&conn, &ann).unwrap().into_iter().find(|s| s.limit == Limit::Deposit).unwrap();
        assert_eq!(st.approved_today, Cents::ZERO);
        // At most $4,000 extra per account per day, and never zero.
        let raise = |conn: &mut Atm, n: u32| {
            admin::raise_limit_today(conn, &admin, ann.account_number(), Limit::Withdrawal, usd(n))
        };
        assert!(matches!(raise(&mut conn, 3_801), Err(AtmError::NotAllowed(_))));
        raise(&mut conn, 3_800).unwrap();
        assert!(raise(&mut conn, 1).is_err());
        assert!(raise(&mut conn, 0).is_err());
        // Logged with who approved and how much.
        let (actor, detail, usd_cents): (String, String, i64) = conn
            .query_row(
                "SELECT actor, detail, usd_cents FROM audit_log WHERE action = 'withdrawal_limit_raised' ORDER BY seq LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(actor, admin.actor());
        assert_eq!(detail, "daily withdrawal limit raised by $200.00 for today; customer at the counter");
        assert_eq!(usd_cents, 20_000);
        assert_eq!(admin::verify_integrity(&mut conn, &admin).unwrap().accounts_checked, 2);
    }

    #[test]
    fn youth_and_other_bank_accounts_cannot_have_limits_raised() {
        let (mut conn, admin, _, _, _) = world();
        let pat =
            admin::create_customer(&mut conn, &admin, "Pat Doe", "1980-01-01", "1593", usd(10)).unwrap();
        let kid = admin::open_youth_account(
            &mut conn,
            &admin,
            CardAndPin { card_number: &pat.card_number, pin: "1593" },
            "Kid Doe",
            "2014-06-06",
            "2580",
            usd(700),
        )
        .unwrap();
        let guest = admin::register_guest_card(
            &mut conn,
            &admin,
            "Ray Park",
            "1990-02-02",
            "2468",
            usd(1500),
            Currency::Usd,
        )
        .unwrap();
        for n in [&kid.account_number, &guest.account_number] {
            assert!(matches!(
                admin::raise_limit_today(&mut conn, &admin, n, Limit::Withdrawal, usd(10)),
                Err(AtmError::NotAllowed(_))
            ));
        }
        // An over-limit guest is not sent to a teller (another bank's card).
        let ray = auth::login_customer(&mut conn, &guest.card_number, "2468").unwrap();
        assert!(matches!(
            check_withdrawal(&conn, &ray, usd(1100)),
            Err(AtmError::LimitExceeded { see_teller: false, .. })
        ));
        // Nor is a youth account (its caps belong to the guardian).
        let kid = auth::login_customer(&mut conn, &kid.card_number, "2580").unwrap();
        assert!(matches!(
            check_withdrawal(&conn, &kid, usd(600)),
            Err(AtmError::LimitExceeded { see_teller: false, .. })
        ));
    }

    #[test]
    fn our_own_accounts_are_always_us_dollars() {
        let (mut conn, admin, _, ann, _) = world();
        assert_eq!(account_info(&conn, &ann).unwrap().currency, Currency::Usd);
        let card =
            admin::create_customer(&mut conn, &admin, "Eva Roux", "1985-03-03", "3691", usd(10)).unwrap();
        let eva = auth::login_customer(&mut conn, &card.card_number, "3691").unwrap();
        assert_eq!(account_info(&conn, &eva).unwrap().currency, Currency::Usd);
    }

    #[test]
    fn guest_cards_only_withdraw_and_pay_the_atm_fee() {
        let (mut conn, admin, _, ann, _) = world();
        let card = admin::register_guest_card(
            &mut conn,
            &admin,
            "Ray Park",
            "1984-02-02",
            "2468",
            usd(400),
            Currency::Usd,
        )
        .unwrap();
        let ray = auth::login_customer(&mut conn, &card.card_number, "2468").unwrap();
        // $40 cash + $3.00 ATM fee (3%, at least $3) = $43 charged; the limit counts the cash.
        let r = withdraw(&mut conn, &ray, usd(40), BillChoice::Only(d(20))).unwrap();
        assert_eq!((r.amount, r.balance_after), (usd(43), usd(357)));
        assert_eq!(
            (r.summary[1].label.as_str(), r.summary[1].amount.as_str()),
            ("+ Other bank's ATM fee", "$3.00")
        );
        assert_eq!(r.summary[2].amount, "$43.00");
        assert_eq!(limits(&conn, &ray).unwrap()[0].remaining_today, usd(960));
        let rule = FeeRule { percent_bp: 300, minimum: usd(3) };
        assert_eq!(account_info(&conn, &ray).unwrap().atm_fee, Some(rule));
        assert_eq!(account_info(&conn, &ann).unwrap().atm_fee, None, "our own customers pay no fee");
        // Everything else is refused, before anything moves.
        let refused = |r: Result<()>| matches!(r, Err(AtmError::NotAllowed(_)));
        assert!(refused(deposit(&mut conn, &ray, &[(d(20), 1)]).map(|_| ())));
        assert!(refused(transfer(&mut conn, &ray, ann.account_number(), usd(5)).map(|_| ())));
        assert!(refused(recipient_hint(&mut conn, &ray, ann.account_number()).map(|_| ())));
        assert!(refused(change_pin(&mut conn, &ray, "2468", "9753")));
        assert!(refused(history(&conn, &ray, 0).map(|_| ())));
        // A guest card isn't a Bank of CCNY account: it can't receive transfers.
        assert!(matches!(
            transfer(&mut conn, &ann, &card.account_number, usd(5)),
            Err(AtmError::NotFound(_))
        ));
        // Nor be a guardian or get a joint holder.
        assert!(
            admin::open_youth_account(
                &mut conn,
                &admin,
                CardAndPin { card_number: &card.card_number, pin: "2468" },
                "Kid Park",
                "2015-01-01",
                "2580",
                usd(0)
            )
            .is_err()
        );
        assert!(
            admin::add_joint_holder(
                &mut conn,
                &admin,
                &card.account_number,
                CardAndPin { card_number: &card.card_number, pin: "2468" },
                "Sue Park",
                "1985-01-01",
                "1593"
            )
            .is_err()
        );
        assert_eq!(admin::verify_integrity(&mut conn, &admin).unwrap().accounts_checked, 3);
    }

    #[test]
    fn foreign_guest_card_converts_cash_plus_fee() {
        let (mut conn, admin, _, _, _) = world();
        crate::fx::set_rate(&mut conn, &admin, Currency::Krw, "1385.50").unwrap();
        let card = admin::register_guest_card(
            &mut conn,
            &admin,
            "Jin Han",
            "1990-07-07",
            "8024",
            Cents::from_dollars(100_000), // 100,000 won
            Currency::Krw,
        )
        .unwrap();
        let jin = auth::login_customer(&mut conn, &card.card_number, "8024").unwrap();
        // $20 = 27,710 won, plus two $3 minimum fees of 4,157 won each (whole won, rounded up).
        let r = withdraw(&mut conn, &jin, usd(20), BillChoice::Any).unwrap();
        assert_eq!(r.amount, Cents::from_dollars(36_024));
        assert_eq!(Currency::Krw.format(r.balance_after), "63,976 KRW");
        // Half a won can't be opened with.
        assert!(
            admin::register_guest_card(
                &mut conn,
                &admin,
                "Ken Han",
                "1990-07-07",
                "8024",
                Cents::new(150).unwrap(),
                Currency::Krw
            )
            .is_err()
        );
    }

    #[test]
    fn euro_card_without_a_fresh_rate_cannot_convert() {
        let (mut conn, admin, _, _, _) = world();
        let open = |conn: &mut Atm, balance| {
            admin::register_guest_card(conn, &admin, "Eva Roux", "1985-03-03", "3691", balance, Currency::Eur)
        };
        // With no rate, even the starting balance can't be valued: refused.
        assert!(matches!(open(&mut conn, usd(100)), Err(AtmError::NotAllowed(_))));
        let card = open(&mut conn, Cents::ZERO).unwrap();
        let eva = auth::login_customer(&mut conn, &card.card_number, "3691").unwrap();
        assert!(matches!(withdraw(&mut conn, &eva, usd(20), BillChoice::Any), Err(AtmError::NotAllowed(_))));
        assert!(matches!(deposit(&mut conn, &eva, &[(d(20), 1)]), Err(AtmError::NotAllowed(_))));
        assert_eq!(balance(&conn, &eva).unwrap(), Cents::ZERO, "nothing moved");
    }

    #[test]
    fn change_pin_needs_the_current_pin_and_a_strong_new_one() {
        let (mut conn, _, _, ann, _) = world();
        assert!(matches!(change_pin(&mut conn, &ann, "0000", "5937"), Err(AtmError::AuthFailed)));
        assert!(change_pin(&mut conn, &ann, "4821", "1234").is_err(), "weak PIN accepted");
        change_pin(&mut conn, &ann, "4821", "5937").unwrap();
        let card = ann.card_number().to_string();
        assert!(auth::login_customer(&mut conn, &card, "4821").is_err());
        assert!(auth::login_customer(&mut conn, &card, "5937").is_ok());
    }

    #[test]
    fn guessing_the_current_pin_locks_the_card_and_ends_the_session() {
        let (mut conn, _, _, ann, _) = world();
        assert!(matches!(change_pin(&mut conn, &ann, "0000", "5937"), Err(AtmError::AuthFailed)));
        assert!(matches!(change_pin(&mut conn, &ann, "1111", "5937"), Err(AtmError::AuthFailed)));
        assert!(matches!(change_pin(&mut conn, &ann, "2222", "5937"), Err(AtmError::CardLocked)));
        assert!(matches!(balance(&conn, &ann), Err(AtmError::SessionExpired)));
        let card = ann.card_number().to_string();
        assert!(matches!(auth::login_customer(&mut conn, &card, "4821"), Err(AtmError::CardLocked)));
    }

    #[test]
    fn recipient_hint_shows_initials_only() {
        let (mut conn, _, _, ann, bo) = world();
        assert_eq!(recipient_hint(&mut conn, &ann, bo.account_number()).unwrap(), "B. P.");
        assert!(recipient_hint(&mut conn, &ann, ann.account_number()).is_err());
        assert!(matches!(recipient_hint(&mut conn, &ann, "0000000001"), Err(AtmError::NotFound(_))));
    }

    #[test]
    fn withdraw_moves_money_and_bills_and_gives_a_receipt() {
        let (mut conn, _, handler, ann, _) = world();
        let r = withdraw(&mut conn, &ann, usd(100), BillChoice::Only(d(20))).unwrap();
        assert_eq!((r.balance_after, r.bills.clone()), (usd(900), vec![(d(20), 5)]));
        assert!(r.account.starts_with("******") && r.reference > 0);
        assert!(cash::view(&conn, &handler).unwrap().bills.contains(&(d(20), 95)));
    }

    #[test]
    fn cannot_withdraw_more_than_balance() {
        let (mut conn, _, _, _, bo) = world();
        let err = withdraw(&mut conn, &bo, usd(60), BillChoice::Only(d(20))).unwrap_err();
        assert!(matches!(err, AtmError::InsufficientFunds));
        assert_eq!(balance(&conn, &bo).unwrap(), usd(50));
    }

    #[test]
    fn daily_limit_is_cumulative() {
        let (mut conn, _, _, ann, _) = world();
        deposit(&mut conn, &ann, &[(d(50), 10)]).unwrap(); // balance $1,500
        withdraw(&mut conn, &ann, usd(800), BillChoice::Only(d(20))).unwrap();
        let err = withdraw(&mut conn, &ann, usd(220), BillChoice::Only(d(20))).unwrap_err();
        assert!(matches!(err, AtmError::LimitExceeded { remaining, .. } if remaining == usd(200)));
        withdraw(&mut conn, &ann, usd(200), BillChoice::Only(d(20))).unwrap(); // exactly to the $1,000 limit
        assert_eq!(balance(&conn, &ann).unwrap(), usd(500));
    }

    #[test]
    fn missing_denomination_is_rejected_and_alternatives_are_named() {
        let (mut conn, _, _, ann, _) = world();
        match withdraw(&mut conn, &ann, usd(100), BillChoice::Only(d(100))) {
            Err(AtmError::DenominationUnavailable { available, mixed_possible }) => {
                assert_eq!(available, vec![20, 50]);
                assert!(mixed_possible);
            }
            other => panic!("expected DenominationUnavailable, got {:?}", other.err()),
        }
        assert_eq!(balance(&conn, &ann).unwrap(), usd(1000), "a rejected withdrawal must not debit");
    }

    #[test]
    fn more_than_40_bills_is_refused_without_a_debit() {
        let (mut conn, _, _, ann, _) = world();
        let err = withdraw(&mut conn, &ann, usd(205), BillChoice::Only(d(5))).unwrap_err();
        assert!(matches!(err, AtmError::TooManyBills { max: 40 }));
        assert_eq!(balance(&conn, &ann).unwrap(), usd(1000));
    }

    #[test]
    fn mixed_bills_withdrawal() {
        let (mut conn, _, _, ann, _) = world();
        let quote = quote_withdrawal(&conn, &ann, usd(120), BillChoice::Prefer(d(50))).unwrap();
        assert_eq!(quote, vec![(d(50), 2), (d(20), 1)]);
        let r = withdraw(&mut conn, &ann, usd(120), BillChoice::Prefer(d(50))).unwrap();
        assert_eq!(r.bills, quote);
    }

    #[test]
    fn amount_must_be_payable() {
        let (mut conn, _, _, ann, _) = world();
        assert!(withdraw(&mut conn, &ann, usd(70), BillChoice::Only(d(20))).is_err());
        assert!(withdraw(&mut conn, &ann, Cents::ZERO, BillChoice::Only(d(20))).is_err());
        assert!(withdraw(&mut conn, &ann, Cents::parse("20.50").unwrap(), BillChoice::Any).is_err());
    }

    #[test]
    fn deposit_credits_account_and_respects_the_daily_limit() {
        let (mut conn, _, handler, _, bo) = world();
        let r = deposit(&mut conn, &bo, &[(d(20), 5), (d(100), 2)]).unwrap();
        assert_eq!((r.amount, r.balance_after), (usd(300), usd(350)));
        assert!(cash::view(&conn, &handler).unwrap().bills.contains(&(d(100), 2)));
        assert!(matches!(deposit(&mut conn, &bo, &[(d(100), 98)]), Err(AtmError::LimitExceeded { .. })));
        assert!(deposit(&mut conn, &bo, &[(d(100), 97)]).is_ok());
        assert!(deposit(&mut conn, &bo, &[]).is_err());
    }

    #[test]
    fn transfer_moves_money_exactly_once() {
        let (mut conn, _, _, ann, bo) = world();
        transfer(&mut conn, &ann, bo.account_number(), Cents::parse("250.75").unwrap()).unwrap();
        assert_eq!(balance(&conn, &ann).unwrap(), Cents::parse("749.25").unwrap());
        assert_eq!(balance(&conn, &bo).unwrap(), Cents::parse("300.75").unwrap());
    }

    #[test]
    fn transfer_validates_target_funds_and_limit() {
        let (mut conn, _, _, ann, bo) = world();
        let ann_no = ann.account_number().to_string();
        assert!(matches!(transfer(&mut conn, &ann, "0000000000", usd(1)), Err(AtmError::NotFound(_))));
        assert!(transfer(&mut conn, &ann, &ann_no, usd(1)).is_err());
        assert!(transfer(&mut conn, &ann, "12345", usd(1)).is_err());
        assert!(matches!(transfer(&mut conn, &bo, &ann_no, usd(51)), Err(AtmError::InsufficientFunds)));
        assert!(transfer(&mut conn, &bo, &ann_no, Cents::ZERO).is_err());
    }

    #[test]
    fn hunting_for_account_numbers_ends_the_session() {
        let (mut conn, _, _, ann, _) = world();
        assert!(transfer(&mut conn, &ann, "0000000001", usd(1)).is_err());
        assert!(transfer(&mut conn, &ann, "0000000002", usd(1)).is_err());
        assert!(matches!(transfer(&mut conn, &ann, "0000000003", usd(1)), Err(AtmError::SessionExpired)));
        assert!(matches!(balance(&conn, &ann), Err(AtmError::SessionExpired)));
    }

    #[test]
    fn history_shows_only_my_transactions_and_incoming_transfers() {
        let (mut conn, _, _, ann, bo) = world();
        withdraw(&mut conn, &ann, usd(40), BillChoice::Only(d(20))).unwrap();
        transfer(&mut conn, &ann, bo.account_number(), usd(10)).unwrap();
        assert_eq!(history(&conn, &ann, 0).unwrap().len(), 2);
        let bo_rows = history(&conn, &bo, 0).unwrap();
        assert_eq!(bo_rows.len(), 1, "Bo sees the incoming transfer, not Ann's withdrawal");
        assert_eq!(bo_rows[0].action, "transfer");
    }

    #[test]
    fn every_operation_keeps_the_ledger_consistent() {
        let (mut conn, _, _, ann, bo) = world();
        withdraw(&mut conn, &ann, usd(40), BillChoice::Only(d(20))).unwrap();
        deposit(&mut conn, &bo, &[(d(20), 1)]).unwrap();
        transfer(&mut conn, &ann, bo.account_number(), usd(10)).unwrap();
        let report = audit::verify(&conn).unwrap();
        assert!(report.entries > 5 && report.accounts_checked == 2);
    }

    #[test]
    fn lowering_a_limit_takes_effect_immediately() {
        let (mut conn, admin, _, ann, _) = world();
        admin::set_limit(&mut conn, &admin, Limit::Withdrawal, usd(60)).unwrap();
        assert!(withdraw(&mut conn, &ann, usd(80), BillChoice::Only(d(20))).is_err());
        assert!(withdraw(&mut conn, &ann, usd(60), BillChoice::Only(d(20))).is_ok());
    }
}
