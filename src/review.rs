//! Suspicious-activity holds: patterns a real bank would stop and confirm
//! with the customer in person.
//!
//! A withdrawal or transfer that matches a rule is refused and a hold is logged. No money
//! leaves the account (withdrawals, transfers, guardian moves) until a teller checks ID and
//! releases it; deposits, balance and history still work.
//!
//! STRIDE (Tampering): "on hold" means the newest hold row in the HMAC-chained log is
//! `hold_placed`, not a table flag, so editing the database can't clear it.
//! STRIDE (Information Disclosure): the customer only sees "unusual activity"; the rule and
//! its threshold are for staff only.
//!
//! Counting restarts after the customer last saw a teller (hold release or approved limit
//! raise); after that, the amount rules (4 to 6) are off for that account until tomorrow.

use crate::Atm;
use crate::audit::{self, Action, Entry};
use crate::auth::AdminSession;
use crate::db::{self, Number};
use crate::error::{AtmError, Result};
use crate::money::Cents;
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};

/// Rule 1: the 4th withdrawal within an hour.
const WITHDRAWALS_PER_HOUR: i64 = 3;
/// Rule 2: the 4th transfer out within an hour.
const TRANSFERS_PER_HOUR: i64 = 3;
/// Rule 3: a transfer to a 3rd different account within 24 hours.
const PAYEES_PER_DAY: i64 = 2;
/// Rule 4: a transfer this large to an account not paid on an earlier day.
const BIG_NEW_PAYEE: Cents = Cents::from_dollars(1_000);
/// Rule 5: this much out within an hour of this much coming in by transfer.
const PASS_THROUGH: Cents = Cents::from_dollars(500);
/// Rule 6: one move of at least this much that takes 90% or more of the balance.
const EMPTYING: Cents = Cents::from_dollars(900);

/// Who wrote a hold row: the bank's own check, not a person.
const ACTOR: &str = "system:activity-check";

/// The money movement being attempted.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Move {
    Withdrawal,
    Transfer { to: i64 },
}

/// Outcome of `screen`. On `Held`, the caller commits (to keep the hold row)
/// and returns `AtmError::OnHold`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Screen {
    Clear,
    Held,
}

/// Why an account is on hold, if it is (the newest hold row decides).
pub(crate) fn hold_reason(conn: &Connection, account_id: i64) -> Result<Option<String>> {
    let newest: Option<(String, String)> = conn
        .query_row(
            "SELECT action, detail FROM audit_log
             WHERE account_id = ?1 AND action IN ('hold_placed', 'hold_released')
             ORDER BY seq DESC LIMIT 1",
            params![account_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(newest.filter(|(action, _)| action == Action::HoldPlaced.as_str()).map(|(_, detail)| detail))
}

/// Refuse if the account is on hold. Read-only; safe in any precheck.
pub(crate) fn check_not_held(conn: &Connection, account_id: i64) -> Result<()> {
    match hold_reason(conn, account_id)? {
        Some(_) => Err(AtmError::OnHold),
        None => Ok(()),
    }
}

/// Run the rules on an attempt (`usd` = US-dollar value, `amount` = in the
/// account's currency). If one matches, write the hold and return `Held`.
/// Call inside the operation's transaction, after its other checks pass.
pub(crate) fn screen(
    conn: &Connection,
    account_id: i64,
    mv: Move,
    usd: Cents,
    amount: Cents,
) -> Result<Screen> {
    check_not_held(conn, account_id)?;
    let Some(reason) = matched_rule(conn, account_id, mv, usd, amount)? else {
        return Ok(Screen::Clear);
    };
    let (what, to) = match mv {
        Move::Withdrawal => ("withdrawal", None),
        Move::Transfer { to } => ("transfer", Some(to)),
    };
    audit::append(
        conn,
        &Entry {
            actor: ACTOR,
            action: Action::HoldPlaced,
            account_id: Some(account_id),
            counterparty_id: to,
            amount: Some(amount),
            usd: Some(usd),
            detail: &format!("{reason}; refused {what} of {usd}"),
        },
    )?;
    Ok(Screen::Held)
}

/// The first rule this attempt matches, as text for the teller.
fn matched_rule(
    conn: &Connection,
    id: i64,
    mv: Move,
    usd: Cents,
    amount: Cents,
) -> Result<Option<&'static str>> {
    // Count only rows after the last teller contact (log order, so rows in
    // the same second as a release don't count) and inside the time window.
    let contact = last_teller_contact(conn, id)?;
    let after = contact.as_ref().map_or(0, |(seq, _)| *seq);
    let since = |minutes: i64| -> String {
        (Utc::now() - chrono::Duration::minutes(minutes)).format("%Y-%m-%dT%H:%M:%SZ").to_string()
    };
    // Rules 1-3: how often.
    match mv {
        Move::Withdrawal => {
            if count_out(conn, id, Action::Withdrawal, &since(60), after)? >= WITHDRAWALS_PER_HOUR {
                return Ok(Some("rule 1: 4th withdrawal within an hour"));
            }
        }
        Move::Transfer { to } => {
            if count_out(conn, id, Action::Transfer, &since(60), after)? >= TRANSFERS_PER_HOUR {
                return Ok(Some("rule 2: 4th transfer within an hour"));
            }
            let other_payees: i64 = conn.query_row(
                "SELECT COUNT(DISTINCT counterparty_id) FROM audit_log
                 WHERE account_id = ?1 AND action = 'transfer' AND counterparty_id != ?2
                   AND ts >= ?3 AND seq > ?4",
                params![id, to, since(24 * 60), after],
                |r| r.get(0),
            )?;
            if other_payees >= PAYEES_PER_DAY {
                return Ok(Some("rule 3: transfer to a 3rd different account within 24 hours"));
            }
        }
    }
    // Rules 4-6: how much. Off once a teller has seen the customer today.
    let today = audit::bank_day_start_utc()?;
    if contact.as_ref().is_some_and(|(_, ts)| *ts >= today) {
        return Ok(None);
    }
    if let Move::Transfer { to } = mv {
        // Paid on an earlier bank day: a cent sent a minute ago doesn't count.
        let paid_before: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM audit_log
                            WHERE account_id = ?1 AND action = 'transfer' AND counterparty_id = ?2
                              AND ts < ?3)",
            params![id, to, today],
            |r| r.get(0),
        )?;
        if usd >= BIG_NEW_PAYEE && !paid_before {
            return Ok(Some("rule 4: $1,000 or more to an account not paid before today"));
        }
    }
    if usd >= PASS_THROUGH {
        let came_in: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM audit_log
                            WHERE counterparty_id = ?1 AND action = 'transfer' AND usd_cents >= ?2
                              AND ts >= ?3 AND seq > ?4)",
            params![id, PASS_THROUGH.as_i64(), since(60), after],
            |r| r.get(0),
        )?;
        if came_in {
            return Ok(Some("rule 5: $500 or more out within an hour of $500 or more coming in"));
        }
    }
    if usd >= EMPTYING {
        let balance: i64 =
            conn.query_row("SELECT balance_cents FROM accounts WHERE id = ?1", params![id], |r| r.get(0))?;
        // amount >= 90% of balance, in integers.
        if amount.as_i64().saturating_mul(10) >= balance.saturating_mul(9) {
            return Ok(Some("rule 6: one move of 90% or more of the balance"));
        }
    }
    Ok(None)
}

/// Withdrawals or transfers out of this account since `since`, after log row `after`.
fn count_out(conn: &Connection, id: i64, action: Action, since: &str, after: i64) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM audit_log WHERE account_id = ?1 AND action = ?2 AND ts >= ?3 AND seq > ?4",
        params![id, action.as_str(), since, after],
        |r| r.get(0),
    )?)
}

/// (log row, time) a teller last dealt with this account in person: a hold
/// release or an approved limit raise.
fn last_teller_contact(conn: &Connection, id: i64) -> Result<Option<(i64, String)>> {
    Ok(conn
        .query_row(
            "SELECT seq, ts FROM audit_log WHERE account_id = ?1 AND action IN
             ('hold_released', 'withdrawal_limit_raised', 'deposit_limit_raised', 'transfer_limit_raised')
             ORDER BY seq DESC LIMIT 1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

// ---------------------------------------------------------------------------
// Teller side
// ---------------------------------------------------------------------------

/// An account on hold, with what the teller needs to talk to the customer.
#[derive(Debug, Clone)]
pub struct Hold {
    pub account_number: String,
    /// Names on the account's cards (check ID against one of these).
    pub holders: Vec<String>,
    /// Which rule matched and what was refused.
    pub reason: String,
    /// When the hold was placed (UTC).
    pub since: String,
}

/// Every open account currently on hold, oldest first.
pub fn holds(atm: &Atm, session: &AdminSession) -> Result<Vec<Hold>> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    let mut stmt = conn.prepare(
        "SELECT a.id, a.account_lookup, a.account_enc, l.detail, l.ts
         FROM audit_log l JOIN accounts a ON a.id = l.account_id
         WHERE l.action = 'hold_placed' AND a.closed = 0
           AND l.seq = (SELECT MAX(seq) FROM audit_log
                        WHERE account_id = l.account_id AND action IN ('hold_placed', 'hold_released'))
         ORDER BY l.seq",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let lookup: String = r.get(1)?;
        out.push(Hold {
            account_number: db::open_number(Number::Account, &lookup, &r.get::<_, Vec<u8>>(2)?)?,
            holders: holder_names(conn, r.get(0)?)?,
            reason: r.get(3)?,
            since: r.get(4)?,
        });
    }
    Ok(out)
}

/// Decrypted names of every card holder on the account, oldest card first.
fn holder_names(conn: &Connection, account_id: i64) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT card_lookup, name_enc FROM cards WHERE account_id = ?1 ORDER BY id")?;
    let mut rows = stmt.query(params![account_id])?;
    let mut names = Vec::new();
    while let Some(r) = rows.next()? {
        names.push(db::holder_name(&r.get::<_, String>(0)?, &r.get::<_, Vec<u8>>(1)?)?);
    }
    Ok(names)
}

/// Release a hold after checking the customer's ID and confirming the
/// activity with them in person. Logged with the teller's name.
pub fn release_hold(atm: &mut Atm, session: &AdminSession, account_number: &str) -> Result<()> {
    atm.admit(session)?;
    let tx = atm.begin()?;
    let id = db::account_id(&tx, account_number)?;
    if hold_reason(&tx, id)?.is_none() {
        return Err(AtmError::NotAllowed("this account is not on hold"));
    }
    audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action: Action::HoldReleased,
            account_id: Some(id),
            counterparty_id: None,
            amount: None,
            usd: None,
            detail: "customer's ID checked and activity confirmed at the counter",
        },
    )?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin;
    use crate::auth::testing::setup;
    use crate::auth::{self, CustomerSession};
    use crate::cash;
    use crate::customer;
    use crate::db::Limit;
    use crate::dispense::BillChoice;
    use crate::money::Denomination;

    fn usd(n: u32) -> Cents {
        Cents::from_dollars(n)
    }
    fn twenties() -> BillChoice {
        BillChoice::Only(Denomination::new(20).unwrap())
    }

    /// Machine with $4,000 in twenties and a teller; `open` adds a customer.
    fn bank() -> (Atm, AdminSession) {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, handler) = setup(&mut atm);
        cash::restock(&mut atm, &handler, Denomination::new(20).unwrap(), 200).unwrap();
        (atm, admin)
    }
    fn open(atm: &mut Atm, admin: &AdminSession, name: &str, pin: &str, dollars: u32) -> CustomerSession {
        let card = admin::create_customer(atm, admin, name, "1980-01-01", pin, usd(dollars)).unwrap();
        auth::login_customer(atm, &card.card_number, pin).unwrap()
    }
    fn reason(atm: &Atm, admin: &AdminSession) -> String {
        let all = holds(atm, admin).unwrap();
        assert_eq!(all.len(), 1);
        all[0].reason.clone()
    }

    #[test]
    fn a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold() {
        let (mut atm, admin) = bank();
        let ann = open(&mut atm, &admin, "Ann Lee", "4821", 1_000);
        for _ in 0..3 {
            customer::withdraw(&mut atm, &ann, usd(20), twenties()).unwrap();
        }
        let err = customer::withdraw(&mut atm, &ann, usd(20), twenties()).unwrap_err();
        assert!(matches!(err, AtmError::OnHold));
        // The customer is told to see a teller, not which rule matched.
        assert!(err.to_string().contains("see a teller") && !err.to_string().contains("rule"));
        assert_eq!(customer::balance(&atm, &ann).unwrap(), usd(940));
        // The teller sees who, why and what was refused.
        let all = holds(&atm, &admin).unwrap();
        assert_eq!(all[0].account_number, ann.account_number());
        assert_eq!(all[0].holders, vec!["Ann Lee".to_string()]);
        assert_eq!(all[0].reason, "rule 1: 4th withdrawal within an hour; refused withdrawal of $20.00");
        // While held: no money out, but deposits and the balance screen work.
        assert!(customer::account_info(&atm, &ann).unwrap().on_hold);
        assert!(matches!(customer::check_withdrawal(&atm, &ann, usd(20)), Err(AtmError::OnHold)));
        let bo = open(&mut atm, &admin, "Bo Kim", "7305", 50);
        assert!(matches!(
            customer::transfer(&mut atm, &ann, bo.account_number(), usd(5)),
            Err(AtmError::OnHold)
        ));
        customer::deposit(&mut atm, &ann, &[(Denomination::new(20).unwrap(), 1)]).unwrap();
        // Release: logged with the teller's name; counting starts again.
        release_hold(&mut atm, &admin, ann.account_number()).unwrap();
        assert!(matches!(release_hold(&mut atm, &admin, ann.account_number()), Err(AtmError::NotAllowed(_))));
        assert!(holds(&atm, &admin).unwrap().is_empty());
        assert!(!customer::account_info(&atm, &ann).unwrap().on_hold);
        customer::withdraw(&mut atm, &ann, usd(20), twenties()).unwrap();
        let actors: String = atm
            .conn
            .query_row(
                "SELECT group_concat(actor, ' ') FROM audit_log WHERE action IN ('hold_placed', 'hold_released')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(actors, format!("system:activity-check {}", admin.actor()));
        assert_eq!(admin::verify_integrity(&mut atm, &admin).unwrap().accounts_checked, 2);
    }

    #[test]
    fn many_transfers_or_many_payees_are_held() {
        let (mut atm, admin) = bank();
        let ann = open(&mut atm, &admin, "Ann Lee", "4821", 1_000);
        let bo = open(&mut atm, &admin, "Bo Kim", "7305", 10);
        for _ in 0..3 {
            customer::transfer(&mut atm, &ann, bo.account_number(), usd(1)).unwrap();
        }
        assert!(matches!(
            customer::transfer(&mut atm, &ann, bo.account_number(), usd(1)),
            Err(AtmError::OnHold)
        ));
        assert!(reason(&atm, &admin).starts_with("rule 2:"));

        let (mut atm, admin) = bank();
        let ann = open(&mut atm, &admin, "Ann Lee", "4821", 1_000);
        let eve = open(&mut atm, &admin, "Eve Lin", "2468", 1_000);
        let payees: Vec<_> = ["Bo Kim", "Cy Ray", "Di Fox"]
            .iter()
            .zip(["7305", "5937", "3691"])
            .map(|(name, pin)| open(&mut atm, &admin, name, pin, 10))
            .collect();
        let pay = |atm: &mut Atm, from: &CustomerSession, to: usize| {
            customer::transfer(atm, from, payees[to].account_number(), usd(5))
        };
        // Paying an account already paid today again is fine...
        for to in [0, 1, 0] {
            pay(&mut atm, &ann, to).unwrap();
        }
        // ...a 3rd different account in 24 hours is not.
        pay(&mut atm, &eve, 0).unwrap();
        pay(&mut atm, &eve, 1).unwrap();
        assert!(matches!(pay(&mut atm, &eve, 2), Err(AtmError::OnHold)));
        assert!(reason(&atm, &admin).starts_with("rule 3:"));
    }

    #[test]
    fn unusual_amounts_are_held() {
        // Rule 4: $1,000+ to an account not paid before today.
        let (mut atm, admin) = bank();
        let ann = open(&mut atm, &admin, "Ann Lee", "4821", 5_000);
        let bo = open(&mut atm, &admin, "Bo Kim", "7305", 10);
        assert!(matches!(
            customer::transfer(&mut atm, &ann, bo.account_number(), usd(1_000)),
            Err(AtmError::OnHold)
        ));
        assert!(reason(&atm, &admin).starts_with("rule 4:"));
        assert_eq!(customer::balance(&atm, &bo).unwrap(), usd(10)); // nothing moved
        // A cent sent first doesn't make Bo "paid before".
        let (mut atm, admin) = bank();
        let ann = open(&mut atm, &admin, "Ann Lee", "4821", 5_000);
        let bo = open(&mut atm, &admin, "Bo Kim", "7305", 10);
        customer::transfer(&mut atm, &ann, bo.account_number(), Cents::new(1).unwrap()).unwrap();
        assert!(matches!(
            customer::transfer(&mut atm, &ann, bo.account_number(), usd(4_000)),
            Err(AtmError::OnHold)
        ));
        assert!(reason(&atm, &admin).starts_with("rule 4:"));

        // Rule 5: $500+ in by transfer, then $500+ straight out.
        let (mut atm, admin) = bank();
        let ann = open(&mut atm, &admin, "Ann Lee", "4821", 5_000);
        let bo = open(&mut atm, &admin, "Bo Kim", "7305", 10);
        customer::transfer(&mut atm, &ann, bo.account_number(), usd(600)).unwrap();
        assert!(matches!(customer::withdraw(&mut atm, &bo, usd(500), twenties()), Err(AtmError::OnHold)));
        assert!(reason(&atm, &admin).starts_with("rule 5:"));

        // Rule 6: one move of 90% or more of the balance.
        let (mut atm, admin) = bank();
        let ann = open(&mut atm, &admin, "Ann Lee", "4821", 1_000);
        let bo = open(&mut atm, &admin, "Bo Kim", "7305", 10);
        assert!(matches!(
            customer::transfer(&mut atm, &ann, bo.account_number(), usd(950)),
            Err(AtmError::OnHold)
        ));
        assert!(reason(&atm, &admin).starts_with("rule 6:"));
    }

    #[test]
    fn once_a_teller_has_seen_the_customer_today_amount_rules_are_off() {
        let (mut atm, admin) = bank();
        let ann = open(&mut atm, &admin, "Ann Lee", "4821", 1_000);
        let bo = open(&mut atm, &admin, "Bo Kim", "7305", 10);
        // The teller approved a larger amount at the counter (ID checked).
        admin::raise_limit_today(&mut atm, &admin, ann.account_number(), Limit::Transfer, usd(100)).unwrap();
        customer::transfer(&mut atm, &ann, bo.account_number(), usd(950)).unwrap();
        assert!(holds(&atm, &admin).unwrap().is_empty());
    }
}
