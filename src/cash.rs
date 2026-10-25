//! The machine's physical cash (bill counts per denomination).
//!
//!   pub fns       - Cash Handler actions; each needs `&HandlerSession`
//!   pub(crate) fns - helpers `customer.rs` calls inside its own transaction
//!
//! How the spec is read:
//!   * Restock = top up, never past CASH_MAXIMUM.
//!   * Customer deposits may push it above the maximum (up to PHYSICAL_CAPACITY).
//!   * "Withdraw to reset to the cash maximum" = remove only what's ABOVE it.
//!
//! STRIDE (Elevation of Privilege / insider): a handler can never empty the
//! machine through this interface, and every bill moved is logged with their name.

use crate::Atm;
use crate::audit::{self, Action, Entry};
use crate::auth::HandlerSession;
use crate::db::{self, CASH_MAXIMUM, Limit};
use crate::dispense::{self, BillChoice, Plan};
use crate::error::{AtmError, Result};
use crate::money::{Cents, Denomination};
use rusqlite::{Connection, params};

/// Sanity cap on bills per handler operation (typos, overflow).
const MAX_BILLS_PER_OPERATION: u32 = 10_000;
/// Warn the handler when a bill type drops below this many.
const LOW_BILL_COUNT: i64 = 20;

/// What the Cash Handler sees.
#[derive(Debug, Clone)]
pub struct Inventory {
    /// (bill, count), smallest bill first.
    pub bills: Vec<(Denomination, i64)>,
    pub total: Cents,
    /// Cash maximum: restocks stop here.
    pub maximum: Cents,
    /// Hard limit: customer deposits stop here.
    pub physical_capacity: Cents,
    /// One customer's daily withdrawal limit (what "low cash" is measured against).
    pub withdrawal_limit: Cents,
    /// Amount above the cash maximum (zero if at or below).
    pub over_maximum: Cents,
    /// Total is below one customer's daily withdrawal limit
    /// (spec: "take into account the customer daily withdraw maximum").
    pub low_cash: bool,
    /// Bill types running low (fewer than 20).
    pub low_bills: Vec<u32>,
}

// ---------------------------------------------------------------------------
// Internal helpers (no session; only reachable from authorised operations)
// ---------------------------------------------------------------------------

/// Current stock, smallest bill first, plus the total value.
pub(crate) fn stock(conn: &Connection) -> Result<(Vec<(Denomination, i64)>, Cents)> {
    let mut bills = Vec::new();
    let mut total = Cents::ZERO;
    for denom in Denomination::all() {
        let count: i64 = conn.query_row(
            "SELECT bill_count FROM cash_inventory WHERE denomination = ?1",
            params![denom.dollars()],
            |r| r.get(0),
        )?;
        total = total
            .checked_add(denom.times(count)?)
            .ok_or_else(|| AtmError::Internal("inventory overflow".into()))?;
        bills.push((denom, count));
    }
    Ok((bills, total))
}

/// Add bills (customer deposit or restock).
pub(crate) fn add_bills(conn: &Connection, denom: Denomination, count: i64) -> Result<()> {
    if count < 0 {
        return Err(AtmError::Internal("negative bill count".into()));
    }
    conn.execute(
        "UPDATE cash_inventory SET bill_count = bill_count + ?2 WHERE denomination = ?1",
        params![denom.dollars(), count],
    )?;
    Ok(())
}

/// Take bills; check-and-take is one atomic statement (`bill_count >= ?2`).
pub(crate) fn take_bills(conn: &Connection, denom: Denomination, count: i64) -> Result<()> {
    if count < 0 {
        return Err(AtmError::Internal("negative bill count".into()));
    }
    let changed = conn.execute(
        "UPDATE cash_inventory SET bill_count = bill_count - ?2
         WHERE denomination = ?1 AND bill_count >= ?2",
        params![denom.dollars(), count],
    )?;
    if changed == 1 { Ok(()) } else { Err(AtmError::NotAllowed("not enough bills in the machine")) }
}

/// Take every bill in a plan (all-or-nothing: caller's transaction rolls back on error).
pub(crate) fn take_plan(conn: &Connection, plan: &Plan) -> Result<()> {
    for &(d, n) in plan {
        take_bills(conn, d, n)?;
    }
    Ok(())
}

/// "3 x $50, 1 x $20" for logs and receipts.
pub fn describe(plan: &[(Denomination, i64)]) -> String {
    plan.iter()
        .filter(|(_, n)| *n > 0)
        .map(|(d, n)| format!("{n} x ${}", d.dollars()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Value of `count` bills of one type; refuses 0 or more than 10,000 bills.
fn bills_value(denom: Denomination, count: u32) -> Result<Cents> {
    if count == 0 || count > MAX_BILLS_PER_OPERATION {
        return Err(AtmError::InvalidInput("enter between 1 and 10000 bills"));
    }
    denom.times(i64::from(count))
}

/// Append one Cash Handler event to the audit log, with the value moved.
fn log(
    conn: &Connection,
    session: &HandlerSession,
    action: Action,
    value: Cents,
    detail: &str,
) -> Result<()> {
    audit::append(
        conn,
        &Entry {
            actor: &session.actor(),
            action,
            account_id: None,
            counterparty_id: None,
            amount: Some(value),
            usd: None,
            detail,
        },
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Cash Handler operations
// ---------------------------------------------------------------------------

/// "View the cumulative cash total, itemized by bill denomination."
pub fn view(atm: &Atm, session: &HandlerSession) -> Result<Inventory> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    let (bills, total) = stock(conn)?;
    let withdrawal_limit = db::get_limit(conn, Limit::Withdrawal)?;
    let low_bills = bills.iter().filter(|(_, n)| *n < LOW_BILL_COUNT).map(|(d, _)| d.dollars()).collect();
    Ok(Inventory {
        bills,
        total,
        maximum: CASH_MAXIMUM,
        physical_capacity: db::PHYSICAL_CAPACITY,
        withdrawal_limit,
        over_maximum: total.checked_sub(CASH_MAXIMUM).unwrap_or(Cents::ZERO),
        low_cash: total < withdrawal_limit,
        low_bills,
    })
}

/// Restock: add bills, never past the cash maximum. Returns the new total.
pub fn restock(atm: &mut Atm, session: &HandlerSession, denom: Denomination, count: u32) -> Result<Cents> {
    atm.admit(session)?;
    let value = bills_value(denom, count)?;
    let tx = atm.begin_for(session)?;
    let (_, total) = stock(&tx)?;
    let new_total = total.checked_add(value).ok_or(AtmError::NotAllowed("too much cash"))?;
    if new_total > CASH_MAXIMUM {
        return Err(AtmError::NotAllowed("that would put the machine over its cash maximum"));
    }
    add_bills(&tx, denom, i64::from(count))?;
    log(&tx, session, Action::CashRestocked, value, &format!("{count} x ${}", denom.dollars()))?;
    tx.commit()?;
    Ok(new_total)
}

/// Remove specific bills, never taking the machine below the cash maximum.
pub fn remove_excess(
    atm: &mut Atm,
    session: &HandlerSession,
    denom: Denomination,
    count: u32,
) -> Result<Cents> {
    atm.admit(session)?;
    let value = bills_value(denom, count)?;
    let tx = atm.begin_for(session)?;
    let (_, total) = stock(&tx)?;
    let new_total = match total.checked_sub(value) {
        Some(t) if t >= CASH_MAXIMUM => t,
        _ => return Err(AtmError::NotAllowed("you may only remove cash above the cash maximum")),
    };
    take_bills(&tx, denom, i64::from(count))?;
    log(&tx, session, Action::CashRemoved, value, &format!("{count} x ${}", denom.dollars()))?;
    tx.commit()?;
    Ok(new_total)
}

/// One-step reset: remove exactly the surplus, fewest bills, back to the maximum.
/// Returns the bills removed.
pub fn reset_to_maximum(atm: &mut Atm, session: &HandlerSession) -> Result<Plan> {
    atm.admit(session)?;
    let tx = atm.begin_for(session)?;
    let (bills, total) = stock(&tx)?;
    let surplus = total.checked_sub(CASH_MAXIMUM).unwrap_or(Cents::ZERO);
    if surplus.is_zero() {
        return Err(AtmError::NotAllowed("the machine is not above its cash maximum"));
    }
    let plan = dispense::plan(&bills, surplus, BillChoice::Any)
        .map_err(|_| AtmError::NotAllowed("no exact set of bills matches the surplus"))?;
    take_plan(&tx, &plan)?;
    log(&tx, session, Action::CashRemoved, surplus, &format!("reset: {}", describe(&plan)))?;
    tx.commit()?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testing::setup;

    fn d(n: u32) -> Denomination {
        Denomination::new(n).unwrap()
    }

    #[test]
    fn restock_is_itemised_and_capped_at_the_maximum() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (_, handler) = setup(&mut conn);
        restock(&mut conn, &handler, d(20), 100).unwrap();
        restock(&mut conn, &handler, d(100), 500).unwrap();
        let inv = view(&conn, &handler).unwrap();
        assert_eq!(inv.total, Cents::from_dollars(52_000));
        assert!(inv.bills.contains(&(d(20), 100)));
        assert!(restock(&mut conn, &handler, d(100), 500).is_err()); // would pass $100k
        restock(&mut conn, &handler, d(100), 480).unwrap(); // exactly to the max is fine
        assert_eq!(view(&conn, &handler).unwrap().total, CASH_MAXIMUM);
    }

    #[test]
    fn handler_can_only_remove_the_overflow() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (_, handler) = setup(&mut conn);
        restock(&mut conn, &handler, d(100), 1000).unwrap();
        assert!(remove_excess(&mut conn, &handler, d(100), 1).is_err());
        add_bills(&conn, d(100), 3).unwrap(); // customer deposits push it $300 over
        conn.reseal();
        assert_eq!(view(&conn, &handler).unwrap().over_maximum, Cents::from_dollars(300));
        assert!(remove_excess(&mut conn, &handler, d(100), 4).is_err());
        assert_eq!(remove_excess(&mut conn, &handler, d(100), 3).unwrap(), CASH_MAXIMUM);
    }

    #[test]
    fn reset_removes_exactly_the_surplus() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (_, handler) = setup(&mut conn);
        restock(&mut conn, &handler, d(100), 1000).unwrap();
        add_bills(&conn, d(50), 3).unwrap();
        add_bills(&conn, d(20), 2).unwrap(); // $190 over
        conn.reseal();
        let removed = reset_to_maximum(&mut conn, &handler).unwrap();
        assert_eq!(removed, vec![(d(100), 1), (d(50), 1), (d(20), 2)]);
        assert_eq!(view(&conn, &handler).unwrap().total, CASH_MAXIMUM);
        assert!(reset_to_maximum(&mut conn, &handler).is_err()); // nothing left to remove
    }

    #[test]
    fn low_cash_flags() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (_, handler) = setup(&mut conn);
        let inv = view(&conn, &handler).unwrap();
        assert!(inv.low_cash && inv.low_bills.len() == 5); // empty machine
        restock(&mut conn, &handler, d(20), 50).unwrap(); // $1,000 = default limit
        let inv = view(&conn, &handler).unwrap();
        assert!(!inv.low_cash && !inv.low_bills.contains(&20));
    }
}
