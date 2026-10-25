//! Which bills to pay out. Pure math: no DB, no sessions.
//!
//! Three ways to choose bills:
//!   Only(d)   - spec 5.1 default: all in bill `d`, or reject and list the
//!               bills that could pay it.
//!   Prefer(d) - as many `d` as possible, the rest in the fewest other bills.
//!               e.g. $230 prefer $50 -> 4 x $50 + $20 + $10.
//!   Any       - fewest bills overall (also used for the handler's reset).
//!
//! Plans only ever use bills the machine actually holds (stock-aware), so a
//! plan can't fail halfway through dispensing. A customer withdrawal is also
//! capped at `MAX_BILLS` bills, like a real dispenser: a bigger payout takes
//! two withdrawals.

use crate::error::{AtmError, Result};
use crate::money::{Cents, Denomination};

/// How the customer wants to be paid.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BillChoice {
    Only(Denomination),
    Prefer(Denomination),
    Any,
}

/// (bill, count) pairs, largest bill first, counts > 0.
pub type Plan = Vec<(Denomination, i64)>;

/// Smallest bill is $5: amounts are counted in $5 units.
const UNIT_CENTS: i64 = 500;
/// Planning cap: $200,000 (more than the machine can ever hold).
const MAX_UNITS: i64 = 40_000;
/// Most bills one customer withdrawal pays out (a typical dispenser
/// setting), so one withdrawal is at most 40 x $100 = $4,000.
pub const MAX_BILLS: i64 = 40;

/// Plan a payout of `amount` from `stock` (bill, count available), with no
/// bill cap (the cash handler's reset).
pub fn plan(stock: &[(Denomination, i64)], amount: Cents, choice: BillChoice) -> Result<Plan> {
    plan_within(stock, amount, choice, i64::MAX)
}

/// Plan a customer withdrawal: as `plan`, but at most `MAX_BILLS` bills.
/// "Mostly" a bill then means as many of it as fit under the cap.
pub fn plan_withdrawal(stock: &[(Denomination, i64)], amount: Cents, choice: BillChoice) -> Result<Plan> {
    plan_within(stock, amount, choice, MAX_BILLS)
}

/// Plan a payout with at most `max_bills` bills; on failure, say which bills could pay it.
fn plan_within(
    stock: &[(Denomination, i64)],
    amount: Cents,
    choice: BillChoice,
    max_bills: i64,
) -> Result<Plan> {
    let units = to_units(amount)?;
    let fits = |plan: &Plan| count(plan) <= max_bills;
    // One bill type that needs too many bills: refuse before looking at stock.
    if let BillChoice::Only(d) = choice
        && d.bills_for(amount).is_some_and(|need| need > max_bills)
    {
        return Err(AtmError::TooManyBills { max: max_bills });
    }
    let found = match choice {
        BillChoice::Only(d) => single(stock, amount, d),
        BillChoice::Prefer(d) => preferred(stock, units, d, max_bills),
        BillChoice::Any => fewest(stock, units),
    };
    if let Some(plan) = found.filter(fits) {
        return Ok(plan);
    }
    // The machine holds the money, but not in few enough bills.
    let mixed = fewest(stock, units);
    if mixed.as_ref().is_some_and(|plan| !fits(plan)) {
        return Err(AtmError::TooManyBills { max: max_bills });
    }
    Err(AtmError::DenominationUnavailable {
        available: singles(stock, amount, max_bills),
        mixed_possible: mixed.is_some(),
    })
}

/// Bills that could pay `amount` on their own within `max_bills` (what the
/// spec says to tell the customer).
fn singles(stock: &[(Denomination, i64)], amount: Cents, max_bills: i64) -> Vec<u32> {
    let mut out: Vec<u32> = stock
        .iter()
        .filter(|&&(d, have)| {
            d.bills_for(amount).is_some_and(|need| need > 0 && need <= max_bills && have >= need)
        })
        .map(|(d, _)| d.dollars())
        .collect();
    out.sort_unstable();
    out
}

/// Amount in $5 units; refuses zero, non-multiples of $5 and amounts over the planning cap.
fn to_units(amount: Cents) -> Result<i64> {
    if amount.is_zero() || amount.as_i64() % UNIT_CENTS != 0 {
        return Err(AtmError::InvalidInput("cash amounts must be a multiple of $5"));
    }
    let units = amount.as_i64() / UNIT_CENTS;
    if units > MAX_UNITS {
        return Err(AtmError::InvalidInput("amount is too large for this machine"));
    }
    Ok(units)
}

/// One bill's value in $5 units.
fn units_of(d: Denomination) -> i64 {
    d.value().as_i64() / UNIT_CENTS
}

/// The whole amount in bill `d`, if it divides evenly and enough are in stock.
fn single(stock: &[(Denomination, i64)], amount: Cents, d: Denomination) -> Option<Plan> {
    let need = d.bills_for(amount)?;
    let have = stock.iter().find(|(s, _)| *s == d).map_or(0, |(_, n)| *n);
    (need > 0 && have >= need).then(|| vec![(d, need)])
}

/// Max bills of `d`, then fewest of the rest; at most `max_bills` in all.
fn preferred(stock: &[(Denomination, i64)], units: i64, d: Denomination, max_bills: i64) -> Option<Plan> {
    let others: Vec<_> = stock.iter().copied().filter(|(s, _)| *s != d).collect();
    let table = MinBills::build(&others, units);
    let have = stock.iter().find(|(s, _)| *s == d).map_or(0, |(_, n)| *n);
    let du = units_of(d);
    let max_p = have.min(units / du).min(max_bills);
    // Try the most preferred bills first; first remainder that fits wins.
    (0..=max_p).rev().find_map(|p| {
        let mut plan = table.reconstruct(units - p * du)?;
        if p > 0 {
            plan.push((d, p));
        }
        (count(&plan) <= max_bills).then(|| sorted(plan))
    })
}

/// Total bills in a plan.
fn count(plan: &Plan) -> i64 {
    plan.iter().map(|&(_, n)| n).sum()
}

/// Fewest bills overall from the stock, largest bill first.
fn fewest(stock: &[(Denomination, i64)], units: i64) -> Option<Plan> {
    MinBills::build(stock, units).reconstruct(units).map(sorted)
}

/// Sort a plan largest bill first.
fn sorted(mut plan: Plan) -> Plan {
    plan.sort_by_key(|&(d, _)| std::cmp::Reverse(d));
    plan
}

/// Bounded "fewest bills for every amount 0..=max" table.
/// Stock is split into 1, 2, 4, ... bundles (binary splitting), turning it
/// into a small 0/1 knapsack: ~75 bundles x amount, fast and exact.
struct MinBills {
    items: Vec<(Denomination, i64)>, // (bill, bundle size)
    best: Vec<i64>,                  // fewest bills to make w units (i64::MAX = impossible)
    take: Vec<Vec<bool>>,            // take[i][w]: bundle i used in best plan for w
}

impl MinBills {
    /// Fill the table for every amount up to `max_units` from the given stock.
    fn build(stock: &[(Denomination, i64)], max_units: i64) -> MinBills {
        let w_max = max_units as usize;
        let mut items = Vec::new();
        for &(d, have) in stock {
            let cap = have.min(max_units / units_of(d)); // never need more than this
            let mut left = cap;
            let mut size = 1;
            while left > 0 {
                let k = size.min(left);
                items.push((d, k));
                left -= k;
                size *= 2;
            }
        }
        let mut best = vec![i64::MAX; w_max + 1];
        best[0] = 0;
        let mut take = vec![vec![false; w_max + 1]; items.len()];
        for (i, &(d, k)) in items.iter().enumerate() {
            let weight = (k * units_of(d)) as usize;
            for w in (weight..=w_max).rev() {
                let prev = best[w - weight];
                if prev != i64::MAX && prev + k < best[w] {
                    best[w] = prev + k;
                    take[i][w] = true;
                }
            }
        }
        MinBills { items, best, take }
    }

    /// The fewest-bills plan for `units`, read back from the table; None if impossible.
    fn reconstruct(&self, units: i64) -> Option<Plan> {
        let mut w = usize::try_from(units).ok()?;
        if *self.best.get(w)? == i64::MAX {
            return None;
        }
        let mut counts: Vec<(Denomination, i64)> = Vec::new();
        for i in (0..self.items.len()).rev() {
            if self.take[i][w] {
                let (d, k) = self.items[i];
                w -= (k * units_of(d)) as usize;
                match counts.iter_mut().find(|(c, _)| *c == d) {
                    Some(entry) => entry.1 += k,
                    None => counts.push((d, k)),
                }
            }
        }
        (w == 0).then_some(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u32) -> Denomination {
        Denomination::new(n).unwrap()
    }
    fn usd(n: u32) -> Cents {
        Cents::from_dollars(n)
    }
    fn full() -> Vec<(Denomination, i64)> {
        Denomination::all().map(|x| (x, 100)).collect()
    }

    #[test]
    fn only_mode_follows_the_spec() {
        assert_eq!(plan(&full(), usd(100), BillChoice::Only(d(20))).unwrap(), vec![(d(20), 5)]);
        // No $20s: rejected, and told which bills can pay.
        let stock = vec![(d(20), 0), (d(50), 10), (d(10), 10)];
        match plan(&stock, usd(100), BillChoice::Only(d(20))) {
            Err(AtmError::DenominationUnavailable { available, mixed_possible }) => {
                assert_eq!(available, vec![10, 50]);
                assert!(mixed_possible);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn prefer_mode_matches_the_groups_examples() {
        let p = |amt, pref| plan(&full(), usd(amt), BillChoice::Prefer(d(pref))).unwrap();
        assert_eq!(p(220, 50), vec![(d(50), 4), (d(20), 1)]);
        assert_eq!(p(230, 50), vec![(d(50), 4), (d(20), 1), (d(10), 1)]);
        assert_eq!(p(270, 100), vec![(d(100), 2), (d(50), 1), (d(20), 1)]);
    }

    #[test]
    fn prefer_mode_falls_back_when_the_bill_is_missing() {
        // $60, prefer $50, but no $50s and no $10s: three $20s.
        let stock = vec![(d(50), 0), (d(20), 10), (d(10), 0)];
        assert_eq!(plan(&stock, usd(60), BillChoice::Prefer(d(50))).unwrap(), vec![(d(20), 3)]);
        // $50s present but no $10 for the remainder: still three $20s.
        let stock = vec![(d(50), 5), (d(20), 10), (d(10), 0)];
        assert_eq!(plan(&stock, usd(60), BillChoice::Prefer(d(50))).unwrap(), vec![(d(20), 3)]);
    }

    #[test]
    fn stock_limits_are_respected_where_greedy_fails() {
        let stock = vec![(d(50), 1), (d(20), 3)];
        assert_eq!(plan(&stock, usd(60), BillChoice::Any).unwrap(), vec![(d(20), 3)]);
        assert!(plan(&stock, usd(70), BillChoice::Any).is_ok());
        assert!(plan(&stock, usd(80), BillChoice::Any).is_err());
    }

    #[test]
    fn withdrawals_pay_at_most_40_bills() {
        let w = |amt, choice| plan_withdrawal(&full(), usd(amt), choice);
        // Exactly 40 is fine; 41 of one bill is refused before stock is checked.
        assert_eq!(w(200, BillChoice::Only(d(5))).unwrap(), vec![(d(5), 40)]);
        assert!(matches!(w(205, BillChoice::Only(d(5))), Err(AtmError::TooManyBills { max: 40 })));
        // "Mostly $5" keeps as many $5s as fit: 36 x $5 + 3 x $100 + $20 = 40 bills.
        assert_eq!(w(500, BillChoice::Prefer(d(5))).unwrap(), vec![(d(100), 3), (d(20), 1), (d(5), 36)]);
        // Fewest bills: $4,000 is 40 x $100; $4,100 needs two withdrawals.
        assert_eq!(w(4000, BillChoice::Any).unwrap(), vec![(d(100), 40)]);
        assert!(matches!(w(4100, BillChoice::Any), Err(AtmError::TooManyBills { max: 40 })));
        // The handler's reset has no cap.
        assert_eq!(plan(&full(), usd(4100), BillChoice::Any).unwrap(), vec![(d(100), 41)]);
    }

    #[test]
    fn short_bill_lists_only_bills_within_the_cap() {
        // $300 in $10s (30 bills) but only 5 $10s: $5 would need 60 bills, so
        // only $20, $50 and $100 are named.
        let stock = vec![(d(5), 100), (d(10), 5), (d(20), 100), (d(50), 100), (d(100), 100)];
        match plan_withdrawal(&stock, usd(300), BillChoice::Only(d(10))) {
            Err(AtmError::DenominationUnavailable { available, mixed_possible }) => {
                assert_eq!(available, vec![20, 50, 100]);
                assert!(mixed_possible);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_amounts_no_bill_can_make() {
        assert!(plan(&full(), Cents::parse("12.50").unwrap(), BillChoice::Any).is_err());
        assert!(plan(&full(), usd(13), BillChoice::Any).is_err());
        assert!(plan(&full(), Cents::ZERO, BillChoice::Any).is_err());
    }
}
