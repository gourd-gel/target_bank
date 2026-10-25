//! Money and bill denominations.
//!
//! STRIDE (Tampering): money is whole cents in an i64, never a float, and a
//! `Cents` can't be negative. "Withdraw -500" can't even be represented.

use crate::error::{AtmError, Result};
use std::fmt;

/// Largest amount accepted from the keyboard: $1,000,000.00.
pub(crate) const MAX_INPUT_CENTS: i64 = 100_000_000;

/// Bills this machine handles, in dollars, smallest first.
pub const DENOMINATIONS: [u32; 5] = [5, 10, 20, 50, 100];

/// A non-negative amount of money in cents.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cents(i64);

impl Cents {
    pub const ZERO: Cents = Cents(0);
    /// Largest money value anywhere: 10^15 hundredths (ten trillion units).
    /// Far above any real balance, far below i64 overflow, so sums of many
    /// values can't wrap (STRIDE: Tampering). The DB has the same CHECK.
    pub const MAX: Cents = Cents(1_000_000_000_000_000);

    /// For values from our own DB or already-validated math. Rejects
    /// negatives and anything above `MAX`.
    pub fn new(cents: i64) -> Result<Cents> {
        if cents < 0 {
            return Err(AtmError::Internal("negative money value".into()));
        }
        if cents > Cents::MAX.0 {
            return Err(AtmError::InvalidInput("amount is too large"));
        }
        Ok(Cents(cents))
    }

    /// Whole dollars as cents.
    pub const fn from_dollars(dollars: u32) -> Cents {
        Cents(dollars as i64 * 100) // u32 dollars always fits in i64 cents
    }

    /// The raw number of cents.
    pub fn as_i64(self) -> i64 {
        self.0
    }

    /// True for $0.00.
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// `None` above `MAX`.
    pub fn checked_add(self, other: Cents) -> Option<Cents> {
        self.0.checked_add(other.0).filter(|&sum| sum <= Cents::MAX.0).map(Cents)
    }

    /// `None` if the result would be negative.
    pub fn checked_sub(self, other: Cents) -> Option<Cents> {
        if other.0 > self.0 { None } else { Some(Cents(self.0 - other.0)) }
    }

    /// Smaller of two amounts.
    pub fn min(self, other: Cents) -> Cents {
        if self <= other { self } else { other }
    }

    /// Parse typed text: "40", "40.5", "40.50". No sign, spaces, commas or exponent.
    pub fn parse(text: &str) -> Result<Cents> {
        Cents::parse_up_to(text, MAX_INPUT_CENTS)
    }

    /// `parse` with another cap, in hundredths (for currencies with more
    /// units per dollar; see `Currency::parse_amount`).
    pub(crate) fn parse_up_to(text: &str, max: i64) -> Result<Cents> {
        const BAD: AtmError = AtmError::InvalidInput("enter an amount like 40 or 40.50");
        let (dollars, cents) = text.split_once('.').unwrap_or((text, ""));
        if dollars.is_empty() || dollars.len() > 9 || cents.len() > 2 {
            return Err(BAD);
        }
        if !dollars.bytes().all(|b| b.is_ascii_digit()) || !cents.bytes().all(|b| b.is_ascii_digit()) {
            return Err(BAD);
        }
        if text.ends_with('.') {
            return Err(BAD); // "40." is ambiguous
        }
        let d: i64 = dollars.parse().map_err(|_| BAD)?;
        let c: i64 = match cents.len() {
            0 => 0,
            1 => cents.parse::<i64>().map_err(|_| BAD)? * 10, // ".5" = 50 cents
            _ => cents.parse().map_err(|_| BAD)?,
        };
        let total = d.checked_mul(100).and_then(|v| v.checked_add(c)).ok_or(BAD)?;
        if total > max {
            return Err(AtmError::InvalidInput("amount is too large"));
        }
        Ok(Cents(total))
    }
}

impl fmt::Display for Cents {
    /// "$1,234.50": comma every 3 digits, always 2 decimals.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dollars = (self.0 / 100).to_string();
        let mut grouped = String::new();
        for (i, c) in dollars.chars().enumerate() {
            if i > 0 && (dollars.len() - i).is_multiple_of(3) {
                grouped.push(',');
            }
            grouped.push(c);
        }
        // `pad` keeps width/alignment working in CLI tables.
        f.pad(&format!("${grouped}.{:02}", self.0 % 100))
    }
}

/// A bill denomination this machine actually handles.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Denomination(u32);

impl Denomination {
    /// A bill value this machine handles ($5, $10, $20, $50, $100); anything else is refused.
    pub fn new(dollars: u32) -> Result<Denomination> {
        if DENOMINATIONS.contains(&dollars) {
            Ok(Denomination(dollars))
        } else {
            Err(AtmError::InvalidInput("this machine handles $5, $10, $20, $50 and $100 bills"))
        }
    }

    /// All denominations, smallest first.
    pub fn all() -> impl Iterator<Item = Denomination> {
        DENOMINATIONS.into_iter().map(Denomination)
    }

    /// The bill's value in dollars.
    pub fn dollars(self) -> u32 {
        self.0
    }

    /// The bill's value in cents.
    pub fn value(self) -> Cents {
        Cents::from_dollars(self.0)
    }

    /// Bills of this type that make up `amount`, or `None` if it doesn't divide evenly.
    pub fn bills_for(self, amount: Cents) -> Option<i64> {
        let unit = self.value().as_i64();
        if amount.as_i64() % unit == 0 { Some(amount.as_i64() / unit) } else { None }
    }

    /// Value of `count` bills, with overflow checking.
    pub fn times(self, count: i64) -> Result<Cents> {
        let v =
            count.checked_mul(self.value().as_i64()).ok_or(AtmError::InvalidInput("amount is too large"))?;
        Cents::new(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_values_are_refused_and_sums_cannot_wrap() {
        assert!(Cents::new(i64::MAX).is_err());
        assert!(Cents::new(Cents::MAX.as_i64()).is_ok());
        assert_eq!(Cents::MAX.checked_add(Cents(1)), None);
    }

    #[test]
    fn displays_with_thousands_separators() {
        assert_eq!(Cents(123_456_789).to_string(), "$1,234,567.89");
        assert_eq!(Cents(100_000).to_string(), "$1,000.00");
        assert_eq!(Cents(99_999).to_string(), "$999.99");
        assert_eq!(Cents(5).to_string(), "$0.05");
    }

    #[test]
    fn parses_ordinary_amounts() {
        assert_eq!(Cents::parse("40").unwrap().as_i64(), 4000);
        assert_eq!(Cents::parse("40.5").unwrap().as_i64(), 4050);
        assert_eq!(Cents::parse("40.05").unwrap().as_i64(), 4005);
        assert_eq!(Cents::parse("0").unwrap(), Cents::ZERO);
    }

    #[test]
    fn rejects_hostile_amounts() {
        for bad in [
            "-5",
            "+5",
            "",
            ".",
            ".50",
            "1.",
            "1.234",
            "1e9",
            " 5",
            "5 ",
            "1,000",
            "٥",
            "0x10",
            "99999999999999999999",
            "1000000.01",
            "NaN",
        ] {
            assert!(Cents::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn subtraction_cannot_go_negative() {
        let five = Cents::from_dollars(5);
        let ten = Cents::from_dollars(10);
        assert!(five.checked_sub(ten).is_none());
        assert_eq!(ten.checked_sub(five), Some(five));
    }

    #[test]
    fn only_real_bills() {
        assert!(Denomination::new(20).is_ok());
        assert!(Denomination::new(0).is_err());
        assert!(Denomination::new(25).is_err());
        let twenty = Denomination::new(20).unwrap();
        assert_eq!(twenty.bills_for(Cents::from_dollars(60)), Some(3));
        assert_eq!(twenty.bills_for(Cents::from_dollars(70)), None);
        assert_eq!(twenty.bills_for(Cents::parse("20.50").unwrap()), None);
    }
}
