//! Currencies, exchange rates and fees.
//!
//! The machine only ever holds and pays US dollar bills, and Bank of CCNY
//! accounts are in US dollars. A card from another bank may be in another
//! currency; it is charged at the day's rate plus an exchange fee, like a
//! card's bank charging a foreign-transaction fee.
//!
//! Fees: each fee is a percent of the cash, but at least a minimum
//! (default 3%, at least $3.00). Two fees exist: the exchange fee (cards in
//! another currency) and the other bank's ATM fee (cards from other banks).
//! Every amount is shown to the customer line by line before they confirm.
//!
//! STRIDE (Tampering / Spoofing):
//!   * Rates are set by a Teller Admin: typed in, or taken from the daily feed
//!     (`rate_feed.rs`) only after the teller has reviewed and approved them.
//!     Customer transactions never touch the network.
//!   * Each rate must fall in a plausible range for its currency (typos and
//!     insider "EUR = 0.01" are refused), is audit-logged, and carries a MAC,
//!     so editing it in the DB file is detected.
//!   * A rate older than 72 hours stops conversions (fail closed, not stale).
//!   * Change cap on typed rates: a rate a teller types may move at most 5%
//!     from every rate in effect during the last 24 hours, so a dishonest
//!     teller can't slip in a "friendly" rate (real rates rarely move 1% a
//!     day). A rate from the daily feed isn't the teller's number, so it is
//!     set in full; a move over 5% in a day is set but paused until a teller
//!     checks it and resumes (`rate_feed.rs`). Every rate ever set is kept in
//!     `rate_history` (append-only, MAC'd) for review.
//!   * Emergency stop: a teller can pause one currency or all of them (for a
//!     currency crash). Pausing only stops conversions, so it is always safe.
//!   * Integer math only. Charges and fees round UP, credits round DOWN, and
//!     the exchange fee applies both ways, so no round trip gains a cent.
//!   * Transfers only between accounts in the same currency (no conversion).
//!   * Yen and won have no fractions: amounts are whole and conversions round
//!     to a whole yen or won (up for charges, down for credits).
//!   * Fees are set by a Teller Admin within fixed bounds (0-5%, minimum
//!     $0-$10), MAC'd and logged with old and new values.

use crate::Atm;
use crate::audit::{self, Action, Entry};
use crate::auth::AdminSession;
use crate::db;
use crate::error::{AtmError, Result};
use crate::keys;
use crate::money::{Cents, MAX_INPUT_CENTS};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};

/// A rate older than this stops conversions (covers a weekend, like card networks).
pub const RATE_MAX_AGE_HOURS: i64 = 72;
/// Highest fee percent a teller can set: 5.00%.
pub const MAX_FEE_BP: i64 = 500;
/// Highest fee minimum a teller can set.
pub const MAX_FEE_MINIMUM: Cents = Cents::from_dollars(10);
/// Most a typed rate may move within any 24 hours: 5.00% (basis points).
/// A bigger move from the daily feed pauses the currency instead.
pub const MAX_DAY_BP: i64 = 500;
/// Rates are stored as foreign units per US dollar, in millionths.
const MICROS: i128 = 1_000_000;
/// Basis points in 100%.
const BP: i128 = 10_000;

/// Currencies an account can be held in: the US dollar plus the ones used
/// most, ranking world use and trading together with New York's largest
/// immigrant communities and top visitor countries. Most used first.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Currency {
    Usd,
    Eur,
    Gbp,
    Cny,
    Jpy,
    Cad,
    Mxn,
    Dop,
    Inr,
    Krw,
    Brl,
    Jmd,
    Cop,
    Bdt,
    Htg,
    Gyd,
}

impl Currency {
    pub const ALL: [Currency; 16] = [
        Currency::Usd,
        Currency::Eur,
        Currency::Gbp,
        Currency::Cny,
        Currency::Jpy,
        Currency::Cad,
        Currency::Mxn,
        Currency::Dop,
        Currency::Inr,
        Currency::Krw,
        Currency::Brl,
        Currency::Jmd,
        Currency::Cop,
        Currency::Bdt,
        Currency::Htg,
        Currency::Gyd,
    ];
    pub const FOREIGN: [Currency; 15] = [
        Currency::Eur,
        Currency::Gbp,
        Currency::Cny,
        Currency::Jpy,
        Currency::Cad,
        Currency::Mxn,
        Currency::Dop,
        Currency::Inr,
        Currency::Krw,
        Currency::Brl,
        Currency::Jmd,
        Currency::Cop,
        Currency::Bdt,
        Currency::Htg,
        Currency::Gyd,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Currency::Usd => "USD",
            Currency::Bdt => "BDT",
            Currency::Brl => "BRL",
            Currency::Cad => "CAD",
            Currency::Cny => "CNY",
            Currency::Cop => "COP",
            Currency::Dop => "DOP",
            Currency::Eur => "EUR",
            Currency::Gbp => "GBP",
            Currency::Gyd => "GYD",
            Currency::Htg => "HTG",
            Currency::Inr => "INR",
            Currency::Jmd => "JMD",
            Currency::Jpy => "JPY",
            Currency::Krw => "KRW",
            Currency::Mxn => "MXN",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Currency::Usd => "US dollar",
            Currency::Bdt => "Bangladeshi taka",
            Currency::Brl => "Brazilian real",
            Currency::Cad => "Canadian dollar",
            Currency::Cny => "Chinese yuan",
            Currency::Cop => "Colombian peso",
            Currency::Dop => "Dominican peso",
            Currency::Eur => "Euro",
            Currency::Gbp => "British pound",
            Currency::Gyd => "Guyanese dollar",
            Currency::Htg => "Haitian gourde",
            Currency::Inr => "Indian rupee",
            Currency::Jmd => "Jamaican dollar",
            Currency::Jpy => "Japanese yen",
            Currency::Krw => "South Korean won",
            Currency::Mxn => "Mexican peso",
        }
    }

    /// Exact code ("EUR"). Anything else is refused.
    pub fn parse(code: &str) -> Result<Currency> {
        Currency::ALL
            .into_iter()
            .find(|c| c.code() == code)
            .ok_or(AtmError::InvalidInput("choose a currency code from the list, such as USD, EUR or DOP"))
    }

    /// Plausible units per US dollar, in millionths. Wide (about ±50%), but a
    /// typo like 92 for 0.92, or a rate set to give money away, is refused.
    pub(crate) fn plausible(self) -> (i64, i64) {
        match self {
            Currency::Usd => (1_000_000, 1_000_000),
            Currency::Bdt => (80_000_000, 200_000_000),
            Currency::Brl => (3_000_000, 9_000_000),
            Currency::Cad => (900_000, 2_000_000),
            Currency::Cny => (5_000_000, 10_000_000),
            Currency::Cop => (2_500_000_000, 6_500_000_000),
            Currency::Dop => (40_000_000, 100_000_000),
            Currency::Eur => (500_000, 1_500_000),
            Currency::Gbp => (400_000, 1_300_000),
            Currency::Gyd => (150_000_000, 300_000_000),
            Currency::Htg => (80_000_000, 220_000_000),
            Currency::Inr => (50_000_000, 150_000_000),
            Currency::Jmd => (100_000_000, 250_000_000),
            Currency::Jpy => (70_000_000, 250_000_000),
            Currency::Krw => (900_000_000, 2_100_000_000),
            Currency::Mxn => (10_000_000, 35_000_000),
        }
    }

    /// Smallest amount, in stored hundredths: 1 (one cent) for most; 100 for
    /// the yen and won, which have no fractions. Their balances are whole.
    pub fn step(self) -> i64 {
        match self {
            Currency::Jpy | Currency::Krw => 100,
            _ => 1,
        }
    }

    /// Refuses an amount this currency can't have (10.50 JPY).
    pub fn check_amount(self, amount: Cents) -> Result<()> {
        if amount.as_i64() % self.step() != 0 {
            return Err(AtmError::InvalidInput(match self {
                Currency::Krw => "won amounts are whole won, with no decimals",
                _ => "yen amounts are whole yen, with no decimals",
            }));
        }
        Ok(())
    }

    /// Parse a typed amount in this currency ("2500000" won, "250.00" euro).
    /// The cap is $1,000,000 worth at the weakest believable rate, so a
    /// normal won balance isn't "too large". Yen and won must be whole.
    pub fn parse_amount(self, text: &str) -> Result<Cents> {
        let (_, high) = self.plausible();
        let cap = i128::from(MAX_INPUT_CENTS) * i128::from(high) / MICROS; // at most 2.1e11
        let amount = Cents::parse_up_to(text, i64::try_from(cap).unwrap_or(i64::MAX))?;
        self.check_amount(amount)?;
        Ok(amount)
    }

    /// "$1,234.50" for dollars, "1,234.50 EUR" for the rest, "2,500,000 KRW".
    pub fn format(self, amount: Cents) -> String {
        let text = amount.to_string();
        if self == Currency::Usd {
            return text;
        }
        let number = text.trim_start_matches('$');
        let number = if self.step() == 100 { number.strip_suffix(".00").unwrap_or(number) } else { number };
        format!("{number} {}", self.code())
    }
}

/// One exchange rate as stored.
#[derive(Debug, Clone)]
pub struct Rate {
    pub currency: Currency,
    /// Foreign units per US dollar, in millionths (920000 = 0.92).
    pub per_usd_micros: i64,
    pub set_at: String,
    pub set_by: String,
    /// Conversions stopped by a teller (emergency stop).
    pub paused: bool,
}

impl Rate {
    /// "0.92", "18.4025": up to 6 decimals, at least 2.
    pub fn text(&self) -> String {
        rate_text(self.per_usd_micros)
    }

    /// Older than `RATE_MAX_AGE_HOURS`, or a timestamp in the future.
    pub fn is_stale(&self) -> bool {
        let Ok(set) = DateTime::parse_from_rfc3339(&self.set_at) else { return true };
        let age = Utc::now().signed_duration_since(set.with_timezone(&Utc));
        age.num_hours() >= RATE_MAX_AGE_HOURS || age.num_seconds() < -120
    }
}

/// The two fees a customer can pay.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Fee {
    /// Accounts in another currency, on every conversion.
    Exchange,
    /// Cards from other banks, on every withdrawal.
    OtherBank,
}

impl Fee {
    pub const ALL: [Fee; 2] = [Fee::Exchange, Fee::OtherBank];

    pub fn label(self) -> &'static str {
        match self {
            Fee::Exchange => "Exchange fee",
            Fee::OtherBank => "Other bank's ATM fee",
        }
    }

    /// Settings keys: (percent, minimum).
    fn keys(self) -> (&'static str, &'static str) {
        match self {
            Fee::Exchange => db::EXCHANGE_FEE_KEYS,
            Fee::OtherBank => db::OTHER_BANK_FEE_KEYS,
        }
    }
}

/// How a fee is worked out: a percent of the cash, but never less than the minimum.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FeeRule {
    /// Basis points (300 = 3.00%).
    pub percent_bp: i64,
    /// Smallest fee, in US dollars.
    pub minimum: Cents,
}

impl FeeRule {
    /// The fee on `cash` US dollars: the higher of the percent (rounded up
    /// to a cent) and the minimum.
    pub fn on(self, cash: Cents) -> Result<Cents> {
        let percent = (i128::from(cash.as_i64()) * i128::from(self.percent_bp) + BP - 1) / BP;
        let percent =
            Cents::new(i64::try_from(percent).map_err(|_| AtmError::InvalidInput("amount is too large"))?)?;
        Ok(if percent > self.minimum { percent } else { self.minimum })
    }

    /// "3.00%, at least $3.00" (staff screens).
    pub fn text(self) -> String {
        format!("{}, at least {}", fee_text(self.percent_bp), self.minimum)
    }

    /// "3% of the amount, $3.00 minimum" (customer small print, worded the
    /// way a bank's fee schedule is).
    pub fn short(self) -> String {
        let percent = fee_text(self.percent_bp).replace(".00%", "%");
        match (self.percent_bp, self.minimum.is_zero()) {
            (0, true) => "no fee".to_string(),
            (0, false) => self.minimum.to_string(),
            (_, true) => format!("{percent} of the amount"),
            (_, false) => format!("{percent} of the amount, {} minimum", self.minimum),
        }
    }
}

/// One fee as charged.
#[derive(Debug, Clone)]
pub struct FeeLine {
    pub fee: Fee,
    pub rule: FeeRule,
    /// In US dollars.
    pub usd: Cents,
    /// In the account's currency (the same as `usd` for dollar accounts).
    pub amount: Cents,
}

/// What an account is charged or credited for a cash amount, part by part.
#[derive(Debug, Clone)]
pub struct Conversion {
    pub currency: Currency,
    /// Cash in US dollars.
    pub usd: Cents,
    /// That cash in the account's currency (the same as `usd` for dollar accounts).
    pub cash_amount: Cents,
    /// "1 USD = 0.86 EUR" (None for dollar accounts).
    pub rate: Option<String>,
    /// Each fee, in the order shown.
    pub fees: Vec<FeeLine>,
    /// Total charged (withdrawal) or added (deposit), in the account's currency.
    pub account_amount: Cents,
}

impl Conversion {
    /// Money that isn't cash, so no rate or fee (a transfer).
    pub(crate) fn plain(currency: Currency, usd: Cents, amount: Cents) -> Conversion {
        Conversion {
            currency,
            usd,
            cash_amount: amount,
            rate: None,
            fees: Vec::new(),
            account_amount: amount,
        }
    }

    /// What the customer sees before confirming and on the receipt: the
    /// cash, each fee and the total in dollars, then (foreign-currency
    /// accounts) what that comes to in the account's currency.
    pub fn summary(&self, deposit: bool) -> Vec<SumLine> {
        let row =
            |label: &str, amount: String, total: bool| SumLine { label: label.to_string(), amount, total };
        let mut rows = vec![row(if deposit { "Deposit" } else { "Withdrawal" }, self.usd.to_string(), false)];
        let mut total = Some(self.usd);
        for f in &self.fees {
            let sign = if deposit { "\u{2212}" } else { "+" };
            rows.push(row(&format!("{sign} {}", f.fee.label()), f.usd.to_string(), false));
            total = total.and_then(|t| if deposit { t.checked_sub(f.usd) } else { t.checked_add(f.usd) });
        }
        if self.fees.is_empty() {
            rows.push(row("Fees", Cents::ZERO.to_string(), false));
        }
        rows.push(row("Total", total.map_or_else(String::new, |t| t.to_string()), true));
        if self.currency != Currency::Usd {
            let label = if deposit { "Added to your account" } else { "Charged to your account" };
            rows.push(row(label, self.currency.format(self.account_amount), true));
        }
        rows
    }

    /// Small print under the summary: how each fee is worked out, and the rate.
    /// Empty when there is neither.
    pub fn fine_print(&self) -> String {
        let same_rule = self.fees.len() > 1 && self.fees.iter().all(|f| f.rule == self.fees[0].rule);
        let mut parts: Vec<String> = if same_rule {
            vec![format!("Each fee: {}.", self.fees[0].rule.short())]
        } else {
            self.fees.iter().map(|f| format!("{}: {}.", f.fee.label(), f.rule.short())).collect()
        };
        if let Some(rate) = &self.rate {
            parts.push(format!("Rate: {rate}."));
        }
        parts.join(" ")
    }

    /// The summary and fine print as plain text lines (command line, tests).
    pub fn breakdown(&self, deposit: bool) -> Vec<String> {
        let mut lines: Vec<String> =
            self.summary(deposit).iter().map(|r| format!("{:<26}{:>16}", r.label, r.amount)).collect();
        let note = self.fine_print();
        if !note.is_empty() {
            lines.push(note);
        }
        lines
    }
}

/// One row of a charge summary: "+ Exchange fee" .. "$3.00".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumLine {
    pub label: String,
    pub amount: String,
    /// A total row (shown in bold).
    pub total: bool,
}

pub(crate) fn rate_text(micros: i64) -> String {
    let whole = micros / 1_000_000;
    let frac = format!("{:06}", micros % 1_000_000);
    let frac = frac.trim_end_matches('0');
    format!("{whole}.{frac:0<2}")
}

/// "3.00%".
pub fn fee_text(bp: i64) -> String {
    format!("{}.{:02}%", bp / 100, bp % 100)
}

/// Parse "0.92" / "18.4" / "3" into an integer with `decimals` places.
/// No sign, spaces, commas or exponent; at most 4 whole digits.
pub(crate) fn parse_fixed(text: &str, decimals: usize) -> Option<i64> {
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || whole.len() > 4 || frac.len() > decimals || !digits(whole) || !digits(frac) {
        return None;
    }
    if text.ends_with('.') {
        return None;
    }
    let scale = 10i64.pow(decimals as u32);
    let frac_value: i64 = if frac.is_empty() { 0 } else { format!("{frac:0<decimals$}").parse().ok()? };
    whole.parse::<i64>().ok()?.checked_mul(scale)?.checked_add(frac_value)
}

// ---------------------------------------------------------------------------
// Stored rates and fee
// ---------------------------------------------------------------------------

fn rate_mac(rate: &Rate) -> Result<String> {
    keys::record_mac(&[
        "exchange_rate",
        rate.currency.code(),
        &rate.per_usd_micros.to_string(),
        &rate.set_at,
        &rate.set_by,
        if rate.paused { "paused" } else { "active" },
    ])
}

fn history_mac(rate: &Rate) -> Result<String> {
    keys::record_mac(&[
        "rate_history",
        rate.currency.code(),
        &rate.per_usd_micros.to_string(),
        &rate.set_at,
        &rate.set_by,
    ])
}

/// The stored rate, MAC-checked. `None` if never set.
pub(crate) fn read_rate(conn: &Connection, currency: Currency) -> Result<Option<Rate>> {
    let row: Option<(i64, String, String, bool, String)> = conn
        .query_row(
            "SELECT per_usd_micros, set_at, set_by, paused, mac FROM exchange_rates WHERE currency = ?1",
            params![currency.code()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((per_usd_micros, set_at, set_by, paused, mac)) = row else { return Ok(None) };
    let rate = Rate { currency, per_usd_micros, set_at, set_by, paused };
    if !keys::same_mac(&mac, &rate_mac(&rate)?) {
        return Err(AtmError::RecordTampered("exchange rates"));
    }
    Ok(Some(rate))
}

/// A rate that may be used right now: set, untouched, not paused and fresh. Fails closed.
fn usable_rate(conn: &Connection, currency: Currency) -> Result<Rate> {
    let rate = read_rate(conn, currency)?.ok_or(AtmError::NotAllowed(
        "no exchange rate is set for this account's currency; please see a teller",
    ))?;
    if rate.paused {
        return Err(AtmError::NotAllowed(
            "the bank has paused exchanges in this currency; please see a teller",
        ));
    }
    if rate.is_stale() {
        return Err(AtmError::NotAllowed("the exchange rate is out of date; please see a teller"));
    }
    Ok(rate)
}

/// Rate history rows (MAC-checked), oldest first. `from_id` limits it to
/// rows with id >= from_id; `currency` None means every currency.
fn read_history(conn: &Connection, currency: Option<Currency>, from_id: i64) -> Result<Vec<(i64, Rate)>> {
    let mut stmt = conn.prepare(
        "SELECT id, currency, per_usd_micros, set_at, set_by, mac FROM rate_history
         WHERE (?1 IS NULL OR currency = ?1) AND id >= ?2 ORDER BY id",
    )?;
    let mut rows = stmt.query(params![currency.map(|c| c.code()), from_id])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let rate = Rate {
            currency: Currency::parse(&r.get::<_, String>(1)?)?,
            per_usd_micros: r.get(2)?,
            set_at: r.get(3)?,
            set_by: r.get(4)?,
            paused: false,
        };
        if !keys::same_mac(&r.get::<_, String>(5)?, &history_mac(&rate)?) {
            return Err(AtmError::RecordTampered("exchange rates"));
        }
        out.push((r.get(0)?, rate));
    }
    Ok(out)
}

/// True if `new` is within `bp` basis points of `base`.
fn within(new: i64, base: i64, bp: i64) -> bool {
    (i128::from(new) - i128::from(base)).abs() * BP <= i128::from(base) * i128::from(bp)
}

/// The change cap on a typed rate: at most 5% from every rate in effect
/// during the last 24 hours, so small steps can't add up to more. The first
/// rate for a currency only has to be believable.
pub(crate) fn check_change_cap(conn: &Connection, currency: Currency, micros: i64) -> Result<()> {
    let recent = recent_rates(conn, currency)?;
    if recent.iter().any(|(_, r)| !within(micros, r.per_usd_micros, MAX_DAY_BP)) {
        return Err(AtmError::NotAllowed(
            "a typed rate can move at most 5% in 24 hours; check today's rates instead, or pause this currency",
        ));
    }
    Ok(())
}

/// The rate in effect 24 hours ago and every rate set since, oldest first.
fn recent_rates(conn: &Connection, currency: Currency) -> Result<Vec<(i64, Rate)>> {
    let cutoff = (Utc::now() - chrono::Duration::hours(24)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let start: i64 = conn.query_row(
        "SELECT COALESCE(MAX(id), 0) FROM rate_history WHERE currency = ?1 AND set_at <= ?2",
        params![currency.code(), cutoff],
        |r| r.get(0),
    )?;
    read_history(conn, Some(currency), start)
}

/// The lowest and highest rate within 5% of every rate in effect during the
/// last 24 hours (the same limits as `check_change_cap`). None for a
/// currency's first rate. If low > high, there is no such rate until the
/// 24-hour window rolls on.
pub(crate) fn allowed_band(conn: &Connection, currency: Currency) -> Result<Option<(i64, i64)>> {
    let recent = recent_rates(conn, currency)?;
    if recent.is_empty() {
        return Ok(None);
    }
    let band = |base: i64, bp: i64| {
        let d = i64::try_from(i128::from(base) * i128::from(bp) / BP).unwrap_or(0);
        (base - d, base + d)
    };
    let (mut low, mut high) = (i64::MIN, i64::MAX);
    for (_, r) in &recent {
        let (l, h) = band(r.per_usd_micros, MAX_DAY_BP);
        (low, high) = (low.max(l), high.min(h));
    }
    Ok(Some((low, high)))
}

/// A fee's current rule (MAC-checked settings).
pub(crate) fn fee_rule_of(conn: &Connection, fee: Fee) -> Result<FeeRule> {
    let (percent, minimum) = fee.keys();
    Ok(FeeRule {
        percent_bp: db::get_setting(conn, percent)?,
        minimum: Cents::new(db::get_setting(conn, minimum)?)?,
    })
}

/// Every stored rate and history row, MAC-checked (part of the integrity
/// check). Returns how many records were checked.
pub(crate) fn verify_rates(conn: &Connection) -> Result<i64> {
    let mut count = 0;
    for currency in Currency::FOREIGN {
        if read_rate(conn, currency)?.is_some() {
            count += 1;
        }
    }
    Ok(count + read_history(conn, None, 0)?.len() as i64)
}

// ---------------------------------------------------------------------------
// Conversions (called by customer.rs inside its transaction)
// ---------------------------------------------------------------------------

/// usd * rate * (1 ± fee), in the account's hundredths, rounded up or down
/// to a whole `step` (a cent, or a whole yen or won).
fn apply(usd: Cents, micros: i64, fee_factor_bp: i128, round_up: bool, step: i64) -> Result<Cents> {
    let numerator = i128::from(usd.as_i64()) * i128::from(micros) * fee_factor_bp;
    let denominator = MICROS * BP * i128::from(step);
    let steps = if round_up { (numerator + denominator - 1) / denominator } else { numerator / denominator };
    let value = steps * i128::from(step);
    Cents::new(i64::try_from(value).map_err(|_| AtmError::InvalidInput("amount is too large"))?)
}

/// "1 USD = 0.86 EUR".
fn rate_line(rate: &Rate) -> String {
    format!("1 USD = {} {}", rate.text(), rate.currency.code())
}

/// Withdrawal: what the account pays for `usd` in cash. Fees: the other
/// bank's ATM fee (if `other_bank`), then the exchange fee (if foreign).
/// Each part is converted and rounded up separately, so the lines add up.
pub(crate) fn charge_for(
    conn: &Connection,
    currency: Currency,
    usd: Cents,
    other_bank: bool,
) -> Result<Conversion> {
    let rate = if currency == Currency::Usd { None } else { Some(usable_rate(conn, currency)?) };
    let convert = |amount: Cents| match &rate {
        Some(r) => apply(amount, r.per_usd_micros, BP, true, currency.step()),
        None => Ok(amount),
    };
    let cash_amount = convert(usd)?;
    let mut fees = Vec::new();
    for (fee, applies) in [(Fee::OtherBank, other_bank), (Fee::Exchange, rate.is_some())] {
        if applies {
            let rule = fee_rule_of(conn, fee)?;
            let fee_usd = rule.on(usd)?;
            fees.push(FeeLine { fee, rule, usd: fee_usd, amount: convert(fee_usd)? });
        }
    }
    let account_amount = fees
        .iter()
        .try_fold(cash_amount, |sum, f| sum.checked_add(f.amount))
        .ok_or(AtmError::InvalidInput("amount is too large"))?;
    Ok(Conversion { currency, usd, cash_amount, rate: rate.as_ref().map(rate_line), fees, account_amount })
}

/// Deposit: what the account receives for `usd` in cash. Foreign accounts:
/// the cash is converted rounding down, the exchange fee rounding up.
pub(crate) fn credit_for(conn: &Connection, currency: Currency, usd: Cents) -> Result<Conversion> {
    if currency == Currency::Usd {
        return Ok(Conversion::plain(currency, usd, usd));
    }
    let rate = usable_rate(conn, currency)?;
    let cash_amount = apply(usd, rate.per_usd_micros, BP, false, currency.step())?;
    let rule = fee_rule_of(conn, Fee::Exchange)?;
    let fee_usd = rule.on(usd)?;
    let fee_amount = apply(fee_usd, rate.per_usd_micros, BP, true, currency.step())?;
    let account_amount = cash_amount.checked_sub(fee_amount).filter(|a| !a.is_zero()).ok_or(
        AtmError::NotAllowed("this deposit is too small to cover the exchange fee; please deposit more"),
    )?;
    let fees = vec![FeeLine { fee: Fee::Exchange, rule, usd: fee_usd, amount: fee_amount }];
    Ok(Conversion { currency, usd, cash_amount, rate: Some(rate_line(&rate)), fees, account_amount })
}

/// US-dollar value of an amount in `currency` (no fee, rounded up), so a
/// foreign-currency transfer counts fully toward the dollar daily limit.
pub(crate) fn usd_value(conn: &Connection, currency: Currency, amount: Cents) -> Result<Cents> {
    if currency == Currency::Usd {
        return Ok(amount);
    }
    let micros = i128::from(usable_rate(conn, currency)?.per_usd_micros);
    let value = (i128::from(amount.as_i64()) * MICROS + micros - 1) / micros;
    Cents::new(i64::try_from(value).map_err(|_| AtmError::InvalidInput("amount is too large"))?)
}

/// Today's rate line for a customer's balance screen (None for dollar accounts
/// or when no usable rate is set): "1 USD = 0.86 EUR; exchange fee 3.00%, at least $3.00".
pub(crate) fn rate_note(conn: &Connection, currency: Currency) -> Result<Option<String>> {
    if currency == Currency::Usd {
        return Ok(None);
    }
    match usable_rate(conn, currency) {
        Ok(rate) => Ok(Some(format!(
            "{}; exchange fee {}",
            rate_line(&rate),
            fee_rule_of(conn, Fee::Exchange)?.text()
        ))),
        Err(AtmError::NotAllowed(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Teller Admin
// ---------------------------------------------------------------------------

/// One row of the teller's rate screen.
#[derive(Debug, Clone)]
pub struct RateStatus {
    pub currency: Currency,
    pub rate: Option<Rate>,
    /// The stored row failed its MAC: edited outside the ATM. Re-enter it.
    pub tampered: bool,
}

/// All foreign currencies with their current rate (if any). A tampered row
/// is flagged rather than failing the list, so the teller can re-enter it.
pub fn rates(atm: &Atm, session: &AdminSession) -> Result<Vec<RateStatus>> {
    atm.admit(session)?;
    let conn = &atm.read()?;
    Currency::FOREIGN
        .into_iter()
        .map(|currency| match read_rate(conn, currency) {
            Ok(rate) => Ok(RateStatus { currency, rate, tampered: false }),
            Err(AtmError::RecordTampered(_)) => Ok(RateStatus { currency, rate: None, tampered: true }),
            Err(e) => Err(e),
        })
        .collect()
}

/// A fee's current rule (percent and minimum).
pub fn fee_rule(atm: &Atm, session: &AdminSession, fee: Fee) -> Result<FeeRule> {
    atm.admit(session)?;
    fee_rule_of(&*atm.read()?, fee)
}

/// Set a fee: the percent ("3" or "2.5", 0 to 5) and the minimum in dollars
/// ("3" or "2.50", $0 to $10). MAC'd and logged with old and new values.
pub fn set_fee_rule(
    atm: &mut Atm,
    session: &AdminSession,
    fee: Fee,
    percent: &str,
    minimum: &str,
) -> Result<()> {
    atm.admit(session)?;
    let percent_bp = parse_fixed(percent, 2)
        .filter(|bp| (0..=MAX_FEE_BP).contains(bp))
        .ok_or(AtmError::InvalidInput("enter a fee percent from 0 to 5, like 3 or 2.5"))?;
    let minimum = Cents::parse(minimum)
        .ok()
        .filter(|m| *m <= MAX_FEE_MINIMUM)
        .ok_or(AtmError::InvalidInput("enter a minimum fee from $0 to $10, like 3 or 2.50"))?;
    let new = FeeRule { percent_bp, minimum };
    let tx = atm.begin()?;
    let old = fee_rule_of(&tx, fee)?;
    let (percent_key, minimum_key) = fee.keys();
    db::put_setting(&tx, percent_key, new.percent_bp)?;
    db::put_setting(&tx, minimum_key, new.minimum.as_i64())?;
    audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action: Action::FeeChanged,
            account_id: None,
            counterparty_id: None,
            amount: None,
            usd: None,
            detail: &format!("{}: {} -> {}", fee.label(), old.text(), new.text()),
        },
    )?;
    tx.commit()?;
    Ok(())
}

/// The last `limit` rates set, newest first (all currencies, or one).
pub fn rate_history(
    atm: &Atm,
    session: &AdminSession,
    currency: Option<Currency>,
    limit: usize,
) -> Result<Vec<Rate>> {
    atm.admit(session)?;
    let all = read_history(&*atm.read()?, currency, 0)?;
    Ok(all.into_iter().rev().take(limit).map(|(_, rate)| rate).collect())
}

/// Emergency stop: pause (or resume) exchanges in one currency, or in every
/// currency that has a rate when `currency` is None. Logged and MAC'd.
pub fn set_paused(
    atm: &mut Atm,
    session: &AdminSession,
    currency: Option<Currency>,
    paused: bool,
) -> Result<()> {
    atm.admit(session)?;
    let tx = atm.begin()?;
    let targets: Vec<Currency> = match currency {
        Some(Currency::Usd) => return Err(AtmError::InvalidInput("the US dollar has no exchange rate")),
        Some(c) => vec![c],
        None => Currency::FOREIGN.to_vec(),
    };
    let mut changed = Vec::new();
    for c in targets {
        let Some(mut rate) = read_rate(&tx, c)? else {
            if currency.is_some() {
                return Err(AtmError::NotAllowed("set a rate for this currency first"));
            }
            continue; // "pause all" skips currencies with no rate (already unusable)
        };
        if rate.paused == paused {
            continue;
        }
        rate.paused = paused;
        tx.execute(
            "UPDATE exchange_rates SET paused = ?2, mac = ?3 WHERE currency = ?1",
            params![c.code(), paused, rate_mac(&rate)?],
        )?;
        changed.push(c.code());
    }
    if changed.is_empty() {
        return Err(AtmError::NotAllowed(if paused { "already paused" } else { "not paused" }));
    }
    audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action: if paused { Action::ExchangePaused } else { Action::ExchangeResumed },
            account_id: None,
            counterparty_id: None,
            amount: None,
            usd: None,
            detail: &changed.join(", "),
        },
    )?;
    tx.commit()?;
    Ok(())
}

/// Set today's rate, typed as foreign units per US dollar ("0.92").
/// Range-checked, change-capped, MAC'd, logged, kept in the history.
/// Also repairs a row flagged as tampered. A paused currency stays paused.
pub fn set_rate(atm: &mut Atm, session: &AdminSession, currency: Currency, per_usd: &str) -> Result<()> {
    atm.admit(session)?;
    if currency == Currency::Usd {
        return Err(AtmError::InvalidInput("the US dollar has no exchange rate"));
    }
    let micros = parse_fixed(per_usd, 6)
        .ok_or(AtmError::InvalidInput("enter a rate like 0.92 (units per US dollar, up to 6 decimals)"))?;
    let (low, high) = currency.plausible();
    if !(low..=high).contains(&micros) {
        return Err(AtmError::InvalidInput("that rate is outside the believable range for this currency"));
    }
    let tx = atm.begin()?;
    check_change_cap(&tx, currency, micros)?;
    store_rate(&tx, session, currency, micros, "", false)?;
    tx.commit()?;
    Ok(())
}

/// Write a checked rate: the row, the history, both MACs and a log line
/// ("EUR per USD: 0.86 -> 0.87" + `how`). The caller has done the range and
/// cap checks inside the same transaction. `pause` also pauses the currency
/// (a big move in the daily feed), logged on its own line.
pub(crate) fn store_rate(
    tx: &Connection,
    session: &AdminSession,
    currency: Currency,
    micros: i64,
    how: &str,
    pause: bool,
) -> Result<()> {
    // An altered row is re-entered as paused, so a teller looks before resuming.
    let (old, was_paused) = match read_rate(tx, currency) {
        Ok(Some(rate)) => (rate.text(), rate.paused),
        Ok(None) => ("not set".to_string(), false),
        Err(_) => ("ALTERED".to_string(), true),
    };
    let paused = was_paused || pause;
    let rate =
        Rate { currency, per_usd_micros: micros, set_at: audit::now_utc(), set_by: session.actor(), paused };
    tx.execute(
        "INSERT INTO exchange_rates (currency, per_usd_micros, set_at, set_by, paused, mac)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (currency) DO UPDATE SET
             per_usd_micros = excluded.per_usd_micros, set_at = excluded.set_at,
             set_by = excluded.set_by, paused = excluded.paused, mac = excluded.mac",
        params![currency.code(), micros, rate.set_at, rate.set_by, paused, rate_mac(&rate)?],
    )?;
    tx.execute(
        "INSERT INTO rate_history (currency, per_usd_micros, set_at, set_by, mac) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![currency.code(), micros, rate.set_at, rate.set_by, history_mac(&rate)?],
    )?;
    audit::append(
        tx,
        &Entry {
            actor: &rate.set_by,
            action: Action::RateChanged,
            account_id: None,
            counterparty_id: None,
            amount: None,
            usd: None,
            detail: &format!("{} per USD: {} -> {}{how}", currency.code(), old, rate_text(micros)),
        },
    )?;
    if paused && !was_paused {
        audit::append(
            tx,
            &Entry {
                actor: &rate.set_by,
                action: Action::ExchangePaused,
                account_id: None,
                counterparty_id: None,
                amount: None,
                usd: None,
                detail: &format!("{} (big move in today's feed: check it, then resume)", currency.code()),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testing::setup;

    fn usd(n: u32) -> Cents {
        Cents::from_dollars(n)
    }

    #[test]
    fn rates_parse_strictly_and_must_be_believable() {
        assert_eq!(parse_fixed("0.92", 6), Some(920_000));
        assert_eq!(parse_fixed("18.4", 6), Some(18_400_000));
        assert_eq!(parse_fixed("3", 2), Some(300));
        for bad in ["", ".9", "9.", "-1", "1e3", " 1", "1,5", "0.1234567", "12345"] {
            assert_eq!(parse_fixed(bad, 6), None, "{bad:?} should be refused");
        }
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut atm);
        assert!(set_rate(&mut atm, &admin, Currency::Eur, "92").is_err(), "typo: 92 instead of 0.92");
        assert!(set_rate(&mut atm, &admin, Currency::Eur, "0.01").is_err(), "give-away rate");
        assert!(set_rate(&mut atm, &admin, Currency::Usd, "1").is_err());
        set_rate(&mut atm, &admin, Currency::Eur, "0.92").unwrap();
        let eur = rates(&atm, &admin).unwrap().into_iter().find(|r| r.currency == Currency::Eur).unwrap();
        assert_eq!(eur.rate.unwrap().text(), "0.92");
        assert!(set_fee_rule(&mut atm, &admin, Fee::Exchange, "5.01", "3").is_err());
        assert!(set_fee_rule(&mut atm, &admin, Fee::Exchange, "3", "10.01").is_err());
        set_fee_rule(&mut atm, &admin, Fee::Exchange, "2.5", "2").unwrap();
        assert_eq!(
            fee_rule(&atm, &admin, Fee::Exchange).unwrap(),
            FeeRule { percent_bp: 250, minimum: usd(2) }
        );
    }

    #[test]
    fn charges_round_up_credits_round_down_and_round_trips_lose() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut atm);
        set_rate(&mut atm, &admin, Currency::Eur, "0.92").unwrap(); // fee stays at 3%, at least $3
        let charge = charge_for(&atm.conn, Currency::Eur, usd(100), false).unwrap();
        assert_eq!(charge.account_amount, Cents::new(9476).unwrap()); // 92.00 + $3.00 fee (2.76) = 94.76
        let credit = credit_for(&atm.conn, Currency::Eur, usd(100)).unwrap();
        assert_eq!(credit.account_amount, Cents::new(8924).unwrap()); // 92.00 - 2.76 = 89.24
        // Tiny amounts: a 1-cent charge never rounds to zero; a 1-cent credit never rounds up.
        assert_eq!(
            apply(Cents::new(1).unwrap(), 920_000, BP + 300, true, 1).unwrap(),
            Cents::new(1).unwrap()
        );
        assert_eq!(apply(Cents::new(1).unwrap(), 920_000, BP - 300, false, 1).unwrap(), Cents::ZERO);
        assert!(credit.account_amount < charge.account_amount);
        // Dollar accounts: no rate, no fee.
        assert_eq!(charge_for(&atm.conn, Currency::Usd, usd(5), false).unwrap().account_amount, usd(5));
        // Other banks' cards: the ATM fee is added ($3 minimum on $20).
        assert_eq!(charge_for(&atm.conn, Currency::Usd, usd(20), true).unwrap().account_amount, usd(23));
        // A euro card from another bank pays both fees: 92.00 + 2.76 + 2.76.
        let both = charge_for(&atm.conn, Currency::Eur, usd(100), true).unwrap();
        assert_eq!((both.account_amount, both.usd), (Cents::new(9752).unwrap(), usd(100)));
    }

    #[test]
    fn won_are_whole_and_round_in_the_banks_favour() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut atm);
        // A typo like 13.85 for 1,385.50 is outside the believable range.
        assert!(set_rate(&mut atm, &admin, Currency::Krw, "13.85").is_err());
        set_rate(&mut atm, &admin, Currency::Krw, "1385.50").unwrap();
        // $20 cash = 27,710 won; $3 minimum fee = 4,156.5 -> 4,157 won (up). Total 31,867 won.
        let charge = charge_for(&atm.conn, Currency::Krw, usd(20), false).unwrap();
        assert_eq!(charge.account_amount, Cents::new(3_186_700).unwrap());
        // $20 deposit: 27,710 - 4,157 = 23,553 won.
        let credit = credit_for(&atm.conn, Currency::Krw, usd(20)).unwrap();
        assert_eq!(Currency::Krw.format(credit.account_amount), "23,553 KRW");
        assert!(Currency::Krw.check_amount(Cents::parse("10.50").unwrap()).is_err());
        assert!(Currency::Krw.check_amount(Cents::parse("10").unwrap()).is_ok());
        // Yen too: $20 at 151.37 = 3,027.4 -> 3,028 yen; $3 fee = 454.11 -> 455 yen.
        set_rate(&mut atm, &admin, Currency::Jpy, "151.37").unwrap();
        let charge = charge_for(&atm.conn, Currency::Jpy, usd(20), false).unwrap();
        assert_eq!(Currency::Jpy.format(charge.account_amount), "3,483 JPY");
        assert!(Currency::Jpy.parse_amount("2500.50").is_err());
        // Large-number currencies: a Colombian peso rate has 4 digits before the point.
        set_rate(&mut atm, &admin, Currency::Cop, "4150.25").unwrap();
        assert!(set_rate(&mut atm, &admin, Currency::Cop, "415.03").is_err());
        // Typed amounts: 2,500,000 won is normal, not "too large"; decimals are refused.
        assert_eq!(Currency::Krw.parse_amount("2500000").unwrap(), Cents::new(250_000_000).unwrap());
        assert!(Currency::Krw.parse_amount("99.50").is_err());
        assert!(Currency::Usd.parse_amount("1000000.01").is_err());
        assert!(Currency::Eur.parse_amount("250.75").is_ok());
    }

    #[test]
    fn each_fee_is_the_higher_of_the_percent_and_the_minimum() {
        let rule = FeeRule { percent_bp: 300, minimum: usd(3) };
        assert_eq!(rule.on(usd(40)).unwrap(), usd(3)); // 3% is only $1.20
        assert_eq!(rule.on(usd(100)).unwrap(), usd(3));
        assert_eq!(rule.on(usd(101)).unwrap(), Cents::parse("3.03").unwrap());
        assert_eq!(rule.on(usd(500)).unwrap(), usd(15));
        // A fraction of a cent rounds up (the bank's favour).
        assert_eq!(
            FeeRule { percent_bp: 250, minimum: Cents::ZERO }.on(usd(5)).unwrap(),
            Cents::new(13).unwrap()
        );
        assert_eq!(rule.text(), "3.00%, at least $3.00");
        assert_eq!(rule.short(), "3% of the amount, $3.00 minimum");
        assert_eq!(FeeRule { percent_bp: 250, minimum: Cents::ZERO }.short(), "2.50% of the amount");
        assert_eq!(FeeRule { percent_bp: 0, minimum: usd(2) }.short(), "$2.00");
        assert_eq!(FeeRule { percent_bp: 0, minimum: Cents::ZERO }.short(), "no fee");

        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut atm);
        set_rate(&mut atm, &admin, Currency::Eur, "0.86").unwrap();
        let rows = |c: &Conversion, deposit: bool| -> Vec<(String, String)> {
            c.summary(deposit).into_iter().map(|l| (l.label, l.amount)).collect()
        };
        let pairs = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
        };
        // A euro card from another bank: cash + each fee = total, then the euros charged.
        let c = charge_for(&atm.conn, Currency::Eur, usd(100), true).unwrap();
        assert_eq!(
            rows(&c, false),
            pairs(&[
                ("Withdrawal", "$100.00"),
                ("+ Other bank's ATM fee", "$3.00"),
                ("+ Exchange fee", "$3.00"),
                ("Total", "$106.00"),
                ("Charged to your account", "91.16 EUR"),
            ])
        );
        assert_eq!(c.fine_print(), "Each fee: 3% of the amount, $3.00 minimum. Rate: 1 USD = 0.86 EUR.");
        // Our own dollar customers: no fee, and the screen says so.
        let own = charge_for(&atm.conn, Currency::Usd, usd(40), false).unwrap();
        assert_eq!(
            rows(&own, false),
            pairs(&[("Withdrawal", "$40.00"), ("Fees", "$0.00"), ("Total", "$40.00")])
        );
        assert_eq!(own.fine_print(), "");
        // Deposit: the exchange fee is taken off.
        let d = credit_for(&atm.conn, Currency::Eur, usd(100)).unwrap();
        assert_eq!(
            rows(&d, true),
            pairs(&[
                ("Deposit", "$100.00"),
                ("\u{2212} Exchange fee", "$3.00"),
                ("Total", "$97.00"),
                ("Added to your account", "83.42 EUR"),
            ])
        );
        // A deposit too small to cover the minimum fee is refused, never credited at zero.
        set_fee_rule(&mut atm, &admin, Fee::Exchange, "3", "10").unwrap();
        assert!(matches!(credit_for(&atm.conn, Currency::Eur, usd(5)), Err(AtmError::NotAllowed(_))));
        // Fee changes are bounded and logged with old and new values.
        assert!(set_fee_rule(&mut atm, &admin, Fee::OtherBank, "3", "10.01").is_err());
        set_fee_rule(&mut atm, &admin, Fee::OtherBank, "2.5", "2.50").unwrap();
        let logged: String = atm
            .conn
            .query_row(
                "SELECT detail FROM audit_log WHERE action = 'fee_changed' ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(logged, "Other bank's ATM fee: 3.00%, at least $3.00 -> 2.50%, at least $2.50");
    }

    #[test]
    fn missing_stale_or_edited_rates_stop_conversions() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut atm);
        assert!(matches!(charge_for(&atm.conn, Currency::Gbp, usd(20), false), Err(AtmError::NotAllowed(_))));
        set_rate(&mut atm, &admin, Currency::Gbp, "0.75").unwrap();
        assert!(charge_for(&atm.conn, Currency::Gbp, usd(20), false).is_ok());
        // Someone edits the rate in the DB file: detected, not used.
        atm.conn.execute("UPDATE exchange_rates SET per_usd_micros = 1 WHERE currency = 'GBP'", []).unwrap();
        assert!(matches!(
            charge_for(&atm.conn, Currency::Gbp, usd(20), false),
            Err(AtmError::RecordTampered(_))
        ));
        assert!(matches!(verify_rates(&atm.conn), Err(AtmError::RecordTampered(_))));
        // The database seal refuses every operation until someone checks it.
        assert!(matches!(set_rate(&mut atm, &admin, Currency::Gbp, "0.75"), Err(AtmError::DatabaseAltered)));
        // (Had it been resealed,) the teller re-enters it: it comes back paused.
        atm.reseal();
        set_rate(&mut atm, &admin, Currency::Gbp, "0.75").unwrap();
        assert!(matches!(charge_for(&atm.conn, Currency::Gbp, usd(20), false), Err(AtmError::NotAllowed(_))));
        set_paused(&mut atm, &admin, Some(Currency::Gbp), false).unwrap();
        assert!(charge_for(&atm.conn, Currency::Gbp, usd(20), false).is_ok());
        // Then it ages past 72 hours and stops working.
        let old = Rate {
            currency: Currency::Gbp,
            per_usd_micros: 750_000,
            set_at: (Utc::now() - chrono::Duration::hours(RATE_MAX_AGE_HOURS)).to_rfc3339(),
            set_by: admin.actor(),
            paused: false,
        };
        atm.conn
            .execute(
                "UPDATE exchange_rates SET set_at = ?1, mac = ?2 WHERE currency = 'GBP'",
                params![old.set_at, rate_mac(&old).unwrap()],
            )
            .unwrap();
        atm.reseal();
        assert!(matches!(charge_for(&atm.conn, Currency::Gbp, usd(20), false), Err(AtmError::NotAllowed(_))));
    }

    #[test]
    fn a_teller_cannot_jump_a_rate_but_can_pause_it() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut atm);
        set_rate(&mut atm, &admin, Currency::Eur, "0.86").unwrap();
        // A "friendly" rate for an accomplice: 0.50 is believable but 42% off.
        assert!(matches!(set_rate(&mut atm, &admin, Currency::Eur, "0.50"), Err(AtmError::NotAllowed(_))));
        // 5% within 24 hours: 0.86 -> 0.90 (4.7%) is fine, 0.91 (5.8%) is not.
        assert!(set_rate(&mut atm, &admin, Currency::Eur, "0.91").is_err());
        set_rate(&mut atm, &admin, Currency::Eur, "0.90").unwrap();
        // Steps can't add up: 0.9116 is within 5% of 0.90 but 6% from 0.86.
        assert!(set_rate(&mut atm, &admin, Currency::Eur, "0.9116").is_err());
        set_rate(&mut atm, &admin, Currency::Eur, "0.8858").unwrap();
        // Every change is kept, newest first.
        let history = rate_history(&atm, &admin, Some(Currency::Eur), 10).unwrap();
        let texts: Vec<String> = history.iter().map(|r| r.text()).collect();
        assert_eq!(texts, ["0.8858", "0.90", "0.86"]);
        // Emergency stop: conversions stop at once, and the rate stays capped while paused.
        set_rate(&mut atm, &admin, Currency::Krw, "1385.00").unwrap();
        set_paused(&mut atm, &admin, None, true).unwrap();
        assert!(matches!(charge_for(&atm.conn, Currency::Eur, usd(20), false), Err(AtmError::NotAllowed(_))));
        assert!(matches!(charge_for(&atm.conn, Currency::Krw, usd(20), false), Err(AtmError::NotAllowed(_))));
        assert!(set_rate(&mut atm, &admin, Currency::Eur, "0.70").is_err());
        set_paused(&mut atm, &admin, Some(Currency::Eur), false).unwrap();
        assert!(charge_for(&atm.conn, Currency::Eur, usd(20), false).is_ok());
        assert!(charge_for(&atm.conn, Currency::Krw, usd(20), false).is_err(), "won still paused");
        // History can't be edited or deleted through SQL, and the pause flag is MAC'd.
        assert!(atm.conn.execute("DELETE FROM rate_history", []).is_err());
        atm.conn.execute("UPDATE exchange_rates SET paused = 0 WHERE currency = 'KRW'", []).unwrap();
        assert!(matches!(
            charge_for(&atm.conn, Currency::Krw, usd(20), false),
            Err(AtmError::RecordTampered(_))
        ));
    }
}
