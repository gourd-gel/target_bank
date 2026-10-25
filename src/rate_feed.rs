//! Daily exchange-rate feed: fetch, check, then a teller approves.
//!
//! A Teller Admin presses "Check today's rates": one request to one fixed source, old vs new
//! shown for every currency, nothing changed until the teller approves.
//!
//! STRIDE:
//!   * Spoofing: HTTPS only, certificate checked (rustls + Mozilla roots), fixed URL, no
//!     redirects.
//!   * Tampering: a feed is only a proposal. Approved rates get the same range check, MAC and
//!     signed log as typed ones, set in full (not capped); a move over 5% in 24 hours is set
//!     but paused until a teller resumes it. The log names the feed and its publish time.
//!   * Repudiation: a failed check is logged with its reason; an untrusted certificate gets
//!     its own message, so an attack doesn't pass for an outage.
//!   * Denial of service: only a teller's button fetches (never a customer or background
//!     task); 10 s timeout; 64 KB cap; a failed fetch changes nothing.
//!   * Elevation: strict parsing (USD base, success flag, recent publish time, numbers only);
//!     a bad entry is skipped, not guessed at.
//!
//! Only `fetch` (feature `online-rates`) goes online; the rest is tested with saved text.

use crate::Atm;
use crate::auth::AdminSession;
use crate::error::{AtmError, Result};
use crate::fx::{self, Currency};
#[cfg(any(test, feature = "online-rates"))]
use chrono::{DateTime, Utc};
use rusqlite::Connection;

/// Who publishes the feed (shown to the teller and written to the log).
pub const FEED_SOURCE: &str = "open.er-api.com";
/// The one address ever fetched: today's rates per US dollar.
pub const FEED_URL: &str = "https://open.er-api.com/v6/latest/USD";
/// Credit the source asks for.
pub const FEED_CREDIT: &str = "Rates by Exchange Rate API (exchangerate-api.com)";
/// Largest response read (the real one is about 3 KB).
pub const FEED_MAX_BYTES: u64 = 64 * 1024;
/// A feed published longer ago than this is refused (the source updates daily).
#[cfg(any(test, feature = "online-rates"))]
const FEED_MAX_AGE_HOURS: i64 = 48;

/// Today's proposed rates, as published. Only `fetch` makes one: the fields
/// are private and there is no public parser, so a front end can't hand in
/// rates of its own choosing (they would skip the 5% limit on typed rates)
/// or text of its own for the log.
#[derive(Debug, Clone)]
pub struct Feed {
    /// When the source published these rates ("2026-10-12 00:02 UTC").
    published: String,
    /// Units per US dollar in millionths; None if missing or not a usable number.
    rates: Vec<(Currency, Option<i64>)>,
}

impl Feed {
    /// When the source published these rates ("2026-10-12 00:02 UTC").
    pub fn published(&self) -> &str {
        &self.published
    }
}

/// One currency on the review screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateCheck {
    pub currency: Currency,
    /// Current rate ("0.86"), "not set", or "ALTERED".
    pub current: String,
    /// The feed's rate, or "missing".
    pub feed: String,
    /// What approving sets; None leaves this currency as it is.
    pub set_to: Option<String>,
    /// "+0.14%", "big move: +10.00%; will be paused",
    /// "outside the believable range: not used"...
    pub note: String,
    /// Approving also pauses this currency (a move over 5% in 24 hours).
    pub pauses: bool,
}

/// Failure messages (the error adds "Rates are unchanged; you can still type a rate.").
#[cfg(feature = "online-rates")]
const UNREACHABLE: &str = "Couldn't reach today's rate feed";
#[cfg(feature = "online-rates")]
const UNTRUSTED: &str =
    "The connection to today's rate feed failed its security check (certificate not trusted)";
#[cfg(any(test, feature = "online-rates"))]
const BAD_FORM: &str = "Today's rate feed was not in the expected form";

/// One HTTPS request to the fixed feed address. Only a teller's button press
/// calls this. Changes no rates: the result goes to `check`, then `approve`.
/// A failure is logged with its reason.
#[cfg(feature = "online-rates")]
pub fn fetch(atm: &mut Atm, session: &AdminSession) -> Result<Feed> {
    atm.admit(session)?;
    read_logged(atm, session, download())
}

/// The request itself: TLS settings, size cap, each failure named.
#[cfg(feature = "online-rates")]
fn download() -> Result<String> {
    use std::time::Duration;
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
    // rustls (TLS 1.2/1.3 only, no weak ciphers), certificate checked against
    // the Mozilla root list built into the program.
    let tls = TlsConfig::builder().provider(TlsProvider::Rustls).root_certs(RootCerts::WebPki).build();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let mut response = agent.get(FEED_URL).call().map_err(failure)?;
    response.body_mut().with_config().limit(FEED_MAX_BYTES).read_to_string().map_err(failure)
}

/// Name the failure. rustls reports a refused certificate as invalid data.
#[cfg(feature = "online-rates")]
fn failure(e: ureq::Error) -> AtmError {
    use ureq::Error as E;
    AtmError::FeedUnavailable(match e {
        E::Io(io) if io.kind() == std::io::ErrorKind::InvalidData => UNTRUSTED,
        E::Rustls(_) | E::Tls(_) | E::TlsRequired | E::RequireHttpsOnly(_) => UNTRUSTED,
        E::BodyExceedsLimit(_) => BAD_FORM,
        _ => UNREACHABLE,
    })
}

/// Parse what the download returned. Any failure is logged with its reason
/// (STRIDE Repudiation), then returned; nothing else changes.
#[cfg(any(test, feature = "online-rates"))]
fn read_logged(atm: &mut Atm, session: &AdminSession, body: Result<String>) -> Result<Feed> {
    use crate::audit::{self, Action, Entry};
    let feed = body.and_then(|b| parse(&b));
    if let Err(AtmError::FeedUnavailable(why)) = &feed {
        let entry = Entry {
            actor: &session.actor(),
            action: Action::RateFeedFailed,
            account_id: None,
            counterparty_id: None,
            amount: None,
            usd: None,
            detail: &format!("{why} ({FEED_SOURCE})"),
        };
        let tx = atm.begin()?;
        audit::append(&tx, &entry)?;
        tx.commit()?;
    }
    feed
}

/// Read a feed response. Strict: anything unexpected is refused or skipped.
/// Inside the library only (see `Feed`).
#[cfg(any(test, feature = "online-rates"))]
fn parse(body: &str) -> Result<Feed> {
    parse_at(body, Utc::now())
}

/// `parse` with a given "now", so tests can check the publish-time rule.
#[cfg(any(test, feature = "online-rates"))]
fn parse_at(body: &str, now: DateTime<Utc>) -> Result<Feed> {
    let bad = || AtmError::FeedUnavailable(BAD_FORM);
    if body.len() as u64 > FEED_MAX_BYTES {
        return Err(bad());
    }
    let json: serde_json::Value = serde_json::from_str(body).map_err(|_| bad())?;
    if json["result"] != "success" || json["base_code"] != "USD" {
        return Err(bad());
    }
    let unix = json["time_last_update_unix"].as_i64().ok_or_else(bad)?;
    let published = DateTime::<Utc>::from_timestamp(unix, 0).ok_or_else(bad)?;
    let age = now.signed_duration_since(published);
    if age.num_hours() >= FEED_MAX_AGE_HOURS || age.num_minutes() < -5 {
        return Err(AtmError::FeedUnavailable("Today's rate feed is out of date"));
    }
    let table = json["rates"].as_object().ok_or_else(bad)?;
    let rates = Currency::FOREIGN
        .into_iter()
        .map(|c| (c, table.get(c.code()).and_then(serde_json::Value::as_f64).and_then(to_micros)))
        .collect();
    Ok(Feed { published: published.format("%Y-%m-%d %H:%M UTC").to_string(), rates })
}

/// A feed number to millionths, through the same strict parser as a typed rate.
#[cfg(any(test, feature = "online-rates"))]
fn to_micros(value: f64) -> Option<i64> {
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    fx::parse_fixed(&format!("{value:.6}"), 6).filter(|m| *m > 0)
}

/// What approving this feed would do, currency by currency. Changes nothing.
pub fn check(atm: &Atm, session: &AdminSession, feed: &Feed) -> Result<Vec<RateCheck>> {
    atm.admit(session)?;
    Ok(plan(&*atm.read()?, feed)?.into_iter().map(|(check, _, _)| check).collect())
}

/// Set every rate the review showed. `shown` is the list the teller looked
/// at: if anything changed since (another teller, the 24-hour window),
/// nothing is set and the teller checks again. Returns how many were set.
pub fn approve(atm: &mut Atm, session: &AdminSession, feed: &Feed, shown: &[RateCheck]) -> Result<usize> {
    atm.admit(session)?;
    let tx = atm.begin()?;
    let planned = plan(&tx, feed)?;
    if planned.iter().map(|(c, _, _)| c).ne(shown.iter()) {
        return Err(AtmError::NotAllowed("rates changed since you checked them; please check again"));
    }
    let mut set = 0;
    for (check, micros, pause) in &planned {
        let Some(micros) = *micros else { continue };
        // Belt and braces: never store a rate outside the believable range.
        let (low, high) = check.currency.plausible();
        if !(low..=high).contains(&micros) {
            return Err(AtmError::NotAllowed("a feed rate is outside the believable range"));
        }
        let how = format!(" (daily feed {FEED_SOURCE}, published {}; {})", feed.published, check.note);
        fx::store_rate(&tx, session, check.currency, micros, &how, *pause)?;
        set += 1;
    }
    tx.commit()?;
    Ok(set)
}

/// Each currency's review line, the rate approval would store, and whether
/// approving pauses the currency (a move over 5% in 24 hours).
fn plan(conn: &Connection, feed: &Feed) -> Result<Vec<(RateCheck, Option<i64>, bool)>> {
    let mut out = Vec::new();
    for &(currency, proposed) in &feed.rates {
        let (current, now_micros, paused) = match fx::read_rate(conn, currency) {
            Ok(Some(r)) => (r.text(), Some(r.per_usd_micros), r.paused),
            Ok(None) => ("not set".to_string(), None, false),
            Err(AtmError::RecordTampered(_)) => ("ALTERED".to_string(), None, true),
            Err(e) => return Err(e),
        };
        let line = |feed: String, set: Option<i64>, note: String, pause: bool| {
            let note = match (set.is_some(), paused, pause) {
                (true, true, _) => format!("{note}; stays paused"),
                (true, false, true) => format!("{note}; will be paused"),
                _ => note,
            };
            let pauses = pause && !paused;
            let set_to = set.map(fx::rate_text);
            (RateCheck { currency, current: current.clone(), feed, set_to, note, pauses }, set, pauses)
        };
        let Some(proposed) = proposed else {
            out.push(line("missing".into(), None, "not in today's feed: unchanged".into(), false));
            continue;
        };
        let feed_text = fx::rate_text(proposed);
        let (low, high) = currency.plausible();
        if !(low..=high).contains(&proposed) {
            out.push(line(feed_text, None, "outside the believable range: not used".into(), false));
            continue;
        }
        let entry = match fx::allowed_band(conn, currency)? {
            None => line(feed_text, Some(proposed), "first rate".into(), false),
            Some((low, high)) => {
                let from = now_micros.unwrap_or(proposed);
                // Over 5% in 24 hours: still the market rate, but a person looks first.
                let big = proposed != from && !(low..=high).contains(&proposed);
                let note = match (proposed == from, big) {
                    (true, _) => "no change (date refreshed)".to_string(),
                    (false, false) => change_text(from, proposed),
                    (false, true) => format!("big move: {}", change_text(from, proposed)),
                };
                line(feed_text, Some(proposed), note, big)
            }
        };
        out.push(entry);
    }
    Ok(out)
}

/// "+0.14%" / "-2.50%" from one rate to another (to the nearest 0.01%).
fn change_text(from: i64, to: i64) -> String {
    let diff = i128::from(to) - i128::from(from);
    let base = i128::from(from.max(1));
    let bp = (diff.abs() * 10_000 * 2 + base) / (2 * base);
    let sign = if diff < 0 { "-" } else { "+" };
    format!("{sign}{}.{:02}%", bp / 100, bp % 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testing::setup;
    use chrono::TimeZone;

    /// A feed in the source's format, published `hours_ago`, with `eur` and `jpy`.
    fn body(hours_ago: i64, eur: &str, jpy: &str) -> String {
        body_at((Utc::now() - chrono::Duration::hours(hours_ago)).timestamp(), eur, jpy)
    }
    fn body_at(t: i64, eur: &str, jpy: &str) -> String {
        format!(
            r#"{{"result":"success","provider":"https://www.exchangerate-api.com",
               "time_last_update_unix":{t},"base_code":"USD",
               "rates":{{"USD":1,"EUR":{eur},"GBP":0.7512,"JPY":{jpy},"MXN":18.42,"XAU":0.0004}}}}"#
        )
    }

    #[test]
    fn a_feed_is_read_strictly() {
        let feed = parse(&body(3, "0.8612", "151.37")).unwrap();
        let eur = feed.rates.iter().find(|(c, _)| *c == Currency::Eur).unwrap().1;
        assert_eq!(eur, Some(861_200));
        // A currency the feed lacks is listed as missing, not guessed.
        assert_eq!(feed.rates.iter().find(|(c, _)| *c == Currency::Dop).unwrap().1, None);
        // Wrong base, failed result, junk, too old, from the future, too big: refused.
        assert!(parse(&body(3, "0.86", "151").replace("\"USD\",", "\"EUR\",")).is_err());
        assert!(parse(&body(3, "0.86", "151").replace("success", "error")).is_err());
        assert!(parse("<html>captive portal</html>").is_err());
        assert!(parse(&body(49, "0.86", "151")).is_err());
        assert!(parse(&body(-1, "0.86", "151")).is_err());
        assert!(parse(&" ".repeat(70 * 1024)).is_err());
        // Negative, zero, text or absurd numbers become "missing".
        for bad in ["-0.86", "0", "\"0.86\"", "1e300"] {
            let feed = parse(&body(3, bad, "151")).unwrap();
            assert_eq!(feed.rates.iter().find(|(c, _)| *c == Currency::Eur).unwrap().1, None, "{bad}");
        }
        let fixed = Utc.with_ymd_and_hms(2026, 10, 12, 0, 2, 0).unwrap();
        let text = body_at(fixed.timestamp(), "0.86", "151");
        assert_eq!(parse_at(&text, fixed).unwrap().published, "2026-10-12 00:02 UTC");
    }

    #[test]
    fn approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut atm);
        fx::set_rate(&mut atm, &admin, Currency::Eur, "0.86").unwrap();
        fx::set_rate(&mut atm, &admin, Currency::Jpy, "151.20").unwrap();
        // EUR +0.14%: used. JPY +10%: used in full, but paused. GBP, MXN: first rates.
        let feed = parse(&body(3, "0.8612", "166.32")).unwrap();
        let shown = check(&atm, &admin, &feed).unwrap();
        let line = |c: Currency| shown.iter().find(|l| l.currency == c).unwrap().clone();
        assert_eq!(
            (line(Currency::Eur).set_to.as_deref(), line(Currency::Eur).note.as_str()),
            (Some("0.8612"), "+0.14%")
        );
        assert_eq!(line(Currency::Jpy).set_to.as_deref(), Some("166.32"));
        assert_eq!(line(Currency::Jpy).note, "big move: +10.00%; will be paused");
        assert!(line(Currency::Jpy).pauses && !line(Currency::Eur).pauses);
        assert_eq!(line(Currency::Gbp).note, "first rate");
        assert_eq!((line(Currency::Dop).set_to, line(Currency::Dop).feed.as_str()), (None, "missing"));
        // Checking changed nothing; approving sets exactly what was shown.
        assert_eq!(fx::read_rate(&atm.conn, Currency::Eur).unwrap().unwrap().text(), "0.86");
        assert_eq!(approve(&mut atm, &admin, &feed, &shown).unwrap(), 4);
        let jpy = fx::read_rate(&atm.conn, Currency::Jpy).unwrap().unwrap();
        assert_eq!((jpy.text(), jpy.paused), ("166.32".to_string(), true));
        assert!(!fx::read_rate(&atm.conn, Currency::Eur).unwrap().unwrap().paused);
        let detail = |action: &str| -> String {
            atm.conn
                .query_row(
                    "SELECT detail FROM audit_log WHERE action = ?1 AND detail LIKE 'JPY%' ORDER BY seq DESC",
                    [action],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let changed = detail("rate_changed");
        assert!(
            changed.starts_with("JPY per USD: 151.20 -> 166.32 (daily feed open.er-api.com, published "),
            "{changed}"
        );
        assert!(changed.ends_with("; big move: +10.00%; will be paused)"));
        assert_eq!(detail("exchange_paused"), "JPY (big move in today's feed: check it, then resume)");
        // Checking again changes nothing for JPY; a stale review is refused.
        let again = check(&atm, &admin, &feed).unwrap();
        let jpy = again.iter().find(|l| l.currency == Currency::Jpy).unwrap();
        assert_eq!(jpy.note, "no change (date refreshed); stays paused");
        assert!(matches!(approve(&mut atm, &admin, &feed, &shown), Err(AtmError::NotAllowed(_))));
        // After a teller resumes it, a typed rate still can't jump back today.
        fx::set_paused(&mut atm, &admin, Some(Currency::Jpy), false).unwrap();
        assert!(fx::set_rate(&mut atm, &admin, Currency::Jpy, "152.00").is_err());
        // A rate outside the believable range is never used.
        let silly = parse(&body(3, "0.01", "151.20")).unwrap();
        let eur =
            check(&atm, &admin, &silly).unwrap().into_iter().find(|l| l.currency == Currency::Eur).unwrap();
        assert_eq!((eur.set_to, eur.note.as_str()), (None, "outside the believable range: not used"));
        assert!(crate::admin::verify_integrity(&mut atm, &admin).unwrap().records_checked > 0);
    }

    #[test]
    fn a_paused_currency_takes_the_new_rate_but_stays_paused() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut atm);
        fx::set_rate(&mut atm, &admin, Currency::Eur, "0.86").unwrap();
        fx::set_paused(&mut atm, &admin, Some(Currency::Eur), true).unwrap();
        let feed = parse(&body(3, "0.86", "151")).unwrap();
        let shown = check(&atm, &admin, &feed).unwrap();
        let eur = shown.iter().find(|l| l.currency == Currency::Eur).unwrap();
        assert_eq!(eur.note, "no change (date refreshed); stays paused");
        approve(&mut atm, &admin, &feed, &shown).unwrap();
        assert!(fx::read_rate(&atm.conn, Currency::Eur).unwrap().unwrap().paused);
    }

    #[test]
    fn a_failed_check_is_logged_with_its_reason_and_changes_nothing() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = setup(&mut atm);
        fx::set_rate(&mut atm, &admin, Currency::Eur, "0.86").unwrap();
        let refused = Err(AtmError::FeedUnavailable("certificate not trusted"));
        assert!(read_logged(&mut atm, &admin, refused).is_err());
        assert!(read_logged(&mut atm, &admin, Ok("<html>captive portal</html>".into())).is_err());
        assert!(read_logged(&mut atm, &admin, Ok(body(3, "0.8612", "151"))).is_ok());
        let mut stmt = atm
            .conn
            .prepare("SELECT actor, detail FROM audit_log WHERE action = 'rate_feed_failed' ORDER BY seq")
            .unwrap();
        let rows: Vec<(String, String)> =
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1, "certificate not trusted (open.er-api.com)");
        assert_eq!(rows[1].1, "Today's rate feed was not in the expected form (open.er-api.com)");
        assert_eq!(rows[0].0, admin.actor());
        // No rate changed, and the log chain still checks out.
        assert_eq!(fx::read_rate(&atm.conn, Currency::Eur).unwrap().unwrap().text(), "0.86");
        assert!(crate::audit::verify(&atm.conn).is_ok());
    }

    #[cfg(feature = "online-rates")]
    #[test]
    fn each_kind_of_fetch_failure_gets_its_own_message() {
        use std::io::{Error, ErrorKind};
        let message = |e| match failure(e) {
            AtmError::FeedUnavailable(m) => m,
            _ => "",
        };
        // How rustls reports a refused certificate (seen behind an HTTPS-inspecting proxy).
        let cert = Error::new(ErrorKind::InvalidData, "invalid peer certificate: UnknownIssuer");
        assert_eq!(message(ureq::Error::Io(cert)), UNTRUSTED);
        assert_eq!(message(ureq::Error::RequireHttpsOnly("http://x".into())), UNTRUSTED);
        assert_eq!(message(ureq::Error::BodyExceedsLimit(FEED_MAX_BYTES)), BAD_FORM);
        assert_eq!(message(ureq::Error::ConnectionFailed), UNREACHABLE);
        assert_eq!(message(ureq::Error::HostNotFound), UNREACHABLE);
    }
}
