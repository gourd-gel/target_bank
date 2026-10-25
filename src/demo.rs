//! DEMO MODE: sample staff, customers and cash for testing.
//!
//! Only compiled with `cargo run --features demo -- --demo`. The normal build
//! contains none of this, so it ships with no known passwords. Demo data goes in its own files (atm-demo.db / .key) and
//! never touches the real atm.db.
//!
//! Everything is created through the normal admin/handler functions, so the
//! demo data obeys every rule and is fully audit-logged.

use crate::admin::{self, NewCard};
use crate::auth::{self, CardAndPin};
use crate::cash;
use crate::error::{AtmError, Result};
use crate::fx::{self, Currency};
use crate::money::{Cents, Denomination};
use crate::{Atm, db};

/// Demo staff logins. PUBLIC, for testing only.
pub const TELLER: (&str, &str) = ("teller", "teller-demo-2026");
pub const HANDLER: (&str, &str) = ("cashier", "cashier-demo-2026");

/// One sample person: name, DOB, PIN, short label, what makes them interesting.
struct Person {
    name: &'static str,
    dob: &'static str,
    pin: &'static str,
    label: &'static str,
    note: &'static str,
    /// A card from another bank (guest): withdraw and balance only, ATM fee.
    guest: bool,
}

const ANN: Person = Person {
    name: "Ann Lee",
    dob: "1985-04-12",
    pin: "4821",
    label: "Joint with Ben",
    note: "joint account with Ben, $2,500",
    guest: false,
};
const BEN: Person = Person {
    name: "Ben Lee",
    dob: "1983-09-30",
    pin: "7305",
    label: "Joint with Ann",
    note: "joint account with Ann",
    guest: false,
};
const PAT: Person = Person {
    name: "Pat Doe",
    dob: "1979-02-17",
    pin: "1357",
    label: "Guardian of Kid",
    note: "$1,000; guardian of Kid",
    guest: false,
};
const KID: Person = Person {
    name: "Kid Doe",
    dob: "2013-06-06",
    pin: "2580",
    label: "Youth account",
    note: "youth account, $150, parental caps",
    guest: false,
};
const SAM: Person = Person {
    name: "Sam Roe",
    dob: "1990-11-03",
    pin: "9512",
    label: "Individual",
    note: "$800, individual",
    guest: false,
};
const LOU: Person = Person {
    name: "Lou Kim",
    dob: "1975-07-21",
    pin: "8642",
    label: "LOCKED card",
    note: "$300, card LOCKED (practice unlock)",
    guest: false,
};
const EVA: Person = Person {
    name: "Eva Roux",
    dob: "1988-08-19",
    pin: "3691",
    label: "Guest: euro card (EUR)",
    note: "French bank's card, 1,200 EUR; ATM fee + conversion",
    guest: true,
};
const YUKI: Person = Person {
    name: "Yuki Sato",
    dob: "1992-03-08",
    pin: "5274",
    label: "Guest: yen card (JPY)",
    note: "Japanese bank's card, 120,000 JPY (whole yen only)",
    guest: true,
};
const RAY: Person = Person {
    name: "Ray Park",
    dob: "1984-02-02",
    pin: "2468",
    label: "Guest: other bank",
    note: "card from another bank, $400; $3 ATM fee, withdraw/balance only",
    guest: true,
};
const LUIS: Person = Person {
    name: "Luis Pena",
    dob: "1977-10-14",
    pin: "3579",
    label: "Guest: DR bank (DOP)",
    note: "Dominican bank's card, 25,000 DOP; ATM fee + conversion",
    guest: true,
};

/// Every sample customer, in wallet order. Bank of CCNY accounts are in US
/// dollars; the last four are other banks' cards (one in USD, three foreign).
const PEOPLE: [Person; 10] = [ANN, BEN, PAT, KID, SAM, LOU, RAY, EVA, YUKI, LUIS];

/// Sample rates (units per US dollar), set at seed time. They expire after
/// 72 hours like real ones: re-enter them under Teller Admin > Exchange rates.
const SAMPLE_RATES: [(Currency, &str); 15] = [
    (Currency::Eur, "0.86"),
    (Currency::Gbp, "0.75"),
    (Currency::Cny, "7.12"),
    (Currency::Jpy, "151.20"),
    (Currency::Cad, "1.38"),
    (Currency::Mxn, "18.40"),
    (Currency::Dop, "63.50"),
    (Currency::Inr, "88.20"),
    (Currency::Krw, "1385.00"),
    (Currency::Brl, "5.42"),
    (Currency::Jmd, "159.80"),
    (Currency::Cop, "4150.00"),
    (Currency::Bdt, "122.00"),
    (Currency::Htg, "131.00"),
    (Currency::Gyd, "209.00"),
];

/// A line of the cheat sheet printed at start-up.
pub struct Login {
    pub who: &'static str,
    /// A few words for the demo wallet card ("Joint with Ben").
    pub label: &'static str,
    pub card: String,
    pub account: String,
    pub pin: &'static str,
    pub note: &'static str,
    /// Another bank's card (shown differently in the demo wallet).
    pub guest: bool,
}

/// Random integer in lo..=hi from the OS RNG.
fn random_between(lo: u32, hi: u32) -> Result<u32> {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).map_err(|_| AtmError::Internal("no system randomness".into()))?;
    Ok(lo + u32::from_le_bytes(b) % (hi - lo + 1))
}

fn usd(n: u32) -> Cents {
    Cents::from_dollars(n)
}

fn login(p: &Person, card: &NewCard) -> Login {
    Login {
        who: p.name,
        label: p.label,
        card: card.card_number.clone(),
        account: card.account_number.clone(),
        pin: p.pin,
        note: p.note,
        guest: p.guest,
    }
}

/// Fill a brand-new demo database. Returns the customer cheat sheet.
pub fn seed(conn: &mut Atm) -> Result<Vec<Login>> {
    // Marked first, so this database can never be opened as a real bank.
    let tx = conn.begin()?;
    db::mark_demo(&tx)?;
    tx.commit()?;
    auth::first_run_setup(conn, TELLER.0, TELLER.1, HANDLER.0, HANDLER.1)?;
    let admin = auth::login_admin(conn, TELLER.0, TELLER.1)?;
    let handler = auth::login_handler(conn, HANDLER.0, HANDLER.1)?;

    // Cash: a random amount, roughly $25k-$63k, every bill type stocked.
    // $5s are kept short (10-15) so "$100 in $5 bills" (20 bills, under the
    // 40-bill cap) is always refused, which shows the "machine is short,
    // here's what it has" rule.
    for (bill, lo, hi) in [(5, 10, 15), (10, 50, 200), (20, 200, 800), (50, 50, 300), (100, 50, 300)] {
        cash::restock(conn, &handler, Denomination::new(bill)?, random_between(lo, hi)?)?;
    }

    let mut out = Vec::new();
    let ann = admin::create_customer(conn, &admin, ANN.name, ANN.dob, ANN.pin, usd(2500))?;
    out.push(login(&ANN, &ann));
    // Ann is "at the counter": her card and PIN confirm the new joint holder.
    let ann_here = CardAndPin { card_number: &ann.card_number, pin: ANN.pin };
    let ben =
        admin::add_joint_holder(conn, &admin, &ann.account_number, ann_here, BEN.name, BEN.dob, BEN.pin)?;
    out.push(login(&BEN, &ben));
    let pat = admin::create_customer(conn, &admin, PAT.name, PAT.dob, PAT.pin, usd(1000))?;
    out.push(login(&PAT, &pat));
    let pat_here = CardAndPin { card_number: &pat.card_number, pin: PAT.pin };
    let kid = admin::open_youth_account(conn, &admin, pat_here, KID.name, KID.dob, KID.pin, usd(150))?;
    out.push(login(&KID, &kid));
    let sam = admin::create_customer(conn, &admin, SAM.name, SAM.dob, SAM.pin, usd(800))?;
    out.push(login(&SAM, &sam));
    let lou = admin::create_customer(conn, &admin, LOU.name, LOU.dob, LOU.pin, usd(300))?;
    out.push(login(&LOU, &lou));
    // Rates first: a starting balance is checked against the deposit limit in dollars.
    for (currency, rate) in SAMPLE_RATES {
        fx::set_rate(conn, &admin, currency, rate)?;
    }
    // Other banks' cards: the balance is what their own bank would approve,
    // in that bank's currency (Cents::from_dollars(1200) = 1,200.00 EUR).
    for (p, amount, currency) in [
        (&RAY, 400, Currency::Usd),
        (&EVA, 1200, Currency::Eur),
        (&YUKI, 120_000, Currency::Jpy),
        (&LUIS, 25_000, Currency::Dop),
    ] {
        let card = admin::register_guest_card(
            conn,
            &admin,
            p.name,
            p.dob,
            p.pin,
            Cents::from_dollars(amount),
            currency,
        )?;
        out.push(login(p, &card));
    }
    // Lock Lou's card the honest way: three wrong PINs.
    for _ in 0..3 {
        let _ = auth::login_customer(conn, &lou.card_number, "0000");
    }
    auth::logout_admin(conn, admin)?;
    auth::logout_handler(conn, handler)?;
    Ok(out)
}

/// Re-read the cheat sheet from an existing demo database (card numbers are
/// random; names are encrypted, so decrypt each card's name to match).
pub fn cheat_sheet(atm: &Atm) -> Result<Vec<Login>> {
    let conn = &atm.read()?;
    let mut stmt = conn.prepare(
        "SELECT c.card_lookup, c.card_enc, a.account_lookup, a.account_enc, c.name_enc
         FROM cards c JOIN accounts a ON a.id = c.account_id ORDER BY c.id",
    )?;
    let mut rows = stmt.query([])?;
    let mut cards = Vec::new();
    while let Some(r) = rows.next()? {
        let card: String = r.get(0)?;
        let name = db::holder_name(&card, &r.get::<_, Vec<u8>>(4)?)?;
        let card_number = db::open_number(db::Number::Card, &card, &r.get::<_, Vec<u8>>(1)?)?;
        let account =
            db::open_number(db::Number::Account, &r.get::<_, String>(2)?, &r.get::<_, Vec<u8>>(3)?)?;
        cards.push((name, card_number, account));
    }
    let mut out = Vec::new();
    for p in PEOPLE {
        let (_, card, account) =
            cards.iter().find(|(name, _, _)| name == p.name).ok_or(AtmError::NotFound("Demo customer"))?;
        out.push(Login {
            who: p.name,
            label: p.label,
            card: card.clone(),
            account: account.clone(),
            pin: p.pin,
            note: p.note,
            guest: p.guest,
        });
    }
    Ok(out)
}

/// TEST BUILDS ONLY (`--features integrity-test`): makes the books wrong
/// the way a bad code path would. Adds $500 to one demo balance with no log
/// entry, through the ATM itself, so the database seal still matches and only
/// the integrity check can catch it. The next Teller Admin sign-in must show
/// the red banner and take the ATM out of service. Demo data only.
#[cfg(feature = "integrity-test")]
pub fn break_integrity(atm: &mut Atm) -> Result<()> {
    let tx = atm.begin()?;
    if !db::is_demo(&tx)? {
        return Err(AtmError::NotAllowed("only demo data can be broken on purpose"));
    }
    tx.execute(
        "UPDATE accounts SET balance_cents = balance_cents + 50000
         WHERE id = (SELECT MIN(id) FROM accounts WHERE kind = 'joint')",
        [],
    )?;
    tx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_builds_a_consistent_demo_bank() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let logins = seed(&mut conn).unwrap();
        assert_eq!(logins.len(), PEOPLE.len());
        assert_eq!(logins[0].account, logins[1].account, "Ann and Ben share an account");
        assert_eq!(cheat_sheet(&conn).unwrap()[3].card, logins[3].card);
        // Ann can log in; Lou is locked; ledger is consistent.
        let ann = auth::login_customer(&mut conn, &logins[0].card, ANN.pin).unwrap();
        // Demo script: $100 in $5s is always refused and names the other bills.
        let five = Denomination::new(5).unwrap();
        match crate::customer::quote_withdrawal(
            &conn,
            &ann,
            usd(100),
            crate::dispense::BillChoice::Only(five),
        ) {
            Err(AtmError::DenominationUnavailable { available, .. }) => {
                assert_eq!(available, vec![10, 20, 50, 100]);
            }
            other => panic!("expected DenominationUnavailable, got {other:?}"),
        }
        assert!(matches!(
            auth::login_customer(&mut conn, &logins[5].card, LOU.pin),
            Err(AtmError::CardLocked)
        ));
        let admin = auth::login_admin(&mut conn, TELLER.0, TELLER.1).unwrap();
        assert_eq!(admin::verify_integrity(&mut conn, &admin).unwrap().accounts_checked, 9);
        // Our own accounts are all in dollars; only other banks' cards aren't.
        let foreign_own: i64 = conn
            .conn
            .query_row("SELECT COUNT(*) FROM accounts WHERE currency != 'USD' AND kind != 'guest'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(foreign_own, 0);
        // The yen card gets dollars at the sample rate plus fees (whole yen only).
        let yuki = auth::login_customer(&mut conn, &logins[8].card, YUKI.pin).unwrap();
        assert_eq!(crate::customer::account_info(&conn, &yuki).unwrap().currency, Currency::Jpy);
        let charge = crate::customer::check_withdrawal(&conn, &yuki, usd(100)).unwrap();
        assert!(charge.account_amount > Cents::from_dollars(15_120), "{charge:?}"); // 100 x 151.20 + fees
    }
}
