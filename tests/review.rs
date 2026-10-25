//! First security review: a dishonest teller, a customer, and someone who
//! can edit atm.db. Each test asserts the SAFE result.

use atm::auth::CardAndPin;
use atm::db::Limit;
use atm::error::AtmError;
use atm::money::{Cents, Denomination};
use atm::{Atm, admin, auth, cash, customer, family};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

const ADMIN: (&str, &str) = ("teller_one", "teller-password-1");
const HANDLER: (&str, &str) = ("cash_one", "handler-password-1");

/// A set-up bank with 500 x $20 loaded and an admin session. One key file
/// for every bank in this test run (the process holds a single key).
fn bank() -> (Atm, auth::AdminSession, PathBuf, PathBuf) {
    static N: AtomicU32 = AtomicU32::new(0);
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir().join(format!("atm-review-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let n = N.fetch_add(1, Ordering::SeqCst);
    let (db, key) = (dir.join(format!("bank-{n}.db")), dir.join("shared.key"));
    let mut atm = Atm::create(&db, &key).unwrap();
    auth::first_run_setup(&mut atm, ADMIN.0, ADMIN.1, HANDLER.0, HANDLER.1).unwrap();
    let h = auth::login_handler(&mut atm, HANDLER.0, HANDLER.1).unwrap();
    cash::restock(&mut atm, &h, d(20), 500).unwrap();
    let a = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    (atm, a, db, key)
}

fn raw(db: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(db).unwrap()
}
fn usd(n: u32) -> Cents {
    Cents::from_dollars(n)
}
fn d(n: u32) -> Denomination {
    Denomination::new(n).unwrap()
}

#[test]
fn a1_emptying_the_staff_table_does_not_reopen_first_run_setup() {
    let (atm, _a, db, key) = bank();
    drop(atm);
    raw(&db).execute("DELETE FROM staff", []).unwrap();
    let took_over = Atm::open(&db, &key).is_ok_and(|mut atm| {
        auth::first_run_setup(&mut atm, "mallory", "mallory-password-1", "mallory_cash", "mallory-password-2")
            .is_ok()
            && auth::login_admin(&mut atm, "mallory", "mallory-password-1").is_ok()
    });
    assert!(!took_over, "deleting the staff rows let the attacker create their own Teller Admin");
}

#[test]
fn a2_resetting_card_columns_does_not_give_unlimited_pin_guesses() {
    let (mut atm, a, db, _key) = bank();
    let victim = admin::create_customer(&mut atm, &a, "Vic Tim", "1980-01-01", "4821", usd(900)).unwrap();
    let mut checked = 0;
    for guess in ["0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008", "0009"] {
        raw(&db).execute("UPDATE cards SET failed_attempts = 0, locked = 0", []).unwrap();
        if matches!(auth::login_customer(&mut atm, &victim.card_number, guess), Err(AtmError::AuthFailed)) {
            checked += 1;
        }
    }
    assert!(checked <= 3, "{checked} wrong PINs were checked without a lock");
}

#[test]
fn b1_a_teller_cannot_take_over_an_account_by_adding_a_joint_holder() {
    let (mut atm, a, _db, _key) = bank();
    let victim = admin::create_customer(&mut atm, &a, "Vic Tim", "1980-01-01", "4821", usd(1500)).unwrap();
    let mule = admin::create_customer(&mut atm, &a, "Mal Lory", "1975-05-05", "7305", Cents::ZERO).unwrap();
    let rogue = admin::add_joint_holder(
        &mut atm,
        &a,
        &victim.account_number,
        CardAndPin { card_number: &victim.card_number, pin: "1111" },
        "Mal Lory",
        "1975-05-05",
        "9512",
    );
    let stolen = rogue.as_ref().map(|card| {
        let s = auth::login_customer(&mut atm, &card.card_number, "9512").unwrap();
        customer::transfer(&mut atm, &s, &mule.account_number, usd(900)).is_ok()
    });
    assert!(!matches!(stolen, Ok(true)), "a teller-added joint card moved $900 out of the victim's account");
}

#[test]
fn b2_a_teller_cannot_mint_unbacked_money() {
    let (mut atm, a, _db, _key) = bank();
    let huge = Cents::new(100_000_000_000_000).unwrap();
    let minted = admin::create_customer(&mut atm, &a, "Mal Lory", "1975-05-05", "7305", huge);
    let uncapped = admin::set_limit(&mut atm, &a, Limit::Transfer, huge);
    assert!(minted.is_err(), "the core accepted a $1 trillion starting balance with no cash behind it");
    assert!(uncapped.is_err(), "the core accepted a $1 trillion daily transfer limit");
}

#[test]
fn b3_a_teller_cannot_lift_a_guardian_freeze_by_appointing_a_guardian() {
    let (mut atm, a, _db, _key) = bank();
    let pat = admin::create_customer(&mut atm, &a, "Pat Doe", "1980-03-03", "4821", usd(10)).unwrap();
    let mal = admin::create_customer(&mut atm, &a, "Mal Lory", "1975-05-05", "7305", Cents::ZERO).unwrap();
    let kid = admin::open_youth_account(
        &mut atm,
        &a,
        CardAndPin { card_number: &pat.card_number, pin: "4821" },
        "Kid Doe",
        "2014-06-06",
        "2580",
        usd(300),
    )
    .unwrap();
    let p = auth::login_customer(&mut atm, &pat.card_number, "4821").unwrap();
    family::set_frozen(&mut atm, &p, &kid.account_number, true).unwrap();
    // The teller doesn't know the parent's PIN, so has to guess.
    let guess = CardAndPin { card_number: &pat.card_number, pin: "1111" };
    let _ = admin::add_guardian(&mut atm, &a, &kid.account_number, guess, &mal.card_number);
    let m = auth::login_customer(&mut atm, &mal.card_number, "7305").unwrap();
    let lifted = family::set_frozen(&mut atm, &m, &kid.account_number, false).is_ok();
    assert!(!lifted, "a guardian the teller appointed lifted the parent's freeze");
}

#[test]
fn b4_closing_guardians_one_by_one_cannot_orphan_a_youth_account() {
    let (mut atm, a, _db, _key) = bank();
    let pat = admin::create_customer(&mut atm, &a, "Pat Doe", "1980-03-03", "4821", Cents::ZERO).unwrap();
    let sam = admin::create_customer(&mut atm, &a, "Sam Doe", "1981-04-04", "7305", Cents::ZERO).unwrap();
    let kid = admin::open_youth_account(
        &mut atm,
        &a,
        CardAndPin { card_number: &pat.card_number, pin: "4821" },
        "Kid Doe",
        "2014-06-06",
        "2580",
        usd(300),
    )
    .unwrap();
    let pat_here = CardAndPin { card_number: &pat.card_number, pin: "4821" };
    admin::add_guardian(&mut atm, &a, &kid.account_number, pat_here, &sam.card_number).unwrap();
    admin::close_account(&mut atm, &a, &pat.account_number).unwrap();
    let second = admin::close_account(&mut atm, &a, &sam.account_number);
    assert!(second.is_err(), "the last open guardian was closed; the youth account has no guardian left");
}

#[test]
fn b6_a_teller_cannot_guess_a_pin_by_unlocking_between_tries() {
    let (mut atm, a, _db, _key) = bank();
    let card = admin::create_customer(&mut atm, &a, "Ann Lee", "1985-04-12", "4821", usd(100)).unwrap();
    let guesses = (0..11).map(|i| format!("{:04}", 5000 + i)).chain(["4821".to_string()]);
    let mut unlocks = 0;
    let mut found = false;
    for g in guesses {
        match auth::login_customer(&mut atm, &card.card_number, &g) {
            Ok(_) => {
                found = true;
                break;
            }
            Err(AtmError::CardLocked) => {
                if admin::unlock_card(&mut atm, &a, &card.card_number).is_err() {
                    break;
                }
                unlocks += 1;
            }
            Err(_) => {}
        }
    }
    assert!(!found, "the PIN was found on guess 12 after {unlocks} unlocks");
}

#[test]
fn c1_a_real_card_and_an_unknown_card_fail_the_same_way() {
    let (mut atm, a, _db, _key) = bank();
    let card = admin::create_customer(&mut atm, &a, "Ann Lee", "1985-04-12", "4821", usd(100)).unwrap();
    let fake = if card.card_number == "1234567890" { "1234567891" } else { "1234567890" };
    for i in 0..3 {
        let real = auth::login_customer(&mut atm, &card.card_number, "0000").err().map(|e| e.to_string());
        let unknown = auth::login_customer(&mut atm, fake, "0000").err().map(|e| e.to_string());
        assert_eq!(real, unknown, "try {}: the message shows which card number exists", i + 1);
    }
}

#[test]
fn c2_one_deposit_cannot_take_more_than_200_bills_of_a_kind() {
    let (mut atm, a, _db, _key) = bank();
    let c = admin::create_customer(&mut atm, &a, "Ann Lee", "1980-01-01", "4821", Cents::ZERO).unwrap();
    let s = auth::login_customer(&mut atm, &c.card_number, "4821").unwrap();
    let r = customer::deposit(&mut atm, &s, &[(d(5), 200), (d(5), 200), (d(5), 200), (d(5), 200)]);
    assert!(r.is_err(), "800 x $5 were accepted in one deposit");
}

#[test]
fn a5_deleting_the_database_but_keeping_the_key_does_not_reopen_first_run_setup() {
    let (atm, _a, db, key) = bank();
    drop(atm);
    std::fs::remove_file(&db).unwrap();
    let reopened = Atm::open(&db, &key).map(|a| a.needs_setup().unwrap_or(false));
    assert!(!matches!(reopened, Ok(true)), "the key survived but the bank was gone, and setup was offered");
}

#[test]
fn a6_resetting_staff_columns_does_not_remove_the_password_pause() {
    let (mut atm, _a, db, _key) = bank();
    let paused = |db: &Path| -> i64 {
        raw(db)
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE detail = 'staff login during cooldown'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    let mut checked = 0;
    for i in 0..9 {
        raw(&db).execute("UPDATE staff SET failed_attempts = 0, cooldown_until = NULL", []).unwrap();
        let before = paused(&db);
        let got = auth::login_admin(&mut atm, ADMIN.0, &format!("wrong-guess-{i:04}"));
        // Only a plain "wrong password" means the guess was really checked.
        // A pause or "database altered" means it was refused unchecked.
        if matches!(got, Err(AtmError::AuthFailed)) && paused(&db) == before {
            checked += 1;
        }
    }
    assert!(checked <= 3, "{checked} admin password guesses were checked without a pause");
}

#[test]
fn a3_a_typed_in_balance_is_not_spendable() {
    let (mut atm, a, db, _key) = bank();
    let mallory = admin::create_customer(&mut atm, &a, "Mal Lory", "1980-01-01", "7302", usd(1)).unwrap();
    raw(&db).execute("UPDATE accounts SET balance_cents = balance_cents + 40000", []).unwrap();
    // Refusing the login (database altered) is also a safe answer.
    if let Ok(s) = auth::login_customer(&mut atm, &mallory.card_number, "7302") {
        let got = customer::withdraw(&mut atm, &s, usd(400), atm::dispense::BillChoice::Only(d(20)));
        assert!(got.is_err(), "withdrew $400 that only exists because it was typed into the file");
    }
}

#[test]
fn a4_clearing_the_frozen_flag_does_not_lift_a_bank_freeze() {
    let (mut atm, a, db, _key) = bank();
    let mallory = admin::create_customer(&mut atm, &a, "Mal Lory", "1980-01-01", "7302", usd(300)).unwrap();
    admin::set_frozen(&mut atm, &a, &mallory.account_number, true).unwrap();
    raw(&db).execute("UPDATE accounts SET frozen = 0", []).unwrap();
    if let Ok(s) = auth::login_customer(&mut atm, &mallory.card_number, "7302") {
        let got = customer::withdraw(&mut atm, &s, usd(100), atm::dispense::BillChoice::Only(d(20)));
        assert!(got.is_err(), "money left an account the bank froze");
    }
}
