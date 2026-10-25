//! Attacks on the bank core, from hostile front-end code (public API only)
//! and from someone who can edit the database file (but has no key file).

use atm::auth::CardAndPin;
use atm::cash;
use atm::db::Limit;
use atm::dispense::BillChoice;
use atm::error::AtmError;
use atm::fx::Currency;
use atm::money::{Cents, Denomination};
use atm::{Atm, admin, auth, customer, family};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

const ADMIN: (&str, &str) = ("teller_one", "teller-password-1");
const HANDLER: (&str, &str) = ("cash_one", "handler-password-1");

/// Fresh database per test; one key file for the whole test binary (the
/// process holds a single key), so new banks use `Atm::create`.
fn paths() -> (PathBuf, PathBuf) {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("atm-attacks-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let n = N.fetch_add(1, Ordering::SeqCst);
    (dir.join(format!("bank-{n}.db")), dir.join("shared.key"))
}

/// A brand-new bank (one at a time: the first call creates the shared key file).
fn new_bank(db: &Path, key: &Path) -> Atm {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    Atm::create(db, key).unwrap()
}

/// A set-up bank plus the path of its database file, for editing behind its back.
fn bank_on_disk() -> (Atm, PathBuf) {
    let (db, key) = paths();
    let mut atm = new_bank(&db, &key);
    auth::first_run_setup(&mut atm, ADMIN.0, ADMIN.1, HANDLER.0, HANDLER.1).unwrap();
    (atm, db)
}

fn bank() -> Atm {
    bank_on_disk().0
}

/// Bank with 500 x $20 loaded and an admin session.
fn stocked() -> (Atm, auth::AdminSession) {
    let mut atm = bank();
    let handler = auth::login_handler(&mut atm, HANDLER.0, HANDLER.1).unwrap();
    cash::restock(&mut atm, &handler, d(20), 500).unwrap();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    (atm, admin_s)
}

fn raw(db: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(db).unwrap()
}

fn reopen(db: &Path) -> atm::error::Result<Atm> {
    Atm::open(db, &db.parent().unwrap().join("shared.key"))
}

fn usd(n: u32) -> Cents {
    Cents::from_dollars(n)
}

fn d(n: u32) -> Denomination {
    Denomination::new(n).unwrap()
}

/// The last 4 digits: all an attacker without the key can match rows on
/// (card and account numbers are stored encrypted).
fn last4(number: &str) -> &str {
    &number[number.len() - 4..]
}

// ---------------------------------------------------------------------------
// Round 1: hostile front-end code
// ---------------------------------------------------------------------------

/// A second, attacker-created bank must not be a source of sessions that the
/// real bank accepts.
#[test]
fn a_session_from_another_database_is_not_accepted() {
    let mut real = bank();
    let admin_s = auth::login_admin(&mut real, ADMIN.0, ADMIN.1).unwrap();
    let victim =
        admin::create_customer(&mut real, &admin_s, "Vic Tim", "1980-01-01", "4821", usd(900)).unwrap();
    for _ in 0..3 {
        let _ = auth::login_customer(&mut real, &victim.card_number, "0000");
    }

    // Attacker: throwaway bank, own passwords, log in there.
    let (db, key) = paths();
    let mut fake = new_bank(&db, &key);
    auth::first_run_setup(&mut fake, "mallory", "mallory-password-1", "mallory2", "mallory-password-2")
        .unwrap();
    let forged = auth::login_admin(&mut fake, "mallory", "mallory-password-1").unwrap();

    // ...then present that session to the real bank.
    let unlock = admin::unlock_card(&mut real, &forged, &victim.card_number);
    assert!(unlock.is_err(), "admin session minted on another database unlocked a card on the real one");
    let list = admin::list_accounts(&real, &forged);
    assert!(list.is_err(), "admin session minted on another database listed the real bank's customers");
}

/// Same idea for customers: a card created in a throwaway bank must not open
/// whichever real account happens to share its internal row id.
#[test]
fn a_customer_session_from_another_database_is_not_accepted() {
    let mut real = bank();
    let admin_s = auth::login_admin(&mut real, ADMIN.0, ADMIN.1).unwrap();
    admin::create_customer(&mut real, &admin_s, "Vic Tim", "1980-01-01", "4821", usd(900)).unwrap();

    let (db, key) = paths();
    let mut fake = new_bank(&db, &key);
    auth::first_run_setup(&mut fake, "mallory", "mallory-password-1", "mallory2", "mallory-password-2")
        .unwrap();
    let fake_admin = auth::login_admin(&mut fake, "mallory", "mallory-password-1").unwrap();
    let mine =
        admin::create_customer(&mut fake, &fake_admin, "Mal Lory", "1980-01-01", "7302", usd(0)).unwrap();
    let forged = auth::login_customer(&mut fake, &mine.card_number, "7302").unwrap();

    let stolen = customer::balance(&real, &forged);
    assert!(stolen.is_err(), "a session from another database read the victim's balance: {stolen:?}");
}

/// Receiving a transfer must not reveal the sender's card number (the
/// "something you have" half of their login) or full account number.
#[test]
fn history_does_not_leak_other_peoples_card_numbers() {
    let mut atm = bank();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let alice =
        admin::create_customer(&mut atm, &admin_s, "Alice Ay", "1980-01-01", "4821", usd(500)).unwrap();
    let bob = admin::create_customer(&mut atm, &admin_s, "Bob Bee", "1981-01-01", "7302", usd(0)).unwrap();
    let a = auth::login_customer(&mut atm, &alice.card_number, "4821").unwrap();
    customer::transfer(&mut atm, &a, &bob.account_number, usd(10)).unwrap();

    let b = auth::login_customer(&mut atm, &bob.card_number, "7302").unwrap();
    let seen = format!("{:?}", customer::history(&atm, &b, 0).unwrap());
    assert!(!seen.contains(&alice.card_number), "recipient's history exposes the sender's card number");
    assert!(
        !seen.contains(&alice.account_number),
        "recipient's history exposes the sender's full account number"
    );
}

/// A bank (fraud) freeze must not be liftable by a customer.
#[test]
fn a_guardian_cannot_lift_a_freeze_placed_by_the_bank() {
    let mut atm = bank();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let pat = admin::create_customer(&mut atm, &admin_s, "Pat Doe", "1979-02-17", "4821", usd(100)).unwrap();
    let kid = admin::open_youth_account(
        &mut atm,
        &admin_s,
        CardAndPin { card_number: &pat.card_number, pin: "4821" },
        "Kid Doe",
        "2013-06-06",
        "2580",
        usd(150),
    )
    .unwrap();
    admin::set_frozen(&mut atm, &admin_s, &kid.account_number, true).unwrap();

    let p = auth::login_customer(&mut atm, &pat.card_number, "4821").unwrap();
    let _ = family::set_frozen(&mut atm, &p, &kid.account_number, false);
    // Still frozen by the bank: the child's card isn't accepted, and
    // the guardian can't take money out of it either.
    let k = auth::login_customer(&mut atm, &kid.card_number, "2580");
    assert!(matches!(k, Err(AtmError::FrozenByBank)), "guardian lifted a bank freeze");
    let out = family::move_money(&mut atm, &p, &kid.account_number, family::Direction::FromChild, usd(20));
    assert!(matches!(out, Err(AtmError::AccountFrozen)), "guardian lifted a bank freeze: {out:?}");
    // Nor put money into it: a bank-frozen account takes no transfers in.
    let into = family::move_money(&mut atm, &p, &kid.account_number, family::Direction::ToChild, usd(20));
    assert!(matches!(into, Err(AtmError::FrozenByBank)), "money moved into a bank-frozen account: {into:?}");
}

// ---------------------------------------------------------------------------
// Round 2
// ---------------------------------------------------------------------------

/// A session must die the moment its card is locked or its account closed,
/// not carry on until someone logs out.
#[test]
fn a_live_session_stops_when_the_card_is_locked_or_the_account_closed() {
    let (mut atm, admin_s) = stocked();
    let c = admin::create_customer(&mut atm, &admin_s, "Cy Lock", "1980-01-01", "4821", usd(100)).unwrap();
    let s = auth::login_customer(&mut atm, &c.card_number, "4821").unwrap();
    for _ in 0..3 {
        let _ = auth::login_customer(&mut atm, &c.card_number, "0000");
    }
    let out = customer::withdraw(&mut atm, &s, usd(20), BillChoice::Only(d(20)));
    assert!(matches!(out, Err(AtmError::SessionExpired)), "locked card still withdrew: {out:?}");

    let e = admin::create_customer(&mut atm, &admin_s, "Em Close", "1980-01-01", "4821", usd(0)).unwrap();
    let s = auth::login_customer(&mut atm, &e.card_number, "4821").unwrap();
    admin::close_account(&mut atm, &admin_s, &e.account_number).unwrap();
    let out = customer::deposit(&mut atm, &s, &[(d(20), 1)]);
    assert!(matches!(out, Err(AtmError::SessionExpired)), "deposit into a closed account: {out:?}");
}

/// Absurd amounts handed straight to the core (bypassing text parsing) must be
/// refused, not stored: an overflowing balance would wreck the account.
#[test]
fn absurd_amounts_cannot_be_stored_or_overflow_a_balance() {
    let (mut atm, admin_s) = stocked();
    if let Ok(huge) = Cents::new(i64::MAX) {
        let made = admin::create_customer(&mut atm, &admin_s, "Max Int", "1980-01-01", "4821", huge);
        if let Ok(card) = made {
            let s = auth::login_customer(&mut atm, &card.card_number, "4821").unwrap();
            let _ = customer::deposit(&mut atm, &s, &[(d(20), 1)]);
            let seen = customer::balance(&atm, &s);
            panic!("an i64::MAX starting balance was accepted; balance after a $20 deposit: {seen:?}");
        }
    }
    assert!(admin::verify_integrity(&mut atm, &admin_s).is_ok());
}

/// Two cards on one account share one daily limit.
#[test]
fn joint_holders_cannot_double_the_daily_limit() {
    let (mut atm, admin_s) = stocked();
    admin::set_limit(&mut atm, &admin_s, Limit::Withdrawal, usd(500)).unwrap();
    let ann = admin::create_customer(&mut atm, &admin_s, "Ann Lee", "1985-04-12", "4821", usd(5000)).unwrap();
    let ben = admin::add_joint_holder(
        &mut atm,
        &admin_s,
        &ann.account_number,
        CardAndPin { card_number: &ann.card_number, pin: "4821" },
        "Ben Lee",
        "1983-09-30",
        "7305",
    )
    .unwrap();
    let third = admin::add_joint_holder(
        &mut atm,
        &admin_s,
        &ann.account_number,
        CardAndPin { card_number: &ann.card_number, pin: "4821" },
        "Cat Lee",
        "1990-01-01",
        "9512",
    );
    assert!(third.is_err(), "a third holder was added to a joint account");

    let a = auth::login_customer(&mut atm, &ann.card_number, "4821").unwrap();
    let b = auth::login_customer(&mut atm, &ben.card_number, "7305").unwrap();
    customer::withdraw(&mut atm, &a, usd(500), BillChoice::Only(d(20))).unwrap();
    let out = customer::withdraw(&mut atm, &b, usd(20), BillChoice::Only(d(20)));
    assert!(matches!(out, Err(AtmError::LimitExceeded { .. })), "second card got a fresh limit: {out:?}");

    // One holder's bad PINs lock only their own card.
    for _ in 0..3 {
        let _ = auth::login_customer(&mut atm, &ben.card_number, "0000");
    }
    assert!(customer::balance(&atm, &a).is_ok(), "locking Ben's card took Ann's session down");
    assert!(auth::login_customer(&mut atm, &ann.card_number, "4821").is_ok());
}

/// Parental controls: only a linked guardian, never the child or a stranger.
#[test]
fn youth_controls_cannot_be_reached_by_the_child_or_a_stranger() {
    let (mut atm, admin_s) = stocked();
    let pat = admin::create_customer(&mut atm, &admin_s, "Pat Doe", "1979-02-17", "4821", usd(100)).unwrap();
    let sam = admin::create_customer(&mut atm, &admin_s, "Sam Roe", "1990-11-03", "9512", usd(100)).unwrap();
    let kid = admin::open_youth_account(
        &mut atm,
        &admin_s,
        CardAndPin { card_number: &pat.card_number, pin: "4821" },
        "Kid Doe",
        "2013-06-06",
        "2580",
        usd(300),
    )
    .unwrap();
    let loose = family::YouthControls {
        daily_withdraw_cap: usd(500),
        daily_transfer_cap: usd(2000),
        family_only_transfers: false,
    };

    let k = auth::login_customer(&mut atm, &kid.card_number, "2580").unwrap();
    assert!(
        family::set_controls(&mut atm, &k, &kid.account_number, loose).is_err(),
        "child changed own caps"
    );
    assert!(family::set_frozen(&mut atm, &k, &kid.account_number, false).is_err());
    let s = auth::login_customer(&mut atm, &sam.card_number, "9512").unwrap();
    assert!(family::set_controls(&mut atm, &s, &kid.account_number, loose).is_err(), "stranger changed caps");
    assert!(family::youth_history(&atm, &s, &kid.account_number, 0).is_err());

    // The child cannot be made a guardian, and the caps hold.
    let pat_here = CardAndPin { card_number: &pat.card_number, pin: "4821" };
    assert!(
        admin::add_guardian(&mut atm, &admin_s, &kid.account_number, pat_here, &kid.card_number).is_err()
    );
    let out = customer::withdraw(&mut atm, &k, usd(120), BillChoice::Only(d(20)));
    assert!(matches!(out, Err(AtmError::LimitExceeded { .. })), "{out:?}");
    let out = customer::transfer(&mut atm, &k, &sam.account_number, usd(10));
    assert!(matches!(out, Err(AtmError::NotAllowed(_))), "{out:?}");

    // A guardian cannot raise a cap above the bank's own limit.
    let p = auth::login_customer(&mut atm, &pat.card_number, "4821").unwrap();
    let too_high = family::YouthControls { daily_withdraw_cap: usd(1001), ..loose };
    assert!(family::set_controls(&mut atm, &p, &kid.account_number, too_high).is_err());

    // A teller cannot lift a guardian's freeze either.
    family::set_frozen(&mut atm, &p, &kid.account_number, true).unwrap();
    assert!(admin::set_frozen(&mut atm, &admin_s, &kid.account_number, false).is_err());
    let out = customer::withdraw(&mut atm, &k, usd(20), BillChoice::Only(d(20)));
    assert!(matches!(out, Err(AtmError::AccountFrozen)), "{out:?}");
}

/// Setup is one-shot, and limits cannot be switched off.
#[test]
fn setup_cannot_be_rerun_and_limits_cannot_be_removed() {
    let (mut atm, admin_s) = stocked();
    let again =
        auth::first_run_setup(&mut atm, "mallory", "mallory-password-1", "mallory2", "mallory-password-2");
    assert!(again.is_err());
    assert!(auth::login_admin(&mut atm, "mallory", "mallory-password-1").is_err());
    assert!(admin::set_limit(&mut atm, &admin_s, Limit::Withdrawal, Cents::ZERO).is_err());
    // Handler credentials do not open the admin interface.
    assert!(auth::login_admin(&mut atm, HANDLER.0, HANDLER.1).is_err());
}

// ---------------------------------------------------------------------------
// Round 3: an attacker who can write to the database file (but has no key
// file), and who holds one ordinary login of their own. Any such edit must
// get them nothing; the bank refuses to carry on until someone checks it.
// ---------------------------------------------------------------------------

#[test]
fn editing_a_staff_role_does_not_make_a_cash_handler_an_admin() {
    let (mut atm, db) = bank_on_disk();
    raw(&db).execute("UPDATE staff SET role = 'admin' WHERE username = ?1", [HANDLER.0]).unwrap();
    let got = auth::login_admin(&mut atm, HANDLER.0, HANDLER.1);
    assert!(got.is_err(), "cash handler became Teller Admin by editing one database cell");
}

#[test]
fn copying_a_password_hash_onto_the_admin_row_does_not_work() {
    let (mut atm, db) = bank_on_disk();
    raw(&db)
        .execute(
            "UPDATE staff SET password_hash = (SELECT password_hash FROM staff WHERE username = ?1)
             WHERE username = ?2",
            [HANDLER.0, ADMIN.0],
        )
        .unwrap();
    let got = auth::login_admin(&mut atm, ADMIN.0, HANDLER.1);
    assert!(got.is_err(), "logged in as the Teller Admin with the cash handler's password");
}

#[test]
fn copying_a_pin_hash_onto_another_card_does_not_work() {
    let (mut atm, db) = bank_on_disk();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let victim =
        admin::create_customer(&mut atm, &admin_s, "Vic Tim", "1980-01-01", "4821", usd(900)).unwrap();
    let mallory =
        admin::create_customer(&mut atm, &admin_s, "Mal Lory", "1980-01-01", "7302", usd(1)).unwrap();
    raw(&db)
        .execute(
            "UPDATE cards SET pin_hash = (SELECT pin_hash FROM cards WHERE card_last4 = ?1)
             WHERE card_last4 = ?2",
            [last4(&mallory.card_number), last4(&victim.card_number)],
        )
        .unwrap();
    let got = auth::login_customer(&mut atm, &victim.card_number, "7302");
    assert!(got.is_err(), "opened the victim's card with the attacker's own PIN");
}

#[test]
fn pointing_a_card_at_another_account_does_not_work() {
    let (mut atm, db) = bank_on_disk();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let victim =
        admin::create_customer(&mut atm, &admin_s, "Vic Tim", "1980-01-01", "4821", usd(900)).unwrap();
    let mallory =
        admin::create_customer(&mut atm, &admin_s, "Mal Lory", "1980-01-01", "7302", usd(1)).unwrap();
    raw(&db)
        .execute(
            "UPDATE cards SET account_id = (SELECT id FROM accounts WHERE account_last4 = ?1)
             WHERE card_last4 = ?2",
            [last4(&victim.account_number), last4(&mallory.card_number)],
        )
        .unwrap();
    match auth::login_customer(&mut atm, &mallory.card_number, "7302") {
        Err(_) => {}
        Ok(s) => {
            let seen = customer::balance(&atm, &s);
            assert!(seen.is_err(), "attacker's own card and PIN now operate the victim's account: {seen:?}");
        }
    }
}

#[test]
fn resetting_the_failure_counter_does_not_give_unlimited_pin_guesses() {
    let (mut atm, db) = bank_on_disk();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let victim =
        admin::create_customer(&mut atm, &admin_s, "Vic Tim", "1980-01-01", "4821", usd(900)).unwrap();
    let raw = raw(&db);
    let mut wrong_guesses_accepted = 0;
    for guess in ["0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008", "0009"] {
        raw.execute("UPDATE cards SET failed_attempts = 0, locked = 0", []).unwrap();
        if matches!(auth::login_customer(&mut atm, &victim.card_number, guess), Err(AtmError::AuthFailed)) {
            wrong_guesses_accepted += 1;
        }
    }
    assert!(wrong_guesses_accepted <= 3, "{wrong_guesses_accepted} wrong PINs were tested with no lock");
}

#[test]
fn clearing_the_locked_flag_does_not_unlock_a_card() {
    let (mut atm, db) = bank_on_disk();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let victim =
        admin::create_customer(&mut atm, &admin_s, "Vic Tim", "1980-01-01", "4821", usd(900)).unwrap();
    for _ in 0..3 {
        let _ = auth::login_customer(&mut atm, &victim.card_number, "0000");
    }
    raw(&db).execute("UPDATE cards SET failed_attempts = 0, locked = 0", []).unwrap();
    let got = auth::login_customer(&mut atm, &victim.card_number, "4821");
    let flagged = admin::verify_integrity(&mut atm, &admin_s).is_err();
    assert!(
        got.is_err() || flagged,
        "a locked card was unlocked by editing a flag, and the integrity check saw nothing"
    );
}

#[test]
fn inserting_a_guardian_link_does_not_give_control_of_a_youth_account() {
    let (mut atm, db) = bank_on_disk();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let pat = admin::create_customer(&mut atm, &admin_s, "Pat Doe", "1979-02-17", "4821", usd(100)).unwrap();
    let kid = admin::open_youth_account(
        &mut atm,
        &admin_s,
        CardAndPin { card_number: &pat.card_number, pin: "4821" },
        "Kid Doe",
        "2013-06-06",
        "2580",
        usd(150),
    )
    .unwrap();
    let mallory =
        admin::create_customer(&mut atm, &admin_s, "Mal Lory", "1980-01-01", "7302", usd(1)).unwrap();
    raw(&db)
        .execute(
            "INSERT INTO guardians (youth_account_id, guardian_card_id)
             SELECT a.id, c.id FROM accounts a, cards c WHERE a.account_last4 = ?1 AND c.card_last4 = ?2",
            [last4(&kid.account_number), last4(&mallory.card_number)],
        )
        .unwrap();
    let seen = match auth::login_customer(&mut atm, &mallory.card_number, "7302") {
        Ok(m) => family::youth_history(&atm, &m, &kid.account_number, 0).is_ok(),
        Err(_) => false,
    };
    let flagged = admin::verify_integrity(&mut atm, &admin_s).is_err();
    assert!(!seen || flagged, "a stranger became a child's guardian by inserting one row, unnoticed");
}

/// Replay: keep a copy of the database, take the cash, put the copy back.
#[test]
fn restoring_an_old_copy_of_the_database_is_detected() {
    let (mut atm, db) = bank_on_disk();
    let handler = auth::login_handler(&mut atm, HANDLER.0, HANDLER.1).unwrap();
    cash::restock(&mut atm, &handler, d(20), 100).unwrap();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let mallory =
        admin::create_customer(&mut atm, &admin_s, "Mal Lory", "1980-01-01", "7302", usd(500)).unwrap();
    drop(atm);
    let saved = std::fs::read(&db).unwrap();

    let mut atm = reopen(&db).unwrap();
    let m = auth::login_customer(&mut atm, &mallory.card_number, "7302").unwrap();
    customer::withdraw(&mut atm, &m, usd(500), BillChoice::Only(d(20))).unwrap();
    drop(atm);

    std::fs::write(&db, &saved).unwrap(); // the withdrawal never happened
    match reopen(&db) {
        Err(_) => {}
        Ok(mut atm) => {
            let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
            let clean = admin::verify_integrity(&mut atm, &admin_s).is_ok();
            let m = auth::login_customer(&mut atm, &mallory.card_number, "7302").unwrap();
            let again = customer::withdraw(&mut atm, &m, usd(500), BillChoice::Only(d(20))).is_ok();
            assert!(
                !(clean && again),
                "database rolled back: the same $500 was withdrawn twice and the integrity check was clean"
            );
        }
    }
}

/// Two programs using the same database at once must not corrupt the log.
#[test]
fn two_instances_at_once_do_not_break_the_audit_chain() {
    let (atm, db) = bank_on_disk();
    drop(atm);
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let db = db.clone();
            std::thread::spawn(move || {
                let mut atm = reopen(&db).unwrap();
                for _ in 0..40 {
                    if let Ok(s) = auth::login_handler(&mut atm, HANDLER.0, HANDLER.1) {
                        let _ = cash::view(&atm, &s);
                        let _ = auth::logout_handler(&mut atm, s);
                    }
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let mut atm = reopen(&db).unwrap();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let report = admin::verify_integrity(&mut atm, &admin_s);
    assert!(report.is_ok(), "concurrent use forked the audit chain: {report:?}");
}

// ---------------------------------------------------------------------------
// Round 4: more edits to the database file.
// ---------------------------------------------------------------------------

#[test]
fn an_edited_balance_cannot_be_spent() {
    let (mut atm, db) = bank_on_disk();
    let handler = auth::login_handler(&mut atm, HANDLER.0, HANDLER.1).unwrap();
    cash::restock(&mut atm, &handler, d(20), 100).unwrap();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let mallory =
        admin::create_customer(&mut atm, &admin_s, "Mal Lory", "1980-01-01", "7302", usd(1)).unwrap();
    let other = admin::create_customer(&mut atm, &admin_s, "Oth Er", "1980-01-01", "4821", usd(1)).unwrap();
    raw(&db).execute("UPDATE accounts SET balance_cents = 99999900", []).unwrap();
    if let Ok(m) = auth::login_customer(&mut atm, &mallory.card_number, "7302") {
        let cash_out = customer::withdraw(&mut atm, &m, usd(400), BillChoice::Only(d(20)));
        assert!(cash_out.is_err(), "withdrew money that was typed into the file: {cash_out:?}");
        let moved = customer::transfer(&mut atm, &m, &other.account_number, usd(400));
        assert!(moved.is_err(), "transferred money that was typed into the file: {moved:?}");
    }
}

#[test]
fn clearing_freeze_and_closed_flags_changes_nothing() {
    let (mut atm, db) = bank_on_disk();
    let handler = auth::login_handler(&mut atm, HANDLER.0, HANDLER.1).unwrap();
    cash::restock(&mut atm, &handler, d(20), 100).unwrap();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let frozen =
        admin::create_customer(&mut atm, &admin_s, "Fro Zen", "1980-01-01", "7302", usd(100)).unwrap();
    let closed = admin::create_customer(&mut atm, &admin_s, "Clo Sed", "1980-01-01", "4821", usd(0)).unwrap();
    admin::set_frozen(&mut atm, &admin_s, &frozen.account_number, true).unwrap();
    admin::close_account(&mut atm, &admin_s, &closed.account_number).unwrap();
    raw(&db).execute("UPDATE accounts SET frozen = 0, closed = 0", []).unwrap();

    if let Ok(f) = auth::login_customer(&mut atm, &frozen.card_number, "7302") {
        let out = customer::withdraw(&mut atm, &f, usd(20), BillChoice::Only(d(20)));
        assert!(out.is_err(), "freeze lifted by editing a flag: {out:?}");
    }
    assert!(
        auth::login_customer(&mut atm, &closed.card_number, "4821").is_err(),
        "closed account reopened by a flag"
    );
}

#[test]
fn an_edited_limit_or_rate_is_refused_at_the_point_of_use() {
    let (mut atm, db) = bank_on_disk();
    let handler = auth::login_handler(&mut atm, HANDLER.0, HANDLER.1).unwrap();
    cash::restock(&mut atm, &handler, d(20), 500).unwrap();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let c = admin::create_customer(&mut atm, &admin_s, "Lim It", "1980-01-01", "7302", usd(5000)).unwrap();
    atm::fx::set_rate(&mut atm, &admin_s, Currency::Eur, "0.92").unwrap();
    let e = admin::register_guest_card(
        &mut atm,
        &admin_s,
        "Eur Oh",
        "1980-01-01",
        "4821",
        usd(500),
        Currency::Eur,
    )
    .unwrap();
    let raw = raw(&db);
    raw.execute("UPDATE settings SET value = 100000000 WHERE key LIKE 'daily_%'", []).unwrap();
    let edited = raw.execute("UPDATE exchange_rates SET per_usd_micros = 1", []).unwrap();
    assert_eq!(edited, 1, "the test must really edit a rate");
    if let Ok(s) = auth::login_customer(&mut atm, &c.card_number, "7302") {
        let out = customer::withdraw(&mut atm, &s, usd(1500), BillChoice::Only(d(50)));
        assert!(out.is_err(), "raised limit was honoured: {out:?}");
    }
    if let Ok(s) = auth::login_customer(&mut atm, &e.card_number, "4821") {
        let out = customer::withdraw(&mut atm, &s, usd(20), BillChoice::Only(d(20)));
        assert!(out.is_err(), "an edited exchange rate was used: {out:?}");
    }
}

#[test]
fn blanking_a_youth_accounts_caps_does_not_free_it() {
    let (mut atm, db) = bank_on_disk();
    let handler = auth::login_handler(&mut atm, HANDLER.0, HANDLER.1).unwrap();
    cash::restock(&mut atm, &handler, d(20), 100).unwrap();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let pat = admin::create_customer(&mut atm, &admin_s, "Pat Doe", "1979-02-17", "4821", usd(100)).unwrap();
    let sam = admin::create_customer(&mut atm, &admin_s, "Sam Roe", "1990-11-03", "9512", usd(100)).unwrap();
    let kid = admin::open_youth_account(
        &mut atm,
        &admin_s,
        CardAndPin { card_number: &pat.card_number, pin: "4821" },
        "Kid Doe",
        "2013-06-06",
        "2580",
        usd(400),
    )
    .unwrap();
    raw(&db)
        .execute(
            "UPDATE accounts SET kind = 'individual', withdraw_cap_cents = NULL,
                    transfer_cap_cents = NULL, family_only_transfers = 0",
            [],
        )
        .unwrap();
    if let Ok(k) = auth::login_customer(&mut atm, &kid.card_number, "2580") {
        let out = customer::withdraw(&mut atm, &k, usd(300), BillChoice::Only(d(20)));
        assert!(out.is_err(), "youth cap removed by an edit: {out:?}");
        let out = customer::transfer(&mut atm, &k, &sam.account_number, usd(10));
        assert!(out.is_err(), "family-only removed by an edit: {out:?}");
    }
}

/// Cutting entries off the end of the log (to erase a lock-out, say) and
/// fixing the row counter used to pass the chain check.
#[test]
fn the_end_of_the_log_cannot_be_cut_off() {
    let (mut atm, db) = bank_on_disk();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    let c = admin::create_customer(&mut atm, &admin_s, "Cut Off", "1980-01-01", "7302", usd(1)).unwrap();
    let keep: i64 = raw(&db).query_row("SELECT MAX(seq) FROM audit_log", [], |r| r.get(0)).unwrap();
    for _ in 0..3 {
        let _ = auth::login_customer(&mut atm, &c.card_number, "0000");
    }
    drop(atm);
    let raw = raw(&db);
    raw.execute("DROP TRIGGER audit_no_delete", []).unwrap();
    raw.execute("DELETE FROM audit_log WHERE seq > ?1", [keep]).unwrap();
    raw.execute("UPDATE sqlite_sequence SET seq = ?1 WHERE name = 'audit_log'", [keep]).unwrap();
    raw.execute("UPDATE cards SET locked = 0, failed_attempts = 0", []).unwrap();
    drop(raw);
    let reopened = reopen(&db);
    assert!(reopened.is_err(), "the lock-out was erased from history unnoticed");
}

/// Deleting the database must not hand first-time setup to whoever is there.
#[test]
fn deleting_the_database_does_not_offer_setup_again() {
    let (atm, db) = bank_on_disk();
    drop(atm);
    std::fs::remove_file(&db).unwrap();
    match reopen(&db) {
        Err(_) => {}
        Ok(mut atm) => {
            let takeover = auth::first_run_setup(
                &mut atm,
                "mallory",
                "mallory-password-1",
                "mallory2",
                "mallory-password-2",
            );
            assert!(takeover.is_err(), "database deleted, and the attacker created their own Teller Admin");
        }
    }
}

/// The anchor itself: edited, or removed, it is refused.
#[test]
fn the_anchor_file_cannot_be_edited_or_removed() {
    let (mut atm, db) = bank_on_disk();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    admin::create_customer(&mut atm, &admin_s, "Anc Hor", "1980-01-01", "7302", usd(1)).unwrap();
    drop(atm);
    let anchor = db.with_extension("anchor");
    let good = std::fs::read_to_string(&anchor).unwrap();
    assert!(reopen(&db).is_ok());

    std::fs::write(&anchor, "1 0000 0000\n").unwrap();
    assert!(reopen(&db).is_err(), "a forged anchor was accepted");
    std::fs::remove_file(&anchor).unwrap();
    assert!(reopen(&db).is_err(), "a missing anchor was accepted for a database with history");
    std::fs::write(&anchor, good).unwrap();
    assert!(reopen(&db).is_ok());
}

/// Settings and rates edited in the file are caught (they also carry their own MACs).
#[test]
fn settings_and_rates_edited_in_the_file_are_detected() {
    let (mut atm, db) = bank_on_disk();
    let admin_s = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
    admin::set_limit(&mut atm, &admin_s, Limit::Withdrawal, usd(750)).unwrap();
    atm::fx::set_rate(&mut atm, &admin_s, Currency::Gbp, "0.75").unwrap();
    assert!(admin::verify_integrity(&mut atm, &admin_s).is_ok());
    drop(atm);
    let edited =
        raw(&db).execute("UPDATE exchange_rates SET per_usd_micros = 1 WHERE currency = 'GBP'", []).unwrap();
    assert_eq!(edited, 1, "the test must really edit a rate");
    let refused = match reopen(&db) {
        Err(_) => true,
        Ok(mut atm) => match auth::login_admin(&mut atm, ADMIN.0, ADMIN.1) {
            Err(_) => true,
            Ok(a) => admin::verify_integrity(&mut atm, &a).is_err(),
        },
    };
    assert!(refused, "an edited exchange rate went unnoticed");
}
