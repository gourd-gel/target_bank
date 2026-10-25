//! Exploits found in the second security audit. Each test asserts the SAFE
//! result.

use atm::error::AtmError;
use atm::money::{Cents, Denomination};
use atm::{Atm, admin, auth, cash, customer};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

const ADMIN: (&str, &str) = ("teller_one", "teller-password-1");
const HANDLER: (&str, &str) = ("cash_one", "handler-password-1");

/// A set-up bank with 500 x $20 loaded and an admin session. One key file
/// for every bank in this test run (the process holds a single key).
fn bank() -> (Atm, auth::AdminSession, PathBuf, PathBuf) {
    static N: AtomicU32 = AtomicU32::new(0);
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir().join(format!("atm-audit-{}", std::process::id()));
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

fn usd(n: u32) -> Cents {
    Cents::from_dollars(n)
}
fn d(n: u32) -> Denomination {
    Denomination::new(n).unwrap()
}

/// Blocking atm.anchor (a folder where the file goes) made a finished
/// deposit report "not completed": the bills would go back to the customer
/// while the account kept the credit.
#[test]
fn a_finished_deposit_is_never_reported_as_failed_and_a_blocked_anchor_stops_the_atm() {
    let (mut atm, a, db, key) = bank();
    let anchor = db.with_extension("anchor");
    let c = admin::create_customer(&mut atm, &a, "Mal Lory", "1980-01-01", "7302", usd(0)).unwrap();
    let m = auth::login_customer(&mut atm, &c.card_number, "7302").unwrap();
    std::fs::remove_file(&anchor).unwrap();
    std::fs::create_dir(&anchor).unwrap();

    // The deposit is permanent, so it is reported as done.
    customer::deposit(&mut atm, &m, &[(d(100), 20)]).expect("a finished deposit was reported as failed");
    // Until the anchor can be written again, nothing else runs.
    assert!(customer::balance(&atm, &m).is_err(), "the ATM kept running without its anchor");
    assert!(auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).is_err());
    assert!(matches!(customer::balance(&atm, &m), Err(AtmError::Internal(_))));

    // Unblocked: the next operation writes the anchor and carries on.
    std::fs::remove_dir(&anchor).unwrap();
    assert_eq!(customer::balance(&atm, &m).unwrap(), usd(2_000));
    assert!(anchor.is_file());
    drop(atm);
    assert!(Atm::open(&db, &key).is_ok(), "the anchor written on catch-up doesn't match");
}

/// Each starting balance was capped, but not their sum: one teller could open
/// account after account with $10,000 each and no cash behind any of it.
#[test]
fn one_teller_cannot_create_unlimited_money_with_starting_balances() {
    let (mut atm, a, _db, _key) = bank();
    let open = |atm: &mut Atm, name: &str, dollars: u32| {
        admin::create_customer(atm, &a, name, "1980-01-01", "7302", usd(dollars))
    };
    open(&mut atm, "First One", 10_000).unwrap();
    open(&mut atm, "Second One", 10_000).unwrap(); // $20,000 today: the most
    assert!(
        matches!(open(&mut atm, "Third One", 1), Err(AtmError::NotAllowed(_))),
        "a teller passed {} of starting balances in one day",
        admin::STARTING_BALANCES_PER_DAY
    );
    // Accounts with no starting balance still open; the money comes in as cash.
    open(&mut atm, "Fourth One", 0).unwrap();
}

/// The seal covers every table row, not the index pages. Swapping two
/// indexes of the same shape in the file (no key needed) made "today's
/// withdrawals" read the wrong index, so the daily limit could be passed.
#[test]
fn an_index_edited_in_the_file_is_caught_before_it_can_mislead() {
    let (mut atm, a, db, key) = bank();
    let c = admin::create_customer(&mut atm, &a, "Mal Lory", "1980-01-01", "7302", usd(5_000)).unwrap();
    let m = auth::login_customer(&mut atm, &c.card_number, "7302").unwrap();
    customer::withdraw(&mut atm, &m, usd(800), customer_bills()).unwrap();
    customer::withdraw(&mut atm, &m, usd(200), customer_bills()).unwrap(); // the $1,000 daily limit
    assert!(matches!(
        customer::withdraw(&mut atm, &m, usd(20), customer_bills()),
        Err(AtmError::LimitExceeded { .. })
    ));
    drop(atm);

    // Swap the two log indexes' root pages: table rows (and so the seal) unchanged.
    let raw = rusqlite::Connection::open(&db).unwrap();
    let root = |name: &str| -> i64 {
        raw.query_row("SELECT rootpage FROM sqlite_schema WHERE name = ?1", [name], |r| r.get(0)).unwrap()
    };
    let (by_account, by_counterparty) = (root("audit_by_account"), root("audit_by_counterparty"));
    raw.execute_batch(&format!(
        "PRAGMA writable_schema = ON;
         UPDATE sqlite_schema SET rootpage = {by_counterparty} WHERE name = 'audit_by_account';
         UPDATE sqlite_schema SET rootpage = {by_account} WHERE name = 'audit_by_counterparty';
         PRAGMA writable_schema = OFF;"
    ))
    .unwrap();
    drop(raw);

    match Atm::open(&db, &key) {
        Err(AtmError::DatabaseAltered) => {}
        Err(e) => panic!("refused, but with the wrong error: {e}"),
        Ok(mut atm) => {
            let m = auth::login_customer(&mut atm, &c.card_number, "7302").unwrap();
            let again = customer::withdraw(&mut atm, &m, usd(800), customer_bills());
            panic!("the edited file opened; another $800 today: {:?}", again.map(|r| r.balance_after));
        }
    }
}

fn customer_bills() -> atm::dispense::BillChoice {
    atm::dispense::BillChoice::Only(d(20))
}

/// The CLI left the last customer's name and balance on the terminal (and in
/// its scrollback) under the main menu for the next person.
#[test]
fn the_cli_wipes_the_screen_when_a_session_ends() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let dir = std::env::temp_dir().join(format!("atm-audit-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let run = |input: &str| -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_atm"))
            .current_dir(&dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).into_owned()
    };
    // First run: staff setup, then the teller opens Ann's account.
    let setup = run(
        "teller_one\nteller-password-1\nteller-password-1\ncash_one\nhandler-password-1\nhandler-password-1\n\
         2\nteller_one\nteller-password-1\n1\nAnn Lee\n1985-04-12\n4821\n4821\n2500\n0\n0\n",
    );
    let card = setup
        .lines()
        .find_map(|l| l.trim().strip_prefix("Card number:").map(|r| r.trim()[..10].to_string()))
        .expect("card number printed for the teller");
    // Ann checks her balance and logs out; the next person walks up.
    let out = run(&format!("1\n{card}\n4821\n1\n0\n"));
    let (during, after) = out.rsplit_once(atm::input::WIPE).expect("the screen is wiped at logout");
    assert!(during.contains("Ann Lee") && during.contains("$2,500.00"));
    assert!(!after.contains("Ann Lee") && !after.contains("$2,500.00"), "left on screen:\n{after}");

    // Ann signs in again; a teller halts the ATM from another console while
    // her menu waits. Her next choice ends the session, and the reason is
    // shown after the wipe, not wiped with it.
    let mut ann = Command::new(env!("CARGO_BIN_EXE_atm"))
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut keys = ann.stdin.take().unwrap();
    let mut screen = ann.stdout.take().unwrap();
    let (sent, shown) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut chunk = [0u8; 4096];
        while let Ok(n @ 1..) = screen.read(&mut chunk) {
            let _ = sent.send(String::from_utf8_lossy(&chunk[..n]).into_owned());
        }
    });
    write!(keys, "1\n{card}\n4821\n").unwrap();
    let mut out = String::new();
    while !out.contains("--- Customer:") {
        out += &shown.recv_timeout(std::time::Duration::from_secs(30)).expect("Ann's menu never showed");
    }
    run("2\nteller_one\nteller-password-1\n18\ny\n0\n0\n");
    write!(keys, "1\n0\n").unwrap();
    drop(keys);
    ann.wait().unwrap();
    reader.join().unwrap();
    out.extend(shown.try_iter());
    let (_, after) = out.rsplit_once(atm::input::WIPE).expect("the screen is wiped when the session stops");
    assert!(after.contains("temporarily out of service"), "the reason was wiped too:\n{after}");
    assert!(!after.contains("Ann Lee") && !after.contains("$2,500.00"), "left on screen:\n{after}");
    let _ = std::fs::remove_dir_all(&dir);
}
