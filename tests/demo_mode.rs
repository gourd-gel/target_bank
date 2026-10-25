//! Demo data (published passwords) never runs as a real bank, and demo mode
//! never opens a real bank's database. Built only with `--features demo`.

#![cfg(feature = "demo")]

use atm::error::AtmError;
use atm::{Atm, auth};
use std::path::PathBuf;

/// A new bank file in this run's folder; all banks share one key file.
fn new_bank(name: &str) -> (Atm, PathBuf, PathBuf) {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = std::env::temp_dir().join(format!("atm-demo-mode-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (db, key) = (dir.join(format!("{name}.db")), dir.join("shared.key"));
    (Atm::create(&db, &key).unwrap(), db, key)
}

#[test]
fn demo_data_and_real_data_stay_apart() {
    // Demo data copied over the real bank's files: refused in normal mode.
    let (mut demo, demo_db, key) = new_bank("demo");
    atm::demo::seed(&mut demo).unwrap();
    drop(demo);
    assert!(matches!(Atm::open(&demo_db, &key), Err(AtmError::NotAllowed(_))));
    assert!(Atm::open_demo(&demo_db, &key).is_ok());

    // A real bank's database: refused in demo mode.
    let (mut real, real_db, key) = new_bank("real");
    auth::first_run_setup(&mut real, "alice", "correct horse battery", "bob", "staple gun orchestra")
        .unwrap();
    drop(real);
    assert!(Atm::open(&real_db, &key).is_ok());
    assert!(matches!(Atm::open_demo(&real_db, &key), Err(AtmError::NotAllowed(_))));
}

/// `--break-integrity` (test builds only): the next teller sign-in catches it.
#[cfg(feature = "integrity-test")]
#[test]
fn a_broken_balance_is_caught_at_the_next_teller_sign_in() {
    let (mut atm, _, _) = new_bank("broken");
    let logins = atm::demo::seed(&mut atm).unwrap();
    atm::demo::break_integrity(&mut atm).unwrap();
    let teller = auth::login_admin(&mut atm, atm::demo::TELLER.0, atm::demo::TELLER.1).unwrap();
    assert!(teller.integrity_problem().is_some());
    assert!(atm::service::status(&atm, &teller).unwrap().out_of_service);
    let ann = &logins[0];
    assert!(matches!(auth::login_customer(&mut atm, &ann.card, ann.pin), Err(AtmError::OutOfService)));

    // Never on real data.
    let (mut real, _, _) = new_bank("real-2");
    auth::first_run_setup(&mut real, "alice", "correct horse battery", "bob", "staple gun orchestra")
        .unwrap();
    assert!(matches!(atm::demo::break_integrity(&mut real), Err(AtmError::NotAllowed(_))));
}
