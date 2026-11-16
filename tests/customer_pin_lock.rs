#![cfg(feature = "authorities-tools")]
mod common;
use atm::{Atm, admin, auth, customer, error::AtmError, money::Cents, service};
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn customer_lock_alert_survives_failed_delivery_and_authorities_cargo_terminal_resolves_it() {
    let folder = std::env::temp_dir().join(format!("atm-customer-pin-lock-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let db = folder.join("atm.db");
    let key = folder.join("atm.key");
    common::provision(&db);
    let phone = "+12125550199";
    std::fs::write(folder.join(auth::recovery::AUTHORITIES_CONFIG_FILE), phone).unwrap();
    std::fs::write(folder.join(atm::identity::LOCATION_CONFIG_FILE), "CCNY customer test ATM 8").unwrap();
    let mut bank = Atm::create(&db, &key).unwrap();
    auth::first_run_setup(&mut bank, "teller", "teller-password-1", "handler", "handler-password-1").unwrap();
    let teller = auth::login_admin(&mut bank, "teller", "teller-password-1").unwrap();
    let ann =
        admin::create_customer(&mut bank, &teller, "Ann Lee", "1980-01-01", "4821", Cents::from_dollars(100))
            .unwrap();
    let bo =
        admin::create_customer(&mut bank, &teller, "Bo Kim", "1980-01-01", "5937", Cents::from_dollars(100))
            .unwrap();
    let live = auth::login_customer(&mut bank, &ann.card_number, "4821").unwrap();
    let alert_path = folder.join(format!("{phone}.txt"));
    std::fs::create_dir(&alert_path).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            auth::login_customer(&mut bank, &ann.card_number, "1111"),
            Err(AtmError::AuthFailed)
        ));
    }
    assert!(matches!(auth::login_customer(&mut bank, &ann.card_number, "2222"), Err(AtmError::CardLocked)));
    assert!(matches!(customer::balance(&bank, &live), Err(AtmError::SessionExpired)));
    assert!(!service::out_of_service(&bank).unwrap());
    assert!(auth::login_customer(&mut bank, &bo.card_number, "5937").is_ok());
    assert!(admin::unlock_card(&mut bank, &teller, &ann.card_number).is_err());
    let raw = rusqlite::Connection::open(&db).unwrap();
    let pending: i64 = raw
        .query_row("SELECT COUNT(*) FROM meta WHERE key LIKE 'customer-pin-alert:%'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(pending, 1);
    drop(raw);
    drop(bank);
    std::fs::remove_dir(&alert_path).unwrap();
    let mut bank = Atm::open(&db, &key).unwrap();
    assert!(matches!(auth::login_customer(&mut bank, &ann.card_number, "4821"), Err(AtmError::CardLocked)));
    let alert = std::fs::read_to_string(&alert_path).unwrap();
    for field in [
        "Customer login locked",
        "Customer actor:",
        "ATM ID:",
        "ATM location: CCNY customer test ATM 8",
        "Incident time (UTC):",
        "ATM signature (HMAC-SHA256):",
    ] {
        assert!(alert.contains(field), "missing {field}: {alert}");
    }
    assert!(!alert.contains(&ann.card_number));
    let raw = rusqlite::Connection::open(&db).unwrap();
    let pending: i64 = raw
        .query_row("SELECT COUNT(*) FROM meta WHERE key LIKE 'customer-pin-alert:%'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(pending, 0);
    drop(raw);
    drop(bank);

    let mut terminal = Command::new(env!("CARGO_BIN_EXE_bank-oversight"))
        .arg("--directory")
        .arg(&folder)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = terminal.stdin.take().unwrap();
    writeln!(input, "{phone}").unwrap();
    input.flush().unwrap();
    let code_path = folder.join(format!("{phone}.authorities-login.txt"));
    let start = std::time::Instant::now();
    while !code_path.is_file() {
        if start.elapsed() > std::time::Duration::from_secs(15) {
            let _ = terminal.kill();
            let output = terminal.wait_with_output().unwrap();
            panic!("Authorities code missing: {}", String::from_utf8_lossy(&output.stderr));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let code = std::fs::read_to_string(code_path).unwrap();
    writeln!(input, "{}\nuser {}\ncheck\nretry-customer-alerts\nresolve-customer {} Verified customer identity and reviewed failed PIN attempts\nadmin-audit\nquit", code.trim(), ann.card_number, ann.card_number).unwrap();
    drop(input);
    let output = terminal.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    for expected in ["Customer PIN lock resolved", "customer_lock_resolved", "Verified customer identity"] {
        assert!(stdout.contains(expected), "missing {expected}: {stdout}");
    }
    let mut bank = Atm::open(&db, &key).unwrap();
    assert!(auth::login_customer(&mut bank, &ann.card_number, "4821").is_ok());
    assert!(auth::login_customer(&mut bank, &bo.card_number, "5937").is_ok());
    drop(bank);
    std::fs::remove_dir_all(folder).unwrap();
}
