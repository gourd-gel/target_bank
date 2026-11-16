#![cfg(feature = "authorities-tools")]
mod common;
use atm::{Atm, auth, service};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn lock_survives_restart_failed_alert_is_retried_and_only_authorities_terminal_restores_service() {
    let folder = std::env::temp_dir().join(format!("atm-teller-service-lock-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let db = folder.join("atm.db");
    let key = folder.join("atm.key");
    common::provision(&db);
    let phone = "+12125550199";
    std::fs::write(folder.join(auth::recovery::AUTHORITIES_CONFIG_FILE), phone).unwrap();
    std::fs::write(folder.join(atm::identity::LOCATION_CONFIG_FILE), "CCNY test ATM 7").unwrap();
    let mut bank = Atm::create(&db, &key).unwrap();
    auth::first_run_setup(&mut bank, "teller", "teller-password-1", "handler", "handler-password-1").unwrap();
    for _ in 0..2 {
        assert!(auth::login_admin(&mut bank, "teller", "wrong-password-1").is_err());
    }
    assert!(!service::out_of_service(&bank).unwrap());
    drop(bank);
    let mut bank = Atm::open(&db, &key).unwrap();
    // Obstruct notification delivery: the security lock must still commit.
    let alert_path = folder.join(format!("{phone}.txt"));
    std::fs::create_dir(&alert_path).unwrap();
    assert!(auth::login_admin(&mut bank, "teller", "bad").is_err());
    assert!(service::out_of_service(&bank).unwrap());
    assert!(matches!(
        auth::login_admin(&mut bank, "teller", "teller-password-1"),
        Err(atm::error::AtmError::OutOfService)
    ));
    assert!(matches!(
        auth::login_handler(&mut bank, "handler", "handler-password-1"),
        Err(atm::error::AtmError::OutOfService)
    ));
    assert!(matches!(
        auth::recovery::request_code(&mut bank, phone),
        Err(atm::error::AtmError::OutOfService)
    ));
    drop(bank);
    std::fs::remove_dir(&alert_path).unwrap();
    // Startup retries the durable alert while leaving the ATM locked.
    let bank = Atm::open(&db, &key).unwrap();
    assert!(service::out_of_service(&bank).unwrap());
    let alert = std::fs::read_to_string(&alert_path).unwrap();
    assert!(alert.contains("3 consecutive"));
    assert!(alert.contains("CCNY test ATM 7"));
    assert!(alert.contains("ATM signature (HMAC-SHA256):"));
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
    writeln!(input, "{}\nservice-status\ncheck\nretry-service-alert\nresume-service Verified teller identity and reviewed incident\nservice-status\nadmin-audit\nquit", code.trim()).unwrap();
    drop(input);
    let output = terminal.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "\"out_of_service\": true",
        "ATM service restored",
        "\"out_of_service\": false",
        "service_resume",
        "Verified teller identity",
    ] {
        assert!(stdout.contains(expected), "missing {expected}: {stdout}");
    }
    let mut bank = Atm::open(&db, &key).unwrap();
    assert!(!service::out_of_service(&bank).unwrap());
    assert!(auth::login_admin(&mut bank, "teller", "teller-password-1").is_ok());
    drop(bank);
    std::fs::remove_dir_all(folder).unwrap();
}
