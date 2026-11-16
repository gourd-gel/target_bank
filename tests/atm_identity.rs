#![cfg(feature = "programmer-tools")]
use argon2::{Argon2, password_hash::PasswordHasher};
use atm::{Atm, auth};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn location_tool_requires_programmer_pin_and_atm_identity_survives_restart() {
    let folder = std::env::temp_dir().join(format!("atm-origin-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let secret = folder.join(auth::recovery::PROGRAMMER_PIN_FILE);
    std::fs::write(&secret, Argon2::default().hash_password(b"0000").unwrap().to_string()).unwrap();
    let run = |location: &str, pin: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bank-atm-location"))
            .current_dir(&folder)
            .arg(location)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(pin.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    };
    let config = folder.join(atm::identity::LOCATION_CONFIG_FILE);
    assert!(!run("Test branch, ATM 01", "9999\n").status.success());
    assert!(!config.exists());
    assert!(run("Test branch, ATM 01", "0000\n").status.success());
    for invalid in ["", "   ", "Branch\nATM ID: forged", "\u{1b}[31mbranch"] {
        assert!(!run(invalid, "0000\n").status.success());
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "Test branch, ATM 01\n");
    }
    assert!(!folder.join("atm.db").exists());
    std::fs::write(folder.join(auth::recovery::AUTHORITIES_CONFIG_FILE), "+12125550199\n").unwrap();
    let db = folder.join("atm.db");
    let key = folder.join("atm.key");
    let mut atm = Atm::create(&db, &key).unwrap();
    assert!(atm.needs_setup().unwrap(), "preconfigured location prevented initial staff setup");
    auth::first_run_setup(&mut atm, "teller", "teller-password-1", "handler", "handler-password-1").unwrap();
    auth::recovery::request_code(&mut atm, "+12125559999").unwrap();
    let read_alert = || std::fs::read_to_string(folder.join("+12125550199.txt")).unwrap();
    let first = read_alert();
    let id = first.lines().find_map(|l| l.strip_prefix("ATM ID: ")).unwrap().to_string();
    assert_eq!(id.len(), 32);
    assert!(first.contains("ATM location: Test branch, ATM 01"));
    assert!(first.contains("ATM signature (HMAC-SHA256): "));
    drop(atm);
    assert!(run("Test branch, ATM 02", "0000\n").status.success());
    let mut atm = Atm::open(&db, &key).unwrap();
    auth::recovery::request_code(&mut atm, "+12125559999").unwrap();
    let second = read_alert();
    assert!(second.contains(&format!("ATM ID: {id}")));
    assert!(second.contains("ATM location: Test branch, ATM 02"));
    drop(atm);
    let second_db = folder.join("other.db");
    let mut other = Atm::create(&second_db, &key).unwrap();
    auth::first_run_setup(&mut other, "teller", "teller-password-1", "handler", "handler-password-1")
        .unwrap();
    auth::recovery::request_code(&mut other, "+12125559999").unwrap();
    assert!(
        !read_alert().contains(&format!("ATM ID: {id}")),
        "different installations reused the same ATM ID"
    );
    drop(other);
    std::fs::remove_file(&secret).unwrap();
    assert!(!run("Other branch", "0000\n").status.success());
    assert_eq!(std::fs::read_to_string(config).unwrap(), "Test branch, ATM 02\n");
    std::fs::remove_dir_all(folder).unwrap();
}
