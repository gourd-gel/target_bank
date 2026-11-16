#![cfg(feature = "programmer-tools")]
use argon2::{Argon2, password_hash::PasswordHasher};
use atm::{Atm, administration, auth, oversight, revenue};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn programmer_and_authorities_events_are_separate_private_and_checkpointed() {
    let folder = std::env::temp_dir().join(format!("atm-private-administration-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let secret = folder.join(auth::recovery::PROGRAMMER_PIN_FILE);
    std::fs::write(&secret, Argon2::default().hash_password(b"0000").unwrap().to_string()).unwrap();
    let run = |binary: &str, value: &str, pin: &str| {
        let mut child = Command::new(binary)
            .current_dir(&folder)
            .arg(value)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(pin.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    };
    assert!(!run(env!("CARGO_BIN_EXE_bank-authorities"), "+12125550199", "9999\n").status.success());
    assert!(!folder.join("atm.db").exists());
    assert!(folder.join("atm.admin-audit.db").is_file());
    assert!(run(env!("CARGO_BIN_EXE_bank-authorities"), "+12125550199", "0000\n").status.success());
    assert!(
        run(env!("CARGO_BIN_EXE_bank-atm-location"), "Private audit test branch", "0000\n").status.success()
    );
    let db = folder.join("atm.db");
    let key = folder.join("atm.key");
    let mut bank = Atm::create(&db, &key).unwrap();
    assert!(bank.needs_setup().unwrap());
    auth::first_run_setup(&mut bank, "teller", "teller-password-1", "handler", "handler-password-1").unwrap();
    let audit = administration::database_path(&db);
    let old = folder.join("old-admin.db");
    std::fs::copy(&audit, &old).unwrap();
    let raw = rusqlite::Connection::open(&db).unwrap();
    let before: (i64, String) = raw
        .query_row("SELECT seq,mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    drop(raw);
    auth::recovery::request_authorities_code(&mut bank, "+12125550199").unwrap();
    let code = std::fs::read_to_string(folder.join("+12125550199.authorities-login.txt")).unwrap();
    assert!(auth::recovery::login_authorities(&mut bank, "+12125550199", "invalid").is_err());
    let authority = auth::recovery::login_authorities(&mut bank, "+12125550199", code.trim()).unwrap();
    oversight::staff(&bank, &authority, Some("teller"), 0).unwrap();
    assert_eq!(oversight::databases(&bank, &authority).unwrap().len(), 3);
    revenue::balances(&bank, &authority).unwrap();
    let rows = administration::recent(&bank, &authority, 0).unwrap();
    for expected in [
        "authorities_phone_change",
        "atm_location_change",
        "authorities_phone_import",
        "atm_location_import",
        "code_request",
        "sign_in",
        "staff_inspection",
        "database_inventory",
        "revenue_balances",
    ] {
        assert!(rows.iter().any(|r| r.event.action == expected), "missing {expected}");
    }
    assert!(rows.iter().any(|r| r.event.outcome == "authentication_failed"));
    assert!(rows.iter().any(|r| r.event.action == "sign_in" && r.event.outcome == "failed"));
    let text = serde_json::to_string(&rows).unwrap();
    assert!(!text.contains("0000"));
    assert!(!text.contains(code.trim()));
    auth::logout_authorities(&mut bank, authority).unwrap();
    drop(bank);
    let raw = rusqlite::Connection::open(&db).unwrap();
    let after: (i64, String) = raw
        .query_row("SELECT seq,mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(before, after);
    drop(raw);
    let current = folder.join("current-admin.db");
    std::fs::copy(&audit, &current).unwrap();
    std::fs::copy(&old, &audit).unwrap();
    assert!(Atm::open(&db, &key).is_err(), "an old administrative database bypassed the bank checkpoint");
    std::fs::copy(&current, &audit).unwrap();
    assert!(Atm::open(&db, &key).is_ok());
    std::fs::remove_file(&audit).unwrap();
    assert!(Atm::open(&db, &key).is_err());
    assert!(!audit.exists());
    std::fs::copy(&current, &audit).unwrap();
    let private_key = folder.join("atm.admin-audit.key");
    let saved_key = folder.join("saved-admin.key");
    std::fs::rename(&private_key, &saved_key).unwrap();
    assert!(Atm::open(&db, &key).is_err());
    std::fs::rename(&saved_key, &private_key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&private_key).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert!(Atm::open(&db, &key).is_ok());
    std::fs::remove_dir_all(folder).unwrap();
}
