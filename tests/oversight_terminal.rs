#![cfg(feature = "authorities-tools")]
mod common;
use atm::money::{Cents, Denomination};
use atm::{Atm, admin, auth, customer};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn authenticated_terminal_inspects_databases_and_traces_users_without_mutating_the_audit() {
    let folder = std::env::temp_dir().join(format!("atm-oversight-terminal-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let db = folder.join("atm.db");
    let key = folder.join("atm.key");
    common::provision(&db);
    std::fs::write(folder.join(auth::recovery::AUTHORITIES_CONFIG_FILE), "+12125550199\n").unwrap();
    let mut bank = Atm::create(&db, &key).unwrap();
    auth::first_run_setup(&mut bank, "teller", "teller-password-1", "handler", "handler-password-1").unwrap();
    let teller = auth::login_admin(&mut bank, "teller", "teller-password-1").unwrap();
    let card =
        admin::create_customer(&mut bank, &teller, "Ann Lee", "1980-01-01", "1357", Cents::from_dollars(100))
            .unwrap();
    let user = auth::login_customer(&mut bank, &card.card_number, "1357").unwrap();
    customer::deposit(&mut bank, &user, &[(Denomination::new(100).unwrap(), 1)]).unwrap();
    drop(bank);
    let audit_head = || {
        let raw = rusqlite::Connection::open(&db).unwrap();
        raw.query_row("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap()
    };
    let before = audit_head();
    let binary = env!("CARGO_BIN_EXE_bank-oversight");
    let mut child = Command::new(binary)
        .arg("--directory")
        .arg(&folder)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "+12125550199").unwrap();
    stdin.flush().unwrap();
    let code_file = folder.join("+12125550199.authorities-login.txt");
    let started = std::time::Instant::now();
    while !code_file.is_file() {
        if started.elapsed() > std::time::Duration::from_secs(15) {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("terminal did not request a code: {}", String::from_utf8_lossy(&output.stderr));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let code = std::fs::read_to_string(&code_file).unwrap();
    writeln!(stdin, "{}", code.trim()).unwrap();
    writeln!(stdin, "databases\ntables main\ntables processing\ntables administration\nrows administration events\nrows main staff\nrows main cards\nrows main meta\nusers\nstaff\naccounts\naudit\nuser {}\nteller teller\naccount {}\nledger\nfees\nrevenue\nrevenue-history\nadmin-audit\ncheck\nquit", card.card_number, card.account_number).unwrap();
    drop(stdin);
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert!(
        result.stderr.is_empty(),
        "inspection command failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    for expected in [
        "Authorities terminal ready",
        "\"database\": \"main\"",
        "\"database\": \"processing\"",
        "\"database\": \"administration\"",
        "administrative_audit_view",
        "Ann Lee",
        "1980-01-01",
        "admin:teller",
        "[protected]",
        "\"result\": \"ok\"",
        "\"requested_cents\": 10000",
        "\"balance_cents\": 300",
    ] {
        assert!(stdout.contains(expected), "terminal output missing {expected}: {stdout}");
    }
    assert!(!stdout.contains("$argon2id$"));
    assert_eq!(before, audit_head());

    // Throttled/invalid authentication must never execute an inspection command.
    let mut rejected = Command::new(binary)
        .arg("--directory")
        .arg(&folder)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    rejected.stdin.take().unwrap().write_all(b"+12125550199\ninvalid\ndatabases\nquit\n").unwrap();
    let rejected = rejected.wait_with_output().unwrap();
    assert!(!rejected.status.success());
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains("Authorities terminal ready"));
    assert_eq!(before, audit_head());

    let missing = folder.join("missing-bank");
    std::fs::create_dir(&missing).unwrap();
    assert!(!Command::new(binary).arg("--directory").arg(&missing).output().unwrap().status.success());
    assert_eq!(std::fs::read_dir(missing).unwrap().count(), 0);
    std::fs::remove_dir_all(folder).unwrap();
}
