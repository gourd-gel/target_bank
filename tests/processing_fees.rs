#![cfg(feature = "programmer-tools")]

use atm::money::{Cents, Denomination};
use atm::{Atm, admin, auth, cash, customer, processing};
use std::process::Command;

#[test]
fn programmer_tool_decrypts_disk_records_and_bank_rejects_missing_or_changed_ledger() {
    let folder = std::env::temp_dir().join(format!("atm-processing-fees-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let db = folder.join("bank.db");
    let key = folder.join("atm.key");
    let private = folder.join("programmer.processing-fees.private.pem");
    let tool = env!("CARGO_BIN_EXE_bank-processing-fees");
    let provision = Command::new(tool).arg("provision").arg(&db).arg(&private).output().unwrap();
    assert!(provision.status.success(), "{}", String::from_utf8_lossy(&provision.stderr));
    assert!(!Command::new(tool).arg("provision").arg(&db).arg(&private).status().unwrap().success());
    std::fs::write(folder.join("bank-authorities-phone.txt"), "+12125550199\n").unwrap();
    let mut bank = Atm::create(&db, &key).unwrap();
    auth::first_run_setup(&mut bank, "teller", "teller-password-1", "handler", "handler-password-1").unwrap();
    let admin = auth::login_admin(&mut bank, "teller", "teller-password-1").unwrap();
    let handler = auth::login_handler(&mut bank, "handler", "handler-password-1").unwrap();
    let twenty = Denomination::new(20).unwrap();
    cash::restock(&mut bank, &handler, twenty, 100).unwrap();
    let customer =
        admin::create_customer(&mut bank, &admin, "Pat Doe", "1980-01-01", "1357", Cents::from_dollars(100))
            .unwrap();
    let session = auth::login_customer(&mut bank, &customer.card_number, "1357").unwrap();
    customer::deposit(&mut bank, &session, &[(twenty, 5)]).unwrap();
    customer::withdraw(&mut bank, &session, Cents::from_dollars(20), atm::dispense::BillChoice::Any).unwrap();
    assert_eq!(customer::balance(&bank, &session).unwrap().as_i64(), 17_640);
    auth::recovery::request_authorities_code(&mut bank, "+12125550199").unwrap();
    let code = std::fs::read_to_string(folder.join("+12125550199.authorities-login.txt")).unwrap();
    let authorities = auth::recovery::login_authorities(&mut bank, "+12125550199", code.trim()).unwrap();
    assert_eq!(atm::revenue::balances(&bank, &authorities).unwrap()[0].balance.as_i64(), 360);
    atm::revenue::adjust(
        &mut bank,
        &authorities,
        atm::fx::Currency::Usd,
        atm::revenue::Adjustment::Credit,
        Cents::from_dollars(1),
        "disk correction",
    )
    .unwrap();
    atm::revenue::adjust(
        &mut bank,
        &authorities,
        atm::fx::Currency::Usd,
        atm::revenue::Adjustment::Debit,
        Cents::new(50).unwrap(),
        "disk correction reversal",
    )
    .unwrap();
    assert_eq!(atm::revenue::balances(&bank, &authorities).unwrap()[0].balance.as_i64(), 410);
    auth::logout_authorities(&mut bank, authorities).unwrap();
    admin::verify_integrity(&mut bank, &admin).unwrap();
    drop(bank);

    let ledger = processing::ledger_path(&db);
    let read = Command::new(tool).arg("read").arg(&ledger).arg(&private).output().unwrap();
    assert!(read.status.success(), "{}", String::from_utf8_lossy(&read.stderr));
    let output = String::from_utf8(read.stdout).unwrap();
    let rows: Vec<serde_json::Value> =
        output.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["record"][4], "deposit");
    assert_eq!(rows[0]["record"][7], 300);
    assert_eq!(rows[1]["record"][7], 60);
    // The bank runtime key cannot read the programmer's ledger.
    let wrong = Command::new(tool).arg("read").arg(&ledger).arg(&key).output().unwrap();
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    let second_private = folder.join("other.processing-fees.private.pem");
    assert!(
        Command::new(tool)
            .arg("provision")
            .arg(folder.join("other.db"))
            .arg(&second_private)
            .output()
            .unwrap()
            .status
            .success()
    );
    let wrong = Command::new(tool).arg("read").arg(&ledger).arg(&second_private).output().unwrap();
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    assert!(Atm::open(&db, &key).is_ok());
    let backup = folder.join("fee-backup.db");
    std::fs::copy(&ledger, &backup).unwrap();
    let raw = rusqlite::Connection::open(&ledger).unwrap();
    raw.execute("DELETE FROM records", []).unwrap();
    drop(raw);
    assert!(Atm::open(&db, &key).is_err());
    std::fs::copy(&backup, &ledger).unwrap();
    assert!(Atm::open(&db, &key).is_ok());
    std::fs::remove_file(&ledger).unwrap();
    assert!(Atm::open(&db, &key).is_err());
    std::fs::copy(&backup, &ledger).unwrap();
    assert!(Atm::open(&db, &key).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&private).unwrap().permissions().mode() & 0o777, 0o600);
    }
    std::fs::remove_dir_all(folder).unwrap();
}
