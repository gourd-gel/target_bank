#![cfg(feature = "programmer-tools")]

use argon2::{Argon2, password_hash::PasswordHasher};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn cargo_tool_requires_secret_file_pin_without_bank_accounts() {
    let folder = std::env::temp_dir().join(format!("atm-programmer-pin-tool-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let secret = folder.join(atm::auth::recovery::PROGRAMMER_PIN_FILE);
    let hash = Argon2::default().hash_password(b"0000").unwrap().to_string();
    std::fs::write(&secret, &hash).unwrap();
    let run = |phone: &str, pin: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bank-authorities"))
            .current_dir(&folder)
            .arg(phone)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(pin.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    };
    let path = folder.join(atm::auth::recovery::AUTHORITIES_CONFIG_FILE);
    assert!(!run("+12125550199", "9999\n").status.success());
    assert!(!path.exists(), "wrong PIN changed the authorities number");
    let valid = run("+1 (212) 555-0199", "0000\n");
    assert!(valid.status.success(), "{}", String::from_utf8_lossy(&valid.stderr));
    assert!(!String::from_utf8_lossy(&valid.stdout).contains("0000"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "+12125550199\n");
    assert!(!run("+12125550198", "9999\n").status.success());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "+12125550199\n");
    assert!(run("+12125550198", "0000\n").status.success());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "+12125550198\n");
    assert!(!run("../invalid", "0000\n").status.success());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "+12125550198\n");
    assert!(!run("+12125550199", "").status.success());
    std::fs::write(&secret, "not a PIN hash\n").unwrap();
    assert!(!run("+12125550199", "0000\n").status.success());
    std::fs::remove_file(&secret).unwrap();
    assert!(!run("+12125550199", "0000\n").status.success());
    assert!(!secret.exists(), "missing secret was silently recreated");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "+12125550198\n");
    assert!(hash.starts_with("$argon2id$"));
    assert!(!folder.join("atm.db").exists(), "maintenance unexpectedly initialized a bank");
}
