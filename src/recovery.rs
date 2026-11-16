//! Teller phone recovery. Verified phones live encrypted in `staff`, beside
//! credentials; sealed `meta` records keep temporary challenge state.
use super::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const TTL: i64 = 300;
const MAX_ATTEMPTS: u8 = 5;
const REQUEST_NOTICE: &str = "If this phone is registered, its code is in <phone-number>.txt beside the bank database. Codes expire after 5 minutes. Wait at least 60 seconds before requesting another.";

#[derive(Default, Serialize, Deserialize)]
struct Record {
    #[serde(default, skip_serializing)]
    phone: Option<String>,
    pending: Option<String>,
    purpose: String,
    hash: String,
    expires: i64,
    attempts: u8,
    next_send: i64,
    window: i64,
    sends: u8,
}

fn phone_number(raw: &str) -> Result<String> {
    if raw.len() > 40 {
        return Err(AtmError::InvalidInput("use a phone number with + and its country code"));
    }
    let phone: String = raw.chars().filter(|c| !matches!(c, ' ' | '-' | '(' | ')')).collect();
    let digits = phone.strip_prefix('+').unwrap_or("");
    if !(8..=15).contains(&digits.len())
        || digits.starts_with('0')
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AtmError::InvalidInput("use a phone number with + and its country code"));
    }
    Ok(phone)
}

fn record_key(username: &str) -> String {
    format!("teller-recovery:{username}")
}

fn load(conn: &Connection, username: &str) -> Result<Record> {
    let key = record_key(username);
    let stored: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [&key], |r| r.get(0)).optional()?;
    let Some(stored) = stored else { return Ok(Record::default()) };
    let bytes: Vec<u8> =
        serde_json::from_str(&stored).map_err(|_| AtmError::RecordTampered("recovery phone"))?;
    let clear = Zeroizing::new(keys::unseal("staff.recovery", username, &bytes)?);
    serde_json::from_str(&clear).map_err(|_| AtmError::RecordTampered("recovery phone"))
}

fn save(conn: &Connection, username: &str, record: &Record) -> Result<()> {
    let clear = Zeroizing::new(
        serde_json::to_string(record).map_err(|_| AtmError::Internal("recovery encoding".into()))?,
    );
    let bytes = keys::seal("staff.recovery", username, &clear)?;
    let stored = serde_json::to_string(&bytes).map_err(|_| AtmError::Internal("recovery encoding".into()))?;
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![record_key(username), stored],
    )?;
    Ok(())
}

const AUTHORITIES: &str = "bank authorities";
pub const ALERT_HEADER: &str = "Alert! A teller has failed to bypass PIN verification and is attempting phone verification. Please verify the phone number. The requested text sent to them: ";

/// Create a notification account with no admin or cash-handler permissions.
/// Its random credential has no published default password.
pub(crate) fn create_authorities(conn: &Connection) -> Result<()> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|_| AtmError::Internal("no system randomness".into()))?;
    let secret = Zeroizing::new(
        serde_json::to_string(&secret).map_err(|_| AtmError::Internal("authority credential".into()))?,
    );
    let hash = hash_secret(&secret, &staff_identity(AUTHORITIES, "authorities"))?;
    conn.execute(
        "INSERT INTO staff (username, role, password_hash) VALUES (?1, 'authorities', ?2)",
        params![AUTHORITIES, hash],
    )?;
    Ok(())
}

/// Called only after startup has verified the original database seal, anchor,
/// and clock. Schema and legacy phone migration commit with a new seal/anchor.
pub(crate) fn migrate_staff(atm: &mut Atm) -> Result<()> {
    let tx = atm.begin()?;
    let version: String =
        tx.query_row("SELECT value FROM meta WHERE key = 'schema_version'", [], |r| r.get(0))?;
    if version != "6" {
        return Ok(());
    }
    tx.execute_batch(
        "CREATE TABLE staff_v7 (
        id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL CHECK(role IN ('admin','handler','authorities')),
        password_hash TEXT NOT NULL, phone_enc BLOB,
        failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK(failed_attempts >= 0), cooldown_until TEXT
    ) STRICT;
    INSERT INTO staff_v7 (id,username,role,password_hash,failed_attempts,cooldown_until)
        SELECT id,username,role,password_hash,failed_attempts,cooldown_until FROM staff;
    DROP TABLE staff;
    ALTER TABLE staff_v7 RENAME TO staff;
    UPDATE meta SET value = '7' WHERE key = 'schema_version';",
    )?;
    let names = {
        let mut stmt = tx.prepare("SELECT username FROM staff WHERE role = 'admin'")?;
        stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for name in names {
        let mut record = load(&tx, &name)?;
        if let Some(phone) = record.phone.take() {
            put_phone(&tx, &name, &phone_number(&phone)?)?;
            save(&tx, &name, &record)?;
        }
    }
    if db::is_initialized(&tx)? {
        create_authorities(&tx)?;
        log(
            &tx,
            "system",
            Action::ControlsChanged,
            None,
            "staff phone records migrated; bank authorities account created",
        )?;
    }
    tx.commit()
}

fn staff_phone(conn: &Connection, username: &str) -> Result<Option<String>> {
    let stored: Option<Vec<u8>> =
        conn.query_row("SELECT phone_enc FROM staff WHERE username = ?1", [username], |r| r.get(0))?;
    stored.map(|bytes| keys::unseal("staff.phone", username, &bytes)).transpose()
}

fn put_phone(conn: &Connection, username: &str, phone: &str) -> Result<()> {
    let sealed = keys::seal("staff.phone", username, phone)?;
    let changed =
        conn.execute("UPDATE staff SET phone_enc = ?2 WHERE username = ?1", params![username, sealed])?;
    if changed != 1 {
        return Err(AtmError::NotAllowed("the staff phone account is missing"));
    }
    Ok(())
}

fn phone_owner(conn: &Connection, phone: &str) -> Result<Option<String>> {
    let names = {
        let mut stmt = conn.prepare("SELECT username FROM staff ORDER BY id")?;
        stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for name in names {
        if staff_phone(conn, &name)?.as_deref() == Some(phone) {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

#[cfg(feature = "demo")]
pub(crate) fn seed_demo_phones(
    atm: &mut Atm,
    teller: &str,
    teller_phone: &str,
    authorities_phone: &str,
) -> Result<()> {
    let bank_id = atm.id;
    let tx = atm.begin()?;
    if !db::is_demo(&tx)? {
        return Err(AtmError::NotAllowed("sample phones require a demo bank"));
    }
    let teller_phone = phone_number(teller_phone)?;
    let authorities_phone = phone_number(authorities_phone)?;
    if teller_phone == authorities_phone {
        return Err(AtmError::InvalidInput("staff phone numbers must differ"));
    }
    put_phone(&tx, teller, &teller_phone)?;
    put_phone(&tx, AUTHORITIES, &authorities_phone)?;
    apply_authorities_configuration(&tx, bank_id)?;
    log(&tx, "system", Action::ControlsChanged, None, "demo staff phone numbers registered")?;
    tx.commit()
}

fn find_phone(conn: &Connection, phone: &str) -> Result<Option<(String, Record)>> {
    let Some(name) = phone_owner(conn, phone)? else { return Ok(None) };
    let admin: bool =
        conn.query_row("SELECT role = 'admin' FROM staff WHERE username = ?1", [&name], |r| r.get(0))?;
    if admin { Ok(Some((name.clone(), load(conn, &name)?))) } else { Ok(None) }
}

/// Programmer-managed configuration, separate from staff credential checks.
pub const AUTHORITIES_CONFIG_FILE: &str = "bank-authorities-phone.txt";
pub const PROGRAMMER_PIN_FILE: &str = ".programmer-pin.secret";

/// Cargo maintenance: verify the separate programmer PIN, then update the
/// configuration without opening a bank or checking staff credentials.
#[cfg(feature = "programmer-tools")]
pub fn write_authorities_configuration(
    directory: &std::path::Path,
    phone: &str,
    secret_file: &std::path::Path,
    pin: &str,
) -> Result<()> {
    verify_programmer_pin(secret_file, pin)?;
    let phone = phone_number(phone)?;
    deliver(&directory.join(AUTHORITIES_CONFIG_FILE), &phone)
}

#[cfg(feature = "programmer-tools")]
pub(crate) fn verify_programmer_pin(secret_file: &std::path::Path, pin: &str) -> Result<()> {
    input::validate_pin(pin).map_err(|_| AtmError::NotAllowed("incorrect programmer PIN"))?;
    let stored = Zeroizing::new(std::fs::read_to_string(secret_file).map_err(|_| {
        AtmError::NotAllowed("programmer PIN secret file is missing or unreadable; provision .programmer-pin.secret in the source workspace")
    })?);
    if stored.len() > 1024 {
        return Err(AtmError::NotAllowed("programmer PIN secret file is invalid"));
    }
    let hash = PasswordHash::new(stored.trim())
        .map_err(|_| AtmError::NotAllowed("programmer PIN secret file is invalid"))?;
    if hash.algorithm.as_str() != "argon2id" {
        return Err(AtmError::NotAllowed("programmer PIN secret file is invalid"));
    }
    Argon2::default()
        .verify_password(pin.as_bytes(), &hash)
        .map_err(|_| AtmError::NotAllowed("incorrect programmer PIN"))?;
    Ok(())
}

fn configuration_path(conn: &Connection, bank_id: u64) -> std::path::PathBuf {
    code_path(conn, bank_id, "+").with_file_name(AUTHORITIES_CONFIG_FILE)
}

fn configure_authorities_phone(conn: &Connection, phone: &str) -> Result<bool> {
    let phone = phone_number(phone)?;
    if phone_owner(conn, &phone)?.is_some_and(|name| name != AUTHORITIES) {
        return Err(AtmError::NotAllowed("bank authorities must have a separate phone number"));
    }
    if staff_phone(conn, AUTHORITIES)?.as_deref() == Some(&phone) {
        return Ok(false);
    }
    put_phone(conn, AUTHORITIES, &phone)?;
    Ok(true)
}

/// Read the programmer's file without a teller/bank login or password check.
/// Maintenance changes commit through the database seal without business audit entries.
pub(crate) fn apply_authorities_configuration(conn: &Connection, bank_id: u64) -> Result<bool> {
    let path = configuration_path(conn, bank_id);
    let phone = match std::fs::read_to_string(&path) {
        Ok(phone) => phone,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(AtmError::NotAllowed("could not read bank-authorities-phone.txt")),
    };
    configure_authorities_phone(conn, phone.trim())
}

pub(crate) fn refresh_authorities_configuration(atm: &mut Atm) -> Result<()> {
    let bank_id = atm.id;
    let tx = atm.begin()?;
    if !db::is_initialized(&tx)? {
        return Ok(());
    }
    if apply_authorities_configuration(&tx, bank_id)? {
        tx.commit()?;
    }
    Ok(())
}

fn notify_authorities(conn: &Connection, bank_id: u64, requested_phone: &str, text: &str) -> Result<()> {
    apply_authorities_configuration(conn, bank_id)?;
    let phone = staff_phone(conn, AUTHORITIES)?.ok_or(AtmError::NotAllowed(
        "set the Bank Authorities phone in bank-authorities-phone.txt before requesting phone verification",
    ))?;
    if phone == requested_phone {
        return Err(AtmError::NotAllowed("bank authorities must have a separate phone number"));
    }
    let path = code_path(conn, bank_id, &phone);
    if conn.path().is_none_or(|path| path.is_empty()) {
        std::fs::create_dir_all(
            path.parent().ok_or_else(|| AtmError::Internal("authority file path".into()))?,
        )
        .map_err(|_| AtmError::NotAllowed("could not create the bank authorities notification folder"))?;
    }
    let origin = crate::identity::origin(conn, bank_id)?;
    let body = format!(
        "{ALERT_HEADER}{text}\nRequested phone: {requested_phone}\nATM ID: {}\nATM location: {}\nAlert time (UTC): {}",
        origin.id,
        origin.location,
        audit::now_utc()
    );
    let signature = keys::alert_signature(&body)?;
    deliver(&path, &format!("{body}\nATM signature (HMAC-SHA256): {signature}"))
}

/// Begin enrollment while signed in. Current password is required, and the
/// phone becomes usable for recovery only after its code has been confirmed.
pub fn enroll(atm: &mut Atm, session: &AdminSession, current_password: &str, phone: &str) -> Result<String> {
    atm.admit(session)?;
    let phone = phone_number(phone)?;
    login_staff(atm, &session.username, current_password, "admin")?;
    let bank_id = atm.id;
    let tx = atm.begin_for(session)?;
    if phone_owner(&tx, &phone)?.is_some_and(|name| name != session.username) {
        return Err(AtmError::NotAllowed("this phone is already registered"));
    }
    let mut record = load(&tx, &session.username)?;
    let (notice, delivery) = start(&tx, bank_id, &mut record, &phone, "enroll")?;
    save(&tx, &session.username, &record)?;
    log(&tx, &session.actor(), Action::ControlsChanged, None, "recovery phone enrollment requested")?;
    tx.commit()?;
    delivery?;
    Ok(notice)
}

/// Confirm possession of a new recovery phone. An unconfirmed replacement
/// does not replace the previously registered number.
pub fn confirm_enrollment(atm: &mut Atm, session: &AdminSession, code: &str) -> Result<()> {
    atm.admit(session)?;
    let tx = atm.begin_for(session)?;
    let mut record = load(&tx, &session.username)?;
    let phone = record.pending.clone().ok_or(AtmError::AuthFailed)?;
    let approved = check(&mut record, &phone, code, "enroll")?;
    if approved {
        if phone_owner(&tx, &phone)?.is_some_and(|name| name != session.username) {
            return Err(AtmError::NotAllowed("this phone is already registered"));
        }
        put_phone(&tx, &session.username, &phone)?;
        record.pending = None;
    }
    save(&tx, &session.username, &record)?;
    log(
        &tx,
        &session.actor(),
        if approved { Action::ControlsChanged } else { Action::LoginFailed },
        None,
        if approved { "recovery phone verified" } else { "recovery phone verification rejected" },
    )?;
    tx.commit()?;
    if approved { Ok(()) } else { Err(AtmError::AuthFailed) }
}

/// Request a sign-in code using only the previously verified phone. Unknown
/// numbers and throttled requests return the same notice. The code itself
/// is delivered only to the phone-number text file, never returned here.
pub fn request_code(atm: &mut Atm, phone: &str) -> Result<String> {
    let bank_id = atm.id;
    let parsed = phone_number(phone);
    let tx = atm.begin()?;
    let phone = match parsed {
        Ok(phone) => phone,
        Err(_) => {
            notify_authorities(
                &tx,
                bank_id,
                "invalid phone number",
                "No verification text was sent: invalid phone number.",
            )?;
            log(&tx, "anonymous", Action::LoginFailed, None, "invalid phone recovery request")?;
            tx.commit()?;
            return Ok(REQUEST_NOTICE.into());
        }
    };
    let Some((username, mut record)) = find_phone(&tx, &phone)? else {
        notify_authorities(
            &tx,
            bank_id,
            &phone,
            "No verification text was sent: the number is not registered to a teller.",
        )?;
        log(&tx, "anonymous", Action::LoginFailed, None, "phone recovery request")?;
        tx.commit()?;
        return Ok(REQUEST_NOTICE.into());
    };
    if !can_send(&record) {
        notify_authorities(
            &tx,
            bank_id,
            &phone,
            "No verification text was sent: the request is temporarily rate limited.",
        )?;
        log(&tx, "anonymous", Action::LoginFailed, None, "phone recovery request rate limited")?;
        tx.commit()?;
        return Ok(REQUEST_NOTICE.into());
    }
    let (_notice, delivery) = start(&tx, bank_id, &mut record, &phone, "login")?;
    save(&tx, &username, &record)?;
    log(
        &tx,
        "anonymous",
        if delivery.is_ok() { Action::ControlsChanged } else { Action::LoginFailed },
        None,
        "phone recovery code requested",
    )?;
    tx.commit()?;
    // Public responses never reveal whether a number exists or delivery failed.
    Ok(REQUEST_NOTICE.into())
}

/// Verify a single-use phone code and sign in as its teller. Runs the same
/// integrity check and uses the same idle timeout as password sign-in.
pub fn login(atm: &mut Atm, phone: &str, code: &str) -> Result<AdminSession> {
    let phone = phone_number(phone).map_err(|_| AtmError::AuthFailed)?;
    let tx = atm.begin()?;
    let Some((username, mut record)) = find_phone(&tx, &phone)? else {
        log(&tx, "anonymous", Action::LoginFailed, None, "phone recovery rejected")?;
        tx.commit()?;
        return Err(AtmError::AuthFailed);
    };
    let approved = check(&mut record, &phone, code, "login")?;
    save(&tx, &username, &record)?;
    log(
        &tx,
        &format!("admin:{username}"),
        if approved { Action::LoginOk } else { Action::LoginFailed },
        None,
        "phone recovery",
    )?;
    if approved {
        tx.execute("UPDATE staff SET failed_attempts = 0, cooldown_until = NULL WHERE username = ?1 AND role = 'admin'", [&username])?;
    }
    tx.commit()?;
    if !approved {
        return Err(AtmError::AuthFailed);
    }
    let integrity_problem = crate::service::check_at_sign_in(atm, &format!("admin:{username}"))?;
    Ok(AdminSession { bank: atm.id, username, clock: IdleClock::new(), integrity_problem })
}

fn can_send(record: &Record) -> bool {
    let now = Utc::now().timestamp();
    now >= record.next_send && (now >= record.window + 900 || record.sends < 3)
}

/// Authorities use their separately configured phone, never a teller's phone or code.
pub fn request_authorities_code(atm: &mut Atm, phone: &str) -> Result<String> {
    let bank_id = atm.id;
    let tx = atm.begin()?;
    apply_authorities_configuration(&tx, bank_id)?;
    let expected = staff_phone(&tx, AUTHORITIES)?;
    let valid = phone_number(phone).ok().filter(|phone| expected.as_deref() == Some(phone));
    if let Some(phone) = valid {
        let mut record = load(&tx, AUTHORITIES)?;
        if can_send(&record) {
            // Challenge state and throttling persist, without writing a business audit event.
            let _ = start(&tx, bank_id, &mut record, &phone, "authorities-login")?;
            save(&tx, AUTHORITIES, &record)?;
        }
    }
    tx.commit()?;
    Ok("If registered to Bank Authorities, the code is in <phone-number>.authorities-login.txt beside the bank database. It expires in 5 minutes; wait 60 seconds before requesting another.".into())
}

pub fn login_authorities(atm: &mut Atm, phone: &str, code: &str) -> Result<AuthoritiesSession> {
    let phone = phone_number(phone).map_err(|_| AtmError::AuthFailed)?;
    let tx = atm.begin()?;
    let is_authorities: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM staff WHERE username = ?1 AND role = 'authorities')",
        [AUTHORITIES],
        |r| r.get(0),
    )?;
    let mut record = load(&tx, AUTHORITIES)?;
    let approved = is_authorities
        && staff_phone(&tx, AUTHORITIES)?.as_deref() == Some(&phone)
        && check(&mut record, &phone, code, "authorities-login")?;
    save(&tx, AUTHORITIES, &record)?;
    tx.commit()?;
    if !approved {
        return Err(AtmError::AuthFailed);
    }
    Ok(AuthoritiesSession { bank: atm.id, username: AUTHORITIES.into(), clock: IdleClock::new() })
}

/// Codes are written beside the database. In-memory test banks use separate
/// temporary folders so parallel banks never overwrite each other's code.
fn code_path(conn: &Connection, bank_id: u64, phone: &str) -> std::path::PathBuf {
    let directory = match conn.path().filter(|path| !path.is_empty()) {
        Some(path) => {
            std::path::Path::new(path).parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf()
        }
        None => std::env::temp_dir().join(format!("atm-phone-codes-{bank_id}")),
    };
    directory.join(format!("{phone}.txt"))
}

// Replace atomically, without following a pre-existing destination symlink.
// Restrict access to the current user on Unix. The file contains only the code.
pub(crate) fn deliver(path: &std::path::Path, code: &str) -> Result<()> {
    use std::io::Write;
    let failure =
        || AtmError::NotAllowed("could not write the authentication code file beside the bank database");
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| failure())?;
    let temporary = path.with_extension(format!("{:016x}.tmp", u64::from_le_bytes(nonce)));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| failure())?;
    let result = (|| {
        writeln!(file, "{code}")?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(|_| failure())
}

// Commit the send limit even when file delivery fails. An undelivered code
// must never become valid, and cannot grant a session.
fn start(
    conn: &Connection,
    bank_id: u64,
    record: &mut Record,
    phone: &str,
    purpose: &str,
) -> Result<(String, Result<()>)> {
    if !can_send(record) {
        notify_authorities(
            conn,
            bank_id,
            phone,
            "No verification text was sent: the request is temporarily rate limited.",
        )?;
        return Err(AtmError::NotAllowed("wait before requesting another phone code"));
    }
    let now = Utc::now().timestamp();
    if now >= record.window + 900 {
        record.window = now;
        record.sends = 0;
    }
    record.sends += 1;
    record.next_send = now + 60;
    record.expires = now + TTL;
    record.attempts = 0;
    record.purpose = purpose.into();
    record.pending = if purpose == "enroll" { Some(phone.into()) } else { None };
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).map_err(|_| AtmError::Internal("no system randomness".into()))?;
    let code = Zeroizing::new(format!("{:06}", u32::from_le_bytes(bytes) % 1_000_000));
    record.hash = keys::record_mac(&["phone-code", phone, purpose, &code])?;
    let path = if purpose == "authorities-login" {
        code_path(conn, bank_id, phone).with_extension("authorities-login.txt")
    } else {
        code_path(conn, bank_id, phone)
    };
    // Only the private per-bank folder for in-memory tests needs creating.
    if conn.path().is_none_or(|path| path.is_empty()) {
        std::fs::create_dir_all(path.parent().ok_or_else(|| AtmError::Internal("code file path".into()))?)
            .map_err(|_| AtmError::NotAllowed("could not create the authentication code folder"))?;
    }
    let text = format!("{}\n", &*code);
    let delivery = if purpose == "authorities-login" {
        deliver(&path, &code)
    } else {
        notify_authorities(conn, bank_id, phone, &text).and_then(|_| deliver(&path, &code))
    };
    if delivery.is_err() {
        record.expires = 0;
    }
    Ok((format!("Read the verification code from {}. It expires in 5 minutes.", path.display()), delivery))
}

fn check(record: &mut Record, phone: &str, code: &str, purpose: &str) -> Result<bool> {
    if record.purpose != purpose
        || record.expires <= Utc::now().timestamp()
        || record.attempts >= MAX_ATTEMPTS
    {
        return Ok(false);
    }
    record.attempts += 1;
    let valid_format = code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit());
    let approved = valid_format
        && keys::same_mac(&record.hash, &keys::record_mac(&["phone-code", phone, purpose, code])?);
    if approved || record.attempts >= MAX_ATTEMPTS {
        record.expires = 0;
    }
    Ok(approved)
}

#[cfg(test)]
mod tests {
    use super::super::testing::{self, ADMIN};
    use super::*;
    const PHONE: &str = "+12125551234";

    fn bank() -> (Atm, AdminSession) {
        let mut atm = Atm::in_memory().unwrap();
        let (admin, _) = testing::setup(&mut atm);
        let tx = atm.begin().unwrap();
        configure_authorities_phone(&tx, "+12125550199").unwrap();
        tx.commit().unwrap();
        (atm, admin)
    }

    fn code(atm: &Atm) -> String {
        std::fs::read_to_string(code_path(&atm.conn, atm.id, PHONE)).unwrap().trim().to_string()
    }

    fn registered() -> (Atm, AdminSession) {
        let (mut atm, admin) = bank();
        let _notice = enroll(&mut atm, &admin, ADMIN.1, PHONE).unwrap();
        let code = code(&atm);
        confirm_enrollment(&mut atm, &admin, &code).unwrap();
        let tx = atm.begin().unwrap();
        let mut record = load(&tx, ADMIN.0).unwrap();
        record.next_send = 0;
        save(&tx, ADMIN.0, &record).unwrap();
        tx.commit().unwrap();
        (atm, admin)
    }

    #[test]
    fn authorities_phone_login_is_single_use_and_never_grants_teller_access() {
        let (mut atm, _) = registered();
        let phone = "+12125550199";
        request_authorities_code(&mut atm, phone).unwrap();
        let file = code_path(&atm.conn, atm.id, phone).with_extension("authorities-login.txt");
        let authority_code = std::fs::read_to_string(&file).unwrap().trim().to_string();
        assert!(!request_authorities_code(&mut atm, phone).unwrap().contains(&authority_code));
        assert_eq!(std::fs::read_to_string(&file).unwrap().trim(), authority_code);
        assert!(login(&mut atm, phone, &authority_code).is_err());
        // A teller alert must not replace the authorities' outstanding sign-in code.
        request_code(&mut atm, PHONE).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap().trim(), authority_code);
        let teller_code = code(&atm);
        assert!(login_authorities(&mut atm, PHONE, &teller_code).is_err());
        let session = login_authorities(&mut atm, phone, &authority_code).unwrap();
        assert_eq!(crate::revenue::balances(&atm, &session).unwrap()[0].balance, crate::money::Cents::ZERO);
        assert!(login_authorities(&mut atm, phone, &authority_code).is_err());
        logout_authorities(&mut atm, session).unwrap();
    }

    #[test]
    fn authorities_codes_expire_and_stop_after_five_wrong_attempts() {
        let (mut atm, _) = bank();
        let phone = "+12125550199";
        request_authorities_code(&mut atm, phone).unwrap();
        let path = code_path(&atm.conn, atm.id, phone).with_extension("authorities-login.txt");
        let code = std::fs::read_to_string(&path).unwrap().trim().to_string();
        for _ in 0..5 {
            assert!(login_authorities(&mut atm, phone, "invalid").is_err());
        }
        assert!(login_authorities(&mut atm, phone, &code).is_err());
        let tx = atm.begin().unwrap();
        let mut record = load(&tx, AUTHORITIES).unwrap();
        record.next_send = 0;
        save(&tx, AUTHORITIES, &record).unwrap();
        tx.commit().unwrap();
        request_authorities_code(&mut atm, phone).unwrap();
        let code = std::fs::read_to_string(&path).unwrap().trim().to_string();
        let tx = atm.begin().unwrap();
        let mut record = load(&tx, AUTHORITIES).unwrap();
        record.expires = Utc::now().timestamp() - 1;
        save(&tx, AUTHORITIES, &record).unwrap();
        tx.commit().unwrap();
        assert!(login_authorities(&mut atm, phone, &code).is_err());
    }

    #[test]
    fn authorities_authentication_leaves_no_business_audit_entries_but_keeps_security_state() {
        let (mut atm, _) = bank();
        let phone = "+12125550199";
        let before: (i64, String) = atm
            .conn
            .query_row("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        request_authorities_code(&mut atm, "invalid").unwrap();
        request_authorities_code(&mut atm, "+12125559999").unwrap();
        request_authorities_code(&mut atm, phone).unwrap();
        let path = code_path(&atm.conn, atm.id, phone).with_extension("authorities-login.txt");
        let code = std::fs::read_to_string(&path).unwrap().trim().to_string();
        request_authorities_code(&mut atm, phone).unwrap(); // throttled, no replacement
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), code);
        assert!(login_authorities(&mut atm, phone, "invalid").is_err());
        let record = load(&atm.read().unwrap(), AUTHORITIES).unwrap();
        assert_eq!(record.attempts, 1);
        assert_eq!(record.sends, 1);
        let session = login_authorities(&mut atm, phone, &code).unwrap();
        crate::revenue::balances(&atm, &session).unwrap();
        logout_authorities(&mut atm, session).unwrap();
        assert!(login_authorities(&mut atm, phone, &code).is_err());
        let after: (i64, String) = atm
            .conn
            .query_row("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(before, after, "Authorities authentication changed the ATM business audit");
        audit::verify(&atm.read().unwrap()).unwrap();
    }

    #[test]
    fn enrollment_requires_password_and_phone_proof() {
        let (mut atm, admin) = bank();
        assert!(enroll(&mut atm, &admin, "incorrect password", PHONE).is_err());
        let _notice = enroll(&mut atm, &admin, ADMIN.1, PHONE).unwrap();
        let code = code(&atm);
        assert!(login(&mut atm, PHONE, &code).is_err());
        assert!(confirm_enrollment(&mut atm, &admin, "bad code").is_err());
        confirm_enrollment(&mut atm, &admin, &code).unwrap();
        assert!(confirm_enrollment(&mut atm, &admin, &code).is_err());
    }

    #[test]
    fn recovery_signs_in_correct_teller_and_consumes_code() {
        let (mut atm, _) = registered();
        let _notice = request_code(&mut atm, "+1 (212) 555-1234").unwrap();
        let code = code(&atm);
        let session = login(&mut atm, PHONE, &code).unwrap();
        assert_eq!(session.actor(), "admin:alice");
        assert!(session.integrity_problem().is_none());
        assert!(login(&mut atm, PHONE, &code).is_err());
        session.end();
        assert!(crate::admin::verify_integrity(&mut atm, &session).is_err());
    }

    #[test]
    fn code_is_delivered_to_normalized_phone_file_without_being_shown() {
        let (mut atm, admin) = bank();
        let notice = enroll(&mut atm, &admin, ADMIN.1, "+1 (212) 555-1234").unwrap();
        let path = code_path(&atm.conn, atm.id, PHONE);
        assert_eq!(path.file_name().unwrap(), "+12125551234.txt");
        let code = code(&atm);
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert!(notice.contains("+12125551234.txt"));
        assert!(!notice.contains(&code));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        confirm_enrollment(&mut atm, &admin, &code).unwrap();
    }

    #[test]
    fn blocked_delivery_invalidates_codes_and_keeps_send_limits() {
        let (mut atm, _) = registered();
        let old_code = code(&atm);
        let path = code_path(&atm.conn, atm.id, PHONE);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(request_code(&mut atm, PHONE).unwrap(), REQUEST_NOTICE);
        assert!(login(&mut atm, PHONE, &old_code).is_err());
        let record = load(&atm.read().unwrap(), ADMIN.0).unwrap();
        assert_eq!(record.expires, 0);
        assert_eq!(record.sends, 2);
        assert!(!can_send(&record));
        assert!(path.is_dir());
        let entries = std::fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(entries, 2, "failed delivery left a temporary code file");
    }

    #[test]
    fn resend_replaces_file_and_invalidates_previous_code() {
        let (mut atm, _) = registered();
        request_code(&mut atm, PHONE).unwrap();
        let old_code = code(&atm);
        assert_eq!(request_code(&mut atm, PHONE).unwrap(), REQUEST_NOTICE);
        assert_eq!(code(&atm), old_code, "throttled request changed the file");
        let tx = atm.begin().unwrap();
        let mut record = load(&tx, ADMIN.0).unwrap();
        record.next_send = 0;
        save(&tx, ADMIN.0, &record).unwrap();
        tx.commit().unwrap();
        request_code(&mut atm, PHONE).unwrap();
        let fresh_code = code(&atm);
        if old_code != fresh_code {
            assert!(login(&mut atm, PHONE, &old_code).is_err());
        }
        assert!(login(&mut atm, PHONE, &fresh_code).is_ok());
    }

    #[test]
    fn recovery_runs_integrity_check_even_after_password_cooldown() {
        let (mut atm, admin) = registered();
        crate::admin::create_customer(
            &mut atm,
            &admin,
            "Test Customer",
            "1990-01-01",
            "4821",
            crate::money::Cents::from_dollars(100),
        )
        .unwrap();
        for _ in 0..3 {
            assert!(super::super::login_admin(&mut atm, ADMIN.0, "incorrect password").is_err());
        }
        let _notice = request_code(&mut atm, PHONE).unwrap();
        let code = code(&atm);
        atm.execute("UPDATE accounts SET balance_cents = balance_cents + 50000", []).unwrap();
        atm.reseal();
        let session = login(&mut atm, PHONE, &code).unwrap();
        assert!(session.integrity_problem().is_some_and(|p| p.contains("balance")));
        assert!(crate::service::out_of_service(&atm).unwrap());
        assert!(super::super::login_admin(&mut atm, ADMIN.0, ADMIN.1).is_ok());
    }

    #[test]
    fn expired_and_exhausted_codes_fail_and_throttle_survives_reload() {
        let (mut atm, _) = registered();
        let _notice = request_code(&mut atm, PHONE).unwrap();
        let code = code(&atm);
        assert_eq!(request_code(&mut atm, PHONE).unwrap(), REQUEST_NOTICE);
        for _ in 0..MAX_ATTEMPTS {
            assert!(login(&mut atm, PHONE, "bad").is_err());
        }
        assert!(login(&mut atm, PHONE, &code).is_err());
        let tx = atm.begin().unwrap();
        let mut record = load(&tx, ADMIN.0).unwrap();
        assert_eq!(record.attempts, MAX_ATTEMPTS);
        record.attempts = 0;
        record.expires = Utc::now().timestamp() - 1;
        save(&tx, ADMIN.0, &record).unwrap();
        tx.commit().unwrap();
        assert!(login(&mut atm, PHONE, &code).is_err());
    }

    #[test]
    fn unknown_phone_is_generic_and_records_keep_secrets_encrypted() {
        let (mut atm, _) = registered();
        assert_eq!(request_code(&mut atm, "+12125559999").unwrap(), REQUEST_NOTICE);
        assert!(login(&mut atm, "+12125559999", "123456").is_err());
        assert!(!code_path(&atm.conn, atm.id, "+12125559999").exists());
        let conn = atm.read().unwrap();
        let stored: String = conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [record_key(ADMIN.0)], |r| r.get(0))
            .unwrap();
        assert!(!stored.contains(PHONE));
        let logged: i64 = conn
            .query_row("SELECT count(*) FROM audit_log WHERE detail LIKE '%2125551234%'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(logged, 0);
    }

    #[test]
    fn file_delivery_uses_database_folder_and_replaces_symlink_safely() {
        let (atm, _) = bank();
        let folder = std::env::temp_dir().join(format!("atm-phone-path-{}", atm.id));
        std::fs::create_dir_all(&folder).unwrap();
        let conn = Connection::open(folder.join("custom-bank.db")).unwrap();
        let path = code_path(&conn, atm.id, PHONE);
        assert_eq!(path, folder.canonicalize().unwrap().join("+12125551234.txt"));
        #[cfg(unix)]
        {
            let other = folder.join("unrelated.txt");
            std::fs::write(&other, "leave unchanged").unwrap();
            std::os::unix::fs::symlink(&other, &path).unwrap();
            deliver(&path, "123456").unwrap();
            assert_eq!(std::fs::read_to_string(&other).unwrap(), "leave unchanged");
            assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        }
        #[cfg(not(unix))]
        deliver(&path, "123456").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "123456\n");
    }

    #[test]
    fn send_budget_blocks_resends_until_window_ends() {
        let (mut atm, _) = registered();
        let tx = atm.begin().unwrap();
        let mut record = load(&tx, ADMIN.0).unwrap();
        record.sends = 3;
        record.next_send = 0;
        save(&tx, ADMIN.0, &record).unwrap();
        tx.commit().unwrap();
        assert_eq!(request_code(&mut atm, PHONE).unwrap(), REQUEST_NOTICE);
        let tx = atm.begin().unwrap();
        let mut record = load(&tx, ADMIN.0).unwrap();
        record.window = Utc::now().timestamp() - 901;
        save(&tx, ADMIN.0, &record).unwrap();
        tx.commit().unwrap();
        let _notice = request_code(&mut atm, PHONE).unwrap();
        let code = code(&atm);
        assert!(login(&mut atm, PHONE, &code).is_ok());
    }

    #[test]
    fn enrollment_checks_session_and_normalizes_numbers() {
        assert_eq!(phone_number("+1 (212) 555-1234").unwrap(), PHONE);
        for bad in ["2125551234", "+0123456789", "+123", "+12125551234x", "++12125551234"] {
            assert!(phone_number(bad).is_err());
        }
        let (mut atm, admin) = bank();
        admin.end();
        assert!(enroll(&mut atm, &admin, ADMIN.1, PHONE).is_err());
    }

    #[test]
    fn unconfirmed_replacement_preserves_old_phone() {
        let (mut atm, admin) = registered();
        enroll(&mut atm, &admin, ADMIN.1, "+12125556789").unwrap();
        let conn = atm.read().unwrap();
        assert!(find_phone(&conn, PHONE).unwrap().is_some());
        assert!(find_phone(&conn, "+12125556789").unwrap().is_none());
    }
    #[test]
    fn staff_rows_hold_verified_phones_and_authority_account_has_no_teller_access() {
        let (mut atm, _) = registered();
        let conn = atm.read().unwrap();
        assert_eq!(staff_phone(&conn, ADMIN.0).unwrap().as_deref(), Some(PHONE));
        assert_eq!(staff_phone(&conn, AUTHORITIES).unwrap().as_deref(), Some("+12125550199"));
        let (role, hash, encrypted): (String, String, Vec<u8>) = conn
            .query_row(
                "SELECT role,password_hash,phone_enc FROM staff WHERE username = ?1",
                [AUTHORITIES],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(role, "authorities");
        assert!(!hash.is_empty());
        assert!(!encrypted.windows(PHONE.len()).any(|bytes| bytes == PHONE.as_bytes()));
        let record = load(&conn, ADMIN.0).unwrap();
        assert!(record.phone.is_none(), "verified number remained in challenge metadata");
        drop(conn);
        assert!(super::super::login_admin(&mut atm, AUTHORITIES, ADMIN.1).is_err());
        assert!(super::super::login_handler(&mut atm, AUTHORITIES, ADMIN.1).is_err());
    }

    #[test]
    fn authority_gets_exact_header_and_copy_for_enrollment_and_login_requests() {
        let (mut atm, admin) = bank();
        enroll(&mut atm, &admin, ADMIN.1, PHONE).unwrap();
        let file = code_path(&atm.conn, atm.id, "+12125550199");
        let delivered = std::fs::read_to_string(code_path(&atm.conn, atm.id, PHONE)).unwrap();
        let alert = std::fs::read_to_string(&file).unwrap();
        assert!(alert.starts_with(&format!("{ALERT_HEADER}{delivered}")));
        assert!(alert.contains(&format!("Requested phone: {PHONE}")));
        assert!(alert.contains("ATM ID: "));
        assert!(alert.contains("ATM location: Not configured"));
        assert_alert_signature(&alert);
        let code = code(&atm);
        confirm_enrollment(&mut atm, &admin, &code).unwrap();
        let tx = atm.begin().unwrap();
        let mut record = load(&tx, ADMIN.0).unwrap();
        record.next_send = 0;
        save(&tx, ADMIN.0, &record).unwrap();
        tx.commit().unwrap();
        request_code(&mut atm, PHONE).unwrap();
        let delivered = std::fs::read_to_string(code_path(&atm.conn, atm.id, PHONE)).unwrap();
        assert!(std::fs::read_to_string(file).unwrap().starts_with(&format!("{ALERT_HEADER}{delivered}")));
    }

    fn assert_alert_signature(alert: &str) {
        let (body, signature) = alert.rsplit_once("\nATM signature (HMAC-SHA256): ").unwrap();
        assert!(keys::same_mac(signature.trim(), &keys::alert_signature(body).unwrap()));
        assert!(!keys::same_mac(
            signature.trim(),
            &keys::alert_signature(&body.replace("Requested phone:", "Changed phone:")).unwrap()
        ));
        let timestamp = body.lines().find_map(|line| line.strip_prefix("Alert time (UTC): ")).unwrap();
        chrono::DateTime::parse_from_rfc3339(timestamp).unwrap();
    }

    #[test]
    fn every_teller_otp_request_alert_has_location_stable_id_and_authentication_signature() {
        let (mut atm, _) = registered();
        let folder = code_path(&atm.conn, atm.id, PHONE).parent().unwrap().to_path_buf();
        std::fs::write(folder.join(crate::identity::LOCATION_CONFIG_FILE), "CCNY — Test branch, ATM 04\n")
            .unwrap();
        let mut id = None;
        for phone in [PHONE, "+12125559999", "invalid", PHONE] {
            request_code(&mut atm, phone).unwrap();
            let alert = std::fs::read_to_string(folder.join("+12125550199.txt")).unwrap();
            assert!(alert.contains("ATM location: CCNY — Test branch, ATM 04"));
            let current = alert.lines().find_map(|l| l.strip_prefix("ATM ID: ")).unwrap().to_string();
            assert_eq!(current.len(), 32);
            if let Some(id) = &id {
                assert_eq!(id, &current);
            } else {
                id = Some(current);
            }
            assert_alert_signature(&alert);
        }
        // A location update is applied before the next alert, without rotating ATM ID.
        std::fs::write(folder.join(crate::identity::LOCATION_CONFIG_FILE), "CCNY — Test branch, ATM 05\n")
            .unwrap();
        request_code(&mut atm, PHONE).unwrap();
        let alert = std::fs::read_to_string(folder.join("+12125550199.txt")).unwrap();
        assert!(alert.contains("ATM location: CCNY — Test branch, ATM 05"));
        assert!(alert.contains(&format!("ATM ID: {}", id.unwrap())));
        assert_alert_signature(&alert);
        let logged: i64 = atm
            .conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE detail LIKE 'ATM % location configured: %'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(logged, 0, "programmer location changes entered the business audit");
    }

    #[test]
    fn malformed_location_cannot_inject_alert_fields_or_issue_a_teller_code() {
        let (mut atm, _) = registered();
        let file = code_path(&atm.conn, atm.id, PHONE);
        std::fs::remove_file(&file).unwrap();
        std::fs::write(
            file.parent().unwrap().join(crate::identity::LOCATION_CONFIG_FILE),
            "Branch\nATM ID: forged",
        )
        .unwrap();
        request_code(&mut atm, PHONE).unwrap();
        assert!(!file.exists());
        assert_eq!(load(&atm.read().unwrap(), ADMIN.0).unwrap().expires, 0);
    }

    #[test]
    fn unregistered_invalid_and_throttled_requests_alert_without_issuing_codes() {
        let (mut atm, _) = registered();
        let authority_file = code_path(&atm.conn, atm.id, "+12125550199");
        request_code(&mut atm, "+12125559999").unwrap();
        let alert = std::fs::read_to_string(&authority_file).unwrap();
        assert!(alert.starts_with(ALERT_HEADER));
        assert!(alert.contains("not registered to a teller"));
        assert!(alert.contains("+12125559999"));
        assert!(!code_path(&atm.conn, atm.id, "+12125559999").exists());
        request_code(&mut atm, "../other").unwrap();
        assert!(std::fs::read_to_string(&authority_file).unwrap().contains("invalid phone number"));
        request_code(&mut atm, PHONE).unwrap();
        let code = code(&atm);
        request_code(&mut atm, PHONE).unwrap();
        assert!(std::fs::read_to_string(&authority_file).unwrap().contains("rate limited"));
        assert!(login(&mut atm, PHONE, &code).is_ok(), "throttle alert invalidated the existing code");
    }

    #[test]
    fn missing_or_unwritable_authority_destination_prevents_code_delivery() {
        let (mut atm, admin) = bank();
        let tx = atm.begin().unwrap();
        tx.execute("UPDATE staff SET phone_enc = NULL WHERE role = 'authorities'", []).unwrap();
        tx.commit().unwrap();
        assert!(enroll(&mut atm, &admin, ADMIN.1, PHONE).is_err());
        assert!(!code_path(&atm.conn, atm.id, PHONE).exists());
        let tx = atm.begin().unwrap();
        configure_authorities_phone(&tx, "+12125550199").unwrap();
        tx.commit().unwrap();
        let authority_path = code_path(&atm.conn, atm.id, "+12125550199");
        std::fs::create_dir(&authority_path).unwrap();
        let tx = atm.begin().unwrap();
        let mut record = load(&tx, ADMIN.0).unwrap();
        record.next_send = 0;
        save(&tx, ADMIN.0, &record).unwrap();
        tx.commit().unwrap();
        assert!(enroll(&mut atm, &admin, ADMIN.1, PHONE).is_err());
        assert!(!code_path(&atm.conn, atm.id, PHONE).exists());
        assert_eq!(load(&atm.read().unwrap(), ADMIN.0).unwrap().expires, 0);
    }

    #[test]
    fn programmer_configuration_imports_preserve_the_business_audit() {
        let (mut atm, _) = registered();
        let before: (i64, String) = atm
            .conn
            .query_row("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let location =
            code_path(&atm.conn, atm.id, PHONE).parent().unwrap().join(crate::identity::LOCATION_CONFIG_FILE);
        std::fs::write(&location, "Maintenance test location\n").unwrap();
        let config = configuration_path(&atm.conn, atm.id);
        std::fs::write(&config, "+12125559999\n").unwrap();
        refresh_authorities_configuration(&mut atm).unwrap();
        crate::identity::initialize(&mut atm).unwrap();
        let after: (i64, String) = atm
            .conn
            .query_row("SELECT seq, mac FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(before, after, "maintenance changed the business audit head");
        assert_eq!(staff_phone(&atm.read().unwrap(), AUTHORITIES).unwrap().as_deref(), Some("+12125559999"));
        let bank_id = atm.id;
        let view = atm.read().unwrap();
        assert_eq!(crate::identity::origin(&view, bank_id).unwrap().location, "Maintenance test location");
        audit::verify(&view).unwrap();
    }

    #[test]
    fn programmer_file_changes_authorities_phone_without_a_staff_session() {
        let (mut atm, admin) = registered();
        admin.end();
        let config = configuration_path(&atm.conn, atm.id);
        std::fs::write(&config, "+1 (212) 555-9999\n").unwrap();
        request_code(&mut atm, PHONE).unwrap();
        assert_eq!(staff_phone(&atm.read().unwrap(), AUTHORITIES).unwrap().as_deref(), Some("+12125559999"));
        let alert = std::fs::read_to_string(code_path(&atm.conn, atm.id, "+12125559999")).unwrap();
        assert!(alert.starts_with(ALERT_HEADER));
        assert!(alert.contains(&code(&atm)));
        let code = code(&atm);
        assert!(login(&mut atm, PHONE, &code).is_ok());
    }

    #[test]
    fn programmer_configuration_rejects_invalid_and_teller_numbers() {
        let (mut atm, _) = registered();
        let config = configuration_path(&atm.conn, atm.id);
        std::fs::write(&config, PHONE).unwrap();
        assert!(request_code(&mut atm, PHONE).is_ok());
        // Delivery fails closed when the configured authority would share the teller file.
        assert_eq!(load(&atm.read().unwrap(), ADMIN.0).unwrap().expires, 0);
        assert_eq!(staff_phone(&atm.read().unwrap(), AUTHORITIES).unwrap().as_deref(), Some("+12125550199"));
        std::fs::write(&config, "../not-a-phone").unwrap();
        assert!(refresh_authorities_configuration(&mut atm).is_err());
    }

    fn make_version6(atm: &mut Atm) {
        let tx = atm.begin().unwrap();
        let mut legacy = serde_json::to_value(Record::default()).unwrap();
        legacy["phone"] = serde_json::Value::String(PHONE.into());
        let bytes = keys::seal("staff.recovery", ADMIN.0, &legacy.to_string()).unwrap();
        tx.execute("INSERT INTO meta (key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![record_key(ADMIN.0),serde_json::to_string(&bytes).unwrap()]).unwrap();
        tx.execute_batch("CREATE TABLE staff_old (
            id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL CHECK(role IN ('admin','handler')), password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK(failed_attempts >= 0), cooldown_until TEXT
        ) STRICT;
        INSERT INTO staff_old SELECT id,username,role,password_hash,failed_attempts,cooldown_until FROM staff WHERE role != 'authorities';
        DROP TABLE staff; ALTER TABLE staff_old RENAME TO staff;
        UPDATE meta SET value = '6' WHERE key = 'schema_version';").unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn startup_migrates_legacy_phones_without_changing_credentials_or_ids() {
        let (seed, _) = bank();
        let folder = std::env::temp_dir().join(format!("atm-staff-migration-{}", seed.id));
        std::fs::create_dir_all(&folder).unwrap();
        let key = folder.join("bank.key");
        std::fs::write(&key, [7u8; 32]).unwrap();
        let db = folder.join("bank.db");
        let mut atm = Atm::create(&db, &key).unwrap();
        testing::setup(&mut atm);
        let before: (i64, String) = atm
            .read()
            .unwrap()
            .query_row("SELECT id,password_hash FROM staff WHERE username = ?1", [ADMIN.0], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        make_version6(&mut atm);
        std::fs::write(folder.join(AUTHORITIES_CONFIG_FILE), "+12125559999\n").unwrap();
        drop(atm);
        let mut migrated = Atm::open(&db, &key).unwrap();
        let after: (i64, String) = migrated
            .read()
            .unwrap()
            .query_row("SELECT id,password_hash FROM staff WHERE username = ?1", [ADMIN.0], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(staff_phone(&migrated.read().unwrap(), ADMIN.0).unwrap().as_deref(), Some(PHONE));
        let count: i64 = migrated
            .read()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM staff WHERE username = 'bank authorities' AND role = 'authorities'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            staff_phone(&migrated.read().unwrap(), AUTHORITIES).unwrap().as_deref(),
            Some("+12125559999")
        );
        assert!(super::super::login_admin(&mut migrated, ADMIN.0, ADMIN.1).is_ok());
        drop(migrated);
        assert!(Atm::open(&db, &key).is_ok(), "new seal and anchor did not survive reopening");
    }

    #[test]
    fn migration_refuses_database_edits_before_altering_the_schema() {
        let (mut atm, _) = bank();
        make_version6(&mut atm);
        atm.conn.execute("UPDATE staff SET failed_attempts = 0 WHERE role = 'admin'", []).unwrap();
        // Make an actual changed value, rather than a no-op update.
        atm.conn.execute("UPDATE staff SET failed_attempts = 19 WHERE role = 'admin'", []).unwrap();
        assert!(matches!(migrate_staff(&mut atm), Err(AtmError::DatabaseAltered)));
        let version: String = atm
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'schema_version'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, "6");
    }
}
