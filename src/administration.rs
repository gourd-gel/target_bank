//! Encrypted administrative audit. Only Authorities sessions can read its events.
//!
//! ```compile_fail,E0308
//! fn read(bank: &atm::Atm, teller: &atm::auth::AdminSession) {
//!     atm::administration::recent(bank, teller, 0);
//! }
//! ```
use crate::{
    Atm, audit,
    auth::AuthoritiesSession,
    error::{AtmError, Result},
    keys,
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CHECKPOINT: &str = "administrative-audit-head/v1";
const SCHEMA: &str = "CREATE TABLE administration.store_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE administration.events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, payload BLOB NOT NULL, prev_mac TEXT NOT NULL, mac TEXT NOT NULL
) STRICT;
CREATE TRIGGER administration.events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'administrative audit is append-only'); END;
CREATE TRIGGER administration.events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'administrative audit is append-only'); END;";

#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub outcome: String,
    pub details: String,
}
#[derive(Debug, Serialize)]
pub struct Row {
    pub reference: i64,
    pub event: Event,
}
#[derive(Serialize, Deserialize)]
struct Head {
    seq: i64,
    mac: String,
}

pub fn database_path(bank: &Path) -> PathBuf {
    bank.with_extension("admin-audit.db")
}
fn key_path(bank: &Path) -> PathBuf {
    bank.with_extension("admin-audit.key")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn tag(key: &[u8], fields: &[&[u8]]) -> Result<String> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
        .map_err(|_| AtmError::Internal("administrative audit key".into()))?;
    for field in fields {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field);
    }
    Ok(hex(&mac.finalize().into_bytes()))
}
fn derive(key: &[u8], purpose: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
        .map_err(|_| AtmError::Internal("administrative audit key".into()))?;
    mac.update(purpose);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(
        fs::read(path)
            .map_err(|_| AtmError::NotAllowed("administrative audit key is missing or unreadable"))?,
    );
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AtmError::NotAllowed("administrative audit key is damaged"))?;
    keys::restrict_permissions(path)?;
    Ok(Zeroizing::new(key))
}
fn provision_key(path: &Path, existing: bool) -> Result<()> {
    if path.exists() {
        read_key(path)?;
        return Ok(());
    }
    if existing {
        return Err(AtmError::NotAllowed("administrative audit key is missing; restore the matching key"));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key).map_err(|_| AtmError::Internal("no system randomness".into()))?;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| AtmError::Internal(format!("create administrative audit key: {e}")))?;
    file.write_all(&*key).and_then(|_| file.sync_all()).map_err(|e| AtmError::Internal(e.to_string()))?;
    Ok(())
}
fn store_key(conn: &Connection) -> Result<Zeroizing<[u8; 32]>> {
    let mut stmt = conn.prepare("PRAGMA database_list")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == "administration" {
            let path: String = row.get(2)?;
            if !path.is_empty() {
                return read_key(&Path::new(&path).with_extension("key"));
            }
            #[cfg(test)]
            {
                static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
                let key = KEY.get_or_init(|| {
                    let mut key = [0u8; 32];
                    getrandom::fill(&mut key).unwrap();
                    key
                });
                return Ok(Zeroizing::new(*key));
            }
        }
    }
    Err(AtmError::NotAllowed("administrative audit is not attached"))
}
fn schema_mac(conn: &Connection, key: &[u8]) -> Result<String> {
    let mut stmt = conn.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql,'') FROM administration.sqlite_schema ORDER BY type, name",
    )?;
    let mut rows = stmt.query([])?;
    let mut hash = Sha256::new();
    while let Some(row) = rows.next()? {
        for column in 0..4 {
            let s: String = row.get(column)?;
            hash.update((s.len() as u64).to_le_bytes());
            hash.update(s.as_bytes());
        }
    }
    tag(key, &[b"admin-audit/schema/v1", &hash.finalize()])
}
fn head(conn: &Connection) -> Result<Head> {
    Ok(conn
        .query_row("SELECT seq, mac FROM administration.events ORDER BY seq DESC LIMIT 1", [], |r| {
            Ok(Head { seq: r.get(0)?, mac: r.get(1)? })
        })
        .optional()?
        .unwrap_or(Head { seq: 0, mac: GENESIS.into() }))
}
fn attach_store(conn: &Connection, bank: Option<&Path>, required: bool) -> Result<()> {
    let path = bank.map(database_path);
    let existed = path.as_ref().is_some_and(|path| path.exists());
    if let Some(bank) = bank {
        if required && !database_path(bank).is_file() {
            return Err(AtmError::NotAllowed(
                "administrative audit database is missing; restore its matching backup",
            ));
        }
        let existing = database_path(bank).exists();
        provision_key(&key_path(bank), existing)?;
    }
    conn.execute(
        "ATTACH DATABASE ?1 AS administration",
        [path.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or(":memory:".into())],
    )?;
    if let Some(path) = path {
        keys::restrict_permissions(&path)?;
    }
    conn.execute_batch("PRAGMA administration.journal_mode = DELETE; PRAGMA administration.synchronous = FULL; PRAGMA busy_timeout = 5000; PRAGMA trusted_schema = OFF;")?;
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM administration.sqlite_schema WHERE name = 'events')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM administration.sqlite_schema", [], |r| r.get(0))?;
        if count != 0 || required || existed {
            return Err(AtmError::DatabaseAltered);
        }
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(SCHEMA)?;
        let key = store_key(&tx)?;
        tx.execute(
            "INSERT INTO administration.store_meta VALUES ('schema_mac', ?1)",
            [schema_mac(&tx, &key[..])?],
        )?;
        tx.commit()?;
    }
    check_store(conn)
}

pub(crate) fn attach(conn: &Connection, bank: Option<&Path>) -> Result<()> {
    let required: bool =
        conn.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE key = ?1)", [CHECKPOINT], |r| r.get(0))?;
    attach_store(conn, bank, required)?;
    check(conn)
}
fn check_store(conn: &Connection) -> Result<()> {
    let structure: String = conn.query_row("PRAGMA administration.integrity_check(1)", [], |r| r.get(0))?;
    if structure != "ok" {
        return Err(AtmError::DatabaseAltered);
    }
    let key = store_key(conn)?;
    let schema: String =
        conn.query_row("SELECT value FROM administration.store_meta WHERE key = 'schema_mac'", [], |r| {
            r.get(0)
        })?;
    if !keys::same_mac(&schema, &schema_mac(conn, &key[..])?) {
        return Err(AtmError::DatabaseAltered);
    }
    let authentication = derive(&key[..], b"admin-audit/authentication/v1")?;
    let mut stmt =
        conn.prepare("SELECT seq, payload, prev_mac, mac FROM administration.events ORDER BY seq")?;
    let mut rows = stmt.query([])?;
    let mut expected = GENESIS.to_string();
    let mut last = 0;
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let payload: Vec<u8> = row.get(1)?;
        let prev: String = row.get(2)?;
        let mac: String = row.get(3)?;
        let actual = tag(
            &authentication[..],
            &[b"admin-audit/event/v1", &seq.to_le_bytes(), &payload, prev.as_bytes()],
        )?;
        if seq != last + 1 || !keys::same_mac(&prev, &expected) || !keys::same_mac(&mac, &actual) {
            return Err(AtmError::DatabaseAltered);
        }
        last = seq;
        expected = mac;
    }
    let highest: Option<i64> = conn
        .query_row("SELECT seq FROM administration.sqlite_sequence WHERE name = 'events'", [], |r| r.get(0))
        .optional()?;
    if highest.unwrap_or(0) != last {
        return Err(AtmError::DatabaseAltered);
    }
    Ok(())
}
pub(crate) fn check(conn: &Connection) -> Result<()> {
    check_store(conn)?;
    let checkpoint: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [CHECKPOINT], |r| r.get(0)).optional()?;
    if let Some(checkpoint) = checkpoint {
        let checkpoint: Head = serde_json::from_str(&checkpoint).map_err(|_| AtmError::DatabaseAltered)?;
        if checkpoint.seq > 0 {
            let mac: Option<String> = conn
                .query_row("SELECT mac FROM administration.events WHERE seq = ?1", [checkpoint.seq], |r| {
                    r.get(0)
                })
                .optional()?;
            if !mac.is_some_and(|mac| keys::same_mac(&mac, &checkpoint.mac)) {
                return Err(AtmError::RolledBack);
            }
        }
    }
    Ok(())
}
pub(crate) fn checkpoint(conn: &Connection) -> Result<()> {
    let value = serde_json::to_string(&head(conn)?).map_err(|e| AtmError::Internal(e.to_string()))?;
    conn.execute(
        "INSERT INTO meta(key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![CHECKPOINT, value],
    )?;
    Ok(())
}
pub(crate) fn append(
    conn: &Connection,
    actor: &str,
    action: &str,
    outcome: &str,
    details: &str,
) -> Result<()> {
    let key = store_key(conn)?;
    let encryption = derive(&key[..], b"admin-audit/encryption/v1")?;
    let authentication = derive(&key[..], b"admin-audit/authentication/v1")?;
    let previous = head(conn)?;
    let next =
        previous.seq.checked_add(1).ok_or(AtmError::Internal("administrative audit exhausted".into()))?;
    let event = Event {
        timestamp: audit::now_utc(),
        actor: actor.into(),
        action: action.into(),
        outcome: outcome.into(),
        details: details.into(),
    };
    let plain = Zeroizing::new(serde_json::to_vec(&event).map_err(|e| AtmError::Internal(e.to_string()))?);
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| AtmError::Internal("no system randomness".into()))?;
    let cipher = Aes256Gcm::new_from_slice(&encryption[..])
        .map_err(|_| AtmError::Internal("administrative audit encryption key".into()))?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: &next.to_le_bytes() })
        .map_err(|_| AtmError::Internal("administrative audit encryption".into()))?;
    let payload = [nonce.as_slice(), encrypted.as_slice()].concat();
    let mac = tag(
        &authentication[..],
        &[b"admin-audit/event/v1", &next.to_le_bytes(), &payload, previous.mac.as_bytes()],
    )?;
    conn.execute(
        "INSERT INTO administration.events(seq,payload,prev_mac,mac) VALUES (?1,?2,?3,?4)",
        params![next, payload, previous.mac, mac],
    )?;
    Ok(())
}

pub(crate) fn access(atm: &Atm, session: &AuthoritiesSession, action: &str, details: &str) -> Result<()> {
    {
        let view = atm.read()?;
        atm.admit(session)?;
        drop(view);
    }
    let tx = Transaction::new_unchecked(&atm.conn, TransactionBehavior::Immediate)?;
    check(&tx)?;
    atm.admit(session)?;
    append(&tx, &session.actor(), action, "requested", details)?;
    tx.commit()?;
    Ok(())
}

pub fn recent(atm: &Atm, session: &AuthoritiesSession, page: u32) -> Result<Vec<Row>> {
    access(atm, session, "administrative_audit_view", &format!("page={page}"))?;
    let conn = atm.read()?;
    atm.admit(session)?;
    let key = store_key(&conn)?;
    let encryption = derive(&key[..], b"admin-audit/encryption/v1")?;
    let cipher = Aes256Gcm::new_from_slice(&encryption[..])
        .map_err(|_| AtmError::Internal("administrative audit encryption key".into()))?;
    let mut stmt =
        conn.prepare("SELECT seq,payload FROM administration.events ORDER BY seq DESC LIMIT 20 OFFSET ?1")?;
    let mut rows = stmt.query([i64::from(page) * 20])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let payload: Vec<u8> = row.get(1)?;
        if payload.len() < 12 {
            return Err(AtmError::DatabaseAltered);
        }
        let clear = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&payload[..12]),
                    Payload { msg: &payload[12..], aad: &seq.to_le_bytes() },
                )
                .map_err(|_| AtmError::DatabaseAltered)?,
        );
        let event = serde_json::from_slice(&clear).map_err(|_| AtmError::DatabaseAltered)?;
        out.push(Row { reference: seq, event });
    }
    Ok(out)
}

#[cfg(feature = "programmer-tools")]
pub fn programmer_event(bank: &Path, action: &str, outcome: &str, details: &str) -> Result<()> {
    let conn = Connection::open_in_memory()?;
    attach_store(&conn, Some(bank), false)?;
    let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)?;
    check_store(&tx)?;
    append(&tx, "programmer", action, outcome, details)?;
    tx.commit()?;
    Ok(())
}

#[cfg(feature = "programmer-tools")]
pub(crate) fn programmer_action(
    directory: &Path,
    action: &str,
    authorized: Result<()>,
    operation: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let bank = directory.join("atm.db");
    programmer_event(
        &bank,
        action,
        if authorized.is_ok() { "authenticated" } else { "authentication_failed" },
        "",
    )?;
    authorized?;
    let result = operation();
    let logged = programmer_event(&bank, action, if result.is_ok() { "succeeded" } else { "failed" }, "");
    match (result, logged) {
        (Ok(()), Err(_)) => Err(AtmError::NotAllowed(
            "configuration saved, but administrative audit completion could not be written",
        )),
        (result, _) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;

    #[test]
    fn encrypted_events_are_readable_only_with_a_live_authorities_session() {
        let mut bank = Atm::in_memory().unwrap();
        auth::testing::setup(&mut bank);
        let tx = bank.begin().unwrap();
        append(&tx, "programmer", "private_maintenance", "succeeded", "sensitive maintenance detail")
            .unwrap();
        tx.commit().unwrap();
        let payload: Vec<u8> = bank
            .conn
            .query_row("SELECT payload FROM administration.events ORDER BY seq LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(!payload.windows(b"programmer".len()).any(|bytes| bytes == b"programmer"));
        assert!(
            !payload
                .windows(b"sensitive maintenance detail".len())
                .any(|bytes| bytes == b"sensitive maintenance detail")
        );
        let authority = auth::testing::authorities(&bank);
        assert!(
            recent(&bank, &authority, 0).unwrap().iter().any(|r| r.event.action == "private_maintenance"
                && r.event.details == "sensitive maintenance detail")
        );
        authority.end();
        assert!(matches!(recent(&bank, &authority, 0), Err(AtmError::SessionExpired)));
        let authority = auth::testing::authorities(&bank);
        let mut other = Atm::in_memory().unwrap();
        auth::testing::setup(&mut other);
        assert!(matches!(recent(&other, &authority, 0), Err(AtmError::SessionExpired)));
    }

    #[test]
    fn administrative_records_are_append_only_and_schema_tampering_is_rejected() {
        let mut bank = Atm::in_memory().unwrap();
        auth::testing::setup(&mut bank);
        let tx = bank.begin().unwrap();
        append(&tx, "programmer", "test", "succeeded", "").unwrap();
        tx.commit().unwrap();
        assert!(bank.conn.execute("DELETE FROM administration.events", []).is_err());
        assert!(bank.conn.execute("UPDATE administration.events SET payload=x'00'", []).is_err());
        bank.conn.execute_batch("DROP TRIGGER administration.events_no_update").unwrap();
        let authority = auth::testing::authorities(&bank);
        assert!(matches!(recent(&bank, &authority, 0), Err(AtmError::DatabaseAltered)));
    }

    #[test]
    fn administrative_events_roll_back_with_the_bank_transaction() {
        let mut bank = Atm::in_memory().unwrap();
        auth::testing::setup(&mut bank);
        let before = head(&bank.conn).unwrap().seq;
        {
            let tx = bank.begin().unwrap();
            tx.execute("UPDATE staff SET failed_attempts = 2 WHERE role='authorities'", []).unwrap();
            append(&tx, "authorities:bank authorities", "sign_in", "failed", "").unwrap();
            // Simulate a failure before commit.
        }
        assert_eq!(head(&bank.conn).unwrap().seq, before);
        assert_eq!(
            bank.conn
                .query_row("SELECT failed_attempts FROM staff WHERE role='authorities'", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        check(&bank.conn).unwrap();
    }
}
