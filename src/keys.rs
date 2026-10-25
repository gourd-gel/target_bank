//! The machine's secret key, kept in a file *outside* the database.
//!
//! Why: a stolen `atm.db` alone should be useless. Sub-keys derived from it:
//!   * PIN pepper: keyed PIN hashes, so offline guessing needs this file; each hash is also
//!     keyed to its owner, so it can't move to another card, account or staff role
//!     (STRIDE: Spoofing / Info Disclosure).
//!   * Audit MAC key: the log chain can't be recomputed by a DB editor (STRIDE: Tampering /
//!     Repudiation).
//!   * Field key: names and birth dates are AES-256-GCM encrypted; GCM also detects edits
//!     (STRIDE: Info Disclosure).
//!   * Record MAC key: settings (limits, fee) and exchange rates carry an HMAC (STRIDE:
//!     Tampering).
//!   * Lookup key: card and account numbers are found by an HMAC of the number, which can't
//!     be reversed without this key (STRIDE: Info Disclosure).
//!   * Fingerprint: proves this key belongs to the DB, so a wrong key file is a clear error.
//!   * Seal key: one HMAC over the whole database (seal.rs).
//!   * Anchor key: tags the anchor file that remembers the newest seal (anchor.rs).
//!
//! Limit: whoever steals BOTH files (or the running machine) has everything.
//! In a real deployment the key would live in an HSM / OS keystore.

use crate::error::{AtmError, Result};
use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Sub-keys derived from the master key. No Debug: can't be printed by accident.
pub struct Keys {
    master: [u8; KEY_LEN],
    pepper: [u8; 32],
    audit_mac: [u8; 32],
    field: [u8; 32],
    record_mac: [u8; 32],
    lookup: [u8; 32],
    seal: [u8; 32],
    anchor: [u8; 32],
}

static KEYS: OnceLock<Keys> = OnceLock::new();

/// Derive a purpose-specific sub-key (HMAC as a KDF).
fn derive(master: &[u8; KEY_LEN], label: &str) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(master)
        .map_err(|_| AtmError::Internal("bad key length".into()))?;
    mac.update(label.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Derive every sub-key from the master key and store them for this process.
fn install(master: &[u8; KEY_LEN]) -> Result<()> {
    let keys = Keys {
        pepper: derive(master, "bank-of-ccny/pin-pepper/v1")?,
        audit_mac: derive(master, "bank-of-ccny/audit-mac/v1")?,
        field: derive(master, "bank-of-ccny/field-encryption/v1")?,
        record_mac: derive(master, "bank-of-ccny/record-mac/v1")?,
        lookup: derive(master, "bank-of-ccny/number-lookup/v1")?,
        seal: derive(master, "bank-of-ccny/database-seal/v1")?,
        anchor: derive(master, "bank-of-ccny/anchor/v1")?,
        master: *master,
    };
    let stored = KEYS.get_or_init(|| keys);
    // A second load in the same process must be the same key.
    if stored.master != *master {
        return Err(AtmError::Internal("a different key is already loaded".into()));
    }
    Ok(())
}

/// Load the key file, or create it on a brand-new install.
/// Fails closed if a database exists but its key is missing.
pub fn load_or_create(path: &Path, db_exists: bool) -> Result<()> {
    if path.exists() {
        // Zeroizing: the raw key bytes are wiped from memory when dropped.
        let bytes = Zeroizing::new(fs::read(path).map_err(|e| AtmError::Internal(format!("read key: {e}")))?);
        let master: &[u8; KEY_LEN] =
            bytes.as_slice().try_into().map_err(|_| AtmError::NotAllowed("the key file is damaged"))?;
        restrict_permissions(path)?;
        return install(master);
    }
    if db_exists {
        return Err(AtmError::NotAllowed("the key file is missing, so this database cannot be used"));
    }
    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(&mut *master).map_err(|_| AtmError::Internal("no system randomness".into()))?;
    // create_new: never overwrite an existing key.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| AtmError::Internal(format!("create key: {e}")))?;
    restrict_permissions(path)?;
    file.write_all(&*master).map_err(|e| AtmError::Internal(format!("write key: {e}")))?;
    file.sync_all().map_err(|e| AtmError::Internal(format!("sync key: {e}")))?;
    install(&master)
}

/// Owner read/write only (Unix). Other systems keep their default permissions.
pub(crate) fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| AtmError::Internal(format!("chmod: {e}")))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The loaded keys; an error if no key file has been loaded yet.
fn get() -> Result<&'static Keys> {
    #[cfg(test)]
    test_init();
    KEYS.get().ok_or_else(|| AtmError::Internal("key not loaded".into()))
}

/// Hashing key for ONE identity (a card on its account in its role, or a staff login in its
/// role), from the pepper. STRIDE (Spoofing / Elevation of Privilege): a hash copied to another
/// card, a card pointed at another account, or a handler row made admin no longer verifies.
pub(crate) fn credential_key(identity: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mac = keyed(&get()?.pepper, &[b"credential/v1", identity.as_bytes()])?;
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

/// Key for the audit-log HMAC chain.
pub(crate) fn audit_mac_key() -> Result<&'static [u8]> {
    Ok(&get()?.audit_mac)
}

/// HMAC (hex) over a record's fields, for settings and exchange-rate rows.
/// Fields are length-prefixed so "ab"+"c" != "a"+"bc".
pub(crate) fn record_mac(fields: &[&str]) -> Result<String> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&get()?.record_mac)
        .map_err(|_| AtmError::Internal("bad MAC key".into()))?;
    for field in fields {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field.as_bytes());
    }
    Ok(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect())
}

/// HMAC-SHA-256 over length-prefixed fields ("ab"+"c" != "a"+"bc").
fn keyed(key: &[u8], fields: &[&[u8]]) -> Result<Hmac<Sha256>> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|_| AtmError::Internal("bad MAC key".into()))?;
    for field in fields {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field);
    }
    Ok(mac)
}

/// Bytes as lowercase hex text.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex text back to bytes; None if it isn't hex.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

/// Constant-time check of a stored hex MAC (no early exit on the first wrong byte).
fn matches(mac: Hmac<Sha256>, stored_hex: &str) -> bool {
    unhex(stored_hex).is_some_and(|bytes| mac.verify_slice(&bytes).is_ok())
}

/// Constant-time comparison of a stored MAC (hex text) with the expected one.
/// Every character is compared, so the time taken can't guide someone
/// guessing a MAC one character at a time (SEv3 §3.4.8.3).
pub(crate) fn same_mac(stored: &str, expected: &str) -> bool {
    let (a, b) = (stored.as_bytes(), expected.as_bytes());
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0 && a.len() == b.len()
}

/// The database seal (hex): HMAC over the change counter and a digest of every table.
pub(crate) fn seal_mac(counter: i64, digest: &[u8]) -> Result<String> {
    let mac = keyed(&get()?.seal, &[b"seal/v1", &counter.to_le_bytes(), digest])?;
    Ok(hex(&mac.finalize().into_bytes()))
}

/// True if `stored` is the right seal for this counter and digest.
pub(crate) fn seal_matches(counter: i64, digest: &[u8], stored: &str) -> Result<bool> {
    Ok(matches(keyed(&get()?.seal, &[b"seal/v1", &counter.to_le_bytes(), digest])?, stored))
}

/// Tag (hex) for one anchor line: the newest seal counter and MAC.
pub(crate) fn anchor_tag(counter: i64, seal: &str) -> Result<String> {
    let mac = keyed(&get()?.anchor, &[b"anchor/v1", &counter.to_le_bytes(), seal.as_bytes()])?;
    Ok(hex(&mac.finalize().into_bytes()))
}

/// True if `stored` is the right tag for this anchor line.
pub(crate) fn anchor_tag_matches(counter: i64, seal: &str, stored: &str) -> Result<bool> {
    Ok(matches(keyed(&get()?.anchor, &[b"anchor/v1", &counter.to_le_bytes(), seal.as_bytes()])?, stored))
}

/// Keyed lookup value (hex) for a card or account number, stored instead of the number.
/// Plain SHA-256 could be reversed by trying all 10^10 numbers. `kind` keeps card and
/// account lookups apart.
pub(crate) fn lookup_hash(kind: &str, number: &str) -> Result<String> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&get()?.lookup)
        .map_err(|_| AtmError::Internal("bad MAC key".into()))?;
    for field in [kind, number] {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field.as_bytes());
    }
    Ok(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect())
}

/// Hex value stored in the DB at creation; must match on every later open.
pub(crate) fn fingerprint() -> Result<String> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(audit_mac_key()?)
        .map_err(|_| AtmError::Internal("bad MAC key".into()))?;
    mac.update(b"bank-of-ccny/key-fingerprint/v1");
    Ok(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect())
}

/// Associated data: binds a ciphertext to its column and row, so an attacker
/// can't swap one customer's encrypted name or DOB into another row.
fn aad(column: &str, row: &str) -> Vec<u8> {
    [column.as_bytes(), b"\0", row.as_bytes()].concat()
}

/// Encrypt one field (AES-256-GCM, random nonce). Stored as nonce || ciphertext+tag.
pub(crate) fn seal(column: &str, row: &str, plaintext: &str) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(&get()?.field).map_err(|_| AtmError::Internal("bad field key".into()))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| AtmError::Internal("no system randomness".into()))?;
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext.as_bytes(), aad: &aad(column, row) })
        .map_err(|_| AtmError::Internal("encryption failed".into()))?;
    Ok([nonce.as_slice(), &sealed].concat())
}

/// Decrypt one field. Any edit to the stored bytes (or a row swap) fails here.
pub(crate) fn unseal(column: &str, row: &str, stored: &[u8]) -> Result<String> {
    let cipher =
        Aes256Gcm::new_from_slice(&get()?.field).map_err(|_| AtmError::Internal("bad field key".into()))?;
    if stored.len() < NONCE_LEN {
        return Err(AtmError::NotAllowed("stored customer data has been altered"));
    }
    let (nonce, sealed) = stored.split_at(NONCE_LEN);
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad: &aad(column, row) })
        .map_err(|_| AtmError::NotAllowed("stored customer data has been altered"))?;
    String::from_utf8(plain).map_err(|_| AtmError::Internal("bad field encoding".into()))
}

/// Tests share one fixed key.
#[cfg(test)]
pub(crate) fn test_init() {
    let _ = install(&[7u8; KEY_LEN]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_macs_are_compared_in_full() {
        let mac = record_mac(&["withdrawal_limit", "100000"]).unwrap();
        assert!(same_mac(&mac, &mac.clone()));
        // A wrong first or last character, or a cut-off copy, never matches.
        let flip = |i: usize| {
            let mut b = mac.clone().into_bytes();
            b[i] = if b[i] == b'0' { b'1' } else { b'0' };
            String::from_utf8(b).unwrap()
        };
        assert!(!same_mac(&flip(0), &mac));
        assert!(!same_mac(&flip(mac.len() - 1), &mac));
        assert!(!same_mac(&mac[..mac.len() - 2], &mac));
        assert!(!same_mac("", &mac));
    }

    #[test]
    fn fields_round_trip_and_resist_edits_and_swaps() {
        let sealed = seal("name", "1111111111", "Ann Lee").unwrap();
        assert!(!sealed.windows(3).any(|w| w == b"Ann"), "name must not be stored in the clear");
        assert_eq!(unseal("name", "1111111111", &sealed).unwrap(), "Ann Lee");
        // Same text twice -> different bytes (random nonce).
        assert_ne!(sealed, seal("name", "1111111111", "Ann Lee").unwrap());
        // Moved to another row or column: refused.
        assert!(unseal("name", "2222222222", &sealed).is_err());
        assert!(unseal("dob", "1111111111", &sealed).is_err());
        // One flipped bit: refused.
        let mut edited = sealed.clone();
        edited[NONCE_LEN] ^= 1;
        assert!(unseal("name", "1111111111", &edited).is_err());
    }
}
