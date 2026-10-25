//! The database seal: one HMAC over everything the bank keeps.
//!
//! STRIDE (Tampering): seal = HMAC(key, counter + SHA-256 of every row and the schema),
//! rewritten inside every committing transaction and checked before every operation. Any edit
//! to `atm.db` made outside the ATM (a balance, a lock flag, a PIN hash, a staff row, a log
//! line) is refused. SQLite's `integrity_check` runs first, since index pages aren't rows.
//! The counter rises once per commit; the anchor file (anchor.rs) keeps the newest, so an
//! older copy put back is refused too. Fail closed. Cost: a full read per operation (ms).

use crate::error::{AtmError, Result};
use crate::keys;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

/// Everything that is sealed, in a fixed order. Fixed SQL (no `format!`).
/// rowid is included so rows can't be swapped or renumbered.
const DUMP: [&str; 12] = [
    "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name",
    "SELECT name, seq FROM sqlite_sequence ORDER BY name",
    "SELECT rowid, * FROM meta ORDER BY rowid",
    "SELECT rowid, * FROM staff ORDER BY rowid",
    "SELECT rowid, * FROM accounts ORDER BY rowid",
    "SELECT rowid, * FROM cards ORDER BY rowid",
    "SELECT rowid, * FROM guardians ORDER BY rowid",
    "SELECT rowid, * FROM settings ORDER BY rowid",
    "SELECT rowid, * FROM exchange_rates ORDER BY rowid",
    "SELECT rowid, * FROM rate_history ORDER BY rowid",
    "SELECT rowid, * FROM cash_inventory ORDER BY rowid",
    "SELECT rowid, * FROM audit_log ORDER BY rowid",
];

/// SHA-256 over every sealed row. Each value is typed and length-prefixed,
/// so no two different databases give the same byte stream.
fn digest(conn: &Connection) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    for (i, sql) in DUMP.iter().enumerate() {
        hash.update((i as u64).to_le_bytes());
        let mut stmt = conn.prepare(sql)?;
        let columns = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            hash.update(b"R");
            for c in 0..columns {
                let (tag, bytes): (u8, Vec<u8>) = match row.get_ref(c)? {
                    ValueRef::Null => (b'N', Vec::new()),
                    ValueRef::Integer(n) => (b'I', n.to_le_bytes().to_vec()),
                    ValueRef::Real(x) => (b'F', x.to_le_bytes().to_vec()),
                    ValueRef::Text(t) => (b'T', t.to_vec()),
                    ValueRef::Blob(b) => (b'B', b.to_vec()),
                };
                hash.update([tag]);
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(&bytes);
            }
        }
    }
    Ok(hash.finalize().into())
}

/// Check the seal; returns its counter. Missing or wrong = altered outside the ATM.
pub(crate) fn check(conn: &Connection) -> Result<i64> {
    // The digest reads table rows, not index pages. SQLite's own check
    // confirms every index matches its table, so an index edited in the
    // file can't steer a lookup (say, hide today's withdrawals).
    let structure: String = conn.query_row("PRAGMA integrity_check(1)", [], |r| r.get(0)).unwrap_or_default();
    if structure != "ok" {
        return Err(AtmError::DatabaseAltered);
    }
    let stored: Option<(i64, String)> = conn
        .query_row("SELECT counter, mac FROM seal WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let (counter, mac) = stored.ok_or(AtmError::DatabaseAltered)?;
    if !keys::seal_matches(counter, &digest(conn)?, &mac)? {
        return Err(AtmError::DatabaseAltered);
    }
    Ok(counter)
}

/// Seal the database as it is now (inside the caller's transaction). Returns the MAC.
pub(crate) fn write(conn: &Connection, counter: i64) -> Result<String> {
    let mac = keys::seal_mac(counter, &digest(conn)?)?;
    conn.execute(
        "INSERT INTO seal (id, counter, mac) VALUES (1, ?1, ?2)
         ON CONFLICT (id) DO UPDATE SET counter = excluded.counter, mac = excluded.mac",
        params![counter, mac],
    )?;
    Ok(mac)
}

/// The stored seal (counter, MAC), for the anchor file.
pub(crate) fn current(conn: &Connection) -> Result<(i64, String)> {
    conn.query_row("SELECT counter, mac FROM seal WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or(AtmError::DatabaseAltered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_edit_breaks_the_seal_and_a_reseal_fixes_it() {
        let atm = crate::Atm::in_memory().unwrap();
        let n = check(&atm).unwrap();
        // One flipped value anywhere is caught: a setting, cash, the schema.
        for sql in [
            "UPDATE cash_inventory SET bill_count = 5 WHERE denomination = 20",
            "UPDATE settings SET mac = 'x' WHERE key = 'daily_withdrawal_limit_cents'",
            "DROP TRIGGER audit_no_delete",
        ] {
            atm.execute_batch(sql).unwrap();
            assert!(matches!(check(&atm), Err(AtmError::DatabaseAltered)), "{sql}");
            write(&atm, n).unwrap();
            assert_eq!(check(&atm).unwrap(), n);
        }
        // The seal row itself: a different counter or MAC is refused.
        atm.execute("UPDATE seal SET counter = counter + 1", []).unwrap();
        assert!(matches!(check(&atm), Err(AtmError::DatabaseAltered)));
        atm.execute("DELETE FROM seal", []).unwrap();
        assert!(matches!(check(&atm), Err(AtmError::DatabaseAltered)));
    }
}
