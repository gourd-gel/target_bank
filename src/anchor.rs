//! The anchor file (`atm.anchor`, next to `atm.db`): the newest seal.
//!
//! STRIDE (Tampering / Repudiation): the database seal (seal.rs) carries a
//! counter that goes up with every change. This file remembers the highest
//! one this machine has written. An older copy of `atm.db` put back (to undo
//! a withdrawal or a lock-out) has a lower counter and is refused. The line
//! is HMAC-tagged, so it can't be edited to match an old copy either.
//!
//! Known limit: an older copy of BOTH `atm.db` and `atm.anchor` still matches.
//! A real bank keeps the anchor on another machine or write-once storage.

use crate::error::{AtmError, Result};
use crate::keys;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const HEADER: &str = "bank-of-ccny anchor v1";

pub(crate) struct Anchor {
    path: PathBuf,
}

impl Anchor {
    /// The anchor that belongs to a database file: same name, `.anchor`.
    pub(crate) fn for_db(db_path: &Path) -> Anchor {
        Anchor { path: db_path.with_extension("anchor") }
    }

    /// True if the anchor file is on disk.
    pub(crate) fn exists(&self) -> bool {
        self.path.exists()
    }

    /// The recorded (counter, seal MAC). An edited or damaged file is refused.
    pub(crate) fn read(&self) -> Result<(i64, String)> {
        let bad =
            || AtmError::NotAllowed("the anchor file has been altered, so this database cannot be trusted");
        let text = fs::read_to_string(&self.path).map_err(|_| {
            AtmError::NotAllowed("the anchor file is missing, so this database cannot be trusted")
        })?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(bad());
        }
        let fields: Vec<&str> = lines.next().unwrap_or("").split(' ').collect();
        let [counter, seal, tag] = fields.as_slice() else { return Err(bad()) };
        let counter: i64 = counter.parse().map_err(|_| bad())?;
        if !keys::anchor_tag_matches(counter, seal, tag)? {
            return Err(bad());
        }
        Ok((counter, seal.to_string()))
    }

    /// Record a newer seal. Never moves backward: if the file already holds a
    /// higher counter (another program on the same bank), it is left alone.
    pub(crate) fn advance(&self, counter: i64, seal: &str) -> Result<()> {
        if self.exists() && self.read().is_ok_and(|(have, _)| have >= counter) {
            return Ok(());
        }
        let line = format!("{HEADER}\n{counter} {seal} {}\n", keys::anchor_tag(counter, seal)?);
        // Write a temporary file, then rename: a crash never leaves half a line.
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| AtmError::Internal("no system randomness".into()))?;
        let tmp = self.path.with_extension(format!("anchor-{:016x}", u64::from_le_bytes(nonce)));
        let write = || -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            file.write_all(line.as_bytes())?;
            file.sync_all()
        };
        write().map_err(|e| AtmError::Internal(format!("write anchor: {e}")))?;
        keys::restrict_permissions(&tmp)?;
        fs::rename(&tmp, &self.path).map_err(|e| AtmError::Internal(format!("replace anchor: {e}")))?;
        Ok(())
    }
}
