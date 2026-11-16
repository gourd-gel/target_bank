//! Per-installation ATM identity and a programmer-configured location for alerts.
use crate::Atm;
use crate::audit::{self, Action, Entry};
use crate::error::{AtmError, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const LOCATION_CONFIG_FILE: &str = "atm-location.txt";
const META_KEY: &str = "atm-origin/v1";

#[derive(Serialize, Deserialize)]
struct StoredOrigin {
    id: String,
    location: Option<String>,
}

pub(crate) struct Origin {
    pub id: String,
    pub location: String,
}

fn validate_location(location: &str) -> Result<&str> {
    let location = location.trim();
    if location.is_empty() || location.chars().count() > 240 || location.chars().any(char::is_control) {
        return Err(AtmError::InvalidInput("ATM location must be 1 to 240 characters on one line"));
    }
    Ok(location)
}

fn config_path(conn: &Connection, bank_id: u64) -> PathBuf {
    match conn.path().filter(|p| !p.is_empty()) {
        Some(path) => Path::new(path).parent().unwrap_or(Path::new(".")).join(LOCATION_CONFIG_FILE),
        None => std::env::temp_dir().join(format!("atm-phone-codes-{bank_id}")).join(LOCATION_CONFIG_FILE),
    }
}

fn save(conn: &Connection, origin: &StoredOrigin) -> Result<()> {
    let value =
        serde_json::to_string(origin).map_err(|_| AtmError::Internal("ATM identity encoding".into()))?;
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![META_KEY, value],
    )?;
    Ok(())
}

/// Run inside a sealed transaction. Refresh location without changing the stable ID.
pub(crate) fn origin(conn: &Connection, bank_id: u64) -> Result<Origin> {
    let stored: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [META_KEY], |r| r.get(0)).optional()?;
    let mut origin = if let Some(value) = stored {
        let value: StoredOrigin =
            serde_json::from_str(&value).map_err(|_| AtmError::RecordTampered("ATM identity"))?;
        if value.id.len() != 32
            || !value.id.bytes().all(|b| b.is_ascii_hexdigit())
            || value.location.as_deref().is_some_and(|l| validate_location(l).is_err())
        {
            return Err(AtmError::RecordTampered("ATM identity"));
        }
        value
    } else {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| AtmError::Internal("no system randomness".into()))?;
        let value = StoredOrigin { id: bytes.iter().map(|b| format!("{b:02x}")).collect(), location: None };
        save(conn, &value)?;
        value
    };
    let location = match std::fs::read_to_string(config_path(conn, bank_id)) {
        Ok(location) => Some(validate_location(&location)?.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(AtmError::NotAllowed("could not read atm-location.txt")),
    };
    if let Some(location) = location {
        if origin.location.as_deref() != Some(&location) {
            origin.location = Some(location);
            save(conn, &origin)?;
            if crate::db::is_initialized(conn)? {
                audit::append(
                    conn,
                    &Entry {
                        actor: "programmer",
                        action: Action::ControlsChanged,
                        account_id: None,
                        counterparty_id: None,
                        amount: None,
                        usd: None,
                        detail: &format!(
                            "ATM {} location configured: {}",
                            origin.id,
                            origin.location.as_deref().unwrap_or("")
                        ),
                    },
                )?;
            }
        }
    }
    Ok(Origin { id: origin.id, location: origin.location.unwrap_or_else(|| "Not configured".into()) })
}

pub(crate) fn initialize(atm: &mut Atm) -> Result<()> {
    let bank_id = atm.id;
    let tx = atm.begin()?;
    let before: Option<String> =
        tx.query_row("SELECT value FROM meta WHERE key = ?1", [META_KEY], |r| r.get(0)).optional()?;
    origin(&tx, bank_id)?;
    let after: String = tx.query_row("SELECT value FROM meta WHERE key = ?1", [META_KEY], |r| r.get(0))?;
    if before.as_deref() != Some(&after) {
        tx.commit()?;
    }
    Ok(())
}

/// The programmer sets physical location without opening a bank or a staff session.
#[cfg(feature = "programmer-tools")]
pub fn write_location_configuration(
    directory: &Path,
    location: &str,
    secret_file: &Path,
    pin: &str,
) -> Result<()> {
    crate::auth::recovery::verify_programmer_pin(secret_file, pin)?;
    let location = validate_location(location)?;
    crate::auth::recovery::deliver(&directory.join(LOCATION_CONFIG_FILE), location)
}
