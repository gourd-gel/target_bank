//! Keyboard reading (CLI only) and field validators (used by every front end).
//!
//! Validation style: allow-lists. Each validator says what IS accepted;
//! everything else is rejected. The core re-validates, so a GUI that forgets
//! to check a field still can't sneak bad data in.

use crate::error::{AtmError, Result};
use chrono::{Datelike, NaiveDate};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use zeroize::Zeroizing;

/// STRIDE (Denial of Service): max bytes per input line.
const MAX_LINE: usize = 256;

/// Adults only for individual/joint accounts and for guardians.
pub const ADULT_AGE: u32 = 18;

// ---------------------------------------------------------------------------
// Reading (CLI)
// ---------------------------------------------------------------------------

/// Print a prompt and read one trimmed line (bounded, UTF-8 only).
pub fn read_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| AtmError::Internal(e.to_string()))?;
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut bytes = Vec::new();
    let n = (&mut lock)
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| AtmError::InvalidInput("unreadable input"))?;
    if n == 0 {
        return Err(AtmError::Eof);
    }
    if bytes.last() != Some(&b'\n') && n > MAX_LINE {
        discard_rest_of_line(&mut lock)?; // so leftovers don't answer the next prompt
        return Err(AtmError::InvalidInput("input too long"));
    }
    let line = String::from_utf8(bytes).map_err(|_| AtmError::InvalidInput("unreadable input"))?;
    Ok(line.trim().to_string())
}

/// Skip input up to and including the next newline (or end of input).
fn discard_rest_of_line(lock: &mut io::StdinLock<'_>) -> Result<()> {
    loop {
        let buf = lock.fill_buf().map_err(|e| AtmError::Internal(e.to_string()))?;
        if buf.is_empty() {
            return Ok(());
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(i) => {
                lock.consume(i + 1);
                return Ok(());
            }
            None => {
                let len = buf.len();
                lock.consume(len);
            }
        }
    }
}

/// Read a PIN/password. Hidden at a real terminal (shoulder-surfing defence);
/// plain line when piped (scripted tests). Zeroizing: wiped from memory when dropped.
pub fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
    let secret = Zeroizing::new(if io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).map_err(|_| AtmError::Eof)?
    } else {
        read_line(prompt)?
    });
    if secret.len() > MAX_LINE {
        return Err(AtmError::InvalidInput("input too long"));
    }
    Ok(secret)
}

/// What `wipe_screen` sends: cursor home, clear the screen, clear the scrollback.
pub const WIPE: &str = "\x1b[H\x1b[2J\x1b[3J";

/// End of a session: clear the terminal and its scrollback, so the next
/// person can't read (or scroll back to) the last one's name and balances.
pub fn wipe_screen() {
    print!("{WIPE}");
    let _ = io::stdout().flush();
}

/// Whole number, digits only (`parse` alone would accept "+5").
pub fn read_u32(prompt: &str) -> Result<u32> {
    let text = read_line(prompt)?;
    if text.is_empty() || text.len() > 9 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AtmError::InvalidInput("enter a whole number"));
    }
    text.parse().map_err(|_| AtmError::InvalidInput("enter a whole number"))
}

/// Ask a yes/no question; only "y" or "Y" means yes.
pub fn confirm(prompt: &str) -> Result<bool> {
    Ok(read_line(prompt)?.eq_ignore_ascii_case("y"))
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// PIN format: 4 to 12 ASCII digits (string, so leading zeros survive).
pub fn validate_pin(pin: &str) -> Result<()> {
    if (4..=12).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(AtmError::InvalidInput("a PIN is 4 to 12 digits"))
    }
}

/// New PINs only: format + not trivially guessable (STRIDE: Spoofing).
/// Rejects 0000-style repeats, 1234/4321 runs, and the birth year / birthday.
pub fn validate_new_pin(pin: &str, dob: NaiveDate) -> Result<()> {
    validate_pin(pin)?;
    let d: Vec<i32> = pin.bytes().map(|b| i32::from(b - b'0')).collect();
    let all_same = d.windows(2).all(|w| w[0] == w[1]);
    let run_up = d.windows(2).all(|w| w[1] == (w[0] + 1) % 10);
    let run_down = d.windows(2).all(|w| w[0] == (w[1] + 1) % 10);
    let birthday = [
        format!("{:04}", dob.year()),
        format!("{:02}{:02}", dob.month(), dob.day()),
        format!("{:02}{:02}", dob.day(), dob.month()),
    ];
    if all_same || run_up || run_down || birthday.iter().any(|b| b == pin) {
        return Err(AtmError::InvalidInput(
            "that PIN is too easy to guess (no repeats, runs like 1234, or birthdays)",
        ));
    }
    Ok(())
}

/// Account and card numbers: exactly 10 ASCII digits.
pub fn validate_number10(number: &str) -> Result<()> {
    if number.len() == 10 && number.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(AtmError::InvalidInput("account and card numbers are 10 digits"))
    }
}

/// Full name: letters, spaces, - ' . ; 2 to 80 characters.
/// STRIDE (Tampering / Repudiation): no newlines or terminal escapes, so a
/// name can't forge or hide lines when the audit log is printed.
pub fn validate_name(name: &str) -> Result<()> {
    let count = name.chars().count();
    let ok_chars = name.chars().all(|c| c.is_alphabetic() || matches!(c, ' ' | '-' | '\'' | '.'));
    if (2..=80).contains(&count) && ok_chars && name.chars().any(|c| c.is_alphabetic()) {
        Ok(())
    } else {
        Err(AtmError::InvalidInput("a name is 2 to 80 letters, spaces, hyphens or apostrophes"))
    }
}

/// Staff usernames: 3 to 32 of a-z, 0-9, underscore.
pub fn validate_username(name: &str) -> Result<()> {
    let ok = name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if (3..=32).contains(&name.len()) && ok {
        Ok(())
    } else {
        Err(AtmError::InvalidInput("a username is 3 to 32 of a-z, 0-9 and underscore"))
    }
}

/// Staff passwords: 12 to 128 characters, no control characters.
pub fn validate_password(password: &str) -> Result<()> {
    let count = password.chars().count();
    if (12..=128).contains(&count) && !password.chars().any(|c| c.is_control()) {
        Ok(())
    } else {
        Err(AtmError::InvalidInput("a staff password is 12 to 128 characters"))
    }
}

/// Date of birth as YYYY-MM-DD: real date, 1900 to today.
pub fn validate_dob(text: &str, today: NaiveDate) -> Result<NaiveDate> {
    const BAD: AtmError = AtmError::InvalidInput("enter a date of birth as YYYY-MM-DD");
    if text.len() != 10 {
        return Err(BAD);
    }
    let date = NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| BAD)?;
    let earliest = NaiveDate::from_ymd_opt(1900, 1, 1).ok_or(BAD)?;
    if date > today || date < earliest {
        return Err(AtmError::InvalidInput("date of birth must be between 1900 and today"));
    }
    Ok(date)
}

/// Age in whole years on `today`.
pub fn age_on(dob: NaiveDate, today: NaiveDate) -> u32 {
    today.years_since(dob).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn pin_rules() {
        assert!(validate_pin("1234").is_ok());
        for bad in ["123", "12a4", "", "1234567890123", "12 34", "-1234", "١٢٣٤"] {
            assert!(validate_pin(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn weak_new_pins_are_refused() {
        let dob = date("1990-07-04");
        assert!(validate_new_pin("4821", dob).is_ok());
        assert!(validate_new_pin("0055", dob).is_ok()); // leading zeros fine
        for weak in ["0000", "1111", "1234", "4321", "7890", "1990", "0704", "0407"] {
            assert!(validate_new_pin(weak, dob).is_err(), "accepted {weak}");
        }
    }

    #[test]
    fn names_cannot_carry_control_characters() {
        assert!(validate_name("Mary-Jane O'Neil Jr.").is_ok());
        assert!(validate_name("José Álvarez").is_ok());
        for bad in ["", "A", "Eve\nadmin unlocked", "Eve\x1b[2J", "Robert'); DROP TABLE--", "----"] {
            assert!(validate_name(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn dob_and_age() {
        let today = date("2026-10-07");
        assert!(validate_dob("2001-02-28", today).is_ok());
        for bad in ["2001-02-30", "2027-01-01", "1899-12-31", "01/02/2001", "2001-2-3", ""] {
            assert!(validate_dob(bad, today).is_err(), "accepted {bad:?}");
        }
        assert_eq!(age_on(date("2008-10-07"), today), 18);
        assert_eq!(age_on(date("2008-10-08"), today), 17);
    }
}
