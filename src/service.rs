//! Out-of-service mode: the ATM stops serving customers until a teller has looked.
//!
//! STRIDE (Tampering / Repudiation): every Teller Admin sign-in runs the full integrity check
//! (log chain, balances and cash against the log, signed settings and rates, limits, rates and
//! account flags against the log). On failure the ATM halts at once: no card is accepted,
//! customer and Cash Handler sessions stop, only a Teller Admin can sign in. A teller can also
//! halt by hand. Only a Teller Admin can resume, logged with the check's result. Fail closed.
//!
//! The state is read from the signed log (newest halt or resume entry): no flag to edit.

use crate::audit::{self, Action, Entry};
use crate::error::{AtmError, Result};
use crate::{Atm, auth::AdminSession};
use rusqlite::{Connection, OptionalExtension, params};

/// Out-of-service state, for the teller's banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub out_of_service: bool,
    /// When and why it was halted (empty while in service).
    pub since: String,
    pub reason: String,
}

/// The newest halt, if the newest halt-or-resume entry is a halt: (time, detail).
pub(crate) fn halted(conn: &Connection) -> Result<Option<(String, String)>> {
    let newest: Option<(String, String, String)> = conn
        .query_row(
            "SELECT action, ts, detail FROM audit_log WHERE action IN (?1, ?2) ORDER BY seq DESC LIMIT 1",
            params![Action::ServiceHalted.as_str(), Action::ServiceResumed.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    Ok(newest.filter(|(action, _, _)| action == Action::ServiceHalted.as_str()).map(|(_, ts, d)| (ts, d)))
}

/// Whether the ATM is out of service, for the start screen (no sign-in
/// needed: a real ATM shows "out of service" to anyone walking up). While it
/// is, no card is accepted and only a Teller Admin can sign in.
pub fn out_of_service(atm: &Atm) -> Result<bool> {
    Ok(halted(&*atm.read()?)?.is_some())
}

/// Refuses cards and Cash Handler sign-in while halted.
pub(crate) fn refuse_if_halted(conn: &Connection) -> Result<()> {
    if halted(conn)?.is_some() { Err(AtmError::OutOfService) } else { Ok(()) }
}

/// Append one halt or resume event to the audit log.
fn log(conn: &Connection, actor: &str, action: Action, detail: &str) -> Result<()> {
    audit::append(
        conn,
        &Entry { actor, action, account_id: None, counterparty_id: None, amount: None, usd: None, detail },
    )?;
    Ok(())
}

/// The full check, as text: None if it passes, Some(what failed) if not.
/// An edited or rolled-back database is a hard stop, not a banner.
fn problem(conn: &Connection) -> Result<Option<String>> {
    match audit::verify(conn) {
        Ok(_) => Ok(None),
        Err(e @ (AtmError::DatabaseAltered | AtmError::RolledBack)) => Err(e),
        Err(e) => Ok(Some(e.to_string())),
    }
}

/// Run at every Teller Admin sign-in (see `auth::login_admin`). On failure the
/// ATM is halted and the failure is returned for the red banner.
pub(crate) fn check_at_sign_in(atm: &mut Atm, actor: &str) -> Result<Option<String>> {
    let tx = atm.begin()?;
    let Some(text) = problem(&tx)? else { return Ok(None) };
    if halted(&tx)?.is_none() {
        log(
            &tx,
            "system",
            Action::ServiceHalted,
            &format!("integrity check failed at sign-in of {actor}: {text}"),
        )?;
    }
    tx.commit()?;
    Ok(Some(text))
}

/// Is the ATM out of service, since when, and why.
pub fn status(atm: &Atm, session: &AdminSession) -> Result<ServiceStatus> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    Ok(match halted(conn)? {
        Some((since, reason)) => ServiceStatus { out_of_service: true, since, reason },
        None => ServiceStatus { out_of_service: false, since: String::new(), reason: String::new() },
    })
}

/// Take the ATM out of service by hand ("Halt ATM"). Logged.
pub fn halt(atm: &mut Atm, session: &AdminSession) -> Result<()> {
    atm.admit(session)?;
    let tx = atm.begin()?;
    if halted(&tx)?.is_some() {
        return Err(AtmError::NotAllowed("the ATM is already out of service"));
    }
    log(&tx, &session.actor(), Action::ServiceHalted, "halted by teller admin")?;
    tx.commit()
}

/// Put the ATM back in service after review. The check runs again and its
/// result is logged with the resume. Returns what still fails, if anything:
/// the teller has then resumed knowingly, and the next sign-in halts it again.
pub fn resume(atm: &mut Atm, session: &AdminSession) -> Result<Option<String>> {
    atm.admit(session)?;
    let tx = atm.begin()?;
    if halted(&tx)?.is_none() {
        return Err(AtmError::NotAllowed("the ATM is already in service"));
    }
    let still = problem(&tx)?;
    let detail = match &still {
        None => "resumed after review; integrity check passed".to_string(),
        Some(text) => format!("resumed after review; integrity check still fails: {text}"),
    };
    log(&tx, &session.actor(), Action::ServiceResumed, &detail)?;
    tx.commit()?;
    Ok(still)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{self, testing::*};
    use crate::fx::Currency;
    use crate::money::Cents;
    use crate::{admin, cash, customer};

    #[test]
    fn bills_moved_with_no_log_entry_take_the_atm_out_of_service() {
        use crate::dispense::BillChoice;
        use crate::money::Denomination;
        let mut atm = Atm::in_memory().unwrap();
        let (admin_s, handler) = setup(&mut atm);
        let hundred = Denomination::new(100).unwrap();
        cash::restock(&mut atm, &handler, hundred, 100).unwrap();
        let ann = admin::create_customer(
            &mut atm,
            &admin_s,
            "Ann Lee",
            "1985-04-12",
            "4821",
            Cents::from_dollars(1000),
        )
        .unwrap();
        let s = auth::login_customer(&mut atm, &ann.card_number, "4821").unwrap();
        customer::withdraw(&mut atm, &s, Cents::from_dollars(500), BillChoice::Only(hundred)).unwrap();
        // A planted extra bill paid out with no log entry; balances still match.
        atm.execute("UPDATE cash_inventory SET bill_count = bill_count - 1 WHERE denomination = 100", [])
            .unwrap();
        atm.reseal();

        let out = admin::verify_integrity(&mut atm, &admin_s);
        assert!(
            matches!(out, Err(AtmError::CashMismatch { counted, logged })
                if counted == Cents::from_dollars(9_400) && logged == Cents::from_dollars(9_500)),
            "{out:?}"
        );
        let a = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
        assert!(a.integrity_problem().is_some_and(|p| p.contains("CASH MISMATCH")));
        assert!(status(&atm, &a).unwrap().out_of_service);
    }

    #[test]
    fn a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged() {
        use crate::money::Denomination;
        let mut atm = Atm::in_memory().unwrap();
        let (a, handler) = setup(&mut atm);
        cash::restock(&mut atm, &handler, Denomination::new(20).unwrap(), 100).unwrap();
        let open = |atm: &mut Atm, name: &str| {
            admin::create_customer(atm, &a, name, "1985-04-12", "4821", Cents::from_dollars(100)).unwrap()
        };
        let (ann, bo) = (open(&mut atm, "Ann Lee"), open(&mut atm, "Bo Kim"));
        let tamper = |atm: &mut Atm, sql: &str| {
            atm.execute(sql, []).unwrap();
            atm.reseal();
        };
        let problem = |atm: &mut Atm| {
            auth::login_admin(atm, ADMIN.0, ADMIN.1).unwrap().integrity_problem().map(str::to_string)
        };

        // First problem: Ann's balance. Reviewed, resumed knowingly.
        tamper(
            &mut atm,
            &format!(
                "UPDATE accounts SET balance_cents = 60000 WHERE account_last4 = '{}'",
                &ann.account_number[6..]
            ),
        );
        let first = problem(&mut atm).unwrap();
        assert!(
            first.contains(&ann.account_number[6..])
                && first.contains("$600.00")
                && first.contains("$100.00")
        );
        resume(&mut atm, &a).unwrap();
        // Later: Bo's balance and the cash. Both show up, next to the known one.
        tamper(
            &mut atm,
            &format!(
                "UPDATE accounts SET balance_cents = 15000 WHERE account_last4 = '{}'",
                &bo.account_number[6..]
            ),
        );
        tamper(&mut atm, "UPDATE cash_inventory SET bill_count = bill_count - 1 WHERE denomination = 20");
        let second = problem(&mut atm).unwrap();
        assert_ne!(first, second);
        assert!(second.starts_with("2 PROBLEMS FOUND."), "{second}");
        for part in [&ann.account_number[6..], &bo.account_number[6..], "CASH MISMATCH"] {
            assert!(second.contains(part), "{part} missing from {second}");
        }
        // The halt and resume rows carry the text; never a full account number.
        let leaks: i64 = atm
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE instr(detail, ?1) > 0 OR instr(detail, ?2) > 0",
                [&ann.account_number, &bo.account_number],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(leaks, 0);
    }

    #[test]
    fn a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service() {
        use crate::{audit, fx, keys};
        use rusqlite::params;
        let mut atm = Atm::in_memory().unwrap();
        let (a, _) = setup(&mut atm);
        fx::set_rate(&mut atm, &a, Currency::Eur, "0.86").unwrap();
        let ann =
            admin::create_customer(&mut atm, &a, "Ann Lee", "1980-01-01", "4821", Cents::from_dollars(900))
                .unwrap();
        admin::set_frozen(&mut atm, &a, &ann.account_number, true).unwrap();
        assert_eq!(auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap().integrity_problem(), None);

        // A planted code path: valid MACs, sealed by the program, no log rows.
        {
            let tx = atm.begin().unwrap();
            crate::db::put_setting(&tx, "daily_withdrawal_limit_cents", 900_000).unwrap();
            let set_by: String = tx
                .query_row("SELECT set_by FROM exchange_rates WHERE currency = 'EUR'", [], |r| r.get(0))
                .unwrap();
            let set_at = audit::now_utc();
            let mac =
                keys::record_mac(&["exchange_rate", "EUR", "430000", &set_at, &set_by, "active"]).unwrap();
            tx.execute(
                "UPDATE exchange_rates SET per_usd_micros = 430000, set_at = ?1, mac = ?2 WHERE currency = 'EUR'",
                params![set_at, mac],
            )
            .unwrap();
            tx.execute("UPDATE accounts SET frozen = 0", []).unwrap();
            // A rate written like the program does (row and history), minus the log line.
            let gbp =
                keys::record_mac(&["exchange_rate", "GBP", "740000", &set_at, &set_by, "active"]).unwrap();
            let gbp_history = keys::record_mac(&["rate_history", "GBP", "740000", &set_at, &set_by]).unwrap();
            tx.execute(
                "INSERT INTO exchange_rates (currency, per_usd_micros, set_at, set_by, paused, mac)
                 VALUES ('GBP', 740000, ?1, ?2, 0, ?3)",
                params![set_at, set_by, gbp],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO rate_history (currency, per_usd_micros, set_at, set_by, mac)
                 VALUES ('GBP', 740000, ?1, ?2, ?3)",
                params![set_at, set_by, gbp_history],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let a2 = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
        let problem = a2.integrity_problem().expect("the sign-in check noticed nothing").to_string();
        for part in ["withdrawal limit", "EUR rate", "GBP rate", "bank freeze of account ******"] {
            assert!(problem.contains(part), "{part} missing from {problem}");
        }
        assert!(status(&atm, &a2).unwrap().out_of_service);
    }

    #[test]
    fn a_failed_check_at_sign_in_takes_the_atm_out_of_service() {
        let mut atm = Atm::in_memory().unwrap();
        let (admin_s, handler) = setup(&mut atm);
        assert_eq!(admin_s.integrity_problem(), None);
        let ann = admin::create_customer(
            &mut atm,
            &admin_s,
            "Ann Lee",
            "1985-04-12",
            "4821",
            Cents::from_dollars(100),
        )
        .unwrap();
        let live = auth::login_customer(&mut atm, &ann.card_number, "4821").unwrap();
        // A balance changed with no log entry (as a bad code path would), sealed.
        atm.execute("UPDATE accounts SET balance_cents = balance_cents + 50000", []).unwrap();
        atm.reseal();

        let a = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
        assert!(a.integrity_problem().is_some_and(|p| p.contains("balance")));
        assert!(status(&atm, &a).unwrap().out_of_service);
        // Cards are refused, and live customer and Cash Handler sessions stop;
        // the Teller Admin keeps working.
        assert!(matches!(customer::balance(&atm, &live), Err(AtmError::OutOfService)));
        assert!(matches!(
            auth::login_customer(&mut atm, &ann.card_number, "4821"),
            Err(AtmError::OutOfService)
        ));
        assert!(matches!(cash::view(&atm, &handler), Err(AtmError::OutOfService)));
        assert!(admin::list_accounts(&atm, &a).is_ok());

        // Resumed after review: logged with the check's result.
        assert!(resume(&mut atm, &a).unwrap().is_some(), "the check still fails");
        assert!(auth::login_customer(&mut atm, &ann.card_number, "4821").is_ok());
        // The next sign-in sees the same problem and halts it again.
        let again = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();
        assert!(again.integrity_problem().is_some());
        assert!(status(&atm, &again).unwrap().out_of_service);
    }

    #[test]
    fn a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first() {
        use crate::dispense::BillChoice;
        use crate::money::Denomination;
        let dir = std::env::temp_dir().join(format!("atm-halt-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (db, key) = (dir.join("atm.db"), dir.join("atm.key"));
        std::fs::write(&key, [7u8; 32]).unwrap(); // the unit tests' fixed key
        let mut teller_side = Atm::create(&db, &key).unwrap();
        let (a, h) = setup(&mut teller_side);
        cash::restock(&mut teller_side, &h, Denomination::new(20).unwrap(), 100).unwrap();
        let ann = admin::create_customer(
            &mut teller_side,
            &a,
            "Ann Lee",
            "1980-01-01",
            "4821",
            Cents::from_dollars(500),
        )
        .unwrap();
        // The customer's front end: a second process on the same files.
        let mut customer_side = Atm::open(&db, &key).unwrap();
        let s = auth::login_customer(&mut customer_side, &ann.card_number, "4821").unwrap();

        // The teller side holds the write lock (as the sign-in check does)...
        let tx = teller_side.begin().unwrap();
        let worker = std::thread::spawn(move || {
            let r = customer::withdraw(&mut customer_side, &s, Cents::from_dollars(100), BillChoice::Any);
            (r.map(|r| r.balance_after), customer_side)
        });
        std::thread::sleep(std::time::Duration::from_millis(500)); // the withdrawal now waits for the lock
        // ...and halts the ATM before letting go.
        log(&tx, "system", Action::ServiceHalted, "integrity check failed at sign-in (test)").unwrap();
        tx.commit().unwrap();
        let (result, customer_side) = worker.join().unwrap();
        assert!(matches!(result, Err(AtmError::OutOfService)), "{result:?}");
        let paid: i64 = customer_side
            .query_row("SELECT COUNT(*) FROM audit_log WHERE action = 'withdrawal'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(paid, 0, "no cash after the ATM went out of service");
        drop(customer_side);
        drop(teller_side);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_teller_can_halt_and_resume_by_hand() {
        let mut atm = Atm::in_memory().unwrap();
        let (a, _) = setup(&mut atm);
        halt(&mut atm, &a).unwrap();
        assert!(matches!(halt(&mut atm, &a), Err(AtmError::NotAllowed(_))));
        assert!(matches!(auth::login_customer(&mut atm, "1234567890", "4821"), Err(AtmError::OutOfService)));
        assert_eq!(resume(&mut atm, &a).unwrap(), None, "the check passes");
        assert!(!status(&atm, &a).unwrap().out_of_service);
        assert!(matches!(resume(&mut atm, &a), Err(AtmError::NotAllowed(_))));
    }

    #[test]
    fn while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in() {
        let mut atm = Atm::in_memory().unwrap();
        let (a, _) = setup(&mut atm);
        let ann =
            admin::create_customer(&mut atm, &a, "Ann Lee", "1985-04-12", "4821", Cents::from_dollars(100))
                .unwrap();
        assert!(!out_of_service(&atm).unwrap());
        halt(&mut atm, &a).unwrap();
        assert!(out_of_service(&atm).unwrap());

        // Any card, right or wrong PIN, is turned away before the PIN is checked:
        // no try is counted against the card.
        for pin in ["4821", "0000", "0000", "0000"] {
            assert!(matches!(
                auth::login_customer(&mut atm, &ann.card_number, pin),
                Err(AtmError::OutOfService)
            ));
        }
        // The Cash Handler can't sign in; the Teller Admin can.
        assert!(matches!(auth::login_handler(&mut atm, HANDLER.0, HANDLER.1), Err(AtmError::OutOfService)));
        let again = auth::login_admin(&mut atm, ADMIN.0, ADMIN.1).unwrap();

        resume(&mut atm, &again).unwrap();
        assert!(!out_of_service(&atm).unwrap());
        assert!(auth::login_handler(&mut atm, HANDLER.0, HANDLER.1).is_ok());
        assert!(auth::login_customer(&mut atm, &ann.card_number, "4821").is_ok(), "no tries were counted");
    }
}
