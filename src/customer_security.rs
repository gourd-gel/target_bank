//! Customer PIN locks: durable alerts and Authorities-only resolution.
use crate::{
    Atm,
    audit::{self, Action, Entry},
    auth::AuthoritiesSession,
    db::{self, Number},
    error::{AtmError, Result},
    keys,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "customer-pin-alert:";
#[derive(Serialize, Deserialize)]
struct Alert {
    actor: String,
    card_id: i64,
    card_last4: String,
    source: String,
    timestamp: String,
    reference: i64,
}

/// Queue in the same transaction as the lock, without storing any PIN.
pub(crate) fn queue(conn: &Connection, card_id: i64, source: &str) -> Result<()> {
    let last4: String =
        conn.query_row("SELECT card_last4 FROM cards WHERE id=?1", [card_id], |r| r.get(0))?;
    let reference = conn.query_row("SELECT MAX(seq) FROM audit_log", [], |r| r.get(0))?;
    let alert = Alert {
        actor: db::customer_actor(card_id, &last4),
        card_id,
        card_last4: last4,
        source: source.into(),
        timestamp: audit::now_utc(),
        reference,
    };
    let key = format!("{PREFIX}{reference}");
    let clear =
        serde_json::to_string(&alert).map_err(|_| AtmError::Internal("customer alert encoding".into()))?;
    let sealed = keys::seal("customer.pin.alert", &key, &clear)?;
    let encoded =
        serde_json::to_string(&sealed).map_err(|_| AtmError::Internal("customer alert encoding".into()))?;
    conn.execute("INSERT INTO meta(key,value) VALUES (?1,?2)", params![key, encoded])?;
    Ok(())
}

/// Deliver only committed incidents. Failed delivery preserves the encrypted
/// outbox; each incident has its own archived notification file.
pub(crate) fn retry(atm: &mut Atm) -> Result<u32> {
    let pending = {
        let read = atm.read()?;
        let mut stmt =
            read.prepare("SELECT key FROM meta WHERE key LIKE 'customer-pin-alert:%' ORDER BY key LIMIT 20")?;
        stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let bank_id = atm.id;
    let mut count = 0;
    for key in pending {
        let tx = atm.begin()?;
        let stored: Option<String> =
            tx.query_row("SELECT value FROM meta WHERE key=?1", [&key], |r| r.get(0)).optional()?;
        let Some(stored) = stored else { continue };
        let sealed: Vec<u8> =
            serde_json::from_str(&stored).map_err(|_| AtmError::RecordTampered("customer alert"))?;
        let clear = keys::unseal("customer.pin.alert", &key, &sealed)?;
        let alert: Alert =
            serde_json::from_str(&clear).map_err(|_| AtmError::RecordTampered("customer alert"))?;
        let body = format!(
            "Alert! Customer login locked after 3 consecutive incorrect PIN attempts.\nCustomer actor: {}\nCard ending: {}\nSource: {}\nIncident time (UTC): {}\nIncident reference: {}\nAuthorities action required: identify the customer, then use resolve-customer <card-number> <review reason> in cargo authorities. This alert reports a committed incident; inspect the current card state before taking action.",
            alert.actor, alert.card_last4, alert.source, alert.timestamp, alert.reference
        );
        let delivered = crate::auth::recovery::deliver_customer_alert(
            &tx,
            bank_id,
            &body,
            alert.card_id,
            alert.reference,
        )
        .is_ok();
        if delivered {
            tx.execute("DELETE FROM meta WHERE key=?1", [&key])?;
            count += 1;
        }
        audit::append(
            &tx,
            &Entry {
                actor: "system",
                action: Action::ControlsChanged,
                account_id: None,
                counterparty_id: None,
                amount: None,
                usd: None,
                detail: &format!(
                    "customer PIN-lock alert reference {} {}; {}",
                    alert.reference,
                    if delivered { "delivered to Authorities" } else { "delivery failed" },
                    if delivered { "outbox cleared" } else { "retained for retry" }
                ),
            },
        )?;
        tx.commit()?;
    }
    Ok(count)
}

pub fn retry_alerts(atm: &mut Atm, session: &AuthoritiesSession) -> Result<u32> {
    crate::administration::access(
        atm,
        session,
        "customer_alert_retry",
        "pending customer PIN-lock notifications",
    )?;
    retry(atm)
}

/// Resolve only this card's PIN lock. A teller session cannot call this API.
/// ```compile_fail,E0308
/// fn unlock(bank: &mut atm::Atm, teller: &atm::auth::AdminSession) {
///     atm::customer_security::resolve(bank, teller, "1234567890", "reviewed");
/// }
/// ```
pub fn resolve(atm: &mut Atm, session: &AuthoritiesSession, card_number: &str, reason: &str) -> Result<()> {
    crate::administration::access(
        atm,
        session,
        "customer_lock_resolution_request",
        "customer PIN-lock review requested",
    )?;
    crate::input::validate_number10(card_number)?;
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > 500 || reason.chars().any(char::is_control) {
        return Err(AtmError::InvalidInput(
            "enter a review reason of 1 to 500 bytes without control characters",
        ));
    }
    atm.admit(session)?;
    let tx = atm.begin_for(session)?;
    let row: Option<(i64, i64, bool, bool)> = tx.query_row(
        "SELECT c.id,c.account_id,c.locked,a.closed FROM cards c JOIN accounts a ON a.id=c.account_id WHERE c.card_lookup=?1",
        [db::lookup(Number::Card, card_number)?], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let (card_id, account_id, locked, closed) = row.ok_or(AtmError::NotFound("Customer card"))?;
    if closed {
        return Err(AtmError::NotAllowed("a closed account cannot be restored by resolving its PIN lock"));
    }
    if !locked {
        return Err(AtmError::NotAllowed("that customer card is not locked"));
    }
    tx.execute("UPDATE cards SET locked=0,failed_attempts=0 WHERE id=?1", [card_id])?;
    let card_ref = db::card_ref(card_id, db::last4(card_number));
    audit::append(
        &tx,
        &Entry {
            actor: "system",
            action: Action::CardUnlocked,
            account_id: Some(account_id),
            counterparty_id: None,
            amount: None,
            usd: None,
            detail: &card_ref,
        },
    )?;
    crate::administration::append(
        &tx,
        &session.actor(),
        "customer_lock_resolved",
        "succeeded",
        &format!("{card_ref}; review: {reason}"),
    )?;
    tx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admin,
        auth::{self, testing::*},
        customer,
        money::Cents,
        service,
    };

    #[test]
    fn only_authorities_can_resolve_one_card_and_other_customers_keep_working() {
        let mut bank = Atm::in_memory().unwrap();
        let (teller, _) = setup(&mut bank);
        let ann = admin::create_customer(
            &mut bank,
            &teller,
            "Ann Lee",
            "1980-01-01",
            "4821",
            Cents::from_dollars(100),
        )
        .unwrap();
        let bo = admin::create_customer(
            &mut bank,
            &teller,
            "Bo Kim",
            "1980-01-01",
            "5937",
            Cents::from_dollars(100),
        )
        .unwrap();
        let live = auth::login_customer(&mut bank, &ann.card_number, "4821").unwrap();
        for pin in ["1111", "bad", "3333"] {
            assert!(auth::login_customer(&mut bank, &ann.card_number, pin).is_err());
        }
        assert!(!service::out_of_service(&bank).unwrap());
        assert!(matches!(
            auth::login_customer(&mut bank, &ann.card_number, "4821"),
            Err(AtmError::CardLocked)
        ));
        assert!(matches!(customer::balance(&bank, &live), Err(AtmError::SessionExpired)));
        assert!(auth::login_customer(&mut bank, &bo.card_number, "5937").is_ok());
        assert!(admin::unlock_card(&mut bank, &teller, &ann.card_number).is_err());
        let authority = authorities(&bank);
        assert!(resolve(&mut bank, &authority, &ann.card_number, " ").is_err());
        let other_bank = Atm::in_memory().unwrap();
        assert!(matches!(
            resolve(&mut bank, &authorities(&other_bank), &ann.card_number, "reviewed"),
            Err(AtmError::SessionExpired)
        ));
        let expired = authorities(&bank);
        expired.end();
        assert!(matches!(
            resolve(&mut bank, &expired, &ann.card_number, "reviewed"),
            Err(AtmError::SessionExpired)
        ));
        admin::set_frozen(&mut bank, &teller, &ann.account_number, true).unwrap();
        resolve(&mut bank, &authority, &ann.card_number, "Verified identity and reviewed incident").unwrap();
        assert!(matches!(
            auth::login_customer(&mut bank, &ann.card_number, "4821"),
            Err(AtmError::FrozenByBank)
        ));
        admin::set_frozen(&mut bank, &teller, &ann.account_number, false).unwrap();
        assert!(auth::login_customer(&mut bank, &ann.card_number, "4821").is_ok());
        assert!(resolve(&mut bank, &authority, &ann.card_number, "already resolved").is_err());
        let audit = crate::administration::recent(&bank, &authority, 0).unwrap();
        assert!(
            audit.iter().any(|r| r.event.action == "customer_lock_resolved"
                && r.event.details.contains("Verified identity"))
        );
    }

    #[test]
    fn failed_delivery_retains_distinct_encrypted_incidents_and_pin_changes_also_alert() {
        let mut bank = Atm::in_memory().unwrap();
        let (teller, _) = setup(&mut bank);
        for name in ["Ann Lee", "Bo Kim"] {
            let card = admin::create_customer(
                &mut bank,
                &teller,
                name,
                "1980-01-01",
                "4821",
                Cents::from_dollars(100),
            )
            .unwrap();
            let session = auth::login_customer(&mut bank, &card.card_number, "4821").unwrap();
            for _ in 0..3 {
                assert!(customer::change_pin(&mut bank, &session, "1111", "5937").is_err());
            }
            assert!(matches!(
                auth::login_customer(&mut bank, &card.card_number, "4821"),
                Err(AtmError::CardLocked)
            ));
        }
        let conn = bank.read().unwrap();
        let records: Vec<(String, String)> = conn
            .prepare("SELECT key,value FROM meta WHERE key LIKE 'customer-pin-alert:%'")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(records.len(), 2);
        for (key, encoded) in records {
            let bytes: Vec<u8> = serde_json::from_str(&encoded).unwrap();
            let clear = keys::unseal("customer.pin.alert", &key, &bytes).unwrap();
            let alert: Alert = serde_json::from_str(&clear).unwrap();
            assert_eq!(alert.source, "customer PIN change");
            let fields: serde_json::Value = serde_json::from_str(&clear).unwrap();
            assert!(fields.get("pin").is_none());
            assert!(fields.get("current_pin").is_none());
        }
    }
}
