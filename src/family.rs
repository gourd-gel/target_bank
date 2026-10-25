//! Parental controls: what a guardian can do for a youth account.
//!
//! A guardian is an ordinary adult customer whose card is linked to the youth
//! account (see `admin::open_youth_account`). Every function checks that link
//! from the session's card, so a customer can only see or control children
//! they are actually a guardian of (STRIDE: Elevation of Privilege / Info
//! Disclosure). "Not yours" and "doesn't exist" give the same error.

use crate::Atm;
use crate::audit::{self, Action, Entry, Row};
use crate::auth::CustomerSession;
use crate::customer::{self, HISTORY_PAGE, mask};
use crate::db::{self, Limit, Number};
use crate::error::{AtmError, Result};
use crate::fx::{self, Currency};
use crate::money::Cents;
use crate::review;
use rusqlite::{Connection, OptionalExtension, params};

/// A youth account as its guardian sees it.
#[derive(Debug, Clone)]
pub struct YouthSummary {
    pub account_number: String,
    pub child_name: String,
    pub balance: Cents,
    /// Frozen by you (the guardian); you can lift it.
    pub frozen: bool,
    /// Frozen by the bank; only a teller can lift it.
    pub bank_frozen: bool,
    pub controls: YouthControls,
}

/// The controls a guardian can set. Effective limit = min(bank limit, cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YouthControls {
    pub daily_withdraw_cap: Cents,
    pub daily_transfer_cap: Cents,
    /// Child may only transfer to a guardian's account.
    pub family_only_transfers: bool,
}

/// Youth account id if this session's card is its guardian; NotFound otherwise.
fn guarded_account(conn: &Connection, session: &CustomerSession, youth_account_number: &str) -> Result<i64> {
    let id = db::account_id(conn, youth_account_number).map_err(|_| AtmError::NotFound("Youth account"))?;
    conn.query_row(
        "SELECT youth_account_id FROM guardians WHERE youth_account_id = ?1 AND guardian_card_id = ?2",
        params![id, session.card_id()],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(AtmError::NotFound("Youth account"))
}

/// Append one guardian action on a youth account to the audit log.
fn log(
    conn: &Connection,
    session: &CustomerSession,
    action: Action,
    account: i64,
    detail: &str,
) -> Result<()> {
    audit::append(
        conn,
        &Entry {
            actor: &session.actor(),
            action,
            account_id: Some(account),
            counterparty_id: None,
            amount: None,
            usd: None,
            detail,
        },
    )?;
    Ok(())
}

/// Youth accounts this guardian manages.
pub fn my_youth_accounts(atm: &Atm, session: &CustomerSession) -> Result<Vec<YouthSummary>> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    let mut stmt = conn.prepare(
        "SELECT a.account_lookup, a.account_enc, c.card_lookup, c.name_enc, a.balance_cents, a.guardian_frozen,
                COALESCE(a.withdraw_cap_cents, 0), COALESCE(a.transfer_cap_cents, 0),
                a.family_only_transfers, a.frozen
         FROM guardians g
         JOIN accounts a ON a.id = g.youth_account_id AND a.closed = 0
         JOIN cards c ON c.account_id = a.id AND c.holder_role = 'minor'
         WHERE g.guardian_card_id = ?1 ORDER BY a.id",
    )?;
    let mut rows = stmt.query(params![session.card_id()])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let child_card: String = r.get(2)?;
        out.push(YouthSummary {
            account_number: db::open_number(
                Number::Account,
                &r.get::<_, String>(0)?,
                &r.get::<_, Vec<u8>>(1)?,
            )?,
            child_name: db::holder_name(&child_card, &r.get::<_, Vec<u8>>(3)?)?,
            balance: Cents::new(r.get(4)?)?,
            frozen: r.get(5)?,
            bank_frozen: r.get(9)?,
            controls: YouthControls {
                daily_withdraw_cap: Cents::new(r.get(6)?)?,
                daily_transfer_cap: Cents::new(r.get(7)?)?,
                family_only_transfers: r.get(8)?,
            },
        });
    }
    Ok(out)
}

/// The child's recent transactions (guardian oversight).
pub fn youth_history(
    atm: &Atm,
    session: &CustomerSession,
    youth_account_number: &str,
    page: u32,
) -> Result<Vec<Row>> {
    let conn = &atm.read()?;
    atm.admit(session)?;
    let id = guarded_account(conn, session, youth_account_number)?;
    audit::for_customer(conn, id, youth_account_number, HISTORY_PAGE, page)
}

/// Change spending caps / family-only setting. Logged with old -> new.
pub fn set_controls(
    atm: &mut Atm,
    session: &CustomerSession,
    youth_account_number: &str,
    controls: YouthControls,
) -> Result<()> {
    atm.admit(session)?;
    let tx = atm.begin_for(session)?;
    let id = guarded_account(&tx, session, youth_account_number)?;
    // Caps can only lower the bank's limits; a higher one would mislead the parent.
    if controls.daily_withdraw_cap > db::get_limit(&tx, db::Limit::Withdrawal)?
        || controls.daily_transfer_cap > db::get_limit(&tx, db::Limit::Transfer)?
    {
        return Err(AtmError::InvalidInput("a youth cap can't be higher than the bank's daily limit"));
    }
    tx.execute(
        "UPDATE accounts SET withdraw_cap_cents = ?2, transfer_cap_cents = ?3, family_only_transfers = ?4
         WHERE id = ?1",
        params![
            id,
            controls.daily_withdraw_cap.as_i64(),
            controls.daily_transfer_cap.as_i64(),
            controls.family_only_transfers
        ],
    )?;
    let detail = format!(
        "youth {}: withdraw cap {}, transfer cap {}, family-only {}",
        mask(youth_account_number),
        controls.daily_withdraw_cap,
        controls.daily_transfer_cap,
        controls.family_only_transfers
    );
    log(&tx, session, Action::ControlsChanged, id, &detail)?;
    tx.commit()?;
    Ok(())
}

/// Freeze (lost card, misuse) or unfreeze the child's account. Deposits still work.
/// This is the guardian's own freeze: it can't lift a freeze the bank placed
/// (STRIDE: Elevation of Privilege), and the bank's unfreeze doesn't lift it.
pub fn set_frozen(
    atm: &mut Atm,
    session: &CustomerSession,
    youth_account_number: &str,
    frozen: bool,
) -> Result<()> {
    atm.admit(session)?;
    let tx = atm.begin_for(session)?;
    let id = guarded_account(&tx, session, youth_account_number)?;
    let (bank, guardian): (bool, bool) =
        tx.query_row("SELECT frozen, guardian_frozen FROM accounts WHERE id = ?1", params![id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    if !frozen && bank && !guardian {
        return Err(AtmError::NotAllowed("the bank froze this account; please see a teller"));
    }
    tx.execute("UPDATE accounts SET guardian_frozen = ?2 WHERE id = ?1", params![id, frozen])?;
    let action = if frozen { Action::AccountFrozen } else { Action::AccountUnfrozen };
    log(&tx, session, action, id, "by guardian")?;
    tx.commit()?;
    Ok(())
}

/// Which way a guardian moves money.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From the guardian's own account into the child's.
    ToChild,
    /// From the child's account back to the guardian's own account.
    FromChild,
}

/// Result of a guardian move: both balances afterwards.
#[derive(Debug, Clone)]
pub struct FamilyMove {
    pub reference: i64,
    pub currency: Currency,
    pub amount: Cents,
    pub your_balance: Cents,
    pub child_balance: Cents,
}

/// Move money between the guardian's own account and a linked child's. Money from the child only
/// goes to the guardian (STRIDE: Elevation of Privilege: never a way to pay a third party). Same
/// checks as a transfer (link, currency, balance, frozen, hold, payer's daily limit, no money into
/// a bank-frozen account; taking back uses the bank limit). Logged as a transfer "by guardian".
pub fn move_money(
    atm: &mut Atm,
    session: &CustomerSession,
    youth_account_number: &str,
    direction: Direction,
    amount: Cents,
) -> Result<FamilyMove> {
    atm.admit(session)?;
    customer::not_guest(session)?;
    if amount.is_zero() {
        return Err(AtmError::InvalidInput("amount must be more than zero"));
    }
    let tx = atm.begin_for(session)?;
    let child = guarded_account(&tx, session, youth_account_number)?;
    let own = session.account_id();
    let currency = customer::currency_of(&tx, own)?;
    if customer::currency_of(&tx, child)? != currency {
        return Err(AtmError::NotAllowed("transfers must be between accounts in the same currency"));
    }
    currency.check_amount(amount)?;
    let (from, to) = match direction {
        Direction::ToChild => (own, child),
        Direction::FromChild => (child, own),
    };
    // Money leaving `from`: frozen, held and balance checks apply to it.
    if customer::is_frozen(&tx, from)? {
        return Err(AtmError::AccountFrozen);
    }
    // Money going into `to`: a bank-frozen account takes no transfers in.
    let to_bank_frozen: bool =
        tx.query_row("SELECT frozen FROM accounts WHERE id = ?1", params![to], |r| r.get(0))?;
    if to_bank_frozen {
        return Err(AtmError::FrozenByBank);
    }
    review::check_not_held(&tx, from)?;
    if amount > customer::balance_of(&tx, from)? {
        return Err(AtmError::InsufficientFunds);
    }
    let usd = fx::usd_value(&tx, currency, amount)?;
    match direction {
        Direction::ToChild => customer::check_daily_limit(&tx, own, Limit::Transfer, usd)?,
        Direction::FromChild => {
            let bank = db::get_limit(&tx, Limit::Transfer)?;
            let used = audit::total_today(&tx, child, Action::Transfer)?;
            let remaining = bank.checked_sub(used).unwrap_or(Cents::ZERO);
            if usd > remaining {
                return Err(AtmError::LimitExceeded { kind: "transfer", remaining, see_teller: false });
            }
        }
    }
    // Same activity rules as any transfer: a stolen guardian card can't sweep
    // a child's savings unchecked. On a hold, keep its log row.
    if review::screen(&tx, from, review::Move::Transfer { to }, usd, amount)? == review::Screen::Held {
        tx.commit()?;
        return Err(AtmError::OnHold);
    }
    customer::debit(&tx, from, amount)?;
    customer::credit(&tx, to, amount)?;
    let detail = match direction {
        Direction::ToChild => format!("by guardian: to youth {}", mask(youth_account_number)),
        Direction::FromChild => {
            format!("by guardian: from youth {} to guardian's own account", mask(youth_account_number))
        }
    };
    let reference = audit::append(
        &tx,
        &Entry {
            actor: &session.actor(),
            action: Action::Transfer,
            account_id: Some(from),
            counterparty_id: Some(to),
            amount: Some(amount),
            usd: Some(usd),
            detail: &detail,
        },
    )?;
    let moved = FamilyMove {
        reference,
        currency,
        amount,
        your_balance: customer::balance_of(&tx, own)?,
        child_balance: customer::balance_of(&tx, child)?,
    };
    tx.commit()?;
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::{self, NewCard};
    use crate::auth::{self, CardAndPin, testing::setup};
    use crate::cash;
    use crate::customer;
    use crate::dispense::BillChoice;
    use crate::money::Denomination;

    fn usd(n: u32) -> Cents {
        Cents::from_dollars(n)
    }
    fn twenties() -> BillChoice {
        BillChoice::Only(Denomination::new(20).unwrap())
    }

    /// Parent (Pat), a stranger (Sam), and Pat's child (Kid) with $300.
    fn family() -> (Atm, NewCard, NewCard, NewCard) {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, handler) = setup(&mut conn);
        cash::restock(&mut conn, &handler, Denomination::new(20).unwrap(), 100).unwrap();
        let pat =
            admin::create_customer(&mut conn, &admin, "Pat Doe", "1980-03-03", "4821", usd(500)).unwrap();
        let sam =
            admin::create_customer(&mut conn, &admin, "Sam Roe", "1985-04-04", "7305", usd(500)).unwrap();
        let kid = admin::open_youth_account(
            &mut conn,
            &admin,
            CardAndPin { card_number: &pat.card_number, pin: "4821" },
            "Kid Doe",
            "2014-06-06",
            "2580",
            usd(300),
        )
        .unwrap();
        (conn, pat, sam, kid)
    }

    #[test]
    fn guardian_moves_money_in_and_out_of_the_childs_account_only() {
        let (mut conn, pat, sam, kid) = family();
        let p = auth::login_customer(&mut conn, &pat.card_number, "4821").unwrap();
        let s = auth::login_customer(&mut conn, &sam.card_number, "7305").unwrap();
        let k = auth::login_customer(&mut conn, &kid.card_number, "2580").unwrap();
        let kid_no = kid.account_number.as_str();
        // In: $50 from Pat's account to Kid's.
        let m = move_money(&mut conn, &p, kid_no, Direction::ToChild, usd(50)).unwrap();
        assert_eq!((m.your_balance, m.child_balance), (usd(450), usd(350)));
        // Out: $100 back to Pat (above the child's own $50 transfer cap).
        let m = move_money(&mut conn, &p, kid_no, Direction::FromChild, usd(100)).unwrap();
        assert_eq!((m.your_balance, m.child_balance), (usd(550), usd(250)));
        assert!(matches!(
            move_money(&mut conn, &p, kid_no, Direction::FromChild, usd(251)),
            Err(AtmError::InsufficientFunds)
        ));
        assert!(move_money(&mut conn, &p, kid_no, Direction::ToChild, Cents::ZERO).is_err());
        // A stranger, or the child's own card, can't use it (same error as "no such account").
        for (who, dir) in [(&s, Direction::ToChild), (&s, Direction::FromChild), (&k, Direction::FromChild)] {
            assert!(matches!(move_money(&mut conn, who, kid_no, dir, usd(1)), Err(AtmError::NotFound(_))));
        }
        // Frozen child account: money can go in, not out.
        set_frozen(&mut conn, &p, kid_no, true).unwrap();
        move_money(&mut conn, &p, kid_no, Direction::ToChild, usd(10)).unwrap();
        assert!(matches!(
            move_money(&mut conn, &p, kid_no, Direction::FromChild, usd(10)),
            Err(AtmError::AccountFrozen)
        ));
        // Logged as transfers "by guardian"; every balance still matches the ledger.
        let rows = youth_history(&conn, &p, kid_no, 0).unwrap();
        assert_eq!(rows.iter().filter(|r| r.detail.starts_with("by guardian:")).count(), 3);
        assert_eq!(audit::verify(&conn.conn).unwrap().accounts_checked, 3);
    }

    #[test]
    fn guardian_moves_go_through_the_same_activity_rules_as_transfers() {
        let (mut conn, pat, _, kid) = family();
        let p = auth::login_customer(&mut conn, &pat.card_number, "4821").unwrap();
        let kid_no = kid.account_number.as_str();
        let kid_id = guarded_account(&conn.conn, &p, kid_no).unwrap();
        // Rule 2: the 4th move out of the child's account within an hour is held.
        for _ in 0..3 {
            move_money(&mut conn, &p, kid_no, Direction::FromChild, usd(10)).unwrap();
        }
        assert!(matches!(
            move_money(&mut conn, &p, kid_no, Direction::FromChild, usd(10)),
            Err(AtmError::OnHold)
        ));
        // The hold is kept (logged) and the money stayed put.
        assert!(review::hold_reason(&conn.conn, kid_id).unwrap().is_some_and(|r| r.starts_with("rule 2")));
        assert_eq!(customer::balance_of(&conn.conn, kid_id).unwrap(), usd(270));
        // Money can still go in; nothing more comes out until a teller releases it.
        move_money(&mut conn, &p, kid_no, Direction::ToChild, usd(5)).unwrap();
        assert!(matches!(
            move_money(&mut conn, &p, kid_no, Direction::FromChild, usd(1)),
            Err(AtmError::OnHold)
        ));
    }

    #[test]
    fn youth_defaults_cap_spending_and_restrict_transfers() {
        let (mut conn, pat, sam, kid) = family();
        let k = auth::login_customer(&mut conn, &kid.card_number, "2580").unwrap();
        // $100/day withdrawal cap, even though the bank limit is $1,000.
        assert!(matches!(
            customer::withdraw(&mut conn, &k, usd(120), twenties()),
            Err(AtmError::LimitExceeded { .. })
        ));
        assert!(customer::withdraw(&mut conn, &k, usd(100), twenties()).is_ok());
        // Family only: a stranger is refused, the parent is fine.
        assert!(matches!(
            customer::transfer(&mut conn, &k, &sam.account_number, usd(5)),
            Err(AtmError::NotAllowed(_))
        ));
        assert!(customer::transfer(&mut conn, &k, &pat.account_number, usd(5)).is_ok());
    }

    #[test]
    fn guardian_can_see_adjust_and_freeze_but_strangers_cannot() {
        let (mut conn, pat, sam, kid) = family();
        let p = auth::login_customer(&mut conn, &pat.card_number, "4821").unwrap();
        let s = auth::login_customer(&mut conn, &sam.card_number, "7305").unwrap();
        let mine = my_youth_accounts(&conn, &p).unwrap();
        assert_eq!((mine.len(), mine[0].balance), (1, usd(300)));
        assert!(my_youth_accounts(&conn, &s).unwrap().is_empty());
        assert!(matches!(youth_history(&conn, &s, &kid.account_number, 0), Err(AtmError::NotFound(_))));

        let looser = YouthControls {
            daily_withdraw_cap: usd(200),
            daily_transfer_cap: usd(50),
            family_only_transfers: false,
        };
        assert!(set_controls(&mut conn, &s, &kid.account_number, looser).is_err());
        set_controls(&mut conn, &p, &kid.account_number, looser).unwrap();
        // Above the bank's $1,000 limit: refused.
        let silly = YouthControls { daily_withdraw_cap: usd(99_999), ..looser };
        assert!(matches!(
            set_controls(&mut conn, &p, &kid.account_number, silly),
            Err(AtmError::InvalidInput(_))
        ));

        set_frozen(&mut conn, &p, &kid.account_number, true).unwrap();
        let k = auth::login_customer(&mut conn, &kid.card_number, "2580").unwrap();
        assert!(matches!(
            customer::withdraw(&mut conn, &k, usd(20), twenties()),
            Err(AtmError::AccountFrozen)
        ));
        // Front ends can find out before the child picks bills.
        assert!(matches!(customer::check_withdrawal(&conn, &k, usd(20)), Err(AtmError::AccountFrozen)));
        assert!(matches!(
            customer::quote_withdrawal(&conn, &k, usd(20), twenties()),
            Err(AtmError::AccountFrozen)
        ));
        set_frozen(&mut conn, &p, &kid.account_number, false).unwrap();
        assert!(customer::withdraw(&mut conn, &k, usd(200), twenties()).is_ok());
        assert_eq!(youth_history(&conn, &p, &kid.account_number, 0).unwrap().len(), 1);
    }

    #[test]
    fn the_bank_and_the_guardian_each_lift_only_their_own_freeze() {
        let (mut conn, pat, _, kid) = family();
        let a = auth::login_admin(&mut conn, crate::auth::testing::ADMIN.0, crate::auth::testing::ADMIN.1)
            .unwrap();
        let p = auth::login_customer(&mut conn, &pat.card_number, "4821").unwrap();
        let k = auth::login_customer(&mut conn, &kid.card_number, "2580").unwrap();
        let frozen = |conn: &mut Atm| customer::is_frozen(conn, k.account_id()).unwrap();

        admin::set_frozen(&mut conn, &a, &kid.account_number, true).unwrap();
        assert!(matches!(
            set_frozen(&mut conn, &p, &kid.account_number, false),
            Err(AtmError::NotAllowed(_))
        ));
        assert!(frozen(&mut conn), "a guardian lifted the bank's freeze");
        assert!(my_youth_accounts(&conn, &p).unwrap()[0].bank_frozen);
        admin::set_frozen(&mut conn, &a, &kid.account_number, false).unwrap();
        assert!(!frozen(&mut conn));

        set_frozen(&mut conn, &p, &kid.account_number, true).unwrap();
        assert!(matches!(
            admin::set_frozen(&mut conn, &a, &kid.account_number, false),
            Err(AtmError::NotAllowed(_))
        ));
        assert!(frozen(&mut conn), "the bank's unfreeze lifted the guardian's freeze");
        // Both freezes on: the bank lifts its own, the guardian's stays.
        admin::set_frozen(&mut conn, &a, &kid.account_number, true).unwrap();
        admin::set_frozen(&mut conn, &a, &kid.account_number, false).unwrap();
        assert!(frozen(&mut conn));
        set_frozen(&mut conn, &p, &kid.account_number, false).unwrap();
        assert!(!frozen(&mut conn));
    }

    #[test]
    fn joint_holders_share_one_balance_and_one_daily_limit() {
        let mut conn = crate::Atm::in_memory().unwrap();
        let (admin, handler) = setup(&mut conn);
        cash::restock(&mut conn, &handler, Denomination::new(20).unwrap(), 100).unwrap();
        let a =
            admin::create_customer(&mut conn, &admin, "Ann Lee", "1980-01-01", "4821", usd(3000)).unwrap();
        let b = admin::add_joint_holder(
            &mut conn,
            &admin,
            &a.account_number,
            CardAndPin { card_number: &a.card_number, pin: "4821" },
            "Ben Lee",
            "1981-02-02",
            "7305",
        )
        .unwrap();
        assert_eq!(a.account_number, b.account_number);
        assert_ne!(a.card_number, b.card_number);
        // Third holder and minors are refused.
        assert!(
            admin::add_joint_holder(
                &mut conn,
                &admin,
                &a.account_number,
                CardAndPin { card_number: &a.card_number, pin: "4821" },
                "Cy Lee",
                "1982-03-03",
                "9512"
            )
            .is_err()
        );

        let ann = auth::login_customer(&mut conn, &a.card_number, "4821").unwrap();
        let ben = auth::login_customer(&mut conn, &b.card_number, "7305").unwrap();
        customer::withdraw(&mut conn, &ann, usd(600), twenties()).unwrap();
        assert_eq!(customer::balance(&conn, &ben).unwrap(), usd(2400));
        // Ben can't use a "fresh" $1,000: the limit is per account.
        assert!(matches!(
            customer::withdraw(&mut conn, &ben, usd(500), twenties()),
            Err(AtmError::LimitExceeded { .. })
        ));
        // Ben's own wrong PINs lock only Ben's card.
        for _ in 0..3 {
            let _ = auth::login_customer(&mut conn, &b.card_number, "0000");
        }
        assert!(auth::login_customer(&mut conn, &a.card_number, "4821").is_ok());
        // Each holder is named separately in the log.
        let rows = admin::audit_for_account(&conn, &admin, &a.account_number, 0).unwrap();
        assert!(rows.iter().any(|r| r.actor == ann.actor()));
        assert!(rows.iter().any(|r| r.actor == ben.actor()));
        assert_ne!(ann.actor(), ben.actor());
    }
}
