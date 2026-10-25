//! DEMO builds only: the wallet of sample cards on the welcome screen.
//!
//! Clicking a card stands in for inserting it: its number goes straight to
//! the PIN screen, so testers only type the PIN. A staff badge fills in the
//! staff ID; the password is still typed. Cards show only their last 4
//! digits and no PIN (the demo PINs are in the user guide). Where a teller
//! form or a transfer needs another customer's number, a "Demo customer"
//! picker fills it in, as the customer handing over their card would.
//! The real build has no wallet and no list of cards.

use std::rc::Rc;

use atm::Atm;
use atm::customer::{RecentPayee, mask};
use atm::demo::{self, HANDLER, TELLER};
use atm::error::AtmError;
use atm::fx::Currency;
use atm::money::Cents;
use slint::{ComponentHandle, SharedString};

use crate::{App, AppWindow, Bank, STAFF_HALTED, screen, strings};

/// What one wallet item does when clicked.
pub enum Item {
    /// A customer card: full card and account numbers (never shown), name.
    Card { card: String, account: String, who: &'static str, guest: bool },
    /// A staff badge: role (1 Teller Admin, 2 Cash Handler) and staff ID.
    Badge(i32, &'static str),
}

/// Last 4 digits only, the way a real card shows it.
fn ending(number: &str) -> String {
    format!("ending {}", &number[number.len().saturating_sub(4)..])
}

/// Creates the demo data on first run (or re-reads it), and returns the
/// wallet items plus what each one shows: [line 1, line 2, line 3, line 4, tone].
pub fn load(atm: &mut Atm) -> Result<(Vec<Item>, Vec<Vec<String>>), AtmError> {
    let logins = if atm.needs_setup()? { demo::seed(atm)? } else { demo::cheat_sheet(atm)? };
    let mut items = Vec::new();
    let mut rows = Vec::new();
    for l in logins {
        // Guest cards are another bank's: no account here to transfer to.
        let (account, tone) = if l.guest {
            ("issued by another bank".into(), "1")
        } else {
            (format!("Account {}", ending(&l.account)), "0")
        };
        rows.push(vec![
            l.who.into(),
            l.label.into(),
            format!("Card {}", ending(&l.card)),
            account,
            tone.into(),
        ]);
        items.push(Item::Card { card: l.card, account: l.account, who: l.who, guest: l.guest });
    }
    for (role, title, (id, _)) in [(1, "Teller Admin", TELLER), (2, "Cash Handler", HANDLER)] {
        rows.push(vec![
            title.into(),
            format!("Staff badge: {id}"),
            "Password: see the".into(),
            "user guide".into(),
            "2".into(),
        ]);
        items.push(Item::Badge(role, id));
    }
    Ok((items, rows))
}

/// Our own customers (not other banks' cards): (name, card, account).
fn customers(items: &[Item]) -> impl Iterator<Item = (&'static str, &str, &str)> {
    items.iter().filter_map(|i| match i {
        Item::Card { card, account, who, guest: false } => Some((*who, card.as_str(), account.as_str())),
        _ => None,
    })
}

/// Names for the "Demo customer" pickers.
pub fn names(items: &[Item]) -> Vec<String> {
    customers(items).map(|(who, _, _)| who.to_string()).collect()
}

/// Demo payees for the transfer screen: every other sample account, masked,
/// with initials like a real recent payee.
pub fn payees(items: &[Item], own_account: &str) -> Vec<RecentPayee> {
    let mut seen = Vec::new();
    customers(items)
        .filter(|(_, _, account)| *account != own_account)
        .filter(|(_, _, account)| {
            let new = !seen.contains(account);
            seen.push(*account);
            new
        })
        .map(|(who, _, account)| RecentPayee {
            number: account.to_string(),
            masked: mask(account),
            initials: who
                .split_whitespace()
                .filter_map(|w| w.chars().next())
                .map(|c| format!("{c}."))
                .collect::<Vec<_>>()
                .join(" "),
            currency: Currency::Usd,
            last_amount: Cents::ZERO,
            last_date: String::new(),
        })
        .collect()
}

pub fn connect(app: &Rc<App>, window: &AppWindow) {
    let a = app.clone();
    window.global::<Bank>().on_insert_card(move |i| {
        a.touch();
        a.insert(i);
    });
    // A picker asks for customer i's card number, or account number.
    let a = app.clone();
    window.global::<Bank>().on_demo_number(move |account, i| {
        let st = a.state();
        let found = usize::try_from(i).ok().and_then(|i| customers(&st.wallet).nth(i));
        let number = found.map(|(_, card, acct)| if account { acct } else { card }).unwrap_or_default();
        SharedString::from(number)
    });
    window.global::<Bank>().set_demo_names(strings(names(&app.state().wallet)));
}

impl App {
    /// "Inserts" wallet item `i`. Only on the welcome screen, with nobody signed in.
    fn insert(&self, i: i32) {
        let mut st = self.state();
        let window = self.window();
        let bank = window.global::<Bank>();
        let signed_in = st.customer.is_some() || st.admin.is_some() || st.handler.is_some();
        if signed_in || bank.get_screen() != screen::WELCOME {
            return;
        }
        let item = usize::try_from(i).ok().and_then(|i| st.wallet.get(i));
        match item {
            // Out of service: no cards, and only the Teller Admin badge works.
            Some(Item::Card { .. }) if self.out_of_service() => self.error(AtmError::OutOfService),
            Some(Item::Badge(role, _)) if *role != 1 && self.out_of_service() => self.error(STAFF_HALTED),
            Some(Item::Card { card, .. }) => {
                st.login_card = Some(card.clone());
                self.ask_pin(&mut st);
            }
            Some(Item::Badge(role, id)) => {
                bank.set_staff_prefill((*id).into());
                bank.set_staff_role(*role);
                self.show(screen::STAFF_LOGIN);
            }
            None => {}
        }
    }
}
