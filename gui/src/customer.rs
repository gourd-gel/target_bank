//! Customer side: card, PIN, menu, every transaction, and the Family screen.
//!
//! Flow of a withdrawal, for example:
//!   menu("withdraw") -> Fast Cash screen -> fast_cash(60)
//!   -> Bills screen  -> choose_bill(2)   (library quotes the exact bills)
//!   -> Confirm screen -> confirm(true)
//!   -> "Would you like a receipt?" -> receipt_choice(2) -> `customer::withdraw`
//!   -> session ends -> "Take your card" -> "Take your cash" -> receipt
//! Deposits and transfers ask about the receipt too, then show the result
//! and stay logged in.

use std::rc::Rc;

use atm::audit::Row;
use atm::auth;
use atm::customer::{self, HISTORY_PAGE, Receipt, mask};
use atm::db::Limit;
use atm::dispense::{BillChoice, MAX_BILLS};
use atm::error::AtmError;
use atm::family::{self, Direction, YouthControls};
use atm::fx::{Currency, SumLine};
use atm::money::{Cents, DENOMINATIONS, Denomination};
use slint::{ComponentHandle, ModelRc, VecModel};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    App, AppWindow, Bank, Pending, Purpose, State, SumRow, bills_text, capitalize, ends_session, plain,
    screen, strings, table, time, typed_amount,
};

/// Index of the "Fewest bills" tile on the Bills screen.
const FEWEST_BILLS: i32 = 5;
/// The Bills screen asks Rust to re-label the tiles (mix toggle changed).
const REDRAW_BILLS: i32 = -1;

pub fn connect(app: &Rc<App>, window: &AppWindow) {
    let bank = window.global::<Bank>();

    let a = app.clone();
    bank.on_start_customer(move || {
        a.touch();
        // Out of service: no cards at all.
        if a.out_of_service() {
            a.error(AtmError::OutOfService);
            return;
        }
        let mut st = a.state();
        st.login_card = None;
        a.open_entry(&mut st, Purpose::Card, "Enter your card number", "The 10 digits printed on your card.");
    });

    let a = app.clone();
    bank.on_key(move |key| {
        a.touch();
        a.key(&key);
    });

    let a = app.clone();
    bank.on_enter(move || {
        a.touch();
        a.enter();
    });

    let a = app.clone();
    bank.on_cancel(move || {
        a.touch();
        a.cancel();
    });

    let a = app.clone();
    bank.on_menu(move |choice| {
        a.touch();
        a.menu(&choice);
    });

    let a = app.clone();
    bank.on_fast_cash(move |dollars| {
        a.touch();
        a.fast_cash(dollars);
    });

    let a = app.clone();
    bank.on_choose_bill(move |index| {
        a.touch();
        a.choose_bill(index);
    });

    let a = app.clone();
    bank.on_confirm(move |yes| {
        a.touch();
        a.confirm(yes);
    });

    let a = app.clone();
    bank.on_receipt_choice(move |choice| {
        a.touch();
        a.receipt_choice(choice);
    });

    let a = app.clone();
    bank.on_take_card(move || {
        a.touch();
        a.take_card();
    });

    let a = app.clone();
    bank.on_take_cash(move || {
        a.touch();
        a.take_cash();
    });

    let a = app.clone();
    bank.on_finish(move || {
        let mut st = a.state();
        a.go_welcome(&mut st, "Thank you for banking with Bank of CCNY.");
    });

    let a = app.clone();
    bank.on_confirm_extra_clicked(move || {
        a.touch();
        a.add_more_bills();
    });

    let a = app.clone();
    bank.on_history_turn(move |step| {
        a.touch();
        let mut st = a.state();
        let page = st.history_page.saturating_add_signed(step);
        a.show_history(&mut st, page);
    });

    let a = app.clone();
    bank.on_youth_select(move |row| {
        a.touch();
        a.youth_select(row);
    });

    let a = app.clone();
    bank.on_youth_save(move |w, t, family_only| {
        a.touch();
        a.youth_save(&w, &t, family_only);
    });

    let a = app.clone();
    bank.on_youth_freeze(move |frozen| {
        a.touch();
        a.youth_freeze(frozen);
    });

    let a = app.clone();
    bank.on_youth_move(move |amount, to_child| {
        a.touch();
        a.youth_move(amount.trim(), to_child);
    });

    let a = app.clone();
    bank.on_entry_choice(move |i| {
        a.touch();
        a.send_again(i);
    });
}

impl App {
    // -----------------------------------------------------------------------
    // Keypad
    // -----------------------------------------------------------------------

    fn key(&self, key: &str) {
        let mut st = self.state();
        match key {
            "clear" => st.entry.zeroize(),
            "back" => {
                st.entry.pop();
            }
            k if k.len() == 1 && k.as_bytes()[0].is_ascii_digit() => {
                if st.entry.len() >= st.purpose.max_digits() {
                    return;
                }
                st.entry.push_str(k);
            }
            _ => return, // letters, arrows: ignore
        }
        self.window().global::<Bank>().set_message("".into());
        self.show_entry(&st);
    }

    /// ENTER on the keypad: what it does depends on what is being typed.
    fn enter(&self) {
        let mut st = self.state();
        let st = &mut *st;
        // Take the digits out of the buffer (it is now empty); `typed` wipes itself.
        let typed = std::mem::take(&mut st.entry);
        self.show_entry(st);
        let digits: &str = &typed;

        match st.purpose {
            Purpose::Card => match atm::input::validate_number10(digits) {
                Ok(()) => {
                    st.login_card = Some(digits.to_string());
                    self.ask_pin(st);
                }
                Err(_) => self.error("Card numbers are 10 digits."),
            },

            Purpose::Pin => self.login(st, typed),

            Purpose::WithdrawAmount => match digits.parse::<u32>() {
                Ok(dollars) if dollars > 0 => self.withdraw_amount(st, Cents::from_dollars(dollars)),
                _ => self.error("Enter an amount in whole dollars."),
            },

            Purpose::DepositCount => match digits.parse::<u32>() {
                Ok(count) if count > 0 => {
                    if let Pending::Deposit { bills, current: Some(bill) } = &mut st.pending {
                        bills.retain(|(d, _)| d != bill); // re-counting a bill replaces it
                        bills.push((*bill, count));
                        bills.sort_by_key(|&(d, _)| std::cmp::Reverse(d));
                    }
                    self.confirm_deposit(st);
                }
                _ => self.error("Enter how many bills (at least 1)."),
            },

            Purpose::TransferTo => {
                let Some(session) = &st.customer else { return };
                // Checks the account exists now, before any amount is typed.
                // Unknown numbers count toward the 3-strike limit in the library.
                let hint = customer::recipient_hint(&mut self.atm(), session, digits);
                match hint {
                    Ok(hint) => {
                        st.pending =
                            Pending::Transfer { to: digits.to_string(), hint: hint.clone(), amount: None };
                        self.open_entry(
                            st,
                            Purpose::TransferAmount,
                            "How much would you like to send?",
                            &format!("To account {} ({hint})", mask(digits)),
                        );
                    }
                    Err(e) => self.fail(st, e),
                }
            }

            Purpose::TransferAmount => {
                let amount = typed_amount(digits, st.currency);
                let Pending::Transfer { to, hint, amount: slot } = &mut st.pending else { return };
                match amount {
                    Some(amount) if !amount.is_zero() => {
                        *slot = Some(amount);
                        let lines = vec![
                            format!("Amount: {}", st.currency.format(amount)),
                            format!("To account: {} ({hint})", mask(to)),
                        ];
                        self.ask_confirm("Send this transfer?", lines, "");
                    }
                    _ => self.error("Enter an amount greater than $0.00."),
                }
            }

            Purpose::PinCurrent => {
                st.pending = Pending::ChangePin { current: Some(typed), new: None };
                self.open_entry(
                    st,
                    Purpose::PinNew,
                    "Choose a new PIN",
                    "4 to 12 digits. No 1234, 0000 or birthdays.",
                );
            }

            Purpose::PinNew => {
                if let Pending::ChangePin { new, .. } = &mut st.pending {
                    *new = Some(typed);
                }
                self.open_entry(
                    st,
                    Purpose::PinRepeat,
                    "Enter the new PIN again",
                    "To make sure it was typed correctly.",
                );
            }

            Purpose::PinRepeat => {
                let Pending::ChangePin { current: Some(current), new: Some(new) } =
                    std::mem::take(&mut st.pending)
                else {
                    return;
                };
                if *new != *typed {
                    st.pending = Pending::ChangePin { current: Some(current), new: None };
                    self.open_entry(
                        st,
                        Purpose::PinNew,
                        "Choose a new PIN",
                        "4 to 12 digits. No 1234, 0000 or birthdays.",
                    );
                    return self.error("The two new PINs did not match. Please choose it again.");
                }
                let Some(session) = &st.customer else { return };
                let changed = customer::change_pin(&mut self.atm(), session, &current, &new);
                match changed {
                    Ok(()) => self.result(true, "PIN changed", vec!["Use your new PIN next time.".into()]),
                    // Wrong current PIN: counted toward the lock-out by the library.
                    Err(AtmError::AuthFailed) => self.result(
                        false,
                        "PIN not changed",
                        vec!["The current PIN was wrong. 3 wrong PINs in a row lock the card.".into()],
                    ),
                    Err(e) if !ends_session(&e) => self.result(false, "PIN not changed", vec![e.to_string()]),
                    Err(e) => self.fail(st, e),
                }
            }
        }
    }

    /// PIN screen for the card in `st.login_card` (typed or inserted).
    pub fn ask_pin(&self, st: &mut State) {
        let card = st.login_card.as_deref().unwrap_or_default();
        let last4 = &card[card.len().saturating_sub(4)..];
        let hint = format!("Card ending in {last4}. Shield the keypad with your hand.");
        self.open_entry(st, Purpose::Pin, "Enter your PIN", &hint);
    }

    fn login(&self, st: &mut State, pin: Zeroizing<String>) {
        let Some(card) = st.login_card.clone() else { return self.go_welcome(st, "") };
        let logged_in = auth::login_customer(&mut self.atm(), &card, &pin);
        drop(pin); // wiped now
        match logged_in {
            Ok(session) => {
                st.customer = Some(session);
                st.login_card = None;
                self.refresh_account_header(st);
                self.show(screen::MENU);
            }
            // Locked, frozen by the bank, or the ATM went out of service: the card is "returned".
            Err(e @ (AtmError::CardLocked | AtmError::FrozenByBank | AtmError::OutOfService)) => {
                self.go_welcome(st, &e.to_string());
                self.window().global::<Bank>().set_message_ok(false);
            }
            // Wrong PIN or unknown card: the library deliberately won't say which.
            Err(AtmError::AuthFailed) => self.error("Login failed. Check the card number and PIN."),
            Err(e) => self.error(e),
        }
    }

    /// Name, masked account, type, frozen flag, Family button.
    fn refresh_account_header(&self, st: &mut State) {
        let Some(session) = &st.customer else { return };
        let info = customer::account_info(&self.atm(), session);
        match info {
            Ok(info) => {
                let window = self.window();
                let bank = window.global::<Bank>();
                bank.set_holder(info.holder_name.into());
                bank.set_account_masked(info.account.into());
                let kind = match info.currency {
                    Currency::Usd => capitalize(&info.kind),
                    other => format!("{} {}", capitalize(&info.kind), other.code()),
                };
                bank.set_account_kind(kind.into());
                bank.set_account_currency(info.currency.code().into());
                let mut note = match info.atm_fee {
                    Some(fee) => format!(
                        "This card is from another bank. Each withdrawal here has an ATM fee of {}. ",
                        fee.short()
                    ),
                    None => String::new(),
                };
                match (info.currency, info.rate) {
                    (Currency::Usd, _) => {}
                    (_, Some(rate)) => note += &format!("Cash is paid in US dollars. Today's rate: {rate}."),
                    (_, None) => {
                        note += "Cash is paid in US dollars. No current exchange rate: please see a teller."
                    }
                }
                bank.set_balance_note(note.trim_end().into());
                bank.set_is_guest(info.kind == "guest");
                st.currency = info.currency;
                bank.set_frozen(info.frozen);
                bank.set_on_hold(info.on_hold);
                bank.set_is_guardian(info.youth_accounts > 0);
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// CANCEL: during login it returns the card; otherwise back to the menu.
    fn cancel(&self) {
        let mut st = self.state();
        let st = &mut *st;
        st.entry.zeroize();
        if st.customer.is_some() {
            st.pending = Pending::None;
            self.show(screen::MENU);
        } else if st.admin.is_none() && st.handler.is_none() {
            self.go_welcome(st, "");
        }
    }

    // -----------------------------------------------------------------------
    // Menu
    // -----------------------------------------------------------------------

    fn menu(&self, choice: &str) {
        let mut st = self.state();
        let st = &mut *st;
        if choice == "logout" {
            return self.go_welcome(st, "Thank you for banking with Bank of CCNY. Please take your card.");
        }
        st.pending = Pending::None;
        let Some(session) = &st.customer else {
            return self.go_welcome(st, "");
        };
        let window = self.window();
        let bank = window.global::<Bank>();

        match choice {
            "menu" => {
                self.refresh_account_header(st);
                self.show(screen::MENU);
            }
            "withdraw" => self.show(screen::FAST_CASH),
            "fast60" => {
                st.pending = Pending::Withdraw { amount: Cents::from_dollars(60), choice: None };
                self.quote(st, BillChoice::Only(bill(20)));
            }
            "deposit" => {
                st.pending = Pending::Deposit { bills: Vec::new(), current: None };
                self.show_deposit_bills(st);
            }
            "transfer" => {
                // Send again: show only the masked number and initials. (A
                // failure here just means no shortcuts; the transfer re-checks.)
                #[allow(unused_mut)]
                let mut recent = customer::recent_payees(&self.atm(), session).unwrap_or_default();
                // Demo builds: the other demo accounts too, so nobody types 10 digits.
                #[cfg(feature = "demo")]
                {
                    let known: Vec<String> = recent.iter().map(|p| p.number.clone()).collect();
                    let demo = crate::wallet::payees(&st.wallet, session.account_number());
                    recent.extend(demo.into_iter().filter(|p| !known.contains(&p.number)));
                }
                self.open_entry(
                    st,
                    Purpose::TransferTo,
                    "Who are you sending money to?",
                    "Enter their 10-digit account number.",
                );
                let labels = recent.iter().map(|p| format!("{}   {}", p.masked, p.initials)).collect();
                bank.set_entry_choices(strings(labels));
                st.recent = recent;
            }
            "balance" => {
                let balance = customer::balance(&self.atm(), session);
                match balance {
                    Ok(balance) => {
                        bank.set_balance(st.currency.format(balance).into());
                        self.show(screen::BALANCE);
                    }
                    Err(e) => self.fail(st, e),
                }
            }
            "history" => self.show_history(st, 0),
            "limits" => {
                let limits = customer::limits(&self.atm(), session);
                match limits {
                    Ok(limits) => {
                        let rows = limits
                            .into_iter()
                            .map(|l| {
                                // A teller may have approved extra for today.
                                let allowed = l.per_day.checked_add(l.approved_today).unwrap_or(l.per_day);
                                let used = allowed.checked_sub(l.remaining_today).unwrap_or(Cents::ZERO);
                                let per_day = if l.approved_today.is_zero() {
                                    l.per_day.to_string()
                                } else {
                                    format!("{} + {} today", l.per_day, l.approved_today)
                                };
                                let label = match l.limit {
                                    Limit::Withdrawal => "Withdrawals",
                                    Limit::Deposit => "Deposits",
                                    Limit::Transfer => "Transfers",
                                };
                                vec![label.into(), per_day, used.to_string(), l.remaining_today.to_string()]
                            })
                            .collect();
                        bank.set_limit_rows(table(rows));
                        self.show(screen::LIMITS);
                    }
                    Err(e) => self.fail(st, e),
                }
            }
            "pin" => self.open_entry(
                st,
                Purpose::PinCurrent,
                "Enter your current PIN",
                "Wrong guesses count toward the 3-try lock.",
            ),
            "family" => self.show_family(st, None),
            _ => {}
        }
    }

    fn show_history(&self, st: &mut State, page: u32) {
        let Some(session) = &st.customer else { return };
        let rows = customer::history(&self.atm(), session, page);
        match rows {
            Ok(rows) => {
                let window = self.window();
                let bank = window.global::<Bank>();
                bank.set_history_more(rows.len() == HISTORY_PAGE as usize);
                bank.set_history_rows(table(history_rows(&rows, session.account_number())));
                bank.set_history_page(page as i32);
                st.history_page = page;
                if bank.get_screen() != screen::HISTORY {
                    self.show(screen::HISTORY);
                }
            }
            Err(e) => self.fail(st, e),
        }
    }

    // -----------------------------------------------------------------------
    // Withdraw and deposit
    // -----------------------------------------------------------------------

    fn fast_cash(&self, dollars: i32) {
        let mut st = self.state();
        let st = &mut *st;
        match u32::try_from(dollars) {
            Ok(0) | Err(_) => self.open_entry(
                st,
                Purpose::WithdrawAmount,
                "Enter an amount",
                "Whole dollars, in multiples of $5.",
            ),
            Ok(d) => self.withdraw_amount(st, Cents::from_dollars(d)),
        }
    }

    /// Amount chosen: show the bill choices.
    fn withdraw_amount(&self, st: &mut State, amount: Cents) {
        if amount.as_i64() % 500 != 0 {
            return self.error("Amounts must be a multiple of $5.");
        }
        let Some(session) = &st.customer else { return };
        // Frozen, balance and daily limit first, before the customer picks bills.
        let allowed = customer::check_withdrawal(&self.atm(), session, amount);
        match allowed {
            Ok(_) => {
                st.pending = Pending::Withdraw { amount, choice: None };
                self.show_withdraw_bills(amount);
            }
            Err(e) if ends_session(&e) => self.fail(st, e),
            Err(e) => {
                if self.window().global::<Bank>().get_screen() != screen::ENTRY {
                    self.show(screen::FAST_CASH);
                }
                self.error(e);
            }
        }
    }

    /// Bills screen for a withdrawal. Without "mix", only bills that divide
    /// the amount exactly (the spec's single-bill rule) in at most 40 bills
    /// are offered.
    fn show_withdraw_bills(&self, amount: Cents) {
        let window = self.window();
        let bank = window.global::<Bank>();
        let mix = bank.get_bills_allow_mix();
        bank.set_bills_withdrawing(true);
        bank.set_bills_title(format!("How would you like your {amount}?").into());
        bank.set_bills_hint(
            if mix {
                "As many of the bill you pick as possible; the rest in the fewest other bills."
            } else {
                "All in one bill type. Bills that can't make this amount, or would take over 40, are greyed out."
            }
            .into(),
        );
        let fits = |d: Denomination| d.bills_for(amount).is_some_and(|n| n <= MAX_BILLS);
        bank.set_bill_enabled(ModelRc::new(VecModel::from(
            Denomination::all().map(|d| mix || fits(d)).collect::<Vec<_>>(),
        )));
        bank.set_bill_captions(strings(
            Denomination::all()
                .map(|d| match d.bills_for(amount) {
                    _ if mix => "Mostly these".to_string(),
                    Some(n) if n > MAX_BILLS => format!("Over {MAX_BILLS} bills"),
                    Some(n) => format!("{n} bill{}", if n == 1 { "" } else { "s" }),
                    None => "Not available".to_string(),
                })
                .collect(),
        ));
        self.show(screen::BILLS);
    }

    fn show_deposit_bills(&self, st: &State) {
        let window = self.window();
        let bank = window.global::<Bank>();
        bank.set_bills_withdrawing(false);
        bank.set_bills_title("Which bills are you depositing?".into());
        bank.set_bills_hint("Pick a bill, then type how many. You can add other bills after.".into());
        bank.set_bill_enabled(ModelRc::new(VecModel::from(vec![true; DENOMINATIONS.len()])));
        let counted = |d: Denomination| match &st.pending {
            Pending::Deposit { bills, .. } => bills.iter().find(|(b, _)| *b == d).map(|(_, n)| *n),
            _ => None,
        };
        bank.set_bill_captions(strings(
            Denomination::all()
                .map(|d| counted(d).map(|n| format!("{n} counted")).unwrap_or_default())
                .collect(),
        ));
        self.show(screen::BILLS);
    }

    fn choose_bill(&self, index: i32) {
        let mut st = self.state();
        let st = &mut *st;
        let picked = usize::try_from(index).ok().and_then(|i| DENOMINATIONS.get(i)).map(|&d| bill(d));
        match &mut st.pending {
            Pending::Withdraw { amount, .. } => {
                let amount = *amount;
                let mix = self.window().global::<Bank>().get_bills_allow_mix();
                match (index, picked) {
                    (REDRAW_BILLS, _) => self.show_withdraw_bills(amount),
                    (FEWEST_BILLS, _) => self.quote(st, BillChoice::Any),
                    (_, Some(d)) if mix => self.quote(st, BillChoice::Prefer(d)),
                    (_, Some(d)) => self.quote(st, BillChoice::Only(d)),
                    _ => {}
                }
            }
            Pending::Deposit { current, .. } => {
                let Some(d) = picked else { return };
                *current = Some(d);
                self.open_entry(
                    st,
                    Purpose::DepositCount,
                    &format!("How many ${} bills?", d.dollars()),
                    "Count the bills, then type the number (up to 200).",
                );
            }
            _ => self.show(screen::MENU),
        }
    }

    /// Ask the library which bills it would pay, then confirm. If the machine
    /// can't, stay on the Bills screen with its message (spec: name the
    /// bills that are available).
    fn quote(&self, st: &mut State, choice: BillChoice) {
        let Pending::Withdraw { amount, choice: slot } = &mut st.pending else { return };
        let amount = *amount;
        let Some(session) = &st.customer else { return };
        let quoted = {
            let atm = self.atm();
            customer::quote_withdrawal(&atm, session, amount, choice)
                .and_then(|plan| Ok((plan, customer::check_withdrawal(&atm, session, amount)?)))
        };
        match quoted {
            Ok((plan, charge)) => {
                *slot = Some(choice);
                // Bills, then cash + each fee = total, fee rules in small print.
                let lines = vec![format!("Paid as {}", bills_text(&plan))];
                self.ask_confirm_sum(
                    "Withdraw this cash?",
                    lines,
                    &charge.summary(false),
                    &charge.fine_print(),
                    "",
                );
            }
            Err(e @ (AtmError::DenominationUnavailable { .. } | AtmError::TooManyBills { .. })) => {
                self.show_withdraw_bills(amount);
                self.error(e);
            }
            Err(e) => self.fail(st, e),
        }
    }

    fn confirm_deposit(&self, st: &State) {
        let Pending::Deposit { bills, .. } = &st.pending else { return };
        let mut total = Cents::ZERO;
        let mut lines = Vec::new();
        for &(d, n) in bills {
            let value = d.times(i64::from(n)).unwrap_or(Cents::ZERO);
            total = total.checked_add(value).unwrap_or(total);
            lines.push(format!("{n} × ${} = {value}", d.dollars()));
        }
        // Cash - any fee = total (and what the account receives, if converted).
        let preview = st.customer.as_ref().map(|s| customer::preview_deposit(&self.atm(), s, total));
        match preview {
            Some(Ok(credit)) => {
                let (sum, note) = (credit.summary(true), credit.fine_print());
                self.ask_confirm_sum("Deposit this cash?", lines, &sum, &note, "Add other bills");
            }
            other => {
                lines.push(format!("Total: {total}"));
                // No usable rate: say so now rather than after the bills go in.
                if let Some(Err(e)) = other {
                    lines.push(e.to_string());
                }
                self.ask_confirm("Deposit this cash?", lines, "Add other bills");
            }
        }
    }

    /// "Add other bills" on the deposit confirmation.
    fn add_more_bills(&self) {
        let st = self.state();
        if matches!(st.pending, Pending::Deposit { .. }) {
            self.show_deposit_bills(&st);
        }
    }

    // -----------------------------------------------------------------------
    // Confirm and result
    // -----------------------------------------------------------------------

    fn ask_confirm(&self, title: &str, lines: Vec<String>, extra: &str) {
        self.ask_confirm_sum(title, lines, &[], "", extra);
    }

    /// Confirm with a charge summary (cash + fees = total) under the lines.
    fn ask_confirm_sum(&self, title: &str, lines: Vec<String>, sum: &[SumLine], note: &str, extra: &str) {
        let window = self.window();
        let bank = window.global::<Bank>();
        bank.set_confirm_title(title.into());
        bank.set_confirm_lines(strings(lines));
        set_sum(&bank, sum, note);
        bank.set_confirm_extra(extra.into());
        self.show(screen::CONFIRM);
    }

    fn result(&self, ok: bool, title: &str, lines: Vec<String>) {
        self.result_sum(ok, title, &[], "", lines);
    }

    /// Result (receipt) with a charge summary above the lines.
    fn result_sum(&self, ok: bool, title: &str, sum: &[SumLine], note: &str, lines: Vec<String>) {
        let window = self.window();
        let bank = window.global::<Bank>();
        bank.set_result_ok(ok);
        bank.set_result_final(false);
        bank.set_result_title(title.into());
        set_sum(&bank, sum, note);
        bank.set_result_lines(strings(lines));
        self.show(screen::RESULT);
    }

    /// Confirm: one more question before any money moves, like a real ATM.
    fn confirm(&self, yes: bool) {
        let mut st = self.state();
        let ready = match &st.pending {
            Pending::Withdraw { choice, .. } => choice.is_some(),
            Pending::Deposit { bills, .. } => !bills.is_empty(),
            Pending::Transfer { amount, .. } => amount.is_some(),
            _ => false,
        };
        if yes && ready {
            return self.show(screen::RECEIPT_ASK);
        }
        st.pending = Pending::None;
        self.show(screen::MENU);
    }

    /// "Would you like a receipt?" answered (0 = cancel, 1 = no, 2 = yes):
    /// now the money moves.
    fn receipt_choice(&self, choice: i32) {
        let mut st = self.state();
        let st = &mut *st;
        let pending = std::mem::take(&mut st.pending);
        if choice == 0 {
            return self.show(screen::MENU);
        }
        let printed = choice == 2;
        let Some(session) = &st.customer else {
            return self.go_welcome(st, "");
        };
        let outcome = {
            let mut atm = self.atm();
            match &pending {
                Pending::Withdraw { amount, choice: Some(choice) } => Some((
                    "Please take your cash",
                    "Withdrawal",
                    customer::withdraw(&mut atm, session, *amount, *choice),
                )),
                Pending::Deposit { bills, .. } if !bills.is_empty() => {
                    Some(("Deposit received", "Deposit", customer::deposit(&mut atm, session, bills)))
                }
                Pending::Transfer { to, amount: Some(amount), .. } => Some((
                    "Transfer complete",
                    "Transfer",
                    customer::transfer(&mut atm, session, to, *amount),
                )),
                _ => None,
            }
        };
        match outcome {
            Some((_, "Withdrawal", Ok(receipt))) => self.return_card(st, receipt, printed),
            Some((title, _, Ok(receipt))) => {
                let note = if printed { receipt.fine_print.as_str() } else { "" };
                self.result_sum(true, title, &receipt.summary, note, receipt_lines(&receipt, printed));
                self.refresh_account_header(st);
            }
            // Machine ran short since the quote: let the customer pick again.
            Some((
                _,
                _,
                Err(e @ (AtmError::DenominationUnavailable { .. } | AtmError::TooManyBills { .. })),
            )) => {
                if let Pending::Withdraw { amount, .. } = pending {
                    st.pending = Pending::Withdraw { amount, choice: None };
                    self.show_withdraw_bills(amount);
                }
                self.error(e);
            }
            Some((_, what, Err(e))) if !ends_session(&e) => {
                self.result(false, &format!("{what} not completed"), vec![e.to_string()]);
            }
            Some((_, _, Err(e))) => self.fail(st, e),
            None => self.show(screen::MENU),
        }
    }

    /// Withdrawal done: the session ends and the card comes back before the
    /// cash, because people who already have their money tend to walk off
    /// without the card (SEv3 §3.2.1, post-completion errors).
    fn return_card(&self, st: &mut State, receipt: Receipt, printed: bool) {
        self.go_welcome(st, ""); // logs out (audited) and clears the customer's details
        self.window().global::<Bank>().set_cash_bills(bills_text(&receipt.bills).into());
        st.cash_out = Some((receipt, printed));
        self.show(screen::TAKE_CARD);
    }

    fn take_card(&self) {
        let mut st = self.state();
        if st.cash_out.is_some() {
            self.show(screen::TAKE_CASH);
        } else {
            self.go_welcome(&mut st, "");
        }
    }

    /// Cash taken: the receipt if they asked for one, else the welcome screen.
    fn take_cash(&self) {
        let mut st = self.state();
        match st.cash_out.take() {
            Some((receipt, true)) => {
                let lines = receipt_lines(&receipt, true);
                self.result_sum(true, "Your receipt", &receipt.summary, &receipt.fine_print, lines);
                self.window().global::<Bank>().set_result_final(true);
            }
            _ => self.go_welcome(&mut st, "Thank you for banking with Bank of CCNY."),
        }
    }

    // -----------------------------------------------------------------------
    // Family (guardian controls)
    // -----------------------------------------------------------------------

    /// Loads the youth accounts this card is a guardian of; re-selects `keep`.
    fn show_family(&self, st: &mut State, keep: Option<usize>) {
        let Some(session) = &st.customer else { return };
        let kids = family::my_youth_accounts(&self.atm(), session);
        match kids {
            Ok(kids) => {
                let rows = kids
                    .iter()
                    .map(|k| {
                        vec![
                            k.child_name.clone(),
                            mask(&k.account_number),
                            k.balance.to_string(),
                            format!("{}/day", k.controls.daily_withdraw_cap),
                            format!("{}/day", k.controls.daily_transfer_cap),
                            if k.controls.family_only_transfers { "Family only" } else { "Anyone" }.into(),
                            if k.bank_frozen {
                                "Frozen by the bank"
                            } else if k.frozen {
                                "FROZEN"
                            } else {
                                "Active"
                            }
                            .into(),
                        ]
                    })
                    .collect();
                st.youth = kids;
                let window = self.window();
                let bank = window.global::<Bank>();
                bank.set_youth_rows(table(rows));
                bank.set_youth_selected(-1);
                if bank.get_screen() != screen::FAMILY {
                    self.show(screen::FAMILY);
                }
                if let Some(i) = keep {
                    self.select_youth(st, i);
                }
            }
            Err(e) => self.fail(st, e),
        }
    }

    fn youth_select(&self, row: i32) {
        let mut st = self.state();
        if let Ok(i) = usize::try_from(row) {
            self.window().global::<Bank>().set_message("".into());
            self.select_youth(&mut st, i);
        }
    }

    fn select_youth(&self, st: &mut State, i: usize) {
        let Some(kid) = st.youth.get(i).cloned() else { return };
        let Some(session) = &st.customer else { return };
        let rows = family::youth_history(&self.atm(), session, &kid.account_number, 0);
        match rows {
            Ok(rows) => {
                let window = self.window();
                let bank = window.global::<Bank>();
                bank.set_youth_selected(i as i32);
                bank.set_youth_title(format!("{}: recent transactions", kid.child_name).into());
                bank.set_youth_history_rows(table(history_rows(&rows, &kid.account_number)));
                bank.set_youth_withdraw_cap(plain(kid.controls.daily_withdraw_cap).into());
                bank.set_youth_transfer_cap(plain(kid.controls.daily_transfer_cap).into());
                bank.set_youth_family_only(kid.controls.family_only_transfers);
                bank.set_youth_frozen(kid.frozen);
            }
            Err(e) => self.fail(st, e),
        }
    }

    fn selected_youth(&self, st: &State) -> Option<(usize, String)> {
        let i = usize::try_from(self.window().global::<Bank>().get_youth_selected()).ok()?;
        st.youth.get(i).map(|k| (i, k.account_number.clone()))
    }

    fn youth_save(&self, withdraw: &str, transfer: &str, family_only: bool) {
        let mut st = self.state();
        let st = &mut *st;
        let Some((i, number)) = self.selected_youth(st) else { return };
        let (w, t) = match (Cents::parse(withdraw.trim()), Cents::parse(transfer.trim())) {
            (Ok(w), Ok(t)) => (w, t),
            (Err(e), _) | (_, Err(e)) => return self.error(e),
        };
        let Some(session) = &st.customer else { return };
        let controls = YouthControls {
            daily_withdraw_cap: w,
            daily_transfer_cap: t,
            family_only_transfers: family_only,
        };
        let saved = family::set_controls(&mut self.atm(), session, &number, controls);
        match saved {
            Ok(()) => {
                self.show_family(st, Some(i));
                self.notice("Controls saved. The bank's own limits still apply on top.");
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// Send again: skip typing the number, go straight to the amount.
    fn send_again(&self, i: i32) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(p) = usize::try_from(i).ok().and_then(|i| st.recent.get(i)).cloned() else { return };
        st.pending = Pending::Transfer { to: p.number.clone(), hint: p.initials.clone(), amount: None };
        self.open_entry(
            st,
            Purpose::TransferAmount,
            "How much would you like to send?",
            &format!("To account {} ({})", p.masked, p.initials),
        );
    }

    /// Guardian moves money to the child's account or back to their own.
    fn youth_move(&self, typed: &str, to_child: bool) {
        let mut st = self.state();
        let st = &mut *st;
        let Some((i, number)) = self.selected_youth(st) else { return };
        let Some(amount) = st.currency.parse_amount(typed).ok().filter(|a| !a.is_zero()) else {
            return self.error("Enter an amount greater than zero.");
        };
        let Some(session) = &st.customer else { return };
        let direction = if to_child { Direction::ToChild } else { Direction::FromChild };
        let moved = family::move_money(&mut self.atm(), session, &number, direction, amount);
        match moved {
            Ok(m) => {
                self.show_family(st, Some(i));
                self.notice(format!(
                    "Moved {}. Your balance: {}. Child's balance: {}. Logged.",
                    m.currency.format(m.amount),
                    m.currency.format(m.your_balance),
                    m.currency.format(m.child_balance)
                ));
            }
            Err(e) => self.fail(st, e),
        }
    }

    fn youth_freeze(&self, frozen: bool) {
        let mut st = self.state();
        let st = &mut *st;
        let Some((i, number)) = self.selected_youth(st) else { return };
        let Some(session) = &st.customer else { return };
        let done = family::set_frozen(&mut self.atm(), session, &number, frozen);
        match done {
            Ok(()) => {
                self.show_family(st, Some(i));
                self.notice(if frozen {
                    "Account frozen: no withdrawals or transfers until you unfreeze it. Deposits still work."
                } else {
                    "Account unfrozen."
                });
            }
            Err(e) => self.fail(st, e),
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

fn bill(dollars: u32) -> Denomination {
    Denomination::new(dollars).expect("listed denomination")
}

/// History rows as the account holder sees them: direction and masked numbers.
fn history_rows(rows: &[Row], my_account: &str) -> Vec<Vec<String>> {
    rows.iter()
        .map(|r| {
            let amount = r.amount.map(|a| r.currency.format(a)).unwrap_or_default();
            let mine = r.account_number.as_deref() == Some(my_account);
            let by_guardian = if r.detail.starts_with("by guardian") { " (guardian)" } else { "" };
            let (what, sign) = match r.action.as_str() {
                "deposit" => (format!("Cash deposit ({})", r.detail), "+"),
                "withdrawal" => (format!("Cash withdrawal ({})", r.detail), "−"),
                "transfer" if mine => (
                    format!(
                        "Transfer to {}{by_guardian}",
                        mask(r.counterparty_number.as_deref().unwrap_or(""))
                    ),
                    "−",
                ),
                "transfer" => (
                    format!("Transfer from {}{by_guardian}", mask(r.account_number.as_deref().unwrap_or(""))),
                    "+",
                ),
                other => (capitalize(&other.replace('_', " ")), ""),
            };
            vec![time(&r.ts), what, format!("{sign}{amount}")]
        })
        .collect()
}

/// Receipt lines under the summary. A transfer has no summary, so its
/// amount comes first. Without a printed receipt, the balance and reference
/// number are left off the screen.
fn receipt_lines(r: &Receipt, printed: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if r.summary.is_empty() {
        lines.push(format!("{} of {}", capitalize(r.kind), r.currency.format(r.amount)));
    }
    if !r.bills.is_empty() {
        let label = if r.kind == "deposit" { "Bills" } else { "Paid as" };
        lines.push(format!("{label} {}", bills_text(&r.bills)));
    }
    if let Some(to) = &r.counterparty {
        lines.push(format!("To account {to}"));
    }
    if printed {
        lines.push(format!("Balance after: {}", r.currency.format(r.balance_after)));
        lines.push(format!("Receipt #{}  ·  {}  ·  account {}", r.reference, time(&r.timestamp), r.account));
    } else {
        lines.push("No receipt printed.".to_string());
    }
    lines
}

/// Fill the summary table: a rule above the first total row.
fn set_sum(bank: &Bank, sum: &[SumLine], note: &str) {
    let first_total = sum.iter().position(|l| l.total);
    let rows: Vec<SumRow> = sum
        .iter()
        .enumerate()
        .map(|(i, l)| SumRow {
            label: l.label.as_str().into(),
            amount: l.amount.as_str().into(),
            total: l.total,
            line_above: Some(i) == first_total,
        })
        .collect();
    bank.set_sum_rows(ModelRc::new(VecModel::from(rows)));
    bank.set_sum_note(note.into());
}
