//! Staff side: first-run setup, Teller Admin console, Cash Handler console.
//!
//! Every button here calls one library function that demands the matching
//! session (`AdminSession` / `HandlerSession`). The GUI only formats results.

use std::rc::Rc;

use atm::admin::{self, AUDIT_PAGE};
use atm::audit::Row;
use atm::auth::{self, CardAndPin};
use atm::cash;
use atm::customer::mask;
use atm::db::Limit;
use atm::error::AtmError;
use atm::fx::{self, Currency, Fee};
use atm::money::{Cents, Denomination};
use atm::rate_feed;
use atm::review;
use atm::service;
use slint::ComponentHandle;
use zeroize::Zeroizing;

use crate::{
    App, AppWindow, Bank, STAFF_HALTED, State, bills_text, capitalize, plain, screen, strings, table, time,
};

/// Teller console tabs (order of the side menu in ui/staff.slint).
mod tab {
    pub const ACCOUNTS: i32 = 0;
    pub const LOCKED: i32 = 2;
    pub const LIMITS: i32 = 3;
    pub const AUDIT: i32 = 4;
    pub const RATES: i32 = 7;
    pub const HOLDS: i32 = 8;
}

/// Open-an-account form kinds (`Bank.open-kind`).
mod kind {
    pub const INDIVIDUAL: i32 = 0;
    pub const JOINT: i32 = 1;
    pub const YOUTH: i32 = 2;
    pub const GUARDIAN: i32 = 3;
    pub const GUEST: i32 = 4;
}

/// What the "Open an account" forms send. `holder` is the existing customer
/// at the counter who agrees (joint, youth, guardian forms; empty otherwise).
struct AccountForm<'a> {
    kind: i32,
    name: &'a str,
    dob: &'a str,
    pin: &'a str,
    pin2: &'a str,
    balance: &'a str,
    account: &'a str,
    guardian: &'a str,
    currency: &'a str,
    holder: CardAndPin<'a>,
}

const ROLE_ADMIN: i32 = 1;

pub fn connect(app: &Rc<App>, window: &AppWindow) {
    let bank = window.global::<Bank>();

    let a = app.clone();
    bank.on_setup(move |t_id, t_pw, t_pw2, h_id, h_pw, h_pw2| {
        a.touch();
        let passwords = [t_pw, t_pw2, h_pw, h_pw2].map(|p| Zeroizing::new(p.to_string()));
        a.setup(&t_id, &h_id, &passwords)
    });

    let a = app.clone();
    bank.on_start_staff(move |role| {
        a.touch();
        // Out of service: only the Teller Admin may sign in.
        if role != ROLE_ADMIN && a.out_of_service() {
            a.error(STAFF_HALTED);
            return;
        }
        let window = a.window();
        let bank = window.global::<Bank>();
        bank.set_staff_role(role);
        a.show(screen::STAFF_LOGIN);
    });

    let a = app.clone();
    bank.on_staff_login(move |id, password| {
        a.touch();
        a.staff_login(&id, Zeroizing::new(password.to_string()));
    });

    let a = app.clone();
    bank.on_staff_logout(move || {
        let mut st = a.state();
        a.go_welcome(&mut st, "Signed out.");
    });

    let a = app.clone();
    bank.on_change_password(move |current, new1, new2| {
        a.touch();
        let [current, new1, new2] = [current, new1, new2].map(|p| Zeroizing::new(p.to_string()));
        a.change_password(&current, &new1, &new2)
    });

    // ---- Teller Admin ----

    let a = app.clone();
    bank.on_teller_open_tab(move |tab| {
        a.touch();
        a.teller_tab(tab);
    });

    let a = app.clone();
    bank.on_open_account(
        move |kind, name, dob, pin, pin2, balance, account, guardian, currency, holder_card, holder_pin| {
            a.touch();
            let [pin, pin2, holder_pin] = [pin, pin2, holder_pin].map(|p| Zeroizing::new(p.to_string()));
            let form = AccountForm {
                kind,
                name: &name,
                dob: &dob,
                pin: &pin,
                pin2: &pin2,
                balance: &balance,
                account: &account,
                guardian: &guardian,
                currency: &currency,
                holder: CardAndPin { card_number: holder_card.trim(), pin: &holder_pin },
            };
            a.open_account(form)
        },
    );

    let a = app.clone();
    bank.on_view_activity(move |account| {
        a.touch();
        a.show_activity(account.trim(), 0);
    });

    let a = app.clone();
    bank.on_activity_turn(move |step| {
        a.touch();
        let (account, page) = {
            let st = a.state();
            (st.activity_account.clone(), st.activity_page.saturating_add_signed(step))
        };
        a.show_activity(&account, page);
    });

    let a = app.clone();
    bank.on_account_action(move |action, account| {
        a.touch();
        a.account_action(&action, account.trim());
    });

    let a = app.clone();
    bank.on_unlock(move |card| {
        a.touch();
        a.unlock(card.trim());
    });

    let a = app.clone();
    bank.on_release_hold(move |account| {
        a.touch();
        a.release_hold(account.trim());
    });

    let a = app.clone();
    bank.on_raise_limit(move |account, kind, extra| {
        a.touch();
        a.raise_limit(account.trim(), kind, extra.trim());
    });

    let a = app.clone();
    bank.on_save_limits(move |w, d, t| {
        a.touch();
        a.save_limits([w.as_str(), d.as_str(), t.as_str()]);
    });

    let a = app.clone();
    bank.on_save_rate(move |code, rate| {
        a.touch();
        a.save_rate(&code, rate.trim())
    });

    let a = app.clone();
    bank.on_save_fee(move |percent, minimum| {
        a.touch();
        a.save_fee(Fee::Exchange, percent.trim(), minimum.trim());
    });

    let a = app.clone();
    bank.on_save_atm_fee(move |percent, minimum| {
        a.touch();
        a.save_fee(Fee::OtherBank, percent.trim(), minimum.trim());
    });

    let a = app.clone();
    bank.on_rate_pause(move |code, paused| {
        a.touch();
        a.rate_pause(&code, paused);
    });

    let a = app.clone();
    bank.on_rate_check_feed(move || {
        a.touch();
        a.check_feed();
    });

    let a = app.clone();
    bank.on_rate_approve_feed(move || {
        a.touch();
        a.approve_feed();
    });

    let a = app.clone();
    bank.on_rate_cancel_feed(move || {
        a.touch();
        a.state().rate_feed = None;
        a.window().global::<Bank>().set_rate_feed_shown(false);
        a.teller_tab(tab::RATES);
        a.notice("Nothing changed.".to_string());
    });

    let a = app.clone();
    bank.on_rate_show_history(move |shown| {
        a.touch();
        a.window().global::<Bank>().set_rate_history_shown(shown);
        a.teller_tab(tab::RATES);
    });

    let a = app.clone();
    bank.on_audit_turn(move |step| {
        a.touch();
        let page = a.state().audit_page.saturating_add_signed(step);
        a.show_audit(page);
    });

    let a = app.clone();
    bank.on_verify(move || {
        a.touch();
        a.verify();
    });

    let a = app.clone();
    bank.on_halt_service(move || {
        a.touch();
        a.halt_service();
    });

    let a = app.clone();
    bank.on_resume_service(move || {
        a.touch();
        a.resume_service();
    });

    // ---- Cash Handler ----

    let a = app.clone();
    bank.on_cash_open_tab(move |tab| {
        a.touch();
        a.window().global::<Bank>().set_cash_tab(tab);
        a.show(screen::CASH);
        if tab == 0 {
            a.refresh_cash();
        }
    });

    let a = app.clone();
    bank.on_cash_move(move |restock, bill, count| {
        a.touch();
        a.cash_move(restock, bill, &count)
    });

    let a = app.clone();
    bank.on_cash_reset(move || {
        a.touch();
        a.cash_reset();
    });
}

impl App {
    // -----------------------------------------------------------------------
    // Setup, sign-in, password
    // -----------------------------------------------------------------------

    /// First run: create the Teller Admin and Cash Handler logins.
    /// `pw` = [teller, teller again, handler, handler again].
    fn setup(&self, teller: &str, handler: &str, pw: &[Zeroizing<String>; 4]) -> bool {
        if pw[0] != pw[1] || pw[2] != pw[3] {
            self.error("The two copies of a password don't match.");
            return false;
        }
        let done = auth::first_run_setup(&mut self.atm(), teller.trim(), &pw[0], handler.trim(), &pw[2]);
        match done {
            Ok(()) => {
                let mut st = self.state();
                self.go_welcome(&mut st, "Setup complete. Staff can now sign in from the welcome screen.");
                true
            }
            Err(e) => {
                self.error(e);
                false
            }
        }
    }

    fn staff_login(&self, id: &str, password: Zeroizing<String>) {
        let mut st = self.state();
        let st = &mut *st;
        let window = self.window();
        let bank = window.global::<Bank>();
        let id = id.trim();
        let result = if bank.get_staff_role() == ROLE_ADMIN {
            auth::login_admin(&mut self.atm(), id, &password).map(|s| st.admin = Some(s))
        } else {
            auth::login_handler(&mut self.atm(), id, &password).map(|s| st.handler = Some(s))
        };
        drop(password);
        match result {
            Ok(()) => {
                bank.set_staff_id(id.into());
                if let Some(admin) = &st.admin {
                    // The automatic check at sign-in (core): red banner if it failed.
                    bank.set_signin_problem(admin.integrity_problem().unwrap_or("").into());
                    self.teller_tab_with(st, tab::ACCOUNTS);
                } else {
                    bank.set_cash_tab(0);
                    self.show(screen::CASH);
                    self.refresh_cash_with(st);
                }
            }
            // Same message for a wrong ID, wrong password or a pause (no hints to a guesser).
            Err(AtmError::AuthFailed) => self.error(
                "Sign-in failed. After 3 failures in a row, sign-in pauses for a while (longer each time).",
            ),
            Err(AtmError::OutOfService) => self.error(STAFF_HALTED),
            Err(e) => self.error(e),
        }
    }

    /// Both consoles. Returns true when the password changed.
    fn change_password(&self, current: &str, new1: &str, new2: &str) -> bool {
        if new1 != new2 {
            self.error("The two new passwords don't match.");
            return false;
        }
        let mut st = self.state();
        let changed = {
            let mut atm = self.atm();
            if let Some(s) = &st.admin {
                auth::change_admin_password(&mut atm, s, current, new1)
            } else if let Some(s) = &st.handler {
                auth::change_handler_password(&mut atm, s, current, new1)
            } else {
                Err(AtmError::SessionExpired)
            }
        };
        match changed {
            Ok(()) => {
                self.notice("Password changed. Use the new one next time.");
                true
            }
            Err(AtmError::AuthFailed) => {
                self.error("Current password is wrong (this counts as a failed sign-in).");
                false
            }
            Err(e) => {
                self.fail(&mut st, e);
                false
            }
        }
    }

    // -----------------------------------------------------------------------
    // Teller Admin
    // -----------------------------------------------------------------------

    fn teller_tab(&self, tab: i32) {
        let mut st = self.state();
        self.teller_tab_with(&mut st, tab);
    }

    /// Switches tab and loads its data fresh (nothing stale is shown).
    fn teller_tab_with(&self, st: &mut State, tab: i32) {
        let window = self.window();
        let bank = window.global::<Bank>();
        bank.set_teller_tab(tab);
        bank.set_activity_shown(false);
        // A feed review only shows while one is waiting for approval.
        bank.set_rate_feed_shown(st.rate_feed.is_some() && tab == tab::RATES);
        self.show(screen::TELLER);
        st.close_armed = None;
        self.refresh_service(st);
        let Some(session) = &st.admin else { return };
        let loaded = {
            let atm = self.atm();
            match tab {
                tab::ACCOUNTS => review::holds(&atm, session).and_then(|holds| {
                    let held: Vec<String> = holds.into_iter().map(|h| h.account_number).collect();
                    let accounts = admin::list_accounts(&atm, session)?;
                    let rows = accounts
                        .into_iter()
                        .map(|a| {
                            let status = if a.closed {
                                "Closed"
                            } else if a.frozen {
                                "FROZEN"
                            } else if a.guardian_frozen {
                                "Frozen by guardian"
                            } else if held.contains(&a.account_number) {
                                "ON HOLD"
                            } else {
                                "Open"
                            };
                            let holders = a
                                .holders
                                .iter()
                                .map(|h| {
                                    let lock = if h.locked { ", card locked" } else { "" };
                                    format!("{} ({}{lock})", h.full_name, h.role)
                                })
                                .collect::<Vec<_>>()
                                .join("; ");
                            let kind = match (a.kind.as_str(), a.currency) {
                                ("guest", c) => format!("Other bank {}", c.code()),
                                (_, Currency::Usd) => capitalize(&a.kind),
                                (_, other) => format!("{} {}", capitalize(&a.kind), other.code()),
                            };
                            vec![a.account_number, kind, status.into(), holders]
                        })
                        .collect();
                    bank.set_account_rows(table(rows));
                    Ok(())
                }),
                tab::HOLDS => review::holds(&atm, session).map(|holds| {
                    let rows = holds
                        .into_iter()
                        .map(|h| vec![h.account_number, h.holders.join(", "), h.reason, time(&h.since)])
                        .collect();
                    bank.set_hold_rows(table(rows));
                }),
                tab::LOCKED => admin::locked_cards(&atm, session).map(|cards| {
                    let rows = cards
                        .into_iter()
                        .map(|c| {
                            vec![
                                format!("ending {}", c.card_last4),
                                format!("ending {}", c.account_last4),
                                c.full_name,
                                c.date_of_birth,
                            ]
                        })
                        .collect();
                    bank.set_locked_rows(table(rows));
                }),
                tab::LIMITS => admin::bank_limits(&atm, session).map(|limits| {
                    for (limit, value) in limits {
                        let set = match limit {
                            Limit::Withdrawal => Bank::set_limit_withdrawal,
                            Limit::Deposit => Bank::set_limit_deposit,
                            Limit::Transfer => Bank::set_limit_transfer,
                        };
                        set(&bank, plain(value).into());
                    }
                }),
                tab::RATES => fx::rates(&atm, session).and_then(|rates| {
                    let codes: Vec<String> = rates.iter().map(|r| r.currency.code().to_string()).collect();
                    let picked =
                        codes.iter().position(|c| *c == bank.get_rate_currency().as_str()).unwrap_or(0);
                    bank.set_rate_selected(picked as i32);
                    bank.set_rate_codes(strings(codes));
                    let current = rates
                        .iter()
                        .map(|r| {
                            r.rate.as_ref().filter(|_| !r.tampered).map(|x| x.text()).unwrap_or_default()
                        })
                        .collect();
                    bank.set_rate_current(strings(current));
                    let rows = rates
                        .into_iter()
                        .map(|r| {
                            let name = format!("{} {}", r.currency.code(), r.currency.name());
                            match r.rate {
                                _ if r.tampered => {
                                    vec![name, "?".into(), "".into(), "".into(), "ALTERED: re-enter".into()]
                                }
                                Some(rate) => vec![
                                    name,
                                    rate.text(),
                                    time(&rate.set_at),
                                    who(&rate.set_by),
                                    if rate.paused {
                                        "PAUSED"
                                    } else if rate.is_stale() {
                                        "OUT OF DATE"
                                    } else {
                                        "Current"
                                    }
                                    .into(),
                                ],
                                None => vec![name, "–".into(), "".into(), "".into(), "Not set".into()],
                            }
                        })
                        .collect();
                    bank.set_rate_rows(table(rows));
                    // Each fee = the higher of a percent and a minimum.
                    let percent = |bp: i64| format!("{}.{:02}", bp / 100, bp % 100);
                    let exchange = fx::fee_rule(&atm, session, Fee::Exchange)?;
                    bank.set_rate_fee(percent(exchange.percent_bp).into());
                    bank.set_rate_fee_min(plain(exchange.minimum).into());
                    let other = fx::fee_rule(&atm, session, Fee::OtherBank)?;
                    bank.set_rate_atm_fee(percent(other.percent_bp).into());
                    bank.set_rate_atm_fee_min(plain(other.minimum).into());
                    if bank.get_rate_history_shown() {
                        bank.set_rate_history_rows(table(history_rows(&fx::rate_history(
                            &atm, session, None, 200,
                        )?)));
                    }
                    Ok(())
                }),
                _ => Ok(()),
            }
        };
        if let Err(e) = loaded {
            return self.fail(st, e);
        }
        if tab == tab::AUDIT {
            self.show_audit_with(st, 0);
        }
    }

    /// One page of everything that happened on one account.
    fn show_activity(&self, account: &str, page: u32) {
        let mut st = self.state();
        self.show_activity_with(&mut st, account, page);
    }

    fn show_activity_with(&self, st: &mut State, account: &str, page: u32) {
        let Some(session) = &st.admin else { return };
        let window = self.window();
        let bank = window.global::<Bank>();
        if atm::input::validate_number10(account).is_err() {
            return self.error("Account numbers are 10 digits.");
        }
        let rows = admin::audit_for_account(&self.atm(), session, account, page);
        match rows {
            Ok(rows) => {
                bank.set_selected_account(account.into());
                bank.set_activity_title(format!("Activity on {account}").into());
                bank.set_activity_more(rows.len() == AUDIT_PAGE as usize);
                bank.set_activity_page(page as i32);
                bank.set_activity_rows(table(rows.iter().map(|r| activity_row(r, account)).collect()));
                bank.set_activity_shown(true);
                st.activity_account = account.to_string();
                st.activity_page = page;
            }
            Err(e) => self.fail(st, e),
        }
    }

    fn show_audit(&self, page: u32) {
        let mut st = self.state();
        self.show_audit_with(&mut st, page);
    }

    fn show_audit_with(&self, st: &mut State, page: u32) {
        let Some(session) = &st.admin else { return };
        let rows = admin::recent_audit(&self.atm(), session, page);
        match rows {
            Ok(rows) => {
                let window = self.window();
                let bank = window.global::<Bank>();
                bank.set_audit_more(rows.len() == AUDIT_PAGE as usize);
                bank.set_audit_page(page as i32);
                bank.set_audit_rows(table(rows.iter().map(audit_row).collect()));
                st.audit_page = page;
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// Freeze / unfreeze / close. Close needs a second click on the same account.
    fn account_action(&self, action: &str, account: &str) {
        let mut st = self.state();
        let st = &mut *st;
        if atm::input::validate_number10(account).is_err() {
            return self.error("Enter or click a 10-digit account number first.");
        }
        let Some(session) = &st.admin else { return };
        let done = match action {
            "freeze" => admin::set_frozen(&mut self.atm(), session, account, true).map(|()| {
                format!("Account {account} frozen: its cards aren't accepted and it takes no transfers.")
            }),
            "unfreeze" => admin::set_frozen(&mut self.atm(), session, account, false)
                .map(|()| format!("Account {account} unfrozen.")),
            "close" if st.close_armed.as_deref() != Some(account) => {
                st.close_armed = Some(account.to_string());
                return self.error(format!(
                    "Close account {account}? Its cards stop working and the number is never reused. \
                     Click Close again to confirm."
                ));
            }
            "close" => admin::close_account(&mut self.atm(), session, account)
                .map(|()| format!("Account {account} closed. Its history stays in the audit log.")),
            _ => return,
        };
        st.close_armed = None;
        match done {
            Ok(text) => {
                self.teller_tab_with(st, tab::ACCOUNTS);
                self.show_activity_with(st, account, 0);
                self.notice(text);
            }
            Err(e) => self.fail(st, e),
        }
    }

    fn unlock(&self, card: &str) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let done = admin::unlock_card(&mut self.atm(), session, card);
        match done {
            Ok(()) => {
                self.teller_tab_with(st, tab::LOCKED);
                self.notice(format!("Card {} unlocked. The customer can use their PIN again.", mask(card)));
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// Release an activity hold (after an ID check at the counter). Logged.
    fn release_hold(&self, account: &str) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let done = review::release_hold(&mut self.atm(), session, account);
        match done {
            Ok(()) => {
                self.teller_tab_with(st, tab::HOLDS);
                self.notice(format!(
                    "Hold released on account {}. Withdrawals and transfers work again. Logged.",
                    mask(account)
                ));
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// Allow more than one daily limit for one account, today only. Logged.
    fn raise_limit(&self, account: &str, kind: i32, extra: &str) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let limit = match kind {
            1 => Limit::Deposit,
            2 => Limit::Transfer,
            _ => Limit::Withdrawal,
        };
        let done = Cents::parse(extra).and_then(|extra| {
            admin::raise_limit_today(&mut self.atm(), session, account, limit, extra).map(|_| extra)
        });
        match done {
            Ok(extra) => {
                self.teller_tab_with(st, tab::HOLDS);
                self.notice(format!(
                    "Approved {extra} more {} today for account {}. Logged.",
                    limit.label(),
                    mask(account)
                ));
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// Saves only the limits that changed (each change is logged with old -> new).
    fn save_limits(&self, typed: [&str; 3]) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let mut new_values = Vec::new();
        for text in typed {
            match Cents::parse(text.trim()) {
                Ok(v) => new_values.push(v),
                Err(e) => return self.error(e),
            }
        }
        let saved = (|| {
            let mut atm = self.atm();
            let current = admin::bank_limits(&atm, session)?;
            let mut changed = 0;
            for ((limit, old), new) in current.into_iter().zip(new_values) {
                if old != new {
                    admin::set_limit(&mut atm, session, limit, new)?;
                    changed += 1;
                }
            }
            Ok::<_, AtmError>(changed)
        })();
        match saved {
            Ok(changed) => {
                self.teller_tab_with(st, tab::LIMITS);
                self.notice(match changed {
                    0 => "Nothing changed.".to_string(),
                    1 => "1 limit saved. Customers see it straight away.".to_string(),
                    n => format!("{n} limits saved. Customers see them straight away."),
                });
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// "Save rate" on the Exchange rates tab. True on success (the field clears).
    fn save_rate(&self, code: &str, rate: &str) -> bool {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return false };
        let saved = Currency::parse(code).and_then(|c| fx::set_rate(&mut self.atm(), session, c, rate));
        match saved {
            Ok(()) => {
                self.teller_tab_with(st, tab::RATES);
                self.notice(format!("{code} rate saved and logged. It is valid for 72 hours."));
                true
            }
            Err(e) => {
                self.fail(st, e);
                false
            }
        }
    }

    /// Save one fee rule (percent and minimum); logged with old -> new.
    fn save_fee(&self, fee: Fee, percent: &str, minimum: &str) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let saved = fx::set_fee_rule(&mut self.atm(), session, fee, percent, minimum);
        match saved {
            Ok(()) => {
                self.teller_tab_with(st, tab::RATES);
                self.notice(format!("{} saved and logged.", fee.label()));
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// "Check today's rates": one HTTPS request, then old vs new for review.
    /// Nothing is set until the teller approves.
    fn check_feed(&self) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let mut atm = self.atm();
        let fetched = rate_feed::fetch(&mut atm, session)
            .and_then(|feed| rate_feed::check(&atm, session, &feed).map(|shown| (feed, shown)));
        drop(atm);
        match fetched {
            Ok((feed, shown)) => {
                let window = self.window();
                let bank = window.global::<Bank>();
                let rows = shown
                    .iter()
                    .map(|c| {
                        vec![
                            format!("{} {}", c.currency.code(), c.currency.name()),
                            c.current.clone(),
                            c.feed.clone(),
                            c.set_to.clone().unwrap_or_else(|| "-".into()),
                            c.note.clone(),
                        ]
                    })
                    .collect();
                bank.set_rate_feed_rows(table(rows));
                bank.set_rate_feed_hint(
                    format!(
                        "From {}, published {}. Nothing changes until you approve. A move over 5% in a day is set but paused until you check it.",
                        rate_feed::FEED_SOURCE,
                        feed.published()
                    )
                    .into(),
                );
                bank.set_rate_feed_credit(rate_feed::FEED_CREDIT.into());
                bank.set_rate_history_shown(false);
                bank.set_rate_feed_shown(true);
                st.rate_feed = Some((feed, shown));
                self.notice("Check each line, then approve. Nothing has changed yet.".to_string());
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// "Approve these rates": sets exactly the reviewed lines, or nothing.
    fn approve_feed(&self) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let Some((feed, shown)) = st.rate_feed.take() else { return };
        self.window().global::<Bank>().set_rate_feed_shown(false);
        let paused: Vec<&str> = shown.iter().filter(|c| c.pauses).map(|c| c.currency.code()).collect();
        let done = rate_feed::approve(&mut self.atm(), session, &feed, &shown);
        self.teller_tab_with(st, tab::RATES);
        match done {
            Ok(n) if paused.is_empty() => self
                .notice(format!("{n} rates set from today's feed. Each change is logged with the source.")),
            Ok(n) => self.notice(format!(
                "{n} rates set from today's feed and logged. Paused after a big move: {}. Check each against \
                 another source, then Resume.",
                paused.join(", ")
            )),
            Err(e) => self.fail(st, e),
        }
    }

    /// Pause or resume one currency ("EUR") or every currency ("ALL").
    fn rate_pause(&self, code: &str, paused: bool) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let which = if code == "ALL" { Ok(None) } else { Currency::parse(code).map(Some) };
        let done = which.and_then(|c| fx::set_paused(&mut self.atm(), session, c, paused));
        match done {
            Ok(()) => {
                self.teller_tab_with(st, tab::RATES);
                let what = if code == "ALL" { "all currencies".to_string() } else { code.to_string() };
                self.notice(if paused {
                    format!("Exchanges paused for {what}. Logged. Customers in that currency can't convert until resumed.")
                } else {
                    format!("Exchanges resumed for {what}. Logged.")
                });
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// Out-of-service banner: reads the state from the core.
    fn refresh_service(&self, st: &State) {
        let Some(session) = &st.admin else { return };
        let window = self.window();
        let bank = window.global::<Bank>();
        if let Ok(status) = service::status(&self.atm(), session) {
            bank.set_service_halted(status.out_of_service);
            bank.set_service_since(time(&status.since).into());
            bank.set_service_reason(status.reason.into());
        }
    }

    /// "Halt ATM": customers are turned away until a teller resumes.
    fn halt_service(&self) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let done = service::halt(&mut self.atm(), session);
        match done {
            Ok(()) => {
                self.refresh_service(st);
                self.notice("The ATM is out of service. Customers are turned away until you resume.");
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// "Resume service", after review. The check runs again and is logged.
    fn resume_service(&self) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let done = service::resume(&mut self.atm(), session);
        match done {
            Ok(still) => {
                let window = self.window();
                let bank = window.global::<Bank>();
                bank.set_signin_problem("".into());
                self.refresh_service(st);
                match still {
                    None => self.notice("Back in service. The integrity check passes."),
                    Some(problem) => self.error(format!(
                        "Back in service, but the integrity check still fails: {problem} This is logged, and \
                         the next Teller Admin sign-in will take the ATM out of service again."
                    )),
                }
            }
            Err(e) => self.fail(st, e),
        }
    }

    /// Re-checks the whole audit chain and every balance against it.
    fn verify(&self) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return };
        let window = self.window();
        let bank = window.global::<Bank>();
        let report = admin::verify_integrity(&mut self.atm(), session);
        let (ok, lines) = match report {
            Ok(r) => (
                true,
                vec![
                    format!("{} audit entries checked: none edited, removed or reordered.", r.entries),
                    format!("{} account balances match the transaction history.", r.accounts_checked),
                    format!(
                        "The cash in the machine ({}) matches every restock, deposit, withdrawal and removal.",
                        r.cash
                    ),
                    format!(
                        "{} signed records (limits, fees, exchange rates, rate history) are unchanged.",
                        r.records_checked
                    ),
                    format!(
                        "{} limits, exchange rates and account freezes or closures match the log.",
                        r.state_checked
                    ),
                    format!("Check code: {}", r.head),
                    "Write the check code down with today's date. If an older code ever stops \
                     matching, the log was rebuilt."
                        .into(),
                ],
            ),
            // Several failures: one red line each.
            Err(AtmError::IntegrityFailures(all)) => (false, all.iter().map(ToString::to_string).collect()),
            Err(
                e @ (AtmError::AuditTampered(_)
                | AtmError::BalanceMismatch(_)
                | AtmError::CashMismatch { .. }
                | AtmError::StateMismatch(_)
                | AtmError::RecordTampered(_)),
            ) => (false, vec![e.to_string()]),
            Err(e) => return self.fail(st, e),
        };
        bank.set_integrity_ok(ok);
        bank.set_integrity_lines(strings(lines));
        bank.set_integrity_ran(true);
    }

    /// The five forms on the "Open an account" tab. Returns true on success.
    fn open_account(&self, form: AccountForm) -> bool {
        let AccountForm { kind, name, dob, pin, pin2, balance, account, guardian, currency, holder } = form;
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.admin else { return false };
        if kind != kind::GUARDIAN && pin != pin2 {
            self.error("The two PINs don't match. Ask the customer to type them again.");
            return false;
        }
        // Typed in the account's currency (a guest card's may be whole yen or won).
        let starting = |currency: Currency| match balance.trim() {
            "" => Ok(Cents::ZERO),
            text => currency.parse_amount(text),
        };
        let (name, dob, account, guardian) = (name.trim(), dob.trim(), account.trim(), guardian.trim());
        let created = {
            let mut atm = self.atm();
            match kind {
                kind::INDIVIDUAL => starting(Currency::Usd)
                    .and_then(|b| admin::create_customer(&mut atm, session, name, dob, pin, b))
                    .map(Some),
                kind::GUEST => Currency::parse(currency)
                    .and_then(|c| {
                        let b = starting(c)?;
                        admin::register_guest_card(&mut atm, session, name, dob, pin, b, c)
                    })
                    .map(Some),
                kind::JOINT => {
                    admin::add_joint_holder(&mut atm, session, account, holder, name, dob, pin).map(Some)
                }
                kind::YOUTH => starting(Currency::Usd)
                    .and_then(|b| admin::open_youth_account(&mut atm, session, holder, name, dob, pin, b))
                    .map(Some),
                kind::GUARDIAN => {
                    admin::add_guardian(&mut atm, session, account, holder, guardian).map(|()| None)
                }
                _ => return false,
            }
        };
        match created {
            Ok(Some(card)) => {
                self.notice(format!(
                    "Done. Card number {} (logs in with the PIN). Account number {} (for receiving transfers). \
                     Give both to the customer.",
                    card.card_number, card.account_number
                ));
                true
            }
            Ok(None) => {
                self.notice(format!("Card {guardian} is now a guardian of account {account}."));
                true
            }
            // The holder at the counter typed their card and PIN (joint, youth, guardian).
            Err(AtmError::AuthFailed) if kind != kind::INDIVIDUAL && kind != kind::GUEST => {
                self.error("The holder's card number or PIN was not accepted. Ask them to type it again.");
                false
            }
            Err(AtmError::CardLocked) if kind != kind::INDIVIDUAL && kind != kind::GUEST => {
                self.error(
                    "The holder's card is locked. Check their ID and unlock it under Locked cards first.",
                );
                false
            }
            Err(AtmError::FrozenByBank) if kind != kind::INDIVIDUAL && kind != kind::GUEST => {
                self.error("The holder's account is frozen by the bank, so their card can't confirm this.");
                false
            }
            Err(e) => {
                self.fail(st, e);
                false
            }
        }
    }

    // -----------------------------------------------------------------------
    // Cash Handler
    // -----------------------------------------------------------------------

    fn refresh_cash(&self) {
        let mut st = self.state();
        self.refresh_cash_with(&mut st);
    }

    fn refresh_cash_with(&self, st: &mut State) {
        let Some(session) = &st.handler else { return };
        let inventory = cash::view(&self.atm(), session);
        let inv = match inventory {
            Ok(inv) => inv,
            Err(e) => return self.fail(st, e),
        };
        let window = self.window();
        let bank = window.global::<Bank>();
        let rows = inv
            .bills
            .iter()
            .map(|(d, n)| {
                vec![
                    format!("${}", d.dollars()),
                    n.to_string(),
                    d.times(*n).unwrap_or(Cents::ZERO).to_string(),
                ]
            })
            .collect();
        bank.set_cash_rows(table(rows));
        bank.set_cash_total(inv.total.to_string().into());
        bank.set_cash_maximum(inv.maximum.to_string().into());
        bank.set_cash_limit(inv.withdrawal_limit.to_string().into());
        bank.set_cash_low(inv.low_cash);
        bank.set_cash_over(!inv.over_maximum.is_zero());
        let mut warnings = Vec::new();
        if !inv.low_bills.is_empty() {
            let list: Vec<String> = inv.low_bills.iter().map(|d| format!("${d}")).collect();
            warnings.push(format!("Running low (under 20 bills): {}.", list.join(", ")));
        }
        if !inv.over_maximum.is_zero() {
            warnings.push(format!(
                "{} over the cash maximum (customer deposits). Hard limit: {}.",
                inv.over_maximum, inv.physical_capacity
            ));
        }
        bank.set_cash_warnings(strings(warnings));
    }

    /// Restock (`restock` = true) or remove bills. Returns true on success.
    fn cash_move(&self, restock: bool, bill: i32, count: &str) -> bool {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.handler else { return false };
        let Some(d) = usize::try_from(bill).ok().and_then(|i| Denomination::all().nth(i)) else {
            return false;
        };
        let Ok(count) = count.trim().replace(',', "").parse::<u32>() else {
            self.error("Enter the number of bills (1 to 10,000).");
            return false;
        };
        let moved = if restock {
            cash::restock(&mut self.atm(), session, d, count)
        } else {
            cash::remove_excess(&mut self.atm(), session, d, count)
        };
        match moved {
            Ok(total) => {
                self.refresh_cash_with(st);
                let verb = if restock { "Added" } else { "Removed" };
                self.notice(format!("{verb} {count} × ${}. The machine now holds {total}.", d.dollars()));
                true
            }
            Err(e) => {
                self.fail(st, e);
                false
            }
        }
    }

    fn cash_reset(&self) {
        let mut st = self.state();
        let st = &mut *st;
        let Some(session) = &st.handler else { return };
        let removed = cash::reset_to_maximum(&mut self.atm(), session);
        match removed {
            Ok(plan) => {
                self.refresh_cash_with(st);
                self.notice(format!(
                    "Take out {}. The machine is back at its cash maximum.",
                    bills_text(&plan)
                ));
            }
            Err(e) => self.fail(st, e),
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Log actor as a short label: "customer:card 7 ending 1234" -> "card 7 ending 1234",
/// "admin:teller" -> "teller (admin)".
fn who(actor: &str) -> String {
    match actor.split_once(':') {
        Some(("customer", card)) => card.to_string(),
        Some((role, name)) => format!("{name} ({role})"),
        None => actor.to_string(),
    }
}

/// "pin_failed" -> "Pin failed".
fn event(action: &str) -> String {
    capitalize(&action.replace('_', " "))
}

/// [When, Who, Event, Amount, Details] for one account's activity.
fn activity_row(r: &Row, account: &str) -> Vec<String> {
    let other = if r.account_number.as_deref() == Some(account) {
        r.counterparty_number.as_deref().map(|n| format!("to {n}"))
    } else {
        r.account_number.as_deref().map(|n| format!("from {n}"))
    };
    let details = [other.unwrap_or_default(), r.detail.clone()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    vec![
        time(&r.ts),
        who(&r.actor),
        event(&r.action),
        r.amount.map(|a| r.currency.format(a)).unwrap_or_default(),
        details,
    ]
}

/// [#, When, Who, Event, Account, Amount, Details] for the full log.
fn audit_row(r: &Row) -> Vec<String> {
    let details = match &r.counterparty_number {
        Some(n) if !r.detail.is_empty() => format!("to {n}; {}", r.detail),
        Some(n) => format!("to {n}"),
        None => r.detail.clone(),
    };
    vec![
        r.seq.to_string(),
        time(&r.ts),
        who(&r.actor),
        event(&r.action),
        r.account_number.clone().unwrap_or_default(),
        r.amount.map(|a| r.currency.format(a)).unwrap_or_default(),
        details,
    ]
}

/// Rate history rows, newest first, with the change from that currency's
/// previous rate ("+1.20%").
fn history_rows(history: &[fx::Rate]) -> Vec<Vec<String>> {
    history
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let previous = history[i + 1..].iter().find(|p| p.currency == r.currency);
            let change = match previous {
                Some(p) => {
                    let bp = (i128::from(r.per_usd_micros) - i128::from(p.per_usd_micros)) * 10_000
                        / i128::from(p.per_usd_micros);
                    format!("{}{}.{:02}%", if bp < 0 { "−" } else { "+" }, bp.abs() / 100, bp.abs() % 100)
                }
                None => "first rate".into(),
            };
            vec![
                format!("{} {}", r.currency.code(), r.currency.name()),
                r.text(),
                time(&r.set_at),
                who(&r.set_by),
                change,
            ]
        })
        .collect()
}
