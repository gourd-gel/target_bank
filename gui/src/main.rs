//! Bank of CCNY ATM: graphical front end (Slint).
//!
//! Same rule as the CLI: nothing here makes a security decision. These files
//! turn taps into library calls and show what comes back. Every check
//! (lockout, limits, balances, bills, roles, guardians) happens inside the
//! `atm` library, which never hands this program a database connection.
//!
//! Files:
//!   main.rs      start-up, shared state, idle timer, helpers   <- start here
//!   customer.rs  everything after the card is "inserted" (+ Family screen)
//!   staff.rs     first-run setup, Teller Admin and Cash Handler consoles
//!   wallet.rs    demo builds only: click a sample card to "insert" it
//!
//! Run from the project root so the GUI and the CLI share `atm.db` / `atm.key`:
//!   cargo run --release -p atm-gui
//!   cargo run --release -p atm-gui --features demo -- --demo   (sample data)

slint::include_modules!();

mod customer;
mod staff;
#[cfg(feature = "demo")]
mod wallet;

use std::cell::{RefCell, RefMut};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use atm::Atm;
use atm::auth::{self, AdminSession, CustomerSession, HandlerSession};
use atm::customer::RecentPayee;
use atm::dispense::BillChoice;
use atm::error::AtmError;
use atm::family::YouthSummary;
use atm::money::{Cents, Denomination};
use chrono::{DateTime, Utc};
use chrono_tz::America::New_York;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use zeroize::{Zeroize, Zeroizing};

/// Screen numbers. Must match `global Screen` in ui/bank.slint.
pub mod screen {
    pub const WELCOME: i32 = 0;
    pub const ENTRY: i32 = 1;
    pub const MENU: i32 = 2;
    pub const BALANCE: i32 = 3;
    pub const FAST_CASH: i32 = 4;
    pub const BILLS: i32 = 5;
    pub const CONFIRM: i32 = 6;
    pub const RESULT: i32 = 7;
    pub const HISTORY: i32 = 8;
    pub const LIMITS: i32 = 9;
    pub const STAFF_LOGIN: i32 = 10;
    pub const TELLER: i32 = 11;
    pub const CASH: i32 = 12;
    pub const FAMILY: i32 = 13;
    pub const SETUP: i32 = 14;
    pub const RECEIPT_ASK: i32 = 15;
    pub const TAKE_CARD: i32 = 16;
    pub const TAKE_CASH: i32 = 17;
}

/// After this long without a tap, ask "Do you need more time?".
const IDLE_WARNING: Duration = Duration::from_secs(90);
/// After this long, end the session. Same as the library's own timeout, so
/// the GUI logs the user out (audited) before the library would refuse them.
const IDLE_LIMIT: Duration = auth::IDLE_TIMEOUT;
/// A half-typed card number or PIN is abandoned after this long.
const IDLE_LOGIN: Duration = Duration::from_secs(60);
/// How often the welcome screen re-reads whether the ATM is out of service.
const SERVICE_CHECK: Duration = Duration::from_secs(5);
/// Shown when a Cash Handler tries to sign in while the ATM is out of service.
pub const STAFF_HALTED: &str =
    "The ATM is out of service. Only a Teller Admin can sign in until it is resumed.";

/// What the keypad entry screen is collecting right now.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Card,
    Pin,
    WithdrawAmount,
    DepositCount,
    TransferTo,
    TransferAmount,
    PinCurrent,
    PinNew,
    PinRepeat,
}

impl Purpose {
    fn masked(self) -> bool {
        matches!(self, Purpose::Pin | Purpose::PinCurrent | Purpose::PinNew | Purpose::PinRepeat)
    }

    fn max_digits(self) -> usize {
        match self {
            Purpose::Card | Purpose::TransferTo => 10,
            Purpose::Pin | Purpose::PinCurrent | Purpose::PinNew | Purpose::PinRepeat => 12,
            Purpose::WithdrawAmount => 5,
            Purpose::DepositCount => 3,
            Purpose::TransferAmount => 9,
        }
    }
}

/// A customer transaction that is being set up across several screens.
#[derive(Default)]
pub enum Pending {
    #[default]
    None,
    Withdraw {
        amount: Cents,
        choice: Option<BillChoice>,
    },
    /// Bills counted so far, and the bill type being counted now.
    Deposit {
        bills: Vec<(Denomination, u32)>,
        current: Option<Denomination>,
    },
    Transfer {
        to: String,
        hint: String,
        amount: Option<Cents>,
    },
    ChangePin {
        current: Option<Zeroizing<String>>,
        new: Option<Zeroizing<String>>,
    },
}

/// Everything the GUI remembers between taps.
pub struct State {
    /// Digits typed on the keypad. Kept here, never in the UI, so a PIN is
    /// never a UI property; wiped (`zeroize`) after every use.
    pub entry: Zeroizing<String>,
    pub purpose: Purpose,
    /// Card number accepted on the first screen, waiting for the PIN.
    pub login_card: Option<String>,
    pub pending: Pending,
    /// At most one of these is `Some`: whoever is using the machine.
    pub customer: Option<CustomerSession>,
    pub admin: Option<AdminSession>,
    pub handler: Option<HandlerSession>,
    pub last_activity: Instant,
    /// When the welcome screen last read the out-of-service state.
    pub service_checked: Option<Instant>,
    // Paging and selections.
    pub history_page: u32,
    pub youth: Vec<YouthSummary>,
    /// "Send again" choices on the transfer screen (cleared whenever an entry opens).
    pub recent: Vec<RecentPayee>,
    pub activity_account: String,
    pub activity_page: u32,
    pub audit_page: u32,
    /// Today's rate feed and the review the teller is looking at (until approved or cancelled).
    pub rate_feed: Option<(atm::rate_feed::Feed, Vec<atm::rate_feed::RateCheck>)>,
    /// "Close" must be clicked twice for the same account.
    pub close_armed: Option<String>,
    /// The logged-in customer's account currency (cash is always US dollars).
    pub currency: atm::fx::Currency,
    /// A finished withdrawal's receipt while the card and then the cash are
    /// taken, and whether the customer asked for it.
    pub cash_out: Option<(atm::customer::Receipt, bool)>,
    /// Demo builds only: what each card and badge in the wallet stands for.
    #[cfg(feature = "demo")]
    pub wallet: Vec<wallet::Item>,
}

/// The running application: the bank, the window, and the state.
pub struct App {
    atm: RefCell<Atm>,
    window: slint::Weak<AppWindow>,
    state: RefCell<State>,
}

/// Which files to use, from the command line. No paths are accepted: a
/// fixed name means nothing can point the ATM at an attacker's database.
enum Mode {
    Normal,
    #[cfg(feature = "demo")]
    Demo,
}

/// The mode, and (test builds only) whether to break one demo balance on purpose.
fn parse_args() -> Result<(Mode, bool), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok((Mode::Normal, false)),
        #[cfg(feature = "demo")]
        [flag] if flag == "--demo" => Ok((Mode::Demo, false)),
        #[cfg(feature = "integrity-test")]
        [flag, test] if flag == "--demo" && test == "--break-integrity" => Ok((Mode::Demo, true)),
        [flag] if flag == "--demo" => {
            Err("Demo mode isn't in this build. Run: cargo run -p atm-gui --features demo -- --demo".into())
        }
        _ => Err("Usage: atm-gui            (normal)\n       atm-gui --demo     (sample data; build with --features demo)".into()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mode, break_integrity) = match parse_args() {
        Ok(parsed) => parsed,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };
    let (db, key) = match mode {
        Mode::Normal => ("atm.db", "atm.key"),
        // The integrity test breaks its own copy, never the normal demo data.
        #[cfg(feature = "integrity-test")]
        Mode::Demo if break_integrity => ("atm-test.db", "atm-test.key"),
        #[cfg(feature = "demo")]
        Mode::Demo => ("atm-demo.db", "atm-demo.key"),
    };
    let opened = match mode {
        Mode::Normal => Atm::open(Path::new(db), Path::new(key)),
        #[cfg(feature = "demo")]
        Mode::Demo => Atm::open_demo(Path::new(db), Path::new(key)),
    };
    let atm = match opened {
        Ok(atm) => atm,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    #[cfg(feature = "demo")]
    let mut atm = atm;
    #[cfg(feature = "demo")]
    let (wallet_items, wallet_rows) = match mode {
        Mode::Demo => wallet::load(&mut atm)?,
        Mode::Normal => (Vec::new(), Vec::new()),
    };
    // Test builds only: make one demo balance wrong so the sign-in check shows.
    #[cfg(feature = "integrity-test")]
    if break_integrity {
        atm::demo::break_integrity(&mut atm)?;
        eprintln!(
            "TEST: Ann and Ben's balance was raised by $500 with no log entry. Sign in as the Teller Admin."
        );
    }
    #[cfg(not(feature = "integrity-test"))]
    let _ = break_integrity;
    let needs_setup = atm.needs_setup()?;

    let window = AppWindow::new()?;
    let app = Rc::new(App {
        atm: RefCell::new(atm),
        window: window.as_weak(),
        state: RefCell::new(State {
            entry: Zeroizing::default(),
            purpose: Purpose::Card,
            login_card: None,
            pending: Pending::None,
            customer: None,
            admin: None,
            handler: None,
            last_activity: Instant::now(),
            service_checked: None,
            history_page: 0,
            youth: Vec::new(),
            recent: Vec::new(),
            activity_account: String::new(),
            activity_page: 0,
            audit_page: 0,
            rate_feed: None,
            close_armed: None,
            currency: atm::fx::Currency::Usd,
            cash_out: None,
            #[cfg(feature = "demo")]
            wallet: wallet_items,
        }),
    });

    customer::connect(&app, &window);
    staff::connect(&app, &window);
    #[cfg(feature = "demo")]
    wallet::connect(&app, &window);

    let bank = window.global::<Bank>();
    #[cfg(feature = "demo")]
    bank.set_demo_wallet(table(wallet_rows));
    if needs_setup {
        bank.set_screen(screen::SETUP);
    }
    bank.on_more_time({
        let app = app.clone();
        move |yes| app.more_time(yes)
    });

    // Once a second: update the clock and enforce the idle timeout.
    app.tick();
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, Duration::from_secs(1), {
        let app = app.clone();
        move || app.tick()
    });

    window.run()?;

    // Window closed while someone was signed in: log them out (audited).
    app.end_all_sessions(&mut app.state());
    Ok(())
}

impl App {
    pub fn window(&self) -> AppWindow {
        self.window.upgrade().expect("window exists while the app runs")
    }

    pub fn state(&self) -> RefMut<'_, State> {
        self.state.borrow_mut()
    }

    /// The bank. Borrow it only for the length of one library call.
    pub fn atm(&self) -> RefMut<'_, Atm> {
        self.atm.borrow_mut()
    }

    /// Reads from the core whether the ATM is out of service, and shows it on
    /// the welcome screen. A failed read (tampering, rollback) counts as out
    /// of service: fail closed.
    pub fn out_of_service(&self) -> bool {
        let halted = atm::service::out_of_service(&self.atm()).unwrap_or(true);
        self.window().global::<Bank>().set_service_halted(halted);
        halted
    }

    /// Records a tap, for the idle timeout.
    pub fn touch(&self) {
        self.state().last_activity = Instant::now();
        self.window().global::<Bank>().set_idle_warning(false);
    }

    pub fn show(&self, screen: i32) {
        let window = self.window();
        let bank = window.global::<Bank>();
        bank.set_message("".into());
        bank.set_screen(screen);
    }

    pub fn error(&self, text: impl std::fmt::Display) {
        let window = self.window();
        let bank = window.global::<Bank>();
        bank.set_message_ok(false);
        bank.set_message(text.to_string().into());
    }

    pub fn notice(&self, text: impl std::fmt::Display) {
        let window = self.window();
        let bank = window.global::<Bank>();
        bank.set_message_ok(true);
        bank.set_message(text.to_string().into());
    }

    /// Opens the keypad entry screen for `purpose`.
    pub fn open_entry(&self, st: &mut State, purpose: Purpose, title: &str, hint: &str) {
        st.purpose = purpose;
        st.entry.zeroize();
        st.recent.clear();
        let window = self.window();
        let bank = window.global::<Bank>();
        bank.set_entry_choices(strings(Vec::new()));
        bank.set_entry_title(title.into());
        bank.set_entry_hint(hint.into());
        bank.set_entry_masked(purpose.masked());
        bank.set_entry_placeholder(
            match purpose {
                Purpose::Card | Purpose::TransferTo => "0000000000",
                Purpose::WithdrawAmount => "$0",
                Purpose::TransferAmount => "$0.00",
                Purpose::DepositCount => "0 bills",
                _ => "",
            }
            .into(),
        );
        self.show_entry(st);
        self.show(screen::ENTRY);
    }

    /// Redraws the entry box from the typed digits.
    pub fn show_entry(&self, st: &State) {
        let window = self.window();
        let bank = window.global::<Bank>();
        let digits: &str = &st.entry;
        let display = match st.purpose {
            _ if st.purpose.masked() || digits.is_empty() => String::new(),
            // Card and account numbers: only the last 4 digits show, so
            // someone looking over a shoulder can't copy them.
            Purpose::Card | Purpose::TransferTo => last_four_typed(digits),
            Purpose::WithdrawAmount => format!("${digits}"),
            // Like a real ATM: digits fill in from the cents side.
            Purpose::TransferAmount => {
                typed_amount(digits, st.currency).map(|c| st.currency.format(c)).unwrap_or_default()
            }
            Purpose::DepositCount => match &st.pending {
                Pending::Deposit { current: Some(bill), .. } => {
                    let count: i64 = digits.parse().unwrap_or(0);
                    let total = bill.times(count).map(|c| c.to_string()).unwrap_or_default();
                    format!("{count} × ${} = {total}", bill.dollars())
                }
                _ => digits.to_string(),
            },
            _ => digits.to_string(),
        };
        bank.set_entry_display(display.into());
        bank.set_entry_length(digits.len() as i32);
    }

    /// Logs out whoever is signed in (each logout is audited by the library).
    pub fn end_all_sessions(&self, st: &mut State) {
        let mut atm = self.atm();
        // A failed log write must not keep anyone signed in: the session is
        // consumed either way, so ignoring the result is safe here.
        if let Some(s) = st.customer.take() {
            let _ = auth::logout_customer(&mut atm, s);
        }
        if let Some(s) = st.admin.take() {
            let _ = auth::logout_admin(&mut atm, s);
        }
        if let Some(s) = st.handler.take() {
            let _ = auth::logout_handler(&mut atm, s);
        }
        st.pending = Pending::None;
        st.login_card = None;
        st.youth.clear();
        st.recent.clear();
        st.rate_feed = None;
        st.close_armed = None;
        st.cash_out = None;
        st.entry.zeroize();
    }

    /// Ends any session and returns to the welcome screen with `message`.
    /// Every property that held someone's data is wiped, not just hidden.
    pub fn go_welcome(&self, st: &mut State, message: &str) {
        self.end_all_sessions(st);
        st.currency = atm::fx::Currency::Usd;
        st.history_page = 0;
        st.activity_account.clear();
        st.activity_page = 0;
        st.audit_page = 0;
        let window = self.window();
        let bank = window.global::<Bank>();
        for clear in [
            Bank::set_holder,
            Bank::set_account_masked,
            Bank::set_account_kind,
            Bank::set_balance,
            Bank::set_balance_note,
            Bank::set_staff_id,
            Bank::set_entry_display,
            Bank::set_confirm_title,
            Bank::set_sum_note,
            Bank::set_confirm_extra,
            Bank::set_result_title,
            Bank::set_cash_bills,
            Bank::set_youth_title,
            Bank::set_youth_withdraw_cap,
            Bank::set_youth_transfer_cap,
            Bank::set_selected_account,
            Bank::set_limit_withdrawal,
            Bank::set_limit_deposit,
            Bank::set_limit_transfer,
            Bank::set_signin_problem,
            Bank::set_service_since,
            Bank::set_service_reason,
            Bank::set_cash_total,
        ] {
            clear(&bank, "".into());
        }
        bank.set_account_currency("USD".into());
        bank.set_activity_title("Account activity".into());
        // Wipe tables and lists that held other people's data.
        for clear in [
            Bank::set_history_rows,
            Bank::set_limit_rows,
            Bank::set_youth_rows,
            Bank::set_youth_history_rows,
            Bank::set_account_rows,
            Bank::set_activity_rows,
            Bank::set_locked_rows,
            Bank::set_hold_rows,
            Bank::set_rate_rows,
            Bank::set_rate_history_rows,
            Bank::set_rate_feed_rows,
            Bank::set_audit_rows,
            Bank::set_cash_rows,
        ] {
            clear(&bank, table(Vec::new()));
        }
        for clear in [
            Bank::set_entry_choices,
            Bank::set_confirm_lines,
            Bank::set_result_lines,
            Bank::set_integrity_lines,
        ] {
            clear(&bank, strings(Vec::new()));
        }
        bank.set_sum_rows(ModelRc::default());
        for clear in [
            Bank::set_frozen,
            Bank::set_on_hold,
            Bank::set_is_guardian,
            Bank::set_is_guest,
            Bank::set_youth_family_only,
            Bank::set_youth_frozen,
            Bank::set_activity_shown,
            Bank::set_rate_history_shown,
            Bank::set_rate_feed_shown,
            Bank::set_integrity_ok,
            Bank::set_integrity_ran,
            Bank::set_idle_warning,
        ] {
            clear(&bank, false);
        }
        bank.set_youth_selected(-1);
        bank.set_entry_length(0);
        bank.set_screen(screen::WELCOME);
        bank.set_message_ok(true);
        bank.set_message(message.into());
        self.out_of_service();
        st.service_checked = Some(Instant::now());
    }

    /// Shows a library error. Errors that end the session (timed out, card
    /// locked meanwhile) return to the welcome screen.
    pub fn fail(&self, st: &mut State, e: AtmError) {
        if ends_session(&e) {
            // A Cash Handler stopped by a halt is told who can still sign in.
            let text = match e {
                AtmError::OutOfService if st.handler.is_some() => STAFF_HALTED.to_string(),
                _ => e.to_string(),
            };
            self.go_welcome(st, &text);
            self.window().global::<Bank>().set_message_ok(false);
        } else {
            self.error(e);
        }
    }

    fn tick(&self) {
        let window = self.window();
        let bank = window.global::<Bank>();
        bank.set_clock(
            Utc::now().with_timezone(&New_York).format("%a %b %-d  ·  %-I:%M %p").to_string().into(),
        );

        let mut st = self.state();
        let idle = st.last_activity.elapsed();
        let signed_in = st.customer.is_some() || st.admin.is_some() || st.handler.is_some();
        if signed_in {
            if idle >= IDLE_LIMIT {
                self.go_welcome(&mut st, "Your session ended because of inactivity.");
            } else if idle >= IDLE_WARNING {
                bank.set_idle_warning(true);
                bank.set_idle_seconds_left((IDLE_LIMIT - idle).as_secs() as i32);
            }
        } else if ![screen::WELCOME, screen::SETUP].contains(&bank.get_screen()) && idle >= IDLE_LOGIN {
            self.go_welcome(&mut st, "");
        } else if bank.get_screen() == screen::WELCOME
            && st.service_checked.is_none_or(|t| t.elapsed() >= SERVICE_CHECK)
        {
            // Out of service: no cards; picked up within a few seconds.
            let was = bank.get_service_halted();
            if self.out_of_service() != was {
                bank.set_message("".into()); // an old notice no longer applies
            }
            st.service_checked = Some(Instant::now());
        }
    }

    fn more_time(&self, yes: bool) {
        let mut st = self.state();
        if !yes {
            self.go_welcome(&mut st, "Session ended. Thank you.");
            return;
        }
        drop(st);
        self.touch();
        // One harmless library call, so the library's own idle timer resets too.
        let mut st = self.state();
        let refreshed = {
            let atm = self.atm();
            if let Some(s) = &st.customer {
                atm::customer::balance(&atm, s).map(|_| ())
            } else if let Some(s) = &st.admin {
                atm::admin::bank_limits(&atm, s).map(|_| ())
            } else if let Some(s) = &st.handler {
                atm::cash::view(&atm, s).map(|_| ())
            } else {
                Ok(())
            }
        };
        if let Err(e) = refreshed {
            self.fail(&mut st, e);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers shared by customer.rs and staff.rs
// ---------------------------------------------------------------------------

/// Errors after which the session is gone.
pub fn ends_session(e: &AtmError) -> bool {
    matches!(e, AtmError::SessionExpired | AtmError::CardLocked | AtmError::OutOfService)
}

/// Rows of cells, for the `[[string]]` tables.
pub fn table(rows: Vec<Vec<String>>) -> ModelRc<ModelRc<SharedString>> {
    let rows: Vec<ModelRc<SharedString>> = rows.into_iter().map(strings).collect();
    ModelRc::new(VecModel::from(rows))
}

pub fn strings(items: Vec<String>) -> ModelRc<SharedString> {
    let items: Vec<SharedString> = items.into_iter().map(SharedString::from).collect();
    ModelRc::new(VecModel::from(items))
}

/// A stored UTC timestamp ("2026-10-11T21:52:09Z") in bank time (New York).
/// The year is shown only when it isn't this year, to keep columns short.
pub fn time(ts: &str) -> String {
    let Ok(t) = DateTime::parse_from_rfc3339(ts) else { return ts.to_string() };
    let local = t.with_timezone(&New_York);
    if local.format("%Y").to_string() == Utc::now().with_timezone(&New_York).format("%Y").to_string() {
        local.format("%b %-d, %-I:%M %p").to_string()
    } else {
        local.format("%b %-d %Y, %-I:%M %p").to_string()
    }
}

/// Money for an editable field: `1234.50`, no `$` or commas.
pub fn plain(amount: Cents) -> String {
    format!("{}.{:02}", amount.as_i64() / 100, amount.as_i64() % 100)
}

/// Bills as "2 × $50, 1 × $20".
pub fn bills_text(plan: &[(Denomination, i64)]) -> String {
    plan.iter()
        .filter(|(_, n)| *n > 0)
        .map(|(d, n)| format!("{n} × ${}", d.dollars()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Transfer amount from keypad digits: cents first ("2500" = 25.00), or
/// whole yen or won ("2500" = 2,500 JPY), which have no cents.
pub fn typed_amount(digits: &str, currency: atm::fx::Currency) -> Option<Cents> {
    digits.parse::<i64>().ok()?.checked_mul(currency.step()).and_then(|v| Cents::new(v).ok())
}

/// Card or account number being typed: dots, then the last 4 digits.
fn last_four_typed(digits: &str) -> String {
    let hidden = digits.len().saturating_sub(4);
    "•".repeat(hidden) + &digits[hidden..]
}

/// "individual" -> "Individual".
pub fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    chars.next().map(|c| c.to_uppercase().collect::<String>() + chars.as_str()).unwrap_or_default()
}
