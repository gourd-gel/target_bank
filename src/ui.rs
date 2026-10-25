//! CLI menus, prompts and printing. No security decisions here: every rule is
//! enforced in the library, so a bug in the menus can't skip a check.
//! The GUI replaces this file and calls the same library functions.
//!
//! STRIDE (Elevation of Privilege): each role's menu only exists after that
//! role's login returns its session type.

use atm::Atm;
use atm::admin::{self, NewCard};
use atm::audit::Row;
use atm::auth::{self, AdminSession, CardAndPin, CustomerSession, HandlerSession, HolderRole};
use atm::customer::{self, Receipt, mask};
use atm::db::Limit;
use atm::dispense::BillChoice;
use atm::error::{AtmError, Result};
use atm::family::{self, Direction, YouthControls};
use atm::fx::{self, Currency, Fee};
use atm::money::{Cents, DENOMINATIONS, Denomination};
use atm::{cash, input, review, service};
use zeroize::Zeroizing;

/// Show an error the way a user should see it (developer detail in debug builds only).
fn report(error: &AtmError) {
    println!("\n  ! {error}");
    #[cfg(debug_assertions)]
    if let AtmError::Internal(detail) = error {
        eprintln!("  [debug] {detail}");
    }
}

/// Show an action's error and keep going. A session that ended (or Eof) is
/// passed up: the flow wipes the screen, then the main menu shows why.
fn run_action(result: Result<()>) -> Result<()> {
    match result {
        Err(e @ (AtmError::Eof | AtmError::SessionExpired | AtmError::OutOfService)) => Err(e),
        Err(e) => {
            report(&e);
            Ok(())
        }
        Ok(()) => Ok(()),
    }
}

/// Read a menu choice; re-ask after unusable input instead of logging out.
fn read_choice() -> Result<String> {
    loop {
        match input::read_line("> ") {
            Ok(choice) => return Ok(choice),
            Err(AtmError::Eof) => return Err(AtmError::Eof),
            Err(e) => report(&e),
        }
    }
}

fn read_bill(prompt: &str) -> Result<Denomination> {
    Denomination::new(input::read_u32(prompt)?)
}

fn new_secret(what: &str) -> Result<Zeroizing<String>> {
    let first = input::read_secret(&format!("{what}: "))?;
    let second = input::read_secret(&format!("{what} again: "))?;
    if first != second {
        return Err(AtmError::InvalidInput("the two entries did not match"));
    }
    Ok(first)
}

// ---------------------------------------------------------------------------
// First run and top level
// ---------------------------------------------------------------------------

pub fn first_run_setup(atm: &mut Atm) -> Result<()> {
    println!("=== Bank of CCNY ATM: first-time setup ===");
    println!("Create the Teller Admin and Cash Handler logins.");
    println!("Usernames: 3-32 of a-z, 0-9, _. Passwords: at least 12 characters.\n");
    loop {
        let attempt = (|| {
            let admin_user = input::read_line("Teller Admin username: ")?;
            let admin_pass = new_secret("Teller Admin password")?;
            let handler_user = input::read_line("Cash Handler username: ")?;
            let handler_pass = new_secret("Cash Handler password")?;
            auth::first_run_setup(atm, &admin_user, &admin_pass, &handler_user, &handler_pass)
        })();
        match attempt {
            Ok(()) => {
                println!("\nSetup complete. Keep atm.key safe: without it the database can't be opened.");
                return Ok(());
            }
            Err(AtmError::Eof) => return Err(AtmError::Eof),
            Err(e) => {
                report(&e);
                println!("  Let's try that again.\n");
            }
        }
    }
}

pub fn main_menu(atm: &mut Atm) -> Result<()> {
    loop {
        println!("\n=== Bank of CCNY ATM ===");
        if service::out_of_service(atm)? {
            println!("  *** OUT OF SERVICE: no cards accepted; Teller Admin sign-in only ***");
        }
        println!("  1) Customer");
        println!("  2) Teller Admin");
        println!("  3) Cash Handler");
        println!("  0) Exit");
        let Ok(choice) = read_choice() else { return Ok(()) };
        let result = match choice.as_str() {
            "1" => customer_flow(atm),
            "2" => admin_flow(atm),
            "3" => handler_flow(atm),
            "0" => return Ok(()),
            _ => Err(AtmError::InvalidInput("choose 0 to 3")),
        };
        if let Err(e) = result {
            if matches!(e, AtmError::Eof) {
                return Ok(());
            }
            report(&e);
        }
    }
}

// ---------------------------------------------------------------------------
// Customer
// ---------------------------------------------------------------------------

fn customer_flow(atm: &mut Atm) -> Result<()> {
    // Out of service: the card isn't taken at all.
    if service::out_of_service(atm)? {
        return Err(AtmError::OutOfService);
    }
    // Hidden like the PIN (shoulder surfing); only the last 4 digits echo back.
    let card = input::read_secret("Card number (hidden): ")?;
    println!("  Card {}", mask(&card));
    let pin = input::read_secret("PIN: ")?;
    let session = auth::login_customer(atm, &card, &pin)?;
    drop(pin); // wiped now (Zeroizing): shortest possible lifetime for the plaintext PIN
    let result = customer_menu(atm, &session);
    let logged_out = auth::logout_customer(atm, session); // audited; session is gone
    input::wipe_screen(); // logged out or timed out: nothing left on screen
    result.and(logged_out)
}

fn customer_menu(atm: &mut Atm, s: &CustomerSession) -> Result<()> {
    loop {
        let info = customer::account_info(atm, s);
        let header = match &info {
            Ok(i) => format!(
                "{}, {} {} account {}{}",
                i.holder_name,
                i.kind,
                i.currency.code(),
                i.account,
                if i.frozen {
                    " (FROZEN)"
                } else if i.on_hold {
                    " (ON HOLD: see a teller)"
                } else {
                    ""
                }
            ),
            Err(_) => "account".to_string(),
        };
        println!("\n--- Customer: {header} ---");
        // Other banks' cards: the library refuses the rest; the menu just hides it.
        let guest = s.role() == HolderRole::Guest;
        println!("  1) Balance           2) Daily limits");
        if guest {
            println!("  3) Withdraw (card from another bank: ATM fee applies)");
        } else {
            println!("  3) Withdraw          4) Deposit");
            println!("  5) Transfer          6) Recent transactions");
            println!("  8) Change PIN");
        }
        if s.role() == HolderRole::Owner || s.role() == HolderRole::Joint {
            println!("  7) Family (youth accounts I manage)");
        }
        println!("  0) Log out");
        let choice = read_choice()?;
        let result = match choice.as_str() {
            "1" => show_balance(atm, s),
            "2" => show_limits(atm, s),
            "3" => withdraw(atm, s),
            "4" => deposit(atm, s),
            "5" => transfer(atm, s),
            "6" => page_through(|page| customer::history(atm, s, page), |rows| print_history(rows, s)),
            "7" if s.role() == HolderRole::Owner || s.role() == HolderRole::Joint => family_menu(atm, s),
            "8" => change_pin(atm, s),
            "0" => return Ok(()),
            _ => Err(AtmError::InvalidInput("choose a listed option")),
        };
        run_action(result)?;
    }
}

fn show_balance(atm: &Atm, s: &CustomerSession) -> Result<()> {
    let info = customer::account_info(atm, s)?;
    println!("\n  Balance: {}", info.currency.format(customer::balance(atm, s)?));
    if info.on_hold {
        println!("  {}", AtmError::OnHold);
    }
    if let Some(fee) = info.atm_fee {
        println!("  This card is from another bank. Each withdrawal here has an ATM fee of {}.", fee.text());
    }
    if info.currency != Currency::Usd {
        println!(
            "  Cash is paid in US dollars. {}",
            match &info.rate {
                Some(rate) => format!("Today's rate: {rate}."),
                None => "No current exchange rate: please see a teller.".to_string(),
            }
        );
    }
    Ok(())
}

fn show_limits(atm: &Atm, s: &CustomerSession) -> Result<()> {
    println!("\n  Limits are in US dollars.");
    for st in customer::limits(atm, s)? {
        println!(
            "  Daily {:<10} limit: {:>12}   remaining today: {:>12}",
            st.limit.label(),
            st.per_day.to_string(),
            st.remaining_today.to_string()
        );
        if !st.approved_today.is_zero() {
            println!("    (includes {} extra approved by a teller for today)", st.approved_today);
        }
    }
    Ok(())
}

fn print_receipt(r: &Receipt) {
    println!("\n  ----- RECEIPT -----");
    println!("  Ref #{}   {}", r.reference, r.timestamp);
    println!("  {} of {}  account {}", r.kind, r.currency.format(r.amount), r.account);
    if let Some(to) = &r.counterparty {
        println!("  To account {to}");
    }
    for row in &r.summary {
        println!("  {:<26}{:>16}", row.label, row.amount);
    }
    if !r.fine_print.is_empty() {
        println!("  {}", r.fine_print);
    }
    if !r.bills.is_empty() {
        println!("  Bills: {}", cash::describe(&r.bills));
    }
    println!("  Balance after: {}", r.currency.format(r.balance_after));
    println!("  -------------------");
}

fn withdraw(atm: &mut Atm, s: &CustomerSession) -> Result<()> {
    let amount = Cents::parse(&input::read_line("Amount to withdraw (US dollars): $")?)?;
    let charge = customer::check_withdrawal(atm, s, amount)?;
    // Fees or a conversion: show every part before the customer commits.
    if !charge.fees.is_empty() || charge.rate.is_some() {
        println!();
        for line in charge.breakdown(false) {
            println!("  {line}");
        }
        if !input::confirm("OK? (y/n) ")? {
            println!("\n  Cancelled.");
            return Ok(());
        }
    }
    println!("How would you like your cash?");
    println!("  1) All in one bill type   2) Mostly one bill type, rest mixed   3) Fewest bills");
    let choice = match input::read_line("> ")?.as_str() {
        "1" => BillChoice::Only(read_bill("Which bill ($5, 10, 20, 50, 100)? $")?),
        "2" => BillChoice::Prefer(read_bill("Preferred bill ($5, 10, 20, 50, 100)? $")?),
        "3" => BillChoice::Any,
        _ => return Err(AtmError::InvalidInput("choose 1 to 3")),
    };
    let receipt = match customer::withdraw(atm, s, amount, choice) {
        // Spec: reject and say which bills are available; then offer mixed bills.
        // Over 40 bills in one type: offer the fewest bills instead.
        Err(
            e @ (AtmError::DenominationUnavailable { mixed_possible: true, .. }
            | AtmError::TooManyBills { .. }),
        ) if choice != BillChoice::Any => {
            report(&e);
            let plan = match customer::quote_withdrawal(atm, s, amount, BillChoice::Any) {
                Err(AtmError::TooManyBills { .. }) => return Ok(()), // already said
                other => other?,
            };
            if !input::confirm(&format!("Take {} instead? (y/n) ", cash::describe(&plan)))? {
                println!("\n  Cancelled.");
                return Ok(());
            }
            customer::withdraw(atm, s, amount, BillChoice::Any)?
        }
        other => other?,
    };
    println!("\n  Please take your cash.");
    print_receipt(&receipt);
    Ok(())
}

fn deposit(atm: &mut Atm, s: &CustomerSession) -> Result<()> {
    println!("Enter how many of each bill you are inserting (0 for none).");
    let mut bills = Vec::new();
    let mut total = Cents::ZERO;
    for d in DENOMINATIONS {
        let count = input::read_u32(&format!("  ${d} bills: "))?;
        let bill = Denomination::new(d)?;
        total = total
            .checked_add(bill.times(i64::from(count))?)
            .ok_or(AtmError::InvalidInput("too many bills"))?;
        bills.push((bill, count));
    }
    // Account in another currency: show the rate and exchange fee first.
    let credit = customer::preview_deposit(atm, s, total)?;
    if credit.rate.is_some() {
        println!();
        for line in credit.breakdown(true) {
            println!("  {line}");
        }
        if !input::confirm("OK? (y/n) ")? {
            println!("\n  Cancelled.");
            return Ok(());
        }
    }
    print_receipt(&customer::deposit(atm, s, &bills)?);
    Ok(())
}

fn transfer(atm: &mut Atm, s: &CustomerSession) -> Result<()> {
    let to = pick_destination(atm, s)?;
    // Checks the account exists and shows initials, so a typo is caught before sending.
    let initials = customer::recipient_hint(atm, s, &to)?;
    let currency = customer::account_info(atm, s)?.currency;
    let amount =
        currency.parse_amount(&input::read_line(&format!("Amount to transfer ({}): ", currency.code()))?)?;
    let shown = currency.format(amount);
    if !input::confirm(&format!("Send {shown} to account {} ({initials})? (y/n) ", mask(&to)))? {
        println!("\n  Cancelled.");
        return Ok(());
    }
    print_receipt(&customer::transfer(atm, s, &to, amount)?);
    Ok(())
}

/// "Send again" from recent payees (masked), or type a number (hidden).
fn pick_destination(atm: &Atm, s: &CustomerSession) -> Result<Zeroizing<String>> {
    let recent = customer::recent_payees(atm, s)?;
    if !recent.is_empty() {
        println!("\n  Send again:");
        for (i, p) in recent.iter().enumerate() {
            println!(
                "  {}) {}  {}   last {} on {}",
                i + 1,
                p.masked,
                p.initials,
                p.currency.format(p.last_amount),
                p.last_date
            );
        }
        let pick = input::read_line("Choose one, or press Enter to type an account number: ")?;
        if !pick.is_empty() {
            let index = pick.parse::<usize>().ok().and_then(|n| n.checked_sub(1));
            let payee =
                index.and_then(|i| recent.get(i)).ok_or(AtmError::InvalidInput("choose a listed account"))?;
            return Ok(Zeroizing::new(payee.number.clone()));
        }
    }
    input::read_secret("Destination account number (hidden): ")
}

fn change_pin(atm: &mut Atm, s: &CustomerSession) -> Result<()> {
    let current = input::read_secret("Current PIN: ")?;
    let new = new_secret("New PIN (4-12 digits)")?;
    customer::change_pin(atm, s, &current, &new)?;
    println!("\n  PIN changed. Use the new PIN next time.");
    Ok(())
}

/// Show one page at a time: Enter = done, n = next page.
fn page_through(mut fetch: impl FnMut(u32) -> Result<Vec<Row>>, print: impl Fn(&[Row])) -> Result<()> {
    let mut page = 0;
    loop {
        let rows = fetch(page)?;
        if rows.is_empty() {
            println!("\n  {}", if page == 0 { "Nothing to show yet." } else { "No more entries." });
            return Ok(());
        }
        print(&rows);
        if !input::read_line("  n = next page, Enter = back: ")?.eq_ignore_ascii_case("n") {
            return Ok(());
        }
        page += 1;
    }
}

fn print_history(rows: &[Row], s: &CustomerSession) {
    println!("\n  {:<21} {:<11} {:>12}  Details", "When (UTC)", "Type", "Amount");
    for row in rows {
        let amount = row.amount.map(|a| row.currency.format(a)).unwrap_or_default();
        // Transfers: show direction; the other account is masked.
        let mine = row.account_number.as_deref() == Some(s.account_number());
        let details = match (row.action.as_str(), mine) {
            ("transfer", true) => format!("to {}", mask(row.counterparty_number.as_deref().unwrap_or(""))),
            ("transfer", false) => format!("from {}", mask(row.account_number.as_deref().unwrap_or(""))),
            _ => row.detail.clone(),
        };
        println!("  {:<21} {:<11} {:>12}  {}", row.ts, row.action, amount, details);
    }
}

// ---------------------------------------------------------------------------
// Family (guardian) menu
// ---------------------------------------------------------------------------

fn family_menu(atm: &mut Atm, s: &CustomerSession) -> Result<()> {
    let kids = family::my_youth_accounts(atm, s)?;
    if kids.is_empty() {
        println!("\n  You don't manage any youth accounts.");
        return Ok(());
    }
    println!();
    for (i, k) in kids.iter().enumerate() {
        println!(
            "  {}) {} ({})  balance {}{}  | caps: withdraw {}/day, transfer {}/day, family-only {}",
            i + 1,
            k.child_name,
            k.account_number,
            k.balance,
            if k.bank_frozen {
                " FROZEN by the bank"
            } else if k.frozen {
                " FROZEN"
            } else {
                ""
            },
            k.controls.daily_withdraw_cap,
            k.controls.daily_transfer_cap,
            if k.controls.family_only_transfers { "on" } else { "off" }
        );
    }
    let pick = input::read_u32("Which child? ")? as usize;
    let kid = kids.get(pick.wrapping_sub(1)).ok_or(AtmError::InvalidInput("choose a listed child"))?;
    let number = kid.account_number.clone();
    println!("  1) Recent transactions  2) Change spending caps  3) Freeze  4) Unfreeze");
    println!("  5) Move money to {}      6) Take money back to my account", kid.child_name);
    match input::read_line("> ")?.as_str() {
        "1" => page_through(|p| family::youth_history(atm, s, &number, p), print_rows_brief),
        "2" => {
            let w = Cents::parse(&input::read_line("Daily withdrawal cap: $")?)?;
            let t = Cents::parse(&input::read_line("Daily transfer cap: $")?)?;
            let f = input::confirm("Only allow transfers to family? (y/n) ")?;
            let controls =
                YouthControls { daily_withdraw_cap: w, daily_transfer_cap: t, family_only_transfers: f };
            family::set_controls(atm, s, &number, controls).map(|_| println!("\n  Controls updated."))
        }
        "3" => family::set_frozen(atm, s, &number, true).map(|_| println!("\n  Account frozen.")),
        "4" => family::set_frozen(atm, s, &number, false).map(|_| println!("\n  Account unfrozen.")),
        "5" => family_move(atm, s, &number, Direction::ToChild),
        "6" => family_move(atm, s, &number, Direction::FromChild),
        _ => Err(AtmError::InvalidInput("choose 1 to 6")),
    }
}

/// Guardian moves money between their own account and the child's.
fn family_move(atm: &mut Atm, s: &CustomerSession, child: &str, direction: Direction) -> Result<()> {
    let currency = customer::account_info(atm, s)?.currency;
    let amount = currency.parse_amount(&input::read_line(&format!("Amount ({}): ", currency.code()))?)?;
    let m = family::move_money(atm, s, child, direction, amount)?;
    println!(
        "\n  Moved {}. Ref #{}. Your balance: {}. Child's balance: {}.",
        m.currency.format(m.amount),
        m.reference,
        m.currency.format(m.your_balance),
        m.currency.format(m.child_balance)
    );
    Ok(())
}

fn print_rows_brief(rows: &[Row]) {
    for row in rows {
        let amount = row.amount.map(|a| row.currency.format(a)).unwrap_or_default();
        println!("  {:<21} {:<11} {:>12}  {}", row.ts, row.action, amount, row.detail);
    }
}

// ---------------------------------------------------------------------------
// Teller Admin
// ---------------------------------------------------------------------------

fn admin_flow(atm: &mut Atm) -> Result<()> {
    let username = input::read_line("Admin username: ")?;
    let password = input::read_secret("Password: ")?;
    let session = auth::login_admin(atm, &username, &password)?;
    drop(password);
    service_banner(atm, &session)?;
    let result = admin_menu(atm, &session);
    let logged_out = auth::logout_admin(atm, session);
    input::wipe_screen(); // logged out or timed out: nothing left on screen
    result.and(logged_out)
}

/// Red banner at sign-in: the automatic integrity check failed, or the ATM
/// is out of service for another reason.
fn service_banner(atm: &Atm, s: &AdminSession) -> Result<()> {
    const RED: &str = "\x1b[1;37;41m";
    const OFF: &str = "\x1b[0m";
    if let Some(problem) = s.integrity_problem() {
        println!("\n{RED} INTEGRITY CHECK FAILED AT SIGN-IN {OFF}");
        println!("  {problem}");
    }
    let status = service::status(atm, s)?;
    if status.out_of_service {
        println!("{RED} ATM OUT OF SERVICE since {} {OFF}", status.since);
        println!("  {}", status.reason);
        println!("  Customers can't use the ATM. Review, then choose 18 to resume service.");
    }
    Ok(())
}

fn halt_or_resume(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    if service::status(atm, s)?.out_of_service {
        if !input::confirm("The ATM is out of service. Resume service now that you've reviewed it? (y/n) ")? {
            return Ok(());
        }
        match service::resume(atm, s)? {
            None => println!("\n  Back in service. The integrity check passes."),
            Some(still) => println!(
                "\n  Back in service, but the integrity check still fails: {still}\n  \
                 This is logged, and the next Teller Admin sign-in will halt it again."
            ),
        }
    } else if input::confirm("Take the ATM out of service now? Customers will be turned away. (y/n) ")? {
        service::halt(atm, s)?;
        println!("\n  The ATM is out of service. Choose 18 again to resume.");
    }
    Ok(())
}

fn admin_menu(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    loop {
        println!("\n--- Teller Admin ---");
        println!("  1) Create customer account     2) Add joint holder");
        println!("  3) Open youth account          4) Add guardian to youth account");
        println!("  5) View account audit log      6) Set daily limits");
        println!("  7) Locked cards / unlock       8) Freeze or unfreeze account");
        println!("  9) Verify audit log + balances 10) List all accounts");
        println!(" 11) All recent events           12) Close an account ($0 balance)");
        println!(" 13) Change my password          14) Exchange rates and fees");
        println!(" 15) Register another bank's card (guest, simulated network)");
        println!(" 16) Approve a larger amount for today (customer at the counter)");
        println!(" 17) Accounts on hold for unusual activity / release");
        println!(" 18) Halt the ATM / resume service");
        println!("  0) Log out");
        let choice = read_choice()?;
        let result = match choice.as_str() {
            "1" => create_customer(atm, s),
            "2" => add_joint(atm, s),
            "3" => open_youth(atm, s),
            "4" => add_guardian(atm, s),
            "5" => show_audit(atm, s),
            "6" => set_limit(atm, s),
            "7" => unlock(atm, s),
            "8" => freeze(atm, s),
            "9" => admin::verify_integrity(atm, s).map(|r| {
                println!(
                    "\n  OK: {} log entries, {} balances, the cash ({}) and {} settings/rates verified;",
                    r.entries, r.accounts_checked, r.cash, r.records_checked
                );
                println!("  {} limits, rates and account flags match the log.", r.state_checked);
                println!("  Head: {} (write this down to detect later rollback)", r.head);
            }),
            "10" => list_accounts(atm, s),
            "11" => page_through(|page| admin::recent_audit(atm, s, page), print_audit_rows),
            "12" => close_account(atm, s),
            "13" => {
                let current = input::read_secret("Current password: ")?;
                let new = new_secret("New password (12+ characters)")?;
                auth::change_admin_password(atm, s, &current, &new).map(|_| println!("\n  Password changed."))
            }
            "14" => rates_menu(atm, s),
            "15" => register_guest(atm, s),
            "16" => raise_limit(atm, s),
            "17" => review_holds(atm, s),
            "18" => halt_or_resume(atm, s),
            "0" => return Ok(()),
            _ => Err(AtmError::InvalidInput("choose 0 to 18")),
        };
        run_action(result)?;
    }
}

/// Name, DOB and PIN (typed twice, by the customer) for a new card holder.
fn holder_details(pin_label: &str) -> Result<(String, String, Zeroizing<String>)> {
    let name = input::read_line("Full name: ")?;
    input::validate_name(&name)?;
    let dob = input::read_line("Date of birth (YYYY-MM-DD): ")?;
    println!("Hand the keypad to the {pin_label} to choose a PIN (4-12 digits).");
    let pin = new_secret("PIN")?;
    Ok((name, dob, pin))
}

fn print_new_card(card: &NewCard) {
    println!("\n  Done. Account number: {}  (for receiving transfers)", card.account_number);
    println!("        Card number:    {}  (for logging in with the PIN)", card.card_number);
}

/// Account currency: Enter = US dollars.
fn read_currency() -> Result<Currency> {
    let codes: Vec<&str> = Currency::FOREIGN.iter().map(|c| c.code()).collect();
    let code = input::read_line(&format!("Currency (Enter = USD; or {}): ", codes.join(", ")))?;
    if code.is_empty() { Ok(Currency::Usd) } else { Currency::parse(&code.to_ascii_uppercase()) }
}

fn create_customer(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let (name, dob, pin) = holder_details("customer")?;
    let balance = Currency::Usd.parse_amount(&input::read_line("Starting balance (USD): ")?)?;
    print_new_card(&admin::create_customer(atm, s, &name, &dob, &pin, balance)?);
    Ok(())
}

/// Stands in for the card network: another bank's card, usable here for
/// withdrawals (with the ATM fee) and balance checks only.
fn register_guest(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let (name, dob, pin) = holder_details("card holder")?;
    let currency = read_currency()?;
    let balance = currency
        .parse_amount(&input::read_line(&format!("Balance at their bank ({}): ", currency.code()))?)?;
    print_new_card(&admin::register_guest_card(atm, s, &name, &dob, &pin, balance, currency)?);
    Ok(())
}

/// Show today's rates and fee; set one rate or the fee.
fn rates_menu(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    println!("\n  Rates are units per US dollar. They expire after {} hours.", fx::RATE_MAX_AGE_HOURS);
    println!("  A typed rate can move at most 5% within 24 hours. Today's feed sets the market");
    println!("  rate; a move over 5% is set but paused until you check it and resume.");
    for r in fx::rates(atm, s)? {
        let shown = match &r.rate {
            _ if r.tampered => "ALTERED outside the ATM: re-enter it".to_string(),
            Some(rate) => format!(
                "{:<10} set {} by {}{}",
                rate.text(),
                rate.set_at,
                rate.set_by,
                if rate.paused {
                    "  PAUSED"
                } else if rate.is_stale() {
                    "  OUT OF DATE"
                } else {
                    ""
                }
            ),
            None => "not set".to_string(),
        };
        println!("  {} {:<16} {}", r.currency.code(), r.currency.name(), shown);
    }
    for fee in Fee::ALL {
        println!("  {}: {}", fee.label(), fx::fee_rule(atm, s, fee)?.text());
    }
    println!("  1) Set a rate   2) Set the exchange fee   3) Set the other bank's ATM fee");
    println!("  4) Pause a currency   5) Resume a currency   6) Pause all   7) Rate history");
    if cfg!(feature = "online-rates") {
        println!("  8) Check today's rates online, then approve");
    }
    println!("  0) Back");
    match input::read_line("> ")?.as_str() {
        "1" => {
            let currency = Currency::parse(&input::read_line("Currency code: ")?.to_ascii_uppercase())?;
            let rate = input::read_line(&format!("{} per 1 US dollar: ", currency.code()))?;
            fx::set_rate(atm, s, currency, &rate)?;
            println!("\n  Rate saved.");
        }
        choice @ ("2" | "3") => {
            let fee = if choice == "2" { Fee::Exchange } else { Fee::OtherBank };
            println!("  Each fee is the percent of the cash, or the minimum if that is higher.");
            let percent = input::read_line("Percent (0 to 5): ")?;
            let minimum = input::read_line("Minimum in dollars (0 to 10): $")?;
            fx::set_fee_rule(atm, s, fee, &percent, &minimum)?;
            println!("\n  {} saved.", fee.label());
        }
        choice @ ("4" | "5") => {
            let currency = Currency::parse(&input::read_line("Currency code: ")?.to_ascii_uppercase())?;
            fx::set_paused(atm, s, Some(currency), choice == "4")?;
            println!("\n  Done (logged).");
        }
        "6" => {
            fx::set_paused(atm, s, None, true)?;
            println!("\n  Exchanges paused for every currency (logged).");
        }
        "7" => {
            for r in fx::rate_history(atm, s, None, 50)? {
                println!("  {}  {} {:<10} by {}", r.set_at, r.currency.code(), r.text(), r.set_by);
            }
        }
        #[cfg(feature = "online-rates")]
        "8" => check_feed(atm, s)?,
        _ => {}
    }
    Ok(())
}

/// Fetch today's feed, show old vs new for every currency, approve all or nothing.
#[cfg(feature = "online-rates")]
fn check_feed(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    use atm::rate_feed;
    let feed = rate_feed::fetch(atm, s)?;
    let shown = rate_feed::check(atm, s, &feed)?;
    println!("\n  Today's rates from {}, published {}.", rate_feed::FEED_SOURCE, feed.published());
    println!("  {:<5}{:>14}{:>14}{:>14}  Note", "", "Now", "Feed", "Will set");
    for c in &shown {
        let set = c.set_to.as_deref().unwrap_or("-");
        println!("  {:<5}{:>14}{:>14}{:>14}  {}", c.currency.code(), c.current, c.feed, set, c.note);
    }
    println!("  {}", rate_feed::FEED_CREDIT);
    if input::confirm("Approve these rates? (y/n) ")? {
        let n = rate_feed::approve(atm, s, &feed, &shown)?;
        println!("\n  {n} rates set and logged.");
    } else {
        println!("\n  Nothing changed.");
    }
    Ok(())
}

/// The customer at the counter types their own card's PIN (the core checks it).
fn at_counter(who: &str) -> Result<(String, Zeroizing<String>)> {
    let card = input::read_line(&format!("{who}'s card number: "))?;
    println!("Hand the keypad to the {} to type their PIN.", who.to_lowercase());
    let pin = input::read_secret("PIN: ")?;
    Ok((card, pin))
}

fn add_joint(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let account = input::read_line("Existing account number: ")?;
    let (card, card_pin) = at_counter("Current holder")?;
    let holder = CardAndPin { card_number: &card, pin: &card_pin };
    let (name, dob, pin) = holder_details("new joint holder")?;
    print_new_card(&admin::add_joint_holder(atm, s, &account, holder, &name, &dob, &pin)?);
    Ok(())
}

fn open_youth(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let (card, card_pin) = at_counter("Guardian")?;
    let guardian = CardAndPin { card_number: &card, pin: &card_pin };
    println!("Child's details:");
    let (name, dob, pin) = holder_details("child")?;
    let balance = Cents::parse(&input::read_line("Starting balance: $")?)?;
    print_new_card(&admin::open_youth_account(atm, s, guardian, &name, &dob, &pin, balance)?);
    println!("  Defaults: $100/day withdrawals, $50/day transfers, transfers to family only.");
    Ok(())
}

fn add_guardian(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let youth = input::read_line("Youth account number: ")?;
    let (card, card_pin) = at_counter("Current guardian")?;
    let current = CardAndPin { card_number: &card, pin: &card_pin };
    let guardian = input::read_line("New guardian's card number: ")?;
    admin::add_guardian(atm, s, &youth, current, &guardian)?;
    println!("\n  Guardian added.");
    Ok(())
}

fn show_audit(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let number = input::read_line("Account number: ")?;
    page_through(|page| admin::audit_for_account(atm, s, &number, page), print_audit_rows)
}

fn print_audit_rows(rows: &[Row]) {
    println!("\n  {:>5} {:<21} {:<22} {:<16} {:>12}  Details", "#", "When (UTC)", "Who", "Action", "Amount");
    for row in rows {
        let amount = row.amount.map(|a| row.currency.format(a)).unwrap_or_default();
        let details = match (&row.account_number, &row.counterparty_number) {
            (Some(from), Some(to)) => format!("{from} -> {to} {}", row.detail),
            (Some(acct), None) => format!("{acct} {}", row.detail),
            _ => row.detail.clone(),
        };
        println!(
            "  {:>5} {:<21} {:<22} {:<16} {:>12}  {}",
            row.seq, row.ts, row.actor, row.action, amount, details
        );
    }
}

fn list_accounts(atm: &Atm, s: &AdminSession) -> Result<()> {
    println!();
    for a in admin::list_accounts(atm, s)? {
        let status = if a.closed {
            "CLOSED"
        } else if a.frozen {
            "FROZEN"
        } else if a.guardian_frozen {
            "frozen by guardian"
        } else {
            "open"
        };
        println!("  {}  {:<10} {} {}", a.account_number, a.kind, a.currency.code(), status);
        for h in &a.holders {
            let lock = if h.locked { "  [card LOCKED]" } else { "" };
            println!("      card ending {}  {:<6} {}{}", h.card_last4, h.role, h.full_name, lock);
        }
    }
    Ok(())
}

fn close_account(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let number = input::read_line("Account number to close: ")?;
    if !input::confirm(&format!("Close account {number}? This can't be undone. (y/n) "))? {
        println!("\n  Cancelled.");
        return Ok(());
    }
    admin::close_account(atm, s, &number)?;
    println!("\n  Account {number} closed. Its history is kept in the audit log.");
    Ok(())
}

fn set_limit(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    println!("Which daily limit?  1) Withdrawal  2) Deposit  3) Transfer");
    let limit = match input::read_line("> ")?.as_str() {
        "1" => Limit::Withdrawal,
        "2" => Limit::Deposit,
        "3" => Limit::Transfer,
        _ => return Err(AtmError::InvalidInput("choose 1 to 3")),
    };
    let current = admin::bank_limits(atm, s)?.into_iter().find(|(l, _)| *l == limit).map(|(_, v)| v);
    if let Some(v) = current {
        println!("Current daily {} limit: {v}", limit.label());
    }
    let value = Cents::parse(&input::read_line("New limit: $")?)?;
    admin::set_limit(atm, s, limit, value)?;
    println!("\n  Daily {} limit is now {value} for all customers.", limit.label());
    Ok(())
}

/// Customer is at the counter with ID: allow more than the daily limit, today only.
fn raise_limit(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    println!("Check the customer's ID first. Which limit?  1) Withdrawal  2) Deposit  3) Transfer");
    let limit = match input::read_line("> ")?.as_str() {
        "1" => Limit::Withdrawal,
        "2" => Limit::Deposit,
        "3" => Limit::Transfer,
        _ => return Err(AtmError::InvalidInput("choose 1 to 3")),
    };
    let number = input::read_line("Account number: ")?;
    println!("Up to {} extra per account per day.", limit.max_raise());
    let extra = Cents::parse(&input::read_line("Extra to allow today: $")?)?;
    admin::raise_limit_today(atm, s, &number, limit, extra)?;
    println!("\n  Approved {extra} more {} today for account {number}. Logged.", limit.label());
    Ok(())
}

/// Accounts held by the activity check; release after confirming with the customer.
fn review_holds(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let held = review::holds(atm, s)?;
    if held.is_empty() {
        println!("\n  No accounts on hold.");
        return Ok(());
    }
    println!("\n  On hold (check ID and confirm the activity with the customer first):");
    for h in &held {
        println!("  account {}  {}  since {}", h.account_number, h.holders.join(", "), h.since);
        println!("    {}", h.reason);
    }
    let number = input::read_line("Account number to release (Enter to cancel): ")?;
    if number.is_empty() {
        return Ok(());
    }
    review::release_hold(atm, s, &number)?;
    println!("\n  Hold released on account {number}. Logged.");
    Ok(())
}

fn unlock(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let locked = admin::locked_cards(atm, s)?;
    if locked.is_empty() {
        println!("\n  No locked cards.");
        return Ok(());
    }
    println!("\n  Locked cards (check the customer's ID matches before unlocking):");
    for c in &locked {
        println!(
            "  card ending {}  account ending {}  {}  born {}",
            c.card_last4, c.account_last4, c.full_name, c.date_of_birth
        );
    }
    let card = input::read_line("Card number, from the card the customer hands you (Enter to cancel): ")?;
    if card.is_empty() {
        return Ok(());
    }
    admin::unlock_card(atm, s, &card)?;
    println!("\n  Card {} unlocked.", mask(&card));
    Ok(())
}

fn freeze(atm: &mut Atm, s: &AdminSession) -> Result<()> {
    let number = input::read_line("Account number: ")?;
    let frozen = match input::read_line("1) Freeze  2) Unfreeze  > ")?.as_str() {
        "1" => true,
        "2" => false,
        _ => return Err(AtmError::InvalidInput("choose 1 or 2")),
    };
    admin::set_frozen(atm, s, &number, frozen)?;
    println!(
        "\n  {}",
        if frozen {
            "Account frozen: its cards aren't accepted and it takes no transfers until you unfreeze it."
        } else {
            "Account unfrozen."
        }
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Cash Handler
// ---------------------------------------------------------------------------

fn handler_flow(atm: &mut Atm) -> Result<()> {
    if service::out_of_service(atm)? {
        println!("  The ATM is out of service. Only a Teller Admin can sign in until it is resumed.");
        return Ok(());
    }
    let username = input::read_line("Cash Handler username: ")?;
    let password = input::read_secret("Password: ")?;
    let session = auth::login_handler(atm, &username, &password)?;
    drop(password);
    let result = handler_menu(atm, &session);
    let logged_out = auth::logout_handler(atm, session);
    input::wipe_screen(); // logged out or timed out: nothing left on screen
    result.and(logged_out)
}

fn handler_menu(atm: &mut Atm, s: &HandlerSession) -> Result<()> {
    loop {
        println!("\n--- Cash Handler ---");
        println!("  1) View cash in machine");
        println!("  2) Restock (add bills, up to the cash maximum)");
        println!("  3) Remove specific bills (only above the maximum)");
        println!("  4) Reset to cash maximum (machine picks the bills)");
        println!("  5) Change my password");
        println!("  0) Log out");
        let choice = read_choice()?;
        let result = match choice.as_str() {
            "1" => show_cash(atm, s),
            "2" => move_cash(atm, s, true),
            "3" => move_cash(atm, s, false),
            "4" => cash::reset_to_maximum(atm, s).map(|plan| {
                println!("\n  Removed {}. Machine is back at its cash maximum.", cash::describe(&plan));
            }),
            "5" => {
                let current = input::read_secret("Current password: ")?;
                let new = new_secret("New password (12+ characters)")?;
                auth::change_handler_password(atm, s, &current, &new)
                    .map(|_| println!("\n  Password changed."))
            }
            "0" => return Ok(()),
            _ => Err(AtmError::InvalidInput("choose 0 to 5")),
        };
        run_action(result)?;
    }
}

fn show_cash(atm: &Atm, s: &HandlerSession) -> Result<()> {
    let inv = cash::view(atm, s)?;
    println!();
    for (denom, count) in &inv.bills {
        println!("  ${:<4} x {:>6}  = {:>14}", denom.dollars(), count, denom.times(*count)?.to_string());
    }
    println!("  {:<14} = {:>14}", "Total", inv.total.to_string());
    println!("  {:<14} = {:>14}", "Cash maximum", inv.maximum.to_string());
    println!("  {:<14} = {:>14}", "Daily limit", inv.withdrawal_limit.to_string());
    if !inv.over_maximum.is_zero() {
        println!("  OVER MAXIMUM by {}. Use option 4 to reset.", inv.over_maximum);
    }
    if inv.low_cash {
        println!("  LOW CASH: less than one customer's daily withdrawal limit. Restock.");
    }
    if !inv.low_bills.is_empty() {
        let list: Vec<String> = inv.low_bills.iter().map(|d| format!("${d}")).collect();
        println!("  Running low on: {}", list.join(", "));
    }
    Ok(())
}

fn move_cash(atm: &mut Atm, s: &HandlerSession, adding: bool) -> Result<()> {
    let denom = read_bill("Which bills ($5, 10, 20, 50 or 100)? $")?;
    let count = input::read_u32("How many bills? ")?;
    let total = if adding {
        cash::restock(atm, s, denom, count)?
    } else {
        cash::remove_excess(atm, s, denom, count)?
    };
    let verb = if adding { "Added" } else { "Removed" };
    println!("\n  {verb} {count} x ${}. Machine now holds {total}.", denom.dollars());
    Ok(())
}

// ---------------------------------------------------------------------------
// Demo mode banner
// ---------------------------------------------------------------------------

/// Print every demo login so testers don't have to remember anything.
#[cfg(feature = "demo")]
pub fn print_demo_banner(logins: &[atm::demo::Login]) {
    use atm::demo::{HANDLER, TELLER};
    println!("\n*** DEMO MODE: sample data in atm-demo.db (delete atm-demo.* to reset) ***");
    println!("  Teller Admin:  {} / {}", TELLER.0, TELLER.1);
    println!("  Cash Handler:  {} / {}", HANDLER.0, HANDLER.1);
    println!("  {:<8} {:<11} {:<11} {:<5} Notes", "Customer", "Card", "Account", "PIN");
    for l in logins {
        println!("  {:<8} {:<11} {:<11} {:<5} {}", l.who, l.card, l.account, l.pin, l.note);
    }
}
