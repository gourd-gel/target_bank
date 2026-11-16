//! Authenticated off-booth Authorities terminal. No shell or arbitrary SQL execution.
#![forbid(unsafe_code)]
use atm::error::{AtmError, Result};
use atm::{Atm, auth, input, oversight, revenue};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

const HELP: &str = "Commands (pages start at 0):
  databases                           list bank, fee and administrative databases
  tables <database> [page]      inspect table schemas
  rows <database> <table> [page]       inspect stored rows (credentials protected)
  users [page] | staff [page]         identify customers/cards and staff actors
  accounts [page]                     inspect accounts, including closed accounts
  user <card-number> [page]           identify a customer and trace their actions
  teller <username> [page]            identify a teller and trace their actions
  account <account-number> [page]     trace all activity for an account
  actor <actor-name>                  trace an exact actor; use user for card actors
  audit [page] | ledger [page]        requested-amount activity or financial records
  fees [page]                        inspect stored encrypted fee records
  admin-audit [page]                 read the private administrative audit
  revenue | revenue-history [page]   inspect processing revenue
  credit <currency> <amount> <reason> record a revenue credit adjustment
  debit <currency> <amount> <reason>  record a revenue debit adjustment
  check                              verify database integrity and reconciliation
  help | quit";

fn output(value: impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value).map_err(|e| AtmError::Internal(e.to_string()))?);
    Ok(())
}
fn page(value: Option<&&str>) -> Result<u32> {
    value.map_or(Ok(0), |value| {
        value.parse().map_err(|_| AtmError::InvalidInput("page must be a non-negative integer"))
    })
}
fn activity(rows: Vec<atm::audit::Row>) -> Value {
    json!(
        rows.iter()
            .map(|r| json!({"reference": r.seq, "timestamp": r.ts, "actor": r.actor,
        "action": r.action, "account": r.account_number, "counterparty": r.counterparty_number,
        "requested_cents": r.amount.map(|a| a.as_i64()), "currency": r.currency.code(), "detail": r.detail}))
            .collect::<Vec<_>>()
    )
}

fn command(bank: &mut Atm, session: &auth::AuthoritiesSession, line: &str) -> Result<()> {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["help"] => { println!("{HELP}"); Ok(()) }
        ["databases"] => output(oversight::databases(bank, session)?),
        ["tables", database, rest @ ..] if rest.len() <= 1 => output(oversight::schema(bank, session, database, page(rest.first())?)?),
        ["rows", database, table, rest @ ..] if rest.len() <= 1 => output(oversight::table(bank, session, database, table, page(rest.first())?)?),
        ["users", rest @ ..] if rest.len() <= 1 => output(oversight::users(bank, session, None, page(rest.first())?)?),
        ["staff", rest @ ..] if rest.len() <= 1 => output(oversight::staff(bank, session, None, page(rest.first())?)?),
        ["accounts", rest @ ..] if rest.len() <= 1 => output(oversight::accounts(bank, session, None, page(rest.first())?)?),
        ["audit", rest @ ..] if rest.len() <= 1 => output(activity(oversight::activity(bank, session, None, None, page(rest.first())?)?)),
        ["ledger", rest @ ..] if rest.len() <= 1 => output(oversight::table(bank, session, "main", "audit_log", page(rest.first())?)?),
        ["admin-audit", rest @ ..] if rest.len() <= 1 => output(atm::administration::recent(bank, session, page(rest.first())?)?),
        ["fees", rest @ ..] if rest.len() <= 1 => output(oversight::table(bank, session, "processing", "records", page(rest.first())?)?),
        ["account", number, rest @ ..] if rest.len() <= 1 => {
            let accounts = oversight::accounts(bank, session, Some(number), 0)?;
            if accounts.is_empty() { return Err(AtmError::NotFound("Account")); }
            output(json!({"accounts": accounts, "activity": activity(oversight::activity(bank, session, Some(number), None, page(rest.first())?)?)}))
        }
        ["user", number, rest @ ..] if rest.len() <= 1 => {
            let users = oversight::users(bank, session, Some(number), 0)?;
            let actor = users.first().and_then(|r| r["actor"].as_str()).ok_or(AtmError::NotFound("Customer card"))?;
            let history = activity(oversight::activity(bank, session, None, Some(actor), page(rest.first())?)?);
            output(json!({"users": users, "activity": history}))
        }
        ["teller", username, rest @ ..] if rest.len() <= 1 => {
            let staff = oversight::staff(bank, session, Some(username), 0)?;
            let teller = staff.first().filter(|r| r["role"] == "admin").ok_or(AtmError::NotFound("Teller"))?;
            let actor = teller["actor"].as_str().ok_or(AtmError::NotFound("Teller"))?;
            let history = activity(oversight::activity(bank, session, None, Some(actor), page(rest.first())?)?);
            output(json!({"teller": teller, "activity": history}))
        }
        ["actor", actor] => output(activity(oversight::activity(bank, session, None, Some(actor), 0)?)),
        ["revenue"] => output(revenue::balances(bank, session)?.iter().map(|r| json!({"currency": r.currency.code(), "balance_cents": r.balance.as_i64()})).collect::<Vec<_>>()),
        ["revenue-history", rest @ ..] if rest.len() <= 1 => output(revenue::history(bank, session, page(rest.first())?)?.iter().map(|r| json!({"reference": r.reference, "timestamp": r.timestamp, "currency": r.currency.code(), "delta_cents": r.delta_cents, "actor": r.actor, "detail": r.detail})).collect::<Vec<_>>()),
        [direction @ ("credit" | "debit"), currency, amount, reason @ ..] if !reason.is_empty() => {
            let currency = atm::fx::Currency::parse(currency)?;
            let amount = currency.parse_amount(amount)?;
            let reference = revenue::adjust(bank, session, currency, if *direction == "credit" {revenue::Adjustment::Credit} else {revenue::Adjustment::Debit}, amount, &reason.join(" "))?;
            output(json!({"reference": reference, "result": "revenue adjustment recorded"}))
        }
        ["check"] => {
            let report = oversight::verify(bank, session)?;
            output(json!({"result": "ok", "entries": report.entries, "accounts_checked": report.accounts_checked,
                "cash_cents": report.cash.as_i64(), "records_checked": report.records_checked,
                "state_checked": report.state_checked, "head": report.head}))
        }
        _ => Err(AtmError::InvalidInput("unknown command or arguments; enter help")),
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.as_slice(), [flag] if flag == "--help" || flag == "-h") {
        println!("Usage: cargo authorities [--directory <bank-folder>] [--demo]\n{HELP}");
        return Ok(());
    }
    let mut directory = PathBuf::from(".");
    let mut demo = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--directory" if i + 1 < args.len() => {
                directory = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--demo" => {
                demo = true;
                i += 1;
            }
            _ => return Err(AtmError::InvalidInput("use --directory <bank-folder> and optionally --demo")),
        }
    }
    let (db, key) = if demo { ("atm-demo.db", "atm-demo.key") } else { ("atm.db", "atm.key") };
    let db = directory.join(db);
    let key = directory.join(key);
    if !db.is_file() || !key.is_file() {
        return Err(AtmError::NotAllowed("the existing bank database and runtime key are required"));
    }
    let mut bank = if demo { open_demo(&db, &key)? } else { Atm::open(&db, &key)? };
    if bank.needs_setup()? {
        return Err(AtmError::NotAllowed("the bank must complete staff setup first"));
    }
    let phone = input::read_line("Bank Authorities registered phone: ")?;
    println!("{}", auth::recovery::request_authorities_code(&mut bank, &phone)?);
    let code = input::read_secret("Authorities verification code: ")?;
    let session = auth::recovery::login_authorities(&mut bank, &phone, code.trim())?;
    drop(code);
    println!("Authorities terminal ready. Enter help for commands.");
    let result = loop {
        let line = match input::read_line("authorities> ") {
            Ok(line) => line,
            Err(AtmError::Eof) => break Ok(()),
            Err(e) => break Err(e),
        };
        if line == "quit" || line == "exit" {
            break Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        if let Err(e) = command(&mut bank, &session, &line) {
            eprintln!("{e}");
            if matches!(e, AtmError::SessionExpired | AtmError::DatabaseAltered | AtmError::RolledBack) {
                break Err(e);
            }
        }
    };
    let signed_out = auth::logout_authorities(&mut bank, session);
    result.and(signed_out)
}

#[cfg(feature = "demo")]
fn open_demo(db: &Path, key: &Path) -> Result<Atm> {
    Atm::open_demo(db, key)
}
#[cfg(not(feature = "demo"))]
fn open_demo(_: &Path, _: &Path) -> Result<Atm> {
    Err(AtmError::NotAllowed("demo support is not compiled; enable the demo feature"))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
