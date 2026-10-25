//! Bank of CCNY ATM: command-line front end.
//! All rules live in the library (src/lib.rs); this is just menus.

#![forbid(unsafe_code)]

mod ui;

use atm::Atm;
use atm::error::{AtmError, Result};
use std::path::Path;
use std::process::ExitCode;

/// Fixed file names in the working directory. Not arguments or env vars, so
/// there's no input that can point the ATM at an attacker-prepared database.
const DB_PATH: &str = "atm.db";
const KEY_PATH: &str = "atm.key";

/// Normal mode: real database, staff created at first run.
fn run_normal() -> Result<()> {
    let mut atm = Atm::open(Path::new(DB_PATH), Path::new(KEY_PATH))?;
    if atm.needs_setup()? {
        ui::first_run_setup(&mut atm)?;
    }
    ui::main_menu(&mut atm)
}

/// Demo mode: separate files, sample data, logins printed on screen.
/// `break_integrity` is only ever true in `--features integrity-test` builds;
/// it uses its own files, so the normal demo data is never broken.
#[cfg(feature = "demo")]
fn run_demo(break_integrity: bool) -> Result<()> {
    #[cfg(feature = "integrity-test")]
    let (db, key) =
        if break_integrity { ("atm-test.db", "atm-test.key") } else { ("atm-demo.db", "atm-demo.key") };
    #[cfg(not(feature = "integrity-test"))]
    let (db, key) = ("atm-demo.db", "atm-demo.key");
    let mut atm = Atm::open_demo(Path::new(db), Path::new(key))?;
    let logins = if atm.needs_setup()? { atm::demo::seed(&mut atm)? } else { atm::demo::cheat_sheet(&atm)? };
    ui::print_demo_banner(&logins);
    #[cfg(feature = "integrity-test")]
    if break_integrity {
        atm::demo::break_integrity(&mut atm)?;
        println!("*** TEST: Ann and Ben's balance was raised by $500 with no log entry. ***");
        println!("*** Sign in as the Teller Admin: the check should catch it and halt the ATM. ***");
    }
    #[cfg(not(feature = "integrity-test"))]
    let _ = break_integrity;
    ui::main_menu(&mut atm)
}

/// Pick normal or demo mode from the command line; anything else prints usage.
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => run_normal(),
        #[cfg(feature = "demo")]
        [flag] if flag == "--demo" => run_demo(false),
        #[cfg(feature = "integrity-test")]
        [flag, test] if flag == "--demo" && test == "--break-integrity" => run_demo(true),
        [flag] if flag == "--demo" => {
            println!("Demo mode isn't in this build. Run: cargo run --features demo -- --demo");
            Ok(())
        }
        _ => {
            println!(
                "Usage: atm            (normal)\n       atm --demo     (sample data; build with --features demo)"
            );
            Ok(())
        }
    }
}

/// Run the ATM; end of input is a normal exit, any other error prints and fails.
fn main() -> ExitCode {
    match run() {
        Ok(()) | Err(AtmError::Eof) => {
            println!("\nGoodbye.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
