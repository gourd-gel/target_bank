//! Programmer-only physical ATM location configuration.
#![forbid(unsafe_code)]
use std::{path::Path, process::ExitCode};

const USAGE: &str = "Usage: cargo atm-location <location> [--directory <bank-folder>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.as_slice(), [flag] if flag == "--help" || flag == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let (location, directory) = match args.as_slice() {
        [location] => (location.as_str(), Path::new(".")),
        [location, flag, directory] if flag == "--directory" => (location.as_str(), Path::new(directory)),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let pin = match atm::input::read_secret("Programmer PIN: ") {
        Ok(pin) => pin,
        Err(_) => {
            eprintln!("Programmer PIN is required.");
            return ExitCode::FAILURE;
        }
    };
    match atm::identity::write_location_configuration(
        directory,
        location,
        Path::new(atm::auth::recovery::PROGRAMMER_PIN_FILE),
        &pin,
    ) {
        Ok(()) => {
            println!("ATM location saved. Applied at startup or before the next teller OTP alert.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
