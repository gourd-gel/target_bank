//! Programmer-only authorities phone maintenance, invoked with Cargo.
#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.as_slice(), [flag] if flag == "--help" || flag == "-h") {
        println!("Usage: cargo authorities-phone <+PHONE> [--directory <bank-folder>]");
        return ExitCode::SUCCESS;
    }
    let (phone, folder) = match args.as_slice() {
        [phone] => (phone.as_str(), Path::new(".")),
        [phone, flag, folder] if flag == "--directory" => (phone.as_str(), Path::new(folder)),
        _ => {
            eprintln!("Usage: cargo authorities-phone <+PHONE> [--directory <bank-folder>]");
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
    let secret_file = Path::new(atm::auth::recovery::PROGRAMMER_PIN_FILE);
    match atm::auth::recovery::write_authorities_configuration(folder, phone, secret_file, &pin) {
        Ok(()) => {
            println!("Bank Authorities phone saved. Applied at startup or before the next alert.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
