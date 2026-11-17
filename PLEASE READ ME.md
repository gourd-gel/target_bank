# Bank of CCNY — unified Cargo and terminal command reference

Run Cargo commands from the project folder containing `Cargo.toml`. Replace
`/path/to/...`, `+PHONE`, and other placeholders with your installation values.
Descriptions below are limited to one or two sentences per command.

## Start, build and check the ATM

| Cargo command | What it does |
|---|---|
| `cargo fetch` | Downloads dependencies so later commands can run with `--offline`. |
| `cargo build --release --workspace` | Builds the standard GUI and development CLI. Role-specific maintenance binaries require the features listed below. |
| `cargo run --release -p atm-gui` | Starts the deployed GUI for Customer, Teller Admin and Cash Handler. First run creates the staff accounts. |
| `cargo run --profile quick -p atm-gui --features demo -- --demo` | Starts the GUI with sample accounts, staff badges and practice data. Uses separate demo bank files. |
| `cargo run --release` | Starts the shared numbered-menu CLI for development/testing. Select Customer, Teller Admin or Cash Handler, then authenticate. |
| `cargo run --release --features demo -- --demo` | Starts the development CLI with sample data and demo logins. |
| `cargo run --release -p atm-gui --features online-rates` | Starts the GUI with the teller's online exchange-rate check enabled. Updates still require teller review. |
| `cargo run --release --features online-rates` | Enables online exchange-rate checks in the development CLI's teller menu. |
| `cargo check -p atm-gui --features demo` | Checks that the GUI and its core dependencies compile, without launching the booth. |
| `cargo test` | Runs the default core tests and compile-fail access checks. |
| `cargo test --features demo,programmer-tools,authorities-tools` | Runs the core, demo, programmer-tool and Authorities-terminal tests together. |
| `cargo test --features online-rates,integrity-test` | Runs tests for online-rate handling and the intentional integrity-test fixture. |
| `cargo fmt --all -- --check` | Checks Rust formatting without rewriting files. |
| `cargo run --release -p atm-gui --features integrity-test -- --demo --break-integrity` | Starts an intentionally damaged test bank to demonstrate integrity detection. Uses the separate test fixture, not a normal bank. |

## Programmer maintenance

These commands run outside the booth. Phone/location configuration prompts for
the programmer PIN; never place that PIN in a command argument.

| Cargo command | What it does |
|---|---|
| `cargo authorities-phone "+PHONE" --directory "/path/to/bank"` | Configures the Authorities notification/sign-in phone. The runtime imports the setting into the existing bank. |
| `cargo atm-location "Branch address, ATM 01" --directory "/path/to/bank"` | Configures the physical location label included in signed Authorities alerts. |
| `cargo run --features programmer-tools --bin bank-processing-fees -- provision /path/to/atm.db /programmer-only/atm.processing-fees.private.pem` | Creates the processing-fee encryption key pair without overwriting existing keys. Keep the private key with the programmer and deliver only the public key to the bank. |
| `cargo run --features programmer-tools --bin bank-processing-fees -- read /backup/atm.processing-fees.db /programmer-only/atm.processing-fees.private.pem` | Decrypts an offline copy of the private processing-fee records using the programmer's private key. |
| `cargo build --release --features authorities-tools --bin bank-oversight` | Builds the separate Authorities terminal for delivery to authorized bank staff. |
| `cargo authorities-phone --help` | Shows the Authorities-phone configuration syntax. |
| `cargo atm-location --help` | Shows the location configuration syntax. |

Provision the processing-fee public key before money transactions. The GUI
creates each teller's hidden simulated secondary destination automatically at
staff setup/startup; its values stay in `<bank-stem>.teller-phones.secret` and
sealed encrypted metadata, never in this reference or terminal reports.

## Bank Authorities — start and authenticate

| Cargo command | What it does |
|---|---|
| `cargo authorities --directory "/path/to/bank"` | Opens the separate Authorities terminal for an existing bank. Enter the registered Authorities phone and its OTP. |
| `cargo run --features authorities-tools --bin bank-oversight -- --directory "/path/to/bank"` | Runs the same Authorities terminal without using the Cargo alias. |
| `cargo run --features authorities-tools,demo --bin bank-oversight -- --demo --directory "/path/to/demo-bank"` | Opens Authorities access to an existing demo bank. |
| `cargo authorities --help` | Lists terminal commands without signing in. |

Read the Authorities OTP from `<phone>.authorities-login.txt` beside the bank.
The following commands are entered **inside `authorities>` after sign-in**;
they are not separate Cargo subcommands. `[page]` means an optional page number
(omit the brackets); pages start at `0`.

| Terminal command | What it does |
|---|---|
| `databases` | Lists the main bank, encrypted processing-fee and administrative audit databases. |
| `tables main [page]` | Shows main bank table schemas; use `processing` or `administration` for the other databases. |
| `rows main TABLE [page]` | Inspects a supported table with credentials and sensitive metadata protected. Replace `main` with `processing` or `administration` as needed. |
| `users [page]` | Identifies customers and their card/account references. |
| `staff [page]` | Identifies staff roles and actors, showing the primary phone and destination count without secondary-number values. |
| `accounts [page]` | Inspects accounts, including closed accounts retained for tracing. |
| `user CARD_NUMBER [page]` | Identifies one customer card and shows its requested-amount activity. |
| `teller USERNAME [page]` | Identifies one teller and traces that teller's activity. |
| `account ACCOUNT_NUMBER [page]` | Shows one account and its related activity. |
| `actor ACTOR_NAME` | Traces an exact audit actor identifier. Use `user` to resolve customer card identities first. |
| `audit [page]` | Reads user activity with requested transaction amounts. |
| `ledger [page]` | Reads the complete signed financial/security ledger used for reconciliation. |
| `fees [page]` | Inspects encrypted processing-fee records; it does not decrypt the programmer's private ledger. |
| `admin-audit [page]` | Reads the private Programmer/Authorities administrative audit. Requires an Authorities session. |
| `revenue` | Shows processing-fee revenue balances by currency. |
| `revenue-history [page]` | Shows revenue credits, debits and adjustment history. |
| `credit CURRENCY AMOUNT REASON` | Records a reasoned revenue credit adjustment in the specified currency. |
| `debit CURRENCY AMOUNT REASON` | Records a reasoned revenue debit adjustment; sufficient revenue funds are required. |
| `check` | Verifies database integrity, signed records and financial reconciliation. |
| `service-status` | Shows whether the ATM is out of service, when it stopped and why. |
| `retry-service-alert` | Retries a queued teller service-lock notification without restoring service. |
| `resume-service REVIEW_REASON` | Restores ATM service after Authorities review and a passing integrity check. Required for a three-failure teller authentication lock. |
| `resolve-customer CARD_NUMBER REVIEW_REASON` | Clears that card's customer PIN lock after review. Leaves the PIN and independent account restrictions unchanged. |
| `retry-customer-alerts` | Retries queued customer PIN-lock notifications. Does not unlock customers. |
| `help` | Prints the available Authorities commands. |
| `quit` | Signs out and closes the Authorities terminal. |

## Teller Admin — development CLI menu

Start with `cargo run --release`, choose **2**, then enter the teller username
and password. Enter `/phone` at the username prompt for OTP recovery: verify
the code and reset the existing password before entering the main menu.

| Menu entry | What it does |
|---|---|
| `1` | Creates an individual customer account with a capped starting balance. |
| `2` | Adds a joint holder after a current holder confirms with their card and PIN. |
| `3` | Opens a youth account with guardian confirmation. |
| `4` | Adds a guardian after confirmation by an existing guardian. |
| `5` | Reads an account's activity audit. |
| `6` | Changes bank-wide daily withdrawal, deposit or transfer limits within teller ceilings. |
| `7` | Views locked customer cards for referral to Authorities. Tellers cannot unlock them. |
| `8` | Freezes or unfreezes an account after the teller's review. |
| `9` | Runs and logs the integrity/reconciliation check. |
| `10` | Lists accounts and holder summaries. |
| `11` | Reads recent user activity events. |
| `12` | Closes an eligible account with a zero balance. |
| `13` | Changes the teller password using the current password. OTP recovery uses the separate reset flow. |
| `14` | Opens exchange-rate and fee controls; online checks require `online-rates`. |
| `15` | Registers a simulated card from another bank. |
| `16` | Approves a capped additional daily allowance for an eligible account, for today only. |
| `17` | Reviews unusual-activity holds and releases an eligible hold. |
| `18` | Manually halts or resumes an ordinary service halt. Cannot release an Authorities-only teller authentication lock. |
| `19` | Verifies a new primary recovery number with the current password and phone OTP. A provisioned hidden secondary is preserved. |
| `0` | Signs the teller out. |

## Cash Handler — development CLI menu

Start with `cargo run --release`, choose **3**, then enter the handler username
and password. Cash handling is separate from teller permissions.

| Menu entry | What it does |
|---|---|
| `1` | Shows cash totals and bill counts by denomination. |
| `2` | Restocks bills without exceeding the $100,000 restocking maximum. |
| `3` | Removes specified bills only from cash above that maximum. |
| `4` | Automatically selects bills to remove the surplus and return to the maximum. |
| `5` | Changes the handler password using the current password. |
| `0` | Signs the handler out. |

## Customer — development CLI menu

Start with `cargo run --release`, choose **1**, then enter the card number and
PIN. Guest cards have the restricted balance/limits/withdrawal menu.

| Menu entry | What it does |
|---|---|
| `1` | Shows the customer's account balance. |
| `2` | Shows daily transaction limits and remaining allowances. |
| `3` | Withdraws cash using the selected bill preference, subject to limits and fees. |
| `4` | Deposits the entered bills, subject to limits and fees. |
| `5` | Transfers money to an eligible account, subject to limits and fees. |
| `6` | Shows recent requested-amount activity. |
| `7` | Opens eligible guardian/family controls and money movements. |
| `8` | Changes the customer card PIN using the current PIN. |
| `0` | Signs the customer out. |

The deployed Customer, Teller Admin and Cash Handler workflows use the GUI;
their CLI menus are development/testing tools. Authorities and Programmer
commands operate separately from the booth. Further workflow details are in
[User Guide](docs/USER_GUIDE.md), [Authorities activities](docs/BANK_AUTHORITIES.md)
and [Teller OTP recovery](docs/TELLER_PHONE_RECOVERY.md).
