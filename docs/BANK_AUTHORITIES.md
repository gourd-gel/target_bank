# Bank Authorities: terminal inspection and activity tracing

Bank Authorities uses a separate authenticated terminal outside the booth GUI.
It can inspect the bank, fee and administrative databases, identify users and tellers, trace activity,
check the financial ledger and revenue, and verify integrity.

## Start and sign in

From the source workspace on a trusted host with access to the existing bank
folder, run:

```sh
cargo authorities --directory /path/to/bank-folder
```

The alias builds `bank-oversight` with `authorities-tools`. The equivalent is:

```sh
cargo run --features authorities-tools --bin bank-oversight -- --directory /path/to/bank-folder
```

The programmer can also build the standalone terminal for Authorities:

```sh
cargo build --release --features authorities-tools --bin bank-oversight
```

Authorities can then run the provided executable directly, without Cargo,
source access or the programmer PIN:

```sh
/path/to/bank-oversight --directory /path/to/bank-folder
```

1. The bank must already exist and have completed staff setup. Keep its matching
   `atm.db`, `atm.key`, `atm.anchor`, `atm.processing-fees.db`,
   `atm.admin-audit.db` and `atm.admin-audit.key` together. Existing installations
   initialize the administrative store on first use after upgrade.
   Keep the matching `<bank-stem>.teller-phones.secret` in the protected backup;
   it contains secondary contact values and must not be pasted into reports.
2. Enter the Authorities phone configured by the programmer with
   `cargo authorities-phone`. No programmer PIN is used to enter this terminal.
3. Read the six-digit code from `<phone-number>.authorities-login.txt` beside
   the bank database, then enter it at the hidden code prompt. For example,
   phone `+12125550199` uses `+12125550199.authorities-login.txt`.
   The plain phone-number `.txt` file contains teller alerts.
4. At `authorities>`, enter one of the commands below. Enter `quit` to sign out.

Codes expire after five minutes, permit five attempts, and work once. Code
requests are limited to one per minute and three per fifteen minutes. Sessions
expire after two minutes of inactivity. Unknown or throttled code requests use
the same generic public notice. A failed sign-in does not open the command loop.
This project delivers codes to local files rather than SMS.

For an existing demo bank, build with both features:

```sh
cargo run --features authorities-tools,demo --bin bank-oversight -- --demo --directory /path/to/demo-folder
```

Demo mode opens `atm-demo.db` and `atm-demo.key`; it does not create or seed a
bank. The terminal refuses missing bank files instead of initializing a bank.
Use `cargo authorities --help` to list commands without signing in.

## Inspect databases and stored rows

The logical database names are `main` (`atm.db`), `processing`
(`atm.processing-fees.db`), and `administration` (`atm.admin-audit.db`). Pages start at **0** and contain up to **20** rows.
Omit a page to use page 0. Outputs are JSON; amounts named `*_cents` are stored
hundredths of the indicated currency (including whole-unit precision for yen/won).

```text
databases
tables main
tables main 1
tables processing
tables administration
rows administration events
admin-audit
admin-audit 1
rows main accounts
rows main cards
rows main staff
rows main guardians
rows main settings
rows main exchange_rates
rows main rate_history
rows main cash_inventory
rows main meta
rows main seal
rows main audit_log 0
rows main bank_revenue
rows main revenue_ledger
rows processing records
rows processing recipient
```

`tables` displays schemas, including tables, indexes and triggers. Stored
binary values are represented as hex. Password/PIN hashes and private recovery
metadata are protected in these reports. The `users`, `staff` and `accounts`
commands below provide decrypted identification data for investigations.

Encrypted fee records can be inspected as stored ciphertext. The separate
programmer-only private key is still required to decrypt those payloads;
it is not installed in the Authorities terminal. Processing fee amounts and
transaction references remain available through revenue and financial records.

## Identify users, accounts and tellers

```text
users
users 1
staff
staff 1
accounts
accounts 1
```

- `users` includes card id/number, holder name, date of birth, holder role,
  account id/number, currency, actual balance, lock/freeze status, and the
  exact activity-log actor identifying that card.
- `staff` includes staff id, username, role, the primary registered `phone` and
  `verified_phone_count`; secondary numbers are not printed,
  failed-attempt/cooldown state and the exact actor identifying that staff user.
- `accounts` includes actual balances and account status, including closed
  accounts retained for investigations.

## Trace requested activity

Replace the example card/account numbers and teller username below with values
returned by the identification reports:

```text
audit
audit 1
user 1234567890
user 1234567890 1
teller teller_username
teller teller_username 1
account 0987654321
account 0987654321 1
actor admin:teller_username
```

`user` reports the matching holder and that card's actions. `teller` reports
the matching Teller Admin and their actions. `account` reports account details
and activity from all its holders, including incoming transfers. Closed
accounts can still be traced. `actor` matches a staff actor exactly; use `user`
for customer actors whose labels include spaces. Filters apply before paging.

`audit` and the tracing commands use the same requested-amount activity records
as the GUI audit. A requested $100 deposit appears as $100, even when its actual
net credit is $97. Cash requests appear in USD even for foreign accounts.
Only GUI user activities and their resulting security events are traced in
that activity view.

## Inspect financial records and revenue

```text
ledger
ledger 1
fees
fees 1
revenue
revenue-history
revenue-history 1
```

`ledger` inspects the complete internal signed financial ledger, including actual
account debits/credits and processing fees. `fees` inspects the encrypted fee
records. `revenue` shows processing-fee balances separately for each currency;
`revenue-history` links fee credits and adjustments to their financial references.
These reports do not change the requested amounts in the GUI activity audit.

Existing Authorities revenue adjustment operations are also available:

```text
credit USD 10.00 Approved opening correction
debit USD 2.00 Approved correction reversal
```

Amounts must be positive and the reason is required. Debits cannot overdraw
that currency's revenue balance. Adjustments create financial entries; they
do not dispense cash or change a customer's balance. Inspection commands leave bank business data unchanged and record administrative
access separately. They use fixed queries, not arbitrary SQL or shell commands.

## Check integrity and sign out

```text
check
service-status
retry-service-alert
resume-service Verified teller identity and reviewed failed sign-ins
retry-customer-alerts
resolve-customer 1234567890 Verified customer identity and reviewed PIN attempts
help
quit
```

Three consecutive incorrect teller credentials lock all booth service until
Authorities restore it with `resume-service <review reason>`. Teller passwords,
phone recovery and GUI resume cannot release this security lock. Review the
incident first; restoration requires passing integrity checks. See
[Teller sign-in service lock](TELLER_SERVICE_LOCK.md) for alerts, retry behavior
and the text-file delivery adapter.

Customer PIN locks affect only the identified card. After reviewing the
customer and incident, use `resolve-customer <card-number> <review reason>`;
tellers cannot release these locks. See [Customer PIN locks](CUSTOMER_PIN_LOCK.md)
for sign-in identifiers, alert retries and exact Cargo recovery instructions.

`check` verifies the bank seal, attached fee-record integrity, all attached database
structures, signed financial chain, balances, cash, settings, revenue and
other reconciled state. It reports counts and the chain head on success.
Invalid sessions or altered/rolled-back bank state are refused by the existing
core checks. No teller or customer session can call these Authorities APIs.

See [Administrative audit and privacy](ADMINISTRATIVE_AUDIT.md) for the
Authorities-only log and its impact on the privacy of people in privileged roles.

For code integration, use `atm::oversight::{databases, schema, table, users,
staff, accounts, activity, verify}` with an authenticated `AuthoritiesSession`.
See [Authorities sign-in API](PROCESSING_FEES.md#bank-authorities-sign-in-code-level),
[processing revenue](PROCESSING_FEES.md#bank-revenue-account), and
[ATM origin alerts](ATM_ALERTS.md) for the related records and configuration.
