# Processing fees

Every successful withdrawal, deposit, bank transfer, and guardian transfer incurs a **3% processing fee**. Failed attempts, previews, balance inquiries, staff cash handling, and account administration incur no fee. Historical transactions are not charged retroactively.

The fee uses principal in the source account currency before existing ATM/exchange fees. Integer arithmetic rounds up to the smallest supported unit (one cent, or a whole yen/won). Foreign cash principal is the converted cash amount.

- Withdraw $100: debit $103, plus any existing ATM/exchange fees.
- Deposit $100: credit $97, less any existing exchange fee.
- Transfer $100: debit the sender $103; credit the recipient $100.
- Guardian transfers: the account money leaves pays the fee.

The GUI is the sole user access channel, and only GUI user activities are traced in the activity audit. The amount the customer confirms is the requested cash or transfer principal. It does not need to equal the final account debit or credit: fee breakdowns show the account impact separately, and receipts report the actual result. For example, confirming a $100 deposit results in a $97 credit; confirming a $100 transfer results in a $103 sender debit and a $100 recipient credit. The bank informs the users regarding processing fees during the bank account sign up process, and the receipt reflects the breakdown of costs incurred to avoid confusion during transactions.

Withdrawals and transfers require sufficient funds including fees. Deposits must leave a positive net credit. Daily limits count principal, excluding processing fees. Receipts show processing fees and net totals. The GUI activity audit shows requested principal only, with no separate fee rows or fee-adjusted transaction amounts. Processing-fee credits are recorded in the bank revenue account. The internal signed financial ledger preserves actual debits, credits and fee records for balance reconciliation; cash reconciliation does not treat fees as physical bills removed.

## Programmer provisioning

Generate a dedicated key pair on the programmer's machine before money transactions. Put the private key outside the bank delivery folder:

```sh
cargo run --features programmer-tools --bin bank-processing-fees -- provision /path/to/atm.db /programmer-only/atm.processing-fees.private.pem
```

This creates `/path/to/atm.processing-fees.public.pem` and the private key without overwriting existing files. Deliver **only the public key**, beside the matching bank database. Restart the ATM to install it. Existing banks can be provisioned too; the installed recipient is pinned in the sealed state. Without a provisioned public key, money transactions roll back; setup and read-only actions remain available.

Keep the private key backed up securely off the bank machine. Neither the ATM nor `atm.key` can recover it. This key is independent of `.programmer-pin.secret`, which also stays with the programmer. Normal GUI builds exclude the programmer tool and private key.

## Separate encrypted database

The ATM writes `atm.processing-fees.db` next to `atm.db`. Each record contains an internal financial reference and an RSA-OAEP-SHA256 encrypted payload. Only the private key holder can decrypt the payload. The versioned JSON array contains: version, original transaction reference, UTC timestamp, source account id, transaction kind, currency, principal in hundredths, and fee in hundredths. Keep currencies distinct when reporting totals.

Read a copy offline on the programmer machine:

```sh
cargo run --features programmer-tools --bin bank-processing-fees -- read /backup/atm.processing-fees.db /programmer-only/atm.processing-fees.private.pem
```

The bank can access the ciphertext file as application owner and inspect processing charges through the bank revenue account. Encryption protects the separate records; it does not hide fees from the bank or customers. No teller/customer/GUI endpoint reads the private ledger.

Both databases commit in one SQLite transaction using DELETE rollback journals and FULL synchronization. A failure rolls back balances, cash, audit entries, and private records together. The bank seal includes a hash of the separate database schema, public key, and encrypted rows; missing or changed data stops operations.

Back up and restore **both databases and the matching `atm.anchor` together** from a consistent snapshot while the ATM is stopped. Keep `atm.key` and the programmer private key in their respective custody. The offline tool decrypts records; the running ATM supplies sealed-state integrity and rollback checks.


## Bank revenue account

Processing fees are credited to the bank's revenue account in `atm.db`, in the same transaction as the customer debit and encrypted fee record. `bank_revenue` holds one balance per currency; `revenue_ledger` links each credit or adjustment to its signed `audit_log` reference. USD, EUR, yen, won, and other currencies are never added together without conversion. Existing ATM and exchange fees are outside this processing-fee account.

On upgrade, fees already recorded as `processing_fee` are credited to revenue once, without charging any customer again. Startup verifies the original seal before migration, and the new tables and balances are included in subsequent seals. Integrity verification reconciles revenue balances and entries with the signed audit. A revenue write failure rolls back the entire customer transaction, including cash and the separate encrypted ledger.

Bank Authorities is a **backend-only role**. There is no Authorities sign-in, menu, dashboard, session or revenue callback in the booth GUI, and no Authorities option in the booth CLI. An authorized code-level integration uses `auth::recovery::request_authorities_code` and `auth::recovery::login_authorities` with the separately configured authorities phone to obtain an `AuthoritiesSession`. The session is required by `revenue::balances`, `revenue::history` and `revenue::adjust`; `auth::logout_authorities` ends it.

Phone configuration remains programmer-managed through `cargo authorities-phone`. Codes are delivered to `<phone-number>.authorities-login.txt`, separately from alert messages. Five-minute expiry, five attempts, single use, and one-per-minute / three-per-fifteen-minute send limits remain enforced. This continues the local text-file phone simulation. A separate authorities application can use these APIs; none is included in the booth.

Authorities can view currency balances and paged history, and record **credit or debit adjustments with a required reason**. Debits cannot overdraw revenue. Adjustments change the internal revenue balance only; they do not dispense cash or transfer money to a customer. Every adjustment records the authorities actor, amount, currency, timestamp, reference and reason. Revenue and internal financial entries remain append-only. Corrections are recorded as new entries, rather than overwriting history.

Tellers, Cash Handlers and customers have no revenue management access. Authorities sessions do not grant teller or cash-handler powers and expire under the usual idle timeout. Revenue access remains available during a service halt, subject to database integrity checks. Bank Authorities does not receive the programmer's private decryption key; the separate encrypted fee records remain readable only by that key's holder.


## Bank Authorities sign-in (code level)

Authorities authenticate through a trusted integration outside the booth. There is no Authorities login in the ATM GUI or booth CLI, and no separate authorities application is bundled.

1. **Configure the Authorities phone.** From the programmer source workspace, run the following with the actual Authorities number and bank folder:

   ```sh
   cargo authorities-phone +12125550199 --directory /path/to/bank-folder
   ```

   Enter the programmer PIN at the hidden prompt. The number above is an example. Keep `.programmer-pin.secret` in the programmer workspace; it is not given to the bank. First-run staff setup must have created the Authorities role before sign-in.

2. **Open the existing bank from the trusted integration.** Use `Atm::open` with the matching bank database and `atm.key`. The matching processing-fee database and anchor must be available too. This is access to the existing bank, not creation of a new bank.
3. **Request a code.** Call `auth::recovery::request_authorities_code(&mut bank, phone)` with the configured Authorities phone. The generic response does not confirm registration or delivery.
4. **Obtain and enter the code.** In this local-file simulation, read `<phone-number>.authorities-login.txt` beside the bank database. For the example number, the file is `+12125550199.authorities-login.txt`. The plain `<phone-number>.txt` file contains teller alerts and is not the Authorities sign-in code file. Call `auth::recovery::login_authorities(&mut bank, phone, code)` to receive an `AuthoritiesSession`.
5. **Access revenue using that session.** Call `revenue::balances`, `revenue::history` (page 0 is newest), or `revenue::adjust`. Adjustments require a supported currency, positive amount, credit/debit direction and a reason. Every adjustment is recorded in the revenue ledger.
6. **Sign out.** Call `auth::logout_authorities(&mut bank, session)`, which consumes and ends the session. Sessions also expire after two minutes of inactivity.

The following function illustrates the API flow inside an authorized off-booth Rust integration. The integration supplies the configured phone and opens the existing bank before calling it:

```rust
use atm::{Atm, auth, input, revenue};

fn authorities_revenue(bank: &mut Atm, phone: &str) -> atm::error::Result<()> {
    println!("{}", auth::recovery::request_authorities_code(bank, phone)?);
    let code = input::read_secret("Authorities verification code: ")?;
    let session = auth::recovery::login_authorities(bank, phone, code.trim())?;
    drop(code);

    let result = (|| {
        for account in revenue::balances(bank, &session)? {
            println!("{}", account.currency.format(account.balance));
        }
        for entry in revenue::history(bank, &session, 0)? {
            println!("#{}: {}", entry.reference, entry.detail);
        }
        Ok(())
    })();
    let signed_out = auth::logout_authorities(bank, session);
    result.and(signed_out)
}
```

Codes expire after five minutes, allow five verification attempts and work only once. Request at most one per minute and three per fifteen-minute window. A teller phone/code cannot produce an Authorities session, and an Authorities session grants no teller or Cash Handler permissions. If sign-in fails, check the configured number, code-file suffix, expiry and resend limits; request another code after the applicable wait. See [ATM origin alerts](ATM_ALERTS.md) for notification location and signature details.
