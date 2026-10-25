# Features and security checklist

What the ATM does, how it lines up with the spec and the rubric, a script to
show the security on demo day, and what the team still has to do.

**Dates** (from the handout): Check-in 2 skeleton/flow chart **Oct 12, 11:59 pm** ·
Software Package I zip **Oct 19, 11:59 pm** · Demo day **Oct 21** (10-minute
demo, then oral exam, no notes).

---

## 1. Spec checklist (handout section 5.1)

The instructor ticks these off during the 10-minute demo. All are done; the
right-hand column is where to show each one in the GUI.

| Requirement | Done | Show it here |
|---|---|---|
| **Teller Admin** authenticates into an admin-only interface | ✓ | Welcome → Teller Admin → sign in |
| Create a customer: full name, date of birth, PIN of their choosing, starting balance | ✓ | Open an account → Individual (a starting balance can be at most the $10,000 daily deposit limit, and one teller's starting balances at most $20,000 a day together) |
| View an audit log of all transactions for any account, with timestamps | ✓ | Customer accounts → click an account (also: Audit log tab for everything) |
| Set daily withdrawal and deposit limits for all customers | ✓ | Daily limits (also transfer) |
| Unlock an account locked by failed PINs | ✓ | Locked cards → type the number from the customer's card → Unlock card (once per card per day; the list shows the last 4 only). Demo: Lou Kim's card starts locked; its number is in the demo wallet |
| **Customer** logs in with their PIN | ✓ | Card → card number → PIN (demo: click a card in the demo wallet, then the PIN) |
| 3 consecutive failed PINs lock it until a Teller Admin unlocks it | ✓ | Type a wrong PIN 3 times; then try the right one |
| View total balance | ✓ | Balance inquiry |
| View withdrawal and transfer limit | ✓ | Daily limits (limit, used, left today; "$1,000.00 + $200.00 today" when a teller approved extra) |
| Withdraw; choose the denomination | ✓ | Withdraw cash → amount → bill type |
| Can't withdraw more than the balance or the limit | ✓ | Sam ($800): try $900. Ann: try $1,200, past the $1,000 daily limit (adult customers are told a teller inside the branch can approve more) |
| Must dispense the chosen bill; if short, reject and name the available bills | ✓ | Demo mode keeps only 10-15 $5 bills. Withdraw $100 and pick $5: "Not enough of that bill. Available for this amount: $10, $20, $50, $100. You can also choose mixed bills." Bills that can't make an amount at all ($20 for $250), or would take more than 40 bills, are greyed out |
| Deposit; not more than the daily limit | ✓ | Deposit cash; deposit past $10,000 in a day (for example 101 × $100) |
| Transfer to another customer; enough funds; target validated | ✓ | Transfer money (initials shown; unknown number refused; Send again lists recent payees) |
| History of own recent transactions | ✓ | Recent transactions |
| **Cash Handler** authenticates into a handler-only interface | ✓ | Welcome → Cash Handler → sign in |
| View cumulative cash, itemised by bill | ✓ | Cash inventory |
| Restock, taking the customer daily withdrawal max and cash total into account | ✓ | Restock (capped at the $100,000 maximum; warns when cash is below one customer's daily limit) |
| Withdraw cash to reset to the cash maximum | ✓ | Reset to cash maximum (or Remove) |
| **Additional feature** | ✓ | See section 2 |

## 2. Additional features (and why they're real-world)

| Feature | Real-world reason | Security angle |
|---|---|---|
| **Joint accounts** | Couples share one account; each has their own card and PIN | Per-card lockout and per-card audit trail (who did it); limits are per account so two cards can't double them |
| **Youth accounts with parental controls** | Banks offer teen accounts managed by a parent | Caps, family-only transfers and freeze enforced in the core; only a linked guardian can change them; strangers get "not found"; the parent's freeze and the bank's freeze are separate, and each side lifts only its own |
| **Holder consent at the counter** (adding a joint holder, opening a youth account, adding a guardian) | A bank asks the account holder, not just the clerk, before adding someone to an account | The current holder (or parent) types their own card number and PIN on the teller's form, checked in the core. One teller can't add an accomplice to an account or appoint a guardian alone; a wrong PIN counts toward that card's lock |
| **Mixed-bill withdrawals** | Real ATMs pay mixed bills | Plans only from bills actually in the machine; never half-pays |
| **"Would you like a receipt?"**, card back before the cash | Real ATMs ask, and hand the card back first so it isn't left behind (textbook §3.2.1) | No money moves until the question is answered; a withdrawal ends the session before the cash appears, so nobody inherits it; no receipt means no balance or reference on screen either |
| **At most 40 bills per withdrawal** | Real dispensers cap notes per payout | One customer can't empty the small-bill drawer or jam the dispenser; refused before anything moves |
| **Receipts** with reference numbers | Every ATM prints one | Ties the customer's paper to the signed log entry (non-repudiation) |
| **Change PIN**, recipient initials, Fast Cash | Standard ATM menu items | Wrong current PIN counts toward the lock; initials only, never full names |
| **Freeze / close account** | Lost or stolen card; customer leaves the bank | A bank freeze refuses the account's cards entirely ("This account is frozen by the bank. Please see a teller inside the branch."), ends a session already open, and takes no transfers in, until a teller lifts it. Closed numbers are never reused; history kept |
| **Integrity check** with a check code | Banks reconcile daily | Recomputes every balance and the cash in the machine from the signed log, checks the log chain and the signed limits, fees and rates, and matches limits, rates, freezes and closures against the log. Lists every problem, accounts by their last 4 digits only. (Any edit made to the file outside the ATM is already refused before every operation, by the database seal, which SQLite's own integrity check backs up) |
| **Out-of-service mode** (integrity check at every Teller Admin sign-in; red banner; **Halt ATM** / **Resume service**) | A real ATM takes itself out of service when it detects a fault: "temporarily out of service" | A failed check stops the ATM at once (fail closed): the start screen takes no card, live customer and Cash Handler sessions stop, and only a Teller Admin can sign in. The state is a row in the signed log, not a flag. Resume is a teller's decision, logged with the check's result |
| **Other banks' cards in other currencies** (15 currencies, with flags; Bank of CCNY accounts are USD) | Debit cards abroad: cash in dollars, the card's account charged in its own currency plus a fee | Integer math rounding in the bank's favour; rates must be believable and expire after 72 hours |
| **Exchange-rate controls** (typed rates at most 5% a day, pause, rate history) | Banks set daily rates from their treasury desk | Stops a rogue teller from setting a "friendly" rate; pause handles a crash; history shows who set what |
| **Check today's rates** (daily feed sets the market rate, teller approves; a move over 5% is paused until checked) | Banks take a daily rate feed and a person signs it off | One HTTPS request to a fixed address, certificate checked against built-in roots (Lecture 4); nothing changes until the teller approves; each rate still capped, HMAC'd and logged with the source; customers never touch the network |
| **Cards from other banks** with an ATM fee | Any ATM takes other banks' cards for a fee | Withdraw and balance only, enforced in the core, not just the menu |
| **Charges added up** (withdrawal + each fee = total, then what the account is charged; fee rule and rate in small print; each fee a percent with a minimum, default "3% of the amount, $3.00 minimum") | Customers see exactly what they pay before confirming | Every part rounds in the bank's favour and the dollars add up; a deposit too small for the fee is refused; a teller can only set 0-5% and $0-$10, HMAC'd and logged old → new |
| **Daily limits like a real bank's** ($1,000 cash, $10,000 deposit, $5,000 transfer) | Typical US debit-card limits; $10,000 is the US cash-reporting line | Per account, counted from the signed log; more needs a teller who sees the customer; a teller can set a limit only up to a ceiling ($5,000 / $50,000 / $25,000), so it can't be switched off |
| **Teller approval over a daily limit** | A customer at the branch can ask to take out more | One account, one limit, today only, capped (+$4,000 withdrawal, +$40,000 deposit, +$20,000 transfer); not for youth or other banks' cards; a signed log row with the teller's name, no flag to edit |
| **Suspicious-activity holds** (6 rules) | Banks pause an account after unusual activity and ask the customer to come in | Stops a thief or a mule cashing out fast; the customer isn't told the thresholds; tellers can't change them; "on hold" lives in the signed log; release logged with the teller's name |
| **Guardian moves money** (to the child, or back to own account) | Parents top up or take back pocket money | Money from the child goes only to the guardian's own account; same checks as a transfer; logged "by guardian" |
| **Send again** (last 5 payees) | Every banking app offers it | Masked number and initials only; read from the signed log; only this account's own transfers; closed accounts left out |
| **Masked and encrypted card and account numbers** | Real ATMs never show the full number; card data must not leak from a stolen file | Dots plus last 4 while typing and on receipts (shoulder surfing, textbook §12.4.2). Stored as a keyed HMAC lookup, an AES-GCM copy and the last 4; the log shows "card 7 ending 1234" |

Lead with joint + youth accounts on demo day: they are the most "real bank"
and the most security-relevant (show the holder's card and PIN on the
teller's form). Holds, teller approvals, today's rates and out-of-service
mode come next.

## 3. Demo-day security script (about 5 minutes, plus about 8 for the extra steps, demo mode)

Start from a fresh demo bank: delete `atm-demo.*`, then
`cargo run --release -p atm-gui --features demo -- --demo`. Demo files from
0.6.0 or older won't open (the database layout changed in 0.7.0). The demo
wallet on the welcome screen holds every card (last 4 digits only) and the
two staff badges: click one to insert it. The PINs and staff passwords are
in the user guide's Demo logins table. When a step has the teller enter a
customer's card or account number, click **Choose** and pick the customer,
as if they had handed the card over.

| # | Do this | You should see | STRIDE |
|---|---|---|---|
| 1 | Teller → Data integrity → Run check. Read out the check code | "No tampering detected", the number of log entries and balances checked, "The cash in the machine ($...) matches every restock, deposit, withdrawal and removal.", the signed records checked, "... limits, exchange rates and account freezes or closures match the log.", and a check code. (The same check already ran when the teller signed in; no red banner means it passed) | T, R |
| 2 | Card: a made-up card number, any PIN, 3 times | "Login failed. Check the card number and PIN." twice, then "This card is locked. Please see a teller to have it unlocked.": exactly what a real card says (step 2b), so it never shows whether a card exists | S, I |
| 2b | Card: Sam's card, wrong PIN 3 times, then the right PIN | "Login failed" twice; the third time "This card is locked. Please see a teller to have it unlocked." The right PIN no longer works | S |
| 3 | Teller → Locked cards. **Choose** Sam (as if Sam handed over the card) → Unlock card | The list shows each card as "ending" + last 4, with name and birth date for the ID check; no full numbers, and no row to click. "Card ******xxxx unlocked. The customer can use their PIN again." The Audit log shows the 3 failures, the lock and the unlock with times | S, R |
| 3b | Lou Kim's card starts locked. Unlock it the same way; then card: Lou, wrong PIN 3 times; then Teller → unlock Lou again | The second unlock is refused: "Not allowed: this card was already unlocked today; it can be unlocked again tomorrow (New York time)." So nobody can keep guessing a PIN 3 at a time with a teller unlocking in between | S, E |
| 4 | Card: Kid (youth). Withdraw $120 | Refused: over the $100/day parental cap | E |
| 5 | Kid: transfer to Sam's account | Refused: family-only transfers | E |
| 6 | Card: Pat (parent) → Family accounts → Freeze Kid | Kid's withdrawals refused straight away; deposits still work | E |
| 7 | Transfer: type a made-up account number 3 times | The third time: "Your session has ended", back to the welcome screen (stops account-number hunting) | I |
| 8 | Close the program. In a terminal: `sqlite3 atm-demo.db "UPDATE accounts SET balance_cents = balance_cents + 100000 WHERE id = 1"` (or open it in DB Browser for SQLite and edit the number; either needs SQLite 3.37 or newer, which reads STRICT tables). Start the demo again | The program refuses to start: "TAMPERING DETECTED: the database was changed outside the ATM. Nothing was done. Stop and escalate." The seal is checked before anything is read, so the edited balance can't be spent | T |
| 9 | Show `sqlite3 atm-demo.db "SELECT pin_hash, name_enc, card_lookup, card_enc, card_last4 FROM cards LIMIT 1"`, then `sqlite3 atm-demo.db "SELECT DISTINCT actor FROM audit_log WHERE actor LIKE 'customer:%' LIMIT 3"` | An Argon2id hash, unreadable bytes, a 64-character keyed lookup value, more bytes and only the last 4 digits: no PINs, names or card numbers in the file. The log names cards as `customer:card 7 ending 1234` | I |
| 10 | Leave a customer logged in for 90 s | "Do you need more time?", then logged out at 2 min | S, I |
| 11 | Point at `src/lib.rs` lines 27-64 | The 5 compile-fail tests: a front end can't run SQL, forge a session, use a customer session as an admin, reuse a session after logout, or make up a rate feed | E, T |
| 12 | Teller → Exchange rates → click EUR, type 0.50, Save rate | Refused: "a typed rate can move at most 5% in 24 hours; check today's rates instead, or pause this currency". The Rate history button shows every rate and who set it | T, R |
| 13 | Teller → Exchange rates → Pause all. Then card: Eva (euro card from another bank) → Withdraw $20 | Eva is refused ("the bank has paused exchanges in this currency"). Resume EUR afterwards, and JPY too if you will do step 16 | D, T |
| 14 | Card: Ray (other bank) | Menu shows only Withdraw, Fast Cash, Balance and Daily limits. Withdraw $40: the confirmation shows the bills, then Withdrawal $40.00, + Other bank's ATM fee $3.00, **Total $43.00**, and in small print "Other bank's ATM fee: 3% of the amount, $3.00 minimum." No "Charged to your account" line: it's a dollar card | E |
| 15 | Card → type a card number by hand | Only the last 4 digits show; the rest are dots | I |

Undo step 8 before continuing (same command with `-`: the rows match the
seal again and the demo starts), or delete `atm-demo.*` to get a fresh demo
bank.

**Extra steps for the new features** (about 8 minutes; do them in this
order, pick what fits the time):

| # | Do this | You should see | STRIDE |
|---|---|---|---|
| 16 | Card: Yuki (yen card from another bank) → Withdraw $100 | The confirmation adds it up: Withdrawal $100.00, + Other bank's ATM fee $3.00, + Exchange fee $3.00, **Total $106.00**, **Charged to your account 16,028 JPY**; small print "Each fee: 3% of the amount, $3.00 minimum." and the rate, 1 USD = 151.20 JPY. Choose **Yes, print one**: "Please take your card" comes first (the session is already over), then the cash, then the receipt with the same lines | T, S |
| 17 | Card: Ann → Transfer money → Sam's account, $1,000 | Refused: "For your protection, withdrawals and transfers on this account are paused after unusual activity. Please see a teller inside the branch to confirm it was you." No rule or amount is named. Back at the menu, the hold notice shows; deposits still work | S, I |
| 18 | Teller → Customer accounts, then Holds and approvals | Ann's account shows ON HOLD. The holds list shows Ann Lee and Ben Lee, "rule 4: $1,000 or more to an account not paid before today; refused transfer of $1,000.00" and the time. Click it → Release hold. The Audit log shows "Hold placed" by the activity check and "Hold released" by the teller | R, T |
| 19 | Card: Ann → Transfer $1,000 to Sam again; then open Transfer money once more | Goes through now (a teller has seen Ann today, so the amount rules are off until tomorrow). The transfer screen now offers Send again: Sam's account as `******` + last 4 and "S. R." only | I |
| 20 | Card: Ann → Withdraw → Other amount $1,200 | Refused: "That would exceed the daily withdrawal limit. Remaining today: $1,000.00. For a larger amount, please see a teller inside the branch, who can approve it." | E |
| 21 | Teller → Holds and approvals → type Ann's account number, Withdrawal, Extra $200 → Approve for today. Then card: Ben (same joint account) → Daily limits; then Withdraw $1,200 | Daily limits shows "$1,000.00 + $200.00 today"; the $1,200 withdrawal works (the account still has $1,500 after step 19, and the teller's release and approval turned the amount rules off for it today). The Audit log shows the approval with the teller's name. A second approval of $3,801 is refused: at most $4,000 extra per account per day | E, R |
| 22 | Card: Pat → Family accounts → Kid (still frozen from step 6) → Move money $20 → To child, then Back to me | To child works; Back to me is refused while Kid is frozen. Unfreeze and Back to me works. There is no field for any other account | E |
| 23 | Teller → Exchange rates → **Check today's rates** (needs internet) | A table for all 15 currencies (Now, Today's feed, Will set, Note) under "From open.er-api.com, published ...". A move over 5% says "big move: +x.xx%; will be paused"; a currency still paused from step 13 says "stays paused". "Nothing has changed yet." Press **Approve these rates**: "N rates set from today's feed..." and, after a big move, "Paused after a big move: JPY. Check each against another source, then Resume." The Audit log shows each one, for example "JPY per USD: 151.20 -> 166.32 (daily feed open.er-api.com, published ...; big move: +10.00%; will be paused)" | S, T, R |
| 23b | If there is no internet, or the network inspects HTTPS | No internet: "Couldn't reach today's rate feed. Rates are unchanged; you can still type a rate." HTTPS inspected: "The connection to today's rate feed failed its security check (certificate not trusted)." Audit log: "Rate feed failed" with the reason. Click EUR, type 0.87, Save rate: it works. Say why: the program trusts only the certificates built into it, a failed check changes nothing, and it leaves a trace | D, S, R |
| 24 | Teller → Open an account → Joint holder. Existing account number and current holder's card number: Sam's (**Choose** Sam). Current holder's PIN: a wrong one. Fill in a new adult holder (name, birth date, PIN) → Add joint holder. Then have Sam's real PIN (9512) typed and try again | First: "The holder's card number or PIN was not accepted. Ask them to type it again." Nothing is added, and the Audit log shows a failed login on Sam's card, "wrong PIN at the counter". With Sam's PIN: "Done. Card number ... Account number ...", and the log line "Holder added" says "confirmed by card ... with PIN". Say why: before 0.7.0 one teller could add an accomplice to anyone's account and empty it | E, S, R |
| 25 | Close the demo. Start the integrity-test build: `cargo run --release -p atm-gui --features integrity-test -- --demo --break-integrity` (a separate build: compile it before the demo). Sign in with the Teller badge, open Data integrity and press **Run check**. Then do step 25c | The terminal says Ann and Ben's balance was raised by $500 with no log entry (the way a bad code path would, so the seal still matches). At sign-in, a red banner: "INTEGRITY CHECK FAILED AT SIGN-IN: ATM OUT OF SERVICE", then the start of "BALANCE MISMATCH: stored balance disagrees with the ledger on account ******nnnn ...". Run check shows the whole line under "Problems found": the account by its last 4 digits only, with both amounts, "(stored $3,000.00, the log says $2,500.00). Escalate." It uses its own `atm-test.*` files, so the demo bank is untouched | T, R, D, I |
| 25b | No time to switch builds: in the normal demo, Teller → Data integrity → **Halt ATM**. Make the window as small as it goes (1080 × 720) and click through the tabs. Then do step 25c | "The ATM is out of service. Customers are turned away until you resume." A red banner: "ATM OUT OF SERVICE", "halted by teller admin (since ...)", "No cards taken; Teller Admin sign-in only. Review Audit log and Data integrity, then resume." and **Resume service**. Sign out stays visible under the menu on every tab, and long pages scroll instead of being cut off | D, R |
| 25c | Sign out. On the start screen, try the card, the Cash Handler link, and the wallet's cards and Cash Handler badge. Then sign in with the Teller Admin badge and press **Resume service** | "Out of service" and "This ATM is temporarily out of service. Please use another ATM." The card is grayed out and says "Not accepting cards"; the Cash Handler link, the wallet's cards and the Cash Handler badge are dimmed and do nothing. Only the Teller Admin badge and link work. Say why: Zack asked that a halted ATM take no cards at all, only admins; nothing is typed, so no PIN goes into a machine whose books may be wrong, and no cash is moved before a teller has looked. Resume after 25: "Back in service, but the integrity check still fails: ... the next Teller Admin sign-in will take the ATM out of service again."; after 25b: "Back in service. The integrity check passes." The Audit log shows "Service halted" (by the system after 25, by the teller after 25b) and "Service resumed" (by the teller) | D, E, R |
| 26 | In the normal demo: Teller → Customer accounts → click Sam's account → **Freeze**. Sign out. Card: Sam, PIN 9512. Then card: Pat → Transfer money → pick Sam's account from the list. Finally, Teller → Sam's account → **Unfreeze** | Teller: "Account ... frozen: its cards aren't accepted and it takes no transfers." Sam is sent back to the start screen with "This account is frozen by the bank. Please see a teller inside the branch." Pat: "Destination account not found.", as for a number that doesn't exist. After Unfreeze, Sam signs in again. Say why: a bank freeze is the response to a stolen card, so the card is refused entirely; a guardian's freeze (step 6) only stops money going out, and Kid's card still works | S, E, I |

Steps 17-21 leave Ann's and Sam's accounts changed, step 23 moves the
rates, step 24 adds a holder to Sam's account and step 26 leaves a freeze
and an unfreeze in Sam's log; delete `atm-demo.*` for a fresh demo bank
before a second run. Delete `atm-test.*` to run step 25
again on fresh data. Screenshots of steps 24-26 (in `docs/screenshots/`):
`joint-holder-consent.png`, `out-of-service-banner.png`,
`integrity-halt-resume.png`, `out-of-service-welcome.png`,
`account-frozen-teller.png`, `frozen-card-refused.png`.

## 4. What changed compared with the three earlier versions

The team had three codebases: the core library (`atm (Merged)`, command
line only), **The-Bank-of-CCNY** (Slint GUI + PostgreSQL in Docker) and
**The-Bank-of-CCNY-2** (Slint GUI + its own SQLite core). This version uses
the first as the core and the second's GUI design, rewired to the core.

**Why The-Bank-of-CCNY-2's GUI as the base**: it already talked to a library
through session types (the same design as our core), it never stores a PIN in
a UI property, its screens follow a real ATM (keypad, Fast Cash, bills, receipt),
and it needs no Docker or database server. The-Bank-of-CCNY needs Docker and a
PostgreSQL superuser over an unencrypted connection, which adds install steps
and attack surface.

| Feature | Core (CLI) | CCNY (GUI 1) | CCNY-2 (GUI 2) | Now |
|---|---|---|---|---|
| GUI | – | ✓ | ✓ | ✓ (GUI 2's design) + CLI |
| Storage | SQLite | PostgreSQL (Docker) | SQLite | SQLite |
| Joint accounts | ✓ | – | – | ✓ |
| Youth accounts + parental controls | ✓ | – | – | ✓ |
| $5 bills, mixed-bill withdrawals | ✓ | – | – | ✓ |
| Receipts | ✓ | – | – | ✓ |
| Freeze account | ✓ | deactivate | – | ✓ (since 0.8.0 a bank freeze refuses the card) |
| Close account | – | delete (number reused) | – | ✓ close, number never reused |
| Change PIN | – | – | ✓ | ✓ |
| Recipient initials before transfer | – | – | ✓ | ✓ |
| List all accounts / full audit log view | – | ✓ | ✓ | ✓ |
| Staff change own password | – | – | – | ✓ (new) |
| Cash maximum vs physical capacity, reset to maximum | ✓ | – | – | ✓ |
| Demo mode with sample data | ✓ | seed program with fixed passwords | – | ✓ (separate build flag; normal build has none, and refuses demo data) |
| PIN hashes keyed with a secret (pepper) | ✓ | – | ✓ | ✓, one key per card and per login (0.7.0) |
| Signed (HMAC) audit chain + balance reconciliation | ✓ | – (log can be edited) | ✓ | ✓, also at every Teller Admin sign-in (0.7.0); the cash, limits, rates and freezes too, every problem listed (0.8.0) |
| Whole database sealed, checked before every operation; older copy refused (`atm.anchor`) | – | – | – | ✓ (new in 0.7.0) |
| Out-of-service mode (red banner, Halt ATM, Resume service) | – | – | – | ✓ (new in 0.7.0; since 0.8.0 no card is taken and only a Teller Admin signs in) |
| Holder's own card and PIN to add a joint holder, youth account or guardian | – | – | – | ✓ (new in 0.7.0) |
| Encrypted names and birth dates | – | – | – | ✓ (new) |
| Key fingerprint (wrong key file refused) | – | – | – | ✓ (new) |
| Staff lockout with growing pauses | 60 s fixed | none (failures logged only) | ✓ from 30 s | ✓ 60 s doubling to 15 min |
| Idle timeout | ✓ | – | ✓ | ✓ + "more time?" warning |
| Logout written to the log | – | – | – | ✓ (new) |
| Clock-rollback check | ✓ | – | – | ✓ |
| Secrets wiped from memory (zeroize) | – | – | ✓ | ✓ |
| SQLite hardening (defensive mode, secure delete) | – | n/a | – | ✓ (new) |
| Foreign-currency accounts, rate limits, pause, rate history | – | – | – | ✓ (new) |
| Cards from other banks with an ATM fee | – | – | – | ✓ (new) |
| Card numbers masked while typing | – | – | – | ✓ (new) |
| Charges shown added up (withdrawal + fees = total) | – | – | – | ✓ (new) |
| Daily rate check over HTTPS, approved by a teller | – | – | – | ✓ (new; the only network use, GUI only) |

**Features from The-Bank-of-CCNY deliberately left out**, with the reason to
give if asked:

| Feature | Why not |
|---|---|
| Collect SSNs (stored as an HMAC fingerprint) | The spec doesn't need them. Data you don't collect can't leak (data minimisation) |
| Teller resets a customer's PIN | A teller who can set PINs can take over accounts. Customers choose their own PIN; tellers only unlock |
| Teller edits customer name/DOB | Same insider risk; name and DOB are what the teller checks ID against |
| Teller creates more staff logins | One admin able to mint admins = hidden persistent access. Setup creates exactly one of each |
| Delete a customer | Deleting breaks the audit trail and frees the number for reuse. Close does neither |

**0.7.0: the teammate's Integration branch and the security review.** A
teammate hardened an early 0.3.0 build on a branch called Integration. A
review of it found 14 holes, 13 of which 0.6.0 had too. 0.7.0 starts from
0.6.0, brings in the teammate's ideas, fixes the 13 (`tests/review.rs`,
`a1_...` to `c2_...`) and adds Zack's out-of-service mode. Full list, with
reasons: `docs/DESIGN_DECISIONS.md` §22.

| From the teammate | In 0.7.0? |
|---|---|
| Ledger check and anchor file | ✓, grown into the whole-database seal and `atm.anchor` |
| PIN and password hashes keyed per card or login | ✓ |
| Sessions bound to the bank that issued them, re-checked on every action | ✓ |
| Separate bank and guardian freezes | ✓ |
| Customer history without other people's numbers | ✓ |
| `Cents::MAX`; STRICT tables | ✓ |
| Their attack tests | ✓, 26 in `tests/attacks.rs` |
| Decisions read from the signed log | – The seal covers every row, so nothing is decided from altered data; simpler, same protection |
| Five display currencies | – This version has 16 currency accounts |
| No new guardian while guardian-frozen | – The current guardian's own card and PIN already cover it |

**0.8.0: Zack's three asks and an audit of 0.7.0.** Out of service takes no
cards and only a Teller Admin signs in; a bank freeze refuses the account's
cards until a teller lifts it; the red banner no longer hides Sign out. An
audit of 0.7.0 found 31 issues (F01 to F31): 21 are fixed, each with a test
(`tests/audit.rs` and 8 more library tests) or a screen check, and 10 are
design limits, written up with the reason (`docs/VULNERABILITIES.md` §9).
Decisions: `docs/DESIGN_DECISIONS.md` §23-29.

## 5. Still to do (team)

**Must do before Oct 19**
- [ ] **Everyone reads the code.** Any member can be shown any snippet. Split it:
  one person each for `auth.rs` + `keys.rs` + `seal.rs` + `anchor.rs` +
  `lib.rs`, `customer.rs` + `family.rs` + `dispense.rs` + `fx.rs` +
  `rate_feed.rs`, `admin.rs` + `cash.rs` + `audit.rs` + `db.rs` +
  `review.rs` + `service.rs`, and `gui/`. Then explain your part to the
  others.
- [ ] **Everyone can say where each security choice comes from** in the
  course, and why the few extras (Argon2id, HMAC instead of signatures, a
  keyed lookup instead of a plain hash for card numbers, rustls for the
  rate feed, the whole-database seal and anchor) are better
  (`docs/COURSE_MAPPING.md`).
- [ ] **Everyone can explain the integrity design** (0.7.0 and 0.8.0;
  `docs/DESIGN_DECISIONS.md` §3, §14, §27, §28): what the seal catches (any
  edit made outside the ATM, refused at once; SQLite's own check covers the
  index pages) and what the sign-in check catches (books that don't add up,
  including the cash, and limits, rates and freezes changed with no log
  entry, even if the program wrote them; every problem listed); why halting is
  automatic but resuming is a person's decision; why one teller can resume,
  and that two-person approval is still open; what an older copy of both
  `atm.db` and `atm.anchor` would still do.
- [ ] **Everyone can explain 0.8.0's choices** (`docs/DESIGN_DECISIONS.md`
  §23-26, §29): why out of service takes no card and stops the Cash Handler
  too; why a bank freeze refuses the card but a guardian's doesn't (Zack's
  "only admins", read two ways); why $20,000 a day for starting balances;
  why rule 4 counts only earlier days; why F03, F13, F19, F21 and F29 stay
  as they are.
- [ ] **Everyone can explain holder consent and the bounded teller powers**
  (`docs/DESIGN_DECISIONS.md` §9, §10, §13, §22): what the teammate's branch
  and the review found, and what each fix stops.
- [ ] **Everyone can explain the rate check** (`docs/DESIGN_DECISIONS.md`
  §20): why fetch, then a teller approves; why this source (the ECB lacks 6
  of our currencies); what TLS checks (Lecture 4: certificate, no
  downgrade); why the feed sets the market rate but a move over 5% is paused
  (Zack's "trust the feed" decision, §8); what happens when it fails.
- [ ] **Try Check today's rates on your own machine, and on the network
  you will demo on.** The automated tests use saved feed text; the real
  source has not yet been reached from the build environment. If a network
  inspects HTTPS (some school networks), expect the refusal and plan to
  show step 23b instead.
- [ ] **Everyone can explain the six hold rules** and why their thresholds
  are fixed in code and hidden from customers (`docs/DESIGN_DECISIONS.md`
  §16).
- [ ] **Everyone can recite the threat model**: stakeholders, adversaries,
  assets, one STRIDE threat + defense per category (`docs/THREAT_MODEL.md`).
- [ ] **Time the install on the demo laptop.** Follow the README exactly. The
  first build compiles Slint and SQLite (about 6 minutes on 4 cores; the
  command line alone about 1 minute). The rubric asks for setup under 3
  minutes: know how long it takes on yours, and build before the demo starts.
- [ ] **Update the flow chart** to match: card number + PIN login, $5 bills,
  Change PIN, Family screen, joint/youth accounts, close account, staff
  password change, other banks' cards (and their currencies), the
  Exchange rates screen, the charge summary on confirm and receipt, the hold
  notice, the teller's Holds and approvals tab, Move money, Send again and
  the Check today's rates review, the receipt question, and the card
  returned before the cash.
  (The current chart offers $10-$100 only.)
  New in 0.7.0, also still to add: the integrity check at Teller Admin
  sign-in and the red out-of-service banner; **Halt ATM** / **Resume
  service** on the Data integrity tab; the holder's card number and PIN on
  the Joint holder, Youth account and Add guardian forms; Locked cards
  unlocked by typing the number from the card; the start-up refusal for an
  edited or rolled-back database.
  New in 0.8.0, also still to add: the out-of-service start screen (no card
  taken, Teller Admin sign-in only, Cash Handler refused; no PIN screen while
  out of service); a bank-frozen card sent back with "This account is frozen
  by the bank. Please see a teller inside the branch."; one line per problem
  on the Data integrity tab.
- [ ] **Write who did what** (oral exam question 6).
- [ ] **Rehearse the 10-minute demo** with each member speaking about equally:
  setup → cash handler → teller → customer → additional features → section 3.
- [ ] **Zip**: `cargo clean`; leave out `target/`, `atm.*` (`atm.db`,
  `atm.key`, `atm.anchor`), `atm-demo.*` and `atm-test.*`; keep
  `Cargo.lock`. Unzip into a fresh folder and build once to check.

**Check on the demo machine**
- [ ] `cargo test` passes: 155 tests (112 library, 26 attack, 13 review,
  4 audit) plus 5 compile-fail checks. `--features demo` adds 2, `--features
  online-rates` adds 1, and `--features integrity-test` adds 3 (the 2 demo
  tests and the broken-balance test).
- [ ] Any `atm.db`, `atm.key`, `atm.anchor`, `atm-demo.*` or `atm-test.*`
  from an older build is deleted (the database layout is schema 6; older
  files are refused).
- [ ] If you will show step 25: build the integrity-test GUI before the
  demo (`cargo build --release -p atm-gui --features integrity-test`), so
  the step doesn't wait for a compile.
- [ ] The GUI can reach `open.er-api.com` from the demo network (step 23),
  or the team is ready to show the failure message (step 23b).
- [ ] Normal build has no demo logins: `cargo run --release -p atm-gui -- --demo`
  must refuse.
- [ ] On macOS/Linux, `ls -l atm.key atm.db atm.anchor` shows `-rw-------`.
- [ ] Windows only: file permissions are not tightened automatically (known limit).

**Optional hardening if time allows** (each is small)
- [x] Run the integrity check automatically when a Teller Admin signs in and
  show a red banner if it fails (done in 0.7.0, with out-of-service mode).
- [ ] Two-person approval for unlock, close, hold release, large limit
  approvals, rate feed approvals, resuming service and starting balances
  (second admin login).
- [ ] Log each time a teller views a customer's details (name, birth date,
  history).
- [ ] Run the rate check on a background thread, so the teller's screen
  doesn't wait up to 10 s.
- [ ] Windows ACLs for `atm.key`, `atm.db` and `atm.anchor`.
- [ ] Turn a youth account into an individual one at 18; remove a joint holder.

## 6. Rubric map

| Rubric line | Points | Where |
|---|---|---|
| Installation | 5 | README §1-2 (assumes Rust; lists every other dependency). The first GUI build takes about 6 minutes on 4 cores: build before the demo |
| Functional requirements | 15 | Section 1 above; `docs/USER_GUIDE.md` |
| Additional feature | 5 | Section 2 above (lead with joint and youth accounts and holder consent; out-of-service mode) |
| Time | 5 | Section 3 above is ~5 min, plus ~8 min of extra steps (steps 24-25 show 0.7.0, steps 25b-26 show 0.8.0); pick what fits and rehearse the rest |
| Design justification | 10 | `docs/DESIGN_DECISIONS.md` (0.7.0: §3 seal and anchor, §13 bounded teller powers, §14 out-of-service mode and why it halts on its own but resumes only by a person, §22 what came from the teammate's branch; 0.8.0: §23 no card while out of service, §24 bank freeze, §25 starting-balance cap, §26 rule 4, §27-28 the wider integrity check, §29 design limits); `docs/COURSE_MAPPING.md` (where each choice comes from in the course; 4.6 for the seal) |
| Threat model / STRIDE | 20 | `docs/THREAT_MODEL.md` §1-4 (Lecture 1's Policy / Incentives / Mechanisms / Assurance, data flow diagram, STRIDE) |
| Security mitigations with code references | 15 | `docs/THREAT_MODEL.md` §4 (file → function → test); `docs/VULNERABILITIES.md`; `STRIDE (...)` comments in the code; attack tests in `tests/attacks.rs` (26), `tests/review.rs` (13, one per review hole) and `tests/audit.rs` (4, from the 0.8.0 audit) |
| Code comprehension | 10 | Section 5, "everyone reads the code" |
| Collaboration | 5 | Who-did-what notes; the teammate's Integration branch and what 0.7.0 took from it (section 4; `docs/DESIGN_DECISIONS.md` §22); Zack's out-of-service idea |
| Preparedness | 5 | Section 3 rehearsed, including the integrity-test build (step 25) on the demo laptop |
| User guide | 5 | `docs/USER_GUIDE.md`: every screen for each role, step by step with screenshots, the command line, and what each message means |
