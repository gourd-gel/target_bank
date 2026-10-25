# Test plan

What to test by hand before the demo, and what the automated tests already
cover. Every step uses the demo bank, so nothing here needs real data.

## 0. Setup

```
rm -f atm-demo.*                           # fresh demo bank: .db, .key, .anchor (Windows: del atm-demo.*)
cargo test                                 # 155 tests + 5 compile-fail checks
cargo test --features demo                 # + 2 tests for the sample data
cargo test --features online-rates         # + 1 test naming each fetch failure
cargo test --features integrity-test       # + 3: the demo tests, and a broken balance caught at sign-in
cargo run --release -p atm-gui --features demo -- --demo
```

Click a card in the demo wallet and type its PIN (PINs are in the user
guide's Demo logins table). When a teller step says "Sam's card" or "Kid's
account number", click **Choose** next to that field and pick the customer.
Teller: `teller` / `teller-demo-2026`. Cash Handler: `cashier` / `cashier-demo-2026`.
Run **Teller > Data integrity > Run check** at the start and the end of every
session: it must say "No tampering detected". The same check runs at every
Teller Admin sign-in, so no red banner may appear, except in the
out-of-service steps of section 7 and the screen checks of section 9.

Two hold tests below need a fresh demo bank (delete `atm-demo.*` again),
because a teller releasing a hold turns the amount rules off for that
account until tomorrow.

Steps that use `sqlite3` need version 3.37 or newer (the tables are STRICT).

## 1. Customer basics

| # | Do | Expect |
|---|---|---|
| 1.1 | Sam: wrong PIN twice, then right | Same "login failed" message both times, then the menu |
| 1.1b | Made-up card number 1234567890, any PIN, three times | "Login failed. Check the card number and PIN." twice, then "This card is locked. Please see a teller to have it unlocked.", exactly like a real card |
| 1.2 | Lou (locked card): right PIN | "This card is locked", even with the right PIN |
| 1.3 | Sam: Withdraw, Other amount 7 | Refused: multiples of $5 only |
| 1.4 | Sam: Withdraw, Other amount 100, tap $5 | Refused: "Not enough of that bill. Available for this amount: $10, $20, $50, $100. You can also choose mixed bills." (the demo machine has 15 or fewer $5s) |
| 1.4b | Sam: Withdraw $400 | The $5 tile is greyed out with "Over 40 bills"; the others show their counts |
| 1.5 | Sam: Fast Cash $60, Confirm, **Yes, print one** | Confirm shows the bills, Withdrawal $60.00, Fees $0.00, Total $60.00; then the card, the cash, and a receipt with the same lines plus balance after and a receipt number |
| 1.6 | Ann: Transfer, type Ann's own account number | Refused: can't transfer to your own account |
| 1.7 | Ann: Transfer, 3 made-up account numbers | Session ends after the 3rd |
| 1.8 | Eva (other bank, EUR): open the menu | No Transfer, Deposit, History or Change PIN: other banks' cards only withdraw and check balance |
| 1.9 | Ann, then Ben: Daily limits | Same "used today" (joint holders share one limit) |
| 1.10 | Any card: wait 90 s | "Do you need more time?"; at 2 min, logged out |
| 1.11 | Sam: Withdraw $40, $20s, Confirm, **No receipt** | "Please take your card" with the name gone from the header (session over); click the card: "Please take your cash, 2 × $20"; click the cash: welcome screen, "Thank you for banking with Bank of CCNY." |
| 1.12 | Sam: Withdraw $40, Confirm, then **Cancel** at "Would you like a receipt?" | Back to the menu; Balance inquiry shows nothing was taken |
| 1.13 | Sam: Deposit one $20, Confirm, **No receipt** | "Deposit received" with "No receipt printed." and no balance or receipt number; still logged in |
| 1.14 | Teller > Customer accounts: click Sam's account, **Freeze**. Sign out. Sam: card and PIN 9512 | Teller: "Account ... frozen: its cards aren't accepted and it takes no transfers." Sam: back at the welcome screen with "This account is frozen by the bank. Please see a teller inside the branch." |
| 1.15 | Sam: card and a wrong PIN | "Login failed. Check the card number and PIN.": the frozen message comes only after the right PIN, and the wrong one still counts toward the lock |
| 1.16 | Ann: Transfer, type Sam's account number | "Destination account not found.", the same as for a made-up number |
| 1.17 | Teller: **Unfreeze** Sam's account. Sam: card and PIN 9512 | "Account ... unfrozen."; Sam reaches the menu |

## 2. Fees: the charge added up

| # | Do | Expect |
|---|---|---|
| 2.1 | Yuki (other bank, JPY): Fast Cash $60 | Withdrawal $60.00, + Other bank's ATM fee $3.00, + Exchange fee $3.00, **Total $66.00**, **Charged to your account 9,980 JPY**. Small print gives the fees and "Rate: 1 USD = 151.20 JPY." |
| 2.2 | Luis (other bank, DOP): Fast Cash $60 | $60.00 + Other bank's ATM fee $3.00 + Exchange fee $3.00 = **$66.00**, charged 4,191.00 DOP. Small print starts "Each fee: 3% of the amount, $3.00 minimum." |
| 2.3 | Ray (other bank, USD): Withdraw $200 | + Other bank's ATM fee $6.00 (3% beats the $3 minimum), Total $206.00, no "Charged to your account" line (dollar card) |
| 2.4 | Teller > Open an account > Individual | No currency choice: Bank of CCNY accounts are in US dollars. Other bank's card still has the currency picker |
| 2.5 | Teller > Exchange rates: exchange fee 2.5 % at least 4 | "Exchange fee saved and logged"; Yuki's next Fast Cash shows + Exchange fee $4.00 and "2.50% of the amount, $4.00 minimum" |
| 2.6 | Teller: exchange fee 6 %, or minimum 11 | Refused (0-5 %, $0-$10) |
| 2.7 | Teller > Audit log | The fee change, with old and new rule and the teller's name |

## 3. Larger amounts (teller approval)

| # | Do | Expect |
|---|---|---|
| 3.0 | Sam: Daily limits | Withdrawals $1,000.00, transfers $5,000.00, deposits $10,000.00 |
| 3.1 | Ann: Withdraw, Other amount 1200 | Refused: "Remaining today: $1,000.00. For a larger amount, please see a teller inside the branch, who can approve it." |
| 3.2 | Teller > Holds and approvals: Ann's account, Withdrawal, extra 200, Approve | "Approved $200.00 more withdrawal today ... Logged." |
| 3.3 | Ben (same joint account): Daily limits | "$1,000.00 + $200.00 today" |
| 3.4 | Ann: Withdraw $1,200 | Works |
| 3.5 | Teller: approve 3,801 more withdrawal for Ann | Refused: more than a teller can approve for one account in one day ($4,000 extra in total; 3,800 would be the most) |
| 3.6 | Teller: approve for Kid's account, or Ray's | Refused (youth caps belong to the guardian; other banks' cards follow their bank) |
| 3.7 | Kid: Withdraw $150 | Over the limit, but no "see a teller" line |
| 3.8 | Sam: Deposit 101 × $100 | Refused: over the $10,000 daily deposit limit, see a teller |
| 3.9 | Teller > Daily limits: Withdrawal limit 5001, **Save limits** | Refused: "Not allowed: the daily withdrawal limit can be at most $5,000.00." (deposit: $50,000.00; transfer: $25,000.00) |
| 3.10 | Teller > Open an account > Individual: a valid name, date of birth and PIN, starting balance 10001 | Refused: "Not allowed: a starting balance can't be more than the daily deposit limit; deposit the rest at the ATM." |
| 3.11 | On the New York day the demo bank was made: the same with starting balance 9000 | Refused: "Not allowed: today's starting balances would pass $20,000; open it with less and deposit the rest at the ATM." The demo bank's own accounts already used about $11,600 of this teller's $20,000 for the day |
| 3.12 | The same with starting balance 5000 | Works. A second one at 5000 is refused (over $20,000 for the day); one with no starting balance still opens |

## 4. Suspicious-activity holds

Bank 1 (fresh):

| # | Do | Expect |
|---|---|---|
| 4.1 | Sam: Fast Cash $60 four times | 4th refused: "For your protection ... please see a teller"; menu shows the notice (rule 1) |
| 4.2 | Sam while held: Deposit $20, Balance, Recent transactions | All work; Withdraw and Transfer are refused |
| 4.3 | Ann: Transfer $1 to Pat four times | 4th refused (rule 2) |
| 4.4 | Pat: Transfer $1 to Ann, then Sam, then Lou | 3rd different account refused (rule 3) |
| 4.5 | Teller > Customer accounts | Sam, Ann/Ben and Pat show ON HOLD |
| 4.6 | Teller > Holds and approvals | One row each: holders, which rule, what was refused, since when |
| 4.7 | Teller: release Sam's hold; Sam withdraws | Works again; release is in the audit log with the teller's name |
| 4.8 | Teller: release Sam's hold again | Refused: not on hold |

Bank 2 (fresh again):

| # | Do | Expect |
|---|---|---|
| 4.9 | Pat: Transfer $950 to Ann | Refused (rule 6: 90 % or more of the balance) |
| 4.10 | Ann: Transfer $600 to Sam; Sam: Withdraw $500 | Ann's transfer works; Sam's withdrawal refused (rule 5: money in, straight out) |
| 4.11 | Ann: Transfer $1,000 to Sam (Ann paid Sam $600 in 4.10, earlier today) | Refused (rule 4: "$1,000 or more to an account not paid before today"): a payment earlier the same day doesn't count, so a small first payment can't switch the rule off |
| 4.12 | Teller > Data integrity | No tampering; every hold and release is in the signed log |

Not testable by hand in one sitting (the automated tests check the logic):
the 1-hour and 24-hour windows rolling over, and limits resetting at
midnight New York time.

## 5. Family (Pat is Kid's guardian)

| # | Do | Expect |
|---|---|---|
| 5.1 | Pat: Family accounts, tap Kid, Move money 20, To child | Both balances shown; Kid +$20 |
| 5.2 | Pat: Move money 75, Back to me | Works (above Kid's own $50 transfer cap) |
| 5.3 | Pat: Back to me, more than Kid has | Refused: insufficient funds |
| 5.4 | Pat: Freeze Kid; To child 10; Back to me 10; then Unfreeze | In works, out refused while frozen |
| 5.5 | Kid: Transfer to Sam | Refused: family-only transfers |
| 5.6 | Kid: Daily limits | Withdrawals $100.00 and transfers $50.00 (the guardian's caps, not the bank's) |
| 5.7 | Sam (not a guardian) | No Family button |
| 5.8 | Kid's history | Guardian moves marked "(guardian)" |
| 5.9 | Pat: Family accounts, Kid, **Freeze**. Teller > Customer accounts | Kid's account shows "Frozen by guardian". The teller's **Unfreeze** is refused: "Not allowed: this account was frozen by its guardian; only the guardian can unfreeze it." |
| 5.10 | Pat: **Unfreeze** Kid. Teller: **Freeze** Kid's account. Pat: Family accounts | Kid's row says "Frozen by the bank". Pat's **Unfreeze** is refused: "Not allowed: the bank froze this account; please see a teller." |
| 5.10a | Pat: Family accounts, Kid, Move money 10, **To child** | Refused: "This account is frozen by the bank. Please see a teller inside the branch." Nothing moves; Pat stays signed in |
| 5.10b | Pat: Sign out. Kid: card and PIN 2580 | "This account is frozen by the bank. Please see a teller inside the branch." (A guardian's freeze, as in 5.4 and 5.9, leaves Kid's card working: it only stops money going out) |
| 5.11 | Teller: **Unfreeze** Kid's account | Works; Pat's list shows Kid as Active; Kid can sign in again |
| 5.12 | Teller > Open an account > Youth account: Parent's card number = Pat's card, Parent's PIN 1111; child Jo Doe, 2015-06-06, starting balance 20, child's PIN 3804 twice | "The holder's card number or PIN was not accepted. Ask them to type it again." All PIN boxes are emptied; nothing is opened |
| 5.13 | The same with Pat's PIN 1357 (and the child's PIN twice again) | "Done. Card number ... Account number ..."; Pat's Family accounts lists Kid and Jo |
| 5.14 | Teller > Open an account > Add guardian: Kid's account number; New guardian's card number = Sam's card; Current guardian's card number = Sam's card, PIN 9512 | Refused: "Not allowed: the card and PIN must be those of a current guardian of this account." Only Pat can agree to a new guardian |

## 6. Send again

| # | Do | Expect |
|---|---|---|
| 6.1 | Pat: transfer to Sam, then to Ann; open Transfer again | "Send again" shows Ann then Sam, as last 4 digits and initials only |
| 6.2 | Tap Sam's button | Goes straight to the amount; confirm shows Sam's masked number |
| 6.3 | Kid after Pat's "Back to me" | Pat is not listed as Kid's payee (Kid didn't send it) |

## 7. Staff and tampering

Staff:

| # | Do | Expect |
|---|---|---|
| 7.1 | Teller: wrong password 3 times | Sign-in paused 60 s, doubling after each further failure |
| 7.2 | Teller: EUR rate 0.86 to 0.95 | Refused: "a typed rate can move at most 5% in 24 hours" |
| 7.2b | Teller: EUR 0.90 (+4.7%), then 0.94 | The first works; the second is refused (still more than 5% from 0.86 within 24 hours), so small steps can't add up |
| 7.3 | Teller: Pause all; Eva withdraws | Refused until resumed |
| 7.4 | Cash Handler: restock past $100,000 | Refused |

Files changed outside the ATM (close the ATM before each step; on Windows use
`copy` and `move`):

| # | Do | Expect |
|---|---|---|
| 7.5 | `cp atm-demo.db saved.db`, then `sqlite3 atm-demo.db "UPDATE accounts SET balance_cents = balance_cents + 100000 WHERE id = 5"`. Start the ATM | It doesn't open. The terminal says "TAMPERING DETECTED: the database was changed outside the ATM. Nothing was done. Stop and escalate." (at once, before anything is decided from the edited row) |
| 7.5b | `cp saved.db atm-demo.db`, start | Opens normally: the untouched copy is still the newest |
| 7.6 | `sqlite3 atm-demo.db "DELETE FROM audit_log WHERE seq = 3"` | Refused by the database (log is append-only) |
| 7.7 | `sqlite3 atm-demo.db "SELECT * FROM cards"` | No full card numbers, names or birth dates: only lookup hashes, ciphertext and last 4 digits |
| 7.8 | `cp atm-demo.db saved.db`, then `sqlite3 atm-demo.db "UPDATE accounts SET account_enc = (SELECT account_enc FROM accounts WHERE id = 1) WHERE id = 2"`. Start | "TAMPERING DETECTED ...", as in 7.5. Then `cp saved.db atm-demo.db` |
| 7.9 | Move `atm-demo.key` away and start | Refused: "Not allowed: the key file is missing, so this database cannot be used." Move it back |
| 7.10 | Move `atm-demo.db` away, as if deleted (keep `atm-demo.key` and `atm-demo.anchor`), and start | Refused: "Not allowed: the bank's database file is missing; restore it, or delete the key and anchor files to start a new bank on purpose." No new bank is made. Move it back: opens normally |
| 7.11 | `cp atm-demo.db old.db`. Start; Ray: Fast Cash $60; close. `cp atm-demo.db new.db`, then `cp old.db atm-demo.db`, start | Refused: "DATABASE ROLLED BACK: this is an older copy of the bank's records. Nothing was done. Stop and escalate." Then `cp new.db atm-demo.db`: opens normally, with Ray's withdrawal still there |

At the counter (type card and account numbers from the demo wallet):

| # | Do | Expect |
|---|---|---|
| 7.12 | Teller > Open an account > Joint holder: Existing account number = Sam's account; Current holder's card number = Sam's card, PIN 1111; new holder Max Roe, 1994-02-11, PIN 2716 twice; **Add joint holder** | "The holder's card number or PIN was not accepted. Ask them to type it again." All PIN boxes are emptied; nothing is added |
| 7.13 | The same with Sam's PIN 9512 (and Max's PIN twice again) | "Done. Card number ... Account number ..." (Sam's account number). Customer accounts: Sam's account is Joint, "Sam Roe (owner); Max Roe (joint)" |
| 7.14 | Teller > Audit log | "Login failed" for Sam's card: "wrong PIN at the counter (admin:teller)"; "Holder added": "joint holder, card ...; confirmed by card ... with PIN" |
| 7.15 | Joint holder on Ann's account with Ann's card and PIN 1111, three times (new holder Kim Hale, 1990-07-04, PIN 2716 twice each time) | 1st and 2nd: "not accepted"; 3rd: "The holder's card is locked. Check their ID and unlock it under Locked cards first." |
| 7.16 | Ann at the ATM with her right PIN 4821 | "This card is locked": wrong PINs at the counter count like the ATM's |
| 7.17 | Teller > Locked cards | Ann's and Lou's cards, shown only as "ending" + last 4, with the account's last 4, name and date of birth. Clicking a row fills in nothing |
| 7.18 | Type only the last 4 digits of Ann's card, **Unlock card** | "Card not found." |
| 7.19 | **Choose** Ann (fills in her full card number), **Unlock card** | "Card ******nnnn unlocked. The customer can use their PIN again." Ann signs in with 4821 |
| 7.20 | Ann: wrong PIN 3 times at the ATM. Teller: unlock Ann's card again | Refused: "Not allowed: this card was already unlocked today; it can be unlocked again tomorrow (New York time)." |
| 7.21 | Teller: unlock Lou's card (**Choose** Lou) | Works: the limit is one unlock per card per day |

Out of service:

| # | Do | Expect |
|---|---|---|
| 7.22 | Teller > Data integrity > **Halt ATM** | "The ATM is out of service. Customers are turned away until you resume." Red banner "ATM OUT OF SERVICE", "halted by teller admin (since ...)", "No cards taken; Teller Admin sign-in only. Review Audit log and Data integrity, then resume."; the button is now **Resume service**. Sign out is still visible under the menu |
| 7.23 | Sign out. Click the card, then Sam's card in the demo wallet | The welcome screen says "Out of service" and "This ATM is temporarily out of service. Please use another ATM." The card is grayed out and says "Not accepting cards"; the wallet's cards are dimmed. Clicking does nothing: no card number or PIN is asked for, so nothing is checked or counted |
| 7.24 | Click the Cash Handler link, then the Cash Handler badge | Both are dimmed and do nothing: only a Teller Admin can sign in while out of service. The Teller Admin link and badge still work |
| 7.25 | Teller: sign in | The red banner is still there, on every tab |
| 7.26 | **Resume service** | "Back in service. The integrity check passes." The banner goes. Sign out: the welcome screen says "Welcome" again and the card works. Sam signs in with 9512, and the Cash Handler can sign in |
| 7.27 | Optional, two windows: also start the command line on the same files (`cargo run --release --features demo -- --demo`) and sign in there as Sam. In the GUI, the teller clicks **Halt ATM**. At the command line, choose 1; then, at the main menu, choose 1 and then 3 | The live session stops: the screen is wiped and the main menu shows "*** OUT OF SERVICE: no cards accepted; Teller Admin sign-in only ***". Choosing 1 gives "! This ATM is temporarily out of service. Please use another ATM." before any card number is asked for; choosing 3 gives "The ATM is out of service. Only a Teller Admin can sign in until it is resumed." before any password. Resume afterwards |
| 7.28 | Teller > Audit log | "Service halted" by teller (admin): "halted by teller admin"; "Service resumed": "resumed after review; integrity check passed" |

Integrity-test build (its own files; close the demo ATM first):

| # | Do | Expect |
|---|---|---|
| 7.29 | `cargo run --release -p atm-gui --features integrity-test -- --demo --break-integrity` | The terminal says "TEST: Ann and Ben's balance was raised by $500 with no log entry. Sign in as the Teller Admin." New files `atm-test.db`, `atm-test.key`, `atm-test.anchor`; `atm-demo.*` is untouched |
| 7.30 | Teller: sign in. Data integrity > **Run check** | Red banner "INTEGRITY CHECK FAILED AT SIGN-IN: ATM OUT OF SERVICE", then the start of "BALANCE MISMATCH: stored balance disagrees with the ledger on account ******nnnn ..." (cut short on screen), and **Resume service**. Run check shows the whole line under "Problems found": the account by its last 4 digits only, "(stored $3,000.00, the log says $2,500.00). Escalate." |
| 7.31 | Sign out. Click Ann's card in the demo wallet | The welcome screen says "Out of service"; the card and Ann's wallet card are grayed out and take no clicks |
| 7.32 | Teller: sign in, **Resume service** | Red notice: "Back in service, but the integrity check still fails: BALANCE MISMATCH ... This is logged, and the next Teller Admin sign-in will take the ATM out of service again." The banner goes; Ann can sign in |
| 7.33 | Teller: sign out and in again | The red banner is back (the balance is still wrong) |
| 7.34 | Teller > Audit log | "Service halted" by system: "integrity check failed at sign-in of admin:teller: BALANCE MISMATCH ..."; "Service resumed" by teller (admin): "resumed after review; integrity check still fails: ..." |
| 7.35 | `cargo run --release -p atm-gui --features demo -- --demo --break-integrity` | Only the usage lines: the option isn't in normal or demo builds |

Delete `atm-test.*`, and start a fresh demo bank after section 7.

## 8. Today's exchange rates (needs internet)

| # | Do | Expect |
|---|---|---|
| 8.1 | Teller > Exchange rates > **Check today's rates** | A table for all 15 currencies: Now, Today's feed, Will set, Note; above it the source and publish time. "Nothing has changed yet." |
| 8.2 | Find a currency whose feed rate is more than 5% from the demo rate (there may be none) | Note "big move: +x.xx%; will be paused" (or −); Will set is the feed's rate |
| 8.3 | **Cancel** | The review closes; Rate history has no new rows |
| 8.4 | Check again, then **Approve these rates** | "N rates set from today's feed. Each change is logged with the source." The table shows the new rates, set by `teller`. After a big move: "... Paused after a big move: JPY. Check each against another source, then Resume." and that currency shows PAUSED |
| 8.4b | Customer with a paused currency: Fast Cash $60 | Refused until the teller clicks **Resume** |
| 8.5 | Audit log | One line per rate, for example "JPY per USD: 151.20 -> 166.32 (daily feed open.er-api.com, published ...; big move: +10.00%; will be paused)", and an "Exchange paused" line for a paused currency |
| 8.6 | Pause EUR, Check, Approve | EUR's note ends "; stays paused"; EUR is still paused afterwards |
| 8.7 | Yuki: Fast Cash $60 | Uses the new JPY rate |
| 8.8 | Turn Wi-Fi off, Check today's rates | "Couldn't reach today's rate feed. Rates are unchanged; you can still type a rate." Typing a rate still works |
| 8.9 | On a network that inspects HTTPS with its own certificate (some school or office networks) | "The connection to today's rate feed failed its security check (certificate not trusted)": the program accepts only certificates from the built-in public root list |
| 8.9b | Audit log | One "Rate feed failed" row per failed check, with the teller and the reason |
| 8.10 | Data integrity | No tampering detected |

## 9. Screen checks (GUI changes in 0.8.0)

Checked on screen for each GUI step of 0.8.0 (G18 to G26); repeat before
the demo. Use the demo build unless a step says otherwise.

| # | Do | Expect |
|---|---|---|
| 9.1 | Teller > Data integrity > **Halt ATM**, sign out | The welcome screen says "Out of service" and "This ATM is temporarily out of service. Please use another ATM." The card is grayed out ("Not accepting cards"); the Cash Handler link and every wallet card except the Teller Admin badge are dimmed and do nothing. The Teller Admin link and badge work |
| 9.2 | Leave the GUI on the welcome screen. In the command line on the same files, sign in as the Teller Admin and resume (option 18); then halt again | Within about 5 seconds the GUI's welcome screen changes back to "Welcome", then to "Out of service" again, with no click (it checks every 5 seconds) |
| 9.3 | Teller signed in while out of service, window at its default size (1180 × 780): visit every tab. Then make the window as small as it goes (1080 × 720) and do the same | The red banner sits over the page only: the title, the reason (cut short with "..." when long) and "No cards taken; Teller Admin sign-in only. Review Audit log and Data integrity, then resume.", with **Resume service** on the right. **Sign out** is always visible under the menu, and a long page (Open an account, Exchange rates) scrolls instead of being cut off |
| 9.4 | Staff sign-in: type the staff ID and press Tab. Teller > Open an account > Individual: click the name field and press Tab until the PIN fields | Tab moves into the password field and into each PIN field, and typing works there |
| 9.5 | Copy some other text first. In a PIN field on Open an account, type a PIN; press Ctrl+A, then Ctrl+C and Ctrl+X (Cmd on macOS); try to select it with the mouse; then paste into the name field | The paste gives the other text: nothing in the PIN field was selected, copied or cut. Copy and paste still work in the name field |
| 9.6 | Data integrity with two problems at once. This needs a build that breaks two things, as the library test `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged` does (a balance and the cash) | Under "Problems found: stop using this machine and escalate", one line per problem: the BALANCE MISMATCH line, with each account's last 4 digits and both amounts, and the CASH MISMATCH line. The banner at sign-in starts "2 PROBLEMS FOUND." |
| 9.7 | Data integrity > **Run check** on a good bank | Besides the log, balance and signed-record lines: "The cash in the machine ($...) matches every restock, deposit, withdrawal and removal." and "... limits, exchange rates and account freezes or closures match the log." |
| 9.8 | Teller: Run check, open an account's activity and the rate review (Check today's rates, if online). Sign out and sign in again. Then a customer: withdraw with a receipt, sign out; another customer signs in | Nothing from before shows: no integrity result until Run check is pressed, the account list instead of the old activity, no rate review, and none of the first customer's receipt, confirm lines, limits or balance |

## 10. What the automated tests cover

`cargo test` runs 155 tests and 5 compile-fail checks:

| Where | Tests | What they cover |
|---|---|---|
| `src/` (library) | 112 (+1 with `demo`, +1 with `online-rates`) | The rules, module by module (below) |
| `tests/attacks.rs` | 26 | Attacks from hostile front-end code (a session from another database, a guardian lifting the bank's freeze, a session outliving a lock or a closed account, absurd amounts, joint holders doubling a limit, a child or stranger reaching youth controls, history showing other people's card numbers, setup run again, two ATMs on one database) and from someone who edits `atm.db` without the key (an edited staff role, copied PIN and password hashes, a card pointed at another account, cleared lock, freeze and failure counters, an inserted guardian link, an edited balance, blanked youth caps, edited limits and rates, an old copy put back, a cut-off log, a deleted database, an edited or removed anchor) |
| `tests/review.rs` | 13 | One test per hole found in the review of the previous version, `a1_...` to `c2_...`. Someone editing the file: an emptied staff table, reset card or staff columns, a typed-in balance, a cleared freeze flag, a deleted database. A dishonest teller: adding a joint holder to drain an account, minting money, appointing a guardian to lift a freeze, orphaning a youth account, unlocking between PIN guesses. A customer: an unknown card answering differently, more than 200 bills of a kind in one deposit |
| `tests/audit.rs` | 4 | Exploits from the audit of 0.7.0 that need a real file or the real program: a blocked anchor file, one teller's starting balances adding up, an index edited in the file, and the command line's screen wipe (below) |
| `tests/demo_mode.rs` | 1 with `demo`, 2 with `integrity-test` | `demo_data_and_real_data_stay_apart`; with `integrity-test`, `a_broken_balance_is_caught_at_the_next_teller_sign_in` |
| `src/lib.rs` (compile-fail) | 5 | A front end can't get a database connection, forge a session, pass a customer session where an admin's is needed, use a session after logout, or make up a rate feed |

The library tests check, among others: money math never goes negative or uses
floats, and absurd amounts are refused; bills paid out exactly, at most 40 per
withdrawal; every limit and cap, including teller approvals and their caps,
the ceilings on bank-wide limits and the cap on starting balances; each fee
rule and its rounding; the charge summary adding up (withdrawal + fees =
total, deposit − fee) and its small print; the rate feed read strictly (wrong
base, failed status, a web page instead of data, stale or future date,
oversized, bad numbers), set at the feed's rate with a move over 5% pausing
that currency, logged with its source, refused if the review is out of date,
and keeping a paused currency paused; a failed check logged with its reason
and changing nothing; the six hold rules, release and "counting restarts";
guardian moves only to the guardian's own account, and held by the same
rules; the bank's freeze and the guardian's freeze each lifted only by their
own side, and the bank's refusing the card; joint holder, youth
account and new guardian needing the holder's own card and PIN; one unlock
per card per day; recent payees (newest first, no repeats, at most 5, not a
guardian's moves); numbers, names and birth dates encrypted at rest and
swapped ciphertext detected; the log naming cards only by id and last 4; a
PIN or password hash working only for its own card or login; the database
seal refusing any row edited outside the ATM (`any_edit_breaks_the_seal_and_a_reseal_fixes_it`)
and STRICT tables refusing values of the wrong type; stored MACs compared in
full; the log chain, balance, cash and state checks and the signed settings
catching records that don't add up, every failure listed; and the integrity
check at sign-in taking the ATM out of service, with halt and resume by hand
(`a_failed_check_at_sign_in_takes_the_atm_out_of_service`,
`a_teller_can_halt_and_resume_by_hand`).

**New in 0.8.0** (8 library tests and the 4 in `tests/audit.rs`):

| Test | Where | What it proves |
|---|---|---|
| `while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in` | `src/service.rs` | While halted, a card is refused before its PIN is checked (right or wrong PIN, and no try is counted); the Cash Handler can't sign in; the Teller Admin can. After a resume the handler and the card work again |
| `a_bank_freeze_stops_the_card_entirely_until_a_teller_lifts_it` | `src/admin.rs` | A bank freeze ends a session already open; the right PIN gets "frozen by the bank" and a wrong one is still a failed login; a transfer to the account is "not found"; the frozen card can't confirm a joint holder at the counter; after Unfreeze the card works |
| `stored_macs_are_compared_in_full` | `src/keys.rs` | `same_mac` accepts only the exact MAC: a wrong first or last character, a cut-off copy or an empty string never match |
| `bills_moved_with_no_log_entry_take_the_atm_out_of_service` | `src/service.rs` | One $100 bill taken out with no log entry (balances still right, database sealed) gives CASH MISMATCH ($9,400.00 counted, $9,500.00 logged), and the next Teller Admin sign-in takes the ATM out of service |
| `guardian_moves_go_through_the_same_activity_rules_as_transfers` | `src/family.rs` | The 4th guardian move out of a child's account within an hour is held (rule 2). The hold is logged, the money stays, and nothing more comes out until a teller releases it; money can still go in |
| `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged` | `src/service.rs` | After a teller resumes over a known wrong balance, a second account and the cash going wrong change the report ("2 PROBLEMS FOUND."), with each account's last 4 digits and both amounts; no full account number is ever written to the log |
| `a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first` | `src/service.rs` | Two connections to one file: a withdrawal waits for the write lock while the other side halts the ATM. Once it gets the lock it is refused ("out of service") and no cash is paid |
| `a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service` | `src/service.rs` | A planted code path raises the withdrawal limit, changes the EUR rate (with a valid MAC) and lifts a bank freeze, sealed, with no log rows. The next sign-in check names all three and takes the ATM out of service |
| `a_finished_deposit_is_never_reported_as_failed_and_a_blocked_anchor_stops_the_atm` | `tests/audit.rs` | With `atm.anchor` blocked (a folder in its place), a deposit is still reported as done. Nothing else runs, not even a Teller Admin sign-in, until the anchor can be written; then the next operation writes it and the bank opens normally |
| `one_teller_cannot_create_unlimited_money_with_starting_balances` | `tests/audit.rs` | Two accounts at $10,000 reach the $20,000 for the day; a third with $1 is refused; one with no starting balance still opens |
| `an_index_edited_in_the_file_is_caught_before_it_can_mislead` | `tests/audit.rs` | After the $1,000 daily withdrawal limit is used, the two audit-log indexes are swapped in the file (no key; every row unchanged). The ATM refuses the file ("the database was changed outside the ATM"), so no further $800 can go out |
| `the_cli_wipes_the_screen_when_a_session_ends` | `tests/audit.rs` | Runs the real `atm` program: after a customer logs out, the screen and its scrollback are wiped, and nothing after the wipe shows the customer's name or balance |

Changed in 0.8.0: `a_failed_check_at_sign_in_takes_the_atm_out_of_service`
(a live Cash Handler session now stops too);
`a_guardian_cannot_lift_a_freeze_placed_by_the_bank` (`tests/attacks.rs`:
the child's card is now refused while the bank's freeze stands, and a
guardian can't move money into the account);
`unusual_amounts_are_held` (a one-cent transfer the same day doesn't switch
rule 4 off); `integrity_check_catches_a_balance_edited_in_the_database`
(the account is named by its last 4 digits only). After the docs pass
found three more gaps, two of the new tests grew:
`a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service`
(a rate set with its history row but no log line, S34) and
`the_cli_wipes_the_screen_when_a_session_ends` (a halt from a second console
while a customer waits; the reason stays on screen after the wipe, S35).
The guardian move into a frozen account above is S33. The fifth compile-fail
check is new: a front end can't make up a rate feed.
