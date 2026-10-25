# Vulnerabilities and exploits

Every attack we considered against this ATM, grouped by where the attacker
stands (at the machine, on the staff side, with the database file, on the
network, or inside the code). For each one: how the exploit would work, its STRIDE category, who
would try it (the adversaries from `THREAT_MODEL.md` §3), the defense, and
its status. The last sections list where a Phase II team would most likely
hide a backdoor, the open items in the order we would fix them, and (§9)
each finding of the audit of 0.7.0 with what 0.8.0 did about it.
Numbers never change, so other notes can cite them; a newly considered
attack takes the next free number in the section where it belongs. Where
the audit showed a row was wrong, the row says so and names the 0.8.0
step that fixed it (S = core library, G = GUI, as in `CHANGES.md`).

Tests named `a1_...` to `c2_...` are in `tests/review.rs` (one per hole the
security review found in 0.6.0), the 26 attack tests in `tests/attacks.rs`,
the 4 audit tests (one per exploit of 0.7.0 that needs a real file or the
real program) in `tests/audit.rs`, and `demo_data_and_real_data_stay_apart`
and `a_broken_balance_is_caught_at_the_next_teller_sign_in` in
`tests/demo_mode.rs`. All other tests are in `src/`.

**Status**
- **Defended**: blocked, and a test or a check proves it.
- **Limited**: the attack still works, but within a small, logged limit.
  Accepted on purpose; the reason is given.
- **Gap**: not defended yet. A fix is listed under "Open items".
- **Out of scope**: needs real hardware or a network this project doesn't have.

---

## 1. At the machine (customers, guests and strangers)

| # | Exploit | STRIDE | Who | Defense | Status |
|---|---|---|---|---|---|
| 1 | Guess a PIN by trying many times | S | Stranger with a stolen card | 3 wrong PINs lock the card. The count is saved before the error returns, so quitting the program doesn't reset it. Test: `three_consecutive_failures_lock_even_against_the_right_pin` | Defended |
| 2 | Guess the PIN through the Change PIN screen of an unlocked session | S | Stranger at a walked-away session | Wrong "current PIN" counts toward the same lock. Test: `guessing_the_current_pin_locks_the_card_and_ends_the_session` | Defended |
| 3 | Find out which card numbers exist from the error message or how long it takes | I | Stranger | An unknown or closed card number answers exactly like a real card: the same Argon2 time, "Login failed." twice, then "card locked" on the 3rd try (`auth.rs` → `like_a_real_card`; counted in memory only, at most 10,000 numbers). Before 0.7.0 the 3rd try gave it away (review hole C1). The stand-in hash is made when the bank opens (`auth.rs` → `warm_up`), so the first try after a start takes as long as any other. Tests: `right_pin_logs_in_and_wrong_pin_does_not`, `c1_a_real_card_and_an_unknown_card_fail_the_same_way` | Defended. Until 0.8.0 the first failed try after each start was slower for an unknown card (audit F26, fixed in S21) |
| 4 | Read a card number over someone's shoulder, or from a thrown-away receipt (textbook §12.4.2) | I | Stranger, cashout gang | Dots plus last 4 while typing; the CLI hides the number; receipts and history show the last 4 only; the customer can choose no receipt, and then the screen shows no balance or reference number | Defended (GUI checked by screenshot) |
| 5 | Use a session someone walked away from, or read what the last person left on screen | S, I | Next person in line | 2-minute idle timeout in the library; GUI warning at 90 s. On logout or timeout the GUI wipes every screen property that held someone's data (`gui/src/main.rs` → `go_welcome`), and the CLI clears the screen and its scrollback (`input.rs` → `wipe_screen`). The teller's Sign out button stays on screen under the red out-of-service banner. Test: `the_cli_wipes_the_screen_when_a_session_ends` | Defended. Was not true until 0.8.0: the CLI wiped nothing (audit F27, S31), the GUI left some properties filled (F30, G25), and the banner pushed Sign out off the teller screen (F06, G19). The CLI waits for a key with no timer, so a session left at a menu ends, and is wiped, at the next key |
| 6 | Hunt for valid account numbers on the transfer screen | I | Stranger, dishonest customer | Random 10-digit numbers; only initials shown; 3 unknown numbers end the session. An account the bank froze looks like an unknown number. Test: `hunting_for_account_numbers_ends_the_session` | Limited (accepted): the count is per session, so signing in again starts a new one; each try needs a real card and PIN and is logged (§9, F18) |
| 7 | Take more than the balance or the daily limit, or run two withdrawals at once | T | Dishonest customer | Every check and the money movement happen in one IMMEDIATE transaction. Tests: `cannot_withdraw_more_than_balance`, `daily_limit_is_cumulative`, `every_operation_keeps_the_ledger_consistent` | Defended |
| 8 | Two joint holders each take the full daily limit | T | Dishonest joint holder | Limits are per account, not per card. Tests: `joint_holders_share_one_balance_and_one_daily_limit`, `joint_holders_cannot_double_the_daily_limit` | Defended |
| 9 | Type a negative, huge, or fractional amount ("-500", "1e9", "10.505", half a yen) | T | Dishonest customer | `Cents` can't be negative or above `Cents::MAX` (10^15 cents); strict parser; checked math; yen and won must be whole; the database refuses a balance outside 0 to `Cents::MAX`. Tests: `rejects_hostile_amounts`, `won_are_whole_and_round_in_the_banks_favour`, `huge_values_are_refused_and_sums_cannot_wrap`, `absurd_amounts_cannot_be_stored_or_overflow_a_balance` | Defended |
| 10 | Make money from rounding by repeating tiny conversions, or deposit a tiny amount to dodge the fee | T | Dishonest customer | Cash and each fee are converted separately; charges and fees round up, credits round down; the exchange fee applies both ways and is at least the minimum ($3.00 by default). A deposit too small to cover the fee is refused. A round trip always loses. Tests: `charges_round_up_credits_round_down_and_round_trips_lose`, `each_fee_is_the_higher_of_the_percent_and_the_minimum` | Defended |
| 11 | Transfer between currencies to profit from the rate | T | Dishonest customer | Bank of CCNY accounts are all USD, and transfers only go between accounts in the same currency | Defended |
| 12 | Use another bank's card to deposit, transfer, change the PIN or read history | E | Guest | The library checks the card's role in every one of those functions, not just the menu. Test: `guest_cards_only_withdraw_and_pay_the_atm_fee` | Defended |
| 13 | Withdraw while a currency is crashing, before the rate catches up | T | Dishonest customer | Today's feed sets the new rate in full, and a move over 5% in a day pauses that currency until a teller checks it; a teller can also pause one currency or all at any time. Tests: `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source`, `a_teller_cannot_jump_a_rate_but_can_pause_it` | Limited: between daily checks, depends on a teller noticing |
| 14 | Youth account gets around a guardian's caps or freeze, for example by asking a teller to approve more | E | Youth customer | Caps, freeze and family-only transfers enforced in the library. A teller can't raise a youth account's limits or lift the guardian's freeze, and the over-limit message doesn't send it to one. Tests: `youth_defaults_cap_spending_and_restrict_transfers`, `youth_and_other_bank_accounts_cannot_have_limits_raised`, `youth_controls_cannot_be_reached_by_the_child_or_a_stranger` | Defended |
| 15 | Choose an easy PIN (1234, birthday) that a thief can guess | S | Stranger | Refused when set or changed. Test: `weak_new_pins_are_refused` | Defended |
| 16 | Lock many people out by guessing their cards | D | Vandal | Card numbers are random, so there is no list to work through. Someone who already knows one card number can lock it with 3 wrong PINs, and again after the unlock (a teller unlocks a card once a day, #85) | Defended for many cards. One known card: Limited (accepted, §9, F19) |
| 17 | A card that is already locked says "locked", so it confirms the card exists | I | Stranger | Since 0.7.0 an unknown number also says "locked" after 3 tries (#3), so "locked" alone proves nothing, and a locked card waits the same Argon2 time as any other try (`auth.rs` → `login_customer`), so timing doesn't tell them apart (from the first try after a start since 0.8.0: audit F26, S21). But a card that is already locked says "locked" on the first try, while an unknown number says "Login failed." first. The unknown-number count is kept in memory only, so a restart resets it | Limited (accepted): only cards that are already locked are revealed, and the customer needs to know to see a teller |
| 18 | Crash the program with odd input | D | Anyone | Length and count caps, no `unwrap` on runtime paths, no `unsafe` | Defended |
| 51 | Empty a stolen card's account fast: many withdrawals or transfers, a big transfer to a new account, or one move of almost everything | S, T | Stranger with a card and PIN, cashout gang | Six fixed activity rules run inside each withdrawal, transfer and guardian move (see `THREAT_MODEL.md` §4, S). A match refuses the attempt and holds the account until a teller checks ID. Rule 4 counts a payee as "paid before" only if paid on an earlier bank day, so a one-cent transfer can't switch it off. Tests: `a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold`, `many_transfers_or_many_payees_are_held`, `unusual_amounts_are_held` (with the one-cent case), `guardian_moves_go_through_the_same_activity_rules_as_transfers` | Limited: a thief who stays under every rule still gets up to the daily limits. Until 0.8.0 guardian moves skipped the rules (audit F16, S26) and a one-cent transfer primed rule 4 (F17, S27) |
| 52 | Pass stolen money through: receive $500+ by transfer and take it straight out | T | Money mule | Rule 5: $500+ out within an hour of $500+ coming in by transfer is held. Test: `unusual_amounts_are_held` | Limited: waiting an hour, or splitting into pieces under $500, gets past this rule (rules 1-3 still count how often) |
| 53 | Learn the rule thresholds by trial, then stay under them | I | Dishonest customer, cashout gang | The customer only sees "paused after unusual activity, see a teller"; the rule is shown to staff only. Every probe that trips a rule holds the account and costs a teller visit. Test: `a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold` (message names no rule) | Limited: the rules are simple and fixed, so patient probing (or the source code) reveals them |
| 54 | Get someone else's account held: send $500+ to an account whose number you know, so the owner's next large withdrawal trips rule 5 | D | Vandal, ex-partner | Only money leaving stops; deposits, balance and history work; a teller releases it, and the amount rules are then off for that account until tomorrow. The sender's transfer is logged with their card. Test: `once_a_teller_has_seen_the_customer_today_amount_rules_are_off` | Limited (accepted): a nuisance, not theft |
| 55 | Guardian uses Move money to pay someone else out of a child's account | E | Dishonest guardian | Money taken from the child can only go to the guardian's own account (there is no destination field). Link, currency, frozen, hold, balance and daily transfer limit are checked, and since 0.8.0 the activity rules too (#51); logged as a transfer "by guardian". A stranger or the child gets the same "not found" as a missing account. Test: `guardian_moves_money_in_and_out_of_the_childs_account_only` | Defended |
| 56 | Use "Send again" to collect other customers' account numbers | I | Dishonest customer, next person in line | Only the masked number and initials are shown; only accounts this account's own card holders paid; closed accounts left out. Tests: `recent_payees_are_newest_first_without_repeats_and_capped_at_five`, `a_guardian_taking_money_back_is_not_a_payee_of_the_child` | Defended |
| 81 | Pick up a card someone left behind after taking their cash, while their session is still open (post-completion error, textbook §3.2.1) | S | Next person in line | A withdrawal ends the session and returns the card **before** the cash; the cash screen has no session behind it. `gui/src/customer.rs` → `return_card`, `take_card`, `take_cash` | Defended (GUI checked by screenshot; `docs/TEST_PLAN.md` 1.11). The CLI has no card to return |
| 82 | Empty the $5 (or $10) bills with one huge payout in small bills, so the machine can't make change for others, or jam a real dispenser | D | Vandal, dishonest customer | A withdrawal pays out at most 40 bills, checked in the library before any money or bills move; the GUI greys out bills that would take more. Tests: `withdrawals_pay_at_most_40_bills`, `short_bill_lists_only_bills_within_the_cap`, `more_than_40_bills_is_refused_without_a_debit` | Limited: 40 bills per withdrawal; repeats count toward hold rule 1 and the daily limit |
| 83 | Put more than 200 bills of one kind into one deposit by splitting them into several entries (4 × 200 × $5) | T | Dishonest customer | `customer.rs` → `deposit` adds up the count per denomination before the 200-bill cap (review hole C2). Test: `c2_one_deposit_cannot_take_more_than_200_bills_of_a_kind` | Defended |

## 2. Staff insiders (Lecture 1, slide 45)

| # | Exploit | STRIDE | Who | Defense | Status |
|---|---|---|---|---|---|
| 19 | Set a "friendly" exchange rate, then withdraw at it (or have an accomplice do it) | T | Dishonest Teller Admin | Believable range; a typed rate must be within 5% of every rate in the last 24 hours, so repeated small changes can't add up; no override; every rate kept in the signed rate history with who set it. A feed approval (#75) can move further, but only `rate_feed::fetch` can make a feed (#80), so the teller can't pick its numbers, and a big move is paused. Tests: `a_teller_cannot_jump_a_rate_but_can_pause_it`, `rates_parse_strictly_and_must_be_believable` | Limited: up to 5% a day, visible in the history. Until 0.8.0 a front end could make up a feed and set any believable rate past the cap (audit F01, S25) |
| 20 | Hide a bad rate afterwards | R, T | Dishonest Teller Admin | `rate_history` is append-only with an HMAC per row | Defended |
| 21 | Raise the exchange fee or the other bank's ATM fee to overcharge | T | Dishonest Teller Admin | Each fee is the higher of a percent and a minimum, bounded at 0-5% and $0-$10; both parts HMAC'd; each change logged old -> new. The customer sees the withdrawal, each fee and the total before confirming, with the fee rule in small print. The fee goes to the bank, not the teller. Test: `each_fee_is_the_higher_of_the_percent_and_the_minimum` | Limited: within the bounds. A fee changed between the confirm screen and the tap is charged without a second prompt (accepted, §9, F21) |
| 22 | Open an account (or many) with a large starting balance and withdraw it | T | Dishonest Teller Admin | Capped twice, in US-dollar value: each starting balance at the bank's daily deposit limit ($10,000 by default, at most $50,000 if a teller first raises that limit, logged; #88), and all of one teller's starting balances in a bank day at $20,000 together, summed from the signed log (`admin.rs` → `insert_account`, `STARTING_BALANCES_PER_DAY`). Youth accounts and guest cards count too. Logged with the teller's name and the dollar value; cash out is held to the $1,000 daily withdrawal limit (up to $5,000 if a teller also approves more, #57). Tests: `b2_a_teller_cannot_mint_unbacked_money`, `one_teller_cannot_mint_money_or_switch_limits_off`, `one_teller_cannot_create_unlimited_money_with_starting_balances` | Limited: up to $20,000 a day per teller with no cash behind it, and no second approval (open item 2). Until 0.8.0 there was no cap across accounts, so the total had no limit (audit F04, S24) |
| 23 | Register a fake "other bank" card with a balance | T | Dishonest Teller Admin | Same as 22: capped per card and within the teller's $20,000 a day, logged, daily limit. A real card network would check with the other bank | Limited (simulation) |
| 24 | Set or reset a customer's PIN and use their account | S | Dishonest Teller Admin | No function sets or resets a PIN; tellers can only unlock, once per card per day (#85). Adding a joint holder or guardian needs the holder's own card and PIN (#84, #86). The customer types their PIN into masked fields on the teller's screen; since 0.8.0 those fields can't be copied out (no select-all, copy, cut or mouse selection; G22). But the teller who opens an account handles that form and sees the new card number, and nothing forces a PIN change at first use | Limited: the opening teller could learn a new customer's first PIN; the customer should change it at first use (§9, F03). Was marked Defended until 0.8.0; in 0.7.0 the PIN could also be copied out of the field (audit F02, G22) |
| 25 | Move money directly between accounts | T | Dishonest Teller Admin | No such function exists for staff | Defended |
| 26 | Browse customers' names, birth dates and full card numbers | I | Curious or dishonest Teller Admin | Names and birth dates are shown only to staff (to check ID before unlocking or releasing a hold). Card numbers are never shown in full to staff: the locked-card list and the account list (GUI and CLI menu option 10) show only the last 4 digits (`admin.rs` → `HolderSummary.card_last4`, `LockedCard`). Test: `card_and_account_numbers_are_stored_encrypted` | **Gap**: viewing names and birth dates isn't logged, so browsing leaves no trace |
| 27 | Pause every currency to annoy customers | D | Dishonest Teller Admin | Logged with the teller's name; dollar accounts keep working; resume is one click | Limited |
| 28 | Create a second admin login as a back door | E | Dishonest Teller Admin | There is no "create staff" function. Setup works only on a bank with no staff and no log entries; emptying the staff table or deleting `atm.db` doesn't bring it back (#92, #95). Tests: `setup_cannot_be_run_twice`, `setup_cannot_be_rerun_and_limits_cannot_be_removed` | Defended |
| 29 | Take cash out of the machine | T | Dishonest Cash Handler | Can only remove cash above the $100,000 maximum; every count is logged, and since 0.8.0 the integrity check counts the cash against the log (#39). The handler can't sign in while the ATM is out of service, and a live handler session stops at a halt. Tests: `handler_can_only_remove_the_overflow`, `while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in` | Defended. Until 0.8.0 the handler kept working while the ATM was out of service (audit F15, S19). Restoring an older `atm.db` and `atm.anchor` together lets the handler remove the same surplus again (#41; §9, F12) |
| 30 | Guess a staff password | S | Anyone | Pauses from 60 s doubling to 15 min, never a permanent lock (so the only admin can't be locked out). The count and the pause sit in sealed rows, so they can't be reset in the file (#96). Test: `staff_pauses_grow_and_are_capped` | Defended |
| 31 | Deny doing any of the above | R | Any staff | Every staff action is in the HMAC-chained log with their username, including unlocks, halts and resumes of service, and the holder's card that confirmed a joint holder or guardian | Defended |
| 57 | Approve a larger amount for an accomplice, then cash out | T, E | Dishonest Teller Admin | One account, one limit, today only; at most +$4,000 withdrawal (so $5,000 cash that day), +$40,000 deposit or +$20,000 transfer per account per day; refused for youth accounts and other banks' cards; logged with the teller's name and the amount. The approval counts as a teller contact, so the amount rules (4-6) are off for that account until tomorrow; the frequency rules (1-3) still run. Tests: `a_teller_can_approve_more_than_the_daily_limit_for_today_only`, `youth_and_other_bank_accounts_cannot_have_limits_raised` | Limited: up to the cap, visible in the log; no second approver (open item 2) |
| 58 | Release a hold on a thief's or an accomplice's account without checking ID | T, E | Dishonest or careless Teller Admin | Logged with the teller's name next to the hold row that names the rule; releasing changes no limit, and counting starts again. Test: `a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold` | Limited: relies on the ID check; no second approver (open item 2) |
| 59 | Switch the activity rules off or loosen a threshold | E | Dishonest Teller Admin | No setting or function exists. The thresholds are constants in `review.rs`; changing them needs a new build, which no staff role in the program can do | Defended |
| 75 | Approve a feed without reading it, or approve on a day it favours an accomplice | T | Careless or dishonest Teller Admin | The review lists every currency with a note ("+1.20%", "big move: +10.00%; will be paused", "outside the believable range: not used", "stays paused"). The teller can only approve or cancel the whole list, not change a number. Whatever is approved still passes the believable range; a move over 5% in a day is set but paused until a teller resumes it; each rate is logged with the teller's name, the feed and its publish time, and each resume with the teller's name. Only `rate_feed::fetch` can make the feed being approved (#80). Test: `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` | Limited: approval and resume are one person's clicks (open item 2); a dishonest teller still can't choose the rate. This was not true until 0.8.0: a front end could make up the feed (audit F01, S25) |
| 76 | Approve a stale review: another teller set a rate, or the 24-hour window moved, so the rates set would differ from what was shown | T | Teller Admin (mistake or race) | `approve` recomputes the plan inside one IMMEDIATE transaction and sets nothing if it differs ("rates changed since you checked them; please check again"). Test: `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` (approving the old list again is refused) | Defended |
| 77 | Use the feed to resume a paused currency, or to clear a rate that was edited in the database | T, E | Dishonest Teller Admin | A paused currency takes the new rate but stays paused. An edited row shows as ALTERED and is re-entered paused, so a teller looks before resuming. Tests: `a_paused_currency_takes_the_new_rate_but_stays_paused`; `missing_stale_or_edited_rates_stop_conversions` (same `fx::store_rate` path) | Defended |
| 84 | Add an accomplice as joint holder on a victim's account, with a PIN the teller picks, then drain it (review hole B1) | S, E | Dishonest Teller Admin | The current holder must be at the counter and type their own card number and PIN, checked in the library (`auth.rs` → `confirm_at_counter`). The card must belong to an owner or joint holder of that account, and a card the bank froze can't confirm anything. A wrong PIN counts toward that card's 3-strike lock and is logged ("wrong PIN at the counter"); the new holder's log line names the card that confirmed. Tests: `b1_a_teller_cannot_take_over_an_account_by_adding_a_joint_holder`, `joint_and_youth_changes_need_the_holders_card_and_pin` | Defended |
| 85 | Guess a customer's PIN 3 at a time, unlocking the card in between, after reading the full card number off the locked-card list (review hole B6) | S, I | Dishonest Teller Admin | One unlock per card per New York bank day, counted from the signed log (`admin.rs` → `unlock_card`). The teller types the number from the card the customer hands over; the locked list shows the last 4 only. So 3 wrong PINs, one unlock and 3 more lock the card until the next day; every try is logged. Tests: `b6_a_teller_cannot_guess_a_pin_by_unlocking_between_tries`, `locked_cards_are_listed_for_id_check_and_unlock_needs_a_locked_card` | Defended |
| 86 | Appoint an accomplice as guardian of a youth account, who then lifts the parent's freeze and sees the child's name, balance and history (review hole B3) | E | Dishonest Teller Admin | Adding a guardian needs a current guardian's own card and PIN at the counter. The bank's freeze (`frozen`) and a guardian's freeze (`guardian_frozen`) are separate; each side lifts only its own. The bank's freeze refuses the account's cards entirely, so a guardian card the bank froze has no Family powers at all; a guardian's freeze stops money leaving the youth account while the child's card still works. Tests: `b3_a_teller_cannot_lift_a_guardian_freeze_by_appointing_a_guardian`, `the_bank_and_the_guardian_each_lift_only_their_own_freeze`, `a_guardian_cannot_lift_a_freeze_placed_by_the_bank` | Defended |
| 87 | Close a youth account's guardians one by one, so it has none left (its money is stuck if it was guardian-frozen) (review hole B4) | D, E | Dishonest Teller Admin | `admin.rs` → `close_account` counts only guardians whose own account is still open, so the last one can't be closed. Test: `b4_closing_guardians_one_by_one_cannot_orphan_a_youth_account` | Defended |
| 88 | Set a daily limit to a huge number, so limits are in effect off, then move unbacked money through it (review hole B2) | T, E | Dishonest Teller Admin | Each limit can be set at most to its default plus one day's largest teller raise: $5,000 withdrawal, $50,000 deposit, $25,000 transfer (`db.rs` → `Limit::ceiling`). Starting balances are capped too (#22). Tests: `b2_a_teller_cannot_mint_unbacked_money`, `one_teller_cannot_mint_money_or_switch_limits_off` | Defended |
| 89 | Resume service without fixing what the integrity check found, or halt the ATM to turn customers away | T, D | Dishonest or careless Teller Admin | Resume runs the check again and logs its result with the teller's name ("resumed after review; integrity check still fails: ..."); if it still fails, the next Teller Admin sign-in halts the ATM again. The check lists every failure, so a known one doesn't hide a new one. A halt by hand is logged too; only a Teller Admin can sign in while halted, and resume is one click. The state is the newest halt or resume entry in the signed log, so there is no flag to edit. Tests: `a_failed_check_at_sign_in_takes_the_atm_out_of_service`, `a_teller_can_halt_and_resume_by_hand`, `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged` | Limited: one teller can resume, no second approver (open item 2). Until 0.8.0 the check reported only its first failure, so after one resume a later problem looked the same (audit F10, S28) |

## 3. Someone with the database file (stolen copy, malware, a backup)

Since 0.7.0 the database is sealed (`seal.rs`): every commit writes
HMAC(counter + SHA-256 of every row of every table and the schema) in the
same transaction, and every operation checks it first (`Atm::begin`,
`Atm::read`). Index pages aren't rows, so since 0.8.0 the check runs
SQLite's `PRAGMA integrity_check` first, which confirms every index still
matches its table. An edit made outside the program gives "TAMPERING DETECTED:
the database was changed outside the ATM. Nothing was done. Stop and
escalate." before anything is read from it. The anchor file `atm.anchor`
(`anchor.rs`) keeps the newest seal, so an older copy of `atm.db` is
refused too. A bank is now three files: `atm.db`, `atm.key`, `atm.anchor`.

| # | Exploit | STRIDE | Who | Defense | Status |
|---|---|---|---|---|---|
| 32 | Read or crack PINs and passwords from a stolen `atm.db` | I | Thief, insider | Argon2id with a salt and a secret key from `atm.key`, made for that one card or login; without the key file not even one guess can be tested. Test: `pins_are_not_stored_in_the_clear` | Defended |
| 33 | Read customer names and birth dates | I | Thief, insider | AES-256-GCM with a random nonce per value. Test: `names_and_birth_dates_are_encrypted_at_rest` | Defended |
| 34 | Read card and account numbers, including from the log | I | Thief, insider | Each number is stored as an HMAC-SHA-256 lookup value (keyed from `atm.key`), an AES-256-GCM copy and the last 4 digits. The log names a card as `customer:card 7 ending 1234`, never the full number. An integrity failure names an account by its last 4 digits only, also when it is logged as the reason for a halt. Databases with another schema version are refused. Tests: `card_and_account_numbers_are_stored_encrypted`, `logs_name_cards_by_id_and_last_four_only`, `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged` | Defended (since 0.6.0). Until 0.8.0 a halt for a balance mismatch wrote the full account number into the log (audit F23, S28) |
| 35 | Edit a balance (review hole A3) | T | Insider with disk access | The seal refuses the edited database at the next operation, so the typed-in money can't be spent. Second layer: the integrity check, now run at every Teller Admin sign-in, recomputes every balance from the signed log. Tests: `a3_a_typed_in_balance_is_not_spendable`, `an_edited_balance_cannot_be_spent`, `integrity_check_catches_a_balance_edited_in_the_database` | Defended |
| 36 | Edit, delete or reorder log entries | T, R | Insider covering their tracks | The seal refuses the change at once. Behind it: append-only triggers and an HMAC chain keyed by `atm.key`. Tests: `chain_verifies_and_detects_edits`, `chain_detects_deletion_in_the_middle_and_at_the_end`, `forger_without_the_key_cannot_rebuild_the_chain`, `the_end_of_the_log_cannot_be_cut_off` | Defended |
| 37 | Edit a limit, fee or exchange rate | T | Insider | The seal refuses the change at once. Behind it, an HMAC per row: an edited limit or fee stops being used; an edited rate stops conversions and comes back paused. Every stored MAC is compared in full, with no early exit, so timing can't guide a forger (`keys.rs` → `same_mac`; since 0.8.0, audit F28, S21). Tests: `stored_macs_are_compared_in_full`, `an_edited_setting_is_detected`, `missing_stale_or_edited_rates_stop_conversions`, `an_edited_limit_or_rate_is_refused_at_the_point_of_use`, `settings_and_rates_edited_in_the_file_are_detected` | Defended |
| 38 | Copy one customer's encrypted name onto another row | T, S | Insider | Each value is bound to its column and card. Test: `copying_one_customers_encrypted_name_onto_another_is_detected` | Defended |
| 39 | Edit the cash counts, or move bills in a code path with no log entry | T | Insider with disk access, Phase II red team | Sealed like every other row (#90): an edited count is refused at once. CHECK constraints keep counts from going negative. Since 0.8.0 the integrity check also counts the bills against the log: restocks plus deposits minus withdrawals minus removals (`audit.rs` → `reconcile_cash`), so an extra bill paid out or phantom bills added through the program halt the ATM at the next Teller Admin sign-in. Tests: `any_edit_breaks_the_seal_and_a_reseal_fixes_it` (edits a cash count), `bills_moved_with_no_log_entry_take_the_atm_out_of_service` | Defended. Was marked Defended before 0.8.0, but nothing checked the counts against the log (audit F08, S23) |
| 40 | Roll the clock back to reset daily limits or the activity-check windows | T | Insider | Program refuses to start if the clock is behind the newest log entry. Test: `clock_rollback_is_refused` | Defended for a clock moved back. Moving it forward starts the next bank day early: accepted (§9, F31) |
| 41 | Restore an older copy of `atm.db` together with its `atm.anchor` to undo withdrawals, or to let a Cash Handler remove the same surplus again | T, R | Insider with disk access | An older `atm.db` alone is refused (#91). With the matching older anchor it opens (the key never changes, so it still fits); only the written-down check code from the last integrity check, or a physical cash count, shows the rollback | Limited: the anchor must be kept where the attacker can't write (another machine, write-once storage), open item 3 (§9, F12) |
| 42 | With both `atm.db` and `atm.key`, rebuild the whole log, re-seal the database and rewrite the anchor so everything verifies | T, R | Insider with both files | Same: the off-machine check code no longer matches | Limited (out of scope): a hardware security module would keep the key out of reach |
| 43 | Edit the rate history (or any other row) so the ATM stops | D | Insider | Fails closed: the seal refuses every operation ("TAMPERING DETECTED ... Nothing was done."), so nothing is decided from altered data. Customers and staff alike are stopped until the bank restores a matching `atm.db` and `atm.anchor` from a backup (an older `atm.db` alone is refused, #91). If `atm.anchor` can't be written after a commit (a blocked or read-only file), the change stands and is reported as done; the next operation writes the anchor first, and the ATM does nothing else until it can (`lib.rs` → `Tx::commit`, `catch_up_anchor`). Test: `a_finished_deposit_is_never_reported_as_failed_and_a_blocked_anchor_stops_the_atm` | Limited (accepted): whoever can write the file can stop the ATM, but gains nothing from it. Until 0.8.0 a blocked anchor made a finished deposit or withdrawal report "not completed", so the customer could get the cash or bills back as well (audit F11, S22) |
| 44 | Point the program at a different database or key | S, T | Insider | Fixed file names; the key fingerprint stored in the database must match (compared in full, `keys.rs` → `same_mac`); a key or anchor without its database is refused (#95). Test: `a_wrong_key_or_version_is_refused_with_a_clear_error` | Defended. The fingerprint uses the audit-log MAC key, not a key of its own: not exploitable, kept so existing banks still open (§9, F29) |
| 60 | Brute-force card or account numbers from their stored lookup values | I | Thief with `atm.db` only | The lookup is HMAC-SHA-256 keyed from `atm.key`, not a plain hash. A plain SHA-256 of a 10-digit number falls to trying all 10^10 in minutes; without the key not one guess can be tested. Card and account lookups use different labels. Test: `card_and_account_numbers_are_stored_encrypted` (checks it isn't plain SHA-256) | Defended (with both files, see #42) |
| 61 | Copy one row's encrypted card or account number onto another row | T | Insider | AES-GCM associated data is the column name plus that row's lookup value, so the copy fails to decrypt. Test: `copying_one_rows_encrypted_number_onto_another_is_detected` | Defended |
| 62 | Delete a hold row, or add a fake approval row, in `atm.db` | T, E | Insider with disk access | The seal refuses the change at once. Behind it, holds and approvals exist only as log rows: append-only (triggers) and HMAC-chained, so a deleted, edited or forged row breaks the chain. Tests: `application_cannot_edit_or_delete_history`, `chain_detects_deletion_in_the_middle_and_at_the_end`, `forger_without_the_key_cannot_rebuild_the_chain`, `the_end_of_the_log_cannot_be_cut_off` | Defended |
| 90 | Edit any other row of `atm.db` outside the program: a guardian link, a youth account's caps, a setting, the schema or a trigger, an index, or type text into a number column | T, E | Insider with disk access | The database seal covers every row of every table and the schema (`seal.rs` → `DUMP`), checked before every operation; the change is refused and nothing is done. Index pages aren't rows, so `seal.rs` → `check` runs SQLite's `PRAGMA integrity_check` first: an index that no longer matches its table is refused the same way. Tables are STRICT, so a value of the wrong type is refused even before that. Tests: `any_edit_breaks_the_seal_and_a_reseal_fixes_it`, `inserting_a_guardian_link_does_not_give_control_of_a_youth_account`, `blanking_a_youth_accounts_caps_does_not_free_it`, `strict_tables_refuse_values_of_the_wrong_type`, `an_index_edited_in_the_file_is_caught_before_it_can_mislead` | Defended (with `atm.key`, see #42). Until 0.8.0 swapping two log indexes in the file, with no key, let a customer pass the daily withdrawal limit (audit F14, S30) |
| 91 | Put back an older copy of `atm.db` alone (to undo a withdrawal or a lock-out), or edit or delete `atm.anchor` | T, R | Insider with disk access | `atm.anchor` holds the newest seal counter, HMAC-tagged. At start, a lower counter is refused ("DATABASE ROLLED BACK: this is an older copy of the bank's records. Nothing was done."), and so is an edited anchor or a missing one. A running program also refuses a counter lower than one it has seen. Tests: `restoring_an_old_copy_of_the_database_is_detected`, `the_anchor_file_cannot_be_edited_or_removed` | Defended (an older copy of both files: #41) |
| 92 | Empty the `staff` table so first-run setup comes back, then create your own Teller Admin (review hole A1) | S, E | Insider with disk access | The seal refuses the edited database. Setup also works only on a bank with no staff and no log entries. Test: `a1_emptying_the_staff_table_does_not_reopen_first_run_setup` | Defended |
| 93 | Reset a card's failure count and lock flag between guesses, for unlimited PIN tries (review hole A2) | S, T | Insider with disk access and a stolen card | The seal refuses the edit at the next login, before any PIN is checked. Tests: `a2_resetting_card_columns_does_not_give_unlimited_pin_guesses`, `resetting_the_failure_counter_does_not_give_unlimited_pin_guesses`, `clearing_the_locked_flag_does_not_unlock_a_card` | Defended |
| 94 | Clear the `frozen` or `closed` flag to get money out of a frozen or closed account (review hole A4) | T, E | Insider with disk access | The seal refuses the edit. Since 0.8.0 the integrity check also compares each bank freeze, guardian freeze and closure with its newest log entry, so a flag changed through the program with no log entry halts the ATM (#101). Tests: `a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service`, `a4_clearing_the_frozen_flag_does_not_lift_a_bank_freeze`, `clearing_freeze_and_closed_flags_changes_nothing` | Defended |
| 95 | Delete `atm.db` but keep `atm.key` (or `atm.anchor`), so the program offers first-run setup with the old key (review hole A5) | S, E | Insider with disk access | Strict open: a key or anchor without its database is refused ("the bank's database file is missing; restore it, or delete the key and anchor files to start a new bank on purpose"). A new bank starts only when none of the three files exists (`lib.rs` → `Atm::start`). Tests: `a5_deleting_the_database_but_keeping_the_key_does_not_reopen_first_run_setup`, `deleting_the_database_does_not_offer_setup_again` | Defended (deleting all three files destroys the bank; the old accounts are gone, not taken over) |
| 96 | Reset a staff login's failure count and pause between password guesses (review hole A6) | S, T | Insider with disk access | The seal refuses the edit, so the pause stays. Test: `a6_resetting_staff_columns_does_not_remove_the_password_pause` | Defended |
| 97 | Copy a PIN or password hash onto another row, point a card at another account, or switch a staff row from handler to admin | S, E | Insider with disk access and a login of their own | Each hash is keyed for its identity: HMAC(pepper, "credential/v1", identity), where the identity is the card's lookup value, account and role, or the username and role (`keys.rs` → `credential_key`; `auth.rs` → `card_identity`, `staff_identity`). A moved hash doesn't verify, and the seal refuses the edit anyway. Tests: `a_hash_only_works_for_its_own_card_and_role`, `copying_a_pin_hash_onto_another_card_does_not_work`, `copying_a_password_hash_onto_the_admin_row_does_not_work`, `pointing_a_card_at_another_account_does_not_work`, `editing_a_staff_role_does_not_make_a_cash_handler_an_admin` | Defended |

## 4. The program itself and its build

| # | Exploit | STRIDE | Who | Defense | Status |
|---|---|---|---|---|---|
| 45 | SQL injection through any text field | T, E | Anyone | Every query uses bound parameters; no SQL text is built from input | Defended |
| 46 | A front end skips a check or runs its own SQL | E | Front-end bug or change | Front ends never get the library's database handle; each action needs the right session type (5 compile-fail tests in `src/lib.rs`; the 5th shows a front end can't make up a rate feed, #80). A front end that opened `atm.db` on its own (the CLI shares the library's crates, so it could) would break the seal, and the next operation refuses (#90) | Defended |
| 47 | Memory corruption (buffer overflow, use after free) | E | Anyone | Rust, with `unsafe` forbidden in the library and denied in the GUI (Lecture 2) | Defended |
| 48 | A malicious or buggy library update | T | Supply chain | Few, widely used crates; exact versions pinned in `Cargo.lock` (Lab 1, question 3). The network crates are #78 | Limited |
| 49 | The demo build, with its known passwords, gets shipped | S | Mistake | Demo data only exists with `--features demo`; the normal build refuses `--demo`, and refuses demo data copied over the real files (#98). Checklist item before submitting | Defended |
| 50 | Error messages reveal internals | I | Anyone | Users only see fixed texts | Defended |
| 78 | A malicious or buggy release of the network crates: `ureq` 3.4, `rustls` 0.23, `ring` 0.17, `webpki-roots` 1.0 and 7 helpers (`ureq-proto`, `http`, `httparse`, `rustls-pki-types`, `rustls-webpki`, `untrusted`, `utf8-zero`) | T, I | Malicious library release | Only compiled with `online-rates` (the GUI); the CLI's default build has none of them. Versions and checksums pinned in `Cargo.lock`; default features off (no compression, cookies or JSON helper). Widely used crates. Limits: `ring` contains C and assembly, which `forbid(unsafe_code)` doesn't reach; `serde_json` (always in) is one more parser | Limited (like #48) |
| 79 | A planted change uses the HTTPS client to send data out (balances, names, the key) | I | Phase II red team | Before 0.5.0 the program had no network code at all. Now there is one call site, `rate_feed::fetch`: a constant URL, a GET with no body. Code check: `grep -rn "ureq" src gui` finds only that function; the CLI's default build has no network code | Limited: a reviewer must read that function; a careful backdoor could hide data in the request |
| 80 | A front end makes up a "feed" with rates it chose and approves it, so rates move past the 5% typed-rate cap and the log says "daily feed" for rates nobody fetched; or it writes its own text into the log through the feed's publish time | T, R | Front-end change, Phase II red team | Since 0.8.0 only `rate_feed::fetch` can make a `Feed`: its fields and `parse` are private (a compile-fail test in `src/lib.rs`). The publish time in the log is text the program writes from the feed's own timestamp ("2026-10-12 00:02 UTC"); a front end can only read it (`Feed::published`). Approving still needs an `AdminSession` and names the teller in the log. A change to `rate_feed.rs` itself is a code check (§7) | Defended. Was marked Limited before 0.8.0 with a wrong reason: the 5% cap never applied on this path, so one teller with a changed front end could set any believable rate in minutes and write any text into the log (audit F01, F24, S25) |
| 98 | Copy demo data (published passwords) over the real bank's files, or open a real bank in demo mode | S | Mistake, insider | A sealed `meta` row marks demo data (`db.rs` → `mark_demo`, `is_demo`). `Atm::open` refuses a demo database; `Atm::open_demo` (demo builds only) refuses a real one. Test: `demo_data_and_real_data_stay_apart` | Defended |
| 99 | The integrity-test code (adds $500 to a balance with no log entry) ends up in a real build, or runs on real data | T | Mistake, Phase II red team | `demo::break_integrity` and the `--demo --break-integrity` option are compiled only with `--features integrity-test` (which implies `demo`); normal and demo builds don't contain them (checked with `nm`). It refuses anything but demo data and uses its own files `atm-test.*`. Test: `a_broken_balance_is_caught_at_the_next_teller_sign_in` (integrity-test builds; also checks real data is refused) | Defended |
| 100 | Hand the real bank a session made elsewhere (a throwaway bank set up with the attacker's own passwords), or keep using a session after the card is locked, the account closed or frozen by the bank, the staff login removed or the ATM taken out of service | S, E | Front-end change, Phase II red team, a thief whose card the bank stops | Each opened bank gets a random id, and its sessions carry it. `Atm::admit` checks the id on every action and re-checks the card, account (not locked, closed or frozen by the bank) or staff row; a mismatch ends the session. Customer and Cash Handler sessions also stop while the ATM is out of service. A change checks all of this again inside the write lock (`auth.rs` → `Atm::begin_for`), so a lock, closure, freeze or halt that another process commits while the change waits still stops it. Tests: `a_session_from_another_database_is_not_accepted`, `a_customer_session_from_another_database_is_not_accepted`, `a_live_session_stops_when_the_card_is_locked_or_the_account_closed`, `a_bank_freeze_stops_the_card_entirely_until_a_teller_lifts_it`, `a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first` | Defended. Until 0.8.0 a bank-frozen card kept working (audit F05, S20) and a change already waiting for the lock ran after a halt (F22, S29) |
| 101 | A code path (a bug or a planted change) moves money or bills, or changes a balance, limit, rate, freeze or closure, without its log entry. The seal can't see it, because the program sealed the change itself | T, R | Phase II red team, bug | Every Teller Admin sign-in runs the full integrity check (`audit.rs` → `verify`): the log chain, every balance against the log, the cash against the log, the signed settings and rates, and each daily limit, exchange rate, bank freeze, guardian freeze and closure against its newest log entry (a rate against its newest rate-history row, with a log entry for every history row) (`reconcile_state`). After the chain, every check runs and every failure is listed, accounts by their last 4 digits only. If anything fails, the ATM takes itself out of service, logged as "system": the start screen takes no card ("Out of service"), live customer and Cash Handler sessions stop, only a Teller Admin can sign in, and the teller sees a red banner with **Resume service** (`service.rs` → `check_at_sign_in`). Tests: `a_failed_check_at_sign_in_takes_the_atm_out_of_service`, `a_broken_balance_is_caught_at_the_next_teller_sign_in`, `bills_moved_with_no_log_entry_take_the_atm_out_of_service`, `a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service`, `while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in` | Limited: found at the next Teller Admin sign-in, not at once; fees, card locks, youth caps, joint holders and guardians aren't rebuilt from the log (open item 4). Until 0.8.0 the check covered only the chain, balances and signed rows, and a halted ATM still took cards and let the Cash Handler in (audit F07, F08, F09, F15) |

## 5. On the network: the daily rate feed (Lecture 4)

Since 0.5.0 a Teller Admin can press **Check today's rates**: the program
makes one HTTPS GET to `https://open.er-api.com/v6/latest/USD` and shows
the result for review (`src/rate_feed.rs`). Nothing listens on a port, so
an attacker on the network can only interfere with that one request. Only
builds with the `online-rates` feature (the GUI) contain the network code.

| # | Exploit | STRIDE | Who | Defense | Status |
|---|---|---|---|---|---|
| 63 | Pretend to be the rate source (rogue Wi-Fi, a fake DNS answer, a proxy that inspects HTTPS with its own certificate) and serve made-up rates | S, T | Network attacker | HTTPS only through rustls; the server's certificate must chain to a root in the Mozilla list built into the program (`webpki-roots`), not the computer's certificate store, so a certificate added to the machine doesn't help. Checked by hand: behind a proxy that inspects HTTPS the fetch is refused ("invalid peer certificate: UnknownIssuer"). A feed that got through anyway is still only a proposal (#68) | Defended (checked by hand; the automated tests never go online) |
| 64 | A hacked or coerced certificate authority issues a real-looking certificate for `open.er-api.com` (textbook §5.7.4, §21.6: DigiNotar) | S, T | Hacked or coerced certificate authority | Not blocked: every root in the built-in list is trusted, there is no pinning and no revocation check. The damage is bounded as in #68: believable range, a teller reviews it, a move over 5% in a day is paused until a teller resumes it, and every rate is logged with its source | Limited (accepted): pinning breaks whenever the source renews its certificate |
| 65 | Strip HTTPS or downgrade it: send the request over `http://`, or push the connection to an old TLS version or a weak cipher suite (L4 slides 12, 17, 21-28) | S, T, I | Network attacker | The URL is a constant (`FEED_URL`) that starts with `https://`; the client is set to `https_only`, so an `http://` address is refused ("configured for https only", checked by hand). rustls speaks only TLS 1.2 and 1.3 and offers only forward-secret ECDHE with AES-GCM or ChaCha20-Poly1305: there is nothing weak to fall back to | Defended |
| 66 | Redirect the request to another host (a 301 or 302 from a hijacked or misconfigured server) | S, T | Network attacker, hacked source | `max_redirects(0)`: a redirect is never followed. The redirect reply itself isn't a feed, so it is refused ("Today's rate feed was not in the expected form"). Code check: `rate_feed.rs` → `fetch` | Defended |
| 67 | Replay an old feed, or send one dated in the future | T | Network attacker, hacked source | TLS stops a network attacker replaying old traffic. The feed's own publish time must be less than 48 hours old and no more than 5 minutes ahead, or "Today's rate feed is out of date". Test: `a_feed_is_read_strictly` | Defended (a hacked source can still put a fresh date on wrong rates: #68) |
| 68 | The real source is hacked, or makes a mistake, and publishes wrong rates | T | Hacked or mistaken rate source | A feed is only a proposal. The teller sees Now, Today's feed, Will set and Note for every currency; nothing changes until they approve. A rate outside the believable range is "not used". A move over 5% in a day is set but the currency is paused until a teller checks it against another source and resumes. Each rate gets its HMAC and a log line naming the feed and its publish time. Test: `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` | Limited: a wrong rate within 5% a day gets in if the teller approves it, and a bigger one if a teller also resumes it; the history shows both |
| 69 | Send a malformed feed to crash the parser or slip in a bad number: a captive-portal web page, wrong base currency, an "error" result, text instead of numbers, negative, zero, 1e300 | E, T | Network attacker, hacked source | `serde_json` (safe Rust) reads it; `result` must be "success" and `base_code` "USD"; only the 15 known currency codes are read; each number goes through `fx::parse_fixed`, the parser for a typed rate. A missing or bad number shows as "missing" and that currency stays as it is, never guessed. Test: `a_feed_is_read_strictly` | Defended |
| 70 | Send a huge or endless reply to fill memory or hang the teller's screen | D | Network attacker, hacked source, slow server | At most 64 KB is read (`FEED_MAX_BYTES`, the real feed is about 3 KB) and the length is checked again before parsing; the whole request, DNS lookup included, has a 10 s limit; compression is not turned on, so nothing grows after reading. Test: `a_feed_is_read_strictly` (70 KB refused); the timeout is a code check in `fetch` | Defended |
| 71 | Make the feed unreachable or slow (cut the network, block the host, break DNS) so rates can't be updated | D | Network attacker, outage at the source | A failed fetch changes nothing and says "Couldn't reach today's rate feed. Rates are unchanged; you can still type a rate." (`AtmError::FeedUnavailable`). Customers never wait on the network. The teller's screen waits up to 10 s | Limited: costs the teller time; if nobody types a rate either, rates expire after 72 hours and conversions stop (fail closed) |
| 72 | Watch the network to learn what the ATM sends | I | Network attacker | A plain GET of a fixed public URL with standard headers only: no key, cookie, account, card or customer data. The reply is public data. An observer sees only that the machine contacted `open.er-api.com` (the DNS lookup and the TLS server name) | Limited (accepted): the host name is visible |
| 73 | Make the ATM fetch over and over, to slow it or flood the source | D | Customer, stranger | Only a Teller Admin's button press fetches (`gui/src/staff.rs` → `check_feed`, `src/ui.rs` → `check_feed`), never a customer screen and never on a timer. Code check: `grep -rn "rate_feed::fetch" src gui` finds only those two | Defended |
| 74 | Hide an attack on the feed: a refused certificate looks like an ordinary outage | R | Network attacker | A refused certificate (or a non-HTTPS answer) gets its own message: "The connection to today's rate feed failed its security check (certificate not trusted)". Every failed check is written to the signed log as "Rate feed failed" with the teller's name and the reason (no connection, certificate not trusted, not in the expected form, out of date). Nothing changes when a check fails. Tests: `a_failed_check_is_logged_with_its_reason_and_changes_nothing`, `each_kind_of_fetch_failure_gets_its_own_message` (`--features online-rates`) | Defended |

## 6. Out of scope (simulated in this project)

Card skimmers and cloned magnetic stripes, fake keypads, counterfeit bills in
the deposit slot, the card network between banks, and the bank's own
treasury desk. The ATM simulates each one (typed card numbers, typed bill
counts, a teller registering other banks' cards, a teller typing a rate or
approving the public daily feed). A real bank would take its rates from a
contracted data provider; the free feed stands in for that.

---

## 7. Phase II: where a backdoor would hide, and what would catch it

In Phase II another team gets this code and must plant a Spoofing, a
Tampering and an Elevation of privilege backdoor, plus two of Repudiation,
Information disclosure and Denial of service. The likely spots, and what
already stands in their way:

| Category | Likely backdoor | What would catch it |
|---|---|---|
| S | A "master PIN" or a card that always logs in, in `auth.rs` → `login_customer` | The login tests; a code review of the one login function |
| S | Lockout counter quietly reset | `three_consecutive_failures_lock_even_against_the_right_pin` |
| S | Make a hash verify for any card or login: drop the account or role from `auth.rs` → `card_identity` / `staff_identity`, or have `keys.rs` → `credential_key` ignore the identity | `a_hash_only_works_for_its_own_card_and_role` (the attack tests alone wouldn't notice, because the seal also refuses the copied hash) |
| S | Let an unknown card answer differently again, in `auth.rs` → `like_a_real_card` | `c1_a_real_card_and_an_unknown_card_fail_the_same_way` |
| S | Let a bank-frozen card sign in or confirm at the counter again: drop the `frozen` check from `auth.rs` → `login_customer`, `confirm_at_counter` or `CustomerSession::still_allowed` | `a_bank_freeze_stops_the_card_entirely_until_a_teller_lifts_it` |
| S | Drop the once-a-day rule in `admin.rs` → `unlock_card` | `b6_a_teller_cannot_guess_a_pin_by_unlocking_between_tries` |
| T | Skip the 5% typed-rate limit or widen a believable range in `fx.rs` | `a_teller_cannot_jump_a_rate_but_can_pause_it`; rate history shows the jump |
| T | Round conversions in the customer's favour | `charges_round_up_credits_round_down_and_round_trips_lose` |
| T | Withdraw without debiting, or credit twice | The integrity check rebuilds balances from the log at every Teller Admin sign-in and takes the ATM out of service: `a_failed_check_at_sign_in_takes_the_atm_out_of_service` |
| T | Pay out an extra bill, or add phantom bills that a later removal takes out | The integrity check counts the cash against the log (`audit.rs` → `reconcile_cash`): `bills_moved_with_no_log_entry_take_the_atm_out_of_service` |
| T | Change a limit, a rate, a freeze or a closure with no log entry | The integrity check matches each against the log (`audit.rs` → `reconcile_state`): `a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service`. Fees, card locks, youth caps, joint holders and guardians are not matched yet (§8, item 4) |
| T | Skip the activity check, or loosen a threshold, in `review.rs`, or drop the `review::screen` call from `family.rs` → `move_money` | `a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold`, `many_transfers_or_many_payees_are_held`, `unusual_amounts_are_held`, `guardian_moves_go_through_the_same_activity_rules_as_transfers`; the thresholds are named constants at the top of the file |
| T | Drop a fee line, or round a fee in the customer's favour | `each_fee_is_the_higher_of_the_percent_and_the_minimum` (checks every line and the total) |
| T | Seal: leave a table out of the `DUMP` list in `seal.rs`, drop the `PRAGMA integrity_check` from `seal::check`, or skip `seal::check` (or the `seen` counter) in `Atm::begin` / `Atm::read` | `any_edit_breaks_the_seal_and_a_reseal_fixes_it` (a cash count, a setting, a trigger), `an_index_edited_in_the_file_is_caught_before_it_can_mislead` (an index), and the attack and review tests that edit `staff`, `accounts`, `cards`, `guardians`, `settings`, `exchange_rates` and `audit_log`. `meta` and `rate_history` are a code check: `DUMP` must list the schema, `sqlite_sequence` and all 10 tables |
| T | Anchor: let `Anchor::advance` move backward, drop the counter comparison in `lib.rs` → `Atm::start`, or let the ATM run on while `atm.anchor` is behind (`catch_up_anchor`) | `restoring_an_old_copy_of_the_database_is_detected`, `the_anchor_file_cannot_be_edited_or_removed`, `a_finished_deposit_is_never_reported_as_failed_and_a_blocked_anchor_stops_the_atm` |
| T | Raise the starting-balance cap in `admin.rs` → `insert_account` or `STARTING_BALANCES_PER_DAY`, or a limit's ceiling in `db.rs` → `Limit::ceiling` | `b2_a_teller_cannot_mint_unbacked_money`, `one_teller_cannot_mint_money_or_switch_limits_off`, `one_teller_cannot_create_unlimited_money_with_starting_balances` |
| T | Integrity-test feature gate: remove `#[cfg(feature = "integrity-test")]` from `demo.rs` → `break_integrity` or from the `--break-integrity` match in `src/main.rs` / `gui/src/main.rs`, or drop its demo-data check, so a shipped build can change a balance with no log entry | `nm` on the release binaries finds no `break_integrity`; `a_broken_balance_is_caught_at_the_next_teller_sign_in` (real data refused); `Cargo.toml` lists `integrity-test` as a test-only feature; if it ran anyway, the sign-in check halts the ATM |
| E | A customer session that can call admin functions | The compile-fail tests in `src/lib.rs` |
| E | Accept a session from another bank, or let it outlive a lock, closure, freeze or halt: drop the id check or `still_allowed` from `auth.rs` → `Atm::admit`, or call `Atm::begin` where `Atm::begin_for` is used | `a_session_from_another_database_is_not_accepted`, `a_customer_session_from_another_database_is_not_accepted`, `a_live_session_stops_when_the_card_is_locked_or_the_account_closed`, `a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first` |
| E | Skip the holder's card and PIN: bypass `auth::confirm_at_counter` in `admin.rs` → `confirmed`, or the "current holder of this account" check in `add_joint_holder` / `add_guardian` | `joint_and_youth_changes_need_the_holders_card_and_pin`, `b1_a_teller_cannot_take_over_an_account_by_adding_a_joint_holder`, `b3_a_teller_cannot_lift_a_guardian_freeze_by_appointing_a_guardian` |
| E | Let `Atm::open` accept demo data (published passwords) | `demo_data_and_real_data_stay_apart` |
| E | A guest card that can deposit or transfer | `guest_cards_only_withdraw_and_pay_the_atm_fee` |
| E | Let a guardian move a child's money to any account | `guardian_moves_money_in_and_out_of_the_childs_account_only` |
| E | Lift the approval cap, or allow approvals on youth or guest accounts | `a_teller_can_approve_more_than_the_daily_limit_for_today_only`, `youth_and_other_bank_accounts_cannot_have_limits_raised` |
| R | Some actions no longer written to the log | Balances and cash are rebuilt from the log at every Teller Admin sign-in, so an unlogged withdrawal halts the ATM as a balance or cash mismatch; limits, rates, freezes and closures are matched against the log; daily limits, approvals, holds, unlocks and each teller's starting balances are computed from the log too |
| R, T | Out of service: make `service.rs` → `halted` or `out_of_service` always answer "in service", skip `check_at_sign_in` in `auth.rs` → `login_admin`, drop `refuse_if_halted` from `login_customer` or `login_staff`, or make `stops_when_halted` false, so a failed check no longer stops customers or the Cash Handler | `a_failed_check_at_sign_in_takes_the_atm_out_of_service`, `a_teller_can_halt_and_resume_by_hand`, `while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in`, `a_broken_balance_is_caught_at_the_next_teller_sign_in` |
| I | PINs or names written to the log or printed | `pins_are_not_stored_in_the_clear`; reading `audit.rs` → `append` callers |
| I | Full card or account numbers written to the log again (an integrity failure, say), or stored in clear | `logs_name_cards_by_id_and_last_four_only`, `card_and_account_numbers_are_stored_encrypted`, `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged` |
| I | Leave the last customer's data on screen: drop `input::wipe_screen` from the CLI flows, or a field from `gui/src/main.rs` → `go_welcome` | `the_cli_wipes_the_screen_when_a_session_ends`; the GUI list is a code check |
| I | Let the teller copy a PIN out of a masked field: remove the key listener or the mouse guard from `gui/ui/theme.slint` → `Field` | A screen check (Ctrl+A, Ctrl+C in a PIN field copies nothing); a code review of `Field` |
| I | Show other people's numbers in a customer's history again (`audit.rs` → `for_customer`) | `history_does_not_leak_other_peoples_card_numbers`, `history_shows_only_my_transactions_and_incoming_transfers` |
| D | A crafted input that panics, or a forced lockout | Input caps; staff pauses instead of locks |
| D | Out of service: halt at every sign-in even when the check passes, or refuse every resume, in `service.rs` | `a_teller_can_halt_and_resume_by_hand` (a passing check must resume and stay in service) |
| S | Rate feed: turn off the certificate check in `rate_feed.rs` → `fetch` (`disable_verification(true)` on the `TlsConfig`, or a `RootCerts` choice other than `RootCerts::WebPki` that adds an attacker's root), or change `FEED_URL` to another host | A code review of `fetch` (about 20 lines); on a network that inspects HTTPS the check must still be refused (`docs/TEST_PLAN.md` 8.9); the log names the source of every feed rate |
| T | Rate feed: skip the believable range or the big-move pause in `rate_feed.rs` → `plan` or `approve` | `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` (JPY +10% must be set and paused; EUR 0.01 must not be used); the rate history shows any jump |
| T | Rate feed: make `rate_feed::parse` or the `Feed` fields public again, so a front end can make up a feed and approve any believable rate | The 5th compile-fail test in `src/lib.rs` (a front end can't build a `Feed`) |
| T | Rate feed: set rates without the teller: apply the feed on fetch or on a timer, or drop the "changed since you checked" comparison in `approve` | `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` (checking changes nothing; a stale list is refused); `grep -rn "rate_feed::" src gui` shows every caller |
| T | Rate feed: read a missing or bad number as 0 or as an old rate, or widen the 48-hour window, in `rate_feed.rs` → `parse` | `a_feed_is_read_strictly` |
| E | Rate feed: let the feed resume a paused currency, or clear an ALTERED rate without the pause | `a_paused_currency_takes_the_new_rate_but_stays_paused`; `missing_stale_or_edited_rates_stop_conversions` |
| R | Rate feed: drop the feed name and publish time from the log line, so a feed rate looks typed (or the reverse) | `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` (checks the log detail) |
| I | Rate feed: send data out with the feed request: in the URL, a header, or a second request | Code check: one `agent.get(FEED_URL).call()` with a constant URL and no body; `grep -rn "ureq" src gui` finds only `fetch`; the CLI's default build has no network code |
| D | Rate feed: remove the 10 s timeout or the 64 KB cap, or fetch in a loop | `a_feed_is_read_strictly` (the size check in `parse`); the timeout, the read limit and the two callers are a code check |

Lecture 1 warns that hiding malicious code takes less skill than finding it.
What makes a backdoor harder to hide here: every rule lives in one small
library, the tests name each rule, and money, limits, approvals, holds,
unlocks, rates and the service state all flow through the signed log. Two
nets catch changed data: the seal stops anything edited outside the
program at once, and the sign-in integrity check catches a change made
through the program that skips the log (balances, cash, limits, rates,
freezes and closures; not yet fees, card locks, youth caps or guardians,
§8 item 4). A planted change that writes through `Atm::begin` is sealed
like an honest one, so for planted code the sign-in check and the tests are
what count (#101). The rate feed adds the
program's only network code, so `rate_feed.rs` → `fetch` deserves a careful
read: it is the one place where data could leave the machine (#79).

## 8. Open items, in the order we would fix them

**Fixed in 0.7.0.** An edit to `atm.db` made outside the program is refused
at once instead of found later by the integrity check (#35-#37, #39, #62,
#90, #92-#97), and an older copy of `atm.db` is refused (#91). The
integrity check runs at every Teller Admin sign-in and takes the ATM out of
service when it fails (#101). A teller can't add a joint holder or guardian
without the holder's card and PIN (#84, #86), unlock the same card twice in
a day (#85), switch a limit off (#88) or leave a youth account with no
guardian (#87); starting balances are capped (#22). Unknown cards answer
like real ones (#3, and a locked card takes as long as any other, #17),
staff lists show card numbers by their last 4 digits only (#26), and a
deposit's 200-bill cap counts each kind of bill once (#83). Card and account numbers have been stored encrypted since 0.6.0
(#34).

**Fixed in 0.8.0** (the audit of 0.7.0, §9). Out of service, the ATM takes
no card at all, the Cash Handler is refused and stopped, and only a Teller
Admin signs in (#29, #89, #101). A bank freeze refuses the account's cards
entirely until a teller lifts it (#86, #100). The integrity check counts
the cash against the log (#39), matches limits, rates, freezes
and closures against the log (#94, #101), and lists every failure by last
4 digits only (#34, #89). One teller's starting balances are capped at
$20,000 a bank day (#22). Only `fetch` can make a rate feed (#19, #75,
#80). Guardian moves go through the activity rules, and rule 4 can't be
primed with a cent (#51, #55). An index edited in the file is refused
(#90). A finished change is never reported as failed (#43). A change
waiting for the write lock obeys a halt, lock, closure or freeze that lands
first (#100). The first failed login after a start is no slower (#3, #17),
stored MACs are compared in constant time (#37), PIN fields at the teller
can't be copied out (#24), the CLI wipes the screen and the GUI wipes every
screen property at logout (#5).

1. **Teller views of personal data not logged (#26).** Log each time a
   teller opens a list that shows names or birth dates. (Card numbers
   already show only their last 4 digits to staff.)
2. **One teller acts alone (#22, #57, #58, #75, #89).** One teller can
   approve a larger amount, release a hold, approve today's rates, resume
   service, and open accounts with starting balances of up to $20,000 a day
   in total and no cash behind them. Require a second staff login for these
   (dual control, textbook §12.2.4).
3. **Rollback of both `atm.db` and `atm.anchor` together (#41; §9, F12).**
   The anchor only helps while it is kept where the attacker can't write: a
   second machine or write-once storage. Here it sits next to `atm.db`, so
   putting back both files also rolls back the cash counts and lets a Cash
   Handler remove the same surplus again. Keep writing down the check code,
   and count the cash at the branch.
4. **Some state isn't rebuilt from the log (#101; §9, F09).** Since 0.8.0
   balances and cash are rebuilt from the log, and limits, rates, freezes
   and closures are matched against it. Fees, card locks, youth caps, joint
   holders and guardians are not. Edits in the file are refused by the seal
   (and each fee row has its own MAC), but a code path that changes one of
   these without a log entry would be sealed like an honest change. Add
   them to `audit.rs` → `reconcile_state`.
5. **The teller's screen waits up to 10 s during a check (#71).** Run the
   fetch on a background thread. Rebuild regularly so the built-in root list
   stays current (#64).
6. **An insider with both `atm.db` and `atm.key` can rebuild and re-seal
   everything (#42).** Out of scope for one program, as before: the fix is a
   hardware key store that keeps the key out of reach.
7. **The 10 design limits from the audit of 0.7.0 (§9).** F03 (the opening
   teller knows the new customer's first PIN), F12 (item 3), F13 (the Cash
   Handler login can't be reset), F18, F19, F20, F21, F25, F29 and F31.
   Each has its reason under the table in §9.

## 9. Audit of 0.7.0 (2026-10-13)

A fresh security audit of 0.7.0 found 31 problems, F01 to F31. 0.8.0 fixes
21 of them, each in one step of `CHANGES.md` with a test that fails on
0.7.0 (or a screen check for the GUI). The other 10 are design limits; the
reason for each is under the table. Severity is as the audit reported it.

| ID | Finding | Severity | Status in 0.8.0 | Where |
|---|---|---|---|---|
| F01 | A made-up rate feed got past the 5% typed-rate cap | High | Fixed in 0.8.0 (S25) | `rate_feed.rs` → `parse`, `Feed`, `approve` |
| F02 | A PIN typed into a masked field on the teller screen could be copied out | High | Fixed in 0.8.0 (G22, G24) | `gui/ui/theme.slint` → `Field` |
| F03 | The opening teller knows the new customer's card number and first PIN | High | Limited: the customer should change the PIN at first use | `admin.rs` → `create_customer`, `open_youth_account`; `auth.rs` → `login_customer` |
| F04 | Starting balances had no cap across accounts | High | Fixed in 0.8.0 (S24) | `admin.rs` → `insert_account` |
| F05 | A bank-frozen card still signed in, deposited, changed its PIN and acted as guardian | Medium | Fixed in 0.8.0 (S20, G20) | `auth.rs` → `login_customer`, `CustomerSession::still_allowed`, `confirm_at_counter`; `customer.rs` → `destination` |
| F06 | The out-of-service banner pushed Sign out off the teller screen | Medium | Fixed in 0.8.0 (G19) | `gui/ui/staff.slint` → `ServiceBanner`, `SideNav`, `TellerScreen` |
| F07 | An out-of-service ATM still took card numbers and PINs | Medium | Fixed in 0.8.0 (S19, G18) | `service.rs` → `out_of_service`; `ui.rs` → `customer_flow`; `gui/src/customer.rs` → `on_start_customer` |
| F08 | Cash counts were never checked against the log | Medium | Fixed in 0.8.0 (S23, G21) | `audit.rs` → `verify`, `reconcile_cash` |
| F09 | Limits, rates and freezes were not checked against the log | Medium | Fixed in 0.8.0 (S32, G26) for limits, rates, freezes and closures; fees, card locks, youth caps and guardians: open item 4 | `audit.rs` → `verify`, `reconcile_state` |
| F10 | After one integrity failure, the check showed only that one and hid later ones | Medium | Fixed in 0.8.0 (S28, G23) | `audit.rs` → `verify`, `reconcile_balances` |
| F11 | A finished change was reported as failed when `atm.anchor` couldn't be written | Medium | Fixed in 0.8.0 (S22) | `lib.rs` → `Tx::commit`, `catch_up_anchor` |
| F12 | Restoring `atm.db` and `atm.anchor` together lets a Cash Handler remove the same surplus again | Medium | Limited: needs an anchor off the machine | `anchor.rs`; `cash.rs` → `reset_to_maximum`, `remove_excess` |
| F13 | The Cash Handler login can't be reset, disabled or replaced | Medium | Accepted: a reset function would let one insider make themselves a handler | `auth.rs` → `first_run_setup`, `change_handler_password` |
| F14 | An index edited in the file wasn't caught by the seal | Medium | Fixed in 0.8.0 (S30) | `seal.rs` → `check` |
| F15 | The Cash Handler kept working while the ATM was out of service | Low | Fixed in 0.8.0 (S19) | `auth.rs` → `login_staff`, `HandlerSession::stops_when_halted` |
| F16 | Guardian Move money skipped the activity rules | Low | Fixed in 0.8.0 (S26) | `family.rs` → `move_money` |
| F17 | A one-cent transfer switched off activity rule 4 | Low | Fixed in 0.8.0 (S27) | `review.rs` → `matched_rule` |
| F18 | The 3-miss limit on unknown account numbers resets at each sign-in | Low | Accepted: 10-digit random numbers, and every try is a logged sign-in | `auth.rs` → `CustomerSession::note_missed_lookup` |
| F19 | Anyone who knows a card number can keep it locked all day | Low | Accepted: standard ATM behaviour; more unlocks would bring back teller PIN guessing | `auth.rs` → `login_customer`; `admin.rs` → `unlock_card` |
| F20 | A mis-stocked machine can't be corrected | Low | Accepted: simulation; counts are logged and matched against the log | `cash.rs` → `restock`, `remove_excess`, `reset_to_maximum` |
| F21 | The fee or rate the customer confirmed is worked out again when the money moves | Low | Accepted: fee changes are capped, logged and rare | `customer.rs` → `withdraw`, `deposit` |
| F22 | A customer change waiting for the write lock ran after a halt | Low | Fixed in 0.8.0 (S29) | `auth.rs` → `Atm::begin_for` |
| F23 | A halt wrote a full account number into the log | Low | Fixed in 0.8.0 (S28) | `audit.rs` → `reconcile_balances`; `error.rs` → `BalanceMismatch` |
| F24 | The feed's publish time was a public field written as is into the log | Low | Fixed in 0.8.0 (S25) | `rate_feed.rs` → `Feed`, `approve` |
| F25 | Every operation re-hashes the whole database, so time grows with the log | Low | Accepted: fast enough for a demo-sized bank | `seal.rs` → `digest`, `check` |
| F26 | The first failed login after a start was slower for an unknown card | Low | Fixed in 0.8.0 (S21) | `auth.rs` → `burn_time_like_a_real_check`, `warm_up` |
| F27 | The CLI never cleared the screen after a session | Low | Fixed in 0.8.0 (S31) | `ui.rs` → `customer_flow`, `admin_flow`, `handler_flow`; `input.rs` → `wipe_screen` |
| F28 | Some stored MACs were compared with an early exit | Low | Fixed in 0.8.0 (S21) | `keys.rs` → `same_mac` |
| F29 | The key fingerprint uses the audit-log MAC key | Info | Accepted: not exploitable; changing it breaks every existing bank | `keys.rs` → `fingerprint` |
| F30 | GUI logout left some screen properties filled | Info | Fixed in 0.8.0 (G25) | `gui/src/main.rs` → `go_welcome` |
| F31 | Moving the clock forward starts a new bank day early | Info | Accepted: the clock belongs to the operating system | `audit.rs` → `check_clock`, `bank_day_start_utc` |

**Why the other 10 are not fixed**

**F03 (reported High; we rate it Limited).** The teller who opens an
account handles the form where the new customer types the PIN, and sees the
new card number. Nothing forces a PIN change at first use, so that teller
could sign in as the customer until the PIN is changed. What limits it: the
customer types the PIN into masked fields that can't be copied out (G22),
Change PIN is on the customer menu, and every sign-in is logged with the
card. A forced change at first use would need a new card state, and every
demo card would then ask for it. Advice: change the PIN at first use.

**F12.** Someone with file access who puts back `atm.db` and `atm.anchor`
together rolls back the cash counts, so a Cash Handler could remove the
same surplus again. Out of scope: the fix is an anchor kept off the machine
(open item 3). What limits it: the check code written down each day shows a
rolled-back or rebuilt log, and the branch counts the cash by hand.

**F13.** The Cash Handler login can't be reset, disabled or replaced, so a
leaked password gives lasting access until the bank is set up again. On
purpose: there is no staff creation or reset from the teller screen, since
one insider could then make themselves a handler (#28). What limits it: the
handler can change their own password, can't sign in while the ATM is out
of service, and every cash action is logged and counted against the log
(S23). The Teller Admin login is the same: it can change its own password,
but no screen resets or replaces it.

**F18.** The 3-miss limit on unknown account numbers (#6) is per session,
so signing in again resets it. Accepted: account numbers are 10 random
digits (10 billion), each try needs a full sign-in with a real card and
PIN, every sign-in is logged, and a hit shows only initials.

**F19.** Anyone who knows a card number can lock it with 3 wrong PINs, and
a teller unlocks a card only once per bank day (#85). Accepted: this is how
ATMs behave, and unlimited unlocks would bring back teller PIN guessing.
Reissuing a card is not in scope.

**F20.** A mis-stocked machine (filled with $5 bills, or a typo in a count)
can't be corrected: restock stops at the maximum, and removal only works
above it. Accepted for the simulation. Counts are logged and now matched
against the log (S23), so a typo shows. A real ATM has a cassette swap done
by two people.

**F21.** The fee and rate the customer confirms are worked out again when
the withdrawal or deposit runs. If another teller changes the fee in
between, the new fee is charged without a second prompt. Accepted: fee
changes are logged, capped (5% and $10) and rare, and a typed rate moves at
most 5% a day.

**F25.** Every operation re-hashes the whole database (the seal) and, since
S30, runs SQLite's structure check, so the time grows with the log.
Measured on a release build of 0.8.0: a seal check takes 13, 91 and 333 ms
at 10,000, 50,000 and 200,000 log rows; the full check at Teller Admin
sign-in takes 51, 246 and 921 ms. A demo bank has a few hundred rows.
Accepted for a demo-sized bank; a real one would seal per page or per day.

**F29.** The key fingerprint is an HMAC with the audit-log key instead of
its own derived key. Not exploitable: its input can't collide with a log
row's, and the fingerprint is public anyway. Left as is: changing it would
make every existing bank fail its key check.

**F31.** Moving the system clock forward starts the next bank day early, so
daily limits, the once-a-day unlock and the hold windows reset. Moving it
back is refused at start (#40). Accepted: the clock belongs to the
operating system; a real ATM uses a trusted time source.
