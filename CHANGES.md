# Changes in 0.9.0

The final submission round:
- **Bank of CCNY accounts are always in US dollars.** Cards from other
  banks keep their own currency and are converted at the day's rate.
- **The demo hides card numbers and PINs.** The wallet shows only the last
  4 digits; the PINs are in `docs/USER_GUIDE.md` (Demo logins). A
  **Choose** picker on the teller's forms fills in a sample customer's
  number, and the transfer screen lists the sample accounts.
- **Shorter first build** (G29), with no change to how the GUI looks.
- **Docs for a new reader:** the README is now a setup guide;
  `docs/STUDY_GUIDE.md` covers the project by rubric line.
- **Comments:** one short line saying what each module and main function
  does; notes about how the code was written were removed.

Same step-by-step rule as before: each step was built and fully tested
before the next. **Nothing to delete:** the database layout is unchanged
(version 6). A 0.8.0 bank opens as is; its foreign-currency accounts keep
working.

## Core library

**S36. Bank of CCNY accounts are always US dollars**
- `admin.rs`: `create_customer` no longer takes a currency;
  `open_adult_account` doc updated. `register_guest_card` still takes one.
- `ui.rs` (CLI): `create_customer` asks for the starting balance in USD
  only.
- `demo.rs`: sample customers cut from 14 to 10; Eva (EUR) and Yuki (JPY)
  are now other banks' cards; `PEOPLE`, `seed` and the demo test updated.
- Tests: every `create_customer` call drops its currency argument.
  `customer.rs`: `our_own_accounts_are_always_us_dollars` (new),
  `euro_card_without_a_fresh_rate_cannot_convert` (was the euro-account
  test, now uses a guest card). `tests/attacks.rs`: the euro test uses a
  guest card.
- `gui/src/staff.rs`: the one GUI call to `create_customer` (so the commit
  builds).

## GUI

**G28. Demo wallet hides numbers; pickers fill them in** (demo builds only)
- `gui/src/wallet.rs`: cards show "Card ending NNNN" and "Account ending
  NNNN", no PIN; staff badges no password. New `customers`, `names`,
  `payees`; `connect` adds `demo-number` and sets `demo-names`.
- `gui/ui/bank.slint`: `demo-names` property, `demo-number` callback.
- `gui/ui/staff.slint`: new `DemoPick` component, used on the holder card,
  joint holder, youth account, add guardian and unlock fields. The
  individual account form has no currency picker (other bank's card only).
- `gui/src/customer.rs`: the transfer screen adds the sample accounts to
  Send again.

**G29. Shorter first build**
- `gui/Cargo.toml`: Slint with only the parts the GUI uses (both renderers
  kept, so the screens look the same; accessibility and system-tray
  support left out). 19 fewer libraries to compile.
- `Cargo.toml`: release builds compile the GUI crate and SQLite's C code at
  `opt-level = 1`; Argon2 and the crypto stay fully optimized.
- Clean release build on 4 cores: 508 s before, 422 s after (measured on the same machine).

**G30. The GUI needs Rust 1.92**
- `gui/Cargo.toml`: `rust-version = "1.92"`, the minimum of Slint 1.18, so
  an older Rust stops with a clear message. The core alone still builds on
  1.88.

**G31. A faster build for a timed install**
- `Cargo.toml`: new `quick` profile (`--profile quick`): opt-level 0 with
  Argon2, BLAKE2, SHA-256 and AES at opt-level 3; overflow checks on. The
  README Quick start uses it: 247 s instead of 368 s on the 4-core test
  machine; login and the teller's integrity check stay under half a second.
  Idea from a teammate's branch.

**G32. Demo screens tidied** (demo builds only, except the field widths)
- `gui/ui/staff.slint`: `GuardianForm` puts the youth account and the new
  guardian's card on separate rows; `HolderConfirm` fields shrink to 200px on
  a narrow window so the picker isn't cut off; picker label "Customer".
- `gui/src/wallet.rs`: `payees` shows initials ("A. L."), like a real recent
  payee, instead of the full name and "(demo)".

## Comments and docs

- Every core module and main function has a short comment saying what it
  does. Comments about how the code was written or reviewed were removed.
- `README.md`: rewritten as a setup guide (install, run, test, files).
- `docs/USER_GUIDE.md`: Demo logins table; USD-only wording.
- `docs/STUDY_GUIDE.md` (new): the project by rubric line, a code map, a
  10-minute demo script and likely questions.
- `docs/THREAT_MODEL.md` §6: the running program's memory is assumed safe.
- `docs/DESIGN_DECISIONS.md` §30: how many ATMs would share one bank.
- Final check: README Quick start is one command (one build instead of
  two); README says Rust 1.92 and `cargo test` (no second GUI build);
  `docs/THREAT_MODEL.md` §4 has a STRIDE-by-asset table and says all six
  categories apply; `docs/STUDY_GUIDE.md` has a who-did-what table to fill
  in and the demo-password question.

# Changes in 0.8.0

Zack's three asks after 0.7.0, plus everything a fresh security audit of
0.7.0 found that could be exploited:
- **Out of service takes no cards at all.** The start screen says "Out of
  service", the card can't be inserted, and only a Teller Admin can sign in
  (the Cash Handler is refused too).
- **A bank freeze refuses the account's cards entirely** until a Teller Admin
  lifts it. A guardian's freeze on a youth account is unchanged (no money
  out; the card still works).
- **The red banner no longer cuts off Sign out.** The banner is shorter, the
  side menu scrolls, and long pages scroll.
- **Audit fixes:** 31 findings (F01 to F31, listed in
  `docs/VULNERABILITIES.md` §9). 21 are fixed below, each with a test that
  fails on 0.7.0 (or a screen check for the GUI); the other 10 are design
  limits, written up there with the reason. Four more gaps turned up while
  the docs were updated, and are fixed too (S33 to S35, G27).

Same step-by-step rule: each step was built and fully tested (`cargo test`
in the default, `demo`, `online-rates` and `integrity-test` builds, clippy,
fmt; GUI steps also checked on screen) before the next started. S steps
change the core library (`src/`); G steps change only the GUI (`gui/`).

**Nothing to delete:** the database layout is unchanged (version 6). A 0.7.0
bank opens as is.

New tests: `tests/audit.rs` (4 tests, for exploits that need a real file or
the real program) and 8 more library tests (named under each step).

## Core library

**S19. Out of service takes no cards; only a Teller Admin signs in** (Zack's
ask; audit F07, F15)
- `service.rs`: new `pub fn out_of_service(atm)`, so a front end can refuse
  the card before anything is typed.
- `auth.rs`: `HandlerSession::stops_when_halted` is now true (a live Cash
  Handler session stops at a halt); `login_staff` refuses the Cash Handler
  while out of service.
- `ui.rs` (CLI): `main_menu` shows an OUT OF SERVICE line; `customer_flow`
  refuses before asking for the card; `handler_flow` refuses before asking
  for a password.
- Test: `while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in`
  (service.rs); `a_failed_check_at_sign_in_takes_the_atm_out_of_service`
  now expects the Cash Handler to be stopped.

**S20. A bank freeze stops the card entirely until a teller lifts it**
(Zack's ask; audit F05)
- `error.rs`: new `FrozenByBank` ("This account is frozen by the bank.
  Please see a teller inside the branch.").
- `auth.rs`: `CardRow` gains the frozen flag; `login_customer` refuses a
  frozen account after the PIN is checked (a wrong PIN still counts, and the
  attempt is logged); `CustomerSession::still_allowed` also requires
  `frozen = 0`, so an open session ends at the freeze; `confirm_at_counter`
  refuses a frozen holder's card (no joint holder, youth account or guardian
  added through it).
- `customer.rs`: `destination` treats a frozen account like an unknown
  number (no transfers in, no name hint).
- `admin.rs`: `set_frozen` doc. `ui.rs`: `freeze` message.
- Tests: `a_bank_freeze_stops_the_card_entirely_until_a_teller_lifts_it`
  (admin.rs); `a_guardian_cannot_lift_a_freeze_placed_by_the_bank`
  (tests/attacks.rs) updated.

**S21. MACs compared in constant time; the first failed login is no slower**
(audit F26, F28)
- `keys.rs`: new `same_mac` (compares every byte). Used by
  `db::check_version_and_key`, `db::get_setting`, `fx::read_rate`,
  `fx::read_history`, `audit::verify_chain` and `Atm::start` (anchor).
- `auth.rs`: the dummy hash is built once (`dummy_hash`, new `warm_up`
  called by `Atm::start`), so `burn_time_like_a_real_check` costs the same
  on the first try as on later ones.
- Test: `stored_macs_are_compared_in_full` (keys.rs).

**S22. A finished change is never reported as failed** (audit F11)
- `lib.rs`: `Atm` and `Tx` gain `anchor_behind`. `Tx::commit` no longer
  returns an error after the database commit when `atm.anchor` can't be
  written; it marks the anchor as behind. New `catch_up_anchor`, called by
  `begin` and `read`: the anchor is written first, and until it can be, the
  ATM does nothing else.
- Test: `a_finished_deposit_is_never_reported_as_failed_and_a_blocked_anchor_stops_the_atm`
  (tests/audit.rs).

**S23. The integrity check counts the cash against the log** (audit F08)
- `audit.rs`: new `reconcile_cash` (bill counts must equal restocks +
  deposits - withdrawals - removals in the log), called by `verify`;
  `IntegrityReport.cash`.
- `error.rs`: new `CashMismatch { counted, logged }`.
- `admin.rs`: `verify_integrity` logs the cash. `ui.rs`: shows it.
- Test: `bills_moved_with_no_log_entry_take_the_atm_out_of_service`
  (service.rs).

**S24. One teller's starting balances are capped at $20,000 a bank day**
(audit F04)
- `admin.rs`: new `STARTING_BALANCES_PER_DAY`; `insert_account` checks the
  day's total for that teller; new `log_opened` writes the US-dollar value
  with each `account_opened` row; `open_adult_account`,
  `open_youth_account` use them.
- `audit.rs`: new `opened_today_by`.
- Test: `one_teller_cannot_create_unlimited_money_with_starting_balances`
  (tests/audit.rs).

**S25. Only `fetch` can make a rate feed** (audit F01, F24)
- `rate_feed.rs`: `Feed` fields are private, with a `published()` getter;
  `parse` is private. Parse-only items are compiled only for tests and the
  `online-rates` build. A front end can no longer build a feed with any
  rates it likes and approve it past the 5% typed-rate limit, or write its
  own text into the log.
- `ui.rs` and `gui/src/staff.rs` (one call site each) use `published()`.
- Test: a 5th compile-fail doc test in `lib.rs` (a front end can't build a
  `Feed`).

**S26. Guardian moves go through the activity rules** (audit F16)
- `family.rs`: `move_money` calls `review::screen` on the account the money
  leaves, and keeps the hold on a match, like `customer::transfer`.
- Test: `guardian_moves_go_through_the_same_activity_rules_as_transfers`
  (family.rs).

**S27. Activity rule 4 can't be primed with a cent** (audit F17)
- `review.rs`: `matched_rule` counts a payee as "paid before" only if paid on
  an earlier bank day. Rule text: "$1,000 or more to an account not paid
  before today".
- Test: `unusual_amounts_are_held` (review.rs) gains the one-cent case.

**S28. The integrity check lists every failure, last 4 digits only** (audit
F10, F23)
- `audit.rs`: `verify` runs every check after the log chain and returns all
  failures; `reconcile_balances` lists every account that is off, with both
  amounts, by its last 4 digits (it no longer decrypts account numbers).
- `error.rs`: `BalanceMismatch` holds those lines; new `IntegrityFailures`.
- `admin.rs`: test `integrity_check_catches_a_balance_edited_in_the_database`
  checks the masking.
- Test: `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged`
  (service.rs).

**S29. A halt, lock or closure that lands while a change waits is obeyed**
(audit F22)
- `auth.rs`: new `Atm::begin_for(session)`: `begin`, then the session checks
  again inside the write lock.
- Used by `customer.rs` (`withdraw`, `deposit`, `transfer`, `recipient_hint`,
  `change_pin`), `family.rs` (`set_controls`, `set_frozen`, `move_money`) and
  `cash.rs` (`restock`, `remove_excess`, `reset_to_maximum`).
- Test: `a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first`
  (service.rs, two connections to one file).

**S30. An index edited in the database file is refused** (audit F14)
- `seal.rs`: `check` runs SQLite's `PRAGMA integrity_check` first. The seal
  covers every table row but not index pages; swapping two log indexes in
  the file let a customer pass the daily withdrawal limit.
- Test: `an_index_edited_in_the_file_is_caught_before_it_can_mislead`
  (tests/audit.rs).

**S31. The CLI wipes the screen when a session ends** (audit F27)
- `input.rs`: new `wipe_screen` and `WIPE` (clear screen and scrollback).
- `ui.rs`: `customer_flow`, `admin_flow`, `handler_flow` call it after
  logout or timeout.
- Test: `the_cli_wipes_the_screen_when_a_session_ends` (tests/audit.rs,
  runs the real `atm` program).

**S32. Limits, rates and account flags are checked against the log** (audit
F09)
- `audit.rs`: new `reconcile_state`, called by `verify`: each daily limit
  must equal its newest `limit_changed` entry (or the default), each
  exchange rate its newest rate-history row, and each account's bank
  freeze, guardian freeze and closure its newest log entry.
  `IntegrityReport.state_checked`.
- `error.rs`: new `StateMismatch`.
- `admin.rs`: `verify_integrity` logs the count. `ui.rs`: shows it.
- Test: `a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service`
  (service.rs).

**S33. A guardian can't move money into a bank-frozen account** (found
while updating the docs)
- `family.rs`: `move_money` refuses with `FrozenByBank` when the account the
  money goes into is frozen by the bank, like a transfer to it.
- Test: `a_guardian_cannot_lift_a_freeze_placed_by_the_bank`
  (tests/attacks.rs) also tries a move into the frozen account.

**S34. Every rate change needs its log line** (found while updating the
docs; completes S32)
- `audit.rs`: `reconcile_state` also requires one `rate_changed` log entry
  for each rate-history row of a currency (one pass over the log). Before,
  a rate written with its history row but no log line passed.
- `service.rs`: module doc lists the full check.
- Test: `a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service`
  (service.rs) also plants a GBP rate with its history row and no log line.

**S35. The CLI says why a session stopped after wiping the screen** (found
while updating the docs; completes S31)
- `ui.rs`: `run_action` passes a stopped session (out of service, session
  ended) up instead of printing it; the flow wipes the screen and
  `main_menu` then shows the reason. `Next` removed. Before, the reason was
  wiped with the rest.
- Test: `the_cli_wipes_the_screen_when_a_session_ends` (tests/audit.rs) also
  halts the ATM from a second console while a customer's menu waits.

## GUI

**G18. Out of service, the start screen takes no cards** (Zack's ask)
- `ui/customer.slint`: `BankCard` and `WalletCard` gain `enabled` (grayed;
  the bank card says "Not accepting cards"); `WelcomeScreen` shows "Out of
  service" and only the Teller Admin link and badge work.
- `ui/bank.slint`: `service-halted` also drives the welcome screen.
- `src/main.rs`: `STAFF_HALTED`, `SERVICE_CHECK`, `State.service_checked`;
  new `App::out_of_service`; `go_welcome` and `tick` (every 5 s on the
  welcome screen) refresh it.
- `src/customer.rs` (`on_start_customer`, `login`), `src/staff.rs`
  (`on_start_staff`, `staff_login`), `src/wallet.rs` (`insert`): refuse a
  card or a Cash Handler badge while out of service.

**G19. The red banner no longer cuts off Sign out** (Zack's ask; audit F06)
- `ui/staff.slint`: `ServiceBanner` is compact (one reason line, one
  instruction line); `SideNav` puts the menu in a `ScrollView` with Sign out
  always below it; `TellerScreen` puts every tab in a scrolling page.
- `src/main.rs`: `fail` tells a Cash Handler stopped by a halt who can still
  sign in.

**G20. A bank-frozen card is returned with "see a teller"**
- `src/customer.rs` (`login`): `FrozenByBank` returns to the welcome screen.
- `src/staff.rs`: `open_account` explains a frozen holder's card;
  `account_action` freeze message.

**G21. The Data integrity tab shows the cash check**
- `src/staff.rs` `verify`; `ui/staff.slint` integrity hint.

**G22. PINs and passwords typed at the teller screen can't be copied out**
(audit F02)
- `ui/theme.slint` `Field`: secret fields ignore Ctrl/Cmd shortcuts (no
  select-all, copy or cut) and the mouse can't select in them.

**G23. Every failure shows on the Data integrity tab, in red** (audit F10)
- `src/staff.rs` `verify`: one red line per failure (`IntegrityFailures`);
  `CashMismatch` shows on the tab instead of as a pop-up.

**G24. Tab reaches PIN and password fields again** (fixes G22)
- `ui/theme.slint` `Field`: the listener added in G22 no longer takes the
  focus itself (`focus-on-click` and `focus-on-tab-navigation` off).

**G25. Signing out wipes every screen property that held someone's data**
(audit F30)
- `src/main.rs` `go_welcome`: also clears receipts, confirm lines, sums,
  limits, holds, rates, cash, integrity results, the sign-in problem, Send
  again choices, youth caps and flags; resets `State.currency` and the page
  counters.

**G26. The Data integrity tab reports the limits, rates and flags check**
- `src/staff.rs` `verify`; `ui/staff.slint` integrity hint.

**G27. A lone "changed with no log entry" failure shows in red on the tab**
(found while updating the docs; completes G23)
- `src/staff.rs` `verify`: `StateMismatch` joins the red-line arm. Before,
  it showed as a pop-up when it was the only failure. Checked by build and
  clippy (no screen check: it needs a planted code change).

# Changes in 0.7.0

The teammate's hardening from the Integration branch, the fixes for the 13
holes the review found in 0.6.0, and Zack's out-of-service idea: the
integrity check runs at every Teller Admin sign-in, and a failure takes the
ATM out of service with a red banner until a teller resumes it.

Same step-by-step rule: each step was built and fully tested (`cargo test`
in the default, `demo`, `online-rates` and `integrity-test` builds, clippy,
fmt) before the next started. S steps change the core library (`src/`); G
steps change only the GUI module (`gui/`).

**Start over before running:** the database layout changed (version 6) and a
bank is now three files. Delete `atm.db`, `atm.key` and `atm-demo.*` (and
`atm.anchor` if you ran a test build).

Review holes are numbered as in `Integration-review/REVIEW.md` (A = someone
who edits `atm.db`, B = a dishonest teller, C = a customer). Tests named
`a1_...` to `c2_...` are in `tests/review.rs`; the teammate's 26 attack tests
are in `tests/attacks.rs`.

## Core library

**S1. The whole database is sealed; older copies are refused** (holes A1,
A2, A3, A4, A6, from the teammate's ledger check and anchor)
- New `seal.rs`: `digest` (SHA-256 over every row of every table and the
  schema), `check`, `write`, `current`. Each commit writes a new seal (HMAC
  of a counter + the digest) in the same transaction.
- New `anchor.rs`: `Anchor` (`for_db`, `exists`, `read`, `advance`). The file
  `atm.anchor` keeps the newest seal, HMAC-tagged, written by rename.
- `keys.rs`: two more derived keys (seal, anchor); new `keyed`, `hex`,
  `unhex`, `matches`, `seal_mac`, `seal_matches`, `anchor_tag`,
  `anchor_tag_matches`.
- `lib.rs`: `Atm` gains `anchor` and `seen`; new `Atm::create` (a bank with
  a key made in advance); `start` refuses a missing database when its key or
  anchor exists (no first-run setup after deleting `atm.db`), checks the
  seal and refuses a rolled-back copy; new `begin` (write lock + seal check)
  and `read` (seal check) used by every operation; new `Tx` (`commit`
  re-seals and moves the anchor). Test helper `reseal`.
- `db.rs`: `SCHEMA_VERSION` 6; new `seal` table; `open(path, fresh)` creates
  a new bank in one transaction (new `create`) or only checks an existing
  one; `check_version_and_key` message names the anchor file.
- `error.rs`: new `DatabaseAltered` ("TAMPERING DETECTED ...") and
  `RolledBack` ("DATABASE ROLLED BACK ...").
- Every module now opens its work with `atm.begin()` / `atm.read()`:
  `admin.rs`, `auth.rs`, `cash.rs`, `customer.rs`, `family.rs`, `fx.rs`,
  `rate_feed.rs`, `review.rs`, `demo.rs` (same functions, same rules).
- Tests: `any_edit_breaks_the_seal_and_a_reseal_fixes_it` (seal.rs); three
  admin tests now expect `DatabaseAltered` at once instead of a later
  integrity-check failure; `tests/attacks.rs` and `tests/review.rs` added.

**S2. A PIN or password hash only works for its own card or login**
(teammate's identity-keyed hashes)
- `keys.rs`: `pepper()` replaced by `credential_key(identity)` =
  HMAC(pepper, "credential/v1", identity).
- `auth.rs`: new `card_identity(card_lookup, account_id, role)` and
  `staff_identity(username, role)`; `hasher`, `hash_secret`, `check_pin`,
  `verify_secret` take the identity; `burn_time_like_a_real_check` checks a
  fixed string; `login_customer`, `login_staff`, `change_staff_password`,
  `first_run_setup` pass it.
- `admin.rs`: `check_holder`, `insert_card` (hashes inside the transaction,
  after the card row exists), `open_adult_account`, `add_joint_holder`,
  `open_youth_account`. `customer.rs`: `change_pin`.
- Test: `a_hash_only_works_for_its_own_card_and_role` (auth.rs).

**S3. A session only works on the bank that issued it** (teammate's session
binding)
- `lib.rs`: `Atm.id` (random per opened bank), `new_id`.
- `auth.rs`: sessions carry `bank`; new `pub(crate) trait Session` (`bank`,
  `clock`, `still_allowed`, `stops_when_halted`) for the three session
  types; new `Atm::admit` (wrong bank, locked card, closed account or
  deleted staff row ends the session; also the idle clock). `touch()`
  removed. `log_logout` refuses a foreign bank's session.
- Every action calls `atm.admit(session)` instead of `session.touch()`:
  `admin.rs`, `cash.rs`, `customer.rs`, `family.rs`, `fx.rs`,
  `rate_feed.rs`, `review.rs`.

**S4. The bank's freeze and a guardian's freeze are separate** (hole B3)
- `db.rs`: `accounts.guardian_frozen`.
- `admin.rs`: `set_frozen` sets `frozen` and refuses to lift a
  guardian-only freeze; `AccountSummary.guardian_frozen`, `list_accounts`.
- `family.rs`: `set_frozen` sets `guardian_frozen` and refuses to lift a
  bank-only freeze; `YouthSummary.bank_frozen`, `my_youth_accounts`,
  `set_controls`.
- `customer.rs`: `is_frozen`, `account_info` (either freeze stops money).
- `ui.rs`: `family_menu`, `list_accounts` labels.
- Test: `the_bank_and_the_guardian_each_lift_only_their_own_freeze`.

**S5. A customer's history hides other people's numbers**
- `audit.rs`: new `for_customer` (other accounts shown as `******1234`,
  other people as "other account holder").
- `customer.rs`: `history`; `family.rs`: `youth_history` use it.

**S6. Absurd amounts and limits are refused** (hole B2)
- `money.rs`: `Cents::MAX` (10^15 cents); `new` refuses more, `checked_add`
  is capped. Test `huge_values_are_refused_and_sums_cannot_wrap`.
- `db.rs`: balance `CHECK` (0 to `Cents::MAX`); new `Limit::default_value`
  and `Limit::ceiling` (default + teller raise: $5,000 / $50,000 /
  $25,000); `insert_defaults` uses `default_value`.
- `admin.rs`: `insert_account` caps a starting balance at the daily deposit
  limit (US-dollar value); `set_limit` refuses above `ceiling`.
- `demo.rs`: `seed` sets rates before opening foreign accounts.
- Tests: `one_teller_cannot_mint_money_or_switch_limits_off` (admin.rs);
  `euro_account_without_a_fresh_rate_cannot_convert` now starts at zero.

**S7. Joint and youth changes need the holder's own card and PIN** (holes
B1, B3)
- `auth.rs`: new `CardAndPin { card_number, pin }`, `Confirmed`, and
  `confirm_at_counter` (checks the holder's card and PIN; a wrong PIN counts
  toward the lock, like at the ATM).
- `admin.rs`: new `confirmed` (commits a refusal, so the try is counted);
  `add_joint_holder(.., holder: CardAndPin, ..)`,
  `open_youth_account(.., guardian: CardAndPin, ..)`,
  `add_guardian(.., current_guardian: CardAndPin, ..)`.
- `ui.rs`: new `at_counter`; `add_joint`, `open_youth`, `add_guardian` ask
  for the holder's card and PIN.
- `demo.rs`: `seed` passes Ann's and Pat's consent.
- Test: `joint_and_youth_changes_need_the_holders_card_and_pin` (admin.rs).

**S8. One unlock per card per day; the locked list shows last 4 only**
(hole B6)
- `admin.rs`: `LockedCard { card_last4, account_last4, full_name,
  date_of_birth }`; `locked_cards`; `unlock_card` allows one unlock per card
  per New York bank day (counted from the signed log) and takes the number
  typed from the customer's card.
- `ui.rs`: `unlock` (masked list and message).
- Test: `locked_cards_are_listed_for_id_check_and_unlock_needs_a_locked_card`
  (extended).

**S9. Closing guardians one by one can't orphan a youth account** (hole B4)
- `admin.rs`: `close_account` counts only guardians whose accounts are open.

**S10. The 200-bill deposit cap counts each kind of bill once** (hole C2)
- `customer.rs`: `deposit` totals bills per denomination before the cap.

**S11. An unknown card fails exactly like a real one** (hole C1)
- `lib.rs`: `Atm.unknown_cards` (in memory, at most 10,000 entries).
- `auth.rs`: new `like_a_real_card`; `login_customer` uses it for unknown
  and closed cards (wrong twice, then "card locked").

**S12. Demo data can't run as a real bank**
- `db.rs`: `mark_demo`, `is_demo` (a sealed `meta` row).
- `lib.rs`: `open` refuses a demo database; new `open_demo` (demo builds
  only) refuses a real one. `demo.rs`: `seed` marks the database first.
- `main.rs`: `run_demo` uses `open_demo`.
- Test: `tests/demo_mode.rs` `demo_data_and_real_data_stay_apart`.

**S13. Integrity check at every Teller Admin sign-in; out-of-service mode**
(Zack's idea)
- New `service.rs`: `ServiceStatus`, `halted`, `refuse_if_halted`, `log`,
  `problem`, `check_at_sign_in`, `status`, `halt`, `resume`. The state is
  the newest halt or resume entry in the signed log (no flag to edit).
- `audit.rs`: `Action::ServiceHalted`, `Action::ServiceResumed`.
- `auth.rs`: `AdminSession.integrity_problem` + `integrity_problem()`;
  `login_admin` runs the check (a failure halts the ATM, logged as
  "system"); `login_customer` refuses while halted; customer sessions stop
  (`stops_when_halted`).
- `error.rs`: `OutOfService` ("This ATM is temporarily out of service.
  Please use another ATM.").
- `ui.rs`: `service_banner` after sign-in; menu option 18 `halt_or_resume`;
  `run_action` ends the customer menu on `OutOfService`.
- Tests: `a_failed_check_at_sign_in_takes_the_atm_out_of_service`,
  `a_teller_can_halt_and_resume_by_hand` (service.rs).

**S14. A test-only build that breaks the data on purpose**
- `Cargo.toml`: feature `integrity-test = ["demo"]`. Normal and demo builds
  don't contain it.
- `demo.rs`: `break_integrity` (adds $500 to Ann and Ben's balance with no
  log entry; demo data only).
- `main.rs`: `run_demo(break_integrity)`, `--demo --break-integrity`.
- Test: `a_broken_balance_is_caught_at_the_next_teller_sign_in`
  (`tests/demo_mode.rs`, integrity-test builds).

**S15. Every table is STRICT** (teammate's STRICT tables)
- `db.rs`: `SCHEMA` tables end in `STRICT`, so text or a fraction can't be
  stored in a number column. Test `strict_tables_refuse_values_of_the_wrong_type`.

**S16. The integrity test breaks its own copy**
- `main.rs`: `run_demo` uses `atm-test.db` / `atm-test.key` with
  `--break-integrity`, so trying the test never spoils `atm-demo.*`.
- `lib.rs`: module map lists `review` and `service` (comment only).

**S17.** `main.rs`: `run_demo` names the `atm-test.*` files only in
integrity-test builds, so demo builds hold no trace of the test.
`.gitignore`: anchor files.

**S18. Two leaks found while updating the docs**
- `admin.rs`: `HolderSummary.card_number` replaced by `card_last4`;
  `list_accounts` reads the stored last 4 instead of decrypting the number.
  The teller's account list (CLI menu 10) now shows "card ending 1234", so
  the full number only comes from the card the customer hands over.
- `auth.rs`: `login_customer` waits the same Argon2 time for a locked card,
  so timing can't tell a locked real card from an unknown number.
- `ui.rs`: `list_accounts`. Test
  `card_and_account_numbers_are_stored_encrypted` checks the last 4.

## GUI module

**G0.** `gui/src/staff.rs`: `check_feed`, `verify` take the bank writable
(the seal check needs it).

**G11. Teller forms ask for the holder's card and PIN**
- `gui/ui/staff.slint`: new `HolderConfirm`; `JointForm`, `YouthForm`,
  `GuardianForm` send it; the PIN is wiped after every try.
- `gui/ui/bank.slint`: `open-account` takes card + PIN (11 values).
- `gui/src/staff.rs`: new `AccountForm`; `open_account(form)`, `connect`.

**G12. Locked cards by last 4; who froze what; demo opens demo data only**
- `gui/ui/staff.slint`: Locked cards tab (no row click; "Card number, from
  the customer's card").
- `gui/src/staff.rs`: `teller_tab_with` ("ending 1234", "Frozen by
  guardian"), `unlock` (masked notice).
- `gui/src/customer.rs`: `show_family` ("Frozen by the bank").
- `gui/src/main.rs`: `main` uses `Atm::open_demo` in demo mode.

**G14. Red banner, Halt ATM and Resume service**
- `gui/ui/staff.slint`: new `ServiceBanner`; `TellerScreen` shows it while
  halted; Data integrity tab gains Halt ATM / Resume service.
- `gui/ui/bank.slint`: `service-halted`, `service-since`, `service-reason`,
  `signin-problem`, `halt-service`, `resume-service`.
- `gui/src/staff.rs`: new `refresh_service`, `halt_service`,
  `resume_service`; `staff_login` shows the sign-in check's result;
  `connect`, `teller_tab_with`.
- `gui/src/main.rs`: `parse_args` (and `--break-integrity` in
  integrity-test builds), `main`, `ends_session` (`OutOfService`).
- `gui/Cargo.toml`: feature `integrity-test`.

**G15. Tidier teller forms; demo wallet shows full card numbers**
- `gui/ui/staff.slint`: `HolderConfirm`, `JointForm`, `YouthForm`,
  `GuardianForm` fields line up in two 300px columns.
- `gui/src/staff.rs`: `open_account` says "The holder's card number or PIN
  was not accepted" / "The holder's card is locked" instead of "Login
  failed".
- `gui/src/wallet.rs`: `Item`, `load` (full card number on each demo card,
  so testers can type it into teller forms, as a customer hands over their
  card); `last4` removed.

**G16, G17.** `gui/src/main.rs`: `main` uses `atm-test.*` with
`--break-integrity`, like the command line (named only in integrity-test
builds).

## Not changed on purpose
- "Decisions read from the signed log" (teammate): the seal gives the same
  protection more simply. Every row is covered, so an edited balance, flag
  or staff row is refused before anything is decided from it.
- Five display currencies (teammate): this version already has 16.
- `add_guardian` for a guardian-frozen account: the current guardian's own
  card and PIN (S7) already cover it.

## Tests
- 106 library tests (104 without `demo`/`online-rates`), 26 attack tests,
  13 review tests, 4 compile-fail checks, 1 demo test (2 in integrity-test
  builds). All pass.

# Changes in 0.6.0

A withdrawal limit per payout, the receipt question with the card returned
before the cash, bank-style fee wording, and Zack's "Trust feed" rule for
exchange rates. Same step-by-step rule: each step was built and fully tested
(`cargo test` with and without `--features demo` and `online-rates`, clippy,
fmt) before the next started. B, F and R steps change the core library
(`src/`); G steps change only the GUI module (`gui/`). The database layout is
unchanged (version 5); nothing needs deleting (delete `atm-demo.*` only for
the new demo cash).

## Core library

**B8. A withdrawal pays out at most 40 bills, like a real dispenser**
- `dispense.rs`: new `MAX_BILLS` (40), `plan_withdrawal` (customer payouts,
  capped) and `count`; `plan` now calls new `plan_within` with no cap (the
  Cash Handler's reset-to-maximum is not a payout); `preferred` and `singles`
  take the cap (`singles` made private), so the "available bills" list only
  names bills that fit.
- `error.rs`: new `AtmError::TooManyBills` ("This machine pays out at most 40
  bills at a time. Choose bigger bills, or take the cash in two withdrawals.").
- `customer.rs`: `quote_withdrawal`, `withdraw` use `plan_withdrawal`.
- `ui.rs`: `withdraw` offers the fewest-bills plan on `TooManyBills`, as it
  already did for a short bill.
- `demo.rs`: fewer $5 bills in the demo stock (10 to 15), so the "not enough of
  that bill" message is easy to show; its test updated.
- Tests: `withdrawals_pay_at_most_40_bills`,
  `short_bill_lists_only_bills_within_the_cap` (dispense.rs),
  `more_than_40_bills_is_refused_without_a_debit` (customer.rs); one teller
  approval test now withdraws in $50s.

**F3. Fee small print reads like a bank's fee schedule**
- `fx.rs`: `FeeRule::short` now says "3% of the amount, $3.00 minimum" (was
  "3% or $3.00, whichever is higher"), "3% of the amount" with no minimum,
  "$3.00" with no percent and "no fee" when both are zero. The money math is
  unchanged. Tests in `fx.rs` and `customer.rs` updated.

**R6. The daily feed sets the market rate; a move over 5% pauses the currency**
(Zack's "Trust feed" choice)
- `fx.rs`: `MAX_STEP_BP` (3% per change) removed, so repeated checks can't add
  up; `check_change_cap` and `allowed_band` keep one rule for typed rates: at
  most 5% (`MAX_DAY_BP`) from every rate in the last 24 hours. `store_rate`
  takes a `pause` flag: a newly paused currency gets its own
  `exchange_paused` log line ("big move in today's feed: check it, then
  resume"). `set_rate` passes `false`.
- `rate_feed.rs`: `RateCheck` gains `pauses`; `plan` no longer caps feed rates
  and marks a move outside the 5% band; notes read "big move: +x.xx%; will be
  paused" or "...; stays paused"; `approve` checks the believable range
  instead of the typed-rate cap and passes the pause flag.
- `ui.rs`: `rates_menu` text.
- Tests: `a_teller_cannot_jump_a_rate_but_can_pause_it` (fx.rs) and
  `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source`
  (rate_feed.rs, renamed) cover the new rule.

## GUI module

**G8. Bill tiles over 40 bills are greyed out**
- `gui/src/customer.rs`: `show_withdraw_bills` (tile caption "Over 40 bills",
  new hint), `quote` and `confirm` treat `TooManyBills` like a short bill
  (stay on the Bills screen). (G10 moved the `confirm` part into
  `receipt_choice`.)

**G9. Rate screen wording for the new rule**
- `gui/src/staff.rs`: `check_feed` (hint), `approve_feed` (names each
  currency paused after a big move).
- `gui/ui/staff.slint`: rates tab hint.

**G10. "Would you like a receipt?", then the card before the cash**
- `gui/src/customer.rs`: `confirm` asks about a receipt before any money
  moves; new `receipt_choice`, `return_card`, `take_card`, `take_cash`;
  `connect` (four new callbacks); `result_sum`, `receipt_lines` (no balance
  or reference without a receipt). A withdrawal ends the session, then shows
  "Please take your card", then "Please take your cash", then the receipt if
  asked for (SEv3 §3.2.1).
- `gui/src/main.rs`: screens `RECEIPT_ASK`, `TAKE_CARD`, `TAKE_CASH`;
  `State.cash_out`, cleared in `end_all_sessions`.
- `gui/ui/bank.slint`: `result-final`, `cash-bills`, `receipt-choice`,
  `take-card`, `take-cash`, `finish`.
- `gui/ui/customer.slint`: new `ReceiptAskScreen`, `TakeCardScreen`,
  `CashStack`, `TakeCashScreen`; `BankCard` caption properties;
  `ResultScreen` "Done" button. `gui/ui/app.slint` shows the new screens.

The command line still prints a receipt after every transaction; the receipt
question and card return are GUI screens.

## Docs

- Tests: 95 (+1 with `--features demo`, +1 with `--features online-rates`)
  plus 4 compile-fail checks.
- New `docs/USER_GUIDE.md`: the user manual, step by step with screenshots
  for every role; README sections 3-4 now point to it.
- README, TEST_PLAN, THREAT_MODEL, VULNERABILITIES, DESIGN_DECISIONS,
  COURSE_MAPPING and FEATURES_AND_SECURITY_CHECKLIST updated; new screenshots
  `receipt-question.png`, `take-card.png`, `take-cash.png`,
  `rate-big-move-paused.png`; refreshed `withdraw-bills.png`,
  `withdraw-fee-breakdown.png`, `rate-feed-review.png`.

# Changes in 0.5.0

Realism round: daily limits like a real bank's, charges shown added up, and a
daily exchange-rate check that a teller approves. Same step-by-step rule as
before: each step was built and fully tested (`cargo test` with and without
`--features demo`, clippy on every feature set, fmt) before the next started.
L, F and R steps change the core library (`src/`); G steps change only the GUI
module (`gui/`). The database layout is unchanged (version 5), but an existing
database keeps its old limits: delete `atm-demo.*` for a fresh demo bank.

## Core library

**L1. Realistic daily limits and teller approval caps**
- `db.rs`: `insert_defaults` now sets $1,000 withdrawal, $10,000 deposit (the
  US cash-reporting line) and $5,000 transfer per day (was $500 / $5,000 /
  $2,000); `Limit::max_raise` is +$4,000 withdrawal, +$40,000 deposit,
  +$20,000 transfer per account per day (was +$3,000 / +$10,000 / +$10,000).
- Youth caps ($100 / $50) and the hold-rule amounts are unchanged.
- Tests updated for the new amounts in `admin.rs`, `cash.rs`, `customer.rs`
  and `family.rs` (no new tests; same checks, bigger numbers).

**F1. Charges shown as a sum; fee rules and rate in small print**
- `fx.rs`: new `SumLine`, `Conversion::summary` (Withdrawal or Deposit,
  "+ fee" or "− fee" rows, "Fees $0.00" when there are none, Total, then
  "Charged to your account" or "Added to your account" for other currencies),
  `Conversion::fine_print`, `FeeRule::short` ("3% or $3.00, whichever is
  higher"); `Conversion::breakdown` now prints the summary as text. The money
  math is unchanged.
- `customer.rs`: `Receipt.breakdown` replaced by `Receipt.summary` and
  `Receipt.fine_print`; `receipt`, `check_withdrawal` doc.
- `ui.rs`: `print_receipt`.
- Tests: summary rows and fine print in `fx.rs`; the euro and other-bank
  receipt tests in `customer.rs` check the new rows.

**F2. A shared fee rule is named once ("Each fee: ...")**
- `fx.rs`: `Conversion::fine_print`; test updated.

**R1. Daily rate feed, network-free part**
- New `rate_feed.rs`: `FEED_SOURCE`, `FEED_URL`, `FEED_CREDIT`,
  `FEED_MAX_BYTES`, `Feed`, `RateCheck`, `parse` (strict: result "success",
  base USD, published within 48 hours and not in the future, size cap, numbers
  through the same fixed-point parser as typed rates), `check` (now / feed /
  will set / note per currency), `approve` (recomputes inside one transaction
  and refuses if it differs from what the teller saw), `plan`, `change_text`;
  tests `a_feed_is_read_strictly`,
  `approving_a_feed_sets_rates_through_the_cap_and_logs_the_source`,
  `a_paused_currency_takes_the_new_rate_but_stays_paused`.
- `fx.rs`: `set_rate` split so the feed uses the same checks: new
  `store_rate` (MAC, history, log line), `allowed_band`, `recent_rates`
  (taken out of `check_change_cap`); `read_rate`, `rate_text`, `parse_fixed`,
  `Currency::plausible`, `check_change_cap` made `pub(crate)` (no logic
  change).
- `lib.rs`: `pub mod rate_feed`. `Cargo.toml`: `serde_json`.

**R2. One HTTPS fetch, behind cargo feature `online-rates`**
- `rate_feed.rs`: new `fetch` (fixed URL, HTTPS only, rustls with the built-in
  Mozilla root list, no redirects, 10-second timeout, 64 KB cap).
- `Cargo.toml`: optional `ureq` (rustls only), feature `online-rates`. The
  default build has no network code.

**R3. Command line: rates menu option 8 (online-rates builds)**
- `ui.rs`: `rates_menu`, new `check_feed` (fetch, table, credit, approve?).

**R4. Feed failures get their own plain message**
- `error.rs`: new `AtmError::FeedUnavailable` ("... Rates are unchanged; you
  can still type a rate.").
- `rate_feed.rs`: `fetch`, `parse_at` use it.

**R5. A failed rate check is logged with its reason; an untrusted certificate has its own message**
- `audit.rs`: new `Action::RateFeedFailed` ("rate_feed_failed"; the teller's
  audit log shows "Rate feed failed").
- `rate_feed.rs`: `fetch` now takes the `Atm` (to log) and is split into
  `download` (the request) and new `failure` (names each failure: couldn't
  reach, certificate not trusted, not in the expected form) and
  `read_logged` (parse, and log any failure); `parse_at` uses the shared
  message. Tests `a_failed_check_is_logged_with_its_reason_and_changes_nothing`
  and, with `--features online-rates`,
  `each_kind_of_fetch_failure_gets_its_own_message`.
- `ui.rs`: `check_feed` passes the `Atm`. The GUI's one call site
  (`gui/src/staff.rs` → `check_feed`) changed the same way in this commit, so
  every commit builds.

## GUI module

**G6. Confirm and receipt screens show the sum in two columns**
- `gui/src/customer.rs`: new `ask_confirm_sum`, `result_sum`, `set_sum`;
  `quote` (withdraw confirm), `confirm_deposit`, `ask_confirm`, `result`,
  `confirm` (receipt), `receipt_lines` (no longer repeats the charges),
  `refresh_account_header` (fee note uses `FeeRule::short`).
- `gui/ui/bank.slint`: struct `SumRow`; `sum-rows`, `sum-note`.
- `gui/ui/customer.slint`: new `SumTable`; `ConfirmScreen`, `ResultScreen`.

**G7. Teller "Check today's rates", then approve or cancel**
- `gui/src/staff.rs`: new `check_feed`, `approve_feed`; `connect` (three new
  callbacks), `teller_tab_with` (review shown only on the rates tab).
- `gui/src/main.rs`: `State.rate_feed`; `end_all_sessions` clears it.
- `gui/ui/bank.slint`: `rate-feed-shown`, `rate-feed-hint`,
  `rate-feed-credit`, `rate-feed-rows`, `rate-check-feed`,
  `rate-approve-feed`, `rate-cancel-feed`.
- `gui/ui/staff.slint`: rates tab review table (Currency / Now / Today's feed /
  Will set / Note), credit line, Cancel and "Approve these rates", "Check
  today's rates" button; daily-limit approval hint shows the new caps.
- `gui/Cargo.toml`: the GUI turns on `online-rates`.

## Docs

- Tests: 92 (+1 with `--features demo`, +1 with `--features online-rates`)
  plus 4 compile-fail checks.
- README, TEST_PLAN (new section 8 for the rate check), THREAT_MODEL,
  VULNERABILITIES, DESIGN_DECISIONS, COURSE_MAPPING and
  FEATURES_AND_SECURITY_CHECKLIST updated; new screenshot
  `rate-feed-review.png`, refreshed `withdraw-fee-breakdown.png` and
  `exchange-rates.png`.

# Changes in 0.4.0

Each step was built and fully tested (`cargo test`, with and without
`--features demo`, plus clippy and fmt) before the next one started.
B steps change the core library (`src/`); G steps change only the GUI module
(`gui/`). Upgrading: delete old `atm.db`, `atm.key` and `atm-demo.*` first
(database layout version 5).

## Core library

**B1. Card and account numbers encrypted at rest; logs name cards by id + last 4**
- `db.rs`: schema version 5 (`cards`: `card_lookup`, `card_enc`, `card_last4`;
  `accounts`: `account_lookup`, `account_enc`, `account_last4`); new `Number`,
  `lookup`, `seal_number`, `open_number`, `last4`, `card_ref`; `account_id`,
  `holder_name`, `holder_dob`, `seal_holder` now keyed by the lookup hash.
- `keys.rs`: `Keys` gains a lookup key; new `lookup_hash`.
- `admin.rs`: new `insert_account`; `fresh_number`, `insert_card`,
  `open_adult_account`, `open_youth_account`, `add_joint_holder`,
  `add_guardian`, `list_accounts`, `locked_cards`, `unlock_card`.
- `auth.rs`: `login_customer`, `CardRow`, `CustomerSession::actor`.
- `audit.rs`: `recent`, `for_account`, `verify_chain`, `reconcile_balances`.
- `customer.rs`: `balance`, `transfer`, `recipient_hint`, `change_pin`.
- `family.rs`: `my_youth_accounts`. `demo.rs`: `seed`.
- New tests: `card_and_account_numbers_are_stored_encrypted`,
  `logs_name_cards_by_id_and_last_four_only`,
  `copying_one_rows_encrypted_number_onto_another_is_detected`.

**B2. Each fee is the higher of a percent or a minimum (default 3% or $3); charges itemised**
- `fx.rs`: new `Fee`, `FeeRule`, `FeeLine`, `MAX_FEE_MINIMUM`, `fee_rule_of`,
  `fee_rule`, `set_fee_rule`, `Conversion::plain`, `Conversion::breakdown`,
  `rate_line`; removed `fee`, `set_fee`, `atm_fee`, `set_atm_fee`,
  `guest_fee`, `fee_bp`, `note`, `MAX_ATM_FEE`.
- `db.rs`: `EXCHANGE_FEE_KEYS`, `OTHER_BANK_FEE_KEYS` replace `FEE_KEY`,
  `ATM_FEE_KEY`; `insert_defaults`.
- `customer.rs`: `atm_fee_for`, `withdraw`, `precheck_withdrawal`,
  `preview_deposit`, `deposit`, `AccountInfo`, `Receipt`.
- `ui.rs`: `show_balance`, `withdraw`, `print_receipt`, `rates_menu`.
- New test: `each_fee_is_the_higher_of_the_percent_and_the_minimum`.

**B3. Over the daily limit: "see a teller", who can approve more for today**
- `error.rs`: `AtmError::LimitExceeded` gains `see_teller`.
- `audit.rs`: `Action::WithdrawalLimitRaised`, `DepositLimitRaised`,
  `TransferLimitRaised`.
- `db.rs`: `Limit::raised_action`, `Limit::max_raise`.
- `admin.rs`: new `raise_limit_today`.
- `customer.rs`: `LimitStatus` (`approved_today`), `limit_status`,
  `check_daily_limit`.
- `ui.rs`: `admin_menu`, new `raise_limit`, `show_limits`.
- New tests: `a_teller_can_approve_more_than_the_daily_limit_for_today_only`,
  `youth_and_other_bank_accounts_cannot_have_limits_raised`.

**B4. Suspicious-activity holds (6 rules, worked out from the signed log)**
- New `review.rs`: `Move`, `Screen`, `hold_reason`, `check_not_held`,
  `screen`, `matched_rule`, `count_out`, `last_teller_contact`, `Hold`,
  `holds`, `release_hold` and 4 tests.
- `error.rs`: `AtmError::OnHold`. `audit.rs`: `Action::HoldPlaced`,
  `HoldReleased`. `lib.rs`: `pub mod review`.
- `customer.rs`: `AccountInfo.on_hold`, `account_info`, `precheck_withdrawal`,
  `withdraw`, `transfer`.
- `ui.rs`: new `review_holds`; `admin_menu`, `customer_menu`, `show_balance`.

**B5. Guardian moves money into and out of a linked child's account**
- `family.rs`: new `Direction`, `FamilyMove`, `move_money` and test
  `guardian_moves_money_in_and_out_of_the_childs_account_only`.
- `customer.rs`: `balance_of`, `currency_of`, `not_guest`, `is_frozen`,
  `check_daily_limit`, `debit`, `credit` made `pub(crate)` (no logic change).
- `ui.rs`: new `family_move`.

**B6. Recent payees ("send again"), newest first, up to 5**
- `customer.rs`: new `RECENT_PAYEES`, `RecentPayee`, `recent_payees`,
  `bank_date`, `holder_initials` (split out of `recipient_hint`); tests
  `recent_payees_are_newest_first_without_repeats_and_capped_at_five`,
  `a_guardian_taking_money_back_is_not_a_payee_of_the_child`.
- `db.rs`: new `customer_actor`; `auth.rs` uses it.
- `ui.rs`: new `pick_destination`; `transfer`.

**B7. Yen demo customer; no repeated currencies**
- `demo.rs`: `YUKI` replaces `MAX`; `PEOPLE`; demo test checks the yen charge
  and that no currency repeats.

## GUI module

**G1. Fee breakdown line by line; teller sets percent and minimum for both fees**
- `gui/src/customer.rs`: withdraw and deposit confirm, `receipt_lines`,
  balance fee note. `gui/src/staff.rs`: `save_fee` (one for both fees),
  rates loader; `save_atm_fee` removed.
- `gui/ui/bank.slint`: `rate-fee-min`, `rate-atm-fee-min`, `save-fee` and
  `save-atm-fee` take a percent and a minimum. `gui/ui/staff.slint`: rates tab
  fee rows. `gui/ui/customer.slint`: confirm card width.

**G2. Teller "Holds and approvals" tab; customer sees hold notice and approved extra**
- `gui/src/staff.rs`: `tab::HOLDS`, new `release_hold`, `raise_limit`;
  accounts list marks ON HOLD. `gui/src/customer.rs`: `set_on_hold`, limits
  table shows "+ approved today".
- `gui/ui/bank.slint`: `on-hold`, `hold-rows`, `raise-kind`, `release-hold`,
  `raise-limit`. `gui/ui/staff.slint`: nav item and tab 8.
  `gui/ui/customer.slint`: menu hint.

**G3. Guardian "Move money" and "Send again" buttons**
- `gui/src/customer.rs`: new `send_again`, `youth_move`; transfer action loads
  recent payees; history marks guardian moves. `gui/src/main.rs`:
  `State.recent`, `open_entry`, `end_all_sessions`.
- `gui/ui/bank.slint`: `entry-choices`, `entry-choice`, `youth-move`.
  `gui/ui/customer.slint`: EntryScreen buttons, FamilyScreen Move money row.

**G4. Screenshots, README; family history column widths**

**G5. Teller audit view names a card once ("card 7 ending 1234")**
- `gui/src/staff.rs`: `who`.

## Docs

- New `docs/TEST_PLAN.md` (manual tests with expected results).
- README, THREAT_MODEL, VULNERABILITIES, DESIGN_DECISIONS, COURSE_MAPPING and
  FEATURES_AND_SECURITY_CHECKLIST updated for the above.
