# Study guide: Bank of CCNY ATM

One page per rubric line, for the demo and the oral exam. Each point names
the file and function to open, so anyone in the group can show the code.
Details live in the other docs; this guide says where.

| Rubric line | Points | Where to look |
|---|---|---|
| Installation | 5 | [Install](#installation) |
| Functional requirements | 15 | [Functional](#functional-requirements) |
| Additional feature | 5 | [Additional feature](#additional-feature) |
| Time | 5 | [Demo script](#demo-script-10-minutes) |
| Design justification | 10 | [Design](#design-justification) |
| Threat model / STRIDE | 20 | [STRIDE](#threat-model-stride) |
| Security mitigations with code | 15 | [Mitigations](#security-mitigations-with-code) |
| Code comprehension | 10 | [Code map](#code-comprehension) |
| Collaboration | 5 | [Collaboration](#collaboration) |
| Preparedness | 5 | [Likely questions](#likely-questions) |
| User guide | 5 | [USER_GUIDE.md](USER_GUIDE.md) |

---

## Installation

- Prerequisites: Rust 1.92+, a C compiler, and on Linux `libfontconfig1-dev`
  ([README §1](../README.md#1-install)).
- One command: `cargo run --profile quick -p atm-gui --features demo -- --demo`
  (the README's Quick start). The `quick` profile in `Cargo.toml` optimizes
  only the crypto, so it compiles about a third faster than `--release`. The first build is the slow part (the GUI
  toolkit); later runs start at once.
- `Cargo.lock` pins every library version, so every machine builds the same
  code. `--locked` makes Cargo refuse to change it.
- If the professor installs it: give them the README's Quick start. The
  command line alone builds in about a minute (`cargo build --release`).

## Functional requirements

Each line of the handout's §5.1, and where it is:

| Requirement | Code |
|---|---|
| Customer signs in with card + PIN | `auth::login_customer` |
| Balance, withdraw, deposit, transfer | `customer::balance`, `withdraw`, `deposit`, `transfer` |
| Bills $5 to $100, 40-bill cap | `dispense::plan_withdrawal` |
| Daily limits | `customer::check_daily_limit`, `db::Limit` |
| Change PIN | `customer::change_pin` |
| Teller Admin: open, freeze, close, unlock, view log | `admin::create_customer`, `set_frozen`, `close_account`, `unlock_card`, `recent_audit` |
| Cash Handler: view, restock, remove | `cash::view`, `restock`, `remove_excess` |
| 3 wrong PINs lock the card | `auth::login_customer` |
| Idle timeout (2 minutes) | `auth::IDLE_TIMEOUT` |
| Everything logged | `audit::append` |

The full list with screenshots is in
[FEATURES_AND_SECURITY_CHECKLIST.md](FEATURES_AND_SECURITY_CHECKLIST.md).

## Additional feature

**Joint and youth (family) accounts.** Two adults share one account, each
with their own card and PIN. A youth account has a guardian who sets caps,
can freeze it, and moves money in or out from the **Family** screen.

- Code: `admin::add_joint_holder`, `open_youth_account`, `add_guardian`;
  `family::set_controls`, `set_frozen`, `move_money`.
- Security angle: adding a holder or guardian decides who can spend someone's
  money, so one teller can't do it alone. The current holder types their own
  card and PIN at the counter (`auth::confirm_at_counter`, type
  `auth::CardAndPin`).

Smaller extras: cards from other banks with an ATM fee and currency
conversion, receipts, Send again, holds on unusual activity, teller approval
for larger amounts, and the out-of-service mode.

## Design justification

Each in one line; the full reasons are in
[DESIGN_DECISIONS.md](DESIGN_DECISIONS.md).

- **Rust:** required, and memory safe. `#![forbid(unsafe_code)]` in
  `src/lib.rs` bans unsafe code anywhere.
- **SQLite:** one file, transactions (money and its log entry commit together
  or not at all), CHECK constraints, triggers, no server to secure.
- **One core library, thin front ends:** the GUI and the command line hold no
  rules. Every rule is in `src/`, so it is checked once for both.
- **Sessions as types:** `CustomerSession`, `AdminSession`, `HandlerSession`.
  An admin function takes `&AdminSession`, so the compiler refuses a
  customer session there.
- **Money as integer cents** (`money::Cents`): no floats, no negatives,
  checked math, so no rounding or overflow tricks.
- **US dollar accounts only:** the bank's own accounts are USD. Other banks'
  cards may be in another currency and are converted at the day's rate.
- **One ATM, not many:** syncing ATMs at several branches is optional in the
  handout. DESIGN_DECISIONS §30 says how it would work (a central server,
  one key per ATM, TLS) and why it was left out.
- **No dual control (two admins):** see [Likely questions](#likely-questions).

## Threat model (STRIDE)

The full model is [THREAT_MODEL.md](THREAT_MODEL.md): assets, data flows,
adversaries (customers, outsiders with the files, insiders), then STRIDE.

| Threat | Example attack | Defense | Code |
|---|---|---|---|
| **S**poofing | Guess a PIN; reuse a stolen card | Argon2id PIN check, 3-try lock, unlock once a day | `auth::login_customer`, `admin::unlock_card` |
| **T**ampering | Edit a balance in `atm.db` | Whole-database HMAC seal; balances recomputed from the signed log | `seal::check`, `audit::verify` |
| **T**ampering | Put an older `atm.db` back | `atm.anchor` remembers the newest seal | `anchor::Anchor::read` |
| **R**epudiation | "I never withdrew that" | HMAC-chained log, written in the same transaction as the money | `audit::append`, `audit::verify_chain` |
| **I**nformation disclosure | Steal `atm.db` and read names, crack PINs | AES-256-GCM on names, dates, numbers; PIN hashes keyed with a secret in `atm.key` | `keys::seal`, `auth::hash_secret` |
| **D**enial of service | Lock other people's cards; guess staff passwords | Lock only after 3 tries; staff pauses double up to 15 minutes | `auth::staff_cooldown_secs` |
| **E**levation of privilege | A front end calls SQL or forges an admin session | Private connection; sessions only come from a login; 5 compile-fail checks | `src/lib.rs` doc tests |

Comments starting `STRIDE (...)` in the code mark each defense; there are
about 60. `grep -rn "STRIDE" src` lists them.

**Phase II (other groups change our code).** In Phase II another group may
add malicious code (a backdoor), not only look for bugs. What makes that
harder or visible:

- `#![forbid(unsafe_code)]`: no memory tricks.
- The trust boundary is checked by the compiler: a front end can't reach the
  database. A backdoor has to be in `src/`, where the rules are.
- 155 tests and 26 attack tests: a change that weakens a rule usually breaks
  one. Run `cargo test` after any change.
- The integrity check at every Teller sign-in recomputes balances and cash
  from the signed log; money created outside the rules takes the ATM out of
  service.
- `Cargo.lock` + `--locked`: a new library can't sneak in unnoticed.
- To check a changed copy: `diff -r` against our submitted zip, then read
  every changed line in `src/`.

## Security mitigations with code

The snippets most likely to be asked about. Open the file, find the
function, explain it in two sentences.

| # | What | File: function |
|---|---|---|
| 1 | PIN hash: Argon2id, keyed per card | `auth.rs: hash_secret`, `check_pin`; `keys.rs: credential_key` |
| 2 | Same time for a wrong card as a wrong PIN | `auth.rs: burn_time_like_a_real_check` |
| 3 | 3-try lock | `auth.rs: login_customer` |
| 4 | Staff password pauses | `auth.rs: login_staff`, `staff_cooldown_secs` |
| 5 | Field encryption with AES-256-GCM | `keys.rs: seal`, `unseal`, `aad` |
| 6 | Find a card without storing its number | `keys.rs: lookup_hash`; `db.rs: lookup` |
| 7 | Chained audit log | `audit.rs: append`, `row_mac`, `verify_chain` |
| 8 | Recompute balances and cash from the log | `audit.rs: reconcile_balances`, `reconcile_cash` |
| 9 | Seal over the whole database | `seal.rs: digest`, `check`, `write` |
| 10 | Rollback refused | `anchor.rs: read`, `advance`; `lib.rs: catch_up_anchor` |
| 11 | Every action re-checks its session | `auth.rs: begin_for`, `admit` |
| 12 | Money can't go negative or overflow | `money.rs: Cents::new`, `checked_add`, `checked_sub` |
| 13 | Daily limits | `customer.rs: check_daily_limit` |
| 14 | Holds on unusual activity | `review.rs: screen`, `matched_rule` |
| 15 | Out of service on a failed check | `service.rs: check_at_sign_in`, `out_of_service` |
| 16 | Holder agrees with their own card and PIN | `auth.rs: confirm_at_counter` |
| 17 | Rates can't be slipped in | `fx.rs: set_rate` (5% in 24 h); `rate_feed.rs: parse_at`, `approve` |
| 18 | Database rules even if the code is bypassed | `db.rs`: STRICT tables, CHECK constraints, append-only triggers |

The list of every attack we considered, its defense and status is
[VULNERABILITIES.md](VULNERABILITIES.md). Where each choice comes from in the
course is [COURSE_MAPPING.md](COURSE_MAPPING.md).

## Code comprehension

Read the code in this order; it follows one withdrawal from start to end.

1. `src/lib.rs`: `Atm::open` opens the database, loads the key, checks the
   seal and anchor.
2. `src/auth.rs`: `login_customer` finds the card by its HMAC, checks the
   PIN, counts failures, returns a `CustomerSession`.
3. `src/customer.rs`: `withdraw` starts a transaction with `begin_for`,
   checks freeze, hold, limit and balance, plans the bills, debits the
   account, writes the log entry, commits.
4. `src/audit.rs`: `append` adds the log row with its HMAC chained to the
   previous one.
5. `src/lib.rs`: `Tx::commit` writes the new seal and advances the anchor.
6. `gui/src/customer.rs`: the GUI only calls `customer::withdraw` and shows
   the result.

Every source file starts with a short comment saying what it does, and the
main functions have a one-line comment above them.

## Collaboration

- Two members wrote the core separately; the best of each was merged, then
  joined with the GUI (built by the other members).
- A teammate's hardening branch (sealed database, anchor, session binding)
  was reviewed and merged in 0.7.0.
- [CHANGES.md](../CHANGES.md) lists every change, function by function, by
  version.

The oral exam asks each member. Fill in before demo day:

| Member | What they built or wrote |
|---|---|
| | |
| | |
| | |
| | |

- **What worked:** _(for example: separate core and GUI, so each could be
  changed and tested alone)_
- **What we'd improve in Phase II:** _(for example: split work earlier,
  review each other's code weekly)_

## Demo script (10 minutes)

Split evenly. Each part is about 2½ minutes; with 3 speakers, merge parts 3
and 4. Build beforehand, start with a fresh demo bank (`rm atm-demo.*`),
and open the [demo logins](USER_GUIDE.md#demo-logins) on screen (no notes
are allowed on demo day; the user guide is part of the submission).

**1. Customer (2½ min).** `cargo run --profile quick -p atm-gui --features demo -- --demo`.
Click Sam's card, PIN 9512. Balance, withdraw $60 in mixed bills (receipt,
card back before cash), deposit, then transfer to a demo payee from the
list. Click Lou's card to show that a locked card is refused.

**2. Additional feature (2½ min).** Pat (1357): Family screen, set Kid's cap,
freeze and unfreeze. Kid (2580): try more than the cap, refused. Ray (2468):
other bank's card pays an ATM fee.

**3. Teller Admin (2½ min).** Badge `teller`. Open an individual account,
unlock Lou's card with **Choose**, freeze an account, view the audit log.
Show that a joint holder needs the current holder's card and
PIN.

**4. Security (2½ min).** Cash Handler restock. Then the integrity test:
`cargo run --profile quick -p atm-gui --features integrity-test -- --demo --break-integrity`,
sign in as teller, show the red banner and out-of-service screen. Close with
the STRIDE table above.

## Likely questions

**Why Argon2id and not SHA-256 for PINs?** A 4-digit PIN has 10,000 values;
SHA-256 tries them all instantly. Argon2id is slow and memory-hard (textbook
SEv3 §3.4.9.1), and the hash is keyed with a secret from `atm.key`, so a
stolen database alone can't be cracked.

**What if someone steals `atm.db`?** Names, dates and numbers are encrypted;
PIN hashes need `atm.key`. Without the key the file is useless.

**What if someone steals `atm.db` and `atm.key`?** That is the bank's root
secret; THREAT_MODEL §7 lists it as an accepted risk. A real bank keeps the
key in a hardware security module.

**What if someone edits a balance?** The seal fails, so the next action is
refused ("TAMPERING DETECTED"). If they re-seal with the key, the next Teller
sign-in recomputes balances from the signed log and takes the ATM out of
service.

**What if someone edits a value in the running program's memory?** Outside
our model (THREAT_MODEL §6): we assume the ATM's computer is not under the
attacker's control. Even so, the core re-checks limits, holds and balances
inside the transaction, not from values the screen holds.

**Why no two-admin approval (dual control)?** It needs a second staff role
and an approval queue for every sensitive action. We chose a cheaper control
with the same goal: actions that change who can spend money need the
customer's own card and PIN, and everything a teller does is in the signed
log. Listed as a known limit in THREAT_MODEL §7 (textbook SEv3 §12.2.4).

**Aren't there hard-coded passwords in `demo.rs`?** Only in the demo build
(`--features demo`), for sample data. The normal build doesn't contain that
file's code, so it has no built-in passwords: first-run setup makes the
staff create their own. A demo database is marked as demo data and refused
as a real bank (`tests/demo_mode.rs`).

**Why one ATM?** The handout makes multi-ATM sync optional.
DESIGN_DECISIONS §30 describes the design we would use.

**How do you know a front end can't skip a check?** The database connection
is a private field; sessions can only come from a login. `src/lib.rs` has 5
code samples that try, and `cargo test` checks that each fails to compile.

**Was an AI used?** The professor allowed it. The GUI was generated with an
LLM; the group designed and justifies the backend, the security features and
the threat model, and can explain any line of `src/`.
