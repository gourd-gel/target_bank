# Threat model: Bank of CCNY ATM

Method, as taught in Lecture 1:

1. **Policy**: what must the system guarantee?
2. **Assets and data flows**: what is worth attacking, and where does it travel?
3. **Incentives**: who is involved, and what do they want?
4. **Mechanisms**: STRIDE, threat by threat, each one tied to the property it
   protects. Every defense names the code that implements it and the test
   that proves it.
5. **Assurance**: can we be sure it works?

Sections 6 and 7 list what we assume and what is **not** defended, on
purpose. [`VULNERABILITIES.md`](VULNERABILITIES.md) goes attack by attack in
more depth. [`COURSE_MAPPING.md`](COURSE_MAPPING.md) ties each mechanism to
its lecture, lab or textbook section.

---

## 1. Policy

Each line is one STRIDE property (Lecture 1, slides 24-31).

| Property | Policy |
|---|---|
| Authentication (against **S**poofing) | Only someone with a card and its PIN can use that card, and no card is accepted while the bank has frozen its account. Only staff with their own password can use a staff role. A teller can't add a joint holder or a guardian without that holder typing their own card number and PIN |
| Integrity (against **T**ampering) | Money is never created or lost. Every balance equals its signed history; the cash count matches what was paid in and out. Limits, fees, exchange rates, teller approvals and holds can't be changed outside the program, and one teller can't bend a rate or a limit far enough to make real money; unbacked starting balances are capped per teller per day. Nothing edited in the bank's files outside the program is ever used, and an older copy of the records is refused: the ATM stops instead. A rate from the internet is only a proposal: nothing changes until a teller approves it, and a currency that moved more than 5% in a day is then paused until a teller checks it and resumes. A typed rate can move at most 5% in 24 hours |
| Non-repudiation (against **R**epudiation) | Every action can be traced to one card or one staff login, including taking the ATM out of service and putting it back |
| Confidentiality (against **I**nformation disclosure) | PINs and passwords stay secret from everyone, staff included. Personal data and full card and account numbers stay secret from other customers, from anyone reading the log, and from someone who copies the database. Nothing secret leaves the machine: the one outbound request carries no data |
| Availability (against **D**enial of service) | Honest customers can keep using the ATM; one person can't lock everyone out. A hold on unusual activity stops only money leaving that one account. Customers never wait on the network; if the rate feed is down, a teller types the rate. Where availability and integrity clash, integrity wins: altered records, or a failed integrity check, stop the ATM on purpose until someone checks it |
| Authorization (against **E**levation of privilege) | Each role can do its own job and nothing more. A session works only on the bank that issued it, and only while its card, account or staff login is still valid. While the ATM is out of service, only a Teller Admin works |

## 2. Assets and data flows

```
                 ┌─────────────────────────── one computer (the "ATM") ────────────────────────────┐
  Customer ──┐   │                                                                                 │
  Guardian ──┤   │  ┌───────────────┐      ┌────────────────────────────┐      ┌──────────────┐    │
  Guest    ──┤   │  │ GUI (Slint)   │─────▶│  atm library (src/)        │─────▶│  atm.db      │    │
  Teller   ──┼──▶│  │ or CLI        │  ②   │  every rule + every check  │  ③   │ (SQLite,     │    │
  Cash     ──┘ ① │  └───────────────┘      │  holds the only DB handle  │      │  sealed)     │    │
  Handler        │   front ends: display   │  and the one network call; │      └──────────────┘    │
                 │   and input only        │  checks the seal before    │─────▶┌──────────────┐    │
                 │                         │  every operation and       │  ④   │  atm.key     │    │
                 │                         │  moves the anchor after    │      │ (32 bytes)   │    │
                 │                         │  every commit              │      └──────────────┘    │
                 │                         │                            │─────▶┌──────────────┐    │
                 │                         └─────────────┬──────────────┘  ⑥   │  atm.anchor  │    │
                 │                                       │ ⑤ Teller Admin's    │ (newest seal)│    │
                 │                                       │   button only       └──────────────┘    │
                 └───────────────────────────────────────┼─────────────────────────────────────────┘
                                                         │ one HTTPS GET, outbound only
                                                         ▼
                        open.er-api.com (ExchangeRate-API daily rate feed, on the internet)

  Out of scope (simulated): card network ─ Teller registers other banks' cards
                            bank treasury ─ Teller types a rate, or approves today's feed (⑤)
                            card reader / bill slot ─ card number and bill counts are typed
```

A bank is three files that belong together: `atm.db` (the records),
`atm.key` (the one secret) and `atm.anchor` (the newest seal). A new bank is
made only when none of the three exists.

Lecture 1's example diagram states the encryption method and strength on
every link. Ours:

| Link | What crosses it | Protection |
|---|---|---|
| ① Person → keypad / screen | Card number, PIN, staff password, amounts | Local keyboard and screen, no network. PIN and password shown as dots; on the teller's screen they can't be copied out of their fields. Card and account numbers shown as dots plus the last 4 digits (hidden fully in the CLI). Receipts and "Send again" show the last 4 only. Out of service, the start screen takes no card number or PIN at all |
| ② Front end → library | Function calls inside one program | Inside one process, no SQL. Every call needs a session object of the right role (checked by the compiler), issued by this same opened bank and re-checked against the database on every call |
| ③ Library → `atm.db` | Balances, cards, staff, log, settings, rates, cash counts | Local file, owner-only permissions. The whole database is sealed: HMAC-SHA-256 over a change counter and a SHA-256 of every row of every table and the schema, rewritten in the same transaction as every change and checked before every operation, after SQLite's `PRAGMA integrity_check` confirms every index still matches its table. PINs and passwords: Argon2id with a salt and a 256-bit secret key made for that one card or login. Names, birth dates, card and account numbers: AES-256-GCM (256-bit key, random 96-bit nonce). Card and account numbers are found by an HMAC-SHA-256 lookup value; only the last 4 digits are in clear. Log: HMAC-SHA-256 chain; it names a card as `card 7 ending 1234`. Limits, fee rules, rates, rate history: HMAC-SHA-256 per row, compared in constant time. Teller approvals, holds and the out-of-service state: rows in the signed log, no flags. Every table is STRICT |
| ④ Library → `atm.key` | The 256-bit master key, from which the hashing, log, field, record, lookup, seal and anchor keys are derived | Local file, owner-only permissions, read once at start. Its fingerprint in `atm.db` must match. A key without its database is refused, so it can't start a new bank on the old key |
| ⑤ Library → rate feed (outbound only, Teller Admin's button only; GUI, or a CLI built with `online-rates`) | Out: one plain GET of a fixed public URL, `https://open.er-api.com/v6/latest/USD`, with only standard headers (host name, the `ureq` user agent): no key, no cookie, no customer data. Back: about 3 KB of JSON, units per US dollar | TLS 1.2 or 1.3 only (rustls): forward-secret ECDHE key exchange (X25519, P-256 or P-384), AES-GCM or ChaCha20-Poly1305. The server's certificate must chain to one of the Mozilla root certificates built into the program (`webpki-roots`). HTTPS only, no redirects, 10 s limit, 64 KB cap. The reply is only a proposal: strict parse, believable range, teller approval, a pause on any move over 5% in a day, then the same HMAC and signed log as a typed rate. Only `fetch` can make a feed, so no front end can supply its own |
| ⑥ Library → `atm.anchor` | The newest seal: its counter and MAC, with an HMAC-SHA-256 tag (anchor key from `atm.key`) | Local file next to `atm.db`, owner-only permissions. Written to a temporary file, then renamed, so a crash never leaves half a line. Read at start; moved forward after every commit, never back. If it can't be written, the committed change stands and the ATM does nothing else until the anchor is written. An older `atm.db`, or an edited or missing anchor, is refused |

**Trust boundaries**
1. **Person → machine.** Anyone can walk up and type. Nothing typed is
   trusted. While the ATM is out of service, nothing is taken from a
   customer: the start screen asks for no card number and no PIN.
2. **Front end → library.** The GUI and CLI are treated as untrusted callers.
   They hold an `Atm` (no database handle) and must present a session for
   every action. The compiler enforces the session types, and that only
   `rate_feed::fetch` can make a rate feed (`src/lib.rs`, 5 compile-fail
   tests). A front end that opened `atm.db` on its own would break the seal
   (boundary 3).
3. **Library → database file.** The file can be copied or edited by anyone with
   disk access. Secrets in it are hashed or encrypted. Any change made
   outside the program breaks the seal (or, for an index, SQLite's own
   integrity check), and the program refuses before it reads anything from
   the file.
4. **Library → key file.** The one secret. Owner-only permissions; a database
   without its key refuses to open, and a key without its database doesn't
   start a new bank.
5. **Library → internet (rate feed).** Only outbound, only when a Teller
   Admin presses **Check today's rates**. Nothing listens on a port, so
   nothing on the network can start a conversation with the ATM. The reply
   is untrusted input: TLS proves who sent it, and the rate rules decide
   whether any of it is used.
6. **Library → anchor file.** Not secret, but it must never go backward: it
   is what makes an older `atm.db` stand out. Here it sits next to `atm.db`,
   so someone who puts back an older copy of both files gets past it (§7).

**Data flow**: login (card + PIN, or staff ID + password) → session object,
tied to this opened bank → actions. Each action first passes `Atm::admit`
(same bank, not idle, card not locked, account not closed or frozen by the
bank, staff login still there; a customer's or Cash Handler's session also
stops while the ATM is out of service). It then opens one IMMEDIATE SQLite
transaction with `Atm::begin`, which runs SQLite's integrity check, checks
the seal and refuses a counter lower than one already seen. Customer,
guardian and Cash Handler changes use `Atm::begin_for`, which repeats the
session checks inside the write lock, so a halt, lock, closure or freeze
that another process committed while this one waited still stops it. The
transaction changes balances, cash and the audit log together, or not at
all. Its commit writes the new seal in the same transaction, then moves
`atm.anchor` forward; if the anchor can't be written, the change still
stands and is reported as done, and the next operation writes the anchor
first or refuses. Screens that only show data use `Atm::read`, which checks
the seal too. Withdrawals, transfers and guardian moves also pass the
activity check (`review.rs`) inside that transaction. A refused attempt
moves no money but still commits its hold row.

**Teller sign-in** (`service.rs`): every Teller Admin sign-in runs the full
integrity check (`audit.rs` → `verify`): the log chain; every balance
against the log; the cash in the machine against every restock, deposit,
withdrawal and removal; the signed settings and rates; and each daily
limit, exchange rate, bank freeze, guardian freeze and closure against its
newest log entry (a rate against its newest rate-history row, with a log
entry for every history row). After the chain, every check runs and
every failure is listed, accounts by their last 4 digits only. If anything
fails, the ATM takes itself out of service, logged as "system". Out of
service, the start screen says "Out of service" and takes no card (the GUI
re-checks every 5 seconds, the CLI before each card); live customer and
Cash Handler sessions stop; the Cash Handler can't sign in; only a Teller
Admin can, to review and resume. The teller screen shows a red banner with
**Resume service**, and Sign out stays on screen. A teller can also **Halt
ATM** by hand (Data integrity tab; CLI menu option 18). Resume runs the
check again and logs its result. The state is the newest `service_halted`
or `service_resumed` entry in the signed log.

**Rate check** (`rate_feed.rs`): Teller Admin presses **Check today's
rates** → `fetch` (one HTTPS GET) → `parse` (strict; private, so only
`fetch` can make a feed) → `check` shows Now, Today's feed, Will set and
Note for every currency and changes nothing → the teller approves or
cancels → `approve` recomputes the plan inside one
IMMEDIATE transaction, refuses if it differs from what was shown, and
stores each rate with its HMAC and a signed log line. A currency that moved
more than 5% in 24 hours is set but paused (its own log line) until a teller
checks it against another source and resumes.

**Assets.** Properties: **C** confidentiality, **I** integrity, **A**
availability, **Au** authenticity, **NR** non-repudiation.

| Asset | Where | Needs | Why it matters |
|---|---|---|---|
| Account balances | `accounts.balance_cents` (0 to `Cents::MAX`) | I, A | It's the money |
| Cash in the machine | `cash_inventory` table | I | Physical money; wrong counts = theft or failed payouts |
| PINs and staff passwords | Argon2id hashes in `cards`, `staff`, each keyed for its own card or login | C, I | Whoever has them is that person |
| Customer personal data (name, date of birth) | `cards.name_enc`, `cards.dob_enc` (encrypted) | C, I | Privacy; DOB also blocks birthday PINs |
| Card and account numbers | `cards.card_lookup`, `card_enc`, `card_last4` (same three in `accounts`); the log only holds `card 7 ending 1234` | C, I | Half of a login; needed to send a transfer; what skimmers and cashout gangs trade in |
| Exchange rates, rate history, fee rules | `exchange_rates`, `rate_history`, `settings` | I, NR | A bent rate or fee moves money without a visible transaction |
| Today's rate feed, while a teller reviews it | in memory only (`rate_feed::Feed`, cleared on logout) | Au, I | A spoofed or wrong feed proposes bad rates |
| Which certificates the program trusts | the Mozilla root list compiled into the GUI (`webpki-roots`) | I | Anyone who can get a trusted certificate for the feed's name can pretend to be the source |
| Sessions (who is logged in) | in memory only, each tied to the opened bank that issued it | Au, I | A session is the permission to act |
| Audit log | `audit_log` | I, NR, A | Proof of who did what. Daily totals, each teller's starting balances for the day, teller approvals, holds, unlocks, recent payees and the out-of-service state are all computed from it. The integrity check compares balances, cash, limits, rates, freezes and closures with it |
| Teller approvals and holds | `audit_log` rows (`*_limit_raised`, `hold_placed`, `hold_released`) | I, NR | A forged approval or a cleared hold lets money out past the checks |
| Bank settings and freezes (daily limits, youth caps, bank and guardian freezes) | `settings`, `accounts` (`frozen`, `guardian_frozen`) | I | Loosening them enables fraud. A bank freeze is the bank's answer to a reported stolen card |
| Demo marker | a row in the `meta` table | I | Keeps demo data (published passwords) from running as the real bank |
| The database seal | `seal` table (counter + HMAC) | I, Au | Proves every row was written by the program; checked before every operation |
| `atm.key` | key file | C, I | Unlocks every other protection, the seal and the anchor included |
| `atm.anchor` | file next to `atm.db` | I, A | Makes an older `atm.db` stand out. Edited or lost, the bank refuses to open |
| The service itself | the program; out of service while the newest `service_halted` / `service_resumed` log row is a halt | A | Customers locked out = no service |

## 3. Incentives: stakeholders and adversaries

| Who | Wants | Can do in the system |
|---|---|---|
| Customer | Their money safe; only they can move it; private balance | Own account only, via card + PIN |
| Joint holder | Same, on a shared account; own card and PIN | Same account, separate lockout and audit identity |
| Guardian (parent) | Control and see a child's spending | Family screen for linked youth accounts only; can move money into the child's account or back to their own, never to anyone else |
| Youth customer | Use their own money within limits | Own account, within caps set by the guardian and bank |
| Guest (another bank's card) | Get cash | Withdraw, balance and limits only; pays the ATM fee |
| Teller Admin | Run accounts, help locked-out customers, set rates, audit | Account management (starting balances capped per account and at $20,000 a day per teller), limits (up to a ceiling), rates (typed, at most 5% a day; or today's feed after review, where a big move pauses the currency), pause, fees (within bounds), unlock (once per card per day), freeze/close, approve a larger amount for today (capped), release activity holds, audit, integrity check, halt and resume service; the only role that can sign in while the ATM is out of service. Adding a joint holder or guardian, or opening a youth account, needs the holder's own card and PIN at the counter. **Cannot** move money, see PINs or change the activity rules |
| Cash Handler | Keep the machine stocked | Cash inventory only, and only while the ATM is in service. **Cannot** see customers or remove cash below the maximum |
| The bank (owner) | No lost money, provable records, legal compliance | Holds `atm.key`; reviews the log and rate history; decides where `atm.anchor` and the backups are kept |
| Rate source (ExchangeRate-API, `open.er-api.com`) | Credit for its free daily data | Publishes the feed. Can't change a rate here by itself: a teller approves, and a move over 5% in a day stays paused until a teller checks it |

Adversaries, grouped as in Lecture 1 ("Who is the adversary?"):

| Type (Lecture 1) | Adversary | Goal | Capabilities |
|---|---|---|---|
| Cybercrime (slide 44: cashout gangs) | Stranger at the machine | Get into someone else's account, then empty it fast | Can type anything; may have seen or stolen a card number and PIN; may watch someone type or pick up a receipt |
| Cybercrime (slide 44: cashout gangs) | Money mule | Take stolen money that was transferred in straight back out | A real account here that can receive transfers |
| Abuse by users | Dishonest customer or guest | Take more than they own or are allowed (overdraw, beat daily limits, double-spend, use a guest card for deposits or transfers, profit from rounding or dodge a fee) | A valid card and PIN; can try odd inputs, race actions, cancel midway, pull the plug |
| Abuse by users | Youth customer | Get around a guardian's caps or freeze | A valid youth card and PIN |
| Abuse by users | Dishonest guardian | Use a child's money to pay someone else | A linked guardian card and PIN |
| Abuse by users | Vandal or ex-partner | Get someone else's account held | Knows an account number; has an account here to send from |
| Insider (slide 45) | Dishonest Teller Admin | Move money, read PINs, set a friendly exchange rate, raise an accomplice's limit or release their hold, add an accomplice to someone's account, hide what they did | Admin login; can see names and dates of birth (card numbers only by their last 4 digits); sets rates and fees; approves larger amounts; releases holds; unlocks cards; halts and resumes service |
| Insider (slide 45) | Dishonest Cash Handler | Take cash from the machine | Handler login; physical access to the cash |
| Insider or thief | Someone with disk access (thief, malware, careless backup) | Read PINs, card numbers and personal data, change balances, rates or fees, clear a hold or a lock, erase the log, put back an older copy, bring first-run setup back | Can copy, read, edit, delete or put back `atm.db` and `atm.anchor`, and sometimes `atm.key` |
| Insider (slide 45: hidden back doors) | Phase II red team | Plant hidden backdoors (now including one that uses the HTTPS client to send data out, or one that changes data through the program, where the seal can't see it) | Full source code; can change it |
| Network (Lecture 4) | Network attacker: rogue Wi-Fi, a fake DNS answer, a proxy that inspects HTTPS | Feed the ATM made-up rates, or block the feed | Can read, change, delay or drop traffic between the ATM and the internet; can't get a certificate the program trusts |
| Third party (Lecture 4, textbook §5.7.4) | Hacked or mistaken rate source; hacked or coerced certificate authority | Publish wrong rates, or a real-looking certificate for the source | Controls what the feed says, or can issue a certificate that chains to a trusted root |
| Third party (Lab 1, question 3) | Malicious library release | Code that runs inside the program | A new version of a crate we use (now also `ureq`, `rustls`, `ring`, `webpki-roots`) |

---

## 4. Mechanisms: STRIDE analysis

Code is cited as `file` → `function`. Tests are in the same file unless
noted. Tests named `a1_...` to `c2_...` are in `tests/review.rs` (one per
hole the security review found in 0.6.0); tests marked *(attacks)* are in
`tests/attacks.rs`; tests marked *(audit)* are in `tests/audit.rs` (exploits
of 0.7.0 that need a real file or the real program, fixed in 0.8.0);
`demo_data_and_real_data_stay_apart` and
`a_broken_balance_is_caught_at_the_next_teller_sign_in` are in
`tests/demo_mode.rs`.

### STRIDE by asset

All six STRIDE categories apply to this ATM, so none is left out. The table
shows which threats apply to each asset from section 2; the tables below
give each threat, its defense, the code and the test.

| Asset | S | T | R | I | D | E | Main defense |
|---|---|---|---|---|---|---|---|
| Account balances | ✓ | ✓ | ✓ | ✓ | | ✓ | Card + PIN login; seal; balances recomputed from the signed log; account comes from the session |
| Cash in the machine | | ✓ | ✓ | | ✓ | ✓ | Cash counts recomputed from the log; restock and removal capped; Cash Handler session only |
| PINs and staff passwords | ✓ | ✓ | | ✓ | | | Argon2id keyed per card or login; 3-try lock; staff pauses |
| Customer personal data | | ✓ | | ✓ | | ✓ | AES-256-GCM; shown only to Teller Admins |
| Card and account numbers | ✓ | ✓ | | ✓ | | | HMAC lookup + AES-256-GCM; last 4 only on screen and in the log |
| Exchange rates and fees | ✓ | ✓ | ✓ | | ✓ | ✓ | MAC'd rows; 5% cap on typed rates; rate history; pause |
| Today's rate feed | ✓ | ✓ | | | ✓ | | HTTPS with certificate check; teller approves; only `fetch` makes a feed |
| Sessions | ✓ | ✓ | | | | ✓ | Only a login makes one; typed by role; idle timeout; tied to the bank |
| Audit log | | ✓ | ✓ | ✓ | ✓ | | HMAC chain; append-only triggers; no full numbers in it |
| Teller approvals and holds | ✓ | ✓ | ✓ | | | ✓ | Rows in the signed log, with the teller's name; capped |
| Settings and freezes | | ✓ | ✓ | | ✓ | ✓ | MAC'd settings; checked against the log at Teller sign-in |
| Database seal, `atm.anchor` | | ✓ | | | ✓ | | Seal checked before every operation; anchor refuses older copies |
| `atm.key` | ✓ | ✓ | | ✓ | ✓ | | Owner-only file; fingerprint must match the database |
| The service itself | | ✓ | | | ✓ | ✓ | Out of service on a failed check; only a Teller Admin resumes; logged |

### S: Spoofing (pretending to be someone else) → Authentication

| Threat | Defense | Code | Test |
|---|---|---|---|
| Guess a customer's PIN at the machine | 3 wrong PINs lock the card. The failure is committed before the error returns, so killing the program doesn't undo it. A locked card isn't even checked against the PIN | `auth.rs` → `login_customer` | `three_consecutive_failures_lock_even_against_the_right_pin` |
| Guess the PIN through Change PIN | A wrong "current PIN" counts toward the same lock and ends the session at 3 | `customer.rs` → `change_pin` | `guessing_the_current_pin_locks_the_card_and_ends_the_session` |
| Guess a staff password | After 3 failures: 60 s pause, doubling each further failure up to 15 min; the count only resets on success; checked before the password. The count and the pause sit in the sealed `staff` row, so resetting them in the file is refused | `auth.rs` → `login_staff`, `staff_cooldown_secs` | `staff_cooldown_after_three_failures`, `staff_pauses_grow_and_are_capped`, `a6_resetting_staff_columns_does_not_remove_the_password_pause` |
| Default or hard-coded passwords | None exist. First-run setup creates the staff logins and works only on a bank with no staff and no log entries, in one transaction | `auth.rs` → `first_run_setup`; `db.rs` → `is_initialized` | `setup_cannot_be_run_twice` |
| Copy a PIN or password hash onto another card or login, point a card at another account, or switch a staff row from handler to admin | Each hash is keyed for its identity: key = HMAC(pepper, "credential/v1", identity), where the identity is the card's lookup value, account and role, or the username and role. A hash moved to any other row doesn't verify (and the seal refuses the edit anyway, see T) | `keys.rs` → `credential_key`; `auth.rs` → `card_identity`, `staff_identity`, `hash_secret` | `a_hash_only_works_for_its_own_card_and_role`; *(attacks)* `copying_a_pin_hash_onto_another_card_does_not_work`, `copying_a_password_hash_onto_the_admin_row_does_not_work`, `pointing_a_card_at_another_account_does_not_work`, `editing_a_staff_role_does_not_make_a_cash_handler_an_admin` |
| A thief keeps using a card after the bank froze its account (a reported stolen card) | A bank freeze refuses the card entirely until a Teller Admin lifts it. Sign-in with the right PIN gets "This account is frozen by the bank. Please see a teller inside the branch." and is logged; a wrong PIN still counts toward the lock, so the message tells a guesser nothing. A session already open ends at its next step. The card can't confirm anything at the counter, and a transfer to the account is refused as if the number were unknown (`docs/screenshots/frozen-card-refused.png`, `docs/screenshots/account-frozen-teller.png`) | `auth.rs` → `login_customer`, `CustomerSession::still_allowed`, `confirm_at_counter`; `customer.rs` → `destination`; `admin.rs` → `set_frozen` | `a_bank_freeze_stops_the_card_entirely_until_a_teller_lifts_it` |
| A teller adds an accomplice as joint holder (with a PIN the teller picks), appoints a guardian, or opens a youth account without the parent | Counter consent: the current holder (or parent, or current guardian) types their own card number and PIN at the counter, checked in the library, not the front end. The card must be a holder of that account (or a guardian of that youth account), and a card the bank froze can't confirm. A wrong PIN counts toward that card's 3-strike lock and is logged ("wrong PIN at the counter"). The GUI says "The holder's card number or PIN was not accepted. Ask them to type it again." | `auth.rs` → `confirm_at_counter`, `CardAndPin`; `admin.rs` → `confirmed`, `add_joint_holder`, `open_youth_account`, `add_guardian` | `joint_and_youth_changes_need_the_holders_card_and_pin`, `b1_a_teller_cannot_take_over_an_account_by_adding_a_joint_holder`, `b3_a_teller_cannot_lift_a_guardian_freeze_by_appointing_a_guardian` |
| The teller who opens an account learns the new customer's first PIN | The customer types the PIN twice into masked fields that can't be copied out: in secret fields, Ctrl/Cmd shortcuts (select all, copy, cut) do nothing and the mouse can't select. Change PIN is on the customer menu, and every sign-in is logged with the card. Not done: a forced PIN change at first use (§7) | `gui/ui/theme.slint` → `Field`; `customer.rs` → `change_pin` | screen check (Ctrl+A, Ctrl+C in a PIN field copies nothing) |
| A teller guesses a PIN 3 at a time, unlocking the card in between | One unlock per card per New York bank day, counted from the signed log. The teller types the number from the card the customer hands over; the locked list shows the last 4 digits only | `admin.rs` → `unlock_card`, `locked_cards` | `b6_a_teller_cannot_guess_a_pin_by_unlocking_between_tries`, `locked_cards_are_listed_for_id_check_and_unlock_needs_a_locked_card` |
| Easy PINs (1234, 0000, birthday) | Rejected when chosen or changed (repeats, runs, birth year, MMDD/DDMM) | `input.rs` → `validate_new_pin` | `weak_new_pins_are_refused` |
| Next person takes a card or session left behind after the cash (post-completion error, textbook §3.2.1: "More people leave cards behind in ATMs that give them the money first and the card back second") | A withdrawal ends the session and hands the card back **before** the cash appears; the cash screen has no session behind it. The receipt question comes before any money moves | `gui/src/customer.rs` → `receipt_choice`, `return_card`, `take_card`, `take_cash` | manual (`docs/TEST_PLAN.md` 1.11) |
| Walk-away session used by the next person | 2-minute idle timeout in the library; GUI warns at 90 s, logs out at 2 min, clears half-typed card/PIN after 60 s and on logout wipes every screen property that held someone's data. The CLI clears the screen and its scrollback when a session ends; it waits for a key with no timer, so a session left at a menu ends (and is wiped) at the next key. The teller's Sign out button stays on screen under the red out-of-service banner | `auth.rs` → `IdleClock`; `gui/src/main.rs` → `tick`, `go_welcome`; `input.rs` → `wipe_screen`; `ui.rs` → `customer_flow`, `admin_flow`, `handler_flow` | `idle_and_logged_out_sessions_stop_working`; *(audit)* `the_cli_wipes_the_screen_when_a_session_ends` |
| Forge a session object | Session fields are private; only a successful login creates one | `auth.rs` session types | compile-fail test in `lib.rs` |
| Pretend to be another role | Staff logins are checked against a required role | `auth.rs` → `login_admin`, `login_handler` | `staff_roles_do_not_cross` |
| Run demo data (published passwords) as the real bank, or open the real bank in demo mode | A sealed `meta` row marks demo data. `Atm::open` refuses a demo database; `Atm::open_demo` (demo builds only) refuses a real one | `lib.rs` → `Atm::open`, `Atm::open_demo`; `db.rs` → `mark_demo`, `is_demo` | `demo_data_and_real_data_stay_apart` |
| Thief with a card and its PIN empties the account fast | Six fixed activity rules run inside each withdrawal, transfer and guardian move: 4th withdrawal in an hour, 4th transfer in an hour, 3rd different payee in 24 hours, $1,000+ to an account not paid before today (so a one-cent transfer can't prime it), $500+ out within an hour of $500+ in, one move of $900+ that takes 90%+ of the balance. A match refuses the attempt and holds the account. Nothing more leaves until a teller checks ID and releases it | `review.rs` → `screen`, `matched_rule`; `customer.rs` → `withdraw`, `transfer`; `family.rs` → `move_money` | `a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold`, `many_transfers_or_many_payees_are_held`, `unusual_amounts_are_held`, `guardian_moves_go_through_the_same_activity_rules_as_transfers` |
| Pretend to be the rate source (rogue Wi-Fi, a fake DNS answer, a proxy that inspects HTTPS) and serve made-up rates | HTTPS only (rustls, TLS 1.2 or 1.3). The server's certificate must chain to a root in the Mozilla list built into the program; the computer's own certificate store is not used, so a certificate someone added to the machine doesn't help. The URL is a constant and redirects are not followed. Even a feed that got through is only a proposal (see T) | `rate_feed.rs` → `fetch`, `FEED_URL` | Checked by hand: behind a proxy that inspects HTTPS the fetch is refused ("invalid peer certificate: UnknownIssuer"); an `http://` URL is refused ("configured for https only"). No automated test: the tests never go online |
| Someone poses as the customer at the counter to get a hold released, a larger amount approved or a card unlocked | The teller screen says to check photo ID first. The release, approval or unlock is logged with the teller's name. The program can't see the ID itself (a procedure, see §6) | `review.rs` → `release_hold`; `admin.rs` → `raise_limit_today`, `unlock_card` | `a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold` (checks the logged teller) |

### T: Tampering (changing data or money) → Integrity

| Threat | Defense | Code | Test |
|---|---|---|---|
| Negative, fractional or overflowing amounts | `Cents` can't be negative or above `Cents::MAX` (10^15 cents); strict parser; all math is checked; the database refuses a balance outside 0 to `Cents::MAX`; release builds keep overflow checks | `money.rs`; `db.rs` schema | `rejects_hostile_amounts`, `subtraction_cannot_go_negative`, `huge_values_are_refused_and_sums_cannot_wrap`; *(attacks)* `absurd_amounts_cannot_be_stored_or_overflow_a_balance` |
| SQL injection | Only bound parameters; no SQL text is ever built from input | all `src/*.rs` | code check: `grep -rn 'format!' src \| grep -i select` finds nothing |
| Half-finished transfer (crash between debit and credit) | Debit, credit and audit entry in one IMMEDIATE transaction | `customer.rs` → `transfer` | `transfer_moves_money_exactly_once` |
| Two operations racing | IMMEDIATE transactions take the write lock first; all checks (the seal included) run inside the transaction. A customer, guardian or Cash Handler change re-checks its session inside the lock, so a halt, lock, closure or freeze that lands while it waits is obeyed | `customer.rs` → `withdraw`, `precheck_withdrawal`; `lib.rs` → `Atm::begin`; `auth.rs` → `Atm::begin_for` | `every_operation_keeps_the_ledger_consistent`, `a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first`; *(attacks)* `two_instances_at_once_do_not_break_the_audit_chain` |
| Edit any row of `atm.db` outside the program: a lock flag, a freeze, a cash count, a staff row, a guardian link, a youth cap, the schema, a trigger or an index | The database seal: every commit writes HMAC(counter + SHA-256 of every row of every table and the schema) in the same transaction, and every operation checks it before reading anything. Index pages aren't rows, so SQLite's `PRAGMA integrity_check` runs first and refuses an index that no longer matches its table (swapping two log indexes once let a customer pass the daily limit). An edit gives "TAMPERING DETECTED: the database was changed outside the ATM. Nothing was done. Stop and escalate." (fail closed) | `seal.rs` → `digest`, `check`, `write`; `lib.rs` → `Atm::begin`, `Atm::read`, `Tx::commit` | `any_edit_breaks_the_seal_and_a_reseal_fixes_it`, `a2_resetting_card_columns_does_not_give_unlimited_pin_guesses`, `a4_clearing_the_frozen_flag_does_not_lift_a_bank_freeze`; *(attacks)* `clearing_freeze_and_closed_flags_changes_nothing`, `inserting_a_guardian_link_does_not_give_control_of_a_youth_account`, `blanking_a_youth_accounts_caps_does_not_free_it`; *(audit)* `an_index_edited_in_the_file_is_caught_before_it_can_mislead` |
| Put back an older copy of `atm.db` (to undo a withdrawal or a lock-out), or edit or delete `atm.anchor` | `atm.anchor` holds the newest seal counter, HMAC-tagged. A lower counter is refused ("DATABASE ROLLED BACK: this is an older copy of the bank's records. Nothing was done."), and so is an edited or missing anchor. A running program also refuses a counter lower than one it has seen | `anchor.rs` → `Anchor::read`, `advance`; `lib.rs` → `Atm::start`, `Atm::begin` | *(attacks)* `restoring_an_old_copy_of_the_database_is_detected`, `the_anchor_file_cannot_be_edited_or_removed` |
| Type text or a fraction into a number column (a balance as text, say) | Every table is STRICT, so a value of the wrong type is refused | `db.rs` → `SCHEMA` | `strict_tables_refuse_values_of_the_wrong_type` |
| Edit a balance directly in `atm.db` | The seal refuses it at the next operation, so the typed-in money can't be spent. Second layer: the integrity check recomputes every balance from the signed log, at every Teller Admin sign-in and on demand, and lists every account that is off by its last 4 digits | `seal.rs` → `check`; `audit.rs` → `reconcile_balances` | `a3_a_typed_in_balance_is_not_spendable`, `integrity_check_catches_a_balance_edited_in_the_database`; *(attacks)* `an_edited_balance_cannot_be_spent` |
| A change made through the program that skips the log (a bug or a planted change moves money or bills, or changes a limit, rate, freeze or closure, with no log entry). The seal can't see it: the program sealed it | The full integrity check runs at every Teller Admin sign-in and on demand: the log chain; every balance against the log; the bills in the machine against every restock, deposit, withdrawal and removal; the signed settings and rates; and each daily limit, exchange rate, bank freeze, guardian freeze and closure against its newest log entry (a rate against its newest rate-history row, with a log entry for every history row). After the chain, every check runs and every failure is listed, so a known failure doesn't hide a new one. If anything fails, the ATM takes itself out of service (see D) and the teller sees a red banner (`docs/screenshots/out-of-service-banner.png`). Not covered yet: fees, card locks, youth caps, joint holders and guardians (§7) | `audit.rs` → `verify`, `reconcile_balances`, `reconcile_cash`, `reconcile_state`; `service.rs` → `check_at_sign_in`, `problem`; `auth.rs` → `login_admin` | `a_failed_check_at_sign_in_takes_the_atm_out_of_service`, `bills_moved_with_no_log_entry_take_the_atm_out_of_service`, `a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service`, `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged`, `a_broken_balance_is_caught_at_the_next_teller_sign_in` (`--features integrity-test`) |
| Edit, delete or reorder log entries | The seal refuses the change at once. Behind it: append-only triggers + HMAC-SHA-256 chain keyed by `atm.key`, so it can't be recomputed without the key; deleted tail entries detected | `db.rs` triggers; `audit.rs` → `append`, `verify_chain` | `chain_verifies_and_detects_edits`, `chain_detects_deletion_in_the_middle_and_at_the_end`, `forger_without_the_key_cannot_rebuild_the_chain`, `application_cannot_edit_or_delete_history`; *(attacks)* `the_end_of_the_log_cannot_be_cut_off` |
| Edit a limit, fee or exchange rate in `atm.db` | The seal refuses the change at once. Behind it, each row carries an HMAC (a fee is two rows: percent and minimum). An edited limit or fee stops the program from using it; an edited rate stops conversions, and re-entering it brings the currency back paused | `keys.rs` → `record_mac`; `fx.rs` → `read_rate`, `verify_rates` | `an_edited_setting_is_detected`, `missing_stale_or_edited_rates_stop_conversions`; *(attacks)* `an_edited_limit_or_rate_is_refused_at_the_point_of_use`, `settings_and_rates_edited_in_the_file_are_detected` |
| Forge a stored MAC one character at a time, timing how long the comparison takes | Every stored MAC (settings, rates, rate history, the log chain, the key fingerprint, the anchor's seal) is compared in full, with no early exit; the seal and anchor tags use the MAC library's own constant-time check. In practice the seal refuses an edited row before these comparisons run | `keys.rs` → `same_mac`, `seal_matches`, `anchor_tag_matches` | `stored_macs_are_compared_in_full` |
| Clear a hold, or add a fake teller approval, by editing `atm.db` | The seal refuses the change at once. Behind it, neither is a flag or a counter. "On hold" means the newest hold row for the account in the log is `hold_placed`; an approval is a log row, summed for the current New York bank day. The log is append-only and HMAC-chained, so a deleted, edited or forged row is detected | `review.rs` → `hold_reason`; `customer.rs` → `limit_status`; `audit.rs` → `total_today`, `verify_chain` | `application_cannot_edit_or_delete_history`, `chain_detects_deletion_in_the_middle_and_at_the_end`, `forger_without_the_key_cannot_rebuild_the_chain` |
| Teller mints money with a huge starting balance (or many), or switches a daily limit off with a huge number | Each starting balance is capped at the bank's daily deposit limit (US-dollar value; $10,000 by default), and all of one teller's starting balances in a bank day at $20,000 together, summed from the signed log (youth accounts and guest cards included). Each limit is capped at its default plus one day's largest teller raise: $5,000 withdrawal, $50,000 deposit, $25,000 transfer | `admin.rs` → `insert_account`, `STARTING_BALANCES_PER_DAY`, `set_limit`; `audit.rs` → `opened_today_by`; `db.rs` → `Limit::ceiling` | `one_teller_cannot_mint_money_or_switch_limits_off`, `b2_a_teller_cannot_mint_unbacked_money`; *(audit)* `one_teller_cannot_create_unlimited_money_with_starting_balances` |
| One deposit takes more than 200 bills of a kind by splitting them into entries | The count is added up per denomination before the 200-bill cap | `customer.rs` → `deposit` | `c2_one_deposit_cannot_take_more_than_200_bills_of_a_kind` |
| Teller sets a fee to overcharge | Each fee is bounded: 0-5%, minimum $0-$10. Both parts carry an HMAC and every change is logged old → new ("Exchange fee: 3.00%, at least $3.00 -> 2.50%, at least $4.00"). The fee goes to the bank, not the teller | `fx.rs` → `set_fee_rule` | `each_fee_is_the_higher_of_the_percent_and_the_minimum` |
| Teller enters a "friendly" exchange rate, typed or by approving a feed | Believable range per currency. A typed rate must be within 5% of every rate in the last 24 hours, so repeated small changes can't add up; no override exists. Approving a feed doesn't let a teller pick a number: only `rate_feed::fetch` can make a feed (`Feed`'s fields and `parse` are private), so the value comes from the fixed source, and a move over 5% pauses that currency | `fx.rs` → `set_rate`, `check_change_cap`, `store_rate`; `rate_feed.rs` → `fetch`, `approve` | `rates_parse_strictly_and_must_be_believable`, `a_teller_cannot_jump_a_rate_but_can_pause_it`, `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source`; compile-fail test in `lib.rs` (a front end can't build a `Feed`) |
| Poisoned feed: made-up or wrong rates (a hacked or mistaken source, or a spoof that got past TLS) | A feed is only a proposal. The teller sees Now, Today's feed, Will set and Note for every currency, and nothing changes until they approve. A rate outside the believable range is not used. A move over 5% in a day is set but the currency is paused ("big move: +10.00%; will be paused"), so no customer is charged at it until a teller checks it against another source and resumes. Each approved rate gets its HMAC and is logged with the feed's name and publish time | `rate_feed.rs` → `check`, `plan`, `approve`; `fx.rs` → `allowed_band`, `store_rate` | `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` |
| Old feed replayed, or junk slipped into it | Strict parse: `result` must be "success" and `base_code` "USD"; published less than 48 hours ago and not more than 5 minutes in the future; each number goes through `fx::parse_fixed`, the parser for a typed rate. A missing or bad number shows as "missing" and that currency is left as it is | `rate_feed.rs` → `parse`, `to_micros` | `a_feed_is_read_strictly` |
| Stale review: the teller approves a list that no longer matches (another teller set a rate, or the 24-hour window moved) | `approve` recomputes the plan inside one IMMEDIATE transaction and sets nothing if it differs from what the teller saw ("rates changed since you checked them; please check again") | `rate_feed.rs` → `approve` | `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` (a second approval of the old list is refused) |
| Use the feed to undo a pause, or to clear an edited ("ALTERED") rate | A paused currency takes the new rate but stays paused. An edited row shows as ALTERED and is re-entered paused, as when typed | `rate_feed.rs` → `plan`; `fx.rs` → `store_rate` | `a_paused_currency_takes_the_new_rate_but_stays_paused`, `missing_stale_or_edited_rates_stop_conversions` |
| Rewrite the rate history to hide a bad rate | `rate_history` is append-only (triggers) and every row has an HMAC; the seal covers it too | `db.rs` triggers; `fx.rs` → `read_history` | `a_teller_cannot_jump_a_rate_but_can_pause_it` |
| Convert at a forgotten, stale rate | Rates expire after 72 hours; conversions stop until a teller re-enters the rate | `fx.rs` → `usable_rate` | `euro_account_without_a_fresh_rate_cannot_convert` |
| Earn money from rounding by repeating tiny conversions | Integer math only. Cash and each fee are converted separately; charges and fees round up, credits round down, so a round trip always loses. The screen adds up the dollars (withdrawal + each fee = total) and then shows what the account is charged | `fx.rs` → `apply`, `charge_for`, `credit_for`, `FeeRule::on` | `charges_round_up_credits_round_down_and_round_trips_lose`, `won_are_whole_and_round_in_the_banks_favour` |
| Deposit a tiny amount to a foreign account and dodge the fee | The exchange fee is at least the minimum; a deposit too small to cover it is refused, never credited at zero | `fx.rs` → `credit_for` | `each_fee_is_the_higher_of_the_percent_and_the_minimum` |
| Swap one customer's encrypted name/DOB into another row | AES-GCM with the column and the card's lookup value as associated data | `keys.rs` → `seal`, `unseal`; `db.rs` → `seal_holder` | `copying_one_customers_encrypted_name_onto_another_is_detected` |
| Copy one row's encrypted card or account number onto another row | Same: AES-GCM with the column and that row's lookup value as associated data, so the copy doesn't decrypt | `db.rs` → `seal_number`, `open_number` | `copying_one_rows_encrypted_number_onto_another_is_detected` |
| Reset daily limits or the activity-check windows by rolling the clock back | Daily totals come from the log, not a counter; the program refuses to start if the clock is behind the newest log entry. Moving the clock forward starts the next bank day early; accepted (§7) | `audit.rs` → `total_today`, `check_clock` | `clock_rollback_is_refused`, `daily_limit_is_cumulative` |
| Point the program at a fake database, or start a new bank on the old key | No path arguments: fixed file names only; the key fingerprint in the DB must match `atm.key`; a key or anchor without its database is refused ("the bank's database file is missing; restore it, or delete the key and anchor files to start a new bank on purpose") | `gui/src/main.rs` → `parse_args`; `db.rs` → `check_version_and_key`; `lib.rs` → `Atm::start` | `a_wrong_key_or_version_is_refused_with_a_clear_error`, `a5_deleting_the_database_but_keeping_the_key_does_not_reopen_first_run_setup` |
| Malicious SQLite schema tricks | `SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema=OFF` | `db.rs` → `configure` | `hardening_pragmas_are_on` |
| Child (or anyone) raising a youth cap | Only a linked guardian can change controls; caps can't exceed the bank limit; the effective limit is the lower of the two | `family.rs` → `set_controls`; `customer.rs` → `check_daily_limit` | `guardian_can_see_adjust_and_freeze_but_strangers_cannot`, `youth_defaults_cap_spending_and_restrict_transfers` |

### R: Repudiation (denying you did something) → Non-repudiation

| Threat | Defense | Code | Test |
|---|---|---|---|
| "I never made that withdrawal" | Every transaction is logged with the **card** (row id and last 4 digits, so joint holders are told apart), time, amount, bills, rate and each fee, in the same transaction as the money movement; the customer gets a receipt with the log reference number | `audit.rs` → `append`; `customer.rs` → `receipt` | `withdraw_moves_money_and_bills_and_gives_a_receipt`, `logs_name_cards_by_id_and_last_four_only` |
| Staff deny an action | Logins, failures, lockouts, unlocks, limit changes (old → new), approvals of a larger amount for today, hold releases, rate changes (typed or from the feed), pauses, fee changes (old → new), freezes, closures, cash moves, password changes, logouts, integrity checks, and halts and resumes of service are all logged with the staff username | `admin.rs`, `cash.rs`, `auth.rs` → `log`; `fx.rs` → `set_rate`, `set_fee_rule`; `admin.rs` → `raise_limit_today`; `review.rs` → `release_hold`; `service.rs` → `halt`, `resume` | `limit_changes_are_validated_and_logged`, `logout_is_logged_and_ends_the_session`, `a_teller_can_approve_more_than_the_daily_limit_for_today_only` |
| A teller resumes service and later denies it, or says the check had passed | Resume runs the check again and logs its result with the teller's name ("resumed after review; integrity check passed", or "...; integrity check still fails: ..."). An automatic halt is logged as "system" with every check that failed (accounts by their last 4 digits) and whose sign-in found it. The state is read from those log entries, so there is no flag to flip quietly | `service.rs` → `check_at_sign_in`, `halt`, `resume`, `halted` | `a_failed_check_at_sign_in_takes_the_atm_out_of_service`, `a_teller_can_halt_and_resume_by_hand`, `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged` |
| A holder denies agreeing to a new joint holder or guardian | The log line names the new card and the card that confirmed it ("joint holder, card 9 ending 1234; confirmed by card 7 ending 5678 with PIN"), with the teller's name | `admin.rs` → `add_joint_holder`, `add_guardian`, `open_youth_account` | `joint_and_youth_changes_need_the_holders_card_and_pin` |
| Dispute over why an account was stopped | The hold row records the rule, what was refused and when, with the actor `system:activity-check`; the release row names the teller | `review.rs` → `screen`, `release_hold` | `a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold` |
| Guardian denies taking money out of a child's account | Logged as a transfer by the guardian's own card, with the detail "by guardian: ..."; it shows in the child's history | `family.rs` → `move_money` | `guardian_moves_money_in_and_out_of_the_childs_account_only` |
| Teller denies setting a rate, or blames the feed | Every rate stays in the rate history with who set it and when, shown with its % change. A rate from the feed is logged with the teller's name and the source: "JPY per USD: 151.20 -> 166.32 (daily feed open.er-api.com, published ...; big move: +10.00%; will be paused)" | `fx.rs` → `set_rate`, `store_rate`, `rate_history`; `rate_feed.rs` → `approve` | `a_teller_cannot_jump_a_rate_but_can_pause_it`, `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` |
| A front end writes its own text into the log through a feed (fake log lines, a false source, megabytes of text) | Only `fetch` makes a feed, and the publish time in the log line is text the program writes from the feed's timestamp ("2026-10-12 00:02 UTC"); a front end can only read it | `rate_feed.rs` → `Feed::published`, `approve` | compile-fail test in `lib.rs` (a front end can't build a `Feed`) |
| An attack on the feed passes for an ordinary outage | Every failed check is logged as "Rate feed failed" with the teller and the reason; a refused certificate has its own message ("failed its security check (certificate not trusted)"), not "couldn't reach" | `rate_feed.rs` → `fetch`, `failure`, `read_logged` | `a_failed_check_is_logged_with_its_reason_and_changes_nothing`, `each_kind_of_fetch_failure_gets_its_own_message` |
| Someone with the stolen key rewrites the whole log, re-seals the database and rewrites the anchor | Integrity check shows a "check code" (head of the chain) to write down off the machine; an older code that stops matching proves a rebuild | `admin.rs` → `verify_integrity` | `chain_verifies_and_detects_edits` |

### I: Information disclosure → Confidentiality

| Threat | Defense | Code | Test |
|---|---|---|---|
| Find out which card numbers exist | Same message and same timing (a dummy Argon2 hash) for unknown card and wrong PIN. The dummy hash is made when the bank opens, so the first try after a start costs the same as any other. An unknown or closed card number also says "card locked" on the 3rd try, exactly like a real card (counted in memory only, at most 10,000 numbers, reset on restart) | `auth.rs` → `burn_time_like_a_real_check`, `warm_up`, `like_a_real_card` | `right_pin_logs_in_and_wrong_pin_does_not`, `c1_a_real_card_and_an_unknown_card_fail_the_same_way` |
| Hunt for account numbers via transfers | Random 10-digit numbers; only initials are shown; 3 unknown destinations end the session (counted per session, §7). An account the bank froze looks like an unknown number | `admin.rs` → `fresh_number`; `customer.rs` → `destination`, `recipient_hint` | `hunting_for_account_numbers_ends_the_session`, `recipient_hint_shows_initials_only` |
| Read a card number over someone's shoulder, or from a thrown-away receipt (textbook §12.4.2) | The GUI shows dots plus the last 4 digits while typing; the CLI hides the number; receipts and history show the last 4 only. The customer can choose no receipt, and then the screen shows no balance or reference number either | `gui/src/main.rs` → `last_four_typed`; `ui.rs` → `read_secret`; `customer.rs` → `mask`; `gui/src/customer.rs` → `receipt_lines` | `history_shows_only_my_transactions_and_incoming_transfers`; GUI checked by screenshot |
| See another customer's data | The account comes from the session, never from input; a customer's history shows other accounts masked (`******3343`) and the sender of a transfer in as "other account holder", never their card; a non-guardian asking about a youth account gets "not found" | `customer.rs` → `history`, `mask`; `audit.rs` → `for_customer`; `family.rs` → `guarded_account` | `history_shows_only_my_transactions_and_incoming_transfers`; *(attacks)* `history_does_not_leak_other_peoples_card_numbers` |
| A teller reads full card numbers off the locked-card list (then guesses PINs at the machine) | The locked list shows the card's and account's last 4 digits, the name and the date of birth (for the ID check). To unlock, the teller types the number from the card the customer hands over. The account list shows card numbers by their last 4 digits too | `admin.rs` → `locked_cards`, `LockedCard`, `unlock_card`, `HolderSummary.card_last4` | `locked_cards_are_listed_for_id_check_and_unlock_needs_a_locked_card`, `card_and_account_numbers_are_stored_encrypted` |
| Stolen `atm.db` | PINs/passwords are Argon2id keyed per card or login from `atm.key` (can't be tested without it); names and DOBs are AES-256-GCM encrypted; no SSN or address is stored at all | `keys.rs` → `credential_key`; `auth.rs` → `hash_secret` | `pins_are_not_stored_in_the_clear`, `names_and_birth_dates_are_encrypted_at_rest` |
| Read card and account numbers from a stolen `atm.db` | Each number is stored three ways: an HMAC-SHA-256 lookup value (key derived from `atm.key`; "card" or "account" mixed in so the two can't be confused), an AES-256-GCM copy, and the last 4 digits. A plain SHA-256 would not do: there are only 10^10 ten-digit numbers, so trying them all takes minutes. Without `atm.key` not one guess can be tested | `keys.rs` → `lookup_hash`; `db.rs` → `lookup`, `seal_number` | `card_and_account_numbers_are_stored_encrypted` |
| Read card numbers from the audit log | Customers appear as `customer:card 7 ending 1234` (card row id and last 4); log details name cards the same way. An integrity failure names an account by its last 4 digits only, so a halt's log line holds no full number. A database with any other schema version than 6 is refused, not used ("delete atm.db, atm.key and atm.anchor to start over") | `db.rs` → `customer_actor`, `card_ref`, `check_version_and_key`; `audit.rs` → `reconcile_balances` | `logs_name_cards_by_id_and_last_four_only`, `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged` |
| Learn the activity-check thresholds in order to stay under them | The customer sees only "For your protection ... paused after unusual activity. Please see a teller inside the branch". Which rule matched, and its amounts, are shown to staff only | `error.rs` → `OnHold`; `review.rs` → `holds` | `a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold` (checks the message names no rule) |
| Collect other customers' account numbers from "Send again" | Shows only the masked number and the holders' initials. Lists only accounts this account's own card holders paid (not a guardian taking money back), never closed ones. The GUI keeps the full number in Rust memory, not in a screen property | `customer.rs` → `recent_payees`; `gui/src/customer.rs` → `send_again` | `recent_payees_are_newest_first_without_repeats_and_capped_at_five`, `a_guardian_taking_money_back_is_not_a_payee_of_the_child` |
| Deleted data left in the file | `secure_delete=ON` overwrites freed pages | `db.rs` → `configure` | `hardening_pragmas_are_on` |
| Other OS users read the files | `atm.key`, `atm.db` and `atm.anchor` are owner-only (0600) on macOS/Linux | `keys.rs` → `restrict_permissions` | manual: `ls -l atm.*` |
| PIN left in memory or on screen, or copied out | At the ATM keypad the GUI keeps typed digits in Rust (`Zeroizing`, wiped after use), never in a UI property; the screen shows dots only; the CLI hides input. On the teller's screen a PIN or password goes into a masked text field: Ctrl/Cmd shortcuts (select all, copy, cut) do nothing there and the mouse can't select, so it can't be copied out; the field is cleared after each try (§7) | `gui/src/main.rs` → `State.entry`; `gui/ui/theme.slint` → `Field`; `input.rs` → `read_secret` | manual (screen check) |
| Error messages leak internals | Users only see fixed texts; database errors become "Internal error" | `error.rs` | all tests use the public messages |
| Next person sees the last person's data | Logout and timeout wipe every screen property in the GUI that held someone's data (receipts, sums, limits, holds, rates, cash, integrity results, youth caps and flags), not just hide it. The CLI clears the screen and its scrollback when a session ends | `gui/src/main.rs` → `go_welcome`; `input.rs` → `wipe_screen` | *(audit)* `the_cli_wipes_the_screen_when_a_session_ends`; GUI manual (idle test) |
| Leak data through the rate request | The only outbound request is a GET of a fixed public URL: no key, cookie, account, card or customer data. The reply is public. Someone watching the network learns only that the machine contacted `open.er-api.com` (the DNS lookup and the TLS server name) | `rate_feed.rs` → `fetch` | code check: `grep -rn "ureq" src gui` finds only `fetch`; one `agent.get(FEED_URL).call()` with no body |

### D: Denial of service → Availability

| Threat | Defense | Code | Test |
|---|---|---|---|
| Lock out many customers by guessing | Card numbers are random, so they can't be enumerated | `admin.rs` → `fresh_number` | `numbers_are_ten_digits_and_distinct` |
| Keep one known card locked: 3 wrong PINs, then again after each unlock | Not blocked. A teller unlocks a card only once per bank day (to stop teller PIN guessing), so the owner can be kept out for the rest of that day. Every try is logged with the card. Accepted (§7) | `auth.rs` → `login_customer`; `admin.rs` → `unlock_card` | `b6_a_teller_cannot_guess_a_pin_by_unlocking_between_tries` |
| Lock out the only Teller Admin | Staff get growing pauses, never a permanent lock | `auth.rs` → `staff_cooldown_secs` | `staff_pauses_grow_and_are_capped` |
| Crash with huge or strange input | Input length caps, bill-count caps, no `unwrap` on runtime paths, `#![forbid(unsafe_code)]`. The in-memory count of failed logins for unknown card numbers holds at most 10,000 entries | `input.rs`, `cash.rs`, `lib.rs`; `auth.rs` → `like_a_real_card` | `rejects_hostile_amounts`, `names_cannot_carry_control_characters` |
| Empty one bill type with a single huge payout in small bills (or jam the dispenser) | A withdrawal pays out at most 40 bills, like a real dispenser. The GUI greys out bills that would take more; the library refuses before any money or bills move | `dispense.rs` → `plan_withdrawal`, `plan_within` | `withdrawals_pay_at_most_40_bills`; `customer.rs`: `more_than_40_bills_is_refused_without_a_debit` |
| Machine runs out of cash mid-payout | Bills are planned from real stock before anything moves; a short machine names what it can pay | `dispense.rs` → `plan` | `missing_denomination_is_rejected_and_alternatives_are_named`, `stock_limits_are_respected_where_greedy_fails` |
| Power loss mid-write | `synchronous=FULL` + atomic transactions; the new seal is part of the same transaction. The anchor is written to a temporary file and renamed, so it is never half written; a crash right after a commit leaves it one step behind, and the next start moves it forward | `db.rs` → `configure`; `anchor.rs` → `advance`; `lib.rs` → `Atm::start` | `every_operation_keeps_the_ledger_consistent` |
| Edit one byte of `atm.db` (or roll it back, or damage or block `atm.anchor`) to stop the bank | Fail closed on purpose: every operation refuses ("TAMPERING DETECTED ..." or "DATABASE ROLLED BACK ..."; "Nothing was done. Stop and escalate."), for customers and staff alike, so nothing is decided from altered data. If `atm.anchor` can't be written after a commit, the change already made stands and is reported as done (a customer is never told "not completed" for money that moved), and the ATM does nothing else until the anchor is written. Accepted trade (§7): the attacker can stop the ATM but gains nothing. The bank restores its files from a backup | `lib.rs` → `Atm::start`, `Atm::begin`, `Atm::read`, `Tx::commit`, `catch_up_anchor`; `error.rs` → `DatabaseAltered`, `RolledBack` | `any_edit_breaks_the_seal_and_a_reseal_fixes_it`; *(attacks)* `the_anchor_file_cannot_be_edited_or_removed`; *(audit)* `a_finished_deposit_is_never_reported_as_failed_and_a_blocked_anchor_stops_the_atm` |
| The integrity check fails at a teller's sign-in, or a teller halts the ATM, and customers are turned away | Out of service on purpose, like a real ATM that stops itself when it finds a fault. The start screen says "Out of service" and "This ATM is temporarily out of service. Please use another ATM.", the card is grayed out and no card number or PIN is taken (`docs/screenshots/out-of-service-welcome.png`); the GUI re-checks every 5 seconds, the CLI before each card. Live customer and Cash Handler sessions stop, a change already waiting for the write lock is refused, and the Cash Handler can't sign in. Only a Teller Admin can, and the red banner keeps Sign out on screen. One Teller Admin resumes after review, with one click; the check runs again and its result is logged. Accepted trade (§7) | `service.rs` → `out_of_service`, `check_at_sign_in`, `refuse_if_halted`, `halt`, `resume`; `auth.rs` → `Atm::admit`, `Atm::begin_for`, `login_staff`; `gui/src/main.rs` → `App::out_of_service`, `tick`; `ui.rs` → `customer_flow`, `handler_flow` | `a_failed_check_at_sign_in_takes_the_atm_out_of_service`, `a_teller_can_halt_and_resume_by_hand`, `while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in`, `a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first` |
| A currency crashes | Today's feed sets the new market rate the same day, but a move over 5% pauses that currency until a teller checks it and resumes. A teller can also pause one currency or all of them at once; dollar accounts keep working | `fx.rs` → `set_paused`; `rate_feed.rs` → `plan` | `a_teller_cannot_jump_a_rate_but_can_pause_it`, `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source` |
| Rate feed down, blocked or slow | Only a Teller Admin's button press fetches: never a customer, never in the background, so customers never wait on the network. The whole request, DNS lookup included, has a 10 s limit. A failure changes nothing and says "Couldn't reach today's rate feed. Rates are unchanged; you can still type a rate." The teller's screen waits up to 10 s | `rate_feed.rs` → `fetch`; `error.rs` → `FeedUnavailable` | manual (`docs/TEST_PLAN.md` 8.8) |
| Huge or endless reply to fill memory | At most 64 KB is read (`FEED_MAX_BYTES`), checked again before parsing; compression is not turned on, so nothing grows after reading | `rate_feed.rs` → `fetch`, `parse` | `a_feed_is_read_strictly` (70 KB refused) |
| A hold shuts an honest customer out of their account | A hold stops only money leaving (withdrawals, transfers, guardian moves out). Deposits, balance and history still work. After a teller contact (a release or an approval) counting starts again, and the amount rules (4-6) stay off for that account until tomorrow | `review.rs` → `check_not_held`, `last_teller_contact` | `a_4th_withdrawal_in_an_hour_is_refused_until_a_teller_releases_the_hold`, `once_a_teller_has_seen_the_customer_today_amount_rules_are_off` |
| Trip someone else's hold: send $500+ to an account whose number you know, so the owner's next large withdrawal matches rule 5 | Same limits on the harm: no money moves, a teller releases it, and the sender's transfer is in the log with their card. Accepted as a nuisance (§7) | `review.rs` → `matched_rule` | `unusual_amounts_are_held` |
| Orphan a youth account: close its guardians one by one, so nobody can lift a guardian's freeze | Only guardians whose own account is still open count; the last one can't be closed | `admin.rs` → `close_account` | `b4_closing_guardians_one_by_one_cannot_orphan_a_youth_account` |

### E: Elevation of privilege → Authorization

| Threat | Defense | Code | Test |
|---|---|---|---|
| Customer calls a teller function | Each function demands its own session type; the wrong one doesn't compile | `auth.rs`, `admin.rs` | compile-fail test in `lib.rs` |
| GUI/CLI skips a rule by running SQL | The connection is private to the library. A front end that opened `atm.db` on its own (the CLI shares the library's crates, so it could) would break the seal, and the next operation refuses | `lib.rs` → `Atm`; `seal.rs` → `check` | compile-fail test in `lib.rs`; `any_edit_breaks_the_seal_and_a_reseal_fixes_it` |
| Using a session after logout | Logout consumes the session | `auth.rs` → `logout_*` | compile-fail test in `lib.rs` |
| Hand the real bank a session made elsewhere (open a throwaway bank, run setup there with your own passwords, pass that admin session to the real one) | Each opened bank gets a random id (`Atm.id`), and every session carries the id of the bank that issued it. `Atm::admit`, the first line of every action, refuses and ends a session from any other bank | `lib.rs` → `Atm`, `new_id`; `auth.rs` → `Atm::admit` | *(attacks)* `a_session_from_another_database_is_not_accepted`, `a_customer_session_from_another_database_is_not_accepted` |
| Keep using a session after the card is locked, the account closed or frozen by the bank, or the staff login removed | `Atm::admit` re-checks the database on every action (`Session::still_allowed`): a locked card, a closed or bank-frozen account or a missing staff row ends the session at once. Customer and Cash Handler sessions also stop while the ATM is out of service. A change re-checks all of this inside the write lock (`Atm::begin_for`), so a lock, closure, freeze or halt that another process commits while the change waits still stops it | `auth.rs` → `Atm::admit`, `Atm::begin_for`, `Session`, `still_staff` | `a_bank_freeze_stops_the_card_entirely_until_a_teller_lifts_it`, `a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first`; *(attacks)* `a_live_session_stops_when_the_card_is_locked_or_the_account_closed` |
| Guest card deposits, transfers, changes its PIN or reads history | Every one of those functions checks the card's role in the library, not only the menu; guest accounts can't receive transfers, be guardians or have joint holders | `customer.rs` → `not_guest`, `destination`; `admin.rs` → `add_joint_holder`, `adult_card` | `guest_cards_only_withdraw_and_pay_the_atm_fee` |
| Cash Handler empties the machine | Can only remove cash above the $100,000 maximum. The cash is counted against the log at every Teller Admin sign-in, and the handler can't sign in (or keep working) while the ATM is out of service. Restoring an older `atm.db` and `atm.anchor` together gets past the maximum (§7) | `cash.rs` → `remove_excess`; `audit.rs` → `reconcile_cash`; `auth.rs` → `login_staff` | `handler_can_only_remove_the_overflow`, `bills_moved_with_no_log_entry_take_the_atm_out_of_service`, `while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in` |
| Teller moves money or learns PINs | No such function exists; PINs are typed by the customer into fields that can't be copied out (at the counter too, for a joint holder, guardian or youth account: see S); tellers see names/DOB only to check ID before unlocking or releasing a hold. The teller who opens an account still handles the form the first PIN is typed into (see S, §7) | `admin.rs`; `gui/ui/theme.slint` → `Field` | n/a (absence of an API) |
| Teller types a rate past the 5% daily limit | No override function exists. The feed is the only way to move further, and only `rate_feed::fetch` can make a feed, so the teller can't choose its numbers; a big move is paused, and the approval and the resume are both logged with the teller's name | `fx.rs`; `rate_feed.rs` → `fetch`, `approve` | `a_teller_cannot_jump_a_rate_but_can_pause_it`, `approving_a_feed_sets_market_rates_pauses_big_moves_and_logs_the_source`; compile-fail test in `lib.rs` (a front end can't build a `Feed`) |
| Someone other than a Teller Admin fetches the feed or approves rates | `fetch`, `check` and `approve` each need an `AdminSession`. Only the teller's Exchange rates tab and the command line's rates menu call them | `rate_feed.rs`; `gui/src/staff.rs` → `check_feed`, `approve_feed`; `ui.rs` → `check_feed` | compile-fail test in `lib.rs` (a customer session is not an admin session) |
| A malformed reply exploits the parser | `serde_json` (safe Rust) reads it into a plain value; only known fields are read; nothing in the reply becomes code, a path or a URL; numbers go through `fx::parse_fixed` | `rate_feed.rs` → `parse` | `a_feed_is_read_strictly` (a web page, wrong base, failed result, text, negative, zero and 1e300 are refused or shown as missing) |
| Teller raises an accomplice's limit, or releases their hold, to cash out | An approval is for one account and one limit, today only, capped per account per day at +$4,000 withdrawal, +$40,000 deposit and +$20,000 transfer, and refused for youth accounts and other banks' cards. It moves no money. It does count as a teller contact, so the amount rules (4-6) are off for that account until tomorrow; the frequency rules (1-3) still run. Every approval and release is in the signed log with the teller's name. The rule thresholds are constants in the code: no setting or function can switch them off | `admin.rs` → `raise_limit_today`; `db.rs` → `Limit::max_raise`; `review.rs` → `release_hold` | `a_teller_can_approve_more_than_the_daily_limit_for_today_only`, `youth_and_other_bank_accounts_cannot_have_limits_raised` |
| Run setup again to mint a new admin: on a set-up bank, after emptying the staff table, or after deleting `atm.db` | Setup only works on a bank with no staff and no log entries. Emptying the staff table breaks the seal. A key or anchor without its database is refused, so deleting `atm.db` doesn't bring setup back | `auth.rs` → `first_run_setup`; `db.rs` → `is_initialized`; `lib.rs` → `Atm::start` | `setup_cannot_be_run_twice`, `a1_emptying_the_staff_table_does_not_reopen_first_run_setup`, `a5_deleting_the_database_but_keeping_the_key_does_not_reopen_first_run_setup`; *(attacks)* `deleting_the_database_does_not_offer_setup_again` |
| Child bypasses guardian controls | Caps, freezes and family-only transfers enforced in the library on every withdrawal and transfer. A teller can't approve more for a youth account, and its over-limit message doesn't send it to one | `customer.rs` → `check_daily_limit`, `transfer`; `admin.rs` → `raise_limit_today` | `youth_defaults_cap_spending_and_restrict_transfers`, `youth_and_other_bank_accounts_cannot_have_limits_raised` |
| A teller lifts a guardian's freeze, a guardian lifts the bank's, or a teller-appointed guardian lifts the parent's | Two separate freezes, each lifted only by its own side. The bank's (`frozen`, set by a Teller Admin) refuses the account's cards entirely: no sign-in, live sessions end, no consent at the counter, and no money goes into it (a transfer looks like an unknown number; a guardian's move in is refused). The guardian's (`guardian_frozen`, on a youth account) stops money leaving; the child's card still works for deposits, balance and history. A new guardian needs a current guardian's card and PIN (see S) | `admin.rs` → `set_frozen`, `add_guardian`; `family.rs` → `set_frozen`, `move_money`; `customer.rs` → `is_frozen`; `auth.rs` → `login_customer`, `CustomerSession::still_allowed` | `the_bank_and_the_guardian_each_lift_only_their_own_freeze`, `a_bank_freeze_stops_the_card_entirely_until_a_teller_lifts_it`, `b3_a_teller_cannot_lift_a_guardian_freeze_by_appointing_a_guardian`; *(attacks)* `a_guardian_cannot_lift_a_freeze_placed_by_the_bank` |
| Guardian uses Move money to pay someone else from the child's account | Move money has no destination field: money taken from the child goes only to the guardian's own account. Checks: guardian link (anyone else gets the same "not found" as a missing account), same currency, frozen, hold, balance, the paying account's daily transfer limit (taking money back uses the bank's transfer limit, not the child's own cap) and the activity rules (see S). Money taken back counts toward the child's daily transfer total | `family.rs` → `move_money`, `guarded_account` | `guardian_moves_money_in_and_out_of_the_childs_account_only` |
| Closed account keeps working | Its cards can't log in; a live session ends at its next action; it can't receive transfers; its number is never reused | `admin.rs` → `close_account`; `db.rs` → `account_id`; `auth.rs` → `Atm::admit` | `closing_needs_a_zero_balance_and_then_blocks_the_account` |
| Memory-safety exploit | No `unsafe` in our code (`forbid` in the library, `deny` in the GUI) | `lib.rs`, `gui/Cargo.toml` | compiler |

---

## 5. Assurance: can we be sure it works?

**Layers.** Lecture 1's Stuxnet kill chain: "protection at any layer would
have broken the links". An attack has to get through all of these:

1. **Network**: nothing listens on a port. The one outbound request (rate
   feed) is HTTPS only, TLS 1.2 or 1.3, certificate checked against the
   built-in root list, fixed URL, no redirects, 10 s and 64 KB limits, and
   only in builds with the `online-rates` feature.
2. **Input**: allow-list validation in `input.rs` and `money.rs`; the feed
   is parsed strictly and its numbers go through the typed-rate parser.
3. **Authorisation**: session types; the compiler rejects wrong-role calls.
   Every action re-checks its session against the bank that issued it and
   the database (`Atm::admit`), and a change checks again inside the write
   lock (`Atm::begin_for`). Out of service, only a Teller Admin gets in.
4. **Business rules**: limits (with a ceiling), caps, freezes, balances,
   cash maximum, starting-balance caps (per account, and $20,000 a day per
   teller), rate limits (5% a day typed; a big feed move pauses), fee
   bounds, approval caps, one unlock per card per day, guest restrictions,
   activity rules on every withdrawal, transfer and guardian move, all in
   the library.
5. **People**: a Teller Admin reviews every feed before it changes a rate,
   checks ID before a release, an approval or an unlock, and reviews before
   resuming service. Holders confirm a joint holder or guardian with their
   own card and PIN.
6. **Atomicity**: one IMMEDIATE transaction per action, including a feed
   approval (re-checked inside it); the new seal is written in the same
   transaction.
7. **Database**: STRICT tables, CHECK constraints (balances 0 to
   `Cents::MAX`), append-only triggers, defensive mode, and the seal over
   every row, checked before every operation together with SQLite's
   `integrity_check` (which covers the indexes).
8. **Cryptography**: Argon2id keyed per card or login, HMAC log chain,
   HMAC'd settings and rates, the database seal and the anchor tag, AES-GCM
   fields, keyed lookups for card and account numbers, key fingerprint,
   every stored MAC compared in constant time, TLS for the feed.
9. **Detection**: the seal (at once), the anchor (at start and on every
   operation), the integrity check at every Teller Admin sign-in (log
   chain, balances, cash, signed settings and rates, and limits, rates,
   freezes and closures against the log; every failure listed; out of
   service if anything fails), the activity-check holds, the clock check,
   the rate history (with each feed rate's source) and the written-down
   check code.

**Evidence.**
- 112 automated library tests (114 with `demo` and `online-rates`), 26
  attack tests (`tests/attacks.rs`, first written by a teammate on another
  branch), 13 review tests (`tests/review.rs`, one per hole the security
  review found in 0.6.0) and 4 audit tests (`tests/audit.rs`, for exploits
  of 0.7.0 that need a real file or the real program; one runs the real
  `atm` program). A plain `cargo test` runs 155 of them, plus the 5
  compile-fail checks. `tests/demo_mode.rs` adds 1 test in demo builds (2 in
  `integrity-test` builds). Each STRIDE row above names the
  test that proves it. The feed's parsing, checks, pausing and approval are tested
  with saved feed text, so the tests never go online. The fetch itself was
  checked by hand: behind a proxy that inspects HTTPS it is refused
  ("invalid peer certificate: UnknownIssuer"), and an `http://` URL is
  refused ("configured for https only"). The real source could not be
  reached from the build environment; try the live fetch on your own
  machine (`docs/TEST_PLAN.md`, section 8).
- 5 compile-fail tests prove a front end can't skip a check or make up a
  rate feed: the program doesn't build if it tries.
- The integrity check re-proves the log, every balance, the cash, every
  signed setting and rate, and each limit, rate, freeze and closure against
  the log at every Teller Admin sign-in, and on demand.
- A test-only build (`--features integrity-test`, run with `--demo
  --break-integrity`) adds $500 to one demo balance with no log entry, in its
  own files `atm-test.*`, so the red banner can be seen at the next teller
  sign-in. Normal and demo builds don't contain that code (checked with
  `nm`).
- `docs/FEATURES_AND_SECURITY_CHECKLIST.md`, section 3, is a step-by-step
  demo script (lockout, tamper detection, role separation, hidden PINs,
  timeout, rate limits, fees, holds, today's rates, card before cash).

**Back doors (Phase II).** Lecture 1 warns that hiding malicious code takes
less skill than finding it. What helps a reviewer: all rules sit in one small
library; no `unsafe`; every query uses bound parameters; front ends can't
reach the database; and a planted change to money, limits or rates breaks
the signed log or a test. An edit made outside the program is refused at
once by the seal. A planted change that writes through the program is
sealed like an honest one, so for that case the sign-in integrity check and
the tests are what catch it. The only network code is one short function
(`rate_feed::fetch`), compiled only with the `online-rates` feature, so a
reviewer has one place to check what the program sends out.

## 6. Assumptions

- The ATM runs on one computer, under one OS account that only the bank controls.
- Nobody can read or change the running program's memory (a debugger, or a
  memory editor). A teammate showed that editing a pending value in
  memory changes what the ATM then does. That takes control of the
  computer, the same control that could copy `atm.key`, so it is outside this
  model (a real ATM is a locked cabinet with a hardened OS). What still
  holds: the core re-checks limits, holds, approvals and balances when the
  money moves, and every change is in the signed log.
- One program runs on a bank at a time. If two do, the log chain stays whole
  and the anchor never moves backward (*(attacks)*
  `two_instances_at_once_do_not_break_the_audit_chain`).
- The "card" is simulated by typing its number (or, in demo builds, clicking
  it in the demo wallet). The deposit slot is simulated by typing bill counts
  (no counterfeit detection).
- The card network is simulated: a Teller Admin registers other banks' cards.
- Rates come from a Teller Admin: typed from the bank's treasury desk, or
  taken from a public daily feed (`open.er-api.com`) after review. The GUI
  goes online only for that button; nothing listens on a port, and customer
  actions never use the network.
- The feed's HTTPS certificate is genuine if it chains to a root in the
  Mozilla list built into the program. We trust those root authorities
  (see §7).
- The feed is right on most days. On a bad day, the teller's review and the
  pause on any move over 5% are what limit it.
- The system clock is roughly right (we refuse to start if it goes backwards).
  Daily limits, each teller's starting-balance total, the one-unlock-a-day
  rule and the activity-check windows (1 hour, 24 hours) rely on it. Moving
  it forward starts the next bank day early (§7).
- A new customer changes the PIN they chose at the counter at first use
  (§7).
- Tellers check photo ID before releasing a hold, approving a larger amount
  or unlocking a card, and the customer types their own card number and PIN
  for a joint holder or guardian. The program records which teller did it;
  it can't see the ID.
- `atm.key` is kept apart from backups of `atm.db`.
- In a real bank `atm.anchor` would be kept where someone who can put back
  an old `atm.db` can't put back an old anchor too (another machine,
  write-once storage). Here it sits next to `atm.db`.

## 7. Known limits (accepted risks)

| Risk | Why it remains | What would fix it |
|---|---|---|
| Someone steals **both** `atm.db` and `atm.key` | The key has to be somewhere the program can read. With both, they can also rebuild the log, re-seal the database and rewrite the anchor | Hardware security module or the OS keychain |
| Someone with the bank's OS account edits the program or files, or restores an older copy of **both** `atm.db` and `atm.anchor` | No program can defend against its own administrator. The older anchor's tag is valid, so the older pair opens; only the written-down check code shows it. It also rolls back the cash counts, so a Cash Handler could remove the same surplus again (a physical cash count shows it) | Signed binaries, read-only install, the anchor on another machine or write-once storage, or a separate audit server |
| A teller nudges a typed rate within the 5% daily limit to help an accomplice | Bounded at 5% from every rate in the last 24 hours; every change is in the rate history | A second person approves each rate (dual control) |
| The teller who opens an account learns the new customer's card number and first PIN | The customer types the PIN on the teller's form (masked, can't be copied out), and the teller sees the new card number. Nothing forces a PIN change at first use, which would need a new card state (every demo card would ask). Change PIN is on the customer menu, and every sign-in is logged | Force a PIN change at first use, or a PIN pad the teller's program never reads |
| Staff passwords, and a holder's PIN typed on the teller's forms, sit briefly in GUI text fields | Slint's text fields can't be wiped; the GUI clears them after each attempt and only keeps a wiped copy in Rust. They can't be copied out (no select-all, copy, cut or mouse selection in secret fields) | Custom input widget |
| An admin abuses allowed powers (freeze, unlock, approve a larger amount, release a hold, approve today's rates, resume service, open accounts with starting balances of up to $20,000 a day and no cash) | Logged with their name; approvals, starting balances and limits are capped; but there is no second approver | Two-person approval for sensitive actions |
| The Cash Handler login can't be reset, disabled or replaced | On purpose: no staff can be created or reset from the teller screen, or one insider could make themselves a handler. A leaked password gives access until the bank is set up again; the handler can change it, can't sign in while the ATM is out of service, and every cash action is logged and counted against the log | Staff management under dual control |
| Tellers can browse names and dates of birth with no log of who looked | Tellers need names and dates of birth to check ID; viewing isn't logged yet | Log each view |
| Any edit to `atm.db`, or a damaged or rolled-back `atm.anchor`, stops the whole ATM | On purpose (fail closed): nothing is decided from altered data. Whoever can write the file can stop the bank, but gains nothing. An older backup is refused too, so recovery means restoring a matching `atm.db` and `atm.anchor` pair, which loses what came after | Keep the files where only the bank can write; frequent backups of both files together |
| The sign-in check takes the ATM out of service until a teller resumes it | On purpose: integrity before availability, like a real ATM that stops itself on a fault. No card is taken and only a Teller Admin can sign in; the Cash Handler waits. One teller can resume, even while the check still fails (they have reviewed it); the resume is logged with the check's result, and the next sign-in halts it again | A second approver for a resume while the check still fails |
| A change made through the program that skips the log is found only at the next Teller Admin sign-in, and not for everything | The seal can't see it (the program sealed it); the integrity check is what catches it. It covers balances, cash, limits, rates, bank and guardian freezes and closures, but not fees, card locks, youth caps, joint holders or guardians (fees still carry their own MAC, and the seal stops edits in the file) | Run the check on a schedule as well; add the rest to it |
| The seal reads the whole database on every operation | It grows with the log. Measured on a release build of 0.8.0 (with the SQLite structure check): 13, 91 and 333 ms per seal check at 10,000, 50,000 and 200,000 log rows; the full check at Teller Admin sign-in 51, 246 and 921 ms. A demo bank has a few hundred rows. Each failed login with an unknown card adds a row | Verify only the rows added since the last check (keep the last verified seal in memory), or seal per day |
| A mis-stocked machine (all $5 bills, or a typo in a count) can't be corrected | Restock stops at the maximum and removal only works above it. Counts are logged and matched against the log, so a typo shows | A cassette swap done by two people |
| The fee or rate the customer confirms is worked out again when the money moves | If another teller changes the fee in between, the new fee is charged without a second prompt. Fee changes are logged, capped (5% and $10) and rare; a typed rate moves at most 5% a day | Pass the confirmed amount back and refuse if it changed |
| The 3-miss limit on unknown account numbers counts per session | Signing in again starts a new count. Account numbers are 10 random digits, each try needs a real card and PIN, every sign-in is logged, and a hit shows only initials | Count misses per card per day in the log |
| Someone who knows a card number can keep it locked for the day | 3 wrong PINs lock it, and a teller unlocks a card once per bank day; more unlocks would let a teller guess PINs between them. Card reissue is not in scope | Card reissue |
| The key fingerprint uses the audit-log MAC key, not its own | Not exploitable: its input can't collide with a log row's, and the fingerprint is public. Changing it would make every existing bank fail its key check | A new key label with a schema version change |
| `atm.db` permissions on Windows | Owner-only permissions are only set on macOS/Linux | Windows ACLs |
| Typed bill counts are trusted | No real hardware in this project | Bill validator hardware |
| Someone who knows an account number sends it $500+, so the owner's next large withdrawal trips rule 5 | A nuisance, not theft: no money moves, a teller releases it, the sender is logged | Ignore money from accounts the owner already pays, or let the customer confirm by phone |
| The activity rules are simple speed and amount checks, not a fraud model | A thief who stays under every rule still gets up to the daily limits | A scored fraud engine tuned on real data (textbook §12.5.4) |
| The rule thresholds are constants in the code | On purpose: a teller setting would let one insider switch them off. Changing them needs a new build | A second person approves any change |
| Rule windows and the bank day use the system clock | Rolling it back is refused at start (`audit.rs` → `check_clock`). Moving it forward starts the next bank day early, so daily limits, the once-a-day unlock and the hold windows reset. Whoever controls the OS clock is outside this model (§6) | A trusted time source |
| A card that is already locked says "locked" at once | An unknown number also says "locked", but only after 3 tries, and that count is kept in memory, so a restart resets it. The customer needs to know to see a teller; it only reveals cards that are already locked | Show the same message and print a slip |
| A hacked or coerced certificate authority issues a certificate for `open.er-api.com` (textbook §5.7.4: hundreds of CAs, "all more or less equally trusted") | Any root in the built-in list is trusted. No pinning (it breaks whenever the source renews its certificate) and no revocation check | A contracted feed on a pinned or private PKI. Meanwhile the believable range, the teller's review and the pause on big moves limit the damage |
| The source publishes a wrong rate, and the teller approves it (or confirms a wrong big move and resumes it) | Within 5% it is set without a pause, like a typed rate; a bigger move stays paused until a teller resumes it. The believable range bounds both, and each step is logged with the source, publish time and teller | Compare two independent sources before resuming; a second person approves (dual control) |
| The feed is a free service with no contract | It can change its format or stop. A new format is refused, not guessed at; typing a rate still works | A paid, contracted feed |
| The trusted root list is fixed when the program is built | A root that Mozilla later removes (as browsers removed DigiNotar's, textbook §21.6) stays trusted until a rebuild | Rebuild with a current `webpki-roots` regularly |
| A network that inspects HTTPS with its own certificate blocks the feed | On purpose: the computer's certificate store is not used, so that certificate is refused | Type the rates, or run the check on another network |
| The teller's screen waits up to 10 s while the feed is fetched | The fetch runs on the screen's own thread, which keeps the code short | Fetch on a background thread |
| Building the GUI and the CLI together (`cargo build --workspace`) gives that CLI the rates option 8 | Cargo turns a feature on for every program in one build | Build the CLI on its own (`cargo build --release`) for a CLI with no network code |
