# Where each security choice comes from

We built the ATM from what the course teaches. This page maps every
security mechanism to its source. Where we went beyond the course, it says
why, so the reason is ready if the professor asks.

Sources:

| Short name | What it is |
|---|---|
| **L1-L4** | Lecture 1 Introduction, Lecture 2 Rust, Lecture 3 Practical crypto, Lecture 4 TLS (slide numbers) |
| **Crypto lab** | The `lab-crypto-engineering` lab (`src/main.rs`, `Cargo.toml`) |
| **Lab 1** | "More fun with Rust" (minigrep) questions |
| **Textbook** | Ross Anderson, *Security Engineering*, 3rd ed. (the course reading), by section |

---

## 1. Method

| What we did | Source |
|---|---|
| Threat model built as Policy → Incentives → Mechanisms → Assurance | L1 slides 19-21, 24, 32, 48 |
| Asset list and a data flow diagram with the protection written on every link | L1 slides 22-23 ("State encryption method & strength") |
| STRIDE, each threat tied to the property it protects | L1 slides 24-31 |
| Adversaries grouped as cybercrime, users abusing the system, and insiders | L1 slides 33-47 (cashout gangs slide 44, insiders slide 45) |
| Layers of protection, so one failure doesn't break everything | L1 slide 43 (Stuxnet: "protection at any layer would have broken the links") |
| Planning for planted back doors (Phase II) | L1 slide 45 ("skill level needed to hide malicious code is much lower than needed to find it") |
| Study of how ATMs actually fail (shoulder surfing, receipts, insiders) | Textbook §12.4 Automatic teller machines |
| Study of how banks catch fraud after login (fraud engines, mules, push-payment fraud) | Textbook §12.5.4, §12.7.1, §12.7.6 |

## 2. Cryptography

| Mechanism | Where in our code | Source | Beyond the course? |
|---|---|---|---|
| AES-256-GCM for customer names, birth dates, card numbers and account numbers | `keys.rs` → `seal`, `unseal`; `db.rs` → `seal_number`, `open_number` | Crypto lab (same `aes-gcm 0.10.3` crate); L3 slide 14 (encryption gives confidentiality); textbook §5.5.6 ("the sensible default for authenticated encryption") | No |
| A fresh random 12-byte nonce on every encryption, stored with the ciphertext | `keys.rs` → `seal` | Crypto lab (`generate_nonce(&mut OsRng)`, appended to the ciphertext); textbook §5.5.3 (reusing a keystream leaks the plaintext) | No. We put the nonce in front instead of at the end |
| Tests that an edited ciphertext or a wrong key fails | `keys.rs` → `fields_round_trip_and_resist_edits_and_swaps` | Crypto lab tests | No |
| Each ciphertext bound to its column and row (GCM "associated data" = column name + the row's lookup value) | `keys.rs` → `aad` | GCM feature, textbook §5.5.6 | **Small extra.** Stops someone copying one customer's encrypted name, or one row's encrypted number, onto another row. Uses the same AES-GCM call, no new algorithm |
| Card and account numbers found by a **keyed** hash (HMAC-SHA-256), not a plain SHA-256 | `keys.rs` → `lookup_hash`; `db.rs` → `lookup` | L3 slide 12 (pre-image resistance); textbook §3.4.9.2 (password cracking: hash every candidate and compare) and §5.6.2 (HMAC) | **Yes, see 4.4** |
| Card and account numbers treated as secrets at rest | `db.rs` schema (`*_lookup`, `*_enc`, `*_last4`) | Textbook §12.5.2 (most traded card numbers came from hacked merchant computers; PCI DSS rules for stored cardholder data) | No |
| SHA-256 | `keys.rs` (inside HMAC); `seal.rs` → `digest` | L3 slide 12 (pre-image and collision resistance); crypto lab `sha2` | No |
| Keys made by hashing a secret, one key per job (seven: PIN pepper, audit MAC, field encryption, record MAC, number lookup, database seal, anchor) | `keys.rs` → `derive` | L3 slides 11 and 13 (Hash(r) → sk); textbook §4.3 ("key diversification or key derivation") | No. We use HMAC-SHA-256 as the hash (see below) |
| **One hashing key per card and per login**: HMAC(pepper, "credential/v1", identity), where the identity is the card's lookup value + account + role, or the username + role. It is the secret key for that one Argon2id hash, so a hash copied to another row doesn't verify | `keys.rs` → `credential_key`; `auth.rs` → `card_identity`, `staff_identity`, `hash_secret`, `verify_secret` | L3 slides 11 and 13 (hash a secret to get a key); textbook §4.3 (key diversification: "each token's key is just its unique device number encrypted under a global master key", so someone who extracts one token's key "cannot masquerade as any other token") | No. HMAC used as the key derivation function, the same way as `derive` |
| **Database seal**: HMAC-SHA-256 over a change counter and a SHA-256 digest of every row of every table and the schema, written in the same transaction as each change and checked before every operation | `seal.rs` → `digest`, `check`, `write`; `keys.rs` → `seal_mac`, `seal_matches`; `lib.rs` → `Atm::begin`, `Atm::read`, `Tx::commit` | L3 slide 12 (collision resistance: two different databases can't give the same digest); L3 slide 14 (integrity); crypto lab `sha2`; textbook §5.6.2 (HMAC); L1 slide 27 (tampering: "records in a database") | **Small extra, see 4.6.** No new algorithm |
| **Anchor file**: the newest seal counter and MAC, with an HMAC tag; an older copy of the database (lower counter) is refused | `anchor.rs` → `Anchor::read`, `advance`; `keys.rs` → `anchor_tag`, `anchor_tag_matches`; `lib.rs` → `Atm::start` | L4 slide 12 (version rollback attacks); textbook §4.3 (freshness: a nonce "can be a random number, a counter ..."), §3.4.8.3 (the iPhone PIN counter beaten by restoring saved memory "after several PIN attempts") and §6.4.2 (backup and recovery: "People can reacquire access rights that were revoked") | **Small extra, see 4.6** |
| Random keys, salts and nonces from the operating system | `keys.rs`, `auth.rs` (`getrandom`) | Crypto lab (`OsRng`, which reads the same OS source) | No |
| Secret key kept out of the database, never sent anywhere | `keys.rs` → `load_or_create` | L3 slides 3-4 (sending the key with the data is a "bad idea") | No |
| **HMAC-SHA-256** chain on the audit log; HMAC on limits, fee rules and rates; the database seal and the anchor tag | `audit.rs` → `append`, `verify_chain`; `keys.rs` → `record_mac`, `seal_mac`, `anchor_tag` | Textbook §5.6.2 (HMAC is "the accepted way" to compute a MAC with a hash) | **Yes, see 4.1** |
| **Argon2id** with a salt and a secret key for PINs and passwords (one key per card or login, made from the pepper) | `auth.rs` → `hash_secret` | Textbook §3.4.9.1 (a salt plus "a slow, cryptographically strong one-way function") | **Yes, see 4.2** |
| Timing-safe checks (same time for an unknown card and a wrong PIN, from the first try after a start; constant-time compare) | `auth.rs` → `burn_time_like_a_real_check`, `warm_up`; `keys.rs` → `matches` (seal and anchor MACs); inside `argon2` and `hmac` | Textbook §3.4.8.3 (timing attacks on PIN checks) | Small extra, see 4.3 |
| **Stored MACs compared in constant time** (0.8.0): every character is compared, with no early exit, for the log chain, settings, rates, rate history, the key fingerprint and the anchor | `keys.rs` → `same_mac`; used by `audit::verify_chain`, `db::get_setting`, `db::check_version_and_key`, `fx::read_rate`, `fx::read_history`, `Atm::start` | Textbook §3.4.8.3 (timing attacks on PIN checks), the same idea applied to a MAC: an early exit would show how many leading characters of a guess were right | Small extra, see 4.3 |
| PINs and key bytes wiped from memory after use | `zeroize` in `keys.rs`, `auth.rs`, `gui/` | Textbook Ch. 18 (zeroising keys in tamper-resistant devices) | Small extra, see 4.3 |
| Known-strong settings only: AES-256, Argon2id's standard parameters, no weak options | `keys.rs`, `auth.rs` | L4 slide 54 ("mandates the use of known-strong configurations"); L4 slides 14-28 (export-grade crypto) | No |
| The daily rate feed is fetched over **TLS** (HTTPS), not plain HTTP | `rate_feed.rs` → `fetch` | L4 slide 3 ("Modifying information in transit can lead to misinformation spreading": integrity of data in transit); L4 slides 6-9 (the TLS handshake); textbook §5.7.5 (TLS protects requests and responses "against both eavesdropping and manipulation") | No |
| **Certificate validation**: the server's certificate must chain to a root certificate built into the program (Mozilla's list, `webpki-roots`), not the computer's own store | `rate_feed.rs` → `fetch` (`RootCerts::WebPki`) | L4 slides 6-9 ("Client verifies signature on certificate"; slide 8: root and intermediate certificate authorities); textbook §5.7.5 (the client "checks the key that signed it in another certificate, and so on back to a root certificate ... stored in the browser"), §5.7.4 and §21.6 (CAs and PKI: why trusting a CA is a risk) | No |
| **No downgrade or rollback**: HTTPS only (an `http://` address is refused), TLS 1.2 and 1.3 only, no export or other broken cipher suites offered | `rate_feed.rs` → `fetch` (`https_only(true)`); rustls | L4 slide 12 (version rollback attacks), slide 17 (downgrade attacks), slides 21-28 (MITM negotiation; "Modern clients don't offer broken cipher suites like RSA_EXPORT"), slides 29-30 (the client offering only strong suites), slides 31-41 (FREAK and LogJam: client bugs, "fix implementations"); textbook §5.7.5.1 (a middleperson forcing weak keys), §5.7.5.2 (browsers reject obsolete ciphersuites; strict transport security "to prevent downgrade attacks") | No |
| **Known-strong TLS configuration**: rustls with forward-secret ECDHE (X25519, P-256, P-384) and AES-GCM or ChaCha20-Poly1305 only | rustls (through `ureq`) | L4 slide 54 (TLS 1.3 "removes insecure cryptography", "mandates the use of known-strong configurations"); L4 slide 2 and L3 slides 11 and 13 (Diffie-Hellman → r, Hash(r) → sk: what the TLS key exchange does); textbook §5.7.5.3 (TLS 1.3 and forward secrecy) | No. Choosing a TLS library is, see 4.5 |
| A proxy that inspects HTTPS with its own certificate is refused | `rate_feed.rs` → `fetch` | L4 slides 21-28 (a man in the middle); textbook §5.7.5.3 (banks "routinely intercept encrypted sessions"; TLS 1.3 makes that harder) and §21.6 (governments getting their own roots trusted) | No |

## 3. Everything else

| Mechanism | Where | Source |
|---|---|---|
| 3 wrong PINs lock the card; the count survives a restart | `auth.rs` → `login_customer` | Textbook §3.4.8.3 (retry counters) |
| An unknown or closed card answers exactly like a real one: "Login failed" twice, then "card locked" (counted in memory, at most 10,000 numbers) | `auth.rs` → `like_a_real_card` | Textbook §3.4.9 (failed logins and logs can leak secrets); L1 slide 29 (information disclosure). The memory bound is L1 slide 30 (denial of service) |
| A teller can unlock a card once per bank day, typing the number from the card the customer hands over; the locked list shows the last 4 only | `admin.rs` → `unlock_card`, `locked_cards` | Textbook §3.4.8.3 (defeats of retry counters: restoring a phone's memory between tries let all "10,000 possible PINs" be tried instead of ten); L1 slide 45 (insiders) |
| A wrong PIN typed at the counter (joint holder, youth account, guardian) counts toward the same lock | `auth.rs` → `confirm_at_counter`; `admin.rs` → `confirmed` | Textbook §3.4.8.3 (retry counters) |
| No PIN or password ever written to the log | `audit.rs` | Textbook §3.4.9 ("the log usually contains a large number of passwords") |
| Receipt question before any money moves; a withdrawal returns the card before the cash and ends the session first | `gui/src/customer.rs` → `receipt_choice`, `return_card`, `take_card`, `take_cash` | Textbook §3.2.1 (post-completion errors: "More people leave cards behind in ATMs that give them the money first and the card back second") |
| At most 40 bills per withdrawal | `dispense.rs` → `MAX_BILLS`, `plan_withdrawal` | L1 slides 24-31 (availability, STRIDE D: one customer can't empty a drawer of small bills); general practice (real dispensers cap notes per payout) |
| Card and account numbers masked on screen, receipts and "Send again" | `gui/src/main.rs` → `last_four_typed`; `customer.rs` → `mask`, `recent_payees` | Textbook §12.4.2 (shoulder surfing and thrown-away ATM slips) |
| Screens wiped when a session ends: the GUI clears every screen property that held someone's data; the command line clears the screen and its scrollback (0.8.0) | `gui/src/main.rs` → `go_welcome`; `input.rs` → `wipe_screen` | Textbook §12.4.2 (shoulder surfing: whatever is left on show can be read by the next person); L1 slide 29 (information disclosure) |
| PIN and password fields on the teller screen can't be copied out: no select-all, copy or cut, and no mouse selection (0.8.0) | `gui/ui/theme.slint` → `Field` | Textbook §12.4.2 (shoulder surfing); L1 slide 29 (information disclosure); L1 slide 45 (insiders: here, the teller at the screen) |
| Log names a card by row id and last 4 digits, never the full number | `db.rs` → `customer_actor`, `card_ref` | Textbook §3.4.9 (logs collect secrets they shouldn't) |
| Append-only audit log written in the same transaction as the money | `db.rs` triggers; `audit.rs` | L1 slide 28 (repudiation: a system "that lacks the ability to trace the operations"); textbook §12.2.3 (Clark-Wilson: every transaction writes to an append-only audit trail) |
| Balances recomputed from the log (integrity check), also at every Teller Admin sign-in | `audit.rs` → `reconcile_balances`, `verify`; `service.rs` → `check_at_sign_in` | Textbook §12.2.1 (double-entry bookkeeping); L1 slide 45 ("Easy to hide code in large software packages": the seal can't tell a bad write by the program itself, the books can) |
| The cash in the machine counted against the log: the bill counts must equal restocks + deposits − withdrawals − removals (0.8.0) | `audit.rs` → `reconcile_cash`, `verify` | Textbook §12.2.1 (double-entry bookkeeping: the cash is one more account that must balance) and §12.2.3 (Clark-Wilson: the audit trail holds enough to reconstruct every transaction, so the cash can be worked out from it); L1 slide 45 (a planted extra-bill payout leaves every balance right) |
| Daily limits, exchange rates, freezes and closures matched against their newest log entry (0.8.0) | `audit.rs` → `reconcile_state` | Textbook §12.2.3 (Clark-Wilson: every change goes through the audit trail, so a change with no log entry is an error); L1 slide 45 (code that changes state without logging it) |
| The integrity check reports every failure, not just the first; each account by its last 4 digits, with both amounts (0.8.0) | `audit.rs` → `verify`, `reconcile_balances`; `error.rs` → `IntegrityFailures` | Textbook §12.2.4 (prevent – detect – recover: a known problem must not hide the next one from detection); §3.4.9 (logs collect secrets they shouldn't) for the last 4 digits |
| SQLite's own `PRAGMA integrity_check` runs with every seal check, so an index edited in the file is refused (0.8.0) | `seal.rs` → `check` | Not from the course: a feature of SQLite, not course cryptography. The threat is L1 slide 27 (tampering with records in a database). See 4.6 |
| A finished change is never reported as failed; if `atm.anchor` can't be written, the ATM does nothing else until it is (0.8.0) | `lib.rs` → `Tx::commit`, `catch_up_anchor` | Fail closed as in textbook §7.3.1.2 |
| **Out-of-service mode**: a failed sign-in check halts the ATM at once (fail closed); the start screen takes no card, the Cash Handler can't sign in, and live customer and Cash Handler sessions stop; only a Teller Admin signs in; a teller can also halt by hand | `service.rs` → `check_at_sign_in`, `halt`, `out_of_service`, `refuse_if_halted`; `auth.rs` → `login_customer`, `login_staff`, `Atm::admit`; `gui/ui/customer.slint` → `WelcomeScreen` | Textbook §7.3.1.2 (fail-stop processes "stop when an inconsistency is detected; for example, bank transaction processing will typically stop if an out-of-balance condition is detected"); §27.5.6.2 ("Which components should fail open, and which should fail secure?"); L1 slide 30 and L4 slide 3 (availability: halting is a denial of service we choose, so it costs only availability, never money) |
| Resume is a teller's decision after review, logged with the check's result; one teller can do it | `service.rs` → `resume` | Textbook §12.2.4 (prevent – detect – recover: the sign-in check detects, the halt stops further harm, and the teller's review and resume is the recovery); §12.2.4 also names the missing piece, dual control ("two or more principals act together to authorize a transaction"), still open |
| Out of service = the newest halt or resume row in the signed log, not a flag | `service.rs` → `halted` | L1 slide 27 (tampering with records in a database); textbook §12.2.3 (Clark-Wilson: append-only audit trail) |
| Teller and Cash Handler can't do each other's jobs; tellers can't move money or set PINs | session types in `auth.rs`; `admin.rs`; `cash.rs` | Textbook §12.2.4 (separation of duty) and §6.2.1 (roles) |
| A joint holder, youth account or guardian needs the current holder's (or parent's) own card and PIN at the counter | `auth.rs` → `CardAndPin`, `confirm_at_counter`; `admin.rs` → `add_joint_holder`, `open_youth_account`, `add_guardian` | Textbook §12.2.4 (dual control: "two or more principals act together to authorize a transaction"; here the customer is the second principal); L1 slide 45 (insiders) |
| The bank's freeze and a guardian's freeze are separate; each side lifts only its own. The bank's freeze refuses the account's cards entirely (sign-in, live sessions, transfers in, consent at the counter); a guardian's stops only money out | `admin.rs` → `set_frozen`; `family.rs` → `set_frozen`; `auth.rs` → `login_customer`, `confirm_at_counter`; `customer.rs` → `destination`; `family.rs` → `move_money` | Textbook §12.2.4 (separation of duty); §6.4.4 (least privilege). Refusing the card entirely is general practice for a card reported stolen (no course source) |
| A starting balance is at most the daily deposit limit, and one teller's starting balances are at most $20,000 a bank day together; a teller can set a limit only up to a ceiling; every amount is at most `Cents::MAX` | `admin.rs` → `insert_account`, `STARTING_BALANCES_PER_DAY`, `set_limit`; `audit.rs` → `opened_today_by`; `db.rs` → `Limit::ceiling`; `money.rs` → `Cents::MAX` | Textbook §12.2.5 (insider frauds); L1 slide 45 (insiders). The $20,000 figure is ours: two accounts at the default deposit limit |
| Each role gets only the functions it needs | session types | Textbook §6.4.4 (principle of least privilege) |
| A guardian's Move money only goes between the child and the guardian's own account, and goes through the six activity rules like any transfer | `family.rs` → `move_money`; `review.rs` → `screen` | Textbook §6.4.4 (least privilege): enough power to take money back, none to pay anyone else; §12.5.4 (fraud engines) for the rules |
| Typed-rate limit (5% in 24 hours), rate history and pause against a rogue teller | `fx.rs` → `check_change_cap`, `set_paused` | L1 slide 45 (insiders); textbook §12.2.4-12.2.5 (internal controls, insider frauds) |
| Fee bounds (0-5%, minimum $0-$10), HMAC'd and logged old → new | `fx.rs` → `set_fee_rule` | L1 slide 45 (authorized users are also threats); textbook §12.2.4 (internal controls) |
| Fee = a percent of the amount with a minimum ("3% of the amount, $3.00 minimum", the way bank fee schedules word it), shown as a sum (withdrawal + each fee = total, then the account amount) with the fee rule and rate in small print, each part rounded in the bank's favour | `fx.rs` → `FeeRule::on`, `FeeRule::short`, `Conversion::summary`, `Conversion::fine_print`, `charge_for` | General practice (no course source) |
| Daily limits at typical US bank levels ($1,000 cash, $10,000 deposit, $5,000 transfer); $10,000 is the US cash-reporting line | `db.rs` → `insert_defaults` | General practice (US Currency Transaction Report rule; no course source) |
| A rate from the feed is only a proposal: a teller reviews it and approves; the same range, HMAC and log apply as for a typed rate, and a move over 5% in a day is set paused until a teller checks it and resumes | `rate_feed.rs` → `check`, `plan`, `approve`; `fx.rs` → `store_rate` | Textbook §12.2.4 (functional separation of duty: one party proposes, another approves); L1 slide 45 and textbook §12.2.5 (insiders) for the pause |
| Only `fetch` can make a rate feed: `Feed`'s fields and `parse` are private, so a front end can't hand in rates of its own choosing; a compile-fail test in `lib.rs` proves it (0.8.0) | `rate_feed.rs` → `Feed`, `fetch`; `lib.rs` (compile-fail) | Textbook §12.2.4 (functional separation of duty: the feed proposes, a teller approves; a feed the front end wrote itself would be both); §6.4.4 (least privilege) |
| An approval re-checks, in one transaction, that the rates are still what the teller saw | `rate_feed.rs` → `approve` | Textbook §6.4.2 and §7.2.1 (time-of-check-to-time-of-use: "attacks still crop up ... at higher levels such as business logic"); §7.2.2 (locking) |
| The feed must be recent (published in the last 48 hours) | `rate_feed.rs` → `parse` | Textbook §7.2.1 (replay: passing off "out-of-date credentials"); L4 slide 12 (rollback) |
| The feed is parsed strictly; its numbers go through the typed-rate parser; a bad number is skipped, never guessed | `rate_feed.rs` → `parse`, `to_micros`; `fx.rs` → `parse_fixed` | Textbook §6.4.2 (failures "to sanitise input"); L2 slide 6 (Rust is memory safe and type safe, and `serde_json` is Rust) |
| Only a teller's button goes online; the network code is compiled only with the `online-rates` feature | `Cargo.toml`; `rate_feed.rs` → `fetch` | Textbook §6.4.4 (least privilege: only the GUI build gets the network); L1 slide 43 (layers) |
| 10 s and 64 KB limits on the fetch; a failure changes nothing | `rate_feed.rs` → `fetch`; `error.rs` → `FeedUnavailable` | L1 slides 24-31 (availability, STRIDE D); L4 slide 3 ("Disabling an online service would be financially catastrophic"). The numbers are general practice |
| Fixed feed address, no redirects | `rate_feed.rs` → `FEED_URL`, `fetch` | General practice (no course source) |
| Teller approval over a daily limit: one account, today only, capped, refused for youth and guest accounts | `admin.rs` → `raise_limit_today`; `db.rs` → `Limit::max_raise` | Textbook §12.5.1 (floor limits: above a set amount the merchant must call the bank for authorization); §12.2.5 (insider frauds) and L1 slide 45 for the cap |
| Holds on unusual activity: six fixed speed and amount rules | `review.rs` → `screen`, `matched_rule` | Textbook §12.5.4 (fraud engines use "thresholding and other techniques to look for unusual patterns"; false positives are the big problem); §12.2.4 ("prevent – detect – recover"); L1 slide 44 (cashout gangs) |
| Rule 4: $1,000+ to a payee not paid before today (only a payment on an earlier bank day counts, so a one-cent transfer can't switch it off) | `review.rs` → `matched_rule` | Textbook §12.7.6 (authorised push payment fraud: "Even medium-sized transactions get held up") |
| Rule 5: $500+ out within an hour of $500+ coming in | `review.rs` | Textbook §12.7.1 (a mule "should find his account frozen before he can walk to Western Union"); §2.3.1.6 (cashout gangs use mules) |
| Holds and approvals are signed log rows, not flags | `review.rs` → `hold_reason`; `customer.rs` → `limit_status` | L1 slide 27 (tampering with records in a database); textbook §12.2.3 (Clark-Wilson: append-only audit trail) |
| Rule thresholds fixed in code, not teller settings | `review.rs` constants | L1 slide 45 (authorized users are also threats); textbook §12.2.5 (insider frauds) |
| Customer is told "unusual activity", not which rule | `error.rs` → `OnHold` | General practice (no course source) |
| Recent payees read from the signed log | `customer.rs` → `recent_payees` | General practice; masking as in §12.4.2 |
| Program refuses an older or different database (version and key fingerprint), and a missing database whose key or anchor is still there (no first-run setup after deleting `atm.db`) | `db.rs` → `check_version_and_key`; `lib.rs` → `Atm::start` | L4 slides 12, 17 (rollback and downgrade attacks); fail closed as in §7.3.1.2 |
| Sessions only work on the bank that issued them, and every action re-checks them (card locked, account closed or frozen by the bank, staff row gone, out of service); a change checks again once it holds the write lock, so a halt, lock or closure that lands while it waits still stops it | `lib.rs` → `Atm.id`; `auth.rs` → `Atm::admit`, `Atm::begin_for`, `Session` | Textbook §6.4.2 (race conditions, where "access rights are verified at the first stage and something sensitive is done at the second"); §7.2.2 (locking); L1 slide 26 (spoofing) |
| A customer's history masks other people's accounts and cards | `audit.rs` → `for_customer` | Textbook §12.4.2 (masking) and §6.4.4 (least privilege) |
| Every table is STRICT; CHECK constraints on every value (balance 0 to `Cents::MAX`, flags 0 or 1, roles, bill types) | `db.rs` → `SCHEMA`; test `strict_tables_refuse_values_of_the_wrong_type` | Textbook §6.4.2 (failures of "type safety", when "data in grammar A is interpreted as being code in grammar B", and failures "to sanitise input"); L2 slide 6 (Rust is "Type safe": STRICT gives the database the same rule) |
| Demo data is marked in the sealed database; a normal build refuses it, and demo mode refuses a real bank | `db.rs` → `mark_demo`, `is_demo`; `lib.rs` → `Atm::open`, `open_demo` | Rubric; textbook §3.4.4.4 ("failing to reset default passwords"): demo logins are published |
| The integrity test is a separate cargo feature, using its own `atm-test.*` files | `Cargo.toml` (`integrity-test`); `demo.rs` → `break_integrity`; `main.rs` → `run_demo` | General practice (test code stays out of the graded build); Zack asked that the test never touch the working data |
| Clock rollback refused | `audit.rs` → `check_clock` | L4 slide 12 (rollback), applied to time |
| One IMMEDIATE transaction per action, so two actions can't race | `lib.rs` → `Atm::begin` (used by every change) | Textbook §7.2.2 (locking to prevent inconsistent updates) |
| Rust with no `unsafe` code; immutable by default; ownership stops a session being reused after logout | `lib.rs` (`#![forbid(unsafe_code)]`), `auth.rs` | L2 slides 6, 11-13, 36, 46 |
| No built-in passwords | `auth.rs` → `first_run_setup` | Rubric; textbook §3.4 (default passwords) |
| Database hardening (defensive mode, `trusted_schema` off, `secure_delete` on) | `db.rs` → `configure` | L4 slide 54 (known-strong configurations); textbook §6.2.10.1 (database access controls) |
| Few, well-known libraries, versions pinned in `Cargo.lock` | `Cargo.toml` | Lab 1 question 3 ("drawbacks of using external libraries… what could go wrong?"); crypto lab's fixed dependency list |

## 4. Beyond the course, and why

### 4.1 HMAC instead of digital signatures

Lecture 3 (slides 14-16) protects integrity with signatures: sign with a
secret key, verify with a public one. We use HMAC because:
- The same machine writes **and** checks the log. A signing key would have
  to sit on that machine next to the log anyway, so signatures add nothing
  here.
- HMAC is the textbook's "accepted way" to put a key into a hash (§5.6.2).
  The naive version, SHA-256(key + message), is not safe.
- It is SHA-256 underneath, which the lecture and lab already cover.

Signatures would matter if an outside auditor checked the log with only a
public key. That is a possible future step, listed in `VULNERABILITIES.md`.

### 4.2 Argon2id for PINs and passwords

No lecture covers storing passwords. The textbook says (§3.4.9.1): "generate
a random key, historically known in this context as a salt; combine the
password with the salt using a slow, cryptographically strong one-way
function; and store both the salt and the hash."
- Argon2id is that function. Argon2 won the 2015 Password Hashing
  Competition, and Argon2id is the variant OWASP's password storage guidance
  recommends first.
- Plain SHA-256 (the course's hash) is built to be **fast**: a graphics card
  tries billions per second. That is exactly what makes stolen password
  hashes easy to crack.
- A 4-digit PIN has only 10,000 values, so no hash alone can save it. The
  secret pepper from `atm.key` does: without the key file, a stolen database
  can't test even one guess. This is the course's own idea of keeping the
  key apart from the data (L3 slides 3-4).
- Each hash gets its own key, derived from the pepper and who the hash
  belongs to (`keys::credential_key`): the card's lookup value, account and
  role, or the staff username and role. So a hash copied onto another card,
  or a staff row switched from handler to admin, doesn't verify. That is
  the textbook's key diversification (§4.3), with HMAC as the hash (4.1).

### 4.3 Small extras

- **Timing-safe checks.** An unknown card takes as long to reject as a wrong
  PIN, so timing can't reveal which cards exist. Since 0.8.0 that holds from
  the first try after a start too: the stand-in hash is made when the bank
  opens (`auth::warm_up`). Stored MACs (the log chain, settings, rates, the
  key fingerprint, the anchor) are compared character by character with no
  early exit (`keys::same_mac`), so timing can't show how much of a forged
  MAC was right. The textbook covers timing attacks on PIN checks
  (§3.4.8.3); the MAC compare is the same idea.
- **Wiping secrets from memory** (`zeroize`). A PIN or key is erased as soon
  as it is used, so it can't be read from a memory dump later. The textbook
  describes zeroising keys in secure hardware (Ch. 18).
- **GCM associated data.** Same AES-GCM call as the lab, with the column name
  and the row's lookup value added as "associated data". Copying one
  customer's encrypted name, or one row's encrypted card or account number,
  onto another row is then detected.
- **STRICT tables.** A SQLite setting the course doesn't mention. It applies
  the textbook's input rule (§6.4.2: type safety, sanitised input) inside
  the database: a value of the wrong type is refused, not stored.
- **Unknown cards counted in memory.** To make an unknown number say "card
  locked" after 3 tries, like a real card, the ATM counts tries per unknown
  number. The count lives in memory, capped at 10,000 numbers, so an
  attacker typing random numbers can't make it grow without end (L1 slide
  30, denial of service). A restart forgets it; that is the trade-off.

### 4.4 Keyed lookup for card and account numbers

The database must find a card from the number someone types, so it needs a
searchable value. Lecture 3 (slide 12) says a good hash is pre-image
resistant: given the hash, finding the input is hard. That only holds when
there are too many inputs to try. There are just 10^10 ten-digit numbers, so
hashing every one with plain SHA-256 and comparing takes minutes. That is
the dictionary attack the textbook describes on password files (§3.4.9.2).
- We store HMAC-SHA-256(lookup key, kind, number) instead (`keys.rs` →
  `lookup_hash`). The lookup key is derived from `atm.key` (label
  `bank-of-ccny/number-lookup/v1`), so without the key file a stolen database
  can't test a single number. Same idea as the PIN pepper (4.2).
- "kind" is "card" or "account", so the same digits give different values in
  the two tables.
- The number itself is AES-GCM encrypted for the screens that need it, and
  the last 4 digits are kept in clear for receipts.
- Nothing new is added: HMAC (4.1) and AES-GCM (the lab) are already in use.

### 4.5 A TLS library for the rate feed

Lecture 4 teaches TLS from the protocol side: the handshake, certificate
checks, rollback and downgrade attacks, and TLS 1.3's known-strong
configurations. It doesn't pick a TLS library, and the crypto lab has none.
We use rustls (through the `ureq` HTTPS client) because it fits the lecture:
- It speaks only TLS 1.2 and 1.3 and only forward-secret, authenticated
  cipher suites, so there is no old version or weak suite to be downgraded
  to (L4 slides 12, 17, 54).
- It checks the server's certificate unless code turns that off (ours
  doesn't); we give it the Mozilla root list built into the program, so a
  certificate added to the computer doesn't count (L4 slides 6-9; textbook
  §5.7.5, §21.6).
- It is written in Rust (L2 slide 6). Its cryptography comes from `ring`,
  which is partly C and assembly, so our `forbid(unsafe_code)` doesn't
  cover it (stated in `VULNERABILITIES.md` #78).
- We wrote no cryptography and no protocol code ourselves. Lab 1 question
  2 asks when to use an existing library instead of writing your own; for
  TLS the answer is clear. Question 3's risks are covered under section 5.

The rest of the feed's safety comes from the course's own ideas, not from
TLS: the feed is a proposal a person approves (textbook §12.2.4), a move
over 5% in a day waits, paused, for a teller to check it (L1 slide 45), and
every rate it sets is in the signed log (textbook §12.2.3).

### 4.6 Sealing the whole database, with an anchor file

The course gives the parts: SHA-256 (L3 slide 12, the crypto lab), HMAC
(4.1) and freshness counters (textbook §4.3). Putting them together into one
seal over the whole database is our own design, so here is why.
- **Why.** Up to 0.6.0 most edits to the file were only *found* later, when
  a teller ran the integrity check. Until someone ran it, an edited
  balance could be spent, a cleared failure count gave more PIN guesses, a
  cleared flag lifted a bank freeze, reset staff columns removed the
  password pause, and an emptied staff table reopened first-run setup
  (review holes A1-A4, A6). That is L1 slide 27's tampering threat: changing
  "records in a database".
- **How.** Inside every change's own transaction, the ATM computes a SHA-256
  over every row of every table, and the schema, and stores HMAC(seal key,
  counter, digest) (`seal.rs`). Before every operation it computes the
  digest again and compares. Collision resistance (L3 slide 12) means a
  changed database can't give the same digest; the HMAC means nobody without
  `atm.key` can make a matching seal. So nothing is decided from altered
  data: the ATM stops (fail closed, textbook §7.3.1.2).
- **The anchor.** An old copy of the database is still correctly sealed. So
  the counter goes up by one per commit, and `atm.anchor` remembers the
  highest, HMAC-tagged (`anchor.rs`). That is the textbook's freshness by
  counter (§4.3). Its prepayment-meter example "checked only that the nonce
  was different from last time", so two old codes could be fed in turn; ours
  refuses anything lower than the highest seen. It also blocks the attack in
  §3.4.8.3 (restore a phone's saved memory after a few PIN tries, to get the
  tries back) and L4 slide 12's rollback, applied to a file.
- **Index pages (0.8.0).** The digest covers table rows and the schema,
  not index pages, yet an index decides which rows a lookup finds. Swapping
  two log indexes in the file left every row, and so the seal, unchanged,
  and let a customer pass the daily withdrawal limit. So every seal check
  first runs SQLite's own `PRAGMA integrity_check`, which confirms each
  index matches its table (`seal.rs` → `check`). This is a check SQLite
  provides and we run; it is not course cryptography.
- **Cost.** The whole database is read on each operation: milliseconds at
  this size, growing with the database.
- **Limits.** An older copy of both `atm.db` and `atm.anchor` together still
  matches; a real bank keeps the anchor on another machine or write-once
  storage. Someone with both `atm.db` and `atm.key` can re-seal anything,
  the same limit as every other key (`VULNERABILITIES.md`).
- No new crate or algorithm: `sha2` and `hmac` were already in use.

## 5. Libraries we use (Lab 1, question 3)

The crypto lab allowed four crates. We use two of them unchanged, skip two
we don't need, and add the rest for a specific job each:

| Crate | Why | In the crypto lab? |
|---|---|---|
| `aes-gcm` 0.10.3 | Encrypts names, birth dates, card and account numbers | Yes, same version |
| `sha2` | SHA-256: inside HMAC, and the database seal's digest of every row (4.6) | Yes (newer 0.11, required by `hmac` 0.13) |
| `x25519-dalek` | Not used. The one network link (the rate feed) does its X25519 Diffie-Hellman inside rustls (through `ring`) | Yes |
| `base64` | Not used. SQLite stores raw bytes | Yes |
| `hmac` | Signed audit log and settings (4.1); card and account number lookups (4.4); one hashing key per card or login (4.2); the database seal and anchor (4.6) | No |
| `argon2` | PIN and password hashing (4.2) | No |
| `getrandom` | OS randomness (what the lab's `OsRng` uses) | Indirectly |
| `zeroize` | Wipes secrets from memory (4.3) | No |
| `rusqlite` (bundled SQLite) | The database, compiled in | No |
| `chrono`, `chrono-tz` | Dates and the New York bank day | No |
| `rpassword` | Hidden PIN and password typing in the command line | No |
| `slint` | The GUI | No |
| flag-icons 7.2.3 (images only, MIT) | The small currency flags. Plain SVG pictures checked for scripts and outside links, then compiled into the program | No |
| `serde_json` 1.0 | Reads the daily rate feed (strictly). Always built, so parsing is tested without a network | No. Not taught in the course |
| `ureq` 3.4 with `rustls` 0.23, `ring` 0.17, `webpki-roots` 1.0 | One HTTPS request for the rate feed (4.5). Only built with the `online-rates` feature, which the GUI turns on | No. TLS is Lecture 4's topic, but no TLS library is taught or used in a lab |

What could go wrong (Lab 1's question): a library could have a bug or be
replaced by a malicious version. We keep the list short, use widely used
crates, and pin exact versions in `Cargo.lock`, so a build can't silently
pick up a new release.

The rate feed made the list longer, and we say so plainly. It adds 11
crates to `Cargo.lock` (`ureq`, `ureq-proto`, `http`, `httparse`, `rustls`,
`rustls-pki-types`, `rustls-webpki`, `ring`, `untrusted`, `utf8-zero`,
`webpki-roots`), though only in builds with `online-rates`. `ring` contains
C and assembly. The root list in `webpki-roots` is fixed when the program
is built, so it ages until the next build. The textbook gives the reasons
to care: supply-chain attacks on software updates (§2.2.2, the Asus case)
and old library versions (§27.5.4: "as many as 70% of apps ... have
vulnerabilities in the open-source libraries they use, and which could
usually be fixed by a simple update"). So: pinned versions, default
features off (no compression, cookies or JSON helper), and a rebuild with
current versions before each release, which also refreshes the root list.
