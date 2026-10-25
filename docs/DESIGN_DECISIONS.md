# Design decisions

Why the ATM is built the way it is. Each section gives the choice, the
reason, and what was considered instead. For the threats and defenses
themselves, see [`THREAT_MODEL.md`](THREAT_MODEL.md). For where each security
choice comes from in the course (lecture, lab or textbook section), see
[`COURSE_MAPPING.md`](COURSE_MAPPING.md).

---

## 1. Architecture: one secure library, thin front ends

**Choice.** All rules live in the `atm` library crate (`src/`). The GUI
(`gui/`) and the command line (`src/main.rs`, `src/ui.rs`) only collect input
and show results.

**Why.**
- One place to check. A rule written once can't be forgotten in a second
  front end.
- The front ends never get a database connection (`Atm` keeps it private to
  the crate), so they can't run SQL or skip a check.
- Each role gets its own session type (`CustomerSession`, `AdminSession`,
  `HandlerSession`). An admin function only accepts an `AdminSession`, so
  calling it with a customer session is a compile error, not a runtime check
  someone might forget. Five compile-fail tests in `src/lib.rs` prove this
  (the fifth: a front end can't make up a rate feed, section 20).
- Sessions can't be copied or built by hand, and logout consumes them.

**Considered instead.** One "ATM" object with a role field checked in every
function. Simpler, but one missed `if role == Admin` is a privilege
escalation.

## 2. Language: Rust

- Memory safety without a garbage collector; `#![forbid(unsafe_code)]` means
  no `unsafe` blocks can hide in our code.
- `Result` errors must be handled, so failures can't be silently ignored.
- Money is a `Cents` type (whole cents, checked arithmetic, never negative,
  no floats, at most `Cents::MAX` = 10^15 cents), so rounding and overflow
  bugs don't compile or are caught. The database has the same cap as a CHECK
  on every balance.

## 3. Storage: SQLite

**Choice.** One SQLite file, `atm.db`, built into the program (no server).
A bank is three files kept together: `atm.db` (the data), `atm.key` (the
secret key, section 4) and `atm.anchor` (the newest seal, below).

**Why.**
- **Atomic transactions.** A transfer debits, credits and writes the audit
  entry in one transaction: all of it happens or none of it. That is what
  actually protects the money.
- **Nothing to install.** No server, no Docker, no database password. The
  installation score depends on the instructor getting it running quickly.
- **No network port.** Nothing listens, so nothing on the network can
  connect to the ATM. (The program's only network use is one outbound
  request that a teller starts, section 20.)
- **Rules in the database too.** CHECK constraints (balances from 0 to
  `Cents::MAX`, valid bill types, flags 0 or 1), and triggers that make the
  audit log append-only, catch bugs even if the code had one.
- **Every table is STRICT.** SQLite normally stores any value in any column.
  STRICT tables refuse a value of the wrong type, so text or a fraction
  can't end up in a balance or a bill count (`src/db.rs` → `SCHEMA`; test
  `strict_tables_refuse_values_of_the_wrong_type`).
- **The whole database is sealed.** Every commit writes a seal in the same
  transaction: an HMAC of a counter plus a SHA-256 of every row of every
  table and the schema (`src/seal.rs`; `src/lib.rs` → `Tx::commit`). Every
  operation checks the seal before it reads or changes anything
  (`Atm::begin`, `Atm::read`). A row edited outside the ATM gives
  "TAMPERING DETECTED: the database was changed outside the ATM. Nothing was
  done. Stop and escalate." (fail closed). The cost is reading the whole
  database on each operation: milliseconds at this size.
- **Index pages are checked too (0.8.0).** The seal covers table rows, not
  index pages, so every seal check first runs SQLite's own
  `PRAGMA integrity_check` (section 28).
- **Older copies are refused.** The counter goes up by one per commit.
  `atm.anchor` keeps the newest seal, HMAC-tagged and written by rename
  (`src/anchor.rs`). An older copy of `atm.db` put back (to undo a withdrawal
  or a lock-out) has a lower counter: "DATABASE ROLLED BACK: this is an older
  copy of the bank's records. Nothing was done. Stop and escalate."
- **A finished change is never reported as failed (0.8.0).** If `atm.anchor`
  can't be written after a commit, the change still stands and is reported
  as done. The next operation writes the anchor first; until that works,
  the ATM does nothing else (`src/lib.rs` → `Tx::commit`,
  `catch_up_anchor`). Before 0.8.0 a blocked anchor made a finished deposit
  say "not completed" (audit F11; test
  `a_finished_deposit_is_never_reported_as_failed_and_a_blocked_anchor_stops_the_atm`).
- **Strict open.** A new bank is made only when none of the three files
  exists. A key or anchor without its database means the database was
  deleted, so the program refuses to start instead of offering first-run
  setup to whoever is at the machine (`Atm::start`).
- **Hardening.** Defensive mode on (blocks writes to SQLite internals),
  `trusted_schema` off, `secure_delete` on (deleted data is overwritten),
  full sync (a crash can't lose a committed transaction). `src/db.rs`.

**Considered instead.**

| Option | Why not |
|---|---|
| PostgreSQL / MySQL | Needs a server and credentials to manage, opens a network port, and adds install steps. More to secure, not less |
| SQLCipher (encrypted SQLite) | Builds OpenSSL from source: slow and fragile on demo day. The key still has to live on the same machine |
| Files / in-memory only | No transactions; lockouts and logs would vanish on restart |

**SQLite's weakness**, and how it is covered: the file has no logins and no
encryption of its own, so anyone who copies `atm.db` can open it, and anyone
who can write to it can change it. Section 4 (keys and encryption) and the
seal above are the answer.

## 4. The key file (`atm.key`) and what it protects

On first run the program creates `atm.key`: 32 random bytes from the
operating system, owner-only permissions, stored **outside** the database.
Seven keys are derived from it (HMAC-SHA256 with a different label each), so
no key is used for two jobs (`src/keys.rs` → `derive`). This is Lecture 3's
"hash the shared secret to get the key" step, done once per purpose:

| Key | Used for | Stops |
|---|---|---|
| PIN pepper | Never used directly. Each PIN or staff password gets its own Argon2id key, made from the pepper and who it belongs to (below) | Offline guessing. A 4-digit PIN has only 10,000 options; without the key file a stolen database can't test even one |
| Audit MAC key | Each log entry carries an HMAC of the entry and the previous entry's HMAC | Editing or deleting log entries. Without the key, nobody can recompute the chain |
| Field key | Customer names, birth dates, card numbers and account numbers are AES-256-GCM encrypted, with a fresh random nonce each time (as in the crypto lab) | Reading personal data or numbers from a copied database. GCM also detects edits, and each value is bound to its column and its row's lookup value, so values can't be swapped between rows |
| Record MAC key | Daily limits, fee rules, exchange rates and every rate-history row carry an HMAC | Changing a limit, fee or rate straight in the database file |
| Lookup key | Each card and account row is found by an HMAC-SHA-256 of its number (label `bank-of-ccny/number-lookup/v1`, with "card" or "account" mixed in) | Recovering a number from a copied database by trying every 10-digit number |
| Seal key | The database seal: an HMAC of the change counter and a SHA-256 of every row (section 3; `keys::seal_mac`, `seal_matches`) | Any edit to `atm.db` made outside the ATM, in any table |
| Anchor key | Tags the line in `atm.anchor` that holds the newest seal (`keys::anchor_tag`, `anchor_tag_matches`) | Editing the anchor to match an older copy of the database |

A fingerprint of the key is stored in the database. A wrong or missing key
file means the program refuses to start (fail closed), and so does a missing
database when its key or anchor is still there (section 3).

**One hashing key per card and per login.** The key for a PIN or password
hash is HMAC(pepper, "credential/v1", identity) (`keys::credential_key`).
For a card the identity is its lookup value, its account and its role
(owner, joint, minor or guest; `auth::card_identity`); for staff it is the
username and role (`auth::staff_identity`). So a hash only verifies for the
row it was made for. Copying a known PIN hash onto another card, pointing a
card at another account, or switching a staff row from handler to admin
gives no login (tests `a_hash_only_works_for_its_own_card_and_role` in
`auth.rs`, `pointing_a_card_at_another_account_does_not_work` in
`tests/attacks.rs`). The seal already refuses such an edit; this is a
second, independent layer. It is the textbook's key diversification (§4.3):
each token's key is derived from the master key and the token's own name.

**Why a keyed lookup, not plain SHA-256, for card and account numbers.** The
program has to find a row from a typed number, so the database needs a
value it can search on. A plain SHA-256 of the number would work for that,
but there are only 10^10 ten-digit numbers: hashing all of them takes
minutes, which turns every stored hash back into its number (the textbook's
dictionary attack on password files, §3.4.9.2). An HMAC keyed from
`atm.key` can't be computed without the key, so a stolen `atm.db` can't test
a single guess. Mixing in "card" or "account" means a card's lookup never
matches an account's, even for the same digits. The number itself is kept
AES-GCM encrypted (so tellers can still see it) and the last 4 digits are
kept in clear (so screens and receipts need no decryption). Logs name a
card by its row id and last 4 (`customer:card 7 ending 1234`). The schema
version is 6; a database with any other version is refused (`src/keys.rs` →
`lookup_hash`; `src/db.rs` → `seal_number`, `open_number`, `customer_actor`).

**Why Argon2id for PINs and passwords.** The lectures don't cover password
storage. The course textbook (Anderson, *Security Engineering* §3.4.9.1)
says the right way is a random salt plus "a slow, cryptographically strong
one-way function". Argon2id is the standard such function. Plain SHA-256 is
fast, which is what makes stolen hashes easy to crack.

**Why HMAC and not digital signatures.** Lecture 3 uses signatures for
integrity. Here the same machine writes and checks the log, so a signing key
would sit next to the log anyway and add nothing. HMAC is the textbook's
"accepted way" to key a hash (§5.6.2); the naive SHA-256(key, message) is not.

**Limits.**
- Whoever steals **both** `atm.db` and `atm.key`, or controls the running
  machine, has everything, and can re-seal any edit. A real bank keeps this
  key in a hardware security module.
- An older copy of **both** `atm.db` and `atm.anchor`, put back together,
  still matches: the old anchor's tag is valid. A real bank keeps the anchor
  on another machine or on write-once storage.

## 5. Login with card number + PIN

The spec says customers "log in using their PIN". A PIN alone can't say
*who* someone is (two people can share a PIN), so customers enter a
10-digit card number first, like inserting a card. This also lets joint
account holders each have their own card and PIN.

- Card and account numbers are random 10-digit numbers, not sequential, so
  they can't be listed by counting (which would let someone lock every card).
  The database never holds them in clear (section 4).
- **An unknown card answers exactly like a real one.** A number that isn't a
  card, or a closed account's card, gives "Login failed" twice and then
  "This card is locked. Please see a teller to have it unlocked.", the same
  as 3 wrong PINs on a real card (`auth.rs` → `like_a_real_card`). Before
  0.7.0 only a real card said "locked", so trying a number three times
  showed whether it existed. The tries for unknown numbers are counted in
  memory only (`Atm.unknown_cards`, at most 10,000 numbers, then cleared),
  so a restart resets them. The stand-in hash an unknown card is checked
  against is made when the bank opens (`auth::warm_up`), so even the first
  try after a start takes as long as a real card's (audit F26, 0.8.0).
- 3 wrong PINs in a row lock the card until a Teller Admin unlocks it.
  The counter is saved before the error is returned, so killing the program
  doesn't reset it, and the seal (section 3) means it can't be reset by
  editing the file either.
- **A PIN hash only works for its own card.** Each hash is keyed for its
  card, account and role (section 4), so a hash copied to another row
  doesn't verify.
- PINs are 4 to 12 digits. New PINs that are easy to guess (0000, 1234,
  4321, the birth year or birthday) are refused.

**Staff** log in with a username and a password of at least 12 characters.
There are no built-in accounts: the first run asks for one Teller Admin and
one Cash Handler. 3 wrong passwords pause sign-in for 60 seconds, doubling
up to 15 minutes. A pause, not a permanent lock, so an attacker can't lock
out the only admin. Each password hash is keyed for its username and role,
so a handler's row edited to say "admin" doesn't sign in as admin. Every
Teller Admin sign-in also runs the integrity check (section 14). While the
ATM is out of service, only the Teller Admin can sign in (section 23).

## 6. Money rules

- **Daily limits** (bank-wide, set by the Teller Admin): withdrawal $1,000,
  deposit $10,000, transfer $5,000 by default (`src/db.rs` →
  `Limit::default_value`, `insert_defaults`). "Today" is the New York bank
  day. Totals are computed from the signed log, not from a counter, so they
  can't be reset by editing one number.
- **Why these amounts.** They are typical US bank debit-card limits. $10,000
  is also the US Currency Transaction Report line: a bank must report cash
  over $10,000 in one day, so a larger cash deposit goes to a teller, who
  sees the customer. The old defaults ($500 / $5,000 / $2,000) sent
  customers to a teller for everyday amounts. Higher defaults would let a
  stolen card and PIN take more each day; the activity holds (section 16)
  catch the faster patterns.
- **Every bank starts with these.** The database layout changed in 0.7.0
  (schema 6, unchanged in 0.8.0), so a database from an older version is
  refused, and a new one
  gets these defaults (`Limit::default_value`). A teller can change them on
  **Daily limits**, but only up to a ceiling: $5,000 / $50,000 / $25,000
  (section 13).
- **Limits are per account**, so two cards on a joint account can't double
  them.
- **Over a limit**, adult Bank of CCNY customers (individual or joint) are
  told to see a teller inside the branch, who can approve more for today
  only (section 15). Youth accounts and other banks' cards are not.
- **Cash maximum** $100,000, physical capacity $150,000. Deposits can take the
  machine above the maximum; the Cash Handler can remove only that surplus,
  never empty the machine.
- **Clock check.** If the computer's clock is earlier than the newest log
  entry, the program refuses to start, so rolling the clock back can't reset
  daily limits.

## 7. Bills (denominations)

The machine holds $5, $10, $20, $50 and $100 bills. Amounts are multiples
of $5.

The spec's rule is the default: the ATM pays the bill type the customer picks;
if it doesn't have enough of that bill, it refuses and says which bills can
pay the amount. On top of that the customer may choose:

1. **All in one bill type** (the spec's rule).
2. **Mostly the bill I pick**: as many of that bill as possible, the rest in
   the fewest other bills.
3. **Fewest bills.**

Examples (each is a test in `src/dispense.rs`):
- $220, mostly $50 → 4 × $50 + 1 × $20
- $230, mostly $50 → 4 × $50 + $20 + $10
- $270, mostly $100 → 2 × $100 + $50 + $20
- $60, mostly $50 with no $50s left → 3 × $20

A plan only uses bills the machine has, and the cash count, the balance and
the log change in one transaction, so a withdrawal is never half paid.

**At most 40 bills per withdrawal** (`src/dispense.rs` → `MAX_BILLS`,
`plan_withdrawal`). Real dispensers limit how many notes they pay at once
(40 is a common setting), because a thick stack jams and one customer could
empty a drawer of small bills. A withdrawal that would take more than 40
bills of the chosen type is refused before anything moves: "This machine
pays out at most 40 bills at a time. Choose bigger bills, or take the cash in
two withdrawals." The GUI greys those bill tiles out ("Over 40 bills"); the
command line offers the fewest-bills plan instead. So $200 is the most in
$5s and $800 the most in $20s; the full $1,000 daily limit needs $50s or
$100s, or two withdrawals, as at a real machine. The cap is for customer
payouts only: the Cash Handler's reset to the cash maximum is not limited.

## 8. Currencies and exchange rates

**Choice.** The machine holds and pays only US dollar bills, and Bank of
CCNY accounts are always in US dollars (0.9.0). A card from another bank can
be in US dollars or in one of 15 other currencies, ranked by world use
and New York use together: EUR, GBP, CNY, JPY, CAD, MXN, DOP, INR, KRW, BRL,
JMD, COP, BDT, HTG and GYD. That covers the most traded currencies, the
city's largest immigrant communities (Dominican, Chinese, Jamaican, Mexican,
Guyanese, Bangladeshi, Haitian, Indian, Korean, Colombian) and its top
visitor countries. Currencies that swing a lot (such as the Turkish lira)
were left out, because they would keep tripping the 5% pause. Each currency
is shown with its flag. Cash taken with a card in another currency is
converted the way a debit card works abroad: at the day's rate plus an
exchange fee (section 12).

**Why our own accounts are USD only.** A New York bank holds its customers'
money in dollars; letting a teller open an account in yen added choices
(and rate risk on every deposit) without a real need. The conversion code
stays for other banks' cards, which is where a real ATM converts. Accounts
opened in another currency by 0.8.0 or older keep working.

**Why this shape.**
- One cash inventory. Foreign bills would need their own stock and counting
  for no gain.
- The customer sees the cost added up before confirming: withdrawal + each
  fee = total in dollars, then what the account is charged in its own
  currency, with the fee rule and the rate in small print (section 12).
- Integer math only (rates in millionths, 128-bit arithmetic). Rounding always
  favours the bank: a charge rounds up, a credit rounds down, so repeating
  tiny conversions can't create money.
- Yen and won have no cents, so their amounts are whole numbers.
- A transfer between accounts in different currencies is refused.

**Where the rate comes from.** A Teller Admin sets it, in one of two ways:
types it, or presses **Check today's rates**, reviews the public daily
feed and approves it (section 20). Either way the teller is the weak spot:
a teller could enter, or approve, a "friendly" rate and withdraw at it. And
a feed adds a network link that can be spoofed, hijacked or go down. The
guards below apply to both, through the same storing code (`fx::store_rate`);
a typed rate also goes through `fx::check_change_cap`:

| Guard | Stops |
|---|---|
| Believable range per currency (for example EUR 0.50-1.50 per dollar; KRW 900-2,100, so 13.85 typed for 1,385 is refused) | Typos and absurd rates |
| A typed rate must be within 5% of every rate in the last 24 hours | Typing a friendly rate. Small steps can't add up, because each one is checked against every rate of the last 24 hours |
| Today's feed sets the market rate in full, but a move over 5% in 24 hours is set **paused** until a teller checks it against another source and resumes | A bad feed, or a real crash, reaching customers before a person looks |
| Every rate ever set stays in `rate_history` (no updates or deletes, each row has an HMAC) and is shown with its % change | Hiding a bad rate afterwards. A reviewer sees every change and who made it |
| Rates expire after 72 hours | Converting at a forgotten, stale rate |
| Behind the database seal (section 3), each rate row also has its own HMAC. An edited row stops conversions, and re-entering it brings the currency back paused | Editing a rate straight in the database |
| **Pause / Resume** per currency, and **Pause all** | A currency crash: stop conversions at once instead of stepping the rate down over days |
| Every rate, pause, resume and fee change is in the signed log with the teller's name; a rate from the feed also names the feed and its publish time | Denying a change, or blaming the feed |
| A feed rate is only a proposal: the teller sees old and new for every currency and nothing changes until they approve | A spoofed or wrong feed setting rates on its own |

A real crash shows up in the next feed check: the new rate is set and the
currency paused until a teller confirms it. A teller can also pause at once.
Pausing can't move money, so it needs no limit.

**Decision (Zack, 2026-10-12): trust the feed.** Until 0.5.0 every change,
typed or from the feed, moved a rate at most 3% a step and 5% in 24 hours, so
a second **Check today's rates** could add another step on the same day. We
compared keeping that, letting a teller override it, and trusting the feed,
and chose the last, because it is best for the bank. A rate held below the
market is a gift to anyone who notices: if the yen really fell 10% and we
moved the rate 3%, a yen account could buy dollars cheaply until the cap
caught up. So the feed now sets the market rate in full, and a big move is paused
until a person looks. Typed rates keep one rule, 5% in 24 hours, with no
per-step limit.

**Limit.** A teller can still nudge a typed rate by up to 5% a day in a
direction that helps an accomplice. The limit bounds the gain and the
history shows the pattern. Approving the feed moves a rate further, but the
teller can't choose the number, and a big move needs a second, logged
click (Resume). A real bank would have a second person approve each rate
(dual control, textbook §12.2.4); this ATM has one Teller Admin login.

## 9. Joint accounts

- One account, up to 2 holders, both 18 or older.
- **Each holder has their own card and PIN.** One person's typos don't lock
  the other out, and the log names which card did what (so neither can deny
  a transaction).
- Balance and daily limits are shared.

**Adding a holder needs the current holder at the counter.** The Teller
Admin's Joint holder form asks for the current holder's card number and
their PIN, typed by them, as at a real teller window's PIN pad
(`admin::add_joint_holder` takes an `auth::CardAndPin`). The core checks it
(`auth::confirm_at_counter`), not the front end, and the card must be the
owner's or the joint holder's card on that same account.
- **Why:** before 0.7.0 a teller could add an accomplice to anyone's
  account, with a PIN the teller chose, and empty it (review hole B1). That
  was the "teller sets a PIN" power left out on purpose (section 13), by
  another route.
- **A wrong PIN counts** toward that card's 3-strike lock, like at the ATM,
  and is logged ("wrong PIN at the counter"). The refusal is committed
  before the error is returned (`admin.rs` → `confirmed`), so retrying
  doesn't reset it. The GUI says "The holder's card number or PIN was not
  accepted. Ask them to type it again." or, once the card is locked, "The
  holder's card is locked. Check their ID and unlock it under Locked cards
  first." (screenshot `docs/screenshots/joint-holder-consent.png`).
- The log line names both cards: "joint holder, card 9 ending 1234;
  confirmed by card 1 ending 4321 with PIN".
- A card on an account the bank froze can't confirm anything at the counter
  (section 24).
- Test `joint_and_youth_changes_need_the_holders_card_and_pin`.

## 10. Youth accounts

- Opened by a Teller Admin for someone under 18, linked to a parent's or
  guardian's card. A second guardian can be added.
- **The parent confirms at the counter.** Opening a youth account needs the
  parent's own card number and PIN, typed by them; adding a guardian needs a
  current guardian's card and PIN (`admin::open_youth_account`,
  `add_guardian`, both through `auth::confirm_at_counter`, as for joint
  holders in section 9). Before 0.7.0 a teller could make any adult a
  guardian, who could then lift the parent's freeze and see the child's
  history (review hole B3). Screenshot
  `docs/screenshots/youth-consent-refused.png`.
- Safe defaults: $100/day withdrawals, $50/day transfers, transfers only to
  a guardian's account.
- The limit that applies is the lower of the bank's limit and the guardian's
  cap. A guardian can't set a cap above the bank's limit.
- The guardian's **Family** screen shows the child's balance and history and
  lets them change caps, switch family-only transfers on or off, and freeze
  the account (lost card). Deposits still work while frozen.
- **Two separate freezes.** The bank's freeze (`frozen`, set by a teller) and
  the guardian's freeze (`guardian_frozen`, set on the Family screen) are
  two flags. Since 0.8.0 they do different things (section 24): the bank's
  freeze refuses the account's cards entirely; the guardian's stops money
  going out, and the child's card still works. Each side can lift only its
  own. A teller who tries to lift a guardian's freeze gets "this account was
  frozen by its guardian; only the guardian can unfreeze it", and a
  guardian who tries to lift the bank's gets "the bank froze this account;
  please see a teller" (`admin::set_frozen`, `family::set_frozen`; test
  `the_bank_and_the_guardian_each_lift_only_their_own_freeze`). Screens say
  who froze it: "Frozen by guardian" for the teller, "Frozen by the bank" for
  the guardian.
- Only a linked guardian can see or change a youth account. Anyone else gets
  "not found", the same as an account that doesn't exist.
- Minors can't open individual accounts, be joint holders or be guardians.
- **A youth account always keeps a guardian.** A guardian's own account
  can't be closed while it is the only open guardian of an open youth
  account. Only guardians whose own account is still open count, so closing
  them one by one can't leave a child (perhaps frozen, with money stuck)
  with no guardian (`admin::close_account`, review hole B4).

**Guardian moves money.** The Family screen can move money from the
guardian's own account into the child's ("To child") or back ("Back to
me"), in the same currency (`src/family.rs` → `move_money`).
- **Choice:** money taken from the child can only go to the guardian's own
  account. The function has no destination field.
- **Why:** a guardian already controls the child's caps, so taking money back
  is a fair power. Sending it to a third party would turn the child's
  account into a way to pay anyone, outside the child's own limits.
- Same checks as a transfer: guardian link (else "not found"), frozen and
  hold on the paying account, balance, and the paying account's daily
  transfer limit. Taking money back uses the bank's transfer limit, not the
  child's own cap, and counts toward the child's transfer total for the day.
- The six activity rules (section 16) run on these moves too, on the account
  the money leaves, like any transfer (`review::screen`); a match holds that
  account. Before 0.8.0 they didn't, so a stolen guardian card and PIN could
  sweep a child's savings with no hold (audit F16; test
  `guardian_moves_go_through_the_same_activity_rules_as_transfers`). A hold
  on the paying account blocks them.
- Logged as a transfer by the guardian's card with the detail "by guardian:
  ...", so history and the balance check treat it like any other transfer.

## 11. Cards from other banks

**Choice.** A Teller Admin can register another bank's card ("Other bank's
card"). This stands in for the card network: a real ATM would ask the card's
own bank over the network.

- Allowed here: withdraw cash, check the balance, see daily limits.
- Not allowed: deposit, transfer, history, PIN change. Those belong to the
  card's own bank. A guest account also can't receive transfers, be a
  guardian or have a joint holder.
- **Other bank's ATM fee** on every withdrawal (section 12), shown before
  confirming and added to what the account is charged. The daily limit
  counts cash only. A foreign guest card pays the exchange fee too.

Every customer function checks the card's role, so a guest card that reaches
the deposit or transfer code is refused there, not only hidden in the menu.

## 12. Fees

**Choice.** Two fees, each a percent of the cash (rounded up to a cent) with
a minimum, so the higher of the two is charged (`src/fx.rs` → `FeeRule::on`):

| Fee | Charged on | Default | Teller can set |
|---|---|---|---|
| Exchange fee | Cards in another currency (and older foreign-currency accounts) | 3%, at least $3.00 | 0-5%, minimum $0-$10 |
| Other bank's ATM fee | Other banks' cards, withdrawals | 3%, at least $3.00 | 0-5%, minimum $0-$10 |

Our own dollar customers pay no fee. A foreign card from another bank pays
both, each worked out on the cash.

**Why a percent with a minimum.** A flat fee is out of proportion on large
amounts; a pure percent makes small withdrawals almost free, though each
one costs the bank the same to handle. One rule covers both ends. The
defaults follow a typical card foreign-transaction fee (3%) and a typical
New York ATM fee ($3.00).

**Shown as a sum.** Before confirming and on the receipt the customer sees
two columns that add up, then one line of small print. A Dominican bank's
card taking $60:

| Line | Amount |
|---|---|
| Withdrawal | $60.00 |
| + Other bank's ATM fee | $3.00 |
| + Exchange fee | $3.00 |
| **Total** | **$66.00** |
| **Charged to your account** | **4,191.00 DOP** |

Small print: "Each fee: 3% of the amount, $3.00 minimum. Rate: 1 USD =
63.50 DOP." With one fee, or two with different rules, each fee is named
("Exchange fee: 2.50% of the amount, $4.00 minimum."). A deposit shows
Deposit, − Exchange fee, Total and "Added to your account". Our own dollar
customers see "Fees $0.00" and no small print (`fx.rs` →
`Conversion::summary`, `Conversion::fine_print`, `FeeRule::short`; the
receipt keeps both, `Receipt.summary` and `Receipt.fine_print`; the command
line prints the same rows with `Conversion::breakdown`). Staff screens keep
the longer "3.00%, at least $3.00" (`FeeRule::text`).

- **Why this wording (Zack, 2026-10-12).** Bank fee schedules state a
  percent with a minimum: "3% of the amount, $3.00 minimum". The earlier "3%
  or $3.00, whichever is higher" was correct but not how a bank puts it. "Up to
  3%" was rejected because it would be untrue: on a $20 withdrawal the $3.00
  minimum is 15%.
- **Why a sum.** A customer can check dollars + dollars = dollars in their
  head. The old line-by-line list put two currencies on each fee line and
  the rule in brackets, which was hard to read at a machine.
- **The money math did not change.** Each part (cash, each fee) is still
  converted on its own and rounded in the bank's favour (charges and fees
  up, credits down). "Charged to your account" is the sum of those
  converted parts, exactly what the balance moves by. A deposit too small
  to cover the exchange fee is refused rather than credited at zero.

**Guards.** The bounds stop a teller from overcharging. Each fee is two
settings (percent and minimum), both with an HMAC, and every change is
logged old → new: "Exchange fee: 3.00%, at least $3.00 -> 2.50%, at least
$4.00" (`fx::set_fee_rule`).

## 13. Teller Admin powers, and what was left out on purpose

A Teller Admin can open accounts, register another bank's card, unlock cards,
freeze, unfreeze and close accounts, set daily limits, type exchange rates
(at most 5% a day) or approve today's feed (a big move is paused), pause or resume
exchanges, set both fee rules, approve a
larger amount for today (section 15), release activity holds (section 16),
read the logs, run the integrity check, and halt or resume the ATM
(section 14). Every one of these is logged with the admin's name.

**Bounded powers (0.7.0).** Some of these let one teller do harm alone, as
the security review showed. Each now has a bound:

| Power | Bound | Why |
|---|---|---|
| Unlock a card | Once per card per New York bank day, counted from the signed log. The Locked cards list shows only the last 4 digits of the card and account, with the name and birth date for the ID check; the teller types the full number from the card the customer hands over ("card present"), instead of clicking a row (`admin::unlock_card`, `locked_cards`; screenshot `docs/screenshots/locked-cards-unlock.png`) | 3 wrong PINs, unlock, 3 more, unlock... let a teller (or a friend of the customer) keep guessing until the PIN was found (review hole B6). A second unlock the same day gets "this card was already unlocked today; it can be unlocked again tomorrow (New York time)" |
| Starting balance | Each at most the daily deposit limit ($10,000 by default, in US-dollar value), and one teller's starting balances together at most $20,000 a bank day (0.8.0; `admin.rs` → `insert_account`, `STARTING_BALANCES_PER_DAY`; section 25) | The teller types it and the machine counts no cash, so without a cap one teller could create money out of nothing (review hole B2). With only the per-account cap, many accounts still added up (audit F04). More goes in as deposits, which the limits cover |
| Daily limits | At most the default plus one day's largest teller approval: $5,000 withdrawal, $50,000 deposit, $25,000 transfer (`Limit::ceiling`, used by `admin::set_limit`) | A huge limit would switch the limit off; with an unbacked balance it let one transfer move it all (B2) |
| Any amount | At most `Cents::MAX` (10^15 cents), in the code and as a CHECK in the database | Sums of many values can't wrap |
| Joint holder, youth account, guardian | Need the current holder's (or parent's) own card and PIN at the counter (sections 9 and 10) | One teller could add an accomplice to an account, or appoint a guardian (B1, B3) |
| Freeze | A teller lifts only the bank's freeze, never a guardian's (section 10) | A guardian's freeze is the parent's decision (B3) |

Left out on purpose, because each would let one insider take over accounts
or hide what they did:

| Not included | Why |
|---|---|
| Teller sets or resets a customer's PIN | A teller who can set PINs can use any account. Customers type their own PIN; tellers only unlock |
| Teller edits a customer's name or birth date | Those are what the teller checks ID against before unlocking |
| Teller creates more staff logins | One admin able to create admins could leave hidden access behind. Setup creates exactly one of each role |
| Delete a customer | Deleting breaks the audit trail and frees the number for reuse. **Close** keeps the history and never reuses the number |
| Store Social Security numbers | The spec doesn't need them, and data that isn't collected can't leak |
| Override the 5% typed-rate limit | An override is exactly what a rogue teller would use. A real move comes from the feed, whose numbers the teller can't choose, and a crash is handled by pausing |
| Change the rate feed's address | One insider could point the ATM at their own "feed". The address is a constant in the code (section 20) |
| Change or switch off the activity rules | One insider could turn them off for an accomplice. The thresholds are constants in the code (section 16) |
| Raise a limit for good, or without a cap | An approval is for one account, one limit, today only, and capped (section 15) |

**Still open.** There is no second approver (dual control, textbook
§12.2.4): one teller can approve larger amounts, release holds, approve the
rate feed, resume service, and open accounts with starting balances of up
to $20,000 a day with no cash. Each is logged with the teller's name, and the
amounts are capped, but none needs a second person. Teller views of
customer details (name, birth date, history) are not logged.

## 14. Audit log and integrity check

- Every login, failure, lock, unlock, transaction, limit change, teller
  approval, hold, hold release, cash movement, halt, resume and logout is
  written to the log **in the same transaction** as the change it records.
- Some state lives only in the log: daily totals, teller approvals, holds,
  recent payees, unlocks per day, each teller's starting balances today and
  whether the ATM is out of service are all read from it. There is no flag
  or counter to edit instead.
- Triggers block `UPDATE` and `DELETE` on the log table, and each entry is
  chained to the one before with an HMAC (section 4).
- **The seal is checked before every operation** (section 3). An edit made
  to `atm.db` outside the ATM (a balance, a lock flag or failure count, a
  staff row, a cash count, a guardian link, a setting, a rate, the log) is
  refused at once, before anything is decided from it. Up to 0.6.0 such an
  edit was found only later, when a teller ran the integrity check, and in
  between an edited balance could be spent or a cleared lock used (review
  holes A2, A3, A4, A6).
- **Data integrity** (Teller Admin) re-checks the whole chain, recomputes
  every balance and the cash in the machine from the log, checks the HMAC on
  every limit, fee, rate and rate-history row, and matches each daily limit,
  exchange rate, freeze and closure against its newest log entry
  (`audit::verify`; the cash and state checks are new in 0.8.0, section 27).
  Every failure is reported, not just the first, each account by its last 4
  digits with both amounts. It shows a check code; writing it down somewhere
  else gives a record the database can't rewrite.
- This is the textbook's Clark-Wilson rule: every transaction writes enough
  to an append-only audit trail to reconstruct it (§12.2.3).

**What each check catches.** The seal proves the file wasn't changed
outside the program. It can't tell whether the program itself wrote
something wrong: a bug, or a back door hidden in the code, could change a
balance with no log entry inside a normal commit, which seals it. The
integrity check catches that, because the books no longer add up. Since
0.8.0 that covers the cash, and limits, rates and account flags changed with
no log entry, too (section 27).

**The check runs at every Teller Admin sign-in; a failure takes the ATM out
of service** (Zack's idea; `src/service.rs`, `auth::login_admin`).
- The check runs as part of signing in (`service::check_at_sign_in`), so it
  runs at least as often as a teller signs in, without anyone having to
  remember to press **Run check**.
- If it fails, the ATM halts itself at once, logged as "system":
  "integrity check failed at sign-in of admin:...: " and what failed.
  - No card is taken (0.8.0, section 23). The start screen says "Out of
    service" and "This ATM is temporarily out of service. Please use
    another ATM.", and the card is grayed out (`service::out_of_service`).
    The core also refuses a card before any PIN is checked
    (`service::refuse_if_halted`), and a customer already signed in is
    stopped at their next action (`Atm::admit`). Screenshot
    `docs/screenshots/out-of-service-welcome.png`.
  - Only the Teller Admin can sign in, to investigate and resume. The Cash
    Handler is refused at sign-in, and a Cash Handler already signed in is
    stopped at their next action (section 23). Up to 0.7.0 all staff kept
    working.
  - The teller's screen shows a red banner with what failed and **Resume
    service**. Sign out stays visible in the menu beside it, and long pages
    scroll (screenshot `docs/screenshots/out-of-service-banner.png`).
- A teller can also **Halt ATM** by hand on the Data integrity tab (command
  line: menu option 18), for example while checking something suspicious
  (`service::halt`; screenshot `docs/screenshots/integrity-halt-resume.png`).
- **No flag to edit.** "Out of service" is the newest `service_halted` or
  `service_resumed` row in the signed log (`service::halted`), like holds.
- An edited or rolled-back database is a hard stop (nothing runs), not a
  banner.
- A halt that lands while a change waits for the write lock still stops it
  (`Atm::begin_for`, section 18).
- Tests `a_failed_check_at_sign_in_takes_the_atm_out_of_service`,
  `a_teller_can_halt_and_resume_by_hand`,
  `while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in`,
  `a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first`
  (`service.rs`).

**Why halting is automatic.** Books that don't add up mean the machine
might pay out money that isn't there, or a theft might still be going on.
Halting moves no money and costs only availability: customers are sent to
another ATM. Carrying on until a person decides would mean serving
customers on books known to be wrong. This is the textbook's fail-stop
design: "bank transaction processing will typically stop if an
out-of-balance condition is detected" (§7.3.1.2). The cost is the one
STRIDE lists under denial of service (Lecture 1): anyone who can make the
check fail can take this ATM offline until a teller looks.

**Why resuming is a person's decision.** Only a person can find out why the
check failed and decide whether it is safe to carry on: a known problem
being fixed elsewhere, or an attack. **Resume service** runs the check again
and logs its result with the teller's name ("resumed after review;
integrity check passed", or "... still fails: ..."; `service::resume`).
Resuming is allowed even if the check still fails, because the teller has
reviewed it. Otherwise one bad row would keep the ATM down for good, and
the only way out would be editing the database, which the seal refuses. The
GUI then says "Back in service, but the integrity check still fails: ...
This is logged, and the next Teller Admin sign-in will take the ATM out of
service again."

**Why one teller can resume, and what is still open.** The bank has one
Teller Admin login (setup creates exactly one of each role), so a second
approver would need a second admin login, which this version doesn't have.
The resume can't be done quietly: it is a signed log row with the teller's
name and the check's result, and the next sign-in halts the ATM again if the
problem is still there. Two-person approval to resume (dual control,
textbook §12.2.4) is still open, like the other single-teller powers in
section 13.

## 15. Teller approval over a daily limit

**Choice.** A customer at the counter who has shown ID can ask a teller to
allow more than one daily limit, for one account, today only
(`src/admin.rs` → `raise_limit_today`). The ATM's over-limit message tells
adult Bank of CCNY customers (individual and joint) to see a teller inside
the branch.

- **Caps** per account per day: +$4,000 withdrawal (so up to $5,000 cash
  that day), +$40,000 deposit, +$20,000 transfer (`Limit::max_raise`).
  Several approvals in one day add up toward the cap. Each cap lets a
  customer who has shown ID do up to five times the daily limit in one day:
  enough for a real one-off need, small enough that one dishonest teller
  can't move much for an accomplice.
- **Refused** for youth accounts (their caps belong to the guardian) and
  other banks' cards (that bank sets their limits).
- The customer's Daily limits screen shows it: "$1,000.00 + $200.00 today".

**Why a log row, not a flag.** The approval exists only as a signed log row
(`withdrawal_limit_raised`, `deposit_limit_raised` or
`transfer_limit_raised`, with the extra amount and the teller's name). The
limit check adds up those rows for the current New York bank day, the same
way it adds up what was used (`customer.rs` → `limit_status`). A flag or a
"raised until" date in the accounts table could be set by anyone who edits
the file; a log row can't be forged without `atm.key` (the HMAC chain
breaks), and it stops counting by itself at midnight.

## 16. Suspicious-activity holds

**Choice.** Six fixed rules run inside every withdrawal, transfer out and
guardian move (`src/review.rs`). Amounts are compared in US dollars:

| Rule | Matches |
|---|---|
| 1 | The 4th withdrawal within an hour |
| 2 | The 4th transfer out within an hour |
| 3 | A transfer to a 3rd different account within 24 hours |
| 4 | $1,000 or more to an account this account has not paid before today (a payment earlier the same day doesn't count; section 26) |
| 5 | $500 or more out within an hour of $500 or more coming in by transfer (money passed through, as a mule would) |
| 6 | One move of $900 or more that takes 90% or more of the balance |

A match refuses the attempt and writes a `hold_placed` row (actor
`system:activity-check`, detail = the rule and what was refused). While
held, no withdrawals, transfers or guardian moves leave the account;
deposits, balance and history still work. The customer sees only "For your
protection, withdrawals and transfers on this account are paused after
unusual activity. Please see a teller inside the branch to confirm it was
you." The teller's
**Holds and approvals** tab lists account, holders, rule and time, and
**Release hold** writes a `hold_released` row with the teller's name.

- **After a teller contact** (a release or an approval), counting restarts
  from that log row, and the amount rules (4-6) are off for that account
  until tomorrow: the teller has just seen the customer.
- **On hold = the newest hold row is `hold_placed`.** Same reason as
  approvals: no flag to clear in the database (`review::hold_reason`).
- **Thresholds are constants in the code,** not teller settings. A setting
  would let one insider switch the rules off for an accomplice.
- **Thresholds aren't shown to the customer,** so a thief can't read off how
  much to stay under.

**Limits, stated plainly.**
- These are simple speed and amount rules, not a fraud model. A thief who
  stays under all six still gets up to the daily limits.
- Someone who knows an account number can send it $500+ so the owner's next
  large withdrawal trips rule 5. That is a nuisance (no money moves, a teller
  releases it, the sender is logged), not theft.
- The 1-hour and 24-hour windows use the system clock. Rolling the clock back
  is already refused at start (`audit::check_clock`).

## 17. Recent payees ("send again")

**Choice.** The transfer screen lists up to 5 accounts this account sent
money to, newest first, as Send again buttons (`customer.rs` →
`recent_payees`).

- **Read from the signed log**, not a saved address book, so there is no
  second list to tamper with or keep in step.
- **Only transfers made by this account's own card holders count.** A
  guardian taking money back is logged on the child's account but isn't
  the child's payee, so it doesn't show.
- **Closed accounts are left out.**
- **Shown as the masked number and initials only** ("******1234 B. P.").
  The GUI keeps the full number in Rust memory to fill in the transfer; it
  never goes into a screen property.
- The transfer itself runs every normal check, including the activity
  rules. Transfers by phone number (Zelle-style) are not offered.

## 18. Sessions and the GUI

- Sessions end after **2 minutes** without activity, for every role; the GUI
  asks "Do you need more time?" at 90 seconds. A half-typed card number or
  PIN is cleared after 60 seconds.
- **A session only works on the bank that issued it.** Each opened bank gets
  a random id (`Atm.id`), and every session carries it. Without this, code
  could open a throwaway database, run first-time setup there with its own
  passwords, and hand that "admin" session to the real bank.
- **Every action re-checks the session** (`Atm::admit`, the first line of
  every operation). A wrong bank, a card locked since login, an account
  closed or frozen by the bank since login, or a staff login no longer in
  the table ends the session ("Your session has ended. Please log in
  again."), and so does the idle clock. While the ATM is out of service,
  customer and Cash Handler sessions stop too (sections 14 and 23); a
  Teller Admin's doesn't. Before 0.7.0 only the idle clock was checked here
  (`touch`), so a session could outlive a lock or a closure.
- **The check runs again inside the write lock** (`Atm::begin_for`, 0.8.0).
  A change can wait for the lock while another window commits a halt, a
  card lock or a closure; the session is checked again once the lock is
  held, so the change is still refused. Used by withdrawals, deposits,
  transfers, PIN changes, guardian controls and moves, and cash actions
  (audit F22; test
  `a_withdrawal_waiting_for_the_lock_stops_when_the_halt_lands_first`).
- Three unknown account numbers in one transfer session end the session, so
  the transfer screen can't be used to hunt for valid accounts.
- Before a transfer the ATM shows the recipient's initials only: enough to
  catch a typo, not enough to collect names.
- Card and account numbers show as dots plus the last 4 digits, even while
  being typed, and receipts show only the last 4. Someone looking over a
  shoulder or picking up a thrown-away receipt can't copy the number
  (textbook §12.4.2, "shoulder surfing"). The command line hides them fully.
- A customer's history shows any other account by its last 4 digits only,
  and a transfer in as from "other account holder", never the sender's card
  (`audit::for_customer`). Staff screens keep the full view.
- **"Would you like a receipt?" comes before any money moves, and a
  withdrawal returns the card before the cash.** Textbook §3.2.1
  (post-completion errors): "More people leave cards behind in ATMs that give
  them the money first and the card back second." So a withdrawal ends the
  session, shows "Please take your card", and only then "Please take your
  cash"; a walk-away leaves no open session behind. Without a receipt, the
  screen leaves off the balance and reference number too. Deposits and
  transfers have no cash to hand back, so the customer stays signed in. The
  command line has no card to return and always prints the receipt
  (`gui/src/customer.rs` → `receipt_choice`, `return_card`, `take_card`,
  `take_cash`).
- The GUI keeps the PIN in Rust memory that is wiped after use, never in a
  screen property. The raw key file bytes are wiped after loading.
- **Nothing is left on screen for the next person (0.8.0).** Signing out, or
  timing out, in the GUI clears every screen property that held someone's
  data: receipts, confirm lines, limits, holds, rates, cash, integrity
  results, the sign-in problem (`gui/src/main.rs` → `go_welcome`; audit
  F30). The command line clears the screen and its scrollback after every
  session (`input.rs` → `wipe_screen`; audit F27; test
  `the_cli_wipes_the_screen_when_a_session_ends`). The command line can't
  notice the 2-minute idle while it waits for a key, but the next key ends
  the session and wipes the screen.
- **PINs and passwords typed at the teller screen can't be copied out
  (0.8.0).** In a PIN or password field, Ctrl and Cmd shortcuts (select
  all, copy, cut) do nothing and the mouse can't select; Tab and a click
  still reach the field (`gui/ui/theme.slint` → `Field`; audit F02).
- **Sign out is always on the teller's screen (0.8.0).** The red
  out-of-service banner is short and sits over the page only; the menu
  scrolls with Sign out below it, and long pages scroll (`gui/ui/staff.slint`;
  audit F06). Before 0.8.0 the banner pushed Sign out off the screen.
- The GUI is built with Slint: a native window, no web browser or local web
  server, so no web attack surface.
- Colors are CCNY's own: purple PMS 2665C (#7D55C7), gray PMS 425C (#545859)
  and white, with gold PMS 129C (#F3D03E) for the Clear key, from the 2026
  CCNY Style Guide.

## 19. Demo mode

Sample data (staff logins, 10 card holders, exchange rates, cash) only
exists when the program is built with `--features demo`. It uses separate
files (`atm-demo.db`, `atm-demo.key`, `atm-demo.anchor`). The normal build
contains no passwords at all, because built-in credentials are a classic
weakness (and the rubric penalises them). The other banks' cards
are in US dollars, euros, yen and Dominican pesos, so each shows a different
rate. Yuki Sato's yen card also shows whole-number amounts.

**Demo data and real data stay apart.** The demo seed marks its database
as demo data first (`db::mark_demo`: a row in the `meta` table, sealed like
every other row, so the mark can't be removed by editing the file).
`Atm::open`, used in normal mode, refuses a demo database ("this is a
demo database with published passwords; it can't run as a real bank"), so
renaming `atm-demo.*` to `atm.*` doesn't give a normal build a bank whose
logins are printed in the README. `Atm::open_demo` (demo builds only)
refuses a real bank's database ("this is a real bank's database, not demo
data"), so the two can't be mixed up either way. Test
`demo_data_and_real_data_stay_apart` (`tests/demo_mode.rs`).

The sample rates are set when the demo bank is made. **Check today's
rates** then sets the real rates; a currency more than 5% off the sample is
set but paused, so the demo shows the pause working. The $5 drawer holds
only 10 to 15 bills, so asking for $100 in $5s shows the spec's "not enough of
that bill" message.

The GUI's demo wallet stands in for a card reader: clicking a card "inserts"
it, so testers type only the PIN. Cards show only their last 4 digits and
no PIN, so the screen gives nothing away; the PINs are in the user guide.
Where a teller's form needs a customer's full card or account number
(unlocking, adding a joint holder or guardian), a **Choose** picker fills
it in, as a customer hands over their card at the counter; the transfer
screen lists the sample accounts the same way (screenshot
`docs/screenshots/welcome-demo-wallet.png`). The wallet code is compiled
only into demo builds, so the graded build has no way to skip typing the
card number.

**The integrity test build.** To see the sign-in check and out-of-service
mode work (section 14), the books have to be wrong, and the seal stops any
edit made from outside. So a separate cargo feature, `integrity-test`
(which turns on `demo`), adds `--demo --break-integrity`
(`demo::break_integrity`): it makes demo data, then adds $500 to Ann and
Ben's balance with no log entry, through the ATM itself, so the seal still
matches and only the integrity check can catch it. The next Teller Admin
sign-in shows the red banner, naming the account by its last 4 digits with
both amounts ("stored $3,000.00, the log says $2,500.00"), and the start
screen then takes no cards. Test
`a_broken_balance_is_caught_at_the_next_teller_sign_in`.
- **Kept out of the normal and demo builds.** The code is compiled only
  with `--features integrity-test` (checked with `nm`: the normal and demo
  binaries don't contain it), and it refuses anything but demo data ("only
  demo data can be broken on purpose").
- **Its own files.** It uses `atm-test.db`, `atm-test.key` and
  `atm-test.anchor`, never `atm.*` or `atm-demo.*`. Zack asked that the
  test must not affect the main working version, so trying it never spoils
  the demo bank used on demo day. Delete `atm-test.*` to run it on fresh
  data.

## 20. The daily rate feed ("Check today's rates")

**Choice.** One button on the teller's **Exchange rates** tab (in the
command line, rates menu option 8 when built with `online-rates`). It makes
one HTTPS GET to a fixed address, `https://open.er-api.com/v6/latest/USD`
(ExchangeRate-API's free daily feed), and shows a review table: Currency,
Now, Today's feed, Will set, Note. Nothing changes until the teller presses
**Approve these rates**; **Cancel** drops it (`src/rate_feed.rs` → `fetch`,
`check`, `approve`; screenshot `docs/screenshots/rate-feed-review.png`).
Customers never trigger a fetch.

The Note column says what approving would do: "+0.14%", "big move:
+10.00%; will be paused" (more than 5% in 24 hours), "first rate", "no change
(date refreshed)", "not in today's feed: unchanged", "outside the believable
range: not used", and "; stays paused" for a paused currency. After
approving, the notice names each currency paused after a big move
(screenshot `docs/screenshots/rate-big-move-paused.png`). The source asks for credit, so the screen shows "Rates by Exchange
Rate API (exchangerate-api.com)".

**Why fetch, then approve.** This is how banks do it: a back office takes a
daily rate feed from a data provider, and a person signs it off before it
is used. Typing 15 rates by hand every day invites typos and lets one
teller choose the numbers; a feed brings the right numbers, and the
approval keeps a person responsible for them. One party proposes and
another approves (functional separation, textbook §12.2.4). The feed is a
proposal, never an order: the guards in section 8 still apply, with the
pause on big moves in place of the typed-rate limit (Zack's "trust the feed"
decision, section 8).

**Why this source.**
- Free and needs no API key, so there is no secret on the machine for it.
- Updates once a day, which is how often a bank sets these rates.
- Covers all 15 of our currencies. The classic free source, the European
  Central Bank's reference rates, has no DOP, JMD, HTG, GYD, BDT or COP:
  6 of the 15, the currencies of the Dominican, Jamaican, Haitian,
  Guyanese, Bangladeshi and Colombian communities the list was chosen for
  (section 8). Its rates are also per euro, so every one would be a cross
  rate.

**The controls.**

| Control | Stops |
|---|---|
| Only a Teller Admin's button press fetches (an `AdminSession` is required); never a customer, never on a timer | Customers waiting on the network; anyone else driving network traffic |
| HTTPS only, through rustls: TLS 1.2 or 1.3, forward-secret key exchange, AES-GCM or ChaCha20-Poly1305 | Reading or changing the reply on the way; downgrade to a weak protocol |
| The server's certificate must chain to the Mozilla root list built into the program (`webpki-roots`), not the computer's certificate store | A spoofed source, or a certificate someone added to the machine (malware, a proxy that inspects HTTPS) |
| A fixed URL in the code (`FEED_URL`), no redirects | Pointing the ATM at another "feed", by a setting, a teller or a redirect |
| 10 s limit on the whole request; at most 64 KB read (`FEED_MAX_BYTES`); no compression | A slow or huge reply freezing the teller's screen or filling memory |
| Strict parse: `result` "success", base "USD", published less than 48 hours ago and not in the future (5 minutes' leeway for clocks), numbers through `fx::parse_fixed` (the typed-rate parser); a missing or bad number is "missing" and left unchanged | A web page instead of data, an error, an old feed, junk numbers |
| Believable range per currency; a move over 5% in 24 hours is set but paused until a teller checks it and resumes (its own log line) | A bad feed, or a real crash, reaching customers before a person looks |
| Only `fetch` can make a `Feed` (0.8.0): its fields and `parse` are private to the library, and the front ends read it through `published()`. A compile-fail test in `src/lib.rs` proves a front end can't build one | A front end (or a planted change in one) making up a "feed" with any rates it likes, approving it past the typed-rate limit, or writing its own text into the log (audit F01, F24) |
| `approve` recomputes the plan in one IMMEDIATE transaction and sets nothing if it differs from what was shown; each rate is checked against the believable range again, gets its HMAC and goes in the signed log, naming the feed and its publish time | Rates the teller didn't see; hiding where a rate came from |
| A paused currency stays paused; an edited (ALTERED) row is re-entered paused | The feed undoing a teller's emergency stop |
| A failure is `AtmError::FeedUnavailable` with its own reason: "Couldn't reach today's rate feed", "The connection to today's rate feed failed its security check (certificate not trusted)", "not in the expected form" or "out of date", each followed by "Rates are unchanged; you can still type a rate." Each failed check is written to the signed log ("Rate feed failed", with the teller and the reason) | An outage stopping rate setting; an attack on the feed passing for an outage |

**Why a feature flag (`online-rates`).** Network code is attack surface,
and a way for a planted backdoor to send data out. Without the flag the
core library and the command line contain no network code at all: `fetch`
and the `ureq` crate aren't compiled, so `cargo build --release` gives a
command line with no network code, as before. The GUI turns the flag on,
because the teller works in the GUI. Checking and approving don't need the
network, so they are always built. Parsing is built with the flag and for
the tests (0.8.0: only `fetch` makes a feed), and all of it is tested with
saved feed text (`serde_json` is always in). One catch: `cargo build
--workspace` builds the GUI and the command line together, and Cargo then
builds the core once, with the flag, so that command line has option 8 too.

**Considered and rejected.**

| Option | Why not |
|---|---|
| Poll the feed all the time (every minute or hour) | The source updates once a day. Constant requests add traffic and failure points, and a background task is something nobody watches |
| Apply the feed automatically | A spoofed or wrong feed would set rates with no person looking |
| Keep capping feed rates (3% a step, 5% a day) | A rate held below the market lets customers trade against the bank until it catches up, and the step cap read as a bypass when a second check moved it again (section 8) |
| A feed address the teller can change | One insider could point the ATM at their own "feed". A fixed address is also one a reviewer can check |
| The computer's certificate store | A certificate added to the machine would be trusted. The built-in list is the same everywhere. The cost: a network that inspects HTTPS blocks the check (typing still works) |
| Pin the source's certificate | Breaks whenever the source renews its certificate. The believable range, the review and the pause on big moves limit the harm of a wrongly issued certificate instead |
| A paid feed with an API key | Puts a secret on the machine and costs money. A real bank would use a contracted provider |
| ECB reference rates | No DOP, JMD, HTG, GYD, BDT or COP |
| The system's TLS library (`native-tls`: OpenSSL on Linux) instead of rustls | One more thing to install on Linux (the reason SQLCipher was rejected, section 3), and which old protocol versions it allows depends on the system. rustls is Rust and speaks only TLS 1.2 and 1.3; its `ring` part is built by `cargo` with the C compiler SQLite already needs |

**Limits.** The feed is a free service with no contract: it can change its
format (then it is refused, not guessed at) or stop (then the teller types
rates). The teller's screen waits up to 10 s during a check. The format is tested with saved sample text, because the
real source could not be reached from the build environment; a proxy that
inspects HTTPS was refused ("invalid peer certificate: UnknownIssuer") and
an `http://` address was refused ("configured for https only"). Try the
live check on your own machine before demo day.

## 21. Constants worth knowing

Most are named constants. The rest are written once, in the function named
in the table: the default limits, approval caps and limit ceilings are small
functions on `Limit`, and the feed's timeout, the unknown-card count, the
one-unlock rule and the per-account starting-balance cap sit in the
function that uses them. So each is easy to find and change.

| Setting | Value | File |
|---|---|---|
| Wrong PINs before lock | 3 (unknown card numbers too) | `src/auth.rs` |
| Unknown card numbers remembered | 10,000, in memory only; cleared when full and on restart | `src/auth.rs` (`like_a_real_card`) |
| Unlocks per card | 1 per New York bank day | `src/admin.rs` (`unlock_card`) |
| Staff pause | 60 s, doubling to 15 min | `src/auth.rs` |
| Idle timeout | 120 s | `src/auth.rs` |
| Unknown transfer targets before logout | 3 | `src/auth.rs` |
| Max joint holders | 2 | `src/admin.rs` |
| Youth defaults | $100 withdrawal, $50 transfer | `src/admin.rs` |
| Default daily limits | $1,000 withdrawal / $10,000 deposit / $5,000 transfer | `src/db.rs` (`Limit::default_value`) |
| Highest daily limit a teller can set | $5,000 withdrawal / $50,000 deposit / $25,000 transfer (default + teller approval cap) | `src/db.rs` (`Limit::ceiling`) |
| Starting balance | Each at most the daily deposit limit, in US-dollar value; $20,000 a New York bank day for one teller's starting balances together | `src/admin.rs` (`insert_account`, `STARTING_BALANCES_PER_DAY`) |
| Largest money value | 10^15 cents (`Cents::MAX`); the same CHECK on every balance in the database | `src/money.rs`, `src/db.rs` |
| Bills per deposit | 200 of each kind, counted per kind across the whole deposit | `src/customer.rs` (`MAX_BILLS_PER_DEPOSIT`) |
| Cash maximum / capacity | $100,000 / $150,000 | `src/db.rs` |
| Exchange fee | 3% of the amount, $3.00 minimum by default; 0-5%, minimum $0-$10 | `src/db.rs`, `src/fx.rs` |
| Other bank's ATM fee | 3% of the amount, $3.00 minimum by default; 0-5%, minimum $0-$10 | `src/db.rs`, `src/fx.rs` |
| Typed-rate limit; feed big-move pause | 5% from every rate in the last 24 hours (`MAX_DAY_BP`) | `src/fx.rs`, `src/rate_feed.rs` |
| Bills per withdrawal | 40 | `src/dispense.rs` (`MAX_BILLS`) |
| Rate expiry | 72 hours | `src/fx.rs` |
| Rate feed address | `https://open.er-api.com/v6/latest/USD` | `src/rate_feed.rs` (`FEED_URL`) |
| Rate feed limits | 10 s per request; 64 KB per reply; published less than 48 hours ago | `src/rate_feed.rs` (`fetch`, `FEED_MAX_BYTES`, `FEED_MAX_AGE_HOURS`) |
| Teller approval cap, per account per day | +$4,000 withdrawal; +$40,000 deposit; +$20,000 transfer | `src/db.rs` (`Limit::max_raise`) |
| Activity rules 1 and 2 | 4th withdrawal, or 4th transfer, within an hour | `src/review.rs` |
| Activity rule 3 | 3rd different payee within 24 hours | `src/review.rs` |
| Activity rule 4 | $1,000 to a payee not paid before today | `src/review.rs` |
| Activity rule 5 | $500 out within an hour of $500 in | `src/review.rs` |
| Activity rule 6 | $900 and 90% of the balance in one move | `src/review.rs` |
| Recent payees shown | 5 | `src/customer.rs` |
| Schema version | 6 | `src/db.rs` (`SCHEMA_VERSION`) |

## 22. What came from the teammate's Integration branch

A teammate hardened an early 0.3.0 build on a branch called Integration,
against someone who can write to `atm.db` but has no key file. A review of
that branch (2026-10-12) found 14 holes; 13 of them were in 0.6.0 too.
0.7.0 starts from 0.6.0, brings in the teammate's ideas, and fixes the 13
(tests `a1_...` to `c2_...` in `tests/review.rs`).

**Taken.**

| From the teammate | Here | Section |
|---|---|---|
| Ledger check and anchor file | Grown into the whole-database seal (every row of every table, checked before every operation) and `atm.anchor` | 3, 14 |
| PIN and password hashes keyed per identity (`keys::credential_key`) | The same | 4, 5 |
| Sessions bound to the bank that issued them, re-checked on every call | `Atm.id`, `Atm::admit` | 18 |
| Separate bank and guardian freezes | `frozen`, `guardian_frozen` | 10 |
| Customer history without other people's numbers | `audit::for_customer` | 18 |
| `Cents::MAX` | The same, plus a CHECK on every balance | 2, 13 |
| STRICT tables | Every table | 3 |
| Their attack tests | Ported to this code: 26 in `tests/attacks.rs` | – |

**Not taken, and why.**

| Not taken | Why |
|---|---|
| Decisions read from the signed log (failed PINs, freezes, closures, guardian links, youth caps, balances and settings worked out from log rows instead of table columns) | The seal gives the same protection more simply. Every row is covered, so an edited balance, flag or staff row is refused before anything is decided from it. The review also showed that log-derived decisions believed inserted rows with a fake MAC unless the whole chain was verified first |
| Five display currencies | This version already has 16 currency accounts, with believable ranges and the 5% rule (section 8) |
| Refusing to add a guardian while the account is guardian-frozen (a review suggestion) | The current guardian's own card and PIN already cover it (section 10): only a current guardian can add one |

**The 13 holes and their fixes.**

| Hole | Who | What it allowed | Fixed by | Section |
|---|---|---|---|---|
| A1 | Edits `atm.db` | Emptying the staff table reopened first-run setup | The seal; a bank with any log entry counts as set up (`db::is_initialized`) | 3 |
| A2 | Edits `atm.db` | Resetting a card's failure count gave unlimited PIN guesses | The seal | 3, 14 |
| A3 | Edits `atm.db` | A typed-in balance could be spent | The seal | 3, 14 |
| A4 | Edits `atm.db` | Clearing the frozen flag lifted a bank freeze | The seal | 3, 14 |
| A5 | Deletes `atm.db` | Deleting `atm.db` but keeping the key reopened setup | Strict open | 3 |
| A6 | Edits `atm.db` | Resetting staff columns removed the password pause | The seal | 3, 14 |
| B1 | Teller | Added a joint holder with their own PIN and drained the account | Holder's card and PIN at the counter | 9 |
| B2 | Teller | Opened an account with unbacked money; set limits with no ceiling | Starting balance and limit ceilings | 13 |
| B3 | Teller | Appointed a guardian who lifted the parent's freeze | Parent's card and PIN; two freezes | 10 |
| B4 | Teller | Closing guardians one by one orphaned a youth account | Only open guardians count | 10 |
| B6 | Teller | Unlocked between guesses to find a PIN; the locked list showed full card numbers | One unlock per card per day, typed from the card; last 4 only | 13 |
| C1 | Customer | An unknown card and a real card failed differently (shows which numbers exist) | Unknown cards answer like real ones | 5 |
| C2 | Customer | One deposit took more than 200 bills of a kind by listing it several times | The cap counts per kind (`customer::deposit`) | 21 |

## 23. Out of service: no card is taken, and only a Teller Admin signs in

**Choice (0.8.0).** While the ATM is out of service (section 14):
- The GUI's start screen says "Out of service" and "This ATM is temporarily
  out of service. Please use another ATM." The card is grayed out ("Not
  accepting cards") and takes no taps. The Cash Handler link is grayed out
  too, and in demo builds every wallet card and the Cash Handler badge are
  dimmed. Only the Teller Admin link and badge work (`gui/ui/customer.slint`
  → `WelcomeScreen`). The start screen checks again every 5 seconds, so a
  halt made in another window shows up by itself (`gui/src/main.rs` →
  `tick`). Screenshot `docs/screenshots/out-of-service-welcome.png`.
- The command line's main menu shows "*** OUT OF SERVICE: no cards accepted;
  Teller Admin sign-in only ***". Choosing Customer is refused before the
  card number is asked for, and Cash Handler before the password (`ui.rs`).
- The core refuses the same things, so a front end that forgets can't skip
  it. `service::out_of_service` tells a front end before anything is typed
  (no sign-in needed, as a real ATM shows "out of service" to anyone walking
  up). `auth::login_customer` refuses before any PIN is checked or
  counted, `auth::login_staff` refuses the Cash Handler, and a Cash Handler
  already signed in is stopped at their next action, like a customer
  (`HandlerSession::stops_when_halted`). A Cash Handler stopped by a halt is
  told "The ATM is out of service. Only a Teller Admin can sign in until it
  is resumed."

**Why.**
- Zack asked: "When frozen I think it shouldn't accept any cards at all,
  only admins." We read "frozen" two ways and did both: the whole ATM out of
  service (this section), and one account frozen by the bank (section 24).
- In 0.7.0 a front end couldn't know the ATM was halted until a customer had
  typed a card number and a PIN, so customers kept typing PINs into a
  machine that had stopped because its books didn't add up, and those
  refused tries left no trace in the log (audit F07). Now nothing is typed,
  so there is nothing to check or to log.
- The Cash Handler moves cash. In 0.7.0 the handler could still sign in and
  add or remove bills while the ATM was halted, changing the evidence before
  a teller had looked (audit F15). The halt may have been caused by cash
  that doesn't match the log (section 27).
- The Teller Admin must still get in: someone has to read the log, find
  out what failed and resume.

Test `while_out_of_service_no_card_is_taken_and_only_a_teller_admin_signs_in`
(`service.rs`); `a_failed_check_at_sign_in_takes_the_atm_out_of_service`
also checks that a live Cash Handler session stops.

## 24. A bank freeze refuses the card; a guardian's freeze doesn't

**Choice (0.8.0).** The two freezes (section 10) now do different things:

| Freeze | Set and lifted by | What it does |
|---|---|---|
| The bank's (`frozen`) | A Teller Admin only (`admin::set_frozen`) | The account's cards aren't accepted at all. The right PIN gets "This account is frozen by the bank. Please see a teller inside the branch." and the card is returned. A session already open ends at its next step. A transfer to the account looks like an unknown number, and a guardian can't move money into it. Its card can't confirm anything at the counter |
| A guardian's (`guardian_frozen`, youth accounts) | A guardian only (`family::set_frozen`) | No money out. The child's card still works: balance, history and deposits |

The teller's notice says so: "Account ... frozen: its cards aren't accepted
and it takes no transfers." Screenshots
`docs/screenshots/account-frozen-teller.png` and
`docs/screenshots/frozen-card-refused.png`.

**Why.**
- Zack's ask, read the second way (section 23).
- A bank freeze is the teller's response to a stolen card. In 0.7.0 it only
  stopped money going out: the card still signed in, a session already open
  kept working, and the thief could read the balance, history and payees,
  deposit, and even change the PIN so the real owner couldn't sign in again
  (audit F05). Refusing the card stops all of that.
- The frozen message comes only after the right PIN, so it tells a guesser
  nothing. A wrong PIN is still just a wrong PIN: it counts toward the lock
  and is logged, and so is a refused try with the right PIN
  (`auth::login_customer`).
- No transfers in from other customers (`customer.rs` → `destination`
  treats a frozen account like an unknown number), so nobody learns the
  holders' initials or sends money into an account under investigation.
  A guardian's "To child" move into it is refused too, with the frozen
  message (`family::move_money`).
- No holder consent at the counter (`auth::confirm_at_counter`): a frozen
  holder's card can't add a joint holder, open a youth account or add a
  guardian.
- A guardian's freeze is a parent's spending control (a lost card, a child
  who spends too much). The child may still need to see the balance or put
  money in, so only money out stops, as before.

Test `a_bank_freeze_stops_the_card_entirely_until_a_teller_lifts_it`
(`admin.rs`); `a_guardian_cannot_lift_a_freeze_placed_by_the_bank`
(`tests/attacks.rs`).

## 25. Starting balances: at most $20,000 per teller per bank day

**Choice (0.8.0).** A starting balance is typed by the teller, and the
machine counts no cash for it. So it is capped twice (`admin.rs` →
`insert_account`):
- each one at most the daily deposit limit ($10,000 by default, in US-dollar
  value), as in 0.7.0;
- all of one Teller Admin login's starting balances in a New York bank day
  at most $20,000 together (`STARTING_BALANCES_PER_DAY`), added up from the
  signed log (`audit::opened_today_by`). Each `account_opened` row now
  carries the US-dollar value of the starting balance (`log_opened`).

Over the cap: "Not allowed: today's starting balances would pass $20,000;
open it with less and deposit the rest at the ATM." An account with no
starting balance still opens.

**Why.**
- In 0.7.0 the cap was per account only, so one teller could open account
  after account at $10,000 each and create money with no cash behind it.
  Ten accounts already equal the machine's whole $100,000 cash maximum. The
  sign-in check passed, because an `account_opened` row is a legitimate
  entry (audit F04).
- Why $20,000: two accounts at the default $10,000 deposit limit. The demo
  bank's own sample accounts add up to about $11,600, opened by the demo
  teller when the demo bank is made, so a fresh demo bank stays under it
  (and that teller has about $8,400 left on that day).
- It is a fixed constant, not tied to the deposit limit, so raising a limit
  doesn't raise it. Anything more goes in as deposits, which the daily
  limits cover.

**Limit.** The bank has one Teller Admin login, so this is also the bank's
cap for the day. A second approver for starting balances is still open
(section 13). Test
`one_teller_cannot_create_unlimited_money_with_starting_balances`
(`tests/audit.rs`).

## 26. Activity rule 4 counts only payees paid on an earlier bank day

**Choice (0.8.0).** Rule 4 holds a transfer of $1,000 or more to an account
this account has not paid before today. A payee counts as "paid before"
only if it was paid on an earlier New York bank day (`review.rs` →
`matched_rule`). The teller sees "rule 4: $1,000 or more to an account not
paid before today".

**Why.** In 0.7.0 any earlier transfer counted, of any amount and any age.
A thief with a stolen card and PIN could send one cent to a new mule
account, then the rest of the day's transfer limit to it seconds later, and
rule 4 never fired (audit F17). A payee the customer really pays has
history from earlier days; one made a minute ago doesn't.

**Limit.** A thief who primes a payee and waits until the next bank day gets
past rule 4, but by then the customer may have reported the card, and the
other five rules and the daily limits still apply. Test
`unusual_amounts_are_held` (the one-cent case).

## 27. The integrity check lists every failure and checks more against the log

**Choice (0.8.0).** `audit::verify` (run by **Data integrity** and at every
Teller Admin sign-in):
- checks the log chain first. If the chain is broken, the other checks
  can't trust the log, so it stops there;
- then runs every other check and reports every failure, not just the first
  ("2 PROBLEMS FOUND. 1) ... 2) ..."; `AtmError::IntegrityFailures`);
- lists every account that is off, by its last 4 digits, with both amounts:
  "account ******8383 (stored $3,000.00, the log says $2,500.00)"
  (`reconcile_balances`);
- counts the cash: the bill counts must equal restocks + deposits −
  withdrawals − removals in the log (`reconcile_cash`; "CASH MISMATCH: the
  bill counts add up to ..., but the log says ... should be in the
  machine.");
- matches state against the log (`reconcile_state`): each daily limit
  against its newest `limit_changed` row (or the default), each exchange
  rate against its newest rate-history row (and every history row against
  its own `rate_changed` log entry), and each account's bank freeze,
  guardian freeze and closure against its newest log entry ("CHANGED WITH
  NO LOG ENTRY ...").

When it passes, the Data integrity tab shows one line per check, including
"The cash in the machine ($...) matches every restock, deposit, withdrawal
and removal." and "... limits, exchange rates and account freezes or
closures match the log." When it fails, every problem is shown, one line
each, under "Problems found: stop using this machine and escalate".

**Why.**
- In 0.7.0 the check stopped at the first failure and named one account.
  Nothing in the program can correct a balance, so after one known problem
  every sign-in showed the same text, and a later, separate problem on
  another account looked exactly the same (audit F10). Now a new or bigger
  difference changes the report.
- The report goes into the signed log (the halt and resume rows), which is
  not encrypted. In 0.7.0 it held the full account number; now only the
  last 4 digits (audit F23).
- Cash: a planted line that pays out one extra bill left every balance
  right, the seal valid and the cassettes matching the software count, so
  every check passed (audit F08). The log already holds the value of every
  cash movement, so one query catches it.
- State: the seal proves the file wasn't edited outside the program, and a
  record's HMAC is just as valid when the program itself computes it. So a
  code path that raised a limit, changed a rate or lifted a freeze with no
  log entry passed every check (audit F09).

**What it still doesn't rebuild from the log:** fees, card locks, youth caps
and controls, joint holders and guardian links. An edit to the file is still
refused by the seal, and fees carry their own HMAC, but a code path that
changed one of these without a log entry would not be noticed.

Tests `a_known_failure_does_not_hide_a_new_one_and_no_full_number_is_logged`,
`bills_moved_with_no_log_entry_take_the_atm_out_of_service`,
`a_limit_rate_or_freeze_changed_with_no_log_entry_takes_the_atm_out_of_service`
(`service.rs`).

## 28. SQLite's own integrity check with every seal check

**Choice (0.8.0).** Every seal check (before every operation, section 3)
first runs SQLite's `PRAGMA integrity_check`. Anything but "ok" is
"TAMPERING DETECTED: the database was changed outside the ATM. Nothing was
done. Stop and escalate." (`seal.rs` → `check`).

**Why.** The seal hashes every table row and the schema, but not index
pages. Indexes hold no data of their own, but they decide which rows a
lookup finds. The audit swapped the root pages of the two audit-log indexes
in the file (no key needed). Every row stayed the same, so the seal still
matched, but "today's withdrawals" then read the wrong index, and a second
$800 went out after the $1,000 daily withdrawal limit (audit F14).
`integrity_check` confirms every index matches its table, so the edited
file is refused before anything is read from it. This is a SQLite feature,
not course cryptography (`COURSE_MAPPING.md` 4.6).

**Cost.** It reads the whole file, as the seal already does: milliseconds
at this size, growing with the log. Test
`an_index_edited_in_the_file_is_caught_before_it_can_mislead`
(`tests/audit.rs`).

## 29. Audit findings left as design limits

An audit of 0.7.0 (2026-10-13) found 31 issues, F01 to F31
(`VULNERABILITIES.md` §9). 21 are fixed in 0.8.0. These five are the ones
most likely to come up, left as they are on purpose:

| Finding | What it is | Why it stays |
|---|---|---|
| F03 (high as reported; we rate it Limited) | The teller who opens an account sees the new card number and handles the form the customer's first PIN is typed into, and nothing makes the customer change that PIN | The customer types the PIN into masked fields that can't be copied (section 18); Change PIN is on the customer menu; every login is logged. A forced PIN change at first use would need a new card state, and every demo card would ask for it. Our advice to customers: change the PIN at first use |
| F13 | The Cash Handler login can't be reset, disabled or replaced, so a leaked password means lasting access until the bank is set up again | On purpose: no staff logins are made or reset from the teller screen, since one insider could then make themselves a handler (section 13). The handler can change their own password; while out of service the handler can't sign in (section 23); every cash action is logged and counted against the log (section 27) |
| F19 | Anyone who knows a card number can lock it with 3 wrong PINs, and a teller unlocks a card only once per bank day | Standard ATM behaviour. Unlimited unlocks would bring back teller PIN guessing (section 13). Card reissue is out of scope |
| F21 | The fee and rate on the confirm screen are worked out again when the withdrawal or deposit runs, so a change in between is charged without being shown | Fee changes are logged, capped (0-5%, minimum $0-$10) and rare; a typed rate moves at most 5% a day |
| F29 | The key fingerprint is made with the audit-log MAC key instead of a key of its own | Not exploitable: its input can't collide with a log row's, and the fingerprint is public anyway. Changing it would make every existing bank fail its key check |

The other five (F12, F18, F20, F25, F31) are written up with their reasons
in `VULNERABILITIES.md` §9.

## 30. Many ATMs at many branches (how this design would grow)

This project simulates one ATM. A real bank has many, and they must agree
on every balance. The design would grow like this (textbook §12.4: real ATMs
work this way):

- **One source of truth.** The accounts, the limits and the signed log move
  to the bank's central server. An ATM keeps no balances; it asks the server
  to approve each withdrawal, deposit or transfer, and the server applies it
  in one transaction. Two ATMs can't both spend the same dollars, because
  the server takes them one at a time (today SQLite's write lock does this
  for one machine).
- **Each ATM is a known device.** Each gets its own key, and talks to the
  server over TLS with that key (Lecture 4). A stolen ATM's key is switched
  off at the server.
- **The anchor lives on the server.** That closes our known rollback limit
  (putting back an old `atm.db` together with an old `atm.anchor`).
- **What stays on the ATM:** its own cash count, the card and PIN entry
  screens, and a local copy of its own log entries, sent to the server.
- **If the network is down,** the ATM goes out of service (fail closed),
  like it does today when the integrity check fails.

We didn't build this because the handout asks for one ATM, and a server
would add a second program to secure. The library is already split so the
same checked functions could run on the server.

