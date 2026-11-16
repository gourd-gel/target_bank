# Customer PIN lock and Authorities resolution

Three consecutive incorrect PIN attempts lock that customer's login identity.
Customers sign in with a **card number**, so the lock applies to that card;
there is no separate customer username. Other customers and other holders'
cards remain available. The whole ATM is not halted by a customer PIN lock.

The same counter covers customer sign-in, wrong current PINs during a PIN
change, and holder PIN confirmation at the teller counter. A successful PIN
check before the third failure resets it. Malformed PINs for an existing card
count as failures too. No PIN is checked once the card is locked. Existing
sessions are refused at their next core operation. The lock and counter
survive restarts, and a correct PIN or waiting until tomorrow does not release
the lock. Teller unlocking is disabled in the core and removed from the GUI.

## Authorities text alert

The third failure queues an encrypted alert in the same sealed transaction as
the lock. After commit the ATM attempts delivery to the configured Authorities
phone. The alert contains the customer actor, masked card suffix, source,
incident reference/time, ATM ID/location, notification UTC time and a complete
HMAC-SHA256 signature. Entered PINs and full card numbers are not included.

The current adapter writes **`<authorities-phone>.txt`** and keeps a separate
**`<phone>.customer-lock.<card-id>.<incident-reference>.txt`** per incident.
Authorities OTP codes stay in their separate `.authorities-login.txt` files.
These are local text files; real SMS requires an SMS gateway integration.

Failed delivery never removes the lock. Pending incidents remain encrypted in
`atm.db` → `meta` (`customer-pin-alert:*`). Startup, customer sign-in attempts,
PIN-lock creation and the explicit Authorities retry command retry delivery,
up to 20 pending incidents per pass. Different incidents retain separate
records. Notification does not unlock a card; a delayed alert describes the
original incident, so Authorities should check the current card state.

## Cargo command for Authorities

Start the separate terminal and complete Authorities phone/OTP authentication:

```sh
cargo authorities --directory /path/to/bank
```

Then use these commands, replacing the example card with the affected card:

```text
users
user 1234567890
check
retry-customer-alerts
resolve-customer 1234567890 Verified customer identity and reviewed PIN attempts
user 1234567890
```

`resolve-customer <card-number> <review reason>` requires an authenticated,
unexpired Authorities session and a nonempty review reason of up to 500 bytes
without control characters. It clears only that card's PIN lock and failure
counter. It does not change the PIN, lift account/guardian freezes, reopen a
closed account, release a teller service lock or unlock other cards. Closed
accounts and cards that are not locked are refused.

The system unlock transition remains in the signed financial/security audit.
The Authorities actor, target reference and review reason are saved in the
private administrative audit; see [Administrative audit and privacy](ADMINISTRATIVE_AUDIT.md).
Tellers can view their locked-card list and refer customers to Authorities,
but cannot execute the resolution command or API.
