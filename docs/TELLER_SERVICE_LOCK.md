# Teller sign-in service lock

Three consecutive incorrect sign-in credentials for an existing Teller Admin
account take the ATM out of service. The booth labels this credential
**Password**; this rule applies to the teller credential, not a customer's card
PIN or the Programmer PIN. An incorrect current password when changing a
teller password or enrolling a recovery phone counts toward the same limit.
Malformed passwords for a valid teller account count too. A successful teller
password sign-in before the third failure resets that account's counter.
Unknown usernames do not trigger an ATM-wide lock.

The failure count and service lock persist across restarts. A cooldown expiring,
a correct teller password, teller phone/OTP recovery, or the teller's GUI
**Resume service** button cannot release this lock. Customers, Cash Handlers
and Tellers lose booth access, including operations from existing sessions.
Authorities can still sign in through their separate terminal and inspect the
bank. An ordinary manual or integrity halt retains its existing teller-review
workflow; this authentication lock specifically requires Authorities release.

## Authorities alert

At the third failure, the system queues an encrypted notification in the
sealed bank state and attempts delivery to the configured Bank Authorities
phone. The alert includes the teller account, failure count, incident UTC
time, notification UTC time, persistent ATM ID, configured ATM location and a
complete-body HMAC-SHA256 signature. It never includes the entered credential.
See [ATM origin alerts](ATM_ALERTS.md) for the signature and location scope.

The current delivery adapter writes text to **`<authorities-phone>.txt`** beside
the bank database. It does **not** send an SMS to a mobile network. Real SMS
delivery requires an SMS gateway integration. The Authorities sign-in code
remains in the separate `<phone>.authorities-login.txt` file.

If the phone is missing or delivery fails, ATM service remains locked and the
pending notification is retained. Startup and staff sign-in attempts retry
it; Authorities can also use `retry-service-alert`. A successful delivery
removes the pending notification. Delivery does not itself restore service.

## Restore service through the Authorities terminal

Follow [Bank Authorities sign-in](BANK_AUTHORITIES.md) and open the existing
bank installation:

```sh
cargo authorities --directory /path/to/bank
```

After phone/OTP authentication, inspect the incident and restore service:

```text
service-status
teller teller
audit
check
retry-service-alert
resume-service Verified teller identity and reviewed failed sign-ins
service-status
```

Replace `teller` with the affected staff username. `retry-service-alert` reports
`delivered: false` when no pending alert exists or delivery is still blocked;
the financial activity log records delivery failures. `resume-service` requires
a nonempty review reason (up to 500 bytes, no control characters) and passing
integrity/reconciliation checks. It restores service and resets Teller Admin
failure/cooldown counters without changing any password or phone number.
It rejects expired or wrong-bank Authorities sessions.

The halt, failed booth sign-ins, delivery outcomes and system service-state
transition remain in `atm.db`'s signed audit. The Authorities identity and review
reason are recorded in the private `atm.admin-audit.db` administrative audit.
See [Administrative audit and privacy](ADMINISTRATIVE_AUDIT.md).
