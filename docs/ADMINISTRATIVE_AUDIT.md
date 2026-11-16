# Programmer and Bank Authorities audit

Administrative activity is saved in **`atm.admin-audit.db`**, separately from
the GUI activity audit and bank financial records. Its application read APIs
require an authenticated **Bank Authorities** session. The Programmer tools
write events but do not grant access to read this administrative history.

## Privacy impact

**These audit records can affect the privacy of people acting as Programmer
or Bank Authorities.** They record the acting role/account, timestamps,
actions, outcomes and inspection targets. This can reveal working patterns,
sign-in attempts, maintenance performed and which users or tellers were
investigated. A role/account label or failed sign-in attempt does not by
itself establish which individual performed an action.

Access to these records is restricted to Bank Authorities. Exported reports
contain the same sensitive information and should receive the same access
restrictions. PINs, OTP values, passwords and private-key material are not
recorded as audit fields.

## Recorded events

- Authorities code requests, including rejected, throttled or failed delivery.
- Authorities successful/failed sign-ins, sign-outs and expired session exits.
- Authorities database/schema/table inspections, user/staff/account lookups,
  activity searches, integrity checks, revenue views and adjustments.
- Reading the administrative audit itself.
- Programmer phone/location changes: PIN authentication result, requested
  operation result and application of valid configuration to a bank.
- Programmer processing-fee key provisioning and encrypted fee-record reads.

Inspection entries record a request and its target; they are not a copy of
the returned personal data. Financial revenue changes also retain their
existing financial ledger entries for reconciliation.

## Authorities terminal commands

Sign in using the [Bank Authorities terminal instructions](BANK_AUTHORITIES.md),
then run:

```text
databases
tables administration
rows administration store_meta
rows administration events
admin-audit
admin-audit 1
```

The database name is **`administration`**. `rows administration events` shows
stored encrypted payloads and integrity metadata. `admin-audit` returns
decrypted events with reference, timestamp, actor, action, outcome and details.
Pages start at 0 and contain up to 20 events, newest first. Teller, Cash Handler
and Customer sessions cannot call the administrative audit reader. There is
no administrative-audit route in the booth GUI.

## Storage and protection

Payloads use AES-256-GCM encryption and an append-only HMAC-linked record chain.
The service stores the separate key in **`atm.admin-audit.key`**. File permissions
are owner-only on Unix. Role restrictions are enforced by the application;
the service account and direct access to its database/key files remain trusted.
Do not distribute those files to ordinary GUI users.

Programmer tools can create this log before a bank exists. The existing-bank
runtime attaches it and checkpoints the observed administrative head in its
sealed state. Missing/mismatched keys, altered records or schema, and rollback
behind that checkpoint are refused. Administrative records and bank state
changes use the same transaction when they occur together. File-based
configuration tools record authentication and operation outcomes in the
administrative store without initializing a bank.

For another database name, the files follow its stem: `branch.db` uses
`branch.admin-audit.db` and `branch.admin-audit.key`. Directory-based phone and
location maintenance commands use the standard `atm` installation files.

Back up and restore a consistent set while the bank is stopped:

- `atm.db`, `atm.processing-fees.db`, and `atm.admin-audit.db`;
- the matching `atm.anchor`, `atm.key`, and `atm.admin-audit.key`.

Keep the programmer's processing-fee private decryption key in its existing
separate custody. It is not the administrative audit encryption key.

The remaining logs are stored as follows:

| Store | Records |
|---|---|
| `atm.db` → `audit_log` | Signed financial records underlying the GUI's requested-amount activity view |
| `atm.db` → `bank_revenue`, `revenue_ledger` | Processing-fee balances and financial credits/debits |
| `atm.processing-fees.db` | Programmer-encrypted processing-fee records |
| `atm.admin-audit.db` → `events` | Encrypted Programmer and Authorities audit events |
