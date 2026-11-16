# ATM origin in Bank Authorities alerts

Every teller phone-code request alert now includes the requested phone and verification message (or rejection reason), plus:

- **ATM ID:** a random 128-bit identifier stored in sealed bank metadata. It remains stable across restarts. Each new installation receives its own ID, even if a deployment uses the same runtime key.
- **ATM location:** the branch/address/building/terminal label configured by the programmer.
- **Alert time (UTC):** an RFC 3339 timestamp.
- **ATM signature (HMAC-SHA256):** an authentication tag covering the complete message body, including the phone, location, identifier, timestamp, and verification text.

These fields appear on enrollment/replacement code requests, teller sign-in recovery requests, and invalid, unknown, or rate-limited requests. Bank Authorities login codes remain separate from teller alerts.

## Set the location

From the programmer source workspace, run:

```sh
cargo atm-location "Branch address, building, terminal 01" --directory /path/to/bank-folder
```

Enter the separate programmer PIN at the hidden prompt. The command requires `.programmer-pin.secret` in the source workspace, creates or replaces `atm-location.txt` in the bank folder atomically, and does not require a bank login or initialize a bank. The programmer secret stays with the programmer and is excluded from the bank delivery. Normal GUI builds exclude this maintenance binary.

Location must be 1–240 characters on a single line. Empty labels and embedded control characters are rejected. Startup and every teller OTP alert import a valid location into sealed bank metadata. The imported state remains sealed. The initial location can be configured before first-run staff setup. Removing the configuration file preserves the last imported label.

Until configured, alerts explicitly report **Not configured**. The application does not invent an address or use GPS/geolocation. An invalid or unreadable location configuration blocks startup or prevents delivery of a newly requested teller code rather than issuing a misleading alert.

## Signature and custody

The final signature line is excluded from the signed body. The tag uses a purpose-specific HMAC key derived from `atm.key` with the label `bank-of-ccny/atm-alert/v1`; this key is separate from the existing PIN, database-seal and audit keys. Verification recomputes the tag over the exact preceding body and compares it with the reported hexadecimal signature.

This is shared-key authentication, not a public-key signature or hardware attestation. Someone holding the runtime key can authenticate messages. The location is the programmer's configured label. Restoring or cloning the complete bank database preserves its ATM ID; independent physical terminals should use separately provisioned bank installations rather than cloned identities.

Alerts continue to use the existing local phone-number `.txt` delivery simulation; this change does not send actual SMS. Keep the identity metadata with the existing coordinated bank/fee database and anchor backups.
