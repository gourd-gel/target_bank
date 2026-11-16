# Teller OTP password reset and recovery phones

“PIN reset” for a teller means resetting the **existing teller password**.
It does not create a separate numeric PIN or change customer card PINs.

## OTP signs in, then password registration completes

1. Choose **Forgot staff ID or password?** on Teller Admin sign-in.
2. Enter the **primary registered phone** and click **Send code**.
3. Read the code from the primary phone's text file and enter it.
4. Successful OTP verification signs the teller into a restricted session and
   sets the account-wide **`is_pin_changed = false`**.
5. The GUI shows **Reset teller password**. Enter a new password twice. The old
   password is not required; the OTP already authorized this reset.
6. Saving the new password sets **`is_pin_changed = true`** in the same database
   transaction and opens the main teller page.

`is_pin_changed` is persistent per teller, shared across sessions/connections,
and survives logout and restart. Merely requesting a code does not reset it.
It returns to false when a new recovery OTP is successfully verified. Existing
accounts without this new field default to true because their initial password
has already been registered.

While false, the core blocks normal teller operations regardless of GUI state.
Another already signed-in session observes the same flag; the GUI checks it
periodically and routes to the reset screen. A password-authenticated session
without the current OTP approval must sign out and verify a recovery OTP first.
Each verified OTP advances a reset-approval generation, so an older OTP session
cannot reset a password after a newer OTP has been approved. Invalid passwords,
failed database writes, expired sessions and wrong-bank sessions cannot approve
the flag. Passwords remain subject to the existing 12–128 character policy.

A successful reset invalidates the old password for subsequent sign-ins. Normal
password sign-in does not itself reset the flag. Teller authentication service
locks still require Authorities restoration before phone recovery can proceed;
see [Teller service lock](TELLER_SERVICE_LOCK.md).

## Primary registration and a hidden secondary

Each teller in a file-backed installation receives a distinct, randomly
allocated **simulated secondary number** at staff setup or startup. The mapping
is kept in **`atm.teller-phones.secret`** for `atm.db`, or
`<bank-stem>.teller-phones.secret` for another database name. It is a local JSON
map from teller username to secondary number, written atomically with owner-only
Unix permissions. It is excluded from version control. Generated numbers are
for the local delivery simulation; they are not verified real mobile numbers.

The secondary is also encrypted in the teller's sealed recovery metadata for
routing and consistency checks. It remains stable across restarts. A mismatch
between an existing secret file and sealed state is refused without printing
number values. Keep the secret file in the protected installation backup.
The older `numbers.txt` contact file is not modified or printed.

A primary number must be registered and verified before phone recovery is
available. After normal sign-in, or after completing an OTP password reset,
open **My password → Cell phone recovery**, enter a primary number privately
and the current password, click **Send code**, and confirm its verification
code. For an installation with a provisioned hidden secondary, a newly verified
primary replaces the old primary; the old primary stays active until proof is
complete. The hidden secondary remains unchanged. There are at most two active
destinations. A number belonging to another staff account or Authorities, or
equal to the hidden secondary, is refused. Ownership is checked again at
confirmation.

Legacy explicitly enrolled two-number records remain supported and are adopted
into the protected secret mapping on startup.

## Delivery and privacy

A recovery request sends the **same six-digit OTP** to both active destinations.
Both copies share a five-minute expiry, five-attempt budget, one request per
minute and up to three requests per fifteen-minute window. Consuming either
copy consumes the challenge. A resend supersedes both copies. Both deliveries
are attempted; failure at either destination invalidates the entire challenge.
The new-primary enrollment code is sent only to that new number to prove access.

The primary recipient uses **`<primary-phone>.txt`** beside the bank database.
A provisioned hidden secondary uses
**`.<bank-stem>.<teller-username>.secondary-otp.txt`**, so the filename does not
reveal the hidden phone value. Authorities sign-in retains its separate
`<phone>.authorities-login.txt` file. These code files are owner-only on Unix.
Actual SMS delivery requires an SMS gateway integration.

The GUI displays only the primary number. New-number input is masked.
Authorities `staff`/`teller` reports show primary `phone` and
`verified_phone_count`, never the secondary value. OTP alerts show the primary
number, destination count, ATM origin and signature. Audit events remain for
OTP sign-in, password reset and phone registration/verification, but do not
record the secondary number. Raw recovery metadata stays protected in table
reports.
