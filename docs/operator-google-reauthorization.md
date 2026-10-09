# Reauthorize an existing Google account

## User journey

An inbox worker should not need a new application, app token or permission rule
when its owner renews Google consent. Reauthorization replaces the provider
tokens for the same saved account. It is not disconnect-and-add, a permission
expansion, or a renewal of the application's own Serverware token.

The account card offers **Reauthorize** only when the deployment advertises the
supported lifecycle. The review names the account, Read Gmail permission and
affected applications. **Continue to Google** starts one browser-bound consent
attempt. The return page goes back to Accounts and keys, not app creation.
The UI reads the exact saved operation and refreshes the catalog before showing
that a replacement was saved. An old active account alone is not success.

A missing or lost response offers **Check saved status**, never an automatic
repeat of consent. The client chooses a public operation UUID before sending
the start request, so a lost response does not lose the lookup reference.
Provider URLs, OAuth state, authorization codes, PKCE verifiers and tokens are
not stored in browser persistence. A one-time unsaved application token blocks
navigation to Google until its existing save-and-clear action is completed.

Not every refresh error requires reauthorization. Client configuration errors
need administrator attention; temporary or uncertain responses are not proof
that consent was revoked. Google's [offline access and error documentation](https://developers.google.com/identity/protocols/oauth2/web-server)
describes the provider lifecycle. Reauthorization does not itself prove that
the next Gmail request will succeed.

## Backend contract

The operation has its own actor-bound durable record. It does not repurpose
initial consent or generic reconnect, and it preserves the original connected
intent, account ownership, credential ID/name, applications, application token
verifiers/expiry, rules and signed policy bytes.

The review binds the current catalog revision, policy hash, core generation,
Google subject/account, OAuth client/profile, exact canonical scopes and the
complete affected assignment set. Normal refresh may continue while the user
is on Google's consent page. If its generation or the reviewed access changes,
the callback refuses before provider contact; it does not silently rebase the
review. State and browser nonce are single-use and PKCE remains required.

Before token exchange, a committed candidate reservation excludes competing
refresh or adoption for the target. No publication lock or database transaction
is held over provider I/O. Issued material enters encrypted custody before later
response, scope or account checks can fail. Wrong-account, malformed and
uncertain results cannot replace the original credential.

The candidate purpose is explicitly non-revoking. Neither a rejected candidate
nor a superseded token enters generic cleanup or Google's grant-wide revocation
path. Explicit disconnect and disconnected/quarantined-family succession remain
different operations. Their exclusions are not cleared by reauthorization.

Successful adoption changes the encrypted material and advances its generation
once, in the same transaction as the exact candidate retirement, durable result
and redacted audit event. An uncertain commit is checked against that receipt;
absence of a candidate alone does not establish adoption or rollback. Receipts
remain meaningful after a later legitimate automatic refresh advances the
generation again. Existing leases and in-flight requests are not recalled by a
management-page success message.

Fresh profiles initialize the metadata-only operation owner. Retained profiles
need an explicit, reviewed additive schema upgrade, not automatic startup repair.
A prior admission marker or retained candidate with missing ownership refuses
reconstruction. This upgrade cannot enable the Google profile, change its client
or callback, migrate a pinned origin allowlist, or grant provider access.

The administrator setup API is
`GET /api/operator-demo/oauth/google/reauthorization-storage`. For a genuinely
older profile it returns `available: false` and an exact `review` containing
`expected_revision`, `expected_policy_hash` and `profile_binding_digest`.
An explicit same-origin administrator `POST` to that same path accepts exactly
that review. An already admitted owner is not re-created, and a lost response
must be checked with GET rather than replaying POST. This is deployment setup,
not another field or step in an account owner's consent form.

## Verification status

The focused synthetic backend passed eight groups across fifteen cold workers
on source `2897498d` (2026-10-09): real ASGI/browser-state/PKCE handling,
encrypted custody, signed policy, SQLite transactions and audit, with only the
provider transport substituted. The successful path replaced the same account,
preserved application authority and then refreshed the replacement token through
the ordinary credential-lease path. The short synthetic lifetime exercised its
actual refresh window; it is not a natural-expiry or live-provider claim.

Controls covered wrong identity/scopes, stale generation, a concurrent refresh,
orphan ownership, SQL replacement guards, reviewed older-schema upgrade,
denial/expiry/replay, HTTP admission, rollback, a real commit followed by a lost
acknowledgement, and separate-process restart. The original harness permission
failure occurred before account setup and is retained separately. The corrected
run used new 0700 scratch directories; no application guard was relaxed.

Unittest time was 218.286 seconds, with no failures, errors or skips. The
network-none, read-only-source/root container exited zero with PID zero and no
OOM. Evidence is `google-reauthorization.8I0mQ6rR/corrected` under the operator
workspace evidence directory. Result SHA-256:
`bae90c7d9fd303187d7bf69e9f61b24f59acc16f094578aa7ee0a06d2d1bfa50`.

Rendered browser acceptance remains in progress. These changes do not establish
a deployed UI, a real Google consent/refresh journey, ordinary SDK compatibility,
native commissioning or production acceptance. No live service or terminal R96
pilot state was changed by this work.

Acceptance must join start, actual browser-state/PKCE handling, token custody,
same-account generation replacement, unchanged application authority and a
subsequent refresh. Negative controls cover stale review, wrong account/scopes,
denial/expiry/replay, conflicting work, unavailable ownership, audit rollback,
lost commit acknowledgement and cold restart. Separate rendered checks exercise
the exact operation lookup, held-token protection and independent consent-panel
holds; intercepted browser fixtures are not real provider acceptance.
