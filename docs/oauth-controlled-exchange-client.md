# Enrolled OAuth consent and callback client

This source path connects the independently cold-enrolled application to the
fixed `oauth.exchange.prepare`, `oauth.exchange.claim`, `oauth.exchange.retain`
and `oauth.pending.stage` writers. It supports a new credential without a setup
session or reconnect target. The old unconfigured development path is unchanged;
enrolled refresh, reconnect and revocation do not fall back to its runtime DML.
The existing portal is not yet wired to these new ceremonies. This is source
integration, not an executed provider flow or a testable pilot claim.

## Consent is an explicit cookie-authenticated ceremony

`POST /api/oauth/consent/options` accepts the existing new-credential OAuth start
fields, with no MFA, credential ID or setup binding. It requires an actual fresh
OIDC browser session carrying the `credential_owner` role, a matching Origin and
CSRF check. Bearer/admin-token headers and admin-cookie substitution are refused;
the client never silently clears them. An administrator-role override alone
does not authorize this profile.

The producer chooses the exchange UUID, state, browser nonce and PKCE verifier
before asking the authority for a genuine purpose-bound hardware WebAuthn
challenge. It sets the state-specific Secure, HttpOnly, SameSite=Lax cookie and
returns exactly `publicKey`, `serverware` and `request`. The first two retain the
five-field WebAuthn options and seven-field authority-options projection; the
third is the exact 18-field `oauth.exchange.prepare` request. Private state/PKCE
is encrypted, not exposed as review text. The echoed ciphertext is not authority.

The requester then explicitly sends `POST /api/oauth/start` with exactly:

- `apiVersion: serverware.oauthExchangeConsentOptions/v1`;
- `request`: the exact prepared request;
- `mfa`: exactly `oauthExchangeProfile` with that same schema and the genuine
  raw `assertion`.

Start repeats fresh cookie identity/CSRF/current-role checks, decrypts and
re-admits the original private state, checks the state-specific browser nonce
and exact application enrollment, and submits the actual assertion to the
controlled prepare writer. Only a definite verified response and exact protected
row readback permit returning the authorization URL. No generic requester MFA
write or separate runtime audit write occurs. The enrolled branch refuses the
old start request format rather than silently upgrading it.

## Original windows and independently configured capacity

The prepared record commits absolute issued, contact, retention and pending
expiry epochs. Prepare must still be within 30 seconds of its original issued
time. Contact is at most 600 seconds after issuance; retention is at most 600
seconds after contact expiry; pending expiry is at most 3600 seconds after
contact expiry. All are clipped to the original enrollment expiry. Options,
start and callback cannot replace these values with a fresh allowance.

Each actual HTTP owner has its own at-most-30-second wall/monotonic operation
budget, further narrowed by those original windows and the retained cold owner.
Claim and token contact use the contact deadline. Retention/staging may use only
the remaining original callback budget before retention expiry; that later
window never permits another token POST. Capacity values are fixed from local
configuration (pending capacity capped at 64 and revocation capacity 64) and must
also match the independently signed current authority policy at every transition.

## Callback claim, retention and staging

The callback obtains the exact protected exchange row by its state-bound UUID,
not from the development JSON state file. It checks the original state and
browser cookie, decrypts the retained private state, and rechecks requester,
policy, application, redirect, scopes, metadata and PKCE commitments. Callback
possession does not manufacture a current OIDC identity: the requester comes
from the original protected row and the authority checks that association.

The claim commits the authorization-code digest and the exact source-constructed
token request commitment before contact. The same actual owner retains the
definite signed claim and full row original, checks them immediately before its
single token POST and consumes its local attempt before sending. A transport
error, HTTP error or uncertain commit never resets this claim. No redirect is
followed, and no automatic second token request is made.

The source keeps a canonical original of the actual response status, ordered
raw headers and body bytes in an independently encrypted response artifact. It
normalizes any usable token material once, encrypts it under the preselected
credential UUID/version 1, and commits both originals before an identity GET.
The response body is limited to 96 KiB, canonical raw headers to 8 KiB and each
canonical response/token plaintext to 190 KiB so the closed encrypted envelope
fits its 256 KiB ceiling. These are additive enrolled bounds; the development
transport's existing bounds are unchanged.

Malformed replies can retain raw bytes and optional minimal revocation material,
but the client never submits them for staging. Exact retained ciphertext is
decrypted and compared with the held plaintext originals before proceeding;
ciphertext equality is not presented as plaintext or provider proof. A valid
reply is followed by the actual configured identity GET. Its resulting metadata
and review preserve requested custom metadata and the independently enrolled
application association. They are not synthetic signed provider evidence.

Staging atomically creates the pending row, consumes the exact retained work and
records the audit event. The same token ciphertext identity continues through
pending staging and later [controlled activation](oauth-controlled-activation.md),
without re-encryption to a different credential ID. Pending expiry is the
original committed epoch, not a new `now + TTL`. The HTTP response contains the
pending ID, not tokens, ciphertext, provider reply bytes or active credentials.

## Failure and product boundaries

Once claimed, a callback cannot be retried as a fresh exchange. A denial or
malformed callback before claim makes no provider contact and does not delete
protected history through a development helper. Failures after contact preserve
the consumed state and any definitely retained originals; no inline revocation,
legacy work deletion or retry is used. This does not guarantee token bytes
survive process death, an expired owner or a retention failure. Raw evidence is
bounded, private and not logged. Authorized revocation/recovery and protected
history retirement remain separate transitions.

The portal still needs to consume these options, preserve the exact request,
perform fresh WebAuthn, explicitly start consent, then drive the distinct-person
activation request/decision/fresh-requester ceremony. Reconnect, refresh, setup
sessions, cross-deployment subject fencing, external application coordination
and measured provider issuance (O02) are not closed by this API. Independent
enrollment/configuration roots and current physical authenticator trust still
must be provisioned. No build, test, browser, provider or runtime execution is
claimed here.
