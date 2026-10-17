# Enrolled OAuth consent, one-shot exchange and pending staging

This source profile connects a genuinely authenticated consent to one claimed
provider token request, immutable retained material and atomic pending staging.
It is not runtime validation, independent provider-authorship evidence (O02),
credential activation, a revocation worker or cross-deployment coordination.
See [application enrollment](oauth-application-ownership.md) and
[atomic activation](oauth-atomic-activation-authority.md). Development JSON state
and its existing route behavior are not promoted into production authority.

## Authority and originals

The independently signed measured configuration must enable the exact operations
and contain `oauthExchangePolicy` (`catchplate.oauthExchangeAuthorityPolicy/v1`):
the enrollment Ed25519 public key and SPKI pin, control-plane configuration digest,
deployment ID, and explicit pending/revocation capacities. The root is independent
of configuration/runtime/authority-role keys. Where activation is also configured,
its OAuth enrollment scope must match; the enabled-operation grants stay separate.
Both verifier and planner reverify the exact signed enrollment under their own
admitted configuration, not a root or success object supplied by HTTP.

`oauth.exchange.prepare` uses the new purpose
`credential.oauth.exchange` / `catchplate.oauthExchangeConsentOptions/v1`.
It requires the actual current OIDC requester with literal `credential_owner`
membership, a fresh raw WebAuthn assertion, hardware attestation/current trust,
UP and UV. An admin override or an `actor_id` string is insufficient. Assertion
and challenge use are consumed atomically with protected state, reserved
revocation capacity and audit. Distinct-person approval remains mandatory in the
separate activation operation; consent is not credential activation authority.

The closed eight-field request keeps enrollment original, requester, policy and
operation binding. Prepare's closed18-field body commits a preselected UUID,
state/browser/PKCE hashes, encrypted private state and empty reserved envelope,
provider/client redirect scope, name/scopes/metadata, enrollment digest, capacities
and original absolute bounds. No setup or reconnect is supported by this new-only
profile; the actual client refuses both before consent/provider contact. These
remain required product work, not permanently excluded features.

## Durable transitions

| Operation | Protected state | Required boundary |
| --- | --- | --- |
| `oauth.exchange.prepare` | absent → `prepared` | Genuine consent; exact absent identity and authenticated complete capacity populations; commit before returning the authorization URL |
| `oauth.exchange.claim` | `prepared` → `claimed` | Exact state/browser possession, retained row digest, code/contact request commitments; atomic reserved-work → exchange-in-flight; definite commit and source-owned readback before the sole POST |
| `oauth.exchange.retain` | `claimed` → `retained` | Exact immutable encrypted raw reply plus nullable normalized token original; retain before identity GET; no overwrite |
| `oauth.pending.stage` | `retained` → `staged` | Exact token ciphertext copied to pending, exact held work consumed, pending expiries/collision/capacity checks and audit in one controlled transaction |

`oauth_exchange_reservations` is a new authenticated sixteen-column relation.
Every original column, including private encrypted originals and nullable stage
fields, participates in its canonical row digest. The executor holds the actual
writer-conflicting fence and revalidates the planner's same roots. There is no
runtime-DML workaround, SQL retry, row deletion, reattachment, contact retry or
"already successful" result that authorizes another provider operation.

The UUID is shared by revocation work, final token envelope, pending credential
and eventual credential, at version1. Staging copies the same ciphertext/AAD;
it does not pretend that different encrypted blobs prove equal plaintext.
Private state and raw replies use separate deterministic UUIDv5 artifact IDs
from `authority_oauth_exchange.artifact_id`, with purpose `state` or `response`.
Raw reply SHA commits the canonical original `{status,rawHeaders,bodyBase64url}`.
The token plaintext hash and exact review preserve the existing activation payload
recipe, including its `sha256:` prefix. Ciphertext/hash equality is not proof that
a provider issued the token or verified an account; the actual retained HTTPS
client performs its identity request and existing checks, without manufacturing
measured provider evidence.

Callbacks do not invent a fresh OIDC requester. They rejoin the original protected
requester, current role, exact enrollment/policy, state and browser-cookie
possession, current signed capacities and full row digest. A nullable retained
token cannot stage. Malformed/error/oversize responses or uncertain contact leave
consumed uncertainty; no old fallback reserve, immediate revoke/retry, work
deletion or success repair is entered. A later purpose-owned cleanup path remains
required, and retained raw data alone is not cleanup permission.

## Bounds and capacity

Consent is at most30s old at prepare. Contact expires at most600s after the
precommitted issue time; retention expires at most600s after contact expiry;
pending expiry is at most3600s after contact expiry. All are ordered and clipped
to the originally admitted enrollment. The live callback owner keeps its original
at-most30s budget. Cleanup-only retention cannot renew that owner or authorize a
second POST. No operation resets expiry to `now + TTL`.

The new transport source profile bounds token replies to96KiB and canonical raw
headers to8KiB so encrypted raw and token originals remain within each256KiB
envelope. Request arguments are at most768KiB, a protected exchange row at most1MiB;
existing global query/plan/frame bounds still apply. These are stricter limits,
not support for every legacy-sized response.

Every complete-population proof reconstructs the entire same-transaction radix
root, rather than trusting a SQL count, row limit or membership proof as absence.
Prepare checks complete exchange/work/pending populations; stage checks complete
credential/pending/setup populations. Each table is limited to64 originals and
aggregate existing proof/byte limits may refuse sooner. Signed capacities are1..64
and must match actual client policy (pending=min(configured pending capacity,64),
revocation64). Google collision checks retain complete local credential and pending
populations, including expired/revocation-pending originals. Staging atomically
marks expired pending rows for revocation and preserves backlog checks. There is
no pruning of completed exchange history to reclaim this initial capacity.
Larger populations and purpose-authorized terminal-history maintenance remain
explicit follow-ons.

## Protected source compatibility and open work

The new table and existing `oauth_revocation_work` have source-owned primary-key
registrations, authenticated roots, guarded writes and manifest/schema inclusion.
The runtime role receives no DML upgrade. This deliberately prevents old direct
work writers from becoming a production fallback: reserve/expiry pruning,
mark-exchange-started, attach/overwrite, mark-uncertain/pending, complete/delete,
create-work, consume-work and revocation-reconciler claim/finish paths require
their real controlled successors. Development behavior remains separate.
The already protected setup/generation writers retain their documented boundary.

Required next work includes controlled revocation/refresh, setup/reconnect,
larger-population acquisition and cross-deployment family coordination. Current
OAuth application enrollment and independent roots/services must be provisioned;
source-connected code is not a tested pilot or a production gate pass. No tests,
builds, interpreter execution, provider requests or cloud work accompanied this
source change.

The paired [data schema](../schemas/oauth-exchange-authority.v1.schema.json)
describes closed shapes only; signatures, possession, current roots, exact bytes,
time and one-use commit/readback remain runtime responsibilities.
