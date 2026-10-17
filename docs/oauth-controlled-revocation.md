# Current authority for retained OAuth cleanup

This source profile connects retained issued-token work from the enrolled
exchange writer to separately authorized cleanup. It is source-only: unbuilt,
unexecuted and unprovisioned. An observed HTTP response is not proof that a
provider invalidated a token, independent provider authorship, O02 measurement,
global application uniqueness, or physical custody.

## Two different authorities

`authority_oauth_revocation.sign_authorization` produces the exact closed
`catchplate.signedOAuthRevocationAuthorization/v1` envelope. Its twenty-field
payload is `catchplate.oauthRevocationAuthorization/v1`, purpose
`retained-oauth-revocation`. Ed25519 signs the payload schema, one NUL byte, and
the exact sorted `ensure_ascii=True` JSON payload, without a trailing LF.
SHA-256 commitments use those same canonical bytes, including escaped DEL.
The current shared source-revision constant is required, not an example cohort
copied into a grant. The original grant interval is at most five minutes.

The measured verifier and planner independently admit `oauthRevocationPolicy`
from their genuinely signed configuration: exact schema, grant-root raw Ed25519
public key and SPKI hash, control-plane configuration digest, and deployment ID.
The current cleanup root must differ from configuration, runtime role, OAuth
enrollment and WebAuthn purpose roots. Merely retaining a token or its raw reply
grants no cleanup permission.

The grant selects the exact retained exchange and work row digests, original
enrollment hash, historical enrollment-root SPKI, token envelope and plaintext
hashes, provider, client identity/material hash, full provider configuration and
ordered token purposes. That current signature authenticates the independently
delivered historical root association. The historical enrollment signature and
exact retained byte association are verified, and exchange creation must fall
inside its historical interval. Its old consent window need not still be live;
it is never renewed or treated as a new application owner. Only the current
cleanup grant and actual current custody authorize this new effect.

The historical parser supports the existing enrollment-v1 original only. This
is not a migration or arbitrary older-source adapter. The full provider
configuration and client material must still match that original. Endpoint or
client rotation requires another explicitly supported authority contract, not
substitution in an old grant.

## Fixed cold delivery and source selection

`control_plane_oauth_revocation.initialize_from_environment()` runs once in
`control_plane_runner`, after genuine cold custody and application-owner startup,
before importing the HTTP runtime or application. ASGI startup only rechecks the
same selection before starting workers; it never admits descriptors or reloads
authority. Runner cleanup closes revocation selection before custody teardown,
including partial-startup errors. Closing poisons further operations without
closing borrowed custody descriptors, renewing a grant, settling uncertain work
or claiming erasure of immutable Python secret bytes. The
fixed descriptor entrypoint delivers `CATCHPLATE_OAUTH_REVOCATION_CONFIG_FD`
from `/run/catchplate/authority-trust/oauth-revocations.json`. Its exact six
fields are `schema`, `sourceRevision`, `configurationDigest`, `authorityRootFd`,
`authorityRootSha256`, and `authorizations`; schema is
`catchplate.oauthRevocationStartup/v1`. At most sixteen entries each contain
only `authorization`, `clientMaterialFd`, and `historicalEnrollmentRootFd`.

Files are selected by source-fixed paths, not paths supplied in a grant:

- Current root: `/run/catchplate/authority-trust/oauth-revocation-root-public-key`.
- Client material: `/run/secrets/catchplate-oauth-revocation-<authorizationId>-client`,
  where the suffix is the signed canonical UUID.
- Historical root: `/run/catchplate/authority-trust/oauth-enrollment-history/<SPKI-hex>-public-key`.

The entrypoint opens bounded root-owned originals and delivers sealed memfds.
Private client originals require mode `0400`; no private grant-signing key is
delivered. Target descriptors are unique, initially unused, in 32..1023, and
disjoint from every other inherited descriptor. The cold owner requires all
of them in the actual custody-owned inherited inventory, retains and rechecks
their identity/seals/bytes, and rejects environment, process, identity or clock
changes. Config is at most 2 MiB; each grant is at most 64 KiB, client original
32 KiB and root PEM 4 KiB. Admission itself is bounded by the original custody
window and thirty seconds. Each cleanup operation is clipped once to at most
thirty seconds, the actual service bound, current custody and the original grant.

An explicit empty production configuration has an empty authorization list and
null root fields. It remains selected: it never falls back to the development
worker. Independently unconfigured development keeps its old profile. Missing,
changed or invalid production delivery fails closed. Provisioning the current
authority policy, grant root, grant originals, historical roots, exact private
material, metadata roots/ACLs and live custody is an external prerequisite; the
source creates none of those authorities.

The application calls `selected()` before any legacy claim/expire/finish DML,
then `reconcile(limit=...)`, capped at sixteen. There is no new HTTP cleanup
endpoint, caller root, callback verdict or caller-supplied token. The fixed
grant list is visited at most once per live cold owner, without reload/backoff.

## Exact protected transition and real contact

`authority_transition_oauth_revocation` implements three registered kernels.
Both new tables have source-owned primary keys and are in the protected-root
inventory. Existing runtime roles receive no generic mutation privilege.

1. `oauth.revocation.claim` selects only the exact `retained` exchange and
   `held`, zero-attempt work from `enrolled-oauth-exchange/v1`. It inserts
   `oauth_revocation_reservations` keyed by the existing work ID and atomically
   changes the actual work to `revocation_reserved`, with audit. This conflicts
   with staging's genuine held-work predicate; cleanup and activation cannot
   both consume the same material. The journal retains the exact grant,
   original work bytes, exchange hash, original expiry and a hash of the live
   owner's random nonce. A public metadata row is not possession of that nonce.
2. `oauth.revocation.contact` inserts a unique per-work/per-token attempt before
   contact, updates the actual attempt count and audit, and binds the actual
   canonical request commitment. Its stable UUID derives from the existing work
   UUID and token purpose, never a new grant ID or renewed lease. The request
   commitment covers exact URL, POST method, encoded-body hash and the hash of
   actual constructed headers. A current grant cannot replace a consumed slot.
3. Only after definite signed writer completion and exact journal/attempt
   readback does the retained private owner enter its single HTTPS call. Before
   claiming, it decrypts the original envelope under the unchanged ID/version/AAD, requires
   the plaintext and enrollment association hashes, and uses only pinned
   endpoint/client originals. It never calls the old live-enrollment owner or
   legacy multi-contact revocation helper.
4. `oauth.revocation.finish` binds the exact consumed attempt, retained owner
   nonce, and canonical transport original. The kernel derives the observation
   from that original; it does not accept `succeeded: true`. Exact raw response
   status, headers and body are retained, or a local `transport-unknown` record
   with all HTTP fields null. Audit and metadata updates are one controlled
   transition. No token, private request or raw response is returned publicly.

Google selects the actual refresh token when present, otherwise the access
token. X requires the exact ordered inventory of present access and refresh
tokens; each has its own definite precontact claim. Request construction keeps
the existing provider revocation recipe: token plus hint, Basic authorization
when configured, and client ID for non-Basic X. Token-endpoint
`client_secret_post` is not silently copied into Google's revocation body.
Unknown first contact stops the operation; it never authorizes another token
contact or a retry. An earlier definite rejection is retained separately.

HTTP response bodies are bounded to 64 KiB, raw canonical headers to 8 KiB and
128 pairs, and canonical transport originals to 128 KiB. Redirects and ambient
proxy use are disabled by the actual HTTP transport. Total authority arguments
are bounded to 384 KiB. Journal original rows are bounded to 1 MiB and attempt
rows to 256 KiB. Bound violations after entering transport are uncertainty, not
proof of noncontact or authorization to resend. This is local HTTPS evidence,
not a provider-signed revocation receipt.

## Interruptions, observations and remaining work

Any existing journal prevents a fresh claim, including expired, incomplete,
unknown and terminal rows. An uncertain controlled request is never retried by
the live owner. Losing that owner cannot reconstruct it from SQL: there is no
reattachment, lease renewal, inline legacy retry, deletion, history rewrite,
token regeneration or cleanup-success callback. Changing a grant or its expiry
does not clear the stable work or per-token identity.

Before an HTTP call is entered, the source can report local `notContacted`.
That observation does not settle a possibly uncertain metadata commit, undo a
claim or grant retry. After entering transport, timeout or exception is unknown,
even if a connection may not have been established. If original time expires
before finish commits, the attempt stays consumed and unresolved; the code does
not manufacture durable HTTP evidence or extend the cleanup window.

The work row preserves ciphertext and null `last_error`, with statuses
`revocation_reserved`, `revocation_observed_accepted`,
`revocation_observed_rejected`, or `revocation_unknown`. Journal statuses are
`claimed`, `observed-accepted`, `observed-rejected`, or `unknown`; per-token
attempts are `contact-claimed`, `accepted`, `rejected`, or `unknown`.
Accepted means only an observed 2xx HTTP reply; rejected means an observed
non-2xx reply. Neither proves final provider-side token state.

Reconciliation returns six non-authoritative counters: `claimed` counts works;
`accepted` and `rejected` count completed contact observations; `unknown`,
`notContacted`, and `blocked` describe local interrupted/refused work. These are
not a `revoked` count and are not grants for another effect. SQL projections may
show retained states without invoking expiry writers or discarding evidence.

Terminal originals remain retained and still occupy the existing sixty-four-row
work inventory, which also bounds these per-work journals and their two attempts.
An independently authorized retirement/capacity-reclamation contract
is not supplied here. The separate [refresh client](oauth-controlled-refresh-client.md)
retains issued/superseded work under distinct source purposes; those labels do
not grant admission to this exchange-only cleanup worker. Pending-cancellation,
superseded/disconnected credential cleanup, issuance-without-retained-token
reconciliation, refresh-specific cleanup and cached-send fencing, reconnect,
setup, larger inventories and cross-deployment coordination remain required
successor work, not a permanently reduced product scope. This slice does not
lift unrelated enrolled-path guards or claim O01/O02/production completion.

The paired [schema](../schemas/oauth-revocation-authority.v1.schema.json) describes
closed data fields only. Cryptographic, UTF-8 byte-count, cross-field, physical
descriptor, exact SQL-original and temporal checks remain runtime obligations.
