# Public-key-only release client authorization

This source-only root purpose authorizes one independently pinned private release
exchange. It is unbuilt, unexecuted and unprovisioned. It delivers no AES/history
key, accepts no successful material as an authority input, and opens no token or
socket. A root-selected outcome identity is not proof of durable retention,
latest-state currentness or successful token delivery.

The purpose is `receive-oidc-session-activation-token-release`. Signed/payload
schemas are `serverware.signedOidcSessionActivationReleaseClientAuthorization/v1`
and `serverware.oidcSessionActivationReleaseClientAuthorization/v1`, with distinct
`ReleaseClientAuthorizationIdentity/v1` and `ReleaseClientServerBootstrapIdentity/v1`
domains under `serverware.oidcSessionActivation`. No generic purpose is widened.

The closed independent scope has seventeen fields:

- `serverBootstrapDigest`, `profile`, `requestIdentity`;
- `configurationDigest`, `databaseId`, `generationDigest`, `runtimeClosureDigest`;
- `clientId`, `clientIdentity`, `callerId`, `receiverIdentity`;
- `producerId`, `producerIdentity`, `stateReceiptDigest`;
- `expectedRelease`, `expectedOutcomeDigest`, `endpoint`.

The three identities retain the existing exact three-digest grammar.
`expectedRelease` is the existing six-field target, including original delivery
scope and five committed-consumption bindings. `requestIdentity` pins the exact
profile-specific raw request; the response composition must derive and join it
from originals. The outcome digest is separately selected by root, never learned
from a response or a directory. Recovery additionally joins the server's genuinely
authenticated checkpoint-one and recovery outcome. Live admission does not claim
that its expected outcome already exists.

The endpoint is exactly `{path, timeoutSeconds, peerUid, peerGid}`. Its path is
`/run/serverware/oidc-session-activation-token-release/release.sock`; timeout is an
integer from 1 through 30 seconds, no greater than the actual signed server launch
timeout. Connect-side peer pins remain 0:0 for the existing root-created listener,
distinct from the fixed client UID/GID 65532 named by this root authorization.
Identity fields are root-selected metadata, not measured-process or hardware
attestation. No new client process mode, descriptor profile or deployment claim
is introduced.

## Original-only APIs

`_verify_on_work` requires `authorization_bytes`, `server_bootstrap_bytes`,
`root_public_key`, independently held `expected_scope`, and mandatory original
`live_window`, `transport_deadline_ns`, `work`. It owns bounded originals/scope
before native callbacks, verifies the root signature and exact independent scope,
and genuinely calls the existing server-bootstrap verifier on the detached
original. The actual configuration, target, caller, producer, receipt, receiver
and endpoint are joined; no parsed bootstrap or incoming successful result can
replace that admission.

The private `_ClientAuthorization` result contains only `payload`,
`authorization_digest`, actual same-call `server_material`, `live_window`,
`deadline_ns` and `live`. These are ordinary outputs, not transferable evidence
accepted by this API. `_scope`, `_read`, `_digest_on_work` and
`_server_bootstrap_digest_on_work` expose bounded shape/exact-original identities;
none authenticates authority by itself.

`_produce_on_work` additionally requires the actual root private/public pair,
payload and independent expected scope. Genuine server-original admission occurs
before signing; canonical output is read back, its real signature checked, and
the exact payload joined under the retained current guards. This is an offline
root producer primitive, not a public payload-signing endpoint or a key delivered
to the private client.

## Bounds and remaining boundary

The client original is capped at 16 KiB, 512 nodes and depth 6; the detached
server original retains its actual 16 MiB cap. Initial original inventory and
the server's nested original admission remain bounded by 64 MiB with cumulative
work. The fresh client interval is contained in the genuine fresh server interval
and cannot extend the original delivery expiry. Actual client/server guards are
retained with cross-guard epoch checks and the same initial clock bracket; the
signed endpoint timeout only narrows the existing lifetime/deadline. Historical
recovery evidence is never renewed into live intent, proof or execution authority.

Independent response authentication must still admit original intent/proof and
enrollments, reconstruct the exact outcome, compare the request echo and validate
the token's public commitment under this current authority. Authorized private
application handoff remains separate from this root contract. No public/browser
release, provisioning, durability observation or current session is claimed here.
