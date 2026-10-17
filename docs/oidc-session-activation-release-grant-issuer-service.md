# One-shot private release grant issuer

`oidc_session_activation_release_grant_issuer_startup` connects the genuine
[original-only grant producer](oidc-session-activation-release-grant-production.md)
to one finite [grant exchange](oidc-session-activation-release-grant-transport.md).
It does not release a plaintext token, provision the release worker or establish
production acceptance.

## Actual cold owner

`initialize_from_environment(work=..., live_window=...,
transport_deadline_ns=..., delivery_current=...)` continues the real same-PID
[root delivery](oidc-session-activation-release-grant-issuer-delivery.md).
It accepts no material carrier or replacement allowance. The closed process
mode is `oidc-session-activation-release-grant-issuer`, UID/GID 65496 with no
supplementary groups. Six inherited descriptors have fixed purposes:

| FD | Original resource |
| --- | --- |
| 198 | Runtime root public key |
| 199 | Signed issuer launch bootstrap |
| 200 | Root-created `grants.sock` listener |
| 201 | Signed issuer policy |
| 202 | Exact policy-bound proof bootstrap |
| 203 | Independently provisioned root signing key |

The worker genuinely re-admits the signed launch, issuer policy and nested
proof originals before reading the private signing key. The key is paired to
the actual runtime root. Sealed original identities, listener socket/path
pins, process/environment, owner identity and exact FD inventory remain checked.
There is no AES, historical bundle key, completion signer, SQL/state writer or
journal descriptor in this inventory.

## One bounded exchange

`require_started().serve_once()` spends its one-use latch before readiness or
accept. `select` adds no selector FD. Startup owns at most one actual accepted
nonblocking/CLOEXEC socket and pins its peer before reading any body bytes;
only UID/GID 65532 is admitted. Launch-v1 permits exactly the six inherited
descriptors plus that one owned connection while it exists. Explicit launch-v2
also permits the single actual issuer-owned staging socket described below,
never an arbitrary extra descriptor list.

The fixed raw8 request contains the issuer purpose followed by the existing
LIVE release raw7. Its exact raw7 suffix is passed directly to the real
producer with the independently held policy, proof bootstrap and root key.
The old token exists only in this ephemeral request path; the service performs
no token/request logging or durable retention.

Only the actual producer's raw2 `(client authorization, server bootstrap)` is
sent. There is no error/status frame or automatic retry. Exact EOF, per-frame
limits and the whole 64 MiB inventory are enforced. Peer/framing checks do not
replace original grant admission by the receiving caller.

## Explicit launch-v2 staging

The unchanged signed bootstrap envelope can select the closed nested
`catchplate.oidcSessionActivationReleaseGrantIssuerLaunch/v2` launch. It adds
only `deliveryEndpoint`: fixed `bootstrap.sock` under the existing release
socket directory, integer timeout 1–30 seconds no greater than the original
issuer request timeout, and root peer UID/GID 0. The immutable admitted
material carries this endpoint. Launch-v1 retains its exact previous fields
and behavior; it neither accepts the new field nor stages a bootstrap.

After genuine production, v2 sends the exact server-bootstrap original over
the [fixed staging transport](oidc-session-activation-release-grant-delivery-transport.md)
before returning either grant to the public caller. Its private
`_DeliveryChannel` is created only by the actual issuer owner. It creates and
registers its own nonblocking/CLOEXEC socket, binds it to the original endpoint,
work and owner guard, pins the root peer before body I/O, and owns its guarded
close/unregister. The transport cannot supply a socket/FD exemption, close or
detach the channel's socket. The staging latch is one-use; failures are terminal.

The issuer requires exact `(b'staged', framedBootstrapDigestASCII71)` and joins
the identity to its actual outgoing server-bootstrap bytes after normal
staging close. Only then can the unchanged public raw2 response be sent.
The ACK means that the root receiver admitted and sealed those exact bytes
and held the corresponding signed resources before its permanent release-UID
drop. It is not worker readiness, successful token delivery or a reason to retry.
The final caller must still genuinely verify the token response.

## Original allowance and truthful cleanup

The original work ledger, limits, epoch/monotonic floors and root-delivery
guard continue through construction, wait, original admission, signing, send
and normal connection close. Signed timeout limits are anchored to the original
opening, never restarted on accept. Genuine state-enrollment age/skew limits
are retained before signing; the actual authenticated output's expiry further
narrows the same bound for send/close. The producer's restrictive continuity
hook exchanges only clock floors, not permission or successful result objects.
The v2 staging endpoint timeout also tightens that original opening; staging
does not start a new processing window or permit another public request.

`serve_once()` returns exact `True` only after the guarded response path and
successful normal connection close. Any uncertainty is terminal. Module
`close()` (also available on the actual owner) attempts each still-owned exact
resource once; changed/indeterminate identities are never closed as replacements.
Cleanup failure remains sticky across repeated close. An uncertain socket
object remains referenced rather than being allowed to close another FD via
its destructor. No secure-memory-erasure guarantee is claimed.

The signed launch/policy resource pins authorize exact resources; they do not
prove those resources were provisioned or the release storage slot is empty.
Independent root issuance, key/resource provisioning, finite worker operation
and public-flow integration must still be established. This is source-only,
unbuilt, unexecuted and unprovisioned; no token delivery or current-session
claim follows from a successful local grant send.
