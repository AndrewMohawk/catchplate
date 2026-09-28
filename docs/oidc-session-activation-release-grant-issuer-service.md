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
only UID/GID 65532 is admitted. The allowed inventory is exactly the six
inherited descriptors plus that one owned connection while it exists.

The fixed raw8 request contains the issuer purpose followed by the existing
LIVE release raw7. Its exact raw7 suffix is passed directly to the real
producer with the independently held policy, proof bootstrap and root key.
The old token exists only in this ephemeral request path; the service performs
no token/request logging or durable retention.

Only the actual producer's raw2 `(client authorization, server bootstrap)` is
sent. There is no error/status frame or automatic retry. Exact EOF, per-frame
limits and the whole 64 MiB inventory are enforced. Peer/framing checks do not
replace original grant admission by the receiving caller.

## Original allowance and truthful cleanup

The original work ledger, limits, epoch/monotonic floors and root-delivery
guard continue through construction, wait, original admission, signing, send
and normal connection close. Signed timeout limits are anchored to the original
opening, never restarted on accept. Genuine state-enrollment age/skew limits
are retained before signing; the actual authenticated output's expiry further
narrows the same bound for send/close. The producer's restrictive continuity
hook exchanges only clock floors, not permission or successful result objects.

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
