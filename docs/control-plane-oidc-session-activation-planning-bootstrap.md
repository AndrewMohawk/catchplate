# Public-only activation planner configuration

Explicit control-plane enrollment bootstrap v7 adds nullable
`oidcSessionActivationPlanning`. Earlier v2–v6 shapes stay strict; v6 activation
caller custody, its fixed FD205 reservation, and the v5 release lane are unchanged.
Planning requires the independently configured activation caller lane. It adds
no key, descriptor, TLS credential, SQL reader, environment override or path
provisioning. The entire root-signed parent still has its original 4 MiB bound;
embedding a planner original does not increase it.

The nested `serverware.controlPlaneOidcSessionActivationPlanning/v1` object has
exactly `schema`, `plannerBootstrap`, and `plannerEndpoint`. The bootstrap record
contains canonical `base64Url` and exact `byteCount`, bounded by the actual
planner's source cap. The endpoint has exactly `socketPath`,
`requestTimeoutSeconds`, `listenerUid`, and `listenerGid`: fixed
`/run/serverware/oidc-session-activation/planner.sock`, integer 1–30 seconds, and
the root-created listener peer 0:0. This peer is not an attestation of the later
accepting process.

The mapper owns the configuration graphs and holds actual original/key
references before native callbacks. It genuinely verifies the nested planner
root signature and launch interval, then joins its full configuration,
generation, runtime cohort, planner key and original state enrollment to the
actual parent and dedicated caller enrollment. The caller's three original
enrollments are reauthenticated; a fabricated material object cannot replace
them. An absent issuer policy does not supply a borrowed key or disable this
separate lane. Runtime cohort joins do not invent a measured control-plane role.

`_PlanningMaterial` retains only immutable `planner_bootstrap_bytes` and the
fixed `planner_endpoint` tuple. Cold admission is not a request-time freshness
result. The actual request caller must admit the same original again under its
existing permission work/window/deadline and use independent policy, target and
complete-vector pins. `_admit_on_work` accepts a paired original processing
window/deadline for this composition; it never opens a replacement request
allowance. The stdlib root entrypoint checks only the closed v7 data shape before
delivering existing purpose keys. Actual root/crypto admission remains in the
child startup, not in the selector.

## Tightening-only planner exchange

The original strict raw8 `SWOAPQ02`/`SWOAPR02` profile remains unchanged. The new
raw9 `SWOAPQ03`/`SWOAPR03` profile appends one canonical positive signed-int64
ASCII `deadlineEpochNs` to the same operation/assertion/pending-token/five-ID
inventory. It is a ceiling, never clock provenance or action authority. The
server retains its three genuine opening samples, policy limits and monotonic
bound, intersecting them with that ceiling before cold preparation.

`_socket_request_bounded(endpoint, *, originals, deadline_epoch_ns, deadline_ns,
work, current, maximum_response_bytes=None)` receives the original raw8 and
returns unverified raw7. The caller's actual current guard runs around each
native chunk and connection closure; all buffer work is charged before
allocation on the same work. The optional response cap can only tighten the
fixed 64 MiB exchange ceiling and is checked against the response header before
body allocation. Request and response headers are respectively 80 and 64 bytes;
the deadline frame is at most 19 bytes. No uncertain response, expired guard or
failed cleanup permits a retry or an authenticated success claim.

The result remains original request/scope/plan bytes, plan and journal locators,
and ciphertext—not permission or proof that the intended action committed.
The real caller still needs original signature/scope/target checks, the live
permission context, separate downstream full replay and durable dispatch/outcome
association. The existing session-binding ceremony is distinct from permission
MFA; its assertion must remain valid against the post-permission credential
counter. This is a partial step-22 source integration, not complete public
activation, execution, deployment or production acceptance.
