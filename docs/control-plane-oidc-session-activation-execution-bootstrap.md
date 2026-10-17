# Dedicated activation caller custody

Explicit control-plane enrollment bootstrap v6 adds nullable
`oidcSessionActivationExecution`. It retains v5's exact public-only release
configuration, all earlier closed schemas, the 4 MiB complete-envelope bound,
and the existing finalization FD204 reservation. It additionally reserves FD205
for the activation caller even when that lane is null; a disabled v6 lane
rejects an occupied or inherited FD205. No earlier version implicitly enables
this purpose or receives a new key.

The nested `catchplate.controlPlaneOidcSessionActivationExecution/v1` object
has exactly `schema`, `activationCallerPrivateKeyFd`, `plannerKey`,
`currentRootEnrollment`, `grantEnrollment`, `authorizationEnrollment`, and
`authorizerEndpoint`. The planner record contains canonical raw32
`publicKeyBase64Url` and `spkiDigest`; each enrollment carries original
`base64Url` and `byteCount`. The endpoint is fixed to
`/run/catchplate/oidc-session-activation-execution/authorizer.sock`, root-created
listener peer 0:0, and an integer timeout of 1–30 seconds. It is not permission
to dispatch an action or change that endpoint from a request.

The new mapper owns every mutable graph and holds key references before
callbacks. It joins the real parent configuration, generation, and runtime
cohort, then genuinely admits all three original enrollments through the
existing activation caller contract. The operation key is the actual runtime
root; the dedicated activation planner key is independently root-pinned, not
borrowed from the generic planner role. Caller and planner keys are separated
from configured role, evidence, transition, enrollment and existing caller
purposes. Actual caller admission additionally separates its key from root,
planner, operation, state, computation, completion and grant-authorizer keys.
An absent enrollment-issuer policy does not disable this independent lane or
cause a fallback to another key.

`_ActivationExecutionMaterial` retains the actual public keys and three
immutable enrollment originals, caller enrollment identity, caller ID and
measurement pin, enrolled maximum age/skew, fixed FD, and endpoint. It is
ordinary private cold data, not an accepted permission or execution result.
Pinned caller measurement text is an explicit trusted-host-local root claim;
it does not create a measured control-plane role or hardware assurance.

## Explicit downstream profile

Source `.183` adds nested `catchplate.controlPlaneOidcSessionActivationExecution/v2`
under the existing parent v6/v7 envelopes. The original nested v1 remains strict.
V2 adds exactly `reserverEndpoint`, `sqlEndpoint`, and `statePredecessor`; it
adds no key, descriptor or top-level bootstrap version. The endpoints retain
the same closed timeout/peer fields and fixed directory, ending respectively
in `reserver.sock` and `sql.sock`. The existing execution socket-directory
overlay covers these independently provisioned listeners.

The predecessor contains `sequence`, `headDigest`, and `nextFence`. Actual
root-enrollment admission joins database/generation and the caller's enrollment
digest, reserves capacity for both reservation and completion, and requires
the enrolled genesis head/fence when sequence is zero. The material appends
`reservation_endpoint`, `reservation_predecessor`, and `sql_endpoint`; all
remain null under v1. The stdlib selector checks the exact public data shape;
only child admission verifies signatures and those independent pins.

No future pending head is guessed or copied into this configuration. A caller
can derive an exact successor observation from the original enrolled reserve
request and signed acknowledgment, after checking the independent predecessor.
That observation is not independently current state. The actual SQL service
still enforces its separately root-admitted pending scope and full private
replay. No history/replay key moves into the public control-plane process.

Configuration is not permission to dispatch, proof of a SQL commit, token
delivery or a completed public session. Source remains unbuilt and unexecuted.

## Explicit completion endpoint profile

Source `.184` adds nested
`catchplate.controlPlaneOidcSessionActivationExecution/v3`: exactly the v2
fields plus `completionEndpoint`. V1 and v2 stay closed and cannot carry this
field. V3 retains the genuine v2 original-enrollment and independent predecessor
admission, including database/generation, genesis and reserve/completion
capacity joins. It adds no key, FD, top-level version or new processing window.

The endpoint has the same exact `socketPath`, `requestTimeoutSeconds`,
`listenerUid` and `listenerGid` fields. Its only path is
`/run/catchplate/oidc-session-activation/completion.sock`; timeout is an exact
integer from 1 through 30 and the independently expected listener peer is 0:0.
`_ActivationExecutionMaterial` appends `completion_endpoint=None`; v3 and v4
populates it. The stdlib-only FD205 selector recognizes the identical v3 shape
before reading any key, while actual child admission still authenticates all
root/enrollment originals. The descriptor inventory is unchanged.

This endpoint opts into the separate original-bound completion dispatch
transport, not the old packet-selector recovery request. The caller sends its
exact signed authorization original. An independently configured completion
service must opt into that profile, compare the bytes to its genuinely
root-held authorization original, and select its own independently root-pinned
packet. This caller configuration carries no guessed future packet identity or
authorization-digest pin. It neither imports the service's historical keys nor
replaces its original packet/commit admission. Endpoint configuration alone
does not prove completion, release a token, update a cookie or admit recovery.

## Explicit consume-planner endpoint profile

Source `.185` adds nested
`catchplate.controlPlaneOidcSessionActivationExecution/v4`: exactly the v3
fields plus `consumePlannerEndpoint` and `consumePlannerKey`. Earlier versions
stay closed. The endpoint uses the same timeout/peer fields, root listener 0:0,
and the fixed `/run/catchplate/oidc-session-activation/delivery-planner.sock`.
The public key object has exactly `publicKeyBase64Url`, `spkiDigest`, and
`measurementDigest`. Admission separates its key from the actual runtime root,
activation planner/caller, state/computation/completion, and other configured
purposes. The stdlib selector recognizes the same shape. No private key, FD,
top-level bootstrap version, or processing allowance is added.

Cold configuration pins only stable endpoint/key/measurement identity. The
consume request, signed activation reservation and post-activation root vector
do not exist before activation, so they must not be guessed or embedded in this
pre-activation envelope. Independently issued root-signed consume-planner and
history originals are admitted afterward, inside the still-active original
permission context. The actual root verifier checks their signatures and
lifetimes; the caller joins the real parent configuration, runtime cohort,
planner key, measurement and state enrollment before the exact target joins.
Derived bootstrap material is ordinary same-call data, not admission authority.

The [private continuation](control-plane-oidc-session-activation-consume-planning.md)
can prepare and export encrypted execution originals, not consume or release a
token. Independent per-request root issuance and the matching UID/GID 65501
planner service remain unprovisioned prerequisites. The existing read-only
planning socket-directory mount covers the endpoint but does not create it.

The stdlib-only cold selector explicitly recognizes v6 without importing
repository crypto. Its actual entrypoint calls the fixed activation-key
delivery helper, which reads only the already-provisioned root-owned mode0400
`/run/secrets/catchplate-oidc-session-activation-execution-caller-key`, subject
to the existing no-follow ancestry, bounded sealed read and non-overwriting
FD reservation checks. It supplies only FD205, adds no environment key or
arbitrary path, and preserves the old four-field slot projection API.
The inherited runtime inventory must independently authorize that descriptor.
No key is created and no path or permission is provisioned.

Actual child [startup](control-plane-enrollment-startup.md#dedicated-activation-caller-extension)
root-admits the original v6 envelope, pairs the delivered Ed25519 private key
with the genuinely enrolled caller public key, separates it from the actual
HTTP response and other retained keys, and retains PID, namespace, runtime
receipt and descriptor continuity. Its `activation_execution_enabled` property
reports cold configuration only. The private `_oidc_session_activation_permission`
wrapper passes the original request, permission bytes, work/window/deadline to
the actual lock-owned permission context. Permission precedes planning because
its assertion advances the credential counter; the context's post-plan signer
expires on exit. Neither a property value nor a past successful context is
permission. This configuration opens no clock allowance and cannot renew old
plan or caller authority.

This source slice is key/config custody, not full step-21 permission, public
activation dispatch, deployment, execution or a current-session claim.
