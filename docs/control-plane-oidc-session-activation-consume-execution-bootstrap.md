# Dedicated consume caller custody

Explicit control-plane enrollment bootstrap v8 adds nullable
`oidcSessionActivationConsumeExecution`. Its signed envelope and payload use
`serverware.signedControlPlaneEnrollmentBootstrap/v8` and
`serverware.controlPlaneEnrollmentBootstrap/v8`. Versions v2–v7 keep their
exact prior fields and behavior. The complete envelope remains bounded to
4 MiB; v8 reserves FD206 even when consume execution is null. An issuer or
bootstrap cannot occupy that slot, and a disabled lane rejects any inherited
or open-but-undeclared FD206. Existing purpose reservations remain unchanged.

The nested `serverware.controlPlaneOidcSessionActivationConsumeExecution/v1`
object has exactly `schema`, `callerPrivateKeyFd`, `grantEnrollment`,
`authorizationEnrollment`, and `authorizerEndpoint`. The only key slot is
206. Each enrollment wrapper contains original `base64Url` and `byteCount`,
with a 16 KiB original bound and canonical base64url encoding. The endpoint
contains exactly `socketPath`, `requestTimeoutSeconds`, `listenerUid`, and
`listenerGid`: fixed path
`/run/serverware/oidc-session-activation-delivery-execution/authorizer.sock`,
an integer timeout of 1–30 seconds, and root-created listener peer 0:0.
Configuration is not permission to contact that endpoint.

## Original admission and purpose separation

Enabling this lane requires actual activation execution v4 and enabled
activation planning. The parent admits those existing purposes first. The
new mapper takes the real v4 consume-planner public key and current-root
enrollment original, not an independently supplied replacement or a generic
planner key. Its operation public key is the actual admitted runtime root.
It owns the nested configuration and actual parent configuration, generation,
and runtime graphs before native callbacks, and retains the original key
references and current-root bytes before capture.

On the same supplied work, the actual consume-only caller contract verifies
the root-signed caller, consume grant and current-root enrollment originals.
It joins configuration, database, generation, enrollment identities, audience,
planner and operation keys. The mapper additionally joins the genuine parent
generation and runtime cohort and separates the new caller from configured
roles, evidence/transition/enrollment policies, issuer, registration,
finalization, activation caller/planner and consume-planner keys. Actual caller
admission also separates it from root, state, computation, completion and
consume-grant authorizer keys. A disabled issuer does not force a borrowed key
or disable this independent lane. No generic grant operation is added.

`_ConsumeExecutionMaterial` holds fixed `caller_private_key_fd`, the caller,
planner and operation public keys, the three immutable enrollment originals,
`authorization_enrollment_digest`, caller ID and measurement pin, enrolled
maximum age/skew, and fixed endpoint tuple. Parent material appends
`consume_execution=None` and `consume_slot_reserved=False`; genuine v8
admission sets the reservation true even when the nested purpose is null.
These are private cold configuration fields, not accepted proof of permission,
plan replay or execution. A root-pinned measurement label is a
trusted-host-local claim, not measured runtime or hardware assurance.

## Actual fixed descriptor delivery

The stdlib-only entrypoint recognizes the exact v8 data shape before optional
purpose-key delivery. It preserves the existing four-field purpose-slot API,
appending only private projection fields for consume target/reservation. It
imports no repository crypto and does not interpret a signature-shaped object
as authority; the actual child performs root and enrollment admission.

The real control-plane entrypoint calls
`_open_control_plane_oidc_session_activation_consume_key`. That fixed helper
reads only the already-provisioned root-owned mode0400
`/run/secrets/serverware-oidc-session-activation-consume-caller-key`, using the
existing bounded sealed-source, no-follow ancestor and non-overwriting
descriptor-reservation machinery. It supplies only FD206, never an environment
key or caller-selected path. An occupied slot is rejected, never overwritten.
The signed runtime inventory must independently authorize the descriptor.
No key, directory, listener or permission is provisioned.

Actual control-plane startup must pair FD206 with the genuinely enrolled
caller key and retain its descriptor, PID and runtime continuity, including
separation from the HTTP and other retained private purposes. The same active
permission context remains necessary for post-plan consume authorization.
Cold admission creates no request work/window, opens no socket and cannot
renew the original caller allowance. No AES or historical custody moves into
the public process. This source slice is not grant issuance, SQL, completion,
token delivery, a cookie update or a current-session claim; it remains unbuilt
and unexecuted.
