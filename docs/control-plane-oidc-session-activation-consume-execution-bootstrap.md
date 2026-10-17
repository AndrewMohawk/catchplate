# Dedicated consume caller custody

Explicit control-plane enrollment bootstrap v8 adds nullable
`oidcSessionActivationConsumeExecution`. Its signed envelope and payload use
`catchplate.signedControlPlaneEnrollmentBootstrap/v8` and
`catchplate.controlPlaneEnrollmentBootstrap/v8`. Versions v2–v7 keep their
exact prior fields and behavior. The complete envelope remains bounded to
4 MiB; v8 reserves FD206 even when consume execution is null. An issuer or
bootstrap cannot occupy that slot, and a disabled lane rejects any inherited
or open-but-undeclared FD206. Existing purpose reservations remain unchanged.

The nested `catchplate.controlPlaneOidcSessionActivationConsumeExecution/v1`
object has exactly `schema`, `callerPrivateKeyFd`, `grantEnrollment`,
`authorizationEnrollment`, and `authorizerEndpoint`. The only key slot is
206. Each enrollment wrapper contains original `base64Url` and `byteCount`,
with a 16 KiB original bound and canonical base64url encoding. The endpoint
contains exactly `socketPath`, `requestTimeoutSeconds`, `listenerUid`, and
`listenerGid`: fixed path
`/run/catchplate/oidc-session-activation-delivery-execution/authorizer.sock`,
an integer timeout of 1–30 seconds, and root-created listener peer 0:0.
Configuration is not permission to contact that endpoint.

## Explicit downstream profile

Source `.187` adds the distinct nested
`catchplate.controlPlaneOidcSessionActivationConsumeExecution/v2` under the
same parent v8. It contains exactly the v1 fields plus `reservationEndpoint`,
`reservationPredecessor`, and `sqlEndpoint`. Nested v1 remains closed and
authorization-only. No parent version, key, descriptor or processing allowance
is added.

The two new endpoints use the same closed timeout/peer grammar. Their only
paths are `/run/catchplate/oidc-session-activation-delivery-execution/reserver.sock`
and `/run/catchplate/oidc-session-activation-delivery-execution/sql.sock`,
respectively, with integer timeouts of 1–30 seconds and root listener peers
0:0. The existing read-only socket-directory overlay already covers all three
fixed paths. It creates no listener and does not choose or authorize a profile.

`reservationPredecessor` contains exactly `sequence`, `headDigest`, and
`nextFence`. The actual consume reservation `_predecessor_scope` checks a
sequence from zero through `MAX_RECORDS - 2` (1022), a canonical SHA256 head,
and a positive signed-i64 fence. The mapper additionally authenticates the
original current-root enrollment, joins its identity/database/generation,
requires room for both reservation and completion under its enrolled record
limit, and joins a zero-sequence predecessor to the enrollment genesis head
and fence one. The stdlib delivery selector recognizes the same closed scalar
shape but supplies no cryptographic admission.

`_ConsumeExecutionMaterial` appends `reservation_endpoint`,
`reservation_predecessor`, and `sql_endpoint`, all defaulting to `None` under
v1. Endpoints are `(path, timeout, 0, 0)`; the predecessor is
`(sequence, headDigest, nextFence)`. These are independent root-signed caller
pins, never synthesized from a returned acknowledgment. They do not establish
current pending state or replace the reserve/SQL services' separately admitted
original scope, actual private replay and durable state transition. Future
returned originals still require genuine admission under the caller's same
live permission and original work/window/deadline. No recovery retry, AES
custody, token release or current-session claim follows from configuration.

## Explicit completion dispatch profile

Source `.188` adds nested
`catchplate.controlPlaneOidcSessionActivationConsumeExecution/v3`: exactly the
v2 fields plus `completionEndpoint`. Parent v8, FD206 and all enrollment/key
purposes remain unchanged. Nested v1 and v2 stay closed; their material has
`completion_endpoint=None` and cannot select this continuation.

The new endpoint is only
`/run/catchplate/oidc-session-activation-delivery-execution/completion.sock`,
with integer timeout 1–30 seconds and root-created listener peer 0:0. Material
appends `completion_endpoint` as the same exact `(path, timeout, 0, 0)` tuple.
The stdlib selector recognizes this closed data shape without crypto imports
or extra descriptor delivery. The existing read-only socket-directory mount
already covers the path and creates nothing.

This is the explicit signed-authorization dispatch profile, not the older
private packet-selector request. The [completion service](oidc-session-activation-delivery-completion-service.md)
must independently admit launch v2 and actual peer 65532, compare the original
consume authorization bytes with its own root-held original, and use only its
own root-pinned packet, pending state, checkpoint and replay expectations.
No future packet identifier, completion enrollment or extra private key is
added to the caller configuration; a returned SQL locator or ACK cannot supply
those server pins. Actual caller continuation still needs the retained
same-context originals, live permission and original work/window/deadline.
The public process receives no AES/history custody, and raw completion output
is not a packet-currentness, token-release or current-session proof.

Explicit nested `/v4` keeps exactly the `/v3` field set and selects the separate
completion release-hint profile through immutable material `release_hints=True`.
Versions v1–v3 retain `False`; no wire boolean or request chooses the profile.
Hints remain unsigned candidate digests, never commit or release authority.
The later private proof must independently reconstruct their real originals.
The [dedicated intent-key lane](control-plane-oidc-session-activation-release-intent-bootstrap.md)
requires this explicit version but adds no consume key or consume descriptor.

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
`/run/secrets/catchplate-oidc-session-activation-consume-caller-key`, using the
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
the public process. This cold configuration alone is not grant issuance, SQL,
completion, token delivery, a cookie update or a current-session claim; it
remains unbuilt and unexecuted.
