# Dedicated activation caller custody

Explicit control-plane enrollment bootstrap v6 adds nullable
`oidcSessionActivationExecution`. It retains v5's exact public-only release
configuration, all earlier closed schemas, the 4 MiB complete-envelope bound,
and the existing finalization FD204 reservation. It additionally reserves FD205
for the activation caller even when that lane is null; a disabled v6 lane
rejects an occupied or inherited FD205. No earlier version implicitly enables
this purpose or receives a new key.

The nested `serverware.controlPlaneOidcSessionActivationExecution/v1` object
has exactly `schema`, `activationCallerPrivateKeyFd`, `plannerKey`,
`currentRootEnrollment`, `grantEnrollment`, `authorizationEnrollment`, and
`authorizerEndpoint`. The planner record contains canonical raw32
`publicKeyBase64Url` and `spkiDigest`; each enrollment carries original
`base64Url` and `byteCount`. The endpoint is fixed to
`/run/serverware/oidc-session-activation-execution/authorizer.sock`, root-created
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

The stdlib-only cold selector explicitly recognizes v6 without importing
repository crypto. Its actual entrypoint calls the fixed activation-key
delivery helper, which reads only the already-provisioned root-owned mode0400
`/run/secrets/serverware-oidc-session-activation-execution-caller-key`, subject
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
