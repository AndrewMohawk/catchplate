# Control-plane registration execution-grant preparation and retention

This source slice adds an opt-in, protected caller key and a private composition
that obtains, locally verifies and optionally retains a registration evidence
execution grant. It is unbuilt and unexecuted. Two explicit public preparation
handlers now admit the present caller and this new purpose before calling the
private composition. They do not execute the grant, finish registration or
activate a session; no dedicated portal preparation workflow is added.

## A new purpose, not an upgraded enrollment grant

The existing enrollment purpose, `authorize-webauthn-registration`, remains
evidence-signing-only. The distinct
[`authorize-registration-evidence-execution`](registration-execution-authorization.md)
purpose requires its own root-delegated caller enrollment and dedicated signing
key. Possessing original browser inputs, an old enrollment grant, signed
evidence or a plan is not present permission to request execution.

## Public preparation endpoints

The two new POST routes are distinct from the unchanged registration `/prepare`
and `/verify` routes:

| Route | Present-caller admission |
| --- | --- |
| `/api/webauthn/register/prepare-execution` | Current `admin` or `approver` operator identity and normal CSRF checks, plus the purpose-specific branch below. |
| `/api/auth/session/webauthn/register/prepare-execution` | Actual pending OIDC browser session, refreshed authoritative RBAC and normal cookie CSRF checks; first-credential branch only. |

The pending-cookie route requires exactly one nonempty CSRF header matching
its CSRF cookie, regardless of any other authorization headers. Both its
pending-session refreshes and active-cookie operator refreshes use uncached
database session lookup before preparation. Ordinary older helpers retain their
default cache behavior; a request-cached identity alone is not this recheck.

The body is a closed JSON object with required `purpose`, `label` and `response`.
`purpose` must be exactly `authorize-registration-evidence-execution`; `label`
is a string of at most 4096 characters and `response` is the registration
response object. Optional `bootstrapToken` is at most 1024
characters. Optional `mfa` is a closed object containing only optional
`assertion` (an object) and `approvalId` (1–4096 characters); the generic
authority evidence fields `authorityChallengeId` and `credentialRecordId` are
not accepted. Framing requires `application/json`, exact `Content-Length`, no
query, transfer encoding or content encoding, and at most 512 KiB. Strict
duplicate/depth checks apply before model admission.

First-credential preparation requires **no credential history**, including
revoked credentials, and a fresh configured bootstrap token of at least 32
characters for this explicit purpose. That requirement also applies in
development; a nonnull `mfa` is rejected in this branch. Neither an older
enrollment grant nor development bootstrap behavior substitutes for present
permission.
The pending-OIDC route also requires the actual session still to be pending;
posting a session or actor dictionary supplies no authority. Preparation leaves
the registration challenge unused and does not activate or finalize a session.

An operator with any credential history instead uses the new mutation action
`webauthn.registration.execution.prepare`, with `resourceId` equal to the actual
registration `challengeId` and a payload digest from `request_binding(originals)`.
A nonnull `bootstrapToken` is rejected in this branch, including when the
history contains only revoked credentials. The handler performs the standard
mutation-assertion verification even when the development MFA toggle is off,
and enforces configured two-person approval. The production required-action set
includes this action only when the actual opt-in v3 execution owner is enabled.
Requesters are `admin` or `approver`; an approver must satisfy the existing
`admin` rule and cannot self-approve. Evidence carried in an authority MFA
wrapper cannot replace this assertion. Current operator/session authorization
and credential-history presence/absence are rechecked before requesting the
grant. This branch check is not an atomic reservation or a guarantee that the
complete credential history stayed unchanged.

[`request_binding(originals)`](../serverware/control_plane_registration_execution_intent.py)
binds the fixed purpose/action, actual user and challenge, label, RP/origin,
credential ID and transports, plus domain-separated byte digests and lengths
of the original client data, attestation object and enrollment-authorization
recipe. The application's canonical payload digest binds that request for MFA
and approval. It exposes neither the original recipe nor a bootstrap token;
the binding itself does not authenticate an actor or grant permission.

After genuine preparation and durable local retention, success is **202** with
no-store headers and this fixed response shape:

| Field | Value |
| --- | --- |
| `schema` | `serverware.webAuthnRegistrationExecutionPreparation/v1` |
| `status` | `retained-execution-grant` |
| `purpose` | `authorize-registration-evidence-execution` |
| `localDigest` | Canonical local `sha256:` content identity |
| `registrationCompleted` | `false` |
| `executionStarted` | `false` |

This is a retained-original locator, not a registration result or live execution
permission. A 412/428 negotiation may create or consume separate MFA/approval
state. In the existing-credential branch, direct assertion verification consumes
MFA before the two-person check; continuing after a 428 requires a fresh
assertion, not reuse of the one already consumed. Do not automatically repeat
a successful call or retry an uncertain
midflight failure: a token, assertion, approval or durable append may already
have been consumed or completed. A 503 does not establish absence or safe retry.

## Cold caller configuration

The [cold enrollment bootstrap](control-plane-enrollment-startup.md) keeps its
closed v2 contract and producer unchanged. Explicit v3 uses envelope
`serverware.signedControlPlaneEnrollmentBootstrap/v3` and payload
`serverware.controlPlaneEnrollmentBootstrap/v3`. It adds exactly one required
field, `registrationExecution`, to the existing eight payload fields. Null
disables execution without new key or endpoint access; a nonnull value is the
following closed object:

| Field | Contract |
| --- | --- |
| `schema` | `serverware.controlPlaneRegistrationExecution/v1` |
| `executionCallerPrivateKeyFd` | Exactly `203`, distinct from the existing enrollment-key/bootstrap slots |
| `currentRootEnrollment` | Exact original `{base64Url, byteCount}`, at most 128 KiB |
| `grantEnrollment` | Exact original `{base64Url, byteCount}`, at most 16 KiB |
| `authorizationEnrollment` | Exact original `{base64Url, byteCount}`, at most 16 KiB |
| `authorizerEndpoint` | Fixed endpoint described below |

The endpoint has exactly `socketPath`, `requestTimeoutSeconds`, `listenerUid`
and `listenerGid`. The path is
`/run/serverware/registration-execution/authorizer.sock`; timeout is an integer
1–30 seconds; listener UID/GID are `0:0`. These are the activated listener's
system-manager peer credentials, not the accepting authorizer child's
`65513:65513` identity. Neither is a substitute for authenticating the grant.
No browser input or environment override selects the destination.

The complete bootstrap remains bounded to 4 MiB. The separate
[`_produce_v3_on_work`](../serverware/control_plane_enrollment_bootstrap.py)
producer signs this explicit version; v2 is not silently promoted. Actual
[execution bootstrap admission](../serverware/control_plane_registration_execution_bootstrap.py)
verifies all three original enrollments and joins configuration, generation,
audience and the actual configured planner/evidence keys.

Existing custody startup must first admit the runtime root and inherited FD
inventory. Enrollment startup then loads the separately provisioned unencrypted
Ed25519 PKCS8 caller key, delivered from the fixed source
`/run/secrets/serverware-registration-execution-caller-key` into FD `203`.
Collisions fail rather than overwrite an existing descriptor. Startup pairs it to the enrolled public
key and rejects reuse of the enrollment or actual HTTP-response signing key.
The owner retains the original descriptor identity and checks its live custody.
The signing key is not sent to the grant-authorizer service. Root-signed scope
and protected host delivery are not hardware custody or release admission.

## Private original-preserving composition

[`prepare_registration_execution_grant(originals)`](../serverware/control_plane_registration_preparation.py)
is an internal authenticated-application continuation, not an HTTP handler.
An original-input container is not evidence that the caller passed the required
operator/OIDC/session or new-purpose authorization gate. The new explicit
preparation handlers supply those gates; the older `/prepare` path remains
custody-only and does not invoke this continuation.

The source flow is:

```text
actual registration source/evidence exchange originals (raw8 + raw2)
    -> dedicated caller authorization, derived by genuine original replay
    -> verifier preparation: signed planning request3 + response4 + before-vector
    -> fixed authorizer exchange: original authorization + planning7 + before-vector
    -> local original grant/authorization/planning/vector verification
    -> original in-memory grant bundle (raw10), no execution
```

The caller-key steps are exposed only through the retained enrollment owner's
private `_authorize_registration_execution(...)` and
`_request_registration_execution_grant(...)` methods. Their
[composition](../serverware/control_plane_registration_execution.py) uses the
same cold v3 scope, actual key and independently admitted endpoint. A socket
return is unverified until the genuine
[receiving verifier](../serverware/authority_registration_execution_response.py)
authenticates it against the exact caller authorization, full signed planning
exchange, root-enrolled keys and complete before-vector. It needs no private
key and returns only the unchanged grant original.

`ControlPlaneCustodyClient.prepare_registration_execution_plan(...)` obtains
the preparation originals through the
[private control-plane → runtime → verifier transport](../serverware/authority_webauthn_registration_execution_caller.py).
It carries original raw10 evidence-exchange input and returns raw8 planning/
vector output, with fixed framing, exact EOF and no retry; framing itself
authenticates none of those originals. The
[verifier-side preparation](../serverware/authority_webauthn_registration_execution_preparation.py)
uses genuine raw8/raw2 replay and an actual `CurrentRootReader` under the same
configured verifier privileges. A posted expectation graph or claimed root
vector cannot replace that acquisition. The observed vector is not itself a
durable pending decision, independently current checkpoint or rollback witness.

The returned tuple preserves exact byte originals in this order:

| Position | Original |
| --- | --- |
| 0 | New-purpose caller authorization |
| 1–3 | Planning request control, context and inputs |
| 4–7 | Planning response control, plan envelope, inputs and evaluation context |
| 8 | Complete before-vector |
| 9 | Locally verified original successor execution grant |

One request work allowance and original live window cover the private
orchestration; nested verification and transport bounds can only shorten them.
Individual frame caps and the existing 64 MiB aggregate still apply, including
repeated original occurrences. There is no automatic retry, refreshed deadline
or transferable successful-verification token. This tuple is not persisted by
the helper and cannot be assumed live after its return; later consumers must
retain and genuinely admit the original bytes under their own required gates.

## Explicit local retention

The separate private
[`prepare_and_retain_registration_execution_grant(originals)`](../serverware/control_plane_registration_preparation.py)
performs the same genuine preparation, then appends its exact raw10 bundle
through the actual cold custody client. It returns only the local content ID
after durable publication, not a grant-verification receipt or execution result.
The existing in-memory preparation API is unchanged. Real present-caller and
new-purpose admission must precede either composition. The new public
preparation handlers call this retaining composition only after those checks.

`ControlPlaneCustodyClient.append_registration_execution_grant(originals)`
uses the [journal's separate retention-only format](control-plane-custody-journal.md#registration-execution-grant-retention).
Its `SWCPG001` frame and
`serverware.controlPlaneRegistrationExecutionGrantRecord/v1` digest domain
keep this raw10 inventory distinct from the five existing evidence/transition
profiles. The lower-level append only stores opaque bytes; it does not perform
the genuine authorization and grant replay done by the preparation composition.

`load_registration_execution_grant(localdigest)` returns the existing opaque
`PreparedRecord`: original bytes, their original `source_revision`, local
digest, fixed `registration-execution` family and
`webauthn.registration.evidence.admit` selector. Preserving that provenance
does not claim current-source compatibility or current authority. Future use
must genuinely replay the originals against independently admitted keys,
configuration and current state, respecting their original issue/expiry bounds.
Neither loading nor appending opens a new authorization window. Publication
may complete after the verified grant expires; it then retains history, not
live permission.

The existing admin [recovery workspace](control-plane-custody-recovery.md)
can inspect local metadata for these records, labeled retention-only. It does
not expose originals or enable reconciliation, forwarding, reservation or
execution. Journal fsync and recovery guarantees depend on the provisioned
filesystem and do not establish off-host custody or resistance to rollback.

## Remaining integration and release boundaries

The dedicated [grant-authorizer service](registration-execution-authorizer.md)
and this caller path do not reserve a current root, create a protected execution
packet, mark an attempt, execute SQL or finalize a credential. The local
retention journal is not a one-use execution ledger. Those remain separate
[successor execution](authority-successor-execution.md) requirements.

A separate [reservation producer and durable delivery owner](registration-execution-reservation.md)
now provide the source path from authenticated grant originals to an original
state acknowledgment. They are not wired into these preparation handlers and
do not supply the missing cold coordinator or SQL/finalization authority.

The new endpoints provide API-only grant preparation, not the later public
execution action or a complete operator UI workflow. Reservation/current-root
admission, protected execution and finalization orchestration remain open.
Independent key/account/FD/listener
provisioning, admitted immutable runtime/release closure, rollback and witness
requirements, and consolidated frozen-source verification also remain open.
Neither source presence nor a returned signed grant is production acceptance.
