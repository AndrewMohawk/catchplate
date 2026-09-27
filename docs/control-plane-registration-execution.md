# Control-plane registration execution-grant preparation

This source slice adds an opt-in, protected caller key and a private composition
that obtains and locally verifies a registration evidence execution grant.
It is unbuilt and unexecuted. No public route, operator/session gate or UI flow
is activated; the actual authenticated application must separately authorize
the present caller and the new execution-request purpose before invoking it.

## A new purpose, not an upgraded enrollment grant

The existing enrollment purpose, `authorize-webauthn-registration`, remains
evidence-signing-only. The distinct
[`authorize-registration-evidence-execution`](registration-execution-authorization.md)
purpose requires its own root-delegated caller enrollment and dedicated signing
key. Possessing original browser inputs, an old enrollment grant, signed
evidence or a plan is not present permission to request execution.

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
operator/OIDC/session or new-purpose authorization gate. The current public
`/prepare` path remains custody-only and does not invoke this continuation.

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

## Remaining integration and release boundaries

The dedicated [grant-authorizer service](registration-execution-authorizer.md)
and this caller path do not reserve a current root, create a durable grant
journal or protected execution packet, mark an attempt, execute SQL or finalize
a credential. Those remain separate
[successor execution](authority-successor-execution.md) requirements.

Actual public handler orchestration, present operator/session authorization for
the new purpose and its UI remain open. Independent key/account/FD/listener
provisioning, admitted immutable runtime/release closure, rollback and witness
requirements, and consolidated frozen-source verification also remain open.
Neither source presence nor a returned signed grant is production acceptance.
