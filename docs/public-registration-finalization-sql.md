# Public retained finalization execution

Source-only implementation; unbuilt and unexecuted. This action is separate
from evidence execution, finalization preparation and reservation. A successful
response reports an **unsigned normal-commit observation**, not independently
authenticated completion, currentness, completed registration or an activated
OIDC session. Production acceptance remains **0/6 verified**.

## Fixed request contract

[Two POST handlers](../serverware/control_plane_registration_finalization_sql_routes.py)
select the same dedicated operation:

- `/api/webauthn/register/execute-finalization` for a current operator.
- `/api/auth/session/webauthn/register/execute-finalization` for the actual
  pending OIDC cookie session.

The [closed request parser](../serverware/control_plane_registration_finalization_sql_http.py)
requires `purpose: "execute-registration-finalization"` and a canonical
`sha256:` `localDigest` identifying the retained **finalization grant**, not its
earlier evidence grant or a reservation record. Optional fields are
`bootstrapToken` and `mfa`. A nonnull bootstrap token is a string of at most
1024 characters. A nonnull `mfa` object allows only `assertion` (an object when
nonnull) and `approvalId` (a 1–4096-character string when nonnull).

The existing bounded middleware requires one canonical positive Content-Length,
an exact `application/json` Content-Type, no query, Transfer-Encoding or
Content-Encoding, and exactly that many body bytes, capped at 64 KiB. Strict
JSON rejects duplicate keys and enforces the shared depth/node/string bounds.
Unknown request/MFA fields fail closed. No actor, user/session identity,
timestamp, key, expected root, pending head, proof object or response status is
accepted from the browser.

## Separate fresh permission

Both handlers require the actual cold owner's `finalization_sql_enabled` and
existing `sql_handoff_enabled` scopes. They genuinely inspect retained-original
ownership before authorizing the new action. The owned seven-scalar subject
(`localDigest`, `userId`, `challengeId`, `sessionId`, `mode`, `requestDigest`,
`operationId`) becomes the domain-separated
`serverware.webAuthnRegistrationFinalizationExecutionIntent/v1` binding for
`webauthn.registration.finalization.execute`. A posted subject dictionary and a
historical enrollment mode cannot supply present permission.

The operator branch authenticates the real request and current admin/approver
role. If any credential history exists, including revoked credentials, it
rejects a bootstrap token and directly verifies a fresh action/resource/payload
bound WebAuthn mutation assertion, then applies configured two-person approval.
The development MFA toggle and an evidence-only authority wrapper cannot bypass
that assertion. The exact requester action is added alongside the existing
finalization actions; no wildcard permission is introduced. Production startup
requires the action's two-person configuration when the actual finalization SQL
and evidence handoff scopes are enabled; that is configuration admission, not
independent provisioning.

Without credential history, operator and pending-session branches instead
require a fresh presentation of the configured bootstrap secret, whose
configuration must contain at least 32 characters even in development. They
reject nonnull MFA. The pending route always requires one matching CSRF
header/cookie pair, regardless of unrelated authorization headers, and performs
uncached pending-session/current-RBAC admission. Active-cookie operator refresh
also uses the existing uncached session check.

Before dispatch, current actor/session scope and credential-history presence
are checked again. This is a presence/absence branch check, not an atomic
history reservation or a claim that all history remains unchanged. The actual
facade repeats genuine retained ownership under the same cold owner lock before
the irreversible dispatch path. It accepts only the authenticated user/session
scalars supplied by the handler, not a successful inspection object.

## Observed commit and uncertainty

The route invokes the actual retained-execution facade, which joins retained
originals to independently admitted pending scope, owns the one-use local
dispatch claim, and retains the bounded returned outcome. Only its successful
`observed-commit` return can produce HTTP 202. Public projection checks the
bounded raw4 carrier but does not authenticate it; the private caller's original
admission and complete marker checks cannot be replaced by the projection.

The response has exactly nine fields:

| Field | Value |
| --- | --- |
| `schema` | `serverware.webAuthnRegistrationFinalizationExecution/v1` |
| `status` | `observed-commit` |
| `purpose` | `execute-registration-finalization` |
| `localDigest` | The same canonical retained finalization-grant locator |
| `observationAuthenticated` | `false` |
| `registrationCompleted` | `false` |
| `sessionActivated` | `false` |
| `currentnessEstablished` | `false` |
| `automaticRetryAllowed` | `false` |

No pending/packet identity, marker, raw original, bootstrap token or assertion
is exposed. Cache-Control is `no-store`; the existing no-cache and nosniff
headers are retained. The application keeps its existing signed-response
boundary without turning this local observation into signed completion.

An internal failure is redacted to HTTP 503 with
`error: "registration_finalization_execution_unavailable"`,
`remoteState: "unknown"`, and false `registrationCompleted`, `sessionActivated`,
`currentnessEstablished` and `automaticRetryAllowed`. A `localDigest` is included
only after genuine subject ownership established that same locator. There is
no `finalizationExecuted: false` or other assertion that SQL did not run.

HTTP 412/428 retain the real action/resource/payload approval negotiation but
remove a generic retry hint and set `automaticRetryAllowed: false`. Assertion
verification precedes two-person approval, so a 428 continuation needs another
fresh assertion. Missing responses, 503 uncertainty, consumed local/remote
attempts and late validation failures never authorize automatic replay or
another SQL dispatch. The seventh portal action uses its own finalization-grant
input and uncertainty display; it does not chain into evidence recovery.

## Remaining boundaries

The [protected SQL composition](registration-finalization-sql.md), cold worker
and original-bound caller are distinct from independently signed finalization
completion/recovery and its public workflow. A real finalization SQL commit may
already have changed credential state while the public observation remains
unavailable. Separate completion/currentness admission and OIDC session
activation are still required; the route does not call the old browser
`/verify` flow or activate a pending session. Deployment, independent
database/key/checkpoint authority, rollback-resistant witnesses and frozen
end-to-end verification remain unproven by this source batch.
