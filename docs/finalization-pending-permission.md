# Pending-session permission for finalization completion

The source-only [pending permission handler](../serverware/control_plane_registration_finalization_completion_pending.py)
separates completion permission from first enrollment, SQL execution and OIDC
session activation. The retained finalization subject includes the exact
`credentialId` regenerated from its authenticated signer originals; a browser
supplies only the retained finalization grant locator, never subject or root pins.

The pending-cookie POST actions are
`/api/auth/session/webauthn/register/complete-finalization` and
`/api/auth/session/webauthn/register/recover-finalization-completion`.
Their respective `/options` routes accept only the fixed action's `purpose`
and `localDigest`. Every route requires explicit cookie CSRF even if an unrelated
authorization header is present, a fresh DB-time-valid pending session, current
admin/approver RBAC, and the exact retained user/session ownership.

| Current credential state | Required present permission |
| --- | --- |
| Empty user history and target absent globally | Fresh configured bootstrap, including development; MFA and options denied. |
| Sole historical credential is the retained, active target owned by this user | Fresh target-key action-bound WebAuthn and configured two-person approval; bootstrap denied. |
| Extra history, foreign target, revocation or inconsistent rows | Denied by this narrow pending-session flow. |

The credential branch uses the existing real mutation-options and assertion
verifiers, not session-binding challenges. Options expose only the actual
target's `publicKey` options plus schema, purpose, localDigest, action, resourceId,
payloadDigest and `automaticRetryAllowed: false`. The browser cannot select the
action, resource or payload hash. A 428 approval negotiation has already consumed
the assertion: an explicit continuation needs another fresh assertion.

Session scope/roles and the credential history are reread before dispatch. The
credential's identity, key, trust and revocation fields must remain unchanged;
only the exact verified signature-counter result and the existing CAS helper's
`last_used_at`/`updated_at` bookkeeping may change. These are current permission
checks, not an atomic database/current-root lease.

Lost bootstrap authority is not recovered from the original enrollment recipe.
An already committed eligible target may authorize a fresh action with its key;
empty history without fresh bootstrap, a lost/revoked target, or an expired,
revoked, activated or changed pending session remains blocked. No route activates
that session, retries SQL or treats an acknowledgment as currentness authority.

Implementation is unbuilt and unexecuted. Frozen verification must cover both
history branches, foreign/extra/revoked credentials, fresh target assertions and
approval continuation, concurrent counter/identity/session changes, options
scope and response bounds, cookie CSRF with auth headers, and redacted failure
paths. Production acceptance remains separate.
