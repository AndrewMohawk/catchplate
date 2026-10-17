# Pending-session permission for finalization completion

The source-only [pending permission handler](../catchplate/control_plane_registration_finalization_completion_pending.py)
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
| Any history, when the selected complete/recover action requires two-person approval | HTTP 503 before options, assertion consumption, bootstrap or dispatch; this protocol is not implemented. |
| Empty user history and target absent globally | Fresh configured bootstrap, including development; MFA and options denied. |
| Sole historical credential is the retained, active target owned by this user | Fresh target-key completion possession when two-person approval is not required; bootstrap denied. |
| Extra history, foreign target, revocation or inconsistent rows | Denied by this narrow pending-session flow. |

The credential branch uses the dedicated
[completion possession helper](../catchplate/control_plane_registration_finalization_permission.py)
and the real WebAuthn signature verifier. It creates no ordinary mutation or
session-binding challenge row. Options expose only the actual
target's `publicKey` options plus schema, purpose, localDigest, action, resourceId,
payloadDigest, `expiresAtEpochNs` and `automaticRetryAllowed: false`. The browser
cannot select the action, resource or payload hash. One random nonce is retained
for the admitted owner's lifetime, with expiry clipped to its original context
and at most 120 seconds. It is spent before verification, including on failure;
the same owner cannot issue a replacement. Owner loss/restart invalidates it.

Configured two-person completion returns the fixed 503 error
`registration_finalization_completion_two_person_unavailable`. There is no 428
approval negotiation or fresh-assertion continuation for this refusal. Supporting
two-person completion requires an explicit future authorization protocol that
preserves the committed pending roots; generic approval writes are not a workaround.

Session scope/roles and the credential history are reread before dispatch. The
credential's identity, key, trust and revocation fields must remain unchanged;
the stored signature counter and `last_used_at`/`updated_at` also stay unchanged.
The real signed counter observation is checked against that stored baseline,
without a CAS or bookkeeping write. No metadata challenge or approval row is
created or consumed. These read-only checks preserve the complete pending vector;
they are not an atomic database/current-root lease or a persisted counter advance.

Lost bootstrap authority is not recovered from the original enrollment recipe.
An already committed eligible target may authorize a fresh action with its key;
empty history without fresh bootstrap, a lost/revoked target, or an expired,
revoked, activated or changed pending session remains blocked. No route activates
that session, retries SQL or treats an acknowledgment as currentness authority.

Implementation is unbuilt and unexecuted. Frozen verification must cover both
history branches, foreign/extra/revoked credentials, fresh target assertions and
the two-person refusal before side effects, spent-nonce and owner-loss behavior,
concurrent counter/identity/session changes, exact pending-vector preservation, options
scope and response bounds, cookie CSRF with auth headers, and redacted failure
paths. Production acceptance remains separate.
