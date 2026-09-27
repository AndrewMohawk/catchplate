# Public retained-registration finalization preparation

Two separate POST routes prepare and retain a finalization plan from the exact
previously retained registration originals:

- `/api/webauthn/register/prepare-finalization` for the current operator.
- `/api/auth/session/webauthn/register/prepare-finalization` for the current
  pending OIDC first-enrollment session.

They **do not execute finalization, create a credential or activate a session**.
This is source-only integration, unbuilt and unexecuted. The existing legacy
`/verify` handlers are unchanged; no fallback to them is performed.

This prepared-only path does not issue finalization execution authorization.
That authorization must precede the signed plan's issue time; a fresh permission
obtained afterward cannot authorize this existing raw7 retroactively. The
production authorization-before-planning path still needs integration, without
backdating, expiry renewal or automatic replanning.

## Separate present permission

The purpose is `prepare-retained-registration-finalization`, with action
`webauthn.registration.finalization.prepare`. Its distinct
`serverware.webAuthnRegistrationFinalizationPreparationIntent/v1` binds the
source action/purpose and genuinely replayed local record, user, challenge,
session, original mode, request digest and operation ID. Evidence-admission or
historical-recovery permission is not permission for this action.

The closed body requires `purpose` and `localDigest`, with optional
`bootstrapToken` and `mfa` containing only optional `assertion`/`approvalId`.
The local digest selects the actual retained execution/evidence-admission raw10
and associated signer originals, not an arbitrary finalization plan. No posted
credential, subject, configuration, key, original bytes or proof-success carrier
is accepted. Framing requires one positive canonical `Content-Length`, exact
JSON content type, no query or transfer/content encoding, strict duplicate-free
JSON and a 64 KiB maximum body.

Genuine live retained-subject inspection precedes permission. Operators require
current admin/approver admission; any credential history, including revoked
history, requires a fresh action-bound WebAuthn assertion and configured
two-person approval. Empty history requires the configured bootstrap token,
including in development. These branches cannot substitute for one another.
The pending-session route additionally requires cookie CSRF without a header
bypass, a fresh pending OIDC session and empty credential history. The handler
rechecks current identity/session/history before dispatch. Production startup
requires the new two-person action when the cold handoff profile is enabled.

## Actual preparation and result

The [retained-original facade](retained-registration-finalization.md) repeats
ownership under the actual cold-owner lock, requires a stored acknowledged
completion (original or reconciled), and genuinely verifies it against the
independently configured original pending scope. It does not request completion,
recover uncertainty or resubmit SQL on the caller's behalf.

Existing **live** finalization replay, bounded sibling lookup and actual
transition planning must prove the current challenge/history, complete sibling
population and unconsumed committed v2 evidence row. The exact prepared raw7 is
durably retained, without forwarding to a writer or acquiring execution power.
Historical recovery does not revive expired originals for this new operation.

Successful HTTP `202` contains exactly:

| Field | Meaning |
| --- | --- |
| `schema` | `serverware.webAuthnRegistrationFinalizationPreparation/v1` |
| `status` | `finalization-prepared` |
| `purpose` | `prepare-retained-registration-finalization` |
| `localDigest` | Unchanged input execution/evidence-admission locator. |
| `finalizationLocalDigest` | Actual newly retained finalization raw7 locator. |
| `operation` | `webauthn.registration.finalize` |
| `finalizationExecuted`, `registrationCompleted`, `currentnessEstablished`, `automaticRetryAllowed` | All `false`. |

Local locators are not execution receipts or currentness authority. Failures
return fixed redacted uncertainty; no exception text, authority originals,
credential secrets or invented finalization locator is exposed. A `localDigest`
is included only after genuine ownership inspection. Existing bounded `412`/
`428` permission negotiation remains available, without automatic retry hints.
An assertion consumed before approval negotiation must not be reused. All
responses are non-cacheable.

Finalization still requires its distinct original caller authorization,
independently admitted grant, fresh current-root reservation and real protected
execution/outcome handling. OIDC browser-session activation is another operation;
even actual credential insertion must not be reported as session activation.
Those execution/activation integrations and full frozen verification remain
open. See the [portal handoff controls](portal-registration-handoff.md) for
explicit source-level preparation/inspection UI, not a completed enrollment claim.

Source: [routes](../serverware/control_plane_registration_finalization_routes.py)
and [HTTP contract](../serverware/control_plane_registration_finalization_http.py).
