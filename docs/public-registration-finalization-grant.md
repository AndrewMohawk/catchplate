# Public finalization execution-grant preparation

Two dedicated POST routes authorize **before** making a new finalization plan,
obtain its genuine execution grant and retain the original exchange:

- `/api/webauthn/register/prepare-finalization-grant` for the current operator.
- `/api/auth/session/webauthn/register/prepare-finalization-grant` for the current
  pending OIDC first-enrollment session.

This is source-only, unbuilt, unexecuted and not browser-verified. A successful
response means locally retained grant preparation, not reservation, SQL,
credential registration or session activation. The existing
[prepared-plan-only routes](public-registration-finalization.md) remain separate;
this path does not retrospectively authorize one of their older raw7 plans.

## Separate present-caller permission

The fixed purpose is `prepare-registration-finalization-grant`; the distinct
action is `webauthn.registration.finalization.authorize`. Permission for evidence
execution, live completion, historical recovery or plan-only preparation cannot
substitute for this action.

The strict JSON body is at most 64 KiB. It requires exactly `purpose` and
`localDigest`, with only optional `bootstrapToken` and `mfa`; the latter permits
only optional `assertion` and `approvalId`. Framing requires one canonical
positive `Content-Length`, exact JSON content type, no query string or
transfer/content encoding, and strict duplicate-free bounded JSON. The digest
selects retained evidence-admission execution originals and their actual signer
association. No posted subject, credential, authority original, configuration,
key, timestamp, vector or successful-verification result is accepted.

Genuine **live** retained ownership is checked before present branch permission.
The operator path requires current admin/approver admission. Any credential
history, including revoked history, requires a fresh action-bound WebAuthn
assertion and configured two-person permission. Empty history requires a fresh
configured bootstrap token, including in development. Pending first enrollment
also requires fresh pending OIDC session/current-role admission, cookie CSRF
without a header-credential bypass and empty credential history. Current caller,
session and history are checked again before dispatch; branch changes deny the
operation rather than selecting a weaker path.

## Actual original-byte continuation

The facade repeats ownership under the actual cold owner and requires an
already retained acknowledged evidence completion, original or reconciled,
genuinely verified against the independently configured pending scope. It never
requests completion, invokes recovery or resubmits evidence SQL automatically.

The [cold caller continuation](control-plane-finalization-execution.md) uses its
separate finalization caller key to issue the original authorization **before**
requesting a new plan. The actual verifier-side read supplies the complete before-vector
and finalization proof from the same read transaction. Genuine live replay must
prove current challenge/history, the complete OIDC sibling population and an
unconsumed committed v2 evidence row. Old expiry is not bypassed, and timestamps
are neither backdated nor substituted to fit an old preparation.

The [dedicated authorizer](registration-finalization-authorizer.md) receives only
original authorization, raw7 and the complete before-vector. Its actual
[grant producer](registration-finalization-grant-production.md) authenticates
the finalization purpose, custody/history and exact request/operation, then
performs genuine complete-vector raw4 replay before signing. The caller verifies
the returned original grant against those same originals and independent scope.
Transport peer admission alone is not grant authority.

The actual journal retains raw10: authorization, raw7, complete before-vector
and grant. It publishes the new finalization association, referencing the
already-existing evidence/signer association, only after those originals have
been durably retained. No unverified incoming carrier or local
association substitutes for cryptographic replay. Original windows and work
remain bounded; retention does not renew execution permission.

## Exact prepared-local result

Successful HTTP `202` is non-cacheable and contains exactly ten keys:

| Field | Value or meaning |
| --- | --- |
| `schema` | `serverware.webAuthnRegistrationFinalizationGrantPreparation/v1` |
| `status` | `finalization-grant-prepared` |
| `purpose` | `prepare-registration-finalization-grant` |
| `localDigest` | Unchanged input evidence-admission execution locator. |
| `finalizationGrantLocalDigest` | Actual newly retained finalization raw10 locator. |
| `operation` | `webauthn.registration.finalize` |
| `finalizationExecuted`, `registrationCompleted`, `currentnessEstablished`, `automaticRetryAllowed` | All `false`. |

Raw authority originals and private material never enter the HTTP response.
Local locators are not execution receipts, currentness witnesses or retry
permission. Failures use bounded redacted uncertainty; permission negotiation
must not turn consumed assertions or an uncertain grant exchange into an
automatic retry. A failure can occur after authorization or durable work, so
absence of a successful response does not establish absence of effects.

Independent reservation and protected finalization execution/outcome handling
remain separate. Actual credential finalization does not itself activate an
OIDC browser session. No service is provisioned or activated by these routes;
frozen verification and production release gates remain outstanding.

Source: [routes](../serverware/control_plane_registration_finalization_grant_routes.py)
and [HTTP contract](../serverware/control_plane_registration_finalization_grant_http.py).
