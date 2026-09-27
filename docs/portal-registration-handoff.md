# Portal retained registration actions

The **Registration actions** workspace's first five actions operate on a real evidence grant
`localDigest` from retained preparation. Paste that locator, or explicitly copy
one already inspected in the admin-only custody inventory. Inspection supplies
local metadata only—not ownership, complete association, currentness or action
permission. The panel neither invents IDs nor loads raw registration originals.
The sixth and seventh actions use the separately labeled finalization-grant input: paste
that real locator, or use the ID filled by a successful fifth action. Neither
the evidence input nor the older preparation-only finalization ID is replaced.

Each button selects one real endpoint and requires an explicit click:

| Control | Action boundary |
| --- | --- |
| Execute evidence | One-use evidence-admission SQL handoff; not credential finalization. |
| Request completion | Completion for live original controls. |
| Recover completion | Separately authorized historical completion recovery; never SQL retry. |
| Prepare finalization | Prepare and retain the separate `webauthn.registration.finalize` request; no finalization execution. |
| Prepare finalization grant | Dedicated authorization before a new plan, complete before vector and retained grant; no reservation or finalization SQL. |
| Reserve finalization | Explicit fresh-authorized reservation of the separate finalization grant and retention of verified returned raw3; no finalization SQL or current-head authority. |
| Execute finalization | Separate fresh-authorized protected SQL handoff using that finalization grant; its unsigned commit observation is not signed completion, currentness or session activation. |

The first three use the existing
[public handoff](public-registration-handoff.md) and
[historical recovery](public-registration-recovery.md) contracts. Finalization
preparation uses `/api/webauthn/register/prepare-finalization` or its
`/api/auth/session/webauthn/register/prepare-finalization` counterpart, purpose
`prepare-retained-registration-finalization`, and action
`webauthn.registration.finalization.prepare`. Its returned finalization local
ID is displayed separately; the evidence grant input is never replaced.
This prepared-only plan cannot gain fresh execution permission retroactively:
the separate grant action must authorize before making a new plan.

**Prepare finalization grant** uses
`/api/webauthn/register/prepare-finalization-grant` or its
`/api/auth/session/webauthn/register/prepare-finalization-grant` counterpart,
purpose `prepare-registration-finalization-grant`, and action
`webauthn.registration.finalization.authorize`. Its closed ten-field success
contract is `serverware.webAuthnRegistrationFinalizationGrantPreparation/v1`
with status `finalization-grant-prepared`, the unchanged evidence `localDigest`,
a separate `finalizationGrantLocalDigest`, operation
`webauthn.registration.finalize`, and all four execution/registration/currentness/
automatic-retry flags false. It does not upgrade the older raw7 preparation.
The grant locator has its own display and user-editable input: neither the
evidence input nor the inspection/preparation-only finalization locator is
overwritten. Filling that input makes no further request.

**[Reserve finalization](public-registration-finalization-reservation.md)** uses `/api/webauthn/register/reserve-finalization` or
its `/api/auth/session/webauthn/register/reserve-finalization` counterpart,
purpose `reserve-registration-finalization`, and action
`webauthn.registration.finalization.reserve`. Its closed ten-field success
contract is `serverware.webAuthnRegistrationFinalizationReservation/v1`, status
`reservation-recorded`, the submitted finalization-grant `localDigest`, operation
`webauthn.registration.finalize`, `reservationRecorded: true`, and
`finalizationExecuted`, `registrationCompleted`, `currentnessEstablished` and
`automaticRetryAllowed` all false. Server-side original authentication precedes
[opaque local retention](control-plane-custody-journal.md#retained-finalization-reservation).
The browser does not independently verify the originals or infer a current
pending head from their acknowledgment.

**Execute finalization** uses `/api/webauthn/register/execute-finalization` or
its `/api/auth/session/webauthn/register/execute-finalization` counterpart,
purpose `execute-registration-finalization`, and action
`webauthn.registration.finalization.execute`. It uses only the finalization-grant
input, never the evidence or older preparation-only locator. Its closed
nine-field success contract is `serverware.webAuthnRegistrationFinalizationExecution/v1`,
status `observed-commit`, the submitted `localDigest`, and
`observationAuthenticated`, `registrationCompleted`, `sessionActivated`,
`currentnessEstablished` and `automaticRetryAllowed` all false. It exposes no
custody IDs or marker. The browser reports the server's unsigned observation,
not independently verified completion; filling a locator or recording a
reservation never dispatches this action automatically.

## Fresh authorization, no action chaining

Select the present operator-with-history, operator-without-history, or pending
OIDC first-enrollment flow. That selection grants no authority: real server
ownership, current actor/session, bootstrap, WebAuthn and two-person gates still
decide. Operator requests use the existing `api` helper. Pending requests use
`sessionApi` with an explicitly obtained cookie CSRF header, including when an
operator token is also present in the page.

The history branch first makes one explicit request. A server `412` displays
the exact public action/resource/payload binding and an explicit **Fresh
assertion + submit** control. A `428` displays the approval ID and links the
existing approval queue. After a different authorized operator approves, the
requester explicitly continues with a **new** assertion; no consumed assertion
is reused. The requester's WebAuthn challenge does not select the approver
challenge: the approval ID is carried only in the final action's MFA body.

The no-history branches prompt for a fresh masked bootstrap token on each
action. The existing dialog clears its input. New panel controls and that
password field are excluded from refresh draft capture/restore. No bootstrap,
assertion, pending request or approval state is written to local/session
storage by this panel. Temporary JavaScript strings are not guaranteed wiped.

There are no automatic `412`/`428` resubmissions, request retries, next-action
chains, polling of these actions, or session-activation calls. Discarding a
local prompt does not revoke a server approval or undo a dispatched operation.
Selection/token changes invalidate in-flight UI continuations. A page-local
duplicate-click guard is convenience only; the server owns durable one-use.

## Read the result narrowly

The panel validates closed, source-fixed response shapes and displays bounded
status rather than raw exception text or response originals. SQL
`observed-commit` is not a signed completion. Completion/recovery reports rely
on the server's actual original verification, not an independent browser proof.
`finalization-prepared` displays the separate finalization locator as
**prepared, not executed**. `finalization-grant-prepared` displays the distinct
grant locator as **not reserved or executed**, never as completed credentials
or a session-activation receipt. The separate `reservation-recorded` result
means the returned reservation originals were retained, not finalization SQL,
credential completion or independent currentness. The seventh action can
request actual finalization SQL, but its `observed-commit` does not establish
signed completion or full enrollment. Every path keeps completed registration
and currentness unestablished, and automatic retry disallowed. No completion result
activates a pending session.

Unavailable, lost or unrecognized responses display remote state as unknown;
the request may have taken effect. Do not repeat SQL. Historical recovery is a
separate explicit action requiring fresh server authorization, not a retry
policy. The existing Recover completion control is for evidence admission,
not finalization SQL reconciliation. Reloading the page cannot clear the
server's attempt history.

This UI is source-only and has not been browser-verified or deployed. Cold
provisioning, independent currentness/release acceptance, signed finalization
completion and separate session activation remain outstanding. Planned frozen browser verification
covers both caller paths, cookie CSRF with an entered token, action-bound fresh
assertions/approvals, bootstrap clearing across refresh, stale async results,
exact status/uncertainty handling, and absence of automatic dispatch or retries.
The sixth- and seventh-action checks also cover independent evidence/finalization
locators, pasted locators after refresh, exact reservation and unsigned execution
response shapes, uncertain outcomes and per-locator/action latches.

Source: [portal fragment](../serverware/portal_registration_handoff.py).
