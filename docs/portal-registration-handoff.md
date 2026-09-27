# Portal retained registration actions

The **Registration actions** workspace operates on a real evidence grant
`localDigest` from retained preparation. Paste that locator, or explicitly copy
one already inspected in the admin-only custody inventory. Inspection supplies
local metadata only—not ownership, complete association, currentness or action
permission. The panel neither invents IDs nor loads raw registration originals.

Each button selects one real endpoint and requires an explicit click:

| Control | Action boundary |
| --- | --- |
| Execute evidence | One-use evidence-admission SQL handoff; not credential finalization. |
| Request completion | Completion for live original controls. |
| Recover completion | Separately authorized historical completion recovery; never SQL retry. |
| Prepare finalization | Prepare and retain the separate `webauthn.registration.finalize` request; no finalization execution. |

The first three use the existing
[public handoff](public-registration-handoff.md) and
[historical recovery](public-registration-recovery.md) contracts. Finalization
preparation uses `/api/webauthn/register/prepare-finalization` or its
`/api/auth/session/webauthn/register/prepare-finalization` counterpart, purpose
`prepare-retained-registration-finalization`, and action
`webauthn.registration.finalization.prepare`. Its returned finalization local
ID is displayed separately; the evidence grant input is never replaced.
This prepared-only plan cannot gain fresh execution permission retroactively:
the dedicated authorization-before-planning execution path is not yet connected.

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
**prepared, not executed**. Every path keeps registration not finalized,
currentness unestablished, and automatic retry disallowed. No completion result
activates a pending session.

Unavailable, lost or unrecognized responses display remote state as unknown;
the request may have taken effect. Do not repeat SQL. Historical recovery is a
separate explicit action requiring fresh server authorization, not a retry
policy. Reloading the page cannot clear the server's attempt history.

This UI is source-only and has not been browser-verified or deployed. Cold
provisioning, independent currentness/release acceptance and actual credential
finalization execution remain separate. Planned frozen browser verification
covers both caller paths, cookie CSRF with an entered token, action-bound fresh
assertions/approvals, bootstrap clearing across refresh, stale async results,
exact status/uncertainty handling, and absence of automatic dispatch or retries.

Source: [portal fragment](../serverware/portal_registration_handoff.py).
