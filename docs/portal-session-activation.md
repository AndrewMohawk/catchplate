# Explicit session activation and recovery workspace

The portal's **Activate or recover this browser session** workspace composes the
real source-integrated routes. A user supplies a retained finalization local ID,
or explicitly copies the ID already present in the registration panel. That
copy is only a locator: genuine server original admission still establishes the
target, ownership, historical state and current authority.

The fixed action catalog separates initial activation, retained-token recovery,
activation-completion reconciliation, consume-completion reconciliation, fresh
consume, intent/proof preparation, first LIVE release and retained-outcome
RECOVERY release. Each action displays its exact endpoint and boundary. No
success selects or submits the next action, and no failure changes profiles.
Preparation permission never becomes release permission.

One explicit click confirms the selected action, obtains fresh target-bound
options and WebAuthn assertions, then submits once. Initial activation also
requires its independent planning assertion. The authorization fragment checks
the fixed route, target credential and purpose; the page never supplies target
keys or treats a local identifier as execution authority. Requests use only the
browser cookie and fixed cookie-bound CSRF acquisition, not operator headers.

A page-local set permanently records each attempted locator/action pair. It is
not durable security state: the server's original-bound one-use claims remain
mandatory. Changing selection, signing in/out, changing operator credentials,
or observing changed authentication, policy or credential-trust metadata drops
the local authorization association without clearing attempted pairs. Busy
state is shared with ordinary session verification/status actions; changing
busy state alone never makes a stale selection current.

Only the server's distinct, strictly checked approval-required projection can
create one explicit continuation association. The original attempt stays in the
set. A different operator reviews the approval queue; the requester must click
Continue and obtain new options and new assertions with the same binding. The
association is consumed before that ceremony. Cancellation, another approval
response, a lost result or an invalid binding cannot enable another page retry.
There is no generic HTTP-428 exception and no manually supplied approval ID.

Outcomes are bounded and classified by the separate confirmation fragment.
Completion and proof-preparation results are historical observations, never
session success. A delivery response is still unconfirmed until the user makes
the separate read-only current-cookie check against the exact retained target.
That check cannot replay an activation action, unlock an attempted pair or
retroactively declare an unknown dispatch successful. Its observation is shown
separately from the action result; it does not replace the browser cookie.

Locators and validated public approval bindings are held only in page memory.
Assertions and request bodies are not put in local/session storage, refresh
drafts, logs or DOM fields. References are dropped after use; JavaScript cannot
promise erasure. No token is read, returned, copied or displayed by this panel.
The server continues to enforce original expiry, fresh authority, target
currentness, normal cleanup and guarded cookie delivery where applicable.

The root portal composition inserts the CSS/HTML and authorization, confirmation
and main scripts before initialization, and excludes this workspace's fields
from ordinary draft restoration. Background refresh observes context changes;
it never repeats a workspace action. This source-only integration is unbuilt
and unexecuted. Browser/runtime acceptance, independent provisioning and all
remaining production requirements remain separate gates.
