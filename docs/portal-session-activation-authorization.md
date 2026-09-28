# Portal session action authorization

`portal_session_activation_authorization.py` supplies the fixed, cookie-only
authorization transport used by the activation workspace. It is browser-side
cancellation and request construction, not an authority verifier. All retained
originals, present cookie possession, roles, trust, assertions, approval and
one-use operation claims remain independently checked by the real handlers.

## Explicit fresh ceremonies

`sessionActivationAuthorize(action, selected, stillCurrent, approvalId,
previousBinding)` returns `{body, binding}` without submitting an action. The
source-fixed action table checks the literal POST and options routes for
activation, retained-intent recovery, both historical completion profiles,
fresh consume, intent/proof preparation, LIVE release and retained RECOVERY
release. The only selected request target is the retained finalization locator;
browser-entered keys or target identities are never posted as authority.

Every call obtains new options with its exact schema, profile and purpose,
then collects a real assertion from the server's sole target key. Activation
also fetches `/api/auth/session/webauthn/options`, validates the distinct
`serverware.challenge_id`, narrows that actual allowed-key list to the same
target, and collects a second real assertion. Permission and planning proofs
are never reused or substituted for one another. A later approval continuation
repeats both activation ceremonies, or the selected recovery ceremony.

Bindings hold the literal route, action/resource/payload digest, locator,
profile/purpose, target key, RP and cookie-authentication snapshot. An explicit
approval continuation must match newly obtained options to that exact prior
in-page binding before asking for another assertion. Selection or authentication
changes cancel the sequence around every asynchronous boundary. These checks
do not replace the server's current-session and original-evidence admission.

## Approval is not automatic retry

Only the actual server approval gate's bounded HTTP 428 projection is accepted:
`serverware.oidcSessionActivationApprovalRequired/v1`, exact action/resource/
payload binding, an approval ID, `dispatchState: approval-required`,
`automaticRetryAllowed: false` and `freshAuthorizationRequired: true`.
`sessionActivationApproval` rejects ordinary 428s, mismatched bindings and all
412s. The UI retains a one-use explicit continuation; it does not poll, approve,
resubmit automatically, or let an entered ID authorize a request. An approval
response is neither successful execution nor proof about a prior attempt.

The previous public activation/recovery handlers flattened this negotiation.
The source-private `_ApprovalRequired` exception and bounded public projection
now preserve only the real local pre-execution gate. Other errors remain
uncertain; browser logic does not manufacture permission from them.

## Transport and limits

`sessionActivationPost(path, body, stillCurrent)` returns the one unconsumed
`Response`. It fetches CSRF directly for the same-origin cookie and sends only
fixed JSON/CSRF headers. It never calls the generic operator API helpers or
reads/sends the entered operator bearer, rejects redirects and uses no-store.
The confirmation helper alone reads an action response; authorization reads
options once with streaming byte caps before JSON decoding. Request caps are
256 KiB for activation and 64 KiB for recovery; options are at most 64 KiB,
CSRF replies 4 KiB and individual assertion carriers 60 KiB. Tighter descriptor
and authenticator representation limits can refuse otherwise valid responses.

Assertions, binding and approval state are page-memory only. There is no
local/session storage, automatic operation chain, response retry or token
exposure. Dropping JavaScript references does not promise memory erasure.
HTTP success is not session success: the separate confirmation helper must
perform a fresh cookie-only current-auth read and the UI must preserve unknown
results without inferring nonexecution. Source only; no browser/runtime
validation or production-readiness claim accompanies this change.
