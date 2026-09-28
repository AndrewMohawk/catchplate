# Same-context public recovery orchestration

`control_plane_oidc_session_activation_recovery_http._recover(request, *,
recovery_bytes)` accepts only the actual `Request` and its exact immutable
64 KiB-bounded framed original at
`POST /api/auth/session/activation/recovery`. No posted authority, target,
grant, proof, outcome, old token or successful permission DTO enters this core.
The existing options route and its fixed unavailable projection are unchanged.

Before parsing or native owner/resource I/O, the core opens one validation work
ledger and processing window from the actual configured owner. A private parent
lifetime retains that same work, clock floors and absolute deadline. It contains
no later actor or response child. The strict parser's owned graph is precharged,
only the validated locator is kept for safe failure data, and the graph is
discarded before private acquisition. The actual actor parses the same original
and independently establishes historical target, ephemeral old-cookie possession,
fresh WebAuthn, current roles/trust/credential, Origin/CSRF and configured approval.

The core enters the class-selected
`_EnrollmentOwner._acquire_oidc_session_activation_recovery_grants` context once,
with the exact original work/window/deadline and parent guard. That path acquires,
durably retains and stages genuine recovery originals. Inside it,
`recovery_delivery._response_on_active(active)` creates the source-owned terminal
boundary before the protected exchange/receiving path. The delivery owner retains
the genuine receiver's narrowed guard, verifies fresh current-auth for the exact
target and stages the fixed nonsecret response and replacement cookie. No token
crosses this orchestrator.

Only after normal acquisition/actor/resource cleanup may the exact
`_StagedRecoveryResponse.finish()` run. The delivery owner's actual send hook
continues checking its original ancestors, receiver guard, exact body and cookie
through signed response send. It does not resurrect a closed actor, accept a
copied token as permission, close the shared startup owner or open a new window.
The separate private recovery facade remains live-context-only by default.

## Truthful failure boundary

Before entering private acquisition, the core sets a conservative local
uncertainty marker. Any failure after that point—including unavailable resources,
busy-owner refusal, failed admission, missing ACK, cleanup or final guard
failure before headers are emitted—uses fixed `recovery-outcome-unknown` data
with HTTP 503. A send that has already become externally uncertain cannot be
undone or replaced with a claimed successful delivery. This does not
assert that a socket, SQL effect or token delivery did or did not happen.
Earlier framing/parse/configuration refusals may use
`recovery-rejected-before-dispatch`; its `not-started` state describes only this
request's private recovery acquisition, never previous activation/SQL or
WebAuthn challenge/counter side effects.

Both failure shapes preserve the existing cookie, report session state as
unknown, forbid automatic retry and suppress exception text/foreign headers.
The only response headers supplied by these helpers are no-store, no-cache and
nosniff. The fixed success schema is ordinary data constructed only by the
genuine delivery owner after its required checks, never caller authority.

The async route deliberately calls this bounded synchronous core on the same
ASGI thread through final send. This preserves thread-bound authority and work;
it is not nonblocking I/O or a throughput claim. No background continuation or
automatic retry is introduced. Prior-stage completion recovery, resources,
provisioning, deployment and portal remain separate; source integration is
unbuilt and unexecuted, not observed runtime or production acceptance.
