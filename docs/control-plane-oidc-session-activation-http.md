# One live-permission activation request

`control_plane_oidc_session_activation_http._activate(request,
activation_bytes=...)` connects the actual authenticated HTTP Request to one
fixed private activation sequence. This is source integration only, unbuilt,
unexecuted and unprovisioned. It supplies no recovery or portal action and
does not establish production acceptance.

## Original request and allowance

The [HTTP adapter](oidc-session-activation-public-http.md) supplies immutable,
bounded bytes from `request.state.oidc_session_activation_bytes`. The core
requires that exact original, not a parsed identity/subject graph or successful
permission carrier. The existing [256 KiB data contract](oidc-session-activation-http-contract.md)
projects separate permission assertion/approval and session-binding planning
assertion/challenge originals. The two ceremonies are not interchangeable.

One actual `_ValidationWork` and opening window precede parsing and native
owner/key work. Bounded decoder/projection work is precharged, and clocks are
checked around parsing. The actual enrollment owner supplies one permission
context: genuine cookie-specific CSRF, fresh pending identity, retained target,
sole credential, assertion counter update and required approval precede
planning. The core refuses a missing configured continuation before dispatch;
that check is not endpoint readiness or substitute authority. Every downstream
component still admits its own original controls.

The async route invokes this bounded synchronous core directly on the ASGI
thread. It can block that control-plane event loop for the bounded invocation;
it is not a high-concurrency or performance claim. No active permission moves
to a worker thread, and no operation receives a replacement work/window.

## Fixed same-call sequence

Inside that single context the source calls:

1. `dispatch_completion(assertion_bytes=..., expected_challenge_id=...)`.
2. `acquire_and_prepare_consume()`.
3. `authorize_consume()`.
4. `dispatch_consume()`.
5. `complete_consume()`.
6. `authorize_release_intent()`.
7. `prove_release()`.
8. The genuine delivery helper, which owns `acquire_and_release_token()` and
   stages the fresh-current-auth cookie response.

Existing phase, original-retention and one-use checks govern every transition.
The core does not call the older startup dispatch wrapper and then attempt to
resume its already-closed permission. Root inputs are acquired through the
fixed private continuations; the browser supplies no grant, bootstrap, proof,
packet or custody key. Token bytes never pass through the orchestrator or
enter a success DTO, response JSON, log or journal.

## Truthful outcome and terminal response

A local irreversible marker is set immediately before `dispatch_completion`.
This is deliberately earlier than the durable pre-planner claim. Any later
failure is conservatively `outcome-unknown`, even if the first socket was not
reached. It uses HTTP 503, preserves the pending cookie and sets
`automaticRetryAllowed: false`. Only known pre-dispatch refusal can use
`rejected-before-dispatch`; that says nothing about permission assertion/CAS
side effects or earlier requests. Exception text and arbitrary exception
headers are never copied into these fixed failure responses.

The source-owned delivery helper retains the exact receiving verifier's
narrowed guard, checks fresh active identity against the original target and
stages a response while permission is still live. `_ActivationPermission`
records `_normal_exit=True` only after its final live check and all per-call
trust/parent-lock cleanup succeed. Failure leaves the marker false. The
orchestrator returns only `staged.finish()` after normal context exit; the
shared enrollment owner is never globally closed.

The delivery continuation must keep its genuine receiver guards and original
resource/bound checks through the final signed HTTP send, without calling a
revoked permission or renewing authority. A staged cookie is not a sent cookie,
and local send is not recipient acknowledgment. Guard, cleanup or response
uncertainty does not authorize a retry, recovery or session-success claim.
