# Guarded completion recovery release response

`control_plane_oidc_session_activation_completion_recovery_delivery_response`
owns the final token-to-cookie boundary for the distinct fresh `release` actor.
It accepts only the actual source-owned `_DeliveryAttempt`, with retained raw2
grant originals and the genuine same-call completion/input/intent/proof chain.
It does not accept an incoming token, successful result object, preparation
permission or caller-selected checkpoint. Genuine LIVE-only grant, request and
response admission remains the exchange's responsibility.

`_response_on_active(active)` selects `_StagedRecoveryResponse` before any new
LIVE admission or protected contact. The exchange selects its base-only
continuity using `_exchange_on_active`, and `_retain_receiver` records the same
genuine receiving guard both on the live attempt and the terminal. That child is
never attached to its own ancestor. Private ordinary actor/input/proof/exchange
guards remain unusable after closure.

During the live call, exact public-original references, fixed input graph
snapshots, parent handoff/client/endpoint pins, root/key/enrollment resources,
actor purpose, request/Origin/CSRF, target, work ledger, PID/thread and narrowing
clock/window bounds are retained. The actual returned token is admitted with
the normal current-session lookup. User/session identity, signed new-token
commitment, sole credential and counter, current authenticator trust, explicit
active RBAC, roles and session/provider expiry must match the fresh actor.
The token appears only in the staged HttpOnly, SameSite=Strict cookie, with
Secure selected from the actual HTTPS request; it is not returned as JSON or
placed in a journal or log.

`finish()` requires both the attempt's and actor's explicit successful
normal-exit markers, cleared ordinary token/receiving references and completed
trust/startup-lock cleanup. The independently retained receiver then checks the
captured original owner scope, source current guard and historical target guard,
plus its exact final narrower bounds/floors. It never revives the actor or calls
a closed input/proof guard. Fixed mutable evidence graphs remain snapshot-checked
across this transition; retaining an object reference alone is insufficient.

The root integrates `_send_response` after response buffering and signing,
immediately before actual success headers. It checks the exact scope, status,
body and sole cookie, runs the full receiver and fresh current-auth checks again,
and preserves the original ASGI thread. This bounded synchronous workflow can
block that thread; no concurrency or runtime claim follows from this source.
A failed pre-send guard discards the stale success, cookie and signature and
emits a fixed cookie-free 503 with unknown session/dispatch state. Once headers
have started, a failure cannot emit replacement headers. `_discard_scope` and
the send wrapper erase the terminal's response and private continuation refs.

Success uses
`serverware.oidcSessionActivationCompletionRecoveryDeliveryResponse/v1`, purpose
`release`, status `released`, session state `active`, and no automatic retry.
The same schema/purpose identifies rejected-before-dispatch responses (400 by
default, or an explicit source-selected error status) and fixed outcome-unknown
503 responses without claiming current-session success.
`_AUTH_RESERVATION` is source-defined representation accounting under the
original whole-call budget, not a new work allowance or a process-heap bound.

This terminal supplies no grant issuance, resource provisioning, SQL retry,
checkpoint fallback, delivery-expiry renewal, RECOVERY outcome-store evidence,
or preparation-permission reuse. Source only: unbuilt, unexecuted and
unprovisioned; no production acceptance gate is implied.
