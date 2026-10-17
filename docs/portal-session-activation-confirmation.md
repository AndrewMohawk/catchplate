# Truthful portal session confirmation

Source checkpoint `.218`; unbuilt, unexecuted and unprovisioned. This connects
portal interpretation and a read-only current-cookie observation, not a runtime
acceptance result. It does not change production gates or automatically chain
any activation, completion, proof, consume or release action.

`portal_session_activation_confirmation.py` exports
`SESSION_ACTIVATION_CONFIRMATION_SCRIPT`. The actual portal calls
`sessionActivationOutcome(action, response, selected, stillCurrent, binding)`
after its one explicit dispatch and separately calls
`sessionActivationConfirm(action, selected, stillCurrent)` on an explicit
read-only check. Both return frozen display data. Selection/authentication epoch
changes invalidate outstanding reads; these helpers neither update generic
authentication state nor restore an attempted action's latch.

## Actual response contracts

The source-fixed action/path table is checked against each selected descriptor.
One stream read is capped at 32 KiB before UTF-8/JSON decoding. Redirects, wrong
origins/paths, incomplete declared lengths, malformed UTF-8, duplicate keys,
unexpected values/fields and changed selections become unknown. The small
object/scalar parser has independent depth, node and object-field limits.
No body, assertion, token, key or response error text is logged or persisted.

- Activation's exact `{ok: true, authenticated: true}` and the recovery/LIVE/
  retained-release exact success schemas mean **delivery reported, unconfirmed**.
  HTTP 200 alone does not prove the browser accepted a cookie.
- Activation/consume completion, fresh consume and intent/proof preparation
  require their actual exact schemas, purposes, statuses and target/profile
  fields where present. They remain **historical data**, with session unknown
  and token release false. They do not imply a cookie or current session.
- Only the exact typed HTTP 428 envelope is passed to
  `sessionActivationApproval(428, payload, action, selected, binding)`. Its
  original binding must validate before a bounded approval ID is exposed for
  the portal's explicit fresh authorization continuation. No response is read
  twice, and no generic 428/error triggers a request or fallback.
- Every other response/transport/parser failure remains unknown. An explicit
  read-only check can observe current state; it cannot retroactively prove the
  previous request executed or authorize repeating it.

## Exact-target, cookie-only observation

The new `portal_session_activation_confirmation_routes.py` exports `router`,
`POST_PATH`, `_frame_request` and `error`. The application wires its exact
`POST /api/auth/session/activation/confirmation` into bounded framing and the
cookie-only CSRF check before generic authentication/body handling.

The request is closed to `schema`, `purpose` and `localDigest`: schema
`catchplate.oidcSessionActivationConfirmationRequest/v1`, purpose
`confirm-current-oidc-session`. It is capped at 1 KiB, requires one exact
Content-Length and JSON content type, and rejects queries, encodings and extra
fields. The locator supplies no subject, session, token, checkpoint or authority.
Bearer/admin headers are rejected. Exact configured Origin and cookie CSRF are
required. The browser obtains the normal CSRF carrier via cookie-only `/api/csrf`
with no entered operator header; the confirmation itself changes no cookie.

One actual work/window and busy-owner refusal precede parsing. The existing
genuine finalization inspector's combined loader reserves the held request/auth
lane before retained body reads. Its actual original admission and separate
acknowledgment verifier authenticate the retained eight-field subject under the
independently configured cold owner. The browser cookie is looked up freshly,
not through the Request's cached authentication. Its user and session must match
that genuine subject; actual sole-credential history and a second current-cookie
lookup must agree on the retained credential. Current role/trust admission is
repeated, and original owner/lifetime checks surround native work and normal
owner/trust cleanup. The 64 MiB source representation ceiling is not a Python
heap, RSS, concurrency or runtime guarantee. FastAPI dispatches the synchronous
endpoint through its thread pool; the owner-lock acquisition refuses immediately
when busy, without claiming nonblocking filesystem, proof or database work.

The six-field response is schema
`catchplate.oidcSessionActivationConfirmationResponse/v1`, the same purpose and
locator, `status: current-target-active`, `sessionState: active` and
`automaticRetryAllowed: false`. Failure uses unknown session/status and never
echoes private errors. It exposes no user/session/credential IDs or token.

This reports that the **current cookie was observed active for the exact retained
target during this read**. It is not durable proof of which preceding action
delivered it, a future authentication guarantee, permission, private-store proof
or a reusable successful authority carrier. The generic `/api/auth/status`
cannot substitute: it exposes no retained-target/session association and could
otherwise mistake an unrelated active cookie for this target. No SQL, history
reconciliation, signing, effect socket, retry, old permission or expiry renewal
is introduced. Independent exact cold configuration and all external production
acceptance gates remain required.
