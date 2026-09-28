# Recovery current-auth and final delivery

`control_plane_oidc_session_activation_recovery_delivery.py` is the source-owned
terminal for the recovery HTTP path. The actual active acquisition constructs
no public permission or token DTO. The terminal is selected before the genuine
exchange derivation, not installed afterward around a copied token.

The protected exchange still re-derives its originals and genuinely verifies
the exact response after normal socket close. Its full receiving guard is held
both by the live acquisition and, independently, by this exact terminal. The
receiver's ancestor never calls its own child. Ordinary private acquisition
continues to reject all use after close.

Before constructing a response, the helper uses the verified token with the
real browser-session authentication entrypoint. It requires the same original
user/session, active status, new-token digest, sole credential and assertion
counter, roles, trust and unchanged session/provider expiry. The old cookie is
only the original possession input, never current identity. Fixed source-known
authentication/snapshot capacity is reserved before exchange; actual work is
charged to the same ledger. This is byte-representation accounting, not a heap
or runtime performance guarantee.

Only successful post-yield guards, actor/trust cleanup and startup lock release
set both normal-exit markers. The terminal then checks the exact cleared state
and retained association. It does not call a closed actor/acquisition guard:
the original owner/resource scope, target-history guard, independent original
source guard, request/policy pins and final receiver restrictions remain in the
same PID/thread and original clock allowance. Fresh exact target, credential,
RBAC and trust checks also run at finish and immediately before sending.

Success is fixed nonsecret JSON: recovery response schema/purpose,
`status: recovered`, `sessionState: active`, and
`automaticRetryAllowed: false`. There is exactly one session cookie, with
HttpOnly, Strict SameSite, `/` path, Secure on HTTPS, and a remaining-lifetime
max-age bounded by the unchanged session/provider expiry. The original
processing/delivery window separately bounds the actual send; it is never
renewed to issue the cookie. Responses are no-store, no-cache and nosniff.
No token appears in JSON, logs or journal records.

The signed ASGI owner invokes `_send_response` after signing. The terminal
checks the exact body/status/cookie and genuine current guards before consuming
one send latch. Pre-send uncertainty discards the stale signed success and
cookie and emits only a fixed cookie-free unknown 503, without re-signing or
retry. Once headers have started there is no fallback or second response.
Cleanup failure never delivers the staged cookie.

This is source-only wiring, unbuilt and unexecuted. It does not prove worker
readiness, durable outcome existence, deployment provisioning or browser
delivery. Recovery of an earlier incomplete stage remains a separate path.
