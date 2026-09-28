# Bounded activation HTTP adapter

Source only: unbuilt, unexecuted and unprovisioned. The new adapter connects
`POST /api/auth/session/activation` to the
[single-permission HTTP orchestrator](oidc-session-activation-public-http.md).
It does not create an authority, authenticate a posted identity or turn an
unsigned response into success. Existing activation permission/options and
registration routes retain their separate framing and behavior.

## Framing before parsing

The app's bounded-request middleware selects this exact path before its
older registration parsing branches. It requires POST, no query string,
exactly one `Content-Length` in canonical positive decimal form, and exactly
one `Content-Type: application/json`. Transfer-Encoding and Content-Encoding
are forbidden, including an explicit identity encoding. Charset parameters,
duplicate headers, leading-zero lengths and alternative media types are not
accepted. The declared body must contain 2–262,144 bytes.

The adapter checks every stream chunk against both the remaining declared
length and the 256 KiB limit **before** extending its bounded accumulator.
Short, overlong, interrupted and non-byte bodies are rejected. Only after
complete framing does it publish immutable original bytes in the actual
request's `oidc_session_activation_bytes` state slot. This slot carries data,
not identity, permission, processing allowance or a successful-result object.

No JSON graph is parsed in this middleware. The actual orchestrator consumes
the body using the [closed HTTP data contract](oidc-session-activation-http-contract.md),
including its separate permission assertion and planning assertion. The
adapter accepts no alternate already-parsed input or unbounded body fallback.

## Exact app and core connection

`control_plane_oidc_session_activation_routes.activate(request)` passes only
the actual Request and bounded original body to
`control_plane_oidc_session_activation_http._activate(request,
activation_bytes=original)`. It returns that actual response without rebuilding
the body, copying an error header, exposing a token or setting a cookie.

The route is async but invokes the bounded synchronous core directly. This
deliberately retains the original ASGI thread through permission processing,
cleanup and the final response-send guard; it does not transfer authority to
a worker thread or open another allowance. The call can block the control-plane
event loop within its bounded lifetime. This is not a throughput or concurrency
claim, and does not alter the separate Rust hot path.

The existing CSRF middleware still receives the actual Request. Its rejection
for this path uses the fixed pre-dispatch failure factory without copying
exception details or headers. The core independently checks the actual pending
cookie, CSRF, current identity and exact retained target before admission.
The existing permission/options route is not redirected through this adapter.

## Failure and cookie boundary

Method/framing refusals and missing bounded state are known pre-core failures.
They use `rejected-before-dispatch` with an unknown session state and
`automaticRetryAllowed: false`. Unsupported methods use 405, invalid framing
400, a body over the fixed cap 413 and an incorrect media type 415. The core's
central response helper restricts all selected status codes and always applies
`Cache-Control: no-store`, `Pragma: no-cache` and `X-Content-Type-Options: nosniff`.

The adapter does not catch a downstream exception and relabel it as a refusal.
The orchestrator marks the dispatch boundary before its first dispatch call;
later failure is outcome-unknown, not evidence of noncommit. No error path
clears or replaces the pending cookie, issues a retry or returns a token in
JSON. A successful cookie response must additionally pass the
[genuine delivery and final-send boundary](control-plane-oidc-session-activation-delivery.md).
Receiving a staging acknowledgment alone satisfies none of those conditions.

Provisioned resources, runtime evidence, separately authorized recovery and
portal integration remain outside this adapter. No test or deployment result
is claimed by this source connection.
