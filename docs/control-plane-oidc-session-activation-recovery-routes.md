# Bounded recovery options route

Source only, unbuilt and unexecuted. The sole new endpoint is
`POST /api/auth/session/activation/recovery/options`. There is no recovery
dispatch route, placeholder success response, automatic SQL retry or new
cookie. Existing activation and permission/options routes retain their behavior.

The request is strict immutable JSON of at most 64 KiB, with exactly `schema`,
`purpose` and `localDigest`. Schema is
`serverware.oidcSessionActivationRecoveryRequest/v1`; purpose is
`recover-oidc-session-activation`. Options reject MFA and all extra fields.
The locator selects retained originals; it is not caller identity or authority.

Before parsing, the app's dedicated branch requires POST, no query, one
canonical positive Content-Length, exact `application/json`, and no transfer
or content encoding. Every chunk is checked against the declared length and
64 KiB cap before accumulation; short, oversized and interrupted bodies fail.
Only completely framed immutable bytes enter the actual Request state slot
`oidc_session_activation_recovery_bytes`.

The recovery-specific CSRF branch uses the fixed double-submit cookie/header
check, with no bearer/admin bypass and no stale-token session lookup. The
actor repeats that check and requires exactly one Origin equal to configured
`WEBAUTHN_ORIGIN`; it does not derive trusted origin from the Host header.
The old OIDC cookie is possession evidence only. Missing or replaced old bytes
cannot be repaired by selecting a different session or reusing new-login data.

The async route directly invokes the bounded synchronous
`recovery_actor._options(request, recovery_bytes=original)` on the same ASGI
thread. This preserves original owner/work/clock guards, with the same bounded
control-plane event-loop blocking tradeoff as activation; no performance claim
or background retry is introduced.

The [actor](control-plane-oidc-session-activation-recovery-actor.md) freshly
authenticates historical target and possession, current RBAC, sole credential,
trust, exact session and provider expiry before issuing genuine action-bound
WebAuthn options. The response schema is
`serverware.oidcSessionActivationRecoveryOptions/v1`, with the exact target-key
publicKey data and action/payload binding. It is not recovery permission.

Failures use only the fixed recovery-unavailable contract: dispatch and session
states remain unknown, and automatic retry is false. Exception text, foreign
headers, keys and tokens are not returned. Success and failure responses use
no-store, no-cache and nosniff headers; neither changes the pending cookie.
An unavailable target or historical proof is not evidence of nonexecution.

The private fresh-assertion authorization context has no standalone public
success endpoint. A later source slice must connect an actual independently
authorized recovery effect owner and truthful delivery boundary.
