# Bounded recovery routes

Source only, unbuilt and unexecuted. The existing
`POST /api/auth/session/activation/recovery/options` keeps its options-only
behavior. The separate `POST /api/auth/session/activation/recovery` enters the
actual one-context recovery and terminal delivery path. Existing activation and
permission/options routes retain their behavior; neither recovery route retries
activation or SQL.

The request is strict immutable JSON of at most 64 KiB, requiring `schema`,
`purpose` and `localDigest`. Schema is
`catchplate.oidcSessionActivationRecoveryRequest/v1`; purpose is
`recover-oidc-session-activation`. Options reject MFA and all extra fields;
dispatch permits only the separate optional `mfa` assertion/approval carrier,
which the actual actor must authenticate. Neither route accepts browser root
originals, grant/proof/outcome objects, target identities or posted tokens.
The locator selects retained originals; it is not caller identity or authority.

Before parsing, the app's dedicated branch requires POST, no query, one
canonical positive Content-Length, exact `application/json`, and no transfer
or content encoding. Every chunk is checked against the declared length and
64 KiB cap before accumulation; short, oversized and interrupted bodies fail.
`_frame_request` selects only those two exact paths, not a path supplied inside
the body. Only completely framed immutable bytes enter the actual Request state slot
`oidc_session_activation_recovery_bytes`.

The recovery-specific CSRF branch uses the fixed double-submit cookie/header
check, with no bearer/admin bypass and no stale-token session lookup. The
actor repeats that check and requires exactly one Origin equal to configured
`WEBAUTHN_ORIGIN`; it does not derive trusted origin from the Host header.
The old OIDC cookie is possession evidence only. Missing or replaced old bytes
cannot be repaired by selecting a different session or reusing new-login data.

Both async routes directly invoke their bounded synchronous core on the same
ASGI thread: options calls `recovery_actor._options(request, recovery_bytes=original)`;
dispatch calls `recovery_http._recover(request, recovery_bytes=original)`.
This preserves original owner/work/clock guards, with the same bounded
control-plane event-loop blocking tradeoff as activation; no performance claim
or background retry is introduced.

The [actor](control-plane-oidc-session-activation-recovery-actor.md) freshly
authenticates historical target and possession, current RBAC, sole credential,
trust, exact session and provider expiry before issuing genuine action-bound
WebAuthn options. The response schema is
`catchplate.oidcSessionActivationRecoveryOptions/v1`, with the exact target-key
publicKey data and action/payload binding. It is not recovery permission.

Options failures retain the fixed recovery-unavailable contract. POST framing
refusals use the fixed pre-acquisition rejection shape; once private acquisition
starts, the [orchestrator](control-plane-oidc-session-activation-recovery-http.md)
uses only an unknown-outcome failure. All failure projections have unknown
session state and forbid automatic retry; they preserve the existing cookie.
Exception text, foreign headers, keys and tokens are not returned. Every
response uses no-store, no-cache and nosniff headers. An unavailable target or
historical proof is not evidence of nonexecution.

The POST tail-returns only the actual terminal delivery owner's response after
normal cleanup. That owner, not a route DTO, handles verified-token current-auth,
the single replacement cookie and the final signed send guard. There is no
standalone successful permission endpoint. Prior-stage completion recovery,
resource provisioning and production acceptance remain separate work.
