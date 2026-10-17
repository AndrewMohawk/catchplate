# Activation current-auth and final cookie boundary

[The final delivery module](../catchplate/control_plane_oidc_session_activation_delivery.py)
owns the last token acquisition, current-session admission and cookie emission
for the actual public activation orchestrator. It does not reuse the legacy
direct-SQL activation or recovery-token path. Source wiring is not deployed or
runtime-verified evidence.

## Live call, not a token result carrier

`_response_on_permission(permission)` accepts only the actual active
`_ActivationPermission`, after its source-owned proof continuation. The helper
calls `permission.acquire_and_release_token(_delivery=boundary)` itself. No
token is returned to the orchestrator, accepted from the browser, put in JSON,
logged or appended to a journal.

The acquisition/handoff private `_delivery` argument carries only this exact
source-owned finishing object. The real response verifier's optional
`_retain_current` hook exports its actual final `current` closure and narrowed
window/deadline after all original joins and token-commitment verification.
The callback return is never authority; the default verifier remains a
token-only return. Its work identity, ceilings and nondecreasing counters are
checked around retention.

That real guard retains the freshly admitted client/server, intent and proof
guards, not only the older permission clock. While permission remains active,
its source-selected continuation runs the original handoff and permission
checks. There is no cycle from `permission._current` back into the receiver.

## Fresh active identity and staged cookie

The helper holds the actual retained user ID, session ID, public credential ID,
credential-record identity and current scope before final acquisition. Under
the genuine receiver guard it invokes the application's real
`oidc_browser_session_from_token` and `oidc_identity_from_browser_session`.
It requires the exact active session/user/credential record, unchanged retained
credential identity, nondecreasing counter, non-revoked state, current
authoritative roles and current credential trust. Active expiry and provider
expiry must still match the retained session and remain live.

The only success body is `{"ok": true, "authenticated": true}`. The token enters
only the staged `catchplate_oidc_session` cookie: HttpOnly, SameSite=Strict,
path `/`, Secure for an HTTPS request, and positive Max-Age derived from the
fresh actual session/provider expiry and the original guarded epoch. The
helper does not replace the old cookie on failure and does not create retry
authority.

The returned `_StagedResponse` is a private finishing owner, not an incoming
success DTO. The orchestrator calls `finish()` only after the permission context
exits normally. `finish()` requires `_normal_exit is True`, which is set only
after the final permission check and successful trust/lock cleanup. It also
requires the exact closed permission and unchanged actual owner/resources.
The process-wide enrollment owner is not closed.

After cleanup, the boundary never calls the revoked permission. It retains the
actual source-owned cold scope/resource continuity, exact final receiver
window/deadline, clock floors and original consume-launch intervals. Every
receiver child guard remains active, and the narrower final clock check stays
last. No fresh bracket, work budget or permission is opened.

## Actual signed-ASGI emission

The route is asynchronous and invokes the bounded synchronous orchestrator
directly, keeping the original PID/thread through permission, cleanup and the
outer signed-ASGI send. This deliberately bounds a blocking control-plane
operation; it is not a high-concurrency or runtime performance claim. No thread
check is disabled and no live permission is transferred to another worker.

The signed response wrapper may buffer, add security headers and sign after
route return. It therefore calls `_send_response` at the real send boundary.
A source-owned registration in the exact request scope binds status, body and
the sole exact cookie header. Immediately before `http.response.start`, the
boundary checks the full retained receiver/resource guards and claims the one
emission. An unrelated response cannot supply a callback or successful object
to gain this path; an activation success without its finishing owner fails
closed.

Before any header is sent, failed guard/framing or downstream uncertainty is
projected to fixed `outcome_unknown`, HTTP 503, with no cookie and no stale
success signature. A known invalid response nonce before dispatch gets the
fixed pre-dispatch rejection. The unknown fallback is not re-signed using a
renewed activation allowance. Once header send begins, any send failure is
terminal: no second headers, replacement response, token resend or automatic
retry is attempted. The staged references are discarded even if buffering or
signing fails before the final send helper is reached.

The pending browser cookie is preserved on uncertainty. Independent resource
provisioning, deployment, runtime verification and separately authorized
recovery remain separate acceptance work.
