# OIDC session activation: explicit, truthful portal status

This is a source-only correction to the existing **Verify passkey** login flow
in [app.py](../serverware/app.py). It is not the protected registration F08
workflow, a new production activation endpoint, or evidence that deployment and
verification gates passed. No browser, build or runtime verification was run.

## Existing login ceremony

The existing button still obtains session-binding options from
`POST /api/auth/session/webauthn/options`, asks for a fresh WebAuthn assertion,
and sends it to `POST /api/auth/session/webauthn/verify`. The existing separately
consented first-enrollment and offline-recovery ceremonies before that assertion
remain unchanged. They are not invoked by finalization completion or recovery.

The server's existing session-binding helper checks the actual credential and
assertion. Its database transaction consumes the session-bound challenge,
compares the credential counter, rotates the browser token and binds the active
session. This existing login path is separate from protected finalization grant,
reservation, SQL and completion ownership. A retained locator or authenticated
historical completion acknowledgment cannot replace fresh session-binding proof.

## Cookie-scoped HTTP boundary

Both options and verification explicitly require the browser's CSRF cookie and
single matching header, even when another valid bearer/admin header is present.
They read pending-session state afresh rather than relying on the request cache;
current authoritative roles remain part of pending identity admission.

After the actual activation transaction, or explicit recovery of an existing
delivery, verification re-reads the rotated session and checks its active
identity, bound credential, current trust and authoritative roles before setting
the cookie. A late failure is reported as delivery unavailable with possible
prior commit and `automaticRetryAllowed: false`; it is not rollback evidence.
These are local admission/delivery checks, not a live external currentness lease
or the protected activation operation still required by F08.

## One verification dispatch

`verifyOIDCSessionPasskey()` sends the activation verification request once.
It no longer resends the same assertion after a transport `TypeError`. A
page-local busy guard disables overlapping activation/status actions; it is not
a server-side one-use guarantee.

After that dispatch, the portal reads `GET /api/auth/status` with same-origin
cookies and `cache: no-store`. It reports successful activation only when both:

- The verification response is exactly `{ok: true, authenticated: true}`.
- The fresh, shape-checked status reports `authenticated: true`,
  `sessionState: "active"` and `authMethod: "oidc-session"`.

A rejected, missing or malformed verification response is not presented as
successful dispatch, even if the subsequent status read independently reports
an active session. Missing, malformed or non-active current status cannot
produce an inferred `{authenticated: true}` result. These branches report an
unknown activation outcome and direct the operator to a read-only status check.
They never establish that activation did not happen or grant retry permission.

## Explicit read-only refresh

The header now has **Refresh session status**, created beside **Verify passkey**.
`refreshOIDCSessionActivationStatus()` performs only the status GET: it does not
request options, ask for an assertion, enroll a key, retry verification or invoke
activation-delivery recovery. The general **Refresh** button remains separate;
its workspace refresh was not an authentication-state read.

An actual active OIDC status is described as the server's current report. Other
valid status is described as not currently reporting an authenticated active
OIDC session, not proof that an earlier request failed. If the status read fails
or is invalid, the cached authentication display is discarded and the header
shows **Session state unknown**. Another explicit status refresh is safe; it
does not repeat a mutation. No assertion or recovery token is saved for retry.

## Remaining boundary

This change does not add retained-finalization target binding, protected session
activation execution, new caller permission, or production authority. Existing
backend delivery-recovery support is not automatically invoked by the portal.
The [finalization completion workflow](control-plane-finalization-completion.md)
still does not activate a browser session. The [F08 tracker](production-status.md)
remains the place to track the separate protected activation integration.

The status display is a point-in-time server observation, not a durable current
head proof or assurance against later revocation, expiry or RBAC changes.
