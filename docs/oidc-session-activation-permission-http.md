# Activation permission options

This source slice exposes only
`POST /api/auth/session/activation/permission/options`. It obtains a fresh
action-bound WebAuthn challenge for the exact retained activation target. It
does not consume an assertion, sign activation permission, activate or recover a
session, return a token, or change portal behavior.

The bounded strict JSON body has exactly two fields:

```json
{"purpose":"authorize-oidc-session-activation","localDigest":"sha256:<64 lowercase hexadecimal characters>"}
```

`localDigest` is a retained finalization locator, not proof or permission.
The fixed application performs exact HTTP framing and retains the immutable
body in `request.state.oidc_session_activation_permission_bytes`. The route
passes that original and the actual request to the permission core; it accepts
no posted actor, session, credential, roots, policy, key or successful subject
object. Bodies are limited to 64 KiB. Query parameters, alternate carriers and
bootstrap authorization are not part of this endpoint.

The core uses genuine current pending-cookie authentication and explicit CSRF
checking, including when an unrelated bearer header is present. Under the real
trust lock it authenticates the retained finalization originals and their
acknowledgment, joins the exact current user/session and sole finalized
credential, and rechecks current session, credential and owner continuity.
Historical completion supplies target provenance only, never new permission.

The action is `webauthn.oidc-session.activation.authorize`. Its distinct
`catchplate.oidcSessionActivationPermissionIntent/v1` binding includes the
retained locator, user, pending session, challenge, request, operation, mode and
credential. Only the actual fresh challenge/options for that exact credential
are returned under `catchplate.oidcSessionActivationPermissionOptions/v1`.
The response is no-store and grants no automatic retry or activation success.

The shared carrier parser also recognizes private permission input with an
optional `mfa` containing only `assertion` and `approvalId`. That shape is not a
public permission-success route and is not authority. The private, live
parent-owned permission context verifies the target-key assertion and configured
independent approval before a new activation plan is generated within that
same call. This ordering preserves the real assertion's credential-counter
update; a pre-permission plan cannot stand in for the post-permission state.
The context permits one signing step and is not accepted as an input proof.
Public dispatch must still be connected separately; neither old options nor a
previously successful permission response can substitute.

Public activation dispatch, public recovery and portal actions remain separate
steps 22–26. This is authored source integration, not a built or executed
endpoint, installed service or production acceptance evidence.
