# Exact retained-target activation permission

[`control_plane_oidc_session_activation_permission.py`](../catchplate/control_plane_oidc_session_activation_permission.py)
connects fresh pending-session ownership to the genuine retained finalization
target. The [bounded public adapter](oidc-session-activation-permission-http.md)
exposes **options only**. There is no permission-success POST, reusable approval
result, public activation/recovery dispatch or token release in this slice.
This is authored source, unbuilt, unexecuted and unprovisioned.

## Actual target and present authority

The core accepts the actual HTTP request and bounded original JSON bytes, not
a posted user, session, credential, successful subject object or policy graph.
The fixed action is `webauthn.oidc-session.activation.authorize`; its purpose is
`authorize-oidc-session-activation`. Only an unbound pending OIDC session with
the actual current admin/approver role is eligible. The genuine session-cookie
CSRF check is mandatory; an unrelated bearer header is not a substitute.

The actual cold owner's retained-target inspector replays original ownership
and the retained acknowledged finalization completion on the same work/window.
Its exact eight-field subject becomes a closed action binding containing the
retained local digest, user/session, first-enrollment mode, challenge, request,
operation and credential identities. An uncertain or missing acknowledgment
cannot become permission or trigger completion recovery.

The current database must contain exactly the sole retained credential for
that user. Identity, trust/revocation fields and the current signature counter
are held and rechecked, along with the complete pending-session scope and roles.
Empty history, a second credential, revocation or ownership drift fails closed;
there is no first-enrollment bootstrap-token or operator/null-session fallback.
The fixed trust read-lock remains held during the operation.

`_options(request, permission_bytes=...)` opens one source-bounded processing
allowance and issues the real mutation challenge for the exact action, retained
challenge ID and full binding digest. The resulting `allowCredentials` must
contain only the retained credential. Only ordinary challenge/options fields
are returned under `catchplate.oidcSessionActivationPermissionOptions/v1`.
Options consume no assertion and grant no authority to a later action.

## Useful same-call continuation

The [private cold composition](control-plane-oidc-session-activation-execution.md)
consumes the original target-key assertion and configured two-person approval
inside a live parent-owned context. The real assertion verifier checks the
action/resource/payload commitment, claims its one-use challenge and performs
the credential-counter CAS. The approval path genuinely checks and consumes
the exact action-bound approval when policy requires it. No returned success
dictionary is accepted in place of either original admission.

That counter update is why permission must precede activation planning. A
standalone endpoint that consumes the assertion and discards its result would
not give the later planner useful authority. Instead, the future fixed step-22
composition obtains its post-counter-update plan inside the same active call,
then invokes the context's one-use exact-original authorization method.

The pending-session expiries can only shorten the original processing window.
Actual owner resources, original receipt and present session/credential facts
remain checked around native work and signing. This is local authority under
the existing trust roots, not independent hardware measurement or proof of
latest off-host state. Failed/expired permission does not permit an automatic
retry. Public activation/recovery, portal integration and all independent
production gates remain separate.
