"""Present pending-session permission for finalization completion, never SQL.

An already committed first credential changes the permission branch, not the
original enrollment rule. Only a genuine retained subject selects that exact
credential. Empty history still requires fresh bootstrap; existing history
requires its live key and the configured independent approval.
"""
from __future__ import annotations

from fastapi import HTTPException
from fastapi.responses import JSONResponse


OPTIONS_SCHEMA = "serverware.webAuthnRegistrationFinalizationPermissionOptions/v1"
_SESSION_FIELDS = ("id", "user_id", "token_digest", "oidc_token_digest", "status",
    "provider_expires_at", "expires_at", "pending_expires_at", "created_at",
    "activated_at", "revoked_at", "bound_webauthn_credential_id",
    "activation_trust_bundle_digest", "activation_trust_bundle_sequence",
    "activation_authenticator_class")
_UNBOUND_FIELDS = ("activated_at", "revoked_at", "bound_webauthn_credential_id",
    "activation_trust_bundle_digest", "activation_trust_bundle_sequence",
    "activation_authenticator_class")
_COUNTER_FIELDS = frozenset({"sign_count", "last_used_at", "updated_at"})


def _deny(message, status=409):
    raise HTTPException(status_code=status, detail=message)


def _hold(value):
    """Snapshot the actual row's bounded scalar/list values without callbacks."""
    if value is None:
        return ("null",)
    if type(value) is bool:
        return ("boolean", value)
    if type(value) is int and -(1 << 63) <= value < (1 << 64):
        return ("integer", value)
    if type(value) is str and len(value) <= 64 * 1024:
        return ("text", value)
    if type(value) is list and len(value) <= 64:
        if any(type(item) is list for item in value):
            _deny("finalization permission row shape is invalid")
        return ("list", tuple(_hold(item) for item in value))
    _deny("finalization permission row shape is invalid")


def _session(application, request):
    _, session = application._pending_oidc_session_for_request(request, fresh=True)
    if (type(session) is not dict or session.get("status") != "pending_webauthn"
            or any(session.get(field) is not None for field in _UNBOUND_FIELDS)):
        _deny("finalization completion requires an unbound pending session")
    # The fresh helper has already performed DB-time expiry and authoritative
    # RBAC checks. Repeat actual role admission, not a browser identity carrier.
    identity = application.require_role("admin", "approver")(
        application.oidc_pending_session_identity(session))
    for field in ("id", "user_id", "expires_at", "pending_expires_at"):
        if type(session.get(field)) is not str or not 1 <= len(session[field]) <= 4096:
            _deny("finalization permission session scope is invalid")
    if identity.user_id != session["user_id"]:
        _deny("finalization permission session user differs", 403)
    snapshot = tuple(_hold(session[field]) for field in _SESSION_FIELDS)
    return session, identity, (snapshot, identity.roles)


def _credential(row, user_id, credential_id):
    if (type(row) is not dict or not 1 <= len(row) <= 64
            or any(type(key) is not str for key in row)
            or row.get("user_id") != user_id or row.get("credential_id") != credential_id
            or type(row.get("id")) is not str or not 1 <= len(row["id"]) <= 4096
            or "revoked_at" not in row or row["revoked_at"] is not None):
        _deny("finalization completion target credential is unavailable")
    count = row.get("sign_count")
    if type(count) is not int or not 0 <= count <= 0xffffffff:
        _deny("finalization completion target counter is invalid")
    # Preserve every actual identity/trust/revocation field. The real assertion
    # CAS changes only these three counter/bookkeeping columns.
    identity = tuple((key, _hold(row[key])) for key in sorted(row)
        if key not in _COUNTER_FIELDS)
    return row["id"], identity, count


def _history(application, user_id, credential_id):
    history = application.db.list_webauthn_credentials(
        user_id, include_revoked=True, limit=2)
    target = application.db.get_webauthn_credential(credential_id, include_revoked=True)
    if type(history) is not list or len(history) > 2:
        _deny("finalization permission credential history is invalid")
    if not history:
        if target is not None:
            _deny("finalization completion target has inconsistent ownership", 403)
        return None
    if len(history) != 1 or target is None:
        _deny("finalization completion requires the sole retained target credential")
    held = _credential(history[0], user_id, credential_id)
    if held != _credential(target, user_id, credential_id):
        _deny("finalization completion target changed during inspection")
    return held


def _recheck(application, request, binding, session_scope, credential, count):
    _, identity, current_scope = _session(application, request)
    if current_scope != session_scope:
        _deny("finalization completion pending session changed")
    current = _history(application, binding["userId"], binding["credentialId"])
    expected = None if credential is None else (credential[0], credential[1], count)
    if current != expected:
        _deny("finalization completion credential state changed")
    return identity


def _assertion(application, payload, binding, credential, payload_digest):
    if payload.get("bootstrapToken") is not None:
        _deny("bootstrap cannot replace existing-credential authorization", 400)
    mfa = payload.get("mfa")
    assertion = None if mfa is None else mfa.get("assertion")
    if not assertion:
        _deny({"error": "control_plane_webauthn_required",
            "message": "Fresh target-key WebAuthn assertion required for finalization completion",
            "action": binding["action"], "resourceId": binding["challengeId"],
            "payloadDigest": payload_digest}, 412)
    # Select only the genuine retained target before the real verifier spends
    # the challenge. Conflicting id/rawId values are not alternative selectors.
    selectors = [assertion[field] for field in ("id", "rawId") if field in assertion]
    if not selectors or any(value != binding["credentialId"] for value in selectors):
        _deny("finalization completion assertion target differs", 403)
    try:
        verified = application.verify_control_plane_mutation_assertion(
            user_id=binding["userId"], action=binding["action"],
            resource_id=binding["challengeId"], payload_digest=payload_digest,
            authn_policy=application._control_plane_mutation_authn_policy(), assertion=assertion)
    except application.WebAuthnError:
        _deny("finalization completion MFA denied", 403)
    if (type(verified) is not dict or verified.get("user_id") != binding["userId"]
            or verified.get("credential_id") != binding["credentialId"]
            or verified.get("credential_record_id") != credential[0]
            or type(verified.get("sign_count")) is not int
            or not 0 <= verified["sign_count"] <= 0xffffffff
            or not (verified["sign_count"] == credential[2] == 0
                or verified["sign_count"] > credential[2])):
        _deny("finalization completion verified assertion scope differs", 403)
    return verified["sign_count"]


def _options(application, binding, payload_digest):
    try:
        issued = application.control_plane_mutation_options(
            user_id=binding["userId"], action=binding["action"],
            resource_id=binding["challengeId"], payload_digest=payload_digest,
            authn_policy=application._control_plane_mutation_authn_policy(), approval_context=None)
    except application.WebAuthnError:
        _deny("finalization completion target has no eligible WebAuthn credential", 403)
    public_key = issued["publicKey"]
    if (type(public_key) is not dict or set(public_key) != {
            "challenge", "rpId", "allowCredentials", "timeout", "userVerification"}):
        _deny("finalization completion options shape changed")
    allowed = public_key["allowCredentials"]
    if (type(allowed) is not list or len(allowed) != 1
            or type(allowed[0]) is not dict or allowed[0].get("type") != "public-key"
            or allowed[0].get("id") != binding["credentialId"]):
        _deny("finalization completion options target changed")
    # Return the real challenge/options, but never the helper's additional
    # challenge-row or payload metadata. No activation challenge is issued.
    return {"schema": OPTIONS_SCHEMA, "purpose": binding["purpose"],
        "localDigest": binding["localDigest"], "action": binding["action"],
        "resourceId": binding["challengeId"], "payloadDigest": payload_digest,
        "publicKey": public_key, "automaticRetryAllowed": False}


def _handle(request, *, recovery, options=False):
    from serverware import app as application
    from serverware import control_plane_registration_handoff_routes as permission
    from serverware import control_plane_registration_finalization_completion_routes as routes

    digest = None
    try:
        if type(recovery) is not bool or type(options) is not bool:
            _deny("finalization completion mode is not source selected", 400)
        application._require_registration_execution_session_csrf(request)
        payload = routes._payload(request, recovery=recovery, options=options)
        owner = routes._owner()
        with application.trust_bundle_lock(exclusive=False):
            session, _, session_scope = _session(application, request)
            binding = routes._subject(payload["localDigest"], session["user_id"],
                session["id"], recovery=recovery)
            if binding["mode"] != "oidc-session-first-enrollment":
                _deny("finalization completion pending ownership differs", 403)
            digest = binding["localDigest"]
            credential = _history(application, binding["userId"], binding["credentialId"])
            count = None if credential is None else credential[2]
            _recheck(application, request, binding, session_scope, credential, count)
            payload_digest = application._control_plane_payload_digest(binding)
            if options:
                if credential is None:
                    _deny("empty credential history requires fresh bootstrap, not MFA options")
                result = _options(application, binding, payload_digest)
                _recheck(application, request, binding, session_scope, credential, count)
                if routes._owner() is not owner:
                    _deny("finalization completion owner changed", 503)
                return JSONResponse(status_code=200, headers=routes.HEADERS, content=result)
            if credential is None:
                permission._bootstrap(application, payload)
            else:
                count = _assertion(application, payload, binding, credential, payload_digest)
                identity = _recheck(application, request, binding, session_scope, credential, count)
                application._require_control_plane_two_person(action=binding["action"],
                    resource_id=binding["challengeId"], payload_digest=payload_digest,
                    mfa=payload.get("mfa"), identity=identity, request=binding)
            _recheck(application, request, binding, session_scope, credential, count)
            return routes._dispatch(owner, digest, binding["userId"], binding["sessionId"],
                recovery=recovery)
    except HTTPException as exc:
        return routes._http_error(exc, recovery=recovery)
    except Exception:
        return routes.error(503, recovery=recovery, local_digest=digest)
