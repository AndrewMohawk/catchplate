"""Separate current-caller authorization for historical completion recovery.

The real historical subject is inspected before spending recovery permission;
the actual facade repeats ownership admission. Fixed existing auth helpers
retain WebAuthn, bootstrap, two-person and current-session checks. Neither
browser roots nor successful-verification carriers enter this route, and no
SQL execution/retry or credential-finalization action is dispatched.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from catchplate import control_plane_enrollment_startup as enrollment
from catchplate import control_plane_registration_handoff_routes as handoff_routes
from catchplate import control_plane_registration_recovery as recovery
from catchplate import control_plane_registration_recovery_http as contract
from catchplate import control_plane_registration_recovery_subject as subjects


router = APIRouter()
PATHS = frozenset({"/api/webauthn/register/recover-completion",
    "/api/auth/session/webauthn/register/recover-completion"})
HEADERS = handoff_routes.HEADERS


def error(status_code, code=None, *, local_digest=None):
    detail = contract.unavailable(local_digest)
    if code is not None:
        detail["error"] = code  # Only source-selected framing errors.
    return JSONResponse(status_code=status_code, headers=HEADERS, content={"detail": detail})


def _http_error(exc):
    if exc.status_code >= 500:
        return error(503)
    detail = exc.detail
    if type(detail) is dict:
        detail = {key: value for key, value in detail.items() if key != "retry"}
        detail["automaticRetryAllowed"] = False
    return JSONResponse(status_code=exc.status_code,
        headers={**(exc.headers or {}), **HEADERS}, content={"detail": detail})


def _payload(request):
    value = getattr(request.state, "registration_recovery_payload", None)
    if type(value) is not dict or value.get("purpose") != contract.PURPOSE:
        raise HTTPException(status_code=400, detail="registration recovery framing is required")
    return value


def _owner():
    owner = enrollment.require_started()
    if type(owner) is not enrollment._EnrollmentOwner or not owner.sql_handoff_enabled:
        raise HTTPException(status_code=503, detail="registration recovery is not enabled")
    return owner


def _subject(digest, user_id, session_id):
    subject = subjects.inspect_retained_registration_recovery_subject(digest)
    binding = contract.request_binding(subject)
    if (binding["localDigest"] != digest or binding["userId"] != user_id
            or binding["sessionId"] != session_id):
        raise HTTPException(status_code=403, detail="registration recovery ownership denied")
    return binding


def _dispatch(owner, digest, user_id, session_id):
    if _owner() is not owner:
        raise HTTPException(status_code=503, detail="registration recovery owner changed")
    result_digest, raw4 = recovery.recover_retained_registration_completion(
        digest, expected_user_id=user_id, expected_session_id=session_id)
    if result_digest != digest:
        raise ValueError("registration recovery returned another local record")
    return JSONResponse(status_code=202, headers=HEADERS,
        content=contract.accepted(result_digest, raw4))


@router.post("/api/webauthn/register/recover-completion", status_code=202)
def recover_operator(request: Request):
    from catchplate import app as application

    digest = None
    try:
        identity = application.require_role("admin", "approver")(
            application.require_admin(request,
                x_catchplate_admin_token=request.headers.get("X-Catchplate-Admin-Token")))
        payload = _payload(request)
        owner = _owner()
        with application.trust_bundle_lock(exclusive=False):
            current = application._registration_execution_current_operator(request, identity)
            binding = _subject(payload["localDigest"], current.user_id, None)
            digest = binding["localDigest"]
            had_history = bool(application.db.list_webauthn_credentials(current.user_id, include_revoked=True))
            if had_history:
                handoff_routes._permission(application, payload, binding, current)
            else:
                handoff_routes._bootstrap(application, payload)
            current = application._registration_execution_current_operator(request, current)
            if bool(application.db.list_webauthn_credentials(current.user_id, include_revoked=True)) != had_history:
                raise HTTPException(status_code=409, detail="registration recovery authorization branch changed")
            return _dispatch(owner, digest, current.user_id, None)
    except HTTPException as exc:
        return _http_error(exc)
    except Exception:
        return error(503, local_digest=digest)


@router.post("/api/auth/session/webauthn/register/recover-completion", status_code=202)
def recover_pending(request: Request):
    from catchplate import app as application

    digest = None
    try:
        application._require_registration_execution_session_csrf(request)
        _, session = application._pending_oidc_session_for_request(request, fresh=True)
        payload = _payload(request)
        owner = _owner()
        with application.trust_bundle_lock(exclusive=False):
            user_id, session_id = str(session["user_id"]), str(session["id"])
            if application.db.list_webauthn_credentials(user_id, include_revoked=True):
                raise HTTPException(status_code=409, detail="first enrollment is closed because credential history exists")
            fields = ("id", "user_id", "expires_at", "pending_expires_at")
            held_scope, held_roles = tuple(session[field] for field in fields), frozenset(session["roles"])
            binding = _subject(payload["localDigest"], user_id, session_id)
            digest = binding["localDigest"]
            handoff_routes._bootstrap(application, payload)
            _, current = application._pending_oidc_session_for_request(request, fresh=True)
            if (tuple(current[field] for field in fields) != held_scope
                    or frozenset(current["roles"]) != held_roles):
                raise HTTPException(status_code=409, detail="registration recovery session changed")
            if application.db.list_webauthn_credentials(user_id, include_revoked=True):
                raise HTTPException(status_code=409, detail="first enrollment is closed because credential history exists")
            return _dispatch(owner, digest, user_id, session_id)
    except HTTPException as exc:
        return _http_error(exc)
    except Exception:
        return error(503, local_digest=digest)
