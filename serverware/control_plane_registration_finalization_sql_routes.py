"""Separate fresh present permission for one retained finalization execution.

Original ownership is genuinely inspected before permission and repeated by
the real facade under the cold owner lock. Preparation, reservation and earlier
evidence execution permission do not authorize this action. Only source-fixed
handlers select the actual facade; no posted proof, actor, key or root is used.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import control_plane_enrollment_startup as enrollment
from serverware import control_plane_registration_handoff_routes as permission
from serverware import control_plane_registration_finalization_handoff as handoff
from serverware import control_plane_registration_finalization_sql_http as contract


router = APIRouter()
PATHS = frozenset({"/api/webauthn/register/execute-finalization",
    "/api/auth/session/webauthn/register/execute-finalization"})
HEADERS = permission.HEADERS


def error(status_code, code=None, *, local_digest=None):
    detail = contract.unavailable(local_digest)
    if code is not None:
        detail["error"] = code  # Source-selected framing code, never exception text.
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
    value = getattr(request.state, "registration_finalization_sql_payload", None)
    if type(value) is not dict or value.get("purpose") != contract.PURPOSE:
        raise HTTPException(status_code=400, detail="finalization execution framing is required")
    return value


def _owner():
    owner = enrollment.require_started()
    if (type(owner) is not enrollment._EnrollmentOwner
            or not owner.sql_handoff_enabled or not owner.finalization_sql_enabled):
        raise HTTPException(status_code=503, detail="finalization execution is disabled")
    return owner


def _subject(digest, user_id, session_id):
    binding = contract.request_binding(handoff.inspect_retained_finalization_sql_subject(digest))
    if (binding["localDigest"] != digest or binding["userId"] != user_id
            or binding["sessionId"] != session_id
            or (binding["mode"] == "oidc-session-first-enrollment") != (session_id is not None)):
        raise HTTPException(status_code=403, detail="finalization execution ownership denied")
    return binding


def _dispatch(owner, digest, user_id, session_id):
    if _owner() is not owner:
        raise HTTPException(status_code=503, detail="finalization execution owner changed")
    returned_digest, raw4 = handoff.execute_retained_registration_finalization(
        digest, expected_user_id=user_id, expected_session_id=session_id)
    if returned_digest != digest:
        raise ValueError("finalization execution returned another original grant locator")
    return JSONResponse(status_code=202, headers=HEADERS,
        content=contract.accepted(returned_digest, raw4))


@router.post("/api/webauthn/register/execute-finalization", status_code=202)
def execute_operator(request: Request):
    from serverware import app as application

    digest = None
    try:
        identity = application.require_role("admin", "approver")(
            application.require_admin(request,
                x_serverware_admin_token=request.headers.get("X-Serverware-Admin-Token")))
        payload, owner = _payload(request), _owner()
        with application.trust_bundle_lock(exclusive=False):
            current = application._registration_execution_current_operator(request, identity)
            binding = _subject(payload["localDigest"], current.user_id, None)
            digest = binding["localDigest"]
            had_history = bool(application.db.list_webauthn_credentials(current.user_id, include_revoked=True))
            if had_history:
                permission._permission(application, payload, binding, current)
            else:
                permission._bootstrap(application, payload)
            current = application._registration_execution_current_operator(request, current)
            if bool(application.db.list_webauthn_credentials(current.user_id, include_revoked=True)) != had_history:
                raise HTTPException(status_code=409, detail="finalization execution authorization branch changed")
            return _dispatch(owner, digest, current.user_id, None)
    except HTTPException as exc:
        return _http_error(exc)
    except Exception:
        return error(503, local_digest=digest)


@router.post("/api/auth/session/webauthn/register/execute-finalization", status_code=202)
def execute_pending(request: Request):
    from serverware import app as application

    digest = None
    try:
        application._require_registration_execution_session_csrf(request)
        _, session = application._pending_oidc_session_for_request(request, fresh=True)
        payload, owner = _payload(request), _owner()
        with application.trust_bundle_lock(exclusive=False):
            user_id, session_id = str(session["user_id"]), str(session["id"])
            if application.db.list_webauthn_credentials(user_id, include_revoked=True):
                raise HTTPException(status_code=409, detail="first enrollment is closed because credential history exists")
            fields = ("id", "user_id", "expires_at", "pending_expires_at")
            held_scope, held_roles = tuple(session[field] for field in fields), frozenset(session["roles"])
            binding = _subject(payload["localDigest"], user_id, session_id)
            digest = binding["localDigest"]
            permission._bootstrap(application, payload)
            _, current = application._pending_oidc_session_for_request(request, fresh=True)
            if (tuple(current[field] for field in fields) != held_scope
                    or frozenset(current["roles"]) != held_roles):
                raise HTTPException(status_code=409, detail="finalization execution session changed")
            if application.db.list_webauthn_credentials(user_id, include_revoked=True):
                raise HTTPException(status_code=409, detail="first enrollment is closed because credential history exists")
            return _dispatch(owner, digest, user_id, session_id)
    except HTTPException as exc:
        return _http_error(exc)
    except Exception:
        return error(503, local_digest=digest)
