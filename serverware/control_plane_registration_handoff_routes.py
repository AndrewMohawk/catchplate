"""Explicit retained-original actions, separate from reserve and finalization.

The fixed application owns real auth/session/CSRF, trust locking and approval.
No injected verifier, parallel expected roots or successful subject DTO is
accepted. Genuine ownership replay precedes purpose admission and is repeated
inside the actual handoff against authenticated user/session scalars.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import control_plane_registration_handoff as handoff
from serverware import control_plane_registration_handoff_http as contract
from serverware import control_plane_registration_handoff_subject as subjects
from serverware import control_plane_enrollment_startup as enrollment


router = APIRouter()
EXECUTE_PATHS = frozenset({"/api/webauthn/register/execute-retained",
    "/api/auth/session/webauthn/register/execute-retained"})
COMPLETE_PATHS = frozenset({"/api/webauthn/register/complete-retained",
    "/api/auth/session/webauthn/register/complete-retained"})
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"}


def error(status_code, code=None, *, completion, local_digest=None):
    detail = contract.unavailable(local_digest, completion=completion)
    if code is not None:
        detail["error"] = code  # Source-selected strings only, never exception text.
    return JSONResponse(status_code=status_code, headers=HEADERS, content={"detail": detail})


def _http_error(exc, *, completion):
    if exc.status_code >= 500:
        return error(503, completion=completion)
    detail = exc.detail
    if type(detail) is dict:
        detail = {key: value for key, value in detail.items() if key != "retry"}
        detail["automaticRetryAllowed"] = False
    return JSONResponse(status_code=exc.status_code,
        headers={**(exc.headers or {}), **HEADERS}, content={"detail": detail})


def _payload(request, completion):
    value = getattr(request.state, "registration_handoff_payload", None)
    if type(value) is not dict or value.get("purpose") != (
            contract.COMPLETE_PURPOSE if completion else contract.EXECUTE_PURPOSE):
        raise HTTPException(status_code=400, detail="registration handoff framing is required")
    return value


def _owner():
    owner = enrollment.require_started()
    if type(owner) is not enrollment._EnrollmentOwner or not owner.sql_handoff_enabled:
        raise HTTPException(status_code=503, detail="registration handoff is not enabled")
    return owner


def _subject(digest, user_id, session_id, *, completion):
    subject = subjects.inspect_retained_registration_subject(digest)
    binding = contract.request_binding(subject, completion=completion)
    if (binding["localDigest"] != digest or binding["userId"] != user_id
            or binding["sessionId"] != session_id):
        raise HTTPException(status_code=403, detail="registration handoff ownership denied")
    return binding


def _bootstrap(application, payload):
    if payload.get("mfa") is not None:
        raise HTTPException(status_code=400, detail="first enrollment requires bootstrap authorization, not mfa")
    application._require_registration_execution_bootstrap(payload.get("bootstrapToken"))


def _permission(application, payload, binding, identity):
    if payload.get("bootstrapToken") is not None:
        raise HTTPException(status_code=400, detail="bootstrap cannot replace existing-credential authorization")
    digest = application._control_plane_payload_digest(binding)
    action, resource_id = binding["action"], binding["challengeId"]
    mfa = payload.get("mfa")
    assertion = None if mfa is None else mfa.get("assertion")
    if not assertion:
        raise HTTPException(status_code=412, detail={
            "error": "control_plane_webauthn_required",
            "message": "Fresh WebAuthn assertion required for this registration handoff",
            "action": action, "resourceId": resource_id, "payloadDigest": digest})
    try:
        application.verify_control_plane_mutation_assertion(user_id=identity.user_id,
            action=action, resource_id=resource_id, payload_digest=digest,
            authn_policy=application._control_plane_mutation_authn_policy(), assertion=assertion)
    except application.WebAuthnError:
        raise HTTPException(status_code=403, detail="registration handoff MFA denied") from None
    application._require_control_plane_two_person(action=action, resource_id=resource_id,
        payload_digest=digest, mfa=mfa, identity=identity, request=binding)


def _dispatch(owner, digest, user_id, session_id, *, completion):
    if _owner() is not owner:
        raise HTTPException(status_code=503, detail="registration handoff owner changed")
    call = (handoff.request_retained_registration_completion if completion
        else handoff.execute_retained_registration)
    result_digest, raw4 = call(digest, expected_user_id=user_id, expected_session_id=session_id)
    if result_digest != digest:
        raise ValueError("registration handoff returned another local record")
    return JSONResponse(status_code=202, headers=HEADERS,
        content=contract.accepted(result_digest, raw4, completion=completion))


def _operator(request, *, completion):
    # Import the fixed application only at runtime: this module's router is
    # registered during application construction, without a cyclic auth clone.
    from serverware import app as application

    digest = None
    try:
        identity = application.require_role("admin", "approver")(
            application.require_admin(request,
                x_serverware_admin_token=request.headers.get("X-Serverware-Admin-Token")))
        payload = _payload(request, completion)
        owner = _owner()
        with application.trust_bundle_lock(exclusive=False):
            current = application._registration_execution_current_operator(request, identity)
            binding = _subject(payload["localDigest"], current.user_id, None, completion=completion)
            digest = binding["localDigest"]
            had_history = bool(application.db.list_webauthn_credentials(current.user_id, include_revoked=True))
            if had_history:
                _permission(application, payload, binding, current)
            else:
                _bootstrap(application, payload)
            current = application._registration_execution_current_operator(request, current)
            if bool(application.db.list_webauthn_credentials(current.user_id, include_revoked=True)) != had_history:
                raise HTTPException(status_code=409, detail="registration handoff authorization branch changed")
            return _dispatch(owner, digest, current.user_id, None, completion=completion)
    except HTTPException as exc:
        return _http_error(exc, completion=completion)
    except Exception:
        return error(503, completion=completion, local_digest=digest)


def _pending(request, *, completion):
    from serverware import app as application

    digest = None
    try:
        application._require_registration_execution_session_csrf(request)
        _, session = application._pending_oidc_session_for_request(request, fresh=True)
        payload = _payload(request, completion)
        owner = _owner()
        with application.trust_bundle_lock(exclusive=False):
            user_id, session_id = str(session["user_id"]), str(session["id"])
            if application.db.list_webauthn_credentials(user_id, include_revoked=True):
                raise HTTPException(status_code=409, detail="first enrollment is closed because credential history exists")
            _bootstrap(application, payload)
            fields = ("id", "user_id", "expires_at", "pending_expires_at")
            held_scope, held_roles = tuple(session[field] for field in fields), frozenset(session["roles"])
            binding = _subject(payload["localDigest"], user_id, session_id, completion=completion)
            digest = binding["localDigest"]
            _, current = application._pending_oidc_session_for_request(request, fresh=True)
            if (tuple(current[field] for field in fields) != held_scope
                    or frozenset(current["roles"]) != held_roles):
                raise HTTPException(status_code=409, detail="registration handoff session changed")
            if application.db.list_webauthn_credentials(user_id, include_revoked=True):
                raise HTTPException(status_code=409, detail="first enrollment is closed because credential history exists")
            return _dispatch(owner, digest, user_id, session_id, completion=completion)
    except HTTPException as exc:
        return _http_error(exc, completion=completion)
    except Exception:
        return error(503, completion=completion, local_digest=digest)


@router.post("/api/webauthn/register/execute-retained", status_code=202)
def execute_operator(request: Request):
    return _operator(request, completion=False)


@router.post("/api/webauthn/register/complete-retained", status_code=202)
def complete_operator(request: Request):
    return _operator(request, completion=True)


@router.post("/api/auth/session/webauthn/register/execute-retained", status_code=202)
def execute_pending(request: Request):
    return _pending(request, completion=False)


@router.post("/api/auth/session/webauthn/register/complete-retained", status_code=202)
def complete_pending(request: Request):
    return _pending(request, completion=True)
