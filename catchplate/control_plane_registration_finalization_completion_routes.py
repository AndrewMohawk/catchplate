"""Separate present permission for retained finalization completion/recovery.

Original eight-field ownership inspection precedes permission; the facade
repeats genuine replay under its cold owner lock before dispatch. The operator
branch uses current role/identity and fresh completion-bound possession, or a
fresh bootstrap only when credential history is genuinely empty. A selected
two-person policy refuses before writes until it has an integrated transition;
it is never bypassed. Pending permission has its
own fixed helper; no incoming successful subject can replace either path.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from catchplate import control_plane_enrollment_startup as enrollment
from catchplate import control_plane_registration_handoff_routes as permission
from catchplate import control_plane_registration_finalization_completion as handoff
from catchplate import control_plane_registration_finalization_completion_subject as subjects
from catchplate import control_plane_registration_finalization_completion_http as contract
from catchplate import control_plane_registration_finalization_permission as possession


router = APIRouter()
COMPLETE_PATHS = frozenset({"/api/webauthn/register/complete-finalization",
    "/api/auth/session/webauthn/register/complete-finalization"})
RECOVER_PATHS = frozenset({"/api/webauthn/register/recover-finalization-completion",
    "/api/auth/session/webauthn/register/recover-finalization-completion"})
OPTIONS_PATHS = frozenset({"/api/webauthn/register/complete-finalization/options",
    "/api/webauthn/register/recover-finalization-completion/options",
    "/api/auth/session/webauthn/register/complete-finalization/options",
    "/api/auth/session/webauthn/register/recover-finalization-completion/options"})
PATHS = COMPLETE_PATHS | RECOVER_PATHS | OPTIONS_PATHS
RECOVERY_PATHS = RECOVER_PATHS | frozenset({
    "/api/webauthn/register/recover-finalization-completion/options",
    "/api/auth/session/webauthn/register/recover-finalization-completion/options"})
HEADERS = permission.HEADERS
TWO_PERSON_UNAVAILABLE_ERROR = "registration_finalization_completion_two_person_unavailable"


def error(status_code, code=None, *, recovery, local_digest=None):
    detail = contract.unavailable(local_digest, recovery=recovery)
    if code is not None:
        detail["error"] = code  # Fixed framing/permission code, never exception text.
    return JSONResponse(status_code=status_code, headers=HEADERS, content={"detail": detail})


def _http_error(exc, *, recovery):
    if exc.status_code >= 500:
        # Expose only this exact source-owned refusal, never server exception text.
        code = (TWO_PERSON_UNAVAILABLE_ERROR if exc.status_code == 503
            and type(exc.detail) is dict
            and exc.detail == {"error": TWO_PERSON_UNAVAILABLE_ERROR} else None)
        return error(503, code, recovery=recovery)
    detail = contract.unavailable(recovery=recovery)
    if type(exc.detail) is dict:
        # Preserve the real permission challenge needed for assertion/approval,
        # not arbitrary originals, retry hints or purported remote outcomes.
        for name in ("error", "message", "action", "resourceId", "payloadDigest",
                "approvalId", "status", "expiresAt", "reason"):
            if name in exc.detail:
                detail[name] = exc.detail[name]
    elif type(exc.detail) is str:
        detail["message"] = exc.detail
    return JSONResponse(status_code=exc.status_code,
        headers={**(exc.headers or {}), **HEADERS}, content={"detail": detail})


def _payload(request, *, recovery, options=False):
    purpose, _, _, _ = contract._mode(recovery)
    if type(options) is not bool:
        raise HTTPException(status_code=400, detail="finalization completion framing mode differs")
    value = getattr(request.state, "registration_finalization_completion_payload", None)
    allowed = {"purpose", "localDigest"} if options else {"purpose", "localDigest", "bootstrapToken", "mfa"}
    if (type(value) is not dict or not {"purpose", "localDigest"} <= value.keys()
            or not value.keys() <= allowed or value.get("purpose") != purpose):
        raise HTTPException(status_code=400, detail="finalization completion framing is required")
    return value


def _owner():
    owner = enrollment.require_started()
    if (type(owner) is not enrollment._EnrollmentOwner
            or not owner.sql_handoff_enabled or not owner.finalization_completion_enabled):
        raise HTTPException(status_code=503, detail="finalization completion is disabled")
    return owner


def _subject(digest, user_id, session_id, *, recovery):
    inspected = subjects.inspect_retained_finalization_completion_subject(digest)
    binding = contract.request_binding(inspected, recovery=recovery)
    if (binding["localDigest"] != digest or binding["userId"] != user_id
            or binding["sessionId"] != session_id
            or (binding["mode"] == "oidc-session-first-enrollment") != (session_id is not None)):
        raise HTTPException(status_code=403, detail="finalization completion ownership denied")
    return binding


def _dispatch(owner, digest, user_id, session_id, *, recovery):
    contract._mode(recovery)
    if _owner() is not owner:
        raise HTTPException(status_code=503, detail="finalization completion owner changed")
    call = (handoff.recover_retained_registration_finalization_completion if recovery
        else handoff.request_retained_registration_finalization_completion)
    returned_digest, raw4 = call(digest, expected_user_id=user_id, expected_session_id=session_id)
    if returned_digest != digest:
        raise ValueError("finalization completion returned another original grant locator")
    return JSONResponse(status_code=202, headers=HEADERS,
        content=contract.accepted(returned_digest, raw4, recovery=recovery))


def _approval_policy(application, binding):
    # Generic approval consume/ensure changes a member of the complete pending
    # metadata vector. Do not mutate it or pretend that requirement is disabled.
    # A selected two-person completion policy needs its own integrated protocol.
    if application._control_plane_two_person_required(binding["action"]):
        raise HTTPException(status_code=503,
            detail={"error": TWO_PERSON_UNAVAILABLE_ERROR})


def _permission(application, payload, binding, identity, owner):
    _approval_policy(application, binding)
    if payload.get("bootstrapToken") is not None:
        raise HTTPException(status_code=400, detail="bootstrap cannot replace existing-credential authorization")
    mfa = payload.get("mfa")
    assertion = None if mfa is None else mfa.get("assertion")
    digest = application._control_plane_payload_digest(binding)
    if not assertion:
        raise HTTPException(status_code=412, detail={"error": "control_plane_webauthn_required",
            "message": "Fresh target-key completion possession assertion required",
            "action": binding["action"], "resourceId": binding["challengeId"], "payloadDigest": digest})
    try:
        possession.consume(owner, binding, application._control_plane_mutation_authn_policy(), assertion)
    except (possession.FinalizationPermissionError, application.WebAuthnError):
        raise HTTPException(status_code=403, detail="finalization completion possession denied") from None
    _approval_policy(application, binding)
    application._require_control_plane_two_person(action=binding["action"],
        resource_id=binding["challengeId"], payload_digest=digest,
        mfa=mfa, identity=identity, request=binding)


def _operator(request, *, recovery, options=False):
    from catchplate import app as application

    digest = None
    try:
        identity = application.require_role("admin", "approver")(
            application.require_admin(request,
                x_catchplate_admin_token=request.headers.get("X-Catchplate-Admin-Token")))
        payload, owner = _payload(request, recovery=recovery, options=options), _owner()
        with application.trust_bundle_lock(exclusive=False):
            current = application._registration_execution_current_operator(request, identity)
            binding = _subject(payload["localDigest"], current.user_id, None, recovery=recovery)
            digest = binding["localDigest"]
            had_history = bool(application.db.list_webauthn_credentials(current.user_id, include_revoked=True))
            _approval_policy(application, binding)
            if options:
                if not had_history:
                    raise HTTPException(status_code=409, detail="empty history requires fresh bootstrap, not possession options")
                result = possession.issue(owner, binding, application._control_plane_mutation_authn_policy())
                application._registration_execution_current_operator(request, current)
                if _owner() is not owner:
                    raise HTTPException(status_code=503, detail="finalization completion owner changed")
                return JSONResponse(status_code=200, headers=HEADERS, content=result)
            if had_history:
                _permission(application, payload, binding, current, owner)
            else:
                permission._bootstrap(application, payload)
            current = application._registration_execution_current_operator(request, current)
            if bool(application.db.list_webauthn_credentials(current.user_id, include_revoked=True)) != had_history:
                raise HTTPException(status_code=409, detail="finalization completion authorization branch changed")
            return _dispatch(owner, digest, current.user_id, None, recovery=recovery)
    except HTTPException as exc:
        return _http_error(exc, recovery=recovery)
    except Exception:
        return error(503, recovery=recovery, local_digest=digest)


@router.post("/api/webauthn/register/complete-finalization", status_code=202)
def complete_operator(request: Request):
    return _operator(request, recovery=False)


@router.post("/api/webauthn/register/recover-finalization-completion", status_code=202)
def recover_operator(request: Request):
    return _operator(request, recovery=True)


@router.post("/api/webauthn/register/complete-finalization/options")
def complete_operator_options(request: Request):
    return _operator(request, recovery=False, options=True)


@router.post("/api/webauthn/register/recover-finalization-completion/options")
def recover_operator_options(request: Request):
    return _operator(request, recovery=True, options=True)


@router.post("/api/auth/session/webauthn/register/complete-finalization", status_code=202)
def complete_pending(request: Request):
    from catchplate import control_plane_registration_finalization_completion_pending as pending

    return pending._handle(request, recovery=False)


@router.post("/api/auth/session/webauthn/register/recover-finalization-completion", status_code=202)
def recover_pending(request: Request):
    from catchplate import control_plane_registration_finalization_completion_pending as pending

    return pending._handle(request, recovery=True)


@router.post("/api/auth/session/webauthn/register/complete-finalization/options")
def complete_pending_options(request: Request):
    from catchplate import control_plane_registration_finalization_completion_pending as pending

    return pending._handle(request, recovery=False, options=True)


@router.post("/api/auth/session/webauthn/register/recover-finalization-completion/options")
def recover_pending_options(request: Request):
    from catchplate import control_plane_registration_finalization_completion_pending as pending

    return pending._handle(request, recovery=True, options=True)
