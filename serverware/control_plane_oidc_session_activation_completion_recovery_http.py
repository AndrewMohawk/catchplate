"""Explicit completion-only recovery; never session, token or retry success.

Each fixed route opens one work/window and selects its own cold profile. Only
normal completion of the actual original-admitting coordinator may produce the
historical reconciliation response. No signed control or private hint is exposed
to the browser, and no cookie is changed on success or failure.
"""
from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import oidc_session_activation_recovery_http_contract as contract
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


ACTIVATION_PATH = "/api/auth/session/activation/completion/recovery"
CONSUME_PATH = "/api/auth/session/activation/consume/completion/recovery"
ACTIVATION_OPTIONS_PATH = ACTIVATION_PATH + "/options"
CONSUME_OPTIONS_PATH = CONSUME_PATH + "/options"
PATHS = frozenset({ACTIVATION_PATH, CONSUME_PATH, ACTIVATION_OPTIONS_PATH, CONSUME_OPTIONS_PATH})
ORIGINAL_STATE_NAME = "oidc_session_activation_recovery_bytes"
RESPONSE_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryResponse/v1"
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"}
_STATUSES = frozenset({400, 401, 403, 405, 409, 413, 415, 422, 429, 503})


def _path(profile, options):
    if type(profile) is not str or profile not in ("activation", "consume") or type(options) is not bool:
        raise ValueError("completion recovery route must select its literal profile")
    base = ACTIVATION_PATH if profile == "activation" else CONSUME_PATH
    return base + "/options" if options else base


def _data(*, status, profile=None, local_digest=None):
    if profile is not None:
        _path(profile, False)
    digest = None if local_digest is None else contract.permission.framing._local_digest(local_digest)
    return {"schema": RESPONSE_SCHEMA, "purpose": "recover-oidc-session-activation-completion",
        "completionProfile": profile, "localDigest": digest, "status": status,
        "sessionState": "unknown", "tokenReleased": False, "automaticRetryAllowed": False}


def error(status_code=503, *, path=None, profile=None, local_digest=None, uncertain=False):
    """Fixed bounded data only; omit exception messages and private originals."""
    if path in (ACTIVATION_PATH, ACTIVATION_OPTIONS_PATH):
        profile = "activation"
    elif path in (CONSUME_PATH, CONSUME_OPTIONS_PATH):
        profile = "consume"
    code = status_code if type(status_code) is int and status_code in _STATUSES else 503
    status = "completion-recovery-outcome-unknown" if uncertain else "completion-recovery-unavailable"
    return JSONResponse(status_code=code, headers=HEADERS,
        content=_data(status=status, profile=profile, local_digest=local_digest))


def _run(request, *, profile, recovery_bytes, options):
    """Same-thread bounded core; cold facade selection cannot come from JSON."""
    from serverware import control_plane_enrollment_startup as startup
    from serverware import control_plane_oidc_session_activation_execution as execution
    from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping

    path = _path(profile, options)
    if (type(request) is not Request or type(recovery_bytes) is not bytes
            or not 2 <= len(recovery_bytes) <= contract.MAX_REQUEST_BYTES
            or getattr(request.state, ORIGINAL_STATE_NAME, None) is not recovery_bytes
            or request.method != "POST" or request.scope.get("path") != path
            or request.scope.get("query_string", b"") != b""):
        return error(400, profile=profile)
    local_digest, uncertain = None, False
    try:
        work = _ValidationWork(QueryReadValidationLimits())
        owner, window = execution._open_on_work(work)
        lifetime = bookkeeping._Lifetime(window, window[4], work, None)
        lifetime.current()
        work.charge(input_bytes=4 * len(recovery_bytes),
            json_nodes=4 * contract.permission.framing._JSON_LIMITS.max_total_nodes)
        try:
            payload = contract.parse_request(recovery_bytes, options=options)
        except (ValueError, RecursionError):
            return error(400, profile=profile)
        local_digest = payload["localDigest"]
        del payload
        lifetime.current()
        arguments = {"request": request, "recovery_bytes": recovery_bytes,
            "live_window": window, "transport_deadline_ns": window[4],
            "work": work, "current": lifetime.current}
        if options:
            method = (startup._EnrollmentOwner._oidc_session_activation_completion_recovery_options
                if profile == "activation" else
                startup._EnrollmentOwner._oidc_session_activation_consume_completion_recovery_options)
            result = method(owner, **arguments)
            lifetime.current()
            return JSONResponse(status_code=200, headers=HEADERS, content=result)
        # From actor admission onward, even a pre-socket failure is unknown.
        # This request cannot establish nonexecution of an older SQL attempt.
        uncertain = True
        method = (startup._EnrollmentOwner._recover_oidc_session_activation_completion
            if profile == "activation" else
            startup._EnrollmentOwner._recover_oidc_session_activation_consume_completion)
        method(owner, **arguments)
        lifetime.current()
        # A historical fact after normal coordinator cleanup, not current
        # authorization, current head, delivery, activation or SQL success.
        return JSONResponse(status_code=200, headers=HEADERS, content=_data(
            status="completion-controls-reconciled", profile=profile, local_digest=local_digest))
    except HTTPException as exc:
        return error(503 if uncertain else exc.status_code, profile=profile,
            local_digest=local_digest, uncertain=uncertain)
    except Exception:
        return error(503, profile=profile, local_digest=local_digest, uncertain=uncertain)
