"""Two fixed fresh release actions, never preparation or automatic fallback."""
from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import control_plane_oidc_session_activation_completion_recovery_http as completion
from serverware import control_plane_oidc_session_activation_completion_recovery_actor as actors


POST_PATH = actors.DELIVERY_PATH
OPTIONS_PATH = POST_PATH + "/options"
RETAINED_POST_PATH = actors.RETAINED_DELIVERY_PATH
RETAINED_OPTIONS_PATH = RETAINED_POST_PATH + "/options"
PATHS = frozenset({POST_PATH, OPTIONS_PATH, RETAINED_POST_PATH, RETAINED_OPTIONS_PATH})
contract = completion.contract


def error(status_code=503, *, path=POST_PATH):
    from serverware import control_plane_oidc_session_activation_completion_recovery_delivery_response as terminal

    code = status_code if type(status_code) is int and status_code in completion._STATUSES else 503
    if path in (RETAINED_POST_PATH, RETAINED_OPTIONS_PATH):
        return terminal._retained_rejected_response(status_code=code)
    return terminal._rejected_response(status_code=code)


def _run(request, *, recovery_bytes, options):
    from serverware import control_plane_enrollment_startup as startup
    from serverware import control_plane_oidc_session_activation_execution as execution
    from serverware import control_plane_oidc_session_activation_completion_recovery_delivery_response as terminal
    from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping

    actual_path = request.scope.get("path") if type(request) is Request else None
    retained = actual_path in (RETAINED_POST_PATH, RETAINED_OPTIONS_PATH)
    rejected = lambda code: error(code, path=actual_path)
    unknown = terminal._retained_unknown_response if retained else terminal._unknown_response
    if type(options) is not bool:
        return rejected(400)
    if retained:
        path = RETAINED_OPTIONS_PATH if options else RETAINED_POST_PATH
    else:
        path = OPTIONS_PATH if options else POST_PATH
    if (type(request) is not Request or type(recovery_bytes) is not bytes
            or not 2 <= len(recovery_bytes) <= contract.MAX_REQUEST_BYTES
            or getattr(request.state, completion.ORIGINAL_STATE_NAME, None) is not recovery_bytes
            or request.method != "POST" or request.scope.get("path") != path
            or request.scope.get("query_string", b"") != b""):
        return rejected(400)
    uncertain = False
    try:
        work = completion._ValidationWork(completion.QueryReadValidationLimits())
        owner, window = execution._open_on_work(work)
        lifetime = bookkeeping._Lifetime(window, window[4], work, None)
        lifetime.current()
        work.charge(input_bytes=4 * len(recovery_bytes),
            json_nodes=4 * contract.permission.framing._JSON_LIMITS.max_total_nodes)
        try:
            contract.parse_request(recovery_bytes, options=options)
        except (ValueError, RecursionError):
            return rejected(400)
        lifetime.current()
        arguments = {"request": request, "recovery_bytes": recovery_bytes,
            "live_window": window, "transport_deadline_ns": window[4],
            "work": work, "current": lifetime.current}
        if options:
            if retained:
                result = startup._EnrollmentOwner._oidc_session_activation_completion_retained_delivery_options(
                    owner, **arguments)
            else:
                result = startup._EnrollmentOwner._oidc_session_activation_completion_delivery_options(
                    owner, **arguments)
            lifetime.current()
            return JSONResponse(status_code=200, headers=completion.HEADERS, content=result)
        # Unknown after fresh-actor admission begins, including authentication
        # side effects. A failure never removes/replaces the old browser cookie.
        uncertain = True
        if retained:
            context = startup._EnrollmentOwner._acquire_oidc_session_activation_completion_retained_delivery(
                owner, **arguments)
        else:
            context = startup._EnrollmentOwner._acquire_oidc_session_activation_completion_delivery(
                owner, **arguments)
        with context as active:
            staged = terminal._response_on_active(active)
            if type(staged) is not terminal._StagedRecoveryResponse:
                execution._fail("completion delivery HTTP lost its actual terminal")
        return staged.finish()
    except HTTPException as exc:
        terminal._discard_scope(request.scope)
        return unknown() if uncertain else rejected(exc.status_code)
    except Exception:
        terminal._discard_scope(request.scope)
        return unknown() if uncertain else rejected(503)
