"""One fixed fresh consume action; completion data is never session delivery."""
from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from catchplate import control_plane_oidc_session_activation_completion_recovery_actor as actors
from catchplate import control_plane_oidc_session_activation_completion_recovery_http as completion


POST_PATH = actors.CONSUME_PATH
OPTIONS_PATH = POST_PATH + "/options"
PATHS = frozenset({POST_PATH, OPTIONS_PATH})
contract = completion.contract


def error(status_code=503, *, path=None):
    """Fixed pre-dispatch data; shared middleware never includes exceptions."""
    from catchplate import control_plane_oidc_session_activation_completion_recovery_consume_response as terminal

    code = status_code if type(status_code) is int and status_code in completion._STATUSES else 503
    return terminal._rejected_response(status_code=code)


def _run(request, *, recovery_bytes, options):
    """Keep the actual purpose-bound owner and terminal on the ASGI thread."""
    from catchplate import control_plane_enrollment_startup as startup
    from catchplate import control_plane_oidc_session_activation_execution as execution
    from catchplate import control_plane_oidc_session_activation_completion_recovery_consume_response as terminal
    from catchplate import authority_oidc_session_activation_consume_input_production as bookkeeping

    if type(options) is not bool:
        return error(400)
    path = OPTIONS_PATH if options else POST_PATH
    if (type(request) is not Request or type(recovery_bytes) is not bytes
            or not 2 <= len(recovery_bytes) <= contract.MAX_REQUEST_BYTES
            or getattr(request.state, completion.ORIGINAL_STATE_NAME, None) is not recovery_bytes
            or request.method != "POST" or request.scope.get("path") != path
            or request.scope.get("query_string", b"") != b""):
        return error(400)
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
            return error(400)
        lifetime.current()
        arguments = {"request": request, "recovery_bytes": recovery_bytes,
            "live_window": window, "transport_deadline_ns": window[4],
            "work": work, "current": lifetime.current}
        if options:
            result = startup._EnrollmentOwner._oidc_session_activation_completion_consume_options(
                owner, **arguments)
            lifetime.current()
            return JSONResponse(status_code=200, headers=completion.HEADERS, content=result)
        # Entry may consume fresh authentication and contact the input issuer,
        # reserve or SQL worker before yielding. Never label later failure as
        # nonexecution, remove a pending cookie, or imply an automatic retry.
        uncertain = True
        with startup._EnrollmentOwner._consume_oidc_session_activation_completion(
                owner, **arguments) as active:
            staged = terminal._response_on_active(active)
            if type(staged) is not terminal._StagedConsumeResponse:
                execution._fail("fresh consume HTTP lost its actual terminal")
        # No token or session authority crosses this boundary. The source-owned
        # terminal itself requires normal actor and owner cleanup before data.
        return staged.finish()
    except HTTPException as exc:
        from catchplate import control_plane_oidc_session_activation_approval as approval

        negotiation = None if options else approval._response_for(exc, action=approval.RECOVERY_ACTION)
        if negotiation is not None:
            return negotiation
        return terminal._unknown_response() if uncertain else error(exc.status_code)
    except Exception:
        return terminal._unknown_response() if uncertain else error(503)
