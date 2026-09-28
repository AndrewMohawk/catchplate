"""Distinct bounded action for fresh intent/proof preparation, never delivery."""
from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import control_plane_oidc_session_activation_completion_recovery_http as completion


POST_PATH = "/api/auth/session/activation/consume/completion/recovery/release-proof"
OPTIONS_PATH = POST_PATH + "/options"
PATHS = frozenset({POST_PATH, OPTIONS_PATH})
RESPONSE_SCHEMA = "serverware.oidcSessionActivationCompletionRecoveryReleaseResponse/v1"
contract = completion.contract


def _data(status, local_digest=None):
    digest = None if local_digest is None else contract.permission.framing._local_digest(local_digest)
    return {"schema": RESPONSE_SCHEMA, "purpose": "release-intent-proof",
        "localDigest": digest, "status": status, "sessionState": "unknown",
        "tokenReleased": False, "automaticRetryAllowed": False}


def error(status_code=503, *, local_digest=None, uncertain=False):
    code = status_code if type(status_code) is int and status_code in completion._STATUSES else 503
    status = "release-proof-outcome-unknown" if uncertain else "release-proof-unavailable"
    return JSONResponse(status_code=code, headers=completion.HEADERS,
        content=_data(status, local_digest))


def _run(request, *, recovery_bytes, options):
    """Literal source-selected action; no profile, originals or keys from JSON."""
    from serverware import control_plane_enrollment_startup as startup
    from serverware import control_plane_oidc_session_activation_execution as execution
    from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping

    if type(options) is not bool:
        return error(400)
    path = OPTIONS_PATH if options else POST_PATH
    if (type(request) is not Request or type(recovery_bytes) is not bytes
            or not 2 <= len(recovery_bytes) <= contract.MAX_REQUEST_BYTES
            or getattr(request.state, completion.ORIGINAL_STATE_NAME, None) is not recovery_bytes
            or request.method != "POST" or request.scope.get("path") != path
            or request.scope.get("query_string", b"") != b""):
        return error(400)
    local_digest, uncertain = None, False
    try:
        work = completion._ValidationWork(completion.QueryReadValidationLimits())
        owner, window = execution._open_on_work(work)
        lifetime = bookkeeping._Lifetime(window, window[4], work, None)
        lifetime.current()
        work.charge(input_bytes=4 * len(recovery_bytes),
            json_nodes=4 * contract.permission.framing._JSON_LIMITS.max_total_nodes)
        try:
            payload = contract.parse_request(recovery_bytes, options=options)
        except (ValueError, RecursionError):
            return error(400)
        local_digest = payload["localDigest"]
        del payload
        lifetime.current()
        arguments = {"request": request, "recovery_bytes": recovery_bytes,
            "live_window": window, "transport_deadline_ns": window[4],
            "work": work, "current": lifetime.current}
        if options:
            result = startup._EnrollmentOwner._oidc_session_activation_completion_release_options(
                owner, **arguments)
            lifetime.current()
            return JSONResponse(status_code=200, headers=completion.HEADERS, content=result)
        uncertain = True
        startup._EnrollmentOwner._prepare_oidc_session_activation_completion_release(owner, **arguments)
        lifetime.current()
        # Only normal source-owned admission/retention completed. A later
        # independently admitted release and current-auth/cookie path is still
        # required; no private-store existence/absence is inferred here.
        return JSONResponse(status_code=200, headers=completion.HEADERS,
            content=_data("release-intent-proof-retained", local_digest))
    except HTTPException as exc:
        return error(503 if uncertain else exc.status_code,
            local_digest=local_digest, uncertain=uncertain)
    except Exception:
        return error(503, local_digest=local_digest, uncertain=uncertain)
