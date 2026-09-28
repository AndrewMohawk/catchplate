"""One original HTTP request through fresh actor and protected recovery.

Token/current-auth/cookie ownership remains inside the genuine delivery owner.
This core returns its staged response only after normal context cleanup; no
token, successful permission DTO or replacement work/window is an argument.
The async route invokes this bounded synchronous core on its own ASGI thread.
"""
from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import oidc_session_activation_recovery_http_contract as contract
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


POST_PATH = "/api/auth/session/activation/recovery"
ORIGINAL_STATE_NAME = "oidc_session_activation_recovery_bytes"
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"}
_REJECTED_STATUSES = frozenset({400, 401, 403, 405, 409, 413, 415, 422, 429, 503})


def _rejected_response(*, status_code=503, local_digest=None):
    """Fixed pre-acquisition refusal; never forward exception text or headers."""
    status = status_code if type(status_code) is int and status_code in _REJECTED_STATUSES else 503
    try:
        content = contract.rejected_before_dispatch(local_digest)
    except ValueError:
        content = contract.rejected_before_dispatch()
    return JSONResponse(status_code=status, headers=HEADERS, content=content)


def _unknown_response(local_digest=None):
    """Preserve the existing cookie and forbid retries after any uncertainty."""
    try:
        content = contract.outcome_unknown(local_digest)
    except ValueError:
        content = contract.outcome_unknown()
    return JSONResponse(status_code=503, headers=HEADERS, content=content)


def _recover(request, *, recovery_bytes):
    """Enter one genuine actor; finish only its real staged HTTP response."""
    from serverware import control_plane_enrollment_startup as startup
    from serverware import control_plane_oidc_session_activation_recovery_acquisition as acquisition
    from serverware import control_plane_oidc_session_activation_recovery_delivery as delivery

    if (type(request) is not Request or type(recovery_bytes) is not bytes
            or not 2 <= len(recovery_bytes) <= contract.MAX_REQUEST_BYTES
            or getattr(request.state, ORIGINAL_STATE_NAME, None) is not recovery_bytes
            or request.method != "POST" or request.scope.get("path") != POST_PATH
            or request.scope.get("query_string", b"") != b""):
        return _rejected_response(status_code=400)
    uncertain, local_digest = False, None
    try:
        work = _ValidationWork(QueryReadValidationLimits())
        # One clock opening before parsing or native owner/resource work. This
        # private lifetime tracks only the original ledger and clock floors;
        # it neither contains nor calls a later actor/receiving child guard.
        owner, window = acquisition.execution._open_on_work(work)
        lifetime = acquisition.production._Lifetime(window, window[4], work, None)
        lifetime.current()
        work.charge(input_bytes=4 * len(recovery_bytes),
            json_nodes=4 * contract.permission.framing._JSON_LIMITS.max_total_nodes)
        try:
            payload = contract.parse_request(recovery_bytes, options=False)
        except (ValueError, RecursionError):
            return _rejected_response(status_code=400)
        local_digest = payload["localDigest"]
        del payload
        lifetime.current()
        # Conservative: any failure after this point is unknown, even before
        # the first durable claim/socket. This is not proof about old activation
        # effects, nor about WebAuthn challenge/counter side effects.
        uncertain = True
        with startup._EnrollmentOwner._acquire_oidc_session_activation_recovery_grants(owner,
                request=request, recovery_bytes=recovery_bytes, live_window=window,
                transport_deadline_ns=window[4], work=work, current=lifetime.current) as active:
            staged = delivery._response_on_active(active)
            if type(staged) is not delivery._StagedRecoveryResponse:
                acquisition.execution._fail("recovery HTTP lost its actual staged response owner")
        # The terminal owner, chosen before receiving verification, retains
        # original ancestors and the final child through known normal cleanup.
        # Its actual send hook remains responsible for the signed boundary.
        return staged.finish()
    except HTTPException as exc:
        if not uncertain:
            return _rejected_response(status_code=exc.status_code, local_digest=local_digest)
        return _unknown_response(local_digest)
    except Exception:
        if not uncertain:
            return _rejected_response(local_digest=local_digest)
        return _unknown_response(local_digest)
