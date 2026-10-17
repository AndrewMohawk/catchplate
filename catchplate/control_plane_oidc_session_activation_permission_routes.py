"""One authenticated pending-session activation-permission options endpoint.

The genuine core owns actor/session/credential and retained-original admission.
This adapter passes the actual request and immutable bounded original body,
never a caller identity, target graph or successful permission carrier.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from catchplate import control_plane_oidc_session_activation_permission_http as contract


router = APIRouter()
OPTIONS_PATH = "/api/auth/session/activation/permission/options"
PATHS = frozenset({OPTIONS_PATH})
MAX_REQUEST_BYTES = contract.MAX_REQUEST_BYTES
ORIGINAL_STATE_NAME = "oidc_session_activation_permission_bytes"
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"}


def error(status_code, code=None):
    detail = contract.unavailable()
    if code is not None:
        detail["error"] = code  # Source-selected framing code, never exception text.
    return JSONResponse(status_code=status_code, headers=HEADERS, content={"detail": detail})


def _http_error(exc):
    if exc.status_code >= 500:
        return error(503)
    detail = contract.unavailable()
    if type(exc.detail) is dict:
        for name in ("error", "message", "action", "resourceId", "payloadDigest",
                "approvalId", "status", "expiresAt", "reason"):
            if name in exc.detail:
                detail[name] = exc.detail[name]
    elif type(exc.detail) is str:
        detail["message"] = exc.detail
    return JSONResponse(status_code=exc.status_code,
        headers={**(exc.headers or {}), **HEADERS}, content={"detail": detail})


def _original(request):
    original = getattr(request.state, ORIGINAL_STATE_NAME, None)
    if (type(original) is not bytes
            or not 2 <= len(original) <= MAX_REQUEST_BYTES):
        raise HTTPException(status_code=400, detail="activation permission framing is required")
    return original


@router.post(OPTIONS_PATH)
def permission_options(request: Request):
    from catchplate import control_plane_oidc_session_activation_permission as permission

    try:
        result = permission._options(request, permission_bytes=_original(request))
        return JSONResponse(status_code=200, headers=HEADERS, content=result)
    except HTTPException as exc:
        return _http_error(exc)
    except Exception:
        return error(503)
