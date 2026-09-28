"""Bounded fresh recovery options and explicit one-context recovery POST."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import oidc_session_activation_recovery_http_contract as contract
from serverware import control_plane_oidc_session_activation_completion_recovery_http as completion
from serverware import control_plane_oidc_session_activation_completion_recovery_release_http as release
from serverware import control_plane_oidc_session_activation_completion_recovery_delivery_http as delivery


router = APIRouter()
OPTIONS_PATH = "/api/auth/session/activation/recovery/options"
POST_PATH = "/api/auth/session/activation/recovery"
PATHS = frozenset({OPTIONS_PATH, POST_PATH}) | completion.PATHS | release.PATHS | delivery.PATHS
ORIGINAL_STATE_NAME = "oidc_session_activation_recovery_bytes"
MAX_REQUEST_BYTES = contract.MAX_REQUEST_BYTES
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"}
_STATUSES = frozenset({400, 401, 403, 405, 409, 413, 415, 422, 429, 503})


def error(status_code=503, *, path=None):
    if path in delivery.PATHS:
        return delivery.error(status_code)
    if path in release.PATHS:
        return release.error(status_code)
    if path in completion.PATHS:
        return completion.error(status_code, path=path)
    if path == POST_PATH:
        from serverware import control_plane_oidc_session_activation_recovery_http as recovery

        return recovery._rejected_response(status_code=status_code)
    status = status_code if type(status_code) is int and status_code in _STATUSES else 503
    return JSONResponse(status_code=status, headers=HEADERS, content=contract.unavailable())


async def _frame_request(request):
    """Reject oversized chunks before accumulation; never parse a graph here."""
    if not isinstance(request, Request):
        return error(400)
    path = request.scope.get("path")
    if path not in PATHS:
        return error(400)

    def refuse(status):
        return error(status, path=path)

    if request.method != "POST":
        return refuse(405)
    lengths = request.headers.getlist("content-length")
    if (len(lengths) != 1 or re.fullmatch(r"[1-9][0-9]{0,5}", lengths[0]) is None
            or request.headers.getlist("transfer-encoding")
            or request.headers.getlist("content-encoding")
            or request.scope.get("query_string", b"") != b""):
        return refuse(400)
    if request.headers.getlist("content-type") != ["application/json"]:
        return refuse(415)
    length = int(lengths[0])
    if length > MAX_REQUEST_BYTES:
        return refuse(413)
    if length < 2:
        return refuse(400)
    body = bytearray()
    try:
        async for chunk in request.stream():
            if type(chunk) is not bytes:
                return refuse(400)
            if len(chunk) > MAX_REQUEST_BYTES - len(body):
                return refuse(413)
            if len(chunk) > length - len(body):
                return refuse(400)
            body.extend(chunk)
    except Exception:
        return refuse(400)
    if len(body) != length:
        return refuse(400)
    original = bytes(body)
    request._body = original
    request._stream_consumed = False
    setattr(request.state, ORIGINAL_STATE_NAME, original)
    return None


@router.post(OPTIONS_PATH)
async def recovery_options(request: Request):
    from serverware import control_plane_oidc_session_activation_recovery_actor as actor

    original = getattr(request.state, ORIGINAL_STATE_NAME, None)
    if type(original) is not bytes or not 2 <= len(original) <= MAX_REQUEST_BYTES:
        return error(400)
    try:
        # Same ASGI thread for the bounded owner/trust scope, never a new
        # worker allowance. The result is only fresh WebAuthn options data.
        result = actor._options(request, recovery_bytes=original)
        return JSONResponse(status_code=200, headers=HEADERS, content=result)
    except HTTPException as exc:
        return error(exc.status_code)
    except Exception:
        return error(503)


@router.post(POST_PATH)
async def recover(request: Request):
    from serverware import control_plane_oidc_session_activation_recovery_http as recovery

    original = getattr(request.state, ORIGINAL_STATE_NAME, None)
    if type(original) is not bytes or not 2 <= len(original) <= MAX_REQUEST_BYTES:
        return recovery._rejected_response(status_code=400)
    # Keep the genuine thread-bound actor, work and final send guard on this
    # ASGI thread. This is bounded synchronous work, not a concurrency claim.
    return recovery._recover(request, recovery_bytes=original)


@router.post(completion.ACTIVATION_OPTIONS_PATH)
async def activation_completion_options(request: Request):
    return completion._run(request, profile="activation", options=True,
        recovery_bytes=getattr(request.state, ORIGINAL_STATE_NAME, None))


@router.post(completion.CONSUME_OPTIONS_PATH)
async def consume_completion_options(request: Request):
    return completion._run(request, profile="consume", options=True,
        recovery_bytes=getattr(request.state, ORIGINAL_STATE_NAME, None))


@router.post(completion.ACTIVATION_PATH)
async def recover_activation_completion(request: Request):
    return completion._run(request, profile="activation", options=False,
        recovery_bytes=getattr(request.state, ORIGINAL_STATE_NAME, None))


@router.post(completion.CONSUME_PATH)
async def recover_consume_completion(request: Request):
    return completion._run(request, profile="consume", options=False,
        recovery_bytes=getattr(request.state, ORIGINAL_STATE_NAME, None))


@router.post(release.OPTIONS_PATH)
async def completion_release_options(request: Request):
    return release._run(request, options=True,
        recovery_bytes=getattr(request.state, ORIGINAL_STATE_NAME, None))


@router.post(release.POST_PATH)
async def prepare_completion_release(request: Request):
    return release._run(request, options=False,
        recovery_bytes=getattr(request.state, ORIGINAL_STATE_NAME, None))


@router.post(delivery.OPTIONS_PATH)
async def completion_delivery_options(request: Request):
    return delivery._run(request, options=True,
        recovery_bytes=getattr(request.state, ORIGINAL_STATE_NAME, None))


@router.post(delivery.POST_PATH)
async def complete_first_release(request: Request):
    return delivery._run(request, options=False,
        recovery_bytes=getattr(request.state, ORIGINAL_STATE_NAME, None))
