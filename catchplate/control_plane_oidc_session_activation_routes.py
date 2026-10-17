"""Exact bounded activation HTTP adapter, never an authority carrier.

Only immutable original body bytes cross into the genuine one-permission
orchestrator. Framing failures are known pre-dispatch; downstream failures
belong to the orchestrator's source-controlled dispatch boundary.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Request

from catchplate import oidc_session_activation_http_contract as contract


router = APIRouter()
POST_PATH = "/api/auth/session/activation"
MAX_REQUEST_BYTES = contract.MAX_REQUEST_BYTES
ORIGINAL_STATE_NAME = "oidc_session_activation_bytes"


def error(status_code=503):
    """Only framing, method and pre-core CSRF refusals use this helper."""
    from catchplate import control_plane_oidc_session_activation_http as activation_http

    return activation_http._rejected_response(status_code=status_code)


async def _frame_request(request):
    """Bound the actual stream before copying or parsing any body graph.

    Return a fixed rejection response, or None after publishing the bounded
    immutable original in the actual Request's shared state. This does not
    parse assertions, authenticate an actor or create a permission.
    """
    # Starlette's HTTP middleware may supply its genuine cached Request
    # subclass; the routed core separately receives the actual Request.
    if not isinstance(request, Request) or request.scope.get("path") != POST_PATH:
        return error(400)
    if request.method != "POST":
        return error(405)
    lengths = request.headers.getlist("content-length")
    if (len(lengths) != 1
            or re.fullmatch(r"[1-9][0-9]{0,5}", lengths[0]) is None
            or request.headers.getlist("transfer-encoding")
            or request.headers.getlist("content-encoding")
            or request.scope.get("query_string", b"") != b""):
        return error(400)
    if request.headers.getlist("content-type") != ["application/json"]:
        return error(415)
    content_length = int(lengths[0])
    if content_length > MAX_REQUEST_BYTES:
        return error(413)
    if content_length < 2:
        return error(400)
    body = bytearray()
    try:
        async for chunk in request.stream():
            if type(chunk) is not bytes:
                return error(400)
            # Never extend the accumulated body with an over-limit chunk.
            if len(chunk) > MAX_REQUEST_BYTES - len(body):
                return error(413)
            if len(chunk) > content_length - len(body):
                return error(400)
            body.extend(chunk)
    except Exception:
        # No permission or dispatch exists during this framing-only stage.
        # Do not echo disconnect/transport exception text or headers.
        return error(400)
    if len(body) != content_length:
        return error(400)
    original = bytes(body)
    request._body = original
    request._stream_consumed = False
    setattr(request.state, ORIGINAL_STATE_NAME, original)
    return None


@router.post(POST_PATH)
async def activate(request: Request):
    from catchplate import control_plane_oidc_session_activation_http as activation_http

    original = getattr(request.state, ORIGINAL_STATE_NAME, None)
    if type(original) is not bytes or not 2 <= len(original) <= MAX_REQUEST_BYTES:
        return error(400)
    # Deliberately stay on the ASGI thread for the original guarded context
    # and final send. The synchronous core is bounded, not a concurrency claim.
    # Do not reclassify a downstream exception as pre-dispatch rejection.
    return activation_http._activate(request, activation_bytes=original)
