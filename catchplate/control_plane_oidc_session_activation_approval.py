"""Bounded public negotiation data from the actual pre-execution approval gate.

This exception originates only at the application's two-person gate. Generic
HTTP errors, remote observations and failures after dispatch do not become
approval continuations. The browser must obtain new action-bound assertions;
this response is neither permission nor evidence about an earlier attempt.
"""
from __future__ import annotations

import re

from fastapi import HTTPException
from fastapi.responses import JSONResponse


ACTIVATION_ACTION = "webauthn.oidc-session.activation.authorize"
RECOVERY_ACTION = "webauthn.oidc-session.activation.recover"
SCHEMA = "catchplate.oidcSessionActivationApprovalRequired/v1"
_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"}


class _ApprovalRequired(HTTPException):
    """Source provenance, not authority; ordinary consumers retain HTTP 428."""


def _text(value, maximum):
    return (type(value) is str and 1 <= len(value) <= maximum
        and all(0x21 <= ord(char) <= 0x7e for char in value))


def _response_for(exc, *, action):
    """Project only a literal action's actual local approval negotiation."""
    if (type(exc) is not _ApprovalRequired or exc.status_code != 428
            or action not in (ACTIVATION_ACTION, RECOVERY_ACTION)
            or type(exc.detail) is not dict):
        return None
    detail = exc.detail
    if (detail.get("error") != "control_plane_approval_required"
            or detail.get("action") != action
            or not _text(detail.get("approvalId"), 4096)
            or not _text(detail.get("resourceId"), 1024)
            or type(detail.get("payloadDigest")) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", detail["payloadDigest"]) is None):
        return None
    body = {"schema": SCHEMA, "error": "control_plane_approval_required",
        "approvalId": detail["approvalId"], "action": action,
        "resourceId": detail["resourceId"], "payloadDigest": detail["payloadDigest"],
        "dispatchState": "approval-required", "automaticRetryAllowed": False,
        "freshAuthorizationRequired": True}
    response = JSONResponse(status_code=428, headers=_HEADERS, content={"detail": body})
    if len(response.body) > 16 * 1024:
        return None
    return response
