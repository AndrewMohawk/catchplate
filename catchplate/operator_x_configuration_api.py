"""Bounded administrator transport for first ordinary X client configuration.

The service owns persistence and original-client custody. This router neither
contacts X nor starts consent, callback, refresh, disconnect, or posting work.
Unknown save outcomes are inspected through actor-owned status, never replayed.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from catchplate import auth, operator_catalog_api as admission

PREFIX = "/api/operator-demo/oauth/x/configuration/v1"
MAX_INPUT_BYTES = 8192
router = APIRouter(prefix=PREFIX)
_UNAVAILABLE = "X configuration outcome unavailable; inspect the retained operation without repeating the action"
_NOT_FOUND = "X configuration operation not found; absence does not authorize retry"


def _admit(request: Request, *, mutation: bool) -> None:
    admission._admit(request, mutation=mutation)
    from catchplate import operator_x_admission

    try:
        enabled = operator_x_admission.enabled()
    except Exception:
        admission._reject(503, _UNAVAILABLE)
    if enabled is False:
        admission._reject(404, "X configuration is not supported by this deployment")
    if enabled is not True:
        admission._reject(503, _UNAVAILABLE)


async def _read(request: Request) -> None:
    _admit(request, mutation=False)
    if (request.headers.getlist("transfer-encoding") or request.headers.getlist("content-encoding")
            or request.headers.getlist("content-length") not in ([], ["0"])):
        admission._reject(400, "X configuration status accepts no body")
    # Framing alone is insufficient: ASGI may deliver bytes with no length or
    # an explicit zero. Reject them without retaining a request body.
    try:
        async with asyncio.timeout(30):
            async for chunk in request.stream():
                if chunk:
                    admission._reject(400, "X configuration status accepts no body")
    except HTTPException:
        raise
    except TimeoutError:
        admission._reject(408, "X configuration status body timed out")
    except Exception:
        admission._reject(400, "X configuration status body unavailable")


def _identifier(value: str) -> None:
    from catchplate.operator_catalog_inputs import _identifier as canonical_identifier

    try:
        canonical_identifier(value)
    except (ValueError, TypeError, AttributeError):
        admission._reject(422, "invalid X configuration operation identifier")


async def _result(function, *args, created: bool = False) -> JSONResponse:
    from catchplate import operator_x_configuration as service
    from catchplate.operator_catalog_schema import CatalogConflict

    try:
        result = await admission._blocking(function, *args)
    except service.ConfigurationNotFound:
        admission._reject(404, _NOT_FOUND)
    except CatalogConflict:
        admission._reject(409, "X configuration review changed; inspect the retained operation before saving again")
    except service.ConfigurationUnavailable:
        admission._reject(503, _UNAVAILABLE)
    except Exception:
        # Provider/storage/validation exception text can contain private input.
        # A lifecycle failure is not proof that a save did not commit.
        admission._reject(503, _UNAVAILABLE)
    try:
        if type(result) is not dict:
            raise ValueError("configuration result unavailable")
        return JSONResponse(result, status_code=201 if created else 200, headers=admission._HEADERS)
    except Exception:
        admission._reject(503, _UNAVAILABLE)


@router.get("")
async def configuration(request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from catchplate import operator_x_configuration as service

    await _read(request)
    return await _result(service.configuration, identity.user_id)


@router.post("")
async def configure(request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from catchplate import operator_x_configuration as service
    from catchplate.operator_x_oauth_profile import XOAuthApplicationInput

    _admit(request, mutation=True)
    payload = await admission._payload(request, XOAuthApplicationInput, MAX_INPUT_BYTES)
    return await _result(service.configure, payload, identity.user_id, created=True)


@router.get("/{operation_id}")
async def configuration_status(operation_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from catchplate import operator_x_configuration as service

    await _read(request)
    _identifier(operation_id)
    return await _result(service.status, operation_id, identity.user_id)
