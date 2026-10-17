"""Bounded administrator API for first managed Google configuration.

Preparation stores inactive configuration; only the existing cold-start owner
may activate it. This router never restarts, contacts Google, changes runtime
configuration or replays an uncertain operation. Legacy setup routes are separate.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from catchplate import auth, operator_catalog_api as admission


PREFIX = "/api/operator-demo/oauth/google/configuration/v2"
router = APIRouter(prefix=PREFIX)
_UNAVAILABLE = "Google configuration outcome unavailable; inspect the retained operation without repeating the action"
_NOT_FOUND = "Managed Google configuration operation not found; absence does not authorize retry"


def _admit(request: Request, *, mutation: bool) -> None:
    admission._admit(request, mutation=mutation)
    from catchplate import operator_google_managed_config as managed

    try:
        enabled = managed.enabled()
    except Exception:
        admission._reject(503, _UNAVAILABLE)
    if not enabled:
        admission._reject(404, "Managed Google configuration is not supported by this deployment")


async def _read(request: Request) -> None:
    _admit(request, mutation=False)
    if (request.headers.getlist("transfer-encoding") or request.headers.getlist("content-encoding")
            or request.headers.getlist("content-length") not in ([], ["0"])):
        admission._reject(400, "Google configuration status accepts no body")
    # Do not trust framing alone: an ASGI client can supply actual bytes with
    # an absent or zero Content-Length. Inspect without retaining any body.
    try:
        async with asyncio.timeout(30):
            async for chunk in request.stream():
                if chunk:
                    admission._reject(400, "Google configuration status accepts no body")
    except HTTPException:
        raise
    except TimeoutError:
        admission._reject(408, "Google configuration status body timed out")
    except Exception:
        admission._reject(400, "Google configuration status body unavailable")


def _identifier(value: str) -> None:
    from catchplate.operator_catalog_inputs import _identifier as canonical_identifier

    try:
        canonical_identifier(value)
    except (ValueError, TypeError, AttributeError):
        admission._reject(422, "invalid Google configuration operation identifier")


def _v2_operation(value):
    from catchplate import operator_google_setup as setup

    if type(value) is dict and value.get("schema") in {
            "catchplate.operatorGoogleSetup/v1", setup.MANAGED_PUBLIC}:
        raise setup.SetupNotFound("operator Google setup not found")
    if (type(value) is not dict or value.get("schema") != setup.MANAGED_PUBLIC_V2
            or value.get("setup_contract") != setup.MANAGED_BINDING_V2):
        raise setup.SetupUnavailable("operator Google setup unavailable")
    return value


def _status(operation_id, actor_id):
    from catchplate import operator_google_setup as setup, operator_publication as publication
    from catchplate.development_sandbox import _open_directory

    # Keep legacy status() unchanged: its db.connect() can initialize storage.
    # Recovery instead uses the original admitted lock and existing read-only
    # database, with the same exact actor/setup/audit/custody decoder.
    with publication.exclusive():
        with publication.closing_fd(_open_directory(publication._directory())) as descriptor:
            with publication._read_database(descriptor) as conn:
                if conn.execute("PRAGMA read_uncommitted").fetchone()[0] != 0:
                    raise setup.SetupUnavailable("operator Google setup unavailable")
                return _v2_operation(setup._public(setup._get(conn, operation_id, actor_id)))


def _prepare(payload, actor_id):
    from catchplate import operator_google_setup as setup

    return _v2_operation(setup.prepare_configuration(payload, actor_id))


def _cancel(payload, actor_id):
    from catchplate import operator_google_setup as setup

    # Retained operation identity/binding cannot be replaced. The exact actor
    # and v2 check precede cancel's existing transaction, which repeats actor,
    # pending-state and current catalog/policy CAS checks before any mutation.
    _status(payload.operation_id, actor_id)
    return _v2_operation(setup.cancel(payload, actor_id))


async def _result(function, *args, created: bool = False) -> JSONResponse:
    from catchplate import operator_google_setup as setup
    from catchplate.operator_catalog_schema import CatalogConflict
    from catchplate.operator_google_configuration import ConfigurationUnavailable

    try:
        result = await admission._blocking(function, *args)
    except ConfigurationUnavailable:
        admission._reject(404, "Managed Google configuration is not supported by this deployment")
    except setup.SetupNotFound:
        admission._reject(404, _NOT_FOUND)
    except CatalogConflict:
        admission._reject(409, "Google configuration review changed; inspect the retained operation before preparing again")
    except Exception:
        # SetupUnavailable can wrap a commit acknowledgement failure. No
        # lifecycle exception is treated as definitive input rejection here.
        admission._reject(503, _UNAVAILABLE)
    try:
        return JSONResponse(result, status_code=201 if created else 200, headers=admission._HEADERS)
    except Exception:
        # Serialization can fail after a successful commit; preserve recovery.
        admission._reject(503, _UNAVAILABLE)


@router.get("")
async def configuration(request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from catchplate import operator_google_configuration as discovery

    await _read(request)
    return await _result(discovery.configuration, identity.user_id)


@router.post("")
async def prepare_configuration(request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from catchplate import operator_google_setup as setup

    _admit(request, mutation=True)
    payload = await admission._payload(request, setup.ManagedSetupInput, 8192)
    return await _result(_prepare, payload, identity.user_id, created=True)


@router.get("/{operation_id}")
async def configuration_status(operation_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    await _read(request)
    _identifier(operation_id)
    return await _result(_status, operation_id, identity.user_id)


@router.post("/cancel")
async def cancel_configuration(request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from catchplate import operator_google_setup as setup

    _admit(request, mutation=True)
    payload = await admission._payload(request, setup.CancelInput, 2048)
    return await _result(_cancel, payload, identity.user_id)
