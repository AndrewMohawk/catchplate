"""Administrator-only, bounded operator notification settings and receipts."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from serverware import auth, operator_catalog_api as admission


PREFIX = "/api/operator-demo/notifications"
SETTINGS_PATH = PREFIX + "/settings"
TEST_PATH = PREFIX + "/test"
MUTATION_PATHS = frozenset({SETTINGS_PATH, TEST_PATH})
router = APIRouter(prefix=PREFIX)


def _read(request: Request) -> None:
    admission._admit(request, mutation=False)
    if request.headers.getlist("transfer-encoding") or request.headers.getlist("content-length") not in ([], ["0"]):
        admission._reject(400, "notification status accepts no body")


async def _result(function, *args, accepted: bool = False) -> JSONResponse:
    from serverware import operator_notification_store as store

    try:
        result = await admission._blocking(function, *args)
        return JSONResponse(result, status_code=202 if accepted else 200, headers=admission._HEADERS)
    except store.NotificationNotFound:
        admission._reject(404, "notification operation not found")
    except store.NotificationConflict as exc:
        codes = {"notification_revision_conflict", "notification_operation_conflict",
            "notification_capacity_conflict", "notification_conflict"}
        code = getattr(exc, "code", "notification_conflict")
        return JSONResponse(status_code=409, headers=admission._HEADERS, content={
            "detail": "notification settings changed; inspect saved status before trying again",
            "code": code if code in codes else "notification_conflict"})
    except ValueError:
        admission._reject(422, "invalid notification input")
    except Exception:
        admission._reject(503, "notification storage unavailable; inspect saved status before retrying")


@router.get("")
async def notification_status(request: Request,
        _: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from serverware import operator_notifications

    _read(request)
    return await _result(operator_notifications.status)


@router.post("/settings")
async def save_settings(request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from serverware import operator_notification_store as store

    admission._admit(request, mutation=True)
    payload = await admission._payload(request, store.SaveInput, 16384)
    return await _result(store.save, payload, identity.user_id)


@router.post("/test")
async def send_test(request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from serverware import operator_notification_store as store

    admission._admit(request, mutation=True)
    payload = await admission._payload(request, store.TestInput, 1024)
    return await _result(store.queue_test, payload, identity.user_id, accepted=True)


@router.get("/operations/{operation_id}")
async def operation_status(operation_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)) -> JSONResponse:
    from serverware import operator_notification_store as store

    _read(request)
    try:
        if str(uuid.UUID(operation_id)) != operation_id:
            raise ValueError
    except (ValueError, AttributeError):
        admission._reject(404, "notification operation not found")
    return await _result(store.operation_status, operation_id, identity.user_id)
