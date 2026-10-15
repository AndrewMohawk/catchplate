"""Authenticated operator-only transport for explicit host-trusted approvals."""
from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from serverware import auth, config, operator_catalog_api as admission
from serverware import operator_host_approvals as store
from serverware.setup_receipts import JsonLimits, parse_strict_json_object

router = APIRouter()
_UUID = store.UUID_PATTERN
owns_post = store.owns_post


def _exact(request, path, *, bodyless=False):
    if (request.scope.get("raw_path") != path.encode("ascii") or request.query_params
            or bodyless and (request.headers.getlist("content-length") not in ([], ["0"])
                or request.headers.getlist("transfer-encoding"))):
        admission._reject(400, "approval request transport refused")


async def _payload(request, maximum):
    if (len(request.headers.getlist("content-type")) != 1
            or request.headers["content-type"].split(";", 1)[0].strip().lower() != "application/json"
            or request.headers.getlist("content-encoding")):
        admission._reject(415, "approval request requires unencoded application/json")
    lengths, transfers = request.headers.getlist("content-length"), request.headers.getlist("transfer-encoding")
    if (len(lengths) > 1 or len(transfers) > 1 or lengths and transfers
            or transfers and transfers != ["chunked"]
            or lengths and (not lengths[0].isascii() or not lengths[0].isdecimal() or len(lengths[0]) > 10)):
        admission._reject(400, "approval request framing refused")
    declared = int(lengths[0]) if lengths else None
    if declared is not None and declared > maximum:
        admission._reject(413, "approval request exceeds size limit")
    body = bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(chunk) > maximum - len(body):
                    admission._reject(413, "approval request exceeds size limit")
                body.extend(chunk)
    except TimeoutError:
        admission._reject(408, "approval request body timed out")
    if declared is not None and declared != len(body):
        admission._reject(400, "approval request length differs")
    try:
        return admission._plain(parse_strict_json_object(bytes(body), limits=JsonLimits(
            max_bytes=maximum, max_depth=16, max_object_keys=128, max_total_keys=1024,
            max_array_items=256, max_total_nodes=4096, max_string_bytes=32768)))
    except (ValueError, TypeError, RecursionError):
        admission._reject(422, "invalid approval request")


async def _result(function, *args):
    try:
        return JSONResponse(await admission._blocking(function, *args), headers=admission._HEADERS)
    except store.ApprovalNotFound:
        admission._reject(404, "approval not found")
    except store.ApprovalConflict:
        admission._reject(409, "approval changed or is unavailable; inspect current status")
    except Exception:
        # A response may be lost after commit: never retry a decision or claim.
        admission._reject(503, "approval outcome unavailable; inspect current status before continuing")


async def _mutation(request, identifier, identity, action):
    admission._admit(request, mutation=True)
    if not re.fullmatch(_UUID, identifier):
        admission._reject(404, "approval not found")
    _exact(request, store.PREFIX + "/" + identifier + "/" + action)
    if (identity.user_id != config.ADMIN_USER_ID or identity.auth_method != "admin-token-header"
            or not identity.has_any_role({"admin"})):
        admission._reject(403, "configured operator administrator required")
    if not await admission._blocking(store.available):
        admission._reject(503, "host-trusted approval runtime unavailable")
    return await _payload(request, 2048)


@router.get(store.PREFIX)
async def approvals(request: Request, identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    admission._admit(request, mutation=False)
    _exact(request, store.PREFIX, bodyless=True)
    return await _result(store.list_pending, identity.user_id)


@router.get(store.PREFIX + "/{approval_id}")
async def approval_status(approval_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    admission._admit(request, mutation=False)
    if not re.fullmatch(_UUID, approval_id):
        admission._reject(404, "approval not found")
    _exact(request, store.PREFIX + "/" + approval_id, bodyless=True)
    return await _result(store.status, approval_id, identity.user_id)


@router.post(store.PREFIX + "/{approval_id}/review")
async def approval_review(approval_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    value = await _mutation(request, approval_id, identity, "review")
    if value != {}:
        admission._reject(422, "review accepts an empty object only")
    return await _result(store.review, approval_id, identity.user_id)


@router.post(store.PREFIX + "/{approval_id}/decision")
async def approval_decision(approval_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    value = await _mutation(request, approval_id, identity, "decision")
    return await _result(store.decide, approval_id, identity.user_id, value)


@router.post(store.CLAIM_PATH)
async def approval_claim(request: Request):
    from serverware import app as application
    admission._profile()
    _exact(request, store.CLAIM_PATH)
    tokens = request.headers.getlist("x-serverware-data-plane-token")
    if len(tokens) != 1:
        admission._reject(401, "data-plane authentication required")
    application._require_data_plane_token(tokens[0], config.DATA_PLANE_CREDENTIAL_LEASE_TOKEN)
    if not store.enabled():
        admission._reject(503, "host-trusted approval runtime unavailable")
    value = await _payload(request, store.MAX_REQUEST_BYTES)
    return await _result(store.claim, value)
