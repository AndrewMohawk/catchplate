"""Bounded machine renewal authenticated only by an enrolled workload key.

The transactional store verifies the current grant and proof. This route
neither enrolls keys nor forwards administrator credentials or retries writes.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import operator_demo, operator_workload_renewal as wire
from serverware.setup_receipts import JsonLimits, parse_strict_json_object

router = APIRouter()
_SLOTS = asyncio.BoundedSemaphore(4)
_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie",
    "x-serverware-admin-token", "x-serverware-bootstrap-token", "x-serverware-data-plane-token",
    "remote-user", "remote-groups", "remote-email", "remote-name", "origin"})


def _reject(status: int, code: str):
    raise HTTPException(status_code=status, detail={"code": code}, headers=_HEADERS)


def _admit(request: Request) -> int:
    try:
        active = operator_demo.active()
    except Exception:
        _reject(503, "workload_renewal_unavailable")
    if not active:
        _reject(404, "not_found")
    if (request.method != "POST" or request.scope.get("path") != wire.INTERNAL_PATH
            or request.scope.get("raw_path", wire.INTERNAL_PATH.encode()) != wire.INTERNAL_PATH.encode()
            or request.scope.get("query_string")):
        _reject(400, "workload_renewal_target_refused")
    if any(request.headers.getlist(name) for name in _CREDENTIAL_HEADERS):
        _reject(401, "workload_renewal_credentials_refused")
    names = [name.lower() for name, _ in request.scope.get("headers", [])]
    if len(names) != len(set(names)):
        _reject(400, "workload_renewal_framing_refused")
    if (request.headers.getlist("content-type") != ["application/json"]
            or request.headers.getlist("content-encoding") or request.headers.getlist("transfer-encoding")):
        _reject(400, "workload_renewal_framing_refused")
    lengths = request.headers.getlist("content-length")
    if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal()
            or len(lengths[0]) > 4 or str(int(lengths[0])) != lengths[0]):
        _reject(400, "workload_renewal_framing_refused")
    length = int(lengths[0])
    if not 0 < length <= wire.MAX_REQUEST_BYTES:
        _reject(413, "workload_renewal_request_too_large")
    return length


async def _payload(request: Request) -> wire.RenewalRequest:
    length = _admit(request)
    raw = bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(chunk) > wire.MAX_REQUEST_BYTES - len(raw):
                    _reject(413, "workload_renewal_request_too_large")
                raw.extend(chunk)
    except HTTPException:
        raise
    except TimeoutError:
        _reject(408, "workload_renewal_body_timeout")
    except Exception:
        _reject(400, "workload_renewal_body_unavailable")
    if len(raw) != length:
        _reject(400, "workload_renewal_framing_refused")
    try:
        value = parse_strict_json_object(bytes(raw), limits=JsonLimits(max_bytes=wire.MAX_REQUEST_BYTES,
            max_depth=2, max_object_keys=16, max_total_keys=16, max_array_items=1,
            max_total_nodes=32, max_string_bytes=1024))
        return wire.RenewalRequest.model_validate(dict(value))
    except (ValueError, TypeError, RecursionError):
        _reject(422, "workload_renewal_request_refused")


async def _renew(payload):
    from serverware import app, operator_workload_renewal_store as store
    # This owner retains its slot until the worker finishes, including after
    # caller cancellation. An unknown outcome never triggers a second call.
    async with asyncio.timeout(10):
        return await app._run_bounded_blocking(_SLOTS, store.renew, payload)


@router.post(wire.INTERNAL_PATH)
async def renew(request: Request) -> JSONResponse:
    from serverware.operator_catalog_mutations import CatalogNotFound
    from serverware.operator_catalog_schema import CatalogConflict, CatalogIntegrityError

    payload = await _payload(request)
    try:
        result = await _renew(payload)
    except CatalogNotFound:
        _reject(404, "workload_renewal_not_found")
    except CatalogConflict:
        _reject(409, "workload_renewal_conflict")
    except CatalogIntegrityError:
        _reject(503, "workload_renewal_outcome_unavailable")
    except ValueError:
        _reject(401, "workload_renewal_proof_refused")
    except Exception:
        _reject(503, "workload_renewal_outcome_unavailable")
    try:
        if len(wire.canonical(result)) > wire.MAX_RESPONSE_BYTES:
            _reject(503, "workload_renewal_outcome_unavailable")
        return JSONResponse(result, headers=_HEADERS)
    except HTTPException:
        raise
    except Exception:
        _reject(503, "workload_renewal_outcome_unavailable")
