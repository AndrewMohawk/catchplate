"""Bounded ordinary X account HTTP boundary, separate from generic OAuth.

Only the account owner can consume consent or perform provider I/O. Recovery
GETs are actor-owned observations; neither an absent response nor an absent
operation authorizes repeating a write. Provider responses never reach HTML.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
import html
import json
import re
import secrets
import time
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from serverware import auth, operator_catalog_api as admission
from serverware.operator_catalog_inputs import _identifier
from serverware.operator_x_account_inputs import DisconnectInput, StartInput

PREFIX = "/api/operator-demo/oauth/x"
CALLBACK = "/api/oauth/callback/x"
router = APIRouter(prefix=PREFIX)
_STATE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COOKIE_PREFIX = "__Host-serverware-x-oauth-"
_OPERATION_FIELDS = frozenset({"schema", "operation_id", "kind", "status", "credential_id",
    "reason", "created_at", "expires_at_epoch_ms"})
_STATUSES = frozenset({"consent_pending", "exchanging", "connected", "denied", "failed",
    "uncertain", "disconnect_pending", "disconnected"})
_UNAVAILABLE = "X account outcome unavailable; inspect the retained operation without repeating the action"
_HEADERS = {**admission._HEADERS, "Referrer-Policy": "no-referrer"}
_HTML_HEADERS = {**_HEADERS, "Content-Security-Policy":
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}


def _need(value):
    if not value:
        raise ValueError("X public response unavailable")


def _enabled():
    from serverware import operator_x_admission
    try:
        enabled = operator_x_admission.enabled()
    except Exception:
        admission._reject(503, _UNAVAILABLE)
    if enabled is not True:
        admission._reject(404, "X accounts are not supported by this deployment")


def _admit(request, *, mutation):
    admission._admit(request, mutation=mutation)
    _enabled()


async def _empty(request):
    if (request.headers.getlist("transfer-encoding") or request.headers.getlist("content-encoding")
            or request.headers.getlist("content-length") not in ([], ["0"])):
        admission._reject(400, "X account observation accepts no body")
    try:
        async with asyncio.timeout(30):
            async for chunk in request.stream():
                if chunk:
                    admission._reject(400, "X account observation accepts no body")
    except HTTPException:
        raise
    except TimeoutError:
        admission._reject(408, "X account observation body timed out")
    except Exception:
        admission._reject(400, "X account observation body unavailable")


def _id(value):
    try:
        _need(type(value) is str)
        return _identifier(value)
    except Exception:
        admission._reject(422, "invalid X account operation identifier")


def _operation(value):
    from serverware import operator_x_accounts as service
    _need(type(value) is dict and set(value) == _OPERATION_FIELDS
        and value["schema"] == "serverware.operatorXAccountOperation/v1"
        and value["kind"] in {"consent", "disconnect"} and value["status"] in _STATUSES)
    _identifier(value["operation_id"])
    if value["credential_id"] is not None:
        _identifier(value["credential_id"])
    _need(value["reason"] is None or value["reason"] in service.PUBLIC_REASONS)
    _need(type(value["created_at"]) is str and len(value["created_at"]) <= 64
        and datetime.fromisoformat(value["created_at"]).tzinfo is not None)
    expiry = value["expires_at_epoch_ms"]
    _need((value["kind"] == "disconnect" and expiry is None)
        or (type(expiry) is int and 0 < expiry < 9_007_199_254_740_991))
    return dict(value)


async def _call(function, *args):
    from serverware import operator_x_accounts as service
    from serverware.operator_catalog_schema import CatalogConflict
    try:
        return await admission._blocking(function, *args)
    except service.AccountNotFound:
        admission._reject(404, "X operation not found; absence does not authorize retry")
    except CatalogConflict:
        admission._reject(409, "X account review changed; inspect the retained operation before another action")
    except Exception:
        admission._reject(503, _UNAVAILABLE)


def _response(value, *, created=False):
    try:
        public = _operation(value)
        return JSONResponse(public, status_code=201 if created else 200, headers=_HEADERS)
    except Exception:
        admission._reject(503, _UNAVAILABLE)


def _start_response(value, nonce):
    from serverware import operator_x_admission, operator_x_oauth_protocol as protocol
    _need(type(value) is dict and set(value) == {"schema", "operation_id", "status", "authorization_url",
        "state", "expires_at_epoch_ms", "profile_binding_digest"}
        and value["schema"] == "serverware.operatorXConsent/v1" and value["status"] == "consent_pending")
    _identifier(value["operation_id"])
    _need(type(value["state"]) is str and _STATE.fullmatch(value["state"])
        and type(value["profile_binding_digest"]) is str and _HASH.fullmatch(value["profile_binding_digest"])
        and type(value["authorization_url"]) is str and len(value["authorization_url"]) <= 8192)
    parsed = urlsplit(value["authorization_url"])
    expected = urlsplit(protocol.AUTHORIZATION_URL)
    _need((parsed.scheme, parsed.netloc, parsed.path, parsed.fragment)
        == (expected.scheme, expected.netloc, expected.path, ""))
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=8)
    query = dict(pairs)
    _need(len(query) == len(pairs) and set(query) == {"response_type", "client_id", "redirect_uri",
        "scope", "state", "code_challenge", "code_challenge_method"}
        and query["response_type"] == "code" and query["state"] == value["state"]
        and query["redirect_uri"] == operator_x_admission.public_origin() + CALLBACK
        and query["scope"] == " ".join(protocol.SCOPES)
        and query["code_challenge_method"] == "S256"
        and re.fullmatch(r"[A-Za-z0-9_-]{43}", query["code_challenge"]))
    expiry = value["expires_at_epoch_ms"]
    remaining = expiry - time.time_ns() // 1_000_000 if type(expiry) is int else -1
    _need(0 < remaining <= 600_000)
    response = JSONResponse(dict(value), status_code=201, headers=_HEADERS)
    response.set_cookie(_COOKIE_PREFIX + value["state"], nonce, max_age=max(1, remaining // 1000),
        path="/", secure=True, httponly=True, samesite="lax")
    return response


@router.post("/start")
async def start(request: Request, identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    from serverware import operator_x_accounts as service
    _admit(request, mutation=True)
    payload = await admission._payload(request, StartInput, 4096)
    nonce = secrets.token_urlsafe(32)
    result = await _call(service.start, payload, identity.user_id, nonce)
    try:
        return _start_response(result, nonce)
    except Exception:
        admission._reject(503, _UNAVAILABLE)


@router.get("/operations/{operation_id}")
async def status(operation_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    from serverware import operator_x_accounts as service
    _admit(request, mutation=False)
    await _empty(request)
    return _response(await _call(service.status, _id(operation_id), identity.user_id))


@router.get("/accounts/{credential_id}/disconnect-review")
async def review(credential_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    from serverware import operator_x_accounts as service
    _admit(request, mutation=False)
    await _empty(request)
    value = await _call(service.review_disconnect, _id(credential_id), identity.user_id)
    # The owner exposes a closed, metadata-only review projection. Validate its
    # exact schema before serialization; private lifecycle records are not DTOs.
    try:
        public = service.validate_public_disconnect_review(value)
        _need(type(public) is dict and len(json.dumps(public).encode()) <= 65536)
        return JSONResponse(public, headers=_HEADERS)
    except Exception:
        admission._reject(503, _UNAVAILABLE)


@router.post("/disconnect")
async def disconnect(request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    from serverware import operator_x_accounts as service
    _admit(request, mutation=True)
    payload = await admission._payload(request, DisconnectInput, 4096)
    return _response(await _call(service.disconnect, payload, identity.user_id))


def _callback_query(request):
    raw = request.scope.get("query_string", b"")
    _need(type(raw) is bytes and 1 <= len(raw) <= 8192)
    text = raw.decode("ascii")
    _need(re.search(r"%(?![0-9a-fA-F]{2})", text) is None)
    pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True,
        encoding="utf-8", errors="strict", max_num_fields=4)
    query = dict(pairs)
    _need(len(query) == len(pairs) and set(query) <= {"state", "code", "error", "error_description"}
        and type(query.get("state")) is str and _STATE.fullmatch(query["state"])
        and ("code" in query) != ("error" in query)
        and ("error_description" not in query or "error" in query))
    for key in ("code", "error"):
        if key in query:
            _need(1 <= len(query[key]) <= (4096 if key == "code" else 128)
                and all(33 <= ord(char) <= 126 for char in query[key]))
    return query


def _callback_nonce(request, state):
    name = _COOKIE_PREFIX + state
    headers = request.headers.getlist("cookie")
    _need(sum(len(value) for value in headers) <= 32768)
    matches = []
    for header in headers:
        for item in header.split(";"):
            key, separator, value = item.strip().partition("=")
            if key == name:
                _need(separator == "=")
                matches.append(value)
    _need(len(matches) == 1 and re.fullmatch(r"[A-Za-z0-9_-]{43}", matches[0]))
    return name, matches[0]


def callback_response(request):
    """Called only by the exact admitted managed-X GET callback route."""
    from serverware import operator_x_accounts as service
    cookie_name = None
    operation_id = None
    connected = False
    try:
        admission._profile()
        _enabled()
        _need(request.method == "GET" and request.url.path == CALLBACK
            and not request.headers.getlist("transfer-encoding")
            and not request.headers.getlist("content-encoding")
            and request.headers.getlist("content-length") in ([], ["0"]))
        query = _callback_query(request)
        cookie_name, nonce = _callback_nonce(request, query["state"])
        operation = _operation(service.complete_callback(state=query["state"], code=query.get("code"),
            error=query.get("error"), browser_nonce=nonce))
        operation_id = operation["operation_id"]
        connected = operation["status"] == "connected"
    except Exception:
        # Never render provider errors, code/state, cookies, paths or exception
        # text. A lost reply does not establish rejection or authorize replay.
        pass
    title = "X account connected" if connected else "X account connection needs review"
    detail = ("Return to Serverware to give an application permission to use this account."
        if connected else "Inspect the saved operation in Serverware. Do not repeat this callback or connection automatically.")
    target = "/#credentials" if operation_id is None else "/?serverware_x_operation=" + operation_id + "#credentials"
    response = HTMLResponse("<!doctype html><html><head><meta charset=utf-8><title>Serverware</title></head>"
        "<body><h1>" + title + "</h1><p>" + detail + "</p><p><a href=\"" + html.escape(target, quote=True)
        + "\">Return to Serverware</a></p></body></html>", status_code=200 if connected else 409,
        headers=_HTML_HEADERS)
    if cookie_name is not None:
        response.delete_cookie(cookie_name, path="/", secure=True, httponly=True, samesite="lax")
    return response


async def callback(request):
    """Do not permit an undeclared callback body to reach the lifecycle owner."""
    admission._profile()
    _enabled()
    await _empty(request)
    return await admission._blocking(callback_response, request)
