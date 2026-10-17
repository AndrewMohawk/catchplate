"""Bounded machine-only ECR signing transport for the ordinary publication owner.

AWS tuples are opened only inside the owner's current signing transaction.
Only encrypted, exact-request signing headers leave it, after possible-send
commits. The application's existing response signer authenticates these replies;
this router is not a standalone unsigned transport and performs no provider I/O.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
import uuid

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from catchplate import aws_ecr_signing as signing, ecr_sdk_protocol as protocol
from catchplate.setup_receipts import JsonLimits, parse_strict_json_object

PREFIX = "/api/data-plane/ecr-publications"
CONTEXT_PATH, RESERVE_PATH, FINISH_PATH = (PREFIX + "/" + name for name in ("context", "reserve", "finish"))
CONTEXT_VERSION = "catchplate.ecrContextRequest/v1"
CONTEXT_RESPONSE_VERSION = "catchplate.ecrContextResponse/v1"
RESERVE_VERSION = "catchplate.ecrSigningRequest/v1"
ENVELOPE_VERSION = "catchplate.ecrSigningEnvelope/v1"
SIGNED_VERSION = "catchplate.ecrSignedRequest/v1"
FINISH_VERSION = "catchplate.ecrFinishRequest/v1"
FINISH_RESPONSE_VERSION = "catchplate.ecrFinishResponse/v1"
MAX_CONTEXT_BYTES = 4096
MAX_RESERVE_BYTES = 22 * 1024**2 + 8192
MAX_FINISH_BYTES = 34 * 1024**2 + 4096
MAX_ERROR_BYTES = 64 * 1024
_COMMON = {"apiVersion", "publicationId", "principalId", "routeId", "credentialId", "policyHash"}
_RESERVE = _COMMON | {"childId", "expectedCredentialVersion", "dataPlaneBinaryDigest", "action",
    "bodyBase64", "bodySha256", "recipientPublicKey", "recipientKeyId", "recipientNonce", "maxTtlSeconds"}
_FINISH = _COMMON | {"childId", "expectedCredentialVersion", "requestBindingSha256", "outcome"}
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
_WORKERS = asyncio.BoundedSemaphore(2)
_BODIES = asyncio.BoundedSemaphore(2)
router = APIRouter()


class SigningUnavailable(ValueError):
    def __init__(self):
        super().__init__("ECR signing request unavailable")


def owns_post(path):
    return path in (CONTEXT_PATH, RESERVE_PATH, FINISH_PATH)


def _need(value):
    if not value:
        raise SigningUnavailable()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash(value):
    _need(type(value) is str and _SHA.fullmatch(value) is not None)


def _uuid(value):
    _need(type(value) is str and len(value) == 36)
    try:
        parsed = uuid.UUID(value)
        _need(str(parsed) == value and parsed.version == 4)
    except (ValueError, AttributeError):
        raise SigningUnavailable() from None


def _url32(value):
    _need(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=")
    _need(len(raw) == 32 and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def _body(value, maximum):
    _need(type(value) is str and len(value) <= 4 * ((maximum + 2) // 3))
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        raise SigningUnavailable() from None
    _need(len(raw) <= maximum and base64.b64encode(raw).decode("ascii") == value)
    return raw


def _common(wire, version):
    _need(type(wire) is dict and wire.get("apiVersion") == version)
    _uuid(wire["publicationId"])
    _hash(wire["policyHash"])
    for field in ("principalId", "routeId", "credentialId"):
        value = wire[field]
        _need(type(value) is str and 0 < len(value.encode("utf-8")) <= 256
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    if "childId" in wire:
        _uuid(wire["childId"])
        _need(type(wire["expectedCredentialVersion"]) is int
            and 1 <= wire["expectedCredentialVersion"] < 2**63)


def _pins(wire):
    return {"principal_id": wire["principalId"], "route_id": wire["routeId"],
        "credential_id": wire["credentialId"], "credential_generation": wire["expectedCredentialVersion"],
        "policy_hash": wire["policyHash"],
        "request_binding_sha256": wire.get("requestBindingSha256", _sha(canonical(wire)))}


def _public_binding(value, wire, *, generation=True):
    _need(type(value) is dict and value.get("id") == wire["publicationId"])
    for key, field in (("principal_id", "principalId"), ("route_id", "routeId"),
                       ("credential_id", "credentialId"), ("policy_hash", "policyHash")):
        _need(value.get(key) == wire[field])
    _need(type(value.get("credential_generation")) is int and value["credential_generation"] > 0)
    if generation:
        _need(value["credential_generation"] == wire["expectedCredentialVersion"])


def context(wire):
    from catchplate import operator_ecr_publications as owner
    _need(type(wire) is dict and set(wire) == _COMMON)
    _common(wire, CONTEXT_VERSION)
    value = owner.require_client(wire["principalId"], wire["publicationId"])
    _public_binding(value, wire, generation=False)
    _need(type(value["expires_at_epoch_ms"]) is int
        and value["expires_at_epoch_ms"] > time.time_ns() // 1_000_000)
    return {**wire, "apiVersion": CONTEXT_RESPONSE_VERSION,
        "credentialVersion": value["credential_generation"], "expiresAtEpochMs": value["expires_at_epoch_ms"]}


def reserve(wire, response_nonce):
    from catchplate import app, crypto, db, operator_ecr_publications as owner
    _need(type(wire) is dict and set(wire) == _RESERVE)
    _common(wire, RESERVE_VERSION)
    for field in ("bodySha256", "recipientKeyId", "dataPlaneBinaryDigest"):
        _hash(wire[field])
    _need(wire["dataPlaneBinaryDigest"] == app.EXPECTED_DATA_PLANE_BINARY_DIGEST
        and type(wire["action"]) is str and wire["action"] in protocol.ACTIONS
        and type(wire["maxTtlSeconds"]) is int and 1 <= wire["maxTtlSeconds"] <= 5
        and wire["recipientNonce"] == response_nonce)
    recipient, nonce = _url32(wire["recipientPublicKey"]), _url32(wire["recipientNonce"])
    _need(_sha(recipient) == wire["recipientKeyId"])
    body = _body(wire["bodyBase64"], protocol.MAX_REQUEST_BYTES)
    _need(body and _sha(body) == wire["bodySha256"])
    pins = _pins(wire)
    owner.reserve(wire["publicationId"], child_id=wire["childId"], action=wire["action"], body=body, **pins)
    child_pins = {**pins, "publication_id": wire["publicationId"]}
    try:
        with owner.signing_transaction(wire["childId"], **child_pins) as (conn, retained):
            _need(retained.publication_id == wire["publicationId"] and retained.child_id == wire["childId"]
                and retained.action == wire["action"] and retained.body == body
                and retained.request_sha256 == wire["bodySha256"]
                and retained.request_binding_sha256 == pins["request_binding_sha256"])
            for key in ("principal_id", "route_id", "credential_id", "credential_generation", "policy_hash"):
                _need(retained.binding[key] == pins[key])
            issued = time.time_ns() // 1_000_000
            publication_expires = retained.deadline.unix_seconds * 1000
            expires = min(issued + wire["maxTtlSeconds"] * 1000, publication_expires)
            _need(expires > issued and time.monotonic_ns() < retained.deadline.monotonic_ns)
            credentials = db.open_operator_ecr_credentials(conn, wire["credentialId"],
                expected_version=wire["expectedCredentialVersion"])
            signed = signing.sign(credentials, region=retained.binding["scope"]["region"],
                action=retained.action, body=retained.body,
                clock=signing.ClockObservation(issued // 1000, time.monotonic_ns()), include_accept=True)
            del credentials
            aad = {"apiVersion": ENVELOPE_VERSION, "requestBindingSha256": pins["request_binding_sha256"],
                "publicationId": wire["publicationId"], "childId": wire["childId"],
                "principalId": wire["principalId"], "routeId": wire["routeId"],
                "credentialId": wire["credentialId"], "credentialVersion": wire["expectedCredentialVersion"],
                "policyHash": wire["policyHash"], "dataPlaneBinaryDigest": wire["dataPlaneBinaryDigest"],
                "recipientKeyId": wire["recipientKeyId"], "recipientNonce": wire["recipientNonce"],
                "issuedAtEpochMs": issued, "expiresAtEpochMs": expires,
                "publicationExpiresAtEpochMs": publication_expires}
            plaintext = {"apiVersion": SIGNED_VERSION, "method": signed.method, "scheme": signed.scheme,
                "authority": signed.authority, "path": signed.path, "query": signed.query,
                "bodySha256": "sha256:" + signed.body_sha256, "bodyLength": signed.body_length,
                "headers": dict(signed.headers)}
            encrypted = crypto.encrypt_credential_lease_envelope(recipient_public_key=recipient,
                recipient_nonce=nonce, aad=aad, plaintext=plaintext)
            del plaintext
            signing.require_fresh(signed, clock=signing.ClockObservation(
                time.time_ns() // 1_000_000_000, time.monotonic_ns()))
            del signed
            _need(time.time_ns() // 1_000_000 < expires
                and time.monotonic_ns() < retained.deadline.monotonic_ns)
        # The owner's context manager has committed possible_send before this
        # point. Losing this response never grants a second signing attempt.
        _need(time.time_ns() // 1_000_000 < expires
            and time.monotonic_ns() < retained.deadline.monotonic_ns)
        return {**aad, **encrypted}
    except Exception:
        try:
            owner.fail(wire["childId"], before_send=True, **child_pins)
        except Exception:
            pass
        raise SigningUnavailable() from None


def finish(wire):
    from catchplate import operator_ecr_publications as owner
    _need(type(wire) is dict and wire.get("outcome") in ("response", "unknown"))
    response = wire["outcome"] == "response"
    _need(set(wire) == _FINISH | ({"statusCode", "responseBodyBase64"} if response else set()))
    _common(wire, FINISH_VERSION)
    _hash(wire["requestBindingSha256"])
    pins = {**_pins(wire), "publication_id": wire["publicationId"]}
    if response:
        status = wire["statusCode"]
        _need(type(status) is int and 100 <= status <= 599)
        body = _body(wire["responseBodyBase64"], protocol.MAX_RESPONSE_BYTES if status == 200 else MAX_ERROR_BYTES)
        value = owner.finish(wire["childId"], status=status, body=body, **pins)
        response_digest = _sha(body)
    else:
        value = owner.fail(wire["childId"], before_send=False, **pins)
        response_digest = None
    _public_binding(value, wire)
    child = value.get("child")
    _need(type(child) is dict and child.get("id") == wire["childId"]
        and child.get("request_binding_sha256") == wire["requestBindingSha256"])
    _hash(child.get("request_sha256"))
    acknowledged = child.get("status") == "acknowledged"
    ack_parent = value.get("status") in {"active", "published"} or (
        value.get("status") == "failed" and value.get("terminal_reason") == "authority_changed_after_send")
    _need(type(value.get("revision")) is int and value["revision"] >= 0
        and value.get("status") in {"active", "published", "failed", "uncertain", "expired"}
        and (response and ack_parent if acknowledged else value["status"] in {"failed", "uncertain", "expired"})
        and (not acknowledged or child.get("response_sha256") == response_digest))
    return {"apiVersion": FINISH_RESPONSE_VERSION, "publicationId": wire["publicationId"],
        "childId": wire["childId"], "requestBindingSha256": wire["requestBindingSha256"],
        "principalId": wire["principalId"], "routeId": wire["routeId"], "credentialId": wire["credentialId"],
        "credentialVersion": wire["expectedCredentialVersion"], "policyHash": wire["policyHash"],
        "requestBodySha256": child["request_sha256"], "responseBodySha256": response_digest,
        "status": value["status"], "revision": value["revision"], "acknowledged": acknowledged,
        # An AWS acknowledgment records an effect, not permission to release its
        # response. In particular, the final write may succeed after revocation.
        "responseReleaseAllowed": acknowledged and value["status"] in {"active", "published"}
            and value.get("terminal_reason") != "authority_changed_after_send"}


def _reject(status):
    raise HTTPException(status_code=status, detail="ECR signing request unavailable", headers=_HEADERS) from None


def _admit(request, path):
    from catchplate import app, config, operator_demo
    tokens = request.headers.getlist("x-catchplate-data-plane-token")
    if len(tokens) != 1:
        _reject(401)
    try:
        app._require_data_plane_token(tokens[0], config.DATA_PLANE_CREDENTIAL_LEASE_TOKEN)
        app._require_currentness_response_context(request, path)
    except HTTPException as exc:
        _reject(exc.status_code if exc.status_code in {400, 401, 403, 503} else 503)
    try:
        enabled = operator_demo.active()
    except Exception:
        _reject(503)
    if not enabled:
        _reject(404)
    if request.scope.get("raw_path") != path.encode("ascii") or request.query_params:
        _reject(400)
    return request.headers["x-catchplate-response-nonce"]


async def _payload(request, maximum):
    if (len(request.headers.getlist("content-type")) != 1
            or request.headers["content-type"].split(";", 1)[0].strip().lower() != "application/json"
            or request.headers.getlist("content-encoding")):
        _reject(415)
    lengths, transfers = request.headers.getlist("content-length"), request.headers.getlist("transfer-encoding")
    if (len(lengths) > 1 or len(transfers) > 1 or lengths and transfers
            or transfers and transfers != ["chunked"]
            or lengths and (not lengths[0].isascii() or not lengths[0].isdecimal() or len(lengths[0]) > 10)):
        _reject(400)
    declared = int(lengths[0]) if lengths else None
    if declared is not None and declared > maximum:
        _reject(413)
    raw = bytearray()
    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                if len(chunk) > maximum - len(raw):
                    _reject(413)
                raw.extend(chunk)
    except HTTPException:
        raise
    except TimeoutError:
        _reject(408)
    except Exception:
        _reject(400)
    if declared is not None and declared != len(raw):
        _reject(400)
    return bytes(raw)


def _execute(raw, maximum, function, nonce):
    try:
        wire = dict(parse_strict_json_object(raw, limits=JsonLimits(max_bytes=maximum,
            max_depth=2, max_object_keys=20, max_total_keys=20, max_array_items=1,
            max_total_nodes=24, max_string_bytes=maximum)))
    except Exception:
        _reject(422)
    try:
        return function(wire, nonce) if function is reserve else function(wire)
    except Exception:
        # Even a lost commit acknowledgment never causes an automatic retry.
        _reject(503)


async def _post(request, path, maximum, function):
    from catchplate import app
    try:
        nonce = _admit(request, path)
        async with _BODIES:
            raw = await _payload(request, maximum)
            result = await app._run_bounded_blocking(_WORKERS, _execute, raw, maximum, function, nonce)
        return JSONResponse(result, headers=_HEADERS)
    except HTTPException:
        raise
    except Exception:
        _reject(503)


@router.post(CONTEXT_PATH)
async def context_request(request: Request):
    return await _post(request, CONTEXT_PATH, MAX_CONTEXT_BYTES, context)


@router.post(RESERVE_PATH)
async def reserve_request(request: Request):
    return await _post(request, RESERVE_PATH, MAX_RESERVE_BYTES, reserve)


@router.post(FINISH_PATH)
async def finish_request(request: Request):
    return await _post(request, FINISH_PATH, MAX_FINISH_BYTES, finish)
