"""Fixed raw JIT original-page packets over the existing exact-peer transport.

Authorization remains opaque original bytes here, not a signature verdict.
The service must independently admit its role signature and parent context.
Response identities bind the original request and exact body only: a read body
remains untrusted until genuine whole-parent replay. No SQL or authority route
is introduced, and no original deadline or work allowance is replaced.

Successful metrics count actual application framing/control/body bytes. I/O
precharges the outgoing frame and checks fixed maximum response capacity under
an allowance-neutral callback before charging the actual received frame. Failed
exchanges return no partial metrics, admission, or retry instruction.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib

from serverware import authority_jit_original_authorization as authorization
from serverware import authority_jit_original_control as control
from serverware import authority_jit_original_transport as transport
from serverware.authority_query_read_work import _ValidationWork


REQUEST_SCHEMA = "serverware.policyAuthorityJitOriginalPageRequest/v1"
RESPONSE_SCHEMA = "serverware.policyAuthorityJitOriginalPageResponse/v1"
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 16 * 1024
MAX_BODY_BYTES = 4 * 1024 * 1024
REQUEST_FIELDS = frozenset({"schema", "authorizationBase64Url", "controlBase64Url"})
RESPONSE_FIELDS = frozenset({"schema", "authorizationDigest", "controlDigest", "bodyDigest", "bodyByteCount"})
_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
evidence = authorization.evidence


class JitOriginalWireError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PageRequest:
    """Unadmitted original bytes, never parsed authorization claims."""

    authorization_bytes: bytes
    control_bytes: bytes


@dataclass(frozen=True, slots=True)
class PageExchange:
    """Untrusted raw body plus actual complete application-wire metrics."""

    body_bytes: bytes
    metrics: transport.ExchangeMetrics


def _require(value):
    if not value:
        raise JitOriginalWireError("JIT original page packet differs from its original request")


def _work(work):
    _require(type(work) is _ValidationWork)
    evidence.capture._SharedLedger(work)


def _raw(value, maximum, *, minimum=2):
    _require(type(value) is bytes and minimum <= len(value) <= maximum)


def _encode64(raw, maximum, work):
    _raw(raw, maximum)
    padded_size = 4 * ((len(raw) + 2) // 3)
    # Reserve original read, standard/url-safe padded bytes, ASCII text and
    # stripped output before emission. Final JSON is charged separately.
    work.charge(input_bytes=len(raw) + 4 * padded_size, json_nodes=1)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode64(value, maximum, work):
    _require(type(value) is str and 3 <= len(value) <= (4 * maximum + 2) // 3)
    work.charge(input_bytes=len(value))
    _require(len(value) % 4 != 1 and all(character in _ALPHABET for character in value))
    padded_size = len(value) + (-len(value) % 4)
    # ASCII, padding/concatenation and the decoder's alphabet translation are
    # reserved before decoding; the exact canonical re-encoding follows below.
    work.charge(input_bytes=len(value) + 3 * padded_size + 3 * (padded_size // 4), json_nodes=1)
    try:
        raw = base64.b64decode(value.encode("ascii") + b"=" * (-len(value) % 4),
            altchars=b"-_", validate=True)
    except (UnicodeError, binascii.Error) as exc:
        raise JitOriginalWireError("JIT original page base64 is not canonical") from exc
    _raw(raw, maximum)
    canonical = _encode64(raw, maximum, work)
    work.charge(input_bytes=len(value) + len(canonical))
    _require(canonical == value)
    return raw


def _encode(value, maximum, work):
    return evidence.plan.retained._bounded_wire(value, evidence.capture._SharedLedger(work),
        maximum_bytes=maximum, maximum_nodes=32)


def _decode(raw, fields, schema, maximum, work):
    value = evidence.wire._decode_object(raw, work=work,
        maximum_bytes=maximum, maximum_nodes=32, maximum_depth=2)
    authorization.parent._object(value, fields)
    _require(type(value["schema"]) is str and value["schema"] == schema)
    canonical = _encode(value, maximum, work)
    work.charge(input_bytes=len(canonical) + len(raw))
    _require(canonical == raw)
    return value


def _request(*, action, authorization_bytes, control_bytes, work):
    _work(work)
    _raw(authorization_bytes, authorization.MAX_BYTES)
    owned_control = control.decode_control(control_bytes, expected_action=action, work=work)
    value = {"schema": REQUEST_SCHEMA,
        "authorizationBase64Url": _encode64(authorization_bytes, authorization.MAX_BYTES, work),
        "controlBase64Url": _encode64(control_bytes, control.MAX_CONTROL_BYTES, work)}
    return _encode(value, MAX_REQUEST_BYTES, work), owned_control


def encode_request(*, action, authorization_bytes, control_bytes, work) -> bytes:
    return _request(action=action, authorization_bytes=authorization_bytes,
        control_bytes=control_bytes, work=work)[0]


def decode_request(request_bytes, *, expected_action, work) -> PageRequest:
    _work(work)
    value = _decode(request_bytes, REQUEST_FIELDS, REQUEST_SCHEMA, MAX_REQUEST_BYTES, work)
    raw_authorization = _decode64(value["authorizationBase64Url"], authorization.MAX_BYTES, work)
    raw_control = _decode64(value["controlBase64Url"], control.MAX_CONTROL_BYTES, work)
    control.decode_control(raw_control, expected_action=expected_action, work=work)
    return PageRequest(raw_authorization, raw_control)


def _response(*, authorization_bytes, control_bytes, body_bytes, work):
    _work(work)
    _raw(authorization_bytes, authorization.MAX_BYTES)
    _raw(control_bytes, control.MAX_CONTROL_BYTES)
    _raw(body_bytes, MAX_BODY_BYTES, minimum=2)
    work.charge(hashes=1, input_bytes=len(body_bytes))
    body_digest = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
    return {"schema": RESPONSE_SCHEMA,
        "authorizationDigest": evidence.plan._frame(authorization.IDENTITY_DOMAIN, (authorization_bytes,), work),
        "controlDigest": evidence.plan._frame(authorization.CONTROL_DOMAIN, (control_bytes,), work),
        "bodyDigest": body_digest, "bodyByteCount": len(body_bytes)}


def encode_response(*, authorization_bytes, control_bytes, body_bytes, work) -> bytes:
    return _encode(_response(authorization_bytes=authorization_bytes, control_bytes=control_bytes,
        body_bytes=body_bytes, work=work), MAX_RESPONSE_BYTES, work)


def decode_response(response_bytes, *, authorization_bytes, control_bytes, body_bytes, work) -> dict:
    _work(work)
    value = _decode(response_bytes, RESPONSE_FIELDS, RESPONSE_SCHEMA, MAX_RESPONSE_BYTES, work)
    # Exact integer checks reject bool aliases before the genuine body join.
    _require(type(value["bodyByteCount"]) is int and 2 <= value["bodyByteCount"] <= MAX_BODY_BYTES)
    for name in ("authorizationDigest", "controlDigest", "bodyDigest"):
        evidence.plan.contract._digest(value[name])
    expected = _response(authorization_bytes=authorization_bytes, control_bytes=control_bytes,
        body_bytes=body_bytes, work=work)
    work.prepare_comparison(value, expected)
    _require(value == expected)
    return value


def exchange(*, path, action, authorization_bytes, control_bytes, body_bytes,
        original_deadline_ns, expected_peer_uid, expected_peer_gid, work,
        transport_deadline_ns=None) -> PageExchange:
    """One exact-peer exchange; no signature verdict or successful proof DTO."""
    packet, selected = _request(action=action, authorization_bytes=authorization_bytes,
        control_bytes=control_bytes, work=work)
    _require(type(original_deadline_ns) is int
        and original_deadline_ns == selected["originalDeadlineNs"])
    # A receiving hop may have less time than the original signed operation.
    # Preserve that original in the packet; only narrow this local I/O budget.
    _require(transport_deadline_ns is None or
        type(transport_deadline_ns) is int and 0 < transport_deadline_ns < 2**63)
    effective_deadline = (original_deadline_ns if transport_deadline_ns is None
        else min(original_deadline_ns, transport_deadline_ns))
    if action == "persist":
        # Check the signed control's detached descriptor against the actual
        # original body before any transport side effect.
        control._body(selected, body_bytes, work)
    else:
        _require(body_bytes is None)
    request_body_size = 0 if body_bytes is None else len(body_bytes)
    expected_request = transport._metrics(len(packet), request_body_size, 17)
    work.charge(input_bytes=expected_request.wire_bytes)
    # The unchanged opaque transport knows incoming lengths before allocating.
    # Capacity for its fixed ceiling is held across an allowance-neutral call;
    # it is not refunded, replenished, or mislabeled as a SQL acquisition.
    _require(work.limits.max_input_bytes - work.input_bytes
        >= 16 + MAX_RESPONSE_BYTES + MAX_BODY_BYTES)
    response = evidence.production._callback(work, lambda: transport._socket_exchange(path,
        action=action, control_bytes=packet, body_bytes=body_bytes,
        original_deadline_ns=effective_deadline,
        expected_peer_uid=expected_peer_uid, expected_peer_gid=expected_peer_gid))
    _require(type(response) is transport.RawResponse
        and type(response.metrics) is transport.ExchangeMetrics
        and type(response.metrics.request) is transport.FrameMetrics
        and type(response.metrics.response) is transport.FrameMetrics)
    _raw(response.control_bytes, MAX_RESPONSE_BYTES)
    _raw(response.body_bytes, MAX_BODY_BYTES, minimum=2)
    expected_response = transport._metrics(len(response.control_bytes), len(response.body_bytes), 16)
    _require(response.metrics.request == expected_request and response.metrics.response == expected_response)
    work.charge(input_bytes=expected_response.wire_bytes)
    decode_response(response.control_bytes, authorization_bytes=authorization_bytes,
        control_bytes=control_bytes, body_bytes=response.body_bytes, work=work)
    if action == "persist":
        work.charge(input_bytes=len(body_bytes) + len(response.body_bytes))
        _require(response.body_bytes == body_bytes)
    evidence.production._callback(work, lambda: transport._deadline(effective_deadline))
    return PageExchange(response.body_bytes, response.metrics)
