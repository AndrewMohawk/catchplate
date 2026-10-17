"""Raw fixed-phase cold-worker requests; an ACK is never execution authority."""
from __future__ import annotations

import errno
import socket

from catchplate import authority_oidc_session_activation_request_issuance_transport as planning
from catchplate import authority_oidc_session_activation_sql_transport as activation
from catchplate import authority_oidc_session_activation_delivery_sql_transport as consume

chunks, framing = planning.chunks, planning.framing
AuthorityTransportError = planning.AuthorityTransportError
LISTENER_PATH = "/run/catchplate/oidc-session-activation-execution-issuance/issue.sock"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOAEQ01", b"SWOAER01"
IDENTITY_DOMAIN = "catchplate.oidcSessionActivationExecutionIssuance/v1"
_PROFILES = {
    b"planning": planning.RESPONSE_LIMITS,
    b"activation-sql": activation.REQUEST_LIMITS,
    b"activation-completion": activation.REQUEST_LIMITS + activation.RESPONSE_LIMITS,
    b"consume-sql": consume.REQUEST_LIMITS,
    b"consume-completion": consume.REQUEST_LIMITS + consume.RESPONSE_LIMITS,
}
REQUEST_LIMITS = (32,) + tuple(max(limits[index] if index < len(limits) else 0
    for limits in _PROFILES.values()) for index in range(12))
RESPONSE_LIMITS = (6, 71)
REQUEST_HEADER_BYTES, RESPONSE_HEADER_BYTES = 112, 24
MAX_BYTES = MAX_EXCHANGE_BYTES = planning.MAX_EXCHANGE_BYTES
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
_deadline_ns = planning._deadline_ns


def _endpoint(value):
    if (type(value) is not tuple or len(value) != 4 or value[0] != LISTENER_PATH
            or type(value[1]) is not int or not 1 <= value[1] <= 30
            or type(value[2]) is not int or type(value[3]) is not int or value[2:] != (0, 0)):
        raise AuthorityTransportError("execution issuance endpoint is not source fixed")
    return value


def _response_lengths(lengths):
    if type(lengths) is not tuple or lengths != RESPONSE_LIMITS:
        raise AuthorityTransportError("execution issuance ACK shape differs")


def _request_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != len(REQUEST_LIMITS)
            or any(type(n) is not int or not 0 <= n <= cap
                for n, cap in zip(lengths, REQUEST_LIMITS, strict=True))
            or not 2 <= lengths[0] <= 32
            or sum(lengths) + REQUEST_HEADER_BYTES + RESPONSE_HEADER_BYTES + MAX_RESPONSE_BYTES > MAX_BYTES):
        raise AuthorityTransportError("execution issuance raw frame exceeds original source caps")


def _originals(values, *, response):
    if type(response) is not bool or type(values) is not tuple or any(type(raw) is not bytes for raw in values):
        raise AuthorityTransportError("execution issuance requires exact original bytes")
    if response:
        _response_lengths(tuple(map(len, values)))
        if values[0] != b"staged" or not framing._digest_bytes(values[1]):
            raise AuthorityTransportError("execution issuance ACK is not the exact original identity")
        return values
    _request_lengths(tuple(map(len, values)))
    phase = values[0]
    if phase not in _PROFILES:
        raise AuthorityTransportError("execution issuance phase is not source fixed")
    limits, raw = _PROFILES[phase], values[1:]
    selected = raw[:len(limits)]
    if any(raw[len(limits):]):
        raise AuthorityTransportError("execution issuance has nonempty unused frames")
    if phase == b"planning":
        planning._originals(selected, response=True)
    else:
        profile = consume if phase.startswith(b"consume") else activation
        profile._originals(selected[:8], response=False)
        if len(selected) == 12:
            profile._originals(selected[8:], response=True)
    return values


def _pack(phase, originals):
    if type(phase) is not bytes or phase not in _PROFILES or type(originals) is not tuple:
        raise AuthorityTransportError("execution issuance requires a fixed phase and raw originals")
    if len(originals) != len(_PROFILES[phase]):
        raise AuthorityTransportError("execution issuance original count differs")
    return _originals((phase, *originals, *(b"" for _ in range(12 - len(originals)))), response=False)


def _identity(originals, work):
    digest = planning.issuance.plan._frame(IDENTITY_DOMAIN, _originals(originals, response=False), work)
    work.charge(input_bytes=71)
    return digest.encode("ascii")


def _recv_request(connection, *, deadline_ns, work, current):
    kwargs = dict(deadline_ns=deadline_ns, work=work, current=current)
    chunks._connection(connection, **kwargs)
    if chunks._recv_exact(connection, 8, **kwargs) != REQUEST_MAGIC:
        raise AuthorityTransportError("execution issuance request magic differs")
    header = chunks._recv_exact(connection, 104, **kwargs)
    work.charge(input_bytes=104)
    lengths = tuple(int.from_bytes(header[i:i + 8], "big") for i in range(0, 104, 8))
    _request_lengths(lengths)
    work.charge(input_bytes=2 * sum(lengths))
    values = tuple(chunks._recv_precharged(connection, n, **kwargs) if n else b"" for n in lengths)
    chunks._eof(connection, **kwargs)
    held = _originals(values, response=False)
    chunks._peer(connection, (0, 0) if held[0] == b"planning" else (65532, 65532), **kwargs)
    return held


def _send_response(connection, originals, *, deadline_ns, work, current):
    kwargs = dict(deadline_ns=deadline_ns, work=work, current=current)
    held = _originals((b"staged", _identity(originals, work)), response=True)
    work.charge(input_bytes=2 * RESPONSE_HEADER_BYTES + sum(map(len, held)))
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        chunks._send_precharged(connection, raw, **kwargs)
    chunks._guard(work, current, deadline_ns)


def _request_on_work(phase, *, originals, deadline_ns, work, current):
    from catchplate import authority_oidc_session_activation_caller_transport as caller
    held = _pack(phase, originals)
    expected = _identity(held, work)
    received = caller._execution_issuance_on_work((LISTENER_PATH, 30, 0, 0),
        originals=held, deadline_ns=deadline_ns, work=work, current=current)
    work.charge(input_bytes=142)
    if received != (b"staged", expected):
        raise AuthorityTransportError("execution issuance ACK changed the raw originals")
    chunks._guard(work, current, deadline_ns)


def _stage_planning_on_work(channel, *, originals, deadline_ns, work, current):
    from catchplate import oidc_session_activation_request_issuer_startup as issuer
    if type(channel) is not issuer._StagingChannel:
        raise AuthorityTransportError("execution staging requires the actual root issuer channel")
    kwargs = dict(deadline_ns=deadline_ns, work=work, current=current)
    held = _pack(b"planning", originals)
    expected = _identity(held, work)
    channel.check(**kwargs)
    try:
        connection = channel.open()
        result = chunks._native(lambda: connection.connect_ex(LISTENER_PATH), **kwargs)
        if type(result) is not int or result not in (0, errno.EINPROGRESS, errno.EALREADY):
            raise AuthorityTransportError("execution staging connection failed")
        if result:
            chunks._ready(connection, writing=True, **kwargs)
            if chunks._native(lambda: connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), **kwargs):
                raise AuthorityTransportError("execution staging connection was not established")
        chunks._peer(connection, (0, 0), **kwargs)
        work.charge(input_bytes=2 * REQUEST_HEADER_BYTES + sum(map(len, held)))
        header = REQUEST_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)
        for raw in (header, *held):
            chunks._send_precharged(connection, raw, **kwargs)
        chunks._native(lambda: connection.shutdown(socket.SHUT_WR), **kwargs)
        if chunks._recv_exact(connection, RESPONSE_HEADER_BYTES, **kwargs) != (
                RESPONSE_MAGIC + (6).to_bytes(8, "big") + (71).to_bytes(8, "big")):
            raise AuthorityTransportError("execution staging response header differs")
        response = chunks._recv_exact(connection, MAX_RESPONSE_BYTES, **kwargs)
        chunks._eof(connection, **kwargs)
        work.charge(input_bytes=MAX_RESPONSE_BYTES)
        if response != b"staged" + expected:
            raise AuthorityTransportError("execution staging ACK changed the actual raw7")
    finally:
        channel.close()
    chunks._guard(work, current, deadline_ns)
