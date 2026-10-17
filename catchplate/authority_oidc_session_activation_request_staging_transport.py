"""Exact root-to-root raw7 staging, never planner-ready or currentness evidence."""
from __future__ import annotations

import errno
import socket

from catchplate import authority_oidc_session_activation_request_issuance_transport as issuance


chunks, framing = issuance.chunks, issuance.framing
LISTENER_PATH = "/run/catchplate/oidc-session-activation/request-bootstrap.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-request-bootstrap"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOASQ01", b"SWOASR01"
IDENTITY_DOMAIN = "catchplate.oidcSessionActivationRequestStagingOriginals/v1"
REQUEST_LIMITS, RESPONSE_LIMITS = issuance.RESPONSE_LIMITS, (6, 71)
REQUEST_HEADER_BYTES, RESPONSE_HEADER_BYTES = 64, 24
MAX_ORIGINAL_BYTES = sum(REQUEST_LIMITS)
MAX_EXCHANGE_BYTES = issuance.MAX_EXCHANGE_BYTES


def _fail(message):
    raise issuance.AuthorityTransportError(message)


def _originals(values, *, response):
    if type(response) is not bool or type(values) is not tuple:
        _fail("activation staging requires exact original tuple/direction")
    limits = RESPONSE_LIMITS if response else REQUEST_LIMITS
    if (len(values) != len(limits) or any(type(raw) is not bytes for raw in values)
            or any(not 2 <= len(raw) <= maximum for raw, maximum in zip(values, limits, strict=True))
            or REQUEST_HEADER_BYTES + MAX_ORIGINAL_BYTES + RESPONSE_HEADER_BYTES
                + sum(RESPONSE_LIMITS) > MAX_EXCHANGE_BYTES):
        _fail("activation staging exceeds its fixed original inventory")
    if response and (values[0] != b"staged" or not framing._digest_bytes(values[1])):
        _fail("activation staging ACK requires exact status and original identity")
    return values


def _identity(originals, *, work, current, deadline_ns):
    held = _originals(originals, response=False)
    chunks._guard(work, current, deadline_ns)
    digest = issuance.issuance.plan._frame(IDENTITY_DOMAIN, held, work)
    work.charge(input_bytes=71)
    result = digest.encode("ascii")
    chunks._guard(work, current, deadline_ns)
    return result


def _receive(connection, *, response, deadline_ns, work, current, maximum_original_bytes):
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    limits = RESPONSE_LIMITS if response else REQUEST_LIMITS
    if (type(maximum_original_bytes) is not int
            or not 14 <= maximum_original_bytes <= MAX_ORIGINAL_BYTES):
        _fail("activation staging cap is not an original tightening")
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    if chunks._recv_exact(connection, 8, **kwargs) != magic:
        _fail("activation staging magic differs")
    header = chunks._recv_exact(connection, 8 * len(limits), **kwargs)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, len(header), 8))
    if (any(not 2 <= size <= maximum for size, maximum in zip(lengths, limits, strict=True))
            or response and lengths != RESPONSE_LIMITS
            or not response and sum(lengths) > maximum_original_bytes):
        _fail("activation staging lengths exceed original retained capacity")
    work.charge(input_bytes=2 * sum(lengths))
    values = tuple(chunks._recv_precharged(connection, size, **kwargs) for size in lengths)
    chunks._eof(connection, **kwargs)
    held = _originals(values, response=response)
    chunks._guard(work, current, deadline_ns)
    return held


def _send(connection, originals, *, response, deadline_ns, work, current):
    held = _originals(originals, response=response)
    header_size = RESPONSE_HEADER_BYTES if response else REQUEST_HEADER_BYTES
    work.charge(input_bytes=2 * header_size + sum(map(len, held)))
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        chunks._send_precharged(connection, raw, **kwargs)
    chunks._guard(work, current, deadline_ns)


def _recv_request(connection, *, deadline_ns, work, current, maximum_original_bytes):
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (0, 0), **kwargs)
    return _receive(connection, response=False,
        maximum_original_bytes=maximum_original_bytes, **kwargs)


def _send_response(connection, originals, *, deadline_ns, work, current):
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (0, 0), **kwargs)
    _send(connection, originals, response=True, **kwargs)


def _stage_on_work(channel, *, originals, deadline_ns, work, current):
    """Only the actual cold issuer channel owns connection creation/cleanup."""
    from catchplate import oidc_session_activation_request_issuer_startup as startup

    if type(channel) is not startup._StagingChannel:
        _fail("activation staging requires the genuine root issuer channel")
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    held = _originals(originals, response=False)
    channel.check(work=work, deadline_ns=deadline_ns, current=current)
    expected = _identity(held, **kwargs)
    try:
        connection = channel.open()
        chunks._connection(connection, **kwargs)
        status = chunks._native(lambda: connection.connect_ex(LISTENER_PATH), **kwargs)
        if type(status) is not int or status not in (0, errno.EINPROGRESS, errno.EALREADY):
            _fail("activation staging connection failed")
        if status:
            chunks._ready(connection, writing=True, **kwargs)
            error = chunks._native(lambda: connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), **kwargs)
            if type(error) is not int or error:
                _fail("activation staging connection was not established")
        chunks._peer(connection, (0, 0), **kwargs)
        _send(connection, held, response=False, **kwargs)
        chunks._native(lambda: connection.shutdown(socket.SHUT_WR), **kwargs)
        received = _receive(connection, response=True,
            maximum_original_bytes=MAX_ORIGINAL_BYTES, **kwargs)
        work.charge(input_bytes=142)
        if received != (b"staged", expected):
            _fail("activation staged ACK differs from the original raw7")
    finally:
        channel.close()
    chunks._guard(work, current, deadline_ns)
    return received
