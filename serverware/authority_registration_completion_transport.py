"""Bounded fixed-purpose exchange with the cold registration completion owner.

The raw2 request selects only recovery of one independently pinned packet.
Raw4 returns original completion request/state receipt, or bounded uncertainty.
Framing and local listener credentials authenticate neither those originals
nor currentness, completion, finalization or new execution permission.

All lengths precede body allocation. Exact EOF and one inherited absolute
deadline cover the exchange; there is no parser, work allowance, callback
input, retry, arbitrary operation or fallback endpoint.
"""
from __future__ import annotations

import math
import socket

from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_current_root_delivery_records as records


PURPOSE = b"recover-registration-evidence-completion"
REQUEST_MAGIC = b"SWRCMP01"
RESPONSE_MAGIC = b"SWRCMR01"
LISTENER_PATH = "/run/serverware/registration-execution/completion.sock"
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
REQUEST_LIMITS = (len(PURPOSE), 71)
RESPONSE_LIMITS = (len(b"acknowledged"), 71, records.MAX_REQUEST_BYTES,
    records.MAX_RECEIPT_BYTES)
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
AuthorityTransportError = authority_transport.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix


def _timeout(timeout_seconds):
    if (type(timeout_seconds) not in (int, float)
            or not 1 <= timeout_seconds <= 30 or not math.isfinite(timeout_seconds)):
        raise AuthorityTransportError("registration completion timeout is invalid")
    return timeout_seconds


def _deadline_ns(timeout_seconds):
    return io._deadline_ns(_timeout(timeout_seconds))


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("registration completion endpoint is not an exact four-tuple")
    path, timeout_seconds, uid, gid = endpoint
    if type(path) is not str or path != LISTENER_PATH:
        raise AuthorityTransportError("registration completion socket path differs")
    if (type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("registration completion endpoint peer differs")
    return path, _timeout(timeout_seconds), uid, gid


def _request_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int for size in lengths)
            or lengths != REQUEST_LIMITS):
        raise AuthorityTransportError("registration completion request lengths differ")


def _response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 4
            or any(type(size) is not int or not 0 <= size <= maximum
                for size, maximum in zip(lengths, RESPONSE_LIMITS))):
        raise AuthorityTransportError("registration completion response lengths exceed their bounds")
    state, digest, request, receipt = lengths
    if not ((state == len(b"acknowledged") and digest == 71
            and 2 <= request <= records.MAX_REQUEST_BYTES
            and 2 <= receipt <= records.MAX_RECEIPT_BYTES)
            or (state == len(b"uncertain") and digest == request == receipt == 0)):
        raise AuthorityTransportError("registration completion response inventory differs")


def _digest_bytes(raw):
    return (len(raw) == 71 and raw[:7] == b"sha256:"
        and all(byte in b"0123456789abcdef" for byte in raw[7:]))


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("registration completion frame direction is invalid")
    count = len(RESPONSE_LIMITS) if response else len(REQUEST_LIMITS)
    if (type(values) is not tuple or len(values) != count
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("registration completion requires its exact original byte inventory")
    lengths = tuple(len(raw) for raw in values)
    if not response:
        _request_lengths(lengths)
        if values[0] != PURPOSE or not _digest_bytes(values[1]):
            raise AuthorityTransportError("registration completion selector differs")
        return values
    _response_lengths(lengths)
    state, digest, request, receipt = values
    if not ((state == b"acknowledged" and _digest_bytes(digest)
            and 2 <= len(request) <= records.MAX_REQUEST_BYTES
            and 2 <= len(receipt) <= records.MAX_RECEIPT_BYTES)
            or (state == b"uncertain" and digest == request == receipt == b"")):
        raise AuthorityTransportError("registration completion response fields differ")
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("registration completion frame direction is invalid")
    count = len(RESPONSE_LIMITS) if response else len(REQUEST_LIMITS)
    header = io._recv_exact_until(connection, count * 8, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, len(header), 8))
    if response:
        _response_lengths(lengths)
    else:
        _request_lengths(lengths)
    values = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        if size else b"" for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _originals(values, response=response)


def _recv_request(connection, *, deadline_ns):
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("registration completion request magic differs")
    return _recv_bodies(connection, response=False, deadline_ns=deadline_ns)


def _send(connection, originals, *, response, deadline_ns):
    held = _originals(originals, response=response)
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        if raw:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_response(connection, originals, *, deadline_ns):
    # The actual owner establishes durable, authenticated acknowledgment.
    # This function supplies only closed framing; its owner closes for EOF.
    _send(connection, originals, response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns=None):
    """Return unverified raw4 after one fixed root-listener peer exchange."""
    path, timeout_seconds, uid, gid = _endpoint(endpoint)
    bound = _deadline_ns(timeout_seconds)
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
        bound = min(bound, deadline_ns)
    held = _originals(originals, response=False)
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("registration completion server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("registration completion response magic differs")
        received = _recv_bodies(connection, response=True, deadline_ns=bound)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(bound)
    return received
