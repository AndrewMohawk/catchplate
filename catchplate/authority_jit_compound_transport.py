"""Fixed opaque JIT planning exchange on one exact-peer Unix connection.

Framing is not signature, request, current-root or execution admission. All
lengths are checked before any body allocation; bodies stay separate immutable
byte strings. The caller supplies one absolute deadline, never a fresh timeout.
The accepted service socket is borrowed and remains owned by its listener.
"""
from __future__ import annotations

from dataclasses import dataclass
import socket

from catchplate import authority_jit_compound_request as request
from catchplate.authority_jit_original_transport import _ProcessingIO
from catchplate import authority_revocation_writer_transport as io
from catchplate import authority_transport


REQUEST_MAGIC = b"SWJP\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWJQ\x00\x00\x00\x01"
plan = request.parent
MAX_CONTROL_BYTES = request.MAX_CONTROL_BYTES
REQUEST_LIMITS = (MAX_CONTROL_BYTES, request.MAX_REQUEST_BYTES)
REPLY_LIMITS = request.RAW4_MAXIMA
REQUEST_HEADER_BYTES, REPLY_HEADER_BYTES = 16, 24
AuthorityTransportError = authority_transport.AuthorityTransportError


@dataclass(frozen=True, slots=True)
class FrameMetrics:
    body_bytes: tuple[int, ...]
    framing_bytes: int
    wire_bytes: int


@dataclass(frozen=True, slots=True)
class ExchangeMetrics:
    request: FrameMetrics
    reply: FrameMetrics


@dataclass(frozen=True, slots=True)
class RawRequest:
    control_bytes: bytes
    request_bytes: bytes
    metrics: FrameMetrics


@dataclass(frozen=True, slots=True)
class RawReply:
    originals: tuple[bytes, bytes, bytes, bytes]
    metrics: ExchangeMetrics


def _require(value):
    if not value:
        raise AuthorityTransportError("JIT planning transport framing differs")


def _deadline(deadline_ns):
    _require(type(deadline_ns) is int and 0 < deadline_ns < 2**63)
    io._check_deadline(deadline_ns)


def _lengths(lengths, limits):
    _require(type(lengths) is tuple and len(lengths) == len(limits)
        and all(type(size) is int and 2 <= size <= maximum
            for size, maximum in zip(lengths, limits, strict=True)))


def _bodies(values, limits):
    _require(type(values) is tuple and len(values) == len(limits)
        and all(type(value) is bytes for value in values))
    lengths = tuple(len(value) for value in values)
    _lengths(lengths, limits)
    return lengths


def _metrics(lengths, header):
    return FrameMetrics(lengths, header, header + sum(lengths))


def _header(magic, lengths):
    return magic + b"".join(size.to_bytes(4, "big") for size in lengths)


def _recv_bodies(connection, limits, deadline_ns):
    header = io._recv_exact_until(connection, 4 * len(limits), deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 4], "big")
        for offset in range(0, len(header), 4))
    _lengths(lengths, limits)
    bodies = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return bodies, lengths


def _recv_request(connection, *, prefix, deadline_ns):
    """Actual configured peer admission must precede prefix acquisition."""
    _deadline(deadline_ns)
    _require(type(prefix) is bytes and prefix == REQUEST_MAGIC)
    bodies, lengths = _recv_bodies(connection, REQUEST_LIMITS, deadline_ns)
    return RawRequest(bodies[0], bodies[1], _metrics(lengths, REQUEST_HEADER_BYTES))


def _send_reply(connection, *, originals, deadline_ns, processing_owner=None, processing_work=None):
    _deadline(deadline_ns)
    lengths = _bodies(originals, REPLY_LIMITS)
    held = _ProcessingIO(processing_owner, processing_work, deadline_ns)
    held.call(lambda: io._send_exact_until(connection, _header(RESPONSE_MAGIC, lengths), deadline_ns=deadline_ns))
    for raw in originals:
        held.call(lambda: io._send_exact_until(connection, raw, deadline_ns=deadline_ns))
    held.check()
    return _metrics(lengths, REPLY_HEADER_BYTES)


def _recv_reply(connection, deadline_ns):
    _require(io._recv_prefix(connection, deadline_ns=deadline_ns) == RESPONSE_MAGIC)
    bodies, lengths = _recv_bodies(connection, REPLY_LIMITS, deadline_ns)
    return bodies, _metrics(lengths, REPLY_HEADER_BYTES)


def _socket_exchange(path, *, control_bytes, request_bytes, original_deadline_ns,
        expected_peer_uid, expected_peer_gid):
    """Raw four-body response only; no peer-provided success/proof object."""
    _require(type(path) is str and 1 <= len(path) <= 107
        and path.startswith("/") and "\x00" not in path)
    try:
        _require(1 <= len(path.encode("utf-8")) <= 107)
    except UnicodeError as exc:
        raise AuthorityTransportError("JIT planning socket path is not Unicode") from exc
    _require(all(type(value) is int and 0 <= value <= 0xFFFFFFFF
        for value in (expected_peer_uid, expected_peer_gid)))
    request = (control_bytes, request_bytes)
    lengths = _bodies(request, REQUEST_LIMITS)
    _deadline(original_deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, original_deadline_ns, lambda: connection.connect(path))
        uid, gid, _pid = io._call_until(connection, original_deadline_ns,
            lambda: authority_transport._peer_identity(connection))
        _require(uid == expected_peer_uid and gid == expected_peer_gid)
        io._send_exact_until(connection, _header(REQUEST_MAGIC, lengths),
            deadline_ns=original_deadline_ns)
        for raw in request:
            io._send_exact_until(connection, raw, deadline_ns=original_deadline_ns)
        io._call_until(connection, original_deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        originals, reply_metrics = _recv_reply(connection, original_deadline_ns)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _deadline(original_deadline_ns)
    return RawReply(originals,
        ExchangeMetrics(_metrics(lengths, REQUEST_HEADER_BYTES), reply_metrics))
