"""One bounded opaque JIT original exchange, not JSON or authority admission.

Both directions keep the caller's original absolute deadline. Server callers
must admit the peer before receiving the eight-byte prefix. Control signatures,
parent context, page digests and database custody are verified elsewhere.
Metrics count actual application framing bytes, not kernel or allocation cost.
"""
from __future__ import annotations

from dataclasses import dataclass
import socket

from catchplate import authority_transport
from catchplate import authority_revocation_writer_transport as wire


AuthorityTransportError = authority_transport.AuthorityTransportError
REQUEST_MAGIC = b"SWJO\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWJR\x00\x00\x00\x01"
MAX_CONTROL_BYTES = 64 * 1024
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_CONTROL_BYTES = 16 * 1024
_ACTIONS = {"persist": b"P", "read": b"R"}


@dataclass(frozen=True, slots=True)
class FrameMetrics:
    control_bytes: int
    body_bytes: int
    framing_bytes: int
    wire_bytes: int


@dataclass(frozen=True, slots=True)
class ExchangeMetrics:
    request: FrameMetrics
    response: FrameMetrics


@dataclass(frozen=True, slots=True)
class RawRequest:
    action: str
    control_bytes: bytes
    body_bytes: bytes | None
    metrics: FrameMetrics


@dataclass(frozen=True, slots=True)
class RawResponse:
    control_bytes: bytes
    body_bytes: bytes
    metrics: ExchangeMetrics


def _require(value):
    if not value:
        raise AuthorityTransportError("JIT original transport framing differs")


def _deadline(deadline_ns):
    _require(type(deadline_ns) is int and 0 < deadline_ns < 2**63)
    wire._check_deadline(deadline_ns)


def _lengths(action, control, body):
    _require(type(action) is str and action in _ACTIONS
        and type(control) is int and 2 <= control <= MAX_CONTROL_BYTES
        and type(body) is int and (2 <= body <= MAX_BODY_BYTES if action == "persist" else body == 0))


def _response_lengths(control, body):
    _require(type(control) is int and 2 <= control <= MAX_RESPONSE_CONTROL_BYTES
        and type(body) is int and 2 <= body <= MAX_BODY_BYTES)


def _metrics(control, body, header):
    return FrameMetrics(control, body, header, header + control + body)


class _ProcessingIO:
    """Exact entered planning owner; fixed body I/O, not per-fragment scans.

    Every underlying syscall still uses the narrowed absolute deadline. These
    owner checks bracket each fixed header/body operation, connect, peer check,
    shutdown and EOF. They do not impose a new stream fragmentation limit.
    """

    def __init__(self, owner, work, deadline):
        self.owner, self.work, self.deadline = owner, work, deadline
        self.held = owner, work, deadline
        _require((owner is None) == (work is None))
        self.check()

    def check(self):
        _require(all(actual is original for actual, original in zip(
            (self.owner, self.work, self.deadline), self.held, strict=True)))
        if self.owner is not None:
            from catchplate.authority_jit_compound_request_service import _RequestOwner, _page_bounds

            _require(type(self.owner) is _RequestOwner)
            bounded, _epoch = _page_bounds(self.owner, original_window=self.owner.original,
                original_deadline_ns=self.owner.original_deadline, work=self.work)
            _require(self.deadline <= bounded)
        _deadline(self.deadline)

    def call(self, operation):
        self.check()
        try:
            result = operation()
        except BaseException:
            try:
                self.check()
            except BaseException:
                pass
            raise
        self.check()
        return result


def _recv_request(connection, *, prefix, deadline_ns):
    """Peer admission precedes prefix acquisition in the actual service owner."""
    _deadline(deadline_ns)
    _require(type(prefix) is bytes and prefix == REQUEST_MAGIC)
    header = wire._recv_exact_until(connection, 9, deadline_ns=deadline_ns)
    _require(header[:1] in (b"P", b"R"))
    action = "persist" if header[:1] == b"P" else "read"
    control, body = int.from_bytes(header[1:5], "big"), int.from_bytes(header[5:9], "big")
    _lengths(action, control, body)  # Both lengths precede either body allocation.
    control_bytes = wire._recv_exact_until(connection, control, deadline_ns=deadline_ns)
    body_bytes = wire._recv_exact_until(connection, body, deadline_ns=deadline_ns) if body else None
    wire._require_eof(connection, deadline_ns)
    return RawRequest(action, control_bytes, body_bytes, _metrics(control, body, 17))


def _send_response(connection, *, control_bytes, body_bytes, deadline_ns):
    _deadline(deadline_ns)
    _require(type(control_bytes) is bytes and type(body_bytes) is bytes)
    control, body = len(control_bytes), len(body_bytes)
    _response_lengths(control, body)
    header = RESPONSE_MAGIC + control.to_bytes(4, "big") + body.to_bytes(4, "big")
    for raw in (header, control_bytes, body_bytes):
        wire._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    wire._check_deadline(deadline_ns)
    # The service owns shutdown/close; this borrowed socket is not closed here.
    return _metrics(control, body, 16)


def _recv_response(connection, deadline_ns, *, processing=None):
    held = _ProcessingIO(None, None, deadline_ns) if processing is None else processing
    _require(type(held) is _ProcessingIO and held.deadline == deadline_ns)
    _require(held.call(lambda: wire._recv_prefix(connection, deadline_ns=deadline_ns)) == RESPONSE_MAGIC)
    header = held.call(lambda: wire._recv_exact_until(connection, 8, deadline_ns=deadline_ns))
    control, body = int.from_bytes(header[:4], "big"), int.from_bytes(header[4:], "big")
    _response_lengths(control, body)
    control_bytes = held.call(lambda: wire._recv_exact_until(connection, control, deadline_ns=deadline_ns))
    body_bytes = held.call(lambda: wire._recv_exact_until(connection, body, deadline_ns=deadline_ns))
    held.call(lambda: wire._require_eof(connection, deadline_ns))
    return control_bytes, body_bytes, _metrics(control, body, 16)


def _socket_exchange(path, *, action, control_bytes, body_bytes, original_deadline_ns,
                     expected_peer_uid, expected_peer_gid, processing_owner=None, processing_work=None):
    """Return raw bytes from one exact-peer exchange; never a verified result."""
    _require(type(path) is str and path.startswith("/") and "\x00" not in path and 1 <= len(path) <= 107)
    try:
        _require(len(path.encode("utf-8")) <= 107)
    except UnicodeError as exc:
        raise AuthorityTransportError("JIT original socket path is not Unicode") from exc
    _require(all(type(value) is int and 0 <= value <= 0xFFFFFFFF
        for value in (expected_peer_uid, expected_peer_gid)))
    _require(type(action) is str and action in _ACTIONS)
    _require(type(control_bytes) is bytes
        and (type(body_bytes) is bytes if action == "persist" else body_bytes is None))
    control, body = len(control_bytes), 0 if body_bytes is None else len(body_bytes)
    _lengths(action, control, body)
    _deadline(original_deadline_ns)
    processing = _ProcessingIO(processing_owner, processing_work, original_deadline_ns)
    header = REQUEST_MAGIC + _ACTIONS[action] + control.to_bytes(4, "big") + body.to_bytes(4, "big")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        processing.call(lambda: wire._call_until(connection, original_deadline_ns,
            lambda: connection.connect(path)))
        peer_uid, peer_gid, _peer_pid = processing.call(lambda: wire._call_until(
            connection, original_deadline_ns, lambda: authority_transport._peer_identity(connection)))
        _require(peer_uid == expected_peer_uid and peer_gid == expected_peer_gid)
        for raw in (header, control_bytes):
            processing.call(lambda: wire._send_exact_until(connection, raw, deadline_ns=original_deadline_ns))
        if body_bytes is not None:
            processing.call(lambda: wire._send_exact_until(connection, body_bytes, deadline_ns=original_deadline_ns))
        processing.call(lambda: wire._call_until(connection, original_deadline_ns,
            lambda: connection.shutdown(socket.SHUT_WR)))
        response_control, response_body, response_metrics = _recv_response(connection,
            original_deadline_ns, processing=processing)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    processing.check()
    return RawResponse(response_control, response_body,
        ExchangeMetrics(_metrics(control, body, 17), response_metrics))
