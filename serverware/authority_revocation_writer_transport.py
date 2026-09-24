"""Fixed detached writer framing, without signature or application admission.

The five bodies remain opaque original bytes. Their aggregate ceiling is a
necessary condition of the unchanged verification work ceiling, not a promise
that a transfer fits the remaining allowance. Socket copies and framing are
transport work, not JSON/hash work. A returned ACK is not authenticated here.
There is one absolute deadline and one exchange per connection; neither side
accepts trailing bytes. The owner must check its peer before receiving a prefix.
"""
from __future__ import annotations

import math
import socket
import time

from serverware import authority_contract, authority_transport
from serverware.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
TRANSFER_SCHEMA = "serverware.policyAuthorityRevocationWriterTransfer/v1"
REQUEST_MAGIC = b"SWRW\x00\x00\x00\x01"
ACK_MAGIC = b"SWRA\x00\x00\x00\x01"
MAX_REQUEST_BYTES = MAX_INPUT_BYTES
MAX_ACK_BYTES = 16384
_PART_LIMITS = (authority_contract.MAX_REQUEST_BYTES,
    authority_contract.MAX_REQUEST_BYTES, authority_contract.MAX_RESULT_BYTES,
    512 * 1024, MAX_INPUT_BYTES)
_CHUNK_BYTES = 1024 * 1024
_NANOSECONDS = 1_000_000_000


def _deadline_ns(timeout_seconds):
    # Match the actual service startup request-timeout range, not DB timeouts.
    if (type(timeout_seconds) not in (int, float)
            or not 0.05 <= timeout_seconds <= 30
            or not math.isfinite(timeout_seconds)):
        raise AuthorityTransportError("writer transfer timeout is invalid")
    now = time.monotonic_ns()
    if type(now) is not int or now < 0:
        raise AuthorityTransportError("writer transfer clock is invalid")
    return now + int(timeout_seconds * _NANOSECONDS)


def _check_deadline(deadline_ns):
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("writer transfer deadline is invalid")
    now = time.monotonic_ns()
    if type(now) is not int or now < 0 or now >= deadline_ns:
        raise AuthorityTransportError("writer transfer deadline expired")
    return deadline_ns - now


def _call_until(connection, deadline_ns, operation):
    remaining = _check_deadline(deadline_ns)
    connection.settimeout(remaining / _NANOSECONDS)
    _check_deadline(deadline_ns)
    result = operation()
    _check_deadline(deadline_ns)
    return result


def _recv_exact_until(connection, count, *, deadline_ns):
    if type(count) is not int or not 1 <= count <= MAX_REQUEST_BYTES:
        raise AuthorityTransportError("writer transfer read length is invalid")
    _check_deadline(deadline_ns)
    # Fixed-size storage avoids one retained Python object per tiny read.
    buffer = bytearray(count)
    remaining = count
    while remaining:
        size = min(remaining, _CHUNK_BYTES)
        chunk = _call_until(connection, deadline_ns, lambda: connection.recv(size))
        if type(chunk) is not bytes or not 1 <= len(chunk) <= size:
            raise AuthorityTransportError("writer transfer closed early or over-read")
        offset = count - remaining
        buffer[offset:offset + len(chunk)] = chunk
        remaining -= len(chunk)
    result = bytes(buffer)
    _check_deadline(deadline_ns)
    return result


def _recv_prefix(connection, *, deadline_ns):
    return _recv_exact_until(connection, 8, deadline_ns=deadline_ns)


def _validate_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 5
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, _PART_LIMITS))
            or sum(lengths) > MAX_REQUEST_BYTES):
        raise AuthorityTransportError("writer transfer body lengths are invalid")


def _require_eof(connection, deadline_ns):
    tail = _call_until(connection, deadline_ns, lambda: connection.recv(1))
    if type(tail) is not bytes or tail != b"":
        raise AuthorityTransportError("writer transfer has trailing bytes")


def _recv_request(connection, *, deadline_ns, prefix):
    if type(prefix) is not bytes or prefix != REQUEST_MAGIC:
        raise AuthorityTransportError("writer transfer request magic is invalid")
    header = _recv_exact_until(connection, 40, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, 40, 8))
    # All five lengths and the sum are admitted before any body allocation.
    _validate_lengths(lengths)
    originals = tuple(_recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    _require_eof(connection, deadline_ns)
    return originals


def _send_exact_until(connection, raw, *, deadline_ns):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_REQUEST_BYTES:
        raise AuthorityTransportError("writer transfer write length is invalid")
    for offset in range(0, len(raw), _CHUNK_BYTES):
        chunk = raw[offset:offset + _CHUNK_BYTES]
        _call_until(connection, deadline_ns, lambda: connection.sendall(chunk))


def _send_ack(connection, acknowledgment_bytes, *, deadline_ns):
    if (type(acknowledgment_bytes) is not bytes
            or not 2 <= len(acknowledgment_bytes) <= MAX_ACK_BYTES):
        raise AuthorityTransportError("writer acknowledgment bytes are invalid")
    header = ACK_MAGIC + len(acknowledgment_bytes).to_bytes(8, "big")
    _send_exact_until(connection, header, deadline_ns=deadline_ns)
    _send_exact_until(connection, acknowledgment_bytes, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(path, *, intent_bytes, relay_bytes, envelope_bytes,
        evaluation_context_bytes, historical_expectations_bytes, timeout_seconds,
        expected_peer_uid, expected_peer_gid):
    """Return original, unauthenticated ACK bytes from one exact peer exchange."""
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("writer transfer socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("writer transfer socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("writer transfer socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("writer transfer peer identity is invalid")
    originals = (intent_bytes, relay_bytes, envelope_bytes,
        evaluation_context_bytes, historical_expectations_bytes)
    if any(type(value) is not bytes for value in originals):
        raise AuthorityTransportError("writer transfer bodies are not exact bytes")
    lengths = tuple(len(value) for value in originals)
    _validate_lengths(lengths)
    deadline_ns = _deadline_ns(timeout_seconds)
    header = REQUEST_MAGIC + b"".join(size.to_bytes(8, "big") for size in lengths)
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _check_deadline(deadline_ns)
        _call_until(connection, deadline_ns, lambda: connection.connect(path))
        peer_uid, peer_gid, _peer_pid = _call_until(connection, deadline_ns,
            lambda: authority_transport._peer_identity(connection))
        if peer_uid != expected_peer_uid or peer_gid != expected_peer_gid:
            raise AuthorityTransportError("writer transfer server peer differs")
        _send_exact_until(connection, header, deadline_ns=deadline_ns)
        for original in originals:
            _send_exact_until(connection, original, deadline_ns=deadline_ns)
        _call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        prefix = _recv_prefix(connection, deadline_ns=deadline_ns)
        if prefix != ACK_MAGIC:
            raise AuthorityTransportError("writer acknowledgment magic is invalid")
        length = int.from_bytes(_recv_exact_until(connection, 8,
            deadline_ns=deadline_ns), "big")
        if not 2 <= length <= MAX_ACK_BYTES:
            raise AuthorityTransportError("writer acknowledgment length is invalid")
        acknowledgment_bytes = _recv_exact_until(connection, length,
            deadline_ns=deadline_ns)
        _require_eof(connection, deadline_ns)
    except BaseException:
        # Cleanup must preserve the first transport/native failure.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return acknowledgment_bytes
