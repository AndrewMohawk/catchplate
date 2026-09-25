"""Fixed verifier-to-planner registration-source byte exchange.

Requests carry original control and context bytes; responses carry original
response-control and source bytes. Framing neither authenticates these bytes
nor admits roots, enrollment, source observations or signing authority.

Both lengths and the existing aggregate ceiling are admitted before any body
allocation. One absolute deadline covers the peer-checked exchange, request
half-close and exact EOF in both directions. The serving owner checks its peer
before the prefix and allocates its one work allowance after the request EOF.
There is no SQL, signing, work allocation, retry or fallback in this module.
"""
from __future__ import annotations

import socket

from serverware import authority_contract, authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
REQUEST_MAGIC = b"SWRSQ001"
RESPONSE_MAGIC = b"SWRSR001"
MAX_REQUEST_BYTES = MAX_INPUT_BYTES
MAX_RESPONSE_BYTES = MAX_INPUT_BYTES
_PART_LIMITS = (authority_contract.MAX_REQUEST_BYTES, MAX_INPUT_BYTES)

_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, _PART_LIMITS))
            or sum(lengths) > MAX_INPUT_BYTES):
        raise AuthorityTransportError("registration source body lengths are invalid")


def _originals(values):
    if (type(values) is not tuple or len(values) != 2
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("registration source requires two original byte strings")
    _lengths(tuple(len(raw) for raw in values))
    return values


def _validate_request(*, control_bytes, context_bytes):
    return _originals((control_bytes, context_bytes))


def _validate_response(response_control_bytes, source_bytes):
    return _originals((response_control_bytes, source_bytes))


def _recv_bodies(connection, *, deadline_ns):
    header = io._recv_exact_until(connection, 16, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in (0, 8))
    # Admit the complete fixed inventory and sum before the first allocation.
    _lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return originals


def _recv_request(connection, *, prefix, deadline_ns):
    if type(prefix) is not bytes or prefix != REQUEST_MAGIC:
        raise AuthorityTransportError("registration source request magic is invalid")
    return _recv_bodies(connection, deadline_ns=deadline_ns)


def _send_response(connection, originals, *, deadline_ns):
    originals = _originals(originals)
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(endpoint, *, control_bytes, context_bytes, deadline_ns=None):
    """Return the original response pair from one configured peer.

    The endpoint is exactly (path, timeout_seconds, expected_peer_uid,
    expected_peer_gid), supplied by the configured owner, never the wire.
    """
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("registration source endpoint is not an exact four-tuple")
    path, timeout_seconds, expected_peer_uid, expected_peer_gid = endpoint
    originals = _validate_request(control_bytes=control_bytes, context_bytes=context_bytes)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("registration source socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("registration source socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("registration source socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("registration source peer identity is invalid")
    bounded_deadline = _deadline_ns(timeout_seconds)
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
        bounded_deadline = min(bounded_deadline, deadline_ns)
    deadline_ns = bounded_deadline
    header = REQUEST_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _check_deadline(deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        peer_uid, peer_gid, _peer_pid = io._call_until(connection, deadline_ns,
            lambda: authority_transport._peer_identity(connection))
        if peer_uid != expected_peer_uid or peer_gid != expected_peer_gid:
            raise AuthorityTransportError("registration source server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
            raise AuthorityTransportError("registration source response magic is invalid")
        response = _recv_bodies(connection, deadline_ns=deadline_ns)
    except BaseException:
        # Preserve the first failure; cleanup cannot authorize a retry.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return response
