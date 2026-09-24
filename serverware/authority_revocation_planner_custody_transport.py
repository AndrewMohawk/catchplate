"""Separate original-byte relay preparation and custody-forwarding exchanges.

SWRL/SWLR returns an opaque original planner relay before any SWRF/SWFA
forwarding exchange. Neither operation authenticates a control or ACK, proves
custody, or automatically invokes the other operation. Callers retain and
independently verify the originals before proceeding or explicitly retrying.

The serving owner must check its peer before receiving the request prefix.
Every request length is admitted before body allocation, and complete request
EOF must precede application work. Clients check their pinned peer before any
send and require response EOF; the serving owner closes its accepted connection.
Each connection has one absolute deadline and
no JSON error union, response reconstruction, re-signing or automatic retry.
The unchanged writer-v1 primitives own bounded I/O, not authentication or work.
"""
from __future__ import annotations

import socket

from serverware import authority_contract, authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
TRANSFER_SCHEMA = "serverware.policyAuthorityRevocationPlannerCustodyTransfer/v1"
RELAY_REQUEST_MAGIC = b"SWRL\x00\x00\x00\x01"
RELAY_RESPONSE_MAGIC = b"SWLR\x00\x00\x00\x01"
FORWARD_REQUEST_MAGIC = b"SWRF\x00\x00\x00\x01"
FORWARD_RESPONSE_MAGIC = b"SWFA\x00\x00\x00\x01"
MAX_REQUEST_BYTES = MAX_INPUT_BYTES
MAX_RELAY_BYTES = authority_contract.MAX_REQUEST_BYTES
MAX_ACK_BYTES = 16384
_RELAY_LIMITS = (authority_contract.MAX_REQUEST_BYTES, authority_contract.MAX_RESULT_BYTES,
    512 * 1024, MAX_INPUT_BYTES)
_FORWARD_LIMITS = (authority_contract.MAX_REQUEST_BYTES, authority_contract.MAX_REQUEST_BYTES,
    authority_contract.MAX_RESULT_BYTES, 512 * 1024, MAX_INPUT_BYTES)

_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _validate_lengths(lengths, limits):
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, limits))
            or sum(lengths) > MAX_REQUEST_BYTES):
        raise AuthorityTransportError("planner custody transfer body lengths are invalid")


def _validate_relay_lengths(lengths):
    _validate_lengths(lengths, _RELAY_LIMITS)


def _validate_forward_lengths(lengths):
    _validate_lengths(lengths, _FORWARD_LIMITS)


def _recv_originals(connection, *, deadline_ns, prefix, request_magic, limits):
    if type(prefix) is not bytes or prefix != request_magic:
        raise AuthorityTransportError("planner custody transfer request magic is invalid")
    header_size = 8 * len(limits)
    header = io._recv_exact_until(connection, header_size, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, header_size, 8))
    _validate_lengths(lengths, limits)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return originals


def _recv_relay_request(connection, *, deadline_ns, prefix):
    return _recv_originals(connection, deadline_ns=deadline_ns, prefix=prefix,
        request_magic=RELAY_REQUEST_MAGIC, limits=_RELAY_LIMITS)


def _recv_forward_request(connection, *, deadline_ns, prefix):
    return _recv_originals(connection, deadline_ns=deadline_ns, prefix=prefix,
        request_magic=FORWARD_REQUEST_MAGIC, limits=_FORWARD_LIMITS)


def _send_response(connection, raw, *, deadline_ns, response_magic, maximum):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise AuthorityTransportError("planner custody transfer response bytes are invalid")
    header = response_magic + len(raw).to_bytes(8, "big")
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_relay(connection, relay_bytes, *, deadline_ns):
    _send_response(connection, relay_bytes, deadline_ns=deadline_ns,
        response_magic=RELAY_RESPONSE_MAGIC, maximum=MAX_RELAY_BYTES)


def _send_ack(connection, acknowledgment_bytes, *, deadline_ns):
    _send_response(connection, acknowledgment_bytes, deadline_ns=deadline_ns,
        response_magic=FORWARD_RESPONSE_MAGIC, maximum=MAX_ACK_BYTES)


def _exchange(path, originals, *, request_magic, limits, response_magic, response_maximum,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("planner custody transfer socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("planner custody transfer socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("planner custody transfer socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("planner custody transfer peer identity is invalid")
    if any(type(raw) is not bytes for raw in originals):
        raise AuthorityTransportError("planner custody transfer bodies are not exact bytes")
    lengths = tuple(len(raw) for raw in originals)
    _validate_lengths(lengths, limits)
    deadline_ns = _deadline_ns(timeout_seconds)
    header = request_magic + b"".join(size.to_bytes(8, "big") for size in lengths)
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _check_deadline(deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        peer_uid, peer_gid, _peer_pid = io._call_until(connection, deadline_ns,
            lambda: authority_transport._peer_identity(connection))
        if peer_uid != expected_peer_uid or peer_gid != expected_peer_gid:
            raise AuthorityTransportError("planner custody transfer server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for original in originals:
            io._send_exact_until(connection, original, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        prefix = _recv_prefix(connection, deadline_ns=deadline_ns)
        if prefix != response_magic:
            raise AuthorityTransportError("planner custody transfer response magic is invalid")
        length = int.from_bytes(io._recv_exact_until(connection, 8,
            deadline_ns=deadline_ns), "big")
        if not 2 <= length <= response_maximum:
            raise AuthorityTransportError("planner custody transfer response length is invalid")
        response = io._recv_exact_until(connection, length, deadline_ns=deadline_ns)
        io._require_eof(connection, deadline_ns)
    except BaseException:
        # Never replace a native first failure with cleanup failure or repeat
        # a request whose delivery may already be uncertain.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return response


def _request_relay(path, *, intent_bytes, envelope_bytes, evaluation_context_bytes,
        historical_expectations_bytes, timeout_seconds, expected_peer_uid, expected_peer_gid):
    """Obtain opaque original relay bytes without forwarding a custody request."""
    originals = (intent_bytes, envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
    return _exchange(path, originals, request_magic=RELAY_REQUEST_MAGIC, limits=_RELAY_LIMITS,
        response_magic=RELAY_RESPONSE_MAGIC, response_maximum=MAX_RELAY_BYTES,
        timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid,
        expected_peer_gid=expected_peer_gid)


def _forward_originals(path, *, intent_bytes, relay_bytes, envelope_bytes,
        evaluation_context_bytes, historical_expectations_bytes, timeout_seconds,
        expected_peer_uid, expected_peer_gid):
    """Forward caller-held originals and return an unauthenticated raw ACK."""
    originals = (intent_bytes, relay_bytes, envelope_bytes,
        evaluation_context_bytes, historical_expectations_bytes)
    return _exchange(path, originals, request_magic=FORWARD_REQUEST_MAGIC, limits=_FORWARD_LIMITS,
        response_magic=FORWARD_RESPONSE_MAGIC, response_maximum=MAX_ACK_BYTES,
        timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid,
        expected_peer_gid=expected_peer_gid)
