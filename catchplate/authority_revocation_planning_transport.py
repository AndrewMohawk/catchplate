"""Opaque original-byte planning frames over the existing bounded Unix I/O.

This distinct SWRP/SWRS protocol does not change writer transfer v1. The owner
must authenticate its peer before receiving a prefix and must receive the full
request, including EOF, before invoking any planning side effect. The client
checks its independently pinned peer before sending a header or body.

All lengths are admitted together before body allocation. Both directions use
one unchanged source-capped aggregate bound and one absolute deadline; neither
framing nor transport allocates JSON/hash work or authenticates a signed plan.
The returned original pair still requires independent genuine handoff replay.
There is no JSON error union, partial response, automatic retry or re-signing.
"""
from __future__ import annotations

import socket

from catchplate import authority_contract, authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
TRANSFER_SCHEMA = "catchplate.policyAuthorityRevocationPlanningTransfer/v1"
REQUEST_MAGIC = b"SWRP\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWRS\x00\x00\x00\x01"
MAX_REQUEST_BYTES = MAX_INPUT_BYTES
MAX_RESPONSE_BYTES = MAX_INPUT_BYTES
_REQUEST_LIMITS = (authority_contract.MAX_REQUEST_BYTES, authority_contract.MAX_RESULT_BYTES,
    authority_contract.MAX_RESULT_BYTES, 512 * 1024, 512 * 1024)
_RESPONSE_LIMITS = (authority_contract.MAX_RESULT_BYTES, 512 * 1024)

# Exactly the existing finite timeout, absolute-clock and bounded-buffer
# primitives. This module adds framing only, not a second I/O implementation.
_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _validate_request_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 5
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, _REQUEST_LIMITS))
            or sum(lengths) > MAX_REQUEST_BYTES):
        raise AuthorityTransportError("planning transfer request lengths are invalid")


def _validate_response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, _RESPONSE_LIMITS))
            or sum(lengths) > MAX_RESPONSE_BYTES):
        raise AuthorityTransportError("planning transfer response lengths are invalid")


def _recv_request(connection, *, deadline_ns, prefix):
    if type(prefix) is not bytes or prefix != REQUEST_MAGIC:
        raise AuthorityTransportError("planning transfer request magic is invalid")
    header = io._recv_exact_until(connection, 40, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, 40, 8))
    _validate_request_lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return originals


def _send_response(connection, envelope_bytes, evaluation_context_bytes, *, deadline_ns):
    originals = (envelope_bytes, evaluation_context_bytes)
    if any(type(raw) is not bytes for raw in originals):
        raise AuthorityTransportError("planning transfer response bodies are not exact bytes")
    lengths = tuple(len(raw) for raw in originals)
    _validate_response_lengths(lengths)
    header = RESPONSE_MAGIC + b"".join(size.to_bytes(8, "big") for size in lengths)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(path, *, control_bytes, request_bytes, evidence_bytes,
        context_bytes, root_inventory_bytes, timeout_seconds,
        expected_peer_uid, expected_peer_gid):
    """Return an unauthenticated original plan/context pair from one exchange."""
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("planning transfer socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("planning transfer socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("planning transfer socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("planning transfer peer identity is invalid")
    originals = (control_bytes, request_bytes, evidence_bytes, context_bytes, root_inventory_bytes)
    if any(type(raw) is not bytes for raw in originals):
        raise AuthorityTransportError("planning transfer request bodies are not exact bytes")
    lengths = tuple(len(raw) for raw in originals)
    _validate_request_lengths(lengths)
    deadline_ns = _deadline_ns(timeout_seconds)
    header = REQUEST_MAGIC + b"".join(size.to_bytes(8, "big") for size in lengths)
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _check_deadline(deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        peer_uid, peer_gid, _peer_pid = io._call_until(connection, deadline_ns,
            lambda: authority_transport._peer_identity(connection))
        if peer_uid != expected_peer_uid or peer_gid != expected_peer_gid:
            raise AuthorityTransportError("planning transfer server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for original in originals:
            io._send_exact_until(connection, original, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        prefix = _recv_prefix(connection, deadline_ns=deadline_ns)
        if prefix != RESPONSE_MAGIC:
            raise AuthorityTransportError("planning transfer response magic is invalid")
        response_header = io._recv_exact_until(connection, 16, deadline_ns=deadline_ns)
        response_lengths = tuple(int.from_bytes(response_header[index:index + 8], "big")
            for index in range(0, 16, 8))
        _validate_response_lengths(response_lengths)
        response = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
            for size in response_lengths)
        io._require_eof(connection, deadline_ns)
    except BaseException:
        # Failure is not a JSON response. Preserve its original cause and do
        # not retry an exchange whose delivery may already be uncertain.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return response
