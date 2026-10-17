"""Fixed locator-to-originals custody reads, without authentication authority.

Two independently supplied canonical digest IDs locate a request; the response
is six opaque originals, never a parsed success object. This framing does not
authenticate those originals, prove absence, authorize historical keys, or
establish current execution authority. There is no signing or automatic retry.

The serving owner checks its peer before receiving a prefix and must receive
the complete request and EOF before application work. The client checks its
pinned peer before sending, half-closes its request, and requires response EOF.
The owner closes the accepted server connection. Existing writer-v1 primitives
enforce bounded I/O and one absolute deadline; existing transfers remain
unchanged. All response lengths are admitted before any response body allocation.
"""
from __future__ import annotations

import socket

from catchplate import authority_contract, authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
TRANSFER_SCHEMA = "catchplate.policyAuthorityRevocationCustodyReadTransfer/v1"
REQUEST_MAGIC = b"SWCR\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWRC\x00\x00\x00\x01"
MAX_RESPONSE_BYTES = MAX_INPUT_BYTES
_IDENTIFIER_BYTES = 71
_RESPONSE_LIMITS = (authority_contract.MAX_REQUEST_BYTES, authority_contract.MAX_REQUEST_BYTES,
    authority_contract.MAX_RESULT_BYTES, 512 * 1024, MAX_INPUT_BYTES, 16384)

_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _validate_ids(execution_envelope_id, planner_transaction_id):
    for value in (execution_envelope_id, planner_transaction_id):
        if (type(value) is not str or len(value) != _IDENTIFIER_BYTES
                or not value.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in value[7:])):
            raise AuthorityTransportError("custody read locator is not a canonical SHA256 identifier")


def _validate_request_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int or size != _IDENTIFIER_BYTES for size in lengths)):
        raise AuthorityTransportError("custody read locator lengths are invalid")


def _validate_response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 6
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, _RESPONSE_LIMITS))
            or sum(lengths) > MAX_RESPONSE_BYTES):
        raise AuthorityTransportError("custody read original lengths are invalid")


def _recv_request(connection, *, deadline_ns, prefix):
    if type(prefix) is not bytes or prefix != REQUEST_MAGIC:
        raise AuthorityTransportError("custody read request magic is invalid")
    header = io._recv_exact_until(connection, 16, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, 16, 8))
    _validate_request_lengths(lengths)
    raw_ids = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    try:
        identifiers = tuple(raw.decode("ascii") for raw in raw_ids)
    except UnicodeError as exc:
        raise AuthorityTransportError("custody read locators are not ASCII") from exc
    _validate_ids(*identifiers)
    io._require_eof(connection, deadline_ns)
    return identifiers


def _send_originals(connection, originals, *, deadline_ns):
    if (type(originals) is not tuple or len(originals) != 6
            or any(type(raw) is not bytes for raw in originals)):
        raise AuthorityTransportError("custody read response is not six original byte strings")
    lengths = tuple(len(raw) for raw in originals)
    _validate_response_lengths(lengths)
    header = RESPONSE_MAGIC + b"".join(size.to_bytes(8, "big") for size in lengths)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for original in originals:
        io._send_exact_until(connection, original, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(path, *, execution_envelope_id, planner_transaction_id,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    """Return opaque intent, relay, plan, context, history and original ACK."""
    _validate_ids(execution_envelope_id, planner_transaction_id)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("custody read socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("custody read socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("custody read socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("custody read peer identity is invalid")
    raw_ids = (execution_envelope_id.encode("ascii"), planner_transaction_id.encode("ascii"))
    lengths = tuple(len(raw) for raw in raw_ids)
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
            raise AuthorityTransportError("custody read server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in raw_ids:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        prefix = _recv_prefix(connection, deadline_ns=deadline_ns)
        if prefix != RESPONSE_MAGIC:
            raise AuthorityTransportError("custody read response magic is invalid")
        response_header = io._recv_exact_until(connection, 48, deadline_ns=deadline_ns)
        response_lengths = tuple(int.from_bytes(response_header[index:index + 8], "big")
            for index in range(0, 48, 8))
        _validate_response_lengths(response_lengths)
        originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
            for size in response_lengths)
        io._require_eof(connection, deadline_ns)
    except BaseException:
        # Preserve the first native/transport error, including when cleanup
        # fails. A failed read supplies no absence or retry authority.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return originals
