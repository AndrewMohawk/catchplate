"""Fixed consume raw8/raw4 SQL transport, never original admission.

The independent before vector and pending pins are held by the cold role, not
learned from a ninth frame or an ACK. Unsigned observations cannot authorize
completion, token release, current authentication, noncommit or an SQL retry.
"""
from __future__ import annotations

import socket

from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_oidc_session_activation_delivery_reservation_transport as reservation
from serverware import authority_registration_execution_sql_transport as outcome


REQUEST_MAGIC, RESPONSE_MAGIC = b"SWODSQ01", b"SWODSR01"
LISTENER_PATH = "/run/serverware/oidc-session-activation-delivery-execution/sql.sock"
SERVICE_UID = SERVICE_GID = 65498
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
REQUEST_LIMITS = reservation.REQUEST_LIMITS + reservation.RESPONSE_LIMITS
RESPONSE_LIMITS = outcome.RESPONSE_LIMITS
REQUEST_HEADER_BYTES = len(REQUEST_MAGIC) + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = len(RESPONSE_MAGIC) + 8 * len(RESPONSE_LIMITS)
MAX_BYTES = reservation.MAX_BYTES
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_REQUEST_BYTES = MAX_BYTES - REQUEST_HEADER_BYTES - RESPONSE_HEADER_BYTES - MAX_RESPONSE_BYTES
AuthorityTransportError = authority_transport.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix
_response_lengths = outcome._response_lengths


def _source_bounds():
    if (len(REQUEST_MAGIC) != 8 or len(RESPONSE_MAGIC) != 8
            or len(REQUEST_LIMITS) != 8 or RESPONSE_LIMITS != (15, 71, 71, 4096)
            or MAX_BYTES != 64 * 1024 * 1024 or MAX_BYTES > io.MAX_REQUEST_BYTES
            or MAX_RESPONSE_BYTES != sum(RESPONSE_LIMITS)
            or MAX_REQUEST_BYTES <= 0
            or MAX_REQUEST_BYTES + MAX_RESPONSE_BYTES + REQUEST_HEADER_BYTES + RESPONSE_HEADER_BYTES != MAX_BYTES):
        raise AuthorityTransportError("consume SQL source frame inventory or aggregate bound changed")


def _timeout(value):
    return reservation._timeout(value)


def _deadline_ns(timeout_seconds):
    return io._deadline_ns(_timeout(timeout_seconds))


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("consume SQL endpoint is not an exact four-tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("consume SQL endpoint differs from its fixed root listener")
    return path, _timeout(timeout), uid, gid


def _request_lengths(lengths):
    _source_bounds()
    if type(lengths) is not tuple or len(lengths) != len(REQUEST_LIMITS):
        raise AuthorityTransportError("consume SQL request requires exact raw8")
    reservation._lengths(lengths[:5], response=False)
    reservation._lengths(lengths[5:], response=True)
    if sum(lengths) > MAX_REQUEST_BYTES:
        raise AuthorityTransportError("consume SQL request exceeds its whole-exchange bound")


def _originals(values, *, response):
    _source_bounds()
    if type(response) is not bool:
        raise AuthorityTransportError("consume SQL direction is not source selected")
    if response:
        # Only the operation-neutral unsigned outcome grammar is shared. No
        # registration grant, original verifier or execution dispatch is used.
        return outcome._originals(values, response=True)
    if (type(values) is not tuple or len(values) != len(REQUEST_LIMITS)
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("consume SQL requires exact immutable original raw8")
    _request_lengths(tuple(len(raw) for raw in values))
    reservation._originals(values[:5], response=False)
    reservation._originals(values[5:], response=True)
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    _source_bounds()
    if type(response) is not bool:
        raise AuthorityTransportError("consume SQL direction is not source selected")
    count = len(RESPONSE_LIMITS if response else REQUEST_LIMITS)
    header = io._recv_exact_until(connection, count * 8, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, len(header), 8))
    if response:
        _response_lengths(lengths)
    else:
        _request_lengths(lengths)
    received = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        if size else b"" for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _originals(received, response=response)


def _recv_request(connection, *, deadline_ns):
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("consume SQL requires an inherited absolute deadline")
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("consume SQL request magic differs")
    return _recv_bodies(connection, response=False, deadline_ns=deadline_ns)


def _send(connection, originals, *, response, deadline_ns):
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("consume SQL requires an inherited absolute deadline")
    held = _originals(originals, response=response)
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        if raw:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_response(connection, originals, *, deadline_ns):
    """Send the actual service's unsigned raw4; final close supplies EOF."""
    _send(connection, originals, response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns):
    """One exchange; returned immutable bytes are unverified observations."""
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("consume SQL requires an inherited absolute deadline")
    path, timeout, uid, gid = _endpoint(endpoint)
    held = _originals(originals, response=False)
    _check_deadline(deadline_ns)
    bound = min(_deadline_ns(timeout), deadline_ns)
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("consume SQL server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("consume SQL response magic differs")
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
