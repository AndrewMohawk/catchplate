"""Fixed finalization raw13/raw4 exchange; no original or SQL admission.

The request is dedicated finalization grant raw10 plus reservation raw3. Its
own fixed magic/path cannot dispatch through the older evidence SQL listener.
The response reuses only that transport's bounded local-outcome carrier:
observed-commit or uncertain, actual custody locators when available, and an
unsigned marker. Framing is not signed completion or independent currentness.

All request group/aggregate bounds precede body allocation. A required original
absolute deadline covers connect, peer admission, half-close and exact EOF.
No work allowance, JSON, key, cold worker, public dispatch or retry is added.
"""
from __future__ import annotations

import socket

from catchplate import authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate import authority_registration_finalization_reservation_transport as reservation
from catchplate import authority_registration_execution_sql_transport as outcome


REQUEST_MAGIC = b"SWRFSQL1"
RESPONSE_MAGIC = b"SWRFSLR1"
LISTENER_PATH = "/run/catchplate/registration-finalization/sql.sock"
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
MAX_BYTES = MAX_REQUEST_BYTES = reservation.MAX_BYTES
REQUEST_LIMITS = reservation.REQUEST_LIMITS + reservation.RESPONSE_LIMITS
RESPONSE_LIMITS = outcome.RESPONSE_LIMITS
MAX_RESPONSE_BYTES = outcome.MAX_RESPONSE_BYTES
AuthorityTransportError = authority_transport.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("finalization SQL endpoint is not an exact four-tuple")
    path, timeout, uid, gid = endpoint
    if type(path) is not str or path != LISTENER_PATH:
        raise AuthorityTransportError("finalization SQL socket path differs")
    if (type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("finalization SQL endpoint peer differs")
    return path, reservation._timeout(timeout), uid, gid


def _request_lengths(lengths):
    if type(lengths) is not tuple or len(lengths) != len(REQUEST_LIMITS):
        raise AuthorityTransportError("finalization SQL request inventory differs")
    reservation._request_lengths(lengths[:10])
    reservation._response_lengths(lengths[10:])
    if sum(lengths) > MAX_REQUEST_BYTES:
        raise AuthorityTransportError("finalization SQL originals exceed their aggregate bound")


def _response_lengths(lengths):
    # The shared four-part shape has no operation, parser or authority state.
    # It does not select the older request profile or the older SQL endpoint.
    outcome._response_lengths(lengths)


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("finalization SQL frame direction is invalid")
    if response:
        return outcome._originals(values, response=True)
    if (type(values) is not tuple or len(values) != len(REQUEST_LIMITS)
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("finalization SQL requires immutable raw13")
    _request_lengths(tuple(len(raw) for raw in values))
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("finalization SQL frame direction is invalid")
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
        raise AuthorityTransportError("finalization SQL request magic differs")
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
    """Actual service selects its unsigned observation and closes for EOF."""
    _send(connection, originals, response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns):
    """Return untrusted raw4 from one fixed peer under the inherited deadline."""
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("finalization SQL requires an original absolute deadline")
    path, timeout, uid, gid = _endpoint(endpoint)
    held = _originals(originals, response=False)
    _check_deadline(deadline_ns)
    bound = min(reservation._deadline_ns(timeout), deadline_ns)
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("finalization SQL server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("finalization SQL response magic differs")
        received = _recv_bodies(connection, response=True, deadline_ns=bound)
        if sum(len(raw) for raw in (*held, *received)) > MAX_BYTES:
            raise AuthorityTransportError("finalization SQL complete exchange exceeds its aggregate bound")
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(bound)
    return received
