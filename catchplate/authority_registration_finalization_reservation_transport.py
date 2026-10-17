"""Fixed finalization raw10 to original reserve/snapshot/ack Unix exchange.

The exact request is authorization, custody raw7, complete before-vector and
grant. The response is unverified raw3, never permission from peer metadata.
All lengths/group/aggregate bounds precede body allocation. A required original
absolute deadline covers connect, peer admission, framing, half-close and EOF.
No JSON, signing, work allowance, retry, alternate endpoint or operation exists.
"""
from __future__ import annotations

import math
import socket

from catchplate import authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate import authority_registration_finalization_transport as grant
from catchplate import control_plane_registration_finalization_records as originals_codec
from catchplate import authority_registration_finalization_reservation_records as records


REQUEST_MAGIC = b"SWRFRQ01"
RESPONSE_MAGIC = b"SWRFRR01"
LISTENER_PATH = "/run/catchplate/registration-finalization/reserver.sock"
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
MAX_BYTES = MAX_REQUEST_BYTES = grant.MAX_BYTES
REQUEST_LIMITS = grant.REQUEST_LIMITS + grant.RESPONSE_LIMITS
RESPONSE_LIMITS = (records.MAX_REQUEST_BYTES, records.MAX_SNAPSHOT_BYTES, records.MAX_RECEIPT_BYTES)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
AuthorityTransportError = authority_transport.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix


def _timeout(timeout_seconds):
    if (type(timeout_seconds) not in (int, float)
            or not 1 <= timeout_seconds <= 30 or not math.isfinite(timeout_seconds)):
        raise AuthorityTransportError("finalization reserve timeout is invalid")
    return timeout_seconds


def _deadline_ns(timeout_seconds):
    return io._deadline_ns(_timeout(timeout_seconds))


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("finalization reserve endpoint is not an exact four-tuple")
    path, timeout_seconds, uid, gid = endpoint
    if type(path) is not str or path != LISTENER_PATH:
        raise AuthorityTransportError("finalization reserve socket path differs")
    if (type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("finalization reserve endpoint peer differs")
    return path, _timeout(timeout_seconds), uid, gid


def _request_lengths(lengths):
    try:
        originals_codec._lengths(lengths)
    except originals_codec.CustodyRecordError as exc:
        raise AuthorityTransportError("finalization reserve originals exceed their fixed bounds") from exc


def _response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != len(RESPONSE_LIMITS)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, RESPONSE_LIMITS))
            or sum(lengths) > MAX_RESPONSE_BYTES):
        raise AuthorityTransportError("finalization reserve response lengths exceed their bounds")


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("finalization reserve frame direction is invalid")
    limits = RESPONSE_LIMITS if response else REQUEST_LIMITS
    if (type(values) is not tuple or len(values) != len(limits)
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("finalization reserve requires its exact original byte inventory")
    lengths = tuple(len(raw) for raw in values)
    if response:
        _response_lengths(lengths)
    else:
        _request_lengths(lengths)
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("finalization reserve frame direction is invalid")
    count = len(RESPONSE_LIMITS) if response else len(REQUEST_LIMITS)
    header = io._recv_exact_until(connection, count * 8, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, len(header), 8))
    if response:
        _response_lengths(lengths)
    else:
        _request_lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return originals


def _recv_request(connection, *, deadline_ns):
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("finalization reserve request magic differs")
    return _recv_bodies(connection, response=False, deadline_ns=deadline_ns)


def _send(connection, originals, *, response, deadline_ns):
    held = _originals(originals, response=response)
    header = (RESPONSE_MAGIC if response else REQUEST_MAGIC) + b"".join(
        len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_response(connection, originals, *, deadline_ns):
    """Owner supplies genuine durable originals and closes to finish exact EOF."""
    _send(connection, originals, response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns):
    """Return unverified raw3 under the caller's required inherited deadline."""
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("finalization reserve requires an original absolute deadline")
    path, timeout_seconds, uid, gid = _endpoint(endpoint)
    held = _originals(originals, response=False)
    _check_deadline(deadline_ns)
    bound = min(_deadline_ns(timeout_seconds), deadline_ns)
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("finalization reserve server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("finalization reserve response magic differs")
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
