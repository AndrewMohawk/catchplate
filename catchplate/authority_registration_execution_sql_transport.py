"""Fixed raw13/raw4 exchange with the cold registration SQL owner.

The request contains the retained grant raw10 followed by reservation raw3.
The response is a bounded local outcome, never a signed completion or a new
permission. Root-activated Unix peer credentials authenticate only the fixed
local listener. The actual service authenticates originals and caller scope.

All individual, planning-group and aggregate lengths precede body allocation.
One absolute deadline covers the exchange and exact EOF. No JSON parser,
work allowance, retry, fallback endpoint or caller-selected SQL is provided.
"""
from __future__ import annotations

import math
import socket

from catchplate import authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate import authority_registration_reservation_transport as reservation


REQUEST_MAGIC = b"SWRSQL01"
RESPONSE_MAGIC = b"SWRSLR01"
LISTENER_PATH = "/run/catchplate/registration-execution/sql.sock"
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
MAX_BYTES = MAX_REQUEST_BYTES = reservation.MAX_BYTES
REQUEST_LIMITS = reservation.REQUEST_LIMITS + reservation.RESPONSE_LIMITS
RESPONSE_LIMITS = (15, 71, 71, 4096)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
AuthorityTransportError = authority_transport.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix


def _timeout(timeout_seconds):
    if (type(timeout_seconds) not in (int, float)
            or not 1 <= timeout_seconds <= 30 or not math.isfinite(timeout_seconds)):
        raise AuthorityTransportError("registration SQL timeout is invalid")
    return timeout_seconds


def _deadline_ns(timeout_seconds):
    return io._deadline_ns(_timeout(timeout_seconds))


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("registration SQL endpoint is not an exact four-tuple")
    path, timeout_seconds, uid, gid = endpoint
    if type(path) is not str or path != LISTENER_PATH:
        raise AuthorityTransportError("registration SQL socket path differs")
    if (type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("registration SQL endpoint peer differs")
    return path, _timeout(timeout_seconds), uid, gid


def _request_lengths(lengths):
    if type(lengths) is not tuple or len(lengths) != len(REQUEST_LIMITS):
        raise AuthorityTransportError("registration SQL request inventory differs")
    reservation._request_lengths(lengths[:10])
    reservation._response_lengths(lengths[10:])
    if sum(lengths) > MAX_REQUEST_BYTES:
        raise AuthorityTransportError("registration SQL originals exceed their aggregate bound")


def _response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != len(RESPONSE_LIMITS)
            or any(type(size) is not int or not 0 <= size <= maximum
                for size, maximum in zip(lengths, RESPONSE_LIMITS))):
        raise AuthorityTransportError("registration SQL response lengths exceed their bounds")
    state, pending, packet, marker = lengths
    if not ((state == 15 and pending == packet == 71 and 2 <= marker <= 4096)
            or (state == 9 and (pending, packet) in ((0, 0), (71, 71)) and marker == 0)):
        raise AuthorityTransportError("registration SQL response inventory differs")


def _digest_bytes(raw):
    return (len(raw) == 71 and raw[:7] == b"sha256:"
        and all(byte in b"0123456789abcdef" for byte in raw[7:]))


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("registration SQL frame direction is invalid")
    count = len(RESPONSE_LIMITS) if response else len(REQUEST_LIMITS)
    if (type(values) is not tuple or len(values) != count
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("registration SQL requires its exact original byte inventory")
    lengths = tuple(len(raw) for raw in values)
    if not response:
        _request_lengths(lengths)
        return values
    _response_lengths(lengths)
    state, pending, packet, marker = values
    ids = _digest_bytes(pending) and _digest_bytes(packet)
    if not ((state == b"observed-commit" and ids and 2 <= len(marker) <= 4096)
            or (state == b"uncertain" and (ids or pending == packet == b"") and marker == b"")):
        raise AuthorityTransportError("registration SQL response fields differ")
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("registration SQL frame direction is invalid")
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
        raise AuthorityTransportError("registration SQL request magic differs")
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
    # Only the actual service may select this local outcome. Its final close
    # supplies EOF; neither this framing nor marker bytes sign a completion.
    _send(connection, originals, response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns=None):
    """Return untrusted raw4 after one fixed root-listener peer exchange."""
    path, timeout_seconds, uid, gid = _endpoint(endpoint)
    bound = _deadline_ns(timeout_seconds)
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
        bound = min(bound, deadline_ns)
    held = _originals(originals, response=False)
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("registration SQL server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("registration SQL response magic differs")
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
