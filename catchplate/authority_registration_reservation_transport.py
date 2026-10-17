"""Fixed original-only exchange with the registration execution reserver.

The request is the retained raw10 grant inventory: caller authorization,
planning request3, planning response4, complete before vector and signed grant.
The response is original reserve request, computation snapshot and state ack.
Neither framing nor root-activated Unix listener credentials authenticate
those originals or establish currentness, SQL permission or completion.

All per-original, planning-group and aggregate bounds precede allocation.
One absolute deadline covers connect, peer admission, framing, half-close and
exact EOF. There are no parsers, work allowances, callbacks, retries, fallback
endpoints or caller-selected operations here. The server owner admits its
peer before reading and owns all actual cryptographic and durability gates.
"""
from __future__ import annotations

import math
import socket

from catchplate import authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate import authority_registration_execution_transport as execution
from catchplate import authority_webauthn_evidence_plan_transport as planning
from catchplate import authority_current_root_authorization as authorization
from catchplate import authority_current_root_computation as computation
from catchplate import authority_current_root_decisions as decisions


REQUEST_MAGIC = b"SWRRQ001"
RESPONSE_MAGIC = b"SWRRR001"
LISTENER_PATH = "/run/catchplate/registration-execution/reserver.sock"
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
MAX_BYTES = MAX_REQUEST_BYTES = execution.MAX_BYTES
REQUEST_LIMITS = execution.REQUEST_LIMITS + execution.RESPONSE_LIMITS
RESPONSE_LIMITS = (authorization.MAX_BYTES, computation.MAX_SNAPSHOT_BYTES,
    decisions.MAX_RECEIPT_BYTES)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
AuthorityTransportError = authority_transport.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix


def _timeout(timeout_seconds):
    if (type(timeout_seconds) not in (int, float)
            or not 1 <= timeout_seconds <= 30 or not math.isfinite(timeout_seconds)):
        raise AuthorityTransportError("registration reserve timeout is invalid")
    return timeout_seconds


def _deadline_ns(timeout_seconds):
    return io._deadline_ns(_timeout(timeout_seconds))


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("registration reserve endpoint is not an exact four-tuple")
    path, timeout_seconds, uid, gid = endpoint
    if type(path) is not str or path != LISTENER_PATH:
        raise AuthorityTransportError("registration reserve socket path differs")
    if (type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("registration reserve endpoint peer differs")
    return path, _timeout(timeout_seconds), uid, gid


def _request_lengths(lengths):
    execution._lengths(lengths, REQUEST_LIMITS)
    # Preserve the tighter actual planning-group ceilings as well as raw10's
    # source-derived per-original bounds and complete 64 MiB aggregate.
    planning._lengths(lengths[1:4], planning._REQUEST_LIMITS)
    planning._lengths(lengths[4:8], planning._RESPONSE_LIMITS)


def _response_lengths(lengths):
    execution._lengths(lengths, RESPONSE_LIMITS)


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("registration reserve frame direction is invalid")
    count = len(RESPONSE_LIMITS) if response else len(REQUEST_LIMITS)
    if (type(values) is not tuple or len(values) != count
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("registration reserve requires its exact original byte inventory")
    lengths = tuple(len(raw) for raw in values)
    if response:
        _response_lengths(lengths)
    else:
        _request_lengths(lengths)
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("registration reserve frame direction is invalid")
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
        raise AuthorityTransportError("registration reserve request magic differs")
    return _recv_bodies(connection, response=False, deadline_ns=deadline_ns)


def _send(connection, originals, *, response, deadline_ns):
    held = _originals(originals, response=response)
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_response(connection, originals, *, deadline_ns):
    # Only the owner can establish that these bytes follow genuine replay and
    # durable state acknowledgment. Exact EOF is supplied by its final close.
    _send(connection, originals, response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns=None):
    """Return unverified raw3 after one fixed root-listener peer exchange."""
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
            raise AuthorityTransportError("registration reserve server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("registration reserve response magic differs")
        received = _recv_bodies(connection, response=True, deadline_ns=bound)
    except BaseException:
        # Preserve the original failure even if cleanup itself fails.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(bound)
    return received
