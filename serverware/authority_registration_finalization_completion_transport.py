"""Distinct finalization completion framing, never authority or SQL retry.

Raw2 selects only recovery of an independently pinned finalization packet.
Raw4 carries the original signed completion and state acknowledgment, or closed
uncertainty. Framing, peer credentials and returned IDs prove no signature,
current head or new execution permission. One required inherited deadline
covers lengths, bodies, EOF and the sole exchange; there is no fallback.
"""
from __future__ import annotations

import socket

from serverware import authority_registration_completion_transport as framing


authority_transport, io = framing.authority_transport, framing.io
AuthorityTransportError = framing.AuthorityTransportError
PURPOSE = b"recover-registration-finalization-completion"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWRFCM01", b"SWRFCR01"
LISTENER_PATH = "/run/serverware/registration-finalization/completion.sock"
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
REQUEST_LIMITS = (len(PURPOSE), 71)
RESPONSE_LIMITS = framing.RESPONSE_LIMITS
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = framing.MAX_RESPONSE_BYTES
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix
_response_lengths = framing._response_lengths


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("finalization completion endpoint is not an exact four-tuple")
    path, timeout, uid, gid = endpoint
    if type(path) is not str or path != LISTENER_PATH:
        raise AuthorityTransportError("finalization completion socket path differs")
    if (type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("finalization completion endpoint peer differs")
    return path, framing._timeout(timeout), uid, gid


def _request_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int for size in lengths) or lengths != REQUEST_LIMITS):
        raise AuthorityTransportError("finalization completion request lengths differ")


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("finalization completion frame direction is invalid")
    if response:
        # Only the byte carrier is shared; no evidence-purpose request or
        # evidence completion admission is delegated to the older transport.
        return framing._originals(values, response=True)
    if (type(values) is not tuple or len(values) != 2
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("finalization completion requires exact immutable raw2")
    _request_lengths(tuple(len(raw) for raw in values))
    if values[0] != PURPOSE or not framing._digest_bytes(values[1]):
        raise AuthorityTransportError("finalization completion selector differs")
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("finalization completion frame direction is invalid")
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
        raise AuthorityTransportError("finalization completion request magic differs")
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
    _send(connection, originals, response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns):
    """Return unverified raw4; require an original deadline and never retry."""
    path, timeout, uid, gid = _endpoint(endpoint)
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("finalization completion requires an original absolute deadline")
    _check_deadline(deadline_ns)
    bound = min(deadline_ns, framing._deadline_ns(timeout))
    held = _originals(originals, response=False)
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("finalization completion server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("finalization completion response magic differs")
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
