"""One bounded peer-checked exchange with the independent registration signer.

Raw eight request parts and raw two response parts remain original bytes.
Framing and Unix credentials do not verify enrollment, source proofs or evidence.
Both complete length inventories and aggregate bounds precede body allocation.
An absolute deadline covers connect, peer checks, framing, half-close and EOF;
an optional earlier caller deadline is never extended. There is no retry,
fallback, JSON parsing, work allocation or signer/key selection here.
"""
from __future__ import annotations

import socket

from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_webauthn_registration_signer_wire as wire


AuthorityTransportError = authority_transport.AuthorityTransportError
REQUEST_MAGIC = b"SWESQ001"
RESPONSE_MAGIC = b"SWESR001"
_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("registration signer frame direction is invalid")
    count = 2 if response else 8
    header = io._recv_exact_until(connection, count * 8, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, count * 8, 8))
    (wire._response_lengths if response else wire._request_lengths)(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return originals


def _recv_request(connection, *, prefix, deadline_ns):
    if type(prefix) is not bytes or prefix != REQUEST_MAGIC:
        raise AuthorityTransportError("registration signer request magic is invalid")
    return _recv_bodies(connection, response=False, deadline_ns=deadline_ns)


def _send_response(connection, originals, *, deadline_ns):
    originals = wire._response_originals(originals)
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    # The owner closes the connection. That exact EOF, not just both lengths,
    # completes the response at the caller; errors never add a JSON fallback.
    _check_deadline(deadline_ns)


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("registration signer endpoint is not an exact four-tuple")
    path, timeout_seconds, uid, gid = endpoint
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("registration signer socket path is invalid")
    try:
        encoded = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("registration signer socket path is invalid") from exc
    if not 1 <= len(encoded) <= 107:
        raise AuthorityTransportError("registration signer socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in (uid, gid)):
        raise AuthorityTransportError("registration signer peer identity is invalid")
    # The common deadline helper validates the same finite bounded timeout
    # before a socket is created. No endpoint setting is accepted from wire.
    return path, timeout_seconds, uid, gid


def _socket_request(endpoint, *, originals, deadline_ns=None):
    """Return unverified response originals after one exact peer exchange."""
    path, timeout_seconds, uid, gid = _endpoint(endpoint)
    originals = wire._request_originals(originals)
    bounded_deadline = _deadline_ns(timeout_seconds)
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
        bounded_deadline = min(bounded_deadline, deadline_ns)
    header = REQUEST_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    _check_deadline(bounded_deadline)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bounded_deadline, lambda: connection.connect(path))
        peer_uid, peer_gid, _peer_pid = io._call_until(connection, bounded_deadline,
            lambda: authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (uid, gid):
            raise AuthorityTransportError("registration signer server peer differs")
        io._send_exact_until(connection, header, deadline_ns=bounded_deadline)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=bounded_deadline)
        io._call_until(connection, bounded_deadline, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bounded_deadline) != RESPONSE_MAGIC:
            raise AuthorityTransportError("registration signer response magic is invalid")
        response = _recv_bodies(connection, response=True, deadline_ns=bounded_deadline)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(bounded_deadline)
    return response
