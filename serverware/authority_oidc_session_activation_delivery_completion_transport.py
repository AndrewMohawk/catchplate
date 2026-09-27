"""Fixed consume completion raw2/raw4 framing, never semantic admission.

The separately admitted completion-purpose caller requests only a known packet
locator. Framing, IDs and socket credentials do not authenticate completion,
currentness, noncommit or new execution permission. Both headers and maximum
bodies fit the fixed whole-exchange bound before any body allocation. One
inherited deadline covers peer checks, framing, EOF and close; no retry exists.
"""
from __future__ import annotations

import socket

from serverware import authority_contract as contract
from serverware import authority_registration_completion_transport as framing


authority_transport, io = framing.authority_transport, framing.io
AuthorityTransportError = framing.AuthorityTransportError
PROCESS_MODE = "oidc-session-activation-delivery-completion"
PURPOSE = b"recover-oidc-session-activation-delivery-completion"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWODCM01", b"SWODCR01"
LISTENER_PATH = "/run/serverware/oidc-session-activation-delivery-execution/completion.sock"
SERVICE_UID = SERVICE_GID = 65497
REQUEST_PEER_UID = REQUEST_PEER_GID = 65497
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
REQUEST_LIMITS = (len(PURPOSE), 71)
RESPONSE_LIMITS = framing.RESPONSE_LIMITS
REQUEST_HEADER_BYTES = len(REQUEST_MAGIC) + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = len(RESPONSE_MAGIC) + 8 * len(RESPONSE_LIMITS)
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_EXCHANGE_BYTES = contract.MAX_RESULT_BYTES
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix
_timeout, _deadline_ns = framing._timeout, framing._deadline_ns


def _exchange_bound():
    if (MAX_EXCHANGE_BYTES != 64 * 1024 * 1024
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
            + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        raise AuthorityTransportError("consume completion source exchange exceeds its aggregate bound")


def _inherited(deadline_ns):
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("consume completion requires an original absolute deadline")
    _check_deadline(deadline_ns)
    return deadline_ns


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("consume completion endpoint is not an exact four-tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("consume completion endpoint differs from its fixed root listener")
    return path, _timeout(timeout), uid, gid


def _request_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int for size in lengths) or lengths != REQUEST_LIMITS):
        raise AuthorityTransportError("consume completion request lengths differ")


def _response_lengths(lengths):
    _exchange_bound()
    # Only neutral byte framing is reused, never an older operation verifier.
    framing._response_lengths(lengths)


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("consume completion frame direction is invalid")
    _exchange_bound()
    if response:
        return framing._originals(values, response=True)
    if (type(values) is not tuple or len(values) != 2
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("consume completion requires exact immutable raw2")
    _request_lengths(tuple(len(raw) for raw in values))
    if values[0] != PURPOSE or not framing._digest_bytes(values[1]):
        raise AuthorityTransportError("consume completion selector differs")
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("consume completion frame direction is invalid")
    _inherited(deadline_ns)
    _exchange_bound()
    count = len(RESPONSE_LIMITS) if response else len(REQUEST_LIMITS)
    header = io._recv_exact_until(connection, count * 8, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, len(header), 8))
    (_response_lengths if response else _request_lengths)(lengths)
    values = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        if size else b"" for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _originals(values, response=response)


def _recv_request(connection, *, deadline_ns):
    _inherited(deadline_ns)
    uid, gid, _pid = io._call_until(connection, deadline_ns,
        lambda: authority_transport._peer_identity(connection))
    if (uid, gid) != (REQUEST_PEER_UID, REQUEST_PEER_GID):
        raise AuthorityTransportError("consume completion caller peer differs")
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("consume completion request magic differs")
    return _recv_bodies(connection, response=False, deadline_ns=deadline_ns)


def _send(connection, originals, *, response, deadline_ns):
    _inherited(deadline_ns)
    held = _originals(originals, response=response)
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        if raw:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_response(connection, originals, *, deadline_ns):
    # The actual recovery owner establishes durable originals. Its accepted
    # socket close supplies response EOF; this function only frames bytes.
    _send(connection, originals, response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns):
    """One fixed root-listener exchange; unverified raw4, never a retry."""
    path, timeout, uid, gid = _endpoint(endpoint)
    bound = min(_inherited(deadline_ns), _deadline_ns(timeout))
    held = _originals(originals, response=False)
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("consume completion server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("consume completion response magic differs")
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
