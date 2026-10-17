"""Exact release-bootstrap staging exchange, not runtime or token readiness.

The issuer's genuine channel owns the outgoing socket; root delivery owns its
accepted socket. Every operation retains original work/current/deadline. A
staged ACK binds the outgoing original only; actual root/resource admission
must precede its construction. No file, key, retry or authority lives here.
"""
from __future__ import annotations

import errno
import socket

from catchplate import authority_contract as authority
from catchplate import authority_registration_completion_transport as framing
from catchplate import oidc_session_activation_release_transport as chunks
from catchplate import oidc_session_activation_release_bootstrap as server
from catchplate import oidc_session_activation_release_client_authorization as client


authority_transport, io = framing.authority_transport, framing.io
AuthorityTransportError = framing.AuthorityTransportError
REQUEST_PEER_UID = REQUEST_PEER_GID = 65496
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = "/run/catchplate/oidc-session-activation-token-release/bootstrap.sock"
PURPOSE = b"stage-oidc-session-activation-release-bootstrap"
ACK_STATUS = b"staged"
BOOTSTRAP_IDENTITY_DOMAIN = client.SERVER_BOOTSTRAP_IDENTITY_DOMAIN
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOGDQ01", b"SWOGDR01"
MAX_BOOTSTRAP_BYTES = server.MAX_BYTES
REQUEST_LIMITS = (len(PURPOSE), MAX_BOOTSTRAP_BYTES)
RESPONSE_LIMITS = (len(ACK_STATUS), 71)
REQUEST_HEADER_BYTES = 8 + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = 8 + 8 * len(RESPONSE_LIMITS)
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_EXCHANGE_BYTES = authority.MAX_RESULT_BYTES
_timeout, _deadline_ns = framing._timeout, framing._deadline_ns
_check_deadline = io._check_deadline


def _fail(message):
    raise AuthorityTransportError(message)


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("release bootstrap staging endpoint requires its exact tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("release bootstrap staging endpoint differs from the fixed root listener")
    return path, _timeout(timeout), uid, gid


def _exchange_bound():
    if (MAX_EXCHANGE_BYTES != 64 * 1024 * 1024
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
                + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("release bootstrap staging exceeds its complete exchange ceiling")


def _bootstrap_limit(maximum_bootstrap_bytes):
    if maximum_bootstrap_bytes is None:
        return MAX_BOOTSTRAP_BYTES
    if (type(maximum_bootstrap_bytes) is not int
            or not 2 <= maximum_bootstrap_bytes <= MAX_BOOTSTRAP_BYTES):
        _fail("release bootstrap allocation cap may only narrow its original bound")
    return maximum_bootstrap_bytes


def _request_lengths(lengths, *, maximum_bootstrap_bytes=None):
    _exchange_bound()
    maximum = _bootstrap_limit(maximum_bootstrap_bytes)
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int for size in lengths)
            or lengths[0] != REQUEST_LIMITS[0] or not 2 <= lengths[1] <= maximum):
        _fail("release bootstrap staging request differs from its fixed raw2")


def _response_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or lengths != RESPONSE_LIMITS
            or any(type(size) is not int for size in lengths)):
        _fail("release bootstrap staging ACK requires exact status6 and identity71")


def _originals(values, *, response):
    if type(response) is not bool:
        _fail("release bootstrap staging frame direction is invalid")
    if (type(values) is not tuple or len(values) != 2
            or any(type(raw) is not bytes for raw in values)):
        _fail("release bootstrap staging requires exact immutable raw2")
    (_response_lengths if response else _request_lengths)(tuple(map(len, values)))
    if response:
        if values[0] != ACK_STATUS or not framing._digest_bytes(values[1]):
            _fail("release bootstrap staging ACK status or identity differs")
    elif values[0] != PURPOSE:
        _fail("release bootstrap staging request purpose differs")
    return values


def _bootstrap_identity_on_work(original, *, deadline_ns, work, current):
    """Frame the actual original; this identity alone admits no root/resource."""
    held = _originals((PURPOSE, original), response=False)[1]
    chunks._guard(work, current, deadline_ns)
    digest = client._server_bootstrap_digest_on_work(held, work)
    work.charge(input_bytes=71)
    identity = digest.encode("ascii")
    if not framing._digest_bytes(identity):
        _fail("release bootstrap staging identity is not canonical")
    chunks._guard(work, current, deadline_ns)
    return identity


def _receive(connection, *, response, deadline_ns, work, current,
        maximum_bootstrap_bytes=None):
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    if chunks._recv_exact(connection, 8, **kwargs) != magic:
        _fail("release bootstrap staging magic differs")
    header = chunks._recv_exact(connection, 16, **kwargs)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in (0, 8))
    if response:
        _response_lengths(lengths)
    else:
        _request_lengths(lengths, maximum_bootstrap_bytes=maximum_bootstrap_bytes)
    # Admit all frame lengths and reserve all body storage before the first body.
    work.charge(input_bytes=2 * sum(lengths))
    values = tuple(chunks._recv_precharged(connection, size, **kwargs) for size in lengths)
    chunks._eof(connection, **kwargs)
    held = _originals(values, response=response)
    chunks._guard(work, current, deadline_ns)
    return held


def _send(connection, originals, *, response, deadline_ns, work, current):
    held = _originals(originals, response=response)
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    header_size = RESPONSE_HEADER_BYTES if response else REQUEST_HEADER_BYTES
    work.charge(input_bytes=2 * header_size + sum(map(len, held)))
    chunks._guard(work, current, deadline_ns)
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        chunks._send_precharged(connection, raw, work=work, current=current, deadline_ns=deadline_ns)
    chunks._guard(work, current, deadline_ns)


def _recv_request(connection, *, deadline_ns, work, current, maximum_bootstrap_bytes=None):
    """Root delivery owns this socket and supplies its remaining inventory cap."""
    maximum = _bootstrap_limit(maximum_bootstrap_bytes)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    return _receive(connection, response=False, maximum_bootstrap_bytes=maximum, **kwargs)


def _send_response(connection, originals, *, deadline_ns, work, current):
    """Frame a genuine receiver's staged ACK, never manufacture staging proof."""
    held = _originals(originals, response=True)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    _send(connection, held, response=True, **kwargs)


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current, channel):
    """Return a matched staged ACK only after the actual channel's normal close."""
    from catchplate import oidc_session_activation_release_grant_issuer_startup as issuer

    if type(channel) is not issuer._DeliveryChannel:
        _fail("release bootstrap staging requires the actual issuer delivery channel")
    try:
        channel.check(endpoint=endpoint, deadline_ns=deadline_ns, work=work, current=current)
        path, timeout, uid, gid = _endpoint(endpoint)
        held = _originals(originals, response=False)
        chunks._guard(work, current, deadline_ns)
        bound = min(deadline_ns, chunks._native(lambda: _deadline_ns(timeout),
            work=work, current=current, deadline_ns=deadline_ns))
        kwargs = {"deadline_ns": bound, "work": work, "current": current}
        identity = _bootstrap_identity_on_work(held[1], **kwargs)
        connection = channel.open()
        chunks._connection(connection, **kwargs)
        connected = chunks._native(lambda: connection.connect_ex(path), **kwargs)
        if type(connected) is not int or connected not in (0, errno.EINPROGRESS, errno.EALREADY):
            _fail("release bootstrap staging connection was not established")
        if connected != 0:
            chunks._ready(connection, writing=True, **kwargs)
            error = chunks._native(lambda: connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), **kwargs)
            if type(error) is not int or error != 0:
                _fail("release bootstrap staging connection failed")
        channel.connected()
        chunks._peer(connection, (uid, gid), **kwargs)
        _send(connection, held, response=False, **kwargs)
        chunks._native(lambda: connection.shutdown(socket.SHUT_WR), **kwargs)
        received = _receive(connection, response=True, **kwargs)
        work.charge(input_bytes=2 * len(identity))
        if received[1] != identity:
            _fail("release bootstrap staging ACK differs from the outgoing original")
        chunks._guard(work, current, bound)
    finally:
        # The genuine owner closes/unregisters once, even when a guard fails.
        # A close exception suppresses the ACK. Never detach or close it here.
        channel.close()
    chunks._guard(work, current, bound)
    return received
