"""Root proof-bootstrap receiving frames, not a readiness receipt.

The fixed issuer peer supplies only an exact root-signed bootstrap. The actual
receiver owns the socket and independently authenticates policy/resources.
The genuine one-shot issuer owns its outgoing channel; this codec neither
creates authority nor exempts an arbitrary descriptor from owner checks.
"""
from __future__ import annotations

import errno
import socket

from catchplate import authority_registration_completion_transport as framing
from catchplate import oidc_session_activation_release_proof_bootstrap as bootstrap
from catchplate import oidc_session_activation_release_transport as chunks


AuthorityTransportError = framing.AuthorityTransportError
authority_transport, io = framing.authority_transport, framing.io
REQUEST_PEER_UID = REQUEST_PEER_GID = 65494
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = "/run/catchplate/oidc-session-activation-token-release/proof-bootstrap.sock"
PURPOSE = b"stage-oidc-session-activation-release-proof-inputs"
ACK_STATUS = b"staged"
BOOTSTRAP_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationReleaseProofInputDeliveryBootstrapIdentity/v1"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOPDQ01", b"SWOPDR01"
MAX_BOOTSTRAP_BYTES = MAX_ORIGINAL_BYTES = bootstrap.MAX_BYTES
REQUEST_LIMITS = (len(PURPOSE), MAX_BOOTSTRAP_BYTES)
RESPONSE_LIMITS = (len(ACK_STATUS), 71)
REQUEST_HEADER_BYTES = RESPONSE_HEADER_BYTES = 24
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_EXCHANGE_BYTES = bootstrap.MAX_ORIGINAL_BYTES
_timeout, _deadline_ns = framing._timeout, framing._deadline_ns


def _fail(message):
    raise AuthorityTransportError(message)


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("proof staging endpoint requires its exact configured tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH or type(timeout) is not int
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("proof staging endpoint differs from its fixed root listener")
    return path, _timeout(timeout), uid, gid


def _original_limit(maximum_original_bytes):
    maximum = MAX_ORIGINAL_BYTES if maximum_original_bytes is None else maximum_original_bytes
    if type(maximum) is not int or not 2 <= maximum <= MAX_ORIGINAL_BYTES:
        _fail("proof staging capacity may only tighten its original ceiling")
    return maximum


def _request_lengths(lengths, *, maximum_original_bytes=None):
    maximum = _original_limit(maximum_original_bytes)
    if (MAX_EXCHANGE_BYTES != 64 * 1024 * 1024
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
                + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES
            or type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int for size in lengths)
            or lengths[0] != len(PURPOSE) or not 2 <= lengths[1] <= maximum):
        _fail("proof staging request differs from its bounded raw2")


def _response_lengths(lengths):
    if (type(lengths) is not tuple or lengths != RESPONSE_LIMITS
            or any(type(size) is not int for size in lengths)):
        _fail("proof staging ACK requires exact status6 and identity71")


def _originals(values, *, response):
    if (type(response) is not bool or type(values) is not tuple or len(values) != 2
            or any(type(raw) is not bytes for raw in values)):
        _fail("proof staging requires exact immutable raw2")
    (_response_lengths if response else _request_lengths)(tuple(map(len, values)))
    if response:
        if values[0] != ACK_STATUS or not framing._digest_bytes(values[1]):
            _fail("proof staging ACK status or identity differs")
    elif values[0] != PURPOSE:
        _fail("proof staging purpose differs")
    return values


def _bootstrap_identity_on_work(original, *, deadline_ns, work, current):
    held = _originals((PURPOSE, original), response=False)
    chunks._guard(work, current, deadline_ns)
    digest = bootstrap.plan._frame(BOOTSTRAP_IDENTITY_DOMAIN, (held[1],), work)
    work.charge(input_bytes=71)
    result = digest.encode("ascii")
    if not framing._digest_bytes(result):
        _fail("proof staging bootstrap identity is not canonical")
    chunks._guard(work, current, deadline_ns)
    return result


def _recv_request(connection, *, deadline_ns, work, current, maximum_original_bytes=None):
    maximum = _original_limit(maximum_original_bytes)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    if chunks._recv_exact(connection, 8, **kwargs) != REQUEST_MAGIC:
        _fail("proof staging request magic differs")
    header = chunks._recv_exact(connection, 16, **kwargs)
    work.charge(input_bytes=16)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in (0, 8))
    _request_lengths(lengths, maximum_original_bytes=maximum)
    work.charge(input_bytes=2 * sum(lengths))
    values = tuple(chunks._recv_precharged(connection, size, **kwargs) for size in lengths)
    chunks._eof(connection, **kwargs)
    held = _originals(values, response=False)
    chunks._guard(work, current, deadline_ns)
    return held


def _send_response(connection, originals, *, deadline_ns, work, current):
    held = _originals(originals, response=True)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    work.charge(input_bytes=2 * RESPONSE_HEADER_BYTES + sum(map(len, held)))
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    for raw in (header, *held):
        chunks._send_precharged(connection, raw, **kwargs)
    chunks._guard(work, current, deadline_ns)


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current, channel):
    """One actual issuer channel; return only matched ACK plus normal close."""
    from catchplate import oidc_session_activation_release_proof_input_issuer_startup as issuer

    if type(channel) is not issuer._DeliveryChannel:
        _fail("proof staging requires the actual proof-input issuer channel")
    try:
        channel.check(endpoint=endpoint, deadline_ns=deadline_ns, work=work, current=current)
        path, timeout, uid, gid = _endpoint(endpoint)
        held = _originals(originals, response=False)
        chunks._guard(work, current, deadline_ns)
        bound = min(deadline_ns, chunks._native(lambda: _deadline_ns(timeout),
            work=work, current=current, deadline_ns=deadline_ns))
        kwargs = {"deadline_ns": bound, "work": work, "current": current}
        expected = _bootstrap_identity_on_work(held[1], **kwargs)
        connection = channel.open()
        chunks._connection(connection, **kwargs)
        connected = chunks._native(lambda: connection.connect_ex(path), **kwargs)
        if type(connected) is not int or connected not in (0, errno.EINPROGRESS, errno.EALREADY):
            _fail("proof staging connection was not established")
        if connected != 0:
            chunks._ready(connection, writing=True, **kwargs)
            error = chunks._native(lambda: connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), **kwargs)
            if type(error) is not int or error != 0:
                _fail("proof staging connection failed")
        channel.connected()
        chunks._peer(connection, (uid, gid), **kwargs)
        work.charge(input_bytes=2 * REQUEST_HEADER_BYTES + sum(map(len, held)))
        header = REQUEST_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in held)
        for raw in (header, *held):
            chunks._send_precharged(connection, raw, **kwargs)
        chunks._native(lambda: connection.shutdown(socket.SHUT_WR), **kwargs)
        if chunks._recv_exact(connection, 8, **kwargs) != RESPONSE_MAGIC:
            _fail("proof staging ACK magic differs")
        header = chunks._recv_exact(connection, RESPONSE_HEADER_BYTES - 8, **kwargs)
        work.charge(input_bytes=len(header))
        lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in (0, 8))
        _response_lengths(lengths)
        work.charge(input_bytes=2 * sum(lengths))
        received = tuple(chunks._recv_precharged(connection, size, **kwargs) for size in lengths)
        chunks._eof(connection, **kwargs)
        received = _originals(received, response=True)
        work.charge(input_bytes=2 * 71)
        if received[1] != expected:
            _fail("proof staging ACK names another bootstrap original")
        chunks._guard(work, current, bound)
    finally:
        # This source-owned channel unregisters and closes once. Failure or
        # indeterminate cleanup suppresses the ACK and never renews the attempt.
        channel.close()
    chunks._guard(work, current, bound)
    return received
