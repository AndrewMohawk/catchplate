"""Fixed recovery-bootstrap staging, never worker readiness or token delivery.

The public caller relays only an exact root-signed original. The independent
root receiver owns admission/resources and its accepted socket. Both sides keep
their own original work/current/deadline; neither frame supplies authority.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_registration_completion_transport as framing
from serverware import oidc_session_activation_release_transport as chunks
from serverware import oidc_session_activation_release_bootstrap as server
from serverware import oidc_session_activation_release_client_authorization as client


authority_transport, io = framing.authority_transport, framing.io
AuthorityTransportError = framing.AuthorityTransportError
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = "/run/serverware/oidc-session-activation-token-release/recovery-bootstrap.sock"
PURPOSE = b"stage-oidc-session-activation-release-recovery-bootstrap"
ACK_STATUS = b"staged"
BOOTSTRAP_IDENTITY_DOMAIN = client.SERVER_BOOTSTRAP_IDENTITY_DOMAIN
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWORDQ01", b"SWORDR01"
MAX_BOOTSTRAP_BYTES = server.MAX_BYTES
REQUEST_LIMITS = (len(PURPOSE), MAX_BOOTSTRAP_BYTES)
RESPONSE_LIMITS = (len(ACK_STATUS), 71)
REQUEST_HEADER_BYTES = 8 + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = 8 + 8 * len(RESPONSE_LIMITS)
MAX_BYTES = MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
MAX_EXCHANGE_BYTES = authority.MAX_RESULT_BYTES
_timeout, _deadline_ns = framing._timeout, framing._deadline_ns


def _fail(message):
    raise AuthorityTransportError(message)


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("recovery staging endpoint requires its exact fixed tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH or type(timeout) is not int
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("recovery staging endpoint differs from the fixed root listener")
    return path, _timeout(timeout), uid, gid


def _exchange_bound():
    if (MAX_EXCHANGE_BYTES != 64 * 1024 * 1024
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
                + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("recovery staging exceeds its complete exchange ceiling")


def _bootstrap_limit(maximum_bootstrap_bytes):
    if maximum_bootstrap_bytes is None:
        return MAX_BOOTSTRAP_BYTES
    if (type(maximum_bootstrap_bytes) is not int
            or not 2 <= maximum_bootstrap_bytes <= MAX_BOOTSTRAP_BYTES):
        _fail("recovery staging allocation cap may only tighten its fixed bound")
    return maximum_bootstrap_bytes


def _request_lengths(lengths, *, maximum_bootstrap_bytes=None):
    _exchange_bound()
    maximum = _bootstrap_limit(maximum_bootstrap_bytes)
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int for size in lengths)
            or lengths[0] != REQUEST_LIMITS[0] or not 2 <= lengths[1] <= maximum):
        _fail("recovery staging request differs from its fixed raw2")


def _response_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or lengths != RESPONSE_LIMITS
            or any(type(size) is not int for size in lengths)):
        _fail("recovery staging ACK requires exact status6 and identity71")


def _originals(values, *, response):
    if (type(response) is not bool or type(values) is not tuple or len(values) != 2
            or any(type(raw) is not bytes for raw in values)):
        _fail("recovery staging requires exact immutable raw2")
    (_response_lengths if response else _request_lengths)(tuple(map(len, values)))
    if response:
        if values[0] != ACK_STATUS or not framing._digest_bytes(values[1]):
            _fail("recovery staging ACK status or identity differs")
    elif values[0] != PURPOSE:
        _fail("recovery staging request purpose differs")
    return values


def _bootstrap_identity_on_work(original, *, deadline_ns, work, current):
    """Bind the actual signed bytes; identity alone proves no staging or trust."""
    held = _originals((PURPOSE, original), response=False)[1]
    chunks._guard(work, current, deadline_ns)
    digest = client._server_bootstrap_digest_on_work(held, work)
    work.charge(input_bytes=71)
    identity = digest.encode("ascii")
    if not framing._digest_bytes(identity):
        _fail("recovery staging bootstrap identity is not canonical")
    chunks._guard(work, current, deadline_ns)
    return identity


def _recv_request(connection, *, deadline_ns, work, current, maximum_bootstrap_bytes=None):
    """Root receiver retains socket ownership; cap every body before allocation."""
    maximum = _bootstrap_limit(maximum_bootstrap_bytes)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    if chunks._recv_exact(connection, 8, **kwargs) != REQUEST_MAGIC:
        _fail("recovery staging request magic differs")
    header = chunks._recv_exact(connection, REQUEST_HEADER_BYTES - 8, **kwargs)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in (0, 8))
    _request_lengths(lengths, maximum_bootstrap_bytes=maximum)
    work.charge(input_bytes=2 * sum(lengths))
    originals = tuple(chunks._recv_precharged(connection, size, **kwargs) for size in lengths)
    chunks._eof(connection, **kwargs)
    held = _originals(originals, response=False)
    chunks._guard(work, current, deadline_ns)
    return held


def _send_response(connection, originals, *, deadline_ns, work, current):
    """Frame only the actual receiver's ACK, without closing its connection."""
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


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current):
    """One fixed exchange; return its matched ACK only after owned normal close."""
    from serverware import authority_oidc_session_activation_caller_transport as caller

    held = _originals(originals, response=False)
    selected = _endpoint(endpoint)
    identity = _bootstrap_identity_on_work(held[1], deadline_ns=deadline_ns, work=work, current=current)
    response = caller._recovery_delivery_on_work(selected, originals=held,
        deadline_ns=deadline_ns, work=work, current=current)
    received = _originals(response, response=True)
    work.charge(input_bytes=2 * len(identity))
    if received[1] != identity:
        _fail("recovery staging ACK differs from the exact outgoing original")
    chunks._guard(work, current, deadline_ns)
    return received
