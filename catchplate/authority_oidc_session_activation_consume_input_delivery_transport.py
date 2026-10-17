"""Fixed consume-original staging exchange, never a worker-ready receipt.

The genuine issuer channel owns its outgoing socket. Root delivery owns the
accepted socket and must admit originals and hold resources before ACK. This
codec transfers no old token, signing key, successful material or retry grant.
"""
from __future__ import annotations

import errno
import socket

from catchplate import authority_contract as authority
from catchplate import authority_registration_completion_transport as framing
from catchplate import oidc_session_activation_release_transport as chunks
from catchplate import oidc_session_activation_delivery_planner_bootstrap as planner


authority_transport, io = framing.authority_transport, framing.io
AuthorityTransportError = framing.AuthorityTransportError
REQUEST_PEER_UID = REQUEST_PEER_GID = 65495
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
LISTENER_PATH = "/run/catchplate/oidc-session-activation/consume-bootstrap.sock"
PURPOSE = b"stage-oidc-session-activation-consume-inputs"
ACK_STATUS = b"staged"
PLANNER_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationConsumeInputDeliveryPlannerBootstrapIdentity/v1"
HISTORY_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationConsumeInputDeliveryHistoryCustodyIdentity/v1"
REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOCDQ01", b"SWOCDR01"
MAX_PLANNER_BYTES, MAX_HISTORY_BYTES = planner.MAX_BYTES, planner.history.MAX_BYTES
MAX_ORIGINAL_BYTES = MAX_PLANNER_BYTES + MAX_HISTORY_BYTES
REQUEST_LIMITS = (len(PURPOSE), MAX_PLANNER_BYTES, MAX_HISTORY_BYTES)
RESPONSE_LIMITS = (len(ACK_STATUS), 71, 71)
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
        _fail("consume staging endpoint requires its exact tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH or type(timeout) is not int
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("consume staging endpoint differs from the fixed root listener")
    return path, _timeout(timeout), uid, gid


def _exchange_bound():
    if (MAX_PLANNER_BYTES != 4 * 1024 * 1024 or MAX_HISTORY_BYTES != 8 * 1024 * 1024
            or MAX_EXCHANGE_BYTES != 64 * 1024 * 1024
            or REQUEST_HEADER_BYTES + MAX_REQUEST_BYTES + RESPONSE_HEADER_BYTES
                + MAX_RESPONSE_BYTES > MAX_EXCHANGE_BYTES):
        _fail("consume staging exceeds its fixed complete exchange ceiling")


def _original_limit(maximum_original_bytes):
    if maximum_original_bytes is None:
        return MAX_ORIGINAL_BYTES
    if (type(maximum_original_bytes) is not int
            or not 4 <= maximum_original_bytes <= MAX_ORIGINAL_BYTES):
        _fail("consume staging allocation cap may only narrow the two original bodies")
    return maximum_original_bytes


def _request_lengths(lengths, *, maximum_original_bytes=None):
    _exchange_bound()
    maximum = _original_limit(maximum_original_bytes)
    if (type(lengths) is not tuple or len(lengths) != 3
            or any(type(size) is not int for size in lengths)
            or lengths[0] != REQUEST_LIMITS[0]
            or not 2 <= lengths[1] <= MAX_PLANNER_BYTES
            or not 2 <= lengths[2] <= MAX_HISTORY_BYTES
            or lengths[1] + lengths[2] > maximum):
        _fail("consume staging request differs from its fixed bounded raw3")


def _response_lengths(lengths):
    _exchange_bound()
    if (type(lengths) is not tuple or lengths != RESPONSE_LIMITS
            or any(type(size) is not int for size in lengths)):
        _fail("consume staging ACK requires exact status6 and two identities71")


def _originals(values, *, response):
    if type(response) is not bool:
        _fail("consume staging direction is invalid")
    if (type(values) is not tuple or len(values) != 3
            or any(type(raw) is not bytes for raw in values)):
        _fail("consume staging requires exact immutable raw3")
    (_response_lengths if response else _request_lengths)(tuple(map(len, values)))
    if response:
        if values[0] != ACK_STATUS or any(not framing._digest_bytes(raw) for raw in values[1:]):
            _fail("consume staging ACK status or original identities differ")
    elif values[0] != PURPOSE:
        _fail("consume staging purpose differs")
    return values


def _pair_identities_on_work(planner_original, history_original, *, deadline_ns, work, current):
    """Domain-frame exact bytes; neither identity is root or resource admission."""
    held = _originals((PURPOSE, planner_original, history_original), response=False)
    result = []
    for domain, original in zip((PLANNER_IDENTITY_DOMAIN, HISTORY_IDENTITY_DOMAIN), held[1:]):
        chunks._guard(work, current, deadline_ns)
        digest = planner.plan._frame(domain, (original,), work)
        work.charge(input_bytes=71)
        identity = digest.encode("ascii")
        if not framing._digest_bytes(identity):
            _fail("consume staging identity is not canonical")
        result.append(identity)
        chunks._guard(work, current, deadline_ns)
    return tuple(result)


def _receive(connection, *, response, deadline_ns, work, current, maximum_original_bytes=None):
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    if chunks._recv_exact(connection, 8, **kwargs) != magic:
        _fail("consume staging magic differs")
    header = chunks._recv_exact(connection, 24, **kwargs)
    work.charge(input_bytes=len(header))
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in (0, 8, 16))
    if response:
        _response_lengths(lengths)
    else:
        _request_lengths(lengths, maximum_original_bytes=maximum_original_bytes)
    # Validate every length and reserve all body storage before any body read.
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


def _recv_request(connection, *, deadline_ns, work, current, maximum_original_bytes=None):
    """Admit fixed issuer peer before bytes; root supplies remaining body capacity."""
    maximum = _original_limit(maximum_original_bytes)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    return _receive(connection, response=False, maximum_original_bytes=maximum, **kwargs)


def _send_response(connection, originals, *, deadline_ns, work, current):
    """Frame an actual receiver's staged ACK; transport establishes no staging."""
    held = _originals(originals, response=True)
    kwargs = {"deadline_ns": deadline_ns, "work": work, "current": current}
    chunks._guard(work, current, deadline_ns)
    chunks._connection(connection, **kwargs)
    chunks._peer(connection, (REQUEST_PEER_UID, REQUEST_PEER_GID), **kwargs)
    _send(connection, held, response=True, **kwargs)


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current, channel):
    """Return a matched staged ACK only after the genuine channel's normal close."""
    from catchplate import oidc_session_activation_consume_input_issuer_startup as issuer

    if type(channel) is not issuer._DeliveryChannel:
        _fail("consume staging requires the actual issuer-owned delivery channel")
    try:
        channel.check(endpoint=endpoint, deadline_ns=deadline_ns, work=work, current=current)
        path, timeout, uid, gid = _endpoint(endpoint)
        held = _originals(originals, response=False)
        chunks._guard(work, current, deadline_ns)
        bound = min(deadline_ns, chunks._native(lambda: _deadline_ns(timeout),
            work=work, current=current, deadline_ns=deadline_ns))
        kwargs = {"deadline_ns": bound, "work": work, "current": current}
        identities = _pair_identities_on_work(held[1], held[2], **kwargs)
        connection = channel.open()
        chunks._connection(connection, **kwargs)
        connected = chunks._native(lambda: connection.connect_ex(path), **kwargs)
        if type(connected) is not int or connected not in (0, errno.EINPROGRESS, errno.EALREADY):
            _fail("consume staging connection was not established")
        if connected != 0:
            chunks._ready(connection, writing=True, **kwargs)
            error = chunks._native(lambda: connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), **kwargs)
            if type(error) is not int or error != 0:
                _fail("consume staging connection failed")
        channel.connected()
        chunks._peer(connection, (uid, gid), **kwargs)
        _send(connection, held, response=False, **kwargs)
        chunks._native(lambda: connection.shutdown(socket.SHUT_WR), **kwargs)
        received = _receive(connection, response=True, **kwargs)
        work.charge(input_bytes=4 * 71)
        if received[1:] != identities:
            _fail("consume staging ACK differs from the exact outgoing pair")
        chunks._guard(work, current, bound)
    finally:
        # The actual owner unregisters/closes once. Uncertain close suppresses
        # the ACK; this transport never detaches, retries or owns another FD.
        channel.close()
    chunks._guard(work, current, bound)
    return received
