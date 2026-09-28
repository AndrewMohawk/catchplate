"""Fixed consume-grant original exchange, not permission or proof replay.

The request carries original caller control, plan, encrypted bundle and closed
expectation data. The response is one original signed grant. Peer admission
precedes body I/O; exact EOF and one inherited deadline cover both directions.
No plaintext token, private key, retry decision or successful input DTO belongs
to this protocol. The caller must independently authenticate returned bytes.
"""
from __future__ import annotations

import socket

from serverware import authority_contract as authority
from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_oidc_session_activation_delivery_execution_authorization as caller
from serverware import authority_oidc_session_activation_delivery_execution_bundle as bundle
from serverware import authority_oidc_session_activation_delivery_execution_expectations as expectations
from serverware import authority_oidc_session_activation_delivery_execution_grant as grants
from serverware import authority_oidc_session_activation_delivery_plan_contract as plan


REQUEST_MAGIC, RESPONSE_MAGIC = b"SWODGQ01", b"SWODGR01"
LISTENER_PATH = "/run/serverware/oidc-session-activation-delivery-execution/authorizer.sock"
SERVICE_UID = SERVICE_GID = 65500
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
# The root-created activation socket's kernel peer is not measured service
# identity or a substitute for the grant's separately enrolled signature.
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
REQUEST_LIMITS = (caller.MAX_AUTHORIZATION_BYTES, plan.MAX_BYTES, bundle.MAX_BYTES, expectations.MAX_BYTES)
RESPONSE_LIMITS = (grants.MAX_GRANT_BYTES,)
REQUEST_HEADER_BYTES = len(REQUEST_MAGIC) + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = len(RESPONSE_MAGIC) + 8 * len(RESPONSE_LIMITS)
MAX_BYTES = authority.MAX_RESULT_BYTES
MAX_RESPONSE_BYTES = grants.MAX_GRANT_BYTES
MAX_REQUEST_BYTES = MAX_BYTES - REQUEST_HEADER_BYTES - RESPONSE_HEADER_BYTES - MAX_RESPONSE_BYTES
AuthorityTransportError = authority_transport.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix


def _fail(message):
    raise AuthorityTransportError(message)


def _source_bounds():
    if (len(REQUEST_MAGIC) != 8 or len(RESPONSE_MAGIC) != 8
            or len(REQUEST_LIMITS) != 4 or len(RESPONSE_LIMITS) != 1
            or MAX_BYTES != 64 * 1024 * 1024 or MAX_BYTES > io.MAX_REQUEST_BYTES
            or MAX_RESPONSE_BYTES != RESPONSE_LIMITS[0]
            or MAX_REQUEST_BYTES < bundle.OVERHEAD_BYTES + 8
            or MAX_REQUEST_BYTES + MAX_RESPONSE_BYTES + REQUEST_HEADER_BYTES + RESPONSE_HEADER_BYTES != MAX_BYTES):
        _fail("consume authorizer source frame inventory or aggregate bound changed")


def _timeout(value):
    if type(value) is not int or not 1 <= value <= 30:
        _fail("consume authorizer timeout differs from its fixed profile")
    return value


def _deadline_ns(timeout_seconds):
    return io._deadline_ns(_timeout(timeout_seconds))


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        _fail("consume authorizer endpoint is not an exact four-tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        _fail("consume authorizer endpoint differs from its fixed root-created listener")
    return path, _timeout(timeout), uid, gid


def _lengths(lengths, *, response):
    _source_bounds()
    if type(response) is not bool:
        _fail("consume authorizer frame direction is not source selected")
    limits = RESPONSE_LIMITS if response else REQUEST_LIMITS
    maximum = MAX_RESPONSE_BYTES if response else MAX_REQUEST_BYTES
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= cap for size, cap in zip(lengths, limits))
            or sum(lengths) > maximum
            or not response and lengths[2] < bundle.OVERHEAD_BYTES + 2):
        _fail("consume authorizer original lengths exceed their fixed bounds")


def _originals(values, *, response):
    if type(response) is not bool:
        _fail("consume authorizer frame direction is invalid")
    count = len(RESPONSE_LIMITS if response else REQUEST_LIMITS)
    if (type(values) is not tuple or len(values) != count
            or any(type(raw) is not bytes for raw in values)):
        _fail("consume authorizer requires exact immutable originals")
    _lengths(tuple(len(raw) for raw in values), response=response)
    if not response:
        try:
            bundle._bounded_frame(values[2])
        except bundle.DeliveryExecutionBundleError as exc:
            raise AuthorityTransportError("consume authorizer ciphertext framing differs") from exc
    return values


def _recv_bodies(connection, *, response, deadline_ns, maximum_request_bytes=None):
    if type(response) is not bool:
        _fail("consume authorizer frame direction is invalid")
    count = len(RESPONSE_LIMITS if response else REQUEST_LIMITS)
    header = io._recv_exact_until(connection, count * 8, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, len(header), 8))
    _lengths(lengths, response=response)
    if maximum_request_bytes is not None and (response
            or type(maximum_request_bytes) is not int or not 1 <= maximum_request_bytes <= MAX_REQUEST_BYTES
            or sum(lengths) > maximum_request_bytes):
        _fail("consume execution request exceeds its retained-original allowance")
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns) for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _originals(originals, response=response)


def _recv_request(connection, *, deadline_ns, maximum_request_bytes=None):
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        _fail("consume authorizer request magic differs")
    return _recv_bodies(connection, response=False, deadline_ns=deadline_ns,
        maximum_request_bytes=maximum_request_bytes)


def _send(connection, originals, *, response, deadline_ns):
    held = _originals(originals, response=response)
    magic = RESPONSE_MAGIC if response else REQUEST_MAGIC
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_response(connection, grant_bytes, *, deadline_ns):
    _send(connection, (grant_bytes,), response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns):
    """One attempt returns unverified grant bytes; no retry or replay authority."""
    path, timeout, uid, gid = _endpoint(endpoint)
    held = _originals(originals, response=False)
    _check_deadline(deadline_ns)
    bound = min(_deadline_ns(timeout), deadline_ns)
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            _fail("consume authorizer server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            _fail("consume authorizer response magic differs")
        received = _recv_bodies(connection, response=True, deadline_ns=bound)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(bound)
    return received[0]


def _socket_request_on_work(endpoint, *, originals, deadline_ns, work, current):
    """Guarded consume raw4/raw1 exchange; return unverified grant bytes."""
    from serverware import authority_oidc_session_activation_caller_transport as guarded
    return guarded._consume_authorizer_on_work(endpoint, originals=originals,
        deadline_ns=deadline_ns, work=work, current=current)
