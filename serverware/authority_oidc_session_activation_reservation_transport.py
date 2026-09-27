"""Fixed activation raw5 to original reserve/snapshot/ack Unix exchange.

Raw five are original caller authorization, signed plan, encrypted execution
originals, canonical expectation data and original grant. Raw three are reserve,
snapshot and acknowledgment originals, not authority from shape or socket peer.
All frame and whole-exchange bounds precede body allocation. The serving owner
admits its fixed peer before reading; clients admit the root-created listener
before send/read. One inherited deadline, half-close and exact EOF cover the
exchange. No JSON parsing, decryption, signing, work allowance or retry occurs.
"""
from __future__ import annotations

import socket

from serverware import authority_contract as authority
from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_oidc_session_activation_execution_authorization as authorization
from serverware import authority_oidc_session_activation_execution_bundle as bundle
from serverware import authority_oidc_session_activation_execution_expectations as expectations
from serverware import authority_oidc_session_activation_plan_contract as plan
from serverware import authority_oidc_session_activation_reservation_records as records
from serverware import authority_successor_execution_grant as grants


REQUEST_MAGIC, RESPONSE_MAGIC = b"SWOARQ01", b"SWOARR01"
LISTENER_PATH = "/run/serverware/oidc-session-activation-execution/reserver.sock"
SERVICE_UID = SERVICE_GID = 65505
REQUEST_PEER_UID = REQUEST_PEER_GID = 65532
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
REQUEST_LIMITS = (authorization.MAX_AUTHORIZATION_BYTES, plan.MAX_BYTES,
    bundle.MAX_BYTES, expectations.MAX_BYTES, grants.MAX_GRANT_BYTES)
RESPONSE_LIMITS = (records.MAX_REQUEST_BYTES, records.MAX_SNAPSHOT_BYTES, records.MAX_RECEIPT_BYTES)
REQUEST_HEADER_BYTES = len(REQUEST_MAGIC) + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = len(RESPONSE_MAGIC) + 8 * len(RESPONSE_LIMITS)
MAX_BYTES = authority.MAX_RESULT_BYTES
MAX_RESPONSE_BYTES = sum(RESPONSE_LIMITS)
# Reserve the maximum response and both headers before allocating any request
# body. The bundle's individual limit never enlarges this 64 MiB exchange cap.
MAX_REQUEST_BYTES = MAX_BYTES - REQUEST_HEADER_BYTES - RESPONSE_HEADER_BYTES - MAX_RESPONSE_BYTES
AuthorityTransportError = authority_transport.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix


def _timeout(value):
    if type(value) is not int or not 1 <= value <= 30:
        raise AuthorityTransportError("activation reserve timeout differs from its fixed profile")
    return value


def _deadline_ns(timeout_seconds):
    return io._deadline_ns(_timeout(timeout_seconds))


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("activation reserve endpoint is not an exact four-tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("activation reserve endpoint differs from its fixed listener")
    return path, _timeout(timeout), uid, gid


def _lengths(lengths, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("activation reserve frame direction is not source selected")
    limits = RESPONSE_LIMITS if response else REQUEST_LIMITS
    maximum = MAX_RESPONSE_BYTES if response else MAX_REQUEST_BYTES
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= cap
                for size, cap in zip(lengths, limits))
            or sum(lengths) > maximum
            or not response and lengths[2] < bundle.OVERHEAD_BYTES + 2):
        raise AuthorityTransportError("activation reserve original lengths exceed their fixed bounds")


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("activation reserve frame direction is invalid")
    count = len(RESPONSE_LIMITS if response else REQUEST_LIMITS)
    if (type(values) is not tuple or len(values) != count
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("activation reserve requires exact immutable originals")
    _lengths(tuple(len(raw) for raw in values), response=response)
    if not response:
        try:
            bundle._bounded_frame(values[2])
        except bundle.ActivationExecutionBundleError as exc:
            raise AuthorityTransportError("activation reserve encrypted-original frame differs") from exc
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("activation reserve frame direction is invalid")
    count = len(RESPONSE_LIMITS if response else REQUEST_LIMITS)
    header = io._recv_exact_until(connection, count * 8, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in range(0, len(header), 8))
    _lengths(lengths, response=response)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns) for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _originals(originals, response=response)


def _recv_request(connection, *, deadline_ns):
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("activation reserve request magic differs")
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
    """Actual owner supplies durable originals and closes for response EOF."""
    _send(connection, originals, response=True, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns):
    """One attempt returns unverified raw3 under the required original bound."""
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("activation reserve requires an original absolute deadline")
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
            raise AuthorityTransportError("activation reserve server peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("activation reserve response magic differs")
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
