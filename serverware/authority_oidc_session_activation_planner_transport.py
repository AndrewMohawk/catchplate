"""Closed private activation-planning exchange, not plan or caller admission.

Raw8 carries only a fixed operation, assertion/pending-token originals and five
subject IDs. Raw7 carries prepared originals/locators plus ciphertext or uncertainty.
Lengths precede bodies, exact EOF is required, and the inherited deadline is
never renewed. No parser, work allowance, retry or arbitrary endpoint exists.
"""
from __future__ import annotations

import socket

from serverware import authority_contract as authority
from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_oidc_session_activation as assertion
from serverware import authority_oidc_session_activation_plan_contract as plan
from serverware import authority_oidc_session_activation_execution_bundle as bundle


OPERATION = b"oidc.session.activate"
REQUEST_MAGIC = b"SWOAPQ02"
RESPONSE_MAGIC = b"SWOAPR02"
LISTENER_PATH = "/run/serverware/oidc-session-activation/planner.sock"
EXPECTED_PEER_UID = EXPECTED_PEER_GID = 0
REQUEST_LIMITS = (len(OPERATION), assertion.MAX_ASSERTION_BYTES, 64,
    4 * 1024, 4 * 128, 1366, 4 * 1024, 4 * 1024)
RESPONSE_LIMITS = (len(b"uncertain"), authority.MAX_REQUEST_BYTES,
    assertion.MAX_CONTEXT_BYTES, plan.MAX_BYTES, 71, 71, bundle.MAX_BYTES)
MAX_REQUEST_BYTES = sum(REQUEST_LIMITS)
MAX_BYTES = authority.MAX_RESULT_BYTES
REQUEST_HEADER_BYTES = len(REQUEST_MAGIC) + 8 * len(REQUEST_LIMITS)
RESPONSE_HEADER_BYTES = len(RESPONSE_MAGIC) + 8 * len(RESPONSE_LIMITS)
# Reserve even the largest valid request and both headers before accepting a
# response body. Adding ciphertext must not enlarge the aggregate 64 MiB cap.
MAX_RESPONSE_BYTES = min(sum(RESPONSE_LIMITS),
    MAX_BYTES - MAX_REQUEST_BYTES - REQUEST_HEADER_BYTES - RESPONSE_HEADER_BYTES)
AuthorityTransportError = authority_transport.AuthorityTransportError
_check_deadline, _recv_prefix = io._check_deadline, io._recv_prefix
_URLSAFE = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


def _timeout(value):
    if type(value) is not int or not 1 <= value <= 30:
        raise AuthorityTransportError("activation planner timeout must be an integer from one through thirty")
    return value


def _deadline_ns(timeout_seconds):
    return io._deadline_ns(_timeout(timeout_seconds))


def _endpoint(endpoint):
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("activation planner endpoint is not an exact four-tuple")
    path, timeout, uid, gid = endpoint
    if (type(path) is not str or path != LISTENER_PATH
            or type(uid) is not int or uid != EXPECTED_PEER_UID
            or type(gid) is not int or gid != EXPECTED_PEER_GID):
        raise AuthorityTransportError("activation planner fixed listener differs")
    return path, _timeout(timeout), uid, gid


def _request_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 8
            or any(type(size) is not int or not 1 <= size <= maximum
                for size, maximum in zip(lengths, REQUEST_LIMITS))
            or lengths[0] != len(OPERATION) or lengths[1] < 2 or lengths[2] != 64
            or sum(lengths) > MAX_REQUEST_BYTES):
        raise AuthorityTransportError("activation planner request length inventory differs")


def _response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 7
            or any(type(size) is not int or not 0 <= size <= maximum
                for size, maximum in zip(lengths, RESPONSE_LIMITS))
            or sum(lengths) > MAX_RESPONSE_BYTES):
        raise AuthorityTransportError("activation planner response exceeds its length inventory")
    state, request, scope, envelope, plan_id, journal_id, encrypted = lengths
    if not ((state == len(b"prepared") and request >= 2 and scope >= 2 and envelope >= 2
            and plan_id == journal_id == 71 and encrypted >= bundle.OVERHEAD_BYTES + 2)
            or (state == len(b"uncertain")
                and request == scope == envelope == plan_id == journal_id == encrypted == 0)):
        raise AuthorityTransportError("activation planner response branch differs")


def _digest(raw):
    return len(raw) == 71 and raw[:7] == b"sha256:" and all(item in b"0123456789abcdef" for item in raw[7:])


def _credential(raw):
    # Canonical unpadded base64url shape without decoding any original.
    if not 1 <= len(raw) <= 1366 or len(raw) % 4 == 1 or any(item not in _URLSAFE for item in raw):
        return False
    if not 1 <= len(raw) * 3 // 4 <= 1024:
        return False
    remainder = len(raw) % 4
    return not ((remainder == 2 and _URLSAFE.index(raw[-1]) & 15)
        or (remainder == 3 and _URLSAFE.index(raw[-1]) & 3))


def _originals(values, *, response):
    if type(response) is not bool:
        raise AuthorityTransportError("activation planner frame direction is invalid")
    count = 7 if response else 8
    if type(values) is not tuple or len(values) != count or any(type(raw) is not bytes for raw in values):
        raise AuthorityTransportError("activation planner requires its exact immutable original inventory")
    lengths = tuple(len(raw) for raw in values)
    if response:
        _response_lengths(lengths)
        if not ((values[0] == b"prepared" and _digest(values[4]) and _digest(values[5]))
                or (values[0] == b"uncertain" and all(raw == b"" for raw in values[1:]))):
            raise AuthorityTransportError("activation planner response values differ")
        if values[0] == b"prepared":
            try:
                bundle._bounded_frame(values[6])
            except bundle.ActivationExecutionBundleError as exc:
                raise AuthorityTransportError("activation planner encrypted-original frame differs") from exc
    else:
        _request_lengths(lengths)
        if (values[0] != OPERATION or any(item not in _URLSAFE for item in values[2])
                or not _credential(values[5]) or any(b"\x00" in raw for raw in values[3:])):
            raise AuthorityTransportError("activation planner request values differ")
    return values


def _recv_bodies(connection, *, response, deadline_ns):
    if type(response) is not bool:
        raise AuthorityTransportError("activation planner frame direction is invalid")
    count = 7 if response else 8
    header = io._recv_exact_until(connection, count * 8, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, len(header), 8))
    (_response_lengths if response else _request_lengths)(lengths)
    values = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns) if size else b""
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _originals(values, response=response)


def _recv_request(connection, *, deadline_ns):
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("activation planner request magic differs")
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
    """Return unverified ciphertext-bearing raw7 after one fixed-peer exchange."""
    if type(deadline_ns) is not int or deadline_ns <= 0:
        raise AuthorityTransportError("activation planner requires the original absolute deadline")
    path, timeout, uid, gid = _endpoint(endpoint)
    held = _originals(originals, response=False)
    _check_deadline(deadline_ns)
    bound = min(deadline_ns, _deadline_ns(timeout))
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("activation planner listener peer differs")
        _send(connection, held, response=False, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("activation planner response magic differs")
        received = _recv_bodies(connection, response=True, deadline_ns=bound)
        if (sum(len(raw) for raw in (*held, *received))
                + REQUEST_HEADER_BYTES + RESPONSE_HEADER_BYTES > MAX_BYTES):
            raise AuthorityTransportError("activation planner exchange exceeds its aggregate source bound")
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(bound)
    return received
