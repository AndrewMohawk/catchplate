"""Fixed UDS framing for decision controls, queries and signed originals.

The bodies are opaque originals, not parsed claims or accepted signatures.
Each length is admitted before body allocation; each receiver requires exact
EOF. The client checks its configured peer before sending any bytes and uses
one absolute monotonic bound for connect, framing, body, half-close and EOF.
The configured duration may shorten, never renew, the supplied deadline.

The serving owner must admit its peer before reading a prefix and bind the
received action to that peer before calling the genuine decision owner. It
owns and closes the accepted socket. A response remains unverified original
receipt/observation bytes here; callers must authenticate it and join their
exact request or query. Query framing is separate from reserve/complete and
does not widen the decision client action allowlist.
Failures, including after publication, grant neither absence nor retry rights.
No JSON, signature admission, work allowance, store or authority is added.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import errno
import os
import socket

from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io


AuthorityTransportError = authority_transport.AuthorityTransportError
RESERVE_REQUEST_MAGIC = b"SWCDRS01"
COMPLETE_REQUEST_MAGIC = b"SWCDCP01"
RESPONSE_MAGIC = b"SWCDOK01"
QUERY_REQUEST_MAGIC = b"SWCDQR01"
OBSERVATION_RESPONSE_MAGIC = b"SWCDST01"
HEAD_QUERY_REQUEST_MAGIC = b"SWCHQR01"
HEAD_OBSERVATION_RESPONSE_MAGIC = b"SWCHST01"
DELIVERY_HEAD_QUERY_REQUEST_MAGIC = b"SWDHQR01"
DELIVERY_HEAD_OBSERVATION_RESPONSE_MAGIC = b"SWDHST01"
REVOCATION_HEAD_QUERY_REQUEST_MAGIC = b"SWRHQR01"
REVOCATION_HEAD_OBSERVATION_RESPONSE_MAGIC = b"SWRHST01"
REGISTRATION_EXECUTION_HEAD_QUERY_REQUEST_MAGIC = b"SWREQR01"
REGISTRATION_EXECUTION_HEAD_OBSERVATION_RESPONSE_MAGIC = b"SWREST01"
REGISTRATION_FINALIZATION_HEAD_QUERY_REQUEST_MAGIC = b"SWRFQR01"
REGISTRATION_FINALIZATION_HEAD_OBSERVATION_RESPONSE_MAGIC = b"SWRFST01"
NATIVE_JIT_REVIEW_AUTHORIZE_HEAD_QUERY_REQUEST_MAGIC = b"SWJAQR01"
NATIVE_JIT_REVIEW_AUTHORIZE_HEAD_OBSERVATION_RESPONSE_MAGIC = b"SWJAST01"
NATIVE_JIT_REVIEW_RECEIPT_HEAD_QUERY_REQUEST_MAGIC = b"SWJJQR01"
NATIVE_JIT_REVIEW_RECEIPT_HEAD_OBSERVATION_RESPONSE_MAGIC = b"SWJJST01"
NATIVE_JIT_REVIEW_RESERVE_REQUEST_MAGIC = b"SWJNRS01"
NATIVE_JIT_REVIEW_COMPLETE_REQUEST_MAGIC = b"SWJNCP01"
NATIVE_JIT_REVIEW_REQUEST_MAGICS = (
    NATIVE_JIT_REVIEW_RESERVE_REQUEST_MAGIC, NATIVE_JIT_REVIEW_COMPLETE_REQUEST_MAGIC)
REQUEST_MAGICS = (RESERVE_REQUEST_MAGIC, COMPLETE_REQUEST_MAGIC)
MAX_REQUEST_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
MAX_QUERY_BYTES = 4 * 1024
MAX_OBSERVATION_BYTES = 32 * 1024
MAX_HEAD_QUERY_BYTES = 4 * 1024
MAX_HEAD_OBSERVATION_BYTES = 8 * 1024
_ACTIONS = ("reserve", "complete")
_NANOSECONDS = 1_000_000_000
_quarantined_delivery_head_sockets = []

_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _validate_configuration(config):
    if type(config) is not tuple or len(config) != 4:
        raise AuthorityTransportError("current-root client configuration is not an exact four-tuple")
    path, timeout, uid, gid = config
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("current-root socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("current-root socket path is not Unicode") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("current-root socket path exceeds its byte bound")
    if (type(timeout) not in (int, float) or not 0.05 <= timeout <= 30
            or not math.isfinite(timeout)):
        raise AuthorityTransportError("current-root client timeout is invalid")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in (uid, gid)):
        raise AuthorityTransportError("current-root server peer identity is invalid")
    return config


def _original(raw, maximum, label):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise AuthorityTransportError("current-root " + label + " is not bounded original bytes")
    return raw


def _action(action):
    if type(action) is not str or action not in _ACTIONS:
        raise AuthorityTransportError("current-root action is not source fixed")
    return RESERVE_REQUEST_MAGIC if action == "reserve" else COMPLETE_REQUEST_MAGIC


def _recv_request(connection, *, prefix, deadline_ns):
    """Receive only after the serving owner has admitted the actual peer."""
    if type(prefix) is not bytes or prefix not in REQUEST_MAGICS:
        raise AuthorityTransportError("current-root request magic is invalid")
    action = "reserve" if prefix == RESERVE_REQUEST_MAGIC else "complete"
    return _recv_control(connection, action=action, deadline_ns=deadline_ns)


def _native_jit_review_action(action):
    _action(action)
    return (NATIVE_JIT_REVIEW_RESERVE_REQUEST_MAGIC if action == "reserve"
        else NATIVE_JIT_REVIEW_COMPLETE_REQUEST_MAGIC)


def _recv_native_jit_review_request(connection, *, prefix, deadline_ns):
    """Native peer/purpose admission must precede this opaque body read."""
    if type(prefix) is not bytes or prefix not in NATIVE_JIT_REVIEW_REQUEST_MAGICS:
        raise AuthorityTransportError("native review current-root request magic is invalid")
    action = "reserve" if prefix == NATIVE_JIT_REVIEW_RESERVE_REQUEST_MAGIC else "complete"
    return _recv_control(connection, action=action, deadline_ns=deadline_ns)


def _recv_control(connection, *, action, deadline_ns):
    length = int.from_bytes(io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big")
    if not 2 <= length <= MAX_REQUEST_BYTES:
        raise AuthorityTransportError("current-root request length exceeds its source bound")
    request = io._recv_exact_until(connection, length, deadline_ns=deadline_ns)
    io._require_eof(connection, deadline_ns)
    return action, request


def _send_response(connection, receipt_bytes, *, deadline_ns):
    """Send opaque receipt originals; the serving owner closes its connection."""
    receipt = _original(receipt_bytes, MAX_RECEIPT_BYTES, "receipt")
    header = RESPONSE_MAGIC + len(receipt).to_bytes(8, "big")
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    io._send_exact_until(connection, receipt, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _recv_lookup(connection, *, prefix, deadline_ns):
    """Receive only after the serving owner has admitted the completion peer."""
    if type(prefix) is not bytes or prefix != QUERY_REQUEST_MAGIC:
        raise AuthorityTransportError("current-root query magic is invalid")
    length = int.from_bytes(io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big")
    if not 2 <= length <= MAX_QUERY_BYTES:
        raise AuthorityTransportError("current-root query length exceeds its source bound")
    query = io._recv_exact_until(connection, length, deadline_ns=deadline_ns)
    io._require_eof(connection, deadline_ns)
    return query


def _send_observation(connection, observation_bytes, *, deadline_ns):
    observation = _original(observation_bytes, MAX_OBSERVATION_BYTES, "observation")
    header = OBSERVATION_RESPONSE_MAGIC + len(observation).to_bytes(8, "big")
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    io._send_exact_until(connection, observation, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _recv_head_query(connection, *, prefix, deadline_ns):
    """Receive only after the fixed activation-planner peer was admitted."""
    return _recv_head_body(connection, prefix=prefix, expected_magic=HEAD_QUERY_REQUEST_MAGIC,
        deadline_ns=deadline_ns)


def _recv_delivery_head_query(connection, *, prefix, deadline_ns):
    """Receive only after the separately admitted consume-planner peer."""
    return _recv_head_body(connection, prefix=prefix, expected_magic=DELIVERY_HEAD_QUERY_REQUEST_MAGIC,
        deadline_ns=deadline_ns)


def _recv_revocation_head_query(connection, *, prefix, deadline_ns):
    return _recv_head_body(connection, prefix=prefix, expected_magic=REVOCATION_HEAD_QUERY_REQUEST_MAGIC,
        deadline_ns=deadline_ns)


def _registration_head_magics(purpose):
    if type(purpose) is str and purpose == "execution":
        return (REGISTRATION_EXECUTION_HEAD_QUERY_REQUEST_MAGIC,
            REGISTRATION_EXECUTION_HEAD_OBSERVATION_RESPONSE_MAGIC)
    if type(purpose) is str and purpose == "finalization":
        return (REGISTRATION_FINALIZATION_HEAD_QUERY_REQUEST_MAGIC,
            REGISTRATION_FINALIZATION_HEAD_OBSERVATION_RESPONSE_MAGIC)
    raise AuthorityTransportError("registration head transport purpose is not source fixed")


def _recv_registration_head_query(connection, *, prefix, deadline_ns, purpose):
    return _recv_head_body(connection, prefix=prefix,
        expected_magic=_registration_head_magics(purpose)[0], deadline_ns=deadline_ns)


def _native_jit_review_head_magics(operation):
    if type(operation) is str and operation == "jit.review-open.authorize":
        return (NATIVE_JIT_REVIEW_AUTHORIZE_HEAD_QUERY_REQUEST_MAGIC,
            NATIVE_JIT_REVIEW_AUTHORIZE_HEAD_OBSERVATION_RESPONSE_MAGIC)
    if type(operation) is str and operation == "jit.review-open.receipt.issue":
        return (NATIVE_JIT_REVIEW_RECEIPT_HEAD_QUERY_REQUEST_MAGIC,
            NATIVE_JIT_REVIEW_RECEIPT_HEAD_OBSERVATION_RESPONSE_MAGIC)
    raise AuthorityTransportError("native review head purpose is not source fixed")


def _recv_native_jit_review_head_query(connection, *, prefix, deadline_ns, operation):
    return _recv_head_body(connection, prefix=prefix,
        expected_magic=_native_jit_review_head_magics(operation)[0], deadline_ns=deadline_ns)


def _recv_head_body(connection, *, prefix, expected_magic, deadline_ns):
    if type(prefix) is not bytes or prefix != expected_magic:
        raise AuthorityTransportError("current-root head query magic is invalid")
    length = int.from_bytes(io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big")
    if not 2 <= length <= MAX_HEAD_QUERY_BYTES:
        raise AuthorityTransportError("current-root head query length exceeds its source bound")
    query = io._recv_exact_until(connection, length, deadline_ns=deadline_ns)
    io._require_eof(connection, deadline_ns)
    return query


def _send_head_observation(connection, observation_bytes, *, deadline_ns):
    return _send_head_body(connection, observation_bytes,
        response_magic=HEAD_OBSERVATION_RESPONSE_MAGIC, deadline_ns=deadline_ns)


def _send_delivery_head_observation(connection, observation_bytes, *, deadline_ns):
    return _send_head_body(connection, observation_bytes,
        response_magic=DELIVERY_HEAD_OBSERVATION_RESPONSE_MAGIC, deadline_ns=deadline_ns)


def _send_revocation_head_observation(connection, observation_bytes, *, deadline_ns):
    return _send_head_body(connection, observation_bytes,
        response_magic=REVOCATION_HEAD_OBSERVATION_RESPONSE_MAGIC, deadline_ns=deadline_ns)


def _send_registration_head_observation(connection, observation_bytes, *, deadline_ns, purpose):
    return _send_head_body(connection, observation_bytes,
        response_magic=_registration_head_magics(purpose)[1], deadline_ns=deadline_ns)


def _send_native_jit_review_head_observation(connection, observation_bytes, *, deadline_ns, operation):
    return _send_head_body(connection, observation_bytes,
        response_magic=_native_jit_review_head_magics(operation)[1], deadline_ns=deadline_ns)


def _send_head_body(connection, observation_bytes, *, response_magic, deadline_ns):
    observation = _original(observation_bytes, MAX_HEAD_OBSERVATION_BYTES, "head observation")
    header = response_magic + len(observation).to_bytes(8, "big")
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    io._send_exact_until(connection, observation, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_exchange(config, *, purpose, original_bytes, deadline_ns):
    configured = _validate_configuration(config)
    if type(purpose) is str and purpose == "query":
        magic, maximum = QUERY_REQUEST_MAGIC, MAX_QUERY_BYTES
        response_magic, response_maximum = OBSERVATION_RESPONSE_MAGIC, MAX_OBSERVATION_BYTES
    elif type(purpose) is str and purpose == "head":
        magic, maximum = HEAD_QUERY_REQUEST_MAGIC, MAX_HEAD_QUERY_BYTES
        response_magic, response_maximum = HEAD_OBSERVATION_RESPONSE_MAGIC, MAX_HEAD_OBSERVATION_BYTES
    elif type(purpose) is str and purpose == "delivery-head":
        magic, maximum = DELIVERY_HEAD_QUERY_REQUEST_MAGIC, MAX_HEAD_QUERY_BYTES
        response_magic, response_maximum = DELIVERY_HEAD_OBSERVATION_RESPONSE_MAGIC, MAX_HEAD_OBSERVATION_BYTES
    elif type(purpose) is str and purpose == "revocation-head":
        magic, maximum = REVOCATION_HEAD_QUERY_REQUEST_MAGIC, MAX_HEAD_QUERY_BYTES
        response_magic, response_maximum = REVOCATION_HEAD_OBSERVATION_RESPONSE_MAGIC, MAX_HEAD_OBSERVATION_BYTES
    elif type(purpose) is str and purpose in ("native-review-reserve", "native-review-complete"):
        magic = _native_jit_review_action("reserve" if purpose == "native-review-reserve" else "complete")
        maximum, response_magic, response_maximum = MAX_REQUEST_BYTES, RESPONSE_MAGIC, MAX_RECEIPT_BYTES
    else:
        magic, maximum = _action(purpose), MAX_REQUEST_BYTES
        response_magic, response_maximum = RESPONSE_MAGIC, MAX_RECEIPT_BYTES
    request = _original(original_bytes, maximum, "request")
    original_deadline = deadline_ns
    # _check_deadline samples the real monotonic clock once. This optional
    # configured duration only narrows the caller's already fixed deadline;
    # no later IO step obtains a new deadline or replacement window.
    remaining = _check_deadline(original_deadline)
    sampled_now = original_deadline - remaining
    bound = min(original_deadline, sampled_now + int(configured[1] * _NANOSECONDS))
    header = magic + len(request).to_bytes(8, "big")
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _check_deadline(bound)
        io._call_until(connection, bound, lambda: connection.connect(configured[0]))
        peer_uid, peer_gid, _peer_pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if peer_uid != configured[2] or peer_gid != configured[3]:
            raise AuthorityTransportError("current-root server peer differs from configured identity")
        io._send_exact_until(connection, header, deadline_ns=bound)
        io._send_exact_until(connection, request, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != response_magic:
            raise AuthorityTransportError("current-root response magic is invalid")
        length = int.from_bytes(io._recv_exact_until(connection, 8, deadline_ns=bound), "big")
        if not 2 <= length <= response_maximum:
            raise AuthorityTransportError("current-root response length exceeds its source bound")
        response = io._recv_exact_until(connection, length, deadline_ns=bound)
        io._require_eof(connection, bound)
    except BaseException:
        # A failed or uncertain exchange grants no retry authority. Keep the
        # original failure even when closing the actual socket also fails.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(bound)
    return response


def _exchange_on_configuration(config, *, action, request_bytes, deadline_ns):
    # Preserve the original exact reserve/complete surface. Query has its own
    # fixed entrypoint and cannot be smuggled through a decision action.
    _action(action)
    return _socket_exchange(config, purpose=action,
        original_bytes=request_bytes, deadline_ns=deadline_ns)


def _exchange_native_jit_review_on_configuration(config, *, action, request_bytes, deadline_ns):
    """Fixed native receipt decision route; no generic action is widened."""
    _native_jit_review_action(action)
    return _socket_exchange(config, purpose="native-review-" + action,
        original_bytes=request_bytes, deadline_ns=deadline_ns)


def _lookup_on_configuration(config, *, query_bytes, deadline_ns):
    return _socket_exchange(config, purpose="query",
        original_bytes=query_bytes, deadline_ns=deadline_ns)


def _head_on_configuration(config, *, query_bytes, deadline_ns):
    """Return only unverified head originals, never a decision or legacy lookup."""
    return _socket_exchange(config, purpose="head",
        original_bytes=query_bytes, deadline_ns=deadline_ns)


def _delivery_head_on_configuration(config, *, query_bytes, deadline_ns):
    """Unverified consume-head originals, never a decision or legacy lookup."""
    return _socket_exchange(config, purpose="delivery-head",
        original_bytes=query_bytes, deadline_ns=deadline_ns)


def _delivery_head_on_work(config, *, query_bytes, deadline_ns, work, current):
    return _guarded_head_on_work(config, query_bytes=query_bytes, deadline_ns=deadline_ns,
        work=work, current=current, revocation=False)


def _revocation_head_on_work(config, *, query_bytes, deadline_ns, work, current):
    return _guarded_head_on_work(config, query_bytes=query_bytes, deadline_ns=deadline_ns,
        work=work, current=current, revocation=True)


def _registration_head_on_work(config, *, query_bytes, deadline_ns, work, current, purpose):
    _registration_head_magics(purpose)
    return _guarded_head_on_work(config, query_bytes=query_bytes, deadline_ns=deadline_ns,
        work=work, current=current, revocation=False, registration=purpose)


def _native_jit_review_head_on_work(config, *, query_bytes, deadline_ns, work, current, operation):
    _native_jit_review_head_magics(operation)
    return _guarded_head_on_work(config, query_bytes=query_bytes, deadline_ns=deadline_ns,
        work=work, current=current, revocation=False, native_review=operation)


def _guarded_head_on_work(config, *, query_bytes, deadline_ns, work, current, revocation,
        registration=None, native_review=None):
    """One source-fixed head query retaining the actual original guard.

    This direct metered path is not invoked inside a stable-metrics callback.
    It owns only its one nonblocking socket and returns unverified originals.
    Existing decision, lookup and numeric-window-only callers are unchanged.
    """
    from serverware import oidc_session_activation_release_transport as chunks

    if type(revocation) is not bool:
        raise AuthorityTransportError("current-root head transport requires a source-fixed purpose")
    if native_review is not None:
        if registration is not None or revocation:
            raise AuthorityTransportError("native review head cannot alias another purpose")
        request_magic, response_magic = _native_jit_review_head_magics(native_review)
    elif registration is not None:
        if revocation:
            raise AuthorityTransportError("registration head cannot alias revocation")
        request_magic, response_magic = _registration_head_magics(registration)
    else:
        request_magic, response_magic = ((REVOCATION_HEAD_QUERY_REQUEST_MAGIC,
            REVOCATION_HEAD_OBSERVATION_RESPONSE_MAGIC) if revocation else
            (DELIVERY_HEAD_QUERY_REQUEST_MAGIC, DELIVERY_HEAD_OBSERVATION_RESPONSE_MAGIC))
    configured = _validate_configuration(config)
    request = _original(query_bytes, MAX_HEAD_QUERY_BYTES, "delivery head query")
    chunks._guard(work, current, deadline_ns)
    bound = min(deadline_ns, chunks._native(lambda: io._deadline_ns(configured[1]),
        work=work, current=current, deadline_ns=deadline_ns))
    connection = None
    descriptor = identity = None
    peer_identity = None
    close_attempted = False

    def fd_identity():
        value = os.fstat(descriptor)
        return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid

    def exact_socket():
        if (connection.fileno() != descriptor or descriptor is None or identity is None
                or fd_identity() != identity or connection.family != socket.AF_UNIX
                or connection.type != socket.SOCK_STREAM or connection.gettimeout() != 0.0
                or connection.get_inheritable()
                or peer_identity is not None and authority_transport._peer_identity(connection) != peer_identity):
            raise AuthorityTransportError("delivery head socket ownership changed")

    def guarded_current():
        observed = current()
        if connection is not None and not close_attempted:
            work.charge(input_bytes=64)
            chunks.production._callback(work, exact_socket)
        return observed

    kwargs = {"deadline_ns": bound, "work": work, "current": guarded_current}

    def opening():
        nonlocal connection, descriptor, identity
        # Retain the actual object before a post-native guard can fail.
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        descriptor = connection.fileno()
        identity = fd_identity()
        connection.setblocking(False)
        connection.set_inheritable(False)

    try:
        work.charge(input_bytes=4096 + 32 + len(request) + MAX_HEAD_OBSERVATION_BYTES)
        chunks._native(opening, **kwargs)
        chunks._connection(connection, **kwargs)
        connected = chunks._native(lambda: connection.connect_ex(configured[0]), **kwargs)
        if type(connected) is not int or connected not in (0, errno.EINPROGRESS, errno.EALREADY):
            raise AuthorityTransportError("delivery head connection was not established")
        if connected != 0:
            chunks._ready(connection, writing=True, **kwargs)
            error = chunks._native(lambda: connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), **kwargs)
            if type(error) is not int or error != 0:
                raise AuthorityTransportError("delivery head connection failed")
        chunks._peer(connection, configured[2:], **kwargs)
        peer_identity = chunks._native(lambda: authority_transport._peer_identity(connection), **kwargs)
        if peer_identity[:2] != configured[2:]:
            raise AuthorityTransportError("delivery head peer changed after connection")
        header = request_magic + len(request).to_bytes(8, "big")
        chunks._send_precharged(connection, header, **kwargs)
        chunks._send_precharged(connection, request, **kwargs)
        chunks._native(lambda: connection.shutdown(socket.SHUT_WR), **kwargs)
        if chunks._recv_exact(connection, 8, **kwargs) != response_magic:
            raise AuthorityTransportError("delivery head response magic differs")
        raw_length = chunks._recv_exact(connection, 8, **kwargs)
        work.charge(input_bytes=8)
        length = int.from_bytes(raw_length, "big")
        if not 2 <= length <= MAX_HEAD_OBSERVATION_BYTES:
            raise AuthorityTransportError("delivery head response length exceeds its fixed bound")
        response = chunks._recv_exact(connection, length, **kwargs)
        chunks._eof(connection, **kwargs)
        chunks._native(exact_socket, **kwargs)
        work.charge(input_bytes=1)
        chunks._guard(work, current, bound)
        close_attempted = True
        chunks.production._callback(work, connection.close)
        if connection.fileno() != -1:
            raise AuthorityTransportError("delivery head socket closure is indeterminate")
        chunks._guard(work, current, bound)
        return response
    finally:
        if connection is not None and connection.fileno() != -1:
            try:
                if close_attempted:
                    raise AuthorityTransportError("delivery head socket cleanup cannot retry")
                close_attempted = True
                exact_socket()
                connection.close()
                if connection.fileno() != -1:
                    raise AuthorityTransportError("delivery head socket cleanup is indeterminate")
            except BaseException:
                _quarantined_delivery_head_sockets.append(connection)
                raise AuthorityTransportError("delivery head socket cleanup is not established") from None


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class CurrentRootDecisionClient:
    """Immutable admitted endpoint pins; construction performs no IO."""

    _configuration: tuple

    def __init__(self, *, path, timeout_seconds, expected_peer_uid, expected_peer_gid):
        configured = _validate_configuration((path, timeout_seconds, expected_peer_uid, expected_peer_gid))
        object.__setattr__(self, "_configuration", configured)

    def _snapshot_configuration(self):
        if type(self) is not CurrentRootDecisionClient:
            raise AuthorityTransportError("current-root client requires its exact configured owner")
        return _validate_configuration(self._configuration)

    def exchange(self, *, action, request_bytes, deadline_ns):
        configured = CurrentRootDecisionClient._snapshot_configuration(self)
        return _exchange_on_configuration(configured,
            action=action, request_bytes=request_bytes, deadline_ns=deadline_ns)

    def exchange_native_jit_review(self, *, action, request_bytes, deadline_ns):
        configured = CurrentRootDecisionClient._snapshot_configuration(self)
        return _exchange_native_jit_review_on_configuration(configured,
            action=action, request_bytes=request_bytes, deadline_ns=deadline_ns)

    def lookup(self, *, query_bytes, deadline_ns):
        configured = CurrentRootDecisionClient._snapshot_configuration(self)
        return _lookup_on_configuration(configured, query_bytes=query_bytes, deadline_ns=deadline_ns)
