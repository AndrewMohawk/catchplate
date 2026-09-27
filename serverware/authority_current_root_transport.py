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
REQUEST_MAGICS = (RESERVE_REQUEST_MAGIC, COMPLETE_REQUEST_MAGIC)
MAX_REQUEST_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
MAX_QUERY_BYTES = 4 * 1024
MAX_OBSERVATION_BYTES = 32 * 1024
MAX_HEAD_QUERY_BYTES = 4 * 1024
MAX_HEAD_OBSERVATION_BYTES = 8 * 1024
_ACTIONS = ("reserve", "complete")
_NANOSECONDS = 1_000_000_000

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
    if type(prefix) is not bytes or prefix != HEAD_QUERY_REQUEST_MAGIC:
        raise AuthorityTransportError("current-root head query magic is invalid")
    length = int.from_bytes(io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big")
    if not 2 <= length <= MAX_HEAD_QUERY_BYTES:
        raise AuthorityTransportError("current-root head query length exceeds its source bound")
    query = io._recv_exact_until(connection, length, deadline_ns=deadline_ns)
    io._require_eof(connection, deadline_ns)
    return query


def _send_head_observation(connection, observation_bytes, *, deadline_ns):
    observation = _original(observation_bytes, MAX_HEAD_OBSERVATION_BYTES, "head observation")
    header = HEAD_OBSERVATION_RESPONSE_MAGIC + len(observation).to_bytes(8, "big")
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


def _lookup_on_configuration(config, *, query_bytes, deadline_ns):
    return _socket_exchange(config, purpose="query",
        original_bytes=query_bytes, deadline_ns=deadline_ns)


def _head_on_configuration(config, *, query_bytes, deadline_ns):
    """Return only unverified head originals, never a decision or legacy lookup."""
    return _socket_exchange(config, purpose="head",
        original_bytes=query_bytes, deadline_ns=deadline_ns)


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

    def lookup(self, *, query_bytes, deadline_ns):
        configured = CurrentRootDecisionClient._snapshot_configuration(self)
        return _lookup_on_configuration(configured, query_bytes=query_bytes, deadline_ns=deadline_ns)
