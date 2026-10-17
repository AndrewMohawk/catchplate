"""Fixed verifier-to-planner original-byte exchange, without plan authority.

The three request parts are an opaque signed control, independent context and
original inputs. The four response parts are an original signed response
control, plan envelope, inputs and evaluation context. Authentication,
independent expectations and genuine replay belong to the configured callers,
never to this framing.

Each complete length inventory and its source aggregate precede any body
allocation. There is one absolute deadline and one exchange per connection,
with peer checks before sending, request half-close and exact EOF in both
directions. The server owner checks its peer before the prefix and allocates
its one work allowance only after receiving the entire request and EOF.
No signing, SQL, planner invocation, work allowance, retry or fallback exists
here. A failed exchange provides no execution or absence authority.
"""
from __future__ import annotations

import socket

from catchplate import authority_contract, authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
REGISTRATION_REQUEST_MAGIC = b"SWEP\x00\x00\x00\x01"
INSTALLATION_REQUEST_MAGIC = b"SWEM\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWES\x00\x00\x00\x01"
MAX_REQUEST_BYTES = MAX_INPUT_BYTES
MAX_RESPONSE_BYTES = MAX_INPUT_BYTES
_REQUEST_LIMITS = (authority_contract.MAX_REQUEST_BYTES, MAX_INPUT_BYTES, MAX_INPUT_BYTES)
_RESPONSE_LIMITS = (authority_contract.MAX_REQUEST_BYTES,
    MAX_INPUT_BYTES, MAX_INPUT_BYTES, MAX_INPUT_BYTES)

_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _lengths(lengths, limits):
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, limits))
            or sum(lengths) > MAX_INPUT_BYTES):
        raise AuthorityTransportError("evidence plan transfer body lengths are invalid")


def _originals(values, limits):
    if (type(values) is not tuple or len(values) != len(limits)
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("evidence plan transfer requires its fixed original byte inventory")
    _lengths(tuple(len(raw) for raw in values), limits)
    return values


def _validate_request(*, control_bytes, context_bytes, inputs_bytes):
    return _originals((control_bytes, context_bytes, inputs_bytes), _REQUEST_LIMITS)


def _validate_response(response_control_bytes, envelope_bytes, inputs_bytes, evaluation_context_bytes):
    return _originals((response_control_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes), _RESPONSE_LIMITS)


def _recv_bodies(connection, *, deadline_ns, limits):
    header_size = 8 * len(limits)
    header = io._recv_exact_until(connection, header_size, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, header_size, 8))
    # All three request or four response lengths and the aggregate precede
    # the first body allocation; no response control is trusted by framing.
    _lengths(lengths, limits)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return originals


def _recv_request(connection, *, prefix, deadline_ns):
    if (type(prefix) is not bytes
            or prefix not in (REGISTRATION_REQUEST_MAGIC, INSTALLATION_REQUEST_MAGIC)):
        raise AuthorityTransportError("evidence plan request magic is invalid")
    purpose = "registration" if prefix == REGISTRATION_REQUEST_MAGIC else "installation"
    originals = _recv_bodies(connection, deadline_ns=deadline_ns, limits=_REQUEST_LIMITS)
    return purpose, originals


def _send_response(connection, originals, *, deadline_ns):
    originals = _originals(originals, _RESPONSE_LIMITS)
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(endpoint, *, purpose, control_bytes, context_bytes, inputs_bytes, deadline_ns=None):
    """Return complete response control and raw3 from one pinned peer.

    The exact endpoint tuple is (path, timeout_seconds, expected_peer_uid,
    expected_peer_gid), supplied by the configured owner, not wire input.
    """
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("evidence plan endpoint is not an exact four-tuple")
    path, timeout_seconds, expected_peer_uid, expected_peer_gid = endpoint
    if type(purpose) is not str or purpose not in ("registration", "installation"):
        raise AuthorityTransportError("evidence plan purpose is not source fixed")
    magic = REGISTRATION_REQUEST_MAGIC if purpose == "registration" else INSTALLATION_REQUEST_MAGIC
    originals = _validate_request(control_bytes=control_bytes, context_bytes=context_bytes, inputs_bytes=inputs_bytes)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("evidence plan socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("evidence plan socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("evidence plan socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("evidence plan peer identity is invalid")
    bounded_deadline = _deadline_ns(timeout_seconds)
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
        bounded_deadline = min(bounded_deadline, deadline_ns)
    deadline_ns = bounded_deadline
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _check_deadline(deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        peer_uid, peer_gid, _peer_pid = io._call_until(connection, deadline_ns,
            lambda: authority_transport._peer_identity(connection))
        if peer_uid != expected_peer_uid or peer_gid != expected_peer_gid:
            raise AuthorityTransportError("evidence plan server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
            raise AuthorityTransportError("evidence plan response magic is invalid")
        response = _recv_bodies(connection, deadline_ns=deadline_ns, limits=_RESPONSE_LIMITS)
    except BaseException:
        # Preserve the original failure even if cleanup fails. A partial or
        # late response is never promoted to a successful plan or retried.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return response
