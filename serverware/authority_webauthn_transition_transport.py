"""Fixed original-byte transport for three successor planning operations.

Requests carry control/context/inputs; responses carry signed response control
and the original plan envelope/proof/inputs/context. Framing authenticates none
of those bytes. Configured callers authenticate controls and genuinely replay
the returned originals against independently admitted expectations.

All lengths and their 64 MiB aggregate are checked before body allocation.
Each connection has one absolute deadline, pinned peer identity before sending,
request half-close and exact EOF in both directions. The server checks its peer
before the prefix and receives full EOF before allocating invocation work.
There is no signing, SQL, retry, execution or replacement work allowance here.
"""
from __future__ import annotations

import socket

from serverware import authority_contract, authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
REGISTRATION_REQUEST_MAGIC = b"SWTR\x00\x00\x00\x01"
STAGE_REQUEST_MAGIC = b"SWTT\x00\x00\x00\x01"
COMPLETION_REQUEST_MAGIC = b"SWTC\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWTP\x00\x00\x00\x01"
REQUEST_MAGICS = (REGISTRATION_REQUEST_MAGIC, STAGE_REQUEST_MAGIC, COMPLETION_REQUEST_MAGIC)
_OPERATIONS = ("webauthn.registration.finalize", "webauthn.trust.stage", "webauthn.trust.complete")
MAX_REQUEST_BYTES = MAX_INPUT_BYTES
MAX_RESPONSE_BYTES = MAX_INPUT_BYTES
_REQUEST_LIMITS = (authority_contract.MAX_REQUEST_BYTES, MAX_INPUT_BYTES, MAX_INPUT_BYTES)
_RESPONSE_LIMITS = (authority_contract.MAX_REQUEST_BYTES,
    MAX_INPUT_BYTES, MAX_INPUT_BYTES, MAX_INPUT_BYTES, MAX_INPUT_BYTES)

_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _lengths(lengths, limits):
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, limits))
            or sum(lengths) > MAX_INPUT_BYTES):
        raise AuthorityTransportError("transition planning transfer lengths are invalid")


def _originals(values, limits):
    if (type(values) is not tuple or len(values) != len(limits)
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("transition planning transfer requires its exact original byte inventory")
    _lengths(tuple(len(raw) for raw in values), limits)
    return values


def _validate_request(control_bytes, context_bytes, inputs_bytes):
    return _originals((control_bytes, context_bytes, inputs_bytes), _REQUEST_LIMITS)


def _validate_response(response_control_bytes, envelope_bytes, proof_bytes, inputs_bytes, context_bytes):
    return _originals((response_control_bytes, envelope_bytes, proof_bytes,
        inputs_bytes, context_bytes), _RESPONSE_LIMITS)


def _recv_bodies(connection, *, deadline_ns, limits):
    header_size = 8 * len(limits)
    header = io._recv_exact_until(connection, header_size, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, header_size, 8))
    _lengths(lengths, limits)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return originals


def _recv_request(connection, *, deadline_ns, prefix):
    if type(prefix) is not bytes or prefix not in REQUEST_MAGICS:
        raise AuthorityTransportError("transition planning request magic is invalid")
    operation = _OPERATIONS[REQUEST_MAGICS.index(prefix)]
    return operation, _recv_bodies(connection, deadline_ns=deadline_ns, limits=_REQUEST_LIMITS)


def _send_response(connection, response, *, deadline_ns):
    response = _originals(response, _RESPONSE_LIMITS)
    header = RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in response)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in response:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(endpoint, *, operation, control_bytes, context_bytes, inputs_bytes):
    """Exchange originals once with the exact configured (path,timeout,uid,gid)."""
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise AuthorityTransportError("transition planning endpoint is not an exact four-tuple")
    path, timeout_seconds, expected_peer_uid, expected_peer_gid = endpoint
    if type(operation) is not str or operation not in _OPERATIONS:
        raise AuthorityTransportError("transition planning operation is not source fixed")
    magic = REQUEST_MAGICS[_OPERATIONS.index(operation)]
    originals = _validate_request(control_bytes, context_bytes, inputs_bytes)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("transition planning socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("transition planning socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("transition planning socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("transition planning peer identity is invalid")
    deadline_ns = _deadline_ns(timeout_seconds)
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _check_deadline(deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        peer_uid, peer_gid, _peer_pid = io._call_until(connection, deadline_ns,
            lambda: authority_transport._peer_identity(connection))
        if peer_uid != expected_peer_uid or peer_gid != expected_peer_gid:
            raise AuthorityTransportError("transition planning server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
            raise AuthorityTransportError("transition planning response magic is invalid")
        response = _recv_bodies(connection, deadline_ns=deadline_ns, limits=_RESPONSE_LIMITS)
    except BaseException:
        # Preserve the first native failure even if closing also fails. No
        # partial or late response is returned or automatically retried.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return response
