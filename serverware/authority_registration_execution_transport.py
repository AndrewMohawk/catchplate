"""Bounded original-only Unix exchange for registration execution grants.

Nine request bodies carry caller authorization, original planning request3,
original planning response4 and the complete before vector, in that order.
The response is one original signed grant, still unverified at this layer.
Neither framing nor SO_PEERCRED supplies cryptographic request permission.
All length bounds precede allocation; one absolute deadline, exact EOF and no
retry apply. No key, configuration, expectation graph or clock override is sent.
"""
from __future__ import annotations

import socket

from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_registration_execution_authorization as authorization
from serverware import authority_webauthn_evidence_plan_request as request
from serverware import authority_webauthn_evidence_plan_response as response
from serverware import authority_current_root_vector as vector


REQUEST_MAGIC = b"SWREQ001"
RESPONSE_MAGIC = b"SWRER001"
MAX_BYTES = authorization.grants.authority.MAX_RESULT_BYTES
REQUEST_LIMITS = (authorization.MAX_AUTHORIZATION_BYTES,
    request.MAX_CONTROL_BYTES, request.MAX_CONTEXT_BYTES, request.MAX_INPUT_BYTES,
    response.MAX_CONTROL_BYTES, response.plan.contract.MAX_BYTES,
    response.plan.inputs_wire.MAX_BYTES, response.retention.context_wire.MAX_BYTES,
    vector.MAX_BYTES)
RESPONSE_LIMITS = (authorization.grants.MAX_GRANT_BYTES,)
AuthorityTransportError = authority_transport.AuthorityTransportError
_deadline_ns, _check_deadline, _recv_prefix = io._deadline_ns, io._check_deadline, io._recv_prefix


def _lengths(lengths, limits):
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, limits))
            or sum(lengths) > MAX_BYTES):
        raise AuthorityTransportError("registration execution original lengths exceed their bounds")


def _originals(values, limits):
    if (type(values) is not tuple or len(values) != len(limits)
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("registration execution requires an exact original byte inventory")
    _lengths(tuple(len(raw) for raw in values), limits)
    return values


def _recv_bodies(connection, limits, *, deadline_ns):
    header = io._recv_exact_until(connection, 8 * len(limits), deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, len(header), 8))
    _lengths(lengths, limits)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return originals


def _recv_request(connection, *, deadline_ns):
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("registration execution request magic differs")
    return _recv_bodies(connection, REQUEST_LIMITS, deadline_ns=deadline_ns)


def _send(connection, magic, originals, limits, *, deadline_ns):
    held = _originals(originals, limits)
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_response(connection, grant_bytes, *, deadline_ns):
    _send(connection, RESPONSE_MAGIC, (grant_bytes,), RESPONSE_LIMITS, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns=None):
    """One peer-checked exchange; return unverified original grant bytes."""
    from serverware.authority_webauthn_registration_signer_transport import _endpoint

    path, timeout, uid, gid = _endpoint(endpoint)
    held = _originals(originals, REQUEST_LIMITS)
    bound = _deadline_ns(timeout)
    if deadline_ns is not None:
        _check_deadline(deadline_ns)
        bound = min(bound, deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("registration execution server peer differs")
        _send(connection, REQUEST_MAGIC, held, REQUEST_LIMITS, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("registration execution response magic differs")
        received = _recv_bodies(connection, RESPONSE_LIMITS, deadline_ns=bound)
    finally:
        connection.close()
    _check_deadline(bound)
    return received[0]
