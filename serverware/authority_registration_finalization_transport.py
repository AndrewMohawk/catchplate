"""Fixed original-only Unix framing for a finalization execution grant.

Raw nine are authorization, custody raw seven and the complete before vector.
The one response is an unverified original signed grant, not permission from
the transport. Fixed endpoint/peer checks precede sending and response reads;
serving owners must admit their client before calling the request reader.
One required caller deadline, exact EOF and request half-close cover the whole
exchange. No JSON, signature work, retry or serving authority is added here.
"""
from __future__ import annotations

import socket

from serverware import authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_registration_finalization_authorization as authorization
from serverware import authority_current_root_plan_replay as replay
from serverware import authority_webauthn_transition_custody_transport as custody
from serverware.authority_webauthn_registration_signer_transport import _endpoint


REQUEST_MAGIC = b"SWRFGQ01"
RESPONSE_MAGIC = b"SWRFGR01"
SOCKET_PATH = "/run/serverware/registration-finalization-authorizer.sock"
MAX_BYTES = replay.MAX_ORIGINAL_BYTES
# Intersect custody's original raw7 limits with the actual raw4 replay limits.
# In particular, a large opaque custody envelope is not a larger grant input.
REQUEST_LIMITS = (authorization.MAX_AUTHORIZATION_BYTES,
    custody._PART_LIMITS[0], custody._PART_LIMITS[1],
    min(custody._PART_LIMITS[2], replay.transition.plan.contract.MAX_BYTES),
    min(custody._PART_LIMITS[3], replay.transition.plan.proof.contract.MAX_BYTES),
    min(custody._PART_LIMITS[4], replay.transition.plan.proof.wire.MAX_BYTES),
    min(custody._PART_LIMITS[5], replay.transition.plan.context.MAX_BYTES),
    custody._PART_LIMITS[6], replay.vector.MAX_BYTES)
RESPONSE_LIMITS = (authorization.grants.MAX_GRANT_BYTES,)
AuthorityTransportError = authority_transport.AuthorityTransportError
_deadline_ns, _check_deadline, _recv_prefix = io._deadline_ns, io._check_deadline, io._recv_prefix


def _lengths(lengths, limits):
    if (limits is not REQUEST_LIMITS and limits is not RESPONSE_LIMITS):
        raise AuthorityTransportError("finalization grant frame profile differs")
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, limits))
            or sum(lengths) > MAX_BYTES):
        raise AuthorityTransportError("finalization grant original lengths exceed their bounds")


def _originals(values, limits):
    if (type(values) is not tuple or len(values) != len(limits)
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("finalization grant requires an exact original byte inventory")
    _lengths(tuple(len(raw) for raw in values), limits)
    return values


def _recv_bodies(connection, limits, *, deadline_ns):
    header = io._recv_exact_until(connection, 8 * len(limits), deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, len(header), 8))
    # The complete fixed inventory and aggregate are checked before any body
    # allocation. EOF rejects both truncated frames and trailing bytes.
    _lengths(lengths, limits)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return originals


def _recv_request(connection, *, deadline_ns):
    """Read originals only after the actual serving owner admits its peer."""
    if _recv_prefix(connection, deadline_ns=deadline_ns) != REQUEST_MAGIC:
        raise AuthorityTransportError("finalization grant request magic differs")
    return _recv_bodies(connection, REQUEST_LIMITS, deadline_ns=deadline_ns)


def _send(connection, magic, originals, limits, *, deadline_ns):
    held = _originals(originals, limits)
    header = magic + b"".join(len(raw).to_bytes(8, "big") for raw in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in held:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_response(connection, grant_bytes, *, deadline_ns):
    """Send one original; the owning server must close to finish exact EOF."""
    _send(connection, RESPONSE_MAGIC, (grant_bytes,), RESPONSE_LIMITS, deadline_ns=deadline_ns)


def _socket_request(endpoint, *, originals, deadline_ns):
    """Return one unverified original grant after one fixed peer exchange."""
    path, timeout, uid, gid = _endpoint(endpoint)
    if (path != SOCKET_PATH or (uid, gid) != (0, 0)
            or type(timeout) is not int or not 1 <= timeout <= 30):
        raise AuthorityTransportError("finalization grant endpoint differs from its fixed profile")
    held = _originals(originals, REQUEST_LIMITS)
    _check_deadline(deadline_ns)
    bound = min(_deadline_ns(timeout), deadline_ns)
    _check_deadline(bound)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, bound, lambda: connection.connect(path))
        actual_uid, actual_gid, _pid = io._call_until(connection, bound,
            lambda: authority_transport._peer_identity(connection))
        if (actual_uid, actual_gid) != (uid, gid):
            raise AuthorityTransportError("finalization grant server peer differs")
        _send(connection, REQUEST_MAGIC, held, REQUEST_LIMITS, deadline_ns=bound)
        io._call_until(connection, bound, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=bound) != RESPONSE_MAGIC:
            raise AuthorityTransportError("finalization grant response magic differs")
        received = _recv_bodies(connection, RESPONSE_LIMITS, deadline_ns=bound)
    except BaseException:
        # Preserve the first failure. A partial or uncertain exchange grants
        # no retry, absence, rollback or successful execution authority.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(bound)
    return received[0]
