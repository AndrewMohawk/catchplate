"""Opaque private reconciliation framing, separate from custody forwarding.

Requests carry current configuration scope and unchanged evidence raw6 or
transition raw7. Responses carry retained raw3/raw4 plus unsigned record/time
metadata. The owning application must authenticate the original controls,
resolve independently admitted history, perform read-only retrieval and replay
the returned originals. This transport supplies none of those authorities and
never signals successful absence, grants a retry, or renews any clock window.

All local lengths and aggregates precede body allocation. One supplied absolute
monotonic deadline covers connection, pinned peer check, request half-close,
response and exact EOF. Accepted sockets are borrowed: the serving owner must
admit the peer before reading a prefix and close the connection on every path.
"""
from __future__ import annotations

import socket

from serverware import authority_transport
from serverware import authority_custody_caller_transport as caller
from serverware import authority_revocation_writer_transport as io
from serverware import authority_webauthn_evidence_custody_read_transport as evidence_read
from serverware import authority_webauthn_transition_custody_read_transport as transition_read


AuthorityTransportError = authority_transport.AuthorityTransportError
EVIDENCE_REGISTRATION_MAGIC = b"SWCRER01"
EVIDENCE_INSTALLATION_MAGIC = b"SWCREI01"
TRANSITION_REGISTRATION_MAGIC = b"SWCRTR01"
TRANSITION_STAGE_MAGIC = b"SWCRTS01"
TRANSITION_COMPLETION_MAGIC = b"SWCRTC01"
RESPONSE_MAGIC = b"SWCROK01"
REQUEST_MAGICS = (EVIDENCE_REGISTRATION_MAGIC, EVIDENCE_INSTALLATION_MAGIC,
    TRANSITION_REGISTRATION_MAGIC, TRANSITION_STAGE_MAGIC, TRANSITION_COMPLETION_MAGIC)
MAX_REQUEST_BYTES = caller.MAX_REQUEST_BYTES
MAX_CONTROL_BYTES = caller.MAX_CONTROL_BYTES
MAX_RESPONSE_BYTES = evidence_read.MAX_RESPONSE_BYTES
_DIGEST_BYTES = 71
_METADATA_BYTES = _DIGEST_BYTES + 8
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix
_validate_originals = caller._validate_originals


def _response_profile(family, selector):
    caller._profile(family, selector)
    return (evidence_read, 3) if family == "evidence" else (transition_read, 4)


def _validate_response(family, selector, response):
    transport, _ = _response_profile(family, selector)
    return transport._validate_response(response)


def _recv_request(connection, *, deadline_ns, prefix):
    if type(prefix) is not bytes or prefix not in REQUEST_MAGICS:
        raise AuthorityTransportError("custody reconciliation request magic is invalid")
    family, selector, count = caller._PROFILES[REQUEST_MAGICS.index(prefix)]
    encoded_digest = io._recv_exact_until(connection, _DIGEST_BYTES, deadline_ns=deadline_ns)
    try:
        configuration_digest = caller._configuration_digest(encoded_digest.decode("ascii"))
    except UnicodeError as exc:
        raise AuthorityTransportError("reconciliation configuration digest is not ASCII") from exc
    header_size = count * 8
    header = io._recv_exact_until(connection, header_size, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, header_size, 8))
    if family == "evidence":
        caller.evidence._validate_lengths(lengths)
    else:
        caller.transition._validate_lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return configuration_digest, family, selector, _validate_originals(family, selector, originals)


def _send_response(connection, *, family, selector, response, deadline_ns):
    response = _validate_response(family, selector, response)
    originals, digest, retained_at = response[:-2], response[-2], response[-1]
    header = (RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
        + digest.encode("ascii") + retained_at.to_bytes(8, "big"))
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _recv_response(connection, *, family, selector, deadline_ns):
    transport, count = _response_profile(family, selector)
    if _recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
        raise AuthorityTransportError("custody reconciliation response magic is invalid")
    vector_size = count * 8
    header = io._recv_exact_until(connection, vector_size + _METADATA_BYTES, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, vector_size, 8))
    # The real family validator includes all originals plus 79 metadata bytes
    # in the 64 MiB ceiling. Only this fixed header exists before admission.
    transport._response_lengths(lengths)
    try:
        digest = header[vector_size:vector_size + _DIGEST_BYTES].decode("ascii")
    except UnicodeError as exc:
        raise AuthorityTransportError("reconciliation response digest is not ASCII") from exc
    digest, retained_at = transport._metadata(digest,
        int.from_bytes(header[vector_size + _DIGEST_BYTES:], "big"))
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return transport._validate_response((*originals, digest, retained_at))


def _socket_request(path, *, configuration_digest, family, selector, originals,
        deadline_ns, expected_peer_uid, expected_peer_gid):
    originals = _validate_originals(family, selector, originals)
    configuration_digest = caller._configuration_digest(configuration_digest)
    index, _ = caller._profile(family, selector)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("custody reconciliation socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("custody reconciliation socket path is not lossless UTF-8") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("custody reconciliation socket path exceeds its byte bound")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("custody reconciliation peer identity is invalid")
    header = (REQUEST_MAGICS[index] + configuration_digest.encode("ascii")
        + b"".join(len(raw).to_bytes(8, "big") for raw in originals))
    _check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _check_deadline(deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        peer_uid, peer_gid, _peer_pid = io._call_until(connection, deadline_ns,
            lambda: authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (expected_peer_uid, expected_peer_gid):
            raise AuthorityTransportError("custody reconciliation peer differs from its admitted identity")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        response = _recv_response(connection, family=family, selector=selector, deadline_ns=deadline_ns)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return response
