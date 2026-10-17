"""Fixed original-plan read framing, without historical or signature authority.

The verifier request and planner-forwarded read each carry the same opaque
signed control and independent historical document. Responses contain only the
three original plan bodies and unsigned record/time metadata. The application
must authenticate the request before I/O and genuinely verify returned
originals against independently admitted history and the expected identity.

All lengths and metadata are admitted before body allocation. Each connection
uses one existing absolute I/O deadline, peer validation before outgoing data,
request half-close and exact EOF. The server owner checks its peer before the
prefix and closes after sending. No missing-record success, retry, fallback,
write, key enrollment, JSON parsing or replacement work allowance exists here.
"""
from __future__ import annotations

import socket

from catchplate import authority_contract, authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
REGISTRATION_REQUEST_MAGIC = b"SWEQ\x00\x00\x00\x01"
INSTALLATION_REQUEST_MAGIC = b"SWEU\x00\x00\x00\x01"
REGISTRATION_FORWARD_MAGIC = b"SWED\x00\x00\x00\x01"
INSTALLATION_FORWARD_MAGIC = b"SWEH\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWEB\x00\x00\x00\x01"
MAX_REQUEST_BYTES = MAX_INPUT_BYTES
MAX_RESPONSE_BYTES = MAX_INPUT_BYTES
MAX_CONTROL_BYTES = authority_contract.MAX_REQUEST_BYTES
_REQUEST_LIMITS = (MAX_CONTROL_BYTES, MAX_INPUT_BYTES)
_REQUEST_MAGICS = (REGISTRATION_REQUEST_MAGIC, INSTALLATION_REQUEST_MAGIC)
_FORWARD_MAGICS = (REGISTRATION_FORWARD_MAGIC, INSTALLATION_FORWARD_MAGIC)
_DIGEST_BYTES = 71
_METADATA_BYTES = _DIGEST_BYTES + 8
_MAX_I64 = (1 << 63) - 1

_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _request_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, _REQUEST_LIMITS))
            or sum(lengths) > MAX_REQUEST_BYTES):
        raise AuthorityTransportError("evidence custody read request lengths are invalid")


def _response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 3
            or any(type(size) is not int or not 2 <= size <= MAX_INPUT_BYTES for size in lengths)
            or sum(lengths) + _METADATA_BYTES > MAX_RESPONSE_BYTES):
        raise AuthorityTransportError("evidence custody read response lengths are invalid")


def _metadata(retained_record_digest, retained_at_epoch_ns):
    if (type(retained_record_digest) is not str or len(retained_record_digest) != _DIGEST_BYTES
            or not retained_record_digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in retained_record_digest[7:])
            or type(retained_at_epoch_ns) is not int or not 1 <= retained_at_epoch_ns <= _MAX_I64):
        raise AuthorityTransportError("evidence custody read metadata is not a canonical digest and positive I64 time")
    return retained_record_digest, retained_at_epoch_ns


def _validate_request(*, control_bytes, historical_expectations_bytes):
    originals = control_bytes, historical_expectations_bytes
    if any(type(raw) is not bytes for raw in originals):
        raise AuthorityTransportError("evidence custody read requires exact original request bytes")
    _request_lengths(tuple(len(raw) for raw in originals))
    return originals


def _validate_response(response):
    if (type(response) is not tuple or len(response) != 5
            or any(type(raw) is not bytes for raw in response[:3])):
        raise AuthorityTransportError("evidence custody read response is not an exact five-tuple")
    _response_lengths(tuple(len(raw) for raw in response[:3]))
    _metadata(response[3], response[4])
    return response


def _recv(connection, *, deadline_ns, prefix, magics):
    if type(prefix) is not bytes or prefix not in magics:
        raise AuthorityTransportError("evidence custody read request magic is invalid")
    purpose = "registration" if prefix == magics[0] else "installation"
    header = io._recv_exact_until(connection, 16, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in (0, 8))
    # Both local lengths and their aggregate precede either body allocation.
    _request_lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return purpose, originals


def _recv_request(connection, *, deadline_ns, prefix):
    return _recv(connection, deadline_ns=deadline_ns, prefix=prefix, magics=_REQUEST_MAGICS)


def _recv_forward_request(connection, *, deadline_ns, prefix):
    return _recv(connection, deadline_ns=deadline_ns, prefix=prefix, magics=_FORWARD_MAGICS)


def _send_response(connection, response, *, deadline_ns):
    envelope_bytes, inputs_bytes, evaluation_context_bytes, digest, retained_at = _validate_response(response)
    originals = envelope_bytes, inputs_bytes, evaluation_context_bytes
    header = (RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
        + digest.encode("ascii") + retained_at.to_bytes(8, "big"))
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _recv_response(connection, *, deadline_ns):
    if _recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
        raise AuthorityTransportError("evidence custody read response magic is invalid")
    # Only this fixed 103-byte header is allocated before validating every
    # body length and all metadata; response bodies have no streaming fallback.
    header = io._recv_exact_until(connection, 24 + _METADATA_BYTES, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in (0, 8, 16))
    _response_lengths(lengths)
    try:
        digest = header[24:24 + _DIGEST_BYTES].decode("ascii")
    except UnicodeError as exc:
        raise AuthorityTransportError("evidence custody read record digest is not ASCII") from exc
    digest, retained_at = _metadata(digest, int.from_bytes(header[24 + _DIGEST_BYTES:], "big"))
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _validate_response((*originals, digest, retained_at))


def _socket_exchange(path, *, magics, purpose, control_bytes, historical_expectations_bytes,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    if type(purpose) is not str or purpose not in ("registration", "installation"):
        raise AuthorityTransportError("evidence custody read purpose is not source fixed")
    magic = magics[0] if purpose == "registration" else magics[1]
    originals = _validate_request(control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("evidence custody read socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("evidence custody read socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("evidence custody read socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("evidence custody read peer identity is invalid")
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
            raise AuthorityTransportError("evidence custody read server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        response = _recv_response(connection, deadline_ns=deadline_ns)
    except BaseException:
        # Preserve the first native/transport failure, even if cleanup fails.
        # An incomplete read yields no absence, rollback or retry authority.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return response


def _socket_request(path, *, purpose, control_bytes, historical_expectations_bytes,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    return _socket_exchange(path, magics=_REQUEST_MAGICS, purpose=purpose,
        control_bytes=control_bytes, historical_expectations_bytes=historical_expectations_bytes,
        timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid, expected_peer_gid=expected_peer_gid)


def _socket_forward_request(path, *, purpose, control_bytes, historical_expectations_bytes,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    return _socket_exchange(path, magics=_FORWARD_MAGICS, purpose=purpose,
        control_bytes=control_bytes, historical_expectations_bytes=historical_expectations_bytes,
        timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid, expected_peer_gid=expected_peer_gid)
