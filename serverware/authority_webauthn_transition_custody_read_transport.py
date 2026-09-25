"""Fixed successor-custody read framing, without authentication authority.

Verifier requests and planner-forwarded reads carry the same original control
and historical document. Responses carry envelope/proof/inputs/context and
unsigned record/time metadata. The application must authenticate the request
before I/O and genuinely replay returned originals against independently
admitted history and the requested content identity. Framing does neither.

All lengths and metadata are admitted before body allocation. One existing
absolute deadline covers each exchange; configured peer checks precede sends,
requests are half-closed, and both receivers require exact EOF. The serving
owner admits its peer before reading the prefix and closes after sending.
There is no write, missing-record success, retry, fallback, JSON parsing,
clock-policy override, key enrollment or replacement work allowance here.
"""
from __future__ import annotations

import socket

from serverware import authority_contract, authority_transport
from serverware import authority_revocation_writer_transport as io
from serverware.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
REGISTRATION_REQUEST_MAGIC = b"SWVQ\x00\x00\x00\x01"
STAGE_REQUEST_MAGIC = b"SWVS\x00\x00\x00\x01"
COMPLETION_REQUEST_MAGIC = b"SWVC\x00\x00\x00\x01"
REGISTRATION_FORWARD_MAGIC = b"SWVD\x00\x00\x00\x01"
STAGE_FORWARD_MAGIC = b"SWVH\x00\x00\x00\x01"
COMPLETION_FORWARD_MAGIC = b"SWVF\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWVB\x00\x00\x00\x01"
OPERATIONS = ("webauthn.registration.finalize", "webauthn.trust.stage", "webauthn.trust.complete")
REQUEST_MAGICS = (REGISTRATION_REQUEST_MAGIC, STAGE_REQUEST_MAGIC, COMPLETION_REQUEST_MAGIC)
FORWARD_REQUEST_MAGICS = (REGISTRATION_FORWARD_MAGIC, STAGE_FORWARD_MAGIC, COMPLETION_FORWARD_MAGIC)
MAX_REQUEST_BYTES = MAX_INPUT_BYTES
MAX_RESPONSE_BYTES = MAX_INPUT_BYTES
MAX_CONTROL_BYTES = authority_contract.MAX_REQUEST_BYTES
_REQUEST_LIMITS = (MAX_CONTROL_BYTES, MAX_INPUT_BYTES)
_DIGEST_BYTES = 71
_METADATA_BYTES = _DIGEST_BYTES + 8
_RESPONSE_LENGTH_BYTES = 4 * 8
_MAX_I64 = (1 << 63) - 1

_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _request_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 2
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, _REQUEST_LIMITS))
            or sum(lengths) > MAX_REQUEST_BYTES):
        raise AuthorityTransportError("transition custody read request lengths are invalid")


def _response_lengths(lengths):
    if (type(lengths) is not tuple or len(lengths) != 4
            or any(type(size) is not int or not 2 <= size <= MAX_INPUT_BYTES for size in lengths)
            or sum(lengths) + _METADATA_BYTES > MAX_RESPONSE_BYTES):
        raise AuthorityTransportError("transition custody read response lengths are invalid")


def _metadata(retained_record_digest, retained_at_epoch_ns):
    if (type(retained_record_digest) is not str or len(retained_record_digest) != _DIGEST_BYTES
            or not retained_record_digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in retained_record_digest[7:])
            or type(retained_at_epoch_ns) is not int or not 1 <= retained_at_epoch_ns <= _MAX_I64):
        raise AuthorityTransportError("transition custody read metadata requires canonical digest and positive I64 time")
    return retained_record_digest, retained_at_epoch_ns


def _validate_request(*, control_bytes, historical_expectations_bytes):
    originals = control_bytes, historical_expectations_bytes
    if any(type(raw) is not bytes for raw in originals):
        raise AuthorityTransportError("transition custody read requires exact original request bytes")
    _request_lengths(tuple(len(raw) for raw in originals))
    return originals


def _validate_response(response):
    if (type(response) is not tuple or len(response) != 6
            or any(type(raw) is not bytes for raw in response[:4])):
        raise AuthorityTransportError("transition custody read response is not an exact six-tuple")
    _response_lengths(tuple(len(raw) for raw in response[:4]))
    _metadata(response[4], response[5])
    return response


def _recv(connection, *, deadline_ns, prefix, magics):
    if type(prefix) is not bytes or prefix not in magics:
        raise AuthorityTransportError("transition custody read request magic is invalid")
    operation = OPERATIONS[magics.index(prefix)]
    header = io._recv_exact_until(connection, 16, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big") for index in (0, 8))
    _request_lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return operation, originals


def _recv_request(connection, *, deadline_ns, prefix):
    return _recv(connection, deadline_ns=deadline_ns, prefix=prefix, magics=REQUEST_MAGICS)


def _recv_forward_request(connection, *, deadline_ns, prefix):
    return _recv(connection, deadline_ns=deadline_ns, prefix=prefix, magics=FORWARD_REQUEST_MAGICS)


def _send_response(connection, response, *, deadline_ns):
    envelope_bytes, proof_bytes, inputs_bytes, context_bytes, digest, retained_at = _validate_response(response)
    originals = envelope_bytes, proof_bytes, inputs_bytes, context_bytes
    header = (RESPONSE_MAGIC + b"".join(len(raw).to_bytes(8, "big") for raw in originals)
        + digest.encode("ascii") + retained_at.to_bytes(8, "big"))
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for raw in originals:
        io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _recv_response(connection, *, deadline_ns):
    if _recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
        raise AuthorityTransportError("transition custody read response magic is invalid")
    # Only the fixed 111-byte header precedes complete length/metadata admission.
    # No body allocation or streaming fallback occurs before those checks.
    header = io._recv_exact_until(connection, _RESPONSE_LENGTH_BYTES + _METADATA_BYTES,
        deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, _RESPONSE_LENGTH_BYTES, 8))
    _response_lengths(lengths)
    try:
        digest = header[_RESPONSE_LENGTH_BYTES:_RESPONSE_LENGTH_BYTES + _DIGEST_BYTES].decode("ascii")
    except UnicodeError as exc:
        raise AuthorityTransportError("transition custody read record digest is not ASCII") from exc
    digest, retained_at = _metadata(digest,
        int.from_bytes(header[_RESPONSE_LENGTH_BYTES + _DIGEST_BYTES:], "big"))
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return _validate_response((*originals, digest, retained_at))


def _socket_exchange(path, *, magics, operation, control_bytes, historical_expectations_bytes,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    if type(operation) is not str or operation not in OPERATIONS:
        raise AuthorityTransportError("transition custody read operation is not source fixed")
    magic = magics[OPERATIONS.index(operation)]
    originals = _validate_request(control_bytes=control_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("transition custody read socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("transition custody read socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("transition custody read socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("transition custody read peer identity is invalid")
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
            raise AuthorityTransportError("transition custody read server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        response = _recv_response(connection, deadline_ns=deadline_ns)
    except BaseException:
        # A failed/incomplete read provides no absent-success or retry
        # authority. Preserve its first error even if closing also fails.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return response


def _socket_request(path, *, operation, control_bytes, historical_expectations_bytes,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    return _socket_exchange(path, magics=REQUEST_MAGICS, operation=operation,
        control_bytes=control_bytes, historical_expectations_bytes=historical_expectations_bytes,
        timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid, expected_peer_gid=expected_peer_gid)


def _socket_forward_request(path, *, operation, control_bytes, historical_expectations_bytes,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    return _socket_exchange(path, magics=FORWARD_REQUEST_MAGICS, operation=operation,
        control_bytes=control_bytes, historical_expectations_bytes=historical_expectations_bytes,
        timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid, expected_peer_gid=expected_peer_gid)
