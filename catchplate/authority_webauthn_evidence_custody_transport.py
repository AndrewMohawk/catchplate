"""Fixed detached evidence-custody exchanges, without application authority.

Relay preparation, explicit planner forwarding and writer retention are
separate operations and connections. This transport never combines them or
retries. The original controls and four detached bodies remain opaque bytes;
only the owning application can authenticate and genuinely replay them.

The digest/time response is unsigned informational data from the pinned peer,
not signed durability, exactly-once execution or rollback proof. Callers must
independently join its record identity and enforce application freshness.

All lengths and their aggregate are checked before body allocation. Existing
absolute-deadline I/O primitives bound the entire exchange. The serving owner
checks its peer before reading the prefix and closes the accepted connection
after sending; both receivers require EOF. No JSON/hash work allowance, SQL,
configuration, key enrollment or serving route is introduced here.
"""
from __future__ import annotations

import socket

from catchplate import authority_contract, authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate.authority_query_read_work import MAX_INPUT_BYTES


AuthorityTransportError = authority_transport.AuthorityTransportError
REGISTRATION_REQUEST_MAGIC = b"SWEG\x00\x00\x00\x01"
INSTALLATION_REQUEST_MAGIC = b"SWEI\x00\x00\x00\x01"
REGISTRATION_RELAY_MAGIC = b"SWER\x00\x00\x00\x01"
INSTALLATION_RELAY_MAGIC = b"SWEJ\x00\x00\x00\x01"
REGISTRATION_FORWARD_MAGIC = b"SWEF\x00\x00\x00\x01"
INSTALLATION_FORWARD_MAGIC = b"SWEK\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWEO\x00\x00\x00\x01"
RELAY_RESPONSE_MAGIC = b"SWEL\x00\x00\x00\x01"
MAX_REQUEST_BYTES = MAX_INPUT_BYTES
MAX_CONTROL_BYTES = authority_contract.MAX_REQUEST_BYTES
_PART_LIMITS = (MAX_CONTROL_BYTES, MAX_CONTROL_BYTES,
    MAX_INPUT_BYTES, MAX_INPUT_BYTES, MAX_INPUT_BYTES, MAX_INPUT_BYTES)
_RELAY_LIMITS = (MAX_CONTROL_BYTES,
    MAX_INPUT_BYTES, MAX_INPUT_BYTES, MAX_INPUT_BYTES, MAX_INPUT_BYTES)
_PROFILES = {
    "retain": (REGISTRATION_REQUEST_MAGIC, INSTALLATION_REQUEST_MAGIC, _PART_LIMITS),
    "relay": (REGISTRATION_RELAY_MAGIC, INSTALLATION_RELAY_MAGIC, _RELAY_LIMITS),
    "forward": (REGISTRATION_FORWARD_MAGIC, INSTALLATION_FORWARD_MAGIC, _PART_LIMITS),
}
_PURPOSES = ("registration", "installation")
_DIGEST_BYTES = 71
_MAX_I64 = (1 << 63) - 1

_deadline_ns = io._deadline_ns
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _lengths(lengths, limits):
    if (type(lengths) is not tuple or len(lengths) != len(limits)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(lengths, limits))
            or sum(lengths) > MAX_REQUEST_BYTES):
        raise AuthorityTransportError("evidence custody body lengths are invalid")


def _validate_lengths(lengths):
    _lengths(lengths, _PART_LIMITS)


def _validate_relay_lengths(lengths):
    _lengths(lengths, _RELAY_LIMITS)


def _originals(values, limits):
    if (type(values) is not tuple or len(values) != len(limits)
            or any(type(raw) is not bytes for raw in values)):
        raise AuthorityTransportError("evidence custody bodies are not exact original bytes")
    _lengths(tuple(len(raw) for raw in values), limits)
    return values


def _validate_originals(*, intent_bytes, relay_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, historical_expectations_bytes):
    return _originals((intent_bytes, relay_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, historical_expectations_bytes), _PART_LIMITS)


def _validate_relay_originals(*, intent_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, historical_expectations_bytes):
    return _originals((intent_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, historical_expectations_bytes), _RELAY_LIMITS)


def _response(retained_record_digest, retained_at_epoch_ns):
    if (type(retained_record_digest) is not str or len(retained_record_digest) != _DIGEST_BYTES
            or not retained_record_digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in retained_record_digest[7:])
            or type(retained_at_epoch_ns) is not int or not 1 <= retained_at_epoch_ns <= _MAX_I64):
        raise AuthorityTransportError("evidence custody response is not a canonical digest and positive I64 time")
    return retained_record_digest, retained_at_epoch_ns


def _recv(connection, *, deadline_ns, prefix, kind):
    registration_magic, installation_magic, limits = _PROFILES[kind]
    if type(prefix) is not bytes or prefix not in (registration_magic, installation_magic):
        raise AuthorityTransportError("evidence custody request magic is invalid")
    purpose = "registration" if prefix == registration_magic else "installation"
    header_size = 8 * len(limits)
    header = io._recv_exact_until(connection, header_size, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[index:index + 8], "big")
        for index in range(0, header_size, 8))
    # Admit every local length and the source aggregate before allocating even
    # the first opaque body. The prefix has already been peer-admitted upstream.
    _lengths(lengths, limits)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return purpose, originals


def _recv_request(connection, *, deadline_ns, prefix):
    return _recv(connection, deadline_ns=deadline_ns, prefix=prefix, kind="retain")


def _recv_relay_request(connection, *, deadline_ns, prefix):
    return _recv(connection, deadline_ns=deadline_ns, prefix=prefix, kind="relay")


def _recv_forward_request(connection, *, deadline_ns, prefix):
    return _recv(connection, deadline_ns=deadline_ns, prefix=prefix, kind="forward")


def _send_response(connection, retained_record_digest, retained_at_epoch_ns, *, deadline_ns):
    digest, retained_at = _response(retained_record_digest, retained_at_epoch_ns)
    response = RESPONSE_MAGIC + digest.encode("ascii") + retained_at.to_bytes(8, "big")
    io._send_exact_until(connection, response, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _send_relay(connection, relay_bytes, *, deadline_ns):
    if type(relay_bytes) is not bytes or not 2 <= len(relay_bytes) <= MAX_CONTROL_BYTES:
        raise AuthorityTransportError("evidence custody relay response is not bounded original bytes")
    header = RELAY_RESPONSE_MAGIC + len(relay_bytes).to_bytes(8, "big")
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    io._send_exact_until(connection, relay_bytes, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_exchange(path, *, kind, purpose, originals, timeout_seconds,
        expected_peer_uid, expected_peer_gid, deadline_ns=None):
    registration_magic, installation_magic, limits = _PROFILES[kind]
    if type(purpose) is not str or purpose not in _PURPOSES:
        raise AuthorityTransportError("evidence custody purpose is not source fixed")
    magic = registration_magic if purpose == "registration" else installation_magic
    originals = _originals(originals, limits)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("evidence custody socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("evidence custody socket path is invalid") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("evidence custody socket path is too long")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("evidence custody peer identity is invalid")
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
            raise AuthorityTransportError("evidence custody server peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for raw in originals:
            io._send_exact_until(connection, raw, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        prefix = _recv_prefix(connection, deadline_ns=deadline_ns)
        if kind == "relay":
            if prefix != RELAY_RESPONSE_MAGIC:
                raise AuthorityTransportError("evidence custody relay response magic is invalid")
            length = int.from_bytes(io._recv_exact_until(connection, 8,
                deadline_ns=deadline_ns), "big")
            if not 2 <= length <= MAX_CONTROL_BYTES:
                raise AuthorityTransportError("evidence custody relay response length is invalid")
            result = io._recv_exact_until(connection, length, deadline_ns=deadline_ns)
        else:
            if prefix != RESPONSE_MAGIC:
                raise AuthorityTransportError("evidence custody response magic is invalid")
            raw = io._recv_exact_until(connection, _DIGEST_BYTES + 8, deadline_ns=deadline_ns)
            try:
                digest = raw[:_DIGEST_BYTES].decode("ascii")
            except UnicodeError as exc:
                raise AuthorityTransportError("evidence custody response digest is not ASCII") from exc
            result = _response(digest, int.from_bytes(raw[_DIGEST_BYTES:], "big"))
        io._require_eof(connection, deadline_ns)
    except BaseException:
        # Preserve the first transport/native failure even if closing fails.
        # An uncertain exchange supplies neither absence nor retry authority.
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return result


def _socket_request(path, *, purpose, intent_bytes, relay_bytes, envelope_bytes,
        inputs_bytes, evaluation_context_bytes, historical_expectations_bytes,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    originals = _validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes,
        evaluation_context_bytes=evaluation_context_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    return _socket_exchange(path, kind="retain", purpose=purpose, originals=originals,
        timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid,
        expected_peer_gid=expected_peer_gid)


def _socket_relay_request(path, *, purpose, intent_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, historical_expectations_bytes, timeout_seconds,
        expected_peer_uid, expected_peer_gid, deadline_ns=None):
    originals = _validate_relay_originals(intent_bytes=intent_bytes, envelope_bytes=envelope_bytes,
        inputs_bytes=inputs_bytes, evaluation_context_bytes=evaluation_context_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    return _socket_exchange(path, kind="relay", purpose=purpose, originals=originals,
        timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid,
        expected_peer_gid=expected_peer_gid, deadline_ns=deadline_ns)


def _socket_forward_request(path, *, purpose, intent_bytes, relay_bytes, envelope_bytes,
        inputs_bytes, evaluation_context_bytes, historical_expectations_bytes,
        timeout_seconds, expected_peer_uid, expected_peer_gid):
    originals = _validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes,
        evaluation_context_bytes=evaluation_context_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    return _socket_exchange(path, kind="forward", purpose=purpose, originals=originals,
        timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid,
        expected_peer_gid=expected_peer_gid)
