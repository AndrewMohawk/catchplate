"""Fixed caller-to-relay-to-verifier custody forwarding of exact originals.

These distinct prefixes carry a configuration scope and evidence raw6 or
transition raw7. The receiving owner joins the untrusted scope to its own
independently admitted current configuration. These transport fields do
not authenticate the controls, replay a plan, admit history, establish storage
or permit a retry. The response is an unsigned informational digest/time pair.

One supplied absolute monotonic deadline bounds each socket exchange; these
helpers never create or renew it. Serving owners establish ingress deadlines
before queuing. All lengths and the source aggregate are checked
before any body allocation. The socket client admits the exact server peer
before sending. The accepted-connection owner must admit its client peer
before reading the prefix and close that borrowed connection in every path.
Request SHUT_WR and exact response/request EOF prevent ambiguous framing.
"""
from __future__ import annotations

import socket

from catchplate import authority_transport
from catchplate import authority_revocation_writer_transport as io
from catchplate import authority_webauthn_evidence_custody_transport as evidence
from catchplate import authority_webauthn_transition_custody_transport as transition


AuthorityTransportError = authority_transport.AuthorityTransportError
EVIDENCE_REGISTRATION_MAGIC = b"SWCJER01"
EVIDENCE_INSTALLATION_MAGIC = b"SWCJEI01"
TRANSITION_REGISTRATION_MAGIC = b"SWCJTR01"
TRANSITION_STAGE_MAGIC = b"SWCJTS01"
TRANSITION_COMPLETION_MAGIC = b"SWCJTC01"
RESPONSE_MAGIC = b"SWCJOK01"
REQUEST_MAGICS = (EVIDENCE_REGISTRATION_MAGIC, EVIDENCE_INSTALLATION_MAGIC,
    TRANSITION_REGISTRATION_MAGIC, TRANSITION_STAGE_MAGIC, TRANSITION_COMPLETION_MAGIC)
MAX_REQUEST_BYTES = evidence.MAX_REQUEST_BYTES
MAX_CONTROL_BYTES = evidence.MAX_CONTROL_BYTES
_PROFILES = (
    ("evidence", "registration", 6),
    ("evidence", "installation", 6),
    ("transition", "webauthn.registration.finalize", 7),
    ("transition", "webauthn.trust.stage", 7),
    ("transition", "webauthn.trust.complete", 7),
)
_DIGEST_BYTES = 71
_check_deadline = io._check_deadline
_recv_prefix = io._recv_prefix


def _profile(family, selector):
    if type(family) is not str or type(selector) is not str:
        raise AuthorityTransportError("caller custody family and selector require exact text")
    for index, profile in enumerate(_PROFILES):
        if profile[:2] == (family, selector):
            return index, profile
    raise AuthorityTransportError("caller custody selector is not one of the fixed five")


def _configuration_digest(value):
    if (type(value) is not str or len(value) != _DIGEST_BYTES
            or not value.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in value[7:])):
        raise AuthorityTransportError("caller custody configuration digest is not canonical SHA-256")
    return value


def _validate_originals(family, selector, originals):
    _, profile = _profile(family, selector)
    if type(originals) is not tuple or len(originals) != profile[2]:
        raise AuthorityTransportError("caller custody originals have the wrong tuple shape")
    if family == "evidence":
        return evidence._validate_originals(intent_bytes=originals[0], relay_bytes=originals[1],
            envelope_bytes=originals[2], inputs_bytes=originals[3],
            evaluation_context_bytes=originals[4], historical_expectations_bytes=originals[5])
    return transition._validate_originals(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], proof_bytes=originals[3], inputs_bytes=originals[4],
        context_bytes=originals[5], historical_expectations_bytes=originals[6])


def _recv_request(connection, *, deadline_ns, prefix):
    """Read one request after the serving owner has admitted the exact peer."""
    if type(prefix) is not bytes or prefix not in REQUEST_MAGICS:
        raise AuthorityTransportError("caller custody request magic is invalid")
    family, selector, count = _PROFILES[REQUEST_MAGICS.index(prefix)]
    encoded_digest = io._recv_exact_until(connection, _DIGEST_BYTES, deadline_ns=deadline_ns)
    try:
        configuration_digest = _configuration_digest(encoded_digest.decode("ascii"))
    except UnicodeError as exc:
        raise AuthorityTransportError("caller custody configuration digest is not ASCII") from exc
    header_size = count * 8
    header = io._recv_exact_until(connection, header_size, deadline_ns=deadline_ns)
    lengths = tuple(int.from_bytes(header[offset:offset + 8], "big")
        for offset in range(0, header_size, 8))
    # Reuse the actual raw-family bounds: first two controls <=4 MiB,
    # every original >=2 bytes, and all originals together <=64 MiB.
    if family == "evidence":
        evidence._validate_lengths(lengths)
    else:
        transition._validate_lengths(lengths)
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        for size in lengths)
    io._require_eof(connection, deadline_ns)
    return configuration_digest, family, selector, _validate_originals(family, selector, originals)


def _send_response(conn, digest, time, *, deadline_ns):
    """Send the canonical unsigned pair; the serving owner closes conn."""
    digest, retained_at = evidence._response(digest, time)
    encoded = RESPONSE_MAGIC + digest.encode("ascii") + retained_at.to_bytes(8, "big")
    io._send_exact_until(conn, encoded, deadline_ns=deadline_ns)
    _check_deadline(deadline_ns)


def _socket_request(path, *, configuration_digest, family, selector, originals, deadline_ns,
        expected_peer_uid, expected_peer_gid):
    """Return one unsigned peer observation, never retrying uncertain I/O."""
    originals = _validate_originals(family, selector, originals)
    configuration_digest = _configuration_digest(configuration_digest)
    index, _ = _profile(family, selector)
    if (type(path) is not str or not 1 <= len(path) <= 107
            or not path.startswith("/") or "\x00" in path):
        raise AuthorityTransportError("caller custody socket path is invalid")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityTransportError("caller custody socket path is not lossless UTF-8") from exc
    if not 1 <= len(path_bytes) <= 107:
        raise AuthorityTransportError("caller custody socket path exceeds its byte bound")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (expected_peer_uid, expected_peer_gid)):
        raise AuthorityTransportError("caller custody peer identity is invalid")
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
            raise AuthorityTransportError("caller custody server peer differs from its admitted identity")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for original in originals:
            io._send_exact_until(connection, original, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        if _recv_prefix(connection, deadline_ns=deadline_ns) != RESPONSE_MAGIC:
            raise AuthorityTransportError("caller custody response magic is invalid")
        raw = io._recv_exact_until(connection, _DIGEST_BYTES + 8, deadline_ns=deadline_ns)
        try:
            digest = raw[:_DIGEST_BYTES].decode("ascii")
        except UnicodeError as exc:
            raise AuthorityTransportError("caller custody response digest is not ASCII") from exc
        result = evidence._response(digest, int.from_bytes(raw[_DIGEST_BYTES:], "big"))
        io._require_eof(connection, deadline_ns)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    _check_deadline(deadline_ns)
    return result
