"""Fixed-purpose public revocation frames; opaque originals are not authority.

The real serving owner checks its peer before intake. Each client verifies the
actual Unix peer before sending; one absolute monotonic deadline, half-close
and exact EOF cover one exchange. There is no retry or caller-chosen endpoint
inside a received frame. Every fixed length vector is bounded before bodies.
"""
from __future__ import annotations

import socket

from catchplate import authority_contract as authority
from catchplate import authority_revocation_writer_transport as io
from catchplate import authority_custody_caller_transport as framing
from catchplate import control_plane_public_revocation_records as records


AuthorityTransportError = framing.AuthorityTransportError
MAX_BYTES = authority.MAX_RESULT_BYTES
_REQUEST = records.PROFILES[1][1]
_PREPARED = records.PROFILES[2][1]
_GRANT = records.PROFILES[3][1]
_COMPUTED = records.PROFILES[4][1][:2]
_RESERVED = records.PROFILES[4][1][2:]
_LOCATORS = records.PROFILES[5][1]
# No received selector can amend these arities, maxima or target roles.
PROFILES = (
    ("approval", b"SWPVAQ01", b"SWPVAR01", _REQUEST, (4 * 1024 * 1024,), "verifier"),
    ("prepare", b"SWPVPQ01", b"SWPVPR01", _REQUEST, _PREPARED, "verifier"),
    ("grant", b"SWPVGQ01", b"SWPVGR01", _REQUEST + _PREPARED, _GRANT, "issuer"),
    ("compute", b"SWPVCQ01", b"SWPVCR01", _REQUEST + _PREPARED + _GRANT, _COMPUTED, "verifier"),
    ("reserve", b"SWPVRQ01", b"SWPVRR01", _REQUEST + _PREPARED + _GRANT + _COMPUTED, _RESERVED, "issuer"),
    ("issue", b"SWPVIQ01", b"SWPVIR01", _REQUEST + _PREPARED + _GRANT + _COMPUTED + _RESERVED,
        _LOCATORS, "issuer"),
    ("execute", b"SWPVEQ01", b"SWPVER01", _REQUEST + _PREPARED + _GRANT + _COMPUTED + _RESERVED + _LOCATORS,
        records.PROFILES[6][1], "executor"),
    ("complete", b"SWPVDQ01", b"SWPVDR01", _REQUEST + _PREPARED + _GRANT + _COMPUTED + _RESERVED + _LOCATORS + (64 * 1024,),
        records.PROFILES[7][1], "executor"),
    ("recover", b"SWPVLQ01", b"SWPVLR01", _REQUEST + _PREPARED + _GRANT + _COMPUTED + _RESERVED
        + _LOCATORS + (64 * 1024,), records.PROFILES[7][1], "executor"),
)
REQUEST_MAGICS = tuple(row[1] for row in PROFILES)


def profile(kind):
    if type(kind) is not str:
        raise AuthorityTransportError("public revocation purpose is not source fixed")
    for row in PROFILES:
        if row[0] == kind:
            return row
    raise AuthorityTransportError("public revocation purpose is not supported")


def kind_from_prefix(prefix):
    if type(prefix) is not bytes:
        raise AuthorityTransportError("public revocation prefix is not immutable bytes")
    for row in PROFILES:
        if row[1] == prefix:
            return row[0]
    raise AuthorityTransportError("public revocation prefix is not source fixed")


def lengths(values, limits, *, outcome=False):
    if (type(values) is not tuple or len(values) != len(limits)
            or any(type(size) is not int or not (0 if outcome and index > 0 else 1) <= size <= maximum
                for index, (size, maximum) in enumerate(zip(values, limits)))
            or sum(values) > MAX_BYTES):
        raise AuthorityTransportError("public revocation fixed original lengths exceed their bounds")


def originals(kind, values, *, response=False):
    fixed = profile(kind)
    if type(values) is not tuple or any(type(value) is not bytes for value in values):
        raise AuthorityTransportError("public revocation frame requires exact immutable originals")
    lengths(tuple(len(value) for value in values), fixed[4 if response else 3],
        outcome=response and kind == "execute")
    return values


def recv_request(connection, *, deadline_ns, prefix):
    kind = kind_from_prefix(prefix)
    fixed = profile(kind)
    raw_digest = io._recv_exact_until(connection, 71, deadline_ns=deadline_ns)
    try:
        digest = framing._configuration_digest(raw_digest.decode("ascii"))
    except UnicodeError as exc:
        raise AuthorityTransportError("public revocation configuration digest is not ASCII") from exc
    epoch = int.from_bytes(io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big")
    if not 0 < epoch < 2**63:
        raise AuthorityTransportError("public revocation signed deadline is not positive int64")
    header = io._recv_exact_until(connection, 8 * len(fixed[3]), deadline_ns=deadline_ns)
    sizes = tuple(int.from_bytes(header[offset:offset + 8], "big") for offset in range(0, len(header), 8))
    lengths(sizes, fixed[3])
    raw = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns) for size in sizes)
    io._require_eof(connection, deadline_ns)
    return kind, digest, epoch, originals(kind, raw)


def send_response(connection, kind, raw, *, deadline_ns):
    fixed = profile(kind)
    held = originals(kind, raw, response=True)
    header = fixed[2] + b"".join(len(value).to_bytes(8, "big") for value in held)
    io._send_exact_until(connection, header, deadline_ns=deadline_ns)
    for value in held:
        io._send_exact_until(connection, value, deadline_ns=deadline_ns)
    io._check_deadline(deadline_ns)


def exchange(path, *, kind, configuration_digest, deadline_epoch_ns, raw, deadline_ns,
        expected_peer_uid, expected_peer_gid):
    fixed = profile(kind)
    held = originals(kind, raw)
    digest = framing._configuration_digest(configuration_digest)
    if (type(path) is not str or not path.startswith("/") or "\x00" in path
            or not 1 <= len(path.encode("utf-8")) <= 107
            or type(deadline_epoch_ns) is not int or not 0 < deadline_epoch_ns < 2**63
            or any(type(value) is not int or not 0 <= value < 2**32
                for value in (expected_peer_uid, expected_peer_gid))):
        raise AuthorityTransportError("public revocation independently configured endpoint is invalid")
    header = (fixed[1] + digest.encode("ascii") + deadline_epoch_ns.to_bytes(8, "big")
        + b"".join(len(value).to_bytes(8, "big") for value in held))
    io._check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        uid, gid, _pid = io._call_until(connection, deadline_ns,
            lambda: framing.authority_transport._peer_identity(connection))
        if (uid, gid) != (expected_peer_uid, expected_peer_gid):
            raise AuthorityTransportError("public revocation actual service peer differs")
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for value in held:
            io._send_exact_until(connection, value, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        if io._recv_prefix(connection, deadline_ns=deadline_ns) != fixed[2]:
            raise AuthorityTransportError("public revocation response has another fixed purpose")
        header = io._recv_exact_until(connection, 8 * len(fixed[4]), deadline_ns=deadline_ns)
        sizes = tuple(int.from_bytes(header[offset:offset + 8], "big")
            for offset in range(0, len(header), 8))
        lengths(sizes, fixed[4], outcome=kind == "execute")
        returned = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns) for size in sizes)
        io._require_eof(connection, deadline_ns)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    io._check_deadline(deadline_ns)
    return originals(kind, returned, response=True)
