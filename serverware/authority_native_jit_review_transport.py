"""Authorize-only Unix framing; transport is not cold or request admission.

The serving owner must authenticate its peer before receiving the prefix or
token. The client checks the configured Unix peer before transmitting any
request bytes. One inherited monotonic deadline covers the entire exchange;
the epoch deadline is an opaque bounded limit for the actual authority owner.
There is no retry, JSON encoding of the token, logging or receipt authority.
Returned originals still require their actual signature and scope checks.
The receiver owns its accepted socket; exchange owns and closes its client.
"""
from __future__ import annotations

import socket
from uuid import UUID

from serverware import authority_native_jit_review_open_contract as wire
from serverware import authority_revocation_writer_transport as io


AuthorityTransportError = io.AuthorityTransportError
REQUEST_MAGIC = b"SWJOAQ01"
RESPONSE_MAGIC = b"SWJOAR01"
_REQUEST_LIMITS = ((2, wire.MAX_NATIVE_ORIGINAL), (36, 36), (64, 64))
_RESPONSE_LIMITS = tuple((2, maximum) for maximum in
    (wire.MAX_AUTHORITY_ORIGINAL, 512 * 1024, 512 * 1024, 1024 * 1024, 128 * 1024))
_TOKEN_CHARACTERS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_ERROR = "native review authorize transport refused"


def _require(value):
    if not value:
        raise AuthorityTransportError(_ERROR)


def _ascii(value, minimum, maximum):
    _require(type(value) is str and minimum <= len(value) <= maximum and value.isascii())
    return value.encode("ascii")


def _digest(value):
    raw = _ascii(value, 71, 71)
    _require(raw.startswith(b"sha256:") and all(c in b"0123456789abcdef" for c in raw[7:]))
    return raw


def _epoch(value):
    _require(type(value) is int and 0 < value < 2**63)
    return value


def _request(challenge_original, session_id, session_token_original):
    challenge = _ascii(challenge_original, *_REQUEST_LIMITS[0])
    session = _ascii(session_id, 36, 36)
    try:
        canonical = str(UUID(session_id))
    except ValueError:
        raise AuthorityTransportError(_ERROR) from None
    _require(canonical == session_id)
    # Exactly the possession grammar in current_read._token_digest, without
    # hashing or retaining the original in a JSON object or durable record.
    _require(type(session_token_original) is bytes and len(session_token_original) == 64
        and all(c in _TOKEN_CHARACTERS for c in session_token_original))
    return challenge, session, session_token_original


def _response(originals):
    _require(type(originals) is tuple and len(originals) == 5)
    return tuple(_ascii(value, *limit) for value, limit in zip(originals, _RESPONSE_LIMITS))


def _lengths(sizes, limits):
    _require(type(sizes) is tuple and len(sizes) == len(limits)
        and all(type(size) is int and minimum <= size <= maximum
            for size, (minimum, maximum) in zip(sizes, limits)))


def _receive_parts(connection, limits, deadline_ns):
    header = io._recv_exact_until(connection, 8 * len(limits), deadline_ns=deadline_ns)
    sizes = tuple(int.from_bytes(header[i:i + 8], "big") for i in range(0, len(header), 8))
    _lengths(sizes, limits)  # Admit every length before allocating any body.
    originals = tuple(io._recv_exact_until(connection, size, deadline_ns=deadline_ns) for size in sizes)
    io._require_eof(connection, deadline_ns)
    return originals


def _text(raw):
    try:
        return raw.decode("ascii")
    except UnicodeError:
        raise AuthorityTransportError(_ERROR) from None


def recv_request(connection, *, deadline_ns, prefix):
    _require(type(prefix) is bytes and prefix == REQUEST_MAGIC)
    digest = _text(io._recv_exact_until(connection, 71, deadline_ns=deadline_ns))
    _digest(digest)
    epoch = _epoch(int.from_bytes(io._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big"))
    challenge, session, token = _receive_parts(connection, _REQUEST_LIMITS, deadline_ns)
    challenge_text, session_text = _text(challenge), _text(session)
    _request(challenge_text, session_text, token)
    io._check_deadline(deadline_ns)
    return digest, epoch, challenge_text, session_text, token


def send_response(connection, originals, *, deadline_ns):
    raw = _response(originals)
    io._send_exact_until(connection, RESPONSE_MAGIC + b"".join(len(value).to_bytes(8, "big") for value in raw),
        deadline_ns=deadline_ns)
    for value in raw:
        io._send_exact_until(connection, value, deadline_ns=deadline_ns)
    io._check_deadline(deadline_ns)


def exchange(path, *, configuration_digest, deadline_epoch_ns, challenge_original,
        session_id, session_token_original, deadline_ns, expected_peer_uid, expected_peer_gid):
    raw = _request(challenge_original, session_id, session_token_original)
    digest, epoch = _digest(configuration_digest), _epoch(deadline_epoch_ns)
    _require(type(path) is str and 1 <= len(path) <= 107 and path.startswith("/") and "\x00" not in path)
    try:
        _require(len(path.encode("utf-8")) <= 107)
    except UnicodeError:
        raise AuthorityTransportError(_ERROR) from None
    _require(all(type(value) is int and 0 <= value < 2**32 for value in (expected_peer_uid, expected_peer_gid)))
    header = REQUEST_MAGIC + digest + epoch.to_bytes(8, "big") + b"".join(len(value).to_bytes(8, "big") for value in raw)
    io._check_deadline(deadline_ns)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        io._call_until(connection, deadline_ns, lambda: connection.connect(path))
        uid, gid, _pid = io._call_until(connection, deadline_ns,
            lambda: io.authority_transport._peer_identity(connection))
        _require((uid, gid) == (expected_peer_uid, expected_peer_gid))
        io._send_exact_until(connection, header, deadline_ns=deadline_ns)
        for value in raw:
            io._send_exact_until(connection, value, deadline_ns=deadline_ns)
        io._call_until(connection, deadline_ns, lambda: connection.shutdown(socket.SHUT_WR))
        _require(io._recv_prefix(connection, deadline_ns=deadline_ns) == RESPONSE_MAGIC)
        returned = tuple(_text(value) for value in _receive_parts(connection, _RESPONSE_LIMITS, deadline_ns))
        _response(returned)
        io._check_deadline(deadline_ns)
    except BaseException:
        try:
            connection.close()
        except BaseException:
            pass
        raise
    connection.close()
    io._check_deadline(deadline_ns)
    return returned
