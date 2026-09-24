"""Private Unix framing, without JSON parsing or protocol authentication.

The successor adapters bound both original request and response bytes to the
source request ceiling. Legacy service callers retain their separate result
ceiling and canonical parser. Socket buffers, framing copies and peer lookup
are transport work, not part of a JSON verification work allowance.
"""
from __future__ import annotations

import socket
import struct

from serverware import authority_contract


class AuthorityTransportError(RuntimeError):
    pass


def _maximum_bytes(maximum_bytes: int) -> None:
    if (type(maximum_bytes) is not int
            or not 2 <= maximum_bytes <= authority_contract.MAX_RESULT_BYTES):
        raise AuthorityTransportError("authority transport limit is invalid")


def _peer_identity(connection: socket.socket) -> tuple[int, int, int | None]:
    if hasattr(socket, "SO_PEERCRED"):
        value = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, gid = struct.unpack("3i", value)
        return uid, gid, pid
    if hasattr(connection, "getpeereid"):
        uid, gid = connection.getpeereid()
        return uid, gid, None
    raise AuthorityTransportError("Unix peer credentials are unavailable")


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(min(remaining, 1024 * 1024))
        if not chunk:
            raise AuthorityTransportError("authority socket closed early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_message_bytes(
    connection: socket.socket, *, maximum_bytes: int,
) -> bytes:
    """Read only a bounded frame; even invalid JSON remains opaque here."""
    _maximum_bytes(maximum_bytes)
    size = int.from_bytes(_recv_exact(connection, 8), "big")
    if not 2 <= size <= maximum_bytes:
        raise AuthorityTransportError("authority message size is invalid")
    return _recv_exact(connection, size)


def _send_encoded_message(
    connection: socket.socket, encoded: bytes, *, maximum_bytes: int,
) -> None:
    _maximum_bytes(maximum_bytes)
    if type(encoded) is not bytes or not 2 <= len(encoded) <= maximum_bytes:
        raise AuthorityTransportError("authority response size is invalid")
    connection.sendall(len(encoded).to_bytes(8, "big") + encoded)


def _socket_request_bytes(
    path: str,
    encoded: bytes,
    *,
    timeout_seconds: float,
    expected_peer_uid: int,
    expected_peer_gid: int,
    maximum_bytes: int,
) -> bytes:
    """Transport original bytes once; no signature or application verdict."""
    _maximum_bytes(maximum_bytes)
    if type(encoded) is not bytes or not 2 <= len(encoded) <= maximum_bytes:
        raise AuthorityTransportError("authority request bytes are not exact and bounded")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout_seconds)
        connection.connect(path)
        peer_uid, peer_gid, _peer_pid = _peer_identity(connection)
        if peer_uid != expected_peer_uid or peer_gid != expected_peer_gid:
            raise AuthorityTransportError(
                "authority socket server identity is not exact"
            )
        _send_encoded_message(connection, encoded, maximum_bytes=maximum_bytes)
        return _recv_message_bytes(connection, maximum_bytes=maximum_bytes)
    finally:
        connection.close()


def _recv_revocation_invocation_bytes(connection: socket.socket) -> bytes:
    return _recv_message_bytes(
        connection, maximum_bytes=authority_contract.MAX_REQUEST_BYTES,
    )


def _socket_request_revocation_bytes(
    path: str,
    encoded: bytes,
    *,
    timeout_seconds: float,
    expected_peer_uid: int,
    expected_peer_gid: int,
) -> bytes:
    return _socket_request_bytes(
        path, encoded, timeout_seconds=timeout_seconds,
        expected_peer_uid=expected_peer_uid,
        expected_peer_gid=expected_peer_gid,
        maximum_bytes=authority_contract.MAX_REQUEST_BYTES,
    )
