#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import hmac
import http.client
import io
import os
import select
import socket
import ssl
import stat
import struct
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

_SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(_SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIRECTORY))

import launch_authorization as protocol  # noqa: E402


AUTHORIZATION_PATH = "/v1/launch-authorizations"
REQUEST_CONTENT_TYPE = "application/catchplate.launch-authorization-request+json"
RESPONSE_CONTENT_TYPE = "application/catchplate.launch-authorization+json"
SOCKET_PATH = "/run/catchplate/launch-authority.sock"
MAX_PACKET_BYTES = 16 * 1024
DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_MAX_RELAY_WORKERS = 8
MAX_TLS_MATERIAL_BYTES = 1024 * 1024


class RelayConfigurationError(ValueError):
    pass


class RelayError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_trusted_ancestors(path: Path, *, label: str) -> None:
    candidate = Path(path.anchor)
    for component in path.parts[1:-1]:
        candidate /= component
        try:
            metadata = os.lstat(candidate)
        except OSError as exc:
            raise RelayConfigurationError(
                f"cannot inspect {label} ancestor: {candidate}"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise RelayConfigurationError(
                f"{label} ancestor must be a real directory: {candidate}"
            )
        mode = stat.S_IMODE(metadata.st_mode)
        root_sticky_directory = (
            metadata.st_uid == 0 and bool(mode & stat.S_ISVTX) and bool(mode & 0o022)
        )
        if metadata.st_uid not in {0, os.geteuid()} or (
            mode & 0o022 and not root_sticky_directory
        ):
            raise RelayConfigurationError(
                f"{label} ancestor is not trusted: {candidate}"
            )


def _read_stable_regular_file(path: Path, *, label: str, owner_only: bool) -> bytes:
    path = Path(path)
    if not path.is_absolute():
        raise RelayConfigurationError(f"{label} path must be absolute")
    _validate_trusted_ancestors(path, label=label)
    try:
        before_path = os.lstat(path)
    except OSError as exc:
        raise RelayConfigurationError(f"cannot inspect {label}: {path}") from exc
    if not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1:
        raise RelayConfigurationError(f"{label} must be a regular non-symlink file")
    mode = stat.S_IMODE(before_path.st_mode)
    if before_path.st_uid not in {0, os.geteuid()}:
        raise RelayConfigurationError(f"{label} must have a trusted owner")
    if owner_only:
        if before_path.st_uid != os.geteuid() or mode not in {0o400, 0o600}:
            raise RelayConfigurationError(
                f"{label} must be owned by the relay user with mode 0400 or 0600"
            )
    elif mode & 0o022:
        raise RelayConfigurationError(f"{label} must not be group/world writable")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RelayConfigurationError(f"cannot open {label} securely: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if _stable_identity(before) != _stable_identity(before_path):
            raise RelayConfigurationError(f"{label} changed before it was read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_TLS_MATERIAL_BYTES:
                raise RelayConfigurationError(
                    f"{label} exceeds {MAX_TLS_MATERIAL_BYTES} bytes"
                )
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.stat(path, follow_symlinks=False)
    if _stable_identity(before) != _stable_identity(after) or _stable_identity(
        after
    ) != _stable_identity(current):
        raise RelayConfigurationError(f"{label} changed while it was read")
    _validate_trusted_ancestors(path, label=label)
    return b"".join(chunks)


def _validate_regular_path(path: Path, *, label: str, owner_only: bool) -> Path:
    path = Path(path)
    _read_stable_regular_file(path, label=label, owner_only=owner_only)
    return path


@dataclass(frozen=True, slots=True)
class RelayConfiguration:
    authority_url: str
    server_name: str
    ca_certificate: Path
    client_certificate: Path
    client_private_key: Path
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    resolved_addresses: tuple[tuple[int, int, int, tuple[object, ...]], ...] = field(
        init=False, repr=False
    )

    def __post_init__(self) -> None:
        if (
            type(self.authority_url) is not str
            or not self.authority_url
            or any(
                ord(character) < 33 or ord(character) == 127
                for character in self.authority_url
            )
        ):
            raise RelayConfigurationError("authority URL is invalid")
        try:
            parsed = urllib.parse.urlsplit(self.authority_url)
            port = parsed.port
        except ValueError as exc:
            raise RelayConfigurationError("authority URL is malformed") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != AUTHORIZATION_PATH
            or parsed.query
            or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise RelayConfigurationError(
                "authority URL must be one exact HTTPS launch-authorization endpoint"
            )
        if (
            type(self.server_name) is not str
            or self.server_name != self.server_name.lower()
            or not self.server_name
            or len(self.server_name) > 253
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789.-"
                for character in self.server_name
            )
            or self.server_name.startswith((".", "-"))
            or self.server_name.endswith((".", "-"))
            or parsed.hostname.lower() != self.server_name
        ):
            raise RelayConfigurationError(
                "pinned TLS server name must exactly match the authority URL host"
            )
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0.01 <= float(self.timeout_seconds) <= 30.0
        ):
            raise RelayConfigurationError(
                "relay timeout must be between 0.01 and 30 seconds"
            )
        try:
            address_records = socket.getaddrinfo(
                parsed.hostname,
                port or 443,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except OSError as exc:
            raise RelayConfigurationError(
                "authority URL host could not be resolved during relay startup"
            ) from exc
        resolved_addresses: list[tuple[int, int, int, tuple[object, ...]]] = []
        for (
            family,
            socktype,
            protocol_number,
            _canonical_name,
            address,
        ) in address_records:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            record = (family, socktype, protocol_number, tuple(address))
            if record not in resolved_addresses:
                resolved_addresses.append(record)
        if not resolved_addresses or len(resolved_addresses) > 16:
            raise RelayConfigurationError(
                "authority URL host must resolve to 1 through 16 IP addresses"
            )
        object.__setattr__(self, "resolved_addresses", tuple(resolved_addresses))
        object.__setattr__(
            self,
            "ca_certificate",
            _validate_regular_path(
                self.ca_certificate, label="authority CA certificate", owner_only=False
            ),
        )
        object.__setattr__(
            self,
            "client_certificate",
            _validate_regular_path(
                self.client_certificate,
                label="relay client certificate",
                owner_only=False,
            ),
        )
        object.__setattr__(
            self,
            "client_private_key",
            _validate_regular_path(
                self.client_private_key,
                label="relay client private key",
                owner_only=True,
            ),
        )

    @property
    def parsed_url(self) -> urllib.parse.SplitResult:
        return urllib.parse.urlsplit(self.authority_url)

    def tls_context(self) -> ssl.SSLContext:
        ca_bytes = _read_stable_regular_file(
            self.ca_certificate,
            label="authority CA certificate",
            owner_only=False,
        )
        client_certificate_bytes = _read_stable_regular_file(
            self.client_certificate,
            label="relay client certificate",
            owner_only=False,
        )
        client_private_key_bytes = _read_stable_regular_file(
            self.client_private_key,
            label="relay client private key",
            owner_only=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            ca_data: str | bytes = ca_bytes.decode("ascii")
        except UnicodeDecodeError:
            ca_data = ca_bytes
        context.load_verify_locations(cadata=ca_data)
        context.load_cert_chain(
            certfile=str(self.client_certificate),
            keyfile=str(self.client_private_key),
        )
        for path, label, expected, owner_only in (
            (self.ca_certificate, "authority CA certificate", ca_bytes, False),
            (
                self.client_certificate,
                "relay client certificate",
                client_certificate_bytes,
                False,
            ),
            (
                self.client_private_key,
                "relay client private key",
                client_private_key_bytes,
                True,
            ),
        ):
            current = _read_stable_regular_file(
                path, label=label, owner_only=owner_only
            )
            if not hmac.compare_digest(current, expected):
                raise RelayConfigurationError(
                    f"{label} changed while the TLS context was created"
                )
        return context


def _single_response_header(headers: list[tuple[str, str]], name: str) -> str:
    values = [value for header, value in headers if header.lower() == name.lower()]
    if len(values) != 1:
        raise RelayError(
            "REMOTE_HEADERS_INVALID", f"remote {name} must appear exactly once"
        )
    return values[0]


def _remaining_relay_deadline(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RelayError(
            "REMOTE_DEADLINE_EXCEEDED",
            "launch authority request exceeded its absolute deadline",
        )
    return remaining


def _wait_for_socket(
    tls_socket: ssl.SSLSocket,
    *,
    readable: bool,
    deadline: float,
) -> None:
    if readable:
        ready, _, _ = select.select(
            [tls_socket], [], [], _remaining_relay_deadline(deadline)
        )
    else:
        _, ready, _ = select.select(
            [], [tls_socket], [], _remaining_relay_deadline(deadline)
        )
    if not ready:
        _remaining_relay_deadline(deadline)


def _connect_tls_before_deadline(
    configuration: RelayConfiguration,
    context: ssl.SSLContext,
    deadline: float,
) -> ssl.SSLSocket:
    last_error: OSError | None = None
    for family, socktype, protocol_number, address in configuration.resolved_addresses:
        raw_socket = socket.socket(family, socktype, protocol_number)
        raw_socket.setblocking(False)
        try:
            result = raw_socket.connect_ex(address)
            if result not in {
                0,
                errno.EINPROGRESS,
                errno.EWOULDBLOCK,
                errno.EALREADY,
                errno.EINTR,
            }:
                raise OSError(result, os.strerror(result))
            if result != 0:
                _, writable, exceptional = select.select(
                    [],
                    [raw_socket],
                    [raw_socket],
                    _remaining_relay_deadline(deadline),
                )
                if not writable or exceptional:
                    _remaining_relay_deadline(deadline)
                    raise OSError("authority TCP connection failed")
                socket_error = raw_socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if socket_error:
                    raise OSError(socket_error, os.strerror(socket_error))
            tls_socket = context.wrap_socket(
                raw_socket,
                server_hostname=configuration.server_name,
                do_handshake_on_connect=False,
            )
            tls_socket.setblocking(False)
            try:
                while True:
                    try:
                        tls_socket.do_handshake()
                        return tls_socket
                    except ssl.SSLWantReadError:
                        _wait_for_socket(tls_socket, readable=True, deadline=deadline)
                    except ssl.SSLWantWriteError:
                        _wait_for_socket(tls_socket, readable=False, deadline=deadline)
            except Exception:
                tls_socket.close()
                raise
        except RelayError:
            raw_socket.close()
            raise
        except (OSError, ssl.SSLError) as exc:
            raw_socket.close()
            last_error = exc if isinstance(exc, OSError) else OSError(str(exc))
    if last_error is None:
        last_error = OSError("authority endpoint resolved to no addresses")
    raise RelayError(
        "REMOTE_TRANSPORT_FAILED", "authority TLS connection failed"
    ) from last_error


def _tls_send_all(tls_socket: ssl.SSLSocket, value: bytes, *, deadline: float) -> None:
    offset = 0
    while offset < len(value):
        try:
            sent = tls_socket.send(value[offset:])
            if sent <= 0:
                raise OSError("authority TLS socket stopped accepting request bytes")
            offset += sent
        except ssl.SSLWantReadError:
            _wait_for_socket(tls_socket, readable=True, deadline=deadline)
        except ssl.SSLWantWriteError:
            _wait_for_socket(tls_socket, readable=False, deadline=deadline)


def _tls_receive(tls_socket: ssl.SSLSocket, maximum: int, *, deadline: float) -> bytes:
    while True:
        try:
            return tls_socket.recv(maximum)
        except ssl.SSLWantReadError:
            _wait_for_socket(tls_socket, readable=True, deadline=deadline)
        except ssl.SSLWantWriteError:
            _wait_for_socket(tls_socket, readable=False, deadline=deadline)


def _read_http_response_before_deadline(
    tls_socket: ssl.SSLSocket, *, deadline: float
) -> tuple[int, list[tuple[str, str]], bytes]:
    received = bytearray()
    header_end = -1
    while header_end < 0:
        if len(received) >= MAX_PACKET_BYTES:
            raise RelayError(
                "REMOTE_HEADERS_INVALID", "authority response headers are oversized"
            )
        chunk = _tls_receive(
            tls_socket,
            MAX_PACKET_BYTES - len(received),
            deadline=deadline,
        )
        if not chunk:
            raise RelayError(
                "REMOTE_FRAME_INVALID", "authority closed before response headers"
            )
        received.extend(chunk)
        header_end = received.find(b"\r\n\r\n")
    raw_headers = bytes(received[: header_end + 4])
    body = bytearray(received[header_end + 4 :])
    lines = raw_headers.split(b"\r\n")
    if not lines or any(line.startswith((b" ", b"\t")) for line in lines[1:]):
        raise RelayError(
            "REMOTE_HEADERS_INVALID", "authority response headers are malformed"
        )
    try:
        status_line = lines[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise RelayError(
            "REMOTE_HEADERS_INVALID", "authority status line is not ASCII"
        ) from exc
    status_parts = status_line.split(" ", 2)
    if (
        len(status_parts) < 2
        or status_parts[0] != "HTTP/1.1"
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
    ):
        raise RelayError("REMOTE_HEADERS_INVALID", "authority status line is invalid")
    try:
        message = http.client.parse_headers(io.BytesIO(b"\r\n".join(lines[1:])))
    except (http.client.HTTPException, UnicodeError) as exc:
        raise RelayError(
            "REMOTE_HEADERS_INVALID", "authority response headers are invalid"
        ) from exc
    headers = list(message.raw_items())
    status = int(status_parts[1])
    if status != 200:
        raise RelayError(
            "REMOTE_STATUS_INVALID",
            f"launch authority returned HTTP status {status}",
        )
    if any(header.lower() == "transfer-encoding" for header, _ in headers):
        raise RelayError(
            "REMOTE_HEADERS_INVALID", "chunked authority responses are forbidden"
        )
    if _single_response_header(headers, "Content-Type") != RESPONSE_CONTENT_TYPE:
        raise RelayError(
            "REMOTE_CONTENT_TYPE_INVALID",
            "authority response content type is invalid",
        )
    raw_length = _single_response_header(headers, "Content-Length")
    if (
        not raw_length.isdigit()
        or len(raw_length) > 5
        or str(int(raw_length)) != raw_length
    ):
        raise RelayError(
            "REMOTE_HEADERS_INVALID", "authority response Content-Length is invalid"
        )
    length = int(raw_length)
    if not 1 <= length <= MAX_PACKET_BYTES:
        raise RelayError(
            "REMOTE_FRAME_INVALID", "authority response is empty or oversized"
        )
    if len(body) > length:
        raise RelayError(
            "REMOTE_FRAME_INVALID", "authority response exceeded Content-Length"
        )
    while len(body) < length:
        chunk = _tls_receive(tls_socket, length - len(body), deadline=deadline)
        if not chunk:
            raise RelayError(
                "REMOTE_FRAME_INVALID",
                "authority response length does not match its header",
            )
        body.extend(chunk)
    return status, headers, bytes(body)


def forward_authorization_request(
    request_bytes: bytes, configuration: RelayConfiguration
) -> bytes:
    if (
        type(request_bytes) is not bytes
        or not 1 <= len(request_bytes) <= MAX_PACKET_BYTES
    ):
        raise RelayError("FRAME_INVALID", "relay request frame is empty or oversized")
    try:
        protocol.validate_launch_authorization_request(
            protocol.require_canonical_json_bytes(
                request_bytes, label="relay launch authorization request"
            )
        )
    except protocol.LaunchAuthorizationError as exc:
        raise RelayError(
            "REQUEST_INVALID", "relay request is not canonical protocol JSON"
        ) from exc

    deadline = time.monotonic() + float(configuration.timeout_seconds)
    tls_socket: ssl.SSLSocket | None = None
    try:
        context = configuration.tls_context()
        parsed = configuration.parsed_url
        tls_socket = _connect_tls_before_deadline(
            configuration,
            context,
            deadline,
        )
        port = parsed.port or 443
        host_header = (
            configuration.server_name
            if port == 443
            else f"{configuration.server_name}:{port}"
        )
        request_head = (
            f"POST {AUTHORIZATION_PATH} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Accept: {RESPONSE_CONTENT_TYPE}\r\n"
            f"Content-Type: {REQUEST_CONTENT_TYPE}\r\n"
            f"Content-Length: {len(request_bytes)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        _tls_send_all(tls_socket, request_head + request_bytes, deadline=deadline)
        _status, _headers, body = _read_http_response_before_deadline(
            tls_socket, deadline=deadline
        )
    except RelayError:
        raise
    except (
        OSError,
        ssl.SSLError,
        http.client.HTTPException,
        TimeoutError,
        RelayConfigurationError,
    ) as exc:
        if time.monotonic() >= deadline:
            raise RelayError(
                "REMOTE_DEADLINE_EXCEEDED",
                "launch authority request exceeded its absolute deadline",
            ) from exc
        raise RelayError(
            "REMOTE_TRANSPORT_FAILED", "authority TLS request failed"
        ) from exc
    finally:
        if tls_socket is not None:
            tls_socket.close()
    _remaining_relay_deadline(deadline)
    try:
        protocol.validate_launch_authorization(
            protocol.require_canonical_json_bytes(
                body, label="relay launch authorization response"
            )
        )
    except protocol.LaunchAuthorizationError as exc:
        raise RelayError(
            "REMOTE_RESPONSE_INVALID",
            "authority response is not canonical protocol JSON",
        ) from exc
    _remaining_relay_deadline(deadline)
    return body


def receive_packet(connection: socket.socket) -> bytes:
    try:
        packet, _ancillary, flags, _address = connection.recvmsg(MAX_PACKET_BYTES + 1)
    except (OSError, TimeoutError) as exc:
        raise RelayError(
            "LOCAL_RECEIVE_FAILED", "could not receive launcher packet"
        ) from exc
    if (
        flags & getattr(socket, "MSG_TRUNC", 0)
        or not packet
        or len(packet) > MAX_PACKET_BYTES
    ):
        raise RelayError("FRAME_INVALID", "launcher packet is empty or oversized")
    return packet


def require_root_peer(connection: socket.socket) -> None:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RelayError("PEER_CREDENTIALS_UNAVAILABLE", "SO_PEERCRED is unavailable")
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        _pid, uid, gid = struct.unpack("3i", raw)
    except (OSError, struct.error) as exc:
        raise RelayError(
            "PEER_CREDENTIALS_UNAVAILABLE", "could not read peer credentials"
        ) from exc
    if uid != 0 or gid != 0:
        raise RelayError("PEER_FORBIDDEN", "launcher relay only accepts root peers")


def serve_connection(
    connection: socket.socket,
    configuration: RelayConfiguration,
    *,
    forwarder: Callable[
        [bytes, RelayConfiguration], bytes
    ] = forward_authorization_request,
    enforce_root_peer: bool = True,
) -> None:
    connection.settimeout(float(configuration.timeout_seconds))
    if enforce_root_peer:
        require_root_peer(connection)
    request = receive_packet(connection)
    response = forwarder(request, configuration)
    if type(response) is not bytes or not 1 <= len(response) <= MAX_PACKET_BYTES:
        raise RelayError("REMOTE_FRAME_INVALID", "forwarder returned an invalid packet")
    try:
        sent = connection.send(response)
    except (OSError, TimeoutError) as exc:
        raise RelayError(
            "LOCAL_SEND_FAILED", "could not send authority response"
        ) from exc
    if sent != len(response):
        raise RelayError(
            "LOCAL_SEND_FAILED", "authority response was not sent atomically"
        )


class BoundedRelayWorkerPool:
    def __init__(self, max_workers: int = DEFAULT_MAX_RELAY_WORKERS) -> None:
        if type(max_workers) is not int or not 1 <= max_workers <= 64:
            raise RelayConfigurationError("relay worker limit must be between 1 and 64")
        self.max_workers = max_workers
        self._slots = threading.BoundedSemaphore(max_workers)
        self._condition = threading.Condition()
        self.active_workers = 0
        self.peak_workers = 0

    def submit(
        self,
        connection: socket.socket,
        configuration: RelayConfiguration,
        *,
        forwarder: Callable[
            [bytes, RelayConfiguration], bytes
        ] = forward_authorization_request,
        enforce_root_peer: bool = True,
    ) -> bool:
        if not self._slots.acquire(blocking=False):
            connection.close()
            return False
        with self._condition:
            self.active_workers += 1
            self.peak_workers = max(self.peak_workers, self.active_workers)
        worker = threading.Thread(
            target=self._run,
            args=(connection, configuration, forwarder, enforce_root_peer),
            name="launch-authority-relay-request",
            daemon=True,
        )
        try:
            worker.start()
        except Exception:
            with self._condition:
                self.active_workers -= 1
                self._condition.notify_all()
            self._slots.release()
            connection.close()
            raise
        return True

    def _run(
        self,
        connection: socket.socket,
        configuration: RelayConfiguration,
        forwarder: Callable[[bytes, RelayConfiguration], bytes],
        enforce_root_peer: bool,
    ) -> None:
        try:
            serve_connection(
                connection,
                configuration,
                forwarder=forwarder,
                enforce_root_peer=enforce_root_peer,
            )
        except RelayError as exc:
            sys.stderr.write(f"launch-authority-relay: {exc.code}\n")
        finally:
            connection.close()
            with self._condition:
                self.active_workers -= 1
                self._condition.notify_all()
            self._slots.release()

    def wait_for_idle(self, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while self.active_workers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True


def _validate_systemd_socket(listener: socket.socket) -> None:
    if (
        listener.family != socket.AF_UNIX
        or listener.type & 0xF != socket.SOCK_SEQPACKET
    ):
        raise RelayConfigurationError("systemd socket must be AF_UNIX SOCK_SEQPACKET")
    if listener.getsockname() != SOCKET_PATH:
        raise RelayConfigurationError(f"systemd socket must use {SOCKET_PATH}")
    if listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1:
        raise RelayConfigurationError("systemd socket is not listening")
    metadata = os.lstat(SOCKET_PATH)
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RelayConfigurationError("relay socket must be root:root mode 0600")


def systemd_listener() -> socket.socket:
    if os.getenv("LISTEN_PID") != str(os.getpid()) or os.getenv("LISTEN_FDS") != "1":
        raise RelayConfigurationError(
            "exactly one systemd-activated socket is required"
        )
    listener = socket.socket(fileno=3)
    _validate_systemd_socket(listener)
    return listener


def run_listener(listener: socket.socket, configuration: RelayConfiguration) -> None:
    workers = BoundedRelayWorkerPool()
    while True:
        connection, _address = listener.accept()
        workers.submit(connection, configuration)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Catchplate local launch authority relay"
    )
    parser.add_argument("--systemd-socket", action="store_true", required=True)
    parser.add_argument("--authority-url", required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--ca-certificate", required=True, type=Path)
    parser.add_argument("--client-certificate", required=True, type=Path)
    parser.add_argument("--client-private-key", required=True, type=Path)
    parser.add_argument(
        "--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = build_parser().parse_args(argv)
    try:
        configuration = RelayConfiguration(
            authority_url=args.authority_url,
            server_name=args.server_name,
            ca_certificate=args.ca_certificate,
            client_certificate=args.client_certificate,
            client_private_key=args.client_private_key,
            timeout_seconds=args.timeout_seconds,
        )
        listener = systemd_listener()
    except (RelayConfigurationError, OSError, ssl.SSLError) as exc:
        sys.stderr.write(f"launch-authority-relay: configuration failed: {exc}\n")
        return 2
    try:
        run_listener(listener, configuration)
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
