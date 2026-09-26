"""Owned, bounded TLS layers for the ordinary workload client.

The inner SSLObject uses MemoryBIOs, never a second wrap_socket around an
SSLSocket: all inner TLS records travel through the authenticated outer TLS
channel. Python 3.11 documents this arrangement and SSLObject's strict EOF at
https://docs.python.org/3.11/library/ssl.html#ssl.SSLContext.wrap_bio .

Limits count outer TLS *plaintext*, not ciphertext or OpenSSL's internal
handshake allocations. Deadline checks reject late results but cannot interrupt
arbitrary blocked kernel/crypto operations; an outer watchdog remains separate.
Contexts/materials are supplied by the caller, not enrolled or provisioned here.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import time
from collections.abc import Callable
from typing import TypeVar


_IO_BYTES = 16 * 1024
_DIRECTION_BYTES = 16 * 1024 * 1024
_BIO_BYTES = 256 * 1024
_PUMP_STEPS = 4096
_T = TypeVar("_T")


class WorkloadClientError(ValueError):
    pass


class Budget:
    """One caller-process, nonrenewing monotonic request deadline."""

    def __init__(self, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 100 <= timeout_ms <= 30_000:
            raise WorkloadClientError("workload timeout must be an integer in 100..30000 milliseconds")
        self._pid = os.getpid()
        self._deadline = time.monotonic() + timeout_ms / 1000

    def check(self) -> None:
        if os.getpid() != self._pid or time.monotonic() >= self._deadline:
            raise WorkloadClientError("workload original process or deadline ended")

    def remaining(self) -> float:
        self.check()
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise WorkloadClientError("workload original deadline ended")
        return remaining


def _require_context(context: ssl.SSLContext) -> None:
    if (
        type(context) is not ssl.SSLContext
        or context.sslsocket_class is not ssl.SSLSocket
        or context.sslobject_class is not ssl.SSLObject
        or context.check_hostname is not True
        or context.verify_mode != ssl.CERT_REQUIRED
        or context.minimum_version != ssl.TLSVersion.TLSv1_3
        or context.maximum_version != ssl.TLSVersion.TLSv1_3
        or context.options & getattr(ssl, "OP_IGNORE_UNEXPECTED_EOF", 0)
    ):
        raise WorkloadClientError("workload TLS requires standard verified, named TLS1.3-only contexts")


def _require_name(value: str) -> None:
    if (
        type(value) is not str or not 1 <= len(value) <= 253
        or not value.isascii() or value != value.lower()
        or value.endswith(".") or "%" in value
    ):
        raise WorkloadClientError("workload TLS server name is not canonical bounded ASCII")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not all(
            1 <= len(label) <= 63
            and label[0].isalnum() and label[-1].isalnum()
            and all(character.isalnum() or character == "-" for character in label)
            for label in value.split(".")
        ):
            raise WorkloadClientError("workload TLS server name is not canonical DNS") from None
    else:
        if str(address) != value:
            raise WorkloadClientError("workload TLS server IP spelling is not canonical")


def _endpoint(value: tuple[str, int]) -> tuple[int, tuple]:
    if (
        type(value) is not tuple or len(value) != 2 or type(value[0]) is not str
        or type(value[1]) is not int or not 1 <= value[1] <= 65535
        or not 1 <= len(value[0]) <= 45 or "%" in value[0]
    ):
        raise WorkloadClientError("workload endpoint must be one literal address and nonzero port")
    try:
        address = ipaddress.ip_address(value[0])
    except ValueError as exc:
        raise WorkloadClientError("workload endpoint cannot use DNS") from exc
    effective = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    effective = effective or address
    if (
        str(address) != value[0] or effective.is_unspecified or effective.is_multicast
        or effective == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise WorkloadClientError("workload endpoint must be canonical concrete unicast")
    if isinstance(address, ipaddress.IPv4Address):
        return socket.AF_INET, value
    return socket.AF_INET6, (value[0], value[1], 0, 0)


def _require_peer(stream: socket.socket, endpoint: tuple[str, int]) -> None:
    peer = stream.getpeername()
    if (
        len(peer) not in (2, 4) or peer[1] != endpoint[1]
        or (len(peer) == 4 and (peer[2] != 0 or peer[3] != 0))
        or ipaddress.ip_address(peer[0]) != ipaddress.ip_address(endpoint[0])
    ):
        raise WorkloadClientError("workload connected peer differs from its literal endpoint")


def _require_negotiated(stream: ssl.SSLSocket | ssl.SSLObject) -> None:
    if (
        stream.version() != "TLSv1.3" or stream.session_reused is not False
        or stream.selected_alpn_protocol() not in (None, "http/1.1")
    ):
        raise WorkloadClientError("workload requires fresh TLS1.3 with HTTP/1.1-compatible ALPN")


def _receive_size(maximum: int) -> int:
    if type(maximum) is not int or maximum <= 0:
        raise WorkloadClientError("workload receive size must be a positive integer")
    return min(maximum, _IO_BYTES)


class OuterTLS:
    """One owned outer mTLS socket; no socket or descriptor escape API."""

    def __init__(self) -> None:
        raise WorkloadClientError("construct outer workload TLS with connect")

    @staticmethod
    def connect(endpoint: tuple[str, int], server_name: str, context: ssl.SSLContext,
                budget: Budget) -> OuterTLS:
        if type(budget) is not Budget:
            raise WorkloadClientError("workload TLS requires an original Budget")
        budget.check()
        family, target = _endpoint(endpoint)
        _require_name(server_name)
        _require_context(context)
        owner = object.__new__(OuterTLS)
        owner._socket = None
        owner._budget = budget
        owner._context = context
        owner._read_bytes = 0
        owner._written_bytes = 0
        raw = None
        try:
            raw = socket.socket(family, socket.SOCK_STREAM)
            raw.set_inheritable(False)
            raw.settimeout(min(3.0, budget.remaining()))
            budget.check()
            try:
                raw.connect(target)
            finally:
                budget.check()
            _require_peer(raw, endpoint)
            budget.check()
            owner._socket = context.wrap_socket(
                raw, server_side=False, server_hostname=server_name,
                do_handshake_on_connect=False, suppress_ragged_eofs=False,
            )
            raw = None  # Ownership moved into the SSLSocket.
            budget.check()
            owner._socket.settimeout(budget.remaining())
            budget.check()
            try:
                owner._socket.do_handshake()
            finally:
                budget.check()
            _require_context(context)
            _require_negotiated(owner._socket)
            _require_peer(owner._socket, endpoint)
            owner._check()
            return owner
        except BaseException as exc:
            owner.close()
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass
            if isinstance(exc, WorkloadClientError):
                raise
            if isinstance(exc, (OSError, ValueError)):
                raise WorkloadClientError("workload outer TLS connection failed") from exc
            raise

    def _check(self) -> None:
        self._budget.check()
        if self._socket is None:
            raise WorkloadClientError("workload outer TLS is closed")
        _require_context(self._context)

    def recv(self, maximum: int) -> bytes:
        try:
            self._check()
            count = min(_receive_size(maximum), _DIRECTION_BYTES - self._read_bytes)
            if count <= 0:
                raise WorkloadClientError("workload outer TLS plaintext input exceeds 16MiB")
            self._socket.settimeout(self._budget.remaining())
            self._check()
            try:
                data = self._socket.recv(count)
            except ssl.SSLZeroReturnError:
                data = b""  # Only a clean TLS close, never SSLEOFError.
            finally:
                self._budget.check()
            self._read_bytes += len(data)
            return data
        except BaseException as exc:
            self.close()
            if isinstance(exc, WorkloadClientError):
                raise
            if isinstance(exc, (OSError, ValueError)):
                raise WorkloadClientError("workload outer TLS read failed or was truncated") from exc
            raise

    def sendall(self, data: bytes) -> None:
        try:
            self._check()
            if type(data) is not bytes or len(data) > _DIRECTION_BYTES - self._written_bytes:
                raise WorkloadClientError("workload outer TLS plaintext output exceeds 16MiB or is not bytes")
            offset = 0
            while offset < len(data):
                self._socket.settimeout(self._budget.remaining())
                self._check()
                try:
                    count = self._socket.send(memoryview(data)[offset:offset + _IO_BYTES])
                finally:
                    self._budget.check()
                if count <= 0:
                    raise WorkloadClientError("workload outer TLS write made no progress")
                offset += count
                self._written_bytes += count
            self._check()
        except BaseException as exc:
            self.close()
            if isinstance(exc, WorkloadClientError):
                raise
            if isinstance(exc, (OSError, ValueError)):
                raise WorkloadClientError("workload outer TLS write failed") from exc
            raise

    def close(self) -> None:
        stream, self._socket = self._socket, None
        if stream is not None:
            # Close the owned descriptor only, even after a fork. No shutdown
            # of a parent's shared socket and no unbounded TLS unwrap exchange.
            try:
                stream.close()
            except OSError:
                # Python's socket owner forgets the descriptor on close error;
                # never retry a possibly reused descriptor number.
                pass


class InnerTLS:
    """TLS over the actual outer plaintext channel after admitted CONNECT."""

    def __init__(self, outer: OuterTLS, server_name: str, context: ssl.SSLContext,
                 budget: Budget) -> None:
        if type(outer) is not OuterTLS:
            raise WorkloadClientError("workload inner TLS requires the actual outer owner")
        self._outer = outer
        self._budget = budget
        self._context = context
        self._closed = False
        self._network_eof = False
        self._read_eof = False
        try:
            self._incoming = ssl.MemoryBIO()
            self._outgoing = ssl.MemoryBIO()
            if budget is not outer._budget:
                raise WorkloadClientError("workload inner TLS cannot replace the original budget")
            self._check()
            _require_name(server_name)
            self._ssl = context.wrap_bio(
                self._incoming, self._outgoing, server_side=False, server_hostname=server_name,
            )
            self._check()
            self._run(self._ssl.do_handshake)
            _require_negotiated(self._ssl)
            self._check()
        except BaseException as exc:
            self.close()
            if isinstance(exc, WorkloadClientError):
                raise
            if isinstance(exc, (OSError, ValueError)):
                raise WorkloadClientError("workload inner TLS handshake failed") from exc
            raise

    def _check(self) -> None:
        self._budget.check()
        if self._closed:
            raise WorkloadClientError("workload inner TLS is closed")
        self._outer._check()
        _require_context(self._context)
        if self._incoming.pending > _BIO_BYTES or self._outgoing.pending > _BIO_BYTES:
            raise WorkloadClientError("workload inner TLS BIO exceeds its bound")

    def _drain(self) -> bool:
        progress = False
        while self._outgoing.pending:
            self._check()
            data = self._outgoing.read(_IO_BYTES)
            self._check()
            if not data:
                raise WorkloadClientError("workload inner TLS outgoing BIO made no progress")
            self._outer.sendall(data)
            self._check()
            progress = True
        return progress

    def _feed(self) -> None:
        self._check()
        if self._network_eof:
            raise WorkloadClientError("workload inner TLS requested input after transport EOF")
        data = self._outer.recv(_IO_BYTES)
        self._check()
        if data:
            if self._incoming.pending + len(data) > _BIO_BYTES:
                raise WorkloadClientError("workload inner TLS incoming BIO exceeds its bound")
            if self._incoming.write(data) != len(data):
                raise WorkloadClientError("workload inner TLS incoming BIO made incomplete progress")
        else:
            # Authenticated outer EOF is not authenticated inner EOF. Feed it
            # to OpenSSL so a missing inner close_notify remains SSLEOFError.
            self._incoming.write_eof()
            self._network_eof = True
        self._check()

    def _run(self, operation: Callable[[], _T]) -> _T:
        for _ in range(_PUMP_STEPS):
            self._check()
            try:
                result = operation()
            except ssl.SSLWantReadError:
                self._check()
                self._drain()
                self._feed()
            except ssl.SSLWantWriteError:
                self._check()
                if not self._drain():
                    raise WorkloadClientError("workload inner TLS write requested no available output")
            else:
                self._check()
                self._drain()
                self._check()
                return result
        raise WorkloadClientError("workload inner TLS exceeded its bounded progress steps")

    def recv(self, maximum: int) -> bytes:
        try:
            self._check()
            count = _receive_size(maximum)
            if self._read_eof:
                return b""
            try:
                data = self._run(lambda: self._ssl.read(count))
            except ssl.SSLZeroReturnError:
                self._check()
                self._drain()
                data = b""
            self._check()
            if not data:
                self._read_eof = True
            return data
        except BaseException as exc:
            self.close()
            if isinstance(exc, WorkloadClientError):
                raise
            if isinstance(exc, (OSError, ValueError)):
                raise WorkloadClientError("workload inner TLS read failed or was truncated") from exc
            raise

    def sendall(self, data: bytes) -> None:
        try:
            self._check()
            if type(data) is not bytes or len(data) > _DIRECTION_BYTES or self._read_eof:
                raise WorkloadClientError("workload inner TLS output is invalid, oversized or closed")
            offset = 0
            while offset < len(data):
                self._check()
                chunk = memoryview(data)[offset:offset + _IO_BYTES]
                count = self._run(lambda: self._ssl.write(chunk))
                if not 0 < count <= len(chunk):
                    raise WorkloadClientError("workload inner TLS write made invalid progress")
                offset += count
            self._check()
        except BaseException as exc:
            self.close()
            if isinstance(exc, WorkloadClientError):
                raise
            if isinstance(exc, (OSError, ValueError)):
                raise WorkloadClientError("workload inner TLS write failed") from exc
            raise

    def close(self) -> None:
        self._closed = True
        self._outer.close()
