"""One-shot X OAuth HTTPS capture, not work admission or credential authority.

The lifecycle must durably claim dispatch before calling ``send`` outside its
publication/database locks. It must encrypt the returned capture (including an
interruption capture) BEFORE classification, clock checks or adoption. A partial
body is never a complete OAuth response, even when it happens to be valid JSON.

Only the fixed protocol requests are sendable. TLS verifies api.x.com, proxies,
redirects and retries are absent, and the original monotonic deadline is never
renewed. http.client owns HTTP interpretation. The bounded raw reader retains
received wire bytes even when HTTP parsing fails before returning body bytes.
Constructor seals are process-local correlation, not hostile-Python isolation,
durable replay protection, native evidence or permission to retire work.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import io
import math
import queue
import re
import socket
import ssl
import threading
import time
from uuid import UUID

from catchplate.http_client import HttpDeadline
from catchplate import operator_x_oauth_protocol as protocol

MAX_SEND_SECONDS = 20.0
MAX_HEADER_BYTES = 16 * 1024
MAX_WIRE_OVERHEAD = 64 * 1024
_CHUNK = 16 * 1024
_ERROR = "operator X OAuth transport refused"
_INTERRUPTED = "operator X OAuth transport interrupted"
_SEAL = object()
_RESOLVER_SLOT = threading.BoundedSemaphore(1)
_LIMITS = {"code": protocol.MAX_TOKEN_RESPONSE_BYTES,
    "refresh": protocol.MAX_TOKEN_RESPONSE_BYTES,
    "identity": protocol.MAX_IDENTITY_RESPONSE_BYTES,
    "revoke": protocol.MAX_REVOKE_RESPONSE_BYTES}
_PATHS = {"code": "/2/oauth2/token", "refresh": "/2/oauth2/token",
    "identity": "/2/users/me", "revoke": "/2/oauth2/revoke"}
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)


class TransportError(ValueError):
    def __init__(self):
        super().__init__(_ERROR)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class CapturedResponse:
    request: protocol.Request = field(repr=False)
    work_id: str
    profile_binding_digest: str
    deadline: HttpDeadline = field(repr=False)
    status: int | None
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)
    wire_prefix: bytes = field(repr=False)
    complete: bool
    outcome: str
    _seal: object = field(repr=False)

    def __repr__(self):
        return "CapturedResponse(private=True)"


class TransportInterrupted(BaseException):
    """Retain ``capture`` and hold work before propagating cancellation."""
    def __init__(self, capture):
        super().__init__(_INTERRUPTED)
        self.capture = capture

    def __repr__(self):
        return "TransportInterrupted(" + repr(_INTERRUPTED) + ")"


def _need(condition):
    if not condition:
        raise TransportError()


def _remaining(expires_at):
    value = expires_at - time.monotonic()
    _need(math.isfinite(value) and value > 0)
    return value


def _inputs(request, work_id, deadline):
    try:
        protocol._request(request, frozenset(_LIMITS))
        _need(type(work_id) is str and str(UUID(work_id)) == work_id)
        _need(type(deadline) is HttpDeadline
            and type(deadline.expires_at) in {int, float}
            and math.isfinite(deadline.expires_at))
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise TransportError() from None


def _capture(request, work_id, deadline, status, headers, body, wire, complete):
    result = object.__new__(CapturedResponse)
    for name, value in (("request", request), ("work_id", work_id),
            ("profile_binding_digest", request.profile.binding_digest),
            ("deadline", deadline), ("status", status), ("headers", headers),
            ("body", bytes(body)), ("wire_prefix", bytes(wire)),
            ("complete", complete), ("outcome", "complete" if complete else "uncertain"),
            ("_seal", _SEAL)):
        object.__setattr__(result, name, value)
    return result


def require_capture(value, *, request, work_id, deadline):
    """Correlate a live capture; intentionally do not reject late retention."""
    _inputs(request, work_id, deadline)
    _need(type(value) is CapturedResponse and getattr(value, "_seal", None) is _SEAL
        and value.request is request and value.work_id == work_id
        and value.deadline is deadline
        and value.profile_binding_digest == request.profile.binding_digest)


def _resolve(expires_at):
    # libc DNS has no Python socket timeout. One credential-free daemon may
    # finish after this caller's deadline, but it cannot connect or send HTTP.
    # A stuck resolver blocks new resolutions, not a growing thread backlog.
    _need(_RESOLVER_SLOT.acquire(blocking=False))
    result = queue.Queue(maxsize=1)

    def lookup():
        try:
            addresses = socket.getaddrinfo("api.x.com", 443, type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP)
            address = next((item for item in addresses if item[0] in
                {socket.AF_INET, socket.AF_INET6}), None)
            result.put_nowait(address)
        except BaseException:
            result.put_nowait(None)
        finally:
            _RESOLVER_SLOT.release()

    thread = threading.Thread(target=lookup, name="operator-x-dns", daemon=True)
    try:
        thread.start()
    except BaseException:
        _RESOLVER_SLOT.release()
        raise
    try:
        address = result.get(timeout=_remaining(expires_at))
    except queue.Empty:
        raise TransportError() from None
    _remaining(expires_at)
    _need(address is not None)
    return address


def _connect(expires_at):
    address = _resolve(expires_at)
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    _need(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED)
    context.set_alpn_protocols(["http/1.1"])
    raw = socket.socket(address[0], socket.SOCK_STREAM, socket.IPPROTO_TCP)
    tls = None
    try:
        raw.settimeout(_remaining(expires_at))
        raw.connect(address[4])
        raw.settimeout(_remaining(expires_at))
        tls = context.wrap_socket(raw, server_hostname="api.x.com", do_handshake_on_connect=False,
            suppress_ragged_eofs=False)
        tls.settimeout(_remaining(expires_at))
        tls.do_handshake()
        _remaining(expires_at)
        _need(tls.selected_alpn_protocol() in {None, "http/1.1"})
        return tls
    except BaseException:
        (tls if tls is not None else raw).close()
        raise


class _CapturedReader(io.RawIOBase):
    def __init__(self, stream, expires_at, wire, maximum):
        self.stream, self.expires_at = stream, expires_at
        self.wire, self.maximum = wire, maximum

    def readable(self):
        return True

    def readinto(self, buffer):
        self.stream.settimeout(_remaining(self.expires_at))
        # Capture before checking bounds/deadline: bytes received at the boundary
        # remain private custody material even though they cannot be accepted.
        data = self.stream.recv(min(len(buffer), _CHUNK, self.maximum - len(self.wire) + 1))
        _need(type(data) is bytes)
        available = self.maximum - len(self.wire)
        self.wire.extend(data[:available])
        _need(len(data) <= available)
        _remaining(self.expires_at)
        buffer[:len(data)] = data
        return len(data)


class _ResponseSocket:
    def __init__(self, stream, expires_at, wire, maximum):
        self.reader = _CapturedReader(stream, expires_at, wire, maximum)

    def makefile(self, mode):
        _need(mode == "rb")
        return io.BufferedReader(self.reader, buffer_size=4096)


class _DeadlineWriter:
    def __init__(self, stream, expires_at):
        self.stream, self.expires_at = stream, expires_at

    def sendall(self, data):
        self.stream.settimeout(_remaining(self.expires_at))
        self.stream.sendall(data)
        _remaining(self.expires_at)


def _headers(response):
    pairs = tuple(response.getheaders())
    _need(len(pairs) <= 64)
    total = 0
    for name, value in pairs:
        _need(type(name) is str and _TOKEN.fullmatch(name)
            and type(value) is str and all(32 <= ord(c) <= 126 or c == "\t" for c in value))
        total += len(name) + len(value)
    _need(total <= MAX_HEADER_BYTES and not response.headers.defects)
    return pairs


def _framing(headers):
    selected = {}
    for name, value in headers:
        name = name.lower()
        if name in {"content-length", "transfer-encoding"}:
            _need(name not in selected)
            selected[name] = value
    length = selected.get("content-length")
    transfer = selected.get("transfer-encoding")
    _need(length is None or re.fullmatch(r"0|[1-9][0-9]{0,8}", length))
    _need(transfer is None or (transfer.lower() == "chunked" and length is None))
    return int(length) if length is not None else None


def send(request, *, work_id, deadline):
    """Capture exactly one fixed request, after the caller's durable claim.

    No classifier is invoked here. A complete capture can still represent a
    redirect, non-JSON response, reflected secret or OAuth failure; the existing
    phase codec must decide that only AFTER encrypted retention. Interruptions
    carry the same private capture and must not escape retention/hold handling.
    """
    _inputs(request, work_id, deadline)
    started = time.monotonic()
    expires_at = min(deadline.expires_at, started + MAX_SEND_SECONDS)
    _remaining(expires_at)
    maximum = _LIMITS[request.phase]
    status, headers, complete = None, (), False
    body, wire = bytearray(), bytearray()
    stream, response = None, None
    interrupted = False
    try:
        stream = _connect(expires_at)
        # No urllib opener, proxy lookup, ambient headers, redirect or retry.
        # http.client emits the validated method/headers with fixed framing.
        connection = http.client.HTTPConnection("api.x.com", 443)
        connection.sock = _DeadlineWriter(stream, expires_at)
        connection.putrequest(request.method, _PATHS[request.phase], skip_host=True,
            skip_accept_encoding=True)
        connection.putheader("Host", "api.x.com")
        for name, value in request.headers:
            connection.putheader(name, value)
        connection.putheader("Connection", "close")
        if request.method == "POST":
            connection.putheader("Content-Length", str(len(request.body)))
        stream.settimeout(_remaining(expires_at))
        connection.endheaders(request.body or None)
        _remaining(expires_at)
        response = http.client.HTTPResponse(
            _ResponseSocket(stream, expires_at, wire, maximum + MAX_WIRE_OVERHEAD),
            method=request.method)
        response.begin()
        status = response.status
        headers = _headers(response)
        expected = _framing(headers)
        while True:
            _remaining(expires_at)
            piece = response.read1(min(_CHUNK, maximum - len(body) + 1))
            _need(type(piece) is bytes)
            room = maximum - len(body)
            body.extend(piece[:room])
            _need(len(piece) <= room)
            if not piece:
                break
        _need(expected is None or expected == len(body))
        _remaining(expires_at)
        complete = True
    except Exception:
        # No exception text, provider error string or headers are logged/raised.
        complete = False
    except BaseException:
        complete = False
        interrupted = True
    finally:
        # Closing an owned stream cannot turn an incomplete result into success
        # or discard already collected material by replacing the fixed result.
        for owned in (response, stream):
            if owned is not None:
                try:
                    owned.close()
                except BaseException:
                    complete = False
    capture = _capture(request, work_id, deadline, status, headers, body, wire, complete)
    if interrupted:
        raise TransportInterrupted(capture) from None
    return capture
