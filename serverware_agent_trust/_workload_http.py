"""Bounded HTTP/1.1 framing for the explicit ordinary-workload client.

No request is sent by the encoders. The caller owns URL admission, the actual
outer/inner TLS streams and final closure. Framed responses are ordinary data,
not proof of authorization, delivery or a successful upstream operation.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from ._workload_stream import Budget, WorkloadClientError


MAX_REQUEST_HEAD_BYTES = 32 * 1024
MAX_RESPONSE_HEAD_BYTES = 64 * 1024
MAX_FIELDS = 128
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_TRAILER_BYTES = 16 * 1024
MAX_CHUNK_LINE_BYTES = 64
MAX_CHUNKS = 65_536
_IO_BYTES = 16 * 1024
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_LENGTH = re.compile(r"(?:0|[1-9][0-9]*)")
_CHUNK = re.compile(rb"[0-9A-Fa-f]+")
_RESERVED = frozenset({
    "host", "connection", "content-length", "transfer-encoding", "trailer",
    "upgrade", "expect", "te", "keep-alive", "proxy-connection",
})
_FORBIDDEN_TRAILERS = _RESERVED | frozenset({"proxy-authenticate", "proxy-authorization"})


class ByteStream(Protocol):
    def recv(self, maximum: int) -> bytes: ...
    def sendall(self, data: bytes) -> None: ...


@dataclass(frozen=True)
class WorkloadResponse:
    phase: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    trailers: tuple[tuple[str, str], ...]


def _authority(value: str) -> None:
    # The controller supplies canonical host/port spelling. This check prevents
    # request-line/Host injection; it is not independent endpoint admission.
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 512
        or not value.isascii()
        or any(ord(char) <= 32 or ord(char) >= 127 or char in "/\\?#@" for char in value)
    ):
        raise WorkloadClientError("workload HTTP authority is invalid")


def _headers(values: Mapping[str, str], *, proxy: bool) -> list[tuple[str, str]]:
    if not isinstance(values, Mapping) or len(values) > MAX_FIELDS:
        raise WorkloadClientError("workload HTTP header inventory exceeds its bound")
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    size = 0
    for name, value in values.items():
        if (
            len(result) >= MAX_FIELDS
            or not isinstance(name, str)
            or not isinstance(value, str)
            or not 1 <= len(name) <= MAX_REQUEST_HEAD_BYTES
            or len(value) > MAX_REQUEST_HEAD_BYTES
            or not name.isascii()
            or not value.isascii()
            or _TOKEN.fullmatch(name) is None
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise WorkloadClientError("workload HTTP header syntax is invalid")
        lower = name.lower()
        if lower in seen or lower in _RESERVED:
            raise WorkloadClientError("workload HTTP header repeats or overrides framing")
        if not proxy and (lower.startswith("proxy-") or lower == "x-serverware-enrollment-session"):
            raise WorkloadClientError("proxy-only header cannot enter a provider request")
        size += len(name) + len(value) + 4
        if size > MAX_REQUEST_HEAD_BYTES:
            raise WorkloadClientError("workload HTTP headers exceed their byte bound")
        seen.add(lower)
        result.append((name, value))
    return result


def _encode_head(start: str, fields: list[tuple[str, str]]) -> bytes:
    if len(fields) > MAX_FIELDS:
        raise WorkloadClientError("workload HTTP header count exceeds its bound")
    size = len(start) + 2 + sum(len(name) + len(value) + 4 for name, value in fields) + 2
    if size > MAX_REQUEST_HEAD_BYTES:
        raise WorkloadClientError("workload HTTP request head exceeds its byte bound")
    return (start + "\r\n" + "".join(f"{name}: {value}\r\n" for name, value in fields)
        + "\r\n").encode("ascii")


def encode_connect(authority: str, headers: Mapping[str, str]) -> bytes:
    _authority(authority)
    fields = [("Host", authority), *_headers(headers, proxy=True)]
    # No close directive or body framing: the successful connection becomes
    # the inner TLS byte stream, rather than ending at the CONNECT response.
    return _encode_head(f"CONNECT {authority} HTTP/1.1", fields)


def encode_request(method: str, target: str, authority: str,
    headers: Mapping[str, str], body: bytes, *,
    proxy_headers: Mapping[str, str] | None = None) -> bytes:
    if not isinstance(method, str) or method not in _METHODS:
        raise WorkloadClientError("workload HTTP method is unsupported")
    _authority(authority)
    if (
        not isinstance(target, str)
        or not 1 <= len(target) <= MAX_REQUEST_HEAD_BYTES
        or not target.isascii()
        or any(ord(char) <= 32 or ord(char) >= 127 or char in "\\#" for char in target)
    ):
        raise WorkloadClientError("workload HTTP request target is invalid")
    if proxy_headers is None:
        if not target.startswith("/"):
            raise WorkloadClientError("inner workload HTTP request requires origin form")
    else:
        prefix = "http://" + authority
        if not target.startswith(prefix) or target[len(prefix):len(prefix) + 1] not in {"", "/", "?"}:
            raise WorkloadClientError("proxy headers require the exact absolute HTTP authority")
    if not isinstance(body, bytes) or len(body) > MAX_BODY_BYTES or (method == "HEAD" and body):
        raise WorkloadClientError("workload HTTP request body is invalid or exceeds its bound")
    fields = _headers(headers, proxy=False)
    if proxy_headers is not None:
        outer = _headers(proxy_headers, proxy=True)
        names = {name.lower() for name, _ in fields}
        if any(name.lower() in names for name, _ in outer):
            raise WorkloadClientError("provider and proxy headers overlap")
        fields.extend(outer)
    fields = [("Host", authority), ("Content-Length", str(len(body))),
        ("Connection", "close"), *fields]
    return _encode_head(f"{method} {target} HTTP/1.1", fields) + body


def _recv(stream: ByteStream, budget: Budget, maximum: int) -> bytes:
    budget.check()
    try:
        data = stream.recv(maximum)
    except WorkloadClientError:
        raise
    except (OSError, ValueError) as exc:
        raise WorkloadClientError("workload HTTP stream read failed") from exc
    budget.check()
    if not isinstance(data, bytes) or len(data) > maximum:
        raise WorkloadClientError("workload HTTP stream violated its read bound")
    return data


def _line(stream: ByteStream, budget: Budget, maximum: int) -> tuple[bytes, int]:
    original = bytearray()
    while len(original) < maximum:
        byte = _recv(stream, budget, 1)
        if not byte:
            raise WorkloadClientError("workload HTTP line ended before CRLF")
        if byte == b"\n":
            if not original or original[-1] != 13:
                raise WorkloadClientError("workload HTTP line contains a bare LF")
            return bytes(original[:-1]), len(original) + 1
        if original and original[-1] == 13:
            raise WorkloadClientError("workload HTTP line contains a bare CR")
        original.extend(byte)
    raise WorkloadClientError("workload HTTP line exceeds its byte bound")


def _field(line: bytes) -> tuple[str, str]:
    name, separator, value = line.partition(b":")
    if not separator:
        raise WorkloadClientError("workload HTTP header lacks a field separator")
    try:
        decoded_name = name.decode("ascii")
    except UnicodeError as exc:
        raise WorkloadClientError("workload HTTP field name is not ASCII") from exc
    if _TOKEN.fullmatch(decoded_name) is None:
        raise WorkloadClientError("workload HTTP field name or folding is invalid")
    if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
        raise WorkloadClientError("workload HTTP field value contains controls")
    # Preserve received obs-text without guessing UTF-8 or merging repeated
    # fields such as Set-Cookie. Only HTTP optional whitespace is removed.
    return decoded_name, value.strip(b" \t").decode("latin-1")


def _read_fields(stream: ByteStream, budget: Budget, maximum: int,
    forbidden: frozenset[str] = frozenset()) -> tuple[tuple[str, str], ...]:
    fields: list[tuple[str, str]] = []
    consumed = 0
    while True:
        line, size = _line(stream, budget, maximum - consumed)
        consumed += size
        if not line:
            return tuple(fields)
        if len(fields) >= MAX_FIELDS:
            raise WorkloadClientError("workload HTTP response has too many fields")
        field = _field(line)
        if field[0].lower() in forbidden:
            raise WorkloadClientError("workload HTTP trailer contains a framing or hop field")
        fields.append(field)


def _tokens(values: list[str]) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        for part in value.split(","):
            token = part.strip(" \t")
            if _TOKEN.fullmatch(token) is None:
                raise WorkloadClientError("workload HTTP hop field has invalid tokens")
            tokens.add(token.lower())
    return tokens


def _append_body(stream: ByteStream, budget: Budget, body: bytearray, count: int) -> None:
    while count:
        chunk = _recv(stream, budget, min(count, _IO_BYTES))
        if not chunk:
            raise WorkloadClientError("workload HTTP body ended before its framing boundary")
        body.extend(chunk)
        count -= len(chunk)


def _chunked(stream: ByteStream, budget: Budget, maximum: int,
    forbidden: frozenset[str]) -> tuple[bytes, tuple[tuple[str, str], ...]]:
    body = bytearray()
    for _ in range(MAX_CHUNKS):
        line, _ = _line(stream, budget, MAX_CHUNK_LINE_BYTES)
        if _CHUNK.fullmatch(line) is None:
            raise WorkloadClientError("workload HTTP chunk size or extension is unsupported")
        count = int(line, 16)
        if count == 0:
            trailers = _read_fields(stream, budget, MAX_TRAILER_BYTES, forbidden)
            return bytes(body), trailers
        if count > maximum - len(body):
            raise WorkloadClientError("workload HTTP chunked body exceeds its byte bound")
        _append_body(stream, budget, body, count)
        ending = bytearray()
        _append_body(stream, budget, ending, 2)
        if ending != b"\r\n":
            raise WorkloadClientError("workload HTTP chunk data lacks its closing CRLF")
    raise WorkloadClientError("workload HTTP chunk count exceeds its bound")


def read_response(stream: ByteStream, budget: Budget, *, method: str,
    max_response_bytes: int, phase: str) -> WorkloadResponse:
    budget.check()
    if (
        not isinstance(phase, str)
        or phase not in {"connect", "response"}
        or not isinstance(method, str)
        or (phase == "connect" and method != "CONNECT")
        or (phase == "response" and method not in _METHODS)
        or type(max_response_bytes) is not int
        or not 1 <= max_response_bytes <= MAX_BODY_BYTES
    ):
        raise WorkloadClientError("workload HTTP response parameters are invalid")
    status_line, used = _line(stream, budget, MAX_RESPONSE_HEAD_BYTES)
    if (
        len(status_line) < 13
        or status_line[:9] != b"HTTP/1.1 "
        or status_line[12:13] != b" "
        or any(byte < 48 or byte > 57 for byte in status_line[9:12])
        or any(byte < 32 and byte != 9 or byte == 127 for byte in status_line[13:])
    ):
        raise WorkloadClientError("workload HTTP status line is invalid")
    status = int(status_line[9:12])
    if not 200 <= status <= 599:
        raise WorkloadClientError("workload HTTP interim or unsupported status is rejected")
    headers = _read_fields(stream, budget, MAX_RESPONSE_HEAD_BYTES - used)
    values: dict[str, list[str]] = {}
    for name, value in headers:
        values.setdefault(name.lower(), []).append(value)
    lengths = values.get("content-length", [])
    codings = values.get("transfer-encoding", [])
    if len(lengths) > 1 or len(codings) > 1 or (lengths and codings):
        raise WorkloadClientError("workload HTTP response framing is ambiguous")
    length: int | None = None
    if lengths:
        value = lengths[0]
        if len(value) > 20 or _LENGTH.fullmatch(value) is None:
            raise WorkloadClientError("workload HTTP Content-Length is not canonical")
        length = int(value)
        if length > 2**64 - 1:
            raise WorkloadClientError("workload HTTP Content-Length exceeds its integer bound")
    if codings and codings[0].lower() != "chunked":
        raise WorkloadClientError("workload HTTP transfer coding is unsupported")
    connection_tokens = _tokens(values.get("connection", []))
    if "upgrade" in values or "upgrade" in connection_tokens:
        raise WorkloadClientError("workload HTTP protocol upgrades are unsupported")
    forbidden = _FORBIDDEN_TRAILERS | frozenset(connection_tokens)
    if _tokens(values.get("trailer", [])) & forbidden:
        raise WorkloadClientError("workload HTTP trailer declaration contains a forbidden field")
    body = b""
    trailers: tuple[tuple[str, str], ...] = ()
    if phase == "connect" and status == 200:
        if codings or length not in {None, 0} or "trailer" in values:
            raise WorkloadClientError("successful CONNECT response cannot carry a body")
        # Do not probe for EOF or read a surplus byte: the next byte belongs to
        # the tunnel, not this response. TLS itself may already have buffered it.
    elif status == 204:
        if codings or length not in {None, 0} or "trailer" in values:
            raise WorkloadClientError("workload HTTP 204 response has body framing")
    elif method == "HEAD" or status == 304:
        # Valid representation length/coding metadata does not describe an
        # actual message body in these responses; consume no payload bytes.
        pass
    elif codings:
        body, trailers = _chunked(stream, budget, max_response_bytes, forbidden)
    elif length is not None:
        if "trailer" in values:
            raise WorkloadClientError("workload HTTP trailers require chunked framing")
        if length > max_response_bytes:
            raise WorkloadClientError("workload HTTP response body exceeds its byte bound")
        collected = bytearray()
        _append_body(stream, budget, collected, length)
        body = bytes(collected)
    else:
        raise WorkloadClientError("close-delimited workload HTTP responses are unsupported")
    budget.check()
    # Exact framing, not peer EOF, completes this ordinary response. The caller
    # closes its owned connection and never pools or reuses surplus bytes.
    return WorkloadResponse(phase, status, headers, body, trailers)
