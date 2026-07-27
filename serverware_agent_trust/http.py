from __future__ import annotations

import http.client
import ipaddress
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping


class HttpClientError(ValueError):
    pass


_HTTP_FIELD_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_CONTENT_LENGTH_RE = re.compile(r"^[0-9]+$")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


def validate_http_url(url: str, *, require_https: bool = False) -> urllib.parse.SplitResult:
    if not isinstance(url, str) or not url or any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise HttpClientError("HTTP URL is empty or contains control characters")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise HttpClientError("HTTP URL is malformed") from exc
    allowed_schemes = {"https"} if require_https else {"http", "https"}
    if parsed.scheme.lower() not in allowed_schemes:
        raise HttpClientError("HTTP URL scheme is not allowed")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise HttpClientError("HTTP URL must have a host and cannot contain credentials")
    if parsed.fragment:
        raise HttpClientError("HTTP URL cannot contain a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise HttpClientError("HTTP URL port is out of range")
    return parsed


def _is_explicit_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _is_token_name(name: str) -> bool:
    normalized = name.lower().replace("_", "-")
    return (
        normalized
        in {
            "authorization",
            "cookie",
            "proxy-authorization",
            "x-serverware-agent",
            "x-serverware-enrollment-session",
        }
        or "token" in normalized
        or "api-key" in normalized
        or normalized.endswith("-secret")
    )


def _request_bears_token(req: urllib.request.Request, parsed: urllib.parse.SplitResult) -> bool:
    if any(_is_token_name(name) and bool(value) for name, value in req.header_items()):
        return True
    return any(_is_token_name(name) and bool(value) for name, value in urllib.parse.parse_qsl(parsed.query))


def _validated_response_headers(headers: Any) -> tuple[dict[str, str], int]:
    defects = tuple(getattr(headers, "defects", ()) or ())
    if defects:
        raise HttpClientError("HTTP response headers are malformed")

    raw_items = getattr(headers, "raw_items", None)
    items = list(raw_items() if callable(raw_items) else headers.items())
    normalized: dict[str, str] = {}
    for raw_name, raw_value in items:
        if (
            not isinstance(raw_name, str)
            or raw_name != raw_name.strip()
            or _HTTP_FIELD_NAME_RE.fullmatch(raw_name) is None
        ):
            raise HttpClientError("HTTP response header name is malformed")
        if not isinstance(raw_value, str):
            raise HttpClientError("HTTP response header value is malformed")
        if any(char in raw_value for char in "\r\n\x00"):
            raise HttpClientError("HTTP response header folding or control characters are forbidden")
        value = raw_value.strip(" \t")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise HttpClientError("HTTP response header value contains control characters")
        name = raw_name.lower()
        if name in normalized:
            raise HttpClientError(f"HTTP response contains duplicate {raw_name} header")
        normalized[name] = value

    content_length = normalized.get("content-length")
    transfer_encoding = normalized.get("transfer-encoding")
    if content_length is not None and transfer_encoding is not None:
        raise HttpClientError("HTTP response cannot contain both Content-Length and Transfer-Encoding")
    if transfer_encoding is not None:
        raise HttpClientError("HTTP response Transfer-Encoding is not supported")
    if content_length is None:
        raise HttpClientError("HTTP response requires unambiguous Content-Length framing")
    if _CONTENT_LENGTH_RE.fullmatch(content_length) is None:
        raise HttpClientError("HTTP response Content-Length is invalid")
    return normalized, int(content_length)


def _raw_body_stream(stream: Any) -> Any:
    current = stream
    seen: set[int] = set()
    while id(current) not in seen:
        seen.add(id(current))
        child = getattr(current, "fp", None)
        if child is None:
            break
        current = child
    if current is stream or not callable(getattr(current, "read", None)):
        raise HttpClientError("HTTP response body stream cannot be verified")
    return current


def _bounded_read(
    stream: Any,
    *,
    max_bytes: int,
    content_length: int,
) -> bytes:
    if max_bytes < 1:
        raise HttpClientError("HTTP response limit must be positive")
    if content_length < 0 or content_length > max_bytes:
        raise HttpClientError(f"HTTP response exceeds {max_bytes} bytes")

    raw_stream = _raw_body_stream(stream)
    remaining = content_length
    body = bytearray()
    try:
        while remaining:
            chunk = raw_stream.read(remaining)
            if not chunk:
                raise HttpClientError("HTTP response body ended before Content-Length")
            body.extend(chunk)
            remaining -= len(chunk)
        if raw_stream.read(1):
            raise HttpClientError("HTTP response contains bytes after Content-Length")
    except HttpClientError:
        raise
    except (OSError, ValueError) as exc:
        raise HttpClientError("HTTP response framing could not be verified") from exc
    return bytes(body)


def request_bytes(
    request: str | urllib.request.Request,
    *,
    timeout: float,
    max_bytes: int,
    context: ssl.SSLContext | None = None,
    require_https: bool = False,
    allow_loopback_http_tokens: bool = False,
) -> HttpResponse:
    req = urllib.request.Request(request) if isinstance(request, str) else request
    parsed = validate_http_url(req.full_url, require_https=require_https)
    if parsed.scheme.lower() == "http" and _request_bears_token(req, parsed):
        if not allow_loopback_http_tokens or not _is_explicit_loopback(str(parsed.hostname or "")):
            raise HttpClientError(
                "token-bearing plaintext HTTP is forbidden outside explicit loopback development"
            )
    req.add_unredirected_header("Connection", "close")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )
    try:
        response_context = opener.open(req, timeout=timeout)
    except http.client.HTTPException as exc:
        raise HttpClientError("HTTP response status line or headers are malformed") from exc
    with response_context as response:
        headers, content_length = _validated_response_headers(response.headers)
        body = _bounded_read(
            response,
            max_bytes=max_bytes,
            content_length=content_length,
        )
        return HttpResponse(
            status=int(response.status),
            headers=headers,
            body=body,
        )


def http_error_body(error: urllib.error.HTTPError, *, max_bytes: int) -> bytes:
    _, content_length = _validated_response_headers(error.headers)
    return _bounded_read(
        error,
        max_bytes=max_bytes,
        content_length=content_length,
    )
