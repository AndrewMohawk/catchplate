from __future__ import annotations

import ipaddress
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Mapping


class HttpClientError(ValueError):
    pass


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


def _bounded_read(stream, *, max_bytes: int, content_length: str | None = None) -> bytes:  # type: ignore[no-untyped-def]
    if max_bytes < 1:
        raise HttpClientError("HTTP response limit must be positive")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise HttpClientError("HTTP response Content-Length is invalid") from exc
        if declared < 0 or declared > max_bytes:
            raise HttpClientError(f"HTTP response exceeds {max_bytes} bytes")
    body = stream.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise HttpClientError(f"HTTP response exceeds {max_bytes} bytes")
    return body


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
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )
    with opener.open(req, timeout=timeout) as response:
        body = _bounded_read(
            response,
            max_bytes=max_bytes,
            content_length=response.headers.get("Content-Length"),
        )
        return HttpResponse(
            status=int(response.status),
            headers={key.lower(): value for key, value in response.headers.items()},
            body=body,
        )


def http_error_body(error: urllib.error.HTTPError, *, max_bytes: int) -> bytes:
    return _bounded_read(
        error,
        max_bytes=max_bytes,
        content_length=error.headers.get("Content-Length") if error.headers else None,
    )
