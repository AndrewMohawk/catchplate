from __future__ import annotations

import http.client
import json
import math
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any, Mapping


class HttpClientError(ValueError):
    pass


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class HttpDeadline:
    expires_at: float

    @classmethod
    def after(cls, timeout: float) -> HttpDeadline:
        return cls(time.monotonic() + _positive_seconds(timeout, label="HTTP total timeout"))


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_MEDIA_TYPE_RE = re.compile(
    rf"(?P<media>{_TOKEN_RE.pattern}/{_TOKEN_RE.pattern})"
    rf'(?:\s*;\s*charset\s*=\s*(?P<charset>{_TOKEN_RE.pattern}|"[^"\r\n]*"))?\s*',
    re.IGNORECASE,
)
_FORBIDDEN_CONTROLLED_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "cookie",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


def _positive_seconds(value: float, *, label: str) -> float:
    if isinstance(value, bool):
        raise HttpClientError(f"{label} must be a positive finite number")
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise HttpClientError(f"{label} must be a positive finite number") from exc
    if not math.isfinite(seconds) or seconds <= 0:
        raise HttpClientError(f"{label} must be a positive finite number")
    return seconds


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


def _header_values(headers: Any, name: str) -> list[str]:
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name)
        if values is not None:
            return [str(value) for value in values]
    value = headers.get(name) if headers is not None else None
    return [] if value is None else [str(value)]


def _content_length(headers: Any, *, max_bytes: int) -> int | None:
    values = _header_values(headers, "Content-Length")
    if not values:
        return None
    if len(values) != 1:
        raise HttpClientError("HTTP response has duplicate Content-Length headers")
    raw = values[0].strip()
    if not raw.isascii() or not raw.isdigit() or len(raw) > 20:
        raise HttpClientError("HTTP response Content-Length is invalid")
    try:
        declared = int(raw, 10)
    except ValueError as exc:
        raise HttpClientError("HTTP response Content-Length is invalid") from exc
    if declared > max_bytes:
        raise HttpClientError(f"HTTP response exceeds {max_bytes} bytes")
    return declared


def _validate_transfer_encoding(headers: Any, *, has_content_length: bool) -> None:
    values = _header_values(headers, "Transfer-Encoding")
    if not values:
        return
    if has_content_length:
        raise HttpClientError("HTTP response contains both Content-Length and Transfer-Encoding")
    if len(values) != 1 or values[0].strip().lower() != "chunked":
        raise HttpClientError("HTTP response Transfer-Encoding is not supported")


def _validate_content_encoding(headers: Any) -> None:
    values = _header_values(headers, "Content-Encoding")
    if not values:
        return
    if len(values) != 1 or values[0].strip().lower() != "identity":
        raise HttpClientError("HTTP response Content-Encoding is not identity")


def _set_stream_timeout(stream: Any, timeout: float) -> None:
    try:
        stream.fp.raw._sock.settimeout(timeout)
    except (AttributeError, OSError):
        pass


def _remaining_seconds(deadline_at: float) -> float:
    remaining = deadline_at - time.monotonic()
    if remaining <= 0:
        raise HttpClientError("HTTP request deadline exceeded")
    return remaining


def _bounded_read(
    stream: Any,
    *,
    max_bytes: int,
    content_length: int | None = None,
    deadline_at: float | None = None,
) -> bytes:
    if max_bytes < 1:
        raise HttpClientError("HTTP response limit must be positive")
    remaining = max_bytes + 1
    chunks: list[bytes] = []
    read = getattr(stream, "read1", None) or stream.read
    while remaining > 0:
        if deadline_at is not None:
            _set_stream_timeout(stream, _remaining_seconds(deadline_at))
        try:
            chunk = read(min(64 * 1024, remaining))
        except TimeoutError as exc:
            raise HttpClientError("HTTP request deadline exceeded") from exc
        except http.client.IncompleteRead as exc:
            raise HttpClientError("HTTP response body is truncated") from exc
        except http.client.HTTPException as exc:
            raise HttpClientError("HTTP response framing is invalid") from exc
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise HttpClientError("HTTP response body reader returned non-bytes data")
        chunks.append(chunk)
        remaining -= len(chunk)
        if remaining < 0:
            break
    body = b"".join(chunks)
    if len(body) > max_bytes:
        raise HttpClientError(f"HTTP response exceeds {max_bytes} bytes")
    if content_length is not None and len(body) != content_length:
        raise HttpClientError("HTTP response body length does not match Content-Length")
    if deadline_at is not None:
        _remaining_seconds(deadline_at)
    return body


def _effective_deadline(timeout: float, deadline: HttpDeadline | None) -> float:
    now = time.monotonic()
    request_deadline = now + _positive_seconds(timeout, label="HTTP request timeout")
    if deadline is None:
        return request_deadline
    if not isinstance(deadline, HttpDeadline) or not math.isfinite(deadline.expires_at):
        raise HttpClientError("HTTP shared deadline is invalid")
    if deadline.expires_at <= now:
        raise HttpClientError("HTTP shared deadline exceeded")
    return min(request_deadline, deadline.expires_at)


def _normalized_statuses(statuses: Collection[int]) -> frozenset[int]:
    try:
        normalized = frozenset(statuses)
    except TypeError as exc:
        raise HttpClientError("HTTP expected statuses are invalid") from exc
    if not normalized or any(
        isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599
        for status in normalized
    ):
        raise HttpClientError("HTTP expected statuses are invalid")
    return normalized


def _normalized_media_types(media_types: Collection[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in media_types:
        media_type = value.strip().lower() if isinstance(value, str) else ""
        if not _TOKEN_RE.fullmatch(media_type.split("/", 1)[0] if "/" in media_type else ""):
            raise HttpClientError("HTTP expected content types are invalid")
        if not re.fullmatch(rf"{_TOKEN_RE.pattern}/{_TOKEN_RE.pattern}", media_type):
            raise HttpClientError("HTTP expected content types are invalid")
        normalized.append(media_type)
    if not normalized or len(set(normalized)) != len(normalized):
        raise HttpClientError("HTTP expected content types are invalid")
    return tuple(normalized)


def _response_media_type(headers: Any, *, expected: Collection[str]) -> str:
    values = _header_values(headers, "Content-Type")
    if len(values) != 1:
        raise HttpClientError("HTTP response must contain exactly one Content-Type header")
    match = _MEDIA_TYPE_RE.fullmatch(values[0])
    if match is None:
        raise HttpClientError("HTTP response Content-Type is invalid")
    media_type = match.group("media").lower()
    charset = match.group("charset")
    if charset is not None and charset.strip('"').lower() not in {"utf-8", "utf8"}:
        raise HttpClientError("HTTP JSON response charset must be UTF-8")
    if media_type not in _normalized_media_types(expected):
        raise HttpClientError(f"HTTP response Content-Type {media_type!r} is not allowed")
    return media_type


def _controlled_headers(headers: Mapping[str, str], *, accept: Collection[str]) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        raise HttpClientError("HTTP request headers must be an explicit mapping")
    controlled: dict[str, str] = {}
    seen: set[str] = set()
    expected_accept = ", ".join(_normalized_media_types(accept))
    for name, value in headers.items():
        if not isinstance(name, str) or not _TOKEN_RE.fullmatch(name):
            raise HttpClientError("HTTP request header name is invalid")
        normalized = name.lower()
        if normalized in seen or normalized in _FORBIDDEN_CONTROLLED_HEADERS:
            raise HttpClientError(f"HTTP request header {name!r} is not allowed")
        if not isinstance(value, str) or any(
            ord(char) < 32 or ord(char) == 127 for char in value
        ):
            raise HttpClientError(f"HTTP request header {name!r} has an invalid value")
        try:
            encoded = value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise HttpClientError(f"HTTP request header {name!r} has an invalid value") from exc
        if len(encoded) > 16 * 1024:
            raise HttpClientError(f"HTTP request header {name!r} has an invalid value")
        if normalized == "accept" and value.strip().lower() != expected_accept:
            raise HttpClientError("HTTP request header 'Accept' is not allowed")
        if normalized == "accept-encoding" and value.strip().lower() != "identity":
            raise HttpClientError("HTTP request header 'Accept-Encoding' is not allowed")
        seen.add(normalized)
        controlled[name] = value
    if "accept" not in seen:
        controlled["Accept"] = expected_accept
    if "accept-encoding" not in seen:
        controlled["Accept-Encoding"] = "identity"
    return controlled


def _strict_json_loads(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HttpClientError("HTTP JSON response is not valid UTF-8") from exc

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise HttpClientError(f"HTTP JSON response contains duplicate object key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise HttpClientError(f"HTTP JSON response contains non-finite number: {value}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise HttpClientError("HTTP JSON response contains a non-finite number")
        return parsed

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_float=finite_float,
            parse_constant=reject_constant,
        )
    except HttpClientError:
        raise
    except (json.JSONDecodeError, OverflowError, RecursionError, ValueError) as exc:
        raise HttpClientError("HTTP response is not valid JSON") from exc


def request_bytes(
    request: str | urllib.request.Request,
    *,
    timeout: float,
    max_bytes: int,
    context: ssl.SSLContext | None = None,
    require_https: bool = False,
    deadline: HttpDeadline | None = None,
    expected_statuses: Collection[int] | None = None,
    expected_content_types: Collection[str] | None = None,
) -> HttpResponse:
    req = urllib.request.Request(request) if isinstance(request, str) else request
    validate_http_url(req.full_url, require_https=require_https)
    deadline_at = _effective_deadline(timeout, deadline)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )
    opener.addheaders = []
    with opener.open(req, timeout=_remaining_seconds(deadline_at)) as response:
        status = int(response.status)
        if expected_statuses is not None and status not in _normalized_statuses(expected_statuses):
            raise HttpClientError(f"HTTP response status {status} is not allowed")
        if expected_content_types is not None:
            _response_media_type(response.headers, expected=expected_content_types)
        content_length = _content_length(response.headers, max_bytes=max_bytes)
        _validate_transfer_encoding(
            response.headers,
            has_content_length=content_length is not None,
        )
        _validate_content_encoding(response.headers)
        body = _bounded_read(
            response,
            max_bytes=max_bytes,
            content_length=content_length,
            deadline_at=deadline_at,
        )
        return HttpResponse(
            status=status,
            headers={key.lower(): value for key, value in response.headers.items()},
            body=body,
        )


def http_error_body(error: urllib.error.HTTPError, *, max_bytes: int) -> bytes:
    content_length = _content_length(error.headers, max_bytes=max_bytes)
    _validate_transfer_encoding(error.headers, has_content_length=content_length is not None)
    _validate_content_encoding(error.headers)
    return _bounded_read(
        error,
        max_bytes=max_bytes,
        content_length=content_length,
    )


def request_json(
    url: str,
    *,
    headers: Mapping[str, str],
    timeout: float,
    max_bytes: int,
    deadline: HttpDeadline | None = None,
    context: ssl.SSLContext | None = None,
    require_https: bool = True,
    expected_statuses: Collection[int] = (200,),
    expected_content_types: Collection[str] = ("application/json",),
) -> Any:
    statuses = _normalized_statuses(expected_statuses)
    media_types = _normalized_media_types(expected_content_types)
    request = urllib.request.Request(
        url,
        headers=_controlled_headers(headers, accept=media_types),
        method="GET",
    )
    try:
        response = request_bytes(
            request,
            timeout=timeout,
            max_bytes=max_bytes,
            context=context,
            require_https=require_https,
            deadline=deadline,
            expected_statuses=statuses,
            expected_content_types=media_types,
        )
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.close()
        raise HttpClientError(f"HTTP response status {status} is not allowed") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise HttpClientError("HTTP request deadline exceeded") from exc
        raise HttpClientError("HTTP transport failed") from exc
    except TimeoutError as exc:
        raise HttpClientError("HTTP request deadline exceeded") from exc
    except http.client.HTTPException as exc:
        raise HttpClientError("HTTP transport failed") from exc
    except OSError as exc:
        raise HttpClientError("HTTP transport failed") from exc
    return _strict_json_loads(response.body)
