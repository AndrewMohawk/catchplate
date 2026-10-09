"""Pure, fixed synthetic oracle for the private ordinary-client proxy check.

This is not a general echo endpoint. All cases accept only REQUEST_BODY and a
synthetic injected credential. Nothing returns request headers or their digests.
The explicit V2 cases add fixed ordinary metadata, never caller-selected fields.
Header checks concern physical fields exposed by ASGI, not bytes an HTTP parser
has already rejected or normalized. There are no network or filesystem effects.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
from typing import AsyncIterable, Sequence


FIXTURE_PATH = "/ordinary-client"
MAX_BODY_BYTES = 65536
MAX_HEADER_BYTES = 16384
MAX_HEADER_COUNT = 64
MAX_QUERY_BYTES = 512
BODY_READ_TIMEOUT_SECONDS = 5.0
DUMMY_AUTHORIZATION = "Bearer SERVERWARE_DUMMY"
QUERY_KEYS = ("case", "expectedAuthorizationSha256", "expectedBodySha256")
REQUEST_BODY = (
    b'\n{\n  "z": [1e+02, 18446744073709551617],\n'
    b'  "escaped": "\\u0061\\/b",\n'
    b'  "nested": {"items": [true, null, {"number": 1.2300}]}\n'
    b'}\r\n'
)
JSON_RESPONSE_BODY = REQUEST_BODY
REQUEST_BODY_SHA256 = hashlib.sha256(REQUEST_BODY).hexdigest()
REQUEST_BODY_LENGTH = len(REQUEST_BODY)
EMPTY_RESPONSE_CONTENT_TYPE = "application/json; charset=utf-8"
FIXTURE_CASES = ("json", "empty", "json_v2", "empty_v2")
V2_RESPONSE_METADATA = (
    ("server", "serverware-synthetic-upstream"),
    ("date", "Thu, 01 Jan 1970 00:00:00 GMT"),
    ("cache-control", "no-store"),
)
REJECTION_BODY = b'{"error":"ordinary_client_fixture_rejected"}'

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_QUERY = re.compile(
    rb"case=(json|empty|json_v2|empty_v2)&expectedAuthorizationSha256=([0-9a-f]{64})"
    rb"&expectedBodySha256=([0-9a-f]{64})\Z"
)
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_SYNTHETIC_AUTHORIZATION = re.compile(rb"Bearer synthetic-operator-[A-Za-z0-9_-]{32,128}\Z")
_CONTENT_LENGTH = re.compile(rb"(?:0|[1-9][0-9]{0,4})\Z")


class FixtureRejected(ValueError):
    """A fixed, non-reflecting failure; no input values enter its message."""

    def __init__(self, status_code: int = 400):
        super().__init__("ordinary client fixture rejected")
        self.status_code = status_code


@dataclass(frozen=True)
class Admission:
    case: str
    content_length: int


@dataclass(frozen=True)
class Outcome:
    status_code: int
    body: bytes
    # Deliberately excludes Content-Length: the HTTP serializer owns framing.
    headers: tuple[tuple[str, str], ...]


def build_target(case: str, expected_authorization_sha256: str) -> str:
    """Canonical target used by the checker; body expectations are not caller-set."""
    if (case not in FIXTURE_CASES or not isinstance(expected_authorization_sha256, str)
            or _DIGEST.fullmatch(expected_authorization_sha256) is None):
        raise FixtureRejected()
    return (FIXTURE_PATH + "?case=" + case
            + "&expectedAuthorizationSha256=" + expected_authorization_sha256
            + "&expectedBodySha256=" + REQUEST_BODY_SHA256)


def admit_request(method: str, raw_path: bytes, raw_query: bytes,
                  headers: Sequence[tuple[bytes, bytes]]) -> Admission:
    """Reject malformed declarations before the bounded body is consumed."""
    if method != "POST":
        raise FixtureRejected(405)
    if raw_path != FIXTURE_PATH.encode("ascii"):
        raise FixtureRejected()
    if not isinstance(raw_query, bytes) or len(raw_query) > MAX_QUERY_BYTES:
        raise FixtureRejected()
    query = _QUERY.fullmatch(raw_query)
    if query is None or not hmac.compare_digest(query[3], REQUEST_BODY_SHA256.encode("ascii")):
        raise FixtureRejected()
    if not isinstance(headers, (list, tuple)) or len(headers) > MAX_HEADER_COUNT:
        raise FixtureRejected()
    physical: dict[bytes, list[bytes]] = {}
    total = 0
    for field in headers:
        if not isinstance(field, (tuple, list)) or len(field) != 2:
            raise FixtureRejected()
        name, value = field
        if (not isinstance(name, bytes) or not isinstance(value, bytes)
                or _HEADER_NAME.fullmatch(name) is None):
            raise FixtureRejected()
        total += len(name) + len(value)
        if total > MAX_HEADER_BYTES or any(byte < 32 or byte == 127 for byte in value):
            raise FixtureRejected()
        physical.setdefault(name.lower(), []).append(value)
    if any(name in physical for name in (b"proxy-authorization", b"transfer-encoding", b"trailer")):
        raise FixtureRejected()
    if physical.get(b"content-encoding", []) not in ([], [b"identity"]):
        raise FixtureRejected(415)
    media = physical.get(b"content-type", [])
    if media not in ([b"application/json"], [b"application/json; charset=utf-8"]):
        raise FixtureRejected(415)
    lengths = physical.get(b"content-length", [])
    if len(lengths) != 1 or _CONTENT_LENGTH.fullmatch(lengths[0]) is None:
        raise FixtureRejected()
    content_length = int(lengths[0])
    if content_length > MAX_BODY_BYTES:
        raise FixtureRejected(413)
    if content_length != REQUEST_BODY_LENGTH:
        raise FixtureRejected()
    authorization = physical.get(b"authorization", [])
    if (len(authorization) != 1 or authorization[0] == DUMMY_AUTHORIZATION.encode("ascii")
            or _SYNTHETIC_AUTHORIZATION.fullmatch(authorization[0]) is None
            or not hmac.compare_digest(hashlib.sha256(authorization[0]).hexdigest().encode("ascii"), query[2])):
        raise FixtureRejected()
    return Admission(query[1].decode("ascii"), content_length)


async def read_bounded_body(chunks: AsyncIterable[bytes]) -> bytes:
    """Never retain more than the body bound, including with a dishonest length."""
    body = bytearray()
    async for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise FixtureRejected()
        if len(chunk) > MAX_BODY_BYTES - len(body):
            raise FixtureRejected(413)
        body.extend(chunk)
    return bytes(body)


def verify_body(admission: Admission, body: bytes) -> Outcome:
    """Independent byte, length and digest oracle; no parsing/reserialization."""
    if (not isinstance(admission, Admission) or admission.case not in FIXTURE_CASES
            or admission.content_length != REQUEST_BODY_LENGTH or not isinstance(body, bytes)
            or len(body) != REQUEST_BODY_LENGTH or len(body) > MAX_BODY_BYTES
            or not hmac.compare_digest(hashlib.sha256(body).hexdigest(), REQUEST_BODY_SHA256)
            or body != REQUEST_BODY):
        raise FixtureRejected()
    metadata = V2_RESPONSE_METADATA if admission.case in ("json_v2", "empty_v2") else ()
    if admission.case in ("empty", "empty_v2"):
        return Outcome(204, b"", (("content-type", EMPTY_RESPONSE_CONTENT_TYPE),) + metadata)
    return Outcome(200, body, (("content-type", "application/json"),) + metadata)
