"""Closed, bounded physical-header admission for the additive response V2 mode.

This is parsed-field evidence, not proof about bytes hidden by an HTTP parser.
No unlisted name/value is included in errors or retained in the returned view.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable

RESPONSE_MODE = "bufferedJsonOrEmpty204V2"
UNLISTED_HEADER_POLICY = "discardUnselectedV1"
MAX_FIELDS = 128
MAX_TOTAL_BYTES = 65536
MAX_NAME_BYTES = 128
MAX_VALUE_BYTES = 8192
TRANSPORT_HEADERS = frozenset({
    "connection", "content-encoding", "content-length", "content-type",
    "keep-alive", "proxy-authenticate", "proxy-connection", "te", "trailer",
    "transfer-encoding", "upgrade",
})
_SECURITY_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie"})
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


def reserved_policy_name(name: str) -> bool:
    classified = name.lower().replace("_", "-")
    return (classified in TRANSPORT_HEADERS or classified in _SECURITY_HEADERS
        or classified.startswith("x-catchplate-"))


class HeaderCompatibilityError(ValueError):
    """Only fixed error codes and bounded aggregate counts cross this boundary."""

    def __init__(self, code: str, field_count: int = 0, byte_count: int = 0):
        super().__init__(code)
        self.code = code
        self.field_count = min(max(field_count, 0), MAX_FIELDS + 1)
        self.byte_count = min(max(byte_count, 0), MAX_TOTAL_BYTES + 1)

    def payload(self) -> dict:
        return {"error": self.code, "headerCount": self.field_count,
            "headerBytes": self.byte_count}


def inspect_physical_headers(
    fields: object,
    *,
    listed_names: Iterable[str],
    detects_secret: Callable[[bytes], bool] | None = None,
    require_secret_guard: bool = False,
) -> list[tuple[str, str]]:
    """Validate every physical field, then return only transport/listed fields.

Duplicates are allowed only for unlisted, nonreserved metadata. Classification
aliases never normalize a policy name or turn an alias into framing evidence.
"""
    if not isinstance(fields, (tuple, list)):
        raise HeaderCompatibilityError("response_metadata_evidence_unavailable")
    count = len(fields)
    if count > MAX_FIELDS:
        raise HeaderCompatibilityError("response_metadata_limit_exceeded", count)
    entries: list[tuple[bytes, bytes]] = []
    total = 0
    for pair in fields:
        if (not isinstance(pair, (tuple, list)) or len(pair) != 2
                or not all(isinstance(value, bytes) for value in pair)):
            raise HeaderCompatibilityError("response_metadata_invalid", count, total)
        name, value = pair
        total += len(name) + len(value)
        if (len(name) > MAX_NAME_BYTES or len(value) > MAX_VALUE_BYTES
                or total > MAX_TOTAL_BYTES):
            raise HeaderCompatibilityError("response_metadata_limit_exceeded", count, total)
        if not _TOKEN.fullmatch(name) or any(byte != 9 and not 32 <= byte <= 126 for byte in value):
            raise HeaderCompatibilityError("response_metadata_invalid", count, total)
        entries.append((name, value))
    if require_secret_guard and detects_secret is None:
        raise HeaderCompatibilityError("response_metadata_guard_unavailable", count, total)
    # Scan the original spelling and all physical occurrences before removing
    # metadata, checking a 204 fast path, or producing an observation.
    if detects_secret is not None and any(
        detects_secret(name) or detects_secret(value) for name, value in entries
    ):
        raise HeaderCompatibilityError("response_credential_reflection", count, total)
    listed = frozenset(listed_names)
    counts: Counter[str] = Counter()
    retained = []
    for raw_name, raw_value in entries:
        name = raw_name.decode("ascii").lower()
        classified = name.replace("_", "-")
        if (classified in _SECURITY_HEADERS or classified.startswith("x-catchplate-")
                or (classified in TRANSPORT_HEADERS and classified != name)):
            raise HeaderCompatibilityError("response_metadata_reserved_header", count, total)
        counts[name] += 1
        if counts[name] > 1 and (name in TRANSPORT_HEADERS or name in listed):
            raise HeaderCompatibilityError("response_metadata_duplicate", count, total)
        if name in TRANSPORT_HEADERS or name in listed:
            retained.append((name, raw_value.decode("ascii")))
    return retained


def listed_response_headers(constraints: Iterable[dict]) -> frozenset[str]:
    """All envelopes protect listed names, including other operation scopes."""
    return frozenset(name for item in constraints if item.get("type") == "responseEnvelope"
        for name in item.get("allowedResponseHeaderNames", ()))
