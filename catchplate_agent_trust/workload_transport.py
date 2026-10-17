"""Signed workload transport requirements, never evidence of a TLS handshake.

This module deliberately depends only on the standalone trust package and the
standard library. Selector spelling and bounds mirror the existing policy
contract; validation neither acquires credentials nor authenticates a peer.
Authenticated consumers call it only after their signature and pin checks.
"""
from __future__ import annotations

import re

from .http import validate_http_url


_MTLS_FIELDS = frozenset({
    "verifiedByTrustedIngress", "sanSpiffeIds", "sanDnsNames", "sanUris",
    "certificateSha256", "spkiSha256", "issuerSpkiSha256",
})
_LEAF_FIELDS = frozenset({
    "sanSpiffeIds", "sanDnsNames", "sanUris", "certificateSha256", "spkiSha256",
})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Keep these patterns aligned with policy_bundle._validate_mtls_identity_policy.
# In particular, do not silently rewrite SANs or strengthen them into a new
# URI profile that the signed policy did not select.
_SPIFFE_RE = re.compile(
    r"^spiffe://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?"
    r"(?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*$"
)
_DNS_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_URI_RE = re.compile(r"^[a-z][a-z0-9+.-]*:[^\s\x00-\x1f\x7f]{1,2040}$")


def _selectors(value: object, pattern: re.Pattern[str], maximum_bytes: int) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise ValueError("mTLS SAN selectors must contain 1-32 unique canonical strings")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > maximum_bytes
            or item != item.strip()
        ):
            raise ValueError("mTLS SAN selector spelling is invalid")
        try:
            size = len(item.encode("utf-8"))
        except UnicodeError as exc:
            raise ValueError("mTLS SAN selector is not valid UTF-8") from exc
        if size > maximum_bytes or pattern.fullmatch(item) is None or item in seen:
            raise ValueError("mTLS SAN selectors exceed their bound or repeat")
        seen.add(item)
        result.append(item)
    return result


def validate_mtls_identity(value: object) -> dict[str, object]:
    """Return a fresh policy-shaped selector object, preserving exact values.

    Optional fields must be absent, not null. Hashes retain the policy's exact
    lowercase SHA-256 syntax (including its permitted all-zero value). This is
    a requirement on trusted ingress, not a claim that ingress verified a peer.
    """
    if not isinstance(value, dict) or any(field not in _MTLS_FIELDS for field in value):
        raise ValueError("mTLS identity must be a closed policy selector object")
    if value.get("verifiedByTrustedIngress") is not True:
        raise ValueError("mTLS identity requires verifiedByTrustedIngress true")
    normalized: dict[str, object] = {"verifiedByTrustedIngress": True}
    for field, pattern, maximum_bytes in (
        ("sanSpiffeIds", _SPIFFE_RE, 2048),
        ("sanDnsNames", _DNS_RE, 253),
        ("sanUris", _URI_RE, 2048),
    ):
        if field in value:
            normalized[field] = _selectors(value[field], pattern, maximum_bytes)
    for field in ("certificateSha256", "spkiSha256", "issuerSpkiSha256"):
        if field not in value:
            continue
        digest = value[field]
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise ValueError("mTLS certificate selector must be canonical SHA-256")
        normalized[field] = digest
    if not any(field in normalized for field in _LEAF_FIELDS):
        raise ValueError("mTLS identity requires at least one leaf or SAN selector")
    return normalized


def validate_workload_transport(packet: dict) -> None:
    """Validate the signed mTLS requirement, without performing any transport.

    Legacy packets without identity.mtls are unchanged. A present null cannot
    erase a configured requirement. This does not validate SDK configuration,
    acquire a client key, install a CA or add receipt/handshake assurance.
    """
    if not isinstance(packet, dict):
        raise ValueError("workload transport requires an enrollment packet object")
    identity = packet.get("identity")
    if not isinstance(identity, dict) or "mtls" not in identity:
        return
    validate_mtls_identity(identity["mtls"])
    catchplate = packet.get("catchplate")
    proxy_url = catchplate.get("proxyUrl") if isinstance(catchplate, dict) else None
    if (
        not isinstance(proxy_url, str)
        or not proxy_url
        or any(char.isspace() or ord(char) < 32 or 127 <= ord(char) <= 159 for char in proxy_url)
    ):
        raise ValueError("mTLS workload proxy URL must be HTTPS without whitespace or controls")
    parsed = validate_http_url(proxy_url, require_https=True)
    if (
        parsed.path not in {"", "/"}
        or "?" in proxy_url
        or "#" in proxy_url
        or "\\" in proxy_url
        or parsed.netloc.endswith(":")
    ):
        raise ValueError("mTLS workload proxy URL must contain only a valid HTTPS authority")
    # validate_http_url rejects credentials, absent hosts and out-of-range or
    # zero ports. An omitted port means standard HTTPS port 443, not raw TCP.
