"""Configured-certificate compatibility, not trusted-ingress authentication.

Only exact original DER slices are hashed. The small DER reader locates fields;
cryptography parses certificates and verifies signatures. A matching issuer is
not a trusted path, a CA admission, revocation evidence or a completed handshake.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature

from ._workload_stream import Budget, WorkloadClientError
from .workload_transport import validate_mtls_identity


_DNS = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*\Z")
_URI_ASCII = re.compile(r"[A-Za-z0-9._~:/?@!$&'()*+,;=%\[\]-]+\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


@dataclass(frozen=True, repr=False)
class CertificateOriginal:
    certificate: x509.Certificate
    der: bytes
    issuer_der: bytes
    subject_der: bytes
    spki_der: bytes


def _tlv(raw: bytes, start: int, limit: int) -> tuple[int, int, int]:
    """Return single-byte tag, value start, end without recursive value parsing."""
    if not 0 <= start < limit <= len(raw) or limit - start < 2:
        raise WorkloadClientError("workload certificate DER is truncated")
    tag, length = raw[start], raw[start + 1]
    if tag == 0 or tag & 0x1f == 0x1f:
        raise WorkloadClientError("workload certificate DER tag is unsupported")
    value = start + 2
    if length & 0x80:
        count = length & 0x7f
        if not 1 <= count <= 4 or value + count > limit or raw[value] == 0:
            raise WorkloadClientError("workload certificate DER length is invalid")
        length = int.from_bytes(raw[value:value + count], "big")
        value += count
        if length < 128:
            raise WorkloadClientError("workload certificate DER length is nonminimal")
    end = value + length
    if end > limit:
        raise WorkloadClientError("workload certificate DER exceeds its container")
    return tag, value, end


def _certificate_parts(raw: bytes) -> tuple[bytes, bytes, bytes]:
    if not 1 <= len(raw) <= 1024 * 1024:
        raise WorkloadClientError("workload certificate DER exceeds its bound")
    tag, outer, end = _tlv(raw, 0, len(raw))
    if tag != 0x30 or end != len(raw):
        raise WorkloadClientError("workload certificate DER must be one exact sequence")
    tag, cursor, tbs_end = _tlv(raw, outer, end)
    if tag != 0x30:
        raise WorkloadClientError("workload certificate TBS is not a sequence")
    # Certificate contains exactly TBS, signatureAlgorithm, signatureValue.
    tag, _, signature_end = _tlv(raw, tbs_end, end)
    if tag != 0x30:
        raise WorkloadClientError("workload certificate signature algorithm is invalid")
    tag, _, final_end = _tlv(raw, signature_end, end)
    if tag != 0x03 or final_end != end:
        raise WorkloadClientError("workload certificate signature container is invalid")
    if cursor < tbs_end and raw[cursor] == 0xa0:
        _, _, cursor = _tlv(raw, cursor, tbs_end)
    fields: list[bytes] = []
    # serial, signature algorithm, issuer, validity, subject, original SPKI.
    for expected in (0x02, 0x30, 0x30, 0x30, 0x30, 0x30):
        start = cursor
        tag, _, cursor = _tlv(raw, start, tbs_end)
        if tag != expected:
            raise WorkloadClientError("workload certificate TBS field has an invalid tag")
        fields.append(raw[start:cursor])
    previous = -1
    optional_tags = (0x81, 0x82, 0xa3)
    for _ in range(3):
        if cursor == tbs_end:
            break
        tag, _, cursor = _tlv(raw, cursor, tbs_end)
        if tag not in optional_tags or optional_tags.index(tag) <= previous:
            raise WorkloadClientError("workload certificate optional fields are invalid")
        previous = optional_tags.index(tag)
    if cursor != tbs_end:
        raise WorkloadClientError("workload certificate TBS has trailing fields")
    return fields[2], fields[4], fields[5]


def parse_certificate_original(pem: bytes, budget: Budget) -> CertificateOriginal:
    budget.check()
    encoded = b"".join(pem.splitlines()[1:-1])
    der = base64.b64decode(encoded, validate=True)
    if base64.b64encode(der) != encoded:
        raise WorkloadClientError("workload certificate PEM base64 is noncanonical")
    issuer, subject, spki = _certificate_parts(der)
    budget.check()
    certificate = x509.load_der_x509_certificate(der)
    budget.check()
    return CertificateOriginal(certificate, der, issuer, subject, spki)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_uri(value: str) -> urllib.parse.SplitResult:
    # Conservative ASCII subset of the Rust URL canonicality check. Ambiguous
    # WHATWG normalization cases are rejected, never silently rewritten into a
    # signed selector. This is intentionally not general URI normalization.
    if (
        not 1 <= len(value) <= 2048
        or not value.isascii()
        or _URI_ASCII.fullmatch(value) is None
        or any(ord(char) <= 32 or ord(char) == 127 for char in value)
        or any(char in value for char in ('\\', '#', '"', '<', '>', '`'))
    ):
        raise WorkloadClientError("workload leaf URI SAN is not canonical")
    scheme, separator, rest = value.partition(":")
    if separator != ":" or _SCHEME.fullmatch(scheme) is None:
        raise WorkloadClientError("workload leaf URI SAN scheme is invalid")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != scheme or parsed.username is not None or parsed.password is not None:
        raise WorkloadClientError("workload leaf URI SAN authority is invalid")
    hierarchical = rest.startswith("/")
    if scheme == "file":
        raise WorkloadClientError("workload leaf file URI SAN is outside the supported profile")
    if scheme in _DEFAULT_PORTS and (
        not rest.startswith("//") or not parsed.netloc or not parsed.path
    ):
        raise WorkloadClientError("workload leaf URI SAN requires its canonical authority and path")
    if parsed.netloc:
        host = parsed.hostname
        if not host or host != host.lower() or host.endswith("."):
            raise WorkloadClientError("workload leaf URI SAN host is invalid")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or _DNS.fullmatch(host) is None:
                raise WorkloadClientError("workload leaf URI SAN host is not canonical") from None
            # Reject alternate numeric IPv4 forms normalized by Rust's URL
            # parser, instead of treating them as ordinary DNS names.
            tail = host.rsplit(".", 1)[-1]
            if tail.isdigit() or tail.lower().startswith("0x"):
                raise WorkloadClientError("workload leaf URI SAN numeric host is ambiguous")
            canonical_host = host
        else:
            if str(address) != host:
                raise WorkloadClientError("workload leaf URI SAN IP spelling is not canonical")
            canonical_host = f"[{host}]" if address.version == 6 else host
        port = parsed.port
        authority = canonical_host if port is None else f"{canonical_host}:{port}"
        if parsed.netloc != authority or (port is not None and port == _DEFAULT_PORTS.get(scheme)):
            raise WorkloadClientError("workload leaf URI SAN authority spelling is not canonical")
    if hierarchical:
        for segment in parsed.path.split("/"):
            if segment.lower().replace("%2e", ".") in {".", ".."}:
                raise WorkloadClientError("workload leaf URI SAN contains a normalized path segment")
    if scheme in _DEFAULT_PORTS and "'" in parsed.query:
        raise WorkloadClientError("workload leaf URI SAN query is not canonical")
    return parsed


def _leaf_sans(leaf: x509.Certificate, budget: Budget) -> dict[str, set[str]]:
    values: dict[str, set[str]] = {"sanDnsNames": set(), "sanUris": set(), "sanSpiffeIds": set()}
    budget.check()
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return values
    budget.check()
    if len(names) > 128:
        raise WorkloadClientError("workload leaf SAN inventory exceeds its bound")
    for name in names:
        budget.check()
        if isinstance(name, x509.DNSName):
            value = name.value.lower()
            if not value.isascii() or len(value) > 253 or _DNS.fullmatch(value) is None:
                raise WorkloadClientError("workload leaf DNS SAN is not canonical")
            values["sanDnsNames"].add(value)
        elif isinstance(name, x509.UniformResourceIdentifier):
            value = name.value
            parsed = _canonical_uri(value)
            values["sanUris"].add(value)
            if value.startswith("spiffe://"):
                if (
                    parsed.hostname is None
                    or _DNS.fullmatch(parsed.hostname) is None
                    or parsed.port is not None
                    or "?" in value
                    or "//" in parsed.path
                ):
                    raise WorkloadClientError("workload leaf SPIFFE SAN is not canonical")
                values["sanSpiffeIds"].add(value)
    if any(len(items) > 32 for items in values.values()):
        raise WorkloadClientError("workload leaf unique SAN inventory exceeds its bound")
    return values


def check_client_selectors(
    certificates: tuple[CertificateOriginal, ...], expected: dict[str, object], budget: Budget,
) -> None:
    budget.check()
    selectors = validate_mtls_identity(expected)
    if not 1 <= len(certificates) <= 16:
        raise WorkloadClientError("workload client certificate inventory is invalid")
    leaf = certificates[0]
    budget.check()
    opened_at = datetime.now(timezone.utc)
    not_before = leaf.certificate.not_valid_before_utc
    not_after = leaf.certificate.not_valid_after_utc
    if not not_before <= opened_at < not_after or not_before >= not_after:
        raise WorkloadClientError("workload client leaf is not currently valid")
    budget.check()
    actual: dict[str, object] = _leaf_sans(leaf.certificate, budget)
    actual["certificateSha256"] = _digest(leaf.der)
    actual["spkiSha256"] = _digest(leaf.spki_der)
    if "issuerSpkiSha256" in selectors:
        issuer_digests: set[str] = set()
        for issuer in certificates[1:]:
            budget.check()
            if leaf.issuer_der != issuer.subject_der:
                continue
            try:
                # This checks only the real name/signature relationship, NOT
                # trust, CA role, validity or a complete certification path.
                leaf.certificate.verify_directly_issued_by(issuer.certificate)
            except (InvalidSignature, ValueError, TypeError):
                continue
            budget.check()
            issuer_digests.add(_digest(issuer.spki_der))
        if len(issuer_digests) != 1:
            raise WorkloadClientError("workload client issuer selector has no unique supplied signer")
        actual["issuerSpkiSha256"] = next(iter(issuer_digests))
    for field, required in selectors.items():
        if field == "verifiedByTrustedIngress":
            # Signed policy requirement, not a fact manufactured locally.
            continue
        observed = actual.get(field)
        if isinstance(required, list):
            if not isinstance(observed, set) or not observed.intersection(required):
                raise WorkloadClientError("workload client certificate does not match signed SAN selectors")
        elif observed != required:
            raise WorkloadClientError("workload client certificate does not match signed certificate selectors")
    budget.check()
    closed_at = datetime.now(timezone.utc)
    if closed_at < opened_at or not not_before <= closed_at < not_after:
        raise WorkloadClientError("workload client leaf validity changed during admission")
    budget.check()


def check_interception_ca(
    certificates: tuple[CertificateOriginal, ...], expected_spki: str, budget: Budget,
) -> None:
    budget.check()
    if (
        not isinstance(expected_spki, str)
        or _SHA256.fullmatch(expected_spki) is None
        or expected_spki == "sha256:" + "0" * 64
        or len(certificates) != 1
    ):
        raise WorkloadClientError("workload interception trust requires one exact pinned CA")
    certificate = certificates[0]
    if _digest(certificate.spki_der) != expected_spki:
        raise WorkloadClientError("workload interception CA does not match the signed SPKI")
    constraints = certificate.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not constraints.ca:
        raise WorkloadClientError("workload interception certificate is not a CA")
    budget.check()
