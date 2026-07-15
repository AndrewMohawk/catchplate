#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


REQUEST_API_VERSION = "serverware.launchAuthorizationRequest/v1"
REQUEST_KIND = "ProductionLaunchAuthorizationRequest"
AUTHORIZATION_API_VERSION = "serverware.launchAuthorization/v1"
AUTHORIZATION_KIND = "ProductionLaunchAuthorization"
REQUEST_DOMAIN = REQUEST_API_VERSION.encode("ascii") + b"\0"
AUTHORIZATION_DOMAIN = AUTHORIZATION_API_VERSION.encode("ascii") + b"\0"

MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_VALIDITY_SECONDS = 30
MAX_FUTURE_SKEW_SECONDS = 5
MAX_JSON_BYTES = 16 * 1024

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_AUDIENCE_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z", re.ASCII)
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)

_REQUEST_FIELDS = frozenset(
    {
        "apiVersion",
        "kind",
        "launcherNonce",
        "bootIdSha256",
        "launcherSha256",
        "manifestSha256",
        "releaseProvenanceSha256",
        "provenanceDigest",
        "reproducibleBuildVerificationSha256",
        "sourceTreeDigest",
        "deploymentAudience",
        "deploymentIdentitySha256",
        "releaseSequence",
        "rollbackEpoch",
    }
)
_REQUEST_DIGEST_FIELDS = (
    "bootIdSha256",
    "launcherSha256",
    "manifestSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "reproducibleBuildVerificationSha256",
    "sourceTreeDigest",
    "deploymentIdentitySha256",
)
_AUTHORIZATION_FIELDS = frozenset({"apiVersion", "kind", "statement", "signature"})
_STATEMENT_FIELDS = frozenset(
    {
        "authorizationId",
        "authorityKeyId",
        "requestSha256",
        "issuedAtUnixSeconds",
        "expiresAtUnixSeconds",
        "useLimit",
    }
)


class LaunchAuthorizationError(ValueError):
    """A strict launch-authorization contract or verification failure."""


@dataclass(frozen=True, slots=True)
class VerifiedLaunchAuthorization:
    authorization_id: str
    authority_key_id: str
    request_sha256: str
    issued_at_unix_seconds: int
    expires_at_unix_seconds: int
    use_limit: int


def _plain_json(value: Any, label: str = "JSON value") -> Any:
    if isinstance(value, Mapping):
        rendered: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise LaunchAuthorizationError(f"{label} contains a non-string object key")
            _require_unicode_scalar_string(key, f"{label} object key")
            rendered[key] = _plain_json(item, label)
        return rendered
    if isinstance(value, (list, tuple)):
        return [_plain_json(item, label) for item in value]
    if type(value) is str:
        _require_unicode_scalar_string(value, label)
        return value
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            raise LaunchAuthorizationError(f"{label} contains an integer outside the safe range")
        return value
    raise LaunchAuthorizationError(f"{label} contains a non-JSON value")


def _require_unicode_scalar_string(value: str, label: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise LaunchAuthorizationError(f"{label} contains an invalid Unicode surrogate") from exc


def canonical_json_bytes(value: Any) -> bytes:
    """Return compact, key-sorted, ASCII JSON with no trailing newline."""

    try:
        rendered = json.dumps(
            _plain_json(value),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise LaunchAuthorizationError("value cannot be encoded as canonical JSON") from exc
    return rendered.encode("ascii")


def parse_strict_json_object(raw: bytes, *, label: str = "document") -> dict[str, Any]:
    """Parse one bounded UTF-8 JSON object, rejecting duplicates and non-integers."""

    if type(raw) is not bytes:
        raise LaunchAuthorizationError(f"{label} must be immutable bytes")
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise LaunchAuthorizationError(f"{label} byte length is outside the accepted bound")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise LaunchAuthorizationError(f"{label} must not contain a UTF-8 BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise LaunchAuthorizationError(f"{label} must be strict UTF-8 JSON") from exc

    def parse_integer(value: str) -> int:
        parsed = int(value, 10)
        if abs(parsed) > MAX_SAFE_INTEGER:
            raise LaunchAuthorizationError(f"{label} contains an integer outside the safe range")
        return parsed

    def reject_float(_: str) -> float:
        raise LaunchAuthorizationError(f"{label} must not contain floating-point values")

    def reject_constant(_: str) -> object:
        raise LaunchAuthorizationError(f"{label} must not contain non-finite values")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                raise LaunchAuthorizationError(f"{label} contains duplicate object key: {key}")
            parsed[key] = value
        return parsed

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_int=parse_integer,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except LaunchAuthorizationError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise LaunchAuthorizationError(f"{label} must be one valid JSON value") from exc
    if not isinstance(parsed, dict):
        raise LaunchAuthorizationError(f"{label} must be a JSON object")
    _plain_json(parsed, label)
    return parsed


def require_canonical_json_bytes(
    raw: bytes, *, label: str = "document"
) -> dict[str, Any]:
    """Parse a strict object and require its bytes to already be canonical JSON."""

    parsed = parse_strict_json_object(raw, label=label)
    if not hmac.compare_digest(raw, canonical_json_bytes(parsed)):
        raise LaunchAuthorizationError(f"{label} is not canonical JSON")
    return parsed


def _require_exact_fields(
    value: Any, expected: frozenset[str], label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LaunchAuthorizationError(f"{label} must be an object")
    if any(type(key) is not str for key in value):
        raise LaunchAuthorizationError(f"{label} contains a non-string object key")
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise LaunchAuthorizationError(f"{label} is missing required fields: {missing}")
    if unknown:
        raise LaunchAuthorizationError(f"{label} contains unknown fields: {unknown}")
    return value


def _require_literal(value: Any, expected: str, label: str) -> str:
    if value != expected or type(value) is not str:
        raise LaunchAuthorizationError(f"{label} must equal {expected!r}")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise LaunchAuthorizationError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def _require_hex_64(value: Any, label: str) -> str:
    if type(value) is not str or _HEX_64_RE.fullmatch(value) is None:
        raise LaunchAuthorizationError(f"{label} must be exactly 64 lowercase hex characters")
    return value


def _require_safe_integer(value: Any, label: str, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise LaunchAuthorizationError(
            f"{label} must be an integer from {minimum} through {MAX_SAFE_INTEGER}"
        )
    return value


def validate_launch_authorization_request(value: Any) -> dict[str, Any]:
    request = _require_exact_fields(value, _REQUEST_FIELDS, "launch authorization request")
    _require_literal(request["apiVersion"], REQUEST_API_VERSION, "request apiVersion")
    _require_literal(request["kind"], REQUEST_KIND, "request kind")
    _require_hex_64(request["launcherNonce"], "request launcherNonce")
    for field in _REQUEST_DIGEST_FIELDS:
        _require_sha256(request[field], f"request {field}")
    audience = request["deploymentAudience"]
    if type(audience) is not str or _AUDIENCE_RE.fullmatch(audience) is None:
        raise LaunchAuthorizationError(
            "request deploymentAudience must match [a-z0-9][a-z0-9._:-]{0,127}"
        )
    _require_safe_integer(request["releaseSequence"], "request releaseSequence", minimum=1)
    _require_safe_integer(request["rollbackEpoch"], "request rollbackEpoch", minimum=0)
    return dict(request)


def launch_authorization_request_sha256(value: Any) -> str:
    request = validate_launch_authorization_request(value)
    digest = hashlib.sha256(REQUEST_DOMAIN + canonical_json_bytes(request)).hexdigest()
    return "sha256:" + digest


def _decode_signature(value: Any) -> bytes:
    if type(value) is not str or _BASE64URL_RE.fullmatch(value) is None or "=" in value:
        raise LaunchAuthorizationError(
            "authorization signature must be canonical unpadded base64url"
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as exc:
        raise LaunchAuthorizationError(
            "authorization signature must be canonical unpadded base64url"
        ) from exc
    if len(decoded) != 64 or canonical_base64url(decoded) != value:
        raise LaunchAuthorizationError("authorization signature must encode exactly 64 bytes")
    return decoded


def canonical_base64url(value: bytes) -> str:
    if type(value) is not bytes:
        raise LaunchAuthorizationError("base64url input must be immutable bytes")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def validate_launch_authorization_statement(value: Any) -> dict[str, Any]:
    statement = _require_exact_fields(value, _STATEMENT_FIELDS, "authorization statement")
    _require_hex_64(statement["authorizationId"], "statement authorizationId")
    _require_sha256(statement["authorityKeyId"], "statement authorityKeyId")
    _require_sha256(statement["requestSha256"], "statement requestSha256")
    issued_at = _require_safe_integer(
        statement["issuedAtUnixSeconds"], "statement issuedAtUnixSeconds", minimum=1
    )
    expires_at = _require_safe_integer(
        statement["expiresAtUnixSeconds"], "statement expiresAtUnixSeconds", minimum=1
    )
    if expires_at <= issued_at:
        raise LaunchAuthorizationError("authorization expiry must be after issuance")
    if expires_at - issued_at > MAX_VALIDITY_SECONDS:
        raise LaunchAuthorizationError(
            f"authorization validity must not exceed {MAX_VALIDITY_SECONDS} seconds"
        )
    if statement["useLimit"] != 1 or type(statement["useLimit"]) is not int:
        raise LaunchAuthorizationError("statement useLimit must equal integer 1")
    return dict(statement)


def validate_launch_authorization(value: Any) -> dict[str, Any]:
    envelope = _require_exact_fields(value, _AUTHORIZATION_FIELDS, "launch authorization")
    _require_literal(
        envelope["apiVersion"], AUTHORIZATION_API_VERSION, "authorization apiVersion"
    )
    _require_literal(envelope["kind"], AUTHORIZATION_KIND, "authorization kind")
    statement = validate_launch_authorization_statement(envelope["statement"])
    _decode_signature(envelope["signature"])
    return {
        "apiVersion": envelope["apiVersion"],
        "kind": envelope["kind"],
        "statement": statement,
        "signature": envelope["signature"],
    }


def _load_ed25519_spki(public_key_spki_der: bytes) -> Ed25519PublicKey:
    if type(public_key_spki_der) is not bytes:
        raise LaunchAuthorizationError("authority SPKI must be immutable DER bytes")
    try:
        public_key = serialization.load_der_public_key(public_key_spki_der)
    except (TypeError, ValueError) as exc:
        raise LaunchAuthorizationError("authority SPKI must be valid DER") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise LaunchAuthorizationError("authority SPKI must contain an Ed25519 public key")
    canonical_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not hmac.compare_digest(public_key_spki_der, canonical_der):
        raise LaunchAuthorizationError("authority SPKI DER must use canonical encoding")
    return public_key


def spki_key_id(public_key_spki_der: bytes) -> str:
    _load_ed25519_spki(public_key_spki_der)
    return "sha256:" + hashlib.sha256(public_key_spki_der).hexdigest()


def _public_key_spki_der(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _unsigned_envelope(statement: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": AUTHORIZATION_API_VERSION,
        "kind": AUTHORIZATION_KIND,
        "statement": dict(statement),
    }


def launch_authorization_signing_bytes(statement: Any) -> bytes:
    validated = validate_launch_authorization_statement(statement)
    return AUTHORIZATION_DOMAIN + canonical_json_bytes(_unsigned_envelope(validated))


def sign_launch_authorization(
    request: Any,
    *,
    private_key: Ed25519PrivateKey,
    authorization_id: str,
    issued_at_unix_seconds: int,
    expires_at_unix_seconds: int,
) -> dict[str, Any]:
    """Create an authorization using a caller-supplied authority key."""

    if not isinstance(private_key, Ed25519PrivateKey):
        raise LaunchAuthorizationError("private_key must be an Ed25519 private key")
    statement = validate_launch_authorization_statement(
        {
            "authorizationId": authorization_id,
            "authorityKeyId": spki_key_id(_public_key_spki_der(private_key.public_key())),
            "requestSha256": launch_authorization_request_sha256(request),
            "issuedAtUnixSeconds": issued_at_unix_seconds,
            "expiresAtUnixSeconds": expires_at_unix_seconds,
            "useLimit": 1,
        }
    )
    unsigned = _unsigned_envelope(statement)
    return {
        **unsigned,
        "signature": canonical_base64url(
            private_key.sign(AUTHORIZATION_DOMAIN + canonical_json_bytes(unsigned))
        ),
    }


def verify_launch_authorization(
    raw: bytes,
    *,
    authority_public_key_spki_der: bytes,
    expected_request_sha256: str,
    expected_authority_key_id: str,
    now_unix_seconds: int,
) -> VerifiedLaunchAuthorization:
    """Verify one canonical authorization against explicit trust and request bindings."""

    _require_sha256(expected_request_sha256, "expected request digest")
    _require_sha256(expected_authority_key_id, "expected authority key ID")
    now = _require_safe_integer(now_unix_seconds, "current Unix time", minimum=0)
    public_key = _load_ed25519_spki(authority_public_key_spki_der)
    actual_key_id = spki_key_id(authority_public_key_spki_der)
    if not hmac.compare_digest(actual_key_id, expected_authority_key_id):
        raise LaunchAuthorizationError("trusted authority key does not match expected key ID")

    envelope = validate_launch_authorization(
        require_canonical_json_bytes(raw, label="launch authorization")
    )
    statement = envelope["statement"]
    try:
        public_key.verify(
            _decode_signature(envelope["signature"]),
            launch_authorization_signing_bytes(statement),
        )
    except InvalidSignature as exc:
        raise LaunchAuthorizationError("launch authorization signature is invalid") from exc

    if not hmac.compare_digest(statement["authorityKeyId"], expected_authority_key_id):
        raise LaunchAuthorizationError("authorization authority key ID binding mismatch")
    if not hmac.compare_digest(statement["requestSha256"], expected_request_sha256):
        raise LaunchAuthorizationError("authorization request digest binding mismatch")
    if statement["issuedAtUnixSeconds"] > now + MAX_FUTURE_SKEW_SECONDS:
        raise LaunchAuthorizationError(
            f"authorization issuance exceeds {MAX_FUTURE_SKEW_SECONDS}-second future skew"
        )
    if now >= statement["expiresAtUnixSeconds"]:
        raise LaunchAuthorizationError("launch authorization is expired")

    return VerifiedLaunchAuthorization(
        authorization_id=statement["authorizationId"],
        authority_key_id=statement["authorityKeyId"],
        request_sha256=statement["requestSha256"],
        issued_at_unix_seconds=statement["issuedAtUnixSeconds"],
        expires_at_unix_seconds=statement["expiresAtUnixSeconds"],
        use_limit=statement["useLimit"],
    )
