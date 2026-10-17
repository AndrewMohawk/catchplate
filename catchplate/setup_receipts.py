from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, TypeAlias

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate.attestation import (
    AttestationContractError,
    NitroVerificationTrust,
    verify_nitro_attestation_document,
)


ENROLLMENT_RECEIPT_API_VERSION = "catchplate.enrollmentVerifierReceipt/v2"
HARDWARE_VERIFICATION_API_VERSION = "catchplate.setupHardwareVerification/v1"
HARDWARE_VERIFICATION_CLOSED_API_VERSION = (
    "catchplate.setupHardwareVerification/v2"
)
VERIFIED_HARDWARE_SUBPROOF_API_VERSION = (
    "catchplate.verifiedHardwareSubproof/v2"
)
VERIFIED_PROXY_SUBPROOF_API_VERSION = "catchplate.verifiedProxySubproof/v2"
SETUP_SUBPROOF_ENVELOPE_API_VERSION = (
    "catchplate.setupVerifiedSubproofEnvelope/v1"
)
PROXY_SUBPROOF_SIGNATURE_DOMAIN = (
    b"catchplate.verifiedProxySubproof/v2\x00Ed25519\x00"
)
PRODUCTION_ATTESTATION_PIPELINE = "manifest-v6-promoted-oci-nitro-eif"
COMPLETION_IDENTITY_API_VERSION = "catchplate.setupCompletionIdentity/v1"
FINAL_CHALLENGE_RECEIPT_API_VERSION = "catchplate.finalChallengeReceipt/v1"

ENROLLMENT_CHECKS = (
    "assignment-binding",
    "enrollment-session-binding",
    "packet-digest",
    "nonce-digest",
    "trust-profile",
    "attestation-quote",
    "runtime-manifest",
    "packet-signature",
    "packet-expiry",
)
HARDWARE_CHECKS = (
    "assignment-binding",
    "runtime-evidence",
    "challenge-binding",
    "hardware-assurance-digest",
    "hardware-statement-digest",
    "hardware-key-binding",
    "release-identity",
    "current-host-identity",
    "proxy-server-statement",
    "trust-profile",
)

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_PROVIDER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_SHA384_RE = re.compile(r"sha384:[0-9a-f]{96}\Z")


class ReceiptErrorCode(str, Enum):
    INVALID_INPUT = "invalid_input"
    INVALID_JSON = "invalid_json"
    LIMIT_EXCEEDED = "limit_exceeded"
    CONTRACT_MISMATCH = "contract_mismatch"
    INVALID_SIGNATURE = "invalid_signature"
    UNTRUSTED_SIGNER = "untrusted_signer"
    BINDING_MISMATCH = "binding_mismatch"
    INVALID_TIME = "invalid_time"
    TRUST_CONFIGURATION = "trust_configuration"


class ReceiptVerificationError(ValueError):
    """A stable, non-secret-bearing verification failure."""

    def __init__(self, code: ReceiptErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReceiptParseError(ReceiptVerificationError):
    pass


class ReceiptContractError(ReceiptVerificationError):
    pass


class ReceiptSignatureError(ReceiptVerificationError):
    pass


class ReceiptTrustError(ReceiptVerificationError):
    pass


class ReceiptBindingError(ReceiptVerificationError):
    pass


class ReceiptTimeError(ReceiptVerificationError):
    pass


class Clock(Protocol):
    def now_unix(self) -> int: ...


@dataclass(frozen=True, slots=True)
class FixedClock:
    value: int

    def now_unix(self) -> int:
        return self.value


@dataclass(frozen=True, slots=True)
class JsonLimits:
    max_bytes: int = 512 * 1024
    max_depth: int = 16
    max_object_keys: int = 64
    max_total_keys: int = 512
    max_array_items: int = 128
    max_total_nodes: int = 4096
    max_string_bytes: int = 256 * 1024
    max_integer_abs: int = (1 << 63) - 1

    def __post_init__(self) -> None:
        for value in (
            self.max_bytes,
            self.max_depth,
            self.max_object_keys,
            self.max_total_keys,
            self.max_array_items,
            self.max_total_nodes,
            self.max_string_bytes,
            self.max_integer_abs,
        ):
            if type(value) is not int or value < 1:
                raise ReceiptTrustError(
                    ReceiptErrorCode.TRUST_CONFIGURATION,
                    "JSON limits must be positive integers",
                )


DEFAULT_JSON_LIMITS = JsonLimits()

FrozenJsonScalar: TypeAlias = None | bool | int | str
FrozenJson: TypeAlias = (
    FrozenJsonScalar | tuple["FrozenJson", ...] | Mapping[str, "FrozenJson"]
)


def _parse_failure(code: ReceiptErrorCode, message: str) -> ReceiptParseError:
    return ReceiptParseError(code, message)


def parse_strict_json_object(
    raw: bytes,
    *,
    limits: JsonLimits = DEFAULT_JSON_LIMITS,
) -> Mapping[str, FrozenJson]:
    """Parse one bounded UTF-8 JSON object and recursively freeze it."""

    if type(raw) is not bytes:
        raise _parse_failure(
            ReceiptErrorCode.INVALID_INPUT,
            "receipt input must be immutable bytes",
        )
    if not raw or len(raw) > limits.max_bytes:
        raise _parse_failure(
            ReceiptErrorCode.LIMIT_EXCEEDED,
            "receipt byte length is outside the accepted bound",
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _parse_failure(ReceiptErrorCode.INVALID_JSON, "UTF-8 BOM is forbidden")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _parse_failure(
            ReceiptErrorCode.INVALID_JSON, "receipt is not strict UTF-8"
        ) from exc

    def parse_integer(value: str) -> int:
        try:
            parsed = int(value, 10)
        except ValueError as exc:
            raise _parse_failure(
                ReceiptErrorCode.INVALID_JSON, "JSON integer is invalid"
            ) from exc
        if abs(parsed) > limits.max_integer_abs:
            raise _parse_failure(
                ReceiptErrorCode.LIMIT_EXCEEDED,
                "JSON integer exceeds the accepted bound",
            )
        return parsed

    def reject_float(_: str) -> float:
        raise _parse_failure(
            ReceiptErrorCode.INVALID_JSON, "JSON floating-point values are forbidden"
        )

    def reject_constant(_: str) -> object:
        raise _parse_failure(
            ReceiptErrorCode.INVALID_JSON, "non-finite JSON values are forbidden"
        )

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len(pairs) > limits.max_object_keys:
            raise _parse_failure(
                ReceiptErrorCode.LIMIT_EXCEEDED,
                "JSON object key count exceeds the accepted bound",
            )
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _parse_failure(
                    ReceiptErrorCode.INVALID_JSON, "duplicate JSON object key"
                )
            result[key] = value
        return result

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_int=parse_integer,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except ReceiptParseError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise _parse_failure(
            ReceiptErrorCode.INVALID_JSON, "receipt is not valid bounded JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise _parse_failure(
            ReceiptErrorCode.INVALID_JSON, "receipt must be a JSON object"
        )

    total_keys = 0
    total_nodes = 0

    def freeze(value: Any, depth: int) -> FrozenJson:
        nonlocal total_keys, total_nodes
        total_nodes += 1
        if total_nodes > limits.max_total_nodes:
            raise _parse_failure(
                ReceiptErrorCode.LIMIT_EXCEEDED,
                "JSON node count exceeds the accepted bound",
            )
        if depth > limits.max_depth:
            raise _parse_failure(
                ReceiptErrorCode.LIMIT_EXCEEDED,
                "JSON nesting depth exceeds the accepted bound",
            )
        if isinstance(value, dict):
            total_keys += len(value)
            if total_keys > limits.max_total_keys:
                raise _parse_failure(
                    ReceiptErrorCode.LIMIT_EXCEEDED,
                    "JSON total key count exceeds the accepted bound",
                )
            frozen: dict[str, FrozenJson] = {}
            for key, item in value.items():
                _bounded_json_string(key, limits, "JSON object key")
                frozen[key] = freeze(item, depth + 1)
            return MappingProxyType(frozen)
        if isinstance(value, list):
            if len(value) > limits.max_array_items:
                raise _parse_failure(
                    ReceiptErrorCode.LIMIT_EXCEEDED,
                    "JSON array length exceeds the accepted bound",
                )
            return tuple(freeze(item, depth + 1) for item in value)
        if isinstance(value, str):
            _bounded_json_string(value, limits, "JSON string")
            return value
        if value is None or type(value) in {bool, int}:
            return value
        raise _parse_failure(ReceiptErrorCode.INVALID_JSON, "unsupported JSON value")

    frozen_root = freeze(parsed, 1)
    if not isinstance(frozen_root, Mapping):
        raise AssertionError("root object was not frozen as a mapping")
    return frozen_root


def _bounded_json_string(value: str, limits: JsonLimits, label: str) -> None:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise _parse_failure(
            ReceiptErrorCode.INVALID_JSON, f"{label} contains a surrogate"
        ) from exc
    if len(encoded) > limits.max_string_bytes:
        raise _parse_failure(
            ReceiptErrorCode.LIMIT_EXCEEDED,
            f"{label} exceeds the accepted bound",
        )


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        _plain_json(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_digest(value: bytes) -> str:
    if type(value) is not bytes:
        raise ReceiptContractError(
            ReceiptErrorCode.INVALID_INPUT,
            "digest input must be immutable bytes",
        )
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_base64url(value: bytes) -> str:
    if type(value) is not bytes:
        raise ReceiptContractError(
            ReceiptErrorCode.INVALID_INPUT,
            "base64url input must be immutable bytes",
        )
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: Any, *, expected_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or not _BASE64URL_RE.fullmatch(value) or "=" in value:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} is not canonical unpadded base64url",
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} is not canonical unpadded base64url",
        ) from exc
    if len(decoded) != expected_bytes or canonical_base64url(decoded) != value:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} has an invalid canonical length",
        )
    return decoded


def _decode_bounded_base64url(
    value: Any, *, minimum: int, maximum: int, label: str
) -> bytes:
    if (
        not isinstance(value, str)
        or not _BASE64URL_RE.fullmatch(value)
        or "=" in value
        or len(value) > ((maximum + 2) // 3) * 4
    ):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} is not bounded canonical unpadded base64url",
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} is not canonical unpadded base64url",
        ) from exc
    if (
        not minimum <= len(decoded) <= maximum
        or canonical_base64url(decoded) != value
    ):
        raise ReceiptContractError(
            ReceiptErrorCode.LIMIT_EXCEEDED,
            f"{label} byte length is outside its bound",
        )
    return decoded


def spki_key_id(public_key_spki_der: bytes) -> str:
    _load_ed25519_spki(public_key_spki_der)
    return sha256_digest(public_key_spki_der)


def _load_ed25519_spki(public_key_spki_der: bytes) -> Ed25519PublicKey:
    if type(public_key_spki_der) is not bytes:
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            "trusted SPKI must be immutable DER bytes",
        )
    try:
        key = serialization.load_der_public_key(public_key_spki_der)
    except (TypeError, ValueError) as exc:
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            "trusted SPKI is invalid DER",
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            "trusted SPKI is not an Ed25519 key",
        )
    canonical_der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not hmac.compare_digest(canonical_der, public_key_spki_der):
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            "trusted SPKI DER is not canonical",
        )
    return key


@dataclass(frozen=True, slots=True)
class Ed25519TrustRoot:
    provider: str
    public_key_spki_der: bytes
    nitro_verification_trust: NitroVerificationTrust | None = None

    def __post_init__(self) -> None:
        _require_provider(self.provider, "trust provider")
        _load_ed25519_spki(self.public_key_spki_der)
        if (
            self.nitro_verification_trust is not None
            and not isinstance(
                self.nitro_verification_trust, NitroVerificationTrust
            )
        ):
            raise ReceiptTrustError(
                ReceiptErrorCode.TRUST_CONFIGURATION,
                "Nitro verification trust has an invalid type",
            )

    @property
    def key_id(self) -> str:
        return sha256_digest(self.public_key_spki_der)


@dataclass(frozen=True, slots=True)
class SetupAssignment:
    principal_id: str
    route_id: str
    credential_id: str
    credential_version: int
    policy_hash: str
    route_policy_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.principal_id, "principal ID")
        _require_identifier(self.route_id, "route ID")
        _require_identifier(self.credential_id, "credential ID")
        if (
            type(self.credential_version) is not int
            or not 1 <= self.credential_version <= (1 << 63) - 1
        ):
            raise ReceiptContractError(
                ReceiptErrorCode.INVALID_INPUT,
                "credential version must be a positive bounded integer",
            )
        _require_digest(self.policy_hash, "policy hash")
        _require_digest(self.route_policy_digest, "route policy digest")

    def as_document(self) -> dict[str, Any]:
        return {
            "principalId": self.principal_id,
            "routeId": self.route_id,
            "credentialId": self.credential_id,
            "credentialVersion": self.credential_version,
            "policyHash": self.policy_hash,
            "routePolicyDigest": self.route_policy_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.as_document()))


@dataclass(frozen=True, slots=True)
class EnrollmentReceiptExpected:
    receipt_id: str
    setup_session_id: str
    assignment: SetupAssignment
    enrollment_session_id: str
    enrollment_packet_sha256: str
    verifier_nonce_sha256: str
    trust_profile_sha256: str

    def __post_init__(self) -> None:
        _require_uuid(self.receipt_id, "enrollment receipt ID")
        _require_uuid(self.setup_session_id, "setup session ID")
        _require_uuid(self.enrollment_session_id, "enrollment session ID")
        _require_digest(self.enrollment_packet_sha256, "enrollment packet digest")
        _require_digest(self.verifier_nonce_sha256, "verifier nonce digest")
        _require_digest(self.trust_profile_sha256, "trust profile digest")


@dataclass(frozen=True, slots=True)
class HardwareVerificationExpected:
    receipt_id: str
    setup_session_id: str
    assignment: SetupAssignment
    runtime_evidence_sha256: str
    challenge: bytes
    hardware_assurance_sha256: str
    hardware_statement_sha256: str
    release_identity_sha256: str
    current_host_identity_sha256: str
    proxy_server_statement_sha256: str
    trust_profile_sha256: str

    def __post_init__(self) -> None:
        _require_uuid(self.receipt_id, "hardware receipt ID")
        _require_uuid(self.setup_session_id, "setup session ID")
        if type(self.challenge) is not bytes or not 32 <= len(self.challenge) <= 64:
            raise ReceiptContractError(
                ReceiptErrorCode.INVALID_INPUT,
                "hardware challenge must be 32 to 64 immutable bytes",
            )
        for value, label in (
            (self.runtime_evidence_sha256, "runtime evidence digest"),
            (self.hardware_assurance_sha256, "hardware assurance digest"),
            (self.hardware_statement_sha256, "hardware statement digest"),
            (self.release_identity_sha256, "release identity digest"),
            (self.current_host_identity_sha256, "current host identity digest"),
            (self.proxy_server_statement_sha256, "proxy server statement digest"),
            (self.trust_profile_sha256, "trust profile digest"),
        ):
            _require_digest(value, label)

    @property
    def challenge_base64url(self) -> str:
        return canonical_base64url(self.challenge)

    @property
    def challenge_sha256(self) -> str:
        return sha256_digest(self.challenge)


@dataclass(frozen=True, slots=True)
class FinalChallengeTrust:
    authority: Ed25519TrustRoot
    hardware_verifier: Ed25519TrustRoot

    def __post_init__(self) -> None:
        if hmac.compare_digest(self.authority.key_id, self.hardware_verifier.key_id):
            raise ReceiptTrustError(
                ReceiptErrorCode.TRUST_CONFIGURATION,
                "final authority and hardware verifier keys must be distinct",
            )
        if hmac.compare_digest(
            self.authority.provider, self.hardware_verifier.provider
        ):
            raise ReceiptTrustError(
                ReceiptErrorCode.TRUST_CONFIGURATION,
                "final authority and hardware verifier providers must be distinct",
            )


@dataclass(frozen=True, slots=True)
class VerifiedEnrollmentVerifierReceipt:
    receipt_id: str
    receipt_sha256: str
    setup_session_id: str
    assignment: SetupAssignment
    enrollment_session_id: str
    enrollment_packet_sha256: str
    verifier_nonce_sha256: str
    trust_profile_sha256: str
    verifier_provider: str
    verifier_key_id: str
    decision: str
    checks: tuple[str, ...]
    issued_at_unix: int
    expires_at_unix: int


@dataclass(frozen=True, slots=True)
class VerifiedSetupHardwareVerification:
    receipt_id: str
    receipt_sha256: str
    setup_session_id: str
    assignment: SetupAssignment
    runtime_evidence_sha256: str
    challenge_base64url: str
    challenge_sha256: str
    hardware_assurance_sha256: str
    hardware_statement_sha256: str
    hardware_verifier_provider: str
    hardware_verifier_key_id: str
    release_identity_sha256: str
    current_host_identity_sha256: str
    proxy_server_statement_sha256: str
    trust_profile_sha256: str
    decision: str
    checks: tuple[str, ...]
    issued_at_unix: int
    expires_at_unix: int
    verified_subproofs_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class SetupCompletionIdentity:
    canonical_bytes: bytes
    digest_sha256: str
    setup_session_id: str
    assignment: SetupAssignment
    trust_profile_sha256: str
    challenge_sha256: str
    release_identity_sha256: str
    hardware_verifier_provider: str
    hardware_verifier_key_id: str
    current_host_identity_sha256: str
    proxy_server_statement_sha256: str
    hardware_issued_at_unix: int

    @property
    def document(self) -> Mapping[str, FrozenJson]:
        return parse_strict_json_object(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class VerifiedFinalChallengeReceipt:
    receipt_sha256: str
    consumption_id: str
    authority_provider: str
    authority_key_id: str
    challenge_sha256: str
    completion_identity_sha256: str
    release_identity_sha256: str
    hardware_verifier_key_id: str
    current_host_identity_sha256: str
    proxy_server_statement_sha256: str
    issued_at_unix: int
    expires_at_unix: int


def verify_enrollment_verifier_receipt(
    raw: bytes,
    *,
    trust: Ed25519TrustRoot,
    expected: EnrollmentReceiptExpected,
    clock: Clock | Callable[[], int],
    limits: JsonLimits = DEFAULT_JSON_LIMITS,
) -> VerifiedEnrollmentVerifierReceipt:
    document = parse_strict_json_object(raw, limits=limits)
    statement = _signed_statement(
        document,
        api_version=ENROLLMENT_RECEIPT_API_VERSION,
        kind="EnrollmentVerifierReceipt",
        trust=trust,
        statement_fields={
            "receipt_id",
            "setup_session_id",
            "assignment",
            "assignment_digest",
            "enrollment_session_id",
            "enrollment_packet_sha256",
            "verifier_nonce_sha256",
            "trust_profile_sha256",
            "verifier_provider",
            "decision",
            "checks",
            "issued_at_unix",
            "expires_at_unix",
        },
    )
    _expect_equal(
        statement.get("receipt_id"), expected.receipt_id, "enrollment receipt ID"
    )
    _expect_equal(
        statement.get("setup_session_id"), expected.setup_session_id, "setup session ID"
    )
    _expect_assignment(statement, expected.assignment)
    _expect_equal(
        statement.get("enrollment_session_id"),
        expected.enrollment_session_id,
        "enrollment session ID",
    )
    _expect_digest(
        statement, "enrollment_packet_sha256", expected.enrollment_packet_sha256
    )
    _expect_digest(statement, "verifier_nonce_sha256", expected.verifier_nonce_sha256)
    _expect_digest(statement, "trust_profile_sha256", expected.trust_profile_sha256)
    _expect_equal(
        statement.get("verifier_provider"),
        trust.provider,
        "enrollment verifier provider",
    )
    _expect_decision_and_checks(statement, ENROLLMENT_CHECKS)
    issued_at, expires_at = _verify_time_window(statement, clock)
    return VerifiedEnrollmentVerifierReceipt(
        receipt_id=expected.receipt_id,
        receipt_sha256=sha256_digest(canonical_json_bytes(document)),
        setup_session_id=expected.setup_session_id,
        assignment=expected.assignment,
        enrollment_session_id=expected.enrollment_session_id,
        enrollment_packet_sha256=expected.enrollment_packet_sha256,
        verifier_nonce_sha256=expected.verifier_nonce_sha256,
        trust_profile_sha256=expected.trust_profile_sha256,
        verifier_provider=trust.provider,
        verifier_key_id=trust.key_id,
        decision="verified",
        checks=ENROLLMENT_CHECKS,
        issued_at_unix=issued_at,
        expires_at_unix=expires_at,
    )


def _require_sha384(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA384_RE.fullmatch(value) is None:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} must be a lowercase SHA-384 digest",
        )
    return value


def _verified_subproof_trust_root(
    value: Any, *, label: str
) -> tuple[str, str, bytes]:
    if not isinstance(value, Mapping):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} trust root must be an object",
        )
    _exact_fields(
        value,
        {"keyId", "provider", "publicKeySpkiDerBase64url"},
        f"{label} trust root",
    )
    key_id = _require_digest(value.get("keyId"), f"{label} trust-root key ID")
    provider = value.get("provider")
    _require_provider(provider, f"{label} trust-root provider")
    public_key_spki_der = _decode_base64url(
        value.get("publicKeySpkiDerBase64url"),
        expected_bytes=44,
        label=f"{label} trust-root SPKI",
    )
    _load_ed25519_spki(public_key_spki_der)
    if not hmac.compare_digest(sha256_digest(public_key_spki_der), key_id):
        raise ReceiptTrustError(
            ReceiptErrorCode.UNTRUSTED_SIGNER,
            f"{label} trust-root key ID does not match its SPKI",
        )
    lowered = str(provider).lower()
    if (
        key_id == "sha256:" + "0" * 64
        or any(marker in lowered for marker in ("dev", "fixture", "self", "test"))
    ):
        raise ReceiptTrustError(
            ReceiptErrorCode.UNTRUSTED_SIGNER,
            f"{label} trust root is not production eligible",
        )
    return str(provider), key_id, public_key_spki_der


def _configured_subproof_trust_root(role: str) -> Ed25519TrustRoot:
    if role != "proxy":
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            "hardware Ed25519 verdict trust is not accepted",
        )
    prefix = "CATCHPLATE_SETUP_PROXY_SUBPROOF"
    provider = os.getenv(f"{prefix}_PROVIDER", "")
    expected_key_id = os.getenv(f"{prefix}_KEY_ID", "")
    path_text = os.getenv(f"{prefix}_PUBLIC_KEY_PATH", "")
    _require_provider(provider, f"{role} subproof provider")
    _require_digest(expected_key_id, f"{role} subproof key ID")
    path = Path(path_text)
    if (
        not path_text
        or not path.is_absolute()
        or ".." in path.parts
        or os.path.normpath(path_text) != path_text
    ):
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            f"{role} subproof public-key path is not normalized and absolute",
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= 16 * 1024
        ):
            raise ReceiptTrustError(
                ReceiptErrorCode.TRUST_CONFIGURATION,
                f"{role} subproof public key is not a bounded regular file",
            )
        raw = os.read(descriptor, 16 * 1024 + 1)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise ReceiptTrustError(
                ReceiptErrorCode.TRUST_CONFIGURATION,
                f"{role} subproof public key changed while read",
            )
    except OSError as exc:
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            f"{role} subproof public key is unavailable",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError):
        try:
            key = serialization.load_der_public_key(raw)
        except (TypeError, ValueError) as exc:
            raise ReceiptTrustError(
                ReceiptErrorCode.TRUST_CONFIGURATION,
                f"{role} subproof public key is invalid",
            ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            f"{role} subproof public key must be Ed25519",
        )
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust = Ed25519TrustRoot(provider=provider, public_key_spki_der=der)
    if not hmac.compare_digest(trust.key_id, expected_key_id):
        raise ReceiptTrustError(
            ReceiptErrorCode.UNTRUSTED_SIGNER,
            f"{role} subproof key differs from its external pin",
        )
    return trust


def _verify_subproof_envelope(
    value: Any,
    *,
    trust: Ed25519TrustRoot,
    domain: bytes,
    label: str,
) -> Mapping[str, FrozenJson]:
    if not isinstance(value, Mapping):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} envelope must be an object",
        )
    _exact_fields(
        value,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signature",
            "signingKeyId",
        },
        f"{label} envelope",
    )
    payload = value.get("payload")
    if (
        value.get("apiVersion") != SETUP_SUBPROOF_ENVELOPE_API_VERSION
        or not isinstance(payload, Mapping)
        or value.get("signingKeyId") != trust.key_id
    ):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} envelope identity is invalid",
        )
    payload_sha256 = sha256_digest(canonical_json_bytes(payload))
    if value.get("payloadSha256") != payload_sha256:
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            f"{label} envelope payload digest is invalid",
        )
    signature_text = value.get("signature")
    if (
        not isinstance(signature_text, str)
        or not signature_text.startswith("ed25519:")
    ):
        raise ReceiptSignatureError(
            ReceiptErrorCode.INVALID_SIGNATURE,
            f"{label} envelope signature is missing",
        )
    signature = _decode_base64url(
        signature_text.split(":", 1)[1],
        expected_bytes=64,
        label=f"{label} signature",
    )
    signed = domain + canonical_json_bytes(
        {"payload": payload, "payloadSha256": payload_sha256}
    )
    try:
        _load_ed25519_spki(trust.public_key_spki_der).verify(
            signature, signed
        )
    except InvalidSignature as exc:
        raise ReceiptSignatureError(
            ReceiptErrorCode.INVALID_SIGNATURE,
            f"{label} envelope signature verification failed",
        ) from exc
    return payload


def _verified_hardware_subproof(
    value: Any,
    *,
    expected: HardwareVerificationExpected,
    outer_trust: Ed25519TrustRoot,
    now_unix: int,
) -> tuple[str, str, str]:
    if not isinstance(value, Mapping):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "verified hardware subproof must be an object",
        )
    _exact_fields(
        value,
        {
            "apiVersion",
            "eifImageSha384",
            "expectedModuleId",
            "nitroTrustBundleSha256",
            "pcrs",
            "rawEvidenceBase64url",
            "rawEvidenceSha256",
            "userDataSha256",
        },
        "verified hardware subproof",
    )
    if value.get("apiVersion") != VERIFIED_HARDWARE_SUBPROOF_API_VERSION:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "verified hardware subproof version is invalid",
        )
    nitro_trust = outer_trust.nitro_verification_trust
    if nitro_trust is None:
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            "setup Nitro trust roots and CRLs are not configured",
        )
    _expect_equal(
        value.get("nitroTrustBundleSha256"),
        nitro_trust.bundle_sha256,
        "hardware Nitro trust bundle",
    )
    raw_evidence = _decode_bounded_base64url(
        value.get("rawEvidenceBase64url"),
        minimum=512,
        maximum=1024 * 1024,
        label="hardware raw Nitro evidence",
    )
    raw_digest = sha256_digest(raw_evidence)
    _expect_equal(
        value.get("rawEvidenceSha256"),
        raw_digest,
        "hardware raw-evidence digest",
    )
    expected_module_id = value.get("expectedModuleId")
    if (
        not isinstance(expected_module_id, str)
        or not 1 <= len(expected_module_id.encode("utf-8")) <= 256
        or "\x00" in expected_module_id
    ):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "expected Nitro module identity is invalid",
        )
    image_sha384 = _require_sha384(
        value.get("eifImageSha384"), "verified hardware EIF"
    )
    pcrs = value.get("pcrs")
    if not isinstance(pcrs, Mapping):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "verified hardware PCRs must be an object",
        )
    _exact_fields(pcrs, {"PCR0", "PCR1", "PCR2"}, "verified hardware PCRs")
    for name in ("PCR0", "PCR1", "PCR2"):
        _require_sha384(pcrs.get(name), f"verified hardware {name}")
    if pcrs.get("PCR0") != image_sha384:
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "verified hardware EIF does not match PCR0",
        )
    trusted_pcrs = {
        name: value
        for name, value in zip(
            ("PCR0", "PCR1", "PCR2"),
            nitro_trust.expected_pcrs,
            strict=True,
        )
    }
    if (
        expected_module_id != nitro_trust.expected_module_id
        or image_sha384 != nitro_trust.expected_eif_sha384
        or _plain_json(pcrs) != trusted_pcrs
    ):
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "hardware module, EIF, or PCR expectations differ from the pinned setup profile",
        )
    expected_user_data = canonical_json_bytes(
        {
            "apiVersion": "catchplate.setupNitroUserData/v1",
            "currentHostIdentitySha256":
            expected.current_host_identity_sha256,
            "hardwareAssuranceSha256":
            expected.hardware_assurance_sha256,
            "hardwareStatementSha256":
            expected.hardware_statement_sha256,
            "pipeline": PRODUCTION_ATTESTATION_PIPELINE,
            "releaseIdentitySha256": expected.release_identity_sha256,
            "runtimeEvidenceSha256": expected.runtime_evidence_sha256,
            "setupSessionId": expected.setup_session_id,
        }
    )
    _expect_equal(
        value.get("userDataSha256"),
        sha256_digest(expected_user_data),
        "hardware Nitro user_data",
    )
    try:
        hardware_identity = verify_nitro_attestation_document(
            raw_evidence,
            trust=nitro_trust,
            expected_module_id=nitro_trust.expected_module_id,
            expected_nonce=expected.challenge,
            expected_user_data=expected_user_data,
            expected_pcrs=trusted_pcrs,
            expected_eif_sha384=nitro_trust.expected_eif_sha384,
            now_unix=now_unix,
        )
    except AttestationContractError as exc:
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "raw Nitro hardware evidence failed cryptographic verification",
        ) from exc
    hardware_identity_sha256 = sha256_digest(
        canonical_json_bytes(hardware_identity)
    )
    return (
        sha256_digest(canonical_json_bytes(value)),
        raw_digest,
        hardware_identity_sha256,
    )


def _verified_proxy_subproof(
    value: Any, *, expected: HardwareVerificationExpected
) -> str:
    if not isinstance(value, Mapping):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "verified proxy subproof must be an object",
        )
    _exact_fields(
        value,
        {
            "apiVersion",
            "rawEvidenceBase64url",
            "rawEvidenceSha256",
            "signedEnvelope",
            "trustRoot",
        },
        "verified proxy subproof",
    )
    if value.get("apiVersion") != VERIFIED_PROXY_SUBPROOF_API_VERSION:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "verified proxy subproof version is invalid",
        )
    provider, key_id, public_key_spki_der = _verified_subproof_trust_root(
        value.get("trustRoot"), label="proxy subproof"
    )
    pinned_trust = _configured_subproof_trust_root("proxy")
    if (
        provider != pinned_trust.provider
        or key_id != pinned_trust.key_id
        or public_key_spki_der != pinned_trust.public_key_spki_der
    ):
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "proxy subproof trust root does not match its external pin",
        )
    raw_evidence = _decode_bounded_base64url(
        value.get("rawEvidenceBase64url"),
        minimum=2,
        maximum=128 * 1024,
        label="raw proxy evidence",
    )
    raw_digest = sha256_digest(raw_evidence)
    _expect_equal(
        value.get("rawEvidenceSha256"),
        expected.proxy_server_statement_sha256,
        "proxy raw-evidence digest",
    )
    if raw_digest != expected.proxy_server_statement_sha256:
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "raw proxy evidence differs from the expected server statement",
        )
    envelope_payload = _verify_subproof_envelope(
        value.get("signedEnvelope"),
        trust=pinned_trust,
        domain=PROXY_SUBPROOF_SIGNATURE_DOMAIN,
        label="proxy subproof",
    )
    _exact_fields(
        envelope_payload,
        {"apiVersion", "claims", "rawEvidenceSha256"},
        "proxy subproof payload",
    )
    if (
        envelope_payload.get("apiVersion")
        != VERIFIED_PROXY_SUBPROOF_API_VERSION
        or envelope_payload.get("rawEvidenceSha256") != raw_digest
    ):
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "proxy signed envelope does not bind its raw evidence",
        )
    claims = envelope_payload.get("claims")
    if not isinstance(claims, Mapping):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "verified proxy claims must be an object",
        )
    _exact_fields(
        claims,
        {
            "leafSpkiSha256",
            "peerSpkiSha256",
            "pipeline",
            "releaseIdentitySha256",
            "requestSha256",
            "responseSha256",
            "tlsExporterSha256",
        },
        "verified proxy claims",
    )
    if claims.get("pipeline") != PRODUCTION_ATTESTATION_PIPELINE:
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "verified proxy subproof pipeline is invalid",
        )
    for field in (
        "leafSpkiSha256",
        "peerSpkiSha256",
        "requestSha256",
        "responseSha256",
        "tlsExporterSha256",
    ):
        _require_digest(claims.get(field), f"verified proxy {field}")
    _expect_equal(
        claims.get("releaseIdentitySha256"),
        expected.release_identity_sha256,
        "proxy release identity",
    )
    raw_document = parse_strict_json_object(
        raw_evidence,
        limits=JsonLimits(
            max_bytes=128 * 1024,
            max_string_bytes=64 * 1024,
        ),
    )
    if (
        raw_evidence != canonical_json_bytes(raw_document)
        or _plain_json(raw_document) != _plain_json(claims)
    ):
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "raw proxy statement does not exactly match signed proxy claims",
        )
    return sha256_digest(canonical_json_bytes(value))


def _verify_closed_setup_hardware_verification(
    document: Mapping[str, FrozenJson],
    *,
    trust: Ed25519TrustRoot,
    expected: HardwareVerificationExpected,
    clock: Clock | Callable[[], int],
) -> VerifiedSetupHardwareVerification:
    statement = _signed_statement(
        document,
        api_version=HARDWARE_VERIFICATION_CLOSED_API_VERSION,
        kind="SetupHardwareVerification",
        trust=trust,
        statement_fields={
            "assignment",
            "assignment_digest",
            "challenge",
            "challenge_sha256",
            "current_host_identity_sha256",
            "expires_at_unix",
            "hardware_verifier_key_id",
            "hardware_verifier_provider",
            "issued_at_unix",
            "receipt_id",
            "release_identity_sha256",
            "runtime_evidence_sha256",
            "setup_session_id",
            "trust_profile_sha256",
            "verified_subproofs",
        },
    )
    _expect_equal(statement.get("receipt_id"), expected.receipt_id, "hardware receipt ID")
    _expect_equal(
        statement.get("setup_session_id"), expected.setup_session_id, "setup session ID"
    )
    _expect_assignment(statement, expected.assignment)
    _expect_digest(
        statement, "runtime_evidence_sha256", expected.runtime_evidence_sha256
    )
    _expect_equal(statement.get("challenge"), expected.challenge_base64url, "hardware challenge")
    _decode_base64url(
        statement.get("challenge"),
        expected_bytes=len(expected.challenge),
        label="hardware challenge",
    )
    _expect_digest(statement, "challenge_sha256", expected.challenge_sha256)
    _expect_equal(
        statement.get("hardware_verifier_provider"),
        trust.provider,
        "hardware verifier provider",
    )
    _expect_digest(statement, "hardware_verifier_key_id", trust.key_id)
    _expect_digest(statement, "release_identity_sha256", expected.release_identity_sha256)
    _expect_digest(
        statement,
        "current_host_identity_sha256",
        expected.current_host_identity_sha256,
    )
    _expect_digest(statement, "trust_profile_sha256", expected.trust_profile_sha256)
    subproofs = statement.get("verified_subproofs")
    if not isinstance(subproofs, Mapping):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "verified setup subproofs must be an object",
        )
    _exact_fields(subproofs, {"hardware", "proxy"}, "verified setup subproofs")
    now_unix = _clock_now(clock)
    (
        hardware_sha256,
        hardware_raw_sha256,
        hardware_identity_sha256,
    ) = _verified_hardware_subproof(
        subproofs.get("hardware"),
        expected=expected,
        outer_trust=trust,
        now_unix=now_unix,
    )
    proxy_sha256 = _verified_proxy_subproof(
        subproofs.get("proxy"), expected=expected
    )
    proxy_root = subproofs["proxy"]["trustRoot"]
    if (
        proxy_root["keyId"] == trust.key_id
        or proxy_root["provider"] == trust.provider
        or proxy_root["publicKeySpkiDerBase64url"]
        == canonical_base64url(trust.public_key_spki_der)
    ):
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            "proxy subproof and setup receipt require independent trust roots",
        )
    issued_at, expires_at = _verify_time_window(
        statement, FixedClock(now_unix)
    )
    subproofs_sha256 = sha256_digest(canonical_json_bytes(subproofs))
    return VerifiedSetupHardwareVerification(
        receipt_id=expected.receipt_id,
        receipt_sha256=sha256_digest(canonical_json_bytes(document)),
        setup_session_id=expected.setup_session_id,
        assignment=expected.assignment,
        runtime_evidence_sha256=expected.runtime_evidence_sha256,
        challenge_base64url=expected.challenge_base64url,
        challenge_sha256=expected.challenge_sha256,
        hardware_assurance_sha256=expected.hardware_assurance_sha256,
        hardware_statement_sha256=expected.hardware_statement_sha256,
        hardware_verifier_provider=trust.provider,
        hardware_verifier_key_id=trust.key_id,
        release_identity_sha256=expected.release_identity_sha256,
        current_host_identity_sha256=expected.current_host_identity_sha256,
        proxy_server_statement_sha256=expected.proxy_server_statement_sha256,
        trust_profile_sha256=expected.trust_profile_sha256,
        decision="verified-hardware-identity-no-custody-claim",
        checks=(
            "signed-closed-receipt",
            "hardware-raw-nitro-cose-es384",
            "hardware-aws-chain-and-current-crls",
            "hardware-module-time-nonce-user-data",
            "hardware-non-debug-eif-pcr0-2",
            "hardware-identity-not-key-custody",
            "proxy-raw-evidence-binding",
            "proxy-independent-trust-root",
            "tls-exporter-and-peer-binding",
        ),
        issued_at_unix=issued_at,
        expires_at_unix=expires_at,
        verified_subproofs_sha256=sha256_digest(
            canonical_json_bytes(
                {
                    "hardwareSha256": hardware_sha256,
                    "hardwareRawEvidenceSha256": hardware_raw_sha256,
                    "hardwareIdentitySha256":
                    hardware_identity_sha256,
                    "keyCustodyVerified": False,
                    "proxySha256": proxy_sha256,
                    "subproofsSha256": subproofs_sha256,
                }
            )
        ),
    )


def verify_setup_hardware_verification(
    raw: bytes,
    *,
    trust: Ed25519TrustRoot,
    expected: HardwareVerificationExpected,
    clock: Clock | Callable[[], int],
    limits: JsonLimits = DEFAULT_JSON_LIMITS,
) -> VerifiedSetupHardwareVerification:
    document = parse_strict_json_object(raw, limits=limits)
    if document.get("apiVersion") == HARDWARE_VERIFICATION_CLOSED_API_VERSION:
        return _verify_closed_setup_hardware_verification(
            document,
            trust=trust,
            expected=expected,
            clock=clock,
        )
    raise ReceiptContractError(
        ReceiptErrorCode.CONTRACT_MISMATCH,
        "setup hardware verification requires v2 raw independently signed subproofs; opaque v1 decisions are rejected",
    )


def derive_setup_completion_identity(
    enrollment: VerifiedEnrollmentVerifierReceipt,
    hardware: VerifiedSetupHardwareVerification,
) -> SetupCompletionIdentity:
    if (
        type(enrollment) is not VerifiedEnrollmentVerifierReceipt
        or type(hardware) is not VerifiedSetupHardwareVerification
    ):
        raise ReceiptBindingError(
            ReceiptErrorCode.INVALID_INPUT,
            "completion identity requires verified receipt projections",
        )
    if enrollment.setup_session_id != hardware.setup_session_id:
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH, "setup session bindings differ"
        )
    if enrollment.assignment != hardware.assignment:
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH, "setup assignment bindings differ"
        )
    if not hmac.compare_digest(
        enrollment.trust_profile_sha256, hardware.trust_profile_sha256
    ):
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH, "trust profile bindings differ"
        )
    if hardware.issued_at_unix < enrollment.issued_at_unix:
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "hardware verification predates enrollment verification",
        )
    completion_document = {
        "apiVersion": COMPLETION_IDENTITY_API_VERSION,
        "kind": "SetupCompletionIdentity",
        "setup_session_id": enrollment.setup_session_id,
        "assignment": enrollment.assignment.as_document(),
        "assignment_digest": enrollment.assignment.digest,
        "trust_profile_sha256": enrollment.trust_profile_sha256,
        "enrollment_verification": {
            "receipt_id": enrollment.receipt_id,
            "receipt_sha256": enrollment.receipt_sha256,
            "verifier_provider": enrollment.verifier_provider,
            "verifier_key_id": enrollment.verifier_key_id,
            "enrollment_session_id": enrollment.enrollment_session_id,
            "enrollment_packet_sha256": enrollment.enrollment_packet_sha256,
            "verifier_nonce_sha256": enrollment.verifier_nonce_sha256,
            "decision": enrollment.decision,
            "checks": list(enrollment.checks),
            "issued_at_unix": enrollment.issued_at_unix,
            "expires_at_unix": enrollment.expires_at_unix,
        },
        "hardware_verification": {
            "receipt_id": hardware.receipt_id,
            "receipt_sha256": hardware.receipt_sha256,
            "runtime_evidence_sha256": hardware.runtime_evidence_sha256,
            "challenge": hardware.challenge_base64url,
            "challenge_sha256": hardware.challenge_sha256,
            "hardware_assurance_sha256": hardware.hardware_assurance_sha256,
            "hardware_statement_sha256": hardware.hardware_statement_sha256,
            "hardware_verifier_provider": hardware.hardware_verifier_provider,
            "hardware_verifier_key_id": hardware.hardware_verifier_key_id,
            "release_identity_sha256": hardware.release_identity_sha256,
            "current_host_identity_sha256": hardware.current_host_identity_sha256,
            "proxy_server_statement_sha256": hardware.proxy_server_statement_sha256,
            "decision": hardware.decision,
            "checks": list(hardware.checks),
            "issued_at_unix": hardware.issued_at_unix,
            "expires_at_unix": hardware.expires_at_unix,
        },
    }
    encoded = canonical_json_bytes(completion_document)
    return SetupCompletionIdentity(
        canonical_bytes=encoded,
        digest_sha256=sha256_digest(encoded),
        setup_session_id=enrollment.setup_session_id,
        assignment=enrollment.assignment,
        trust_profile_sha256=enrollment.trust_profile_sha256,
        challenge_sha256=hardware.challenge_sha256,
        release_identity_sha256=hardware.release_identity_sha256,
        hardware_verifier_provider=hardware.hardware_verifier_provider,
        hardware_verifier_key_id=hardware.hardware_verifier_key_id,
        current_host_identity_sha256=hardware.current_host_identity_sha256,
        proxy_server_statement_sha256=hardware.proxy_server_statement_sha256,
        hardware_issued_at_unix=hardware.issued_at_unix,
    )


def verify_final_challenge_receipt(
    raw: bytes,
    *,
    trust: FinalChallengeTrust,
    completion: SetupCompletionIdentity,
    clock: Clock | Callable[[], int],
    limits: JsonLimits = DEFAULT_JSON_LIMITS,
) -> VerifiedFinalChallengeReceipt:
    if type(completion) is not SetupCompletionIdentity:
        raise ReceiptBindingError(
            ReceiptErrorCode.INVALID_INPUT,
            "final verification requires a derived completion identity",
        )
    if not hmac.compare_digest(
        completion.hardware_verifier_key_id, trust.hardware_verifier.key_id
    ):
        raise ReceiptTrustError(
            ReceiptErrorCode.UNTRUSTED_SIGNER,
            "completion hardware verifier does not match the pinned hardware trust root",
        )
    if completion.hardware_verifier_provider != trust.hardware_verifier.provider:
        raise ReceiptTrustError(
            ReceiptErrorCode.UNTRUSTED_SIGNER,
            "completion hardware provider does not match the pinned hardware provider",
        )
    document = parse_strict_json_object(raw, limits=limits)
    statement = _signed_statement(
        document,
        api_version=FINAL_CHALLENGE_RECEIPT_API_VERSION,
        kind="FinalChallengeConsumption",
        trust=trust.authority,
        statement_fields={
            "authority_provider",
            "consumption_id",
            "status",
            "issued_at_unix",
            "expires_at_unix",
            "challenge_nonce_sha256",
            "completion_identity_sha256",
            "release_identity_sha256",
            "hardware_verifier_key_id",
            "current_host_identity_sha256",
            "proxy_server_statement_sha256",
        },
    )
    _expect_equal(
        statement.get("authority_provider"),
        trust.authority.provider,
        "final authority provider",
    )
    consumption_id = statement.get("consumption_id")
    _require_identifier(consumption_id, "final consumption ID")
    _expect_equal(statement.get("status"), "consumed", "final challenge status")
    _expect_digest(statement, "challenge_nonce_sha256", completion.challenge_sha256)
    _expect_digest(statement, "completion_identity_sha256", completion.digest_sha256)
    _expect_digest(
        statement, "release_identity_sha256", completion.release_identity_sha256
    )
    _expect_digest(
        statement, "hardware_verifier_key_id", completion.hardware_verifier_key_id
    )
    _expect_digest(
        statement,
        "current_host_identity_sha256",
        completion.current_host_identity_sha256,
    )
    _expect_digest(
        statement,
        "proxy_server_statement_sha256",
        completion.proxy_server_statement_sha256,
    )
    issued_at, expires_at = _verify_time_window(statement, clock)
    if issued_at < completion.hardware_issued_at_unix:
        raise ReceiptTimeError(
            ReceiptErrorCode.INVALID_TIME,
            "final challenge receipt predates hardware verification",
        )
    return VerifiedFinalChallengeReceipt(
        receipt_sha256=sha256_digest(canonical_json_bytes(document)),
        consumption_id=str(consumption_id),
        authority_provider=trust.authority.provider,
        authority_key_id=trust.authority.key_id,
        challenge_sha256=completion.challenge_sha256,
        completion_identity_sha256=completion.digest_sha256,
        release_identity_sha256=completion.release_identity_sha256,
        hardware_verifier_key_id=completion.hardware_verifier_key_id,
        current_host_identity_sha256=completion.current_host_identity_sha256,
        proxy_server_statement_sha256=completion.proxy_server_statement_sha256,
        issued_at_unix=issued_at,
        expires_at_unix=expires_at,
    )


def _signed_statement(
    document: Mapping[str, FrozenJson],
    *,
    api_version: str,
    kind: str,
    trust: Ed25519TrustRoot,
    statement_fields: set[str],
) -> Mapping[str, FrozenJson]:
    _exact_fields(
        document,
        {"apiVersion", "kind", "statement", "signing_key_id", "signature"},
        "signed receipt",
    )
    if document.get("apiVersion") != api_version or document.get("kind") != kind:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "receipt type does not match the required contract",
        )
    statement = document.get("statement")
    if not isinstance(statement, Mapping):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "receipt statement must be an object",
        )
    _exact_fields(statement, statement_fields, "signed statement")
    signing_key_id = document.get("signing_key_id")
    _require_digest(signing_key_id, "receipt signing key ID")
    if not hmac.compare_digest(str(signing_key_id), trust.key_id):
        raise ReceiptTrustError(
            ReceiptErrorCode.UNTRUSTED_SIGNER,
            "receipt signing key does not match the pinned trust root",
        )
    signature = document.get("signature")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "receipt signature must use canonical Ed25519 encoding",
        )
    signature_bytes = _decode_base64url(
        signature[len("ed25519:") :],
        expected_bytes=64,
        label="receipt signature",
    )
    try:
        _load_ed25519_spki(trust.public_key_spki_der).verify(
            signature_bytes,
            canonical_json_bytes(statement),
        )
    except InvalidSignature as exc:
        raise ReceiptSignatureError(
            ReceiptErrorCode.INVALID_SIGNATURE,
            "receipt signature verification failed",
        ) from exc
    return statement


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} fields do not exactly match the contract",
        )


def _expect_assignment(
    statement: Mapping[str, FrozenJson], expected: SetupAssignment
) -> None:
    assignment = statement.get("assignment")
    if not isinstance(assignment, Mapping):
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "receipt assignment must be an object",
        )
    _exact_fields(
        assignment,
        {
            "principalId",
            "routeId",
            "credentialId",
            "credentialVersion",
            "policyHash",
            "routePolicyDigest",
        },
        "receipt assignment",
    )
    if not hmac.compare_digest(
        canonical_json_bytes(assignment), canonical_json_bytes(expected.as_document())
    ):
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            "receipt assignment does not match the expected immutable assignment",
        )
    _expect_digest(statement, "assignment_digest", expected.digest)


def _expect_decision_and_checks(
    statement: Mapping[str, FrozenJson],
    expected_checks: tuple[str, ...],
) -> None:
    if statement.get("decision") != "verified":
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "receipt decision is not the required verified decision",
        )
    checks = statement.get("checks")
    if type(checks) is not tuple or checks != expected_checks:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            "receipt checks do not exactly match the required signed contract",
        )


def _verify_time_window(
    statement: Mapping[str, FrozenJson],
    clock: Clock | Callable[[], int],
    *,
    max_lifetime_seconds: int = 900,
    future_skew_seconds: int = 30,
) -> tuple[int, int]:
    issued_at = statement.get("issued_at_unix")
    expires_at = statement.get("expires_at_unix")
    if type(issued_at) is not int or type(expires_at) is not int:
        raise ReceiptTimeError(
            ReceiptErrorCode.INVALID_TIME,
            "receipt times must be integer Unix timestamps",
        )
    now = _clock_now(clock)
    if issued_at < 1 or issued_at > now + future_skew_seconds:
        raise ReceiptTimeError(
            ReceiptErrorCode.INVALID_TIME, "receipt issue time is invalid"
        )
    if expires_at <= now or expires_at <= issued_at:
        raise ReceiptTimeError(
            ReceiptErrorCode.INVALID_TIME,
            "receipt is expired or has an invalid interval",
        )
    if expires_at - issued_at > max_lifetime_seconds:
        raise ReceiptTimeError(
            ReceiptErrorCode.INVALID_TIME, "receipt validity interval is too long"
        )
    return issued_at, expires_at


def _clock_now(clock: Clock | Callable[[], int]) -> int:
    try:
        value = clock.now_unix() if hasattr(clock, "now_unix") else clock()
    except Exception as exc:
        raise ReceiptTimeError(
            ReceiptErrorCode.INVALID_TIME, "injected clock failed"
        ) from exc
    if type(value) is not int or value < 1:
        raise ReceiptTimeError(
            ReceiptErrorCode.INVALID_TIME, "injected clock returned an invalid time"
        )
    return value


def _expect_digest(
    statement: Mapping[str, FrozenJson], field: str, expected: str
) -> None:
    actual = statement.get(field)
    _require_digest(actual, field)
    if not hmac.compare_digest(str(actual), expected):
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            f"receipt {field} does not match the expected binding",
        )


def _expect_equal(actual: Any, expected: Any, label: str) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise ReceiptBindingError(
            ReceiptErrorCode.BINDING_MISMATCH,
            f"receipt {label} does not match the expected binding",
        )


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} must be a lowercase SHA-256 digest",
        )
    return value


def _require_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or _UUID_RE.fullmatch(value) is None:
        raise ReceiptContractError(
            ReceiptErrorCode.INVALID_INPUT,
            f"{label} must be a canonical lowercase UUID",
        )
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ReceiptContractError(
            ReceiptErrorCode.INVALID_INPUT,
            f"{label} must be a canonical lowercase UUID",
        ) from exc
    if str(parsed) != value:
        raise ReceiptContractError(
            ReceiptErrorCode.INVALID_INPUT,
            f"{label} must be a canonical lowercase UUID",
        )
    return value


def _require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ReceiptContractError(
            ReceiptErrorCode.CONTRACT_MISMATCH,
            f"{label} is not a canonical identifier",
        )
    return value


def _require_provider(value: Any, label: str) -> str:
    if not isinstance(value, str) or _PROVIDER_RE.fullmatch(value) is None:
        raise ReceiptTrustError(
            ReceiptErrorCode.TRUST_CONFIGURATION,
            f"{label} is not a canonical provider identifier",
        )
    return value


__all__ = [
    "COMPLETION_IDENTITY_API_VERSION",
    "DEFAULT_JSON_LIMITS",
    "ENROLLMENT_CHECKS",
    "ENROLLMENT_RECEIPT_API_VERSION",
    "Ed25519TrustRoot",
    "FinalChallengeTrust",
    "FixedClock",
    "HARDWARE_CHECKS",
    "HARDWARE_VERIFICATION_CLOSED_API_VERSION",
    "HARDWARE_VERIFICATION_API_VERSION",
    "HardwareVerificationExpected",
    "JsonLimits",
    "PRODUCTION_ATTESTATION_PIPELINE",
    "ReceiptBindingError",
    "ReceiptContractError",
    "ReceiptErrorCode",
    "ReceiptParseError",
    "ReceiptSignatureError",
    "ReceiptTimeError",
    "ReceiptTrustError",
    "ReceiptVerificationError",
    "SetupAssignment",
    "SetupCompletionIdentity",
    "VerifiedEnrollmentVerifierReceipt",
    "VerifiedFinalChallengeReceipt",
    "VerifiedSetupHardwareVerification",
    "VERIFIED_HARDWARE_SUBPROOF_API_VERSION",
    "VERIFIED_PROXY_SUBPROOF_API_VERSION",
    "EnrollmentReceiptExpected",
    "canonical_base64url",
    "canonical_json_bytes",
    "derive_setup_completion_identity",
    "parse_strict_json_object",
    "sha256_digest",
    "spki_key_id",
    "verify_enrollment_verifier_receipt",
    "verify_final_challenge_receipt",
    "verify_setup_hardware_verification",
]
