from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, TypeAlias

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ENROLLMENT_RECEIPT_API_VERSION = "serverware.enrollmentVerifierReceipt/v2"
HARDWARE_VERIFICATION_API_VERSION = "serverware.setupHardwareVerification/v1"
COMPLETION_IDENTITY_API_VERSION = "serverware.setupCompletionIdentity/v1"
FINAL_CHALLENGE_RECEIPT_API_VERSION = "serverware.finalChallengeReceipt/v1"

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
    max_bytes: int = 64 * 1024
    max_depth: int = 16
    max_object_keys: int = 64
    max_total_keys: int = 512
    max_array_items: int = 128
    max_total_nodes: int = 4096
    max_string_bytes: int = 4096
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

    def __post_init__(self) -> None:
        _require_provider(self.provider, "trust provider")
        _load_ed25519_spki(self.public_key_spki_der)

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


def verify_setup_hardware_verification(
    raw: bytes,
    *,
    trust: Ed25519TrustRoot,
    expected: HardwareVerificationExpected,
    clock: Clock | Callable[[], int],
    limits: JsonLimits = DEFAULT_JSON_LIMITS,
) -> VerifiedSetupHardwareVerification:
    document = parse_strict_json_object(raw, limits=limits)
    statement = _signed_statement(
        document,
        api_version=HARDWARE_VERIFICATION_API_VERSION,
        kind="SetupHardwareVerification",
        trust=trust,
        statement_fields={
            "receipt_id",
            "setup_session_id",
            "assignment",
            "assignment_digest",
            "runtime_evidence_sha256",
            "challenge",
            "challenge_sha256",
            "hardware_assurance_sha256",
            "hardware_statement_sha256",
            "hardware_verifier_provider",
            "hardware_verifier_key_id",
            "release_identity_sha256",
            "current_host_identity_sha256",
            "proxy_server_statement_sha256",
            "trust_profile_sha256",
            "decision",
            "checks",
            "issued_at_unix",
            "expires_at_unix",
        },
    )
    _expect_equal(
        statement.get("receipt_id"), expected.receipt_id, "hardware receipt ID"
    )
    _expect_equal(
        statement.get("setup_session_id"), expected.setup_session_id, "setup session ID"
    )
    _expect_assignment(statement, expected.assignment)
    _expect_digest(
        statement, "runtime_evidence_sha256", expected.runtime_evidence_sha256
    )
    _expect_equal(
        statement.get("challenge"), expected.challenge_base64url, "hardware challenge"
    )
    _decode_base64url(
        statement.get("challenge"),
        expected_bytes=len(expected.challenge),
        label="hardware challenge",
    )
    _expect_digest(statement, "challenge_sha256", expected.challenge_sha256)
    _expect_digest(
        statement, "hardware_assurance_sha256", expected.hardware_assurance_sha256
    )
    _expect_digest(
        statement, "hardware_statement_sha256", expected.hardware_statement_sha256
    )
    _expect_equal(
        statement.get("hardware_verifier_provider"),
        trust.provider,
        "hardware verifier provider",
    )
    _expect_digest(statement, "hardware_verifier_key_id", trust.key_id)
    _expect_digest(
        statement, "release_identity_sha256", expected.release_identity_sha256
    )
    _expect_digest(
        statement, "current_host_identity_sha256", expected.current_host_identity_sha256
    )
    _expect_digest(
        statement,
        "proxy_server_statement_sha256",
        expected.proxy_server_statement_sha256,
    )
    _expect_digest(statement, "trust_profile_sha256", expected.trust_profile_sha256)
    _expect_decision_and_checks(statement, HARDWARE_CHECKS)
    issued_at, expires_at = _verify_time_window(statement, clock)
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
        decision="verified",
        checks=HARDWARE_CHECKS,
        issued_at_unix=issued_at,
        expires_at_unix=expires_at,
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
    "HARDWARE_VERIFICATION_API_VERSION",
    "HardwareVerificationExpected",
    "JsonLimits",
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
