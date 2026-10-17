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


REQUEST_API_VERSION = "catchplate.launchAuthorizationRequest/v2"
REQUEST_KIND = "ProductionLaunchAuthorizationRequest"
AUTHORIZATION_API_VERSION = "catchplate.launchAuthorization/v2"
AUTHORIZATION_KIND = "ProductionLaunchAuthorization"
AUTHORIZATION_SCOPE = "trusted-host-readiness"
FRESHNESS_AUTHORITY = "trusted-host-wall-clock"
CAPABILITY_SEMANTICS = "time-bounded-idempotent-readiness-authorization"
GLOBAL_ROLE_REGISTRY_API_VERSION = (
    "catchplate.productionLaunchGlobalRoleRegistry/v1"
)
GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE = "roles-present-in-native-launch-contract"
GLOBAL_ROLE_REGISTRY_REQUIRED_ROLES = frozenset(
    {
        "launchAuthority",
        "launchAuthorityWitness",
        "launchAuthorityWitnessStoreAssurance",
        "launchAuthorityWitnessTls",
        "nonceAuthorityAssuranceEvidence",
        "nonceAuthorityVerifierState",
        "nonceAuthorityVerifierStateStoreAttestation",
        "policyActivation",
        "policyIdentity",
        "reproducibleBuild",
    }
)
GLOBAL_ROLE_REGISTRY_ROLES_OUTSIDE_CLAIM = (
    "actionGate",
    "publicAttestationNonceStore",
    "publicAttestationProducer",
    "publicAttestationWitnessStore",
    "finalVerifier",
    "nonceAuthorityVerifierStateStoreAssurance",
    "release",
    "response",
    "verifierStateTlsClient",
    "verifierStateTlsServer",
)
LAUNCH_ATTEMPT_JOURNAL_DOMAIN = (
    "catchplate.launchAuthorizationAttemptJournal/v1"
)
WITNESS_REQUEST_API_VERSION = "catchplate.launchAuthorityWitnessTransitionRequest/v1"
WITNESS_REQUEST_KIND = "LaunchAuthorityWitnessTransitionRequest"
WITNESS_API_VERSION = "catchplate.launchAuthorityWitnessTransition/v1"
WITNESS_KIND = "LaunchAuthorityWitnessTransition"
WITNESS_OPERATION = "authorize-trusted-host-readiness"
REGISTRY_OBSERVATION_REQUEST_API_VERSION = (
    "catchplate.launchAuthorityRegistryObservationRequest/v1"
)
REGISTRY_OBSERVATION_REQUEST_KIND = "LaunchAuthorityRegistryObservationRequest"
REGISTRY_OBSERVATION_API_VERSION = (
    "catchplate.launchAuthorityRegistryObservation/v1"
)
REGISTRY_OBSERVATION_KIND = "LaunchAuthorityRegistryObservation"
REGISTRY_OBSERVATION_OPERATION = "observe-launch-authority-registry-head"
REQUEST_DOMAIN = REQUEST_API_VERSION.encode("ascii") + b"\0"
AUTHORIZATION_DOMAIN = AUTHORIZATION_API_VERSION.encode("ascii") + b"\0"
WITNESS_DOMAIN = WITNESS_API_VERSION.encode("ascii") + b"\0"
REGISTRY_OBSERVATION_DOMAIN = (
    REGISTRY_OBSERVATION_API_VERSION.encode("ascii") + b"\0"
)
LAUNCH_ATTEMPT_RECOVERY_IDENTITY_DOMAIN = (
    b"catchplate.launchAuthorizationAttemptRecoveryIdentity/v1\0"
)

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
        "nonceRollbackAssuranceContractSha256",
        "nonceRollbackAssurancePinsSha256",
        "releaseProvenanceSha256",
        "provenanceDigest",
        "reproducibleBuildVerificationSha256",
        "sourceTreeDigest",
        "deploymentAudience",
        "deploymentIdentitySha256",
        "releaseSequence",
        "rollbackEpoch",
        "authorizationScope",
        "freshnessAuthority",
        "launchAuthorityWitnessChallenge",
        "launchAuthorityWitnessKeyId",
        "launchAuthorityWitnessIdentitySha256",
        "launchAuthorityWitnessAdministrativeDomainSha256",
        "launchAuthorityWitnessStoreAssuranceSha256",
        "globalRoleRegistry",
        "globalRoleRegistrySha256",
        "globalRoleRegistryPinsSha256",
        "launchAttemptJournalDomain",
        "launchAttemptRecoveryIdentitySha256",
    }
)
_REQUEST_DIGEST_FIELDS = (
    "bootIdSha256",
    "launcherSha256",
    "manifestSha256",
    "nonceRollbackAssuranceContractSha256",
    "nonceRollbackAssurancePinsSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "reproducibleBuildVerificationSha256",
    "sourceTreeDigest",
    "deploymentIdentitySha256",
    "launchAuthorityWitnessKeyId",
    "launchAuthorityWitnessIdentitySha256",
    "launchAuthorityWitnessAdministrativeDomainSha256",
    "launchAuthorityWitnessStoreAssuranceSha256",
    "globalRoleRegistrySha256",
    "globalRoleRegistryPinsSha256",
    "launchAttemptRecoveryIdentitySha256",
)
_AUTHORIZATION_FIELDS = frozenset({"apiVersion", "kind", "statement", "signature"})
_STATEMENT_FIELDS = frozenset(
    {
        "authorizationId",
        "authorityKeyId",
        "requestSha256",
        "issuedAtUnixSeconds",
        "expiresAtUnixSeconds",
        "authorizationScope",
        "freshnessAuthority",
        "capabilitySemantics",
        "globalRoleRegistrySha256",
        "monotonicWitness",
    }
)
_GLOBAL_ROLE_REGISTRY_FIELDS = frozenset(
    {
        "apiVersion",
        "claimScope",
        "roles",
        "rolesOutsideClaim",
    }
)
_WITNESS_FIELDS = frozenset({"apiVersion", "kind", "statement", "signature"})
_WITNESS_REQUEST_FIELDS = frozenset(
    {
        "apiVersion",
        "kind",
        "operation",
        "operationId",
        "authorizationId",
        "requestSha256",
        "challenge",
        "issuedAtUnixSeconds",
        "expiresAtUnixSeconds",
        "authorityKeyId",
        "witnessKeyId",
        "witnessIdentitySha256",
        "witnessAdministrativeDomainSha256",
        "storeAssuranceSha256",
        "registryGeneration",
        "registrySha256",
        "predecessorStateSha256",
        "successorStateSha256",
        "deploymentAudience",
        "deploymentIdentitySha256",
        "releaseSequence",
        "rollbackEpoch",
        "authorizationScope",
    }
)
_WITNESS_STATEMENT_FIELDS = frozenset(
    {
        "operation",
        "operationId",
        "authorizationId",
        "requestSha256",
        "challenge",
        "issuedAtUnixSeconds",
        "expiresAtUnixSeconds",
        "authorityKeyId",
        "witnessKeyId",
        "witnessIdentitySha256",
        "witnessAdministrativeDomainSha256",
        "storeAssuranceSha256",
        "registryGeneration",
        "registrySha256",
        "predecessorStateSha256",
        "successorStateSha256",
        "deploymentAudience",
        "deploymentIdentitySha256",
        "releaseSequence",
        "rollbackEpoch",
        "authorizationScope",
        "stateTransitionCommitted",
        "checkpointSequence",
    }
)
_REGISTRY_OBSERVATION_REQUEST_FIELDS = frozenset(
    {
        "apiVersion",
        "kind",
        "operation",
        "operationId",
        "challenge",
        "authorityKeyId",
        "witnessKeyId",
        "witnessIdentitySha256",
        "witnessAdministrativeDomainSha256",
        "storeAssuranceSha256",
        "registryGeneration",
        "registrySha256",
    }
)
_REGISTRY_OBSERVATION_FIELDS = frozenset(
    {"apiVersion", "kind", "statement", "signature"}
)
_REGISTRY_OBSERVATION_STATEMENT_FIELDS = frozenset(
    {
        "operation",
        "operationId",
        "challenge",
        "authorityKeyId",
        "witnessKeyId",
        "witnessIdentitySha256",
        "witnessAdministrativeDomainSha256",
        "storeAssuranceSha256",
        "registryGeneration",
        "registrySha256",
        "registryHeadObserved",
        "checkpointSequence",
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
    authorization_scope: str
    freshness_authority: str
    capability_semantics: str
    global_role_registry_sha256: str
    monotonic_witness: Mapping[str, Any]


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


def launch_global_role_registry_sha256(value: Any) -> str:
    registry = _require_exact_fields(
        value, _GLOBAL_ROLE_REGISTRY_FIELDS, "launch global role registry"
    )
    _require_literal(
        registry["apiVersion"],
        GLOBAL_ROLE_REGISTRY_API_VERSION,
        "launch global role registry apiVersion",
    )
    _require_literal(
        registry["claimScope"],
        GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE,
        "launch global role registry claimScope",
    )
    roles = _require_exact_fields(
        registry["roles"],
        GLOBAL_ROLE_REGISTRY_REQUIRED_ROLES,
        "launch global role registry roles",
    )
    normalized_roles = {
        role: _require_sha256(
            roles[role], f"launch global role registry {role} SPKI digest"
        )
        for role in sorted(roles)
    }
    if len(set(normalized_roles.values())) != len(normalized_roles):
        raise LaunchAuthorizationError(
            "launch global role registry reuses an SPKI across security roles"
        )
    roles_outside_claim = registry["rolesOutsideClaim"]
    if (
        not isinstance(roles_outside_claim, (list, tuple))
        or tuple(roles_outside_claim)
        != GLOBAL_ROLE_REGISTRY_ROLES_OUTSIDE_CLAIM
    ):
        raise LaunchAuthorizationError(
            "launch global role registry rolesOutsideClaim is not the closed list"
        )
    normalized = {
        "apiVersion": GLOBAL_ROLE_REGISTRY_API_VERSION,
        "claimScope": GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE,
        "roles": normalized_roles,
        "rolesOutsideClaim": list(GLOBAL_ROLE_REGISTRY_ROLES_OUTSIDE_CLAIM),
    }
    return (
        "sha256:"
        + hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
    )


def validate_launch_global_role_registry(value: Any) -> dict[str, Any]:
    registry = _require_exact_fields(
        value, _GLOBAL_ROLE_REGISTRY_FIELDS, "launch global role registry"
    )
    launch_global_role_registry_sha256(registry)
    return {
        "apiVersion": GLOBAL_ROLE_REGISTRY_API_VERSION,
        "claimScope": GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE,
        "roles": {
            role: registry["roles"][role]
            for role in sorted(GLOBAL_ROLE_REGISTRY_REQUIRED_ROLES)
        },
        "rolesOutsideClaim": list(GLOBAL_ROLE_REGISTRY_ROLES_OUTSIDE_CLAIM),
    }


def _require_launch_authority_witness_role_binding(
    registry: Mapping[str, Any],
    witness_key_id: Any,
    *,
    label: str,
) -> str:
    normalized_witness_key_id = _require_sha256(
        witness_key_id, f"{label} witness key ID"
    )
    registry_witness_key_id = registry["roles"]["launchAuthorityWitness"]
    if not hmac.compare_digest(
        registry_witness_key_id, normalized_witness_key_id
    ):
        raise LaunchAuthorizationError(
            f"{label} witness key differs from global role registry "
            "launchAuthorityWitness"
        )
    return normalized_witness_key_id


def build_launch_global_role_registry(
    roles: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "apiVersion": GLOBAL_ROLE_REGISTRY_API_VERSION,
        "claimScope": GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE,
        "roles": dict(roles),
        "rolesOutsideClaim": list(GLOBAL_ROLE_REGISTRY_ROLES_OUTSIDE_CLAIM),
    }
    return validate_launch_global_role_registry(core)


def launch_attempt_recovery_identity_sha256(
    request: Mapping[str, Any],
) -> str:
    identity = {
        "domain": LAUNCH_ATTEMPT_JOURNAL_DOMAIN,
        "launcherNonce": request["launcherNonce"],
        "witnessChallenge": request["launchAuthorityWitnessChallenge"],
        "bootIdSha256": request["bootIdSha256"],
        "manifestSha256": request["manifestSha256"],
        "globalRoleRegistrySha256": request["globalRoleRegistrySha256"],
    }
    return (
        "sha256:"
        + hashlib.sha256(
            LAUNCH_ATTEMPT_RECOVERY_IDENTITY_DOMAIN
            + canonical_json_bytes(identity)
        ).hexdigest()
    )


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
    _require_literal(
        request["authorizationScope"], AUTHORIZATION_SCOPE, "request authorizationScope"
    )
    _require_literal(
        request["freshnessAuthority"], FRESHNESS_AUTHORITY, "request freshnessAuthority"
    )
    _require_hex_64(
        request["launchAuthorityWitnessChallenge"],
        "request launchAuthorityWitnessChallenge",
    )
    global_role_registry = validate_launch_global_role_registry(
        request["globalRoleRegistry"]
    )
    _require_launch_authority_witness_role_binding(
        global_role_registry,
        request["launchAuthorityWitnessKeyId"],
        label="request",
    )
    global_role_registry_sha256 = launch_global_role_registry_sha256(
        global_role_registry
    )
    if not hmac.compare_digest(
        request["globalRoleRegistrySha256"],
        global_role_registry_sha256,
    ):
        raise LaunchAuthorizationError(
            "request global role registry digest binding mismatch"
        )
    _require_literal(
        request["launchAttemptJournalDomain"],
        LAUNCH_ATTEMPT_JOURNAL_DOMAIN,
        "request launchAttemptJournalDomain",
    )
    if not hmac.compare_digest(
        request["launchAttemptRecoveryIdentitySha256"],
        launch_attempt_recovery_identity_sha256(request),
    ):
        raise LaunchAuthorizationError(
            "request launch attempt recovery identity binding mismatch"
        )
    rendered = dict(request)
    rendered["globalRoleRegistry"] = global_role_registry
    return rendered


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
    _require_literal(
        statement["authorizationScope"],
        AUTHORIZATION_SCOPE,
        "statement authorizationScope",
    )
    _require_literal(
        statement["freshnessAuthority"],
        FRESHNESS_AUTHORITY,
        "statement freshnessAuthority",
    )
    _require_literal(
        statement["capabilitySemantics"],
        CAPABILITY_SEMANTICS,
        "statement capabilitySemantics",
    )
    _require_sha256(
        statement["globalRoleRegistrySha256"],
        "statement globalRoleRegistrySha256",
    )
    rendered = dict(statement)
    rendered["monotonicWitness"] = validate_launch_authority_witness(
        statement["monotonicWitness"]
    )
    return rendered


def validate_launch_authority_witness_statement(value: Any) -> dict[str, Any]:
    statement = _require_exact_fields(
        value, _WITNESS_STATEMENT_FIELDS, "launch-authority witness statement"
    )
    _require_literal(
        statement["operation"], WITNESS_OPERATION, "witness statement operation"
    )
    _require_hex_64(statement["operationId"], "witness statement operationId")
    _require_hex_64(statement["authorizationId"], "witness statement authorizationId")
    _require_sha256(statement["requestSha256"], "witness statement requestSha256")
    _require_hex_64(statement["challenge"], "witness statement challenge")
    for field in (
        "authorityKeyId",
        "witnessKeyId",
        "witnessIdentitySha256",
        "witnessAdministrativeDomainSha256",
        "storeAssuranceSha256",
        "registrySha256",
        "predecessorStateSha256",
        "successorStateSha256",
        "deploymentIdentitySha256",
    ):
        _require_sha256(statement[field], f"witness statement {field}")
    audience = statement["deploymentAudience"]
    if type(audience) is not str or _AUDIENCE_RE.fullmatch(audience) is None:
        raise LaunchAuthorizationError("witness statement deploymentAudience is invalid")
    for field, minimum in (
        ("registryGeneration", 1),
        ("releaseSequence", 1),
        ("rollbackEpoch", 0),
        ("checkpointSequence", 1),
        ("issuedAtUnixSeconds", 1),
        ("expiresAtUnixSeconds", 1),
    ):
        _require_safe_integer(statement[field], f"witness statement {field}", minimum=minimum)
    if (
        statement["expiresAtUnixSeconds"] <= statement["issuedAtUnixSeconds"]
        or statement["expiresAtUnixSeconds"] - statement["issuedAtUnixSeconds"]
        > MAX_VALIDITY_SECONDS
    ):
        raise LaunchAuthorizationError(
            "witness statement authorization validity interval is invalid"
        )
    _require_literal(
        statement["authorizationScope"],
        AUTHORIZATION_SCOPE,
        "witness statement authorizationScope",
    )
    if statement["stateTransitionCommitted"] is not True:
        raise LaunchAuthorizationError(
            "witness statement stateTransitionCommitted must equal true"
        )
    if hmac.compare_digest(
        statement["predecessorStateSha256"], statement["successorStateSha256"]
    ):
        raise LaunchAuthorizationError(
            "witness statement must commit a non-identity state transition"
        )
    return dict(statement)


def validate_launch_authority_witness_request(value: Any) -> dict[str, Any]:
    request = _require_exact_fields(
        value, _WITNESS_REQUEST_FIELDS, "launch-authority witness request"
    )
    _require_literal(
        request["apiVersion"],
        WITNESS_REQUEST_API_VERSION,
        "witness request apiVersion",
    )
    _require_literal(
        request["kind"], WITNESS_REQUEST_KIND, "witness request kind"
    )
    synthetic_statement = {
        **{
            field: request[field]
            for field in _WITNESS_REQUEST_FIELDS
            if field not in {"apiVersion", "kind"}
        },
        "stateTransitionCommitted": True,
        "checkpointSequence": 1,
    }
    validate_launch_authority_witness_statement(synthetic_statement)
    return dict(request)


def validate_launch_authority_witness(value: Any) -> dict[str, Any]:
    envelope = _require_exact_fields(value, _WITNESS_FIELDS, "launch-authority witness")
    _require_literal(envelope["apiVersion"], WITNESS_API_VERSION, "witness apiVersion")
    _require_literal(envelope["kind"], WITNESS_KIND, "witness kind")
    statement = validate_launch_authority_witness_statement(envelope["statement"])
    _decode_signature(envelope["signature"])
    return {
        "apiVersion": envelope["apiVersion"],
        "kind": envelope["kind"],
        "statement": statement,
        "signature": envelope["signature"],
    }


def validate_registry_observation_request(value: Any) -> dict[str, Any]:
    request = _require_exact_fields(
        value,
        _REGISTRY_OBSERVATION_REQUEST_FIELDS,
        "launch-authority registry observation request",
    )
    _require_literal(
        request["apiVersion"],
        REGISTRY_OBSERVATION_REQUEST_API_VERSION,
        "registry observation request apiVersion",
    )
    _require_literal(
        request["kind"],
        REGISTRY_OBSERVATION_REQUEST_KIND,
        "registry observation request kind",
    )
    _require_literal(
        request["operation"],
        REGISTRY_OBSERVATION_OPERATION,
        "registry observation request operation",
    )
    _require_hex_64(
        request["operationId"], "registry observation request operationId"
    )
    _require_hex_64(
        request["challenge"], "registry observation request challenge"
    )
    for field in (
        "authorityKeyId",
        "witnessKeyId",
        "witnessIdentitySha256",
        "witnessAdministrativeDomainSha256",
        "storeAssuranceSha256",
        "registrySha256",
    ):
        _require_sha256(
            request[field], f"registry observation request {field}"
        )
    _require_safe_integer(
        request["registryGeneration"],
        "registry observation request registryGeneration",
        minimum=1,
    )
    return dict(request)


def validate_registry_observation_statement(value: Any) -> dict[str, Any]:
    statement = _require_exact_fields(
        value,
        _REGISTRY_OBSERVATION_STATEMENT_FIELDS,
        "launch-authority registry observation statement",
    )
    request_fields = {
        field: statement[field]
        for field in _REGISTRY_OBSERVATION_REQUEST_FIELDS
        if field not in {"apiVersion", "kind"}
    }
    validate_registry_observation_request(
        {
            "apiVersion": REGISTRY_OBSERVATION_REQUEST_API_VERSION,
            "kind": REGISTRY_OBSERVATION_REQUEST_KIND,
            **request_fields,
        }
    )
    if statement["registryHeadObserved"] is not True:
        raise LaunchAuthorizationError(
            "registry observation registryHeadObserved must equal true"
        )
    _require_safe_integer(
        statement["checkpointSequence"],
        "registry observation checkpointSequence",
        minimum=1,
    )
    return dict(statement)


def validate_registry_observation(value: Any) -> dict[str, Any]:
    envelope = _require_exact_fields(
        value, _REGISTRY_OBSERVATION_FIELDS, "launch-authority registry observation"
    )
    _require_literal(
        envelope["apiVersion"],
        REGISTRY_OBSERVATION_API_VERSION,
        "registry observation apiVersion",
    )
    _require_literal(
        envelope["kind"],
        REGISTRY_OBSERVATION_KIND,
        "registry observation kind",
    )
    statement = validate_registry_observation_statement(envelope["statement"])
    _decode_signature(envelope["signature"])
    return {
        "apiVersion": envelope["apiVersion"],
        "kind": envelope["kind"],
        "statement": statement,
        "signature": envelope["signature"],
    }


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


def _unsigned_witness_envelope(statement: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": WITNESS_API_VERSION,
        "kind": WITNESS_KIND,
        "statement": dict(statement),
    }


def _unsigned_registry_observation_envelope(
    statement: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "apiVersion": REGISTRY_OBSERVATION_API_VERSION,
        "kind": REGISTRY_OBSERVATION_KIND,
        "statement": dict(statement),
    }


def launch_authority_witness_signing_bytes(statement: Any) -> bytes:
    validated = validate_launch_authority_witness_statement(statement)
    return WITNESS_DOMAIN + canonical_json_bytes(_unsigned_witness_envelope(validated))


def registry_observation_signing_bytes(statement: Any) -> bytes:
    validated = validate_registry_observation_statement(statement)
    return REGISTRY_OBSERVATION_DOMAIN + canonical_json_bytes(
        _unsigned_registry_observation_envelope(validated)
    )


def verify_registry_observation(
    value: Any,
    *,
    witness_public_key_spki_der: bytes,
    expected_witness_key_id: str,
    expected_request: Mapping[str, Any],
) -> dict[str, Any]:
    request = validate_registry_observation_request(expected_request)
    observation = validate_registry_observation(value)
    statement = observation["statement"]
    public_key = _load_ed25519_spki(witness_public_key_spki_der)
    actual_key_id = spki_key_id(witness_public_key_spki_der)
    if not hmac.compare_digest(actual_key_id, expected_witness_key_id):
        raise LaunchAuthorizationError(
            "trusted registry observation key does not match its key ID"
        )
    try:
        public_key.verify(
            _decode_signature(observation["signature"]),
            registry_observation_signing_bytes(statement),
        )
    except InvalidSignature as exc:
        raise LaunchAuthorizationError(
            "launch-authority registry observation signature is invalid"
        ) from exc
    for field in _REGISTRY_OBSERVATION_REQUEST_FIELDS:
        if field in {"apiVersion", "kind"}:
            continue
        actual = statement[field]
        expected = request[field]
        equal = (
            hmac.compare_digest(actual, expected)
            if isinstance(actual, str) and isinstance(expected, str)
            else actual == expected
        )
        if not equal:
            raise LaunchAuthorizationError(
                f"launch-authority registry observation {field} binding mismatch"
            )
    if not hmac.compare_digest(statement["witnessKeyId"], expected_witness_key_id):
        raise LaunchAuthorizationError(
            "launch-authority registry observation key ID binding mismatch"
        )
    return observation


def verify_launch_authority_witness(
    value: Any,
    *,
    witness_public_key_spki_der: bytes,
    expected_witness_key_id: str,
    expected_request: Mapping[str, Any],
    expected_authorization_id: str,
    expected_authority_key_id: str,
    expected_registry_generation: int | None = None,
    expected_registry_sha256: str | None = None,
    expected_predecessor_state_sha256: str | None = None,
    expected_successor_state_sha256: str | None = None,
    expected_issued_at_unix_seconds: int | None = None,
    expected_expires_at_unix_seconds: int | None = None,
) -> dict[str, Any]:
    request = validate_launch_authorization_request(expected_request)
    _require_launch_authority_witness_role_binding(
        request["globalRoleRegistry"],
        expected_witness_key_id,
        label="verifier",
    )
    witness = validate_launch_authority_witness(value)
    statement = witness["statement"]
    public_key = _load_ed25519_spki(witness_public_key_spki_der)
    actual_key_id = spki_key_id(witness_public_key_spki_der)
    if not hmac.compare_digest(actual_key_id, expected_witness_key_id):
        raise LaunchAuthorizationError("trusted witness key does not match its key ID")
    try:
        public_key.verify(
            _decode_signature(witness["signature"]),
            launch_authority_witness_signing_bytes(statement),
        )
    except InvalidSignature as exc:
        raise LaunchAuthorizationError("launch-authority witness signature is invalid") from exc
    exact = {
        "operationId": request["launcherNonce"],
        "authorizationId": expected_authorization_id,
        "requestSha256": launch_authorization_request_sha256(request),
        "challenge": request["launchAuthorityWitnessChallenge"],
        "authorityKeyId": expected_authority_key_id,
        "witnessKeyId": request["launchAuthorityWitnessKeyId"],
        "witnessIdentitySha256": request["launchAuthorityWitnessIdentitySha256"],
        "witnessAdministrativeDomainSha256": request[
            "launchAuthorityWitnessAdministrativeDomainSha256"
        ],
        "storeAssuranceSha256": request[
            "launchAuthorityWitnessStoreAssuranceSha256"
        ],
        "deploymentAudience": request["deploymentAudience"],
        "deploymentIdentitySha256": request["deploymentIdentitySha256"],
        "releaseSequence": request["releaseSequence"],
        "rollbackEpoch": request["rollbackEpoch"],
        "authorizationScope": request["authorizationScope"],
    }
    for field, expected in exact.items():
        actual = statement[field]
        equal = (
            hmac.compare_digest(actual, expected)
            if isinstance(actual, str) and isinstance(expected, str)
            else actual == expected
        )
        if not equal:
            raise LaunchAuthorizationError(
                f"launch-authority witness {field} binding mismatch"
            )
    if not hmac.compare_digest(statement["witnessKeyId"], expected_witness_key_id):
        raise LaunchAuthorizationError("launch-authority witness key ID binding mismatch")
    for field, expected in (
        ("registryGeneration", expected_registry_generation),
        ("registrySha256", expected_registry_sha256),
        ("predecessorStateSha256", expected_predecessor_state_sha256),
        ("successorStateSha256", expected_successor_state_sha256),
        ("issuedAtUnixSeconds", expected_issued_at_unix_seconds),
        ("expiresAtUnixSeconds", expected_expires_at_unix_seconds),
    ):
        if expected is None:
            continue
        actual = statement[field]
        equal = (
            hmac.compare_digest(actual, expected)
            if isinstance(actual, str) and isinstance(expected, str)
            else actual == expected
        )
        if not equal:
            raise LaunchAuthorizationError(
                f"launch-authority witness {field} binding mismatch"
            )
    return witness


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
    monotonic_witness: Any,
) -> dict[str, Any]:
    """Create an authorization using a caller-supplied authority key."""

    if not isinstance(private_key, Ed25519PrivateKey):
        raise LaunchAuthorizationError("private_key must be an Ed25519 private key")
    validated_request = validate_launch_authorization_request(request)
    authority_key_id = spki_key_id(
        _public_key_spki_der(private_key.public_key())
    )
    if not hmac.compare_digest(
        validated_request["globalRoleRegistry"]["roles"]["launchAuthority"],
        authority_key_id,
    ):
        raise LaunchAuthorizationError(
            "launch authority signing key differs from the global role registry"
        )
    validated_witness = validate_launch_authority_witness(monotonic_witness)
    _require_launch_authority_witness_role_binding(
        validated_request["globalRoleRegistry"],
        validated_witness["statement"]["witnessKeyId"],
        label="authorization signer",
    )
    statement = validate_launch_authorization_statement(
        {
            "authorizationId": authorization_id,
            "authorityKeyId": authority_key_id,
            "requestSha256": launch_authorization_request_sha256(
                validated_request
            ),
            "issuedAtUnixSeconds": issued_at_unix_seconds,
            "expiresAtUnixSeconds": expires_at_unix_seconds,
            "authorizationScope": AUTHORIZATION_SCOPE,
            "freshnessAuthority": FRESHNESS_AUTHORITY,
            "capabilitySemantics": CAPABILITY_SEMANTICS,
            "globalRoleRegistrySha256": validated_request[
                "globalRoleRegistrySha256"
            ],
            "monotonicWitness": validated_witness,
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
    expected_global_role_registry_sha256: str | None = None,
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
    if expected_global_role_registry_sha256 is not None:
        _require_sha256(
            expected_global_role_registry_sha256,
            "expected global role registry digest",
        )
        if not hmac.compare_digest(
            statement["globalRoleRegistrySha256"],
            expected_global_role_registry_sha256,
        ):
            raise LaunchAuthorizationError(
                "authorization global role registry digest binding mismatch"
            )
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
        authorization_scope=statement["authorizationScope"],
        freshness_authority=statement["freshnessAuthority"],
        capability_semantics=statement["capabilitySemantics"],
        global_role_registry_sha256=statement["globalRoleRegistrySha256"],
        monotonic_witness=statement["monotonicWitness"],
    )


def verify_launch_authorization_for_recovery(
    raw: bytes,
    *,
    authority_public_key_spki_der: bytes,
    expected_request_sha256: str,
    expected_authority_key_id: str,
    expected_global_role_registry_sha256: str,
) -> VerifiedLaunchAuthorization:
    """Verify authenticity for saga recovery without asserting current freshness.

    This helper must never authorize launch. It samples the signed issuance instant only
    so an expired envelope can be durably recovered and then rejected by the caller.
    """

    envelope = validate_launch_authorization(
        require_canonical_json_bytes(raw, label="launch authorization recovery envelope")
    )
    return verify_launch_authorization(
        raw,
        authority_public_key_spki_der=authority_public_key_spki_der,
        expected_request_sha256=expected_request_sha256,
        expected_authority_key_id=expected_authority_key_id,
        now_unix_seconds=envelope["statement"]["issuedAtUnixSeconds"],
        expected_global_role_registry_sha256=(
            expected_global_role_registry_sha256
        ),
    )


def verify_launch_authorization_with_witness(
    raw: bytes,
    *,
    authority_public_key_spki_der: bytes,
    expected_request: Mapping[str, Any],
    expected_authority_key_id: str,
    witness_public_key_spki_der: bytes,
    expected_witness_key_id: str,
    now_unix_seconds: int,
    expected_registry_generation: int | None = None,
    expected_registry_sha256: str | None = None,
    expected_predecessor_state_sha256: str | None = None,
    expected_successor_state_sha256: str | None = None,
) -> VerifiedLaunchAuthorization:
    """Verify the authority envelope and its exact external witness transition."""

    request = validate_launch_authorization_request(expected_request)
    request_sha256 = launch_authorization_request_sha256(request)
    verified = verify_launch_authorization(
        raw,
        authority_public_key_spki_der=authority_public_key_spki_der,
        expected_request_sha256=request_sha256,
        expected_authority_key_id=expected_authority_key_id,
        now_unix_seconds=now_unix_seconds,
        expected_global_role_registry_sha256=request[
            "globalRoleRegistrySha256"
        ],
    )
    verify_launch_authority_witness(
        verified.monotonic_witness,
        witness_public_key_spki_der=witness_public_key_spki_der,
        expected_witness_key_id=expected_witness_key_id,
        expected_request=request,
        expected_authorization_id=verified.authorization_id,
        expected_authority_key_id=verified.authority_key_id,
        expected_registry_generation=expected_registry_generation,
        expected_registry_sha256=expected_registry_sha256,
        expected_predecessor_state_sha256=expected_predecessor_state_sha256,
        expected_successor_state_sha256=expected_successor_state_sha256,
        expected_issued_at_unix_seconds=verified.issued_at_unix_seconds,
        expected_expires_at_unix_seconds=verified.expires_at_unix_seconds,
    )
    return verified


def verify_launch_authorization_with_witness_for_recovery(
    raw: bytes,
    *,
    authority_public_key_spki_der: bytes,
    expected_request: Mapping[str, Any],
    expected_authority_key_id: str,
    witness_public_key_spki_der: bytes,
    expected_witness_key_id: str,
    expected_registry_generation: int | None = None,
    expected_registry_sha256: str | None = None,
    expected_predecessor_state_sha256: str | None = None,
    expected_successor_state_sha256: str | None = None,
) -> VerifiedLaunchAuthorization:
    """Authenticate an exact terminal artifact without accepting it for launch."""

    request = validate_launch_authorization_request(expected_request)
    verified = verify_launch_authorization_for_recovery(
        raw,
        authority_public_key_spki_der=authority_public_key_spki_der,
        expected_request_sha256=launch_authorization_request_sha256(request),
        expected_authority_key_id=expected_authority_key_id,
        expected_global_role_registry_sha256=request[
            "globalRoleRegistrySha256"
        ],
    )
    verify_launch_authority_witness(
        verified.monotonic_witness,
        witness_public_key_spki_der=witness_public_key_spki_der,
        expected_witness_key_id=expected_witness_key_id,
        expected_request=request,
        expected_authorization_id=verified.authorization_id,
        expected_authority_key_id=verified.authority_key_id,
        expected_registry_generation=expected_registry_generation,
        expected_registry_sha256=expected_registry_sha256,
        expected_predecessor_state_sha256=(
            expected_predecessor_state_sha256
        ),
        expected_successor_state_sha256=(
            expected_successor_state_sha256
        ),
        expected_issued_at_unix_seconds=verified.issued_at_unix_seconds,
        expected_expires_at_unix_seconds=verified.expires_at_unix_seconds,
    )
    return verified
