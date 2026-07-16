from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ENROLLMENT_RECEIPT_API_VERSION = "serverware.enrollmentVerifierReceipt/v3"
EGRESS_EVIDENCE_API_VERSION = "serverware.agentEgressEvidence/v1"
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
    "quote-provider",
    "quote-digest",
    "verified-claims-digest",
    "quote-verifier-identity",
    "attestation-assurance",
    "egress-evidence-signature",
    "network-namespace-binding",
    "deny-by-default-installed",
    "allow-canary-results",
    "deny-canary-result",
)
ATTESTATION_ASSURANCE_FIELDS = frozenset(
    {
        "class",
        "debug",
        "hardware_proof",
        "workload_custody_proven",
        "tls_peer_binding_proven",
        "fact_origin",
        "completion_eligible",
    }
)
ATTESTATION_EVIDENCE_FIELDS = frozenset(
    {
        "quote_provider",
        "quote_sha256",
        "verified_claims_sha256",
        "verifier_identity_sha256",
        "self_rooted",
        "debug",
        "assurance",
    }
)
EGRESS_RECEIPT_BINDING_FIELDS = frozenset(
    {
        "evidence_id",
        "evidence_sha256",
        "evidence_mode",
        "evidence_provider",
        "evidence_key_id",
        "network_namespace_sha256",
        "firewall_state_sha256",
        "allow_results_sha256",
        "deny_result_sha256",
        "observed_at_unix",
    }
)
ENROLLMENT_RECEIPT_STATEMENT_FIELDS = frozenset(
    {
        "receipt_id",
        "setup_session_id",
        "assignment",
        "assignment_digest",
        "enrollment_session_id",
        "enrollment_packet_sha256",
        "verifier_nonce_sha256",
        "trust_profile_sha256",
        "verifier_provider",
        "assurance_mode",
        "attestation_evidence",
        "egress_evidence",
        "decision",
        "checks",
        "issued_at_unix",
        "expires_at_unix",
    }
)

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_PROVIDER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
_NETNS_RE = re.compile(r"net:\[[1-9][0-9]{0,19}\]\Z")
_DEVELOPMENT_MARKERS = ("dev", "fixture", "self-signed", "self-rooted", "test")
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_EGRESS_EVIDENCE_BYTES = 128 * 1024


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
        raise ValueError("digest input must be immutable bytes")
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_base64url(value: bytes) -> str:
    if type(value) is not bytes:
        raise ValueError("base64url input must be immutable bytes")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _load_ed25519_spki(public_key_spki_der: bytes) -> Ed25519PublicKey:
    if type(public_key_spki_der) is not bytes:
        raise ValueError("trusted SPKI must be immutable DER bytes")
    try:
        key = serialization.load_der_public_key(public_key_spki_der)
    except (TypeError, ValueError) as exc:
        raise ValueError("trusted SPKI is invalid DER") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("trusted SPKI is not an Ed25519 key")
    canonical_der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not hmac.compare_digest(canonical_der, public_key_spki_der):
        raise ValueError("trusted SPKI DER is not canonical")
    return key


def _require_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a SHA-256 digest")


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    if isinstance(value, list):
        return [_plain_json(item) for item in value]
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_float(value: str) -> object:
    raise ValueError(f"JSON floating-point values are forbidden: {value}")


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constants are forbidden: {value}")


def parse_strict_json_object(raw: bytes, *, label: str, max_bytes: int) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > max_bytes:
        raise ValueError(f"{label} byte length is outside the accepted bound")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{label} is not strict bounded UTF-8 JSON") from exc
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    if len(canonical_json_bytes(value)) > max_bytes:
        raise ValueError(f"{label} canonical form exceeds the accepted bound")
    return value


def _require_exact_fields(value: Any, expected: frozenset[str] | set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError(f"{label} fields do not match the closed contract")
    return value


def _require_uuid(value: Any, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{label} must be a canonical UUID")
    return str(value)


def _decode_signature(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("ed25519:"):
        raise ValueError(f"{label} is invalid")
    encoded = value.split(":", 1)[1]
    if not _BASE64URL_RE.fullmatch(encoded) or "=" in encoded:
        raise ValueError(f"{label} is not canonical unpadded base64url")
    try:
        decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical unpadded base64url") from exc
    if len(decoded) != 64 or canonical_base64url(decoded) != encoded:
        raise ValueError(f"{label} must contain exactly 64 canonical bytes")
    return decoded


def _is_development_provider(provider: str) -> bool:
    lowered = provider.lower()
    return any(marker in lowered for marker in _DEVELOPMENT_MARKERS)


def _clock_value(clock: Callable[[], int] | Any) -> int:
    value = clock.now_unix() if hasattr(clock, "now_unix") else clock()
    if type(value) is not int or value < 1:
        raise ValueError("receipt clock returned an invalid Unix timestamp")
    return value


def _verify_signature(document: dict[str, Any], trust: "Ed25519TrustRoot", *, label: str) -> dict[str, Any]:
    _require_exact_fields(
        document,
        {"apiVersion", "kind", "statement", "signing_key_id", "signature"},
        label,
    )
    if not hmac.compare_digest(str(document.get("signing_key_id") or ""), trust.key_id):
        raise ValueError(f"{label} signer is not the configured trust root")
    statement = document.get("statement")
    if type(statement) is not dict:
        raise ValueError(f"{label} statement is invalid")
    try:
        _load_ed25519_spki(trust.public_key_spki_der).verify(
            _decode_signature(document.get("signature"), f"{label} signature"),
            canonical_json_bytes(statement),
        )
    except InvalidSignature as exc:
        raise ValueError(f"{label} signature verification failed") from exc
    return statement


@dataclass(frozen=True, slots=True)
class Ed25519TrustRoot:
    provider: str
    public_key_spki_der: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.provider, str) or _PROVIDER_RE.fullmatch(self.provider) is None:
            raise ValueError("trust provider is invalid")
        _load_ed25519_spki(self.public_key_spki_der)

    @property
    def key_id(self) -> str:
        return sha256_digest(self.public_key_spki_der)


@dataclass(frozen=True, slots=True)
class FixedClock:
    value: int

    def now_unix(self) -> int:
        return self.value


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
        if type(self.credential_version) is not int or not 1 <= self.credential_version <= (1 << 63) - 1:
            raise ValueError("credential version must be a positive bounded integer")
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
class VerifiedAgentEgressEvidence:
    evidence_id: str
    evidence_sha256: str
    evidence_mode: str
    evidence_provider: str
    evidence_key_id: str
    network_namespace_sha256: str
    firewall_state_sha256: str
    allow_results_sha256: str
    deny_result_sha256: str
    observed_at_unix: int

    def as_receipt_binding(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
            "evidence_mode": self.evidence_mode,
            "evidence_provider": self.evidence_provider,
            "evidence_key_id": self.evidence_key_id,
            "network_namespace_sha256": self.network_namespace_sha256,
            "firewall_state_sha256": self.firewall_state_sha256,
            "allow_results_sha256": self.allow_results_sha256,
            "deny_result_sha256": self.deny_result_sha256,
            "observed_at_unix": self.observed_at_unix,
        }


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
    assurance_mode: str
    attestation_evidence: Mapping[str, Any]
    egress_evidence: Mapping[str, Any]
    decision: str
    checks: tuple[str, ...]
    issued_at_unix: int
    expires_at_unix: int


def verify_agent_egress_evidence(
    raw: bytes,
    *,
    trust: Ed25519TrustRoot,
    packet: Mapping[str, Any],
    enrollment_session_id: str,
    allow_development_fixture: bool,
) -> VerifiedAgentEgressEvidence:
    document = parse_strict_json_object(
        raw,
        label="agent egress evidence",
        max_bytes=_MAX_EGRESS_EVIDENCE_BYTES,
    )
    if document.get("apiVersion") != EGRESS_EVIDENCE_API_VERSION or document.get("kind") != "AgentEgressEvidence":
        raise ValueError("agent egress evidence type is invalid")
    statement = _verify_signature(document, trust, label="agent egress evidence")
    _require_exact_fields(
        statement,
        {
            "evidence_id",
            "packet_sha256",
            "principal_id",
            "enrollment_session_id",
            "evidence_mode",
            "evidence_provider",
            "launcher_recorded_network_namespace",
            "observed_network_namespace",
            "firewall",
            "allow_canaries",
            "deny_canary",
            "observed_at_unix",
        },
        "agent egress evidence statement",
    )
    evidence_id = _require_uuid(statement.get("evidence_id"), "egress evidence ID")
    authenticity = packet.get("authenticity")
    packet_statement = authenticity.get("statement") if isinstance(authenticity, Mapping) else None
    expected_packet_sha256 = packet_statement.get("packetSha256") if isinstance(packet_statement, Mapping) else None
    _require_digest(str(expected_packet_sha256 or ""), "signed enrollment packet digest")
    if not hmac.compare_digest(str(statement.get("packet_sha256") or ""), str(expected_packet_sha256)):
        raise ValueError("agent egress evidence packet digest mismatch")
    if statement.get("principal_id") != packet.get("principalId"):
        raise ValueError("agent egress evidence principal mismatch")
    if statement.get("enrollment_session_id") != enrollment_session_id:
        raise ValueError("agent egress evidence enrollment session mismatch")

    mode = statement.get("evidence_mode")
    provider = statement.get("evidence_provider")
    if not isinstance(provider, str) or _PROVIDER_RE.fullmatch(provider) is None or provider != trust.provider:
        raise ValueError("agent egress evidence provider is not trusted")
    if allow_development_fixture:
        if mode != "development-fixture":
            raise ValueError("development egress evidence must identify itself as a fixture")
    elif mode != "production-launcher" or _is_development_provider(provider):
        raise ValueError("production enrollment requires non-fixture launcher egress evidence")

    recorded_netns = statement.get("launcher_recorded_network_namespace")
    observed_netns = statement.get("observed_network_namespace")
    if (
        not isinstance(recorded_netns, str)
        or _NETNS_RE.fullmatch(recorded_netns) is None
        or not hmac.compare_digest(recorded_netns, str(observed_netns or ""))
    ):
        raise ValueError("agent egress evidence network namespace binding is invalid")

    packet_egress = packet.get("egress")
    packet_firewall = packet_egress.get("firewall") if isinstance(packet_egress, Mapping) else None
    packet_verification = packet_firewall.get("verification") if isinstance(packet_firewall, Mapping) else None
    if not isinstance(packet_firewall, Mapping) or not isinstance(packet_verification, Mapping):
        raise ValueError("enrollment packet is missing its firewall contract")
    firewall = _require_exact_fields(
        statement.get("firewall"),
        {
            "backend",
            "table_family",
            "table_name",
            "chain_name",
            "chain_hook",
            "chain_policy",
            "ruleset_sha256",
            "installed_state_sha256",
            "expected_rule_comments",
            "installed",
        },
        "agent egress evidence firewall",
    )
    expected_firewall = {
        "backend": packet_firewall.get("backend"),
        "table_family": packet_firewall.get("tableFamily"),
        "table_name": packet_firewall.get("tableName"),
        "chain_name": packet_verification.get("chainName"),
        "chain_hook": packet_verification.get("chainHook"),
        "chain_policy": packet_verification.get("chainPolicy"),
        "ruleset_sha256": sha256_digest(str(packet_firewall.get("ruleset") or "").encode("utf-8")),
        "expected_rule_comments": packet_verification.get("expectedRuleComments"),
        "installed": True,
    }
    for field, expected_value in expected_firewall.items():
        if firewall.get(field) != expected_value:
            raise ValueError(f"agent egress evidence firewall {field} mismatch")
    _require_digest(firewall.get("installed_state_sha256"), "installed firewall state digest")

    canaries = packet.get("canaries")
    expected_allow = canaries.get("allow") if isinstance(canaries, Mapping) else None
    expected_deny_items = canaries.get("deny") if isinstance(canaries, Mapping) else None
    if not isinstance(expected_allow, list) or not expected_allow:
        raise ValueError("production enrollment completion requires at least one safe allow canary")
    allow_results = statement.get("allow_canaries")
    if not isinstance(allow_results, list) or len(allow_results) != len(expected_allow):
        raise ValueError("agent egress evidence does not cover every allow canary")
    for expected_canary, result in zip(expected_allow, allow_results, strict=True):
        result = _require_exact_fields(
            result,
            {"route_id", "method", "url", "outcome", "status_code", "response_evidence_sha256"},
            "agent allow canary result",
        )
        if (
            result.get("route_id") != expected_canary.get("routeId")
            or result.get("method") != expected_canary.get("method")
            or result.get("url") != expected_canary.get("url")
            or result.get("outcome") != "allowed"
            or type(result.get("status_code")) is not int
            or not 200 <= result["status_code"] <= 399
        ):
            raise ValueError("agent allow canary result does not match the signed packet")
        _require_digest(result.get("response_evidence_sha256"), "allow canary response evidence digest")

    if not isinstance(expected_deny_items, list) or len(expected_deny_items) != 1:
        raise ValueError("enrollment packet deny canary contract is invalid")
    expected_deny = expected_deny_items[0]
    deny_result = _require_exact_fields(
        statement.get("deny_canary"),
        {"method", "url", "outcome", "status_code", "error", "response_evidence_sha256"},
        "agent deny canary result",
    )
    if (
        deny_result.get("method") != expected_deny.get("method")
        or deny_result.get("url") != expected_deny.get("url")
        or deny_result.get("outcome") != "denied"
        or deny_result.get("status_code") != expected_deny.get("expectedStatus")
        or deny_result.get("error") != expected_deny.get("expectedError")
    ):
        raise ValueError("agent deny canary result does not match the signed packet")
    _require_digest(deny_result.get("response_evidence_sha256"), "deny canary response evidence digest")

    observed_at = statement.get("observed_at_unix")
    issued_at_ms = packet.get("issuedAtEpochMs")
    expires_at_ms = packet.get("expiresAtEpochMs")
    if (
        type(observed_at) is not int
        or type(issued_at_ms) is not int
        or type(expires_at_ms) is not int
        or not issued_at_ms // 1000 <= observed_at <= (expires_at_ms - 1) // 1000
    ):
        raise ValueError("agent egress evidence observation time is outside the packet lifetime")

    return VerifiedAgentEgressEvidence(
        evidence_id=evidence_id,
        evidence_sha256=sha256_digest(canonical_json_bytes(document)),
        evidence_mode=str(mode),
        evidence_provider=provider,
        evidence_key_id=trust.key_id,
        network_namespace_sha256=sha256_digest(recorded_netns.encode("ascii")),
        firewall_state_sha256=str(firewall["installed_state_sha256"]),
        allow_results_sha256=sha256_digest(canonical_json_bytes(allow_results)),
        deny_result_sha256=sha256_digest(canonical_json_bytes(deny_result)),
        observed_at_unix=observed_at,
    )


def validate_attestation_evidence_binding(value: Any, *, require_production: bool) -> dict[str, Any]:
    evidence = _require_exact_fields(value, ATTESTATION_EVIDENCE_FIELDS, "attestation evidence binding")
    provider = evidence.get("quote_provider")
    if not isinstance(provider, str) or _PROVIDER_RE.fullmatch(provider) is None:
        raise ValueError("attestation quote provider is invalid")
    for field in ("quote_sha256", "verified_claims_sha256", "verifier_identity_sha256"):
        _require_digest(evidence.get(field), f"attestation evidence {field}")
    if type(evidence.get("self_rooted")) is not bool or type(evidence.get("debug")) is not bool:
        raise ValueError("attestation debug or self-rooted state is invalid")
    assurance = _require_exact_fields(
        evidence.get("assurance"), ATTESTATION_ASSURANCE_FIELDS, "attestation assurance"
    )
    if (
        not isinstance(assurance.get("class"), str)
        or not isinstance(assurance.get("fact_origin"), str)
        or any(
            type(assurance.get(field)) is not bool
            for field in (
                "debug",
                "hardware_proof",
                "workload_custody_proven",
                "tls_peer_binding_proven",
                "completion_eligible",
            )
        )
        or assurance.get("debug") != evidence.get("debug")
    ):
        raise ValueError("attestation assurance values are invalid")
    if require_production and (
        _is_development_provider(provider)
        or evidence["verifier_identity_sha256"] == "sha256:" + "0" * 64
        or evidence["debug"] is not False
        or evidence["self_rooted"] is not False
        or assurance["debug"] is not False
        or assurance["hardware_proof"] is not True
        or assurance["workload_custody_proven"] is not True
        or assurance["tls_peer_binding_proven"] is not True
        or assurance["completion_eligible"] is not True
        or assurance["fact_origin"] != "independent-verifier"
        or _is_development_provider(assurance["class"])
    ):
        raise ValueError("production enrollment rejects development, debug, self-rooted, or incomplete quote assurance")
    return evidence


def validate_egress_receipt_binding(value: Any, *, require_production: bool) -> dict[str, Any]:
    binding = _require_exact_fields(value, EGRESS_RECEIPT_BINDING_FIELDS, "egress receipt binding")
    _require_uuid(binding.get("evidence_id"), "egress evidence ID")
    for field in (
        "evidence_sha256",
        "evidence_key_id",
        "network_namespace_sha256",
        "firewall_state_sha256",
        "allow_results_sha256",
        "deny_result_sha256",
    ):
        _require_digest(binding.get(field), f"egress receipt {field}")
    provider = binding.get("evidence_provider")
    if not isinstance(provider, str) or _PROVIDER_RE.fullmatch(provider) is None:
        raise ValueError("egress receipt provider is invalid")
    if type(binding.get("observed_at_unix")) is not int or binding["observed_at_unix"] < 1:
        raise ValueError("egress receipt observation time is invalid")
    expected_mode = "production-launcher" if require_production else "development-fixture"
    if binding.get("evidence_mode") != expected_mode:
        raise ValueError(f"egress receipt must use {expected_mode} evidence")
    if require_production and _is_development_provider(provider):
        raise ValueError("production enrollment rejects fixture egress evidence providers")
    return binding


def verify_enrollment_verifier_receipt(
    raw: bytes,
    *,
    trust: Ed25519TrustRoot,
    expected: EnrollmentReceiptExpected,
    clock: Callable[[], int] | Any,
    require_production: bool,
) -> VerifiedEnrollmentVerifierReceipt:
    document = parse_strict_json_object(raw, label="enrollment verifier receipt", max_bytes=_MAX_RECEIPT_BYTES)
    if document.get("apiVersion") != ENROLLMENT_RECEIPT_API_VERSION or document.get("kind") != "EnrollmentVerifierReceipt":
        raise ValueError("enrollment verifier receipt type is invalid")
    statement = _verify_signature(document, trust, label="enrollment verifier receipt")
    _require_exact_fields(statement, ENROLLMENT_RECEIPT_STATEMENT_FIELDS, "enrollment receipt statement")
    if statement.get("receipt_id") != expected.receipt_id or statement.get("setup_session_id") != expected.setup_session_id:
        raise ValueError("enrollment receipt session or receipt ID binding mismatch")
    if statement.get("enrollment_session_id") != expected.enrollment_session_id:
        raise ValueError("enrollment receipt enrollment session binding mismatch")
    if statement.get("assignment") != expected.assignment.as_document() or statement.get("assignment_digest") != expected.assignment.digest:
        raise ValueError("enrollment receipt assignment binding mismatch")
    for field, expected_value in (
        ("enrollment_packet_sha256", expected.enrollment_packet_sha256),
        ("verifier_nonce_sha256", expected.verifier_nonce_sha256),
        ("trust_profile_sha256", expected.trust_profile_sha256),
    ):
        _require_digest(statement.get(field), f"enrollment receipt {field}")
        if not hmac.compare_digest(str(statement[field]), expected_value):
            raise ValueError(f"enrollment receipt {field} binding mismatch")
    if statement.get("verifier_provider") != trust.provider:
        raise ValueError("enrollment receipt verifier provider mismatch")
    if require_production and _is_development_provider(trust.provider):
        raise ValueError("production enrollment rejects development receipt verifier providers")
    expected_assurance_mode = "production" if require_production else "development-fixture"
    if statement.get("assurance_mode") != expected_assurance_mode:
        raise ValueError(f"enrollment receipt must use {expected_assurance_mode} assurance")
    attestation_evidence = validate_attestation_evidence_binding(
        statement.get("attestation_evidence"), require_production=require_production
    )
    egress_evidence = validate_egress_receipt_binding(
        statement.get("egress_evidence"), require_production=require_production
    )
    if statement.get("decision") != "verified" or statement.get("checks") != list(ENROLLMENT_CHECKS):
        raise ValueError("enrollment receipt decision or checks are incomplete")
    issued_at = statement.get("issued_at_unix")
    expires_at = statement.get("expires_at_unix")
    now = _clock_value(clock)
    if (
        type(issued_at) is not int
        or type(expires_at) is not int
        or not issued_at <= now < expires_at
        or not 1 <= expires_at - issued_at <= 900
        or egress_evidence["observed_at_unix"] > issued_at
    ):
        raise ValueError("enrollment receipt time window is invalid")
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
        assurance_mode=expected_assurance_mode,
        attestation_evidence=attestation_evidence,
        egress_evidence=egress_evidence,
        decision="verified",
        checks=ENROLLMENT_CHECKS,
        issued_at_unix=issued_at,
        expires_at_unix=expires_at,
    )
