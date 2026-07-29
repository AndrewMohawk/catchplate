#!/usr/bin/env python3
"""Independent nonce-authority verifier-state service.

Production deployment requires two facilities that this source tree does not
provision or emulate:

* an independently administered, linearizable, rollback-resistant state store
  that retains the signed current head, atomically reserves one-use operation
  IDs, durably commits exactly one successor, and supports operation-ID
  recovery after every ambiguous transport outcome; and
* an independently retained non-exportable Ed25519 key exposed through the
  remote signing adapter.

The local SQLite and file-key classes are reference fixtures only. They always
advertise non-production capability, and ``VerifierStateService`` rejects them
when configured with production rollback assurance. A successful response from
this service is continuity evidence, never an action authorization.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Any, Mapping, Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SIGNED_STATE_VERSION = "serverware.signedNonceAuthorityVerifierState/v1"
STATE_VERSION = "serverware.nonceAuthorityVerifierState/v1"
AUTHORIZATION_VERSION = (
    "serverware.nonceAuthorityVerifierStatePreparedAuthorization/v3"
)
COMMIT_RECEIPT_VERSION = (
    "serverware.nonceAuthorityVerifierStateCommitReceipt/v3"
)
NONCE_AUTHORITY_STATE_VERSION = "serverware.nonceAuthorityState/v1"
HIGH_WATER_PREIMAGE_VERSION = (
    "serverware.nonceAuthorityHighWaterCommitment/v1"
)
READ_REQUEST_VERSION = (
    "serverware.nonceAuthorityVerifierStateReadRequest/v2"
)
READ_RESPONSE_VERSION = (
    "serverware.nonceAuthorityVerifierStateReadResponse/v3"
)
PREPARE_REQUEST_VERSION = (
    "serverware.attestationVerifierStatePrepareRequest/v4"
)
PREPARE_RESPONSE_VERSION = (
    "serverware.attestationVerifierStatePrepareResponse/v4"
)
PREPARED_OPERATION_VERSION = (
    "serverware.attestationVerifierStatePreparedOperation/v1"
)
REQUEST_BINDING_VERSION = (
    "serverware.attestationVerifierStateRequestBinding/v1"
)
RECOVERY_BINDING_VERSION = (
    "serverware.attestationVerifierStateRecoveryBinding/v1"
)
RECOVERY_IDENTITY_VERSION = (
    "serverware.attestationVerifierStateRecoveryIdentity/v1"
)
SUCCESSOR_INTENT_VERSION = (
    "serverware.attestationVerifierStateSuccessorIntent/v1"
)
MARK_CONSUMPTION_REQUEST_VERSION = (
    "serverware.attestationVerifierStateMarkConsumptionRequest/v1"
)
MARK_CONSUMPTION_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateMarkConsumptionResponse/v1"
)
ATTACH_NONCE_STATUS_REQUEST_VERSION = (
    "serverware.attestationVerifierStateAttachNonceStatusRequest/v1"
)
ATTACH_NONCE_STATUS_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateAttachNonceStatusResponse/v1"
)
COMMIT_REQUEST_VERSION = (
    "serverware.attestationVerifierStateCommitRequest/v3"
)
RECOVERY_REQUEST_VERSION = (
    "serverware.attestationVerifierStateRecoveryRequest/v3"
)
RECOVERY_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateRecoveryResponse/v3"
)
RECOVERY_LOOKUP_REQUEST_VERSION = (
    "serverware.attestationVerifierStateRecoveryLookupRequest/v1"
)
RECOVERY_LOOKUP_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateRecoveryLookupResponse/v1"
)
ISSUE_CHALLENGE_REQUEST_VERSION = (
    "serverware.attestationVerifierStateIssueChallengeRequest/v1"
)
ISSUE_CHALLENGE_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateIssueChallengeResponse/v1"
)
RECOVER_CHALLENGE_REQUEST_VERSION = (
    "serverware.attestationVerifierStateRecoverChallengeRequest/v1"
)
RECOVER_CHALLENGE_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateRecoverChallengeResponse/v1"
)
ABORT_REQUEST_VERSION = (
    "serverware.attestationVerifierStateAbortRequest/v1"
)
ABORT_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateAbortResponse/v1"
)
EXTERNAL_STORE_REQUEST_VERSION = (
    "serverware.externalVerifierStateStoreRequest/v3"
)
EXTERNAL_STORE_RESPONSE_VERSION = (
    "serverware.externalVerifierStateStoreResponse/v3"
)
REMOTE_SIGN_REQUEST_VERSION = "serverware.remoteEd25519SignRequest/v1"
REMOTE_SIGN_RESPONSE_VERSION = "serverware.remoteEd25519SignResponse/v1"
STORE_COMMIT_PROOF_VERSION = (
    "serverware.verifierStateStoreCommitProof/v3"
)
SIGNED_STORE_COMMIT_PROOF_VERSION = (
    "serverware.signedVerifierStateStoreCommitProof/v3"
)
STORE_COMMIT_CANDIDATE_VERSION = (
    "serverware.verifierStateStoreCommitCandidate/v2"
)
SIGNED_NONCE_RECEIPT_VERSION = (
    "serverware.signedAttestationNonceConsumptionReceipt/v2"
)
NONCE_RECEIPT_PAYLOAD_VERSION = (
    "serverware.attestationNonceConsumptionReceiptPayload/v2"
)
NONCE_CONSUMPTION_VERSION = (
    "serverware.publicAttestationNonceConsumption/v1"
)
NONCE_CONSUME_ONCE_REQUEST_VERSION = (
    "serverware.attestationNonceConsumeOnceRequest/v3"
)
SIGNED_NONCE_STATUS_EVIDENCE_VERSION = (
    "serverware.signedAttestationNonceTransactionStatusEvidence/v1"
)
NONCE_STATUS_EVIDENCE_VERSION = (
    "serverware.attestationNonceTransactionStatusEvidence/v1"
)
ROLE_SEPARATION_EVIDENCE_VERSION = (
    "serverware.verifierStateRoleSeparationEvidence/v1"
)
SIGNED_ROLE_SEPARATION_EVIDENCE_VERSION = (
    "serverware.signedVerifierStateRoleSeparationEvidence/v1"
)
STORE_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.verifierStateStoreAssuranceEvidence/v1"
)
SIGNED_STORE_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.signedVerifierStateStoreAssuranceEvidence/v1"
)
SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.signedNonceAuthorityAssuranceEvidence/v1"
)
NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.nonceAuthorityAssuranceEvidence/v1"
)
SERVICE_CONFIG_VERSION = (
    "serverware.attestationVerifierStateServiceConfiguration/v3"
)

STATE_DOMAIN = b"serverware.nonceAuthorityVerifierState/v1\x00Ed25519\x00"
AUTHORIZATION_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStatePreparedAuthorization/v3\x00"
    b"Ed25519\x00"
)
COMMIT_RECEIPT_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStateCommitReceipt/v3\x00"
    b"Ed25519\x00"
)
GENESIS_DOMAIN = b"serverware.nonceAuthorityGenesisCommitment/v1\x00"
HIGH_WATER_DOMAIN = (
    b"serverware.nonceAuthorityHighWaterCommitment/v1\x00"
)
STATE_HEAD_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStateHead/v1\x00"
)
STORE_COMMIT_PROOF_DOMAIN = (
    b"serverware.verifierStateStoreCommitProof/v3\x00Ed25519\x00"
)
NONCE_STATUS_EVIDENCE_DOMAIN = (
    b"serverware.attestationNonceTransactionStatusEvidence/v1\x00"
    b"Ed25519\x00"
)
NONCE_RECEIPT_DOMAIN = (
    b"serverware.attestationNonceConsumptionReceipt/v2\x00Ed25519\x00"
)
NONCE_CONSUME_REQUEST_DIGEST_DOMAIN = (
    b"serverware.attestationNonceConsumeRequestDigest/v3\x00"
)
RECOVERY_KEY_DOMAIN = (
    b"serverware.attestationVerifierStateRecoveryKey/v1\x00"
)
OPERATION_ID_DOMAIN = (
    b"serverware.attestationVerifierStateOperationId/v1\x00"
)
CHALLENGE_VALUE_DOMAIN = (
    b"serverware.attestationVerifierStateChallengeValue/v1\x00"
)
REQUEST_BINDING_DOMAIN = (
    b"serverware.attestationVerifierStateRequestBinding/v1\x00"
)
ROLE_SEPARATION_EVIDENCE_DOMAIN = (
    b"serverware.verifierStateRoleSeparationEvidence/v1\x00Ed25519\x00"
)
STORE_ASSURANCE_EVIDENCE_DOMAIN = (
    b"serverware.verifierStateStoreAssuranceEvidence/v1\x00Ed25519\x00"
)
NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN = (
    b"serverware.nonceAuthorityAssuranceEvidence/v1\x00Ed25519\x00"
)

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
B64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
MAX_JSON_BYTES = 256 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_DEPTH = 64
MAX_U64 = (1 << 64) - 1
MAX_AUTHORIZATION_SECONDS = 30
MAX_CHALLENGE_SECONDS = 30
MAX_OUTBOUND_CONCURRENCY = 8
HANDSHAKE_TIMEOUT_SECONDS = 3.0
HEADER_TIMEOUT_SECONDS = 3.0
BODY_TIMEOUT_SECONDS = 3.0
EOF_TIMEOUT_SECONDS = 1.0
TOTAL_REQUEST_TIMEOUT_SECONDS = 10.0
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

PRODUCTION_PROFILES = frozenset(
    {
        (
            "hardwareMonotonicCounter",
            "hardwareMonotonicCounter",
            "nonExportableHsm",
            "monotonicCounterCommitment",
            "hardwareProtectedStateStore",
            "hardwareMonotonicCounterAttestation",
        ),
        (
            "independentlyAdministeredLinearizableCas",
            "linearizableCasWithRollbackProtectedStorage",
            "nonExportableKmsHsm",
            "hashChainedLinearizableCommitment",
            "independentlyAdministeredLinearizableCas",
            "linearizableCasOperatorAttestation",
        ),
        (
            "appendOnlyTransparencyLedger",
            "appendOnlyWitnessedLedger",
            "nonExportableKmsHsm",
            "appendOnlyMerkleCommitment",
            "independentlyAdministeredLinearizableCas",
            "transparencyLedgerOperatorAttestation",
        ),
    }
)
NONPRODUCTION_SQLITE_PROFILE = (
    "nonProductionSqlite",
    "none",
    "retainedFdReference",
    "localHashChain",
    "nonProductionCallerFile",
    "none",
)


class ContractError(ValueError):
    pass


class ConflictError(ContractError):
    pass


class UnknownOutcomeError(RuntimeError):
    """The caller must recover by operation ID before attempting another CAS."""

    def __init__(
        self,
        message: str,
        *,
        operation_id: str | None = None,
        commit_request_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.operation_id = operation_id
        self.commit_request_sha256 = commit_request_sha256

    def bind_recovery(
        self,
        *,
        operation_id: str,
        commit_request_sha256: str,
    ) -> "UnknownOutcomeError":
        if self.operation_id is None:
            self.operation_id = operation_id
        if self.commit_request_sha256 is None:
            self.commit_request_sha256 = commit_request_sha256
        return self


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate_json_value(value: Any, *, label: str, depth: int = 0) -> None:
    require(depth <= MAX_DEPTH, f"{label} exceeds the nesting limit")
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, f"{label} contains a non-string key")
            require(
                "\x00" not in key
                and unicodedata.normalize("NFC", key) == key,
                f"{label} contains a noncanonical key",
            )
            validate_json_value(child, label=label, depth=depth + 1)
        return
    if type(value) is list:
        for child in value:
            validate_json_value(child, label=label, depth=depth + 1)
        return
    if type(value) is str:
        require(
            "\x00" not in value
            and not any(0xD800 <= ord(character) <= 0xDFFF for character in value)
            and unicodedata.normalize("NFC", value) == value,
            f"{label} contains a noncanonical string",
        )
        return
    require(
        value is None
        or type(value) is bool
        or (type(value) is int and -(1 << 63) <= value <= MAX_U64),
        f"{label} contains a value outside the canonical JSON profile",
    )


def canonical_json(value: Any) -> bytes:
    validate_json_value(value, label="JSON document")
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    require(len(encoded) <= MAX_JSON_BYTES, "canonical JSON exceeds 256 KiB")
    return encoded


def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def reject_noninteger(value: str) -> Any:
    raise ContractError(f"noninteger JSON number is forbidden: {value!r}")


def parse_canonical_json(raw: bytes, *, label: str) -> Any:
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_JSON_BYTES, f"{label} size is invalid")
    require(not raw.endswith(b"\n"), f"{label} must not carry transport whitespace")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_pairs,
            parse_float=reject_noninteger,
            parse_constant=reject_noninteger,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError(f"{label} is not strict UTF-8 JSON") from exc
    require(raw == canonical_json(document), f"{label} is not canonical JSON")
    return document


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} fields are not closed")
    return value


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def require_sha256(value: Any, label: str) -> str:
    require(type(value) is str and DIGEST_RE.fullmatch(value) is not None, f"{label} is not a SHA-256 digest")
    return value


def require_uint(value: Any, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    require(type(value) is int and minimum <= value <= MAX_U64, f"{label} is not an unsigned integer")
    return value


def checked_add_uint(value: Any, increment: Any, label: str) -> int:
    base = require_uint(value, label)
    delta = require_uint(increment, f"{label} increment", positive=True)
    require(
        base <= MAX_U64 - delta,
        f"{label} overflowed the canonical unsigned-64 range",
    )
    return base + delta


def b64url_decode(value: Any, label: str, *, exact_bytes: int) -> bytes:
    require(
        type(value) is str
        and value
        and "=" not in value
        and B64URL_RE.fullmatch(value) is not None,
        f"{label} is not canonical base64url",
    )
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ContractError(f"{label} is invalid base64url") from exc
    require(len(decoded) == exact_bytes, f"{label} has the wrong length")
    require(
        base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value,
        f"{label} is not canonical base64url",
    )
    return decoded


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def require_absolute_path(value: Any, label: str) -> str:
    require(
        type(value) is str
        and value.startswith("/")
        and Path(value).is_absolute(),
        f"{label} must be an absolute path",
    )
    return value


def require_trust_path(value: Any, label: str) -> str:
    path = require_absolute_path(value, label)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ContractError(f"{label} cannot be inspected") from exc
    require(
        not stat.S_ISLNK(metadata.st_mode)
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and metadata.st_uid == 0,
        f"{label} must be one root-owned regular file without links",
    )
    return path


def load_ed25519_public_key(
    value: Any,
    *,
    label: str,
) -> tuple[Ed25519PublicKey, str]:
    der = b64url_decode(value, label, exact_bytes=44)
    require(
        der.startswith(ED25519_SPKI_PREFIX),
        f"{label} is not an Ed25519 SPKI",
    )
    try:
        key = serialization.load_der_public_key(der)
    except ValueError as exc:
        raise ContractError(f"{label} is malformed") from exc
    require(isinstance(key, Ed25519PublicKey), f"{label} is not Ed25519")
    return key, sha256_bytes(der)


def validate_certificate_identity(
    certificate_der: bytes,
    *,
    expected_spki_sha256: str,
    expected_spiffe_uri: str | None,
    label: str,
) -> None:
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as exc:
        raise ContractError(f"{label} certificate is malformed") from exc
    public_key_der = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    require(
        hmac.compare_digest(
            sha256_bytes(public_key_der),
            require_sha256(expected_spki_sha256, f"{label} SPKI"),
        ),
        f"{label} certificate SPKI is not pinned",
    )
    if expected_spiffe_uri is None:
        return
    require(
        type(expected_spiffe_uri) is str
        and expected_spiffe_uri.startswith("spiffe://")
        and 10 <= len(expected_spiffe_uri) <= 512,
        f"{label} SPIFFE URI is invalid",
    )
    try:
        alternative_names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound as exc:
        raise ContractError(f"{label} certificate has no SPIFFE SAN") from exc
    spiffe_uris = [
        value
        for value in alternative_names.get_values_for_type(
            x509.UniformResourceIdentifier
        )
        if value.startswith("spiffe://")
    ]
    require(
        spiffe_uris == [expected_spiffe_uri],
        f"{label} SPIFFE identity is not exact",
    )


def certificate_spki_sha256_from_path(
    path: str,
    *,
    label: str,
) -> str:
    require_trust_path(path, f"{label} certificate path")
    raw = Path(path).read_bytes()
    try:
        if b"-----BEGIN CERTIFICATE-----" in raw:
            certificate = x509.load_pem_x509_certificate(raw)
        else:
            certificate = x509.load_der_x509_certificate(raw)
    except ValueError as exc:
        raise ContractError(f"{label} certificate is malformed") from exc
    return sha256_bytes(
        certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def validate_assurance(
    document: Any,
    *,
    expected_sha256: str,
    require_production: bool,
) -> dict[str, Any]:
    assurance = exact(
        document,
        {
            "apiVersion",
            "administrativeDomainSha256",
            "assuranceEvidenceSha256",
            "assuranceEvidenceType",
            "assuranceLevel",
            "authorityEpoch",
            "authorityGeneration",
            "authorityIdentitySha256",
            "backendClass",
            "productionEligible",
            "rollbackProtection",
        },
        "nonce authority assurance",
    )
    rollback = exact(
        assurance["rollbackProtection"],
        {
            "administrativeRollbackResistance",
            "backendAttestationRequired",
            "exactSuccessorRequired",
            "freshVerifierChallengeRequired",
            "keyProtection",
            "mechanism",
            "stateCommitment",
            "verifierStateStoreClass",
        },
        "nonce authority rollback protection",
    )
    require(
        assurance["apiVersion"] == "serverware.nonceAuthorityAssurance/v1"
        and sha256_json(assurance) == require_sha256(expected_sha256, "assurance digest")
        and require_sha256(assurance["administrativeDomainSha256"], "authority administrative domain")
        and require_sha256(assurance["authorityIdentitySha256"], "authority identity")
        and require_uint(assurance["authorityEpoch"], "authority epoch", positive=True)
        and require_uint(assurance["authorityGeneration"], "authority generation", positive=True)
        and rollback["exactSuccessorRequired"] is True
        and rollback["freshVerifierChallengeRequired"] is True,
        "nonce authority assurance identity or continuity contract is invalid",
    )
    profile = (
        assurance["backendClass"],
        rollback["mechanism"],
        rollback["keyProtection"],
        rollback["stateCommitment"],
        rollback["verifierStateStoreClass"],
        assurance["assuranceEvidenceType"],
    )
    if require_production:
        require(
            assurance["productionEligible"] is True
            and assurance["assuranceLevel"] == "productionRollbackProtected"
            and require_sha256(assurance["assuranceEvidenceSha256"], "assurance evidence")
            and rollback["administrativeRollbackResistance"] is True
            and rollback["backendAttestationRequired"] is True
            and profile in PRODUCTION_PROFILES,
            "production mode requires an allowed rollback-protected assurance profile",
        )
    else:
        require(
            assurance["productionEligible"] is False
            and assurance["assuranceLevel"]
            in {"nonProductionFixture", "nonProductionDurableReference"}
            and assurance["assuranceEvidenceSha256"] is None
            and rollback["administrativeRollbackResistance"] is False
            and rollback["backendAttestationRequired"] is False
            and profile == NONPRODUCTION_SQLITE_PROFILE,
            "reference mode requires the closed non-production SQLite profile",
        )
    return assurance


def genesis_commitment(assurance_sha256: str) -> str:
    return sha256_bytes(
        GENESIS_DOMAIN
        + canonical_json(
            {"assuranceSha256": require_sha256(assurance_sha256, "assurance digest")}
        )
    )


def high_water_commitment(preimage: Any) -> str:
    value = exact(
        preimage,
        {
            "apiVersion",
            "assuranceSha256",
            "authorityEpoch",
            "authorityGeneration",
            "nonceConsumptionSha256",
            "nonceVerifierStateAuthorizationSha256",
            "previousHighWaterCommitmentSha256",
            "previousReceiptSha256",
            "sequence",
            "transactionIdBase64url",
        },
        "nonce authority high-water commitment preimage",
    )
    sequence = require_uint(value["sequence"], "high-water sequence", positive=True)
    require(
        value["apiVersion"] == HIGH_WATER_PREIMAGE_VERSION,
        "high-water commitment preimage version is invalid",
    )
    for field in (
        "assuranceSha256",
        "nonceConsumptionSha256",
        "nonceVerifierStateAuthorizationSha256",
        "previousHighWaterCommitmentSha256",
    ):
        require_sha256(value[field], f"high-water preimage {field}")
    require_uint(value["authorityEpoch"], "high-water epoch", positive=True)
    require_uint(value["authorityGeneration"], "high-water generation", positive=True)
    if sequence == 1:
        require(value["previousReceiptSha256"] is None, "first high-water state has a receipt predecessor")
    else:
        require_sha256(value["previousReceiptSha256"], "previous nonce receipt")
    b64url_decode(value["transactionIdBase64url"], "transaction ID", exact_bytes=32)
    return sha256_bytes(HIGH_WATER_DOMAIN + canonical_json(value))


def state_head_commitment(preimage: Any) -> str:
    value = exact(
        preimage,
        {
            "assuranceSha256",
            "authorizationSha256",
            "commitOperationIdBase64url",
            "nonceAuthorityStateSha256",
            "nonceConsumptionReceiptSha256",
            "previousStateStoreHeadSha256",
            "stateStoreGeneration",
        },
        "verifier-state head commitment preimage",
    )
    for field in (
        "assuranceSha256",
        "authorizationSha256",
        "nonceAuthorityStateSha256",
        "nonceConsumptionReceiptSha256",
        "previousStateStoreHeadSha256",
    ):
        require_sha256(value[field], f"state-head preimage {field}")
    b64url_decode(value["commitOperationIdBase64url"], "commit operation ID", exact_bytes=32)
    require_uint(value["stateStoreGeneration"], "state-store generation", positive=True)
    return sha256_bytes(STATE_HEAD_DOMAIN + canonical_json(value))


class SigningAdapter(Protocol):
    production_capable: bool
    key_id: str
    public_key: Ed25519PublicKey
    administrative_domain_sha256: str
    endpoint_identity_sha256: str
    credential_identity_sha256: str
    assurance_evidence_sha256: str | None

    def sign(self, value: bytes) -> bytes:
        ...


class NonProductionEd25519Signer:
    """Exportable local key fixture; never accepted by production mode."""

    production_capable = False

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self.public_key = private_key.public_key()
        der = self.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.key_id = sha256_bytes(der)
        self.administrative_domain_sha256 = sha256_bytes(
            b"non-production-verifier-state-signer-admin"
        )
        self.endpoint_identity_sha256 = sha256_bytes(
            b"non-production-verifier-state-signer-endpoint"
        )
        self.credential_identity_sha256 = sha256_bytes(
            b"non-production-verifier-state-signer-credential"
        )
        self.assurance_evidence_sha256 = None

    @classmethod
    def from_file(cls, path: Path) -> "NonProductionEd25519Signer":
        raw = path.read_bytes()
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except ValueError:
            key = Ed25519PrivateKey.from_private_bytes(raw)
        require(isinstance(key, Ed25519PrivateKey), "reference signing key is not Ed25519")
        return cls(key)

    def sign(self, value: bytes) -> bytes:
        return self._private_key.sign(value)


class NumericAddressHttpsConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        *,
        numeric_address: str,
        port: int,
        context: ssl.SSLContext,
        remaining: Any,
    ) -> None:
        super().__init__(
            host=numeric_address,
            port=port,
            timeout=remaining("connect"),
            context=context,
        )
        self._numeric_address = numeric_address
        self._remaining = remaining

    def connect(self) -> None:
        raw_socket: socket.socket | None = None
        tls_socket: ssl.SSLSocket | None = None
        try:
            raw_socket = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
            os.set_inheritable(raw_socket.fileno(), False)
            raw_socket.settimeout(self._remaining("TCP connect"))
            raw_socket.connect(
                (self._numeric_address, self.port)
            )
            raw_socket.settimeout(self._remaining("TLS wrap"))
            tls_socket = self._context.wrap_socket(
                raw_socket,
                server_hostname=self._numeric_address,
                do_handshake_on_connect=False,
            )
            raw_socket = None
            tls_socket.settimeout(
                self._remaining("TLS handshake")
            )
            tls_socket.do_handshake()
            self.sock = tls_socket
            tls_socket = None
        finally:
            if tls_socket is not None:
                tls_socket.close()
            if raw_socket is not None:
                raw_socket.close()


class CanonicalHttpsClient:
    def __init__(
        self,
        *,
        endpoint: str,
        ca_file: str,
        client_certificate_file: str,
        client_key_file: str,
        expected_server_certificate_spki_sha256: str,
        expected_server_spiffe_uri: str | None,
        timeout_seconds: float,
        max_concurrent_requests: int = MAX_OUTBOUND_CONCURRENCY,
    ) -> None:
        parsed_endpoint = urllib.parse.urlsplit(endpoint)
        require(
            parsed_endpoint.scheme == "https"
            and parsed_endpoint.hostname is not None
            and parsed_endpoint.path in {"", "/"}
            and not parsed_endpoint.query
            and not parsed_endpoint.fragment
            and parsed_endpoint.username is None
            and parsed_endpoint.password is None,
            "production adapter endpoint must be one exact HTTPS authority",
        )
        try:
            numeric_address = ipaddress.ip_address(
                parsed_endpoint.hostname
            )
        except ValueError as exc:
            raise ContractError(
                "production adapter endpoint must use a literal IPv4 address"
            ) from exc
        require(
            isinstance(numeric_address, ipaddress.IPv4Address)
            and str(numeric_address) == parsed_endpoint.hostname,
            "production adapter endpoint must use one canonical literal "
            "IPv4 address",
        )
        require(0.1 <= timeout_seconds <= 10.0, "adapter timeout is outside the bounded range")
        for path, label in (
            (ca_file, "adapter CA file"),
            (client_certificate_file, "adapter client certificate file"),
            (client_key_file, "adapter client key file"),
        ):
            require_absolute_path(path, label)
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(client_certificate_file, client_key_file)
        require(
            type(max_concurrent_requests) is int
            and 1 <= max_concurrent_requests <= MAX_OUTBOUND_CONCURRENCY,
            "adapter concurrency is outside the bounded range",
        )
        self._context = context
        self._numeric_address = str(numeric_address)
        self._port = parsed_endpoint.port or 443
        self._authority = parsed_endpoint.netloc
        self._expected_server_certificate_spki_sha256 = require_sha256(
            expected_server_certificate_spki_sha256,
            "adapter server certificate SPKI",
        )
        self._expected_server_spiffe_uri = expected_server_spiffe_uri
        self._timeout = timeout_seconds
        self._request_slots = threading.BoundedSemaphore(
            max_concurrent_requests
        )

    def post(
        self,
        path: str,
        document: dict[str, Any],
        *,
        outcome_may_be_unknown: bool,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        require(
            type(path) is str
            and path.startswith("/v1/")
            and "?" not in path
            and "#" not in path,
            "external adapter path is not exact",
        )
        body = canonical_json(document)
        started_at = time.monotonic()
        if deadline is not None:
            require(
                type(deadline) is float and deadline > started_at,
                "ingress deadline expired before the external adapter "
                "operation began",
            )
        operation_deadline = min(
            started_at + self._timeout,
            deadline
            if deadline is not None
            else started_at + self._timeout,
        )

        def remaining(phase: str) -> float:
            value = operation_deadline - time.monotonic()
            if value <= 0:
                if outcome_may_be_unknown:
                    raise UnknownOutcomeError(
                        f"mutating external adapter {phase} exceeded its total deadline"
                    )
                raise ContractError(
                    f"non-mutating external adapter {phase} exceeded its total deadline"
                )
            return value

        if not self._request_slots.acquire(
            timeout=remaining("admission"),
        ):
            raise ContractError(
                "external adapter concurrency was not admitted before "
                "the ingress deadline"
            )
        connection: NumericAddressHttpsConnection | None = None
        try:
            connection = NumericAddressHttpsConnection(
                numeric_address=self._numeric_address,
                port=self._port,
                context=self._context,
                remaining=remaining,
            )
            connection.connect()
            peer_socket = connection.sock
            require(
                isinstance(peer_socket, ssl.SSLSocket),
                "external adapter did not establish TLS",
            )
            certificate_der = peer_socket.getpeercert(binary_form=True)
            require(
                type(certificate_der) is bytes and certificate_der,
                "external adapter server certificate is missing",
            )
            validate_certificate_identity(
                certificate_der,
                expected_spki_sha256=(
                    self._expected_server_certificate_spki_sha256
                ),
                expected_spiffe_uri=self._expected_server_spiffe_uri,
                label="external adapter server",
            )
            peer_socket.settimeout(remaining("request headers"))
            connection.putrequest(
                "POST",
                path,
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", self._authority)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(len(body)))
            connection.putheader("Accept", "application/json")
            connection.putheader("Connection", "close")
            peer_socket.settimeout(remaining("request body"))
            connection.endheaders(body)
            peer_socket.settimeout(remaining("response headers"))
            response = connection.getresponse()
            headers = response.headers
            require(
                response.version == 11
                and len(headers.items()) <= 64
                and sum(
                    len(name) + len(value) + 4
                    for name, value in headers.items()
                )
                <= MAX_HEADER_BYTES
                and not headers.get_all("Transfer-Encoding")
                and not headers.get_all("Trailer")
                and not headers.get_all("Content-Encoding"),
                "external adapter response framing is forbidden",
            )
            content_lengths = headers.get_all("Content-Length")
            require(
                content_lengths is not None
                and len(content_lengths) == 1
                and re.fullmatch(
                    r"0|[1-9][0-9]*",
                    content_lengths[0],
                    re.ASCII,
                )
                is not None,
                "external adapter response Content-Length is ambiguous",
            )
            content_length = int(content_lengths[0])
            require(
                1 <= content_length <= MAX_JSON_BYTES,
                "external adapter response body size is invalid",
            )
            require(
                headers.get_all("Content-Type") == ["application/json"]
                and headers.get_all("Connection") == ["close"],
                "external adapter response media type or close framing is invalid",
            )
            chunks: list[bytes] = []
            received = 0
            while received < content_length:
                peer_socket.settimeout(remaining("response body"))
                chunk = response.read1(
                    min(64 * 1024, content_length - received)
                )
                require(
                    chunk,
                    "external adapter response was truncated",
                )
                chunks.append(chunk)
                received += len(chunk)
            raw = b"".join(chunks)
            require(
                len(raw) == content_length,
                "external adapter response was truncated or oversized",
            )
            peer_socket.settimeout(
                min(remaining("response EOF"), EOF_TIMEOUT_SECONDS)
            )
            trailing = peer_socket.recv(1)
            require(
                trailing == b"",
                "external adapter response carried trailing bytes",
            )
            if response.status != 200:
                if outcome_may_be_unknown:
                    raise UnknownOutcomeError(
                        "mutating external adapter returned a non-200 response"
                    )
                raise ContractError(
                    "non-mutating external adapter returned a non-200 response"
                )
        except UnknownOutcomeError:
            raise
        except ContractError as exc:
            if outcome_may_be_unknown:
                raise UnknownOutcomeError(
                    "mutating external adapter returned an invalid response"
                ) from exc
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            if outcome_may_be_unknown:
                raise UnknownOutcomeError(
                    "mutating external adapter outcome is unknown"
                ) from exc
            raise ContractError(
                "non-mutating external adapter transport failed closed"
            ) from exc
        finally:
            if connection is not None:
                connection.close()
            self._request_slots.release()
        try:
            return exact(
                parse_canonical_json(
                    raw,
                    label="external adapter response",
                ),
                {
                    "apiVersion",
                    "operation",
                    "requestSha256",
                    "result",
                },
                "external adapter response",
            )
        except ContractError as exc:
            if outcome_may_be_unknown:
                raise UnknownOutcomeError(
                    "mutating external adapter returned an invalid response"
                ) from exc
            raise


class ExternalEd25519Signer:
    """Remote signer transport; capability is asserted only by verified evidence."""

    production_capable = False

    def __init__(
        self,
        *,
        client: CanonicalHttpsClient,
        public_key_spki_der_base64url: str,
        administrative_domain_sha256: str,
        endpoint_identity_sha256: str,
        credential_identity_sha256: str,
        assurance_evidence_sha256: str,
    ) -> None:
        self.public_key, self.key_id = load_ed25519_public_key(
            public_key_spki_der_base64url,
            label="remote signer public key",
        )
        self.administrative_domain_sha256 = require_sha256(
            administrative_domain_sha256,
            "signer administrative domain",
        )
        self.endpoint_identity_sha256 = require_sha256(
            endpoint_identity_sha256,
            "signer endpoint identity",
        )
        self.credential_identity_sha256 = require_sha256(
            credential_identity_sha256,
            "signer credential identity",
        )
        self.assurance_evidence_sha256 = require_sha256(
            assurance_evidence_sha256,
            "signer assurance evidence",
        )
        self._client = client

    def sign(
        self,
        value: bytes,
        *,
        deadline: float | None = None,
    ) -> bytes:
        request = {
            "apiVersion": REMOTE_SIGN_REQUEST_VERSION,
            "messageBase64url": b64url_encode(value),
            "messageSha256": sha256_bytes(value),
            "signingKeySpkiSha256": self.key_id,
        }
        response = self._client.post(
            "/v1/sign",
            request,
            outcome_may_be_unknown=False,
            deadline=deadline,
        )
        result = exact(
            response["result"],
            {
                "apiVersion",
                "messageSha256",
                "signatureAlgorithm",
                "signatureBase64url",
                "signingKeySpkiSha256",
            },
            "remote signer result",
        )
        require(
            response["apiVersion"] == EXTERNAL_STORE_RESPONSE_VERSION
            and response["operation"] == "sign"
            and response["requestSha256"] == sha256_json(request)
            and result["apiVersion"] == REMOTE_SIGN_RESPONSE_VERSION
            and result["messageSha256"] == request["messageSha256"]
            and result["signatureAlgorithm"] == "Ed25519"
            and result["signingKeySpkiSha256"] == self.key_id,
            "remote signer response crossed its request or key",
        )
        signature = b64url_decode(result["signatureBase64url"], "remote signature", exact_bytes=64)
        try:
            self.public_key.verify(signature, value)
        except InvalidSignature as exc:
            raise ContractError("remote signer returned an invalid signature") from exc
        return signature


def sign_envelope(
    signer: SigningAdapter,
    *,
    api_version: str,
    domain: bytes,
    payload: dict[str, Any],
    deadline: float | None = None,
) -> dict[str, Any]:
    payload_sha256 = sha256_json(payload)
    signing_input = domain + canonical_json(
        {"payload": payload, "payloadSha256": payload_sha256}
    )
    signature = (
        signer.sign(signing_input, deadline=deadline)
        if isinstance(signer, ExternalEd25519Signer)
        else signer.sign(signing_input)
    )
    require(len(signature) == 64, "Ed25519 signer returned a malformed signature")
    return {
        "apiVersion": api_version,
        "payload": payload,
        "payloadSha256": payload_sha256,
        "signatureAlgorithm": "Ed25519",
        "signatureBase64url": b64url_encode(signature),
        "signingKeyId": signer.key_id,
        "signingKeySpkiSha256": signer.key_id,
    }


def verify_envelope(
    document: Any,
    *,
    api_version: str,
    domain: bytes,
    signer: SigningAdapter,
    label: str,
) -> dict[str, Any]:
    envelope = exact(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        label,
    )
    payload_sha256 = sha256_json(envelope["payload"])
    require(
        envelope["apiVersion"] == api_version
        and envelope["payloadSha256"] == payload_sha256
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == signer.key_id
        and envelope["signingKeySpkiSha256"] == signer.key_id,
        f"{label} crossed its version, digest, or key",
    )
    signature = b64url_decode(envelope["signatureBase64url"], f"{label} signature", exact_bytes=64)
    try:
        signer.public_key.verify(
            signature,
            domain
            + canonical_json(
                {"payload": envelope["payload"], "payloadSha256": payload_sha256}
            ),
        )
    except InvalidSignature as exc:
        raise ContractError(f"{label} signature is invalid") from exc
    return envelope


def verify_pinned_envelope(
    document: Any,
    *,
    api_version: str,
    domain: bytes,
    public_key: Ed25519PublicKey,
    key_id: str,
    label: str,
) -> dict[str, Any]:
    envelope = exact(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        label,
    )
    payload_sha256 = sha256_json(envelope["payload"])
    require(
        envelope["apiVersion"] == api_version
        and envelope["payloadSha256"] == payload_sha256
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == key_id
        and envelope["signingKeySpkiSha256"] == key_id,
        f"{label} crossed its version, digest, or pinned key",
    )
    signature = b64url_decode(
        envelope["signatureBase64url"],
        f"{label} signature",
        exact_bytes=64,
    )
    try:
        public_key.verify(
            signature,
            domain
            + canonical_json(
                {
                    "payload": envelope["payload"],
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise ContractError(f"{label} signature is invalid") from exc
    return envelope


class NonceAuthorityReceiptVerifier:
    def __init__(
        self,
        *,
        signing_public_key_spki_der_base64url: str,
        store_identity_sha256: str,
        administrative_domain_sha256: str,
        endpoint_identity_sha256: str,
        credential_identity_sha256: str,
        assurance_evidence_sha256: str | None,
    ) -> None:
        self.public_key, self.key_id = load_ed25519_public_key(
            signing_public_key_spki_der_base64url,
            label="nonce authority receipt signing key",
        )
        self.store_identity_sha256 = require_sha256(
            store_identity_sha256,
            "nonce authority store identity",
        )
        self.administrative_domain_sha256 = require_sha256(
            administrative_domain_sha256,
            "nonce authority administrative domain",
        )
        self.endpoint_identity_sha256 = require_sha256(
            endpoint_identity_sha256,
            "nonce authority endpoint identity",
        )
        self.credential_identity_sha256 = require_sha256(
            credential_identity_sha256,
            "nonce authority credential identity",
        )
        self.assurance_evidence_sha256 = (
            None
            if assurance_evidence_sha256 is None
            else require_sha256(
                assurance_evidence_sha256,
                "nonce authority assurance evidence",
            )
        )

    def validate(
        self,
        document: Any,
        *,
        assurance: dict[str, Any],
        assurance_sha256: str,
        authorization_payload: dict[str, Any],
        authorization_sha256: str,
        now: int | None,
    ) -> dict[str, Any]:
        envelope = verify_pinned_envelope(
            document,
            api_version=SIGNED_NONCE_RECEIPT_VERSION,
            domain=NONCE_RECEIPT_DOMAIN,
            public_key=self.public_key,
            key_id=self.key_id,
            label="signed nonce consumption receipt",
        )
        payload = exact(
            envelope["payload"],
            {
                "apiVersion",
                "consumeRequestSha256",
                "consumedAtUnix",
                "expiresAtUnix",
                "finalExternalVerifierChallengeConsumed",
                "finalExternalVerifierChallengeConsumptionRequired",
                "nonceAuthorityAssuranceSha256",
                "nonceAuthorityState",
                "nonceAuthorityStateSha256",
                "nonceAuthorityVerifierStateAuthorizationSha256",
                "nonceConsumption",
                "nonceConsumptionSha256",
                "nonceSha256",
                "previousReceiptSha256",
                "producerChannelChallengeBase64url",
                "producerEphemeralKeySha256",
                "producerInvocationSha256",
                "receiptIssuedAtUnix",
                "requestBodySha256",
                "sequence",
                "signerChannelBindingSha256",
                "storeIdentitySha256",
                "tlsBindingSha256",
                "transactionIdBase64url",
            },
            "signed nonce consumption receipt payload",
        )
        consumption = exact(
            payload["nonceConsumption"],
            {
                "apiVersion",
                "consumedAtUnix",
                "nonceSha256",
                "oneUse",
                "requestBodySha256",
                "sequence",
                "storeIdentitySha256",
                "tlsBindingSha256",
            },
            "nonce consumption",
        )
        state = exact(
            payload["nonceAuthorityState"],
            {
                "apiVersion",
                "assuranceSha256",
                "authorityEpoch",
                "authorityGeneration",
                "highWaterCommitmentSha256",
                "highWaterSequence",
                "previousHighWaterCommitmentSha256",
            },
            "nonce authority state",
        )
        sequence = require_uint(
            payload["sequence"],
            "nonce receipt sequence",
            positive=True,
        )
        consumed_at = require_uint(
            payload["consumedAtUnix"],
            "nonce consumed time",
            positive=True,
        )
        expires_at = require_uint(
            payload["expiresAtUnix"],
            "nonce expiration",
            positive=True,
        )
        issued_at = require_uint(
            payload["receiptIssuedAtUnix"],
            "nonce receipt issue time",
            positive=True,
        )
        for field in (
            "consumeRequestSha256",
            "nonceAuthorityAssuranceSha256",
            "nonceAuthorityStateSha256",
            "nonceAuthorityVerifierStateAuthorizationSha256",
            "nonceConsumptionSha256",
            "nonceSha256",
            "producerEphemeralKeySha256",
            "producerInvocationSha256",
            "requestBodySha256",
            "signerChannelBindingSha256",
            "storeIdentitySha256",
            "tlsBindingSha256",
        ):
            require_sha256(payload[field], f"nonce receipt {field}")
        b64url_decode(
            payload["producerChannelChallengeBase64url"],
            "producer channel challenge",
            exact_bytes=32,
        )
        b64url_decode(
            payload["transactionIdBase64url"],
            "nonce transaction ID",
            exact_bytes=32,
        )
        expected_sequence = checked_add_uint(
            authorization_payload["highWaterSequence"],
            1,
            "nonce authority high-water sequence",
        )
        consumption_sha256 = sha256_json(consumption)
        state_sha256 = sha256_json(state)
        receipt_sha256 = sha256_json(envelope)
        consume_request_sha256 = sha256_bytes(
            NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
            + canonical_json(
                {
                    "apiVersion":
                    NONCE_CONSUME_ONCE_REQUEST_VERSION,
                    "expiresAtUnix": expires_at,
                    "nonceAuthorityVerifierStateAuthorizationSha256":
                    authorization_sha256,
                    "nonceSha256": payload["nonceSha256"],
                    "producerChannelChallengeBase64url":
                    payload["producerChannelChallengeBase64url"],
                    "producerEphemeralKeySha256":
                    payload["producerEphemeralKeySha256"],
                    "producerInvocationSha256":
                    payload["producerInvocationSha256"],
                    "requestBodySha256":
                    payload["requestBodySha256"],
                    "tlsBindingSha256": payload["tlsBindingSha256"],
                    "transactionIdBase64url":
                    payload["transactionIdBase64url"],
                }
            )
        )
        preimage = {
            "apiVersion": HIGH_WATER_PREIMAGE_VERSION,
            "assuranceSha256": assurance_sha256,
            "authorityEpoch": assurance["authorityEpoch"],
            "authorityGeneration": assurance["authorityGeneration"],
            "nonceConsumptionSha256": consumption_sha256,
            "nonceVerifierStateAuthorizationSha256":
            authorization_sha256,
            "previousHighWaterCommitmentSha256":
            authorization_payload["highWaterCommitmentSha256"],
            "previousReceiptSha256":
            authorization_payload["highWaterReceiptSha256"],
            "sequence": sequence,
            "transactionIdBase64url":
            payload["transactionIdBase64url"],
        }
        require(
            payload["apiVersion"] == NONCE_RECEIPT_PAYLOAD_VERSION
            and payload["consumeRequestSha256"]
            == consume_request_sha256
            and payload["nonceAuthorityAssuranceSha256"]
            == assurance_sha256
            and payload["nonceAuthorityVerifierStateAuthorizationSha256"]
            == authorization_sha256
            and payload["storeIdentitySha256"]
            == self.store_identity_sha256
            and payload["previousReceiptSha256"]
            == authorization_payload["highWaterReceiptSha256"]
            and payload["nonceConsumptionSha256"]
            == consumption_sha256
            and payload["nonceAuthorityStateSha256"] == state_sha256
            and payload["finalExternalVerifierChallengeConsumptionRequired"]
            is True
            and payload["finalExternalVerifierChallengeConsumed"] is False
            and sequence == expected_sequence
            and consumed_at == issued_at
            and consumed_at < expires_at
            and authorization_payload["issuedAtUnix"]
            <= consumed_at
            < authorization_payload["expiresAtUnix"]
            and (
                now is None
                or consumed_at <= now < expires_at
            )
            and consumption["apiVersion"] == NONCE_CONSUMPTION_VERSION
            and consumption["oneUse"] is True
            and consumption["consumedAtUnix"] == consumed_at
            and consumption["sequence"] == sequence
            and consumption["nonceSha256"] == payload["nonceSha256"]
            and consumption["requestBodySha256"]
            == payload["requestBodySha256"]
            and consumption["tlsBindingSha256"]
            == payload["tlsBindingSha256"]
            and consumption["storeIdentitySha256"]
            == self.store_identity_sha256
            and state["apiVersion"] == NONCE_AUTHORITY_STATE_VERSION
            and state["assuranceSha256"] == assurance_sha256
            and state["authorityEpoch"] == assurance["authorityEpoch"]
            and state["authorityGeneration"]
            == assurance["authorityGeneration"]
            and state["highWaterSequence"] == sequence
            and state["previousHighWaterCommitmentSha256"]
            == authorization_payload["highWaterCommitmentSha256"]
            and state["highWaterCommitmentSha256"]
            == high_water_commitment(preimage),
            "signed nonce receipt crossed its authority, authorization, "
            "consumption, predecessor, or exact successor",
        )
        return {
            "consumption": consumption,
            "consumptionSha256": consumption_sha256,
            "document": envelope,
            "payload": payload,
            "preimage": preimage,
            "receiptSha256": receipt_sha256,
            "state": state,
            "stateSha256": state_sha256,
            "transactionIdBase64url":
            payload["transactionIdBase64url"],
        }

    def validate_status_evidence(
        self,
        document: Any,
        *,
        prepared_operation: dict[str, Any],
        nonce_consumption_receipt: dict[str, Any] | None,
        now: int,
    ) -> dict[str, Any]:
        envelope = verify_pinned_envelope(
            document,
            api_version=SIGNED_NONCE_STATUS_EVIDENCE_VERSION,
            domain=NONCE_STATUS_EVIDENCE_DOMAIN,
            public_key=self.public_key,
            key_id=self.key_id,
            label="signed nonce transaction status evidence",
        )
        payload = exact(
            envelope["payload"],
            {
                "apiVersion",
                "consumeRequestSha256",
                "evidenceIssuedAtUnix",
                "neverConsumable",
                "nonceAuthorityVerifierStateAuthorizationSha256",
                "nonceConsumptionReceiptSha256",
                "nonceSha256",
                "preparedOperationSha256",
                "recoveryKeySha256",
                "requestBindingSha256",
                "requestOperation",
                "status",
                "transactionIdBase64url",
            },
            "nonce transaction status evidence payload",
        )
        prepared = exact(
            prepared_operation,
            {
                "apiVersion",
                "authorization",
                "authorizationSha256",
                "nonceConsumeRequest",
                "nonceConsumeRequestSha256",
                "prepareRequest",
                "prepareRequestSha256",
                "recoveryBinding",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
                "requestBinding",
                "requestBindingSha256",
                "successorIntent",
                "successorIntentSha256",
            },
            "prepared operation",
        )
        consume_request = prepared["nonceConsumeRequest"]
        status = payload["status"]
        receipt_sha256 = (
            None
            if nonce_consumption_receipt is None
            else sha256_json(nonce_consumption_receipt)
        )
        issued = require_uint(
            payload["evidenceIssuedAtUnix"],
            "nonce status evidence issue time",
            positive=True,
        )
        require(
            payload["apiVersion"] == NONCE_STATUS_EVIDENCE_VERSION
            and payload["consumeRequestSha256"]
            == prepared["nonceConsumeRequestSha256"]
            and payload[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ]
            == prepared["authorizationSha256"]
            and payload["nonceSha256"]
            == consume_request["nonceSha256"]
            and payload["transactionIdBase64url"]
            == consume_request["transactionIdBase64url"]
            and payload["preparedOperationSha256"]
            == sha256_json(prepared)
            and payload["recoveryKeySha256"]
            == prepared["recoveryKeySha256"]
            and payload["requestBindingSha256"]
            == prepared["requestBindingSha256"]
            and issued <= now
            and now - issued <= 60
            and status
            in {"consumed", "neverConsumed", "notObserved"},
            "nonce transaction status evidence crossed its prepared operation",
        )
        if status == "consumed":
            require(
                payload["requestOperation"] == "recoverExact"
                and payload["neverConsumable"] is False
                and type(nonce_consumption_receipt) is dict
                and payload["nonceConsumptionReceiptSha256"]
                == receipt_sha256,
                "consumed nonce status omitted its exact retained receipt",
            )
        elif status == "neverConsumed":
            require(
                payload["requestOperation"]
                in {"recoverExact", "proveNeverConsumedAndBlock"}
                and payload["neverConsumable"] is True
                and nonce_consumption_receipt is None
                and payload["nonceConsumptionReceiptSha256"] is None,
                "never-consumed evidence is not an irrevocable authority tombstone",
            )
        else:
            require(
                payload["requestOperation"] == "recoverExact"
                and payload["neverConsumable"] is False
                and nonce_consumption_receipt is None
                and payload["nonceConsumptionReceiptSha256"] is None,
                "not-observed nonce status carried actionable authority",
            )
        return {
            "document": envelope,
            "documentSha256": sha256_json(envelope),
            "payload": payload,
        }


def validate_nonce_authority_assurance_evidence(
    document: Any,
    *,
    evidence_public_key: Ed25519PublicKey,
    evidence_key_id: str,
    assurance: dict[str, Any],
    nonce_authority: NonceAuthorityReceiptVerifier,
    store: StateStoreAdapter,
    verifier_state_signing_key_id: str,
    now: int,
) -> dict[str, Any]:
    envelope = verify_pinned_envelope(
        document,
        api_version=(
            SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
        ),
        domain=NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN,
        public_key=evidence_public_key,
        key_id=evidence_key_id,
        label="signed nonce authority assurance evidence",
    )
    payload = exact(
        envelope["payload"],
        {
            "administrativeDomainSha256",
            "apiVersion",
            "assuranceEvidenceType",
            "authorityEpoch",
            "authorityGeneration",
            "authorityIdentitySha256",
            "backendClass",
            "expiresAtUnix",
            "issuedAtUnix",
            "nonceAuthorityStateSigningKeySpkiSha256",
            "rollbackMechanism",
            "stateCommitment",
            "verifierStateStoreAdministrativeDomainSha256",
            "verifierStateStoreClass",
            "verifierStateStoreIdentitySha256",
            "verifierStateStoreSigningKeySpkiSha256",
        },
        "nonce authority assurance evidence payload",
    )
    issued = require_uint(
        payload["issuedAtUnix"],
        "nonce authority assurance evidence issue time",
        positive=True,
    )
    expires = require_uint(
        payload["expiresAtUnix"],
        "nonce authority assurance evidence expiry",
        positive=True,
    )
    rollback = assurance["rollbackProtection"]
    require(
        sha256_json(envelope)
        == assurance["assuranceEvidenceSha256"]
        == nonce_authority.assurance_evidence_sha256
        and payload["apiVersion"]
        == NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
        and payload["administrativeDomainSha256"]
        == assurance["administrativeDomainSha256"]
        == nonce_authority.administrative_domain_sha256
        and payload["assuranceEvidenceType"]
        == assurance["assuranceEvidenceType"]
        and payload["authorityEpoch"] == assurance["authorityEpoch"]
        and payload["authorityGeneration"]
        == assurance["authorityGeneration"]
        and payload["authorityIdentitySha256"]
        == assurance["authorityIdentitySha256"]
        == nonce_authority.store_identity_sha256
        and payload["backendClass"] == assurance["backendClass"]
        and payload["nonceAuthorityStateSigningKeySpkiSha256"]
        == nonce_authority.key_id
        and payload["rollbackMechanism"] == rollback["mechanism"]
        and payload["stateCommitment"] == rollback["stateCommitment"]
        and payload["verifierStateStoreAdministrativeDomainSha256"]
        == store.administrative_domain_sha256
        and payload["verifierStateStoreClass"] == store.store_class
        and payload["verifierStateStoreIdentitySha256"]
        == store.store_identity_sha256
        and payload["verifierStateStoreSigningKeySpkiSha256"]
        == verifier_state_signing_key_id
        and payload["verifierStateStoreAdministrativeDomainSha256"]
        != payload["administrativeDomainSha256"]
        and issued <= now < expires
        and expires - issued <= 86400,
        "nonce authority assurance evidence is stale, substituted, or crossed with the configured authority/store",
    )
    return {
        "document": envelope,
        "documentSha256": sha256_json(envelope),
        "payload": payload,
    }


def validate_store_assurance_evidence(
    document: Any,
    *,
    evidence_public_key: Ed25519PublicKey,
    evidence_key_id: str,
    expected_issuer_administrative_domain_sha256: str,
    expected_issuer_credential_identity_sha256: str,
    expected_issuer_identity_sha256: str,
    store: StateStoreAdapter,
    now: int,
) -> dict[str, Any]:
    envelope = verify_pinned_envelope(
        document,
        api_version=SIGNED_STORE_ASSURANCE_EVIDENCE_VERSION,
        domain=STORE_ASSURANCE_EVIDENCE_DOMAIN,
        public_key=evidence_public_key,
        key_id=evidence_key_id,
        label="signed verifier-state store assurance evidence",
    )
    payload = exact(
        envelope["payload"],
        {
            "apiVersion",
            "commitIndexSemantics",
            "evidenceExpiresAtUnix",
            "evidenceIssuedAtUnix",
            "generationSemantics",
            "issuerAdministrativeDomainSha256",
            "issuerCredentialIdentitySha256",
            "issuerIdentitySha256",
            "minimumStoreCommitIndex",
            "minimumStoreGeneration",
            "productionEligible",
            "rollbackMechanism",
            "storeAdministrativeDomainSha256",
            "storeAttestationKeySpkiSha256",
            "storeConfigurationSha256",
            "storeCredentialIdentitySha256",
            "storeIdentitySha256",
        },
        "verifier-state store assurance evidence payload",
    )
    issued = require_uint(
        payload["evidenceIssuedAtUnix"],
        "store assurance evidence issue time",
        positive=True,
    )
    expires = require_uint(
        payload["evidenceExpiresAtUnix"],
        "store assurance evidence expiry",
        positive=True,
    )
    minimum_generation = require_uint(
        payload["minimumStoreGeneration"],
        "store assurance minimum generation",
        positive=True,
    )
    minimum_commit_index = require_uint(
        payload["minimumStoreCommitIndex"],
        "store assurance minimum commit index",
        positive=True,
    )
    require(
        sha256_json(envelope) == store.assurance_evidence_sha256
        and payload["apiVersion"] == STORE_ASSURANCE_EVIDENCE_VERSION
        and payload["productionEligible"] is True
        and payload["generationSemantics"] == "strictlyMonotonicU64"
        and payload["commitIndexSemantics"]
        == "equalToVerifierStateGeneration"
        and payload["rollbackMechanism"] == store.rollback_mechanism
        and payload["storeIdentitySha256"]
        == store.store_identity_sha256
        and payload["storeAdministrativeDomainSha256"]
        == store.administrative_domain_sha256
        and payload["storeCredentialIdentitySha256"]
        == store.credential_identity_sha256
        and payload["storeAttestationKeySpkiSha256"]
        == store.attestation_key_id
        and payload["storeConfigurationSha256"]
        == store.configuration_sha256
        and payload["issuerAdministrativeDomainSha256"]
        == require_sha256(
            expected_issuer_administrative_domain_sha256,
            "store assurance issuer administrative domain",
        )
        and payload["issuerCredentialIdentitySha256"]
        == require_sha256(
            expected_issuer_credential_identity_sha256,
            "store assurance issuer credential identity",
        )
        and payload["issuerIdentitySha256"]
        == require_sha256(
            expected_issuer_identity_sha256,
            "store assurance issuer identity",
        )
        and issued <= now < expires
        and expires - issued <= 86400
        and minimum_generation == store.minimum_generation
        and minimum_commit_index == store.minimum_commit_index,
        "store assurance evidence is stale, substituted, or incomplete",
    )
    for issuer_field, store_value in (
        (
            payload["issuerAdministrativeDomainSha256"],
            store.administrative_domain_sha256,
        ),
        (
            payload["issuerCredentialIdentitySha256"],
            store.credential_identity_sha256,
        ),
        (
            payload["issuerIdentitySha256"],
            store.store_identity_sha256,
        ),
    ):
        require(
            issuer_field != store_value,
            "store assurance is self-attested by the store role",
        )
    require(
        evidence_key_id != store.attestation_key_id,
        "store assurance issuer key collides with store attestation key",
    )
    return envelope


def validate_global_attestation_key_role_separation(
    role_key_ids: Mapping[str, Any],
) -> dict[str, str]:
    require(
        bool(role_key_ids),
        "global verifier-state role registry is empty",
    )
    normalized = {
        name: require_sha256(
            key_id,
            f"global verifier-state {name} role",
        )
        for name, key_id in role_key_ids.items()
    }
    collisions: dict[str, list[str]] = {}
    for name, key_id in normalized.items():
        collisions.setdefault(key_id, []).append(name)
    duplicate_roles = sorted(
        sorted(names)
        for names in collisions.values()
        if len(names) > 1
    )
    require(
        not duplicate_roles,
        "global verifier-state key roles collide: "
        f"{duplicate_roles!r}",
    )
    return normalized


def validate_role_separation_evidence(
    document: Any,
    *,
    evidence_public_key: Ed25519PublicKey,
    evidence_key_id: str,
    assurance_sha256: str,
    nonce_authority: NonceAuthorityReceiptVerifier,
    signer: SigningAdapter,
    store: StateStoreAdapter,
    expected_additional_roles: dict[str, dict[str, Any]],
    now: int,
) -> dict[str, Any]:
    envelope = verify_pinned_envelope(
        document,
        api_version=SIGNED_ROLE_SEPARATION_EVIDENCE_VERSION,
        domain=ROLE_SEPARATION_EVIDENCE_DOMAIN,
        public_key=evidence_public_key,
        key_id=evidence_key_id,
        label="signed verifier-state role-separation evidence",
    )
    payload = exact(
        envelope["payload"],
        {
            "apiVersion",
            "assuranceSha256",
            "evidenceExpiresAtUnix",
            "evidenceIssuedAtUnix",
            "nonceAuthority",
            "nonceAuthorityAssuranceEvidenceIssuer",
            "publicAttestationClientTls",
            "productionEligible",
            "roleSeparationEvidenceIssuer",
            "storeAssuranceEvidenceIssuer",
            "verifierStateSigner",
            "verifierStateSignerClientTls",
            "verifierStateSignerServerTls",
            "verifierStateStore",
            "verifierStateStoreClientTls",
            "verifierStateStoreServerTls",
            "verifierStateServiceListenerTls",
        },
        "verifier-state role-separation evidence payload",
    )

    def role(value: Any, label: str) -> dict[str, Any]:
        result = exact(
            value,
            {
                "administrativeDomainSha256",
                "assuranceEvidenceSha256",
                "credentialIdentitySha256",
                "endpointIdentitySha256",
                "keySpkiSha256",
                "roleIdentitySha256",
            },
            label,
        )
        for field in result:
            require_sha256(result[field], f"{label} {field}")
        return result

    roles = {
        "nonceAuthority": role(
            payload["nonceAuthority"],
            "nonce authority role",
        ),
        "verifierStateSigner": role(
            payload["verifierStateSigner"],
            "verifier-state signer role",
        ),
        "verifierStateStore": role(
            payload["verifierStateStore"],
            "verifier-state store role",
        ),
    }
    issued = require_uint(
        payload["evidenceIssuedAtUnix"],
        "role evidence issue time",
        positive=True,
    )
    expires = require_uint(
        payload["evidenceExpiresAtUnix"],
        "role evidence expiry",
        positive=True,
    )
    expected_roles = {
        "nonceAuthority": {
        "administrativeDomainSha256":
        nonce_authority.administrative_domain_sha256,
        "assuranceEvidenceSha256":
        nonce_authority.assurance_evidence_sha256,
        "credentialIdentitySha256":
        nonce_authority.credential_identity_sha256,
        "endpointIdentitySha256":
        nonce_authority.endpoint_identity_sha256,
        "keySpkiSha256": nonce_authority.key_id,
        "roleIdentitySha256":
        nonce_authority.store_identity_sha256,
        },
        "verifierStateSigner": {
        "administrativeDomainSha256":
        signer.administrative_domain_sha256,
        "assuranceEvidenceSha256":
        signer.assurance_evidence_sha256,
        "credentialIdentitySha256":
        signer.credential_identity_sha256,
        "endpointIdentitySha256":
        signer.endpoint_identity_sha256,
        "keySpkiSha256": signer.key_id,
        "roleIdentitySha256": signer.key_id,
        },
        "verifierStateStore": {
        "administrativeDomainSha256":
        store.administrative_domain_sha256,
        "assuranceEvidenceSha256":
        store.assurance_evidence_sha256,
        "credentialIdentitySha256":
        store.credential_identity_sha256,
        "endpointIdentitySha256":
        store.endpoint_identity_sha256,
        "keySpkiSha256": store.attestation_key_id,
        "roleIdentitySha256": store.store_identity_sha256,
        },
    }
    required_additional_role_names = {
        "nonceAuthorityAssuranceEvidenceIssuer",
        "publicAttestationClientTls",
        "roleSeparationEvidenceIssuer",
        "storeAssuranceEvidenceIssuer",
        "verifierStateServiceListenerTls",
        "verifierStateSignerClientTls",
        "verifierStateSignerServerTls",
        "verifierStateStoreClientTls",
        "verifierStateStoreServerTls",
    }
    require(
        set(expected_additional_roles)
        == required_additional_role_names,
        "role-separation additional-role pins are incomplete",
    )
    for role_name in sorted(required_additional_role_names):
        roles[role_name] = role(
            payload[role_name],
            f"{role_name} role",
        )
        expected_roles[role_name] = role(
            expected_additional_roles[role_name],
            f"expected {role_name} role",
        )
    require(
        payload["apiVersion"] == ROLE_SEPARATION_EVIDENCE_VERSION
        and payload["assuranceSha256"] == assurance_sha256
        and payload["productionEligible"] is True
        and issued <= now < expires
        and expires - issued <= 86400
        and roles == expected_roles,
        "role-separation evidence is stale, substituted, or incomplete",
    )
    for field in (
        "administrativeDomainSha256",
        "credentialIdentitySha256",
        "endpointIdentitySha256",
        "keySpkiSha256",
        "roleIdentitySha256",
    ):
        require(
            len({value[field] for value in roles.values()})
            == len(roles),
            f"verifier-state production roles collide on {field}",
        )
    require(
        roles["roleSeparationEvidenceIssuer"]["keySpkiSha256"]
        == evidence_key_id,
        "role-evidence signing key is not its modeled issuer role",
    )
    validate_global_attestation_key_role_separation(
        {
            name: value["keySpkiSha256"]
            for name, value in roles.items()
        }
    )
    return envelope


def validate_state_payload(
    payload: Any,
    *,
    assurance: dict[str, Any],
    assurance_sha256: str,
    store_identity_sha256: str,
) -> dict[str, Any]:
    state = exact(
        payload,
        {
            "apiVersion",
            "assuranceSha256",
            "authorityEpoch",
            "authorityGeneration",
            "commitOperationIdBase64url",
            "committedAtUnix",
            "highWaterCommitmentSha256",
            "highWaterReceiptSha256",
            "highWaterSequence",
            "priorVerifierStateSha256",
            "stateStoreGeneration",
            "stateStoreHeadSha256",
            "stateStoreIdentitySha256",
        },
        "verifier-state payload",
    )
    sequence = require_uint(state["highWaterSequence"], "high-water sequence")
    require(
        state["apiVersion"] == STATE_VERSION
        and state["assuranceSha256"] == assurance_sha256
        and state["authorityEpoch"] == assurance["authorityEpoch"]
        and state["authorityGeneration"] == assurance["authorityGeneration"]
        and state["stateStoreIdentitySha256"] == store_identity_sha256,
        "verifier state crossed its assurance or store",
    )
    require_uint(state["committedAtUnix"], "state commit time", positive=True)
    require_uint(state["stateStoreGeneration"], "state-store generation", positive=True)
    require_sha256(state["stateStoreHeadSha256"], "state-store head")
    if sequence == 0:
        require(
            state["commitOperationIdBase64url"] is None
            and state["highWaterReceiptSha256"] is None
            and state["priorVerifierStateSha256"] is None
            and state["highWaterCommitmentSha256"] == genesis_commitment(assurance_sha256),
            "genesis verifier state is malformed",
        )
    else:
        b64url_decode(state["commitOperationIdBase64url"], "state commit operation", exact_bytes=32)
        for field in (
            "highWaterCommitmentSha256",
            "highWaterReceiptSha256",
            "priorVerifierStateSha256",
        ):
            require_sha256(state[field], f"state {field}")
    return state


class StateStoreAdapter(Protocol):
    production_capable: bool
    store_class: str
    rollback_mechanism: str
    store_identity_sha256: str
    administrative_domain_sha256: str
    endpoint_identity_sha256: str
    credential_identity_sha256: str
    assurance_evidence_sha256: str | None
    configuration_sha256: str
    minimum_generation: int
    minimum_commit_index: int
    attestation_public_key: Ed25519PublicKey
    attestation_key_id: str

    def install_genesis(self, signed_state: dict[str, Any]) -> None:
        ...

    def read(self) -> dict[str, Any]:
        ...

    def issue_challenge(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        issue_request_sha256: str,
        producer_invocation_base_sha256: str,
        challenge_base64url: str,
        challenge_sha256: str,
        expected_state_sha256: str,
        issued_at_unix: int,
        expires_at_unix: int,
    ) -> dict[str, Any]:
        ...

    def recover_challenge(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        issue_request_sha256: str,
    ) -> dict[str, Any] | None:
        ...

    def prepare(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        request_binding_sha256: str,
        prepare_request_sha256: str,
        expected_state_sha256: str,
        authorization: dict[str, Any],
        challenge_sha256: str,
        producer_invocation_base_sha256: str,
        prepared_operation: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    def mark_consumption_attempted(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        prepared_operation_sha256: str,
        nonce_consume_request_sha256: str,
    ) -> dict[str, Any]:
        ...

    def attach_nonce_status(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        prepared_operation_sha256: str,
        nonce_status_evidence: dict[str, Any],
        nonce_consumption_receipt: dict[str, Any] | None,
    ) -> dict[str, Any]:
        ...

    def abort_prepared(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        prepared_operation_sha256: str,
        nonce_status_evidence: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    def commit_candidate(
        self,
        *,
        operation_id: str,
        commit_request_sha256: str,
        authorization: dict[str, Any],
        expected_state_sha256: str,
        commit_candidate: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    def finalize_commit(
        self,
        *,
        operation_id: str,
        commit_request_sha256: str,
        commit_proof_sha256: str,
        next_state: dict[str, Any],
        commit_receipt: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    def recover(
        self,
        *,
        recovery_key_sha256: str,
        request_binding_sha256: str | None = None,
        operation_id: str | None = None,
        prepare_request_sha256: str | None = None,
        commit_request_sha256: str | None = None,
    ) -> dict[str, Any]:
        ...


class NonProductionSqliteStateStore:
    """Durable test reference with no production rollback assurance."""

    production_capable = False
    store_class = "nonProductionCallerFile"
    rollback_mechanism = "none"

    def __init__(
        self,
        path: Path,
        *,
        store_identity_sha256: str,
        administrative_domain_sha256: str,
    ) -> None:
        self.path = path
        self.store_identity_sha256 = require_sha256(store_identity_sha256, "store identity")
        self.administrative_domain_sha256 = require_sha256(
            administrative_domain_sha256,
            "store administrative domain",
        )
        self.endpoint_identity_sha256 = sha256_bytes(
            b"non-production-verifier-state-store-endpoint"
        )
        self.credential_identity_sha256 = sha256_bytes(
            b"non-production-verifier-state-store-credential"
        )
        self.assurance_evidence_sha256 = None
        self.configuration_sha256 = sha256_bytes(
            b"non-production-verifier-state-store-configuration"
        )
        self.minimum_generation = 1
        self.minimum_commit_index = 1
        self._attestation_signer = NonProductionEd25519Signer(
            Ed25519PrivateKey.generate()
        )
        self.attestation_public_key = (
            self._attestation_signer.public_key
        )
        self.attestation_key_id = self._attestation_signer.key_id
        self.raise_unknown_after_commit_once = False
        self.raise_unknown_after_finalize_once = False
        self._lock = threading.Lock()
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS verifier_head_v1 (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    signed_state BLOB NOT NULL,
                    signed_state_sha256 TEXT NOT NULL,
                    pending_operation_id TEXT
                );
                CREATE TABLE IF NOT EXISTS verifier_operations_v1 (
                    operation_id TEXT PRIMARY KEY,
                    recovery_key_sha256 TEXT NOT NULL UNIQUE,
                    request_binding_sha256 TEXT NOT NULL,
                    prepare_request_sha256 TEXT NOT NULL,
                    authorization_sha256 TEXT NOT NULL,
                    authorization BLOB NOT NULL,
                    challenge_sha256 TEXT NOT NULL UNIQUE,
                    prepared_operation_sha256 TEXT NOT NULL UNIQUE,
                    prepared_operation BLOB NOT NULL,
                    nonce_consume_request_sha256 TEXT NOT NULL UNIQUE,
                    nonce_status_evidence BLOB,
                    nonce_consumption_receipt BLOB,
                    commit_request_sha256 TEXT,
                    commit_candidate BLOB,
                    commit_proof BLOB,
                    commit_receipt BLOB,
                    next_state BLOB,
                    status TEXT NOT NULL CHECK (
                        status IN (
                            'prepared','consumptionPending',
                            'nonceConsumed','casCommitted',
                            'committed','aborted'
                        )
                    )
                );
                CREATE TABLE IF NOT EXISTS verifier_challenges_v1 (
                    challenge_sha256 TEXT PRIMARY KEY,
                    challenge_base64url TEXT NOT NULL UNIQUE,
                    expected_state_sha256 TEXT NOT NULL,
                    issued_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    operation_id TEXT UNIQUE,
                    status TEXT NOT NULL CHECK (
                        status IN ('issued','bound')
                    )
                );
                CREATE TABLE IF NOT EXISTS verifier_challenges_v2 (
                    operation_id TEXT PRIMARY KEY,
                    recovery_key_sha256 TEXT NOT NULL UNIQUE,
                    issue_request_sha256 TEXT NOT NULL UNIQUE,
                    producer_invocation_base_sha256 TEXT NOT NULL,
                    challenge_sha256 TEXT NOT NULL UNIQUE,
                    challenge_base64url TEXT NOT NULL UNIQUE,
                    expected_state_sha256 TEXT NOT NULL,
                    issued_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('issued','bound','expired')
                    )
                );
                """
            )
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=5.0)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @staticmethod
    def _decode(raw: bytes, label: str) -> dict[str, Any]:
        return exact(
            parse_canonical_json(raw, label=label),
            {
                "apiVersion",
                "payload",
                "payloadSha256",
                "signatureAlgorithm",
                "signatureBase64url",
                "signingKeyId",
                "signingKeySpkiSha256",
            },
            label,
        )

    def install_genesis(self, signed_state: dict[str, Any]) -> None:
        encoded = canonical_json(signed_state)
        digest = sha256_bytes(encoded)
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT signed_state, signed_state_sha256 FROM verifier_head_v1 WHERE singleton = 1"
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO verifier_head_v1(singleton,signed_state,signed_state_sha256) VALUES(1,?,?)",
                        (encoded, digest),
                    )
                else:
                    require(bytes(row[0]) == encoded and row[1] == digest, "SQLite reference genesis differs")
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

    def read(self) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT signed_state,pending_operation_id FROM verifier_head_v1 WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
        require(
            row is not None,
            "verifier-state store has no current head",
        )
        return self._decode(bytes(row[0]), "stored signed verifier state")

    def issue_challenge(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        issue_request_sha256: str,
        producer_invocation_base_sha256: str,
        challenge_base64url: str,
        challenge_sha256: str,
        expected_state_sha256: str,
        issued_at_unix: int,
        expires_at_unix: int,
    ) -> dict[str, Any]:
        challenge = b64url_decode(
            challenge_base64url,
            "issued verifier challenge",
            exact_bytes=32,
        )
        require(
            b64url_decode(
                operation_id,
                "issued challenge operation ID",
                exact_bytes=32,
            )
            and require_sha256(
                recovery_key_sha256,
                "issued challenge recovery key",
            )
            and require_sha256(
                issue_request_sha256,
                "issued challenge request",
            )
            and require_sha256(
                producer_invocation_base_sha256,
                "issued challenge producer invocation base",
            )
            and
            sha256_bytes(challenge)
            == require_sha256(
                challenge_sha256,
                "issued verifier challenge digest",
            )
            and require_sha256(
                expected_state_sha256,
                "issued challenge state",
            )
            and require_uint(
                issued_at_unix,
                "issued challenge time",
                positive=True,
            )
            < require_uint(
                expires_at_unix,
                "issued challenge expiry",
                positive=True,
            ),
            "issued verifier challenge is malformed",
        )
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    """
                    SELECT recovery_key_sha256,issue_request_sha256,
                           producer_invocation_base_sha256,
                           challenge_sha256,challenge_base64url,
                           expected_state_sha256,issued_at_unix,
                           expires_at_unix,status
                    FROM verifier_challenges_v2
                    WHERE operation_id=? OR recovery_key_sha256=?
                    """,
                    (operation_id, recovery_key_sha256),
                ).fetchone()
                if existing is not None:
                    require(
                        existing[0] == recovery_key_sha256
                        and existing[1] == issue_request_sha256
                        and existing[2]
                        == producer_invocation_base_sha256
                        and existing[3] == challenge_sha256
                        and existing[4] == challenge_base64url
                        and existing[5] == expected_state_sha256
                        and existing[6] == issued_at_unix
                        and existing[7] == expires_at_unix,
                        "challenge operation or recovery key was reused with different context",
                    )
                    connection.execute("COMMIT")
                    return {
                        "challengeBase64url": existing[4],
                        "challengeExpiresAtUnix": existing[7],
                        "challengeIssuedAtUnix": existing[6],
                        "challengeSha256": existing[3],
                        "expectedVerifierStateSha256": existing[5],
                        "issueRequestSha256": existing[1],
                        "operationIdBase64url": operation_id,
                        "producerInvocationBaseSha256": existing[2],
                        "recoveryKeySha256": existing[0],
                        "replacementForbidden": True,
                        "status": existing[8],
                    }
                head = connection.execute(
                    "SELECT signed_state_sha256,pending_operation_id "
                    "FROM verifier_head_v1 WHERE singleton=1"
                ).fetchone()
                require(
                    head is not None
                    and head[0] == expected_state_sha256
                    and head[1] is None,
                    "challenge predecessor is no longer current",
                )
                connection.execute(
                    """
                    INSERT INTO verifier_challenges_v2(
                        operation_id,recovery_key_sha256,
                        issue_request_sha256,
                        producer_invocation_base_sha256,
                        challenge_sha256,challenge_base64url,
                        expected_state_sha256,issued_at_unix,
                        expires_at_unix,status
                    ) VALUES(?,?,?,?,?,?,?,?,?,'issued')
                    """,
                    (
                        operation_id,
                        recovery_key_sha256,
                        issue_request_sha256,
                        producer_invocation_base_sha256,
                        challenge_sha256,
                        challenge_base64url,
                        expected_state_sha256,
                        issued_at_unix,
                        expires_at_unix,
                    ),
                )
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise ConflictError(
                    "verifier challenge was already issued"
                ) from exc
            except Exception:
                connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        return {
            "challengeBase64url": challenge_base64url,
            "challengeExpiresAtUnix": expires_at_unix,
            "challengeIssuedAtUnix": issued_at_unix,
            "challengeSha256": challenge_sha256,
            "expectedVerifierStateSha256": expected_state_sha256,
            "issueRequestSha256": issue_request_sha256,
            "operationIdBase64url": operation_id,
            "producerInvocationBaseSha256":
            producer_invocation_base_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "replacementForbidden": True,
            "status": "issued",
        }

    def recover_challenge(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        issue_request_sha256: str,
    ) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT recovery_key_sha256,issue_request_sha256,
                       producer_invocation_base_sha256,
                       challenge_sha256,challenge_base64url,
                       expected_state_sha256,issued_at_unix,
                       expires_at_unix,status
                FROM verifier_challenges_v2
                WHERE operation_id=? OR recovery_key_sha256=?
                """,
                (operation_id, recovery_key_sha256),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        require(
            row[0] == recovery_key_sha256
            and row[1] == issue_request_sha256,
            "challenge recovery identity was reused with a different request",
        )
        return {
            "challengeBase64url": row[4],
            "challengeExpiresAtUnix": row[7],
            "challengeIssuedAtUnix": row[6],
            "challengeSha256": row[3],
            "expectedVerifierStateSha256": row[5],
            "issueRequestSha256": row[1],
            "operationIdBase64url": operation_id,
            "producerInvocationBaseSha256": row[2],
            "recoveryKeySha256": row[0],
            "replacementForbidden": True,
            "status": row[8],
        }

    def prepare(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        request_binding_sha256: str,
        prepare_request_sha256: str,
        expected_state_sha256: str,
        authorization: dict[str, Any],
        challenge_sha256: str,
        producer_invocation_base_sha256: str,
        prepared_operation: dict[str, Any],
    ) -> dict[str, Any]:
        authorization_raw = canonical_json(authorization)
        authorization_sha256 = sha256_bytes(authorization_raw)
        prepared_raw = canonical_json(prepared_operation)
        prepared_operation_sha256 = sha256_bytes(prepared_raw)
        nonce_consume_request_sha256 = require_sha256(
            prepared_operation["nonceConsumeRequestSha256"],
            "prepared nonce consume request",
        )
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    """
                    SELECT operation_id,recovery_key_sha256,
                           request_binding_sha256,
                           prepare_request_sha256,authorization,
                           challenge_sha256,prepared_operation,status
                    FROM verifier_operations_v1
                    WHERE operation_id=? OR recovery_key_sha256=?
                    """,
                    (operation_id, recovery_key_sha256),
                ).fetchone()
                if existing is not None:
                    require(
                        existing[0] == operation_id
                        and existing[1] == recovery_key_sha256
                        and existing[2] == request_binding_sha256
                        and existing[3] == prepare_request_sha256
                        and bytes(existing[4]) == authorization_raw
                        and existing[5] == challenge_sha256
                        and bytes(existing[6]) == prepared_raw,
                        "operation or recovery key was reused with different prepared context",
                    )
                    connection.execute("COMMIT")
                    return parse_canonical_json(
                        bytes(existing[6]),
                        label="retained prepared operation",
                    )
                head = connection.execute(
                    "SELECT signed_state_sha256,pending_operation_id FROM verifier_head_v1 WHERE singleton=1"
                ).fetchone()
                if (
                    head is None
                    or head[0] != expected_state_sha256
                    or head[1] is not None
                ):
                    raise ConflictError(
                        "authorization predecessor is no longer current"
                    )
                challenge = connection.execute(
                    """
                    SELECT expected_state_sha256,issued_at_unix,
                           expires_at_unix,operation_id,status,
                           producer_invocation_base_sha256
                    FROM verifier_challenges_v2
                    WHERE challenge_sha256=? AND operation_id=?
                    """,
                    (challenge_sha256, operation_id),
                ).fetchone()
                authorization_payload = authorization["payload"]
                if not (
                    challenge is not None
                    and challenge[0] == expected_state_sha256
                    and challenge[4] == "issued"
                    and challenge[3] == operation_id
                    and challenge[5]
                    == producer_invocation_base_sha256
                    and challenge[1]
                    <= authorization_payload["issuedAtUnix"]
                    < authorization_payload["expiresAtUnix"]
                    <= challenge[2]
                ):
                    raise ConflictError(
                        "authorization challenge is absent, stale, reused, "
                        "or bound to another head"
                    )
                challenge_update = connection.execute(
                    """
                    UPDATE verifier_challenges_v2
                    SET status='bound'
                    WHERE challenge_sha256=? AND status='issued'
                      AND operation_id=?
                    """,
                    (challenge_sha256, operation_id),
                )
                head_update = connection.execute(
                    """
                    UPDATE verifier_head_v1
                    SET pending_operation_id=?
                    WHERE singleton=1
                      AND signed_state_sha256=?
                      AND pending_operation_id IS NULL
                    """,
                    (operation_id, expected_state_sha256),
                )
                connection.execute(
                    """
                    INSERT INTO verifier_operations_v1(
                        operation_id,recovery_key_sha256,
                        request_binding_sha256,prepare_request_sha256,
                        authorization_sha256,authorization,
                        challenge_sha256,prepared_operation_sha256,
                        prepared_operation,nonce_consume_request_sha256,
                        status
                    ) VALUES(?,?,?,?,?,?,?,?,?,?, 'prepared')
                    """,
                    (
                        operation_id,
                        recovery_key_sha256,
                        request_binding_sha256,
                        prepare_request_sha256,
                        authorization_sha256,
                        authorization_raw,
                        challenge_sha256,
                        prepared_operation_sha256,
                        prepared_raw,
                        nonce_consume_request_sha256,
                    ),
                )
                if (
                    challenge_update.rowcount != 1
                    or head_update.rowcount != 1
                ):
                    raise ConflictError(
                        "verifier challenge or current head was concurrently prepared"
                    )
                connection.execute("COMMIT")
                return prepared_operation
            except Exception:
                connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

    def mark_consumption_attempted(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        prepared_operation_sha256: str,
        nonce_consume_request_sha256: str,
    ) -> dict[str, Any]:
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT recovery_key_sha256,
                           prepared_operation_sha256,
                           nonce_consume_request_sha256,status
                    FROM verifier_operations_v1
                    WHERE operation_id=?
                    """,
                    (operation_id,),
                ).fetchone()
                require(
                    row is not None
                    and row[0] == recovery_key_sha256
                    and row[1] == prepared_operation_sha256
                    and row[2] == nonce_consume_request_sha256,
                    "consumption-attempt marker crossed its prepared operation",
                )
                if row[3] == "prepared":
                    updated = connection.execute(
                        """
                        UPDATE verifier_operations_v1
                        SET status='consumptionPending'
                        WHERE operation_id=? AND status='prepared'
                        """,
                        (operation_id,),
                    )
                    require(
                        updated.rowcount == 1,
                        "prepared operation was not marked exactly once",
                    )
                    retained_status = "consumptionPending"
                else:
                    require(
                        row[3]
                        in {
                            "consumptionPending",
                            "nonceConsumed",
                            "casCommitted",
                            "committed",
                        },
                        "consumption attempt cannot follow abort",
                    )
                    retained_status = row[3]
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        return {
            "nonceConsumeRequestSha256":
            nonce_consume_request_sha256,
            "operationIdBase64url": operation_id,
            "preparedOperationSha256":
            prepared_operation_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "status": retained_status,
        }

    def attach_nonce_status(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        prepared_operation_sha256: str,
        nonce_status_evidence: dict[str, Any],
        nonce_consumption_receipt: dict[str, Any] | None,
    ) -> dict[str, Any]:
        evidence_raw = canonical_json(nonce_status_evidence)
        receipt_raw = (
            None
            if nonce_consumption_receipt is None
            else canonical_json(nonce_consumption_receipt)
        )
        evidence_status = nonce_status_evidence["payload"]["status"]
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT recovery_key_sha256,
                           prepared_operation_sha256,
                           nonce_status_evidence,
                           nonce_consumption_receipt,status
                    FROM verifier_operations_v1
                    WHERE operation_id=?
                    """,
                    (operation_id,),
                ).fetchone()
                require(
                    row is not None
                    and row[0] == recovery_key_sha256
                    and row[1] == prepared_operation_sha256,
                    "nonce status crossed its prepared operation",
                )
                if evidence_status == "consumed":
                    require(
                        receipt_raw is not None
                        and row[4]
                        in {
                            "consumptionPending",
                            "nonceConsumed",
                            "casCommitted",
                            "committed",
                        },
                        "consumed status was not authorized by a persisted attempt",
                    )
                    if row[2] is not None:
                        require(
                            bytes(row[2]) == evidence_raw
                            and bytes(row[3]) == receipt_raw,
                            "nonce status recovery substituted retained evidence",
                        )
                    else:
                        connection.execute(
                            """
                            UPDATE verifier_operations_v1
                            SET nonce_status_evidence=?,
                                nonce_consumption_receipt=?,
                                status='nonceConsumed'
                            WHERE operation_id=?
                              AND status='consumptionPending'
                            """,
                            (
                                evidence_raw,
                                receipt_raw,
                                operation_id,
                            ),
                        )
                else:
                    require(
                        evidence_status == "notObserved"
                        and receipt_raw is None
                        and row[4] == "consumptionPending",
                        "non-consumed recovery cannot release or advance the saga",
                    )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        return {
            "nonceConsumptionReceipt":
            nonce_consumption_receipt,
            "nonceStatusEvidence": nonce_status_evidence,
            "status":
            (
                "nonceConsumed"
                if evidence_status == "consumed"
                else "consumptionPending"
            ),
        }

    def abort_prepared(
        self,
        *,
        operation_id: str,
        recovery_key_sha256: str,
        prepared_operation_sha256: str,
        nonce_status_evidence: dict[str, Any],
    ) -> dict[str, Any]:
        evidence_raw = canonical_json(nonce_status_evidence)
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT recovery_key_sha256,
                           prepared_operation_sha256,
                           nonce_status_evidence,status
                    FROM verifier_operations_v1
                    WHERE operation_id=?
                    """,
                    (operation_id,),
                ).fetchone()
                require(
                    row is not None
                    and row[0] == recovery_key_sha256
                    and row[1] == prepared_operation_sha256
                    and nonce_status_evidence["payload"]["status"]
                    == "neverConsumed"
                    and nonce_status_evidence["payload"][
                        "neverConsumable"
                    ]
                    is True,
                    "abort evidence crossed its exact prepared operation",
                )
                if row[3] == "aborted":
                    require(
                        bytes(row[2]) == evidence_raw,
                        "abort replay substituted nonce-authority evidence",
                    )
                else:
                    require(
                        row[3] in {"prepared", "consumptionPending"},
                        "abort is forbidden after nonce consumption was observed",
                    )
                    operation_update = connection.execute(
                        """
                        UPDATE verifier_operations_v1
                        SET nonce_status_evidence=?,status='aborted'
                        WHERE operation_id=?
                          AND status IN ('prepared','consumptionPending')
                        """,
                        (evidence_raw, operation_id),
                    )
                    head_update = connection.execute(
                        """
                        UPDATE verifier_head_v1
                        SET pending_operation_id=NULL
                        WHERE singleton=1 AND pending_operation_id=?
                        """,
                        (operation_id,),
                    )
                    require(
                        operation_update.rowcount == 1
                        and head_update.rowcount == 1,
                        "abort did not release exactly one prepared head",
                    )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        return {
            "nonceStatusEvidence": nonce_status_evidence,
            "operationIdBase64url": operation_id,
            "preparedOperationSha256":
            prepared_operation_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "status": "aborted",
        }

    def commit_candidate(
        self,
        *,
        operation_id: str,
        commit_request_sha256: str,
        authorization: dict[str, Any],
        expected_state_sha256: str,
        commit_candidate: dict[str, Any],
    ) -> dict[str, Any]:
        authorization_raw = canonical_json(authorization)
        authorization_sha256 = sha256_bytes(authorization_raw)
        candidate_raw = canonical_json(commit_candidate)
        candidate_sha256 = sha256_bytes(candidate_raw)
        authorization_payload = authorization["payload"]
        require(
            commit_candidate["authorizationSha256"]
            == authorization_sha256
            and commit_candidate["commitRequestSha256"]
            == commit_request_sha256
            and commit_candidate["expectedVerifierStateSha256"]
            == expected_state_sha256
            and commit_candidate["operationIdBase64url"]
            == operation_id,
            "SQLite reference commit candidate crossed its retained inputs",
        )
        unsigned_proof = {
            "apiVersion": STORE_COMMIT_PROOF_VERSION,
            "authorizationSha256": authorization_sha256,
            "casCommitted": True,
            "commitCandidateSha256": candidate_sha256,
            "commitClockMonotonic": True,
            "commitRequestSha256": commit_request_sha256,
            "committedAtUnix": 0,
            "operationIdBase64url": operation_id,
            "previousCommittedAtUnix":
            commit_candidate["previousCommittedAtUnix"],
            "previousVerifierStateSha256": expected_state_sha256,
            "productionEligible": False,
            "stateStoreAdministrativeDomainSha256":
            self.administrative_domain_sha256,
            "stateStoreAssuranceEvidenceSha256": None,
            "stateStoreAttestationKeySpkiSha256":
            self.attestation_key_id,
            "stateStoreCommitIndex":
            commit_candidate["proposedStateStoreGeneration"],
            "stateStoreConfigurationSha256":
            self.configuration_sha256,
            "stateStoreGeneration":
            commit_candidate["proposedStateStoreGeneration"],
            "stateStoreIdentitySha256": self.store_identity_sha256,
        }
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                operation = connection.execute(
                    """
                    SELECT authorization_sha256,commit_request_sha256,
                           commit_candidate,commit_proof,status
                    FROM verifier_operations_v1 WHERE operation_id=?
                    """,
                    (operation_id,),
                ).fetchone()
                require(operation is not None, "commit operation was not authorized")
                require(operation[0] == authorization_sha256, "commit crossed its authorization")
                if operation[4] in {"casCommitted", "committed"}:
                    require(
                        operation[1] == commit_request_sha256
                        and bytes(operation[2]) == candidate_raw,
                        "committed operation ID was reused with different input",
                    )
                    connection.execute("COMMIT")
                    return self._decode(
                        bytes(operation[3]),
                        label="retained store commit proof",
                    )
                head = connection.execute(
                    "SELECT signed_state_sha256,pending_operation_id FROM verifier_head_v1 WHERE singleton=1"
                ).fetchone()
                require(
                    head is not None
                    and head[0] == expected_state_sha256
                    and head[1] == operation_id,
                    "linearizable CAS predecessor is not reserved by this operation",
                )
                committed_at = max(
                    int(time.time()),
                    require_uint(
                        commit_candidate["previousCommittedAtUnix"],
                        "prior durable commit time",
                        positive=True,
                    ),
                )
                proof = sign_envelope(
                    self._attestation_signer,
                    api_version=SIGNED_STORE_COMMIT_PROOF_VERSION,
                    domain=STORE_COMMIT_PROOF_DOMAIN,
                    payload={
                        **unsigned_proof,
                        "committedAtUnix": committed_at,
                    },
                )
                proof_raw = canonical_json(proof)
                operation_update = connection.execute(
                    """
                    UPDATE verifier_operations_v1
                    SET commit_request_sha256=?,commit_candidate=?,
                        commit_proof=?,status='casCommitted'
                    WHERE operation_id=? AND status='nonceConsumed'
                    """,
                    (
                        commit_request_sha256,
                        candidate_raw,
                        proof_raw,
                        operation_id,
                    ),
                )
                require(
                    operation_update.rowcount == 1,
                    "SQLite reference CAS did not update exactly one consumed saga",
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        if self.raise_unknown_after_commit_once:
            self.raise_unknown_after_commit_once = False
            raise UnknownOutcomeError("simulated crash after durable SQLite CAS")
        return proof

    def finalize_commit(
        self,
        *,
        operation_id: str,
        commit_request_sha256: str,
        commit_proof_sha256: str,
        next_state: dict[str, Any],
        commit_receipt: dict[str, Any],
    ) -> dict[str, Any]:
        next_state_raw = canonical_json(next_state)
        next_state_sha256 = sha256_bytes(next_state_raw)
        receipt_raw = canonical_json(commit_receipt)
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                operation = connection.execute(
                    """
                    SELECT commit_request_sha256,commit_proof,
                           commit_receipt,next_state,status
                    FROM verifier_operations_v1 WHERE operation_id=?
                    """,
                    (operation_id,),
                ).fetchone()
                require(
                    operation is not None
                    and operation[0] == commit_request_sha256
                    and sha256_bytes(bytes(operation[1]))
                    == commit_proof_sha256,
                    "commit finalization crossed its retained CAS proof",
                )
                if operation[4] == "committed":
                    require(
                        bytes(operation[2]) == receipt_raw
                        and bytes(operation[3]) == next_state_raw,
                        "finalized operation differs from retained artifacts",
                    )
                    connection.execute("COMMIT")
                    return self._decode(
                        bytes(operation[2]),
                        "retained commit receipt",
                    )
                require(
                    operation[4] == "casCommitted",
                    "commit has no durable CAS proof",
                )
                head_update = connection.execute(
                    """
                    UPDATE verifier_head_v1
                    SET signed_state=?,signed_state_sha256=?,
                        pending_operation_id=NULL
                    WHERE singleton=1 AND pending_operation_id=?
                    """,
                    (next_state_raw, next_state_sha256, operation_id),
                )
                operation_update = connection.execute(
                    """
                    UPDATE verifier_operations_v1
                    SET commit_receipt=?,next_state=?,status='committed'
                    WHERE operation_id=? AND status='casCommitted'
                    """,
                    (receipt_raw, next_state_raw, operation_id),
                )
                require(
                    head_update.rowcount == 1
                    and operation_update.rowcount == 1,
                    "SQLite reference finalization did not update exactly one head and operation",
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        if self.raise_unknown_after_finalize_once:
            self.raise_unknown_after_finalize_once = False
            raise UnknownOutcomeError(
                "simulated crash after durable SQLite finalization"
            )
        return commit_receipt

    def recover(
        self,
        *,
        recovery_key_sha256: str,
        request_binding_sha256: str | None = None,
        operation_id: str | None = None,
        prepare_request_sha256: str | None = None,
        commit_request_sha256: str | None = None,
    ) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT operation_id,request_binding_sha256,
                       prepare_request_sha256,prepared_operation,
                       nonce_status_evidence,
                       nonce_consumption_receipt,
                       commit_request_sha256,commit_proof,
                       commit_receipt,status
                FROM verifier_operations_v1
                WHERE recovery_key_sha256=?
                """,
                (recovery_key_sha256,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return {
                "status": "notFound",
                "preparedOperation": None,
                "nonceStatusEvidence": None,
                "nonceConsumptionReceipt": None,
                "commitProof": None,
                "commitReceipt": None,
            }
        require(
            (
                request_binding_sha256 is None
                or row[1] == request_binding_sha256
            )
            and (
                operation_id is None
                or row[0] == operation_id
            )
            and (
                prepare_request_sha256 is None
                or row[2] == prepare_request_sha256
            ),
            "recovery key was bound to different prepared input",
        )
        prepared_operation = parse_canonical_json(
            bytes(row[3]),
            label="recovered prepared operation",
        )
        if commit_request_sha256 is not None:
            require(
                row[6] == commit_request_sha256,
                "operation ID was committed for different input",
            )
        nonce_status_evidence = (
            None
            if row[4] is None
            else parse_canonical_json(
                bytes(row[4]),
                label="recovered nonce status evidence",
            )
        )
        nonce_consumption_receipt = (
            None
            if row[5] is None
            else parse_canonical_json(
                bytes(row[5]),
                label="recovered nonce consumption receipt",
            )
        )
        commit_proof = (
            None
            if row[7] is None
            else parse_canonical_json(
                bytes(row[7]),
                label="recovered store commit proof",
            )
        )
        commit_receipt = (
            None
            if row[8] is None
            else self._decode(
                bytes(row[8]),
                "recovered commit receipt",
            )
        )
        return {
            "status": row[9],
            "preparedOperation": prepared_operation,
            "nonceStatusEvidence": nonce_status_evidence,
            "nonceConsumptionReceipt":
            nonce_consumption_receipt,
            "commitProof": commit_proof,
            "commitReceipt": commit_receipt,
        }


class ExternalLinearizableStateStore:
    """Closed adapter boundary for a separately attested production backend.

    Every mutating operation is idempotent by ``operation_id``. The adapter must
    return conflicts as canonical HTTP-200 result documents; a non-200 or
    transport failure is deliberately an unknown outcome that must be recovered
    before any successor operation. ``commitCasCandidate`` must return a proof
    only after the candidate and pending-head marker are durably linearized.
    ``finalizeCommitArtifacts`` attaches the subsequently signed state and
    receipt to that exact retained candidate. This process does not provision,
    emulate, or attest such an external store.
    """

    production_capable = False

    def __init__(
        self,
        *,
        client: CanonicalHttpsClient,
        store_class: str,
        rollback_mechanism: str,
        store_identity_sha256: str,
        administrative_domain_sha256: str,
        endpoint_identity_sha256: str,
        credential_identity_sha256: str,
        assurance_evidence_sha256: str,
        configuration_sha256: str,
        minimum_generation: int,
        minimum_commit_index: int,
        attestation_public_key_spki_der_base64url: str,
    ) -> None:
        self._client = client
        self.store_class = store_class
        self.rollback_mechanism = rollback_mechanism
        self.store_identity_sha256 = require_sha256(store_identity_sha256, "store identity")
        self.administrative_domain_sha256 = require_sha256(
            administrative_domain_sha256,
            "store administrative domain",
        )
        self.endpoint_identity_sha256 = require_sha256(
            endpoint_identity_sha256,
            "store endpoint identity",
        )
        self.credential_identity_sha256 = require_sha256(
            credential_identity_sha256,
            "store credential identity",
        )
        self.assurance_evidence_sha256 = require_sha256(
            assurance_evidence_sha256,
            "store assurance evidence",
        )
        self.configuration_sha256 = require_sha256(
            configuration_sha256,
            "store configuration",
        )
        self.minimum_generation = require_uint(
            minimum_generation,
            "store minimum generation",
            positive=True,
        )
        self.minimum_commit_index = require_uint(
            minimum_commit_index,
            "store minimum commit index",
            positive=True,
        )
        (
            self.attestation_public_key,
            self.attestation_key_id,
        ) = load_ed25519_public_key(
            attestation_public_key_spki_der_base64url,
            label="store attestation public key",
        )

    def _operation(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        mutation = operation in {
            "issueChallenge",
            "prepareOperation",
            "markConsumptionAttempted",
            "attachNonceStatus",
            "abortPreparedOperation",
            "commitCasCandidate",
            "finalizeCommitArtifacts",
            "recoverOperation",
        }
        request = {
            "apiVersion": EXTERNAL_STORE_REQUEST_VERSION,
            "operation": operation,
            "payload": payload,
            "storeIdentitySha256": self.store_identity_sha256,
        }
        response = self._client.post(
            "/v1/state",
            request,
            outcome_may_be_unknown=mutation,
            deadline=deadline,
        )
        try:
            response = exact(
                response,
                {
                    "apiVersion",
                    "operation",
                    "requestSha256",
                    "result",
                },
                "external store response",
            )
            require(
                response["apiVersion"]
                == EXTERNAL_STORE_RESPONSE_VERSION
                and response["operation"] == operation
                and response["requestSha256"] == sha256_json(request),
                "external store response crossed its request",
            )
            result = exact(
                response["result"],
                {"status", "value"},
                "external store operation result",
            )
            require(
                type(result["status"]) is str,
                "external store result status is malformed",
            )
            if result["status"] in {"conflict", "unknown", "notFound"}:
                require(
                    result["value"] is None,
                    "external store empty outcome must carry null value",
                )
            return result
        except ContractError as exc:
            if mutation:
                raise UnknownOutcomeError(
                    "mutating external store response is invalid"
                ) from exc
            raise

    def install_genesis(self, signed_state: dict[str, Any]) -> None:
        raise ContractError(
            "production genesis must be provisioned by the external rollback-resistant store"
        )

    def read(self, *, deadline: float | None = None) -> dict[str, Any]:
        result = self._operation("read", {}, deadline=deadline)
        require(
            result["status"] == "current"
            and type(result["value"]) is dict,
            "external store did not return a current head",
        )
        return result["value"]

    def issue_challenge(self, **values: Any) -> dict[str, Any]:
        deadline = values.pop("deadline", None)
        result = self._operation(
            "issueChallenge",
            values,
            deadline=deadline,
        )
        if result["status"] == "conflict":
            raise ConflictError(
                "external store rejected reused or stale challenge"
            )
        if result["status"] != "challengeIssued":
            raise UnknownOutcomeError(
                "external challenge issuance outcome is unknown"
            )
        expected = {
            "challengeBase64url": values["challenge_base64url"],
            "challengeExpiresAtUnix": values["expires_at_unix"],
            "challengeIssuedAtUnix": values["issued_at_unix"],
            "challengeSha256": values["challenge_sha256"],
            "expectedVerifierStateSha256":
            values["expected_state_sha256"],
            "issueRequestSha256": values["issue_request_sha256"],
            "operationIdBase64url": values["operation_id"],
            "producerInvocationBaseSha256":
            values["producer_invocation_base_sha256"],
            "recoveryKeySha256": values["recovery_key_sha256"],
            "replacementForbidden": True,
            "status": "issued",
        }
        if result["value"] != expected:
            raise UnknownOutcomeError(
                "external store returned a substituted challenge binding"
            )
        return result["value"]

    def recover_challenge(self, **values: Any) -> dict[str, Any] | None:
        deadline = values.pop("deadline", None)
        result = self._operation(
            "recoverChallenge",
            values,
            deadline=deadline,
        )
        if result["status"] == "notFound":
            return None
        require(
            result["status"] == "challengeRecovered"
            and type(result["value"]) is dict
            and result["value"]["operationIdBase64url"]
            == values["operation_id"]
            and result["value"]["recoveryKeySha256"]
            == values["recovery_key_sha256"]
            and result["value"]["issueRequestSha256"]
            == values["issue_request_sha256"]
            and result["value"]["replacementForbidden"] is True
            and result["value"]["status"]
            in {"issued", "bound", "expired"},
            "external challenge recovery crossed its exact retained mutation",
        )
        return result["value"]

    def prepare(self, **values: Any) -> dict[str, Any]:
        deadline = values.pop("deadline", None)
        result = self._operation(
            "prepareOperation",
            values,
            deadline=deadline,
        )
        if result["status"] == "conflict":
            raise ConflictError("external store rejected stale or reused prepare")
        if result["status"] == "unknown":
            raise UnknownOutcomeError(
                "external prepare outcome is unknown"
            )
        if result["status"] != "prepared":
            raise UnknownOutcomeError(
                "external prepare outcome is unknown"
            )
        if result["value"] != values["prepared_operation"]:
            raise UnknownOutcomeError(
                "external store returned substituted prepared context"
            )
        return result["value"]

    def mark_consumption_attempted(
        self,
        **values: Any,
    ) -> dict[str, Any]:
        deadline = values.pop("deadline", None)
        result = self._operation(
            "markConsumptionAttempted",
            values,
            deadline=deadline,
        )
        if result["status"] == "conflict":
            raise ConflictError(
                "external store rejected consumption-attempt marker"
            )
        if (
            result["status"]
            not in {
                "consumptionPending",
                "nonceConsumed",
                "casCommitted",
                "committed",
            }
            or type(result["value"]) is not dict
            or result["value"].get("status") != result["status"]
            or result["value"].get("operationIdBase64url")
            != values["operation_id"]
            or result["value"].get("recoveryKeySha256")
            != values["recovery_key_sha256"]
            or result["value"].get("preparedOperationSha256")
            != values["prepared_operation_sha256"]
            or result["value"].get("nonceConsumeRequestSha256")
            != values["nonce_consume_request_sha256"]
        ):
            raise UnknownOutcomeError(
                "external consumption-attempt outcome is unknown"
            )
        return result["value"]

    def attach_nonce_status(self, **values: Any) -> dict[str, Any]:
        deadline = values.pop("deadline", None)
        result = self._operation(
            "attachNonceStatus",
            values,
            deadline=deadline,
        )
        if result["status"] == "conflict":
            raise ConflictError(
                "external store rejected crossed nonce status"
            )
        if (
            result["status"]
            not in {"consumptionPending", "nonceConsumed"}
            or type(result["value"]) is not dict
            or result["value"].get("status") != result["status"]
            or result["value"].get("nonceStatusEvidence")
            != values["nonce_status_evidence"]
            or result["value"].get("nonceConsumptionReceipt")
            != values["nonce_consumption_receipt"]
        ):
            raise UnknownOutcomeError(
                "external nonce-status attachment outcome is unknown"
            )
        return result["value"]

    def abort_prepared(self, **values: Any) -> dict[str, Any]:
        deadline = values.pop("deadline", None)
        result = self._operation(
            "abortPreparedOperation",
            values,
            deadline=deadline,
        )
        if result["status"] == "conflict":
            raise ConflictError(
                "external store rejected abort after possible consumption"
            )
        if (
            result["status"] != "aborted"
            or type(result["value"]) is not dict
            or result["value"].get("operationIdBase64url")
            != values["operation_id"]
            or result["value"].get("recoveryKeySha256")
            != values["recovery_key_sha256"]
            or result["value"].get("preparedOperationSha256")
            != values["prepared_operation_sha256"]
            or result["value"].get("nonceStatusEvidence")
            != values["nonce_status_evidence"]
        ):
            raise UnknownOutcomeError(
                "external abort outcome is unknown"
            )
        return result["value"]

    def commit_candidate(self, **values: Any) -> dict[str, Any]:
        deadline = values.pop("deadline", None)
        result = self._operation(
            "commitCasCandidate",
            values,
            deadline=deadline,
        )
        if result["status"] == "conflict":
            raise ConflictError("external store rejected competing successor")
        if result["status"] == "unknown":
            raise UnknownOutcomeError("external CAS outcome is unknown")
        if result["status"] != "casCommitted":
            raise UnknownOutcomeError("external CAS outcome is unknown")
        try:
            envelope = verify_pinned_envelope(
                result["value"],
                api_version=SIGNED_STORE_COMMIT_PROOF_VERSION,
                domain=STORE_COMMIT_PROOF_DOMAIN,
                public_key=self.attestation_public_key,
                key_id=self.attestation_key_id,
                label="external signed store commit proof",
            )
            proof = exact(
                envelope["payload"],
                {
                    "apiVersion",
                    "authorizationSha256",
                    "casCommitted",
                    "commitCandidateSha256",
                    "commitClockMonotonic",
                    "commitRequestSha256",
                    "committedAtUnix",
                    "operationIdBase64url",
                    "previousCommittedAtUnix",
                    "previousVerifierStateSha256",
                    "productionEligible",
                    "stateStoreAdministrativeDomainSha256",
                    "stateStoreAssuranceEvidenceSha256",
                    "stateStoreAttestationKeySpkiSha256",
                    "stateStoreCommitIndex",
                    "stateStoreConfigurationSha256",
                    "stateStoreGeneration",
                    "stateStoreIdentitySha256",
                },
                "external store commit proof",
            )
        except ContractError as exc:
            raise UnknownOutcomeError(
                "external store commit proof is malformed"
            ) from exc
        if not (
            proof["apiVersion"] == STORE_COMMIT_PROOF_VERSION
            and proof["authorizationSha256"]
            == sha256_json(values["authorization"])
            and proof["casCommitted"] is True
            and proof["commitCandidateSha256"]
            == sha256_json(values["commit_candidate"])
            and proof["commitClockMonotonic"] is True
            and proof["commitRequestSha256"]
            == values["commit_request_sha256"]
            and proof["operationIdBase64url"]
            == values["operation_id"]
            and proof["previousCommittedAtUnix"]
            == values["commit_candidate"]["previousCommittedAtUnix"]
            and proof["previousVerifierStateSha256"]
            == values["expected_state_sha256"]
            and proof["productionEligible"] is True
            and proof["stateStoreAdministrativeDomainSha256"]
            == self.administrative_domain_sha256
            and proof["stateStoreAssuranceEvidenceSha256"]
            == self.assurance_evidence_sha256
            and proof["stateStoreAttestationKeySpkiSha256"]
            == self.attestation_key_id
            and proof["stateStoreConfigurationSha256"]
            == self.configuration_sha256
            and proof["stateStoreGeneration"]
            == values["commit_candidate"][
                "proposedStateStoreGeneration"
            ]
            and proof["stateStoreCommitIndex"]
            == proof["stateStoreGeneration"]
            and proof["stateStoreIdentitySha256"]
            == self.store_identity_sha256
        ):
            raise UnknownOutcomeError(
                "external store commit proof crossed its candidate"
            )
        return envelope

    def finalize_commit(self, **values: Any) -> dict[str, Any]:
        deadline = values.pop("deadline", None)
        result = self._operation(
            "finalizeCommitArtifacts",
            values,
            deadline=deadline,
        )
        if result["status"] == "conflict":
            raise ConflictError(
                "external store rejected crossed commit artifacts"
            )
        if result["status"] == "unknown":
            raise UnknownOutcomeError(
                "external commit finalization outcome is unknown"
            )
        if result["status"] != "committed":
            raise UnknownOutcomeError(
                "external commit finalization outcome is unknown"
            )
        if result["value"] != values["commit_receipt"]:
            raise UnknownOutcomeError(
                "external store returned substituted commit artifacts"
            )
        return result["value"]

    def recover(self, **values: Any) -> dict[str, Any]:
        deadline = values.pop("deadline", None)
        try:
            return self._recover(values, deadline=deadline)
        except UnknownOutcomeError:
            raise
        except Exception as exc:
            raise UnknownOutcomeError(
                "external same-operation recovery output is invalid"
            ) from exc

    def _recover(
        self,
        values: dict[str, Any],
        *,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        result = self._operation(
            "recoverOperation",
            values,
            deadline=deadline,
        )
        require(
            result["status"]
            in {
                "notFound",
                "prepared",
                "consumptionPending",
                "nonceConsumed",
                "casCommitted",
                "committed",
                "aborted",
            },
            "external recovery status is invalid",
        )
        if result["status"] == "notFound":
            require(
                result["value"] is None,
                "external recovery notFound result must be null",
            )
            return {
                "status": "notFound",
                "preparedOperation": None,
                "nonceStatusEvidence": None,
                "nonceConsumptionReceipt": None,
                "commitProof": None,
                "commitReceipt": None,
            }
        recovered = exact(
            result["value"],
            {
                "commitProof",
                "commitReceipt",
                "nonceConsumptionReceipt",
                "nonceStatusEvidence",
                "preparedOperation",
            },
            "external recovered operation",
        )
        require(
            type(recovered["preparedOperation"]) is dict,
            "external recovered prepared operation is malformed",
        )
        if result["status"] == "prepared":
            require(
                recovered["nonceStatusEvidence"] is None
                and recovered["nonceConsumptionReceipt"] is None
                and
                recovered["commitProof"] is None
                and recovered["commitReceipt"] is None,
                "external prepared operation contains later artifacts",
            )
        elif result["status"] == "consumptionPending":
            require(
                (
                    recovered["nonceStatusEvidence"] is None
                    or type(recovered["nonceStatusEvidence"]) is dict
                )
                and recovered["nonceConsumptionReceipt"] is None
                and recovered["commitProof"] is None
                and recovered["commitReceipt"] is None,
                "external pending-consumption recovery is malformed",
            )
        elif result["status"] == "nonceConsumed":
            require(
                type(recovered["nonceStatusEvidence"]) is dict
                and type(recovered["nonceConsumptionReceipt"]) is dict
                and recovered["commitProof"] is None
                and recovered["commitReceipt"] is None,
                "external consumed-nonce recovery is malformed",
            )
        elif result["status"] == "casCommitted":
            require(
                type(recovered["nonceStatusEvidence"]) is dict
                and type(recovered["nonceConsumptionReceipt"]) is dict
                and
                type(recovered["commitProof"]) is dict
                and recovered["commitReceipt"] is None,
                "external CAS recovery is malformed",
            )
        elif result["status"] == "committed":
            require(
                type(recovered["nonceStatusEvidence"]) is dict
                and type(recovered["nonceConsumptionReceipt"]) is dict
                and
                type(recovered["commitProof"]) is dict
                and type(recovered["commitReceipt"]) is dict,
                "external committed recovery is malformed",
            )
        else:
            require(
                type(recovered["nonceStatusEvidence"]) is dict
                and recovered["nonceConsumptionReceipt"] is None
                and recovered["commitProof"] is None
                and recovered["commitReceipt"] is None,
                "external aborted recovery is malformed",
            )
        return {
            "status": result["status"],
            "preparedOperation": recovered["preparedOperation"],
            "nonceStatusEvidence": recovered["nonceStatusEvidence"],
            "nonceConsumptionReceipt":
            recovered["nonceConsumptionReceipt"],
            "commitProof": (
                recovered["commitProof"]
                if result["status"]
                in {"casCommitted", "committed"}
                else None
            ),
            "commitReceipt":
            (
                recovered["commitReceipt"]
                if result["status"] == "committed"
                else None
            ),
        }


class VerifierStateService:
    def __init__(
        self,
        *,
        mode: str,
        assurance: dict[str, Any],
        assurance_sha256: str,
        store: StateStoreAdapter,
        signer: SigningAdapter,
        nonce_authority: NonceAuthorityReceiptVerifier,
        nonce_authority_assurance_evidence:
        dict[str, Any] | None = None,
        nonce_authority_assurance_evidence_public_key:
        Ed25519PublicKey | None = None,
        nonce_authority_assurance_evidence_key_id:
        str | None = None,
        role_separation_evidence: dict[str, Any] | None = None,
        role_separation_evidence_public_key:
        Ed25519PublicKey | None = None,
        role_separation_evidence_key_id: str | None = None,
        role_separation_additional_roles:
        dict[str, dict[str, Any]] | None = None,
        store_assurance_evidence: dict[str, Any] | None = None,
        store_assurance_evidence_public_key:
        Ed25519PublicKey | None = None,
        store_assurance_evidence_key_id: str | None = None,
        store_assurance_issuer_administrative_domain_sha256:
        str | None = None,
        store_assurance_issuer_credential_identity_sha256:
        str | None = None,
        store_assurance_issuer_identity_sha256: str | None = None,
        authorization_lifetime_seconds: int = 15,
        initialize_reference_genesis: bool = True,
    ) -> None:
        require(mode in {"production", "nonProductionReference"}, "service mode is invalid")
        production = mode == "production"
        self.assurance = validate_assurance(
            assurance,
            expected_sha256=assurance_sha256,
            require_production=production,
        )
        self.assurance_sha256 = assurance_sha256
        self.store = store
        self.signer = signer
        self.nonce_authority = nonce_authority
        self.mode = mode
        self.production_capable = False
        self._runtime_clock_lock = threading.Lock()
        self._last_runtime_unix = 0
        self._ingress_deadline = threading.local()
        require(
            type(authorization_lifetime_seconds) is int
            and 1 <= authorization_lifetime_seconds <= MAX_AUTHORIZATION_SECONDS,
            "authorization lifetime must be between 1 and 30 seconds",
        )
        self.authorization_lifetime_seconds = authorization_lifetime_seconds
        rollback = self.assurance["rollbackProtection"]
        require(
            store.store_identity_sha256 != self.assurance["authorityIdentitySha256"]
            and store.administrative_domain_sha256
            != self.assurance["administrativeDomainSha256"]
            and nonce_authority.store_identity_sha256
            == self.assurance["authorityIdentitySha256"]
            and nonce_authority.administrative_domain_sha256
            == self.assurance["administrativeDomainSha256"]
            and nonce_authority.assurance_evidence_sha256
            == self.assurance["assuranceEvidenceSha256"],
            "verifier-state store is not administratively independent",
        )
        if production:
            require(
                isinstance(store, ExternalLinearizableStateStore)
                and isinstance(signer, ExternalEd25519Signer)
                and store.store_class
                == rollback["verifierStateStoreClass"]
                and store.rollback_mechanism == rollback["mechanism"]
                and store.store_class != "nonProductionCallerFile",
                "production service requires external rollback-resistant store and remote signer",
            )
            require(
                nonce_authority_assurance_evidence is not None
                and nonce_authority_assurance_evidence_public_key
                is not None
                and nonce_authority_assurance_evidence_key_id is not None
                and
                role_separation_evidence is not None
                and role_separation_evidence_public_key is not None
                and role_separation_evidence_key_id is not None
                and role_separation_additional_roles is not None
                and store_assurance_evidence is not None
                and store_assurance_evidence_public_key is not None
                and store_assurance_evidence_key_id is not None
                and store_assurance_issuer_administrative_domain_sha256
                is not None
                and store_assurance_issuer_credential_identity_sha256
                is not None
                and store_assurance_issuer_identity_sha256 is not None,
                "production service requires signed role and store assurance evidence",
            )
            evidence_now = max(1, int(time.time()))
            self._nonce_authority_assurance_evidence_document = (
                nonce_authority_assurance_evidence
            )
            self._nonce_authority_assurance_evidence_public_key = (
                nonce_authority_assurance_evidence_public_key
            )
            self._nonce_authority_assurance_evidence_key_id = (
                nonce_authority_assurance_evidence_key_id
            )
            self.nonce_authority_assurance_evidence = (
                validate_nonce_authority_assurance_evidence(
                    nonce_authority_assurance_evidence,
                    evidence_public_key=(
                        nonce_authority_assurance_evidence_public_key
                    ),
                    evidence_key_id=(
                        nonce_authority_assurance_evidence_key_id
                    ),
                    assurance=self.assurance,
                    nonce_authority=nonce_authority,
                    store=store,
                    verifier_state_signing_key_id=signer.key_id,
                    now=evidence_now,
                )
            )
            self._role_separation_evidence_document = (
                role_separation_evidence
            )
            self._role_separation_evidence_public_key = (
                role_separation_evidence_public_key
            )
            self._role_separation_evidence_key_id = (
                role_separation_evidence_key_id
            )
            self._role_separation_additional_roles = (
                role_separation_additional_roles
            )
            self.role_separation_evidence = (
                validate_role_separation_evidence(
                    role_separation_evidence,
                    evidence_public_key=(
                        role_separation_evidence_public_key
                    ),
                    evidence_key_id=role_separation_evidence_key_id,
                    assurance_sha256=assurance_sha256,
                    nonce_authority=nonce_authority,
                    signer=signer,
                    store=store,
                    expected_additional_roles=(
                        role_separation_additional_roles
                    ),
                    now=evidence_now,
                )
            )
            self._store_assurance_evidence_document = (
                store_assurance_evidence
            )
            self._store_assurance_evidence_public_key = (
                store_assurance_evidence_public_key
            )
            self._store_assurance_evidence_key_id = (
                store_assurance_evidence_key_id
            )
            self._store_assurance_issuer_administrative_domain_sha256 = (
                store_assurance_issuer_administrative_domain_sha256
            )
            self._store_assurance_issuer_credential_identity_sha256 = (
                store_assurance_issuer_credential_identity_sha256
            )
            self._store_assurance_issuer_identity_sha256 = (
                store_assurance_issuer_identity_sha256
            )
            self.store_assurance_evidence = (
                validate_store_assurance_evidence(
                    store_assurance_evidence,
                    evidence_public_key=(
                        store_assurance_evidence_public_key
                    ),
                    evidence_key_id=store_assurance_evidence_key_id,
                    expected_issuer_administrative_domain_sha256=(
                        store_assurance_issuer_administrative_domain_sha256
                    ),
                    expected_issuer_credential_identity_sha256=(
                        store_assurance_issuer_credential_identity_sha256
                    ),
                    expected_issuer_identity_sha256=(
                        store_assurance_issuer_identity_sha256
                    ),
                    store=store,
                    now=evidence_now,
                )
            )
            self._validate_global_role_bindings()
            self.production_capable = True
        else:
            require(
                not store.production_capable
                and not signer.production_capable
                and store.store_class == "nonProductionCallerFile",
                "reference mode is closed to the non-production SQLite fixture",
            )
            require(
                nonce_authority_assurance_evidence is None
                and nonce_authority_assurance_evidence_public_key is None
                and nonce_authority_assurance_evidence_key_id is None
                and
                role_separation_evidence is None
                and role_separation_evidence_public_key is None
                and role_separation_evidence_key_id is None
                and role_separation_additional_roles is None
                and store_assurance_evidence is None
                and store_assurance_evidence_public_key is None
                and store_assurance_evidence_key_id is None
                and store_assurance_issuer_administrative_domain_sha256
                is None
                and store_assurance_issuer_credential_identity_sha256
                is None
                and store_assurance_issuer_identity_sha256 is None
                and nonce_authority.assurance_evidence_sha256 is None,
                "reference mode forbids production role evidence",
            )
            self.role_separation_evidence = None
            self.store_assurance_evidence = None
            self.nonce_authority_assurance_evidence = None
        for field in (
            "administrative_domain_sha256",
            "endpoint_identity_sha256",
            "credential_identity_sha256",
        ):
            require(
                len(
                    {
                        getattr(nonce_authority, field),
                        getattr(signer, field),
                        getattr(store, field),
                    }
                )
                == 3,
                f"nonce, signer, and store roles collide on {field}",
            )
        require(
            len(
                {
                    nonce_authority.key_id,
                    signer.key_id,
                    store.attestation_key_id,
                }
            )
            == 3,
            "nonce, signer, and store behavioral keys collide",
        )
        if production:
            require(
                store_assurance_evidence_key_id
                not in {
                    nonce_authority.key_id,
                    signer.key_id,
                    store.attestation_key_id,
                    role_separation_evidence_key_id,
                }
                and store_assurance_issuer_administrative_domain_sha256
                not in {
                    nonce_authority.administrative_domain_sha256,
                    signer.administrative_domain_sha256,
                    store.administrative_domain_sha256,
                }
                and store_assurance_issuer_credential_identity_sha256
                not in {
                    nonce_authority.credential_identity_sha256,
                    signer.credential_identity_sha256,
                    store.credential_identity_sha256,
                },
                "store assurance issuer is not independent from operational roles",
            )
        if initialize_reference_genesis:
            require(not production, "production genesis cannot be initialized locally")
            committed_at = max(1, int(time.time()))
            payload = {
                "apiVersion": STATE_VERSION,
                "assuranceSha256": assurance_sha256,
                "authorityEpoch": self.assurance["authorityEpoch"],
                "authorityGeneration": self.assurance["authorityGeneration"],
                "commitOperationIdBase64url": None,
                "committedAtUnix": committed_at,
                "highWaterCommitmentSha256": genesis_commitment(assurance_sha256),
                "highWaterReceiptSha256": None,
                "highWaterSequence": 0,
                "priorVerifierStateSha256": None,
                "stateStoreGeneration": 1,
                "stateStoreHeadSha256": sha256_bytes(
                    STATE_HEAD_DOMAIN
                    + canonical_json(
                        {
                            "assuranceSha256": assurance_sha256,
                            "stateStoreGeneration": 1,
                            "storeIdentitySha256": store.store_identity_sha256,
                        }
                    )
                ),
                "stateStoreIdentitySha256": store.store_identity_sha256,
            }
            store.install_genesis(
                sign_envelope(
                    signer,
                    api_version=SIGNED_STATE_VERSION,
                    domain=STATE_DOMAIN,
                    payload=payload,
                )
            )

    def observe_runtime_time(self) -> int:
        observed = require_uint(
            int(time.time()),
            "verifier-state runtime clock",
            positive=True,
        )
        with self._runtime_clock_lock:
            require(
                observed >= self._last_runtime_unix,
                "verifier-state runtime clock rolled backward",
            )
            self._last_runtime_unix = observed
        return observed

    def bind_ingress_deadline(self, deadline: float) -> None:
        require(
            type(deadline) is float
            and deadline > time.monotonic()
            and getattr(self._ingress_deadline, "value", None) is None,
            "verifier-state ingress deadline is invalid or already bound",
        )
        self._ingress_deadline.value = deadline

    def clear_ingress_deadline(self) -> None:
        self._ingress_deadline.value = None

    def _deadline_for_hop(
        self,
        *,
        ambiguous_mutation: bool = False,
    ) -> float | None:
        deadline = getattr(self._ingress_deadline, "value", None)
        if deadline is None:
            return None
        if time.monotonic() >= deadline:
            if ambiguous_mutation:
                raise UnknownOutcomeError(
                    "the ingress deadline expired after a mutation became "
                    "ambiguous; recover only the same operation"
                )
            raise ContractError(
                "the ingress deadline expired before a new state or signer "
                "operation could begin"
            )
        return deadline

    def _store_call(
        self,
        operation: str,
        *,
        ambiguous_mutation: bool = False,
        **values: Any,
    ) -> Any:
        deadline = self._deadline_for_hop(
            ambiguous_mutation=ambiguous_mutation
        )
        method = getattr(self.store, operation)
        if isinstance(self.store, ExternalLinearizableStateStore):
            return method(deadline=deadline, **values)
        return method(**values)

    def _sign_envelope(
        self,
        *,
        api_version: str,
        domain: bytes,
        payload: dict[str, Any],
        ambiguous_mutation: bool = False,
    ) -> dict[str, Any]:
        deadline = self._deadline_for_hop(
            ambiguous_mutation=ambiguous_mutation
        )
        return sign_envelope(
            self.signer,
            api_version=api_version,
            domain=domain,
            payload=payload,
            deadline=deadline,
        )

    def _validate_production_evidence(self, now: int) -> None:
        if self.mode != "production":
            return
        self.nonce_authority_assurance_evidence = (
            validate_nonce_authority_assurance_evidence(
                self._nonce_authority_assurance_evidence_document,
                evidence_public_key=(
                    self._nonce_authority_assurance_evidence_public_key
                ),
                evidence_key_id=(
                    self._nonce_authority_assurance_evidence_key_id
                ),
                assurance=self.assurance,
                nonce_authority=self.nonce_authority,
                store=self.store,
                verifier_state_signing_key_id=self.signer.key_id,
                now=now,
            )
        )
        self.role_separation_evidence = (
            validate_role_separation_evidence(
                self._role_separation_evidence_document,
                evidence_public_key=(
                    self._role_separation_evidence_public_key
                ),
                evidence_key_id=self._role_separation_evidence_key_id,
                assurance_sha256=self.assurance_sha256,
                nonce_authority=self.nonce_authority,
                signer=self.signer,
                store=self.store,
                expected_additional_roles=(
                    self._role_separation_additional_roles
                ),
                now=now,
            )
        )
        self.store_assurance_evidence = (
            validate_store_assurance_evidence(
                self._store_assurance_evidence_document,
                evidence_public_key=(
                    self._store_assurance_evidence_public_key
                ),
                evidence_key_id=self._store_assurance_evidence_key_id,
                expected_issuer_administrative_domain_sha256=(
                    self
                    ._store_assurance_issuer_administrative_domain_sha256
                ),
                expected_issuer_credential_identity_sha256=(
                    self
                    ._store_assurance_issuer_credential_identity_sha256
                ),
                expected_issuer_identity_sha256=(
                    self._store_assurance_issuer_identity_sha256
                ),
                store=self.store,
                now=now,
            )
        )
        self._validate_global_role_bindings()

    def _validate_global_role_bindings(self) -> None:
        require(
            self.mode == "production",
            "global role bindings are production-only",
        )
        role_payload = exact(
            self.role_separation_evidence["payload"],
            {
                "apiVersion",
                "assuranceSha256",
                "evidenceExpiresAtUnix",
                "evidenceIssuedAtUnix",
                "nonceAuthority",
                "nonceAuthorityAssuranceEvidenceIssuer",
                "publicAttestationClientTls",
                "productionEligible",
                "roleSeparationEvidenceIssuer",
                "storeAssuranceEvidenceIssuer",
                "verifierStateSigner",
                "verifierStateSignerClientTls",
                "verifierStateSignerServerTls",
                "verifierStateStore",
                "verifierStateStoreClientTls",
                "verifierStateStoreServerTls",
                "verifierStateServiceListenerTls",
            },
            "global verifier-state role payload",
        )
        role_key_ids = {
            name: value["keySpkiSha256"]
            for name, value in role_payload.items()
            if isinstance(value, Mapping)
            and "keySpkiSha256" in value
        }
        role_key_ids = validate_global_attestation_key_role_separation(
            role_key_ids
        )
        require(
            role_key_ids[
                "nonceAuthorityAssuranceEvidenceIssuer"
            ]
            == self._nonce_authority_assurance_evidence_key_id
            and role_key_ids["roleSeparationEvidenceIssuer"]
            == self._role_separation_evidence_key_id
            and role_key_ids["storeAssuranceEvidenceIssuer"]
            == self._store_assurance_evidence_key_id
            and role_key_ids["nonceAuthority"]
            == self.nonce_authority.key_id
            and role_key_ids["verifierStateSigner"]
            == self.signer.key_id
            and role_key_ids["verifierStateStore"]
            == self.store.attestation_key_id,
            "signed assurance evidence crossed the global role registry",
        )

    def _verified_current_state(self) -> tuple[dict[str, Any], dict[str, Any], str]:
        envelope = verify_envelope(
            self._store_call("read"),
            api_version=SIGNED_STATE_VERSION,
            domain=STATE_DOMAIN,
            signer=self.signer,
            label="signed verifier state",
        )
        payload = validate_state_payload(
            envelope["payload"],
            assurance=self.assurance,
            assurance_sha256=self.assurance_sha256,
            store_identity_sha256=self.store.store_identity_sha256,
        )
        if self.mode == "production":
            require(
                payload["stateStoreGeneration"]
                >= self.store.minimum_generation
                and payload["stateStoreGeneration"]
                >= self.store.minimum_commit_index,
                "retained verifier state predates signed store assurance high water",
            )
        return envelope, payload, sha256_json(envelope)

    def _recover_store(self, **values: Any) -> dict[str, Any]:
        try:
            recovered = exact(
                self._store_call(
                    "recover",
                    ambiguous_mutation=True,
                    **values,
                ),
                {
                    "commitProof",
                    "commitReceipt",
                    "nonceConsumptionReceipt",
                    "nonceStatusEvidence",
                    "preparedOperation",
                    "status",
                },
                "same-operation store recovery result",
            )
            status = recovered["status"]
            require(
                status
                in {
                    "notFound",
                    "prepared",
                    "consumptionPending",
                    "nonceConsumed",
                    "casCommitted",
                    "committed",
                    "aborted",
                },
                "same-operation store recovery status is invalid",
            )
            if status == "notFound":
                require(
                    recovered["preparedOperation"] is None
                    and recovered["nonceStatusEvidence"] is None
                    and recovered["nonceConsumptionReceipt"] is None
                    and recovered["commitProof"] is None
                    and recovered["commitReceipt"] is None,
                    "notFound recovery carried operation artifacts",
                )
            elif status == "prepared":
                require(
                    type(recovered["preparedOperation"]) is dict
                    and recovered["nonceStatusEvidence"] is None
                    and recovered["nonceConsumptionReceipt"] is None
                    and recovered["commitProof"] is None
                    and recovered["commitReceipt"] is None,
                    "prepared recovery artifacts are malformed",
                )
            elif status == "consumptionPending":
                require(
                    type(recovered["preparedOperation"]) is dict
                    and (
                        recovered["nonceStatusEvidence"] is None
                        or type(recovered["nonceStatusEvidence"])
                        is dict
                    )
                    and recovered["nonceConsumptionReceipt"] is None
                    and recovered["commitProof"] is None
                    and recovered["commitReceipt"] is None,
                    "pending-consumption recovery artifacts are malformed",
                )
            elif status == "nonceConsumed":
                require(
                    type(recovered["preparedOperation"]) is dict
                    and type(recovered["nonceStatusEvidence"]) is dict
                    and type(recovered["nonceConsumptionReceipt"])
                    is dict
                    and recovered["commitProof"] is None
                    and recovered["commitReceipt"] is None,
                    "consumed-nonce recovery artifacts are malformed",
                )
            elif status == "casCommitted":
                require(
                    type(recovered["preparedOperation"]) is dict
                    and type(recovered["nonceStatusEvidence"]) is dict
                    and type(recovered["nonceConsumptionReceipt"])
                    is dict
                    and type(recovered["commitProof"]) is dict
                    and recovered["commitReceipt"] is None,
                    "CAS recovery artifacts are malformed",
                )
            elif status == "committed":
                require(
                    type(recovered["preparedOperation"]) is dict
                    and type(recovered["nonceStatusEvidence"]) is dict
                    and type(recovered["nonceConsumptionReceipt"])
                    is dict
                    and type(recovered["commitProof"]) is dict
                    and type(recovered["commitReceipt"]) is dict,
                    "committed recovery artifacts are malformed",
                )
            else:
                require(
                    type(recovered["preparedOperation"]) is dict
                    and type(recovered["nonceStatusEvidence"]) is dict
                    and recovered["nonceConsumptionReceipt"] is None
                    and recovered["commitProof"] is None
                    and recovered["commitReceipt"] is None,
                    "aborted recovery artifacts are malformed",
                )
            return recovered
        except UnknownOutcomeError:
            raise
        except ContractError:
            raise
        except Exception as exc:
            raise UnknownOutcomeError(
                "same-operation recovery transport or output failed"
            ) from exc

    def read_state(
        self,
        request: Any,
        *,
        now: int,
    ) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {"apiVersion", "assuranceSha256"},
            "state read request",
        )
        require(
            value["apiVersion"] == READ_REQUEST_VERSION
            and value["assuranceSha256"] == self.assurance_sha256,
            "state read request crossed its assurance",
        )
        envelope, payload, envelope_sha256 = self._verified_current_state()
        require(
            now >= payload["committedAtUnix"],
            "service clock rolled behind the retained state",
        )
        return {
            "apiVersion": READ_RESPONSE_VERSION,
            "nonActionable": True,
            "state": envelope,
            "stateSha256": envelope_sha256,
        }

    def issue_challenge(
        self,
        request: Any,
        *,
        now: int,
    ) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {
                "apiVersion",
                "assuranceSha256",
                "expectedVerifierStateSha256",
                "operationIdBase64url",
                "producerInvocationBaseSha256",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
            },
            "verifier-state challenge issue request",
        )
        require(
            value["apiVersion"] == ISSUE_CHALLENGE_REQUEST_VERSION
            and value["assuranceSha256"] == self.assurance_sha256,
            "challenge issue request crossed its assurance",
        )
        recovery_identity = self._validated_recovery_identity(
            value["recoveryIdentity"]
        )
        recovery_identity_sha256 = sha256_json(recovery_identity)
        operation_id = value["operationIdBase64url"]
        recovery_key_sha256 = value["recoveryKeySha256"]
        require(
            value["recoveryIdentitySha256"]
            == recovery_identity_sha256
            and operation_id == self._operation_id(recovery_identity)
            and recovery_key_sha256
            == self._recovery_key(recovery_identity),
            "challenge issue request recovery identity is not deterministic",
        )
        require_sha256(
            value["producerInvocationBaseSha256"],
            "challenge issue producer invocation base",
        )
        _state, state_payload, state_sha256 = (
            self._verified_current_state()
        )
        require(
            value["expectedVerifierStateSha256"] == state_sha256
            and now >= state_payload["committedAtUnix"],
            "challenge issue request does not target the current predecessor",
        )
        issue_request_sha256 = sha256_json(value)
        recovered = self._store_call(
            "recover_challenge",
            operation_id=operation_id,
            recovery_key_sha256=recovery_key_sha256,
            issue_request_sha256=issue_request_sha256,
        )
        if recovered is None:
            issued = require_uint(
                now,
                "challenge issue time",
                positive=True,
            )
            expires = checked_add_uint(
                issued,
                MAX_CHALLENGE_SECONDS,
                "challenge expiry",
            )
            challenge = hashlib.sha256(
                CHALLENGE_VALUE_DOMAIN
                + canonical_json(
                    {
                        "expectedVerifierStateSha256": state_sha256,
                        "issueRequestSha256": issue_request_sha256,
                        "operationIdBase64url": operation_id,
                        "producerInvocationBaseSha256": value[
                            "producerInvocationBaseSha256"
                        ],
                        "recoveryKeySha256": recovery_key_sha256,
                    }
                )
            ).digest()
            try:
                recovered = self._store_call(
                    "issue_challenge",
                    operation_id=operation_id,
                    recovery_key_sha256=recovery_key_sha256,
                    issue_request_sha256=issue_request_sha256,
                    producer_invocation_base_sha256=value[
                        "producerInvocationBaseSha256"
                    ],
                    challenge_base64url=b64url_encode(challenge),
                    challenge_sha256=sha256_bytes(challenge),
                    expected_state_sha256=state_sha256,
                    issued_at_unix=issued,
                    expires_at_unix=expires,
                )
            except UnknownOutcomeError:
                recovered = self._store_call(
                    "recover_challenge",
                    ambiguous_mutation=True,
                    operation_id=operation_id,
                    recovery_key_sha256=recovery_key_sha256,
                    issue_request_sha256=issue_request_sha256,
                )
                require(
                    recovered is not None,
                    "unknown challenge issuance outcome has no exact authoritative recovery",
                )
        require(
            recovered["operationIdBase64url"] == operation_id
            and recovered["recoveryKeySha256"]
            == recovery_key_sha256
            and recovered["issueRequestSha256"]
            == issue_request_sha256
            and recovered["producerInvocationBaseSha256"]
            == value["producerInvocationBaseSha256"]
            and recovered["expectedVerifierStateSha256"]
            == state_sha256
            and recovered["replacementForbidden"] is True
            and recovered["status"] in {"issued", "bound"},
            "challenge issuance recovered a crossed or terminal mutation",
        )
        return {
            "apiVersion": ISSUE_CHALLENGE_RESPONSE_VERSION,
            **recovered,
            "nonActionable": True,
        }

    def recover_challenge(
        self,
        request: Any,
        *,
        now: int,
    ) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {
                "apiVersion",
                "assuranceSha256",
                "issueRequestSha256",
                "operationIdBase64url",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
            },
            "verifier-state challenge recovery request",
        )
        recovery_identity = self._validated_recovery_identity(
            value["recoveryIdentity"]
        )
        require(
            value["apiVersion"] == RECOVER_CHALLENGE_REQUEST_VERSION
            and value["assuranceSha256"] == self.assurance_sha256
            and value["recoveryIdentitySha256"]
            == sha256_json(recovery_identity)
            and value["operationIdBase64url"]
            == self._operation_id(recovery_identity)
            and value["recoveryKeySha256"]
            == self._recovery_key(recovery_identity),
            "challenge recovery request identity is invalid",
        )
        recovered = self._store_call(
            "recover_challenge",
            operation_id=value["operationIdBase64url"],
            recovery_key_sha256=value["recoveryKeySha256"],
            issue_request_sha256=require_sha256(
                value["issueRequestSha256"],
                "challenge recovery issue request",
            ),
        )
        if recovered is None:
            return {
                "apiVersion": RECOVER_CHALLENGE_RESPONSE_VERSION,
                "challenge": None,
                "nonActionable": True,
                "replacementForbidden": True,
                "status": "notFound",
            }
        status = recovered["status"]
        if status == "issued" and now >= recovered[
            "challengeExpiresAtUnix"
        ]:
            status = "expired"
        return {
            "apiVersion": RECOVER_CHALLENGE_RESPONSE_VERSION,
            "challenge": {**recovered, "status": status},
            "nonActionable": True,
            "replacementForbidden": True,
            "status": status,
        }

    @staticmethod
    def _validated_request_binding(value: Any) -> dict[str, Any]:
        binding = exact(
            value,
            {
                "apiVersion",
                "expiresAtUnix",
                "nonceSha256",
                "producerChannelChallengeBase64url",
                "producerEphemeralKeySha256",
                "producerInvocationSha256",
                "requestBodySha256",
                "tlsBindingSha256",
                "transactionIdBase64url",
            },
            "verifier-state request binding",
        )
        require(
            binding["apiVersion"] == REQUEST_BINDING_VERSION,
            "verifier-state request-binding version is invalid",
        )
        require_uint(
            binding["expiresAtUnix"],
            "bound nonce expiry",
            positive=True,
        )
        for field in (
            "nonceSha256",
            "producerEphemeralKeySha256",
            "producerInvocationSha256",
            "requestBodySha256",
            "tlsBindingSha256",
        ):
            require_sha256(
                binding[field],
                f"verifier-state request binding {field}",
            )
        b64url_decode(
            binding["producerChannelChallengeBase64url"],
            "bound producer channel challenge",
            exact_bytes=32,
        )
        b64url_decode(
            binding["transactionIdBase64url"],
            "bound nonce transaction",
            exact_bytes=32,
        )
        return binding

    def _recovery_binding(
        self,
        *,
        expected_state_sha256: str,
        operation_id: str,
        request_binding_sha256: str,
        verifier_challenge_sha256: str,
    ) -> dict[str, Any]:
        return {
            "apiVersion": RECOVERY_BINDING_VERSION,
            "assuranceSha256": self.assurance_sha256,
            "expectedVerifierStateSha256": expected_state_sha256,
            "operationIdBase64url": operation_id,
            "requestBindingSha256": request_binding_sha256,
            "verifierChallengeSha256": verifier_challenge_sha256,
        }

    @staticmethod
    def _validated_recovery_identity(value: Any) -> dict[str, Any]:
        identity = exact(
            value,
            {
                "apiVersion",
                "assuranceSha256",
                "callerNonceSha256",
                "immutableConfigSha256",
                "releaseIdentitySha256",
                "requestBodySha256",
            },
            "verifier-state recovery identity",
        )
        require(
            identity["apiVersion"] == RECOVERY_IDENTITY_VERSION,
            "verifier-state recovery identity version is invalid",
        )
        for field in (
            "assuranceSha256",
            "callerNonceSha256",
            "immutableConfigSha256",
            "releaseIdentitySha256",
            "requestBodySha256",
        ):
            require_sha256(
                identity[field],
                f"verifier-state recovery identity {field}",
            )
        return identity

    @staticmethod
    def _recovery_key(recovery_identity: dict[str, Any]) -> str:
        return sha256_bytes(
            RECOVERY_KEY_DOMAIN + canonical_json(recovery_identity)
        )

    @staticmethod
    def _operation_id(recovery_identity: dict[str, Any]) -> str:
        return b64url_encode(
            hashlib.sha256(
                OPERATION_ID_DOMAIN + canonical_json(recovery_identity)
            ).digest()
        )

    def prepare(self, request: Any, *, now: int) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {
                "apiVersion",
                "assuranceSha256",
                "challengeIssue",
                "challengeIssueSha256",
                "expectedVerifierStateSha256",
                "operationIdBase64url",
                "priorStateRead",
                "priorStateReadSha256",
                "producerInvocation",
                "producerInvocationBaseSha256",
                "producerInvocationSha256",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
                "requestBinding",
                "requestBindingSha256",
                "verifierChallengeBase64url",
            },
            "verifier-state prepare request",
        )
        require(
            value["apiVersion"] == PREPARE_REQUEST_VERSION
            and value["assuranceSha256"] == self.assurance_sha256,
            "prepare request crossed its assurance",
        )
        operation_id = value["operationIdBase64url"]
        b64url_decode(operation_id, "prepare operation ID", exact_bytes=32)
        challenge = b64url_decode(
            value["verifierChallengeBase64url"],
            "prepare verifier challenge",
            exact_bytes=32,
        )
        challenge_sha256 = sha256_bytes(challenge)
        request_binding = self._validated_request_binding(
            value["requestBinding"]
        )
        recovery_identity = self._validated_recovery_identity(
            value["recoveryIdentity"]
        )
        recovery_identity_sha256 = sha256_json(recovery_identity)
        require(
            recovery_identity["assuranceSha256"]
            == self.assurance_sha256
            and recovery_identity["callerNonceSha256"]
            == request_binding["nonceSha256"]
            and recovery_identity["requestBodySha256"]
            == request_binding["requestBodySha256"]
            and value["recoveryIdentitySha256"]
            == recovery_identity_sha256
            and operation_id == self._operation_id(recovery_identity),
            "prepare recovery identity crossed its exact request",
        )
        request_binding_sha256 = sha256_bytes(
            REQUEST_BINDING_DOMAIN + canonical_json(request_binding)
        )
        require(
            value["requestBindingSha256"] == request_binding_sha256
            and request_binding["transactionIdBase64url"]
            == operation_id,
            "prepare request binding or transaction is invalid",
        )
        recovery_binding = self._recovery_binding(
            expected_state_sha256=require_sha256(
                value["expectedVerifierStateSha256"],
                "prepared predecessor",
            ),
            operation_id=operation_id,
            request_binding_sha256=request_binding_sha256,
            verifier_challenge_sha256=challenge_sha256,
        )
        require(
            value["recoveryKeySha256"]
            == self._recovery_key(recovery_identity),
            "prepare recovery key is not deterministic for its request",
        )
        recovery_key_sha256 = value["recoveryKeySha256"]
        producer_invocation = exact(
            value["producerInvocation"],
            {
                "apiVersion",
                "callerNonceSha256",
                "expiresAtUnix",
                "issuedAtUnix",
                "minimumReleaseIdentitySha256",
                "minimumRollbackContinuityCommitmentSha256",
                "nonceAuthorityVerifierChallengeBase64url",
                "nonceAuthorityVerifierStateOperationIdBase64url",
                "producerChannelChallengeBase64url",
                "producerEphemeralKeySpkiDerBase64url",
                "producerEphemeralKeySpkiSha256",
                "releaseIdentitySha256",
                "requestBodySha256",
                "staticPins",
                "tlsBindingSha256",
                "witnessVerifierChallengeBase64url",
            },
            "prepared producer invocation",
        )
        producer_invocation_sha256 = sha256_json(producer_invocation)
        producer_invocation_base = {
            key: item
            for key, item in producer_invocation.items()
            if key
            not in {
                "nonceAuthorityVerifierChallengeBase64url",
                "nonceAuthorityVerifierStateOperationIdBase64url",
            }
        }
        producer_invocation_base_sha256 = sha256_json(
            producer_invocation_base
        )
        static_pins = exact(
            producer_invocation["staticPins"],
            {
                "descriptorSha256",
                "executableSha256",
                "immutableConfigSha256",
                "nonceStoreIdentitySha256",
                "nonceStoreKeySpkiSha256",
                "producerRequestSchemaSha256",
                "sandboxDescriptorSha256",
                "sandboxLauncherSha256",
                "trustRootsSha256",
                "witnessStoreIdentitySha256",
                "witnessStoreKeySpkiSha256",
            },
            "prepared producer invocation static pins",
        )
        for field, digest in static_pins.items():
            require_sha256(
                digest,
                f"prepared producer invocation static pin {field}",
            )
        producer_ephemeral_spki = b64url_decode(
            producer_invocation[
                "producerEphemeralKeySpkiDerBase64url"
            ],
            "prepared producer ephemeral public key",
            exact_bytes=44,
        )
        prior_read = exact(
            value["priorStateRead"],
            {
                "apiVersion",
                "nonActionable",
                "state",
                "stateSha256",
            },
            "prepared prior-state read",
        )
        challenge_issue = exact(
            value["challengeIssue"],
            {
                "apiVersion",
                "challengeBase64url",
                "challengeExpiresAtUnix",
                "challengeIssuedAtUnix",
                "challengeSha256",
                "expectedVerifierStateSha256",
                "issueRequestSha256",
                "nonActionable",
                "operationIdBase64url",
                "producerInvocationBaseSha256",
                "recoveryKeySha256",
                "replacementForbidden",
                "status",
            },
            "prepared challenge issue response",
        )
        require(
            value["producerInvocationSha256"]
            == producer_invocation_sha256
            == request_binding["producerInvocationSha256"]
            and value["producerInvocationBaseSha256"]
            == producer_invocation_base_sha256
            and value["challengeIssueSha256"]
            == sha256_json(challenge_issue)
            and challenge_issue["apiVersion"]
            == ISSUE_CHALLENGE_RESPONSE_VERSION
            and challenge_issue["operationIdBase64url"]
            == operation_id
            and challenge_issue["recoveryKeySha256"]
            == recovery_key_sha256
            and challenge_issue["producerInvocationBaseSha256"]
            == producer_invocation_base_sha256
            and challenge_issue["expectedVerifierStateSha256"]
            == value["expectedVerifierStateSha256"]
            and challenge_issue["challengeBase64url"]
            == value["verifierChallengeBase64url"]
            and challenge_issue["challengeSha256"] == challenge_sha256
            and challenge_issue["replacementForbidden"] is True
            and challenge_issue["nonActionable"] is True
            and challenge_issue["status"] == "issued"
            and producer_invocation["apiVersion"]
            == "serverware.publicAttestationProducerInvocation/v1"
            and producer_invocation["callerNonceSha256"]
            == recovery_identity["callerNonceSha256"]
            and producer_invocation["expiresAtUnix"]
            == request_binding["expiresAtUnix"]
            and producer_invocation[
                "nonceAuthorityVerifierChallengeBase64url"
            ]
            == value["verifierChallengeBase64url"]
            and producer_invocation[
                "nonceAuthorityVerifierStateOperationIdBase64url"
            ]
            == operation_id
            and producer_invocation[
                "producerChannelChallengeBase64url"
            ]
            == request_binding[
                "producerChannelChallengeBase64url"
            ]
            and producer_invocation["producerEphemeralKeySpkiSha256"]
            == request_binding["producerEphemeralKeySha256"]
            == sha256_bytes(producer_ephemeral_spki)
            and producer_invocation["releaseIdentitySha256"]
            == recovery_identity["releaseIdentitySha256"]
            and producer_invocation["requestBodySha256"]
            == recovery_identity["requestBodySha256"]
            and recovery_identity["immutableConfigSha256"]
            == static_pins["immutableConfigSha256"]
            and producer_invocation["tlsBindingSha256"]
            == request_binding["tlsBindingSha256"]
            and value["priorStateReadSha256"]
            == sha256_json(prior_read)
            and prior_read["apiVersion"] == READ_RESPONSE_VERSION
            and prior_read["stateSha256"]
            == value["expectedVerifierStateSha256"]
            and prior_read["nonActionable"] is True,
            "prepare request omitted or crossed its restart context",
        )
        prepare_request_sha256 = sha256_json(value)
        recovered = self._recover_store(
            recovery_key_sha256=recovery_key_sha256,
            request_binding_sha256=request_binding_sha256,
            operation_id=operation_id,
            prepare_request_sha256=prepare_request_sha256,
        )
        if recovered["status"] != "notFound":
            prepared = self._validated_prepared_operation(
                recovered["preparedOperation"],
                now=None,
            )
            require(
                prepared["prepareRequest"] == value,
                "recovered prepared operation crossed its exact request",
            )
            return self._prepare_response(
                prepared,
                status=recovered["status"],
            )

        _prior_envelope, prior, prior_sha256 = (
            self._verified_current_state()
        )
        require(
            value["expectedVerifierStateSha256"] == prior_sha256,
            "prepare request does not target the current signed state",
        )
        require(
            prior_read["state"] == _prior_envelope,
            "prepare prior read did not carry the exact signed predecessor",
        )
        issued = require_uint(now, "authorization issue time", positive=True)
        require(
            prior["highWaterSequence"] < MAX_U64
            and prior["stateStoreGeneration"] < MAX_U64
            and issued >= prior["committedAtUnix"],
            "verifier-state sequence is terminal or service clock rolled back",
        )
        expires = checked_add_uint(
            issued,
            self.authorization_lifetime_seconds,
            "authorization expiry",
        )
        require(
            issued < request_binding["expiresAtUnix"],
            "prepared nonce request is already stale",
        )
        authorization_payload = {
            "apiVersion": AUTHORIZATION_VERSION,
            "assuranceSha256": self.assurance_sha256,
            "authorityEpoch": self.assurance["authorityEpoch"],
            "authorityGeneration": self.assurance["authorityGeneration"],
            "expiresAtUnix": expires,
            "highWaterCommitmentSha256": prior["highWaterCommitmentSha256"],
            "highWaterReceiptSha256": prior["highWaterReceiptSha256"],
            "highWaterSequence": prior["highWaterSequence"],
            "issuedAtUnix": issued,
            "nonceReceiptSigningKeySpkiSha256":
            self.nonce_authority.key_id,
            "nonceTransactionIdBase64url":
            request_binding["transactionIdBase64url"],
            "oneUse": True,
            "operationIdBase64url": operation_id,
            "prepareRequestSha256": prepare_request_sha256,
            "priorCommittedAtUnix": prior["committedAtUnix"],
            "priorVerifierStateSha256": prior_sha256,
            "recoveryIdentitySha256": recovery_identity_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "requestBindingSha256": request_binding_sha256,
            "stateStoreGeneration": prior["stateStoreGeneration"],
            "stateStoreHeadSha256": prior["stateStoreHeadSha256"],
            "stateStoreAttestationKeySpkiSha256":
            self.store.attestation_key_id,
            "stateStoreAssuranceEvidenceSha256":
            self.store.assurance_evidence_sha256,
            "stateStoreConfigurationSha256":
            self.store.configuration_sha256,
            "stateStoreIdentitySha256": self.store.store_identity_sha256,
            "verifierChallengeSha256": challenge_sha256,
        }
        authorization = self._sign_envelope(
            api_version=AUTHORIZATION_VERSION,
            domain=AUTHORIZATION_DOMAIN,
            payload=authorization_payload,
        )
        authorization_sha256 = sha256_json(authorization)
        nonce_consume_request = {
            "apiVersion": NONCE_CONSUME_ONCE_REQUEST_VERSION,
            "expiresAtUnix": request_binding["expiresAtUnix"],
            "nonceAuthorityVerifierStateAuthorizationSha256":
            authorization_sha256,
            "nonceSha256": request_binding["nonceSha256"],
            "producerChannelChallengeBase64url":
            request_binding["producerChannelChallengeBase64url"],
            "producerEphemeralKeySha256":
            request_binding["producerEphemeralKeySha256"],
            "producerInvocationSha256":
            request_binding["producerInvocationSha256"],
            "requestBodySha256": request_binding["requestBodySha256"],
            "tlsBindingSha256": request_binding["tlsBindingSha256"],
            "transactionIdBase64url":
            request_binding["transactionIdBase64url"],
        }
        nonce_consume_request_sha256 = sha256_bytes(
            NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
            + canonical_json(nonce_consume_request)
        )
        successor_intent = {
            "apiVersion": SUCCESSOR_INTENT_VERSION,
            "authorizationSha256": authorization_sha256,
            "expectedHighWaterSequence": checked_add_uint(
                prior["highWaterSequence"],
                1,
                "prepared successor high-water sequence",
            ),
            "expectedStateStoreGeneration": checked_add_uint(
                prior["stateStoreGeneration"],
                1,
                "prepared successor store generation",
            ),
            "expectedVerifierStateSha256": prior_sha256,
            "nonceConsumeRequestSha256":
            nonce_consume_request_sha256,
            "operationIdBase64url": operation_id,
            "previousStateStoreHeadSha256":
            prior["stateStoreHeadSha256"],
            "requestBindingSha256": request_binding_sha256,
            "transactionIdBase64url":
            request_binding["transactionIdBase64url"],
            "verifierChallengeSha256": challenge_sha256,
        }
        prepared_operation = {
            "apiVersion": PREPARED_OPERATION_VERSION,
            "authorization": authorization,
            "authorizationSha256": authorization_sha256,
            "nonceConsumeRequest": nonce_consume_request,
            "nonceConsumeRequestSha256":
            nonce_consume_request_sha256,
            "prepareRequest": value,
            "prepareRequestSha256": prepare_request_sha256,
            "recoveryBinding": recovery_binding,
            "recoveryIdentity": recovery_identity,
            "recoveryIdentitySha256": recovery_identity_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "requestBinding": request_binding,
            "requestBindingSha256": request_binding_sha256,
            "successorIntent": successor_intent,
            "successorIntentSha256": sha256_json(successor_intent),
        }
        try:
            retained = self._store_call(
                "prepare",
                operation_id=operation_id,
                recovery_key_sha256=recovery_key_sha256,
                request_binding_sha256=request_binding_sha256,
                prepare_request_sha256=prepare_request_sha256,
                expected_state_sha256=prior_sha256,
                authorization=authorization,
                challenge_sha256=challenge_sha256,
                producer_invocation_base_sha256=(
                    producer_invocation_base_sha256
                ),
                prepared_operation=prepared_operation,
            )
        except UnknownOutcomeError:
            recovered = self._recover_store(
                recovery_key_sha256=recovery_key_sha256,
                request_binding_sha256=request_binding_sha256,
                operation_id=operation_id,
                prepare_request_sha256=prepare_request_sha256,
            )
            if recovered["status"] == "notFound":
                raise UnknownOutcomeError(
                    "prepare outcome remains unknown; recover only the "
                    "deterministic recovery key"
                )
            retained = recovered["preparedOperation"]
        require(
            retained == prepared_operation,
            "state store substituted the prepared operation",
        )
        return self._prepare_response(
            self._validated_prepared_operation(
                retained,
                now=now,
            ),
            status="prepared",
        )

    @staticmethod
    def _prepare_response(
        prepared_operation: dict[str, Any],
        *,
        status: str,
    ) -> dict[str, Any]:
        return {
            "apiVersion": PREPARE_RESPONSE_VERSION,
            "nonActionable": True,
            "preparedOperation": prepared_operation,
            "preparedOperationSha256":
            sha256_json(prepared_operation),
            "recoveryKeySha256":
            prepared_operation["recoveryKeySha256"],
            "replacementForbidden": status != "aborted",
            "status": status,
        }

    def _validated_prepared_operation(
        self,
        value: Any,
        *,
        now: int | None,
    ) -> dict[str, Any]:
        prepared = exact(
            value,
            {
                "apiVersion",
                "authorization",
                "authorizationSha256",
                "nonceConsumeRequest",
                "nonceConsumeRequestSha256",
                "prepareRequest",
                "prepareRequestSha256",
                "recoveryBinding",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
                "requestBinding",
                "requestBindingSha256",
                "successorIntent",
                "successorIntentSha256",
            },
            "prepared verifier-state operation",
        )
        require(
            prepared["apiVersion"] == PREPARED_OPERATION_VERSION,
            "prepared operation version is invalid",
        )
        prepare_request = exact(
            prepared["prepareRequest"],
            {
                "apiVersion",
                "assuranceSha256",
                "expectedVerifierStateSha256",
                "operationIdBase64url",
                "priorStateRead",
                "priorStateReadSha256",
                "producerInvocation",
                "producerInvocationSha256",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
                "requestBinding",
                "requestBindingSha256",
                "verifierChallengeBase64url",
            },
            "retained prepare request",
        )
        request_binding = self._validated_request_binding(
            prepared["requestBinding"]
        )
        recovery_identity = self._validated_recovery_identity(
            prepared["recoveryIdentity"]
        )
        challenge = b64url_decode(
            prepare_request["verifierChallengeBase64url"],
            "retained verifier challenge",
            exact_bytes=32,
        )
        authorization, authorization_payload, authorization_sha256 = (
            self._validated_authorization(
                prepared["authorization"],
                challenge=challenge,
                now=now,
            )
        )
        recovery_binding = self._recovery_binding(
            expected_state_sha256=prepare_request[
                "expectedVerifierStateSha256"
            ],
            operation_id=prepare_request["operationIdBase64url"],
            request_binding_sha256=prepared[
                "requestBindingSha256"
            ],
            verifier_challenge_sha256=sha256_bytes(challenge),
        )
        nonce_request = exact(
            prepared["nonceConsumeRequest"],
            {
                "apiVersion",
                "expiresAtUnix",
                "nonceAuthorityVerifierStateAuthorizationSha256",
                "nonceSha256",
                "producerChannelChallengeBase64url",
                "producerEphemeralKeySha256",
                "producerInvocationSha256",
                "requestBodySha256",
                "tlsBindingSha256",
                "transactionIdBase64url",
            },
            "retained nonce consume request",
        )
        successor_intent = exact(
            prepared["successorIntent"],
            {
                "apiVersion",
                "authorizationSha256",
                "expectedHighWaterSequence",
                "expectedStateStoreGeneration",
                "expectedVerifierStateSha256",
                "nonceConsumeRequestSha256",
                "operationIdBase64url",
                "previousStateStoreHeadSha256",
                "requestBindingSha256",
                "transactionIdBase64url",
                "verifierChallengeSha256",
            },
            "retained successor intent",
        )
        request_binding_sha256 = sha256_bytes(
            REQUEST_BINDING_DOMAIN + canonical_json(request_binding)
        )
        nonce_request_sha256 = sha256_bytes(
            NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
            + canonical_json(nonce_request)
        )
        require(
            prepare_request["apiVersion"] == PREPARE_REQUEST_VERSION
            and prepare_request["assuranceSha256"]
            == self.assurance_sha256
            and prepare_request["expectedVerifierStateSha256"]
            == authorization_payload["priorVerifierStateSha256"]
            and recovery_identity["assuranceSha256"]
            == self.assurance_sha256
            and recovery_identity["callerNonceSha256"]
            == request_binding["nonceSha256"]
            and recovery_identity["requestBodySha256"]
            == request_binding["requestBodySha256"]
            and prepared["prepareRequestSha256"]
            == sha256_json(prepare_request)
            and prepared["requestBinding"] == request_binding
            and prepared["requestBindingSha256"]
            == request_binding_sha256
            and prepare_request["requestBinding"] == request_binding
            and prepare_request["requestBindingSha256"]
            == request_binding_sha256
            and prepared["recoveryBinding"] == recovery_binding
            and prepared["recoveryIdentity"] == recovery_identity
            and prepared["recoveryIdentitySha256"]
            == sha256_json(recovery_identity)
            and prepare_request["recoveryIdentity"]
            == recovery_identity
            and prepare_request["recoveryIdentitySha256"]
            == prepared["recoveryIdentitySha256"]
            and prepared["recoveryKeySha256"]
            == self._recovery_key(recovery_identity)
            and prepare_request["recoveryKeySha256"]
            == prepared["recoveryKeySha256"]
            and prepare_request["operationIdBase64url"]
            == self._operation_id(recovery_identity)
            and prepare_request["producerInvocationSha256"]
            == request_binding["producerInvocationSha256"]
            and sha256_json(prepare_request["producerInvocation"])
            == prepare_request["producerInvocationSha256"]
            and sha256_json(prepare_request["priorStateRead"])
            == prepare_request["priorStateReadSha256"]
            and prepared["authorization"] == authorization
            and prepared["authorizationSha256"]
            == authorization_sha256
            and prepared["nonceConsumeRequestSha256"]
            == nonce_request_sha256
            and nonce_request["apiVersion"]
            == NONCE_CONSUME_ONCE_REQUEST_VERSION
            and nonce_request[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ]
            == authorization_sha256
            and nonce_request["expiresAtUnix"]
            == request_binding["expiresAtUnix"]
            and all(
                nonce_request[field] == request_binding[field]
                for field in (
                    "nonceSha256",
                    "producerChannelChallengeBase64url",
                    "producerEphemeralKeySha256",
                    "producerInvocationSha256",
                    "requestBodySha256",
                    "tlsBindingSha256",
                    "transactionIdBase64url",
                )
            )
            and successor_intent["apiVersion"]
            == SUCCESSOR_INTENT_VERSION
            and prepared["successorIntentSha256"]
            == sha256_json(successor_intent)
            and successor_intent["authorizationSha256"]
            == authorization_sha256
            and successor_intent["expectedHighWaterSequence"]
            == authorization_payload["highWaterSequence"] + 1
            and successor_intent["expectedStateStoreGeneration"]
            == authorization_payload["stateStoreGeneration"] + 1
            and successor_intent["expectedVerifierStateSha256"]
            == authorization_payload["priorVerifierStateSha256"]
            and successor_intent["nonceConsumeRequestSha256"]
            == nonce_request_sha256
            and successor_intent["operationIdBase64url"]
            == authorization_payload["operationIdBase64url"]
            and successor_intent["previousStateStoreHeadSha256"]
            == authorization_payload["stateStoreHeadSha256"]
            and successor_intent["requestBindingSha256"]
            == request_binding_sha256
            and successor_intent["transactionIdBase64url"]
            == request_binding["transactionIdBase64url"]
            and successor_intent["verifierChallengeSha256"]
            == authorization_payload["verifierChallengeSha256"]
            and authorization_payload["prepareRequestSha256"]
            == prepared["prepareRequestSha256"]
            and authorization_payload["recoveryKeySha256"]
            == prepared["recoveryKeySha256"]
            and authorization_payload["recoveryIdentitySha256"]
            == prepared["recoveryIdentitySha256"]
            and authorization_payload["requestBindingSha256"]
            == request_binding_sha256
            and authorization_payload["nonceTransactionIdBase64url"]
            == request_binding["transactionIdBase64url"],
            "prepared operation is not the exact authorized saga context",
        )
        return prepared

    def _recovered_prepared(
        self,
        *,
        recovery_key_sha256: Any,
        request_binding_sha256: Any | None = None,
        recovery_identity: Any | None = None,
        recovery_identity_sha256: Any | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        recovery_key = require_sha256(
            recovery_key_sha256,
            "operation recovery key",
        )
        request_binding = (
            None
            if request_binding_sha256 is None
            else require_sha256(
                request_binding_sha256,
                "operation request binding",
            )
        )
        identity = (
            None
            if recovery_identity is None
            else self._validated_recovery_identity(
                recovery_identity
            )
        )
        require(
            (request_binding is None) is (identity is not None),
            "recovery requires either the retained request binding or "
            "the deterministic recovery identity",
        )
        if identity is not None:
            require(
                recovery_identity_sha256 == sha256_json(identity)
                and recovery_key == self._recovery_key(identity),
                "recovery identity did not derive the requested key",
            )
        recovered = self._recover_store(
            recovery_key_sha256=recovery_key,
            **(
                {}
                if request_binding is None
                else {
                    "request_binding_sha256":
                    request_binding
                }
            ),
        )
        require(
            recovered["status"] != "notFound",
            "recovery key does not identify a prepared operation",
        )
        prepared = self._validated_prepared_operation(
            recovered["preparedOperation"],
            now=None,
        )
        require(
            prepared["recoveryKeySha256"] == recovery_key
            and (
                request_binding is None
                or prepared["requestBindingSha256"]
                == request_binding
            )
            and (
                identity is None
                or (
                    prepared["recoveryIdentity"] == identity
                    and prepared["recoveryIdentitySha256"]
                    == recovery_identity_sha256
                )
            ),
            "recovered operation crossed its deterministic binding",
        )
        return recovered, prepared

    def lookup_recovery(
        self,
        request: Any,
        *,
        now: int,
    ) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {
                "apiVersion",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
            },
            "verifier-state recovery lookup",
        )
        require(
            value["apiVersion"] == RECOVERY_LOOKUP_REQUEST_VERSION,
            "recovery lookup version is invalid",
        )
        recovery_identity = self._validated_recovery_identity(
            value["recoveryIdentity"]
        )
        require(
            value["recoveryIdentitySha256"]
            == sha256_json(recovery_identity)
            and value["recoveryKeySha256"]
            == self._recovery_key(recovery_identity),
            "recovery lookup did not derive its exact request-bound key",
        )
        initial = self._recover_store(
            recovery_key_sha256=value["recoveryKeySha256"],
        )
        if initial["status"] == "notFound":
            return {
                "apiVersion": RECOVERY_LOOKUP_RESPONSE_VERSION,
                "commitReceipt": None,
                "nonActionable": True,
                "nonceConsumptionReceipt": None,
                "nonceRecoveryRequired": False,
                "nonceStatusEvidence": None,
                "preparedOperation": None,
                "preparedOperationSha256": None,
                "recoveryIdentity": recovery_identity,
                "recoveryIdentitySha256":
                value["recoveryIdentitySha256"],
                "recoveryKeySha256":
                value["recoveryKeySha256"],
                "replacementForbidden": False,
                "requestBindingSha256": None,
                "status": "notFound",
            }
        recovered, prepared = self._recovered_prepared(
            recovery_key_sha256=value["recoveryKeySha256"],
            recovery_identity=value["recoveryIdentity"],
            recovery_identity_sha256=value[
                "recoveryIdentitySha256"
            ],
        )
        return {
            "apiVersion": RECOVERY_LOOKUP_RESPONSE_VERSION,
            "commitReceipt": recovered["commitReceipt"],
            "nonActionable": True,
            "nonceConsumptionReceipt":
            recovered["nonceConsumptionReceipt"],
            "nonceRecoveryRequired":
            recovered["status"]
            in {"prepared", "consumptionPending"},
            "nonceStatusEvidence":
            recovered["nonceStatusEvidence"],
            "preparedOperation": prepared,
            "preparedOperationSha256": sha256_json(prepared),
            "recoveryKeySha256":
            prepared["recoveryKeySha256"],
            "recoveryIdentity": prepared["recoveryIdentity"],
            "recoveryIdentitySha256":
            prepared["recoveryIdentitySha256"],
            "replacementForbidden":
            recovered["status"] != "aborted",
            "requestBindingSha256":
            prepared["requestBindingSha256"],
            "status": recovered["status"],
        }

    def mark_consumption(
        self,
        request: Any,
        *,
        now: int,
    ) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {
                "apiVersion",
                "preparedOperationSha256",
                "recoveryKeySha256",
                "requestBindingSha256",
            },
            "verifier-state consumption marker",
        )
        require(
            value["apiVersion"] == MARK_CONSUMPTION_REQUEST_VERSION,
            "consumption marker version is invalid",
        )
        recovered, prepared = self._recovered_prepared(
            recovery_key_sha256=value["recoveryKeySha256"],
            request_binding_sha256=value["requestBindingSha256"],
        )
        require(
            recovered["status"]
            in {
                "prepared",
                "consumptionPending",
                "nonceConsumed",
                "casCommitted",
                "committed",
            }
            and value["preparedOperationSha256"]
            == sha256_json(prepared),
            "consumption marker crossed or followed an aborted operation",
        )
        marked = self._store_call(
            "mark_consumption_attempted",
            operation_id=prepared["authorization"]["payload"][
                "operationIdBase64url"
            ],
            recovery_key_sha256=prepared["recoveryKeySha256"],
            prepared_operation_sha256=sha256_json(prepared),
            nonce_consume_request_sha256=prepared[
                "nonceConsumeRequestSha256"
            ],
        )
        return {
            "apiVersion": MARK_CONSUMPTION_RESPONSE_VERSION,
            "nonActionable": True,
            **marked,
            "requestBindingSha256":
            prepared["requestBindingSha256"],
        }

    def attach_nonce_status(
        self,
        request: Any,
        *,
        now: int,
    ) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {
                "apiVersion",
                "nonceConsumptionReceipt",
                "nonceStatusEvidence",
                "preparedOperationSha256",
                "recoveryKeySha256",
                "requestBindingSha256",
            },
            "verifier-state nonce-status attachment",
        )
        require(
            value["apiVersion"]
            == ATTACH_NONCE_STATUS_REQUEST_VERSION,
            "nonce-status attachment version is invalid",
        )
        recovered, prepared = self._recovered_prepared(
            recovery_key_sha256=value["recoveryKeySha256"],
            request_binding_sha256=value["requestBindingSha256"],
        )
        require(
            recovered["status"]
            in {
                "consumptionPending",
                "nonceConsumed",
                "casCommitted",
                "committed",
            }
            and value["preparedOperationSha256"]
            == sha256_json(prepared),
            "nonce status was not preceded by the durable consumption marker",
        )
        status = self.nonce_authority.validate_status_evidence(
            value["nonceStatusEvidence"],
            prepared_operation=prepared,
            nonce_consumption_receipt=value[
                "nonceConsumptionReceipt"
            ],
            now=now,
        )
        receipt = value["nonceConsumptionReceipt"]
        if status["payload"]["status"] == "consumed":
            authorization_payload = prepared["authorization"]["payload"]
            verified_receipt = self.nonce_authority.validate(
                receipt,
                assurance=self.assurance,
                assurance_sha256=self.assurance_sha256,
                authorization_payload=authorization_payload,
                authorization_sha256=prepared[
                    "authorizationSha256"
                ],
                now=None,
            )
            require(
                verified_receipt["receiptSha256"]
                == status["payload"][
                    "nonceConsumptionReceiptSha256"
                ]
                and verified_receipt["payload"][
                    "consumeRequestSha256"
                ]
                == prepared["nonceConsumeRequestSha256"],
                "nonce status did not carry the exact prepared receipt",
            )
        retained = self._store_call(
            "attach_nonce_status",
            operation_id=prepared["authorization"]["payload"][
                "operationIdBase64url"
            ],
            recovery_key_sha256=prepared["recoveryKeySha256"],
            prepared_operation_sha256=sha256_json(prepared),
            nonce_status_evidence=status["document"],
            nonce_consumption_receipt=receipt,
        )
        return {
            "apiVersion": ATTACH_NONCE_STATUS_RESPONSE_VERSION,
            "nonActionable": True,
            **retained,
            "preparedOperationSha256": sha256_json(prepared),
            "recoveryKeySha256": prepared["recoveryKeySha256"],
            "requestBindingSha256":
            prepared["requestBindingSha256"],
        }

    def abort(self, request: Any, *, now: int) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {
                "apiVersion",
                "nonceStatusEvidence",
                "preparedOperationSha256",
                "recoveryKeySha256",
                "requestBindingSha256",
            },
            "verifier-state abort request",
        )
        require(
            value["apiVersion"] == ABORT_REQUEST_VERSION,
            "abort request version is invalid",
        )
        recovered, prepared = self._recovered_prepared(
            recovery_key_sha256=value["recoveryKeySha256"],
            request_binding_sha256=value["requestBindingSha256"],
        )
        require(
            recovered["status"]
            in {"prepared", "consumptionPending", "aborted"}
            and value["preparedOperationSha256"]
            == sha256_json(prepared),
            "abort crossed a consumed or committed operation",
        )
        status = self.nonce_authority.validate_status_evidence(
            value["nonceStatusEvidence"],
            prepared_operation=prepared,
            nonce_consumption_receipt=None,
            now=now,
        )
        require(
            status["payload"]["status"] == "neverConsumed"
            and status["payload"]["neverConsumable"] is True,
            "abort lacks an irrevocable never-consumed nonce tombstone",
        )
        retained = self._store_call(
            "abort_prepared",
            operation_id=prepared["authorization"]["payload"][
                "operationIdBase64url"
            ],
            recovery_key_sha256=prepared["recoveryKeySha256"],
            prepared_operation_sha256=sha256_json(prepared),
            nonce_status_evidence=status["document"],
        )
        return {
            "apiVersion": ABORT_RESPONSE_VERSION,
            "nonActionable": True,
            "operationIdBase64url":
            prepared["authorization"]["payload"][
                "operationIdBase64url"
            ],
            "preparedOperationSha256": sha256_json(prepared),
            "recoveryKeySha256": prepared["recoveryKeySha256"],
            "replacementForbidden": False,
            "requestBindingSha256":
            prepared["requestBindingSha256"],
            "status": "aborted",
            **retained,
        }

    def _validated_authorization(
        self,
        document: Any,
        *,
        challenge: bytes,
        now: int | None,
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        envelope = verify_envelope(
            document,
            api_version=AUTHORIZATION_VERSION,
            domain=AUTHORIZATION_DOMAIN,
            signer=self.signer,
            label="current-head authorization",
        )
        payload = exact(
            envelope["payload"],
            {
                "apiVersion",
                "assuranceSha256",
                "authorityEpoch",
                "authorityGeneration",
                "expiresAtUnix",
                "highWaterCommitmentSha256",
                "highWaterReceiptSha256",
                "highWaterSequence",
                "issuedAtUnix",
                "nonceReceiptSigningKeySpkiSha256",
                "nonceTransactionIdBase64url",
                "oneUse",
                "operationIdBase64url",
                "prepareRequestSha256",
                "priorCommittedAtUnix",
                "priorVerifierStateSha256",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
                "requestBindingSha256",
                "stateStoreGeneration",
                "stateStoreHeadSha256",
                "stateStoreAssuranceEvidenceSha256",
                "stateStoreAttestationKeySpkiSha256",
                "stateStoreConfigurationSha256",
                "stateStoreIdentitySha256",
                "verifierChallengeSha256",
            },
            "current-head authorization payload",
        )
        issued = require_uint(payload["issuedAtUnix"], "authorization issue time", positive=True)
        expires = require_uint(payload["expiresAtUnix"], "authorization expiry", positive=True)
        b64url_decode(payload["operationIdBase64url"], "authorization operation ID", exact_bytes=32)
        b64url_decode(
            payload["nonceTransactionIdBase64url"],
            "authorization nonce transaction",
            exact_bytes=32,
        )
        for field in (
            "prepareRequestSha256",
            "recoveryIdentitySha256",
            "recoveryKeySha256",
            "requestBindingSha256",
        ):
            require_sha256(
                payload[field],
                f"authorization {field}",
            )
        require(
            payload["apiVersion"] == AUTHORIZATION_VERSION
            and payload["assuranceSha256"] == self.assurance_sha256
            and payload["authorityEpoch"] == self.assurance["authorityEpoch"]
            and payload["authorityGeneration"] == self.assurance["authorityGeneration"]
            and payload["stateStoreIdentitySha256"] == self.store.store_identity_sha256
            and payload["stateStoreAttestationKeySpkiSha256"]
            == self.store.attestation_key_id
            and payload["stateStoreAssuranceEvidenceSha256"]
            == self.store.assurance_evidence_sha256
            and payload["stateStoreConfigurationSha256"]
            == self.store.configuration_sha256
            and payload["nonceReceiptSigningKeySpkiSha256"]
            == self.nonce_authority.key_id
            and require_uint(
                payload["priorCommittedAtUnix"],
                "authorization prior commit time",
                positive=True,
            )
            <= issued
            and issued < expires
            and expires - issued
            == self.authorization_lifetime_seconds
            and payload["verifierChallengeSha256"] == sha256_bytes(challenge)
            and payload["nonceTransactionIdBase64url"]
            == payload["operationIdBase64url"]
            and payload["oneUse"] is True
            and (
                now is None
                or issued <= now < expires
            )
            and issued < expires
            and expires - issued <= MAX_AUTHORIZATION_SECONDS,
            "current-head authorization is stale or crossed",
        )
        return envelope, payload, sha256_json(envelope)

    def _validated_nonce_successor(
        self,
        signed_nonce_receipt: dict[str, Any],
        *,
        authorization_payload: dict[str, Any],
        authorization_sha256: str,
        now: int | None,
    ) -> dict[str, Any]:
        return self.nonce_authority.validate(
            signed_nonce_receipt,
            assurance=self.assurance,
            assurance_sha256=self.assurance_sha256,
            authorization_payload=authorization_payload,
            authorization_sha256=authorization_sha256,
            now=now,
        )

    def _validated_recovered_commit_receipt(
        self,
        document: Any,
        *,
        authorization_payload: dict[str, Any],
        authorization_sha256: str,
        commit_request_sha256: str,
        commit_candidate: dict[str, Any],
        nonce_transition: dict[str, Any],
        challenge: bytes,
        now: int,
    ) -> dict[str, Any]:
        envelope = verify_envelope(
            document,
            api_version=COMMIT_RECEIPT_VERSION,
            domain=COMMIT_RECEIPT_DOMAIN,
            signer=self.signer,
            label="recovered verifier-state commit receipt",
        )
        payload = exact(
            envelope["payload"],
            {
                "apiVersion",
                "assuranceSha256",
                "authorizationSha256",
                "casCommitted",
                "commitOperationIdBase64url",
                "commitRequestSha256",
                "committedAtUnix",
                "committedVerifierState",
                "committedVerifierStateSha256",
                "nonceAuthorityStateSha256",
                "nonceConsumptionReceiptSha256",
                "nonceConsumptionSha256",
                "nonceReceiptSigningKeySpkiSha256",
                "oneUseAuthorizationConsumed",
                "preparedOperationSha256",
                "previousStateStoreGeneration",
                "previousStateStoreHeadSha256",
                "priorVerifierStateSha256",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
                "requestBindingSha256",
                "signedStoreCommitProof",
                "signedStoreCommitProofSha256",
                "stateStoreAdministrativeDomainSha256",
                "stateStoreAssuranceEvidenceSha256",
                "stateStoreAttestationKeySpkiSha256",
                "stateStoreCommitIndex",
                "stateStoreConfigurationSha256",
                "stateStoreGeneration",
                "stateStoreIdentitySha256",
                "verifierChallengeSha256",
            },
            "recovered verifier-state commit receipt payload",
        )
        committed_at = require_uint(
            payload["committedAtUnix"],
            "recovered commit time",
            positive=True,
        )
        store_proof = self._validated_store_commit_proof(
            payload["signedStoreCommitProof"],
            authorization_payload=authorization_payload,
            authorization_sha256=authorization_sha256,
            commit_request_sha256=commit_request_sha256,
            commit_candidate=commit_candidate,
            nonce_transition=nonce_transition,
            now=now,
        )
        expected_state = store_proof["committedState"]
        retained_prepared = self._recover_store(
            recovery_key_sha256=authorization_payload[
                "recoveryKeySha256"
            ],
            request_binding_sha256=authorization_payload[
                "requestBindingSha256"
            ],
        )["preparedOperation"]
        require(
            payload["apiVersion"] == COMMIT_RECEIPT_VERSION
            and payload["assuranceSha256"]
            == self.assurance_sha256
            and payload["authorizationSha256"]
            == authorization_sha256
            and payload["casCommitted"] is True
            and payload["commitOperationIdBase64url"]
            == authorization_payload["operationIdBase64url"]
            and payload["commitRequestSha256"]
            == commit_request_sha256
            and committed_at
            == store_proof["payload"]["committedAtUnix"]
            and payload["committedVerifierState"]
            == expected_state
            and payload["committedVerifierStateSha256"]
            == sha256_json(expected_state)
            and payload["nonceAuthorityStateSha256"]
            == nonce_transition["stateSha256"]
            and payload["nonceConsumptionReceiptSha256"]
            == nonce_transition["receiptSha256"]
            and payload["nonceConsumptionSha256"]
            == nonce_transition["consumptionSha256"]
            and payload["nonceReceiptSigningKeySpkiSha256"]
            == self.nonce_authority.key_id
            and payload["oneUseAuthorizationConsumed"] is True
            and payload["preparedOperationSha256"]
            == sha256_json(retained_prepared)
            and payload["previousStateStoreGeneration"]
            == authorization_payload["stateStoreGeneration"]
            and payload["previousStateStoreHeadSha256"]
            == authorization_payload["stateStoreHeadSha256"]
            and payload["priorVerifierStateSha256"]
            == authorization_payload["priorVerifierStateSha256"]
            and payload["recoveryKeySha256"]
            == authorization_payload["recoveryKeySha256"]
            and payload["recoveryIdentitySha256"]
            == authorization_payload["recoveryIdentitySha256"]
            and payload["requestBindingSha256"]
            == authorization_payload["requestBindingSha256"]
            and payload["signedStoreCommitProofSha256"]
            == store_proof["envelopeSha256"]
            and payload["stateStoreAdministrativeDomainSha256"]
            == self.store.administrative_domain_sha256
            and payload["stateStoreAssuranceEvidenceSha256"]
            == self.store.assurance_evidence_sha256
            and payload["stateStoreConfigurationSha256"]
            == self.store.configuration_sha256
            and payload["stateStoreGeneration"]
            == commit_candidate["proposedStateStoreGeneration"]
            and payload["stateStoreCommitIndex"]
            == payload["stateStoreGeneration"]
            and payload["stateStoreAttestationKeySpkiSha256"]
            == self.store.attestation_key_id
            and payload["stateStoreIdentitySha256"]
            == self.store.store_identity_sha256
            and payload["verifierChallengeSha256"]
            == sha256_bytes(challenge)
            and nonce_transition["payload"]["consumedAtUnix"]
            <= committed_at
            and committed_at <= now,
            "recovered CAS receipt differs from its authorized transition",
        )
        return envelope

    def _validated_recovered_commit_receipt_or_unknown(
        self,
        document: Any,
        *,
        authorization_payload: dict[str, Any],
        authorization_sha256: str,
        commit_request_sha256: str,
        commit_candidate: dict[str, Any],
        nonce_transition: dict[str, Any],
        challenge: bytes,
        now: int,
    ) -> dict[str, Any]:
        try:
            return self._validated_recovered_commit_receipt(
                document,
                authorization_payload=authorization_payload,
                authorization_sha256=authorization_sha256,
                commit_request_sha256=commit_request_sha256,
                commit_candidate=commit_candidate,
                nonce_transition=nonce_transition,
                challenge=challenge,
                now=now,
            )
        except UnknownOutcomeError:
            raise
        except Exception as exc:
            raise UnknownOutcomeError(
                "retained post-CAS artifacts are invalid; recover only "
                "this operation ID",
                operation_id=authorization_payload[
                    "operationIdBase64url"
                ],
                commit_request_sha256=commit_request_sha256,
            ) from exc

    def _build_commit_candidate(
        self,
        *,
        authorization_payload: dict[str, Any],
        authorization_sha256: str,
        commit_request_sha256: str,
        nonce_transition: dict[str, Any],
        prior_committed_at: int,
    ) -> dict[str, Any]:
        next_generation = checked_add_uint(
            authorization_payload["stateStoreGeneration"],
            1,
            "state-store generation",
        )
        proposed_head = state_head_commitment(
            {
                "assuranceSha256": self.assurance_sha256,
                "authorizationSha256": authorization_sha256,
                "commitOperationIdBase64url":
                authorization_payload["operationIdBase64url"],
                "nonceAuthorityStateSha256":
                nonce_transition["stateSha256"],
                "nonceConsumptionReceiptSha256":
                nonce_transition["receiptSha256"],
                "previousStateStoreHeadSha256":
                authorization_payload["stateStoreHeadSha256"],
                "stateStoreGeneration": next_generation,
            }
        )
        return {
            "apiVersion": STORE_COMMIT_CANDIDATE_VERSION,
            "assuranceSha256": self.assurance_sha256,
            "authorizationSha256": authorization_sha256,
            "commitRequestSha256": commit_request_sha256,
            "expectedVerifierStateSha256":
            authorization_payload["priorVerifierStateSha256"],
            "nonceAuthorityStateSha256":
            nonce_transition["stateSha256"],
            "nonceConsumptionReceiptSha256":
            nonce_transition["receiptSha256"],
            "nonceConsumptionSha256":
            nonce_transition["consumptionSha256"],
            "operationIdBase64url":
            authorization_payload["operationIdBase64url"],
            "previousCommittedAtUnix": require_uint(
                prior_committed_at,
                "prior durable commit time",
                positive=True,
            ),
            "previousStateStoreGeneration":
            authorization_payload["stateStoreGeneration"],
            "previousStateStoreHeadSha256":
            authorization_payload["stateStoreHeadSha256"],
            "proposedStateStoreGeneration": next_generation,
            "proposedStateStoreHeadSha256": proposed_head,
            "verifierChallengeSha256":
            authorization_payload["verifierChallengeSha256"],
        }

    def _build_committed_state(
        self,
        *,
        authorization_payload: dict[str, Any],
        authorization_sha256: str,
        nonce_state: dict[str, Any],
        nonce_state_sha256: str,
        nonce_consumption_receipt_sha256: str,
        committed_at: int,
    ) -> dict[str, Any]:
        next_generation = checked_add_uint(
            authorization_payload["stateStoreGeneration"],
            1,
            "state-store generation",
        )
        head_preimage = {
            "assuranceSha256": self.assurance_sha256,
            "authorizationSha256": authorization_sha256,
            "commitOperationIdBase64url":
            authorization_payload["operationIdBase64url"],
            "nonceAuthorityStateSha256": nonce_state_sha256,
            "nonceConsumptionReceiptSha256":
            nonce_consumption_receipt_sha256,
            "previousStateStoreHeadSha256":
            authorization_payload["stateStoreHeadSha256"],
            "stateStoreGeneration": next_generation,
        }
        return {
            "apiVersion": STATE_VERSION,
            "assuranceSha256": self.assurance_sha256,
            "authorityEpoch": self.assurance["authorityEpoch"],
            "authorityGeneration":
            self.assurance["authorityGeneration"],
            "commitOperationIdBase64url":
            authorization_payload["operationIdBase64url"],
            "committedAtUnix": require_uint(
                committed_at,
                "commit time",
                positive=True,
            ),
            "highWaterCommitmentSha256":
            nonce_state["highWaterCommitmentSha256"],
            "highWaterReceiptSha256":
            nonce_consumption_receipt_sha256,
            "highWaterSequence": nonce_state["highWaterSequence"],
            "priorVerifierStateSha256":
            authorization_payload["priorVerifierStateSha256"],
            "stateStoreGeneration": next_generation,
            "stateStoreHeadSha256":
            state_head_commitment(head_preimage),
            "stateStoreIdentitySha256":
            self.store.store_identity_sha256,
        }

    def _validated_store_commit_proof(
        self,
        document: Any,
        *,
        authorization_payload: dict[str, Any],
        authorization_sha256: str,
        commit_request_sha256: str,
        commit_candidate: dict[str, Any],
        nonce_transition: dict[str, Any],
        now: int,
    ) -> dict[str, Any]:
        envelope = verify_pinned_envelope(
            document,
            api_version=SIGNED_STORE_COMMIT_PROOF_VERSION,
            domain=STORE_COMMIT_PROOF_DOMAIN,
            public_key=self.store.attestation_public_key,
            key_id=self.store.attestation_key_id,
            label="signed rollback-resistant store commit proof",
        )
        proof = exact(
            envelope["payload"],
            {
                "apiVersion",
                "authorizationSha256",
                "casCommitted",
                "commitCandidateSha256",
                "commitClockMonotonic",
                "commitRequestSha256",
                "committedAtUnix",
                "operationIdBase64url",
                "previousCommittedAtUnix",
                "previousVerifierStateSha256",
                "productionEligible",
                "stateStoreAdministrativeDomainSha256",
                "stateStoreAssuranceEvidenceSha256",
                "stateStoreAttestationKeySpkiSha256",
                "stateStoreCommitIndex",
                "stateStoreConfigurationSha256",
                "stateStoreGeneration",
                "stateStoreIdentitySha256",
            },
            "rollback-resistant store commit proof",
        )
        # The durable CAS may cross a wall-clock second. Bound its signed
        # commit time against an observation made after receipt of the proof.
        now = self.observe_runtime_time()
        committed_at = require_uint(
            proof["committedAtUnix"],
            "durable store commit time",
            positive=True,
        )
        require(
            proof["apiVersion"] == STORE_COMMIT_PROOF_VERSION
            and proof["authorizationSha256"]
            == authorization_sha256
            and proof["casCommitted"] is True
            and proof["commitCandidateSha256"]
            == sha256_json(commit_candidate)
            and proof["commitClockMonotonic"] is True
            and proof["commitRequestSha256"]
            == commit_request_sha256
            and proof["operationIdBase64url"]
            == authorization_payload["operationIdBase64url"]
            and proof["previousCommittedAtUnix"]
            == commit_candidate["previousCommittedAtUnix"]
            and proof["previousVerifierStateSha256"]
            == authorization_payload["priorVerifierStateSha256"]
            and proof["productionEligible"]
            is (self.mode == "production")
            and proof["stateStoreAdministrativeDomainSha256"]
            == self.store.administrative_domain_sha256
            and proof["stateStoreAssuranceEvidenceSha256"]
            == self.store.assurance_evidence_sha256
            and proof["stateStoreConfigurationSha256"]
            == self.store.configuration_sha256
            and proof["stateStoreGeneration"]
            == commit_candidate["proposedStateStoreGeneration"]
            and proof["stateStoreCommitIndex"]
            == proof["stateStoreGeneration"]
            and proof["stateStoreGeneration"]
            >= self.store.minimum_generation
            and proof["stateStoreCommitIndex"]
            >= self.store.minimum_commit_index
            and proof["stateStoreAttestationKeySpkiSha256"]
            == self.store.attestation_key_id
            and proof["stateStoreIdentitySha256"]
            == self.store.store_identity_sha256
            and commit_candidate["previousCommittedAtUnix"]
            <= committed_at
            and nonce_transition["payload"]["consumedAtUnix"]
            <= committed_at
            and committed_at <= now,
            "store commit proof crossed or did not durably commit the candidate",
        )
        committed_state = self._build_committed_state(
            authorization_payload=authorization_payload,
            authorization_sha256=authorization_sha256,
            nonce_state=nonce_transition["state"],
            nonce_state_sha256=nonce_transition["stateSha256"],
            nonce_consumption_receipt_sha256=(
                nonce_transition["receiptSha256"]
            ),
            committed_at=committed_at,
        )
        require(
            committed_state["stateStoreGeneration"]
            == commit_candidate["proposedStateStoreGeneration"]
            and committed_state["stateStoreHeadSha256"]
            == commit_candidate["proposedStateStoreHeadSha256"],
            "store proof candidate cannot reconstruct the exact successor",
        )
        return {
            "document": envelope,
            "envelopeSha256": sha256_json(envelope),
            "payload": proof,
            "committedState": committed_state,
        }

    def _finalize_committed_candidate(
        self,
        *,
        commit_proof: dict[str, Any],
        commit_request_sha256: str,
        commit_candidate: dict[str, Any],
        authorization_payload: dict[str, Any],
        authorization_sha256: str,
        nonce_transition: dict[str, Any],
        challenge: bytes,
        now: int,
    ) -> dict[str, Any]:
        try:
            verified_proof = self._validated_store_commit_proof(
                commit_proof,
                authorization_payload=authorization_payload,
                authorization_sha256=authorization_sha256,
                commit_request_sha256=commit_request_sha256,
                commit_candidate=commit_candidate,
                nonce_transition=nonce_transition,
                now=now,
            )
            committed_state = verified_proof["committedState"]
            next_signed_state = self._sign_envelope(
                api_version=SIGNED_STATE_VERSION,
                domain=STATE_DOMAIN,
                payload=committed_state,
                ambiguous_mutation=True,
            )
            receipt_payload = {
                "apiVersion": COMMIT_RECEIPT_VERSION,
                "assuranceSha256": self.assurance_sha256,
                "authorizationSha256": authorization_sha256,
                "casCommitted": True,
                "commitOperationIdBase64url":
                authorization_payload["operationIdBase64url"],
                "commitRequestSha256": commit_request_sha256,
                "committedAtUnix":
                committed_state["committedAtUnix"],
                "committedVerifierState": committed_state,
                "committedVerifierStateSha256":
                sha256_json(committed_state),
                "nonceAuthorityStateSha256":
                nonce_transition["stateSha256"],
                "nonceConsumptionReceiptSha256":
                nonce_transition["receiptSha256"],
                "nonceConsumptionSha256":
                nonce_transition["consumptionSha256"],
                "nonceReceiptSigningKeySpkiSha256":
                self.nonce_authority.key_id,
                "oneUseAuthorizationConsumed": True,
                "preparedOperationSha256":
                sha256_json(
                    self._recover_store(
                        recovery_key_sha256=authorization_payload[
                            "recoveryKeySha256"
                        ],
                        request_binding_sha256=authorization_payload[
                            "requestBindingSha256"
                        ],
                    )["preparedOperation"]
                ),
                "previousStateStoreGeneration":
                authorization_payload["stateStoreGeneration"],
                "previousStateStoreHeadSha256":
                authorization_payload["stateStoreHeadSha256"],
                "priorVerifierStateSha256":
                authorization_payload["priorVerifierStateSha256"],
                "recoveryIdentitySha256":
                authorization_payload["recoveryIdentitySha256"],
                "recoveryKeySha256":
                authorization_payload["recoveryKeySha256"],
                "requestBindingSha256":
                authorization_payload["requestBindingSha256"],
                "signedStoreCommitProof":
                verified_proof["document"],
                "signedStoreCommitProofSha256":
                verified_proof["envelopeSha256"],
                "stateStoreAdministrativeDomainSha256":
                self.store.administrative_domain_sha256,
                "stateStoreAssuranceEvidenceSha256":
                self.store.assurance_evidence_sha256,
                "stateStoreAttestationKeySpkiSha256":
                self.store.attestation_key_id,
                "stateStoreCommitIndex":
                verified_proof["payload"]["stateStoreCommitIndex"],
                "stateStoreConfigurationSha256":
                self.store.configuration_sha256,
                "stateStoreGeneration":
                verified_proof["payload"]["stateStoreGeneration"],
                "stateStoreIdentitySha256":
                self.store.store_identity_sha256,
                "verifierChallengeSha256":
                sha256_bytes(challenge),
            }
            commit_receipt = self._sign_envelope(
                api_version=COMMIT_RECEIPT_VERSION,
                domain=COMMIT_RECEIPT_DOMAIN,
                payload=receipt_payload,
                ambiguous_mutation=True,
            )
            proof_sha256 = verified_proof["envelopeSha256"]
            try:
                retained = self._store_call(
                    "finalize_commit",
                    operation_id=authorization_payload[
                        "operationIdBase64url"
                    ],
                    commit_request_sha256=commit_request_sha256,
                    commit_proof_sha256=proof_sha256,
                    next_state=next_signed_state,
                    commit_receipt=commit_receipt,
                )
            except Exception:
                recovered = self._recover_store(
                    recovery_key_sha256=authorization_payload[
                        "recoveryKeySha256"
                    ],
                    request_binding_sha256=authorization_payload[
                        "requestBindingSha256"
                    ],
                    operation_id=authorization_payload[
                        "operationIdBase64url"
                    ],
                    commit_request_sha256=commit_request_sha256,
                )
                if recovered["status"] == "committed":
                    retained = recovered["commitReceipt"]
                elif (
                    recovered["status"] == "casCommitted"
                    and recovered["commitProof"]
                    == verified_proof["document"]
                ):
                    retained = self._store_call(
                        "finalize_commit",
                        ambiguous_mutation=True,
                        operation_id=authorization_payload[
                            "operationIdBase64url"
                        ],
                        commit_request_sha256=commit_request_sha256,
                        commit_proof_sha256=proof_sha256,
                        next_state=next_signed_state,
                        commit_receipt=commit_receipt,
                    )
                else:
                    raise UnknownOutcomeError(
                        "commit finalization outcome remains unknown"
                    )
            require(
                retained == commit_receipt,
                "state store substituted finalized commit artifacts",
            )
            return commit_receipt
        except UnknownOutcomeError:
            raise
        except Exception as exc:
            raise UnknownOutcomeError(
                "post-CAS signing, validation, finalization, or recovery "
                "failed; recover only this operation ID"
            ) from exc

    def commit(self, request: Any, *, now: int) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {
                "apiVersion",
                "authorization",
                "nonceConsumptionReceipt",
                "preparedOperationSha256",
                "recoveryKeySha256",
                "requestBindingSha256",
                "verifierChallengeBase64url",
            },
            "verifier-state commit request",
        )
        require(
            value["apiVersion"] == COMMIT_REQUEST_VERSION,
            "commit request version is invalid",
        )
        recovered, prepared = self._recovered_prepared(
            recovery_key_sha256=value["recoveryKeySha256"],
            request_binding_sha256=value["requestBindingSha256"],
        )
        require(
            recovered["status"]
            in {"nonceConsumed", "casCommitted", "committed"}
            and value["preparedOperationSha256"]
            == sha256_json(prepared)
            and value["authorization"] == prepared["authorization"]
            and value["nonceConsumptionReceipt"]
            == recovered["nonceConsumptionReceipt"],
            "commit request is not the exact durably prepared consumed saga",
        )
        challenge = b64url_decode(
            value["verifierChallengeBase64url"],
            "verifier challenge",
            exact_bytes=32,
        )
        authorization, authorization_payload, authorization_sha256 = (
            self._validated_authorization(
                prepared["authorization"],
                challenge=challenge,
                now=None,
            )
        )
        require(
            challenge
            == b64url_decode(
                prepared["prepareRequest"][
                    "verifierChallengeBase64url"
                ],
                "prepared verifier challenge",
                exact_bytes=32,
            ),
            "commit request substituted the prepared challenge",
        )
        nonce_transition = self._validated_nonce_successor(
            recovered["nonceConsumptionReceipt"],
            authorization_payload=authorization_payload,
            authorization_sha256=authorization_sha256,
            now=None,
        )
        require(
            nonce_transition["payload"]["consumeRequestSha256"]
            == prepared["nonceConsumeRequestSha256"],
            "commit receipt crossed the prepared nonce request",
        )
        operation_id = authorization_payload["operationIdBase64url"]
        commit_request_sha256 = sha256_json(value)
        commit_candidate = self._build_commit_candidate(
            authorization_payload=authorization_payload,
            authorization_sha256=authorization_sha256,
            commit_request_sha256=commit_request_sha256,
            nonce_transition=nonce_transition,
            prior_committed_at=authorization_payload[
                "priorCommittedAtUnix"
            ],
        )
        if recovered["status"] == "committed":
            return self._validated_recovered_commit_receipt_or_unknown(
                recovered["commitReceipt"],
                authorization_payload=authorization_payload,
                authorization_sha256=authorization_sha256,
                commit_request_sha256=commit_request_sha256,
                commit_candidate=commit_candidate,
                nonce_transition=nonce_transition,
                challenge=challenge,
                now=self.observe_runtime_time(),
            )
        if recovered["status"] == "casCommitted":
            return self._finalize_committed_candidate(
                commit_proof=recovered["commitProof"],
                commit_request_sha256=commit_request_sha256,
                commit_candidate=commit_candidate,
                authorization_payload=authorization_payload,
                authorization_sha256=authorization_sha256,
                nonce_transition=nonce_transition,
                challenge=challenge,
                now=self.observe_runtime_time(),
            )
        _prior_envelope, prior, prior_sha256 = (
            self._verified_current_state()
        )
        require(
            authorization_payload["priorVerifierStateSha256"]
            == prior_sha256
            and authorization_payload["stateStoreGeneration"]
            == prior["stateStoreGeneration"]
            and authorization_payload["stateStoreHeadSha256"]
            == prior["stateStoreHeadSha256"]
            and authorization_payload["highWaterSequence"]
            == prior["highWaterSequence"]
            and authorization_payload["highWaterCommitmentSha256"]
            == prior["highWaterCommitmentSha256"]
            and authorization_payload["highWaterReceiptSha256"]
            == prior["highWaterReceiptSha256"]
            and authorization_payload["priorCommittedAtUnix"]
            == prior["committedAtUnix"],
            "prepared predecessor is no longer the exact current head",
        )
        try:
            commit_proof = self._store_call(
                "commit_candidate",
                operation_id=operation_id,
                commit_request_sha256=commit_request_sha256,
                authorization=authorization,
                expected_state_sha256=prior_sha256,
                commit_candidate=commit_candidate,
            )
        except ConflictError:
            raise
        except Exception:
            recovered = self._recover_store(
                recovery_key_sha256=prepared["recoveryKeySha256"],
                request_binding_sha256=prepared[
                    "requestBindingSha256"
                ],
                operation_id=operation_id,
                commit_request_sha256=commit_request_sha256,
            )
            if recovered["status"] == "committed":
                return self._validated_recovered_commit_receipt_or_unknown(
                    recovered["commitReceipt"],
                    authorization_payload=authorization_payload,
                    authorization_sha256=authorization_sha256,
                    commit_request_sha256=commit_request_sha256,
                    commit_candidate=commit_candidate,
                    nonce_transition=nonce_transition,
                    challenge=challenge,
                    now=self.observe_runtime_time(),
                )
            if recovered["status"] != "casCommitted":
                raise UnknownOutcomeError(
                    "CAS outcome remains unknown; recover only the "
                    "deterministic operation"
                )
            commit_proof = recovered["commitProof"]
        return self._finalize_committed_candidate(
            commit_proof=commit_proof,
            commit_request_sha256=commit_request_sha256,
            commit_candidate=commit_candidate,
            authorization_payload=authorization_payload,
            authorization_sha256=authorization_sha256,
            nonce_transition=nonce_transition,
            challenge=challenge,
            now=self.observe_runtime_time(),
        )

    def recover(self, request: Any, *, now: int) -> dict[str, Any]:
        self._validate_production_evidence(now)
        value = exact(
            request,
            {
                "apiVersion",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
            },
            "operation recovery request",
        )
        require(
            value["apiVersion"] == RECOVERY_REQUEST_VERSION,
            "recovery request version is invalid",
        )
        recovered, prepared = self._recovered_prepared(
            recovery_key_sha256=value["recoveryKeySha256"],
            recovery_identity=value["recoveryIdentity"],
            recovery_identity_sha256=value[
                "recoveryIdentitySha256"
            ],
        )
        receipt = recovered["commitReceipt"]
        status = recovered["status"]
        commit_request_sha256: str | None = None
        if status in {"nonceConsumed", "casCommitted"}:
            commit_request = {
                "apiVersion": COMMIT_REQUEST_VERSION,
                "authorization": prepared["authorization"],
                "nonceConsumptionReceipt":
                recovered["nonceConsumptionReceipt"],
                "preparedOperationSha256": sha256_json(prepared),
                "recoveryKeySha256":
                prepared["recoveryKeySha256"],
                "requestBindingSha256":
                prepared["requestBindingSha256"],
                "verifierChallengeBase64url":
                prepared["prepareRequest"][
                    "verifierChallengeBase64url"
                ],
            }
            commit_request_sha256 = sha256_json(commit_request)
            receipt = self.commit(
                commit_request,
                now=self.observe_runtime_time(),
            )
            status = "committed"
        elif status == "committed":
            retained_commit_request = {
                "apiVersion": COMMIT_REQUEST_VERSION,
                "authorization": prepared["authorization"],
                "nonceConsumptionReceipt":
                recovered["nonceConsumptionReceipt"],
                "preparedOperationSha256": sha256_json(prepared),
                "recoveryKeySha256":
                prepared["recoveryKeySha256"],
                "requestBindingSha256":
                prepared["requestBindingSha256"],
                "verifierChallengeBase64url":
                prepared["prepareRequest"][
                    "verifierChallengeBase64url"
                ],
            }
            commit_request_sha256 = sha256_json(
                retained_commit_request
            )
            receipt = self.commit(
                retained_commit_request,
                now=self.observe_runtime_time(),
            )
        return {
            "apiVersion": RECOVERY_RESPONSE_VERSION,
            "commitReceipt": receipt,
            "commitRequestSha256": commit_request_sha256,
            "nonActionable": True,
            "nonceConsumptionReceipt":
            recovered["nonceConsumptionReceipt"],
            "nonceRecoveryRequired":
            status in {"prepared", "consumptionPending"},
            "nonceStatusEvidence":
            recovered["nonceStatusEvidence"],
            "operationIdBase64url":
            prepared["authorization"]["payload"][
                "operationIdBase64url"
            ],
            "preparedOperation": prepared,
            "preparedOperationSha256": sha256_json(prepared),
            "recoveryKeySha256": prepared["recoveryKeySha256"],
            "recoveryIdentity": prepared["recoveryIdentity"],
            "recoveryIdentitySha256":
            prepared["recoveryIdentitySha256"],
            "replacementForbidden": status != "aborted",
            "requestBindingSha256":
            prepared["requestBindingSha256"],
            "sameOperationOnly": status != "aborted",
            "status": status,
        }


class ServiceHandler(http.server.BaseHTTPRequestHandler):
    server: "VerifierStateHttpServer"
    protocol_version = "HTTP/1.1"

    def _reset_request_io_timeout(
        self,
        cap_seconds: float | None = None,
    ) -> None:
        remaining = self.server.remaining_request_seconds()
        self.connection.settimeout(
            remaining
            if cap_seconds is None
            else min(cap_seconds, remaining)
        )

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        del message, explain
        body = canonical_json(
            {
                "error": "httpRejected",
                "message": "HTTP request rejected",
                "nonActionable": True,
            }
        )
        self.send_response_only(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self._reset_request_io_timeout()
        self.end_headers()
        if self.command != "HEAD":
            self._reset_request_io_timeout()
            self.wfile.write(body)

    def handle_expect_100(self) -> bool:
        self.send_error(417)
        return False

    def do_POST(self) -> None:
        document: Any = None
        self.close_connection = True
        try:
            self.server.validate_live_peer(self.connection)
            allowed_paths = {
                "/v1/state/read",
                "/v1/state/issue-challenge",
                "/v1/state/recover-challenge",
                "/v1/state/prepare",
                "/v1/state/recovery-lookup",
                "/v1/state/mark-consumption",
                "/v1/state/attach-nonce-status",
                "/v1/state/abort",
                "/v1/state/commit",
                "/v1/state/recover",
            }
            require(
                self.path in allowed_paths
                and "?" not in self.path
                and "#" not in self.path,
                "unknown or query-bearing verifier-state endpoint",
            )
            require(
                self.request_version == "HTTP/1.1"
                and len(self.requestline.encode("ascii"))
                <= 2048
                and len(self.headers.items()) <= 64
                and len(self.headers.as_bytes())
                <= MAX_HEADER_BYTES,
                "HTTP version or header count is invalid",
            )
            host_headers = self.headers.get_all("Host")
            require(
                host_headers == [
                    self.server.expected_host_authority
                ],
                "Host authority is absent, duplicated, or unexpected",
            )
            require(
                not self.headers.get_all("Transfer-Encoding"),
                "Transfer-Encoding is forbidden",
            )
            require(
                not self.headers.get_all("Trailer")
                and not self.headers.get_all("Content-Encoding")
                and not self.headers.get_all("Upgrade")
                and not self.headers.get_all("Expect"),
                "trailers, encodings, upgrades, and expectations are forbidden",
            )
            require(
                self.headers.get_all("Content-Type")
                == ["application/json"],
                "Content-Type must be exactly application/json",
            )
            content_lengths = self.headers.get_all("Content-Length")
            require(
                content_lengths is not None
                and len(content_lengths) == 1
                and re.fullmatch(
                    r"[1-9][0-9]*",
                    content_lengths[0],
                    re.ASCII,
                )
                is not None,
                "Content-Length must be one canonical decimal value",
            )
            content_length = int(content_lengths[0])
            require(1 <= content_length <= MAX_JSON_BYTES, "request body size is invalid")
            self._reset_request_io_timeout(BODY_TIMEOUT_SECONDS)
            raw = self.rfile.read(content_length)
            require(len(raw) == content_length, "request body was truncated")
            if isinstance(self.connection, socket.socket):
                self.connection.setblocking(False)
                try:
                    trailing = self.connection.recv(
                        1,
                        socket.MSG_PEEK,
                    )
                except BlockingIOError:
                    trailing = b""
                finally:
                    self.connection.setblocking(True)
                    self._reset_request_io_timeout(
                        BODY_TIMEOUT_SECONDS
                    )
                require(
                    trailing == b"",
                    "request carried pipelined or trailing bytes",
                )
            document = parse_canonical_json(raw, label="HTTP request")
            now = self.server.service.observe_runtime_time()
            if self.path == "/v1/state/read":
                response = self.server.service.read_state(
                    document,
                    now=now,
                )
            elif self.path == "/v1/state/issue-challenge":
                response = self.server.service.issue_challenge(
                    document,
                    now=now,
                )
            elif self.path == "/v1/state/recover-challenge":
                response = self.server.service.recover_challenge(
                    document,
                    now=now,
                )
            elif self.path == "/v1/state/prepare":
                response = self.server.service.prepare(
                    document,
                    now=now,
                )
            elif self.path == "/v1/state/recovery-lookup":
                response = self.server.service.lookup_recovery(
                    document,
                    now=now,
                )
            elif self.path == "/v1/state/mark-consumption":
                response = self.server.service.mark_consumption(
                    document,
                    now=now,
                )
            elif self.path == "/v1/state/attach-nonce-status":
                response = self.server.service.attach_nonce_status(
                    document,
                    now=now,
                )
            elif self.path == "/v1/state/abort":
                response = self.server.service.abort(
                    document,
                    now=now,
                )
            elif self.path == "/v1/state/commit":
                response = self.server.service.commit(document, now=now)
            elif self.path == "/v1/state/recover":
                response = self.server.service.recover(
                    document,
                    now=now,
                )
            body = canonical_json(response)
            self.send_response(200)
        except ConflictError:
            self.close_connection = True
            body = canonical_json(
                {
                    "error": "conflict",
                    "message":
                    "verifier-state transition conflicts with the current head",
                    "nonActionable": True,
                }
            )
            self.send_response(409)
        except UnknownOutcomeError as exc:
            self.close_connection = True
            try:
                if (
                    exc.operation_id is None
                    and type(document) is dict
                ):
                    commit_request = (
                        document.get("commitRequest")
                        if self.path == "/v1/state/recover"
                        else document
                    )
                    if type(commit_request) is dict:
                        operation_id = commit_request.get(
                            "authorization",
                            {},
                        ).get("payload", {}).get(
                            "operationIdBase64url"
                        )
                        if type(operation_id) is str:
                            exc.bind_recovery(
                                operation_id=operation_id,
                                commit_request_sha256=sha256_json(
                                    commit_request
                                ),
                            )
            except (ContractError, AttributeError, TypeError):
                pass
            body = canonical_json(
                {
                    "commitRequestSha256":
                    exc.commit_request_sha256,
                    "error": "unknownOutcome",
                    "message":
                    "operation outcome is unknown; recover by operation ID",
                    "nonActionable": True,
                    "operationIdBase64url": exc.operation_id,
                    "recoveryRequired": True,
                    "replacementForbidden": True,
                    "sameOperationOnly": True,
                }
            )
            self.send_response(503)
        except (ContractError, ValueError):
            self.close_connection = True
            body = canonical_json(
                {
                    "error": "invalidRequest",
                    "message":
                    "request rejected by the closed verifier-state contract",
                    "nonActionable": True,
                }
            )
            self.send_response(400)
        except Exception:
            self.close_connection = True
            body = canonical_json(
                {
                    "error": "internalFailure",
                    "message": "verifier-state operation failed closed",
                    "nonActionable": True,
                }
            )
            self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            self.send_header("Connection", "close")
        self._reset_request_io_timeout()
        self.end_headers()
        self._reset_request_io_timeout()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


class VerifierStateHttpServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        service: VerifierStateService,
        *,
        listener_context: ssl.SSLContext | None,
        listener_peer_policy: "ListenerPeerPolicy | None",
        expected_host_authority: str,
        max_concurrent_requests: int,
    ) -> None:
        self.service = service
        self.listener_context = listener_context
        self.listener_peer_policy = listener_peer_policy
        require(
            type(expected_host_authority) is str
            and expected_host_authority
            and "/" not in expected_host_authority
            and "@" not in expected_host_authority,
            "expected listener Host authority is invalid",
        )
        self.expected_host_authority = expected_host_authority
        require(
            type(max_concurrent_requests) is int
            and 1 <= max_concurrent_requests <= 256,
            "max concurrent requests must be between 1 and 256",
        )
        self._request_slots = threading.BoundedSemaphore(
            max_concurrent_requests
        )
        self._request_deadline = threading.local()
        super().__init__(address, ServiceHandler)

    def remaining_request_seconds(self) -> float:
        deadline = getattr(self._request_deadline, "value", None)
        require(
            type(deadline) is float,
            "request total deadline is unavailable",
        )
        remaining = deadline - time.monotonic()
        require(remaining > 0, "request total deadline expired")
        return remaining

    def validate_live_peer(self, connection: Any) -> None:
        if self.listener_peer_policy is None:
            return
        require(
            isinstance(connection, ssl.SSLSocket),
            "production request did not use the configured TLS listener",
        )
        certificate_der = connection.getpeercert(binary_form=True)
        require(
            type(certificate_der) is bytes and certificate_der,
            "production request has no authenticated client certificate",
        )
        self.listener_peer_policy.validate_certificate_der(
            certificate_der
        )

    def process_request(
        self,
        request: Any,
        client_address: Any,
    ) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        thread = threading.Thread(
            target=self._bounded_request_thread,
            args=(request, client_address),
            daemon=self.daemon_threads,
        )
        thread.start()

    def _bounded_request_thread(
        self,
        request: Any,
        client_address: Any,
    ) -> None:
        admitted_request = request
        deadline = time.monotonic() + TOTAL_REQUEST_TIMEOUT_SECONDS
        self._request_deadline.value = deadline
        service_deadline_bound = False
        admitted_holder = [request]

        def expire_request() -> None:
            try:
                admitted_holder[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                admitted_holder[0].close()
            except OSError:
                pass

        deadline_timer = threading.Timer(
            TOTAL_REQUEST_TIMEOUT_SECONDS,
            expire_request,
        )
        deadline_timer.daemon = True
        deadline_timer.start()
        try:
            self.service.bind_ingress_deadline(deadline)
            service_deadline_bound = True
            request.settimeout(
                min(
                    HANDSHAKE_TIMEOUT_SECONDS,
                    self.remaining_request_seconds(),
                )
            )
            if self.listener_context is not None:
                admitted_request = self.listener_context.wrap_socket(
                    request,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
                admitted_holder[0] = admitted_request
                admitted_request.settimeout(
                    min(
                        HANDSHAKE_TIMEOUT_SECONDS,
                        self.remaining_request_seconds(),
                    )
                )
                admitted_request.do_handshake()
            admitted_request.settimeout(
                min(
                    HEADER_TIMEOUT_SECONDS,
                    self.remaining_request_seconds(),
                )
            )
            self.validate_live_peer(admitted_request)
            self.finish_request(admitted_request, client_address)
        except Exception:
            self.handle_error(admitted_request, client_address)
        finally:
            deadline_timer.cancel()
            self.shutdown_request(admitted_request)
            if service_deadline_bound:
                self.service.clear_ingress_deadline()
            self._request_slots.release()
            self._request_deadline.value = None


class ListenerPeerPolicy:
    def __init__(
        self,
        *,
        expected_spki_sha256: str,
        expected_spiffe_uri: str | None,
    ) -> None:
        self.expected_spki_sha256 = require_sha256(
            expected_spki_sha256,
            "expected listener client SPKI",
        )
        require(
            expected_spiffe_uri is None
            or (
                type(expected_spiffe_uri) is str
                and expected_spiffe_uri.startswith("spiffe://")
                and 10 <= len(expected_spiffe_uri) <= 512
            ),
            "expected listener client SPIFFE URI is invalid",
        )
        self.expected_spiffe_uri = expected_spiffe_uri

    def validate_certificate_der(self, certificate_der: bytes) -> None:
        try:
            certificate = x509.load_der_x509_certificate(
                certificate_der
            )
        except ValueError as exc:
            raise ContractError(
                "listener client certificate is malformed"
            ) from exc
        public_key_der = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        actual_spki_sha256 = sha256_bytes(public_key_der)
        require(
            hmac.compare_digest(
                actual_spki_sha256,
                self.expected_spki_sha256,
            ),
            "listener client certificate SPKI is not pinned",
        )
        if self.expected_spiffe_uri is not None:
            try:
                alternative_names = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
            except x509.ExtensionNotFound as exc:
                raise ContractError(
                    "listener client certificate has no SPIFFE SAN"
                ) from exc
            spiffe_uris = [
                value
                for value in alternative_names.get_values_for_type(
                    x509.UniformResourceIdentifier
                )
                if value.startswith("spiffe://")
            ]
            require(
                spiffe_uris == [self.expected_spiffe_uri],
                "listener client certificate SPIFFE identity is not exact",
            )


def load_config(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    require(raw.endswith(b"\n"), "service configuration must end in one LF")
    document = parse_canonical_json(raw[:-1], label="service configuration")
    return exact(
        document,
        {
            "apiVersion",
            "assurance",
            "assuranceSha256",
            "authorizationLifetimeSeconds",
            "listen",
            "listenerTls",
            "maxConcurrentRequests",
            "mode",
            "nonceAuthority",
            "nonceAuthorityAssuranceEvidenceIssuer",
            "roleSeparationEvidence",
            "roleSeparationEvidenceIssuer",
            "roleSeparationEvidenceSigningPublicKeySpkiDerBase64url",
            "signer",
            "stateStore",
        },
        "service configuration",
    )


def build_service(
    config: dict[str, Any],
) -> tuple[
    VerifierStateService,
    tuple[str, int],
    ssl.SSLContext | None,
    ListenerPeerPolicy | None,
    str,
    int,
]:
    require(config["apiVersion"] == SERVICE_CONFIG_VERSION, "service configuration version is invalid")
    listen = exact(
        config["listen"],
        {"expectedHostAuthority", "host", "port"},
        "service listen configuration",
    )
    require(type(listen["host"]) is str and listen["host"], "listen host is invalid")
    require(type(listen["port"]) is int and 1 <= listen["port"] <= 65535, "listen port is invalid")
    require(
        type(listen["expectedHostAuthority"]) is str
        and listen["expectedHostAuthority"]
        and "/" not in listen["expectedHostAuthority"]
        and "@" not in listen["expectedHostAuthority"],
        "expected Host authority is invalid",
    )
    max_concurrent_requests = require_uint(
        config["maxConcurrentRequests"],
        "max concurrent requests",
        positive=True,
    )
    require(
        max_concurrent_requests <= 256,
        "max concurrent requests exceeds 256",
    )
    mode = config["mode"]
    state_store = config["stateStore"]
    signer_config = config["signer"]

    def configured_role(
        value: Any,
        *,
        label: str,
        expected_key_spki_sha256: str,
    ) -> dict[str, Any]:
        role = exact(
            value,
            {
                "administrativeDomainSha256",
                "assuranceEvidenceSha256",
                "credentialIdentitySha256",
                "endpointIdentitySha256",
                "keySpkiSha256",
                "roleIdentitySha256",
            },
            label,
        )
        for field in role:
            require_sha256(role[field], f"{label} {field}")
        require(
            role["keySpkiSha256"]
            == require_sha256(
                expected_key_spki_sha256,
                f"{label} expected key",
            ),
            f"{label} key does not match the loaded certificate or signer",
        )
        return role
    nonce_config = exact(
        config["nonceAuthority"],
        {
            "administrativeDomainSha256",
            "assuranceEvidence",
            "assuranceEvidenceSha256",
            "assuranceEvidenceSigningPublicKeySpkiDerBase64url",
            "credentialIdentitySha256",
            "endpointIdentitySha256",
            "signingPublicKeySpkiDerBase64url",
            "storeIdentitySha256",
        },
        "nonce authority verification configuration",
    )
    nonce_authority = NonceAuthorityReceiptVerifier(
        signing_public_key_spki_der_base64url=nonce_config[
            "signingPublicKeySpkiDerBase64url"
        ],
        store_identity_sha256=nonce_config[
            "storeIdentitySha256"
        ],
        administrative_domain_sha256=nonce_config[
            "administrativeDomainSha256"
        ],
        endpoint_identity_sha256=nonce_config[
            "endpointIdentitySha256"
        ],
        credential_identity_sha256=nonce_config[
            "credentialIdentitySha256"
        ],
        assurance_evidence_sha256=nonce_config[
            "assuranceEvidenceSha256"
        ],
    )
    if mode == "nonProductionReference":
        require(
            config["listenerTls"] is None
            and nonce_config["assuranceEvidence"] is None
            and nonce_config["assuranceEvidenceSha256"] is None
            and nonce_config[
                "assuranceEvidenceSigningPublicKeySpkiDerBase64url"
            ]
            is None
            and config["nonceAuthorityAssuranceEvidenceIssuer"] is None
            and config["roleSeparationEvidence"] is None
            and config["roleSeparationEvidenceIssuer"] is None
            and config[
                "roleSeparationEvidenceSigningPublicKeySpkiDerBase64url"
            ]
            is None,
            "reference TLS and role evidence must be null",
        )
        store_config = exact(
            state_store,
            {
                "administrativeDomainSha256",
                "kind",
                "path",
                "storeIdentitySha256",
            },
            "SQLite reference store configuration",
        )
        local_signer = exact(
            signer_config,
            {"kind", "privateKeyFile"},
            "reference signer configuration",
        )
        require(
            store_config["kind"] == "nonProductionSqlite"
            and local_signer["kind"] == "nonProductionFileEd25519",
            "reference mode requires explicit non-production adapters",
        )
        require_absolute_path(
            store_config["path"],
            "reference state-store path",
        )
        require_absolute_path(
            local_signer["privateKeyFile"],
            "reference signer key path",
        )
        store: StateStoreAdapter = NonProductionSqliteStateStore(
            Path(store_config["path"]),
            store_identity_sha256=store_config["storeIdentitySha256"],
            administrative_domain_sha256=store_config[
                "administrativeDomainSha256"
            ],
        )
        signer: SigningAdapter = NonProductionEd25519Signer.from_file(
            Path(local_signer["privateKeyFile"])
        )
        initialize_genesis = True
        listener_context = None
        listener_peer_policy = None
        role_evidence = None
        role_evidence_key = None
        role_evidence_key_id = None
        role_separation_additional_roles = None
        store_assurance_evidence = None
        store_assurance_evidence_key = None
        store_assurance_evidence_key_id = None
        store_assurance_issuer_administrative_domain_sha256 = None
        store_assurance_issuer_credential_identity_sha256 = None
        store_assurance_issuer_identity_sha256 = None
        nonce_assurance_evidence = None
        nonce_assurance_evidence_key = None
        nonce_assurance_evidence_key_id = None
    elif mode == "production":
        listener_tls = exact(
            config["listenerTls"],
            {
                "clientCaFile",
                "clientRole",
                "expectedClientCertificateSpkiSha256",
                "expectedClientSpiffeUri",
                "kind",
                "serverCertificateFile",
                "serverKeyFile",
                "serverRole",
            },
            "production listener TLS configuration",
        )
        require(
            listener_tls["kind"] == "mutualTls",
            "production listener requires mutual TLS",
        )
        for field in (
            "clientCaFile",
            "serverCertificateFile",
            "serverKeyFile",
        ):
            require_trust_path(
                listener_tls[field],
                f"production listener {field}",
            )
        listener_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        listener_context.minimum_version = ssl.TLSVersion.TLSv1_3
        listener_context.maximum_version = ssl.TLSVersion.TLSv1_3
        listener_context.verify_mode = ssl.CERT_REQUIRED
        listener_context.load_verify_locations(
            cafile=listener_tls["clientCaFile"]
        )
        listener_context.load_cert_chain(
            listener_tls["serverCertificateFile"],
            listener_tls["serverKeyFile"],
        )
        listener_server_certificate_spki_sha256 = (
            certificate_spki_sha256_from_path(
                listener_tls["serverCertificateFile"],
                label="verifier-state listener",
            )
        )
        listener_server_role = configured_role(
            listener_tls["serverRole"],
            label="verifier-state listener TLS role",
            expected_key_spki_sha256=(
                listener_server_certificate_spki_sha256
            ),
        )
        public_client_role = configured_role(
            listener_tls["clientRole"],
            label="public attestation client TLS role",
            expected_key_spki_sha256=listener_tls[
                "expectedClientCertificateSpkiSha256"
            ],
        )
        listener_peer_policy = ListenerPeerPolicy(
            expected_spki_sha256=listener_tls[
                "expectedClientCertificateSpkiSha256"
            ],
            expected_spiffe_uri=listener_tls[
                "expectedClientSpiffeUri"
            ],
        )
        store_config = exact(
            state_store,
            {
                "administrativeDomainSha256",
                "assuranceEvidence",
                "assuranceEvidenceSha256",
                "assuranceEvidenceIssuerAdministrativeDomainSha256",
                "assuranceEvidenceIssuerCredentialIdentitySha256",
                "assuranceEvidenceIssuerEndpointIdentitySha256",
                "assuranceEvidenceIssuerIdentitySha256",
                "assuranceEvidenceSigningPublicKeySpkiDerBase64url",
                "attestationPublicKeySpkiDerBase64url",
                "caFile",
                "clientCertificateFile",
                "clientCertificateSpkiSha256",
                "clientTlsRole",
                "clientKeyFile",
                "credentialIdentitySha256",
                "endpoint",
                "endpointIdentitySha256",
                "expectedServerCertificateSpkiSha256",
                "expectedServerSpiffeUri",
                "kind",
                "minimumCommitIndex",
                "minimumGeneration",
                "rollbackMechanism",
                "serverTlsRole",
                "storeClass",
                "storeConfigurationSha256",
                "storeIdentitySha256",
                "timeoutMilliseconds",
            },
            "external production store configuration",
        )
        remote_signer = exact(
            signer_config,
            {
                "administrativeDomainSha256",
                "assuranceEvidenceSha256",
                "caFile",
                "clientCertificateFile",
                "clientCertificateSpkiSha256",
                "clientTlsRole",
                "clientKeyFile",
                "credentialIdentitySha256",
                "endpoint",
                "endpointIdentitySha256",
                "expectedServerCertificateSpkiSha256",
                "expectedServerSpiffeUri",
                "kind",
                "publicKeySpkiDerBase64url",
                "serverTlsRole",
                "timeoutMilliseconds",
            },
            "external production signer configuration",
        )
        require(
            store_config["kind"] == "externalLinearizableRollbackProtected"
            and remote_signer["kind"] == "externalNonExportableEd25519",
            "production mode forbids local store or key adapters",
        )
        for role_config, role_label in (
            (store_config, "production store"),
            (remote_signer, "production signer"),
        ):
            for field in (
                "caFile",
                "clientCertificateFile",
                "clientKeyFile",
            ):
                require_trust_path(
                    role_config[field],
                    f"{role_label} {field}",
                )
        store_client_certificate_spki_sha256 = (
            certificate_spki_sha256_from_path(
                store_config["clientCertificateFile"],
                label="verifier-state store client",
            )
        )
        signer_client_certificate_spki_sha256 = (
            certificate_spki_sha256_from_path(
                remote_signer["clientCertificateFile"],
                label="verifier-state signer client",
            )
        )
        require(
            store_config["clientCertificateSpkiSha256"]
            == store_client_certificate_spki_sha256
            and remote_signer["clientCertificateSpkiSha256"]
            == signer_client_certificate_spki_sha256,
            "outbound TLS client certificate SPKI pins do not match loaded certificates",
        )
        store_client_role = configured_role(
            store_config["clientTlsRole"],
            label="verifier-state store-client TLS role",
            expected_key_spki_sha256=(
                store_client_certificate_spki_sha256
            ),
        )
        signer_client_role = configured_role(
            remote_signer["clientTlsRole"],
            label="verifier-state signer-client TLS role",
            expected_key_spki_sha256=(
                signer_client_certificate_spki_sha256
            ),
        )
        store_server_role = configured_role(
            store_config["serverTlsRole"],
            label="verifier-state store-server TLS role",
            expected_key_spki_sha256=store_config[
                "expectedServerCertificateSpkiSha256"
            ],
        )
        signer_server_role = configured_role(
            remote_signer["serverTlsRole"],
            label="verifier-state signer-server TLS role",
            expected_key_spki_sha256=remote_signer[
                "expectedServerCertificateSpkiSha256"
            ],
        )
        store_client = CanonicalHttpsClient(
            endpoint=store_config["endpoint"],
            ca_file=store_config["caFile"],
            client_certificate_file=store_config["clientCertificateFile"],
            client_key_file=store_config["clientKeyFile"],
            expected_server_certificate_spki_sha256=store_config[
                "expectedServerCertificateSpkiSha256"
            ],
            expected_server_spiffe_uri=store_config[
                "expectedServerSpiffeUri"
            ],
            timeout_seconds=store_config["timeoutMilliseconds"] / 1000,
        )
        signer_client = CanonicalHttpsClient(
            endpoint=remote_signer["endpoint"],
            ca_file=remote_signer["caFile"],
            client_certificate_file=remote_signer["clientCertificateFile"],
            client_key_file=remote_signer["clientKeyFile"],
            expected_server_certificate_spki_sha256=remote_signer[
                "expectedServerCertificateSpkiSha256"
            ],
            expected_server_spiffe_uri=remote_signer[
                "expectedServerSpiffeUri"
            ],
            timeout_seconds=remote_signer["timeoutMilliseconds"] / 1000,
        )
        store = ExternalLinearizableStateStore(
            client=store_client,
            store_class=store_config["storeClass"],
            rollback_mechanism=store_config["rollbackMechanism"],
            store_identity_sha256=store_config["storeIdentitySha256"],
            administrative_domain_sha256=store_config[
                "administrativeDomainSha256"
            ],
            endpoint_identity_sha256=store_config[
                "endpointIdentitySha256"
            ],
            credential_identity_sha256=store_config[
                "credentialIdentitySha256"
            ],
            assurance_evidence_sha256=store_config[
                "assuranceEvidenceSha256"
            ],
            configuration_sha256=store_config[
                "storeConfigurationSha256"
            ],
            minimum_generation=store_config["minimumGeneration"],
            minimum_commit_index=store_config["minimumCommitIndex"],
            attestation_public_key_spki_der_base64url=store_config[
                "attestationPublicKeySpkiDerBase64url"
            ],
        )
        (
            store_assurance_evidence_key,
            store_assurance_evidence_key_id,
        ) = load_ed25519_public_key(
            store_config[
                "assuranceEvidenceSigningPublicKeySpkiDerBase64url"
            ],
            label="store assurance evidence signing key",
        )
        store_assurance_evidence = exact(
            store_config["assuranceEvidence"],
            {
                "apiVersion",
                "payload",
                "payloadSha256",
                "signatureAlgorithm",
                "signatureBase64url",
                "signingKeyId",
                "signingKeySpkiSha256",
            },
            "signed store assurance evidence",
        )
        require(
            sha256_json(store_assurance_evidence)
            == store_config["assuranceEvidenceSha256"],
            "store assurance evidence digest does not match its config pin",
        )
        store_assurance_issuer_administrative_domain_sha256 = (
            require_sha256(
                store_config[
                    "assuranceEvidenceIssuerAdministrativeDomainSha256"
                ],
                "store assurance issuer administrative domain",
            )
        )
        store_assurance_issuer_credential_identity_sha256 = (
            require_sha256(
                store_config[
                    "assuranceEvidenceIssuerCredentialIdentitySha256"
                ],
                "store assurance issuer credential identity",
            )
        )
        store_assurance_issuer_endpoint_identity_sha256 = (
            require_sha256(
                store_config[
                    "assuranceEvidenceIssuerEndpointIdentitySha256"
                ],
                "store assurance issuer endpoint identity",
            )
        )
        store_assurance_issuer_identity_sha256 = require_sha256(
            store_config["assuranceEvidenceIssuerIdentitySha256"],
            "store assurance issuer identity",
        )
        signer = ExternalEd25519Signer(
            client=signer_client,
            public_key_spki_der_base64url=remote_signer[
                "publicKeySpkiDerBase64url"
            ],
            administrative_domain_sha256=remote_signer[
                "administrativeDomainSha256"
            ],
            endpoint_identity_sha256=remote_signer[
                "endpointIdentitySha256"
            ],
            credential_identity_sha256=remote_signer[
                "credentialIdentitySha256"
            ],
            assurance_evidence_sha256=remote_signer[
                "assuranceEvidenceSha256"
            ],
        )
        role_evidence_key, role_evidence_key_id = (
            load_ed25519_public_key(
                config[
                    "roleSeparationEvidenceSigningPublicKeySpkiDerBase64url"
                ],
                label="role-separation evidence signing key",
            )
        )
        role_evidence = exact(
            config["roleSeparationEvidence"],
            {
                "apiVersion",
                "payload",
                "payloadSha256",
                "signatureAlgorithm",
                "signatureBase64url",
                "signingKeyId",
                "signingKeySpkiSha256",
            },
            "signed role-separation evidence",
        )
        (
            nonce_assurance_evidence_key,
            nonce_assurance_evidence_key_id,
        ) = load_ed25519_public_key(
            nonce_config[
                "assuranceEvidenceSigningPublicKeySpkiDerBase64url"
            ],
            label="nonce assurance evidence signing key",
        )
        nonce_assurance_evidence = exact(
            nonce_config["assuranceEvidence"],
            {
                "apiVersion",
                "payload",
                "payloadSha256",
                "signatureAlgorithm",
                "signatureBase64url",
                "signingKeyId",
                "signingKeySpkiSha256",
            },
            "signed nonce authority assurance evidence",
        )
        require(
            sha256_json(nonce_assurance_evidence)
            == nonce_config["assuranceEvidenceSha256"],
            "nonce assurance evidence digest does not match its configuration pin",
        )
        nonce_assurance_evidence_issuer_role = configured_role(
            config["nonceAuthorityAssuranceEvidenceIssuer"],
            label="nonce assurance evidence issuer role",
            expected_key_spki_sha256=(
                nonce_assurance_evidence_key_id
            ),
        )
        role_evidence_issuer_role = configured_role(
            config["roleSeparationEvidenceIssuer"],
            label="role-separation evidence issuer role",
            expected_key_spki_sha256=role_evidence_key_id,
        )
        store_assurance_issuer_role = {
            "administrativeDomainSha256":
            store_assurance_issuer_administrative_domain_sha256,
            "assuranceEvidenceSha256":
            store.assurance_evidence_sha256,
            "credentialIdentitySha256":
            store_assurance_issuer_credential_identity_sha256,
            "endpointIdentitySha256":
            store_assurance_issuer_endpoint_identity_sha256,
            "keySpkiSha256": store_assurance_evidence_key_id,
            "roleIdentitySha256":
            store_assurance_issuer_identity_sha256,
        }
        role_separation_additional_roles = {
            "nonceAuthorityAssuranceEvidenceIssuer":
            nonce_assurance_evidence_issuer_role,
            "publicAttestationClientTls": public_client_role,
            "roleSeparationEvidenceIssuer":
            role_evidence_issuer_role,
            "storeAssuranceEvidenceIssuer":
            store_assurance_issuer_role,
            "verifierStateServiceListenerTls":
            listener_server_role,
            "verifierStateSignerClientTls":
            signer_client_role,
            "verifierStateSignerServerTls":
            signer_server_role,
            "verifierStateStoreClientTls": store_client_role,
            "verifierStateStoreServerTls": store_server_role,
        }
        initialize_genesis = False
    else:
        raise ContractError("service mode is invalid")
    service = VerifierStateService(
        mode=mode,
        assurance=config["assurance"],
        assurance_sha256=config["assuranceSha256"],
        store=store,
        signer=signer,
        nonce_authority=nonce_authority,
        nonce_authority_assurance_evidence=(
            nonce_assurance_evidence
        ),
        nonce_authority_assurance_evidence_public_key=(
            nonce_assurance_evidence_key
        ),
        nonce_authority_assurance_evidence_key_id=(
            nonce_assurance_evidence_key_id
        ),
        role_separation_evidence=role_evidence,
        role_separation_evidence_public_key=role_evidence_key,
        role_separation_evidence_key_id=role_evidence_key_id,
        role_separation_additional_roles=(
            role_separation_additional_roles
        ),
        store_assurance_evidence=store_assurance_evidence,
        store_assurance_evidence_public_key=(
            store_assurance_evidence_key
        ),
        store_assurance_evidence_key_id=(
            store_assurance_evidence_key_id
        ),
        store_assurance_issuer_administrative_domain_sha256=(
            store_assurance_issuer_administrative_domain_sha256
        ),
        store_assurance_issuer_credential_identity_sha256=(
            store_assurance_issuer_credential_identity_sha256
        ),
        store_assurance_issuer_identity_sha256=(
            store_assurance_issuer_identity_sha256
        ),
        authorization_lifetime_seconds=config[
            "authorizationLifetimeSeconds"
        ],
        initialize_reference_genesis=initialize_genesis,
    )
    return (
        service,
        (listen["host"], listen["port"]),
        listener_context,
        listener_peer_policy,
        listen["expectedHostAuthority"],
        max_concurrent_requests,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Serve rollback-assured nonce-authority verifier state. "
            "Responses are always non-actionable."
        )
    )
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args(argv)
    try:
        (
            service,
            address,
            listener_context,
            listener_peer_policy,
            expected_host_authority,
            max_concurrent_requests,
        ) = build_service(
            load_config(Path(arguments.config))
        )
        server = VerifierStateHttpServer(
            address,
            service,
            listener_context=listener_context,
            listener_peer_policy=listener_peer_policy,
            expected_host_authority=expected_host_authority,
            max_concurrent_requests=max_concurrent_requests,
        )
        server.serve_forever()
    except (ContractError, OSError, sqlite3.Error) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
