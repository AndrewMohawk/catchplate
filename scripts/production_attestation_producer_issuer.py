#!/usr/bin/python3
"""Production stable-release issuer and public-attestation producer.

This executable never loads production release, nonce-store, or witness private
keys and never launches a child process. Stable-release signing, nonce
consumption, and current-witness lookup cross explicit retained file-descriptor
protocols. For each bundle invocation only, the producer reads one exact
32-byte Ed25519 seed from the sealed descriptor role
``producerEphemeralSeed`` supplied as
``--producer-ephemeral-seed-fd``. It proves possession by signing the closed
producer binding, closes the FD, and overwrites its mutable seed buffer. The
pinned external sandbox launcher owns all containment and seed-FD destruction
claims.

Stable-release signing is not a generic retained-FD signing service. The signer
must hold an independently provisioned, one-use preauthorization for the exact
issuer-request digest and stable statement target, and must atomically consume
that authorization before reconstructing and signing the fixed-domain message.
Production additionally requires a rollback-resistant signer-owned
authorization, consumption, authorization-sequence, and release-tuple backend.
Integer retained FDs do not authenticate their peer: the measured launcher must
create, validate, retain, and pass the intended channels without substitution.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import select
import socket
import stat
import sys
import time
import unicodedata
import urllib.parse
from typing import Any, Mapping, NoReturn

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:
    from scripts import verify_nitro_tee as _native_nitro_contract
except ImportError:
    import verify_nitro_tee as _native_nitro_contract

ISSUER_REQUEST_VERSION = (
    "serverware.productionStableReleaseIssuerRequest/v1"
)
PRODUCER_REQUEST_VERSION = "serverware.publicAttestationProducerRequest/v2"
LIVE_REQUEST_VERSION = "serverware.publicAttestationLiveRequest/v1"
NONCE_CONSUMPTION_VERSION = (
    "serverware.publicAttestationNonceConsumption/v1"
)
SIGNED_NONCE_RECEIPT_VERSION = (
    "serverware.signedAttestationNonceConsumptionReceipt/v2"
)
NONCE_RECEIPT_PAYLOAD_VERSION = (
    "serverware.attestationNonceConsumptionReceiptPayload/v2"
)
NONCE_AUTHORITY_ASSURANCE_VERSION = (
    "serverware.nonceAuthorityAssurance/v1"
)
SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.signedNonceAuthorityAssuranceEvidence/v1"
)
NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.nonceAuthorityAssuranceEvidence/v1"
)
SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.signedVerifierStateStoreAssuranceEvidence/v1"
)
VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.verifierStateStoreAssuranceEvidence/v1"
)
SIGNED_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION = (
    "serverware.signedVerifierStateRoleSeparationEvidence/v1"
)
VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION = (
    "serverware.verifierStateRoleSeparationEvidence/v1"
)
NONCE_AUTHORITY_STATE_VERSION = "serverware.nonceAuthorityState/v1"
NONCE_AUTHORITY_HIGH_WATER_INPUT_VERSION = (
    "serverware.nonceAuthorityHighWaterCommitment/v1"
)
SIGNED_NONCE_AUTHORITY_VERIFIER_STATE_VERSION = (
    "serverware.signedNonceAuthorityVerifierState/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_VERSION = (
    "serverware.nonceAuthorityVerifierState/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION = (
    "serverware.nonceAuthorityVerifierStatePreparedAuthorization/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION = (
    "serverware.nonceAuthorityVerifierStateCommitReceipt/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION = (
    "serverware.nonceAuthorityVerifierStateTransition/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_READ_RESPONSE_VERSION = (
    "serverware.nonceAuthorityVerifierStateReadResponse/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_REQUEST_VERSION = (
    "serverware.attestationVerifierStateCommitRequest/v3"
)
SIGNED_VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION = (
    "serverware.signedVerifierStateStoreCommitProof/v3"
)
VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION = (
    "serverware.verifierStateStoreCommitProof/v3"
)
VERIFIER_STATE_STORE_COMMIT_CANDIDATE_VERSION = (
    "serverware.verifierStateStoreCommitCandidate/v2"
)
VERIFIER_STATE_CLIENT_VERSION = (
    "serverware.attestationVerifierStateClient/v2"
)
VERIFIER_STATE_PREPARED_OPERATION_VERSION = (
    "serverware.attestationVerifierStatePreparedOperation/v1"
)
VERIFIER_STATE_REQUEST_BINDING_VERSION = (
    "serverware.attestationVerifierStateRequestBinding/v1"
)
VERIFIER_STATE_PREPARE_REQUEST_VERSION = (
    "serverware.attestationVerifierStatePrepareRequest/v4"
)
VERIFIER_STATE_RECOVERY_BINDING_VERSION = (
    "serverware.attestationVerifierStateRecoveryBinding/v1"
)
VERIFIER_STATE_RECOVERY_IDENTITY_VERSION = (
    "serverware.attestationVerifierStateRecoveryIdentity/v1"
)
VERIFIER_STATE_SUCCESSOR_INTENT_VERSION = (
    "serverware.attestationVerifierStateSuccessorIntent/v1"
)
NONCE_CONSUME_ONCE_REQUEST_VERSION = (
    "serverware.attestationNonceConsumeOnceRequest/v3"
)
PRODUCER_INVOCATION_VERSION = (
    "serverware.publicAttestationProducerInvocation/v1"
)
PRODUCER_BINDING_VERSION = (
    "serverware.publicAttestationProducerBinding/v3"
)
SIGNED_PRODUCER_BINDING_VERSION = (
    "serverware.signedPublicAttestationProducerBinding/v1"
)
PUBLIC_BUNDLE_VERSION = "serverware.publicAttestationBundle/v3"
RELEASE_GRAPH_VERSION = "serverware.publicReleaseGraph/v1"
RELEASE_CONFIG_VERSION = "serverware.publicAttestationConfig/v2"
STABLE_STATEMENT_VERSION = "serverware.stableReleaseStatement/v1"
LIVE_WITNESS_HEAD_VERSION = "serverware.liveWitnessHead/v1"
PROTECTED_WITNESS_VERSION = "serverware.protectedLiveWitnessState/v2"
SIGN_REQUEST_VERSION = "serverware.retainedFdEd25519SignRequest/v1"
SIGN_RESPONSE_VERSION = "serverware.retainedFdEd25519SignResponse/v1"
WITNESS_REQUEST_VERSION = "serverware.attestationWitnessCurrentRequest/v2"
WITNESS_RESPONSE_VERSION = "serverware.attestationWitnessCurrentResponse/v2"
WITNESS_INVOCATION_BINDING_VERSION = (
    "serverware.attestationWitnessInvocationBinding/v1"
)
PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_VERSION = (
    "serverware.publicNitroLiveVerificationResultEnvelope/v1"
)
PUBLIC_NITRO_RESULT_SIGNING_REQUEST_VERSION = (
    "serverware.publicNitroLiveVerificationResultSigningRequest/v1"
)
PUBLIC_NITRO_RESULT_SIGNING_RESPONSE_VERSION = (
    "serverware.publicNitroLiveVerificationResultSigningResponse/v1"
)
PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION = (
    "serverware.publicNitroLiveVerificationResultRecoveryRequest/v1"
)
PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION = (
    "serverware.publicNitroLiveVerificationResultStatusRequest/v1"
)

STABLE_STATEMENT_DOMAIN = (
    b"serverware.stableReleaseStatement/v1\x00Ed25519\x00"
)
PROTECTED_WITNESS_DOMAIN = (
    b"serverware.protectedLiveWitnessState/v2\x00Ed25519\x00"
)
LIVE_WITNESS_HEAD_DOMAIN = (
    b"serverware.liveWitnessHead/v1\x00Ed25519\x00"
)
LIVE_WITNESS_HEAD_CHAIN_DOMAIN = (
    b"serverware:live-witness-head-chain:v1:"
)
LIVE_WITNESS_CONTINUITY_DOMAIN = (
    b"serverware:live-witness-continuity:v1:"
)
LIVE_WITNESS_CONTINUITY_VERSION = (
    "serverware.liveWitnessContinuity/v1"
)
NONCE_RECEIPT_DOMAIN = (
    b"serverware.attestationNonceConsumptionReceipt/v2\x00Ed25519\x00"
)
NONCE_CONSUME_REQUEST_DIGEST_DOMAIN = (
    b"serverware.attestationNonceConsumeRequestDigest/v3\x00"
)
VERIFIER_STATE_RECOVERY_KEY_DOMAIN = (
    b"serverware.attestationVerifierStateRecoveryKey/v1\x00"
)
VERIFIER_STATE_OPERATION_ID_DOMAIN = (
    b"serverware.attestationVerifierStateOperationId/v1\x00"
)
VERIFIER_STATE_REQUEST_BINDING_DOMAIN = (
    b"serverware.attestationVerifierStateRequestBinding/v1\x00"
)
NONCE_AUTHORITY_GENESIS_DOMAIN = (
    b"serverware.nonceAuthorityGenesisCommitment/v1\x00"
)
NONCE_AUTHORITY_HIGH_WATER_DOMAIN = (
    b"serverware.nonceAuthorityHighWaterCommitment/v1\x00"
)
NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN = (
    b"serverware.nonceAuthorityAssuranceEvidence/v1\x00Ed25519\x00"
)
VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN = (
    b"serverware.verifierStateStoreAssuranceEvidence/v1\x00Ed25519\x00"
)
VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN = (
    b"serverware.verifierStateRoleSeparationEvidence/v1\x00Ed25519\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_DOMAIN = (
    b"serverware.nonceAuthorityVerifierState/v1\x00Ed25519\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStatePreparedAuthorization/v3\x00"
    b"Ed25519\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStateCommitReceipt/v3\x00"
    b"Ed25519\x00"
)
VERIFIER_STATE_STORE_COMMIT_PROOF_DOMAIN = (
    b"serverware.verifierStateStoreCommitProof/v3\x00Ed25519\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_HEAD_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStateHead/v1\x00"
)
PRODUCER_BINDING_DOMAIN = (
    b"serverware.publicAttestationProducerBinding/v3\x00Ed25519\x00"
)
PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN = (
    _native_nitro_contract.PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
)
PUBLIC_NITRO_RESULT_SIGNING_OPERATION_DOMAIN = (
    b"serverware.publicNitroLiveVerificationResultSigningOperation/v1\x00"
)
PUBLIC_NITRO_RESULT_SIGNING_RECOVERY_DOMAIN = (
    b"serverware.publicNitroLiveVerificationResultSigningRecovery/v1\x00"
)
TRUST_ROOTS_VERSION = "serverware.publicNitroTrustRoots/v4"
RELEASE_IDENTITY_VERSION = "serverware.releaseIdentity/v1"
RELEASE_PIPELINE = "manifest-v6-promoted-oci-nitro-eif"

MAX_U64 = (1 << 64) - 1
PUBLIC_NITRO_CANONICAL_INTEGER_MAX = (
    _native_nitro_contract.PUBLIC_NITRO_CANONICAL_INTEGER_MAX
)
MAX_ISSUER_REQUEST_BYTES = 2 * 1024 * 1024
MAX_PRODUCER_REQUEST_BYTES = 256 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_STABLE_STATEMENT_BYTES = 2 * 1024 * 1024
MAX_DESCRIPTOR_BYTES = 64 * 1024
MAX_EXECUTABLE_BYTES = 32 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_SANDBOX_DESCRIPTOR_BYTES = 256 * 1024
MAX_SCHEMA_BYTES = 1024 * 1024
MAX_TRUST_ROOT_BYTES = 4 * 1024 * 1024
MAX_WITNESS_RESPONSE_BYTES = 1024 * 1024
MAX_PUBLIC_NITRO_SIGNING_BYTES = 4 * 1024 * 1024
DEFAULT_IO_TIMEOUT_MS = 30_000
MAX_RELEASE_SIGN_AUTHORIZATION_SECONDS = 15 * 60
MAX_JSON_DEPTH = 64
MAX_JSON_ITEMS = 4096
MAX_CERTIFICATES = 16
MAX_CERT_BYTES = 64 * 1024

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA384_RE = re.compile(r"^sha384:[0-9a-f]{96}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
PUBLIC_NITRO_PROVIDER_RE = (
    _native_nitro_contract.PUBLIC_NITRO_PROVIDER_RE
)
STORE_IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,126}[a-z0-9]$"
)

STATEMENT_PIN_FIELDS = frozenset(
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
    }
)
COMPONENT_PIN_FIELDS = frozenset(
    {
        "nonceStoreIdentitySha256",
        "nonceStoreKeySpkiSha256",
        "producerDescriptorSha256",
        "producerExecutableSha256",
        "producerRequestSchemaSha256",
        "sandboxDescriptorSha256",
        "sandboxLauncherSha256",
        "witnessStoreIdentitySha256",
        "witnessStoreKeySpkiSha256",
    }
)
NONCE_RECEIPT_FIELDS = frozenset(
    {
        "apiVersion",
        "payload",
        "payloadSha256",
        "signatureAlgorithm",
        "signatureBase64url",
        "signingKeyId",
        "signingKeySpkiSha256",
    }
)
NONCE_RECEIPT_PAYLOAD_FIELDS = frozenset(
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
    }
)
NONCE_AUTHORITY_STATE_FIELDS = frozenset(
    {
        "apiVersion",
        "assuranceSha256",
        "authorityEpoch",
        "authorityGeneration",
        "highWaterCommitmentSha256",
        "highWaterSequence",
        "previousHighWaterCommitmentSha256",
    }
)
NONCE_AUTHORITY_VERIFIER_STATE_FIELDS = frozenset(
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
    }
)
NONCE_AUTHORITY_ASSURANCE_FIELDS = frozenset(
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
    }
)
NONCE_AUTHORITY_ROLLBACK_FIELDS = frozenset(
    {
        "administrativeRollbackResistance",
        "backendAttestationRequired",
        "exactSuccessorRequired",
        "freshVerifierChallengeRequired",
        "keyProtection",
        "mechanism",
        "stateCommitment",
        "verifierStateStoreClass",
    }
)
PRODUCTION_NONCE_AUTHORITY_PROFILES = frozenset(
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
TLS_BINDING_FIELDS = frozenset(
    {
        "apiVersion",
        "bindingSha256",
        "connectionId",
        "connectionNonceSha256",
        "enclaveBootId",
        "enclaveInstanceId",
        "expiresAtUnix",
        "exporterLabel",
        "exporterSha256",
        "issuedAtUnix",
        "leafCertificateSha256",
        "leafSpkiSha256",
        "peerCertificateSha256",
        "peerIdentity",
        "peerSpkiSha256",
        "provider",
        "tlsKeyGeneration",
        "tlsScopeEnvelopeSha256",
        "tlsScopeKeyGeneration",
        "tlsScopeKeySpkiSha256",
        "tlsStackMeasurementSha256",
    }
)
NONCE_CONSUMPTION_FIELDS = frozenset(
    {
        "apiVersion",
        "consumedAtUnix",
        "nonceSha256",
        "oneUse",
        "requestBodySha256",
        "sequence",
        "storeIdentitySha256",
        "tlsBindingSha256",
    }
)
TRUST_KEY_ROLES = (
    "sourceGitInventory",
    "sourceUntrackedApproval",
    "buildWatchdog",
    "promotion",
    "builderA",
    "builderB",
    "manifestV6EifBuilder",
    "completion",
    "completionCheckpoint",
    "witness",
    "kmsAudit",
    "clientState",
    "clientStateCheckpoint",
    "stateCommit",
    "currentHeadAuthorization",
    "currentHeadRedemption",
)
STABLE_DYNAMIC_FIELD_NAMES = frozenset(
    {
        "actionauthorization",
        "callernonce",
        "callernoncesha256",
        "challenge",
        "challengenonce",
        "challengenoncesha256",
        "connectionid",
        "evidence",
        "evidencebodysha256",
        "expiresatunix",
        "httprequest",
        "issuedatunix",
        "livesession",
        "livesessionproof",
        "nonce",
        "noncesha256",
        "oneuse",
        "producerrequest",
        "producerrequestsha256",
        "request",
        "requestbodysha256",
        "session",
        "tlsbinding",
        "tlsbindingsha256",
    }
)


class ContractError(ValueError):
    pass


def reject(message: str) -> NoReturn:
    raise ContractError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        reject(message)


def exact_object(
    value: Any,
    fields: set[str] | frozenset[str],
    label: str,
) -> dict[str, Any]:
    require(
        isinstance(value, dict) and set(value) == set(fields),
        f"{label} is not a closed object",
    )
    return value


def require_sha256(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
        f"{label} is not a canonical SHA-256 digest",
    )
    return value


def require_public_nitro_provider(value: Any, label: str) -> str:
    require(
        isinstance(value, str)
        and PUBLIC_NITRO_PROVIDER_RE.fullmatch(value) is not None,
        f"{label} is invalid",
    )
    return value


def require_u64(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_U64,
) -> int:
    require(
        type(value) is int and minimum <= value <= maximum,
        f"{label} is outside its unsigned integer range",
    )
    return value


def reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "JSON object contains a duplicate key")
        result[key] = value
    return result


def reject_non_integer(_: str) -> NoReturn:
    reject("floating-point and non-finite JSON values are forbidden")


def validate_json_shape(
    value: Any,
    *,
    label: str,
    depth: int = 0,
) -> None:
    require(depth <= MAX_JSON_DEPTH, f"{label} exceeds nesting limit")
    if isinstance(value, dict):
        require(
            len(value) <= MAX_JSON_ITEMS,
            f"{label} has too many object fields",
        )
        for key, child in value.items():
            require(
                isinstance(key, str)
                and 0 < len(key) <= 256
                and "\x00" not in key
                and unicodedata.normalize("NFC", key) == key
                and not any(
                    0xD800 <= ord(character) <= 0xDFFF
                    for character in key
                ),
                f"{label} contains an invalid object key",
            )
            validate_json_shape(child, label=label, depth=depth + 1)
    elif isinstance(value, list):
        require(
            len(value) <= MAX_JSON_ITEMS,
            f"{label} has too many array items",
        )
        for child in value:
            validate_json_shape(child, label=label, depth=depth + 1)
    elif isinstance(value, str):
        require(
            "\x00" not in value
            and unicodedata.normalize("NFC", value) == value
            and not any(
                0xD800 <= ord(character) <= 0xDFFF
                for character in value
            ),
            f"{label} contains invalid Unicode",
        )
    elif value is None or isinstance(value, bool):
        return
    elif type(value) is int:
        require(
            -(1 << 63) <= value <= MAX_U64,
            f"{label} integer is outside signed-64/u64 range",
        )
    else:
        reject(f"{label} contains an unsupported JSON value")


def parse_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_pairs,
            parse_float=reject_non_integer,
            parse_constant=reject_non_integer,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ContractError(f"{label} is not strict JSON") from exc
    validate_json_shape(value, label=label)
    return value


def canonical_json(value: Any) -> bytes:
    validate_json_shape(value, label="canonical JSON")
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContractError("document is not canonical JSON data") from exc


def sha256_bytes(value: bytes | bytearray | memoryview) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def base64url_encode(value: bytes | bytearray | memoryview) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def base64url_decode(
    value: Any,
    label: str,
    *,
    exact_length: int | None = None,
    maximum: int,
) -> bytes:
    require(isinstance(value, str), f"{label} is not base64url text")
    require(
        len(value) % 4 != 1
        and re.fullmatch(r"[A-Za-z0-9_-]*", value) is not None,
        f"{label} is not canonical base64url",
    )
    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * ((4 - len(value) % 4) % 4)
        )
    except (binascii.Error, ValueError) as exc:
        raise ContractError(f"{label} is not base64url") from exc
    require(
        len(decoded) <= maximum
        and base64url_encode(decoded) == value
        and (exact_length is None or len(decoded) == exact_length),
        f"{label} has an invalid canonical length",
    )
    return decoded


def strict_json_line(raw: bytes, label: str, maximum: int) -> Any:
    require(
        1 < len(raw) <= maximum
        and raw.endswith(b"\n")
        and not raw.endswith(b"\n\n"),
        f"{label} is outside its byte contract",
    )
    body = raw[:-1]
    value = parse_json(body, label)
    require(
        raw == canonical_json(value) + b"\n",
        f"{label} is not canonical JSON plus exactly one LF",
    )
    return value


def _poll(fd: int, event: int, deadline: float, label: str) -> None:
    remaining = deadline - time.monotonic()
    require(remaining > 0, f"{label} timed out")
    poller = select.poll()
    poller.register(fd, event | select.POLLERR | select.POLLHUP)
    events = poller.poll(max(1, int(remaining * 1000)))
    require(events, f"{label} timed out")
    returned = events[0][1]
    require(
        (
            returned & event
            or event == select.POLLIN
            and returned & select.POLLHUP
        )
        and not returned & (select.POLLERR | select.POLLNVAL),
        f"{label} descriptor failed",
    )
    require(
        event != select.POLLOUT or not returned & select.POLLHUP,
        f"{label} descriptor closed",
    )


def read_json_line_fd(
    fd: int,
    *,
    maximum: int,
    timeout_ms: int,
    label: str,
    deadline: float | None = None,
) -> tuple[Any, bytes]:
    require_u64(fd, f"{label} descriptor", maximum=1_048_575)
    require_u64(
        timeout_ms,
        f"{label} timeout",
        minimum=100,
        maximum=30_000,
    )
    if deadline is None:
        deadline = time.monotonic() + timeout_ms / 1000.0
    else:
        require(deadline > time.monotonic(), f"{label} timed out")
    os.set_blocking(fd, False)
    result = bytearray()
    while b"\n" not in result:
        _poll(fd, select.POLLIN, deadline, label)
        try:
            chunk = os.read(
                fd,
                min(65_536, maximum + 1 - len(result)),
            )
        except BlockingIOError:
            continue
        require(chunk, f"{label} ended before a complete line")
        result.extend(chunk)
        require(len(result) <= maximum, f"{label} exceeds its byte limit")
    newline = result.find(b"\n")
    require(
        newline == len(result) - 1,
        f"{label} contains trailing or multiple records",
    )
    raw = bytes(result)
    return strict_json_line(raw, label, maximum), raw


def write_json_line_fd(
    fd: int,
    value: Any,
    *,
    maximum: int,
    timeout_ms: int,
    label: str,
    deadline: float | None = None,
) -> bytes:
    raw = canonical_json(value) + b"\n"
    require(1 < len(raw) <= maximum, f"{label} exceeds its byte limit")
    if deadline is None:
        deadline = time.monotonic() + timeout_ms / 1000.0
    else:
        require(deadline > time.monotonic(), f"{label} timed out")
    os.set_blocking(fd, False)
    offset = 0
    while offset < len(raw):
        _poll(fd, select.POLLOUT, deadline, label)
        try:
            written = os.write(fd, raw[offset:])
        except BlockingIOError:
            continue
        require(written > 0, f"{label} write failed")
        offset += written
    return raw


def _fd_is_sealed(fd: int) -> bool:
    if not hasattr(fcntl, "F_GET_SEALS"):
        return False
    try:
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
    except OSError:
        return False
    required = 0
    for name in ("F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_WRITE"):
        required |= int(getattr(fcntl, name, 0))
    return required != 0 and seals & required == required


def _require_close_on_exec(fd: int, label: str) -> None:
    descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    require(
        descriptor_flags & fcntl.FD_CLOEXEC != 0,
        f"{label} descriptor is not close-on-exec",
    )


def validate_retained_pipe_fd(
    fd: int,
    *,
    label: str,
    writable: bool,
) -> tuple[int, int, int]:
    """Validate a retained pipe endpoint immediately before protocol use.

    This proves local descriptor type and direction only. It cannot authenticate
    the process at the other end; that remains a measured-launcher obligation.
    """
    require_u64(fd, f"{label} descriptor", minimum=3, maximum=1_048_575)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    expected_mode = os.O_WRONLY if writable else os.O_RDONLY
    require(
        flags & os.O_ACCMODE == expected_mode,
        f"{label} descriptor has the wrong pipe direction",
    )
    descriptor = os.fstat(fd)
    require(
        stat.S_ISFIFO(descriptor.st_mode),
        f"{label} descriptor is not a pipe endpoint",
    )
    _require_close_on_exec(fd, label)
    return descriptor.st_dev, descriptor.st_ino, descriptor.st_mode


def _require_memfd(fd: int, label: str) -> None:
    try:
        target = os.readlink(f"/proc/self/fd/{fd}")
    except OSError as exc:
        raise ContractError(
            f"{label} descriptor cannot be identified as a memfd"
        ) from exc
    require(
        target.startswith("/memfd:") and target.endswith(" (deleted)"),
        f"{label} descriptor is not the expected anonymous memfd",
    )


def read_immutable_fd(fd: int, *, maximum: int, label: str) -> bytes:
    require_u64(fd, f"{label} descriptor", minimum=3, maximum=1_048_575)
    _require_close_on_exec(fd, label)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    require(
        flags & os.O_ACCMODE == os.O_RDONLY,
        f"{label} descriptor is not read-only",
    )
    before = os.fstat(fd)
    require(
        stat.S_ISREG(before.st_mode)
        and 0 < before.st_size <= maximum,
        f"{label} is not a bounded regular file",
    )
    if not _fd_is_sealed(fd):
        require(
            before.st_uid == 0
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) & 0o022 == 0,
            f"{label} is neither sealed nor root-owned immutable input",
        )
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        require(chunk, f"{label} changed while being read")
        chunks.append(chunk)
        remaining -= len(chunk)
    after = os.fstat(fd)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_uid,
        before.st_gid,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    require(identity_before == identity_after, f"{label} changed while read")
    os.lseek(fd, 0, os.SEEK_SET)
    return b"".join(chunks)


def read_exact_sealed_secret_fd(fd: int, *, label: str) -> bytearray:
    require_u64(fd, f"{label} descriptor", minimum=3, maximum=1_048_575)
    secret = bytearray()
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        before = os.fstat(fd)
        _require_close_on_exec(fd, label)
        _require_memfd(fd, label)
        require(
            flags & os.O_ACCMODE == os.O_RDONLY
            and stat.S_ISREG(before.st_mode)
            and before.st_nlink == 0
            and before.st_size == 32
            and _fd_is_sealed(fd),
            f"{label} is not an exact sealed read-only 32-byte memfd",
        )
        os.lseek(fd, 0, os.SEEK_SET)
        while len(secret) < 32:
            # os.read necessarily creates short-lived immutable bytes in
            # CPython; only the retained mutable copy can be explicitly wiped.
            chunk = os.read(fd, 32 - len(secret))
            require(chunk, f"{label} ended before 32 bytes")
            secret.extend(chunk)
        require(
            os.read(fd, 1) == b"",
            f"{label} contains trailing bytes",
        )
        after = os.fstat(fd)
        require(
            (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            f"{label} changed while read",
        )
        return secret
    except BaseException:
        zeroize(secret)
        raise
    finally:
        os.close(fd)


def read_ephemeral_seed_fd(fd: int) -> bytearray:
    return read_exact_sealed_secret_fd(
        fd,
        label="producer ephemeral signing seed",
    )


def ephemeral_public_key(
    seed: bytearray,
) -> tuple[bytes, str]:
    require(len(seed) == 32, "producer ephemeral seed length is invalid")
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
    try:
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    finally:
        del private_key
    require(
        len(public_der) == 44,
        "producer ephemeral key is not canonical Ed25519 SPKI",
    )
    return public_der, sha256_bytes(public_der)


def zeroize(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def validate_distinct_fds(values: Mapping[str, int]) -> None:
    normalized: dict[int, str] = {}
    for label, fd in values.items():
        require_u64(fd, label, maximum=1_048_575)
        previous = normalized.get(fd)
        require(previous is None, f"{label} aliases {previous}")
        normalized[fd] = label


class OwnedFd:
    """Single-owner descriptor transfer helper for fail-closed cleanup."""

    def __init__(self, fd: int, *, label: str) -> None:
        require_u64(fd, label, minimum=3, maximum=1_048_575)
        self._fd = fd

    def fileno(self) -> int:
        require(self._fd >= 0, "descriptor ownership was already transferred")
        return self._fd

    def take(self) -> int:
        require(self._fd >= 0, "descriptor ownership was transferred twice")
        fd = self._fd
        self._fd = -1
        return fd

    def close(self) -> None:
        if self._fd >= 0:
            fd = self._fd
            self._fd = -1
            os.close(fd)


def statement_pins(value: Any, label: str) -> dict[str, str]:
    pins = exact_object(value, STATEMENT_PIN_FIELDS, label)
    return {
        field: require_sha256(pins[field], f"{label} {field}")
        for field in sorted(STATEMENT_PIN_FIELDS)
    }


def component_pins_from_statement(
    pins: Mapping[str, str],
) -> dict[str, str]:
    return {
        "nonceStoreIdentitySha256": pins["nonceStoreIdentitySha256"],
        "nonceStoreKeySpkiSha256": pins["nonceStoreKeySpkiSha256"],
        "producerDescriptorSha256": pins["descriptorSha256"],
        "producerExecutableSha256": pins["executableSha256"],
        "producerRequestSchemaSha256":
        pins["producerRequestSchemaSha256"],
        "sandboxDescriptorSha256": pins["sandboxDescriptorSha256"],
        "sandboxLauncherSha256": pins["sandboxLauncherSha256"],
        "witnessStoreIdentitySha256":
        pins["witnessStoreIdentitySha256"],
        "witnessStoreKeySpkiSha256":
        pins["witnessStoreKeySpkiSha256"],
    }


def require_sha384(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and SHA384_RE.fullmatch(value) is not None,
        f"{label} is not a canonical SHA-384 digest",
    )
    return value


def reject_dynamic_stable_fields(
    value: Any,
    *,
    label: str,
    path: str = "$",
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            require(
                normalized not in STABLE_DYNAMIC_FIELD_NAMES,
                f"{label} contains dynamic field at {path}.{key}",
            )
            reject_dynamic_stable_fields(
                child,
                label=label,
                path=f"{path}.{key}",
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_dynamic_stable_fields(
                child,
                label=label,
                path=f"{path}[{index}]",
            )


def validate_component_pins(
    value: Any,
    label: str,
) -> dict[str, str]:
    pins = exact_object(value, COMPONENT_PIN_FIELDS, label)
    return {
        field: require_sha256(pins[field], f"{label} {field}")
        for field in sorted(COMPONENT_PIN_FIELDS)
    }


def validate_release_identity(
    value: Any,
    *,
    label: str,
) -> dict[str, Any]:
    reject_dynamic_stable_fields(value, label=label)
    identity = exact_object(
        value,
        {
            "apiVersion",
            "build",
            "configuration",
            "eif",
            "monotonicRelease",
            "pipeline",
            "policy",
            "source",
        },
        label,
    )
    require(
        identity["apiVersion"] == RELEASE_IDENTITY_VERSION
        and identity["pipeline"] == RELEASE_PIPELINE,
        f"{label} version or pipeline is invalid",
    )
    source = exact_object(
        identity["source"],
        {
            "sourceClosureSha256",
            "sourceInputApprovalSha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
        },
        f"{label} source roots",
    )
    build = exact_object(
        identity["build"],
        {
            "builderCoreSha256s",
            "buildWatchdogReceiptSha256",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "dependencyClosureSha256",
            "eifBuildCoreSha256",
            "importedImageMappingsSha256",
            "promotedManifestSha256",
            "promotionReceiptSha256",
            "releaseCoreSha256",
        },
        f"{label} build roots",
    )
    eif = exact_object(
        identity["eif"],
        {"imageSha384", "pcrs"},
        f"{label} EIF roots",
    )
    policy = exact_object(
        identity["policy"],
        {"hash", "sequence"},
        f"{label} policy roots",
    )
    configuration = exact_object(
        identity["configuration"],
        {
            "caSpkiSha256",
            "publicAttestation",
            "releaseKeySpkiSha256",
            "responseKeySpkiSha256",
            "tlsScopeSigningKeySpkiSha256",
            "trustRootBundleSha256",
            "witnessKeySpkiSha256",
        },
        f"{label} configuration roots",
    )
    monotonic = exact_object(
        identity["monotonicRelease"],
        {"releaseGeneration", "rollbackEpoch"},
        f"{label} monotonic release",
    )
    for field, digest in source.items():
        require_sha256(digest, f"{label} source {field}")
    for field, digest in build.items():
        if field != "builderCoreSha256s":
            require_sha256(digest, f"{label} build {field}")
    for field in (
        "caSpkiSha256",
        "releaseKeySpkiSha256",
        "responseKeySpkiSha256",
        "tlsScopeSigningKeySpkiSha256",
        "trustRootBundleSha256",
        "witnessKeySpkiSha256",
    ):
        require_sha256(
            configuration[field],
            f"{label} configuration {field}",
        )
    validate_component_pins(
        configuration["publicAttestation"],
        f"{label} public attestation component pins",
    )
    builders = build["builderCoreSha256s"]
    require(
        isinstance(builders, list)
        and len(builders) == 2
        and builders == sorted(set(builders)),
        f"{label} builder roots are not unique canonical pairs",
    )
    for digest in builders:
        require_sha256(digest, f"{label} builder root")
    image_sha384 = require_sha384(
        eif["imageSha384"],
        f"{label} EIF image",
    )
    pcrs = exact_object(
        eif["pcrs"],
        {"PCR0", "PCR1", "PCR2"},
        f"{label} EIF PCRs",
    )
    for name, digest in pcrs.items():
        require_sha384(digest, f"{label} {name}")
    require(
        pcrs["PCR0"] == image_sha384,
        f"{label} EIF image differs from PCR0",
    )
    require_sha256(policy["hash"], f"{label} policy hash")
    require_u64(
        policy["sequence"],
        f"{label} policy sequence",
        minimum=1,
    )
    require_u64(
        monotonic["releaseGeneration"],
        f"{label} release generation",
        minimum=1,
    )
    require_u64(
        monotonic["rollbackEpoch"],
        f"{label} rollback epoch",
    )
    return identity


def load_ed25519_key_record(
    value: Any,
    label: str,
) -> tuple[Ed25519PublicKey, str]:
    record = exact_object(
        value,
        {"fileBase64url", "keyFileSha256", "keyId", "rawKeySha256"},
        label,
    )
    key_file = base64url_decode(
        record["fileBase64url"],
        f"{label} file",
        maximum=8192,
    )
    require(
        record["keyFileSha256"] == sha256_bytes(key_file),
        f"{label} key-file digest is invalid",
    )
    try:
        if key_file.startswith(b"-----BEGIN PUBLIC KEY-----"):
            key = serialization.load_pem_public_key(key_file)
        else:
            key = serialization.load_der_public_key(key_file)
    except ValueError as exc:
        raise ContractError(f"{label} is not a public key") from exc
    require(isinstance(key, Ed25519PublicKey), f"{label} is not Ed25519")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_id = sha256_bytes(der)
    require(
        record["keyId"] == key_id
        and record["rawKeySha256"] == sha256_bytes(raw),
        f"{label} key identity is invalid",
    )
    return key, key_id


def validate_trust_roots_document(
    value: Any,
    raw: bytes,
    *,
    independently_expected_sha256: str,
) -> dict[str, Any]:
    document = exact_object(
        value,
        {
            "apiVersion",
            "awsNitroCrlsDerBase64url",
            "awsNitroRootCertificatesPem",
            "keys",
            "nitroCertificateProfile",
        },
        "public trust roots",
    )
    require(
        document["apiVersion"] == TRUST_ROOTS_VERSION
        and sha256_bytes(raw) == independently_expected_sha256,
        "public trust roots crossed their independent digest",
    )
    roots_value = document["awsNitroRootCertificatesPem"]
    require(
        isinstance(roots_value, list)
        and 1 <= len(roots_value) <= MAX_CERTIFICATES,
        "AWS Nitro root inventory is invalid",
    )
    root_digests: list[str] = []
    for index, pem in enumerate(roots_value):
        try:
            require(
                isinstance(pem, str),
                f"AWS Nitro root {index} is invalid",
            )
            pem_bytes = pem.encode("ascii")
            require(
                len(pem_bytes) <= MAX_CERT_BYTES,
                f"AWS Nitro root {index} is invalid",
            )
            certificate = x509.load_pem_x509_certificate(
                pem_bytes
            )
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except (
            UnicodeEncodeError,
            ValueError,
            x509.ExtensionNotFound,
        ) as exc:
            raise ContractError(f"AWS Nitro root {index} is invalid") from exc
        require(constraints.ca, f"AWS Nitro root {index} is not a CA")
        root_digests.append(
            sha256_bytes(
                certificate.public_bytes(serialization.Encoding.DER)
            )
        )
    require(
        len(root_digests) == len(set(root_digests)),
        "AWS Nitro roots are duplicated",
    )
    crls_value = document["awsNitroCrlsDerBase64url"]
    require(
        isinstance(crls_value, list)
        and 1 <= len(crls_value) <= MAX_CERTIFICATES,
        "AWS Nitro CRL inventory is invalid",
    )
    crl_digests: list[str] = []
    for index, encoded in enumerate(crls_value):
        der = base64url_decode(
            encoded,
            f"AWS Nitro CRL {index}",
            maximum=MAX_CERT_BYTES,
        )
        try:
            crl = x509.load_der_x509_crl(der)
        except ValueError as exc:
            raise ContractError(f"AWS Nitro CRL {index} is invalid") from exc
        crl_digests.append(
            sha256_bytes(crl.public_bytes(serialization.Encoding.DER))
        )
    require(
        len(crl_digests) == len(set(crl_digests)),
        "AWS Nitro CRLs are duplicated",
    )
    profile = exact_object(
        document["nitroCertificateProfile"],
        {"allowedLeafExtendedKeyUsageOids", "profileId"},
        "Nitro certificate profile",
    )
    oids = profile["allowedLeafExtendedKeyUsageOids"]
    require(
        profile["profileId"] == "aws-nitro-attestation-pki-offline-v1"
        and isinstance(oids, list)
        and oids == sorted(set(oids))
        and all(
            isinstance(oid, str)
            and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", oid) is not None
            for oid in oids
        ),
        "Nitro certificate profile is invalid",
    )
    keys_value = exact_object(
        document["keys"],
        set(TRUST_KEY_ROLES),
        "public trust-root keys",
    )
    keys: dict[str, Ed25519PublicKey] = {}
    key_ids: dict[str, str] = {}
    for role in TRUST_KEY_ROLES:
        key, key_id = load_ed25519_key_record(
            keys_value[role],
            f"{role} trust root",
        )
        keys[role] = key
        key_ids[role] = key_id
    require(
        len(set(key_ids.values())) == len(key_ids),
        "independent trust roles reuse a key",
    )
    return {
        "keys": keys,
        "keyIds": key_ids,
        "trustRootBundleSha256": independently_expected_sha256,
    }


def verify_standard_envelope(
    value: Any,
    *,
    api_version: str,
    domain: bytes,
    key: Ed25519PublicKey,
    key_id: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    document = exact_object(
        value,
        {"apiVersion", "payload", "payloadSha256", "signature", "signingKeyId"},
        label,
    )
    require(
        document["apiVersion"] == api_version
        and document["signingKeyId"] == key_id,
        f"{label} version or key identity is invalid",
    )
    payload = document["payload"]
    payload_sha256 = require_sha256(
        document["payloadSha256"],
        f"{label} payload",
    )
    require(
        payload_sha256 == sha256_json(payload),
        f"{label} payload digest is invalid",
    )
    signature = base64url_decode(
        document["signature"],
        f"{label} signature",
        exact_length=64,
        maximum=64,
    )
    signed = domain + canonical_json(
        {
            "payload": payload,
            "payloadSha256": payload_sha256,
        }
    )
    try:
        key.verify(signature, signed)
    except InvalidSignature as exc:
        raise ContractError(f"{label} signature is invalid") from exc
    require(isinstance(payload, dict), f"{label} payload is not an object")
    return payload, sha256_bytes(canonical_json(document) + b"\n")


def verify_service_envelope(
    value: Any,
    *,
    api_version: str,
    domain: bytes,
    key: Ed25519PublicKey,
    key_id: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    document = exact_object(
        value,
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
    payload = document["payload"]
    payload_sha256 = require_sha256(
        document["payloadSha256"],
        f"{label} payload",
    )
    require(
        document["apiVersion"] == api_version
        and document["signatureAlgorithm"] == "Ed25519"
        and document["signingKeyId"] == key_id
        and document["signingKeySpkiSha256"] == key_id
        and isinstance(payload, dict)
        and payload_sha256 == sha256_json(payload),
        f"{label} version, key, or payload digest is invalid",
    )
    signature = base64url_decode(
        document["signatureBase64url"],
        f"{label} signature",
        exact_length=64,
        maximum=64,
    )
    try:
        key.verify(
            signature,
            domain
            + canonical_json(
                {
                    "payload": payload,
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise ContractError(f"{label} signature is invalid") from exc
    return payload, sha256_json(document)


def verify_stable_release(
    value: Any,
    *,
    trust: Mapping[str, Any],
) -> dict[str, Any]:
    payload, statement_sha256 = verify_standard_envelope(
        value,
        api_version=STABLE_STATEMENT_VERSION,
        domain=STABLE_STATEMENT_DOMAIN,
        key=trust["keys"]["completion"],
        key_id=trust["keyIds"]["completion"],
        label="stable release statement",
    )
    payload = exact_object(
        payload,
        {
            "attestationPins",
            "releaseIdentity",
            "releaseIdentitySha256",
            "trustRootBundleSha256",
        },
        "stable release statement payload",
    )
    release_identity = validate_release_identity(
        payload["releaseIdentity"],
        label="authenticated stable release identity",
    )
    release_identity_sha256 = sha256_json(release_identity)
    pins = statement_pins(
        payload["attestationPins"],
        "stable release attestation pins",
    )
    require(
        payload["releaseIdentitySha256"] == release_identity_sha256
        and payload["trustRootBundleSha256"]
        == trust["trustRootBundleSha256"]
        == release_identity["configuration"]["trustRootBundleSha256"]
        == pins["trustRootsSha256"]
        and component_pins_from_statement(pins)
        == release_identity["configuration"]["publicAttestation"]
        and trust["keyIds"]["completion"]
        == release_identity["configuration"]["releaseKeySpkiSha256"]
        and trust["keyIds"]["witness"]
        == release_identity["configuration"]["witnessKeySpkiSha256"],
        "stable release statement crossed identity or trust roots",
    )
    return {
        "attestationPins": pins,
        "releaseIdentity": release_identity,
        "releaseIdentitySha256": release_identity_sha256,
        "statementSha256": statement_sha256,
    }


def ed25519_spki(
    encoded: Any,
    *,
    expected_sha256: str,
    label: str,
) -> Ed25519PublicKey:
    der = base64url_decode(
        encoded,
        label,
        exact_length=44,
        maximum=44,
    )
    require(
        sha256_bytes(der) == expected_sha256,
        f"{label} differs from its stable digest",
    )
    try:
        key = serialization.load_der_public_key(der)
    except ValueError as exc:
        raise ContractError(f"{label} is not a public key") from exc
    require(
        isinstance(key, Ed25519PublicKey),
        f"{label} is not Ed25519",
    )
    canonical_der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    require(canonical_der == der, f"{label} is not canonical SPKI DER")
    return key


def embedded_ed25519_spki(
    encoded: Any,
    *,
    label: str,
) -> tuple[Ed25519PublicKey, str]:
    der = base64url_decode(
        encoded,
        label,
        exact_length=44,
        maximum=44,
    )
    key_id = sha256_bytes(der)
    return (
        ed25519_spki(
            encoded,
            expected_sha256=key_id,
            label=label,
        ),
        key_id,
    )


def validate_nonce_authority_assurance(
    value: Any,
    *,
    expected_authority_identity_sha256: str,
) -> dict[str, Any]:
    assurance = exact_object(
        value,
        NONCE_AUTHORITY_ASSURANCE_FIELDS,
        "nonce authority assurance",
    )
    rollback = exact_object(
        assurance["rollbackProtection"],
        NONCE_AUTHORITY_ROLLBACK_FIELDS,
        "nonce authority rollback protection",
    )
    require(
        assurance["apiVersion"] == NONCE_AUTHORITY_ASSURANCE_VERSION
        and assurance["authorityIdentitySha256"]
        == require_sha256(
            expected_authority_identity_sha256,
            "expected nonce authority identity",
        )
        and require_sha256(
            assurance["administrativeDomainSha256"],
            "nonce authority administrative domain",
        )
        == assurance["administrativeDomainSha256"]
        and require_u64(
            assurance["authorityEpoch"],
            "nonce authority epoch",
            minimum=1,
        )
        >= 1
        and require_u64(
            assurance["authorityGeneration"],
            "nonce authority generation",
            minimum=1,
        )
        >= 1
        and rollback["exactSuccessorRequired"] is True
        and rollback["freshVerifierChallengeRequired"] is True,
        "nonce authority assurance crossed its identity or continuity contract",
    )
    profile = (
        assurance["backendClass"],
        rollback["mechanism"],
        rollback["keyProtection"],
        rollback["stateCommitment"],
        rollback["verifierStateStoreClass"],
        assurance["assuranceEvidenceType"],
    )
    if assurance["productionEligible"] is True:
        require(
            assurance["assuranceLevel"]
            == "productionRollbackProtected"
            and require_sha256(
                assurance["assuranceEvidenceSha256"],
                "nonce authority assurance evidence",
            )
            == assurance["assuranceEvidenceSha256"]
            and rollback["administrativeRollbackResistance"] is True
            and rollback["backendAttestationRequired"] is True
            and profile in PRODUCTION_NONCE_AUTHORITY_PROFILES,
            "nonce authority production profile is not structurally closed",
        )
    else:
        require(
            assurance["productionEligible"] is False
            and assurance["assuranceLevel"]
            in {
                "nonProductionFixture",
                "nonProductionDurableReference",
            }
            and assurance["assuranceEvidenceSha256"] is None
            and rollback["administrativeRollbackResistance"] is False
            and rollback["backendAttestationRequired"] is False
            and profile
            == (
                "nonProductionSqlite",
                "none",
                "retainedFdReference",
                "localHashChain",
                "nonProductionCallerFile",
                "none",
            ),
            "nonce authority non-production profile is not closed",
        )
    # Structural validation does not establish production assurance. The final
    # verifier must independently pin the digest and validate external evidence.
    return assurance


def validate_nonce_authority_assurance_evidence(
    value: Any,
    *,
    key: Ed25519PublicKey,
    key_id: str,
    assurance: Mapping[str, Any],
    nonce_store_key_id: str,
    verifier_state_key_id: str,
    verifier_state_store_identity_sha256: str,
    verifier_state_store_administrative_domain_sha256: str,
    now: int,
) -> dict[str, Any] | None:
    if assurance["productionEligible"] is not True:
        require(
            value is None,
            "non-production assurance must not carry assurance evidence",
        )
        return None
    payload, envelope_sha256 = verify_service_envelope(
        value,
        api_version=(
            SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
        ),
        domain=NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN,
        key=key,
        key_id=key_id,
        label="nonce authority assurance evidence",
    )
    payload = exact_object(
        payload,
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
    issued = require_u64(
        payload["issuedAtUnix"],
        "nonce authority assurance evidence issue time",
        minimum=1,
    )
    expires = require_u64(
        payload["expiresAtUnix"],
        "nonce authority assurance evidence expiry",
        minimum=1,
    )
    rollback = assurance["rollbackProtection"]
    require(
        envelope_sha256 == assurance["assuranceEvidenceSha256"]
        and payload["apiVersion"]
        == NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
        and payload["administrativeDomainSha256"]
        == assurance["administrativeDomainSha256"]
        and payload["assuranceEvidenceType"]
        == assurance["assuranceEvidenceType"]
        and payload["authorityEpoch"] == assurance["authorityEpoch"]
        and payload["authorityGeneration"]
        == assurance["authorityGeneration"]
        and payload["authorityIdentitySha256"]
        == assurance["authorityIdentitySha256"]
        and payload["backendClass"] == assurance["backendClass"]
        and payload["nonceAuthorityStateSigningKeySpkiSha256"]
        == nonce_store_key_id
        and payload["rollbackMechanism"] == rollback["mechanism"]
        and payload["stateCommitment"]
        == rollback["stateCommitment"]
        and payload["verifierStateStoreClass"]
        == rollback["verifierStateStoreClass"]
        and payload["verifierStateStoreIdentitySha256"]
        == verifier_state_store_identity_sha256
        and payload[
            "verifierStateStoreAdministrativeDomainSha256"
        ]
        == verifier_state_store_administrative_domain_sha256
        and payload["verifierStateStoreSigningKeySpkiSha256"]
        == verifier_state_key_id
        and verifier_state_store_administrative_domain_sha256
        != assurance["administrativeDomainSha256"]
        and issued <= now < expires
        and expires - issued <= 900,
        "nonce authority assurance evidence is stale or crossed",
    )
    return dict(value)


def validate_verifier_state_store_assurance(
    config: Mapping[str, Any],
    *,
    store_attestation_key_id: str,
    now: int,
) -> dict[str, Any]:
    evidence_key, evidence_key_id = embedded_ed25519_spki(
        config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
        ],
        label="verifier-state store assurance issuer key",
    )
    payload, envelope_sha256 = verify_service_envelope(
        config["nonceAuthorityVerifierStateStoreAssuranceEvidence"],
        api_version=SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION,
        domain=VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN,
        key=evidence_key,
        key_id=evidence_key_id,
        label="verifier-state store assurance evidence",
    )
    payload = exact_object(
        payload,
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
        "verifier-state store assurance payload",
    )
    issued = require_u64(
        payload["evidenceIssuedAtUnix"],
        "verifier-state store assurance issue time",
        minimum=1,
    )
    expires = require_u64(
        payload["evidenceExpiresAtUnix"],
        "verifier-state store assurance expiry",
        minimum=1,
    )
    minimum_generation = require_u64(
        payload["minimumStoreGeneration"],
        "verifier-state store assurance minimum generation",
        minimum=1,
    )
    minimum_commit_index = require_u64(
        payload["minimumStoreCommitIndex"],
        "verifier-state store assurance minimum commit index",
        minimum=1,
    )
    for field in (
        "issuerAdministrativeDomainSha256",
        "issuerCredentialIdentitySha256",
        "issuerIdentitySha256",
        "storeAdministrativeDomainSha256",
        "storeAttestationKeySpkiSha256",
        "storeConfigurationSha256",
        "storeCredentialIdentitySha256",
        "storeIdentitySha256",
    ):
        require_sha256(
            payload[field],
            f"verifier-state store assurance {field}",
        )
    require(
        envelope_sha256
        == config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ]
        and payload["apiVersion"]
        == VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION
        and payload["productionEligible"] is True
        and payload["generationSemantics"] == "strictlyMonotonicU64"
        and payload["commitIndexSemantics"]
        == "equalToVerifierStateGeneration"
        and payload["rollbackMechanism"]
        == config[
            "nonceAuthorityVerifierStateStoreRollbackMechanism"
        ]
        and payload["storeIdentitySha256"]
        == config["nonceAuthorityVerifierStateStoreIdentitySha256"]
        and payload["storeAdministrativeDomainSha256"]
        == config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ]
        and payload["storeCredentialIdentitySha256"]
        == config[
            "nonceAuthorityVerifierStateStoreCredentialIdentitySha256"
        ]
        and payload["storeAttestationKeySpkiSha256"]
        == store_attestation_key_id
        and payload["storeConfigurationSha256"]
        == config[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ]
        and payload["issuerAdministrativeDomainSha256"]
        == config[
            "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256"
        ]
        and payload["issuerCredentialIdentitySha256"]
        == config[
            "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256"
        ]
        and payload["issuerIdentitySha256"]
        == config[
            "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256"
        ]
        and minimum_generation
        == config[
            "nonceAuthorityVerifierStateStoreMinimumGeneration"
        ]
        and minimum_commit_index
        == config[
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
        ]
        and issued <= now < expires
        and expires - issued <= 86400,
        "verifier-state store assurance is stale, substituted, or incomplete",
    )
    require(
        len(
            {
                payload["issuerAdministrativeDomainSha256"],
                payload["storeAdministrativeDomainSha256"],
            }
        )
        == 2
        and len(
            {
                payload["issuerCredentialIdentitySha256"],
                payload["storeCredentialIdentitySha256"],
            }
        )
        == 2
        and payload["issuerIdentitySha256"]
        != payload["storeIdentitySha256"]
        and evidence_key_id != store_attestation_key_id,
        "verifier-state store assurance is self-attested",
    )
    return {
        "document": config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidence"
        ],
        "key": evidence_key,
        "keyId": evidence_key_id,
        "payload": payload,
        "sha256": envelope_sha256,
    }


def validate_verifier_state_role_separation(
    config: Mapping[str, Any],
    *,
    nonce_authority_assurance: Mapping[str, Any],
    nonce_store_key_id: str,
    verifier_state_key_id: str,
    store_attestation_key_id: str,
    store_assurance: Mapping[str, Any],
    service: Mapping[str, Any],
    now: int,
) -> dict[str, Any]:
    _assurance_evidence_key, assurance_evidence_key_id = (
        embedded_ed25519_spki(
            config[
                "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
            ],
            label="nonce authority assurance-evidence issuer key",
        )
    )
    evidence_key, evidence_key_id = embedded_ed25519_spki(
        config[
            "nonceAuthorityVerifierStateRoleSeparationEvidenceSigningPublicKeySpkiDerBase64url"
        ],
        label="verifier-state role-separation issuer key",
    )
    payload, envelope_sha256 = verify_service_envelope(
        config["nonceAuthorityVerifierStateRoleSeparationEvidence"],
        api_version=SIGNED_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION,
        domain=VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN,
        key=evidence_key,
        key_id=evidence_key_id,
        label="verifier-state role-separation evidence",
    )
    payload = exact_object(
        payload,
        {
            "apiVersion",
            "assuranceSha256",
            "evidenceExpiresAtUnix",
            "evidenceIssuedAtUnix",
            "nonceAuthority",
            "nonceAuthorityAssuranceEvidenceIssuer",
            "productionEligible",
            "publicAttestationClientTls",
            "roleSeparationEvidenceIssuer",
            "storeAssuranceEvidenceIssuer",
            "verifierStateServiceListenerTls",
            "verifierStateSigner",
            "verifierStateSignerClientTls",
            "verifierStateSignerServerTls",
            "verifierStateStore",
            "verifierStateStoreClientTls",
            "verifierStateStoreServerTls",
        },
        "verifier-state role-separation payload",
    )

    def role(value: Any, label: str) -> dict[str, Any]:
        result = exact_object(
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

    role_names = (
        "nonceAuthority",
        "nonceAuthorityAssuranceEvidenceIssuer",
        "publicAttestationClientTls",
        "roleSeparationEvidenceIssuer",
        "storeAssuranceEvidenceIssuer",
        "verifierStateServiceListenerTls",
        "verifierStateSigner",
        "verifierStateSignerClientTls",
        "verifierStateSignerServerTls",
        "verifierStateStore",
        "verifierStateStoreClientTls",
        "verifierStateStoreServerTls",
    )
    roles = {
        name: role(payload[name], f"{name} role")
        for name in role_names
    }
    pinned_issuer = role(
        config[
            "nonceAuthorityVerifierStateRoleSeparationEvidenceIssuer"
        ],
        "pinned role-separation issuer",
    )
    issued = require_u64(
        payload["evidenceIssuedAtUnix"],
        "verifier-state role-separation issue time",
        minimum=1,
    )
    expires = require_u64(
        payload["evidenceExpiresAtUnix"],
        "verifier-state role-separation expiry",
        minimum=1,
    )
    store_assurance_payload = store_assurance["payload"]
    require(
        sha256_json(
            config[
                "nonceAuthorityVerifierStateRoleSeparationEvidence"
            ]
        )
        == envelope_sha256
        and payload["apiVersion"]
        == VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION
        and payload["assuranceSha256"]
        == config["nonceAuthorityAssuranceSha256"]
        and payload["productionEligible"] is True
        and issued <= now < expires
        and expires - issued <= 86400
        and roles["roleSeparationEvidenceIssuer"] == pinned_issuer
        and roles["roleSeparationEvidenceIssuer"]["keySpkiSha256"]
        == evidence_key_id
        and roles["nonceAuthority"]["keySpkiSha256"]
        == nonce_store_key_id
        and roles["nonceAuthority"]["administrativeDomainSha256"]
        == nonce_authority_assurance["administrativeDomainSha256"]
        and roles["nonceAuthority"]["roleIdentitySha256"]
        == nonce_authority_assurance["authorityIdentitySha256"]
        and roles["nonceAuthority"]["assuranceEvidenceSha256"]
        == nonce_authority_assurance["assuranceEvidenceSha256"]
        and roles["nonceAuthorityAssuranceEvidenceIssuer"][
            "keySpkiSha256"
        ]
        == assurance_evidence_key_id
        and roles["verifierStateSigner"]["keySpkiSha256"]
        == verifier_state_key_id
        and roles["verifierStateStore"]["keySpkiSha256"]
        == store_attestation_key_id
        and roles["verifierStateStore"]["roleIdentitySha256"]
        == config["nonceAuthorityVerifierStateStoreIdentitySha256"]
        and roles["verifierStateStore"][
            "administrativeDomainSha256"
        ]
        == config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ]
        and roles["verifierStateStore"]["credentialIdentitySha256"]
        == config[
            "nonceAuthorityVerifierStateStoreCredentialIdentitySha256"
        ]
        and roles["verifierStateStore"]["assuranceEvidenceSha256"]
        == store_assurance["sha256"]
        and roles["storeAssuranceEvidenceIssuer"]["keySpkiSha256"]
        == store_assurance["keyId"]
        and roles["storeAssuranceEvidenceIssuer"][
            "administrativeDomainSha256"
        ]
        == store_assurance_payload[
            "issuerAdministrativeDomainSha256"
        ]
        and roles["storeAssuranceEvidenceIssuer"][
            "credentialIdentitySha256"
        ]
        == store_assurance_payload[
            "issuerCredentialIdentitySha256"
        ]
        and roles["storeAssuranceEvidenceIssuer"]["roleIdentitySha256"]
        == store_assurance_payload["issuerIdentitySha256"]
        and roles["publicAttestationClientTls"]["keySpkiSha256"]
        == service["clientCertificateSpkiSha256"]
        and roles["verifierStateServiceListenerTls"]["keySpkiSha256"]
        == service["serverLeafSpkiSha256"],
        "verifier-state role-separation evidence is stale or crossed",
    )
    for field in (
        "administrativeDomainSha256",
        "credentialIdentitySha256",
        "endpointIdentitySha256",
        "keySpkiSha256",
        "roleIdentitySha256",
    ):
        require(
            len({roles[name][field] for name in role_names})
            == len(role_names),
            f"verifier-state roles collide on {field}",
        )
    return {
        "document": config[
            "nonceAuthorityVerifierStateRoleSeparationEvidence"
        ],
        "key": evidence_key,
        "keyId": evidence_key_id,
        "payload": payload,
        "roleKeyIdsByRole": {
            name: roles[name]["keySpkiSha256"]
            for name in role_names
        },
        "roleKeyIds": tuple(
            roles[name]["keySpkiSha256"]
            for name in role_names
        ),
        "sha256": envelope_sha256,
    }


def validate_release_config(
    raw: bytes,
    *,
    pins: Mapping[str, str],
    release_identity: Mapping[str, Any],
    trust_key_ids: Mapping[str, str],
) -> tuple[
    dict[str, Any],
    Ed25519PublicKey,
    Ed25519PublicKey,
    Ed25519PublicKey,
    Ed25519PublicKey,
    Ed25519PublicKey,
]:
    document = strict_json_line(
        raw,
        "immutable public attestation config",
        MAX_CONFIG_BYTES,
    )
    config = exact_object(
        document,
        {
            "apiVersion",
            "minimumRollbackContinuityCommitmentSha256",
            "nonceAuthorityAssurance",
            "nonceAuthorityAssuranceEvidence",
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityAssuranceSha256",
            "nonceAuthorityVerifierStateService",
            "nonceAuthorityVerifierStateRoleSeparationEvidence",
            "nonceAuthorityVerifierStateRoleSeparationEvidenceIssuer",
            "nonceAuthorityVerifierStateRoleSeparationEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256",
            "nonceAuthorityVerifierStateStoreAssuranceEvidence",
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256",
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256",
            "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256",
            "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256",
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreConfigurationSha256",
            "nonceAuthorityVerifierStateStoreCredentialIdentitySha256",
            "nonceAuthorityVerifierStateStoreIdentitySha256",
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex",
            "nonceAuthorityVerifierStateStoreMinimumGeneration",
            "nonceAuthorityVerifierStateStoreRollbackMechanism",
            "nonceStoreSigningPublicKeySpkiDerBase64url",
            "producerPolicy",
            "releaseIdentity",
            "releaseIdentitySha256",
            "sandboxDescriptorSha256",
            "tlsScopeSigningPublicKeySpkiDerBase64url",
            "witnessStoreSigningPublicKeySpkiDerBase64url",
        },
        "immutable public attestation config",
    )
    require(
        config["apiVersion"] == RELEASE_CONFIG_VERSION,
        "immutable config version is invalid",
    )
    require(
        sha256_bytes(raw) == pins["immutableConfigSha256"],
        "immutable config digest differs from stable pins",
    )
    validated_identity = validate_release_identity(
        config["releaseIdentity"],
        label="immutable config release identity",
    )
    require(
        validated_identity == release_identity
        and config["releaseIdentitySha256"]
        == sha256_json(release_identity)
        and config["sandboxDescriptorSha256"]
        == pins["sandboxDescriptorSha256"],
        "immutable config crossed its stable release identity",
    )
    require_sha256(
        config["minimumRollbackContinuityCommitmentSha256"],
        "immutable config minimum rollback continuity commitment",
    )
    nonce_authority_assurance = validate_nonce_authority_assurance(
        config["nonceAuthorityAssurance"],
        expected_authority_identity_sha256=pins[
            "nonceStoreIdentitySha256"
        ],
    )
    nonce_authority_assurance_sha256 = sha256_json(
        nonce_authority_assurance
    )
    require(
        config["nonceAuthorityAssuranceSha256"]
        == nonce_authority_assurance_sha256,
        "immutable config nonce authority assurance digest is invalid",
    )
    verifier_state_key, verifier_state_key_id = (
        embedded_ed25519_spki(
            config[
                "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
            ],
            label="nonce authority verifier-state signing public key",
        )
    )
    assurance_evidence_key, assurance_evidence_key_id = (
        embedded_ed25519_spki(
            config[
                "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
            ],
            label="nonce authority assurance-evidence signing public key",
        )
    )
    verifier_state_store_attestation_key, store_attestation_key_id = (
        embedded_ed25519_spki(
            config[
                "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
            ],
            label="verifier-state store attestation public key",
        )
    )
    require_sha256(
        config["nonceAuthorityVerifierStateStoreIdentitySha256"],
        "nonce authority verifier-state store identity",
    )
    verifier_state_administrative_domain_sha256 = require_sha256(
        config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        "nonce authority verifier-state administrative domain",
    )
    require(
        verifier_state_administrative_domain_sha256
        != nonce_authority_assurance["administrativeDomainSha256"],
        "nonce authority and verifier-state store share an administrative domain",
    )
    verifier_state_store_identity_sha256 = require_sha256(
        config["nonceAuthorityVerifierStateStoreIdentitySha256"],
        "nonce authority verifier-state store identity",
    )
    require(
        nonce_authority_assurance["productionEligible"] is True,
        "public production producer requires production nonce assurance",
    )
    require_sha256(
        config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ],
        "verifier-state store assurance evidence",
    )
    require_sha256(
        config[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ],
        "verifier-state store configuration",
    )
    require_sha256(
        config[
            "nonceAuthorityVerifierStateStoreCredentialIdentitySha256"
        ],
        "verifier-state store credential identity",
    )
    for field in (
        "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256",
        "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256",
        "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256",
    ):
        require_sha256(config[field], field)
    require_u64(
        config["nonceAuthorityVerifierStateStoreMinimumGeneration"],
        "verifier-state store minimum generation",
        minimum=1,
    )
    require_u64(
        config["nonceAuthorityVerifierStateStoreMinimumCommitIndex"],
        "verifier-state store minimum commit index",
        minimum=1,
    )
    require(
        isinstance(
            config["nonceAuthorityVerifierStateStoreRollbackMechanism"],
            str,
        )
        and 1
        <= len(
            config[
                "nonceAuthorityVerifierStateStoreRollbackMechanism"
            ]
        )
        <= 256,
        "verifier-state store rollback mechanism is invalid",
    )
    require(
        verifier_state_store_identity_sha256
        != nonce_authority_assurance["authorityIdentitySha256"],
        "nonce authority and verifier-state store share an identity",
    )
    service = exact_object(
        config["nonceAuthorityVerifierStateService"],
        {
            "abortPath",
            "apiVersion",
            "attachNonceStatusPath",
            "clientCertificateSpkiSha256",
            "commitPath",
            "concurrencyLimit",
            "endpoint",
            "issueChallengePath",
            "markConsumptionPath",
            "maxResponseBytes",
            "preparePath",
            "readPath",
            "recoverPath",
            "recoverChallengePath",
            "recoveryLookupPath",
            "serverLeafSpkiSha256",
            "serviceConfigurationSha256",
            "timeoutMilliseconds",
        },
        "immutable verifier-state service",
    )
    endpoint = service["endpoint"]
    try:
        parsed_endpoint = urllib.parse.urlsplit(endpoint)
        endpoint_port = parsed_endpoint.port
        packed_endpoint_address = socket.inet_pton(
            socket.AF_INET,
            str(parsed_endpoint.hostname),
        )
    except (TypeError, ValueError) as exc:
        raise ContractError(
            "immutable verifier-state endpoint is invalid"
        ) from exc
    except OSError as exc:
        raise ContractError(
            "immutable verifier-state endpoint must use a literal IPv4 address"
        ) from exc
    require(
        service["apiVersion"] == VERIFIER_STATE_CLIENT_VERSION
        and isinstance(endpoint, str)
        and parsed_endpoint.scheme == "https"
        and parsed_endpoint.hostname is not None
        and socket.inet_ntop(
            socket.AF_INET,
            packed_endpoint_address,
        )
        == parsed_endpoint.hostname
        and endpoint_port is not None
        and 1 <= endpoint_port <= 65535
        and parsed_endpoint.path == ""
        and not parsed_endpoint.query
        and not parsed_endpoint.fragment
        and parsed_endpoint.username is None
        and parsed_endpoint.password is None
        and parsed_endpoint.netloc
        == endpoint.removeprefix("https://")
        and service["readPath"] == "/v1/state/read"
        and service["issueChallengePath"]
        == "/v1/state/issue-challenge"
        and service["recoverChallengePath"]
        == "/v1/state/recover-challenge"
        and service["preparePath"] == "/v1/state/prepare"
        and service["recoveryLookupPath"]
        == "/v1/state/recovery-lookup"
        and service["markConsumptionPath"]
        == "/v1/state/mark-consumption"
        and service["attachNonceStatusPath"]
        == "/v1/state/attach-nonce-status"
        and service["abortPath"] == "/v1/state/abort"
        and service["commitPath"] == "/v1/state/commit"
        and service["recoverPath"] == "/v1/state/recover"
        and require_u64(
            service["concurrencyLimit"],
            "verifier-state service concurrency",
            minimum=1,
        )
        == 1
        and 1024
        <= require_u64(
            service["maxResponseBytes"],
            "verifier-state response bound",
            minimum=1,
        )
        <= 256 * 1024
        and 100
        <= require_u64(
            service["timeoutMilliseconds"],
            "verifier-state timeout",
            minimum=1,
        )
        <= 10_000,
        "immutable verifier-state service contract is invalid",
    )
    for field in (
        "clientCertificateSpkiSha256",
        "serverLeafSpkiSha256",
        "serviceConfigurationSha256",
    ):
        require_sha256(
            service[field],
            f"immutable verifier-state service {field}",
        )
    validate_nonce_authority_assurance_evidence(
        config["nonceAuthorityAssuranceEvidence"],
        key=assurance_evidence_key,
        key_id=assurance_evidence_key_id,
        assurance=nonce_authority_assurance,
        nonce_store_key_id=pins["nonceStoreKeySpkiSha256"],
        verifier_state_key_id=verifier_state_key_id,
        verifier_state_store_identity_sha256=(
            verifier_state_store_identity_sha256
        ),
        verifier_state_store_administrative_domain_sha256=(
            verifier_state_administrative_domain_sha256
        ),
        now=int(time.time()),
    )
    evidence_now = int(time.time())
    store_assurance = validate_verifier_state_store_assurance(
        config,
        store_attestation_key_id=store_attestation_key_id,
        now=evidence_now,
    )
    role_separation = validate_verifier_state_role_separation(
        config,
        nonce_authority_assurance=nonce_authority_assurance,
        nonce_store_key_id=pins["nonceStoreKeySpkiSha256"],
        verifier_state_key_id=verifier_state_key_id,
        store_attestation_key_id=store_attestation_key_id,
        store_assurance=store_assurance,
        service=service,
        now=evidence_now,
    )
    expected_components = component_pins_from_statement(pins)
    policy = exact_object(
        config["producerPolicy"],
        COMPONENT_PIN_FIELDS,
        "immutable producer policy",
    )
    require(
        policy == expected_components
        and release_identity["configuration"]["publicAttestation"]
        == expected_components,
        "immutable producer policy crossed stable component pins",
    )
    tls_scope_key = ed25519_spki(
        config["tlsScopeSigningPublicKeySpkiDerBase64url"],
        expected_sha256=release_identity["configuration"][
            "tlsScopeSigningKeySpkiSha256"
        ],
        label="TLS-scope signing public key",
    )
    witness_store_key = ed25519_spki(
        config["witnessStoreSigningPublicKeySpkiDerBase64url"],
        expected_sha256=pins["witnessStoreKeySpkiSha256"],
        label="witness-store signing public key",
    )
    nonce_store_key = ed25519_spki(
        config["nonceStoreSigningPublicKeySpkiDerBase64url"],
        expected_sha256=pins["nonceStoreKeySpkiSha256"],
        label="nonce-store signing public key",
    )
    require(
        set(trust_key_ids) == set(TRUST_KEY_ROLES)
        and release_identity["configuration"]["releaseKeySpkiSha256"]
        == trust_key_ids["completion"]
        and release_identity["configuration"]["witnessKeySpkiSha256"]
        == trust_key_ids["witness"],
        "release/witness aliases do not match the canonical trust-root roles",
    )
    global_role_key_ids = {
        **role_separation["roleKeyIdsByRole"],
        "release": release_identity["configuration"][
            "releaseKeySpkiSha256"
        ],
        "releaseCa": release_identity["configuration"]["caSpkiSha256"],
        "responseKey": release_identity["configuration"][
            "responseKeySpkiSha256"
        ],
        "tlsScope": release_identity["configuration"][
            "tlsScopeSigningKeySpkiSha256"
        ],
        "witness": release_identity["configuration"][
            "witnessKeySpkiSha256"
        ],
        "witnessStore": pins["witnessStoreKeySpkiSha256"],
        **{
            f"trustRoot:{name}": trust_key_ids[name]
            for name in sorted(trust_key_ids)
            if name not in {"completion", "witness"}
        },
    }
    validate_global_attestation_key_role_separation(
        global_role_key_ids,
        expected_roles=global_role_key_ids,
    )
    del tls_scope_key
    return (
        config,
        nonce_store_key,
        witness_store_key,
        verifier_state_key,
        assurance_evidence_key,
        verifier_state_store_attestation_key,
    )


def load_trust_roots(
    raw: bytes,
    *,
    independently_expected_sha256: str,
) -> dict[str, Any]:
    document = strict_json_line(
        raw,
        "public Nitro trust roots",
        MAX_TRUST_ROOT_BYTES,
    )
    return validate_trust_roots_document(
        document,
        raw,
        independently_expected_sha256=independently_expected_sha256,
    )


def static_artifact_bytes(args: argparse.Namespace) -> dict[str, bytes]:
    return {
        "descriptorSha256": read_immutable_fd(
            args.producer_descriptor_fd,
            maximum=MAX_DESCRIPTOR_BYTES,
            label="producer descriptor",
        ),
        "executableSha256": read_immutable_fd(
            args.producer_executable_fd,
            maximum=MAX_EXECUTABLE_BYTES,
            label="producer executable",
        ),
        "immutableConfigSha256": read_immutable_fd(
            args.immutable_config_fd,
            maximum=MAX_CONFIG_BYTES,
            label="immutable producer config",
        ),
        "producerRequestSchemaSha256": read_immutable_fd(
            args.producer_request_schema_fd,
            maximum=MAX_SCHEMA_BYTES,
            label="producer request schema",
        ),
        "sandboxDescriptorSha256": read_immutable_fd(
            args.sandbox_descriptor_fd,
            maximum=MAX_SANDBOX_DESCRIPTOR_BYTES,
            label="sandbox descriptor",
        ),
        "sandboxLauncherSha256": read_immutable_fd(
            args.sandbox_launcher_fd,
            maximum=MAX_EXECUTABLE_BYTES,
            label="sandbox launcher",
        ),
        "trustRootsSha256": read_immutable_fd(
            args.trust_roots_fd,
            maximum=MAX_TRUST_ROOT_BYTES,
            label="public Nitro trust roots",
        ),
    }


def verify_static_artifacts(
    artifacts: Mapping[str, bytes],
    pins: Mapping[str, str],
) -> None:
    for pin_name, raw in artifacts.items():
        require(
            sha256_bytes(raw) == pins[pin_name],
            f"{pin_name} differs from its stable pin",
        )


def issue_stable_release_signature(
    *,
    key: Ed25519PublicKey,
    key_id: str,
    approved_issuer_request_sha256: str,
    authorization_nonce: bytearray,
    preauthorization: Mapping[str, Any],
    statement_payload: Mapping[str, Any],
    request_fd: int,
    response_fd: int,
    maximum_request: int,
    maximum_response: int,
    timeout_ms: int,
    deadline: float,
) -> str:
    # The signer must retrieve this exact record from its own rollback-resistant
    # preauthorization store, enforce its monotonic high-water mark, and
    # atomically consume it before reconstructing the fixed-domain message. The
    # retained-FD caller supplies no arbitrary message or signature domain.
    validate_retained_pipe_fd(
        request_fd,
        label="release signer request",
        writable=True,
    )
    validate_retained_pipe_fd(
        response_fd,
        label="release signer response",
        writable=False,
    )
    preauthorization_document = dict(preauthorization)
    statement_payload_document = dict(statement_payload)
    authorization_nonce_base64url = base64url_encode(
        authorization_nonce
    )
    authorization_nonce_sha256 = sha256_bytes(authorization_nonce)
    statement_payload_sha256 = sha256_json(statement_payload_document)
    require(
        preauthorization_document["approvedIssuerRequestSha256"]
        == approved_issuer_request_sha256
        and preauthorization_document["authorizationNonceSha256"]
        == authorization_nonce_sha256
        and preauthorization_document["statementPayloadSha256"]
        == statement_payload_sha256,
        "release signing preauthorization crossed issuer input",
    )
    signing_core = {
        "payload": statement_payload_document,
        "payloadSha256": statement_payload_sha256,
    }
    message = STABLE_STATEMENT_DOMAIN + canonical_json(signing_core)
    message_sha256 = sha256_bytes(message)
    preauthorization_sha256 = sha256_json(preauthorization_document)
    request = {
        "algorithm": "Ed25519",
        "apiVersion": SIGN_REQUEST_VERSION,
        "authorizationNonceBase64url": authorization_nonce_base64url,
        "keyId": key_id,
        "preauthorization": preauthorization_document,
        "preauthorizationSha256": preauthorization_sha256,
        "purpose": "stable-release-statement",
        "statementPayload": statement_payload_document,
        "statementPayloadSha256": statement_payload_sha256,
    }
    write_json_line_fd(
        request_fd,
        request,
        maximum=maximum_request,
        timeout_ms=timeout_ms,
        label="release signer request",
        deadline=deadline,
    )
    # Python's JSON and base64 APIs necessarily leave immutable serialized
    # copies until allocator reclamation. Drop live references promptly; the
    # mutable source buffer is wiped by the caller on every exit path.
    request.clear()
    authorization_nonce_base64url = ""
    response_value, _ = read_json_line_fd(
        response_fd,
        maximum=maximum_response,
        timeout_ms=timeout_ms,
        label="release signer response",
        deadline=deadline,
    )
    response = exact_object(
        response_value,
        {
            "algorithm",
            "apiVersion",
            "approvedIssuerRequestSha256",
            "authorizationIdBase64url",
            "authorizationSequence",
            "keyId",
            "messageSha256",
            "preauthorizationSha256",
            "releaseIdentitySha256",
            "signatureBase64url",
            "statementPayloadSha256",
        },
        "release signer response",
    )
    require(
        response["apiVersion"] == SIGN_RESPONSE_VERSION
        and response["algorithm"] == "Ed25519"
        and response["keyId"] == key_id
        and response["approvedIssuerRequestSha256"]
        == approved_issuer_request_sha256
        and response["authorizationIdBase64url"]
        == preauthorization_document["authorizationIdBase64url"]
        and response["authorizationSequence"]
        == preauthorization_document["authorizationSequence"]
        and response["messageSha256"] == message_sha256,
        "release signer response crossed its command",
    )
    require(
        response["preauthorizationSha256"] == preauthorization_sha256
        and response["releaseIdentitySha256"]
        == preauthorization_document["releaseIdentitySha256"]
        and response["statementPayloadSha256"]
        == statement_payload_sha256,
        "release signer response crossed its command",
    )
    signature = base64url_decode(
        response["signatureBase64url"],
        "release signer signature",
        exact_length=64,
        maximum=64,
    )
    try:
        key.verify(signature, message)
    except InvalidSignature as exc:
        raise ContractError("release signer returned an invalid signature") from exc
    return base64url_encode(signature)


def validate_release_signing_preauthorization(
    value: Any,
    *,
    pins: Mapping[str, str],
    release_identity: Mapping[str, Any],
    release_identity_sha256: str,
) -> dict[str, Any]:
    preauthorization = exact_object(
        value,
        {
            "authorizationExpiresAtUnix",
            "authorizationIdBase64url",
            "authorizationIssuedAtUnix",
            "authorizationNonceSha256",
            "authorizationSequence",
            "minimumPolicySequence",
            "minimumReleaseGeneration",
            "minimumRollbackEpoch",
            "releaseIdentitySha256",
            "statementPayloadSha256",
            "useLimit",
        },
        "release signing preauthorization",
    )
    base64url_decode(
        preauthorization["authorizationIdBase64url"],
        "release signing authorization id",
        exact_length=32,
        maximum=32,
    )
    require_sha256(
        preauthorization["authorizationNonceSha256"],
        "release signing authorization nonce",
    )
    require_sha256(
        preauthorization["releaseIdentitySha256"],
        "release signing release identity",
    )
    require_sha256(
        preauthorization["statementPayloadSha256"],
        "release signing statement payload",
    )
    issued_at = require_u64(
        preauthorization["authorizationIssuedAtUnix"],
        "release signing authorization issue time",
        minimum=1,
    )
    expires_at = require_u64(
        preauthorization["authorizationExpiresAtUnix"],
        "release signing authorization expiry",
        minimum=1,
    )
    require_u64(
        preauthorization["authorizationSequence"],
        "release signing authorization sequence",
        minimum=1,
    )
    minimum_policy_sequence = require_u64(
        preauthorization["minimumPolicySequence"],
        "release signing minimum policy sequence",
        minimum=1,
    )
    minimum_release_generation = require_u64(
        preauthorization["minimumReleaseGeneration"],
        "release signing minimum release generation",
        minimum=1,
    )
    minimum_rollback_epoch = require_u64(
        preauthorization["minimumRollbackEpoch"],
        "release signing minimum rollback epoch",
    )
    require(
        preauthorization["useLimit"] == 1,
        "release signing authorization is not one-use",
    )
    now = int(time.time())
    require(
        issued_at <= now < expires_at
        and expires_at - issued_at
        <= MAX_RELEASE_SIGN_AUTHORIZATION_SECONDS,
        "release signing authorization is outside its validity window",
    )
    statement_payload = {
        "attestationPins": dict(pins),
        "releaseIdentity": dict(release_identity),
        "releaseIdentitySha256": release_identity_sha256,
        "trustRootBundleSha256": pins["trustRootsSha256"],
    }
    require(
        preauthorization["releaseIdentitySha256"]
        == release_identity_sha256
        and preauthorization["statementPayloadSha256"]
        == sha256_json(statement_payload),
        "release signing preauthorization crossed its stable target",
    )
    monotonic = release_identity["monotonicRelease"]
    policy = release_identity["policy"]
    require(
        policy["sequence"] >= minimum_policy_sequence
        and monotonic["releaseGeneration"]
        >= minimum_release_generation
        and monotonic["rollbackEpoch"] >= minimum_rollback_epoch,
        "release signing preauthorization violates its monotonic floor",
    )
    return preauthorization


def validate_issuer_request(
    value: Any,
    *,
    raw_sha256: str,
    allow_fixture_non_production: bool = False,
) -> tuple[
    dict[str, Any],
    dict[str, str],
    dict[str, Any],
    dict[str, Any],
]:
    request = exact_object(
        value,
        {
            "apiVersion",
            "attestationPins",
            "containmentBoundary",
            "deploymentMode",
            "fixtureMode",
            "limits",
            "releaseIdentity",
            "releaseIdentitySha256",
            "signerBoundary",
        },
        "production stable-release issuer request",
    )
    production_request = (
        request["deploymentMode"] == "production-retained-fd"
        and request["fixtureMode"] is False
    )
    fixture_request = (
        allow_fixture_non_production is True
        and request["deploymentMode"]
        == "fixture-non-production-retained-fd"
        and request["fixtureMode"] is True
    )
    require(
        request["apiVersion"] == ISSUER_REQUEST_VERSION
        and (production_request or fixture_request),
        "issuer deployment mode is not explicitly authorized",
    )
    containment = exact_object(
        request["containmentBoundary"],
        {"producerMakesContainmentClaim", "requiredLauncherContract"},
        "issuer containment boundary",
    )
    require(
        containment["producerMakesContainmentClaim"] is False
        and containment["requiredLauncherContract"]
        == "serverware.publicAttestationExecutionSandbox/v2",
        "issuer request attempts to claim local containment",
    )
    pins = statement_pins(
        request["attestationPins"],
        "issuer attestation pins",
    )
    release_identity = validate_release_identity(
        request["releaseIdentity"],
        label="issuer stable release identity",
    )
    require(
        request["releaseIdentitySha256"] == sha256_json(release_identity),
        "issuer release identity digest is invalid",
    )
    require(
        release_identity["configuration"]["trustRootBundleSha256"]
        == pins["trustRootsSha256"]
        and release_identity["configuration"]["publicAttestation"]
        == component_pins_from_statement(pins),
        "issuer pins crossed the stable release identity",
    )
    signer = exact_object(
        request["signerBoundary"],
        {
            "algorithm",
            "keyId",
            "preauthorization",
            "requestFd",
            "responseFd",
            "signatureDomain",
            "transport",
        },
        "issuer signer boundary",
    )
    require(
        signer["algorithm"] == "Ed25519"
        and signer["signatureDomain"] == STABLE_STATEMENT_VERSION
        and signer["transport"]
        == "canonical-json-lines-over-retained-fd/v1"
        and signer["keyId"]
        == release_identity["configuration"]["releaseKeySpkiSha256"],
        "issuer signer boundary crossed the stable release key",
    )
    validate_release_signing_preauthorization(
        signer["preauthorization"],
        pins=pins,
        release_identity=release_identity,
        release_identity_sha256=request["releaseIdentitySha256"],
    )
    require_u64(
        signer["requestFd"],
        "issuer signer request FD",
        minimum=3,
        maximum=1_048_575,
    )
    require_u64(
        signer["responseFd"],
        "issuer signer response FD",
        minimum=3,
        maximum=1_048_575,
    )
    limits = exact_object(
        request["limits"],
        {
            "maxSignerRequestBytes",
            "maxSignerResponseBytes",
            "signerTimeoutMilliseconds",
        },
        "issuer limits",
    )
    require_u64(
        limits["maxSignerRequestBytes"],
        "maximum signer request bytes",
        minimum=4096,
        maximum=2 * 1024 * 1024,
    )
    require_u64(
        limits["maxSignerResponseBytes"],
        "maximum signer response bytes",
        minimum=256,
        maximum=4096,
    )
    require_u64(
        limits["signerTimeoutMilliseconds"],
        "signer timeout",
        minimum=100,
        maximum=30_000,
    )
    require_sha256(raw_sha256, "issuer request digest")
    return request, pins, release_identity, signer


def issue_stable_release(args: argparse.Namespace) -> None:
    authorization_nonce_fd = OwnedFd(
        args.signer_authorization_nonce_fd,
        label="signer authorization nonce FD",
    )
    args.signer_authorization_nonce_fd = -1
    try:
        _issue_stable_release(args, authorization_nonce_fd)
    finally:
        authorization_nonce_fd.close()


def _issue_stable_release(
    args: argparse.Namespace,
    authorization_nonce_fd: OwnedFd,
) -> None:
    operation_deadline = (
        time.monotonic() + args.io_timeout_ms / 1000.0
    )
    validate_distinct_fds(
        {
            "request FD": args.request_fd,
            "response FD": args.response_fd,
            "signer authorization nonce FD":
            authorization_nonce_fd.fileno(),
            "signer request FD": args.signer_request_fd,
            "signer response FD": args.signer_response_fd,
            "producer descriptor FD": args.producer_descriptor_fd,
            "producer executable FD": args.producer_executable_fd,
            "immutable config FD": args.immutable_config_fd,
            "producer request schema FD": args.producer_request_schema_fd,
            "sandbox descriptor FD": args.sandbox_descriptor_fd,
            "sandbox launcher FD": args.sandbox_launcher_fd,
            "trust roots FD": args.trust_roots_fd,
        }
    )
    request_value, request_raw = read_json_line_fd(
        args.request_fd,
        maximum=MAX_ISSUER_REQUEST_BYTES,
        timeout_ms=args.io_timeout_ms,
        label="production stable-release issuer request",
        deadline=operation_deadline,
    )
    request_sha256 = sha256_bytes(request_raw)
    require(
        request_sha256 == args.expected_issuer_request_sha256,
        "issuer request differs from its independent digest",
    )
    request, pins, release_identity, signer = validate_issuer_request(
        request_value,
        raw_sha256=request_sha256,
        allow_fixture_non_production=bool(
            getattr(args, "fixture_non_production", False)
        ),
    )
    require(
        signer["requestFd"] == args.signer_request_fd
        and signer["responseFd"] == args.signer_response_fd,
        "retained signer descriptors differ from the pinned issuer request",
    )
    artifacts = static_artifact_bytes(args)
    verify_static_artifacts(artifacts, pins)
    require(
        pins["trustRootsSha256"] == args.expected_trust_roots_sha256,
        "stable trust roots differ from their independent digest",
    )
    trust = load_trust_roots(
        artifacts["trustRootsSha256"],
        independently_expected_sha256=args.expected_trust_roots_sha256,
    )
    validate_release_config(
        artifacts["immutableConfigSha256"],
        pins=pins,
        release_identity=release_identity,
        trust_key_ids=trust["keyIds"],
    )
    release_key_id = release_identity["configuration"][
        "releaseKeySpkiSha256"
    ]
    require(
        trust["keyIds"]["completion"] == release_key_id,
        "release signer public root crossed the stable release identity",
    )
    payload = {
        "attestationPins": pins,
        "releaseIdentity": release_identity,
        "releaseIdentitySha256": sha256_json(release_identity),
        "trustRootBundleSha256": pins["trustRootsSha256"],
    }
    payload_sha256 = sha256_json(payload)
    require(
        signer["preauthorization"]["statementPayloadSha256"]
        == payload_sha256,
        "release signing preauthorization crossed the final payload",
    )
    preauthorization = {
        "approvedIssuerRequestSha256": request_sha256,
        **signer["preauthorization"],
    }
    limits = request["limits"]
    authorization_nonce = read_exact_sealed_secret_fd(
        authorization_nonce_fd.take(),
        label="release signing authorization nonce",
    )
    try:
        signature = issue_stable_release_signature(
            key=trust["keys"]["completion"],
            key_id=release_key_id,
            approved_issuer_request_sha256=request_sha256,
            authorization_nonce=authorization_nonce,
            preauthorization=preauthorization,
            statement_payload=payload,
            request_fd=args.signer_request_fd,
            response_fd=args.signer_response_fd,
            maximum_request=limits["maxSignerRequestBytes"],
            maximum_response=limits["maxSignerResponseBytes"],
            timeout_ms=limits["signerTimeoutMilliseconds"],
            deadline=operation_deadline,
        )
    finally:
        zeroize(authorization_nonce)
    statement = {
        "apiVersion": STABLE_STATEMENT_VERSION,
        "payload": payload,
        "payloadSha256": payload_sha256,
        "signature": signature,
        "signingKeyId": release_key_id,
    }
    verified = verify_stable_release(statement, trust=trust)
    require(
        verified["releaseIdentitySha256"] == sha256_json(release_identity)
        and verified["attestationPins"] == pins,
        "issued stable release statement crossed issuer input",
    )
    write_json_line_fd(
        args.response_fd,
        statement,
        maximum=MAX_STABLE_STATEMENT_BYTES,
        timeout_ms=args.io_timeout_ms,
        label="stable release statement",
        deadline=operation_deadline,
    )


def producer_invocation_preimage(
    *,
    caller_nonce_sha256: str,
    expires_at_unix: int,
    issued_at_unix: int,
    minimum_release_identity_sha256: str,
    minimum_rollback_continuity_commitment_sha256: str,
    nonce_authority_verifier_challenge_base64url: str,
    nonce_authority_verifier_state_operation_id_base64url: str,
    producer_channel_challenge_base64url: str,
    producer_ephemeral_key_spki_der_base64url: str,
    producer_ephemeral_key_spki_sha256: str,
    release_identity_sha256: str,
    request_body_sha256: str,
    static_pins: Mapping[str, str],
    tls_binding_sha256: str,
    witness_verifier_challenge_base64url: str,
) -> dict[str, Any]:
    return {
        "apiVersion": PRODUCER_INVOCATION_VERSION,
        "callerNonceSha256": caller_nonce_sha256,
        "expiresAtUnix": expires_at_unix,
        "issuedAtUnix": issued_at_unix,
        "minimumReleaseIdentitySha256":
        minimum_release_identity_sha256,
        "minimumRollbackContinuityCommitmentSha256":
        minimum_rollback_continuity_commitment_sha256,
        "nonceAuthorityVerifierChallengeBase64url":
        nonce_authority_verifier_challenge_base64url,
        "nonceAuthorityVerifierStateOperationIdBase64url":
        nonce_authority_verifier_state_operation_id_base64url,
        "producerChannelChallengeBase64url":
        producer_channel_challenge_base64url,
        "producerEphemeralKeySpkiDerBase64url":
        producer_ephemeral_key_spki_der_base64url,
        "producerEphemeralKeySpkiSha256":
        producer_ephemeral_key_spki_sha256,
        "releaseIdentitySha256": release_identity_sha256,
        "requestBodySha256": request_body_sha256,
        "staticPins": dict(static_pins),
        "tlsBindingSha256": tls_binding_sha256,
        "witnessVerifierChallengeBase64url":
        witness_verifier_challenge_base64url,
    }


def validate_nonce_consumption(
    value: Any,
    *,
    caller_nonce_sha256: str,
    request_body_sha256: str,
    tls_binding_sha256: str,
    nonce_store_identity_sha256: str,
    consumed_at_unix: int,
    sequence: int,
) -> dict[str, Any]:
    consumption = exact_object(
        value,
        NONCE_CONSUMPTION_FIELDS,
        "durable nonce consumption",
    )
    actual_consumed_at = require_u64(
        consumption["consumedAtUnix"],
        "nonce consumption time",
        minimum=1,
    )
    actual_sequence = require_u64(
        consumption["sequence"],
        "nonce consumption sequence",
        minimum=1,
    )
    require(
        consumption["apiVersion"] == NONCE_CONSUMPTION_VERSION
        and consumption["oneUse"] is True
        and consumption["nonceSha256"] == caller_nonce_sha256
        and consumption["requestBodySha256"] == request_body_sha256
        and consumption["tlsBindingSha256"] == tls_binding_sha256
        and consumption["storeIdentitySha256"]
        == nonce_store_identity_sha256
        and actual_consumed_at == consumed_at_unix
        and actual_sequence == sequence,
        "durable nonce consumption crossed its request or store",
    )
    for field in (
        "nonceSha256",
        "requestBodySha256",
        "storeIdentitySha256",
        "tlsBindingSha256",
    ):
        require_sha256(consumption[field], f"nonce consumption {field}")
    return consumption


def nonce_authority_genesis_commitment(
    assurance_sha256: str,
) -> str:
    return sha256_bytes(
        NONCE_AUTHORITY_GENESIS_DOMAIN
        + canonical_json(
            {
                "assuranceSha256": require_sha256(
                    assurance_sha256,
                    "nonce authority assurance",
                ),
            }
        )
    )


def nonce_authority_high_water_commitment(
    *,
    assurance_sha256: str,
    authority_epoch: int,
    authority_generation: int,
    nonce_consumption_sha256: str,
    nonce_verifier_state_authorization_sha256: str,
    previous_high_water_commitment_sha256: str,
    previous_receipt_sha256: str | None,
    sequence: int,
    transaction_id_base64url: str,
) -> str:
    checked_sequence = require_u64(
        sequence,
        "nonce authority high-water sequence",
        minimum=1,
    )
    if checked_sequence == 1:
        require(
            previous_receipt_sha256 is None,
            "first nonce authority state has a receipt predecessor",
        )
    else:
        require_sha256(
            previous_receipt_sha256,
            "nonce authority receipt predecessor",
        )
    base64url_decode(
        transaction_id_base64url,
        "nonce authority transaction id",
        exact_length=32,
        maximum=32,
    )
    commitment_input = {
        "apiVersion": NONCE_AUTHORITY_HIGH_WATER_INPUT_VERSION,
        "assuranceSha256": require_sha256(
            assurance_sha256,
            "nonce authority assurance",
        ),
        "authorityEpoch": require_u64(
            authority_epoch,
            "nonce authority epoch",
            minimum=1,
        ),
        "authorityGeneration": require_u64(
            authority_generation,
            "nonce authority generation",
            minimum=1,
        ),
        "nonceConsumptionSha256": require_sha256(
            nonce_consumption_sha256,
            "nonce authority consumption",
        ),
        "nonceVerifierStateAuthorizationSha256": require_sha256(
            nonce_verifier_state_authorization_sha256,
            "nonce verifier-state authorization",
        ),
        "previousHighWaterCommitmentSha256": require_sha256(
            previous_high_water_commitment_sha256,
            "previous nonce authority high-water commitment",
        ),
        "previousReceiptSha256": previous_receipt_sha256,
        "sequence": checked_sequence,
        "transactionIdBase64url": transaction_id_base64url,
    }
    return sha256_bytes(
        NONCE_AUTHORITY_HIGH_WATER_DOMAIN
        + canonical_json(commitment_input)
    )


def validate_nonce_authority_state(
    value: Any,
    *,
    assurance: Mapping[str, Any],
    assurance_sha256: str,
    nonce_consumption_sha256: str,
    nonce_verifier_state_authorization_sha256: str,
    previous_receipt_sha256: str | None,
    sequence: int,
    transaction_id_base64url: str,
    prior_verifier_state: Mapping[str, Any],
) -> dict[str, Any]:
    state = exact_object(
        value,
        NONCE_AUTHORITY_STATE_FIELDS,
        "signed receipt nonce authority state",
    )
    previous_high_water_commitment_sha256 = require_sha256(
        state["previousHighWaterCommitmentSha256"],
        "nonce authority previous high-water commitment",
    )
    prior = exact_object(
        prior_verifier_state["payload"],
        NONCE_AUTHORITY_VERIFIER_STATE_FIELDS,
        "prior nonce authority verifier-state payload",
    )
    require(
        sequence == prior["highWaterSequence"] + 1
        and previous_high_water_commitment_sha256
        == prior["highWaterCommitmentSha256"]
        and previous_receipt_sha256
        == prior["highWaterReceiptSha256"],
        "nonce authority state is not the exact successor of the signed prior head",
    )
    expected_commitment = nonce_authority_high_water_commitment(
        assurance_sha256=assurance_sha256,
        authority_epoch=assurance["authorityEpoch"],
        authority_generation=assurance["authorityGeneration"],
        nonce_consumption_sha256=nonce_consumption_sha256,
        nonce_verifier_state_authorization_sha256=(
            nonce_verifier_state_authorization_sha256
        ),
        previous_high_water_commitment_sha256=(
            previous_high_water_commitment_sha256
        ),
        previous_receipt_sha256=previous_receipt_sha256,
        sequence=sequence,
        transaction_id_base64url=transaction_id_base64url,
    )
    require(
        state["apiVersion"] == NONCE_AUTHORITY_STATE_VERSION
        and state["assuranceSha256"] == assurance_sha256
        and require_u64(
            state["authorityEpoch"],
            "nonce authority state epoch",
            minimum=1,
        )
        == assurance["authorityEpoch"]
        and require_u64(
            state["authorityGeneration"],
            "nonce authority state generation",
            minimum=1,
        )
        == assurance["authorityGeneration"]
        and require_u64(
            state["highWaterSequence"],
            "nonce authority state high-water sequence",
            minimum=1,
        )
        == sequence
        and state["highWaterCommitmentSha256"]
        == expected_commitment,
        "nonce authority state crossed its assurance or successor commitment",
    )
    return state


def verify_nonce_authority_verifier_state(
    value: Any,
    *,
    key: Ed25519PublicKey,
    key_id: str,
    assurance: Mapping[str, Any],
    assurance_sha256: str,
    state_store_identity_sha256: str,
) -> dict[str, Any]:
    payload, envelope_sha256 = verify_service_envelope(
        value,
        api_version=SIGNED_NONCE_AUTHORITY_VERIFIER_STATE_VERSION,
        domain=NONCE_AUTHORITY_VERIFIER_STATE_DOMAIN,
        key=key,
        key_id=key_id,
        label="signed nonce authority verifier state",
    )
    payload = exact_object(
        payload,
        NONCE_AUTHORITY_VERIFIER_STATE_FIELDS,
        "nonce authority verifier-state payload",
    )
    sequence = require_u64(
        payload["highWaterSequence"],
        "nonce authority verifier-state high-water sequence",
    )
    require_u64(
        payload["committedAtUnix"],
        "nonce authority verifier-state commit time",
        minimum=1,
    )
    require_u64(
        payload["stateStoreGeneration"],
        "nonce authority verifier-state store generation",
        minimum=1,
    )
    require_sha256(
        payload["stateStoreHeadSha256"],
        "nonce authority verifier-state store head",
    )
    require(
        payload["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_VERSION
        and payload["assuranceSha256"] == assurance_sha256
        and payload["authorityEpoch"] == assurance["authorityEpoch"]
        and payload["authorityGeneration"]
        == assurance["authorityGeneration"]
        and payload["stateStoreIdentitySha256"]
        == state_store_identity_sha256,
        "nonce authority verifier state crossed its assurance or store",
    )
    if sequence == 0:
        require(
            payload["commitOperationIdBase64url"] is None
            and payload["highWaterReceiptSha256"] is None
            and payload["priorVerifierStateSha256"] is None
            and payload["highWaterCommitmentSha256"]
            == nonce_authority_genesis_commitment(
                assurance_sha256
            ),
            "nonce authority verifier-state genesis is malformed",
        )
    else:
        base64url_decode(
            payload["commitOperationIdBase64url"],
            "nonce authority verifier-state operation",
            exact_length=32,
            maximum=32,
        )
        for field in (
            "highWaterCommitmentSha256",
            "highWaterReceiptSha256",
            "priorVerifierStateSha256",
        ):
            require_sha256(
                payload[field],
                f"nonce authority verifier-state {field}",
            )
    return {
        "document": dict(value),
        "envelopeSha256": envelope_sha256,
        "payload": payload,
    }


def verify_nonce_authority_state_authorization(
    value: Any,
    *,
    key: Ed25519PublicKey,
    key_id: str,
    assurance: Mapping[str, Any],
    assurance_sha256: str,
    state_store_identity_sha256: str,
    nonce_receipt_signing_key_id: str,
    state_store_attestation_key_id: str,
    state_store_assurance_evidence_sha256: str | None,
    state_store_configuration_sha256: str,
    prior_verifier_state: Mapping[str, Any],
    verifier_challenge: bytes,
    operation_id_base64url: str,
    now: int | None,
) -> dict[str, Any]:
    payload, envelope_sha256 = verify_service_envelope(
        value,
        api_version=(
            NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION
        ),
        domain=NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_DOMAIN,
        key=key,
        key_id=key_id,
        label="signed nonce authority current-head authorization",
    )
    payload = exact_object(
        payload,
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
            "stateStoreAssuranceEvidenceSha256",
            "stateStoreAttestationKeySpkiSha256",
            "stateStoreConfigurationSha256",
            "stateStoreGeneration",
            "stateStoreHeadSha256",
            "stateStoreIdentitySha256",
            "verifierChallengeSha256",
        },
        "nonce authority current-head authorization payload",
    )
    issued = require_u64(
        payload["issuedAtUnix"],
        "nonce authority authorization issue time",
        minimum=1,
    )
    expires = require_u64(
        payload["expiresAtUnix"],
        "nonce authority authorization expiry",
        minimum=1,
    )
    base64url_decode(
        operation_id_base64url,
        "nonce authority verifier-state operation ID",
        exact_length=32,
        maximum=32,
    )
    base64url_decode(
        payload["nonceTransactionIdBase64url"],
        "nonce authority transaction ID",
        exact_length=32,
        maximum=32,
    )
    for field in (
        "prepareRequestSha256",
        "recoveryIdentitySha256",
        "recoveryKeySha256",
        "requestBindingSha256",
    ):
        require_sha256(
            payload[field],
            f"nonce authority authorization {field}",
        )
    prior = prior_verifier_state["payload"]
    require(
        payload["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION
        and payload["assuranceSha256"] == assurance_sha256
        and payload["authorityEpoch"] == assurance["authorityEpoch"]
        and payload["authorityGeneration"]
        == assurance["authorityGeneration"]
        and payload["operationIdBase64url"]
        == operation_id_base64url
        and payload["nonceTransactionIdBase64url"]
        == operation_id_base64url
        and payload["nonceReceiptSigningKeySpkiSha256"]
        == nonce_receipt_signing_key_id
        and payload["priorCommittedAtUnix"]
        == prior["committedAtUnix"]
        and payload["priorVerifierStateSha256"]
        == prior_verifier_state["envelopeSha256"]
        and payload["stateStoreIdentitySha256"]
        == state_store_identity_sha256
        and payload["stateStoreAttestationKeySpkiSha256"]
        == state_store_attestation_key_id
        and payload["stateStoreAssuranceEvidenceSha256"]
        == state_store_assurance_evidence_sha256
        and payload["stateStoreConfigurationSha256"]
        == state_store_configuration_sha256
        and payload["stateStoreGeneration"]
        == prior["stateStoreGeneration"]
        and payload["stateStoreHeadSha256"]
        == prior["stateStoreHeadSha256"]
        and payload["highWaterSequence"]
        == prior["highWaterSequence"]
        and payload["highWaterCommitmentSha256"]
        == prior["highWaterCommitmentSha256"]
        and payload["highWaterReceiptSha256"]
        == prior["highWaterReceiptSha256"]
        and payload["verifierChallengeSha256"]
        == sha256_bytes(verifier_challenge)
        and payload["oneUse"] is True
        and (now is None or issued <= now < expires)
        and issued < expires
        and expires - issued <= 30,
        "nonce authority authorization is stale or not for the exact signed head",
    )
    return {
        "document": dict(value),
        "envelopeSha256": envelope_sha256,
        "payload": payload,
    }


def validate_verifier_state_transition_prefix(
    value: Any,
    *,
    release_config: Mapping[str, Any],
    verifier_state_key: Ed25519PublicKey,
    assurance_evidence_key: Ed25519PublicKey,
    store_attestation_key: Ed25519PublicKey,
    now: int,
) -> dict[str, Any]:
    transition = exact_object(
        value,
        {
            "apiVersion",
            "assurance",
            "assuranceEvidence",
            "assuranceEvidenceSha256",
            "assuranceSha256",
            "authorization",
            "authorizationSha256",
            "commitRequest",
            "commitRequestSha256",
            "commitReceipt",
            "commitReceiptSha256",
            "committedState",
            "committedStateRead",
            "committedStateReadSha256",
            "committedStateSha256",
            "nonActionable",
            "nonceAuthorityState",
            "nonceAuthorityStateSha256",
            "nonceConsumptionReceipt",
            "nonceConsumptionReceiptSha256",
            "nonceConsumptionSha256",
            "operationIdBase64url",
            "preparedOperation",
            "preparedOperationSha256",
            "priorState",
            "priorStateRead",
            "priorStateReadSha256",
            "priorStateSha256",
            "roleSeparationEvidence",
            "roleSeparationEvidenceSha256",
            "recoveryIdentity",
            "recoveryIdentitySha256",
            "recoveryKeySha256",
            "requestBindingSha256",
            "serviceBinding",
            "signedStoreCommitProof",
            "signedStoreCommitProofSha256",
            "storeAssuranceEvidence",
            "storeAssuranceEvidenceSha256",
            "transactionIdBase64url",
            "verifierChallengeBase64url",
            "verifierChallengeSha256",
        },
        "nonce authority verifier-state transition",
    )
    require(
        transition["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION
        and transition["nonActionable"] is True
        and transition["assurance"]
        == release_config["nonceAuthorityAssurance"]
        and transition["assuranceSha256"]
        == release_config["nonceAuthorityAssuranceSha256"]
        and transition["assuranceEvidence"]
        == release_config["nonceAuthorityAssuranceEvidence"],
        "verifier-state transition crossed its immutable assurance",
    )
    assurance_evidence = transition["assuranceEvidence"]
    require(
        transition["assuranceEvidenceSha256"]
        == (
            None
            if assurance_evidence is None
            else sha256_json(assurance_evidence)
        ),
        "verifier-state transition assurance evidence digest is invalid",
    )
    require(
        transition["storeAssuranceEvidence"]
        == release_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidence"
        ]
        and transition["storeAssuranceEvidenceSha256"]
        == release_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ]
        and transition["roleSeparationEvidence"]
        == release_config[
            "nonceAuthorityVerifierStateRoleSeparationEvidence"
        ]
        and transition["roleSeparationEvidenceSha256"]
        == sha256_json(transition["roleSeparationEvidence"]),
        "verifier-state transition crossed store or role assurance evidence",
    )
    verifier_state_key_id = sha256_bytes(
        verifier_state_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assurance_evidence_key_id = sha256_bytes(
        assurance_evidence_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    store_attestation_key_id = sha256_bytes(
        store_attestation_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    require(
        store_attestation_key_id
        == sha256_bytes(
            base64url_decode(
                release_config[
                    "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
                ],
                "verifier-state store attestation key",
                exact_length=44,
                maximum=44,
            )
        ),
        "verifier-state store attestation key is not canonical",
    )
    validate_nonce_authority_assurance_evidence(
        assurance_evidence,
        key=assurance_evidence_key,
        key_id=assurance_evidence_key_id,
        assurance=release_config["nonceAuthorityAssurance"],
        nonce_store_key_id=sha256_bytes(
            base64url_decode(
                release_config[
                    "nonceStoreSigningPublicKeySpkiDerBase64url"
                ],
                "nonce-store signing public key",
                exact_length=44,
                maximum=44,
            )
        ),
        verifier_state_key_id=verifier_state_key_id,
        verifier_state_store_identity_sha256=release_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
        verifier_state_store_administrative_domain_sha256=release_config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        now=now,
    )
    service = exact_object(
        transition["serviceBinding"],
        {
            "apiVersion",
            "clientCertificateSpkiSha256",
            "endpoint",
            "serverLeafSpkiSha256",
            "serviceConfigurationSha256",
            "signingKeySpkiSha256",
            "roleSeparationEvidenceSha256",
            "stateStoreAdministrativeDomainSha256",
            "stateStoreAssuranceEvidenceSha256",
            "stateStoreAttestationKeySpkiSha256",
            "stateStoreConfigurationSha256",
            "stateStoreIdentitySha256",
            "stateStoreMinimumCommitIndex",
            "stateStoreMinimumGeneration",
        },
        "verifier-state service binding",
    )
    configured_service = release_config[
        "nonceAuthorityVerifierStateService"
    ]
    require(
        service
        == {
            "apiVersion": VERIFIER_STATE_CLIENT_VERSION,
            "clientCertificateSpkiSha256":
            configured_service["clientCertificateSpkiSha256"],
            "endpoint": configured_service["endpoint"],
            "serverLeafSpkiSha256":
            configured_service["serverLeafSpkiSha256"],
            "serviceConfigurationSha256":
            configured_service["serviceConfigurationSha256"],
            "signingKeySpkiSha256": verifier_state_key_id,
            "roleSeparationEvidenceSha256":
            transition["roleSeparationEvidenceSha256"],
            "stateStoreAdministrativeDomainSha256":
            release_config[
                "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
            ],
            "stateStoreAssuranceEvidenceSha256":
            release_config[
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
            ],
            "stateStoreAttestationKeySpkiSha256":
            store_attestation_key_id,
            "stateStoreConfigurationSha256":
            release_config[
                "nonceAuthorityVerifierStateStoreConfigurationSha256"
            ],
            "stateStoreIdentitySha256":
            release_config[
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ],
            "stateStoreMinimumCommitIndex":
            release_config[
                "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
            ],
            "stateStoreMinimumGeneration":
            release_config[
                "nonceAuthorityVerifierStateStoreMinimumGeneration"
            ],
        },
        "verifier-state service binding crossed immutable configuration",
    )
    verifier_challenge = base64url_decode(
        transition["verifierChallengeBase64url"],
        "verifier-state challenge",
        exact_length=32,
        maximum=32,
    )
    operation_id = base64url_decode(
        transition["operationIdBase64url"],
        "verifier-state operation ID",
        exact_length=32,
        maximum=32,
    )
    require(
        verifier_challenge != operation_id,
        "verifier-state challenge and operation ID are not independent",
    )
    require(
        transition["verifierChallengeSha256"]
        == sha256_bytes(verifier_challenge),
        "verifier-state challenge digest is invalid",
    )
    prior = verify_nonce_authority_verifier_state(
        transition["priorState"],
        key=verifier_state_key,
        key_id=verifier_state_key_id,
        assurance=release_config["nonceAuthorityAssurance"],
        assurance_sha256=release_config[
            "nonceAuthorityAssuranceSha256"
        ],
        state_store_identity_sha256=release_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
    )
    require(
        transition["priorStateSha256"]
        == prior["envelopeSha256"],
        "verifier-state transition prior state digest is invalid",
    )
    authorization = verify_nonce_authority_state_authorization(
        transition["authorization"],
        key=verifier_state_key,
        key_id=verifier_state_key_id,
        assurance=release_config["nonceAuthorityAssurance"],
        assurance_sha256=release_config[
            "nonceAuthorityAssuranceSha256"
        ],
        state_store_identity_sha256=release_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
        nonce_receipt_signing_key_id=sha256_bytes(
            base64url_decode(
                release_config[
                    "nonceStoreSigningPublicKeySpkiDerBase64url"
                ],
                "nonce-store signing public key",
                exact_length=44,
                maximum=44,
            )
        ),
        state_store_attestation_key_id=store_attestation_key_id,
        state_store_assurance_evidence_sha256=release_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ],
        state_store_configuration_sha256=release_config[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ],
        prior_verifier_state=prior,
        verifier_challenge=verifier_challenge,
        operation_id_base64url=transition[
            "operationIdBase64url"
        ],
        now=None,
    )
    require(
        transition["authorizationSha256"]
        == authorization["envelopeSha256"],
        "verifier-state transition authorization digest is invalid",
    )
    prepared = exact_object(
        transition["preparedOperation"],
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
        "verifier-state prepared operation",
    )
    prepare_request = exact_object(
        prepared["prepareRequest"],
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
    recovery_identity = exact_object(
        prepared["recoveryIdentity"],
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
    request_binding = exact_object(
        prepared["requestBinding"],
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
    recovery_binding = exact_object(
        prepared["recoveryBinding"],
        {
            "apiVersion",
            "assuranceSha256",
            "expectedVerifierStateSha256",
            "operationIdBase64url",
            "requestBindingSha256",
            "verifierChallengeSha256",
        },
        "verifier-state recovery binding",
    )
    nonce_consume_request = exact_object(
        prepared["nonceConsumeRequest"],
        set(request_binding)
        | {
            "nonceAuthorityVerifierStateAuthorizationSha256",
        },
        "verifier-state prepared nonce request",
    )
    successor_intent = exact_object(
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
        "verifier-state successor intent",
    )
    recovery_identity_sha256 = sha256_json(recovery_identity)
    deterministic_operation_id = base64url_encode(
        hashlib.sha256(
            VERIFIER_STATE_OPERATION_ID_DOMAIN
            + canonical_json(recovery_identity)
        ).digest()
    )
    recovery_key_sha256 = sha256_bytes(
        VERIFIER_STATE_RECOVERY_KEY_DOMAIN
        + canonical_json(recovery_identity)
    )
    request_binding_sha256 = sha256_bytes(
        VERIFIER_STATE_REQUEST_BINDING_DOMAIN
        + canonical_json(request_binding)
    )
    nonce_consume_request_sha256 = sha256_bytes(
        NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
        + canonical_json(nonce_consume_request)
    )
    producer_invocation_base = {
        key: item
        for key, item in prepare_request["producerInvocation"].items()
        if key
        not in {
            "nonceAuthorityVerifierChallengeBase64url",
            "nonceAuthorityVerifierStateOperationIdBase64url",
        }
    }
    challenge_issue = prepare_request["challengeIssue"]
    require(
        prepared["apiVersion"]
        == VERIFIER_STATE_PREPARED_OPERATION_VERSION
        and transition["preparedOperationSha256"]
        == sha256_json(prepared)
        and prepared["authorization"] == authorization["document"]
        and prepared["authorizationSha256"]
        == authorization["envelopeSha256"]
        and prepared["prepareRequestSha256"]
        == sha256_json(prepare_request)
        == authorization["payload"]["prepareRequestSha256"]
        and prepared["recoveryIdentity"] == recovery_identity
        and prepared["recoveryIdentitySha256"]
        == recovery_identity_sha256
        == authorization["payload"]["recoveryIdentitySha256"]
        and prepared["recoveryKeySha256"]
        == recovery_key_sha256
        == authorization["payload"]["recoveryKeySha256"]
        and prepared["requestBinding"] == request_binding
        and prepared["requestBindingSha256"]
        == request_binding_sha256
        == authorization["payload"]["requestBindingSha256"]
        and prepared["nonceConsumeRequestSha256"]
        == nonce_consume_request_sha256
        and prepared["successorIntentSha256"]
        == sha256_json(successor_intent)
        and prepare_request["apiVersion"]
        == VERIFIER_STATE_PREPARE_REQUEST_VERSION
        and prepare_request["assuranceSha256"]
        == release_config["nonceAuthorityAssuranceSha256"]
        and prepare_request["expectedVerifierStateSha256"]
        == prior["envelopeSha256"]
        and prepare_request["operationIdBase64url"]
        == transition["operationIdBase64url"]
        == deterministic_operation_id
        and prepare_request["priorStateRead"]
        == transition["priorStateRead"]
        and prepare_request["priorStateReadSha256"]
        == transition["priorStateReadSha256"]
        and prepare_request["recoveryIdentity"]
        == recovery_identity
        and prepare_request["recoveryIdentitySha256"]
        == recovery_identity_sha256
        and prepare_request["recoveryKeySha256"]
        == recovery_key_sha256
        and prepare_request["requestBinding"] == request_binding
        and prepare_request["requestBindingSha256"]
        == request_binding_sha256
        and prepare_request["producerInvocationSha256"]
        == sha256_json(prepare_request["producerInvocation"])
        == request_binding["producerInvocationSha256"]
        and prepare_request["producerInvocationBaseSha256"]
        == sha256_json(producer_invocation_base)
        == challenge_issue["producerInvocationBaseSha256"]
        and prepare_request["challengeIssueSha256"]
        == sha256_json(challenge_issue)
        and challenge_issue["apiVersion"]
        == "serverware.attestationVerifierStateIssueChallengeResponse/v1"
        and challenge_issue["operationIdBase64url"]
        == deterministic_operation_id
        and challenge_issue["recoveryKeySha256"]
        == recovery_key_sha256
        and challenge_issue["challengeBase64url"]
        == prepare_request["verifierChallengeBase64url"]
        and challenge_issue["challengeSha256"]
        == recovery_binding["verifierChallengeSha256"]
        and challenge_issue["replacementForbidden"] is True
        and challenge_issue["nonActionable"] is True
        and challenge_issue["status"] == "issued"
        and prepare_request["verifierChallengeBase64url"]
        == transition["verifierChallengeBase64url"]
        and recovery_identity["apiVersion"]
        == VERIFIER_STATE_RECOVERY_IDENTITY_VERSION
        and recovery_identity["assuranceSha256"]
        == release_config["nonceAuthorityAssuranceSha256"]
        and recovery_identity["callerNonceSha256"]
        == request_binding["nonceSha256"]
        and recovery_identity["requestBodySha256"]
        == request_binding["requestBodySha256"]
        and request_binding["apiVersion"]
        == VERIFIER_STATE_REQUEST_BINDING_VERSION
        and recovery_binding["apiVersion"]
        == VERIFIER_STATE_RECOVERY_BINDING_VERSION
        and recovery_binding["assuranceSha256"]
        == release_config["nonceAuthorityAssuranceSha256"]
        and recovery_binding["expectedVerifierStateSha256"]
        == prior["envelopeSha256"]
        and recovery_binding["operationIdBase64url"]
        == transition["operationIdBase64url"]
        and recovery_binding["requestBindingSha256"]
        == request_binding_sha256
        and recovery_binding["verifierChallengeSha256"]
        == transition["verifierChallengeSha256"]
        and nonce_consume_request["apiVersion"]
        == NONCE_CONSUME_ONCE_REQUEST_VERSION
        and nonce_consume_request[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ]
        == authorization["envelopeSha256"]
        and all(
            nonce_consume_request[field] == request_binding[field]
            for field in request_binding
            if field != "apiVersion"
        )
        and successor_intent["apiVersion"]
        == VERIFIER_STATE_SUCCESSOR_INTENT_VERSION
        and successor_intent["authorizationSha256"]
        == authorization["envelopeSha256"]
        and successor_intent["expectedHighWaterSequence"]
        == prior["payload"]["highWaterSequence"] + 1
        and successor_intent["expectedStateStoreGeneration"]
        == prior["payload"]["stateStoreGeneration"] + 1
        and successor_intent["expectedVerifierStateSha256"]
        == prior["envelopeSha256"]
        and successor_intent["nonceConsumeRequestSha256"]
        == nonce_consume_request_sha256
        and successor_intent["operationIdBase64url"]
        == transition["operationIdBase64url"]
        and successor_intent["previousStateStoreHeadSha256"]
        == prior["payload"]["stateStoreHeadSha256"]
        and successor_intent["requestBindingSha256"]
        == request_binding_sha256
        and successor_intent["transactionIdBase64url"]
        == request_binding["transactionIdBase64url"]
        and successor_intent["verifierChallengeSha256"]
        == transition["verifierChallengeSha256"]
        and transition["recoveryIdentity"] == recovery_identity
        and transition["recoveryIdentitySha256"]
        == recovery_identity_sha256
        and transition["recoveryKeySha256"]
        == recovery_key_sha256
        and transition["requestBindingSha256"]
        == request_binding_sha256,
        "verifier-state transition did not bind its exact prepared saga",
    )
    return {
        "authorization": authorization,
        "document": transition,
        "operationId": operation_id,
        "priorState": prior,
        "preparedOperation": prepared,
        "preparedOperationSha256":
        transition["preparedOperationSha256"],
        "recoveryIdentity": recovery_identity,
        "recoveryIdentitySha256": recovery_identity_sha256,
        "recoveryKeySha256": recovery_key_sha256,
        "requestBindingSha256": request_binding_sha256,
        "verifierChallenge": verifier_challenge,
        "verifierStateKeyId": verifier_state_key_id,
        "storeAttestationKey": store_attestation_key,
        "storeAttestationKeyId": store_attestation_key_id,
    }


def verify_signed_nonce_receipt(
    value: Any,
    *,
    key: Ed25519PublicKey,
    key_id: str,
    caller_nonce_sha256: str,
    request_body_sha256: str,
    tls_binding_sha256: str,
    nonce_store_identity_sha256: str,
    producer_invocation: Mapping[str, Any],
    producer_invocation_sha256: str,
    issued_at_unix: int,
    expires_at_unix: int,
    nonce_authority_assurance: Mapping[str, Any],
    nonce_authority_assurance_sha256: str,
    prior_verifier_state: Mapping[str, Any],
) -> dict[str, Any]:
    require(
        nonce_authority_assurance_sha256
        == sha256_json(nonce_authority_assurance),
        "nonce authority assurance digest is invalid",
    )
    envelope = exact_object(
        value,
        NONCE_RECEIPT_FIELDS,
        "signed nonce consumption receipt",
    )
    require(
        envelope["apiVersion"] == SIGNED_NONCE_RECEIPT_VERSION
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == key_id
        and envelope["signingKeySpkiSha256"] == key_id,
        "signed nonce receipt crossed its independently pinned key",
    )
    payload_sha256 = require_sha256(
        envelope["payloadSha256"],
        "signed nonce receipt payload",
    )
    require(
        payload_sha256 == sha256_json(envelope["payload"]),
        "signed nonce receipt payload digest is invalid",
    )
    signature = base64url_decode(
        envelope["signatureBase64url"],
        "signed nonce receipt signature",
        exact_length=64,
        maximum=64,
    )
    try:
        key.verify(
            signature,
            NONCE_RECEIPT_DOMAIN
            + canonical_json(
                {
                    "payload": envelope["payload"],
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise ContractError(
            "signed nonce consumption receipt signature is invalid"
        ) from exc
    payload = exact_object(
        envelope["payload"],
        NONCE_RECEIPT_PAYLOAD_FIELDS,
        "signed nonce consumption receipt payload",
    )
    consumed_at = require_u64(
        payload["consumedAtUnix"],
        "nonce receipt consumed time",
        minimum=1,
    )
    receipt_issued = require_u64(
        payload["receiptIssuedAtUnix"],
        "nonce receipt issue time",
        minimum=1,
    )
    receipt_expires = require_u64(
        payload["expiresAtUnix"],
        "nonce receipt expiry",
        minimum=1,
    )
    sequence = require_u64(
        payload["sequence"],
        "nonce receipt sequence",
        minimum=1,
    )
    base64url_decode(
        payload["transactionIdBase64url"],
        "nonce receipt transaction id",
        exact_length=32,
        maximum=32,
    )
    base64url_decode(
        payload["producerChannelChallengeBase64url"],
        "nonce receipt producer challenge",
        exact_length=32,
        maximum=32,
    )
    previous_receipt_sha256 = payload["previousReceiptSha256"]
    if sequence == 1:
        require(
            previous_receipt_sha256 is None,
            "first nonce receipt has a predecessor",
        )
    else:
        require_sha256(
            previous_receipt_sha256,
            "nonce receipt predecessor",
        )
    consumption = validate_nonce_consumption(
        payload["nonceConsumption"],
        caller_nonce_sha256=caller_nonce_sha256,
        request_body_sha256=request_body_sha256,
        tls_binding_sha256=tls_binding_sha256,
        nonce_store_identity_sha256=nonce_store_identity_sha256,
        consumed_at_unix=consumed_at,
        sequence=sequence,
    )
    consumption_sha256 = sha256_json(consumption)
    nonce_authority_verifier_state_authorization_sha256 = (
        require_sha256(
            payload[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ],
            "nonce authority verifier-state authorization",
        )
    )
    authority_state = validate_nonce_authority_state(
        payload["nonceAuthorityState"],
        assurance=nonce_authority_assurance,
        assurance_sha256=nonce_authority_assurance_sha256,
        nonce_consumption_sha256=consumption_sha256,
        nonce_verifier_state_authorization_sha256=(
            nonce_authority_verifier_state_authorization_sha256
        ),
        previous_receipt_sha256=previous_receipt_sha256,
        sequence=sequence,
        transaction_id_base64url=payload[
            "transactionIdBase64url"
        ],
        prior_verifier_state=prior_verifier_state,
    )
    authority_state_sha256 = sha256_json(authority_state)
    consume_request = {
        "apiVersion":
        "serverware.attestationNonceConsumeOnceRequest/v3",
        "expiresAtUnix": receipt_expires,
        "nonceAuthorityVerifierStateAuthorizationSha256": (
            nonce_authority_verifier_state_authorization_sha256
        ),
        "nonceSha256": caller_nonce_sha256,
        "producerChannelChallengeBase64url":
        producer_invocation["producerChannelChallengeBase64url"],
        "producerEphemeralKeySha256":
        producer_invocation["producerEphemeralKeySpkiSha256"],
        "producerInvocationSha256":
        producer_invocation_sha256,
        "requestBodySha256": request_body_sha256,
        "tlsBindingSha256": tls_binding_sha256,
        "transactionIdBase64url": payload[
            "transactionIdBase64url"
        ],
    }
    expected_consume_request_sha256 = sha256_bytes(
        NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
        + canonical_json(consume_request)
    )
    require(
        payload["apiVersion"] == NONCE_RECEIPT_PAYLOAD_VERSION
        and payload["consumeRequestSha256"]
        == expected_consume_request_sha256
        and payload["nonceAuthorityAssuranceSha256"]
        == nonce_authority_assurance_sha256
        and payload["nonceAuthorityStateSha256"]
        == authority_state_sha256
        and payload["nonceConsumptionSha256"]
        == consumption_sha256
        and payload["nonceSha256"] == caller_nonce_sha256
        and payload["requestBodySha256"] == request_body_sha256
        and payload["tlsBindingSha256"] == tls_binding_sha256
        and payload["storeIdentitySha256"]
        == nonce_store_identity_sha256
        and payload["producerChannelChallengeBase64url"]
        == producer_invocation["producerChannelChallengeBase64url"]
        and payload["producerEphemeralKeySha256"]
        == producer_invocation["producerEphemeralKeySpkiSha256"]
        and payload["producerInvocationSha256"]
        == producer_invocation_sha256
        and payload["finalExternalVerifierChallengeConsumptionRequired"]
        is True
        and payload["finalExternalVerifierChallengeConsumed"] is False
        and consumed_at == receipt_issued
        and consumed_at <= issued_at_unix < expires_at_unix
        <= receipt_expires
        and issued_at_unix - consumed_at <= 30,
        "signed nonce receipt crossed its invocation, request, or validity window",
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
    return {
        "authorityState": authority_state,
        "authorityStateSha256": authority_state_sha256,
        "consumption": consumption,
        "consumptionSha256": consumption_sha256,
        "document": envelope,
        "nonceAuthorityAssuranceSha256":
        nonce_authority_assurance_sha256,
        "nonceAuthorityVerifierStateAuthorizationSha256": (
            nonce_authority_verifier_state_authorization_sha256
        ),
        "payload": payload,
        "receiptSha256": sha256_json(envelope),
    }


def verifier_state_head_sha256(
    *,
    assurance_sha256: str,
    authorization_sha256: str,
    operation_id_base64url: str,
    nonce_authority_state_sha256: str,
    nonce_receipt_sha256: str,
    previous_head_sha256: str,
    generation: int,
) -> str:
    return sha256_bytes(
        NONCE_AUTHORITY_VERIFIER_STATE_HEAD_DOMAIN
        + canonical_json(
            {
                "assuranceSha256": assurance_sha256,
                "authorizationSha256": authorization_sha256,
                "commitOperationIdBase64url":
                operation_id_base64url,
                "nonceAuthorityStateSha256":
                nonce_authority_state_sha256,
                "nonceConsumptionReceiptSha256":
                nonce_receipt_sha256,
                "previousStateStoreHeadSha256":
                previous_head_sha256,
                "stateStoreGeneration": generation,
            }
        )
    )


def verifier_state_commit_candidate(
    *,
    release_config: Mapping[str, Any],
    transition_prefix: Mapping[str, Any],
    nonce_receipt: Mapping[str, Any],
    commit_request_sha256: str,
) -> dict[str, Any]:
    authorization = transition_prefix["authorization"]
    authorization_payload = authorization["payload"]
    prior_payload = transition_prefix["priorState"]["payload"]
    next_generation = require_u64(
        prior_payload["stateStoreGeneration"],
        "prior verifier-state generation",
        minimum=1,
    ) + 1
    require(
        next_generation <= MAX_U64,
        "verifier-state generation is terminal",
    )
    return {
        "apiVersion": VERIFIER_STATE_STORE_COMMIT_CANDIDATE_VERSION,
        "assuranceSha256":
        release_config["nonceAuthorityAssuranceSha256"],
        "authorizationSha256": authorization["envelopeSha256"],
        "commitRequestSha256": commit_request_sha256,
        "expectedVerifierStateSha256":
        transition_prefix["priorState"]["envelopeSha256"],
        "nonceAuthorityStateSha256":
        nonce_receipt["authorityStateSha256"],
        "nonceConsumptionReceiptSha256":
        nonce_receipt["receiptSha256"],
        "nonceConsumptionSha256":
        nonce_receipt["consumptionSha256"],
        "operationIdBase64url":
        authorization_payload["operationIdBase64url"],
        "previousCommittedAtUnix": prior_payload["committedAtUnix"],
        "previousStateStoreGeneration":
        prior_payload["stateStoreGeneration"],
        "previousStateStoreHeadSha256":
        prior_payload["stateStoreHeadSha256"],
        "proposedStateStoreGeneration": next_generation,
        "proposedStateStoreHeadSha256":
        verifier_state_head_sha256(
            assurance_sha256=release_config[
                "nonceAuthorityAssuranceSha256"
            ],
            authorization_sha256=authorization["envelopeSha256"],
            operation_id_base64url=authorization_payload[
                "operationIdBase64url"
            ],
            nonce_authority_state_sha256=nonce_receipt[
                "authorityStateSha256"
            ],
            nonce_receipt_sha256=nonce_receipt["receiptSha256"],
            previous_head_sha256=prior_payload[
                "stateStoreHeadSha256"
            ],
            generation=next_generation,
        ),
        "verifierChallengeSha256":
        authorization_payload["verifierChallengeSha256"],
    }


def validate_verifier_state_read_response(
    value: Any,
    *,
    release_config: Mapping[str, Any],
    verifier_state_key: Ed25519PublicKey,
    verifier_state_key_id: str,
    expected_state: Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    response = exact_object(
        value,
        {
            "apiVersion",
            "nonActionable",
            "state",
            "stateSha256",
        },
        label,
    )
    state = verify_nonce_authority_verifier_state(
        response["state"],
        key=verifier_state_key,
        key_id=verifier_state_key_id,
        assurance=release_config["nonceAuthorityAssurance"],
        assurance_sha256=release_config[
            "nonceAuthorityAssuranceSha256"
        ],
        state_store_identity_sha256=release_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
    )
    require(
        response["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_READ_RESPONSE_VERSION
        and response["nonActionable"] is True
        and response["stateSha256"] == state["envelopeSha256"]
        and response["state"] == expected_state["document"]
        and state["envelopeSha256"]
        == expected_state["envelopeSha256"],
        f"{label} crossed its signed state",
    )
    return {
        "document": response,
        "documentSha256": sha256_json(response),
        "state": state,
    }


def validate_verifier_state_transition_suffix(
    transition_prefix: Mapping[str, Any],
    *,
    nonce_receipt: Mapping[str, Any],
    release_config: Mapping[str, Any],
    verifier_state_key: Ed25519PublicKey,
    store_attestation_key: Ed25519PublicKey,
    now: int,
) -> dict[str, Any]:
    transition = transition_prefix["document"]
    authorization = transition_prefix["authorization"]
    authorization_payload = authorization["payload"]
    prior = transition_prefix["priorState"]
    verifier_state_key_id = transition_prefix["verifierStateKeyId"]
    store_attestation_key_id = transition_prefix[
        "storeAttestationKeyId"
    ]
    require(
        transition["nonceConsumptionReceipt"]
        == nonce_receipt["document"]
        and transition["nonceConsumptionReceiptSha256"]
        == nonce_receipt["receiptSha256"]
        and transition["nonceConsumptionSha256"]
        == nonce_receipt["consumptionSha256"]
        and transition["nonceAuthorityState"]
        == nonce_receipt["authorityState"]
        and transition["nonceAuthorityStateSha256"]
        == nonce_receipt["authorityStateSha256"]
        and transition["transactionIdBase64url"]
        == nonce_receipt["payload"]["transactionIdBase64url"]
        and nonce_receipt[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ]
        == authorization["envelopeSha256"],
        "verifier-state transition crossed its complete signed nonce receipt",
    )
    prior_read = validate_verifier_state_read_response(
        transition["priorStateRead"],
        release_config=release_config,
        verifier_state_key=verifier_state_key,
        verifier_state_key_id=verifier_state_key_id,
        expected_state=prior,
        label="prior verifier-state read",
    )
    challenge_issue = transition_prefix["preparedOperation"][
        "prepareRequest"
    ]["challengeIssue"]
    require(
        transition["priorStateReadSha256"]
        == prior_read["documentSha256"]
        and transition["verifierChallengeBase64url"]
        == challenge_issue["challengeBase64url"]
        and transition["verifierChallengeSha256"]
        == challenge_issue["challengeSha256"]
        and challenge_issue["challengeIssuedAtUnix"]
        <= authorization_payload["issuedAtUnix"]
        < authorization_payload["expiresAtUnix"]
        <= challenge_issue["challengeExpiresAtUnix"]
        and challenge_issue["status"] == "issued"
        and challenge_issue["replacementForbidden"] is True,
        "verifier-state authorization escaped its exact service-issued challenge",
    )
    receipt_consumed_at = require_u64(
        nonce_receipt["payload"]["consumedAtUnix"],
        "signed nonce receipt consumption time",
        minimum=1,
    )
    require(
        authorization_payload["issuedAtUnix"]
        <= receipt_consumed_at
        < authorization_payload["expiresAtUnix"],
        "signed nonce receipt was not consumed under the live authorization",
    )
    commit_request = {
        "apiVersion":
        NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_REQUEST_VERSION,
        "authorization": authorization["document"],
        "nonceConsumptionReceipt": nonce_receipt["document"],
        "preparedOperationSha256":
        transition_prefix["preparedOperationSha256"],
        "recoveryKeySha256":
        transition_prefix["recoveryKeySha256"],
        "requestBindingSha256":
        transition_prefix["requestBindingSha256"],
        "verifierChallengeBase64url":
        transition["verifierChallengeBase64url"],
    }
    commit_request_sha256 = sha256_json(commit_request)
    require(
        transition["commitRequest"] == commit_request
        and transition["commitRequestSha256"]
        == commit_request_sha256,
        "verifier-state commit request is not the exact prepared v3 request",
    )
    commit_candidate = verifier_state_commit_candidate(
        release_config=release_config,
        transition_prefix=transition_prefix,
        nonce_receipt=nonce_receipt,
        commit_request_sha256=commit_request_sha256,
    )
    store_proof_payload, store_proof_sha256 = verify_service_envelope(
        transition["signedStoreCommitProof"],
        api_version=SIGNED_VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION,
        domain=VERIFIER_STATE_STORE_COMMIT_PROOF_DOMAIN,
        key=store_attestation_key,
        key_id=store_attestation_key_id,
        label="signed verifier-state store commit proof",
    )
    store_proof = exact_object(
        store_proof_payload,
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
        "verifier-state store commit proof payload",
    )
    committed_at = require_u64(
        store_proof["committedAtUnix"],
        "durable verifier-state commit time",
        minimum=1,
    )
    proof_observed_at = int(time.time())
    expected_production_eligible = (
        release_config["nonceAuthorityAssurance"][
            "productionEligible"
        ]
        is True
    )
    require(
        transition["signedStoreCommitProofSha256"]
        == store_proof_sha256
        and store_proof["apiVersion"]
        == VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION
        and store_proof["authorizationSha256"]
        == authorization["envelopeSha256"]
        and store_proof["casCommitted"] is True
        and store_proof["commitCandidateSha256"]
        == sha256_json(commit_candidate)
        and store_proof["commitClockMonotonic"] is True
        and store_proof["commitRequestSha256"]
        == commit_request_sha256
        and store_proof["operationIdBase64url"]
        == transition["operationIdBase64url"]
        and store_proof["previousCommittedAtUnix"]
        == prior["payload"]["committedAtUnix"]
        and store_proof["previousVerifierStateSha256"]
        == prior["envelopeSha256"]
        and store_proof["productionEligible"]
        is expected_production_eligible
        and store_proof["stateStoreAdministrativeDomainSha256"]
        == release_config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ]
        and store_proof["stateStoreAssuranceEvidenceSha256"]
        == release_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ]
        and store_proof["stateStoreAttestationKeySpkiSha256"]
        == store_attestation_key_id
        and store_proof["stateStoreConfigurationSha256"]
        == release_config[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ]
        and store_proof["stateStoreGeneration"]
        == commit_candidate["proposedStateStoreGeneration"]
        and store_proof["stateStoreCommitIndex"]
        == store_proof["stateStoreGeneration"]
        and store_proof["stateStoreGeneration"]
        >= release_config[
            "nonceAuthorityVerifierStateStoreMinimumGeneration"
        ]
        and store_proof["stateStoreCommitIndex"]
        >= release_config[
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
        ]
        and store_proof["stateStoreIdentitySha256"]
        == release_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ]
        and prior["payload"]["committedAtUnix"]
        <= committed_at
        and receipt_consumed_at <= committed_at
        <= proof_observed_at,
        "signed verifier-state store proof crossed its exact durable CAS",
    )
    committed_state_payload = {
        "apiVersion": NONCE_AUTHORITY_VERIFIER_STATE_VERSION,
        "assuranceSha256":
        release_config["nonceAuthorityAssuranceSha256"],
        "authorityEpoch":
        release_config["nonceAuthorityAssurance"]["authorityEpoch"],
        "authorityGeneration":
        release_config["nonceAuthorityAssurance"][
            "authorityGeneration"
        ],
        "commitOperationIdBase64url":
        transition["operationIdBase64url"],
        "committedAtUnix": committed_at,
        "highWaterCommitmentSha256":
        nonce_receipt["authorityState"][
            "highWaterCommitmentSha256"
        ],
        "highWaterReceiptSha256": nonce_receipt["receiptSha256"],
        "highWaterSequence":
        nonce_receipt["authorityState"]["highWaterSequence"],
        "priorVerifierStateSha256": prior["envelopeSha256"],
        "stateStoreGeneration":
        commit_candidate["proposedStateStoreGeneration"],
        "stateStoreHeadSha256":
        commit_candidate["proposedStateStoreHeadSha256"],
        "stateStoreIdentitySha256":
        release_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
    }
    commit_receipt_payload, commit_receipt_sha256 = (
        verify_service_envelope(
            transition["commitReceipt"],
            api_version=(
                NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION
            ),
            domain=(
                NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_DOMAIN
            ),
            key=verifier_state_key,
            key_id=verifier_state_key_id,
            label="signed verifier-state commit receipt",
        )
    )
    commit_receipt = exact_object(
        commit_receipt_payload,
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
        "verifier-state commit receipt payload",
    )
    nonce_store_key_id = sha256_bytes(
        base64url_decode(
            release_config[
                "nonceStoreSigningPublicKeySpkiDerBase64url"
            ],
            "nonce-store signing public key",
            exact_length=44,
            maximum=44,
        )
    )
    require(
        transition["commitReceiptSha256"] == commit_receipt_sha256
        and commit_receipt["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION
        and commit_receipt["assuranceSha256"]
        == release_config["nonceAuthorityAssuranceSha256"]
        and commit_receipt["authorizationSha256"]
        == authorization["envelopeSha256"]
        and commit_receipt["casCommitted"] is True
        and commit_receipt["commitOperationIdBase64url"]
        == transition["operationIdBase64url"]
        and commit_receipt["commitRequestSha256"]
        == commit_request_sha256
        and commit_receipt["committedAtUnix"] == committed_at
        and commit_receipt["committedVerifierState"]
        == committed_state_payload
        and commit_receipt["committedVerifierStateSha256"]
        == sha256_json(committed_state_payload)
        and commit_receipt["nonceAuthorityStateSha256"]
        == nonce_receipt["authorityStateSha256"]
        and commit_receipt["nonceConsumptionReceiptSha256"]
        == nonce_receipt["receiptSha256"]
        and commit_receipt["nonceConsumptionSha256"]
        == nonce_receipt["consumptionSha256"]
        and commit_receipt["nonceReceiptSigningKeySpkiSha256"]
        == nonce_store_key_id
        and commit_receipt["oneUseAuthorizationConsumed"] is True
        and commit_receipt["preparedOperationSha256"]
        == transition_prefix["preparedOperationSha256"]
        and commit_receipt["previousStateStoreGeneration"]
        == prior["payload"]["stateStoreGeneration"]
        and commit_receipt["previousStateStoreHeadSha256"]
        == prior["payload"]["stateStoreHeadSha256"]
        and commit_receipt["priorVerifierStateSha256"]
        == prior["envelopeSha256"]
        and commit_receipt["recoveryIdentitySha256"]
        == transition_prefix["recoveryIdentitySha256"]
        and commit_receipt["recoveryKeySha256"]
        == transition_prefix["recoveryKeySha256"]
        and commit_receipt["requestBindingSha256"]
        == transition_prefix["requestBindingSha256"]
        and commit_receipt["signedStoreCommitProof"]
        == transition["signedStoreCommitProof"]
        and commit_receipt["signedStoreCommitProofSha256"]
        == store_proof_sha256
        and commit_receipt["stateStoreAdministrativeDomainSha256"]
        == release_config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ]
        and commit_receipt["stateStoreAssuranceEvidenceSha256"]
        == release_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ]
        and commit_receipt["stateStoreAttestationKeySpkiSha256"]
        == store_attestation_key_id
        and commit_receipt["stateStoreConfigurationSha256"]
        == release_config[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ]
        and commit_receipt["stateStoreGeneration"]
        == store_proof["stateStoreGeneration"]
        and commit_receipt["stateStoreCommitIndex"]
        == store_proof["stateStoreCommitIndex"]
        and commit_receipt["stateStoreIdentitySha256"]
        == release_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ]
        and commit_receipt["verifierChallengeSha256"]
        == transition["verifierChallengeSha256"],
        "signed verifier-state commit receipt crossed its request, receipt, store proof, or successor",
    )
    committed_state = verify_nonce_authority_verifier_state(
        transition["committedState"],
        key=verifier_state_key,
        key_id=verifier_state_key_id,
        assurance=release_config["nonceAuthorityAssurance"],
        assurance_sha256=release_config[
            "nonceAuthorityAssuranceSha256"
        ],
        state_store_identity_sha256=release_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
    )
    require(
        transition["committedStateSha256"]
        == committed_state["envelopeSha256"]
        and committed_state["payload"] == committed_state_payload,
        "signed committed verifier state is not the exact durable successor",
    )
    final_read = validate_verifier_state_read_response(
        transition["committedStateRead"],
        release_config=release_config,
        verifier_state_key=verifier_state_key,
        verifier_state_key_id=verifier_state_key_id,
        expected_state=committed_state,
        label="committed verifier-state read",
    )
    require(
        transition["committedStateReadSha256"]
        == final_read["documentSha256"],
        "committed verifier-state read digest is invalid",
    )
    return {
        "commitCandidate": commit_candidate,
        "commitReceipt": commit_receipt,
        "commitReceiptSha256": commit_receipt_sha256,
        "commitRequest": commit_request,
        "commitRequestSha256": commit_request_sha256,
        "committedState": committed_state,
        "committedStateRead": final_read,
        "document": transition,
        "documentSha256": sha256_json(transition),
        "priorStateRead": prior_read,
        "signedStoreCommitProof": store_proof,
        "signedStoreCommitProofSha256": store_proof_sha256,
    }


def validate_tls_binding(value: Any) -> tuple[dict[str, Any], str]:
    binding = exact_object(
        value,
        TLS_BINDING_FIELDS,
        "producer TLS binding",
    )
    require(
        binding["apiVersion"] == "serverware.enclaveTlsScope/v2"
        and binding["exporterLabel"]
        == "EXPORTER-Serverware-Attestation-v1",
        "producer TLS binding version is invalid",
    )
    for field in (
        "bindingSha256",
        "connectionNonceSha256",
        "exporterSha256",
        "leafCertificateSha256",
        "leafSpkiSha256",
        "peerCertificateSha256",
        "peerSpkiSha256",
        "tlsScopeEnvelopeSha256",
        "tlsScopeKeySpkiSha256",
        "tlsStackMeasurementSha256",
    ):
        require_sha256(binding[field], f"TLS binding {field}")
    for field in (
        "connectionId",
        "enclaveBootId",
        "enclaveInstanceId",
        "peerIdentity",
    ):
        require(
            isinstance(binding[field], str)
            and IDENTIFIER_RE.fullmatch(binding[field]) is not None,
            f"TLS binding {field} is invalid",
        )
    require(
        isinstance(binding["provider"], str)
        and re.fullmatch(
            r"enclave-[A-Za-z0-9._:@+-]{1,120}",
            binding["provider"],
        )
        is not None,
        "TLS binding provider is invalid",
    )
    issued = require_u64(
        binding["issuedAtUnix"],
        "TLS binding issue time",
        minimum=1,
    )
    expires = require_u64(
        binding["expiresAtUnix"],
        "TLS binding expiry",
        minimum=1,
    )
    require(
        issued < expires and expires - issued <= 60,
        "TLS binding validity is invalid",
    )
    require_u64(
        binding["tlsKeyGeneration"],
        "TLS key generation",
        minimum=1,
    )
    require_u64(
        binding["tlsScopeKeyGeneration"],
        "TLS-scope key generation",
        minimum=1,
    )
    without_digest = {
        key: item
        for key, item in binding.items()
        if key != "bindingSha256"
    }
    expected_digest = sha256_json(without_digest)
    require(
        binding["bindingSha256"] == expected_digest,
        "TLS binding digest is invalid",
    )
    return binding, expected_digest


def validate_producer_request(
    value: Any,
    *,
    raw: bytes,
    stable_pins: Mapping[str, str],
    release_identity_sha256: str,
    producer_ephemeral_public_key_spki_der: bytes,
    producer_ephemeral_key_spki_sha256: str,
    nonce_store_key: Ed25519PublicKey,
    nonce_authority_assurance: Mapping[str, Any],
    nonce_authority_assurance_sha256: str,
    minimum_rollback_continuity_commitment_sha256: str,
    release_config: Mapping[str, Any],
    trust_key_ids: Mapping[str, str],
    verifier_state_key: Ed25519PublicKey,
    assurance_evidence_key: Ed25519PublicKey,
    store_attestation_key: Ed25519PublicKey,
) -> dict[str, Any]:
    request = exact_object(
        value,
        {
            "apiVersion",
            "liveSessionRequest",
            "releaseIdentitySha256",
            "staticPins",
        },
        "public attestation producer request",
    )
    require(
        request["apiVersion"] == PRODUCER_REQUEST_VERSION
        and request["releaseIdentitySha256"] == release_identity_sha256,
        "producer request crossed the stable release identity",
    )
    request_pins = statement_pins(
        request["staticPins"],
        "producer request static pins",
    )
    require(
        request_pins == stable_pins,
        "producer request static pins differ from the signed release",
    )
    validated_nonce_authority_assurance = (
        validate_nonce_authority_assurance(
            nonce_authority_assurance,
            expected_authority_identity_sha256=stable_pins[
                "nonceStoreIdentitySha256"
            ],
        )
    )
    require(
        nonce_authority_assurance_sha256
        == sha256_json(validated_nonce_authority_assurance),
        "producer nonce authority assurance differs from its release config",
    )
    evidence_now = int(time.time())
    nonce_store_key_id = sha256_bytes(
        nonce_store_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    verifier_state_key_id = sha256_bytes(
        verifier_state_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    store_attestation_key_id = sha256_bytes(
        store_attestation_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    store_assurance = validate_verifier_state_store_assurance(
        release_config,
        store_attestation_key_id=store_attestation_key_id,
        now=evidence_now,
    )
    role_separation = validate_verifier_state_role_separation(
        release_config,
        nonce_authority_assurance=validated_nonce_authority_assurance,
        nonce_store_key_id=nonce_store_key_id,
        verifier_state_key_id=verifier_state_key_id,
        store_attestation_key_id=store_attestation_key_id,
        store_assurance=store_assurance,
        service=release_config["nonceAuthorityVerifierStateService"],
        now=evidence_now,
    )
    live = exact_object(
        request["liveSessionRequest"],
        {
            "apiVersion",
            "callerNonceBase64url",
            "callerNonceSha256",
            "expiresAtUnix",
            "httpRequest",
            "issuedAtUnix",
            "nonceConsumption",
            "nonceConsumptionReceipt",
            "nonceConsumptionReceiptSha256",
            "nonceAuthorityVerifierStateTransition",
            "oneUse",
            "producerInvocation",
            "producerInvocationSha256",
            "tlsBinding",
            "tlsBindingSha256",
        },
        "public attestation live request",
    )
    require(
        live["apiVersion"] == LIVE_REQUEST_VERSION
        and live["oneUse"] is True,
        "producer request is not a one-use live request",
    )
    nonce = base64url_decode(
        live["callerNonceBase64url"],
        "caller nonce",
        exact_length=32,
        maximum=32,
    )
    caller_nonce_sha256 = sha256_bytes(nonce)
    require(
        live["callerNonceSha256"] == caller_nonce_sha256,
        "caller nonce digest is invalid",
    )
    http_request = exact_object(
        live["httpRequest"],
        {"bodySha256", "method", "path"},
        "producer HTTP request",
    )
    request_body_sha256 = require_sha256(
        http_request["bodySha256"],
        "producer HTTP request body",
    )
    require(
        http_request["method"] == "POST"
        and http_request["path"] == "/attestation/public-evidence",
        "producer HTTP request target is invalid",
    )
    issued = require_u64(
        live["issuedAtUnix"],
        "live request issue time",
        minimum=1,
    )
    expires = require_u64(
        live["expiresAtUnix"],
        "live request expiry",
        minimum=1,
    )
    require(
        issued < expires and 15 <= expires - issued <= 30,
        "live request validity is invalid",
    )
    tls_binding, tls_binding_sha256 = validate_tls_binding(
        live["tlsBinding"]
    )
    require(
        live["tlsBindingSha256"] == tls_binding_sha256
        and tls_binding["issuedAtUnix"] <= issued < tls_binding["expiresAtUnix"]
        and expires <= tls_binding["expiresAtUnix"],
        "live request crossed its TLS binding",
    )
    invocation = exact_object(
        live["producerInvocation"],
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
        "public attestation producer invocation",
    )
    for field in (
        "nonceAuthorityVerifierChallengeBase64url",
        "nonceAuthorityVerifierStateOperationIdBase64url",
        "producerChannelChallengeBase64url",
        "witnessVerifierChallengeBase64url",
    ):
        base64url_decode(
            invocation[field],
            f"producer invocation {field}",
            exact_length=32,
            maximum=32,
        )
    require_sha256(
        invocation["minimumRollbackContinuityCommitmentSha256"],
        "producer invocation minimum rollback continuity",
    )
    invocation_public_key_der = base64url_decode(
        invocation[
            "producerEphemeralKeySpkiDerBase64url"
        ],
        "producer invocation ephemeral public key",
        exact_length=44,
        maximum=44,
    )
    require(
        invocation["apiVersion"] == PRODUCER_INVOCATION_VERSION
        and invocation["minimumReleaseIdentitySha256"]
        == release_identity_sha256
        and invocation[
            "minimumRollbackContinuityCommitmentSha256"
        ]
        == minimum_rollback_continuity_commitment_sha256
        and invocation_public_key_der
        == producer_ephemeral_public_key_spki_der
        and invocation["producerEphemeralKeySpkiSha256"]
        == producer_ephemeral_key_spki_sha256,
        "producer invocation crossed its release or sealed ephemeral seed",
    )
    require(
        set(trust_key_ids) == set(TRUST_KEY_ROLES),
        "producer request trust-root role registry is incomplete",
    )
    global_request_role_keys = {
        **role_separation["roleKeyIdsByRole"],
        "witnessStore": stable_pins["witnessStoreKeySpkiSha256"],
        "releaseCa": release_config["releaseIdentity"]["configuration"][
            "caSpkiSha256"
        ],
        "responseKey": release_config["releaseIdentity"][
            "configuration"
        ]["responseKeySpkiSha256"],
        "release": release_config["releaseIdentity"]["configuration"][
            "releaseKeySpkiSha256"
        ],
        "tlsScope": release_config["releaseIdentity"]["configuration"][
            "tlsScopeSigningKeySpkiSha256"
        ],
        "witness": release_config["releaseIdentity"]["configuration"][
            "witnessKeySpkiSha256"
        ],
        **{
            f"trustRoot:{name}": trust_key_ids[name]
            for name in sorted(trust_key_ids)
            if name not in {"completion", "witness"}
        },
        "producer": producer_ephemeral_key_spki_sha256,
        "producerServiceTls": require_sha256(
            tls_binding["leafSpkiSha256"],
            "producer request TLS leaf SPKI",
        ),
        "publicEvidenceCallerTls": require_sha256(
            tls_binding["peerSpkiSha256"],
            "producer request TLS peer SPKI",
        ),
    }
    validate_global_attestation_key_role_separation(
        global_request_role_keys,
        expected_roles=global_request_role_keys,
    )
    preimage = producer_invocation_preimage(
        caller_nonce_sha256=caller_nonce_sha256,
        expires_at_unix=expires,
        issued_at_unix=issued,
        minimum_release_identity_sha256=invocation[
            "minimumReleaseIdentitySha256"
        ],
        minimum_rollback_continuity_commitment_sha256=invocation[
            "minimumRollbackContinuityCommitmentSha256"
        ],
        nonce_authority_verifier_challenge_base64url=invocation[
            "nonceAuthorityVerifierChallengeBase64url"
        ],
        nonce_authority_verifier_state_operation_id_base64url=invocation[
            "nonceAuthorityVerifierStateOperationIdBase64url"
        ],
        producer_channel_challenge_base64url=invocation[
            "producerChannelChallengeBase64url"
        ],
        producer_ephemeral_key_spki_der_base64url=(
            invocation[
                "producerEphemeralKeySpkiDerBase64url"
            ]
        ),
        producer_ephemeral_key_spki_sha256=invocation[
            "producerEphemeralKeySpkiSha256"
        ],
        release_identity_sha256=release_identity_sha256,
        request_body_sha256=request_body_sha256,
        static_pins=stable_pins,
        tls_binding_sha256=tls_binding_sha256,
        witness_verifier_challenge_base64url=invocation[
            "witnessVerifierChallengeBase64url"
        ],
    )
    require(
        invocation == preimage
        and live["producerInvocationSha256"]
        == sha256_json(invocation),
        "producer invocation preimage digest is invalid",
    )
    verifier_state_transition = (
        validate_verifier_state_transition_prefix(
            live["nonceAuthorityVerifierStateTransition"],
            release_config=release_config,
            trust_key_ids=trust["keyIds"],
            verifier_state_key=verifier_state_key,
            assurance_evidence_key=assurance_evidence_key,
            store_attestation_key=store_attestation_key,
            now=int(time.time()),
        )
    )
    require(
        invocation["nonceAuthorityVerifierChallengeBase64url"]
        == live["nonceAuthorityVerifierStateTransition"][
            "verifierChallengeBase64url"
        ]
        and invocation[
            "nonceAuthorityVerifierStateOperationIdBase64url"
        ]
        == live["nonceAuthorityVerifierStateTransition"][
            "operationIdBase64url"
        ],
        "producer invocation crossed its verifier-state challenge or operation",
    )
    prepared_operation = verifier_state_transition[
        "preparedOperation"
    ]
    prepared_invocation = prepared_operation["prepareRequest"][
        "producerInvocation"
    ]
    prepared_recovery_identity = verifier_state_transition[
        "recoveryIdentity"
    ]
    prepared_request_binding = prepared_operation["requestBinding"]
    require(
        prepared_invocation == invocation
        and prepared_operation["prepareRequest"][
            "producerInvocationSha256"
        ]
        == live["producerInvocationSha256"]
        and prepared_recovery_identity["callerNonceSha256"]
        == caller_nonce_sha256
        and prepared_recovery_identity["requestBodySha256"]
        == request_body_sha256
        and prepared_recovery_identity["releaseIdentitySha256"]
        == release_identity_sha256
        and prepared_recovery_identity["immutableConfigSha256"]
        == stable_pins["immutableConfigSha256"]
        and prepared_request_binding["expiresAtUnix"]
        == invocation["expiresAtUnix"]
        and prepared_request_binding["nonceSha256"]
        == caller_nonce_sha256
        and prepared_request_binding[
            "producerChannelChallengeBase64url"
        ]
        == invocation["producerChannelChallengeBase64url"]
        and prepared_request_binding["producerEphemeralKeySha256"]
        == invocation["producerEphemeralKeySpkiSha256"]
        and prepared_request_binding["producerInvocationSha256"]
        == live["producerInvocationSha256"]
        and prepared_request_binding["requestBodySha256"]
        == request_body_sha256
        and prepared_request_binding["tlsBindingSha256"]
        == tls_binding_sha256
        and prepared_request_binding["transactionIdBase64url"]
        == verifier_state_transition["document"][
            "operationIdBase64url"
        ],
        "producer request crossed its exact prepared verifier-state saga",
    )
    nonce_receipt = verify_signed_nonce_receipt(
        live["nonceConsumptionReceipt"],
        key=nonce_store_key,
        key_id=stable_pins["nonceStoreKeySpkiSha256"],
        caller_nonce_sha256=caller_nonce_sha256,
        request_body_sha256=request_body_sha256,
        tls_binding_sha256=tls_binding_sha256,
        nonce_store_identity_sha256=stable_pins[
            "nonceStoreIdentitySha256"
        ],
        producer_invocation=invocation,
        producer_invocation_sha256=live[
            "producerInvocationSha256"
        ],
        issued_at_unix=issued,
        expires_at_unix=expires,
        nonce_authority_assurance=(
            validated_nonce_authority_assurance
        ),
        nonce_authority_assurance_sha256=(
            nonce_authority_assurance_sha256
        ),
        prior_verifier_state=verifier_state_transition[
            "priorState"
        ],
    )
    require(
        live["nonceConsumptionReceiptSha256"]
        == nonce_receipt["receiptSha256"]
        and live["nonceConsumption"] == nonce_receipt["consumption"],
        "producer request nonce receipt or compatibility projection is invalid",
    )
    completed_verifier_state_transition = (
        validate_verifier_state_transition_suffix(
            verifier_state_transition,
            nonce_receipt=nonce_receipt,
            release_config=release_config,
            verifier_state_key=verifier_state_key,
            store_attestation_key=store_attestation_key,
            now=int(time.time()),
        )
    )
    verifier_state_challenge = base64url_decode(
            invocation[
                "nonceAuthorityVerifierChallengeBase64url"
            ],
            "producer invocation verifier-state challenge",
            exact_length=32,
            maximum=32,
        )
    verifier_state_operation = base64url_decode(
            invocation[
                "nonceAuthorityVerifierStateOperationIdBase64url"
            ],
            "producer invocation verifier-state operation",
            exact_length=32,
            maximum=32,
        )
    producer_challenge = base64url_decode(
            invocation["producerChannelChallengeBase64url"],
            "producer invocation producer challenge",
            exact_length=32,
            maximum=32,
        )
    witness_challenge = base64url_decode(
            invocation["witnessVerifierChallengeBase64url"],
            "producer invocation witness challenge",
            exact_length=32,
            maximum=32,
        )
    nonce_transaction = base64url_decode(
            nonce_receipt["payload"]["transactionIdBase64url"],
            "producer invocation transaction ID",
            exact_length=32,
            maximum=32,
        )
    require(
        nonce_transaction == verifier_state_operation,
        "nonce transaction ID must equal the verifier-state operation ID",
    )
    invocation_randoms = {
        nonce,
        verifier_state_challenge,
        verifier_state_operation,
        producer_challenge,
        witness_challenge,
    }
    require(
        len(invocation_randoms) == 5,
        "producer request must use five independent values with one shared verifier operation/nonce transaction identity",
    )
    return {
        "callerNonceSha256": caller_nonce_sha256,
        "expiresAtUnix": expires,
        "issuedAtUnix": issued,
        "minimumReleaseIdentitySha256":
        invocation["minimumReleaseIdentitySha256"],
        "minimumRollbackContinuityCommitmentSha256":
        invocation[
            "minimumRollbackContinuityCommitmentSha256"
        ],
        "nonceAuthorityAssuranceSha256":
        nonce_receipt["nonceAuthorityAssuranceSha256"],
        "nonceAuthorityAssuranceEvidenceSha256": (
            None
            if release_config["nonceAuthorityAssuranceEvidence"] is None
            else sha256_json(
                release_config["nonceAuthorityAssuranceEvidence"]
            )
        ),
        "nonceAuthorityState": nonce_receipt["authorityState"],
        "nonceAuthorityStateSha256":
        nonce_receipt["authorityStateSha256"],
        "nonceAuthorityVerifierStateAuthorizationSha256":
        nonce_receipt[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ],
        "nonceAuthorityVerifierStateCommitReceiptSha256":
        completed_verifier_state_transition[
            "commitReceiptSha256"
        ],
        "nonceAuthorityVerifierStateCommitRequestSha256":
        completed_verifier_state_transition[
            "commitRequestSha256"
        ],
        "nonceAuthorityVerifierStateCommittedStateReadSha256":
        completed_verifier_state_transition[
            "committedStateRead"
        ]["documentSha256"],
        "nonceAuthorityVerifierStateCommittedStateSha256":
        completed_verifier_state_transition[
            "committedState"
        ]["envelopeSha256"],
        "nonceAuthorityVerifierStatePriorStateReadSha256":
        completed_verifier_state_transition[
            "priorStateRead"
        ]["documentSha256"],
        "nonceAuthorityVerifierStatePriorStateSha256":
        verifier_state_transition["priorState"]["envelopeSha256"],
        "nonceAuthorityVerifierStateStoreCommitProofSha256":
        completed_verifier_state_transition[
            "signedStoreCommitProofSha256"
        ],
        "nonceAuthorityVerifierStateTransition":
        completed_verifier_state_transition["document"],
        "nonceAuthorityVerifierStateTransitionSha256":
        completed_verifier_state_transition["documentSha256"],
        "nonceAuthorityVerifierChallengeSha256":
        live["nonceAuthorityVerifierStateTransition"][
            "verifierChallengeSha256"
        ],
        "nonceAuthorityVerifierStateOperationIdBase64url":
        live["nonceAuthorityVerifierStateTransition"][
            "operationIdBase64url"
        ],
        "nonceAuthorityVerifierStateServiceConfigurationSha256":
        release_config["nonceAuthorityVerifierStateService"][
            "serviceConfigurationSha256"
        ],
        "nonceAuthorityVerifierStateSigningKeySpkiSha256":
        verifier_state_transition["verifierStateKeyId"],
        "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256":
        release_config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256":
        release_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ],
        "nonceAuthorityVerifierStateRoleSeparationEvidenceSha256":
        sha256_json(
            release_config[
                "nonceAuthorityVerifierStateRoleSeparationEvidence"
            ]
        ),
        "nonceAuthorityVerifierStateStoreConfigurationSha256":
        release_config[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ],
        "nonceAuthorityVerifierStateStoreMinimumCommitIndex":
        release_config[
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
        ],
        "nonceAuthorityVerifierStateStoreMinimumGeneration":
        release_config[
            "nonceAuthorityVerifierStateStoreMinimumGeneration"
        ],
        "nonceAuthorityVerifierStateStoreAttestationKeySpkiSha256":
        verifier_state_transition["storeAttestationKeyId"],
        "nonceAuthorityVerifierStateStoreIdentitySha256":
        release_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
        "nonceConsumption": nonce_receipt["consumption"],
        "nonceConsumptionReceipt": nonce_receipt["document"],
        "nonceConsumptionReceiptSha256":
        nonce_receipt["receiptSha256"],
        "nonceConsumptionSha256":
        nonce_receipt["consumptionSha256"],
        "producerChannelChallengeBase64url":
        invocation["producerChannelChallengeBase64url"],
        "producerEphemeralKeySpkiSha256":
        invocation["producerEphemeralKeySpkiSha256"],
        "producerInvocationSha256":
        live["producerInvocationSha256"],
        "producerRequestSha256": sha256_bytes(raw),
        "requestBodySha256": request_body_sha256,
        "transactionIdBase64url":
        nonce_receipt["payload"]["transactionIdBase64url"],
        "tlsBindingSha256": tls_binding_sha256,
        "witnessVerifierChallengeBase64url":
        invocation["witnessVerifierChallengeBase64url"],
    }


def _verify_standard_envelope(
    document: Any,
    *,
    api_version: str,
    domain: bytes,
    key: Ed25519PublicKey,
    key_id: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    return verify_standard_envelope(
        document,
        api_version=api_version,
        domain=domain,
        key=key,
        key_id=key_id,
        label=label,
    )


def live_witness_head_chain_sha256(
    current: Mapping[str, Any],
    previous: Mapping[str, Any] | None,
) -> str:
    return sha256_bytes(
        LIVE_WITNESS_HEAD_CHAIN_DOMAIN
        + canonical_json(
            {
                "checkpointSha256": current["checkpointSha256"],
                "previousHeadSha256": (
                    None if previous is None else previous["headSha256"]
                ),
            }
        )
    )


def live_witness_continuity_sha256(
    *,
    current: Mapping[str, Any],
    previous_commitment_sha256: str | None,
    witness_store_identity_sha256: str,
    witness_store_key_spki_sha256: str,
) -> str:
    return sha256_bytes(
        LIVE_WITNESS_CONTINUITY_DOMAIN
        + canonical_json(
            {
                "apiVersion": LIVE_WITNESS_CONTINUITY_VERSION,
                "checkpointSha256": current["checkpointSha256"],
                "generation": current["generation"],
                "headSha256": current["headSha256"],
                "previousRollbackContinuityCommitmentSha256":
                previous_commitment_sha256,
                "releaseIdentitySha256":
                current["releaseIdentitySha256"],
                "rollbackEpoch": current["rollbackEpoch"],
                "sequence": current["sequence"],
                "treeSize": current["treeSize"],
                "witnessStoreIdentitySha256":
                witness_store_identity_sha256,
                "witnessStoreKeySpkiSha256":
                witness_store_key_spki_sha256,
            }
        )
    )


def verify_witness_service_envelope(
    value: Any,
    *,
    api_version: str,
    domain: bytes,
    key: Ed25519PublicKey,
    key_id: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    document = exact_object(
        value,
        {"apiVersion", "payload", "payloadSha256", "signature", "signingKeyId"},
        label,
    )
    require(
        document["apiVersion"] == api_version
        and document["signingKeyId"] == key_id,
        f"{label} version or key identity is invalid",
    )
    payload_sha256 = require_sha256(
        document["payloadSha256"],
        f"{label} payload",
    )
    require(
        payload_sha256 == sha256_json(document["payload"]),
        f"{label} payload digest is invalid",
    )
    signature = base64url_decode(
        document["signature"],
        f"{label} signature",
        exact_length=64,
        maximum=64,
    )
    try:
        key.verify(
            signature,
            domain
            + canonical_json(
                {
                    "payload": document["payload"],
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise ContractError(f"{label} signature is invalid") from exc
    require(
        isinstance(document["payload"], dict),
        f"{label} payload is not an object",
    )
    return (
        document["payload"],
        sha256_bytes(canonical_json(document) + b"\n"),
    )


def validate_witness_invocation_binding(
    value: Any,
    *,
    expected: Mapping[str, Any],
) -> dict[str, Any]:
    binding = exact_object(
        value,
        {
            "apiVersion",
            "currentRequestSha256",
            "producerEphemeralKeySpkiSha256",
            "producerInvocationSha256",
            "producerRequestSha256",
            "tlsBindingSha256",
            "verifierChallengeBase64url",
        },
        "witness invocation binding",
    )
    base64url_decode(
        binding["verifierChallengeBase64url"],
        "witness verifier challenge",
        exact_length=32,
        maximum=32,
    )
    for field in (
        "currentRequestSha256",
        "producerEphemeralKeySpkiSha256",
        "producerInvocationSha256",
        "producerRequestSha256",
        "tlsBindingSha256",
    ):
        require_sha256(binding[field], f"witness invocation {field}")
    require(
        binding["apiVersion"] == WITNESS_INVOCATION_BINDING_VERSION
        and binding == expected,
        "witness invocation binding crossed its exact current request",
    )
    return binding


def verify_live_witness_response(
    value: Any,
    *,
    witness_request: Mapping[str, Any],
    context: Mapping[str, Any],
    release_identity: Mapping[str, Any],
    trust: Mapping[str, Any],
    witness_store_key: Ed25519PublicKey,
    pins: Mapping[str, str],
) -> dict[str, Any]:
    now = require_u64(
        int(time.time()),
        "producer current time",
        minimum=1,
    )
    response = exact_object(
        value,
        {
            "apiVersion",
            "checkpointCasReceipt",
            "currentRequestSha256",
            "invocationBinding",
            "liveWitnessHead",
            "protectedLiveWitnessState",
            "rollbackContinuityCommitmentSha256",
            "witnessStoreIdentitySha256",
            "witnessStoreKeySpkiSha256",
        },
        "attestation witness current response",
    )
    current_request_sha256 = sha256_json(dict(witness_request))
    expected_invocation_binding = {
        "apiVersion": WITNESS_INVOCATION_BINDING_VERSION,
        "currentRequestSha256": current_request_sha256,
        "producerEphemeralKeySpkiSha256":
        context["producerEphemeralKeySpkiSha256"],
        "producerInvocationSha256":
        context["producerInvocationSha256"],
        "producerRequestSha256": context["producerRequestSha256"],
        "tlsBindingSha256": context["tlsBindingSha256"],
        "verifierChallengeBase64url":
        context["witnessVerifierChallengeBase64url"],
    }
    response_invocation = validate_witness_invocation_binding(
        response["invocationBinding"],
        expected=expected_invocation_binding,
    )
    require(
        response["apiVersion"] == WITNESS_RESPONSE_VERSION
        and response["currentRequestSha256"]
        == current_request_sha256
        and response["witnessStoreIdentitySha256"]
        == pins["witnessStoreIdentitySha256"]
        and response["witnessStoreKeySpkiSha256"]
        == pins["witnessStoreKeySpkiSha256"],
        "live witness response crossed its request",
    )
    live_payload, _ = verify_witness_service_envelope(
        response["liveWitnessHead"],
        api_version=LIVE_WITNESS_HEAD_VERSION,
        domain=LIVE_WITNESS_HEAD_DOMAIN,
        key=trust["keys"]["witness"],
        key_id=trust["keyIds"]["witness"],
        label="live witness head",
    )
    live = exact_object(
        live_payload,
        {
            "expiresAtUnix",
            "generation",
            "headSha256",
            "invocationBinding",
            "issuedAtUnix",
            "releaseIdentitySha256",
            "rollbackEpoch",
            "sequence",
            "treeSize",
        },
        "live witness head payload",
    )
    live_issued = require_u64(
        live["issuedAtUnix"],
        "live witness issue time",
        minimum=1,
    )
    live_expires = require_u64(
        live["expiresAtUnix"],
        "live witness expiry",
        minimum=1,
    )
    live_generation = require_u64(
        live["generation"],
        "live witness generation",
        minimum=1,
    )
    live_rollback = require_u64(
        live["rollbackEpoch"],
        "live witness rollback epoch",
    )
    live_sequence = require_u64(
        live["sequence"],
        "live witness sequence",
        minimum=1,
    )
    live_tree_size = require_u64(
        live["treeSize"],
        "live witness tree size",
        minimum=1,
    )
    require_sha256(live["headSha256"], "live witness head")
    validate_witness_invocation_binding(
        live["invocationBinding"],
        expected=expected_invocation_binding,
    )
    require(
        context["issuedAtUnix"] <= live_issued <= now < live_expires
        and 1 <= live_expires - live_issued <= 30
        and live_expires >= context["expiresAtUnix"]
        and live["releaseIdentitySha256"]
        == sha256_json(release_identity)
        and live_generation
        == release_identity["monotonicRelease"]["releaseGeneration"]
        and live_rollback
        == release_identity["monotonicRelease"]["rollbackEpoch"],
        "live witness head is stale or crossed its stable release",
    )
    protected_payload, _ = verify_witness_service_envelope(
        response["protectedLiveWitnessState"],
        api_version=PROTECTED_WITNESS_VERSION,
        domain=PROTECTED_WITNESS_DOMAIN,
        key=witness_store_key,
        key_id=pins["witnessStoreKeySpkiSha256"],
        label="protected live witness state",
    )
    protected = exact_object(
        protected_payload,
        {
            "checkpointCasReceipt",
            "current",
            "expiresAtUnix",
            "invocationBinding",
            "issuedAtUnix",
            "previous",
            "releaseIdentitySha256",
            "rollbackContinuityCommitmentSha256",
            "storeAssurance",
            "witnessStoreIdentity",
            "witnessStoreIdentitySha256",
            "witnessStoreKeySpkiSha256",
            "witnessSigningKeyId",
        },
        "protected live witness payload",
    )
    protected_issued = require_u64(
        protected["issuedAtUnix"],
        "protected witness issue time",
        minimum=1,
    )
    protected_expires = require_u64(
        protected["expiresAtUnix"],
        "protected witness expiry",
        minimum=1,
    )
    require(
        context["issuedAtUnix"]
        <= protected_issued
        <= now
        < protected_expires
        and 1 <= protected_expires - protected_issued <= 30
        and protected_expires >= context["expiresAtUnix"]
        and protected["releaseIdentitySha256"]
        == sha256_json(release_identity)
        and protected["storeAssurance"]
        == "externallyWitnessedRollbackProtected"
        and protected["witnessStoreIdentitySha256"]
        == pins["witnessStoreIdentitySha256"]
        and protected["witnessStoreKeySpkiSha256"]
        == pins["witnessStoreKeySpkiSha256"]
        and protected["witnessSigningKeyId"]
        == trust["keyIds"]["witness"],
        "protected witness state crossed its release, store, or time window",
    )
    validate_witness_invocation_binding(
        protected["invocationBinding"],
        expected=expected_invocation_binding,
    )
    require(
        live["invocationBinding"]
        == protected["invocationBinding"]
        == response_invocation,
        "witness signed envelopes disagree on invocation binding",
    )
    require_sha256(
        protected["rollbackContinuityCommitmentSha256"],
        "witness rollback continuity commitment",
    )
    store_identity = exact_object(
        protected["witnessStoreIdentity"],
        {
            "apiVersion",
            "assurance",
            "deploymentId",
            "serviceId",
            "storageBackend",
        },
        "witness store identity",
    )
    require(
        store_identity["apiVersion"]
        == "serverware.attestationWitnessStoreIdentity/v2"
        and store_identity["assurance"]
        == "externallyWitnessedRollbackProtected"
        and store_identity["storageBackend"]
        == "external-linearizable-cas"
        and isinstance(store_identity["deploymentId"], str)
        and STORE_IDENTIFIER_RE.fullmatch(store_identity["deploymentId"])
        is not None
        and isinstance(store_identity["serviceId"], str)
        and STORE_IDENTIFIER_RE.fullmatch(store_identity["serviceId"])
        is not None
        and sha256_json(store_identity)
        == pins["witnessStoreIdentitySha256"],
        "witness store identity is not the pinned external CAS service",
    )
    current = exact_object(
        protected["current"],
        {
            "checkpointSha256",
            "generation",
            "headSha256",
            "liveWitnessHeadPayloadSha256",
            "releaseIdentitySha256",
            "rollbackEpoch",
            "sequence",
            "treeSize",
        },
        "protected current witness checkpoint",
    )
    for field in (
        "checkpointSha256",
        "headSha256",
        "liveWitnessHeadPayloadSha256",
        "releaseIdentitySha256",
    ):
        require_sha256(current[field], f"current witness {field}")
    current_generation = require_u64(
        current["generation"],
        "current witness generation",
        minimum=1,
    )
    current_rollback = require_u64(
        current["rollbackEpoch"],
        "current witness rollback epoch",
    )
    current_sequence = require_u64(
        current["sequence"],
        "current witness sequence",
        minimum=1,
    )
    current_tree = require_u64(
        current["treeSize"],
        "current witness tree size",
        minimum=1,
    )
    require(
        current_generation == live_generation
        and current_rollback == live_rollback
        and current_sequence == live_sequence
        and current_tree == live_tree_size
        and current["headSha256"] == live["headSha256"]
        and current["releaseIdentitySha256"]
        == live["releaseIdentitySha256"]
        and current["liveWitnessHeadPayloadSha256"]
        == response["liveWitnessHead"]["payloadSha256"],
        "protected current checkpoint differs from the signed live head",
    )
    receipt = exact_object(
        protected["checkpointCasReceipt"],
        {
            "apiVersion",
            "checkpointSha256",
            "committedAtUnix",
            "committedRollbackContinuityCommitmentSha256",
            "generation",
            "previousRollbackContinuityCommitmentSha256",
            "releaseIdentitySha256",
            "sequence",
            "transactionIdBase64url",
            "witnessStoreIdentitySha256",
        },
        "witness CAS receipt",
    )
    committed_at = require_u64(
        receipt["committedAtUnix"],
        "witness CAS commit time",
        minimum=1,
    )
    receipt_generation = require_u64(
        receipt["generation"],
        "witness CAS generation",
        minimum=1,
    )
    receipt_sequence = require_u64(
        receipt["sequence"],
        "witness CAS sequence",
        minimum=1,
    )
    base64url_decode(
        receipt["transactionIdBase64url"],
        "witness CAS transaction id",
        exact_length=32,
        maximum=32,
    )
    require(
        receipt["apiVersion"] == "serverware.liveWitnessCasReceipt/v1"
        and receipt["checkpointSha256"] == current["checkpointSha256"]
        and receipt["committedRollbackContinuityCommitmentSha256"]
        == protected["rollbackContinuityCommitmentSha256"]
        and receipt_generation == live_generation
        and receipt_sequence == live_sequence
        and receipt["releaseIdentitySha256"]
        == live["releaseIdentitySha256"]
        and receipt["witnessStoreIdentitySha256"]
        == pins["witnessStoreIdentitySha256"]
        and committed_at
        <= context["issuedAtUnix"]
        <= protected_issued,
        "witness CAS receipt crossed the protected current checkpoint",
    )
    require(
        response["checkpointCasReceipt"]
        == protected["checkpointCasReceipt"]
        and response["rollbackContinuityCommitmentSha256"]
        == protected["rollbackContinuityCommitmentSha256"],
        "witness response wrapper differs from the signed protected state",
    )
    previous = protected["previous"]
    previous_commitment = receipt[
        "previousRollbackContinuityCommitmentSha256"
    ]
    if previous is None:
        require(
            previous_commitment is None,
            "genesis witness state has a previous continuity commitment",
        )
    else:
        prior = exact_object(
            previous,
            {
                "checkpointSha256",
                "generation",
                "headSha256",
                "releaseIdentitySha256",
                "rollbackEpoch",
                "sequence",
                "treeSize",
            },
            "protected previous witness checkpoint",
        )
        for field in (
            "checkpointSha256",
            "headSha256",
            "releaseIdentitySha256",
        ):
            require_sha256(prior[field], f"previous witness {field}")
        require_sha256(
            previous_commitment,
            "previous rollback continuity commitment",
        )
        prior_generation = require_u64(
            prior["generation"],
            "previous witness generation",
            minimum=1,
        )
        prior_rollback = require_u64(
            prior["rollbackEpoch"],
            "previous witness rollback epoch",
        )
        prior_sequence = require_u64(
            prior["sequence"],
            "previous witness sequence",
            minimum=1,
        )
        prior_tree = require_u64(
            prior["treeSize"],
            "previous witness tree size",
            minimum=1,
        )
        require(
            prior["releaseIdentitySha256"]
            == live["releaseIdentitySha256"]
            and prior_generation <= live_generation
            and prior_rollback <= live_rollback
            and (
                prior_generation < live_generation
                or (
                    prior_sequence < live_sequence
                    and prior_tree <= live_tree_size
                )
            ),
            "protected witness transition is not monotonic",
        )
    require(
        current["headSha256"]
        == live_witness_head_chain_sha256(current, previous)
        and protected["rollbackContinuityCommitmentSha256"]
        == live_witness_continuity_sha256(
            current=current,
            previous_commitment_sha256=previous_commitment,
            witness_store_identity_sha256=(
                pins["witnessStoreIdentitySha256"]
            ),
            witness_store_key_spki_sha256=(
                pins["witnessStoreKeySpkiSha256"]
            ),
        ),
        "protected witness chain or rollback commitment is invalid",
    )
    return {
        "currentRequestSha256": current_request_sha256,
        "document": response["liveWitnessHead"],
        "expiresAtUnix": live_expires,
        "invocationBinding": response_invocation,
        "protectedDocument": response["protectedLiveWitnessState"],
        "witness": {
            "generation": live_generation,
            "headSha256": live["headSha256"],
            "rollbackEpoch": live_rollback,
            "sequence": live_sequence,
            "treeSize": live_tree_size,
        },
    }


def obtain_live_witness(
    args: argparse.Namespace,
    *,
    context: Mapping[str, Any],
    release_identity: Mapping[str, Any],
    trust: Mapping[str, Any],
    witness_store_key: Ed25519PublicKey,
    pins: Mapping[str, str],
    deadline: float,
) -> dict[str, Any]:
    request = {
        "apiVersion": WITNESS_REQUEST_VERSION,
        "minimumReleaseIdentitySha256":
        context["minimumReleaseIdentitySha256"],
        "minimumRollbackContinuityCommitmentSha256":
        context["minimumRollbackContinuityCommitmentSha256"],
        "producerEphemeralKeySpkiSha256":
        context["producerEphemeralKeySpkiSha256"],
        "producerInvocationSha256":
        context["producerInvocationSha256"],
        "producerRequestSha256": context["producerRequestSha256"],
        "tlsBindingSha256": context["tlsBindingSha256"],
        "verifierChallengeBase64url":
        context["witnessVerifierChallengeBase64url"],
    }
    write_json_line_fd(
        args.witness_request_fd,
        request,
        maximum=MAX_PRODUCER_REQUEST_BYTES,
        timeout_ms=args.io_timeout_ms,
        label="retained-FD live witness request",
        deadline=deadline,
    )
    response_value, _ = read_json_line_fd(
        args.witness_response_fd,
        maximum=MAX_WITNESS_RESPONSE_BYTES,
        timeout_ms=args.io_timeout_ms,
        label="retained-FD live witness response",
        deadline=deadline,
    )
    return verify_live_witness_response(
        response_value,
        witness_request=request,
        context=context,
        release_identity=release_identity,
        trust=trust,
        witness_store_key=witness_store_key,
        pins=pins,
    )


def artifact(name: str, raw: bytes) -> dict[str, Any]:
    return {
        "contentBase64url": base64url_encode(raw),
        "mediaType": "application/json",
        "name": name,
        "sha256": sha256_bytes(raw),
    }


def sign_producer_binding(
    payload: Mapping[str, Any],
    *,
    seed: bytearray,
    public_key_spki_der: bytes,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    payload_document = dict(payload)
    payload_sha256 = sha256_json(payload_document)
    message = PRODUCER_BINDING_DOMAIN + canonical_json(
        {
            "payload": payload_document,
            "payloadSha256": payload_sha256,
            "signingKeySpkiSha256": public_key_spki_sha256,
        }
    )
    private_key: Ed25519PrivateKey | None = None
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
        signature = private_key.sign(message)
    finally:
        if private_key is not None:
            del private_key
        zeroize(seed)
    require(
        len(signature) == 64,
        "producer ephemeral key returned a non-Ed25519 signature",
    )
    return {
        "apiVersion": SIGNED_PRODUCER_BINDING_VERSION,
        "payload": payload_document,
        "payloadSha256": payload_sha256,
        "signatureAlgorithm": "Ed25519",
        "signatureBase64url": base64url_encode(signature),
        "signingKeySpkiDerBase64url":
        base64url_encode(public_key_spki_der),
        "signingKeySpkiSha256": public_key_spki_sha256,
    }


def build_public_bundle(
    *,
    context: Mapping[str, Any],
    pins: Mapping[str, str],
    release_identity: Mapping[str, Any],
    release_config_raw: bytes,
    stable_statement_raw: bytes,
    trust_roots_raw: bytes,
    live_witness: Mapping[str, Any],
    producer_ephemeral_seed: bytearray,
    producer_ephemeral_public_key_spki_der: bytes,
) -> dict[str, Any]:
    release_identity_sha256 = sha256_json(release_identity)
    stable_statement_sha256 = sha256_bytes(stable_statement_raw)
    artifacts = [
        artifact("nitro-trust-roots", trust_roots_raw),
        artifact("release-config", release_config_raw),
        artifact("stable-release-statement", stable_statement_raw),
    ]
    require(
        [item["name"] for item in artifacts]
        == sorted(item["name"] for item in artifacts),
        "public artifacts are not in canonical order",
    )
    release_graph = {
        "apiVersion": RELEASE_GRAPH_VERSION,
        "releaseConfigSha256": pins["immutableConfigSha256"],
        "releaseIdentity": release_identity,
        "releaseIdentitySha256": release_identity_sha256,
        "stableReleaseStatementSha256": stable_statement_sha256,
        "trustRootBundleSha256": pins["trustRootsSha256"],
    }
    bundle = {
        "artifacts": artifacts,
        "generatedAtUnix": context["issuedAtUnix"],
        "releaseGraph": release_graph,
        "schemaVersions": {
            "endpointBundle": PUBLIC_BUNDLE_VERSION,
            "liveSessionProof": "serverware.liveSessionProof/v1",
            "liveWitnessHead": LIVE_WITNESS_HEAD_VERSION,
            "nonceAuthorityVerifierStateTransition":
            NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION,
            "protectedLiveWitnessState": PROTECTED_WITNESS_VERSION,
            "releaseConfig": RELEASE_CONFIG_VERSION,
            "releaseIdentity": "serverware.releaseIdentity/v1",
            "stableReleaseStatement": STABLE_STATEMENT_VERSION,
            "trustRoots": TRUST_ROOTS_VERSION,
        },
    }
    producer_binding_payload = {
        "apiVersion": PRODUCER_BINDING_VERSION,
        "callerNonceSha256": context["callerNonceSha256"],
        "descriptorSha256": pins["descriptorSha256"],
        "executableSha256": pins["executableSha256"],
        "expiresAtUnix": context["expiresAtUnix"],
        "immutableConfigSha256": pins["immutableConfigSha256"],
        "issuedAtUnix": context["issuedAtUnix"],
        "nonceAuthorityAssuranceEvidenceSha256":
        context["nonceAuthorityAssuranceEvidenceSha256"],
        "nonceAuthorityAssuranceSha256":
        context["nonceAuthorityAssuranceSha256"],
        "nonceAuthorityVerifierChallengeSha256":
        context["nonceAuthorityVerifierChallengeSha256"],
        "nonceAuthorityVerifierStateAuthorizationSha256":
        context[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ],
        "nonceAuthorityVerifierStateCommitReceiptSha256":
        context[
            "nonceAuthorityVerifierStateCommitReceiptSha256"
        ],
        "nonceAuthorityVerifierStateCommitRequestSha256":
        context[
            "nonceAuthorityVerifierStateCommitRequestSha256"
        ],
        "nonceAuthorityVerifierStateCommittedStateReadSha256":
        context[
            "nonceAuthorityVerifierStateCommittedStateReadSha256"
        ],
        "nonceAuthorityVerifierStateCommittedStateSha256":
        context[
            "nonceAuthorityVerifierStateCommittedStateSha256"
        ],
        "nonceAuthorityVerifierStateOperationIdBase64url":
        context[
            "nonceAuthorityVerifierStateOperationIdBase64url"
        ],
        "nonceAuthorityVerifierStatePriorStateReadSha256":
        context[
            "nonceAuthorityVerifierStatePriorStateReadSha256"
        ],
        "nonceAuthorityVerifierStatePriorStateSha256":
        context[
            "nonceAuthorityVerifierStatePriorStateSha256"
        ],
        "nonceAuthorityVerifierStateServiceConfigurationSha256":
        context[
            "nonceAuthorityVerifierStateServiceConfigurationSha256"
        ],
        "nonceAuthorityVerifierStateSigningKeySpkiSha256":
        context[
            "nonceAuthorityVerifierStateSigningKeySpkiSha256"
        ],
        "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256":
        context[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256":
        context[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ],
        "nonceAuthorityVerifierStateRoleSeparationEvidenceSha256":
        context[
            "nonceAuthorityVerifierStateRoleSeparationEvidenceSha256"
        ],
        "nonceAuthorityVerifierStateStoreAttestationKeySpkiSha256":
        context[
            "nonceAuthorityVerifierStateStoreAttestationKeySpkiSha256"
        ],
        "nonceAuthorityVerifierStateStoreCommitProofSha256":
        context[
            "nonceAuthorityVerifierStateStoreCommitProofSha256"
        ],
        "nonceAuthorityVerifierStateStoreIdentitySha256":
        context[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
        "nonceAuthorityVerifierStateStoreConfigurationSha256":
        context[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ],
        "nonceAuthorityVerifierStateStoreMinimumCommitIndex":
        context[
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
        ],
        "nonceAuthorityVerifierStateStoreMinimumGeneration":
        context[
            "nonceAuthorityVerifierStateStoreMinimumGeneration"
        ],
        "nonceAuthorityVerifierStateTransitionSha256":
        context["nonceAuthorityVerifierStateTransitionSha256"],
        "nonceConsumptionSha256": context["nonceConsumptionSha256"],
        "nonceConsumptionReceiptSha256":
        context["nonceConsumptionReceiptSha256"],
        "nonceStoreIdentitySha256": pins["nonceStoreIdentitySha256"],
        "nonceStoreKeySpkiSha256":
        pins["nonceStoreKeySpkiSha256"],
        "producerEphemeralKeySpkiSha256":
        context["producerEphemeralKeySpkiSha256"],
        "producerInvocationSha256":
        context["producerInvocationSha256"],
        "producerRequestSchemaSha256":
        pins["producerRequestSchemaSha256"],
        "producerRequestSha256": context["producerRequestSha256"],
        "requestBodySha256": context["requestBodySha256"],
        "sandboxDescriptorSha256": pins["sandboxDescriptorSha256"],
        "sandboxLauncherSha256": pins["sandboxLauncherSha256"],
        "tlsBindingSha256": context["tlsBindingSha256"],
        "transactionIdBase64url": context["transactionIdBase64url"],
        "trustRootsSha256": pins["trustRootsSha256"],
        "witnessCurrentRequestSha256":
        live_witness["currentRequestSha256"],
        "witnessStoreIdentitySha256":
        pins["witnessStoreIdentitySha256"],
        "witnessStoreKeySpkiSha256":
        pins["witnessStoreKeySpkiSha256"],
    }
    producer_binding = sign_producer_binding(
        producer_binding_payload,
        seed=producer_ephemeral_seed,
        public_key_spki_der=producer_ephemeral_public_key_spki_der,
        public_key_spki_sha256=context[
            "producerEphemeralKeySpkiSha256"
        ],
    )
    return {
        "apiVersion": PUBLIC_BUNDLE_VERSION,
        "bundle": bundle,
        "bundleSha256": sha256_json(bundle),
        "liveWitnessHead": live_witness["document"],
        "nonceAuthorityVerifierStateTransition":
        context["nonceAuthorityVerifierStateTransition"],
        "producerBinding": producer_binding,
        "protectedLiveWitnessState":
        live_witness["protectedDocument"],
    }


def produce_public_bundle(args: argparse.Namespace) -> None:
    operation_deadline = (
        time.monotonic() + args.io_timeout_ms / 1000.0
    )
    validate_distinct_fds(
        {
            "request FD": args.request_fd,
            "response FD": args.response_fd,
            "producer ephemeral seed FD":
            args.producer_ephemeral_seed_fd,
            "stable statement FD": args.stable_statement_fd,
            "nonce request FD": args.nonce_request_fd,
            "nonce response FD": args.nonce_response_fd,
            "witness request FD": args.witness_request_fd,
            "witness response FD": args.witness_response_fd,
            "producer descriptor FD": args.producer_descriptor_fd,
            "producer executable FD": args.producer_executable_fd,
            "immutable config FD": args.immutable_config_fd,
            "producer request schema FD": args.producer_request_schema_fd,
            "sandbox descriptor FD": args.sandbox_descriptor_fd,
            "sandbox launcher FD": args.sandbox_launcher_fd,
            "trust roots FD": args.trust_roots_fd,
        }
    )
    os.close(args.nonce_request_fd)
    os.close(args.nonce_response_fd)
    artifacts = static_artifact_bytes(args)
    trust = load_trust_roots(
        artifacts["trustRootsSha256"],
        independently_expected_sha256=args.expected_trust_roots_sha256,
    )
    stable_statement_raw = read_immutable_fd(
        args.stable_statement_fd,
        maximum=MAX_STABLE_STATEMENT_BYTES,
        label="stable release statement",
    )
    require(
        sha256_bytes(stable_statement_raw)
        == args.expected_stable_statement_sha256,
        "stable release statement differs from its independent digest",
    )
    stable_statement = strict_json_line(
        stable_statement_raw,
        "stable release statement",
        MAX_STABLE_STATEMENT_BYTES,
    )
    verified_release = verify_stable_release(
        stable_statement,
        trust=trust,
    )
    pins = statement_pins(
        verified_release["attestationPins"],
        "verified stable release pins",
    )
    require(
        pins["trustRootsSha256"] == args.expected_trust_roots_sha256
        and verified_release["statementSha256"]
        == args.expected_stable_statement_sha256,
        "stable statement crossed independent release roots",
    )
    verify_static_artifacts(artifacts, pins)
    release_identity = verified_release["releaseIdentity"]
    (
        release_config,
        nonce_store_key,
        witness_store_key,
        verifier_state_key,
        assurance_evidence_key,
        store_attestation_key,
    ) = validate_release_config(
        artifacts["immutableConfigSha256"],
        pins=pins,
        release_identity=release_identity,
        trust_key_ids=trust["keyIds"],
    )
    producer_ephemeral_seed = read_ephemeral_seed_fd(
        args.producer_ephemeral_seed_fd
    )
    try:
        (
            producer_ephemeral_public_key_spki_der,
            producer_ephemeral_key_spki_sha256,
        ) = ephemeral_public_key(producer_ephemeral_seed)
        producer_request_value, producer_request_raw = read_json_line_fd(
            args.request_fd,
            maximum=MAX_PRODUCER_REQUEST_BYTES,
            timeout_ms=args.io_timeout_ms,
            label="public attestation producer request",
            deadline=operation_deadline,
        )
        context = validate_producer_request(
            producer_request_value,
            raw=producer_request_raw,
            stable_pins=pins,
            release_identity_sha256=verified_release[
                "releaseIdentitySha256"
            ],
            producer_ephemeral_public_key_spki_der=(
                producer_ephemeral_public_key_spki_der
            ),
            producer_ephemeral_key_spki_sha256=(
                producer_ephemeral_key_spki_sha256
            ),
            nonce_store_key=nonce_store_key,
            nonce_authority_assurance=release_config[
                "nonceAuthorityAssurance"
            ],
            nonce_authority_assurance_sha256=release_config[
                "nonceAuthorityAssuranceSha256"
            ],
            minimum_rollback_continuity_commitment_sha256=(
                release_config[
                    "minimumRollbackContinuityCommitmentSha256"
                ]
            ),
            release_config=release_config,
            verifier_state_key=verifier_state_key,
            assurance_evidence_key=assurance_evidence_key,
            store_attestation_key=store_attestation_key,
        )
        live_witness = obtain_live_witness(
            args,
            context=context,
            release_identity=release_identity,
            trust=trust,
            witness_store_key=witness_store_key,
            pins=pins,
            deadline=operation_deadline,
        )
        document = build_public_bundle(
            context=context,
            pins=pins,
            release_identity=release_identity,
            release_config_raw=artifacts["immutableConfigSha256"],
            stable_statement_raw=stable_statement_raw,
            trust_roots_raw=artifacts["trustRootsSha256"],
            live_witness=live_witness,
            producer_ephemeral_seed=producer_ephemeral_seed,
            producer_ephemeral_public_key_spki_der=(
                producer_ephemeral_public_key_spki_der
            ),
        )
    finally:
        zeroize(producer_ephemeral_seed)
    write_json_line_fd(
        args.response_fd,
        document,
        maximum=MAX_BUNDLE_BYTES,
        timeout_ms=args.io_timeout_ms,
        label="public attestation bundle v3",
        deadline=operation_deadline,
    )


PUBLIC_NITRO_RESULT_FIELDS = frozenset(
    {
        "actionAuthorization",
        "apiVersion",
        "attestationRequestSha256",
        "buildWatchdogReceiptFileSha256",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "candidateToEifBuildStatementFileSha256",
        "canonicalProfile",
        "completionCoreDigests",
        "completionIdentity",
        "completionIdentitySha256",
        "eifSha384",
        "evidenceBundleFileSha256",
        "expectationsFileSha256",
        "finalCompletionVerified",
        "kmsAuditProofSha256s",
        "nextClientState",
        "nitroAttestationDocumentSha256",
        "okForAction",
        "pcrs",
        "pipeline",
        "productionIdentitySha256",
        "promotedManifestFileSha256",
        "promotionReceiptFileSha256",
        "requestSha256",
        "responseBytesSha256",
        "roleKeyIds",
        "roleRegistrySha256",
        "runtimeKeyCustodyFileSha256",
        "runtimeStateFileSha256",
        "sourceClosureSha256",
        "sourceInputManifestFileSha256",
        "stateCommit",
        "stateTransition",
        "status",
        "tlsExporterSha256",
        "tlsPeerSpkiSha256",
        "tlsSpkiSha256",
        "tlsStackMeasurementSha256",
        "trustRootBundleFileSha256",
        "verificationOk",
        "verifiedAtUnix",
        "witness",
    }
)
PUBLIC_NITRO_RESULT_ROLE_NAMES = frozenset(
    {
        "builderA",
        "builderB",
        "buildWatchdog",
        "clientState",
        "clientStateCheckpoint",
        "currentHeadAuthorization",
        "currentHeadRedemption",
        "keyCustody",
        "kmsAudit",
        "manifestV6EifBuilder",
        "nitroAttestationVerifier",
        "promotion",
        "publicNitroResult",
        "sourceGitInventory",
        "sourceUntrackedApproval",
        "stateCommit",
        "stateStore",
        "storeAssurance",
        "tlsRelease",
        "verifierState",
        "witness",
        "witnessStore",
    }
)


def validate_public_nitro_final_result_contract(
    value: Any,
) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value) == PUBLIC_NITRO_RESULT_FIELDS,
        "public Nitro signer accepts only the exact final result field set",
    )
    try:
        from scripts import verify_nitro_tee as native_verifier
    except ImportError:
        import verify_nitro_tee as native_verifier
    require(
        PUBLIC_NITRO_RESULT_FIELDS
        == native_verifier.PUBLIC_NITRO_RESULT_FIELDS
        and PUBLIC_NITRO_RESULT_ROLE_NAMES
        == native_verifier.PUBLIC_NITRO_RESULT_ROLE_NAMES
        and PUBLIC_NITRO_CANONICAL_INTEGER_MAX
        == native_verifier.PUBLIC_NITRO_CANONICAL_INTEGER_MAX
        and PUBLIC_NITRO_PROVIDER_RE.pattern
        == native_verifier.PUBLIC_NITRO_PROVIDER_RE.pattern
        and PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
        == native_verifier.PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN,
        "production signer and native verifier public Nitro contracts diverged",
    )
    try:
        validated = native_verifier.validate_public_nitro_final_result_contract(
            value
        )
    except (
        native_verifier.VerificationError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ContractError(
            "public Nitro signer rejected the native final result contract"
        ) from exc
    require(
        validated == value,
        "native public Nitro verifier changed the final result",
    )
    return value


def validate_public_nitro_signing_request(
    value: Any,
) -> dict[str, Any]:
    request = exact_object(
        value,
        {
            "apiVersion",
            "envelopeCore",
            "operation",
            "operationIdSha256",
            "recoveryKeySha256",
            "requestSha256",
            "retrySemantics",
            "signingMessageSha256",
            "transportPins",
        },
        "public Nitro result signing request",
    )
    envelope = exact_object(
        request["envelopeCore"],
        {
            "apiVersion",
            "provider",
            "result",
            "resultSha256",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "public Nitro result signing envelope core",
    )
    transport_pins = exact_object(
        request["transportPins"],
        {"signerServerTlsSpkiSha256"},
        "public Nitro signer transport pins",
    )
    result = envelope["result"]
    result = validate_public_nitro_final_result_contract(result)
    require_public_nitro_provider(
        envelope["provider"],
        "public Nitro result signer provider",
    )
    require(
        request["apiVersion"]
        == PUBLIC_NITRO_RESULT_SIGNING_REQUEST_VERSION
        and request["operation"]
        == "sign-public-nitro-live-verification-result"
        and request["retrySemantics"]
        == "same-recovery-key-requires-byte-identical-request-and-response"
        and envelope["apiVersion"]
        == PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_VERSION
        and envelope["resultSha256"] == sha256_json(result)
        and envelope["signingKeyId"]
        == envelope["signingKeySpkiSha256"]
        == result["roleKeyIds"].get("publicNitroResult"),
        "public Nitro signing request crossed its final result or signer role",
    )
    require_sha256(
        transport_pins["signerServerTlsSpkiSha256"],
        "public Nitro signer server TLS SPKI",
    )
    signing_message = (
        PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
        + canonical_json(envelope)
    )
    request_core = {
        "apiVersion": request["apiVersion"],
        "envelopeCore": envelope,
        "operation": request["operation"],
        "retrySemantics": request["retrySemantics"],
        "signingMessageSha256": request["signingMessageSha256"],
        "transportPins": transport_pins,
    }
    operation_id = sha256_bytes(
        PUBLIC_NITRO_RESULT_SIGNING_OPERATION_DOMAIN
        + canonical_json(request_core)
    )
    require(
        request["signingMessageSha256"]
        == sha256_bytes(signing_message)
        and request["operationIdSha256"] == operation_id
        and request["recoveryKeySha256"]
        == sha256_bytes(
            PUBLIC_NITRO_RESULT_SIGNING_RECOVERY_DOMAIN
            + operation_id.encode("ascii")
        )
        and request["requestSha256"]
        == sha256_json(
            {
                **request_core,
                "operationIdSha256": operation_id,
                "recoveryKeySha256": request[
                    "recoveryKeySha256"
                ],
            }
        ),
        "public Nitro signing request deterministic operation or recovery identity is invalid",
    )
    return request


def load_public_nitro_signing_key(
    raw: bytes,
) -> tuple[Ed25519PublicKey, str]:
    try:
        if raw.startswith(b"-----BEGIN PUBLIC KEY-----"):
            key = serialization.load_pem_public_key(raw)
        else:
            key = serialization.load_der_public_key(raw)
    except ValueError as exc:
        raise ContractError(
            "public Nitro result signing key is invalid"
        ) from exc
    require(
        isinstance(key, Ed25519PublicKey),
        "public Nitro result signing key is not Ed25519",
    )
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, sha256_bytes(der)


def validate_public_nitro_signer_response(
    value: Any,
    *,
    request: Mapping[str, Any],
    signing_key: Ed25519PublicKey,
) -> dict[str, Any]:
    response = exact_object(
        value,
        {
            "apiVersion",
            "envelope",
            "operationIdSha256",
            "recoveryKeySha256",
            "requestSha256",
            "status",
            "transportPins",
        },
        "public Nitro result signing response",
    )
    envelope = exact_object(
        response["envelope"],
        {
            "apiVersion",
            "provider",
            "result",
            "resultSha256",
            "signature",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "signed public Nitro live result envelope",
    )
    signature_value = envelope["signature"]
    require(
        response["apiVersion"]
        == PUBLIC_NITRO_RESULT_SIGNING_RESPONSE_VERSION
        and response["status"] == "signed"
        and response["operationIdSha256"]
        == request["operationIdSha256"]
        and response["recoveryKeySha256"]
        == request["recoveryKeySha256"]
        and response["requestSha256"] == request["requestSha256"]
        and response["transportPins"] == request["transportPins"]
        and {
            key: item
            for key, item in envelope.items()
            if key != "signature"
        }
        == request["envelopeCore"]
        and isinstance(signature_value, str)
        and signature_value.startswith("ed25519:"),
        "public Nitro signer response crossed the exact request or envelope core",
    )
    signature = base64url_decode(
        signature_value[len("ed25519:"):],
        "public Nitro result signature",
        exact_length=64,
        maximum=64,
    )
    try:
        signing_key.verify(
            signature,
            PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
            + canonical_json(request["envelopeCore"]),
        )
    except InvalidSignature as exc:
        raise ContractError(
            "public Nitro result signer returned an invalid signature"
        ) from exc
    return response


def relay_public_nitro_result_signing(
    args: argparse.Namespace,
) -> None:
    operation_deadline = (
        time.monotonic() + args.io_timeout_ms / 1000.0
    )
    expected_signer_provider = require_public_nitro_provider(
        args.expected_signer_provider,
        "expected public Nitro result signer provider",
    )
    validate_distinct_fds(
        {
            "request FD": args.request_fd,
            "response FD": args.response_fd,
            "remote signer request FD": args.signer_request_fd,
            "remote signer response FD": args.signer_response_fd,
            "signing public key FD": args.signing_public_key_fd,
        }
    )
    relay_pipe_endpoints = {
        "request FD": validate_retained_pipe_fd(
            args.request_fd,
            label="public Nitro result signing request",
            writable=False,
        ),
        "response FD": validate_retained_pipe_fd(
            args.response_fd,
            label="public Nitro result signing response",
            writable=True,
        ),
        "remote signer request FD": validate_retained_pipe_fd(
            args.signer_request_fd,
            label="remote public Nitro signer request",
            writable=True,
        ),
        "remote signer response FD": validate_retained_pipe_fd(
            args.signer_response_fd,
            label="remote public Nitro signer response",
            writable=False,
        ),
    }
    endpoint_owners: dict[tuple[int, int], str] = {}
    for label, endpoint in relay_pipe_endpoints.items():
        identity = endpoint[:2]
        previous = endpoint_owners.get(identity)
        require(
            previous is None,
            f"{label} aliases the underlying pipe endpoint for {previous}",
        )
        endpoint_owners[identity] = label
    signing_key_raw = read_immutable_fd(
        args.signing_public_key_fd,
        maximum=8192,
        label="public Nitro result signing public key",
    )
    signing_key, signing_key_id = load_public_nitro_signing_key(
        signing_key_raw
    )
    require(
        signing_key_id == args.expected_signing_key_id
        == args.expected_signing_key_spki_sha256,
        "public Nitro result signing public key differs from caller pins",
    )
    operation_request, _ = read_json_line_fd(
        args.request_fd,
        maximum=MAX_PUBLIC_NITRO_SIGNING_BYTES,
        timeout_ms=args.io_timeout_ms,
        label="public Nitro result signing request",
        deadline=operation_deadline,
    )
    operation_version = (
        operation_request.get("apiVersion")
        if isinstance(operation_request, Mapping)
        else None
    )
    if operation_version == PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION:
        recovery_request = (
            validate_public_nitro_result_recovery_request(
                operation_request
            )
        )
        signing_request = recovery_request["signingRequest"]
    elif operation_version == PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION:
        status_request = validate_public_nitro_result_status_request(
            operation_request
        )
        signing_request = status_request["signingRequest"]
    else:
        signing_request = validate_public_nitro_signing_request(
            operation_request
        )
    require(
        signing_request["envelopeCore"]["provider"]
        == expected_signer_provider
        and signing_request["envelopeCore"]["signingKeyId"]
        == signing_key_id
        and signing_request["envelopeCore"]["signingKeySpkiSha256"]
        == signing_key_id,
        "public Nitro signing request differs from caller-pinned provider/key/SPKI",
    )
    require(
        signing_request["transportPins"][
            "signerServerTlsSpkiSha256"
        ]
        == args.expected_signer_server_tls_spki_sha256,
        "public Nitro signing request differs from the caller-pinned remote signer TLS SPKI",
    )
    write_json_line_fd(
        args.signer_request_fd,
        operation_request,
        maximum=MAX_PUBLIC_NITRO_SIGNING_BYTES,
        timeout_ms=args.io_timeout_ms,
        label="remote public Nitro signer request",
        deadline=operation_deadline,
    )
    response, response_raw = read_json_line_fd(
        args.signer_response_fd,
        maximum=MAX_PUBLIC_NITRO_SIGNING_BYTES,
        timeout_ms=args.io_timeout_ms,
        label="remote public Nitro signer response",
        deadline=operation_deadline,
    )
    validated = validate_public_nitro_signer_response(
        response,
        request=signing_request,
        signing_key=signing_key,
    )
    relayed_raw = write_json_line_fd(
        args.response_fd,
        validated,
        maximum=MAX_PUBLIC_NITRO_SIGNING_BYTES,
        timeout_ms=args.io_timeout_ms,
        label="validated public Nitro signer response",
        deadline=operation_deadline,
    )
    require(
        relayed_raw == response_raw,
        "public Nitro signer relay changed the terminal response bytes",
    )


def add_common_static_fd_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--producer-descriptor-fd", required=True, type=int)
    parser.add_argument("--producer-executable-fd", required=True, type=int)
    parser.add_argument("--immutable-config-fd", required=True, type=int)
    parser.add_argument("--producer-request-schema-fd", required=True, type=int)
    parser.add_argument("--sandbox-descriptor-fd", required=True, type=int)
    parser.add_argument("--sandbox-launcher-fd", required=True, type=int)
    parser.add_argument("--trust-roots-fd", required=True, type=int)
    parser.add_argument(
        "--expected-trust-roots-sha256",
        required=True,
        type=require_cli_sha256,
    )
    parser.add_argument(
        "--io-timeout-ms",
        type=bounded_timeout,
        default=DEFAULT_IO_TIMEOUT_MS,
    )


def require_cli_sha256(value: str) -> str:
    if SHA256_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected canonical sha256:<hex>")
    return value


def bounded_timeout(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout is not an integer") from exc
    if not 100 <= parsed <= 30_000:
        raise argparse.ArgumentTypeError("timeout is outside 100..30000")
    return parsed


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description=(
            "Issue a production stable release statement or produce an exact "
            "public attestation bundle using retained file descriptors."
        )
    )
    commands = root.add_subparsers(dest="command", required=True)

    issuer = commands.add_parser("issue-stable")
    issuer.add_argument("--request-fd", type=int, default=0)
    issuer.add_argument("--response-fd", type=int, default=1)
    issuer.add_argument(
        "--signer-authorization-nonce-fd",
        required=True,
        type=int,
        help=(
            "sealed read-only FD containing the exact 32-byte one-use "
            "release-signing authorization nonce"
        ),
    )
    issuer.add_argument("--signer-request-fd", required=True, type=int)
    issuer.add_argument("--signer-response-fd", required=True, type=int)
    issuer.add_argument(
        "--expected-issuer-request-sha256",
        required=True,
        type=require_cli_sha256,
    )
    issuer.add_argument(
        "--fixture-non-production",
        action="store_true",
        help=(
            "accept only an explicitly non-production fixture issuer request; "
            "the resulting statement remains trusted solely by its fixture roots"
        ),
    )
    add_common_static_fd_arguments(issuer)

    producer = commands.add_parser("produce-bundle")
    producer.add_argument("--request-fd", type=int, default=0)
    producer.add_argument("--response-fd", type=int, default=1)
    producer.add_argument(
        "--producer-ephemeral-seed-fd",
        required=True,
        type=int,
        help=(
            "sealed read-only FD for descriptor role "
            "producerEphemeralSeed; exactly 32 bytes"
        ),
    )
    producer.add_argument("--stable-statement-fd", required=True, type=int)
    producer.add_argument(
        "--nonce-request-fd",
        required=True,
        type=int,
        help=(
            "retained nonce-service request role; closed without use because "
            "the final producer request already carries the signed receipt"
        ),
    )
    producer.add_argument(
        "--nonce-response-fd",
        required=True,
        type=int,
        help=(
            "retained nonce-service response role; closed without use because "
            "nonce consumption precedes one-shot producer launch"
        ),
    )
    producer.add_argument("--witness-request-fd", required=True, type=int)
    producer.add_argument("--witness-response-fd", required=True, type=int)
    producer.add_argument(
        "--expected-stable-statement-sha256",
        required=True,
        type=require_cli_sha256,
    )
    add_common_static_fd_arguments(producer)

    final_signer = commands.add_parser(
        "relay-public-nitro-result-signing"
    )
    final_signer.add_argument("--request-fd", type=int, default=0)
    final_signer.add_argument("--response-fd", type=int, default=1)
    final_signer.add_argument("--signer-request-fd", required=True, type=int)
    final_signer.add_argument("--signer-response-fd", required=True, type=int)
    final_signer.add_argument(
        "--signing-public-key-fd",
        required=True,
        type=int,
    )
    final_signer.add_argument(
        "--expected-signer-provider",
        required=True,
    )
    final_signer.add_argument(
        "--expected-signing-key-id",
        required=True,
        type=require_cli_sha256,
    )
    final_signer.add_argument(
        "--expected-signing-key-spki-sha256",
        required=True,
        type=require_cli_sha256,
    )
    final_signer.add_argument(
        "--expected-signer-server-tls-spki-sha256",
        required=True,
        type=require_cli_sha256,
    )
    final_signer.add_argument(
        "--io-timeout-ms",
        type=bounded_timeout,
        default=DEFAULT_IO_TIMEOUT_MS,
    )
    return root


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "issue-stable":
            issue_stable_release(arguments)
        elif arguments.command == "produce-bundle":
            produce_public_bundle(arguments)
        elif arguments.command == "relay-public-nitro-result-signing":
            relay_public_nitro_result_signing(arguments)
        else:
            reject("unsupported production attestation command")
        return 0
    except ContractError:
        os.write(2, b"production attestation contract rejected input\n")
        return 2
    except (OSError, BrokenPipeError):
        os.write(2, b"production attestation retained-FD boundary failed\n")
        return 3
    except Exception:
        os.write(2, b"production attestation failed closed\n")
        return 4


def _public_nitro_recovery_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


GLOBAL_ATTESTATION_KEY_ROLES = (
    "release",
    "releaseCa",
    "responseKey",
    "tlsScope",
    "witness",
    "witnessStore",
    "nonceReceipt",
    "nonceAuthorityAssuranceEvidenceIssuer",
    "verifierState",
    "verifierStateSigner",
    "verifierStateStore",
    "verifierStateSignerClientTls",
    "verifierStateSignerServerTls",
    "verifierStateStoreClientTls",
    "verifierStateStoreServerTls",
    "storeAssuranceEvidenceIssuer",
    "storeAttestation",
    "producer",
    "producerService",
    "publicAttestationClientTls",
    "roleSeparationEvidenceIssuer",
    "remoteSignerServerTls",
    "remoteStoreServerTls",
)


def validate_global_attestation_key_role_separation(
    role_key_ids: Mapping[str, Any],
    *,
    expected_roles: Any = GLOBAL_ATTESTATION_KEY_ROLES,
) -> dict[str, str]:
    expected = tuple(expected_roles)
    if set(role_key_ids) != set(expected):
        missing = sorted(set(expected) - set(role_key_ids))
        extra = sorted(set(role_key_ids) - set(expected))
        raise ContractError(
            "global attestation key roles are not exact: "
            f"missing={missing!r} extra={extra!r}"
        )
    normalized: dict[str, str] = {}
    for role in expected:
        value = role_key_ids[role]
        if not isinstance(value, str) or not value:
            raise ContractError(
                f"global attestation key role {role} is invalid"
            )
        normalized[role] = value
    collisions: dict[str, list[str]] = {}
    for role, value in normalized.items():
        collisions.setdefault(value, []).append(role)
    duplicate_roles = [
        sorted(roles)
        for roles in collisions.values()
        if len(roles) > 1
    ]
    if duplicate_roles:
        raise ContractError(
            "global attestation key roles must be pairwise distinct: "
            f"{duplicate_roles!r}"
        )
    return normalized


def _validate_public_nitro_result_terminal_request(
    value: Any,
    *,
    api_version: str,
    operation: str,
    digest_field: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(
            f"public Nitro signer {label} request must be an object"
        )
    request = dict(value)
    exact_fields = {
        "apiVersion",
        "operation",
        "operationIdSha256",
        "recoveryKeySha256",
        "requestSha256",
        "signingRequest",
        "transportPins",
        digest_field,
    }
    if set(request) != exact_fields:
        raise ContractError(
            f"public Nitro signer {label} request fields are not exact"
        )
    if (
        request["apiVersion"] != api_version
        or request["operation"] != operation
    ):
        raise ContractError(
            f"public Nitro signer {label} request contract is invalid"
        )
    signing_request = request["signingRequest"]
    if not isinstance(signing_request, Mapping):
        raise ContractError(
            f"public Nitro signer {label} signingRequest must be an object"
        )
    signing_request = validate_public_nitro_signing_request(
        signing_request
    )
    for field in (
        "operationIdSha256",
        "recoveryKeySha256",
        "requestSha256",
        "transportPins",
    ):
        if signing_request.get(field) != request[field]:
            raise ContractError(
                f"public Nitro signer {label} identity conflicts with "
                f"signingRequest.{field}"
            )
    core = {
        key: request[key]
        for key in exact_fields
        if key != digest_field
    }
    if request[digest_field] != _public_nitro_recovery_sha256(core):
        raise ContractError(
            f"public Nitro signer {label} request digest is invalid"
        )
    return request


def validate_public_nitro_result_recovery_request(
    value: Any,
) -> dict[str, Any]:
    return _validate_public_nitro_result_terminal_request(
        value,
        api_version=PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION,
        operation="recover-public-nitro-live-verification-result",
        digest_field="recoveryRequestSha256",
        label="recovery",
    )


def validate_public_nitro_result_status_request(
    value: Any,
) -> dict[str, Any]:
    return _validate_public_nitro_result_terminal_request(
        value,
        api_version=PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION,
        operation="status-public-nitro-live-verification-result",
        digest_field="statusRequestSha256",
        label="status",
    )


def relay_public_nitro_result_signer_operation(
    operation_request: Mapping[str, Any],
    *,
    invoke_signer: Any,
    signing_key: Ed25519PublicKey,
) -> bytes:
    request = dict(operation_request)
    if request.get("apiVersion") == (
        PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION
    ):
        recovery = validate_public_nitro_result_recovery_request(request)
        signing_request = recovery["signingRequest"]
    elif request.get("apiVersion") == (
        PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION
    ):
        status = validate_public_nitro_result_status_request(request)
        signing_request = status["signingRequest"]
    else:
        signing_request = validate_public_nitro_signing_request(request)
    raw_response = invoke_signer(request)
    if not isinstance(raw_response, (bytes, bytearray)):
        raise ContractError(
            "public Nitro signer relay must return the exact response bytes"
        )
    try:
        response = json.loads(bytes(raw_response).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(
            "public Nitro signer relay returned invalid JSON"
        ) from exc
    validated = validate_public_nitro_signer_response(
        response,
        request=signing_request,
        signing_key=signing_key,
    )
    canonical_response = canonical_json(validated) + b"\n"
    require(
        bytes(raw_response) == canonical_response,
        "public Nitro signer relay changed the terminal response bytes",
    )
    return canonical_response


if __name__ == "__main__":
    raise SystemExit(main())
