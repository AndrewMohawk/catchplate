from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import resource
import socket
import stat
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from serverware import authority_launch_guard

_launch_role = {
    "policy-authority-runtime": "runtime",
    "policy-authority-verifier": "verifier",
    "policy-authority-planner": "planner",
    "policy-authority-planner-writer": "planner-writer",
    "policy-authority-issuer": "issuer",
    "policy-authority-executor": "executor",
}.get(os.environ.get("SERVERWARE_PROCESS_MODE", "").strip())
if (
    _launch_role is None
    and os.environ.get("SERVERWARE_PROCESS_MODE", "").strip()
    != "serverware-control-plane"
):
    raise RuntimeError("authority service process mode is not closed")
if _launch_role is not None:
    authority_launch_guard.require_active(_launch_role)

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from serverware import authority_contract
from serverware import authority_planner
from serverware import authority_transition_registry
from serverware import authority_transport
from serverware import authority_webauthn_trust
from serverware.authority_store.verifier_read_sql import (
    verifier_read_privilege_check,
)

SOURCE_REVISION = (
    authority_contract.SOURCE_REVISION
)
CONFIG_SCHEMA = "serverware.policyAuthorityServiceConfiguration/v2"
SIGNED_CONFIG_SCHEMA = (
    "serverware.signedPolicyAuthorityServiceConfiguration/v2"
)
ATTESTATION_SCHEMA = (
    "serverware.policyAuthorityCredentialReleaseAttestation/v2"
)
RUNTIME_REQUEST_SCHEMA = authority_contract.REQUEST_SCHEMA
RUNTIME_RESPONSE_SCHEMA = authority_contract.RESULT_SCHEMA
INTERNAL_ENVELOPE_SCHEMA = authority_contract.INTERNAL_ENVELOPE_SCHEMA
RUNTIME_TRUST_SCHEMA = "serverware.policyAuthorityRuntimeTrust/v1"
SIGNED_RUNTIME_TRUST_SCHEMA = (
    "serverware.signedPolicyAuthorityRuntimeTrust/v1"
)
MAX_MESSAGE_BYTES = authority_contract.MAX_RESULT_BYTES
MAX_CONFIG_BYTES = authority_contract.MAX_REQUEST_BYTES
MAX_RUNTIME_TRUST_BYTES = 8 * 1024 * 1024
MAX_CLOSURE_FILES = 4096
MAX_MULTIPROOF_NODES = authority_contract.MAX_PROOF_NODES
TREE_DEPTH = authority_contract.TREE_DEPTH
TREE_RADIX = authority_contract.TREE_RADIX
PROCESS_MODES = {
    "verifier": "policy-authority-verifier",
    "planner": "policy-authority-planner",
    "planner-writer": "policy-authority-planner-writer",
    "issuer": "policy-authority-issuer",
    "executor": "policy-authority-executor",
}
RUNTIME_RELAY_PROCESS_MODE = "policy-authority-runtime"
PRIVILEGED_DSN_ENVIRONMENTS = {
    "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD",
    "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD",
    "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD",
    "SERVERWARE_POLICY_AUTHORITY_CAPABILITY_ISSUER_POSTGRES_DSN_FD",
    "SERVERWARE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD",
}
VERIFIER_SIGNING_KEY_ENVIRONMENTS = {
    "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SIGNING_KEY_FD",
    "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SIGNING_KEY_PATH",
}
RELEASE_CONSUMER_KEY_ENVIRONMENTS = {
    "SERVERWARE_POLICY_AUTHORITY_RELEASE_CONSUMER_SIGNING_KEY_FD",
    "SERVERWARE_POLICY_AUTHORITY_RELEASE_CONSUMER_SIGNING_KEY_PATH",
}
PLANNER_SIGNING_KEY_ENVIRONMENTS = {
    "SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY_FD",
    "SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY_PATH",
}
WITNESS_REQUEST_SCHEMA_V2 = (
    "serverware.policyAuthorityReplayWitnessRequest/v2"
)
WITNESS_RECEIPT_SCHEMA_V2 = (
    "serverware.policyAuthorityReplayWitnessReceipt/v2"
)
TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA = (
    "serverware.trustedHostLocalAuthorityAttestation/v1"
)
TRUSTED_HOST_LOCAL_CONSUMPTION_SCHEMA = (
    "serverware.trustedHostLocalAuthorityAttestationConsumption/v1"
)
REQUIRED_DISTRIBUTIONS = frozenset({"cbor2", "cryptography", "psycopg"})


class AuthorityServiceError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _b64url_decode(value: object, *, size: int | None = None) -> bytes:
    if not isinstance(value, str) or not value:
        raise AuthorityServiceError("base64url value is missing")
    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * (-len(value) % 4)
        )
    except (ValueError, TypeError) as exc:
        raise AuthorityServiceError("base64url value is invalid") from exc
    if size is not None and len(decoded) != size:
        raise AuthorityServiceError("base64url value has the wrong size")
    return decoded


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _domain_digest(domain: str, *frames: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\0")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def _witness_envelope_id(request: Mapping[str, Any]) -> str:
    material = {
        "phase": request.get("phase"),
        "operation": request.get("operation"),
        "requestDigest": request.get("requestDigest"),
        "capabilityId": request.get("capabilityId"),
        "resultDigest": request.get("resultDigest"),
        "predecessorReceiptDigest":
            request.get("predecessorReceiptDigest"),
        "generationSequence": request.get("generationSequence"),
        "generationDigest": request.get("generationDigest"),
    }
    return _domain_digest(
        "serverware.policyAuthorityReplayWitnessEnvelope/v2",
        _canonical(material),
    )


def _framed_digest(domain: str, *frames: bytes) -> str:
    digest = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    digest.update(len(encoded_domain).to_bytes(8, "big"))
    digest.update(encoded_domain)
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def _require_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise AuthorityServiceError(f"{label} is not a canonical digest")
    return value


def _read_bounded_descriptor(
    environment_name: str,
    *,
    maximum: int,
    require_root_owned: bool,
    require_descriptor: bool = False,
) -> bytes:
    descriptor_text = os.environ.get(environment_name + "_FD", "").strip()
    path_text = os.environ.get(environment_name + "_PATH", "").strip()
    if bool(descriptor_text) == bool(path_text):
        raise AuthorityServiceError(
            f"exactly one of {environment_name}_FD or "
            f"{environment_name}_PATH is required"
        )
    if require_descriptor and not descriptor_text:
        raise AuthorityServiceError(
            f"{environment_name} must be delivered by retained descriptor"
        )
    if descriptor_text:
        try:
            descriptor = int(descriptor_text)
        except ValueError as exc:
            raise AuthorityServiceError(
                f"{environment_name}_FD is invalid"
            ) from exc
        metadata = os.fstat(descriptor)
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
            value = handle.read(maximum + 1)
    else:
        path = Path(path_text)
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise AuthorityServiceError(
                f"{environment_name}_PATH is not a regular file"
            )
        with path.open("rb") as handle:
            value = handle.read(maximum + 1)
    if len(value) > maximum:
        raise AuthorityServiceError(f"{environment_name} exceeds its bound")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise AuthorityServiceError(f"{environment_name} is mutable")
    if require_root_owned and metadata.st_uid != 0:
        raise AuthorityServiceError(f"{environment_name} is not root owned")
    return value


def _load_ed25519_public_key(value: bytes) -> Ed25519PublicKey:
    try:
        if len(value) == 32:
            return Ed25519PublicKey.from_public_bytes(value)
        key = serialization.load_pem_public_key(value)
    except (ValueError, TypeError) as exc:
        raise AuthorityServiceError("Ed25519 public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AuthorityServiceError("public key is not Ed25519")
    return key


def _read_dsn_descriptor(environment_name: str) -> str:
    value = _read_bounded_descriptor(
        environment_name,
        maximum=64 * 1024,
        require_root_owned=False,
        require_descriptor=True,
    )
    try:
        dsn = value.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise AuthorityServiceError(
            "authority database DSN is not UTF-8"
        ) from exc
    if (
        not dsn
        or "\x00" in dsn
        or "\n" in dsn
        or "\r" in dsn
    ):
        raise AuthorityServiceError(
            "authority database DSN descriptor is invalid"
        )
    return dsn


def _close_inherited_descriptors(
    retained: frozenset[int],
) -> None:
    for descriptor in _open_inherited_descriptors() - set(retained):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_inherited_descriptors() -> set[int]:
    directory = (
        Path("/proc/self/fd")
        if Path("/proc/self/fd").is_dir()
        else Path("/dev/fd")
    )
    descriptors: set[int] = set()
    for name in os.listdir(directory):
        try:
            descriptor = int(name)
        except ValueError:
            continue
        if descriptor < 3:
            continue
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        descriptors.add(descriptor)
    return descriptors


def _load_ed25519_private_key(value: bytes) -> Ed25519PrivateKey:
    try:
        if len(value) == 32:
            return Ed25519PrivateKey.from_private_bytes(value)
        key = serialization.load_pem_private_key(value, password=None)
    except (ValueError, TypeError) as exc:
        raise AuthorityServiceError("Ed25519 private key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AuthorityServiceError("private key is not Ed25519")
    return key


def _public_spki_digest(key: Ed25519PublicKey) -> str:
    return _sha256(
        key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _verify_public_attestation_evidence(
    *,
    evidence: Mapping[str, Any],
    policy: Mapping[str, Any],
    expected_receipt_digest: str,
    expected_configuration_digest: str,
    expected_response_spki_digest: str,
) -> dict[str, Any]:
    if evidence.get("schema") == TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA:
        policy_fields = {
            "schema",
            "rootPublicKeyBase64Url",
            "verifierSigningPublicKeyBase64Url",
            "maximumReceiptAgeNs",
            "trustMode",
            "coLocated",
            "hardwareBacked",
            "nativeStageZero",
            "hsmBackedKeys",
            "teeVerified",
            "externalWitnessVerified",
        }
        payload = evidence.get("payload")
        required_payload = {
            "schema",
            "role",
            "processMode",
            "configurationDigest",
            "sourceRevision",
            "launchManifestDigest",
            "runtimeClosureDigest",
            "operationManifestDigest",
            "generationDigest",
            "stageZeroRequestDigest",
            "artifactPackageDigest",
            "measurementDigest",
            "responseSigningSpkiDigest",
            "trustMode",
            "coLocated",
            "hardwareBacked",
            "nativeStageZero",
            "hsmBackedKeys",
            "teeVerified",
            "externalWitnessVerified",
            "issuedAtEpochNs",
            "expiresAtEpochNs",
        }
        now_epoch_ns = time.time_ns()
        local_claims = {
            "trustMode": "trusted-host-local",
            "coLocated": True,
            "hardwareBacked": False,
            "nativeStageZero": False,
            "hsmBackedKeys": False,
            "teeVerified": False,
            "externalWitnessVerified": False,
        }
        if (
            set(policy) != policy_fields
            or policy.get("schema")
                != (
                    "serverware."
                    "trustedHostLocalPublicAttestationPolicy/v1"
                )
            or {
                field: policy.get(field) for field in local_claims
            } != local_claims
            or not isinstance(policy.get("maximumReceiptAgeNs"), int)
            or policy["maximumReceiptAgeNs"] <= 0
            or set(evidence) != {"schema", "payload", "signature"}
            or not isinstance(payload, Mapping)
            or set(payload) != required_payload
            or payload.get("schema")
                != TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA
            or payload.get("role") != "verifier"
            or payload.get("processMode") != PROCESS_MODES["verifier"]
            or payload.get("configurationDigest")
                != expected_configuration_digest
            or payload.get("sourceRevision") != SOURCE_REVISION
            or payload.get("operationManifestDigest")
                != authority_contract.OPERATION_MANIFEST_DIGEST
            or payload.get("responseSigningSpkiDigest")
                != expected_response_spki_digest
            or {
                field: payload.get(field) for field in local_claims
            } != local_claims
            or not isinstance(payload.get("issuedAtEpochNs"), int)
            or not isinstance(payload.get("expiresAtEpochNs"), int)
            or payload["issuedAtEpochNs"] > now_epoch_ns
            or payload["expiresAtEpochNs"] <= now_epoch_ns
            or payload["expiresAtEpochNs"]
                - payload["issuedAtEpochNs"]
                > policy["maximumReceiptAgeNs"]
            or _domain_digest(
                TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA,
                _canonical(dict(evidence)),
            )
                != expected_receipt_digest
        ):
            raise AuthorityServiceError(
                "trusted-host-local public attestation is not exact"
            )
        root_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                policy["rootPublicKeyBase64Url"],
                size=32,
            )
        )
        try:
            root_key.verify(
                _b64url_decode(evidence["signature"], size=64),
                _domain_digest(
                    TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA,
                    _canonical(dict(payload)),
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "trusted-host-local public attestation signature is invalid"
            ) from exc
        return dict(evidence)

    raise AuthorityServiceError(
        "TEE and external-witness public attestation are unavailable "
        "prerequisites"
    )

    policy_fields = {
        "schema",
        "brokerPublicKeyBase64Url",
        "providerVerifierPublicKeyBase64Url",
        "replayWitnessSigningPublicKeyBase64Url",
        "brokerVerificationPolicyDigest",
        "allowedMeasurements",
        "allowedTeeTypes",
        "maximumReceiptAgeNs",
        "teeTrustAnchorDigest",
    }
    if (
        set(policy) != policy_fields
        or policy.get("schema")
            != "serverware.policyAuthorityPublicAttestationPolicy/v1"
        or not isinstance(policy.get("allowedMeasurements"), list)
        or not policy["allowedMeasurements"]
        or not isinstance(policy.get("allowedTeeTypes"), list)
        or not policy["allowedTeeTypes"]
        or not isinstance(policy.get("maximumReceiptAgeNs"), int)
        or policy["maximumReceiptAgeNs"] <= 0
    ):
        raise AuthorityServiceError(
            "public attestation verification policy is not closed"
        )
    if (
        set(evidence)
        != {
            "schema",
            "payload",
            "attestationDocumentBase64Url",
            "providerVerification",
            "releaseWitnessReceipt",
            "signature",
        }
        or evidence.get("schema") != ATTESTATION_SCHEMA
        or not isinstance(evidence.get("payload"), dict)
        or not isinstance(evidence.get("providerVerification"), dict)
        or not isinstance(evidence.get("releaseWitnessReceipt"), dict)
        or _domain_digest(
            "serverware.policyAuthorityCredentialReleaseReceipt/v1",
            _canonical(dict(evidence)),
        ) != expected_receipt_digest
    ):
        raise AuthorityServiceError(
            "public attestation evidence is not closed"
        )
    payload = dict(evidence["payload"])
    provider = dict(evidence["providerVerification"])
    witness = dict(evidence["releaseWitnessReceipt"])
    document = _b64url_decode(
        evidence["attestationDocumentBase64Url"]
    )
    if len(document) > 4 * 1024 * 1024:
        raise AuthorityServiceError(
            "public attestation document exceeds 4 MiB"
        )
    document_digest = _sha256(document)
    provider_digest = _domain_digest(
        "serverware.teeAttestationVerification/v1",
        _canonical(provider),
    )
    witness_digest = _domain_digest(
        authority_contract.WITNESS_SCHEMA,
        _canonical(witness),
    )
    broker_statement = {
        "payload": payload,
        "attestationDocumentDigest": document_digest,
        "providerVerificationDigest": provider_digest,
        "releaseWitnessReceiptDigest": witness_digest,
    }
    broker_key = Ed25519PublicKey.from_public_bytes(
        _b64url_decode(
            policy["brokerPublicKeyBase64Url"], size=32
        )
    )
    provider_unsigned = dict(provider)
    provider_signature = provider_unsigned.pop("signature", None)
    provider_key = Ed25519PublicKey.from_public_bytes(
        _b64url_decode(
            policy["providerVerifierPublicKeyBase64Url"], size=32
        )
    )
    witness_unsigned = dict(witness)
    witness_signature = witness_unsigned.pop("signature", None)
    witness_key = Ed25519PublicKey.from_public_bytes(
        _b64url_decode(
            policy["replayWitnessSigningPublicKeyBase64Url"],
            size=32,
        )
    )
    try:
        broker_key.verify(
            _b64url_decode(evidence["signature"], size=64),
            _domain_digest(
                ATTESTATION_SCHEMA,
                _canonical(broker_statement),
            ).encode("ascii"),
        )
        provider_key.verify(
            _b64url_decode(provider_signature, size=64),
            _domain_digest(
                "serverware.teeAttestationVerification/v1",
                _canonical(provider_unsigned),
            ).encode("ascii"),
        )
        witness_key.verify(
            _b64url_decode(witness_signature, size=64),
            _domain_digest(
                authority_contract.WITNESS_SCHEMA,
                _canonical(witness_unsigned),
            ).encode("ascii"),
        )
    except InvalidSignature as exc:
        raise AuthorityServiceError(
            "public attestation signature chain is invalid"
        ) from exc
    now_ns = time.time_ns()
    payload_fields = {
        "schema",
        "role",
        "processMode",
        "configurationDigest",
        "sourceRevision",
        "launchManifestDigest",
        "runtimeClosureDigest",
        "operationManifestDigest",
        "measurementDigest",
        "nonceDigest",
        "teeType",
        "attestationDocumentDigest",
        "providerVerificationDigest",
        "releaseWitnessReceiptDigest",
        "brokerVerificationPolicyDigest",
        "credentialSetDigest",
        "responseSigningSpkiDigest",
        "providerAttestationVerified",
        "credentialReleaseBoundToMeasurement",
        "credentialReleaseId",
        "issuedAtEpochNs",
        "expiresAtEpochNs",
    }
    provider_fields = {
        "schema",
        "attestationDocumentDigest",
        "measurementDigest",
        "nonceDigest",
        "teeType",
        "verifierIdentityDigest",
        "verificationPolicyDigest",
        "issuedAtEpochNs",
        "expiresAtEpochNs",
        "signature",
    }
    witness_fields = {
        "schema",
        "phase",
        "operation",
        "requestDigest",
        "capabilityId",
        "resultDigest",
        "witnessIdentityDigest",
        "sequence",
        "fence",
        "headDigest",
        "predecessorHeadDigest",
        "predecessorReceiptDigest",
        "logPredecessorHeadDigest",
        "deadlineMonotonicNs",
        "issuedAtEpochNs",
        "signature",
    }
    release_request_digest = _domain_digest(
        "serverware.policyAuthorityCredentialRelease/v1",
        str(payload.get("credentialReleaseId", "")).encode("utf-8"),
        str(payload.get("credentialSetDigest", "")).encode("ascii"),
        str(payload.get("measurementDigest", "")).encode("ascii"),
    )
    witness_head_material = dict(witness_unsigned)
    witness_head_material["headDigest"] = None
    if (
        set(payload) != payload_fields
        or set(provider) != provider_fields
        or set(witness) != witness_fields
        or payload.get("schema") != ATTESTATION_SCHEMA
        or payload.get("role") != "verifier"
        or payload.get("processMode") != PROCESS_MODES["verifier"]
        or payload.get("configurationDigest")
            != expected_configuration_digest
        or payload.get("sourceRevision") != SOURCE_REVISION
        or payload.get("operationManifestDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or payload.get("measurementDigest")
            not in policy["allowedMeasurements"]
        or payload.get("teeType") not in policy["allowedTeeTypes"]
        or payload.get("attestationDocumentDigest")
            != document_digest
        or payload.get("providerVerificationDigest")
            != provider_digest
        or payload.get("releaseWitnessReceiptDigest")
            != witness_digest
        or payload.get("brokerVerificationPolicyDigest")
            != policy["brokerVerificationPolicyDigest"]
        or payload.get("responseSigningSpkiDigest")
            != expected_response_spki_digest
        or payload.get("providerAttestationVerified") is not True
        or payload.get("credentialReleaseBoundToMeasurement") is not True
        or not isinstance(payload.get("issuedAtEpochNs"), int)
        or not isinstance(payload.get("expiresAtEpochNs"), int)
        or payload["issuedAtEpochNs"] > now_ns
        or payload["expiresAtEpochNs"] <= now_ns
        or payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"]
            > policy["maximumReceiptAgeNs"]
        or provider.get("schema")
            != "serverware.teeAttestationVerification/v1"
        or provider.get("attestationDocumentDigest")
            != document_digest
        or provider.get("measurementDigest")
            != payload.get("measurementDigest")
        or provider.get("nonceDigest") != payload.get("nonceDigest")
        or provider.get("teeType") != payload.get("teeType")
        or provider.get("verificationPolicyDigest")
            != policy["brokerVerificationPolicyDigest"]
        or not isinstance(provider.get("issuedAtEpochNs"), int)
        or not isinstance(provider.get("expiresAtEpochNs"), int)
        or provider.get("issuedAtEpochNs") > payload["issuedAtEpochNs"]
        or provider.get("expiresAtEpochNs") < payload["expiresAtEpochNs"]
        or witness.get("schema") != authority_contract.WITNESS_SCHEMA
        or witness.get("phase") != "credential-release"
        or witness.get("operation") != "verifier"
        or witness.get("requestDigest") != release_request_digest
        or witness.get("capabilityId")
            != payload.get("credentialReleaseId")
        or witness.get("resultDigest") != document_digest
        or witness.get("predecessorHeadDigest") is not None
        or witness.get("predecessorReceiptDigest") is not None
        or not isinstance(witness.get("sequence"), int)
        or witness["sequence"] < 1
        or not isinstance(witness.get("fence"), int)
        or witness["fence"] < 1
        or not isinstance(witness.get("deadlineMonotonicNs"), int)
        or witness["deadlineMonotonicNs"] <= 0
        or not isinstance(witness.get("issuedAtEpochNs"), int)
        or _require_digest(
            witness.get("headDigest"),
            "credential-release witness head digest",
        )
            != _domain_digest(
                "serverware.policyAuthorityReplayWitnessHead/v1",
                _canonical(witness_head_material),
            )
    ):
        raise AuthorityServiceError(
            "public attestation evidence binding is invalid"
        )
    return dict(evidence)


def _verify_public_attestation_consumption(
    *,
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    policy: Mapping[str, Any],
    expected_attestation_receipt_digest: str,
) -> str:
    if evidence.get("schema") == TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA:
        unsigned = dict(receipt)
        signature = _b64url_decode(
            unsigned.pop("signature", None),
            size=64,
        )
        assurance_fields = {
            "trustMode": "trusted-host-local",
            "coLocated": True,
            "hardwareBacked": False,
            "nativeStageZero": False,
            "hsmBackedKeys": False,
            "teeVerified": False,
            "externalWitnessVerified": False,
        }
        if (
            set(receipt)
            != {
                "schema",
                "role",
                "configurationDigest",
                "generationDigest",
                "launchIdentityCertificateDigest",
                "attestationReceiptDigest",
                "trustMode",
                "coLocated",
                "hardwareBacked",
                "nativeStageZero",
                "hsmBackedKeys",
                "teeVerified",
                "externalWitnessVerified",
                "issuedAtEpochNs",
                "signerPurpose",
                "signature",
            }
            or receipt.get("schema")
                != TRUSTED_HOST_LOCAL_CONSUMPTION_SCHEMA
            or receipt.get("role") != "verifier"
            or receipt.get("configurationDigest")
                != evidence["payload"].get("configurationDigest")
            or receipt.get("generationDigest")
                != evidence["payload"].get("generationDigest")
            or receipt.get("attestationReceiptDigest")
                != expected_attestation_receipt_digest
            or {
                field: receipt.get(field)
                for field in assurance_fields
            } != assurance_fields
            or receipt.get("signerPurpose") != "verifier-response-key"
            or not isinstance(receipt.get("issuedAtEpochNs"), int)
            or receipt["issuedAtEpochNs"]
                < evidence["payload"].get("issuedAtEpochNs", 0)
            or receipt["issuedAtEpochNs"]
                >= evidence["payload"].get("expiresAtEpochNs", 0)
        ):
            raise AuthorityServiceError(
                "trusted-host-local consumption receipt is not exact"
            )
        verifier_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                policy["verifierSigningPublicKeyBase64Url"],
                size=32,
            )
        )
        try:
            verifier_key.verify(
                signature,
                _domain_digest(
                    TRUSTED_HOST_LOCAL_CONSUMPTION_SCHEMA,
                    _canonical(unsigned),
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "trusted-host-local consumption signature is invalid"
            ) from exc
        return _domain_digest(
            TRUSTED_HOST_LOCAL_CONSUMPTION_SCHEMA,
            _canonical(dict(receipt)),
        )

    raise AuthorityServiceError(
        "TEE and external-witness attestation consumption are unavailable "
        "prerequisites"
    )

    predecessor = evidence.get("releaseWitnessReceipt")
    if not isinstance(predecessor, dict):
        raise AuthorityServiceError(
            "credential-release predecessor evidence is absent"
        )
    predecessor_digest = _domain_digest(
        authority_contract.WITNESS_SCHEMA,
        _canonical(predecessor),
    )
    unsigned = dict(receipt)
    signature = _b64url_decode(
        unsigned.pop("signature", None),
        size=64,
    )
    head_material = dict(unsigned)
    head_material["headDigest"] = None
    if (
        set(receipt)
        != {
            "schema",
            "phase",
            "operation",
            "requestDigest",
            "capabilityId",
            "resultDigest",
            "witnessIdentityDigest",
            "sequence",
            "fence",
            "headDigest",
            "predecessorHeadDigest",
            "predecessorReceiptDigest",
            "logPredecessorHeadDigest",
            "deadlineMonotonicNs",
            "issuedAtEpochNs",
            "signature",
        }
        or receipt.get("schema") != authority_contract.WITNESS_SCHEMA
        or receipt.get("phase") != "credential-release-consume"
        or receipt.get("operation") != "verifier"
        or receipt.get("requestDigest")
            != predecessor.get("requestDigest")
        or receipt.get("capabilityId")
            != predecessor.get("capabilityId")
        or receipt.get("resultDigest")
            != expected_attestation_receipt_digest
        or receipt.get("predecessorReceiptDigest")
            != predecessor_digest
        or receipt.get("predecessorHeadDigest")
            != predecessor.get("headDigest")
        or receipt.get("fence") != predecessor.get("fence")
        or receipt.get("deadlineMonotonicNs")
            != predecessor.get("deadlineMonotonicNs")
        or not isinstance(receipt.get("sequence"), int)
        or receipt["sequence"] <= int(predecessor.get("sequence", 0))
        or _require_digest(
            receipt.get("headDigest"),
            "public credential-release consumption head digest",
        )
            != _domain_digest(
                "serverware.policyAuthorityReplayWitnessHead/v1",
                _canonical(head_material),
            )
    ):
        raise AuthorityServiceError(
            "public credential-release consumption binding is invalid"
        )
    witness_key = Ed25519PublicKey.from_public_bytes(
        _b64url_decode(
            policy["replayWitnessSigningPublicKeyBase64Url"],
            size=32,
        )
    )
    try:
        witness_key.verify(
            signature,
            _domain_digest(
                authority_contract.WITNESS_SCHEMA,
                _canonical(unsigned),
            ).encode("ascii"),
        )
    except InvalidSignature as exc:
        raise AuthorityServiceError(
            "public credential-release consumption signature is invalid"
        ) from exc
    return _domain_digest(
        authority_contract.WITNESS_SCHEMA,
        _canonical(dict(receipt)),
    )


@dataclass(frozen=True)
class MeasuredConfiguration:
    payload: dict[str, Any]
    digest: str
    root_key: Ed25519PublicKey
    attestation_evidence: dict[str, Any] | None = None

    @classmethod
    def load(cls, *, role: str) -> "MeasuredConfiguration":
        root_value = _read_bounded_descriptor(
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY",
            maximum=64 * 1024,
            require_root_owned=True,
            require_descriptor=True,
        )
        config_value = _read_bounded_descriptor(
            "SERVERWARE_POLICY_AUTHORITY_CONFIG",
            maximum=MAX_CONFIG_BYTES,
            require_root_owned=True,
            require_descriptor=True,
        )
        root_key = _load_ed25519_public_key(root_value)
        try:
            envelope = json.loads(config_value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorityServiceError(
                "authority configuration is not JSON"
            ) from exc
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"schema", "payload", "signature"}
            or envelope.get("schema") != SIGNED_CONFIG_SCHEMA
            or not isinstance(envelope.get("payload"), dict)
        ):
            raise AuthorityServiceError(
                "authority configuration envelope is not closed"
            )
        payload = dict(envelope["payload"])
        required_payload_fields = {
            "schema",
            "sourceRevision",
            "roles",
            "runtimeUid",
            "runtimeGid",
            "launchManifestDigests",
            "runtimeClosureDigests",
            "packageVersions",
            "launchNonceDigest",
            "queryManifestDigest",
            "generationSequence",
            "generationDigest",
            "generationPredecessorDigest",
            "generationMinimumRollbackSequence",
            "credentialReleaseTrust",
            "replayWitness",
            "webauthn",
            "issuerSessionIdentityDigest",
            "executorSessionIdentityDigest",
            "executorRole",
            "executorTlsClientDn",
            "executorTlsClientSerial",
            "executorTlsIssuerDn",
            "issuerCredentialIssuanceDigest",
            "executorCredentialIssuanceDigest",
        }
        payload_bytes = _canonical(payload)
        try:
            root_key.verify(
                _b64url_decode(envelope["signature"], size=64),
                _domain_digest(
                    SIGNED_CONFIG_SCHEMA, payload_bytes
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "authority configuration root signature is invalid"
            ) from exc
        if (
            set(payload) != required_payload_fields
            or payload.get("schema") != CONFIG_SCHEMA
            or payload.get("sourceRevision") != SOURCE_REVISION
            or role not in PROCESS_MODES
            or not isinstance(payload.get("roles"), dict)
            or role not in payload["roles"]
            or not isinstance(payload.get("generationSequence"), int)
            or isinstance(payload.get("generationSequence"), bool)
            or payload["generationSequence"] < 0
            or not isinstance(
                payload.get("generationMinimumRollbackSequence"), int
            )
            or isinstance(
                payload.get("generationMinimumRollbackSequence"), bool
            )
            or payload["generationMinimumRollbackSequence"] < 0
            or payload["generationMinimumRollbackSequence"]
                > payload["generationSequence"]
            or (
                payload["generationSequence"] == 0
                and payload.get("generationPredecessorDigest")
                    is not None
            )
            or (
                payload["generationSequence"] > 0
                and _require_digest(
                    payload.get("generationPredecessorDigest"),
                    "generation predecessor digest",
                )
                    != payload.get("generationPredecessorDigest")
            )
            or any(
                _require_digest(
                    payload.get(field),
                    field,
                ) != payload.get(field)
                for field in (
                    "launchNonceDigest",
                    "queryManifestDigest",
                    "generationDigest",
                    "issuerSessionIdentityDigest",
                    "executorSessionIdentityDigest",
                    "issuerCredentialIssuanceDigest",
                    "executorCredentialIssuanceDigest",
                )
            )
        ):
            raise AuthorityServiceError(
                "authority configuration contract is invalid"
            )
        configuration = cls(
            payload=payload,
            digest=_domain_digest(CONFIG_SCHEMA, payload_bytes),
            root_key=root_key,
        )
        configuration._verify_generation_binding()
        configuration._verify_role_topology()
        configuration._verify_runtime_closure()
        configuration._verify_attestation(role=role)
        return configuration

    def _verify_generation_binding(self) -> None:
        generation = dict(authority_launch_guard.generation())
        if (
            generation.get("sequence")
                != self.payload.get("generationSequence")
            or generation.get("digest")
                != self.payload.get("generationDigest")
            or generation.get("predecessorDigest")
                != self.payload.get("generationPredecessorDigest")
            or generation.get("minimumRollbackSequence")
                != self.payload.get("generationMinimumRollbackSequence")
            or generation.get("operationManifestDigest")
                != authority_contract.OPERATION_MANIFEST_DIGEST
            or self.digest not in generation.get(
                "configurationDigests", ()
            )
        ):
            raise AuthorityServiceError(
                "authority configuration generation binding changed"
            )

    def role(self, role: str) -> dict[str, Any]:
        value = self.payload["roles"].get(role)
        if not isinstance(value, dict):
            raise AuthorityServiceError(
                f"authority {role} configuration is unavailable"
            )
        return dict(value)

    def _verify_role_topology(self) -> None:
        roles = self.payload.get("roles")
        launch_manifest_digests = self.payload.get(
            "launchManifestDigests"
        )
        runtime_closure_digests = self.payload.get(
            "runtimeClosureDigests"
        )
        credential_release_trust = self.payload.get(
            "credentialReleaseTrust"
        )
        replay_witness = self.payload.get("replayWitness")
        webauthn = self.payload.get("webauthn")
        trusted_host_local = (
            authority_launch_guard.launch_assurance().get("trustMode")
            == "trusted-host-local"
        )
        credential_release_trust_valid = (
            isinstance(credential_release_trust, dict)
            and (
                (
                    trusted_host_local
                    and set(credential_release_trust)
                        == {
                            "schema",
                            "trustMode",
                            "maximumReceiptAgeNs",
                        }
                    and credential_release_trust.get("schema")
                        == (
                            "serverware."
                            "trustedHostLocalCredentialReleaseTrust/v1"
                        )
                    and credential_release_trust.get("trustMode")
                        == "trusted-host-local"
                )
                or (
                    not trusted_host_local
                    and set(credential_release_trust)
                        == {
                            "brokerPublicKeyBase64Url",
                            "providerVerifierPublicKeyBase64Url",
                            "providerVerifierIdentityDigest",
                            "allowedMeasurements",
                            "allowedTeeTypes",
                            "brokerVerificationPolicyDigest",
                            "maximumReceiptAgeNs",
                        }
                    and isinstance(
                        credential_release_trust.get(
                            "allowedMeasurements"
                        ),
                        list,
                    )
                    and bool(
                        credential_release_trust["allowedMeasurements"]
                    )
                    and isinstance(
                        credential_release_trust.get(
                            "allowedTeeTypes"
                        ),
                        list,
                    )
                    and bool(
                        credential_release_trust["allowedTeeTypes"]
                    )
                )
            )
        )
        if not isinstance(roles, dict) or set(roles) != set(PROCESS_MODES):
            raise AuthorityServiceError(
                "authority role topology is not closed"
            )
        if (
            not isinstance(launch_manifest_digests, dict)
            or set(launch_manifest_digests) != set(PROCESS_MODES)
            or not isinstance(runtime_closure_digests, dict)
            or set(runtime_closure_digests) != set(PROCESS_MODES)
            or any(
                _require_digest(
                    launch_manifest_digests[role],
                    f"{role} launch manifest digest",
                ) != launch_manifest_digests[role]
                or _require_digest(
                    runtime_closure_digests[role],
                    f"{role} runtime closure digest",
                ) != runtime_closure_digests[role]
                for role in PROCESS_MODES
            )
        ):
            raise AuthorityServiceError(
                "authority role measurement topology is not closed"
            )
        if (
            not credential_release_trust_valid
            or not isinstance(replay_witness, dict)
            or set(replay_witness)
            != {
                "socketPath",
                "serviceUid",
                "serviceGid",
                "requestTimeoutSeconds",
                "identityDigest",
                "signingPublicKeyBase64Url",
            }
            or not isinstance(webauthn, dict)
            or set(webauthn)
            != {
                "rpId",
                "origin",
                "challengeLifetimeNs",
                "maximumChallengeAgeNs",
                "allowedAuthenticatorClasses",
                "requireAttestationTrusted",
            }
            or not Path(
                str(replay_witness.get("socketPath", ""))
            ).is_absolute()
            or not isinstance(
                replay_witness.get("serviceUid"), int
            )
            or not isinstance(
                replay_witness.get("serviceGid"), int
            )
            or isinstance(
                replay_witness.get("serviceUid"), bool
            )
            or isinstance(
                replay_witness.get("serviceGid"), bool
            )
            or min(
                int(replay_witness.get("serviceUid", -1)),
                int(replay_witness.get("serviceGid", -1)),
            ) < 0
            or not isinstance(
                replay_witness.get("requestTimeoutSeconds"),
                (int, float),
            )
            or replay_witness["requestTimeoutSeconds"] <= 0
            or _require_digest(
                replay_witness.get("identityDigest"),
                "replay witness identity digest",
            ) != replay_witness.get("identityDigest")
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
                for value in (
                    webauthn.get("challengeLifetimeNs"),
                    webauthn.get("maximumChallengeAgeNs"),
                    credential_release_trust.get(
                        "maximumReceiptAgeNs"
                    ),
                )
            )
        ):
            raise AuthorityServiceError(
                "authority trust topology is not closed"
            )
        service_uids: set[int] = set()
        service_gids: set[int] = set()
        socket_paths: set[str] = set()
        database_roles: set[str] = set()
        common_role_fields = {
            "processMode",
            "serviceUid",
            "serviceGid",
            "peerUid",
            "peerGid",
            "socketPath",
            "databaseRole",
            "tlsClientDn",
            "tlsClientSerial",
            "tlsIssuerDn",
            "measurementDigest",
            "attestationReceiptDigest",
            "credentialSetDigest",
            "responseSigningSpkiDigest",
            "requestTimeoutSeconds",
            "databaseConnectTimeoutSeconds",
            "maximumInternalAgeNs",
            "capabilityLifetimeNs",
            "workers",
            "maximumInFlight",
            "listenBacklog",
        }
        for role, process_mode in PROCESS_MODES.items():
            role_value = roles.get(role)
            if not isinstance(role_value, dict):
                raise AuthorityServiceError(
                    "authority role topology entry is invalid"
                )
            service_identity = (
                int(role_value.get("serviceUid", -1)),
                int(role_value.get("serviceGid", -1)),
            )
            socket_path = str(role_value.get("socketPath", ""))
            database_role = str(role_value.get("databaseRole", ""))
            required_role_fields = set(common_role_fields)
            if role == "verifier":
                required_role_fields.update(
                    {
                        "runtimeSocketPath",
                        "signingSpkiDigest",
                        "signingPublicKeyBase64Url",
                        "maximumEndToEndDeadlineNs",
                    }
                )
            elif role == "planner":
                required_role_fields.update(
                    {
                        "enabledOperations",
                        "plannerSessionIdentityDigest",
                        "signingSpkiDigest",
                        "signingPublicKeyBase64Url",
                    }
                )
            elif role == "planner-writer":
                required_role_fields.update(
                    {
                        "plannerSessionIdentityDigest",
                        "plannerSigningSpkiDigest",
                        "plannerSigningPublicKeyBase64Url",
                    }
                )
            if (
                set(role_value) != required_role_fields
                or role_value.get("processMode") != process_mode
                or min(service_identity) < 0
                or service_identity[0] in service_uids
                or service_identity[1] in service_gids
                or not Path(socket_path).is_absolute()
                or socket_path in socket_paths
                or not database_role
                or database_role in database_roles
                or _require_digest(
                    role_value.get("responseSigningSpkiDigest"),
                    "role response signing key digest",
                ) != role_value.get("responseSigningSpkiDigest")
                or any(
                    _require_digest(
                        role_value.get(field),
                        f"{role} {field}",
                    ) != role_value.get(field)
                    for field in (
                        "measurementDigest",
                        "attestationReceiptDigest",
                        "credentialSetDigest",
                    )
                )
                or any(
                    not isinstance(role_value.get(field), int)
                    or isinstance(role_value.get(field), bool)
                    or role_value[field] <= 0
                    for field in (
                        "maximumInternalAgeNs",
                        "capabilityLifetimeNs",
                        "workers",
                        "maximumInFlight",
                        "listenBacklog",
                    )
                )
                or any(
                    not isinstance(
                        role_value.get(field), (int, float)
                    )
                    or isinstance(role_value.get(field), bool)
                    or role_value[field] <= 0
                    for field in (
                        "requestTimeoutSeconds",
                        "databaseConnectTimeoutSeconds",
                    )
                )
                or role_value["maximumInFlight"]
                    < role_value["workers"]
                or any(
                    not isinstance(role_value.get(field), str)
                    or not role_value[field]
                    for field in (
                        "tlsClientDn",
                        "tlsClientSerial",
                        "tlsIssuerDn",
                    )
                )
            ):
                raise AuthorityServiceError(
                    "authority role identity or socket topology is invalid"
                )
            service_uids.add(service_identity[0])
            service_gids.add(service_identity[1])
            socket_paths.add(socket_path)
            database_roles.add(database_role)
            if role == "verifier":
                verifier_public_key = Ed25519PublicKey.from_public_bytes(
                    _b64url_decode(
                        role_value["signingPublicKeyBase64Url"],
                        size=32,
                    )
                )
                if (
                    _public_spki_digest(verifier_public_key)
                        != role_value["signingSpkiDigest"]
                    or role_value["responseSigningSpkiDigest"]
                        != role_value["signingSpkiDigest"]
                    or not isinstance(
                        role_value["maximumEndToEndDeadlineNs"], int
                    )
                    or role_value["maximumEndToEndDeadlineNs"] <= 0
                ):
                    raise AuthorityServiceError(
                        "verifier signing or deadline topology is invalid"
                    )
            elif role == "planner":
                enabled_operations = role_value.get(
                    "enabledOperations"
                )
                planner_key = Ed25519PublicKey.from_public_bytes(
                    _b64url_decode(
                        role_value["signingPublicKeyBase64Url"],
                        size=32,
                    )
                )
                if (
                    not isinstance(enabled_operations, list)
                    or enabled_operations
                        != sorted(set(enabled_operations))
                    or set(enabled_operations)
                        - set(authority_planner.PLANNING_PROGRAMS)
                    or _require_digest(
                        role_value["plannerSessionIdentityDigest"],
                        "planner session identity digest",
                    )
                        != role_value["plannerSessionIdentityDigest"]
                    or _public_spki_digest(planner_key)
                        != role_value["signingSpkiDigest"]
                    or role_value["responseSigningSpkiDigest"]
                        != role_value["signingSpkiDigest"]
                ):
                    raise AuthorityServiceError(
                        "planner program or signing topology is invalid"
                    )
            elif role == "planner-writer":
                planner_key = Ed25519PublicKey.from_public_bytes(
                    _b64url_decode(
                        role_value[
                            "plannerSigningPublicKeyBase64Url"
                        ],
                        size=32,
                    )
                )
                if (
                    _public_spki_digest(planner_key)
                        != role_value["plannerSigningSpkiDigest"]
                    or role_value["plannerSessionIdentityDigest"]
                        != roles["planner"].get(
                            "plannerSessionIdentityDigest"
                        )
                    or role_value["plannerSigningSpkiDigest"]
                        != roles["planner"].get("signingSpkiDigest")
                ):
                    raise AuthorityServiceError(
                        "planner-writer trust topology is invalid"
                    )
        verifier = roles["verifier"]
        planner = roles["planner"]
        planner_writer = roles["planner-writer"]
        issuer = roles["issuer"]
        executor = roles["executor"]
        runtime_identity = (
            int(self.payload.get("runtimeUid", -1)),
            int(self.payload.get("runtimeGid", -1)),
        )
        if (
            runtime_identity[0] in service_uids
            or runtime_identity[1] in service_gids
            or min(runtime_identity) < 0
            or (
                int(verifier.get("peerUid", -1)),
                int(verifier.get("peerGid", -1)),
            )
            != runtime_identity
            or verifier.get("runtimeSocketPath")
            != verifier.get("socketPath")
            or (
                int(planner.get("peerUid", -1)),
                int(planner.get("peerGid", -1)),
            )
            != (
                int(verifier["serviceUid"]),
                int(verifier["serviceGid"]),
            )
            or (
                int(planner_writer.get("peerUid", -1)),
                int(planner_writer.get("peerGid", -1)),
            )
            != (
                int(planner["serviceUid"]),
                int(planner["serviceGid"]),
            )
            or (
                int(issuer.get("peerUid", -1)),
                int(issuer.get("peerGid", -1)),
            )
            != (
                int(verifier["serviceUid"]),
                int(verifier["serviceGid"]),
            )
            or (
                int(executor.get("peerUid", -1)),
                int(executor.get("peerGid", -1)),
            )
            != (
                int(verifier["serviceUid"]),
                int(verifier["serviceGid"]),
            )
        ):
            raise AuthorityServiceError(
                "authority peer topology is invalid"
            )

    def _verify_runtime_closure(self) -> None:
        packages = self.payload.get("packageVersions")
        measured_packages = dict(
            authority_launch_guard.package_versions()
        )
        launch_manifest_digest = authority_launch_guard.require_active(
            _launch_role
        )
        if (
            not isinstance(packages, dict)
            or packages != measured_packages
            or self.payload["launchManifestDigests"].get(_launch_role)
                != launch_manifest_digest
        ):
            raise AuthorityServiceError(
                "authority runtime closure is not closed"
            )
        if not REQUIRED_DISTRIBUTIONS.issubset(packages):
            raise AuthorityServiceError(
                "authority package closure omits a required distribution"
            )
        for distribution, expected_version in sorted(packages.items()):
            if not isinstance(distribution, str) or not isinstance(
                expected_version, str
            ):
                raise AuthorityServiceError(
                    f"authority package closure changed: {distribution}"
                )
        closure_digest = _domain_digest(
            "serverware.policyAuthorityRuntimeClosure/v2",
            launch_manifest_digest.encode("ascii"),
            _canonical(packages),
        )
        if closure_digest != self.payload[
            "runtimeClosureDigests"
        ].get(_launch_role):
            raise AuthorityServiceError(
                "authority runtime closure digest is invalid"
            )

    def _verify_trusted_host_local_attestation(
        self,
        *,
        role: str,
        attestation_value: bytes,
    ) -> None:
        try:
            envelope = json.loads(attestation_value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorityServiceError(
                "trusted-host-local attestation is not JSON"
            ) from exc
        assurance = dict(authority_launch_guard.launch_assurance())
        generation = dict(authority_launch_guard.generation())
        verified_package = (
            authority_launch_guard.verified_artifact_package()
        )
        payload = (
            envelope.get("payload")
            if isinstance(envelope, dict)
            else None
        )
        required_payload = {
            "schema",
            "role",
            "processMode",
            "configurationDigest",
            "sourceRevision",
            "launchManifestDigest",
            "runtimeClosureDigest",
            "operationManifestDigest",
            "generationDigest",
            "stageZeroRequestDigest",
            "artifactPackageDigest",
            "measurementDigest",
            "responseSigningSpkiDigest",
            "trustMode",
            "coLocated",
            "hardwareBacked",
            "nativeStageZero",
            "hsmBackedKeys",
            "teeVerified",
            "externalWitnessVerified",
            "issuedAtEpochNs",
            "expiresAtEpochNs",
        }
        now_epoch_ns = time.time_ns()
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"schema", "payload", "signature"}
            or envelope.get("schema")
                != TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA
            or not isinstance(payload, dict)
            or set(payload) != required_payload
            or attestation_value != _canonical(envelope)
            or payload.get("schema")
                != TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA
            or payload.get("role") != role
            or payload.get("processMode") != PROCESS_MODES[role]
            or payload.get("configurationDigest") != self.digest
            or payload.get("sourceRevision") != SOURCE_REVISION
            or payload.get("launchManifestDigest")
                != self.payload["launchManifestDigests"][role]
            or payload.get("runtimeClosureDigest")
                != self.payload["runtimeClosureDigests"][role]
            or payload.get("operationManifestDigest")
                != authority_contract.OPERATION_MANIFEST_DIGEST
            or payload.get("generationDigest")
                != generation.get("digest")
            or payload.get("stageZeroRequestDigest")
                != generation.get("stageZeroRequestDigest")
            or payload.get("artifactPackageDigest")
                != verified_package.package_digest
            or payload.get("measurementDigest")
                != self.role(role).get("measurementDigest")
            or payload.get("responseSigningSpkiDigest")
                != self.role(role).get("responseSigningSpkiDigest")
            or {
                field: payload.get(field)
                for field in (
                    "trustMode",
                    "coLocated",
                    "hardwareBacked",
                    "nativeStageZero",
                    "hsmBackedKeys",
                    "teeVerified",
                    "externalWitnessVerified",
                )
            }
                != {
                    field: assurance[field]
                    for field in (
                        "trustMode",
                        "coLocated",
                        "hardwareBacked",
                        "nativeStageZero",
                        "hsmBackedKeys",
                        "teeVerified",
                        "externalWitnessVerified",
                    )
                }
            or not isinstance(payload.get("issuedAtEpochNs"), int)
            or isinstance(payload.get("issuedAtEpochNs"), bool)
            or not isinstance(payload.get("expiresAtEpochNs"), int)
            or isinstance(payload.get("expiresAtEpochNs"), bool)
            or payload["issuedAtEpochNs"] > now_epoch_ns
            or payload["expiresAtEpochNs"] <= now_epoch_ns
            or payload["expiresAtEpochNs"]
                - payload["issuedAtEpochNs"]
                > int(
                    self.payload["credentialReleaseTrust"][
                        "maximumReceiptAgeNs"
                    ]
                )
        ):
            raise AuthorityServiceError(
                "trusted-host-local attestation binding changed"
            )
        try:
            self.root_key.verify(
                _b64url_decode(envelope["signature"], size=64),
                _domain_digest(
                    TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA,
                    _canonical(payload),
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "trusted-host-local attestation signature is invalid"
            ) from exc
        receipt_digest = _domain_digest(
            TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA,
            _canonical(envelope),
        )
        if (
            self.role(role).get("attestationReceiptDigest")
            != receipt_digest
        ):
            raise AuthorityServiceError(
                "trusted-host-local attestation digest changed"
            )
        object.__setattr__(
            self,
            "attestation_evidence",
            dict(envelope),
        )

    def _verify_attestation(self, *, role: str) -> None:
        attestation_value = _read_bounded_descriptor(
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION",
            maximum=4 * 1024 * 1024,
            require_root_owned=True,
            require_descriptor=True,
        )
        assurance = dict(authority_launch_guard.launch_assurance())
        if assurance.get("trustMode") == "trusted-host-local":
            self._verify_trusted_host_local_attestation(
                role=role,
                attestation_value=attestation_value,
            )
            return
        raise AuthorityServiceError(
            "native stage zero, HSM, TEE, and external witness attestation "
            "remain unavailable prerequisites"
        )


def _peer_identity(connection: socket.socket) -> tuple[int, int, int | None]:
    try:
        return authority_transport._peer_identity(connection)
    except authority_transport.AuthorityTransportError as exc:
        raise AuthorityServiceError(str(exc)) from exc


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    try:
        return authority_transport._recv_exact(connection, count)
    except authority_transport.AuthorityTransportError as exc:
        raise AuthorityServiceError(str(exc)) from exc


def _recv_message_bytes(
    connection: socket.socket, *, maximum_bytes: int = MAX_MESSAGE_BYTES,
) -> bytes:
    try:
        return authority_transport._recv_message_bytes(
            connection, maximum_bytes=maximum_bytes,
        )
    except authority_transport.AuthorityTransportError as exc:
        raise AuthorityServiceError(str(exc)) from exc


def _recv_revocation_invocation_bytes(connection: socket.socket) -> bytes:
    try:
        return authority_transport._recv_revocation_invocation_bytes(connection)
    except authority_transport.AuthorityTransportError as exc:
        raise AuthorityServiceError(str(exc)) from exc


def _recv_message(connection: socket.socket) -> dict[str, Any]:
    _encoded, value = _recv_message_with_bytes(connection)
    return value


def _recv_message_with_bytes(
    connection: socket.socket,
) -> tuple[bytes, dict[str, Any]]:
    """Retain the actual framed response before parsing or canonical checks.

    The original immutable bytes are returned only with a bounded canonical
    object. They are not reconstructed from the parsed value and establish no
    protocol or signature authority on their own.
    """
    encoded = _recv_message_bytes(connection)
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityServiceError("authority message is not JSON") from exc
    if not isinstance(value, dict) or _canonical(value) != encoded:
        raise AuthorityServiceError("authority message is not canonical")
    return encoded, value


def _send_message(connection: socket.socket, value: Mapping[str, Any]) -> None:
    encoded = _canonical(dict(value))
    _send_encoded_message(connection, encoded)


def _send_encoded_message(connection: socket.socket, encoded: bytes) -> None:
    try:
        authority_transport._send_encoded_message(
            connection, encoded, maximum_bytes=MAX_MESSAGE_BYTES,
        )
    except authority_transport.AuthorityTransportError as exc:
        raise AuthorityServiceError(str(exc)) from exc


def _activated_listener(
    *,
    socket_path: str,
    service_uid: int,
    service_gid: int,
) -> socket.socket:
    descriptor = authority_launch_guard.listener_descriptor()
    listener_binding = authority_launch_guard.stage_zero_request().get(
        "listener"
    )
    listener = socket.fromfd(
        descriptor,
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )
    try:
        descriptor_metadata = os.fstat(listener.fileno())
        path_metadata = os.stat(socket_path, follow_symlinks=False)
        bound_path = listener.getsockname()
        if isinstance(bound_path, bytes):
            bound_path = os.fsdecode(bound_path)
        if (
            not stat.S_ISSOCK(descriptor_metadata.st_mode)
            or not stat.S_ISSOCK(path_metadata.st_mode)
            or not isinstance(listener_binding, Mapping)
            or listener.family != socket.AF_UNIX
            or listener.type & socket.SOCK_STREAM
                != socket.SOCK_STREAM
            or listener.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_ACCEPTCONN,
            )
                != 1
            or bound_path != socket_path
            or (
                path_metadata.st_dev,
                path_metadata.st_ino,
            )
                != (
                    listener_binding.get("device"),
                    listener_binding.get("inode"),
                )
            or path_metadata.st_uid != service_uid
            or path_metadata.st_gid != service_gid
            or stat.S_IMODE(path_metadata.st_mode) != 0o660
        ):
            raise AuthorityServiceError(
                "activated authority listener binding changed"
            )
    except Exception:
        listener.close()
        raise
    return listener


def _socket_request(
    path: str,
    value: Mapping[str, Any],
    *,
    timeout_seconds: float,
    expected_peer_uid: int,
    expected_peer_gid: int,
) -> dict[str, Any]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout_seconds)
    try:
        connection.connect(path)
        peer_uid, peer_gid, _peer_pid = _peer_identity(connection)
        if (
            peer_uid != expected_peer_uid
            or peer_gid != expected_peer_gid
        ):
            raise AuthorityServiceError(
                "authority socket server identity is not exact"
            )
        _send_message(connection, value)
        return _recv_message(connection)
    finally:
        connection.close()


def _socket_request_bytes(
    path: str,
    encoded: bytes,
    *,
    timeout_seconds: float,
    expected_peer_uid: int,
    expected_peer_gid: int,
) -> dict[str, Any]:
    _response_bytes, response = _socket_request_bytes_with_response(
        path,
        encoded,
        timeout_seconds=timeout_seconds,
        expected_peer_uid=expected_peer_uid,
        expected_peer_gid=expected_peer_gid,
    )
    return response


def _socket_request_bytes_with_response(
    path: str,
    encoded: bytes,
    *,
    timeout_seconds: float,
    expected_peer_uid: int,
    expected_peer_gid: int,
) -> tuple[bytes, dict[str, Any]]:
    """Send source-owned original bytes without decoding or re-encoding them.

    The caller constructs canonical bytes; this transport grants no protocol
    or signature authority. Preserve the original received bytes through the
    same fixed framing and canonical response checks as the mapping transport.
    Every post-open failure still closes the actual socket.
    """
    if type(encoded) is not bytes or not 2 <= len(encoded) <= MAX_MESSAGE_BYTES:
        raise AuthorityServiceError("authority request bytes are not exact and bounded")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout_seconds)
        connection.connect(path)
        peer_uid, peer_gid, _peer_pid = _peer_identity(connection)
        if peer_uid != expected_peer_uid or peer_gid != expected_peer_gid:
            raise AuthorityServiceError(
                "authority socket server identity is not exact"
            )
        _send_encoded_message(connection, encoded)
        return _recv_message_with_bytes(connection)
    finally:
        connection.close()


def _socket_request_revocation_bytes(
    path: str,
    encoded: bytes,
    *,
    timeout_seconds: float,
    expected_peer_uid: int,
    expected_peer_gid: int,
) -> bytes:
    """Private raw adapter; public dispatch and authentication are separate."""
    try:
        return authority_transport._socket_request_revocation_bytes(
            path, encoded, timeout_seconds=timeout_seconds,
            expected_peer_uid=expected_peer_uid,
            expected_peer_gid=expected_peer_gid,
        )
    except authority_transport.AuthorityTransportError as exc:
        raise AuthorityServiceError(str(exc)) from exc


@lru_cache(maxsize=TREE_DEPTH + 1)
def _empty_digest(depth: int) -> str:
    if not 0 <= depth <= TREE_DEPTH:
        raise AuthorityServiceError("authenticated empty depth is invalid")
    if depth == TREE_DEPTH:
        return _framed_digest(
            "serverware.policyAuthorityAuthenticatedEmptyLeaf/v1",
            str(depth).encode("ascii"),
        )
    child = _empty_digest(depth + 1)
    return _framed_digest(
        "serverware.policyAuthorityAuthenticatedNode/v1",
        str(depth).encode("ascii"),
        _canonical([child] * TREE_RADIX),
    )


def _authenticated_key_digest(table: str, key: Mapping[str, Any]) -> str:
    return _framed_digest(
        "serverware.policyAuthorityAuthenticatedKey/v1",
        table.encode("utf-8"),
        _canonical(dict(key)),
    )


def _authenticated_leaf_digest(
    table: str,
    key: Mapping[str, Any],
    row_digest: str,
) -> tuple[str, str]:
    key_digest = _authenticated_key_digest(table, key)
    return key_digest, _framed_digest(
        "serverware.policyAuthorityAuthenticatedLeaf/v1",
        table.encode("utf-8"),
        key_digest.encode("ascii"),
        _canonical(dict(key)),
        row_digest.encode("ascii"),
    )


def _derive_contract_selector_keys(
    *,
    operation: str,
    table: str,
    key_columns: list[str],
    request: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if (
        not key_columns
        or len(set(key_columns)) != len(key_columns)
        or any(not isinstance(column, str) or not column for column in key_columns)
    ):
        raise AuthorityServiceError("query manifest key columns are invalid")
    try:
        selector_values = authority_contract.extract_selectors(
            operation,
            request,
        ).get(table, ())
    except ValueError as exc:
        raise AuthorityServiceError(
            "closed operation selector extraction failed"
        ) from exc
    if not selector_values:
        return []
    if len(key_columns) != 1:
        raise AuthorityServiceError(
            "explicit selector requires one canonical primary key column"
        )
    projected = {
        _canonical({key_columns[0]: value}): {
            key_columns[0]: value
        }
        for value in selector_values
    }
    return sorted(
        projected.values(),
        key=lambda key: _authenticated_key_digest(table, key),
    )


def _verify_radix_multiproof(
    *,
    table: str,
    selectors: list[dict[str, Any]],
    proof: Mapping[str, Any],
    expected_root: str,
) -> str:
    maximum_frontier = min(
        MAX_MULTIPROOF_NODES,
        max(
            1,
            TREE_DEPTH
            * max(1, len(selectors))
            * (TREE_RADIX - 1),
        ),
    )
    if (
        proof.get("schema")
        != "serverware.policyAuthorityRadixMultiproof/v2"
        or not isinstance(proof.get("frontier"), list)
        or len(proof["frontier"]) > maximum_frontier
    ):
        raise AuthorityServiceError("authenticated multiproof is invalid")
    opened: dict[str, str] = {}
    for selector in selectors:
        key = selector.get("key")
        if not isinstance(key, dict):
            raise AuthorityServiceError("query selector key is invalid")
        key_digest = _authenticated_key_digest(table, key)
        path = key_digest[7:]
        if selector.get("present") is True:
            row_digest = _require_digest(
                selector.get("rowDigest"), "selector row digest"
            )
            _, leaf_digest = _authenticated_leaf_digest(
                table, key, row_digest
            )
        elif selector.get("present") is False and selector.get(
            "rowDigest"
        ) is None:
            leaf_digest = _empty_digest(TREE_DEPTH)
        else:
            raise AuthorityServiceError(
                "query selector presence is invalid"
            )
        if path in opened:
            raise AuthorityServiceError("query selector key is duplicated")
        opened[path] = leaf_digest
    frontier: dict[tuple[int, str], str] = {}
    frontier_order: list[tuple[int, str]] = []
    for node in proof["frontier"]:
        if (
            not isinstance(node, dict)
            or set(node) != {"depth", "prefix", "digest"}
            or not isinstance(node["depth"], int)
            or not 0 <= node["depth"] <= TREE_DEPTH
            or not isinstance(node["prefix"], str)
            or len(node["prefix"]) != node["depth"]
            or any(character not in "0123456789abcdef" for character in node["prefix"])
        ):
            raise AuthorityServiceError("multiproof frontier node is invalid")
        identity = (node["depth"], node["prefix"])
        if identity in frontier:
            raise AuthorityServiceError(
                "multiproof frontier node is duplicated"
            )
        frontier[identity] = _require_digest(
            node["digest"], "frontier digest"
        )
        frontier_order.append(identity)
    if frontier_order != sorted(frontier_order):
        raise AuthorityServiceError(
            "multiproof frontier order is not canonical"
        )
    opened_prefixes = {
        (depth, path[:depth])
        for path in opened
        for depth in range(TREE_DEPTH + 1)
    }
    relevant_prefixes = opened_prefixes | {
        (depth, node_prefix[:depth])
        for node_depth, node_prefix in frontier
        for depth in range(node_depth + 1)
    }
    consumed_frontier: set[tuple[int, str]] = set()
    consumed_opened: set[str] = set()

    def calculate(depth: int, prefix: str) -> str:
        identity = (depth, prefix)
        if identity in frontier:
            if identity in opened_prefixes:
                raise AuthorityServiceError(
                    "multiproof frontier hides an opened selector"
                )
            consumed_frontier.add(identity)
            return frontier[identity]
        if depth == TREE_DEPTH:
            if prefix in opened:
                consumed_opened.add(prefix)
                return opened[prefix]
            return _empty_digest(depth)
        if identity not in relevant_prefixes:
            return _empty_digest(depth)
        children = [
            calculate(depth + 1, prefix + nibble)
            for nibble in "0123456789abcdef"
        ]
        return _framed_digest(
            "serverware.policyAuthorityAuthenticatedNode/v1",
            str(depth).encode("ascii"),
            _canonical(children),
        )

    root = calculate(0, "")
    if (
        root != expected_root
        or consumed_frontier != set(frontier)
        or consumed_opened != set(opened)
    ):
        raise AuthorityServiceError(
            "authenticated multiproof root is invalid"
        )
    return root


def _verify_webauthn_authorization(
    authorization: Mapping[str, Any],
    *,
    expected_operation_id: str,
    configuration: MeasuredConfiguration,
) -> tuple[dict[str, Any], str]:
    required = {"challenge", "credential", "assertion"}
    if set(authorization) != required:
        raise AuthorityServiceError("WebAuthn authorization is not closed")
    challenge = authorization["challenge"]
    credential = authorization["credential"]
    assertion = authorization["assertion"]
    if not all(
        isinstance(value, dict)
        for value in (challenge, credential, assertion)
    ):
        raise AuthorityServiceError("WebAuthn authorization is invalid")
    webauthn = configuration.payload.get("webauthn")
    now_ns = time.time_ns()
    if (
        not isinstance(webauthn, dict)
        or challenge.get("operationId") != expected_operation_id
        or challenge.get("rpId") != webauthn.get("rpId")
        or challenge.get("origin") != webauthn.get("origin")
        or not isinstance(challenge.get("issuedAtEpochNs"), int)
        or not isinstance(challenge.get("expiresAtEpochNs"), int)
        or challenge["issuedAtEpochNs"] > now_ns
        or challenge["expiresAtEpochNs"] <= now_ns
        or challenge["expiresAtEpochNs"] - challenge["issuedAtEpochNs"]
        > int(webauthn.get("maximumChallengeAgeNs", 0))
        or assertion.get("credentialId") != credential.get("credentialId")
        or credential.get("rpId") != webauthn.get("rpId")
        or credential.get("origin") != webauthn.get("origin")
        or credential.get("authenticatorClass")
        not in webauthn.get("allowedAuthenticatorClasses", [])
        or (
            bool(webauthn.get("requireAttestationTrusted", True))
            and credential.get("attestationTrusted") is not True
        )
        or credential.get("revoked") is not False
    ):
        raise AuthorityServiceError("WebAuthn binding is invalid")
    client_data_raw = _b64url_decode(assertion.get("clientDataJSON"))
    authenticator_data = _b64url_decode(assertion.get("authenticatorData"))
    signature = _b64url_decode(assertion.get("signature"))
    try:
        client_data = json.loads(client_data_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityServiceError(
            "WebAuthn client data is invalid"
        ) from exc
    expected_challenge = challenge.get("challenge")
    if (
        not isinstance(client_data, dict)
        or set(client_data) != {
            "type",
            "challenge",
            "origin",
            "crossOrigin",
        }
        or client_data.get("type") != "webauthn.get"
        or client_data.get("challenge") != expected_challenge
        or client_data.get("origin") != webauthn.get("origin")
        or client_data.get("crossOrigin") is not False
        or len(authenticator_data) < 37
    ):
        raise AuthorityServiceError("WebAuthn client binding is invalid")
    expected_rp_hash = hashlib.sha256(
        str(webauthn["rpId"]).encode("utf-8")
    ).digest()
    flags = authenticator_data[32]
    counter = int.from_bytes(authenticator_data[33:37], "big")
    prior_counter = credential.get("signCount")
    if (
        authenticator_data[:32] != expected_rp_hash
        or flags & 0x01 == 0
        or flags & 0x04 == 0
        or not isinstance(prior_counter, int)
        or counter <= prior_counter
        or counter > 2_147_483_647
    ):
        raise AuthorityServiceError(
            "WebAuthn RP, UP, UV, or counter binding is invalid"
        )
    cose_raw = _b64url_decode(credential.get("publicKeyCoseBase64Url"))
    try:
        cose = cbor2.loads(cose_raw)
        if (
            not isinstance(cose, dict)
            or cose.get(1) != 2
            or cose.get(3) != -7
            or cose.get(-1) != 1
            or not isinstance(cose.get(-2), bytes)
            or not isinstance(cose.get(-3), bytes)
            or len(cose[-2]) != 32
            or len(cose[-3]) != 32
        ):
            raise ValueError("unsupported WebAuthn COSE key")
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b"\x04" + cose[-2] + cose[-3]
        )
        public_key.verify(
            signature,
            authenticator_data + hashlib.sha256(client_data_raw).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
    except (
        ValueError,
        TypeError,
        cbor2.CBORDecodeError,
        InvalidSignature,
    ) as exc:
        raise AuthorityServiceError(
            "WebAuthn assertion signature is invalid"
        ) from exc
    receipt = {
        "schema": "serverware.policyAuthorityWebAuthnReceipt/v1",
        "operationId": expected_operation_id,
        "challengeDigest": _sha256(_canonical(challenge)),
        "challengeId": challenge["challengeId"],
        "challengeRowDigest": challenge["challengeRowDigest"],
        "credentialRecordId": credential["credentialRecordId"],
        "credentialId": credential["credentialId"],
        "credentialBindingDigest":
            credential["credentialBindingDigest"],
        "credentialPolicyDigest": _require_digest(
            credential.get("credentialPolicyDigest"),
            "WebAuthn credential policy digest",
        ),
        "trustHighWaterDigest": _require_digest(
            credential.get("trustHighWaterDigest"),
            "WebAuthn trust high-water digest",
        ),
        "clientDataJSONDigest": _sha256(client_data_raw),
        "authenticatorDataDigest": _sha256(authenticator_data),
        "signatureDigest": _sha256(signature),
        "flags": flags,
        "priorCounter": prior_counter,
        "counter": counter,
        "userPresent": True,
        "userVerified": True,
        "verifiedAtEpochNs": now_ns,
    }
    receipt_digest = _domain_digest(
        "serverware.policyAuthorityWebAuthnReceipt/v1",
        _canonical(receipt),
    )
    return receipt, receipt_digest


def _authorization_arguments(
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    excluded = {
        "authn",
        "authn_evidence",
        "webauthn_authorization",
        "challenge_id",
    }
    return {
        key: value
        for key, value in sorted(arguments.items())
        if key not in excluded
    }


def _synthesize_business_arguments(
    operation: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    if "businessIntent" in arguments:
        raise AuthorityServiceError(
            "caller-supplied authority businessIntent is forbidden"
        )
    try:
        intent = authority_contract.synthesize_business_intent(
            operation,
            arguments,
        )
    except ValueError as exc:
        raise AuthorityServiceError(
            "authority businessIntent synthesis failed"
        ) from exc
    return {
        **dict(arguments),
        "businessIntent": intent,
    }


def _controlled_writer_request_digest(
    operation: str,
    arguments: Mapping[str, Any],
) -> str:
    spec = authority_contract.operation_spec(operation)
    synthesized_arguments = _synthesize_business_arguments(
        operation,
        arguments,
    )
    return _domain_digest(
        "serverware.policyAuthorityV9Request/v1",
        _canonical(
            {
                "schema":
                    "serverware.policyAuthorityV9Authorization/v1",
                "operation": operation,
                "handler": spec["handler"],
                "operationManifestDigest":
                    authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": _authorization_arguments(
                    synthesized_arguments
                ),
            }
        ),
    )


class AuthorityRuntimeClient:
    def __init__(
        self,
        *,
        socket_path: str,
        timeout_seconds: float,
        response_key: Ed25519PublicKey,
        configuration_digest: str,
        server_uid: int,
        server_gid: int,
        maximum_deadline_ns: int,
        operation_manifest_digest: str,
        attestation_receipt_digest: str,
        attestation_evidence: dict[str, Any],
        attestation_verification_policy: dict[str, Any],
        verifier_socket_path: str,
        verifier_uid: int,
        verifier_gid: int,
        control_plane_uid: int,
        control_plane_gid: int,
    ) -> None:
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds
        self.response_key = response_key
        self.configuration_digest = configuration_digest
        self.server_uid = server_uid
        self.server_gid = server_gid
        self.maximum_deadline_ns = maximum_deadline_ns
        self.operation_manifest_digest = operation_manifest_digest
        self.attestation_receipt_digest = attestation_receipt_digest
        self.attestation_evidence = dict(attestation_evidence)
        self.attestation_verification_policy = dict(
            attestation_verification_policy
        )
        self.verifier_socket_path = verifier_socket_path
        self.verifier_uid = verifier_uid
        self.verifier_gid = verifier_gid
        self.control_plane_uid = control_plane_uid
        self.control_plane_gid = control_plane_gid

    @classmethod
    def from_environment(
        cls, *, hot_runtime: bool = False
    ) -> "AuthorityRuntimeClient":
        process_mode = os.environ.get(
            "SERVERWARE_PROCESS_MODE", ""
        ).strip()
        expected_mode = (
            RUNTIME_RELAY_PROCESS_MODE
            if hot_runtime
            else "serverware-control-plane"
        )
        if process_mode != expected_mode:
            raise AuthorityServiceError(
                "authority runtime client process identity is invalid"
            )
        forbidden_environment = {
            name
            for name, value in os.environ.items()
            if value.strip()
            and (
                name in PRIVILEGED_DSN_ENVIRONMENTS
                or name in VERIFIER_SIGNING_KEY_ENVIRONMENTS
                or name in RELEASE_CONSUMER_KEY_ENVIRONMENTS
                or name in {
                    "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
                    "SERVERWARE_POLICY_AUTHORITY_CONFIG_PATH",
                    "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
                    "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_PATH",
                }
                or hot_runtime
                and (
                    name.endswith("_POSTGRES_DSN")
                    or name.endswith("_DATABASE_URL")
                    or name in {
                        "DATABASE_URL",
                        "PGHOST",
                        "PGPORT",
                        "PGDATABASE",
                        "PGUSER",
                        "PGPASSWORD",
                        "PGPASSFILE",
                    }
                )
            )
        }
        if forbidden_environment:
            raise AuthorityServiceError(
                "hot runtime contains a database or privileged authority "
                "credential"
            )
        root_value = _read_bounded_descriptor(
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY",
            maximum=64 * 1024,
            require_root_owned=True,
            require_descriptor=True,
        )
        trust_value = _read_bounded_descriptor(
            "SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST",
            maximum=MAX_RUNTIME_TRUST_BYTES,
            require_root_owned=True,
            require_descriptor=True,
        )
        root_key = _load_ed25519_public_key(root_value)
        try:
            envelope = json.loads(trust_value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorityServiceError(
                "authority runtime trust is not JSON"
            ) from exc
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"schema", "payload", "signature"}
            or envelope.get("schema") != SIGNED_RUNTIME_TRUST_SCHEMA
            or not isinstance(envelope.get("payload"), dict)
        ):
            raise AuthorityServiceError(
                "authority runtime trust envelope is not closed"
            )
        payload = dict(envelope["payload"])
        try:
            root_key.verify(
                _b64url_decode(envelope["signature"], size=64),
                _domain_digest(
                    SIGNED_RUNTIME_TRUST_SCHEMA, _canonical(payload)
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "authority runtime trust signature is invalid"
            ) from exc
        required_payload_fields = {
            "schema",
            "sourceRevision",
            "configurationDigest",
            "operationManifestDigest",
            "relaySocketPath",
            "relayServiceUid",
            "relayServiceGid",
            "verifierSocketPath",
            "verifierServiceUid",
            "verifierServiceGid",
            "controlPlaneUid",
            "controlPlaneGid",
            "verifierSigningPublicKeyBase64Url",
            "maximumDeadlineNs",
            "attestationReceiptDigest",
            "attestationEvidence",
            "attestationVerificationPolicy",
            "trustMode",
            "controlPlaneInheritedFileDescriptors",
            "relayInheritedFileDescriptors",
        }
        allowed_descriptors = payload.get(
            (
                "relayInheritedFileDescriptors"
                if hot_runtime
                else "controlPlaneInheritedFileDescriptors"
            )
        )
        if (
            set(payload) != required_payload_fields
            or payload.get("schema") != RUNTIME_TRUST_SCHEMA
            or payload.get("sourceRevision") != SOURCE_REVISION
            or payload.get("operationManifestDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
            or payload.get("trustMode") != "trusted-host-local"
            or not isinstance(payload.get("relaySocketPath"), str)
            or not Path(payload["relaySocketPath"]).is_absolute()
            or not isinstance(payload.get("verifierSocketPath"), str)
            or not Path(payload["verifierSocketPath"]).is_absolute()
            or payload["relaySocketPath"]
                == payload["verifierSocketPath"]
            or any(
                not isinstance(payload.get(field), int)
                or isinstance(payload.get(field), bool)
                or payload[field] < 0
                for field in (
                    "relayServiceUid",
                    "relayServiceGid",
                    "verifierServiceUid",
                    "verifierServiceGid",
                    "controlPlaneUid",
                    "controlPlaneGid",
                )
            )
            or len(
                {
                    (
                        payload["relayServiceUid"],
                        payload["relayServiceGid"],
                    ),
                    (
                        payload["verifierServiceUid"],
                        payload["verifierServiceGid"],
                    ),
                    (
                        payload["controlPlaneUid"],
                        payload["controlPlaneGid"],
                    ),
                }
            )
                != 3
            or (
                (
                    int(payload["relayServiceUid"]),
                    int(payload["relayServiceGid"]),
                )
                if hot_runtime
                else (
                    int(payload["controlPlaneUid"]),
                    int(payload["controlPlaneGid"]),
                )
            )
                != (os.geteuid(), os.getegid())
            or not isinstance(payload.get("maximumDeadlineNs"), int)
            or not 1_000_000
            <= payload["maximumDeadlineNs"]
            <= 30_000_000_000
            or _require_digest(
                payload.get("configurationDigest"),
                "runtime configuration digest",
            )
            != payload.get("configurationDigest")
            or _require_digest(
                payload.get("attestationReceiptDigest"),
                "runtime attestation receipt digest",
            )
            != payload.get("attestationReceiptDigest")
            or not isinstance(payload.get("attestationEvidence"), dict)
            or not isinstance(
                payload.get("attestationVerificationPolicy"), dict
            )
            or (
                isinstance(payload.get("attestationEvidence"), dict)
                and payload["attestationEvidence"].get("schema")
                    != TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA
            )
            or not isinstance(allowed_descriptors, list)
            or not isinstance(
                payload.get(
                    "controlPlaneInheritedFileDescriptors"
                ),
                list,
            )
            or not isinstance(
                payload.get("relayInheritedFileDescriptors"),
                list,
            )
            or any(
                any(
                    not isinstance(descriptor, int)
                    or isinstance(descriptor, bool)
                    or descriptor < 3
                    for descriptor in payload[field]
                )
                or len(set(payload[field]))
                    != len(payload[field])
                for field in (
                    "controlPlaneInheritedFileDescriptors",
                    "relayInheritedFileDescriptors",
                )
            )
            or any(
                not isinstance(descriptor, int)
                or isinstance(descriptor, bool)
                or descriptor < 3
                for descriptor in allowed_descriptors
            )
            or len(set(allowed_descriptors)) != len(allowed_descriptors)
            or _open_inherited_descriptors()
            != set(allowed_descriptors)
        ):
            raise AuthorityServiceError(
                "hot runtime inherited descriptor set is not exact"
            )
        response_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                payload.get("verifierSigningPublicKeyBase64Url"), size=32
            )
        )
        attestation_evidence = _verify_public_attestation_evidence(
            evidence=payload["attestationEvidence"],
            policy=payload["attestationVerificationPolicy"],
            expected_receipt_digest=
                payload["attestationReceiptDigest"],
            expected_configuration_digest=
                payload["configurationDigest"],
            expected_response_spki_digest=
                _public_spki_digest(response_key),
        )
        return cls(
            socket_path=payload["relaySocketPath"],
            timeout_seconds=(
                float(payload["maximumDeadlineNs"]) / 1_000_000_000
            ),
            response_key=response_key,
            configuration_digest=payload["configurationDigest"],
            server_uid=int(payload["relayServiceUid"]),
            server_gid=int(payload["relayServiceGid"]),
            maximum_deadline_ns=int(payload["maximumDeadlineNs"]),
            operation_manifest_digest=payload[
                "operationManifestDigest"
            ],
            attestation_receipt_digest=payload[
                "attestationReceiptDigest"
            ],
            attestation_evidence=attestation_evidence,
            attestation_verification_policy=
                payload["attestationVerificationPolicy"],
            verifier_socket_path=payload["verifierSocketPath"],
            verifier_uid=int(payload["verifierServiceUid"]),
            verifier_gid=int(payload["verifierServiceGid"]),
            control_plane_uid=int(payload["controlPlaneUid"]),
            control_plane_gid=int(payload["controlPlaneGid"]),
        )

    def request(
        self, *, operation: str, input_value: Mapping[str, Any]
    ) -> Any:
        if (
            operation
            not in authority_transition_registry.PLANNABLE_OPERATIONS
        ):
            raise AuthorityServiceError(
                "runtime authority operation has no exact transition program"
            )
        started_monotonic_ns = time.monotonic_ns()
        deadline_monotonic_ns = (
            started_monotonic_ns + self.maximum_deadline_ns
        )
        request_id = _domain_digest(
            "serverware.policyAuthorityRuntimeRequestId/v1",
            operation.encode("ascii"),
            _canonical(dict(input_value)),
            os.urandom(32),
        )
        request = {
            "schema": RUNTIME_REQUEST_SCHEMA,
            "requestId": request_id,
            "operation": operation,
            "input": dict(input_value),
            "configurationDigest": self.configuration_digest,
            "operationManifestDigest": self.operation_manifest_digest,
            "startedMonotonicNs": started_monotonic_ns,
            "deadlineMonotonicNs": deadline_monotonic_ns,
        }
        response = _socket_request(
            self.socket_path,
            request,
            timeout_seconds=self.timeout_seconds,
            expected_peer_uid=self.server_uid,
            expected_peer_gid=self.server_gid,
        )
        signature = _b64url_decode(response.get("signature"), size=64)
        unsigned = dict(response)
        unsigned.pop("signature", None)
        consumption_receipt = response.get(
            "attestationConsumptionReceipt"
        )
        if not isinstance(consumption_receipt, dict):
            raise AuthorityServiceError(
                "authority response lacks attestation consumption"
            )
        consumption_digest = _verify_public_attestation_consumption(
            receipt=consumption_receipt,
            evidence=self.attestation_evidence,
            policy=self.attestation_verification_policy,
            expected_attestation_receipt_digest=
                self.attestation_receipt_digest,
        )
        if (
            set(response)
            != {
                "schema",
                "requestId",
                "operation",
                "configurationDigest",
                "requestDigest",
                "issuedAtEpochNs",
                "deadlineMonotonicNs",
                "fence",
                "result",
                "resultDigest",
                "commitReceiptDigest",
                "witnessCommitDigest",
                "attestationReceiptDigest",
                "attestationConsumptionReceipt",
                "attestationConsumptionReceiptDigest",
                "signature",
            }
            or response.get("schema") != RUNTIME_RESPONSE_SCHEMA
            or response.get("requestId") != request_id
            or response.get("operation") != operation
            or response.get("configurationDigest")
            != self.configuration_digest
            or response.get("requestDigest") != _domain_digest(
                RUNTIME_REQUEST_SCHEMA, _canonical(request)
            )
            or response.get("attestationReceiptDigest")
            != self.attestation_receipt_digest
            or response.get(
                "attestationConsumptionReceiptDigest"
            ) != consumption_digest
            or not isinstance(response.get("resultDigest"), str)
            or not isinstance(response.get("commitReceiptDigest"), str)
            or response.get("deadlineMonotonicNs")
            != deadline_monotonic_ns
            or not isinstance(response.get("fence"), int)
            or response["fence"] < 1
            or time.monotonic_ns() >= deadline_monotonic_ns
        ):
            raise AuthorityServiceError(
                "authority runtime response is not closed"
            )
        try:
            self.response_key.verify(
                signature,
                _domain_digest(
                    RUNTIME_RESPONSE_SCHEMA, _canonical(unsigned)
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "authority runtime response signature is invalid"
            ) from exc
        return response["result"]


class AuthorityRuntimeRelay:
    def __init__(self, trust: AuthorityRuntimeClient) -> None:
        self.trust = trust
        self.socket_path = Path(trust.socket_path)
        self.socket = _activated_listener(
            socket_path=str(self.socket_path),
            service_uid=int(trust.server_uid),
            service_gid=int(trust.server_gid),
        )
        self.pool = ThreadPoolExecutor(
            max_workers=32,
            thread_name_prefix="authority-runtime-relay",
        )
        self.in_flight = threading.BoundedSemaphore(256)

    def serve_forever(self) -> None:
        while True:
            connection, _ = self.socket.accept()
            if not self.in_flight.acquire(blocking=False):
                connection.close()
                continue
            future = self.pool.submit(
                self._serve_connection,
                connection,
            )
            future.add_done_callback(
                lambda _future: self.in_flight.release()
            )

    def _serve_connection(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(self.trust.timeout_seconds)
            uid, gid, _pid = _peer_identity(connection)
            if (
                uid != self.trust.control_plane_uid
                or gid != self.trust.control_plane_gid
            ):
                raise AuthorityServiceError(
                    "authority relay peer identity is not allowed"
                )
            request = _recv_message(connection)
            now_monotonic_ns = time.monotonic_ns()
            if (
                set(request)
                != {
                    "schema",
                    "requestId",
                    "operation",
                    "input",
                    "configurationDigest",
                    "operationManifestDigest",
                    "startedMonotonicNs",
                    "deadlineMonotonicNs",
                }
                or request.get("schema") != RUNTIME_REQUEST_SCHEMA
                or not isinstance(request.get("requestId"), str)
                or _require_digest(
                    request["requestId"],
                    "runtime request ID",
                )
                    != request["requestId"]
                or request.get("operation")
                    not in authority_contract.OPERATIONS
                or not isinstance(request.get("input"), dict)
                or request.get("configurationDigest")
                    != self.trust.configuration_digest
                or request.get("operationManifestDigest")
                    != self.trust.operation_manifest_digest
                or not isinstance(
                    request.get("startedMonotonicNs"), int
                )
                or not isinstance(
                    request.get("deadlineMonotonicNs"), int
                )
                or request["startedMonotonicNs"]
                    > now_monotonic_ns
                or now_monotonic_ns
                    >= request["deadlineMonotonicNs"]
                or request["deadlineMonotonicNs"]
                    - request["startedMonotonicNs"]
                    > self.trust.maximum_deadline_ns
                or len(_canonical(request))
                    > authority_contract.MAX_REQUEST_BYTES
            ):
                raise AuthorityServiceError(
                    "authority relay request is not closed"
                )
            remaining_seconds = (
                request["deadlineMonotonicNs"]
                - time.monotonic_ns()
            ) / 1_000_000_000
            if remaining_seconds <= 0:
                raise AuthorityServiceError(
                    "authority relay request deadline expired"
                )
            response = _socket_request(
                self.trust.verifier_socket_path,
                request,
                timeout_seconds=min(
                    self.trust.timeout_seconds,
                    remaining_seconds,
                ),
                expected_peer_uid=self.trust.verifier_uid,
                expected_peer_gid=self.trust.verifier_gid,
            )
            if time.monotonic_ns() >= request["deadlineMonotonicNs"]:
                raise AuthorityServiceError(
                    "authority relay response was late"
                )
            _send_message(connection, response)
        except Exception as exc:
            try:
                _send_message(
                    connection,
                    {
                        "schema":
                            "serverware.policyAuthorityError/v1",
                        "code": "authority_denied",
                        "detailDigest": _sha256(
                            str(exc).encode("utf-8")
                        ),
                    },
                )
            except Exception:
                pass
        finally:
            connection.close()


class AuthorityProcess:
    def __init__(
        self, *, role: str, configuration: MeasuredConfiguration
    ) -> None:
        self.role_name = role
        self.process_mode = PROCESS_MODES[role]
        self.configuration = configuration
        self.role_config = configuration.role(role)
        if (
            os.getuid() != int(self.role_config["serviceUid"])
            or os.getgid() != int(self.role_config["serviceGid"])
        ):
            raise AuthorityServiceError(
                "authority service OS identity is not exact"
            )
        self.signing_key: Ed25519PrivateKey | None = None
        launch_descriptors = dict(
            authority_launch_guard.launch_identity_descriptors()
        )
        try:
            launch_private_descriptor = int(
                launch_descriptors["privateKey"]
            )
            launch_certificate_descriptor = int(
                launch_descriptors["certificate"]
            )
            with os.fdopen(
                os.dup(launch_private_descriptor),
                "rb",
                closefd=True,
            ) as handle:
                launch_private_value = handle.read(64 * 1024 + 1)
            with os.fdopen(
                os.dup(launch_certificate_descriptor),
                "rb",
                closefd=True,
            ) as handle:
                launch_certificate_value = handle.read(
                    MAX_CONFIG_BYTES + 1
                )
        except (KeyError, OSError, ValueError) as exc:
            raise AuthorityServiceError(
                "stage-zero launch identity descriptors are invalid"
            ) from exc
        if (
            len(launch_private_value) > 64 * 1024
            or len(launch_certificate_value) > MAX_CONFIG_BYTES
        ):
            raise AuthorityServiceError(
                "stage-zero launch identity exceeds its bound"
            )
        self.launch_identity_key = _load_ed25519_private_key(
            launch_private_value
        )
        try:
            launch_certificate = json.loads(launch_certificate_value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorityServiceError(
                "stage-zero launch certificate is not JSON"
            ) from exc
        if (
            not isinstance(launch_certificate, dict)
            or _canonical(launch_certificate)
                != launch_certificate_value
            or not isinstance(launch_certificate.get("payload"), dict)
        ):
            raise AuthorityServiceError(
                "stage-zero launch certificate is not canonical"
            )
        launch_payload = launch_certificate["payload"]
        launch_public = self.launch_identity_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        generation = dict(authority_launch_guard.generation())
        launch_assurance = dict(
            authority_launch_guard.launch_assurance()
        )
        if (
            launch_payload.get("role") != role
            or launch_payload.get("generationDigest")
                != generation.get("digest")
            or launch_payload.get("trustMode")
                != launch_assurance.get("trustMode")
            or launch_payload.get("coLocated")
                is not launch_assurance.get("coLocated")
            or launch_payload.get("hardwareBacked")
                is not launch_assurance.get("hardwareBacked")
            or _b64url_decode(
                launch_payload.get("launchPublicKeyBase64Url"),
                size=32,
            )
                != launch_public
        ):
            raise AuthorityServiceError(
                "stage-zero launch identity binding changed"
            )
        self.launch_identity_certificate = launch_certificate
        self.launch_identity_certificate_digest = _domain_digest(
            "serverware.authorityLaunchIdentityCertificateDigest/v1",
            launch_certificate_value,
        )
        if role == "verifier":
            private_value = _read_bounded_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SIGNING_KEY",
                maximum=64 * 1024,
                require_root_owned=True,
                require_descriptor=True,
            )
            self.signing_key = _load_ed25519_private_key(private_value)
            expected = self.role_config.get("signingSpkiDigest")
            if _public_spki_digest(self.signing_key.public_key()) != expected:
                raise AuthorityServiceError(
                    "verifier signing key does not match measured config"
                )
        elif role == "planner":
            private_value = _read_bounded_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY",
                maximum=64 * 1024,
                require_root_owned=True,
                require_descriptor=True,
            )
            self.signing_key = _load_ed25519_private_key(private_value)
            if (
                _public_spki_digest(self.signing_key.public_key())
                != self.role_config.get("signingSpkiDigest")
            ):
                raise AuthorityServiceError(
                    "planner signing key does not match measured config"
                )
        self._reject_wrong_credentials()
        if authority_launch_guard.launch_assurance().get(
            "trustMode"
        ) == "trusted-host-local":
            self.attestation_consumption_receipt = (
                self._trusted_host_local_consumption_receipt()
            )
        else:
            self.attestation_consumption_receipt = (
                self._consume_attestation_release()
            )

    def _trusted_host_local_consumption_receipt(
        self,
    ) -> dict[str, Any]:
        evidence = self.configuration.attestation_evidence
        assurance = dict(authority_launch_guard.launch_assurance())
        generation = dict(authority_launch_guard.generation())
        if (
            not isinstance(evidence, dict)
            or evidence.get("schema")
                != TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA
            or assurance
                != {
                    "schema": "serverware.authorityLaunchAssurance/v1",
                    "trustMode": "trusted-host-local",
                    "coLocated": True,
                    "hardwareBacked": False,
                    "nativeStageZero": False,
                    "hsmBackedKeys": False,
                    "teeVerified": False,
                    "externalWitnessVerified": False,
                }
        ):
            raise AuthorityServiceError(
                "trusted-host-local consumption prerequisites changed"
            )
        unsigned = {
            "schema": TRUSTED_HOST_LOCAL_CONSUMPTION_SCHEMA,
            "role": self.role_name,
            "configurationDigest": self.configuration.digest,
            "generationDigest": generation["digest"],
            "launchIdentityCertificateDigest":
                self.launch_identity_certificate_digest,
            "attestationReceiptDigest":
                self.role_config["attestationReceiptDigest"],
            "trustMode": "trusted-host-local",
            "coLocated": True,
            "hardwareBacked": False,
            "nativeStageZero": False,
            "hsmBackedKeys": False,
            "teeVerified": False,
            "externalWitnessVerified": False,
            "issuedAtEpochNs": time.time_ns(),
            "signerPurpose": (
                "verifier-response-key"
                if self.role_name == "verifier"
                else "launch-identity-key"
            ),
        }
        signing_key = (
            self.signing_key
            if self.role_name == "verifier"
            else self.launch_identity_key
        )
        if signing_key is None:
            raise AuthorityServiceError(
                "trusted-host-local consumption signer is unavailable"
            )
        return {
            **unsigned,
            "signature": _b64url_encode(
                signing_key.sign(
                    _domain_digest(
                        TRUSTED_HOST_LOCAL_CONSUMPTION_SCHEMA,
                        _canonical(unsigned),
                    ).encode("ascii")
                )
            ),
        }

    def _reject_wrong_credentials(self) -> None:
        allowed = {
            "verifier": {
                "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD"
            },
            "planner": {
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD"
            },
            "planner-writer": {
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD"
            },
            "issuer": {
                "SERVERWARE_POLICY_AUTHORITY_CAPABILITY_ISSUER_POSTGRES_DSN_FD"
            },
            "executor": {
                "SERVERWARE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD"
            },
        }[self.role_name]
        for name in PRIVILEGED_DSN_ENVIRONMENTS:
            present = bool(os.environ.get(name, "").strip())
            if present != (name in allowed):
                raise AuthorityServiceError(
                    "authority role credential set is not exact"
                )
        if any(
            os.environ.get(name, "").strip()
            for name in RELEASE_CONSUMER_KEY_ENVIRONMENTS
        ):
            raise AuthorityServiceError(
                "static credential-release consumer keys are forbidden"
            )
        signing_descriptor = bool(
            os.environ.get(
                "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SIGNING_KEY_FD", ""
            ).strip()
        )
        signing_path = bool(
            os.environ.get(
                "SERVERWARE_POLICY_AUTHORITY_VERIFIER_SIGNING_KEY_PATH", ""
            ).strip()
        )
        if (
            self.role_name == "verifier"
            and (not signing_descriptor or signing_path)
        ) or (
            self.role_name != "verifier"
            and (signing_descriptor or signing_path)
        ):
            raise AuthorityServiceError(
                "authority verifier signer credential set is not exact"
            )
        planner_signing_descriptor = bool(
            os.environ.get(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY_FD", ""
            ).strip()
        )
        planner_signing_path = bool(
            os.environ.get(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY_PATH", ""
            ).strip()
        )
        if (
            self.role_name == "planner"
            and (not planner_signing_descriptor or planner_signing_path)
        ) or (
            self.role_name != "planner"
            and (planner_signing_descriptor or planner_signing_path)
        ):
            raise AuthorityServiceError(
                "authority planner signer credential set is not exact"
            )

    def _consume_attestation_release(self) -> dict[str, Any]:
        evidence = self.configuration.attestation_evidence
        witness_config = self.configuration.payload.get("replayWitness")
        generation = dict(authority_launch_guard.generation())
        if (
            not isinstance(evidence, dict)
            or not isinstance(witness_config, dict)
            or not isinstance(
                evidence.get("releaseWitnessReceipt"), dict
            )
        ):
            raise AuthorityServiceError(
                "credential-release consumption evidence is unavailable"
            )
        predecessor = dict(evidence["releaseWitnessReceipt"])
        predecessor_digest = _domain_digest(
            WITNESS_RECEIPT_SCHEMA_V2,
            _canonical(predecessor),
        )
        deadline_monotonic_ns = predecessor.get(
            "deadlineMonotonicNs"
        )
        authorization_projection_digest = _domain_digest(
            "serverware.policyAuthorityCredentialRelease"
            "AuthorizationProjection/v1",
            self.configuration.digest.encode("ascii"),
            self.role_name.encode("ascii"),
            self.role_config["attestationReceiptDigest"].encode(
                "ascii"
            ),
            str(generation.get("digest", "")).encode("ascii"),
        )
        launch_payload = self.launch_identity_certificate["payload"]
        consumer_launch_id = launch_payload.get("launchId")
        consumer_launch_key_id = _domain_digest(
            "serverware.authorityLaunchPublicKey/v1",
            _b64url_decode(
                launch_payload.get("launchPublicKeyBase64Url"),
                size=32,
            ),
        )
        transition_material = {
            "predecessorReceiptDigest": predecessor_digest,
            "operation": self.role_name,
            "requestDigest": predecessor.get("requestDigest"),
            "capabilityId": predecessor.get("capabilityId"),
            "resultDigest":
                self.role_config["attestationReceiptDigest"],
            "authorizationProjectionDigest":
                authorization_projection_digest,
            "generationDigest": generation.get("digest"),
            "consumerLaunchId": consumer_launch_id,
            "consumerLaunchKeyId": consumer_launch_key_id,
            "consumerLaunchCertificateDigest":
                self.launch_identity_certificate_digest,
        }
        transition_id = _domain_digest(
            "serverware.policyAuthorityCredentialReleaseTransition/v1",
            _canonical(transition_material),
        )
        if (
            predecessor.get("schema") != WITNESS_RECEIPT_SCHEMA_V2
            or predecessor.get("phase") != "credential-release"
            or predecessor.get("operation") != self.role_name
            or predecessor.get("generationSequence")
                != generation.get("sequence")
            or predecessor.get("generationDigest")
                != generation.get("digest")
            or not isinstance(deadline_monotonic_ns, int)
            or time.monotonic_ns() >= deadline_monotonic_ns
        ):
            raise AuthorityServiceError(
                "credential-release v2 receipt cannot be consumed"
            )
        issued_at_epoch_ns = time.time_ns()
        envelope_material = {
            "phase": "credential-release-consume",
            "operation": self.role_name,
            "requestDigest": predecessor["requestDigest"],
            "capabilityId": predecessor["capabilityId"],
            "resultDigest":
                self.role_config["attestationReceiptDigest"],
            "predecessorReceiptDigest": predecessor_digest,
            "generationSequence": generation["sequence"],
            "generationDigest": generation["digest"],
        }
        unsigned_request = {
            "schema": WITNESS_REQUEST_SCHEMA_V2,
            "envelopeId": _witness_envelope_id(envelope_material),
            "parentEnvelopeId": predecessor_digest,
            "phase": "credential-release-consume",
            "operation": self.role_name,
            "requestDigest": predecessor["requestDigest"],
            "capabilityId": predecessor["capabilityId"],
            "resultDigest":
                self.role_config["attestationReceiptDigest"],
            "predecessorReceiptDigest": predecessor_digest,
            "deadlineMonotonicNs": deadline_monotonic_ns,
            "configurationDigest": self.configuration.digest,
            "operationManifestDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "generationSequence": generation["sequence"],
            "generationDigest": generation["digest"],
            "issuedAtEpochNs": issued_at_epoch_ns,
            "transitionId": transition_id,
            "authorizationProjectionDigest":
                authorization_projection_digest,
            "launchIdentityCertificate":
                self.launch_identity_certificate,
            "launchIdentityCertificateDigest":
                self.launch_identity_certificate_digest,
            "launchStageZeroRequest":
                dict(authority_launch_guard.stage_zero_request()),
            "launchArtifactPackage":
                dict(authority_launch_guard.artifact_package()),
            "launchArtifactTrustState":
                dict(authority_launch_guard.artifact_trust_state()),
        }
        request = {
            **unsigned_request,
            "signature": _b64url_encode(
                self.launch_identity_key.sign(
                    _domain_digest(
                        WITNESS_REQUEST_SCHEMA_V2,
                        _canonical(unsigned_request),
                    ).encode("ascii")
                )
            ),
        }
        response = _socket_request(
            str(witness_config["socketPath"]),
            request,
            timeout_seconds=min(
                float(witness_config["requestTimeoutSeconds"]),
                max(
                    0.001,
                    (
                        deadline_monotonic_ns - time.monotonic_ns()
                    ) / 1_000_000_000,
                ),
            ),
            expected_peer_uid=int(witness_config["serviceUid"]),
            expected_peer_gid=int(witness_config["serviceGid"]),
        )
        unsigned_response = dict(response)
        signature = _b64url_decode(
            unsigned_response.pop("signature", None),
            size=64,
        )
        required = {
            "schema",
            "envelopeId",
            "parentEnvelopeId",
            "phase",
            "operation",
            "requestDigest",
            "capabilityId",
            "resultDigest",
            "witnessIdentityDigest",
            "sequence",
            "fence",
            "headDigest",
            "predecessorHeadDigest",
            "predecessorReceiptDigest",
            "logPredecessorHeadDigest",
            "deadlineMonotonicNs",
            "issuedAtEpochNs",
            "generationSequence",
            "generationDigest",
            "canonicalRequestDigest",
            "transitionId",
            "authorizationProjectionDigest",
            "consumerLaunchId",
            "consumerLaunchKeyId",
            "consumerLaunchCertificateDigest",
            "signature",
        }
        head_material = dict(unsigned_response)
        head_material["headDigest"] = None
        if (
            set(response) != required
            or response.get("schema") != WITNESS_RECEIPT_SCHEMA_V2
            or response.get("phase") != "credential-release-consume"
            or response.get("envelopeId")
                != unsigned_request["envelopeId"]
            or response.get("parentEnvelopeId")
                != predecessor_digest
            or response.get("operation") != self.role_name
            or response.get("requestDigest")
                != predecessor.get("requestDigest")
            or response.get("capabilityId")
                != predecessor.get("capabilityId")
            or response.get("resultDigest")
                != self.role_config["attestationReceiptDigest"]
            or response.get("witnessIdentityDigest")
                != witness_config.get("identityDigest")
            or response.get("predecessorReceiptDigest")
                != predecessor_digest
            or response.get("predecessorHeadDigest")
                != predecessor.get("headDigest")
            or response.get("fence") != predecessor.get("fence")
            or response.get("deadlineMonotonicNs")
                != deadline_monotonic_ns
            or response.get("generationSequence")
                != generation.get("sequence")
            or response.get("generationDigest")
                != generation.get("digest")
            or response.get("canonicalRequestDigest")
                != _domain_digest(
                    WITNESS_REQUEST_SCHEMA_V2,
                    _canonical(request),
                )
            or response.get("transitionId") != transition_id
            or response.get("authorizationProjectionDigest")
                != authorization_projection_digest
            or response.get("consumerLaunchId")
                != consumer_launch_id
            or response.get("consumerLaunchKeyId")
                != consumer_launch_key_id
            or response.get("consumerLaunchCertificateDigest")
                != self.launch_identity_certificate_digest
            or _require_digest(
                response.get("headDigest"),
                "credential-release v2 head digest",
            )
                != _domain_digest(
                    "serverware.policyAuthorityReplayWitnessHead/v2",
                    _canonical(head_material),
                )
        ):
            raise AuthorityServiceError(
                "credential-release v2 consumption receipt is invalid"
            )
        witness_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                witness_config["signingPublicKeyBase64Url"],
                size=32,
            )
        )
        try:
            witness_key.verify(
                signature,
                _domain_digest(
                    WITNESS_RECEIPT_SCHEMA_V2,
                    _canonical(unsigned_response),
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "credential-release v2 signature is invalid"
            ) from exc
        return dict(response)

    def _consume_attestation_release_v1_disabled(
        self,
    ) -> dict[str, Any]:
        raise AuthorityServiceError(
            "witness v1 credential-release consumption is disabled"
        )
        evidence = self.configuration.attestation_evidence
        witness_config = self.configuration.payload.get(
            "replayWitness"
        )
        if (
            not isinstance(evidence, dict)
            or not isinstance(witness_config, dict)
            or not isinstance(
                evidence.get("releaseWitnessReceipt"), dict
            )
        ):
            raise AuthorityServiceError(
                "credential-release consumption evidence is unavailable"
            )
        predecessor = dict(evidence["releaseWitnessReceipt"])
        predecessor_digest = _domain_digest(
            authority_contract.WITNESS_SCHEMA,
            _canonical(predecessor),
        )
        deadline_monotonic_ns = predecessor.get(
            "deadlineMonotonicNs"
        )
        if (
            predecessor.get("phase") != "credential-release"
            or predecessor.get("operation") != self.role_name
            or not isinstance(deadline_monotonic_ns, int)
            or time.monotonic_ns() >= deadline_monotonic_ns
        ):
            raise AuthorityServiceError(
                "credential-release receipt cannot be consumed"
            )
        unsigned_request = {
            "schema":
                "serverware.policyAuthorityReplayWitnessRequest/v1",
            "phase": "credential-release-consume",
            "operation": self.role_name,
            "requestDigest": predecessor["requestDigest"],
            "capabilityId": predecessor["capabilityId"],
            "resultDigest":
                self.role_config["attestationReceiptDigest"],
            "predecessorReceiptDigest": predecessor_digest,
            "deadlineMonotonicNs": deadline_monotonic_ns,
            "configurationDigest": self.configuration.digest,
            "operationManifestDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "issuedAtEpochNs": time.time_ns(),
        }
        request = {
            **unsigned_request,
            "signature": _b64url_encode(
                self.release_consumer_key.sign(
                    _domain_digest(
                        "serverware.policyAuthorityReplayWitnessRequest/v1",
                        _canonical(unsigned_request),
                    ).encode("ascii")
                )
            ),
        }
        response = _socket_request(
            str(witness_config["socketPath"]),
            request,
            timeout_seconds=min(
                float(witness_config["requestTimeoutSeconds"]),
                max(
                    0.001,
                    (
                        deadline_monotonic_ns - time.monotonic_ns()
                    ) / 1_000_000_000,
                ),
            ),
            expected_peer_uid=int(witness_config["serviceUid"]),
            expected_peer_gid=int(witness_config["serviceGid"]),
        )
        unsigned_response = dict(response)
        signature = _b64url_decode(
            unsigned_response.pop("signature", None),
            size=64,
        )
        head_material = dict(unsigned_response)
        head_material["headDigest"] = None
        if (
            set(response)
            != {
                "schema",
                "phase",
                "operation",
                "requestDigest",
                "capabilityId",
                "resultDigest",
                "witnessIdentityDigest",
                "sequence",
                "fence",
                "headDigest",
                "predecessorHeadDigest",
                "predecessorReceiptDigest",
                "logPredecessorHeadDigest",
                "deadlineMonotonicNs",
                "issuedAtEpochNs",
                "signature",
            }
            or response.get("schema")
                != authority_contract.WITNESS_SCHEMA
            or response.get("phase")
                != "credential-release-consume"
            or response.get("operation") != self.role_name
            or response.get("requestDigest")
                != predecessor.get("requestDigest")
            or response.get("capabilityId")
                != predecessor.get("capabilityId")
            or response.get("resultDigest")
                != self.role_config["attestationReceiptDigest"]
            or response.get("witnessIdentityDigest")
                != witness_config.get("identityDigest")
            or response.get("predecessorReceiptDigest")
                != predecessor_digest
            or response.get("predecessorHeadDigest")
                != predecessor.get("headDigest")
            or response.get("fence") != predecessor.get("fence")
            or response.get("deadlineMonotonicNs")
                != deadline_monotonic_ns
            or not isinstance(response.get("sequence"), int)
            or response["sequence"]
                <= int(predecessor.get("sequence", 0))
            or _require_digest(
                response.get("headDigest"),
                "credential-release consumption head digest",
            )
                != _domain_digest(
                    "serverware.policyAuthorityReplayWitnessHead/v1",
                    _canonical(head_material),
                )
        ):
            raise AuthorityServiceError(
                "credential-release consumption receipt is invalid"
            )
        witness_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                witness_config["signingPublicKeyBase64Url"],
                size=32,
            )
        )
        try:
            witness_key.verify(
                signature,
                _domain_digest(
                    authority_contract.WITNESS_SCHEMA,
                    _canonical(unsigned_response),
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "credential-release consumption signature is invalid"
            ) from exc
        return dict(response)

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if self.role_name == "verifier":
            return self._handle_runtime(request)
        if self.role_name == "planner":
            _purpose, envelope = self._verify_internal_envelope(
                request,
                allowed_purposes={"plan-operation"},
            )
            return self._handle_plan(envelope)
        if self.role_name == "planner-writer":
            purpose, envelope = self._verify_internal_envelope(
                request,
                allowed_purposes={
                    "persist-measured-plan",
                    "read-persisted-plan",
                    "reserve-execution-envelope",
                },
            )
            if purpose == "read-persisted-plan":
                return self._handle_read_persisted_plan(envelope)
            if purpose == "reserve-execution-envelope":
                return self._handle_reserve_execution_envelope(
                    envelope
                )
            return self._handle_persist_measured_plan(envelope)
        purpose, envelope = self._verify_internal_envelope(
            request,
            allowed_purposes=(
                {
                    "issue-capability",
                    "record-witness-receipt",
                }
                if self.role_name == "issuer"
                else {
                    "execute-v9",
                }
            ),
        )
        if self.role_name == "issuer":
            if purpose == "record-witness-receipt":
                return self._handle_record_witness_receipt(envelope)
            return self._handle_issue(envelope)
        return self._handle_execute(envelope, purpose=purpose)

    def _read_revocation_root_observations(self, *, work):
        """Private independent verifier read, not an enabled request purpose.

        Main's real MeasuredConfiguration.load and active launch establish the
        configuration admission prerequisite. This scalar snapshot does not
        repeat its signature verification or make a forged dataclass trusted.
        Returned full roots/heads are observations, not a plan or writer token.
        """
        if (self.role_name != "verifier"
                or self.process_mode != "policy-authority-verifier"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation root verifier process is not configured")
        configuration = self.configuration
        payload = configuration.payload
        if (type(payload) is not dict or type(payload.get("roles")) is not dict
                or type(payload["roles"].get("verifier")) is not dict):
            raise AuthorityServiceError("revocation root verifier configuration is not closed data")
        role = payload["roles"]["verifier"]
        try:
            timeout = role["databaseConnectTimeoutSeconds"]
            # libpq rounds one second up to two and treats zero as unbounded.
            # Floor only measured values already within its real 2..300 bound.
            if type(timeout) not in (int, float) or not 2 <= timeout <= 300:
                raise AuthorityServiceError("revocation root verifier timeout is not bounded")
            pins = (int(timeout), role["databaseRole"], role["tlsClientDn"],
                role["tlsClientSerial"], role["tlsIssuerDn"], payload["queryManifestDigest"])
        except KeyError as exc:
            raise AuthorityServiceError("revocation root verifier configuration is incomplete") from exc
        from serverware import authority_revocation_root_reader

        authority_revocation_root_reader._validate_pins(pins)
        authority_revocation_root_reader.roots._callback(
            work, authority_launch_guard.require_active, "verifier")
        dsn = authority_revocation_root_reader.roots._callback(work, _read_dsn_descriptor,
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN")
        reader = authority_revocation_root_reader.RevocationRootReader(
            dsn=dsn, connect_timeout_seconds=pins[0], database_role=pins[1],
            tls_client_dn=pins[2], tls_client_serial=pins[3], tls_issuer_dn=pins[4],
            query_manifest_digest=pins[5])
        return reader.read(work=work)

    def _revocation_capability_issuer(self, *, work):
        """Construct the private successor only from this admitted issuer.

        The actual main loads root-signed measured configuration before this
        process is constructed. A dataclass or arbitrary mapping supplied to
        the pure mapper is not equivalent to that admission. This factory is
        not wired into legacy dispatch and does not relax its kernel gates.
        """
        if (self.role_name != "issuer"
                or self.process_mode != "policy-authority-issuer"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation issuer process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        authority_launch_guard.require_active("issuer")
        generation = dict(authority_launch_guard.generation())
        from serverware import authority_revocation_configuration

        return authority_revocation_configuration._issuer_from_configuration_on_work(
            payload=payload, configuration_digest=configuration_digest,
            generation=generation, work=work)

    def _issue_revocation_invocation_bytes(self, *, envelope_bytes, work):
        """Private original-byte composition, not an enabled service purpose."""
        if (type(envelope_bytes) is not bytes
                or not 2 <= len(envelope_bytes) <= authority_contract.MAX_REQUEST_BYTES):
            raise AuthorityServiceError("revocation invocation is not bounded original bytes")
        issuer = self._revocation_capability_issuer(work=work)
        return issuer.issue_authenticated(envelope_bytes=envelope_bytes, work=work)

    def _sign_internal(
        self,
        purpose: str,
        payload: Mapping[str, Any],
        *,
        deadline_monotonic_ns: int | None = None,
        fence: int | None = None,
        envelope_id: str | None = None,
        parent_envelope_id: str | None = None,
    ) -> dict[str, Any]:
        if self.signing_key is None:
            raise AuthorityServiceError("verifier signing key is unavailable")
        issued_monotonic_ns = time.monotonic_ns()
        if deadline_monotonic_ns is None:
            deadline_monotonic_ns = issued_monotonic_ns + int(
                self.role_config["maximumInternalAgeNs"]
            )
        if (
            not isinstance(deadline_monotonic_ns, int)
            or deadline_monotonic_ns <= issued_monotonic_ns
            or fence is not None
            and (not isinstance(fence, int) or fence < 1)
        ):
            raise AuthorityServiceError(
                "authority internal envelope deadline or fence is invalid"
            )
        if envelope_id is None:
            raise AuthorityServiceError(
                "authority internal envelope lacks a durable identity"
            )
        _require_digest(envelope_id, "authority internal envelope ID")
        unsigned = {
            "schema": INTERNAL_ENVELOPE_SCHEMA,
            "envelopeId": envelope_id,
            "parentEnvelopeId": parent_envelope_id,
            "purpose": purpose,
            "configurationDigest": self.configuration.digest,
            "issuedAtEpochNs": time.time_ns(),
            "issuedMonotonicNs": issued_monotonic_ns,
            "deadlineMonotonicNs": deadline_monotonic_ns,
            "fence": fence,
            "payload": dict(payload),
        }
        signature = self.signing_key.sign(
            _domain_digest(
                INTERNAL_ENVELOPE_SCHEMA, _canonical(unsigned)
            ).encode("ascii")
        )
        return {**unsigned, "signature": _b64url_encode(signature)}

    def _verify_internal_envelope(
        self,
        request: Mapping[str, Any],
        *,
        allowed_purposes: set[str],
    ) -> tuple[str, dict[str, Any]]:
        if (
            not isinstance(request, dict)
            or set(request)
            != {
                "schema",
                "envelopeId",
                "parentEnvelopeId",
                "purpose",
                "configurationDigest",
                "issuedAtEpochNs",
                "issuedMonotonicNs",
                "deadlineMonotonicNs",
                "fence",
                "payload",
                "signature",
            }
            or request.get("schema") != INTERNAL_ENVELOPE_SCHEMA
            or request.get("configurationDigest")
            != self.configuration.digest
            or request.get("purpose") not in allowed_purposes
            or not isinstance(request.get("payload"), dict)
            or not isinstance(request.get("issuedAtEpochNs"), int)
            or not isinstance(request.get("issuedMonotonicNs"), int)
            or not isinstance(request.get("deadlineMonotonicNs"), int)
            or not isinstance(request.get("envelopeId"), str)
            or not request["envelopeId"].startswith("sha256:")
            or request.get("fence") is not None
            and (
                not isinstance(request["fence"], int)
                or request["fence"] < 1
            )
            or request["issuedMonotonicNs"] > time.monotonic_ns()
            or time.monotonic_ns() >= request["deadlineMonotonicNs"]
            or abs(time.time_ns() - request["issuedAtEpochNs"])
            > int(self.role_config["maximumInternalAgeNs"])
        ):
            raise AuthorityServiceError(
                "authority internal envelope is invalid"
            )
        signer_role = (
            "planner"
            if request.get("purpose")
                in {"persist-measured-plan", "read-persisted-plan"}
            else "verifier"
        )
        signer_config = self.configuration.role(signer_role)
        key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                signer_config["signingPublicKeyBase64Url"], size=32
            )
        )
        unsigned = dict(request)
        signature = _b64url_decode(unsigned.pop("signature"), size=64)
        try:
            key.verify(
                signature,
                _domain_digest(
                    INTERNAL_ENVELOPE_SCHEMA, _canonical(unsigned)
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "authority internal envelope signature is invalid"
            ) from exc
        return str(request["purpose"]), dict(request["payload"])

    def _handle_runtime(
        self, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        if (
            set(request)
            != {
                "schema",
                "requestId",
                "operation",
                "input",
                "configurationDigest",
                "operationManifestDigest",
                "startedMonotonicNs",
                "deadlineMonotonicNs",
            }
            or request.get("schema") != RUNTIME_REQUEST_SCHEMA
            or request.get("configurationDigest")
            != self.configuration.digest
            or request.get("operationManifestDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
            or not isinstance(request.get("operation"), str)
            or not isinstance(request.get("input"), dict)
            or not isinstance(request.get("startedMonotonicNs"), int)
            or not isinstance(request.get("deadlineMonotonicNs"), int)
        ):
            raise AuthorityServiceError("runtime request is not closed")
        operation = request["operation"]
        now_monotonic_ns = time.monotonic_ns()
        maximum_deadline_ns = int(
            self.role_config["maximumEndToEndDeadlineNs"]
        )
        if (
            operation
                not in authority_transition_registry.PLANNABLE_OPERATIONS
            or operation
                not in self.configuration.role("planner")[
                    "enabledOperations"
                ]
            or request["startedMonotonicNs"] > now_monotonic_ns
            or now_monotonic_ns >= request["deadlineMonotonicNs"]
            or request["deadlineMonotonicNs"]
            - request["startedMonotonicNs"]
            > maximum_deadline_ns
        ):
            raise AuthorityServiceError(
                "runtime authority operation or deadline is invalid"
            )
        handler_name = str(
            authority_contract.operation_spec(operation)["handler"]
        )
        runtime_input = dict(request["input"])
        authority_planner.reject_authoritative_input(runtime_input)
        if (
            operation == "webauthn.challenge.create"
            and set(runtime_input)
            == {"operation", "input", "userId", "credentialId"}
        ):
            runtime_input = self._prepare_webauthn_challenge_writer(
                runtime_input
            )
        execution = self._execute_v9_operation(
            operation=operation,
            handler_name=handler_name,
            runtime_input=runtime_input,
            deadline_monotonic_ns=request["deadlineMonotonicNs"],
        )
        if (
            not isinstance(execution, dict)
            or set(execution)
            != {
                "result",
                "resultDigest",
                "commitReceiptDigest",
                "witnessCommitDigest",
                "fence",
            }
            or time.monotonic_ns() >= request["deadlineMonotonicNs"]
        ):
            raise AuthorityServiceError(
                "authority execution result is not closed or timely"
            )
        request_digest = _domain_digest(
            RUNTIME_REQUEST_SCHEMA, _canonical(dict(request))
        )
        unsigned = {
            "schema": RUNTIME_RESPONSE_SCHEMA,
            "requestId": request["requestId"],
            "operation": operation,
            "configurationDigest": self.configuration.digest,
            "requestDigest": request_digest,
            "issuedAtEpochNs": time.time_ns(),
            "deadlineMonotonicNs": request["deadlineMonotonicNs"],
            "fence": execution["fence"],
            "result": execution["result"],
            "resultDigest": execution["resultDigest"],
            "commitReceiptDigest":
                execution["commitReceiptDigest"],
            "witnessCommitDigest":
                execution["witnessCommitDigest"],
            "attestationReceiptDigest":
                self.role_config["attestationReceiptDigest"],
            "attestationConsumptionReceipt":
                self.attestation_consumption_receipt,
            "attestationConsumptionReceiptDigest":
                _domain_digest(
                    str(
                        self.attestation_consumption_receipt[
                            "schema"
                        ]
                    ),
                    _canonical(
                        self.attestation_consumption_receipt
                    ),
                ),
        }
        if self.signing_key is None:
            raise AuthorityServiceError("verifier signer is unavailable")
        return {
            **unsigned,
            "signature": _b64url_encode(
                self.signing_key.sign(
                    _domain_digest(
                        RUNTIME_RESPONSE_SCHEMA, _canonical(unsigned)
                    ).encode("ascii")
                )
            ),
        }

    def _read_roots(self, operation: str) -> tuple[list[dict[str, Any]], str]:
        import psycopg
        from psycopg.rows import dict_row

        dsn = _read_dsn_descriptor(
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"
        )
        with psycopg.connect(
            dsn,
            row_factory=dict_row,
            connect_timeout=int(self.role_config["databaseConnectTimeoutSeconds"]),
            options="-c search_path=pg_catalog",
        ) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ "
                        "READ ONLY"
                    )
                    identity = cursor.execute(
                        "SELECT current_user AS role, ssl.ssl, "
                        "ssl.client_dn, ssl.client_serial::text "
                        "AS client_serial, ssl.issuer_dn, "
                        "role_record.rolsuper, "
                        "role_record.rolcreaterole, "
                        "role_record.rolcreatedb, "
                        "role_record.rolreplication, "
                        "role_record.rolbypassrls, "
                        "pg_catalog.has_schema_privilege("
                        "current_user, 'serverware_metadata', 'CREATE') "
                        "AS schema_create, "
                        "pg_catalog.has_database_privilege("
                        "current_user, pg_catalog.current_database(), "
                        "'CREATE') AS database_create, "
                        "pg_catalog.has_database_privilege("
                        "current_user, pg_catalog.current_database(), "
                        "'TEMPORARY') AS database_temporary "
                        "FROM pg_catalog.pg_stat_ssl AS ssl "
                        "JOIN pg_catalog.pg_roles AS role_record "
                        "ON role_record.oid = "
                        "current_user::pg_catalog.regrole::oid "
                        "WHERE ssl.pid = pg_catalog.pg_backend_pid()"
                    ).fetchone()
                    if (
                        identity is None
                        or identity["role"]
                        != self.role_config["databaseRole"]
                        or not bool(identity["ssl"])
                        or identity["client_dn"]
                        != self.role_config["tlsClientDn"]
                        or identity["client_serial"]
                        != self.role_config["tlsClientSerial"]
                        or identity["issuer_dn"]
                        != self.role_config["tlsIssuerDn"]
                        or any(
                            bool(identity[field])
                            for field in (
                                "rolsuper",
                                "rolcreaterole",
                                "rolcreatedb",
                                "rolreplication",
                                "rolbypassrls",
                                "schema_create",
                                "database_create",
                                "database_temporary",
                            )
                        )
                    ):
                        raise AuthorityServiceError(
                            "verifier database mTLS identity is not exact"
                        )
                    direct_mutation = cursor.execute(
                        "SELECT 1 FROM pg_catalog.pg_class AS relation "
                        "JOIN pg_catalog.pg_namespace AS namespace "
                        "ON namespace.oid = relation.relnamespace "
                        "WHERE namespace.nspname = 'serverware_metadata' "
                        "AND relation.relkind IN ('r', 'p', 'S') "
                        "AND ((relation.relkind IN ('r', 'p') AND "
                        "pg_catalog.has_table_privilege(current_user, "
                        "relation.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,"
                        "REFERENCES,TRIGGER')) OR "
                        "(relation.relkind = 'S' AND "
                        "pg_catalog.has_sequence_privilege(current_user, "
                        "relation.oid, 'USAGE,UPDATE'))) LIMIT 1"
                    ).fetchone()
                    if direct_mutation is not None:
                        raise AuthorityServiceError(
                            "verifier database role has mutation authority"
                        )
                    inherited_or_function_authority = cursor.execute(
                        "SELECT 1 FROM pg_catalog.pg_auth_members "
                        "WHERE member = "
                        "current_user::pg_catalog.regrole::oid "
                        "OR roleid = "
                        "current_user::pg_catalog.regrole::oid "
                        "UNION ALL "
                        "SELECT 1 FROM pg_catalog.pg_proc AS function_record "
                        "JOIN pg_catalog.pg_namespace AS namespace "
                        "ON namespace.oid = "
                        "function_record.pronamespace "
                        "WHERE namespace.nspname = 'serverware_metadata' "
                        "AND pg_catalog.has_function_privilege("
                        "current_user, function_record.oid, 'EXECUTE') "
                        "LIMIT 1"
                    ).fetchone()
                    if inherited_or_function_authority is not None:
                        raise AuthorityServiceError(
                            "verifier database role has inherited or "
                            "function authority"
                        )
                    rows = cursor.execute(
                        "SELECT manifest.ordinal, manifest.predicate_id, "
                        "manifest.table_name, manifest.handler_digest, "
                        "manifest.key_columns_json, "
                        "manifest.write_access, manifest.predicate_kind, "
                        "manifest.selector_paths_json, "
                        "manifest.proof_kind, "
                        "manifest.maximum_rows, "
                        "manifest.entry_digest, manifest.manifest_digest, "
                        "root.root_revision, root.root_digest, root.leaf_count "
                        "FROM serverware_metadata."
                        "policy_authority_query_dependency_manifests "
                        "AS manifest JOIN serverware_metadata."
                        "policy_authority_authenticated_table_roots AS root "
                        "ON root.table_name = manifest.table_name "
                        "WHERE manifest.operation = %s "
                        "ORDER BY manifest.ordinal",
                        (operation,),
                    ).fetchall()
        if not rows:
            raise AuthorityServiceError(
                "operation query manifest is unavailable"
            )
        manifest_digest = str(rows[0]["manifest_digest"])
        operation_spec = authority_contract.operation_spec(operation)
        business_tables = tuple(
            sorted(
                set(operation_spec["businessReads"])
                | set(operation_spec["businessWrites"])
            )
        )
        if (
            any(row["manifest_digest"] != manifest_digest for row in rows)
            or manifest_digest
            != self.configuration.payload.get("queryManifestDigest")
            or tuple(str(row["table_name"]) for row in rows)
            != business_tables
            or any(
                str(row["table_name"])
                in (
                    set(operation_spec["frameworkPreconditions"])
                    | set(operation_spec["frameworkWrites"])
                )
                for row in rows
            )
            or any(
                bool(row["write_access"])
                != (
                    str(row["table_name"])
                    in operation_spec["businessWrites"]
                )
                for row in rows
            )
            or any(
                json.loads(str(row["selector_paths_json"]))
                != [
                    list(path)
                    for path in operation_spec["selectors"].get(
                        str(row["table_name"]),
                        (),
                    )
                ]
                or row["proof_kind"]
                != "radix16-canonical-multiproof-v2"
                or row["handler_digest"]
                != authority_contract.handler_contract_digest(
                    operation
                )
                for row in rows
            )
        ):
            raise AuthorityServiceError(
                "operation query manifest changed"
            )
        return [dict(row) for row in rows], manifest_digest

    def _read_writer_outcome(
        self,
        *,
        capability_id: str,
        operation: str,
        request_digest: str,
        fence: int,
        allow_absent: bool = False,
    ) -> dict[str, Any]:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(
            _read_dsn_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"
            ),
            row_factory=dict_row,
            connect_timeout=int(
                self.role_config["databaseConnectTimeoutSeconds"]
            ),
            options="-c search_path=pg_catalog",
        ) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ "
                        "READ ONLY"
                    )
                    identity = cursor.execute(
                        "SELECT current_user AS role, ssl.ssl, "
                        "ssl.client_dn, ssl.client_serial::text "
                        "AS client_serial, ssl.issuer_dn "
                        "FROM pg_catalog.pg_stat_ssl AS ssl "
                        "WHERE ssl.pid = pg_catalog.pg_backend_pid()"
                    ).fetchone()
                    if (
                        identity is None
                        or identity["role"]
                        != self.role_config["databaseRole"]
                        or not bool(identity["ssl"])
                        or identity["client_dn"]
                        != self.role_config["tlsClientDn"]
                        or identity["client_serial"]
                        != self.role_config["tlsClientSerial"]
                        or identity["issuer_dn"]
                        != self.role_config["tlsIssuerDn"]
                    ):
                        raise AuthorityServiceError(
                            "verifier outcome reader identity is not exact"
                        )
                    row = cursor.execute(
                        "SELECT capability_id, operation, request_digest, "
                        "fence, status, result_digest, "
                        "commit_receipt_digest "
                        "FROM serverware_metadata."
                        "policy_authority_writer_capabilities "
                        "WHERE capability_id = %s",
                        (capability_id,),
                    ).fetchone()
        if row is None and allow_absent:
            return {
                "status": "absent",
                "result_digest": None,
                "commit_receipt_digest": None,
            }
        if (
            row is None
            or row["capability_id"] != capability_id
            or row["operation"] != operation
            or row["request_digest"] != request_digest
            or int(row["fence"]) != fence
            or row["status"] not in {
                "issued",
                "reserved",
                "committed",
                "expired",
                "reconciled",
            }
        ):
            raise AuthorityServiceError(
                "controlled writer outcome binding is unavailable"
            )
        return dict(row)

    def _read_policy_capability_outcome(
        self,
        *,
        capability_id: str,
        operation: str,
        request_digest: str,
        fence: int,
        allow_absent: bool = False,
    ) -> dict[str, Any]:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(
            _read_dsn_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"
            ),
            row_factory=dict_row,
            connect_timeout=int(
                self.role_config["databaseConnectTimeoutSeconds"]
            ),
            options="-c search_path=pg_catalog",
        ) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ "
                        "READ ONLY"
                    )
                    identity = cursor.execute(
                        "SELECT current_user AS role, ssl.ssl, "
                        "ssl.client_dn, ssl.client_serial::text "
                        "AS client_serial, ssl.issuer_dn "
                        "FROM pg_catalog.pg_stat_ssl AS ssl "
                        "WHERE ssl.pid = pg_catalog.pg_backend_pid()"
                    ).fetchone()
                    if (
                        identity is None
                        or identity["role"]
                        != self.role_config["databaseRole"]
                        or not bool(identity["ssl"])
                        or identity["client_dn"]
                        != self.role_config["tlsClientDn"]
                        or identity["client_serial"]
                        != self.role_config["tlsClientSerial"]
                        or identity["issuer_dn"]
                        != self.role_config["tlsIssuerDn"]
                    ):
                        raise AuthorityServiceError(
                            "policy capability outcome reader identity "
                            "is not exact"
                        )
                    row = cursor.execute(
                        "SELECT capability_id, operation, request_digest, "
                        "fence, status, result_digest "
                        "FROM serverware_metadata."
                        "policy_authority_verifier_capabilities "
                        "WHERE capability_id = %s",
                        (capability_id,),
                    ).fetchone()
        if row is None and allow_absent:
            return {
                "status": "absent",
                "result_digest": None,
            }
        if (
            row is None
            or row["capability_id"] != capability_id
            or row["operation"] != operation
            or row["request_digest"] != request_digest
            or int(row["fence"]) != fence
            or row["status"] not in {
                "issued",
                "committed",
                "expired",
                "reconciled",
            }
        ):
            raise AuthorityServiceError(
                "policy capability outcome binding is unavailable"
            )
        return dict(row)

    def _read_committed_writer_replay(
        self,
        *,
        operation: str,
        request_digest: str,
    ) -> dict[str, Any] | None:
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(
            _read_dsn_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"
            ),
            row_factory=dict_row,
            connect_timeout=int(
                self.role_config["databaseConnectTimeoutSeconds"]
            ),
            options="-c search_path=pg_catalog",
        ) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ "
                        "READ ONLY"
                    )
                    identity = cursor.execute(
                        "SELECT current_user AS role, ssl.ssl, "
                        "ssl.client_dn, ssl.client_serial::text "
                        "AS client_serial, ssl.issuer_dn "
                        "FROM pg_catalog.pg_stat_ssl AS ssl "
                        "WHERE ssl.pid = pg_catalog.pg_backend_pid()"
                    ).fetchone()
                    if (
                        identity is None
                        or identity["role"]
                        != self.role_config["databaseRole"]
                        or not bool(identity["ssl"])
                        or identity["client_dn"]
                        != self.role_config["tlsClientDn"]
                        or identity["client_serial"]
                        != self.role_config["tlsClientSerial"]
                        or identity["issuer_dn"]
                        != self.role_config["tlsIssuerDn"]
                    ):
                        raise AuthorityServiceError(
                            "committed writer replay reader identity "
                            "is not exact"
                        )
                    rows = cursor.execute(
                        "SELECT capability.capability_id, "
                        "capability.operation, capability.request_digest, "
                        "capability.operation_manifest_digest, "
                        "capability.query_manifest_digest, "
                        "capability.status, capability.fence, "
                        "receipt.envelope_id, receipt.handler_name, "
                        "receipt.result_json, receipt.result_digest, "
                        "receipt.commit_receipt_digest, "
                        "receipt.authority_root_set_before_digest, "
                        "receipt.authority_root_set_after_digest, "
                        "receipt.operation_manifest_digest "
                        "AS receipt_operation_manifest_digest, "
                        "receipt.query_manifest_digest "
                        "AS receipt_query_manifest_digest, "
                        "receipt.witness_reservation_digest, "
                        "receipt.witness_sequence, "
                        "receipt.deadline_monotonic_ns, "
                        "receipt.committed_at_epoch_ns, "
                        "receipt.source_revision, "
                        "terminal.witness_receipt_digest "
                        "AS terminal_witness_receipt_digest, "
                        "terminal.operation AS terminal_operation, "
                        "terminal.request_digest "
                        "AS terminal_request_digest, "
                        "terminal.fence AS terminal_fence "
                        "FROM serverware_metadata."
                        "policy_authority_writer_capabilities "
                        "AS capability "
                        "JOIN serverware_metadata."
                        "policy_authority_writer_receipts AS receipt "
                        "ON receipt.capability_id = "
                        "capability.capability_id "
                        "JOIN serverware_metadata."
                        "policy_authority_external_witness_receipts "
                        "AS terminal "
                        "ON terminal.capability_id = "
                        "capability.capability_id "
                        "AND terminal.phase IN ('commit', 'reconcile') "
                        "AND terminal.result_digest = "
                        "receipt.result_digest "
                        "WHERE capability.operation = %s "
                        "AND capability.request_digest = %s "
                        "AND capability.status IN "
                        "('committed', 'reconciled') "
                        "ORDER BY terminal.witness_sequence DESC "
                        "LIMIT 2",
                        (operation, request_digest),
                    ).fetchall()
                    manifest_rows = cursor.execute(
                        "SELECT DISTINCT manifest_digest "
                        "FROM serverware_metadata."
                        "policy_authority_query_dependency_manifests"
                    ).fetchall()
        if not rows:
            return None
        if (
            len(manifest_rows) != 1
            or not isinstance(manifest_rows[0]["manifest_digest"], str)
        ):
            raise AuthorityServiceError(
                "committed writer replay query manifest is ambiguous"
            )
        current_query_manifest_digest = manifest_rows[0][
            "manifest_digest"
        ]
        if len(rows) != 1:
            raise AuthorityServiceError(
                "committed writer replay identity is ambiguous"
            )
        row = rows[0]
        try:
            result = json.loads(str(row["result_json"]))
        except json.JSONDecodeError as exc:
            raise AuthorityServiceError(
                "committed writer replay result is invalid"
            ) from exc
        commit_receipt = {
            "schema":
                "serverware.policyAuthorityWriterCommitReceipt/v1",
            "capabilityId": row["capability_id"],
            "envelopeId": row["envelope_id"],
            "operation": row["operation"],
            "handlerName": row["handler_name"],
            "requestDigest": row["request_digest"],
            "resultDigest": row["result_digest"],
            "authorityRootSetBeforeDigest":
                row["authority_root_set_before_digest"],
            "authorityRootSetAfterDigest":
                row["authority_root_set_after_digest"],
            "operationManifestDigest":
                row["receipt_operation_manifest_digest"],
            "queryManifestDigest":
                row["receipt_query_manifest_digest"],
            "witnessReservationDigest":
                row["witness_reservation_digest"],
            "witnessSequence": row["witness_sequence"],
            "deadlineMonotonicNs": row["deadline_monotonic_ns"],
            "fence": row["fence"],
            "committedAtEpochNs": row["committed_at_epoch_ns"],
            "sourceRevision": row["source_revision"],
        }
        if (
            row["operation"] != operation
            or row["request_digest"] != request_digest
            or row["operation_manifest_digest"]
                != authority_contract.OPERATION_MANIFEST_DIGEST
            or row["handler_name"]
                != authority_contract.operation_spec(operation)["handler"]
            or row["query_manifest_digest"]
                != current_query_manifest_digest
            or row["receipt_operation_manifest_digest"]
                != row["operation_manifest_digest"]
            or row["receipt_query_manifest_digest"]
                != row["query_manifest_digest"]
            or row["source_revision"] != SOURCE_REVISION
            or row["terminal_operation"] != operation
            or row["terminal_request_digest"] != request_digest
            or row["terminal_fence"] != row["fence"]
            or _canonical(result).decode("ascii")
                != row["result_json"]
            or _framed_digest(
                "serverware.policyAuthorityControlledWriterResult/v1",
                str(row["result_json"]).encode("ascii"),
            ) != row["result_digest"]
            or _domain_digest(
                "serverware.policyAuthorityWriterCommitReceipt/v1",
                _canonical(commit_receipt),
            ) != row["commit_receipt_digest"]
            or not isinstance(
                row["terminal_witness_receipt_digest"], str
            )
            or not isinstance(row["fence"], int)
            or int(row["fence"]) < 1
        ):
            raise AuthorityServiceError(
                "committed writer replay binding changed"
            )
        return {
            "result": result,
            "resultDigest": row["result_digest"],
            "commitReceiptDigest": row["commit_receipt_digest"],
            "witnessCommitDigest":
                row["terminal_witness_receipt_digest"],
            "fence": int(row["fence"]),
        }

    def _terminalize_failed_capability_issue(
        self,
        *,
        policy_operation: bool,
        operation: str,
        request_digest: str,
        capability_id: str,
        reservation: Mapping[str, Any],
        deadline_monotonic_ns: int,
    ) -> None:
        outcome_error: Exception | None = None
        try:
            if policy_operation:
                outcome = self._read_policy_capability_outcome(
                    capability_id=capability_id,
                    operation=operation,
                    request_digest=request_digest,
                    fence=int(reservation["fence"]),
                    allow_absent=True,
                )
            else:
                outcome = self._read_writer_outcome(
                    capability_id=capability_id,
                    operation=operation,
                    request_digest=request_digest,
                    fence=int(reservation["fence"]),
                    allow_absent=True,
                )
        except Exception as exc:
            outcome_error = exc
            outcome = {
                "status": "unknown",
                "result_digest": None,
            }
        committed = outcome["status"] in {"committed", "reconciled"}
        terminal_receipt = self._witness_transition(
            phase="reconcile" if committed else "abort",
            operation=operation,
            request_digest=request_digest,
            capability_id=capability_id,
            result_digest=(
                outcome["result_digest"] if committed else None
            ),
            predecessor_receipt=reservation,
            deadline_monotonic_ns=deadline_monotonic_ns,
        )
        if outcome["status"] != "absent":
            try:
                self._persist_writer_witness_receipt(terminal_receipt)
            except Exception as persistence_error:
                if outcome_error is not None:
                    raise AuthorityServiceError(
                        "capability issue was externally aborted but its "
                        "database witness receipt requires reconciliation"
                    ) from persistence_error
                raise
        if outcome_error is not None:
            raise AuthorityServiceError(
                "capability issue was externally aborted because its "
                "database outcome could not be read"
            ) from outcome_error

    def _read_webauthn_authority(
        self,
        *,
        authorization: Mapping[str, Any],
        operation_id: str,
    ) -> tuple[dict[str, Any], dict[str, Any], Mapping[str, Any]]:
        credential_reference_fields = {
            field
            for field in ("credentialId", "credentialRecordId")
            if field in authorization
        }
        if (
            set(authorization)
            != {"challengeId", "assertion"} | credential_reference_fields
            or len(credential_reference_fields) != 1
            or not isinstance(authorization.get("challengeId"), str)
            or not isinstance(
                authorization[next(iter(credential_reference_fields))],
                str,
            )
            or not isinstance(authorization.get("assertion"), dict)
        ):
            raise AuthorityServiceError(
                "WebAuthn authorization reference is not closed"
            )
        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(
            _read_dsn_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"
            ),
            row_factory=dict_row,
            connect_timeout=int(
                self.role_config["databaseConnectTimeoutSeconds"]
            ),
            options="-c search_path=pg_catalog",
        ) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ "
                        "READ ONLY"
                    )
                    identity = cursor.execute(
                        "SELECT current_user AS role, ssl.ssl, "
                        "ssl.client_dn, ssl.client_serial::text "
                        "AS client_serial, ssl.issuer_dn, "
                        "role_record.rolcanlogin, "
                        "role_record.rolsuper, "
                        "role_record.rolcreaterole, "
                        "role_record.rolcreatedb, "
                        "role_record.rolreplication, "
                        "role_record.rolbypassrls, "
                        "pg_catalog.has_schema_privilege("
                        "current_user, 'serverware_metadata', 'CREATE') "
                        "AS schema_create, "
                        "pg_catalog.has_database_privilege("
                        "current_user, pg_catalog.current_database(), "
                        "'CREATE') AS database_create, "
                        "pg_catalog.has_database_privilege("
                        "current_user, pg_catalog.current_database(), "
                        "'TEMPORARY') AS database_temporary "
                        "FROM pg_catalog.pg_stat_ssl AS ssl "
                        "JOIN pg_catalog.pg_roles AS role_record "
                        "ON role_record.oid = "
                        "current_user::pg_catalog.regrole::oid "
                        "WHERE ssl.pid = pg_catalog.pg_backend_pid()"
                    ).fetchone()
                    if (
                        identity is None
                        or identity["role"]
                        != self.role_config["databaseRole"]
                        or identity.get("ssl") is not True
                        or identity.get("rolcanlogin") is not True
                        or identity["client_dn"]
                        != self.role_config["tlsClientDn"]
                        or identity["client_serial"]
                        != self.role_config["tlsClientSerial"]
                        or identity["issuer_dn"]
                        != self.role_config["tlsIssuerDn"]
                        or any(
                            identity.get(field) is not False
                            for field in (
                                "rolsuper",
                                "rolcreaterole",
                                "rolcreatedb",
                                "rolreplication",
                                "rolbypassrls",
                                "schema_create",
                                "database_create",
                                "database_temporary",
                            )
                        )
                    ):
                        raise AuthorityServiceError(
                            "WebAuthn authority read role changed"
                        )
                    forbidden_authority = cursor.execute(
                        *verifier_read_privilege_check(
                            role=self.role_config["databaseRole"],
                            namespace="serverware_metadata",
                        )
                    ).fetchone()
                    if forbidden_authority is not None:
                        raise AuthorityServiceError(
                            "WebAuthn authority read role is privileged"
                        )
                    challenge_row = cursor.execute(
                        "SELECT id, challenge, challenge_type, user_id, "
                        "scope_key, approval_request_id, payload_json, "
                        "expires_at, used_at, created_at "
                        "FROM serverware_metadata.webauthn_challenges "
                        "WHERE id = %s LIMIT 2",
                        (authorization["challengeId"],),
                    ).fetchall()
                    credential_field = next(
                        iter(credential_reference_fields)
                    )
                    credential_column = (
                        "credential_id"
                        if credential_field == "credentialId"
                        else "id"
                    )
                    credential_row = cursor.execute(
                        "SELECT id, credential_id, user_id, public_key_cose, "
                        "sign_count, aaguid, authenticator_class, "
                        "attestation_trusted, attestation_leaf_sha256, "
                        "attestation_root_sha256, "
                        "attestation_trust_bundle_digest, "
                        "attestation_trust_bundle_sequence, revoked_at "
                        "FROM serverware_metadata.webauthn_credentials "
                        "WHERE "
                        + credential_column
                        + " = %s LIMIT 2",
                        (authorization[credential_field],),
                    ).fetchall()
                    trust_rows = cursor.execute(
                        "SELECT publication.bundle_digest, "
                        "publication.sequence, publication.rollback_epoch, "
                        "publication.payload_digest, "
                        "publication.withdrawn_credential_ids_json, "
                        "high_water.publication_digest, "
                        "high_water.metadata_blob_digest, "
                        "high_water.revocation_set_digest, "
                        "high_water.witness_receipt_digest, "
                        "high_water.witness_sequence "
                        "FROM serverware_metadata."
                        "webauthn_trust_publication_high_water "
                        "AS high_water "
                        "JOIN serverware_metadata."
                        "webauthn_trust_publications AS publication "
                        "ON publication.rollback_epoch = "
                        "high_water.rollback_epoch "
                        "AND publication.sequence = "
                        "high_water.publication_sequence "
                        "AND publication.bundle_digest = "
                        "high_water.publication_digest "
                        "AND publication.payload_digest = "
                        "high_water.metadata_blob_digest "
                        "WHERE high_water.authority_scope = "
                        "'webauthn-metadata' "
                        "AND publication.status = 'published' LIMIT 2"
                    ).fetchall()
                    pending_trust = cursor.execute(
                        "SELECT 1 FROM serverware_metadata."
                        "webauthn_trust_publications "
                        "WHERE status = 'pending' LIMIT 1"
                    ).fetchone()
        if (
            len(challenge_row) != 1
            or len(credential_row) != 1
            or len(trust_rows) != 1
            or pending_trust is not None
        ):
            raise AuthorityServiceError(
                "WebAuthn challenge or credential is unavailable"
            )
        challenge_binding = dict(challenge_row[0])
        credential_binding = dict(credential_row[0])
        trust_binding = dict(trust_rows[0])
        try:
            payload = json.loads(challenge_binding["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AuthorityServiceError(
                "WebAuthn challenge payload is invalid"
            ) from exc
        webauthn = self.configuration.payload.get("webauthn")
        try:
            withdrawn_credential_ids = json.loads(
                trust_binding["withdrawn_credential_ids_json"]
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AuthorityServiceError(
                "WebAuthn revocation publication is invalid"
            ) from exc
        try:
            trust_high_water = authority_webauthn_trust.high_water_document(
                rollback_epoch=int(trust_binding["rollback_epoch"]),
                sequence=int(trust_binding["sequence"]),
                publication_digest=trust_binding["publication_digest"],
                metadata_blob_digest=trust_binding["metadata_blob_digest"],
                revocation_set_digest=trust_binding["revocation_set_digest"],
                witness_receipt_digest=trust_binding["witness_receipt_digest"],
                witness_sequence=int(trust_binding["witness_sequence"]),
            )
            trust_high_water_digest = authority_webauthn_trust.high_water_digest(trust_high_water)
        except (TypeError, ValueError, OverflowError) as exc:
            raise AuthorityServiceError("WebAuthn trust high-water is invalid") from exc
        try:
            credential_policy = authority_webauthn_trust.credential_policy_document(
                credential=credential_binding, high_water=trust_high_water,
                trust_high_water_digest=trust_high_water_digest,
            )
            credential_policy_digest = authority_webauthn_trust.credential_policy_digest(credential_policy)
        except (TypeError, ValueError, OverflowError) as exc:
            raise AuthorityServiceError("WebAuthn credential policy is invalid") from exc
        if (
            not isinstance(webauthn, dict)
            or not isinstance(payload, dict)
            or set(payload)
            != {
                "schema",
                "operationId",
                "rpId",
                "origin",
                "issuedAtEpochNs",
                "expiresAtEpochNs",
                "credentialId",
            }
            or payload.get("schema")
            != "serverware.policyAuthorityWebAuthnChallenge/v1"
            or challenge_binding["challenge_type"]
            != "policy_authority"
            or challenge_binding["scope_key"] != operation_id
            or challenge_binding["used_at"] is not None
            or challenge_binding["user_id"]
            != credential_binding["user_id"]
            or credential_binding["revoked_at"] is not None
            or not isinstance(withdrawn_credential_ids, list)
            or credential_binding["credential_id"]
            in withdrawn_credential_ids
            or credential_binding["id"] in withdrawn_credential_ids
            or credential_binding["attestation_trust_bundle_digest"]
            != trust_binding["bundle_digest"]
            or int(
                credential_binding[
                    "attestation_trust_bundle_sequence"
                ]
            )
            != int(trust_binding["sequence"])
            or trust_binding["publication_digest"]
            != trust_binding["bundle_digest"]
            or payload.get("operationId") != operation_id
            or payload.get("rpId") != webauthn.get("rpId")
            or payload.get("origin") != webauthn.get("origin")
            or payload.get("credentialId")
            != credential_binding["credential_id"]
        ):
            raise AuthorityServiceError(
                "WebAuthn authoritative binding is invalid"
            )
        challenge = {
            **payload,
            "challengeId": challenge_binding["id"],
            "challenge": challenge_binding["challenge"],
            "challengeRowDigest": _domain_digest(
                "serverware.policyAuthorityWebAuthnChallengeRow/v1",
                _canonical(challenge_binding),
            ),
        }
        credential = {
            "credentialRecordId": credential_binding["id"],
            "credentialId": credential_binding["credential_id"],
            "userId": credential_binding["user_id"],
            "publicKeyCoseBase64Url":
                credential_binding["public_key_cose"],
            "signCount": int(credential_binding["sign_count"]),
            "authenticatorClass":
                credential_binding["authenticator_class"],
            "attestationTrusted":
                bool(credential_binding["attestation_trusted"]),
            "credentialPolicyDigest": credential_policy_digest,
            "trustHighWaterDigest": trust_high_water_digest,
            "credentialBindingDigest": _framed_digest(
                "serverware.policyAuthorityWebAuthnCredentialBinding/v1",
                _canonical(credential_binding),
            ),
            "rpId": webauthn["rpId"],
            "origin": webauthn["origin"],
            "revoked": False,
        }
        return challenge, credential, authorization["assertion"]

    def _prepare_webauthn_challenge_writer(
        self,
        input_value: dict[str, Any],
    ) -> dict[str, Any]:
        target_operation = input_value.get("operation")
        target_arguments = input_value.get("input")
        user_id = input_value.get("userId")
        credential_id = input_value.get("credentialId")
        if (
            not isinstance(target_operation, str)
            or target_operation
                not in authority_transition_registry.PLANNABLE_OPERATIONS
            or target_operation
                not in self.configuration.role("planner")[
                    "enabledOperations"
                ]
            or not bool(
                authority_contract.operation_spec(target_operation)[
                    "assertionRequired"
                ]
            )
            or not isinstance(target_arguments, dict)
            or _authorization_arguments(target_arguments)
            != target_arguments
            or not isinstance(user_id, str)
            or not user_id
            or not isinstance(credential_id, str)
            or not credential_id
        ):
            raise AuthorityServiceError(
                "policy-authority WebAuthn challenge input is invalid"
            )
        webauthn = self.configuration.payload.get("webauthn")
        if not isinstance(webauthn, dict):
            raise AuthorityServiceError(
                "WebAuthn measured configuration is unavailable"
            )
        lifetime_ns = int(webauthn.get("challengeLifetimeNs", 0))
        if (
            lifetime_ns % 1_000_000_000 != 0
            or not 30_000_000_000 <= lifetime_ns <= 300_000_000_000
            or lifetime_ns
            > int(webauthn.get("maximumChallengeAgeNs", 0))
        ):
            raise AuthorityServiceError(
                "WebAuthn challenge lifetime is outside the closed range"
            )
        issued_at_ns = time.time_ns() // 1_000_000 * 1_000_000
        authorization_digest = _controlled_writer_request_digest(
            target_operation,
            target_arguments,
        )
        operation_id = _domain_digest(
            "serverware.policyAuthorityOperation/v2",
            target_operation.encode("ascii"),
            authorization_digest.encode("ascii"),
        )
        challenge_value = _b64url_encode(os.urandom(32))
        item_id = _domain_digest(
            "serverware.policyAuthorityWebAuthnChallengeId/v1",
            operation_id.encode("ascii"),
            challenge_value.encode("ascii"),
        )
        expires_at_ns = issued_at_ns + lifetime_ns
        created_at = datetime.fromtimestamp(
            issued_at_ns // 1_000_000_000,
            tz=timezone.utc,
        ).replace(
            microsecond=(issued_at_ns // 1_000) % 1_000_000
        ).isoformat()
        expires_at = datetime.fromtimestamp(
            expires_at_ns // 1_000_000_000,
            tz=timezone.utc,
        ).replace(
            microsecond=(expires_at_ns // 1_000) % 1_000_000
        ).isoformat()
        challenge_payload = {
            "schema":
                "serverware.policyAuthorityWebAuthnChallenge/v1",
            "operationId": operation_id,
            "rpId": webauthn["rpId"],
            "origin": webauthn["origin"],
            "issuedAtEpochNs": issued_at_ns,
            "expiresAtEpochNs": expires_at_ns,
            "credentialId": credential_id,
        }
        arguments = {
            "challenge_id": item_id,
            "challenge": challenge_value,
            "challenge_type": "policy_authority",
            "user_id": user_id,
            "payload": challenge_payload,
            "approval_request_id": None,
            "scope_key": operation_id,
            "ttl_seconds": lifetime_ns // 1_000_000_000,
            "created_at": created_at,
            "expires_at": expires_at,
        }
        return {
            "schema": "serverware.policyAuthorityControlledWriterInput/v1",
            "handler": "create_webauthn_challenge",
            "operationManifestDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "arguments": arguments,
        }

    def _witness_transition(
        self,
        *,
        phase: str,
        operation: str,
        request_digest: str,
        deadline_monotonic_ns: int,
        capability_id: str | None = None,
        result_digest: str | None = None,
        predecessor_receipt: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        _request_bytes, receipt = self._witness_transition_with_request(
            phase=phase,
            operation=operation,
            request_digest=request_digest,
            deadline_monotonic_ns=deadline_monotonic_ns,
            capability_id=capability_id,
            result_digest=result_digest,
            predecessor_receipt=predecessor_receipt,
        )
        return receipt

    def _witness_transition_with_request(
        self,
        *,
        phase: str,
        operation: str,
        request_digest: str,
        deadline_monotonic_ns: int,
        capability_id: str | None = None,
        result_digest: str | None = None,
        predecessor_receipt: Mapping[str, Any] | None = None,
    ) -> tuple[bytes, dict[str, Any]]:
        request_bytes, _response_bytes, receipt = self._witness_transition_with_originals(
            phase=phase,
            operation=operation,
            request_digest=request_digest,
            deadline_monotonic_ns=deadline_monotonic_ns,
            capability_id=capability_id,
            result_digest=result_digest,
            predecessor_receipt=predecessor_receipt,
        )
        return request_bytes, receipt

    def _witness_transition_with_originals(
        self,
        *,
        phase: str,
        operation: str,
        request_digest: str,
        deadline_monotonic_ns: int,
        capability_id: str | None = None,
        result_digest: str | None = None,
        predecessor_receipt: Mapping[str, Any] | None = None,
    ) -> tuple[bytes, bytes, dict[str, Any]]:
        """Publish original request/response bytes after genuine receipt checks.

        This is still the existing witness protocol and preliminary reservation,
        not a post-plan bind or a v4 service route. Neither transport is rebuilt
        from a parsed or stored receipt; no request is re-signed or cached for
        retry after the transport callback. The unchanged closed receipt,
        request/head bindings, pinned key and actual signature checks precede
        publication of both original byte strings.
        """
        if (
            phase
            not in {
                "reserve",
                "commit",
                "abort",
                "reconcile",
                "webauthn-trust-publish",
            }
            or operation
                not in authority_transition_registry.PLANNABLE_OPERATIONS
            or (
                phase not in {"abort", "reconcile"}
                and time.monotonic_ns() >= deadline_monotonic_ns
            )
        ):
            raise AuthorityServiceError(
                "external replay witness v2 transition is invalid"
            )
        witness = self.configuration.payload.get("replayWitness")
        generation = dict(authority_launch_guard.generation())
        if not isinstance(witness, dict):
            raise AuthorityServiceError(
                "external replay witness is not configured"
            )
        predecessor_digest = (
            None
            if predecessor_receipt is None
            else _domain_digest(
                WITNESS_RECEIPT_SCHEMA_V2,
                _canonical(dict(predecessor_receipt)),
            )
        )
        envelope_material = {
            "phase": phase,
            "operation": operation,
            "requestDigest": request_digest,
            "capabilityId": capability_id,
            "resultDigest": result_digest,
            "predecessorReceiptDigest": predecessor_digest,
            "generationSequence": generation["sequence"],
            "generationDigest": generation["digest"],
        }
        unsigned_request = {
            "schema": WITNESS_REQUEST_SCHEMA_V2,
            "envelopeId": _witness_envelope_id(envelope_material),
            "parentEnvelopeId": (
                predecessor_digest
                if phase in {"commit", "abort", "reconcile"}
                else None
            ),
            "phase": phase,
            "operation": operation,
            "requestDigest": request_digest,
            "capabilityId": capability_id,
            "resultDigest": result_digest,
            "predecessorReceiptDigest": predecessor_digest,
            "deadlineMonotonicNs": deadline_monotonic_ns,
            "configurationDigest": self.configuration.digest,
            "operationManifestDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "generationSequence": generation["sequence"],
            "generationDigest": generation["digest"],
            "issuedAtEpochNs": time.time_ns(),
        }
        if self.signing_key is None or self.role_name != "verifier":
            raise AuthorityServiceError("verifier signer is unavailable")
        request = {
            **unsigned_request,
            "signature": _b64url_encode(
                self.signing_key.sign(
                    _domain_digest(
                        WITNESS_REQUEST_SCHEMA_V2,
                        _canonical(unsigned_request),
                    ).encode("ascii")
                )
            ),
        }
        request_bytes = _canonical(request)
        response_bytes, response = _socket_request_bytes_with_response(
            str(witness["socketPath"]),
            request_bytes,
            timeout_seconds=(
                float(witness["requestTimeoutSeconds"])
                if phase in {"abort", "reconcile"}
                else min(
                    float(witness["requestTimeoutSeconds"]),
                    max(
                        0.001,
                        (
                            deadline_monotonic_ns
                            - time.monotonic_ns()
                        ) / 1_000_000_000,
                    ),
                )
            ),
            expected_peer_uid=int(witness["serviceUid"]),
            expected_peer_gid=int(witness["serviceGid"]),
        )
        signature = _b64url_decode(response.get("signature"), size=64)
        unsigned_response = dict(response)
        unsigned_response.pop("signature", None)
        required = {
            "schema",
            "envelopeId",
            "parentEnvelopeId",
            "phase",
            "operation",
            "requestDigest",
            "capabilityId",
            "resultDigest",
            "witnessIdentityDigest",
            "sequence",
            "fence",
            "headDigest",
            "predecessorHeadDigest",
            "predecessorReceiptDigest",
            "logPredecessorHeadDigest",
            "deadlineMonotonicNs",
            "issuedAtEpochNs",
            "generationSequence",
            "generationDigest",
            "canonicalRequestDigest",
            "signature",
        }
        expected_predecessor_head = (
            None
            if predecessor_receipt is None
            else predecessor_receipt.get("headDigest")
        )
        expected_fence = (
            None
            if predecessor_receipt is None
            else predecessor_receipt.get("fence")
        )
        head_material = dict(unsigned_response)
        head_material["headDigest"] = None
        if (
            set(response) != required
            or response.get("schema") != WITNESS_RECEIPT_SCHEMA_V2
            or response.get("phase") != phase
            or response.get("envelopeId")
                != unsigned_request["envelopeId"]
            or response.get("parentEnvelopeId")
                != unsigned_request["parentEnvelopeId"]
            or response.get("operation") != operation
            or response.get("requestDigest") != request_digest
            or response.get("capabilityId") != capability_id
            or response.get("resultDigest") != result_digest
            or response.get("witnessIdentityDigest")
                != witness.get("identityDigest")
            or response.get("predecessorReceiptDigest")
                != predecessor_digest
            or response.get("predecessorHeadDigest")
                != expected_predecessor_head
            or (
                expected_fence is not None
                and response.get("fence") != expected_fence
            )
            or response.get("deadlineMonotonicNs")
                != deadline_monotonic_ns
            or response.get("generationSequence")
                != generation.get("sequence")
            or response.get("generationDigest")
                != generation.get("digest")
            or response.get("canonicalRequestDigest")
                != _domain_digest(
                    WITNESS_REQUEST_SCHEMA_V2,
                    request_bytes,
                )
            or _require_digest(
                response.get("headDigest"),
                "witness v2 head digest",
            )
                != _domain_digest(
                    "serverware.policyAuthorityReplayWitnessHead/v2",
                    _canonical(head_material),
                )
            or not isinstance(response.get("sequence"), int)
            or response["sequence"] < 1
            or not isinstance(response.get("fence"), int)
            or response["fence"] < 1
            or (
                phase not in {"abort", "reconcile"}
                and time.monotonic_ns() >= deadline_monotonic_ns
            )
        ):
            raise AuthorityServiceError(
                "external replay witness v2 response is not exact"
            )
        witness_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                witness["signingPublicKeyBase64Url"], size=32
            )
        )
        try:
            witness_key.verify(
                signature,
                _domain_digest(
                    WITNESS_RECEIPT_SCHEMA_V2,
                    _canonical(unsigned_response),
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "external replay witness v2 signature is invalid"
            ) from exc
        return request_bytes, response_bytes, dict(response)

    def _witness_transition_v1_disabled(
        self,
        *,
        phase: str,
        operation: str,
        request_digest: str,
        deadline_monotonic_ns: int,
        capability_id: str | None = None,
        result_digest: str | None = None,
        predecessor_receipt: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        raise AuthorityServiceError(
            "witness v1 transitions are disabled"
        )
        if (
            phase
            not in {
                "reserve",
                "commit",
                "abort",
                "reconcile",
                "webauthn-trust-publish",
            }
            or operation not in authority_contract.OPERATIONS
            or (
                phase not in {"abort", "reconcile"}
                and time.monotonic_ns() >= deadline_monotonic_ns
            )
        ):
            raise AuthorityServiceError(
                "external replay witness transition is invalid"
            )
        witness = self.configuration.payload.get("replayWitness")
        if not isinstance(witness, dict):
            raise AuthorityServiceError(
                "external replay witness is not configured"
            )
        predecessor_digest = (
            None
            if predecessor_receipt is None
            else _domain_digest(
                authority_contract.WITNESS_SCHEMA,
                _canonical(dict(predecessor_receipt)),
            )
        )
        unsigned_request = {
            "schema": "serverware.policyAuthorityReplayWitnessRequest/v1",
            "phase": phase,
            "operation": operation,
            "requestDigest": request_digest,
            "capabilityId": capability_id,
            "resultDigest": result_digest,
            "predecessorReceiptDigest": predecessor_digest,
            "deadlineMonotonicNs": deadline_monotonic_ns,
            "configurationDigest": self.configuration.digest,
            "operationManifestDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "issuedAtEpochNs": time.time_ns(),
        }
        if self.signing_key is None:
            raise AuthorityServiceError("verifier signer is unavailable")
        request = {
            **unsigned_request,
            "signature": _b64url_encode(
                self.signing_key.sign(
                    _domain_digest(
                        "serverware.policyAuthorityReplayWitnessRequest/v1",
                        _canonical(unsigned_request),
                    ).encode("ascii")
                )
            ),
        }
        response = _socket_request(
            str(witness["socketPath"]),
            request,
            timeout_seconds=(
                float(witness["requestTimeoutSeconds"])
                if phase in {"abort", "reconcile"}
                else min(
                    float(witness["requestTimeoutSeconds"]),
                    max(
                        0.001,
                        (
                            deadline_monotonic_ns
                            - time.monotonic_ns()
                        )
                        / 1_000_000_000,
                    ),
                )
            ),
            expected_peer_uid=int(witness["serviceUid"]),
            expected_peer_gid=int(witness["serviceGid"]),
        )
        signature = _b64url_decode(response.get("signature"), size=64)
        unsigned_response = dict(response)
        unsigned_response.pop("signature", None)
        required_fields = {
            "schema",
            "phase",
            "operation",
            "requestDigest",
            "capabilityId",
            "resultDigest",
            "witnessIdentityDigest",
            "sequence",
            "fence",
            "headDigest",
            "predecessorHeadDigest",
            "predecessorReceiptDigest",
            "logPredecessorHeadDigest",
            "deadlineMonotonicNs",
            "issuedAtEpochNs",
            "signature",
        }
        expected_predecessor_head = (
            None
            if predecessor_receipt is None
            else predecessor_receipt.get("headDigest")
        )
        expected_fence = (
            None
            if predecessor_receipt is None
            else predecessor_receipt.get("fence")
        )
        head_material = dict(unsigned_response)
        head_material["headDigest"] = None
        if (
            set(response) != required_fields
            or response.get("schema")
            != authority_contract.WITNESS_SCHEMA
            or response.get("phase") != phase
            or response.get("operation") != operation
            or response.get("requestDigest") != request_digest
            or response.get("capabilityId") != capability_id
            or response.get("resultDigest") != result_digest
            or response.get("witnessIdentityDigest")
            != witness.get("identityDigest")
            or not isinstance(response.get("sequence"), int)
            or response["sequence"] < 1
            or not isinstance(response.get("fence"), int)
            or response["fence"] < 1
            or response.get("deadlineMonotonicNs")
            != deadline_monotonic_ns
            or response.get("predecessorReceiptDigest")
            != predecessor_digest
            or response.get("predecessorHeadDigest")
            != expected_predecessor_head
            or (
                expected_fence is not None
                and response.get("fence") != expected_fence
            )
            or _require_digest(
                response.get("headDigest"),
                "witness head digest",
            )
            != _domain_digest(
                "serverware.policyAuthorityReplayWitnessHead/v1",
                _canonical(head_material),
            )
            or not isinstance(response.get("issuedAtEpochNs"), int)
            or response["issuedAtEpochNs"] > time.time_ns()
            or (
                response["sequence"] == 1
                and response.get("logPredecessorHeadDigest")
                    is not None
            )
            or (
                response["sequence"] > 1
                and _require_digest(
                    response.get("logPredecessorHeadDigest"),
                    "witness log predecessor head digest",
                )
                    != response.get("logPredecessorHeadDigest")
            )
            or (
                response.get("logPredecessorHeadDigest") is not None
                and not isinstance(
                    response.get("logPredecessorHeadDigest"), str
                )
            )
            or (
                phase not in {"abort", "reconcile"}
                and time.monotonic_ns() >= deadline_monotonic_ns
            )
        ):
            raise AuthorityServiceError(
                "external replay witness response is not exact"
            )
        witness_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                witness["signingPublicKeyBase64Url"], size=32
            )
        )
        try:
            witness_key.verify(
                signature,
                _domain_digest(
                    authority_contract.WITNESS_SCHEMA,
                    _canonical(unsigned_response),
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "external replay witness signature is invalid"
            ) from exc
        return dict(response)

    def _persist_writer_witness_receipt(
        self,
        receipt: Mapping[str, Any],
    ) -> str:
        if (
            self.role_name != "verifier"
            or receipt.get("phase") not in {
                "commit",
                "reconcile",
                "abort",
            }
            or not isinstance(receipt.get("deadlineMonotonicNs"), int)
            or not isinstance(receipt.get("fence"), int)
        ):
            raise AuthorityServiceError(
                "writer witness persistence request is invalid"
            )
        receipt_value = dict(receipt)
        receipt_digest = _domain_digest(
            WITNESS_RECEIPT_SCHEMA_V2,
            _canonical(receipt_value),
        )
        issuer = self.configuration.role("issuer")
        persisted = _socket_request(
            str(issuer["socketPath"]),
            self._sign_internal(
                "record-witness-receipt",
                {
                    "witnessReceipt": receipt_value,
                    "witnessReceiptDigest": receipt_digest,
                    "authorizationDeadlineMonotonicNs":
                        receipt["deadlineMonotonicNs"],
                },
                fence=receipt["fence"],
                envelope_id=receipt_digest,
            ),
            timeout_seconds=float(issuer["requestTimeoutSeconds"]),
            expected_peer_uid=int(issuer["serviceUid"]),
            expected_peer_gid=int(issuer["serviceGid"]),
        )
        if persisted != {"witnessReceiptDigest": receipt_digest}:
            raise AuthorityServiceError(
                "writer witness persistence result changed"
            )
        return receipt_digest

    @staticmethod
    def _policy_argument_value(value: Any) -> Any:
        if isinstance(value, list):
            return [
                AuthorityProcess._policy_argument_value(item)
                for item in value
            ]
        if not isinstance(value, Mapping):
            return value
        value_type = value.get("$authorityType")
        if (
            value_type in {"set", "tuple"}
            and set(value) == {"$authorityType", "items"}
            and isinstance(value["items"], list)
        ):
            return sorted(
                (
                    AuthorityProcess._policy_argument_value(item)
                    for item in value["items"]
                ),
                key=lambda item: _canonical(item),
            )
        return {
            str(key): AuthorityProcess._policy_argument_value(item)
            for key, item in value.items()
        }

    @staticmethod
    def _approver_policy_material(
        arguments: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        aliases = {
            "requiredApproverRoles": (
                "required_approver_roles",
                "required_roles",
            ),
            "allowedApproverIds": ("allowed_approver_ids",),
            "requireWebAuthn": (
                "require_webauthn",
                "require_approver_webauthn",
            ),
            "threshold": ("threshold", "approval_threshold"),
            "credentialPolicy": (
                "credential_policy",
                "approver_credential_policy",
            ),
        }
        material: dict[str, Any] = {
            "schema": "serverware.authorityApproverPolicyBinding/v1"
        }
        missing = False
        for output_name, input_names in aliases.items():
            found = False
            for input_name in input_names:
                if input_name in arguments:
                    material[output_name] = (
                        AuthorityProcess._policy_argument_value(
                            arguments[input_name]
                        )
                    )
                    found = True
                    break
            if not found:
                missing = True
        if missing:
            return None
        allowed_ids = material["allowedApproverIds"]
        if allowed_ids is None:
            material["allowedApproverIds"] = []
            material["allowAnyApproverId"] = True
        else:
            if not isinstance(allowed_ids, list):
                return None
            material["allowedApproverIds"] = sorted(allowed_ids)
            material["allowAnyApproverId"] = False
        roles = material["requiredApproverRoles"]
        if not isinstance(roles, list):
            return None
        material["requiredApproverRoles"] = sorted(roles)
        if (
            not isinstance(material["requireWebAuthn"], bool)
            or not isinstance(material["threshold"], int)
            or isinstance(material["threshold"], bool)
            or material["threshold"] < 1
            or not isinstance(material["credentialPolicy"], Mapping)
        ):
            return None
        material["credentialPolicy"] = dict(
            material["credentialPolicy"]
        )
        return material

    @staticmethod
    def _approver_policy_digest(
        arguments: Mapping[str, Any],
    ) -> str | None:
        material = AuthorityProcess._approver_policy_material(arguments)
        if material is None:
            return None
        return _domain_digest(
            "serverware.authorityApproverPolicyBinding/v1",
            _canonical(material),
        )

    @staticmethod
    def _enforce_approver_webauthn_policy(
        *,
        arguments: Mapping[str, Any],
        challenge: Mapping[str, Any],
        credential: Mapping[str, Any],
    ) -> None:
        policy = AuthorityProcess._approver_policy_material(arguments)
        if policy is None:
            raise AuthorityServiceError(
                "approver WebAuthn policy is not closed"
            )
        credential_policy = policy["credentialPolicy"]
        approver_id = (
            AuthorityProcess._policy_argument_value(
                arguments.get("actor_id")
            )
            or AuthorityProcess._policy_argument_value(
                arguments.get("approver_id")
            )
        )
        allowed_approvers = policy["allowedApproverIds"]
        allowed_credentials = credential_policy.get(
            "allowedCredentialRecordIds", []
        )
        allowed_classes = credential_policy.get(
            "allowedAuthenticatorClasses", []
        )
        allowed_aaguids = credential_policy.get(
            "allowedAaguids", []
        )
        minimum_sequence = credential_policy.get(
            "minimumTrustBundleSequence"
        )
        issued_at_ns = challenge.get("issuedAtEpochNs")
        maximum_age_seconds = credential_policy.get(
            "maxAssertionAgeSeconds"
        )
        if (
            not isinstance(approver_id, str)
            or (
                not policy["allowAnyApproverId"]
                and approver_id not in allowed_approvers
            )
            or not isinstance(allowed_credentials, list)
            or (
                allowed_credentials
                and credential.get("credentialRecordId")
                    not in allowed_credentials
            )
            or not isinstance(allowed_classes, list)
            or credential.get("authenticatorClass")
                not in allowed_classes
            or not isinstance(allowed_aaguids, list)
            or (
                allowed_aaguids
                and credential.get("aaguid") not in allowed_aaguids
            )
            or credential_policy.get(
                "requireAttestationTrusted", True
            )
            and credential.get("attestationTrusted") is not True
            or (
                credential_policy.get("requiredTrustBundleDigest")
                is not None
                and credential.get("trustBundleDigest")
                    != credential_policy[
                        "requiredTrustBundleDigest"
                    ]
            )
            or (
                minimum_sequence is not None
                and (
                    not isinstance(minimum_sequence, int)
                    or credential.get("trustBundleSequence", 0)
                        < minimum_sequence
                )
            )
            or credential_policy.get("rpId")
                != challenge.get("rpId")
            or challenge.get("origin")
                not in credential_policy.get("origins", [])
            or credential_policy.get("requireUserPresence") is not True
            or credential_policy.get("requireUserVerification")
                is not True
            or not isinstance(issued_at_ns, int)
            or not isinstance(maximum_age_seconds, int)
            or time.time_ns() - issued_at_ns >
                maximum_age_seconds * 1_000_000_000
        ):
            raise AuthorityServiceError(
                "WebAuthn credential violates the approver policy"
            )

    @staticmethod
    def _webauthn_reference_from_arguments(
        arguments: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        evidence = arguments.get("authn_evidence")
        if not isinstance(evidence, Mapping):
            evidence = arguments.get("authn")
        if not isinstance(evidence, Mapping):
            evidence = arguments.get("webauthn_authorization")
        if not isinstance(evidence, Mapping):
            return None
        assertion = evidence.get("assertion")
        challenge_id = (
            arguments.get("challenge_id")
            or evidence.get("challenge_id")
            or evidence.get("challengeId")
        )
        credential_id = (
            evidence.get("credential_id")
            or evidence.get("credentialId")
        )
        credential_record_id = (
            evidence.get("credential_record_id")
            or evidence.get("credentialRecordId")
        )
        if not isinstance(assertion, Mapping):
            return None
        assertion_value = dict(assertion)
        browser_response = assertion_value.get("response")
        if isinstance(browser_response, Mapping):
            browser_credential_id = (
                assertion_value.get("id")
                or assertion_value.get("rawId")
            )
            if (
                not isinstance(browser_credential_id, str)
                or not {
                    "clientDataJSON",
                    "authenticatorData",
                    "signature",
                } <= set(browser_response)
            ):
                return None
            assertion_value = {
                "credentialId": browser_credential_id,
                "clientDataJSON": browser_response["clientDataJSON"],
                "authenticatorData":
                    browser_response["authenticatorData"],
                "signature": browser_response["signature"],
            }
        reference = {
            "challengeId": challenge_id,
            "assertion": assertion_value,
        }
        if credential_id is not None:
            reference["credentialId"] = credential_id
        elif credential_record_id is not None:
            reference["credentialRecordId"] = credential_record_id
        else:
            return None
        return reference

    def _planner_identity(self) -> authority_planner.PlannerIdentity:
        planner_config = self.configuration.role("planner")
        return authority_planner.PlannerIdentity.from_mapping(
            {
                "databaseRole": planner_config["databaseRole"],
                "tlsClientDn": planner_config["tlsClientDn"],
                "tlsClientSerial": planner_config["tlsClientSerial"],
                "tlsIssuerDn": planner_config["tlsIssuerDn"],
                "sessionIdentityDigest":
                    planner_config["plannerSessionIdentityDigest"],
                "measurementDigest":
                    planner_config["measurementDigest"],
                "attestationReceiptDigest":
                    planner_config["attestationReceiptDigest"],
            }
        )

    def _build_v9_webauthn_evidence(
        self,
        *,
        operation: str,
        operation_id: str,
        request_digest: str,
        capability_id: str,
        authorization_reference: Mapping[str, Any],
        deadline_epoch_ns: int,
        arguments: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        challenge, credential, assertion = self._read_webauthn_authority(
            authorization=authorization_reference,
            operation_id=operation_id,
        )
        if authority_contract.operation_spec(operation)[
            "approverPolicyRequired"
        ]:
            self._enforce_approver_webauthn_policy(
                arguments=arguments,
                challenge=challenge,
                credential=credential,
            )
        receipt, receipt_digest = _verify_webauthn_authorization(
            {
                "challenge": challenge,
                "credential": credential,
                "assertion": assertion,
            },
            expected_operation_id=operation_id,
            configuration=self.configuration,
        )
        client_data = _b64url_decode(assertion["clientDataJSON"])
        authenticator_data = _b64url_decode(
            assertion["authenticatorData"]
        )
        signature = _b64url_decode(assertion["signature"])
        try:
            client_value = json.loads(client_data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorityServiceError(
                "verified WebAuthn client data changed"
            ) from exc
        challenge_bytes = _b64url_decode(client_value["challenge"])
        verified_at = int(receipt["verifiedAtEpochNs"])
        expires_at = min(
            int(challenge["expiresAtEpochNs"]),
            deadline_epoch_ns,
        )
        verifier_identity_digest = _domain_digest(
            "serverware.policyAuthorityVerifierSession/v2",
            self.configuration.digest.encode("ascii"),
            self.role_config["measurementDigest"].encode("ascii"),
            self.role_config["attestationReceiptDigest"].encode(
                "ascii"
            ),
        )
        evidence = {
            "operation": operation,
            "operationId": operation_id,
            "requestDigest": request_digest,
            "capabilityId": capability_id,
            "challengeId": receipt["challengeId"],
            "challengeDigest": receipt["challengeDigest"],
            "clientChallengeDigest": _sha256(challenge_bytes),
            "credentialRecordId": receipt["credentialRecordId"],
            "credentialId": receipt["credentialId"],
            "credentialPolicyDigest":
                receipt["credentialPolicyDigest"],
            "authenticatorDataBase64url":
                assertion["authenticatorData"],
            "authenticatorDataDigest": _sha256(authenticator_data),
            "clientDataJSONBase64url": assertion["clientDataJSON"],
            "clientDataJSONDigest": _sha256(client_data),
            "signatureBase64url": assertion["signature"],
            "signatureDigest": _sha256(signature),
            "rpId": challenge["rpId"],
            "rpIdHashDigest": _sha256(
                str(challenge["rpId"]).encode("utf-8")
            ),
            "origin": challenge["origin"],
            "flags": receipt["flags"],
            "userPresent": True,
            "userVerified": True,
            "priorCounter": receipt["priorCounter"],
            "counter": receipt["counter"],
            "trustHighWaterDigest":
                receipt["trustHighWaterDigest"],
            "metadataPublicationSequence":
                credential["trustBundleSequence"],
            "verifierSessionIdentityDigest":
                verifier_identity_digest,
            "verifierMeasurementDigest":
                self.role_config["measurementDigest"],
            "verifierAttestationReceiptDigest":
                self.role_config["attestationReceiptDigest"],
            "verifiedAtEpochNs": verified_at,
            "expiresAtEpochNs": expires_at,
        }
        if self.signing_key is None:
            raise AuthorityServiceError(
                "WebAuthn evidence verifier signer is unavailable"
            )
        evidence_receipt_digest = _domain_digest(
            "serverware."
            "policyAuthorityVerifiedWebAuthnAssertionReceipt/v1",
            _canonical(evidence),
        )
        verifier_signature = self.signing_key.sign(
            evidence_receipt_digest.encode("ascii")
        )
        evidence["verifiedAssertionReceiptDigest"] = (
            evidence_receipt_digest
        )
        evidence["verifierSignatureBase64url"] = _b64url_encode(
            verifier_signature
        )
        evidence["verifierSignatureDigest"] = _sha256(
            verifier_signature
        )
        return evidence, receipt, receipt_digest

    def _execute_v9_operation(
        self,
        *,
        operation: str,
        handler_name: str,
        runtime_input: dict[str, Any],
        deadline_monotonic_ns: int,
    ) -> dict[str, Any]:
        if (
            operation
                not in authority_transition_registry.PLANNABLE_OPERATIONS
            or operation
                not in self.configuration.role("planner")[
                    "enabledOperations"
                ]
        ):
            raise AuthorityServiceError(
                "authority operation has no enabled exact transition program"
            )
        spec = authority_contract.operation_spec(operation)
        if handler_name != spec["handler"]:
            raise AuthorityServiceError(
                "typed authority handler binding changed"
            )
        if (
            set(runtime_input)
            == {
                "schema",
                "handler",
                "operationManifestDigest",
                "arguments",
            }
            and runtime_input.get("schema")
                == "serverware.policyAuthorityControlledWriterInput/v1"
            and runtime_input.get("handler") == handler_name
            and runtime_input.get("operationManifestDigest")
                == authority_contract.OPERATION_MANIFEST_DIGEST
            and isinstance(runtime_input.get("arguments"), dict)
        ):
            arguments = dict(runtime_input["arguments"])
            explicit_webauthn = None
        elif (
            set(runtime_input) == {"input", "webauthnAuthorization"}
            and isinstance(runtime_input.get("input"), dict)
            and isinstance(
                runtime_input.get("webauthnAuthorization"), dict
            )
        ):
            arguments = dict(runtime_input["input"])
            explicit_webauthn = dict(
                runtime_input["webauthnAuthorization"]
            )
        else:
            raise AuthorityServiceError(
                "authority v9 accepts only semantic typed input"
            )
        if "businessIntent" in arguments:
            raise AuthorityServiceError(
                "caller-supplied authority businessIntent is forbidden"
            )
        authority_planner.reject_authoritative_input(arguments)
        typed_arguments = _synthesize_business_arguments(
            operation,
            arguments,
        )
        authorization_material = {
            "schema": "serverware.policyAuthorityV9Authorization/v1",
            "operation": operation,
            "handler": handler_name,
            "operationManifestDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "arguments": _authorization_arguments(typed_arguments),
        }
        request_digest = _domain_digest(
            "serverware.policyAuthorityV9Request/v1",
            _canonical(authorization_material),
        )
        operation_identifier = _domain_digest(
            "serverware.policyAuthorityOperation/v2",
            operation.encode("ascii"),
            request_digest.encode("ascii"),
        )
        typed_request = {
            "schema": "serverware.policyAuthorityV9Request/v1",
            "operation": operation,
            "operationId": operation_identifier,
            "requestDigest": request_digest,
            "handler": handler_name,
            "operationManifestDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "arguments": typed_arguments,
        }
        authority_planner.reject_authoritative_input(typed_request)
        issued_monotonic_ns = time.monotonic_ns()
        issued_at_epoch_ns = time.time_ns()
        remaining_ns = deadline_monotonic_ns - issued_monotonic_ns
        if remaining_ns <= 0:
            raise AuthorityServiceError(
                "authority v9 deadline expired before planning"
            )
        deadline_epoch_ns = issued_at_epoch_ns + remaining_ns
        capability_id = _domain_digest(
            "serverware.policyAuthorityDatabaseCapabilityId/v3",
            operation_identifier.encode("ascii"),
            request_digest.encode("ascii"),
            os.urandom(32),
        )
        planner_transaction_id = _domain_digest(
            "serverware.policyAuthorityPlannerTransaction/v1",
            operation_identifier.encode("ascii"),
            request_digest.encode("ascii"),
            capability_id.encode("ascii"),
        )
        reservation = self._witness_transition(
            phase=(
                "webauthn-trust-publish"
                if operation == "webauthn.trust.complete"
                else "reserve"
            ),
            operation=operation,
            request_digest=request_digest,
            capability_id=capability_id,
            deadline_monotonic_ns=deadline_monotonic_ns,
        )
        approver_policy_digest = self._approver_policy_digest(
            arguments
        )
        if (
            spec["approverPolicyRequired"]
            and approver_policy_digest is None
        ):
            raise AuthorityServiceError(
                "authority v9 approver policy is absent"
            )
        webauthn_evidence = None
        webauthn_receipt = None
        webauthn_receipt_digest = None
        webauthn_trust_high_water_digest = None
        if spec["assertionRequired"]:
            reference = (
                explicit_webauthn
                if explicit_webauthn is not None
                else self._webauthn_reference_from_arguments(arguments)
            )
            if reference is None:
                raise AuthorityServiceError(
                    "authority v9 requires a raw WebAuthn assertion"
                )
            (
                webauthn_evidence,
                webauthn_receipt,
                webauthn_receipt_digest,
            ) = self._build_v9_webauthn_evidence(
                operation=operation,
                operation_id=operation_identifier,
                request_digest=request_digest,
                capability_id=capability_id,
                authorization_reference=reference,
                deadline_epoch_ns=deadline_epoch_ns,
                arguments=arguments,
            )
            webauthn_trust_high_water_digest = (
                webauthn_receipt["trustHighWaterDigest"]
            )
        planner_request = {
            "schema": authority_planner.PLANNER_REQUEST_SCHEMA,
            "plannerTransactionId": planner_transaction_id,
            "operation": operation,
            "operationId": operation_identifier,
            "requestDigest": request_digest,
            "capabilityId": capability_id,
            "typedRequest": typed_request,
            "approverPolicyDigest": approver_policy_digest,
            "webauthnEvidence": webauthn_evidence,
            "verifierIdentity": {
                "sessionIdentityDigest": _domain_digest(
                    "serverware.policyAuthorityVerifierSession/v2",
                    self.configuration.digest.encode("ascii"),
                    self.role_config["measurementDigest"].encode(
                        "ascii"
                    ),
                    self.role_config[
                        "attestationReceiptDigest"
                    ].encode("ascii"),
                ),
                "measurementDigest":
                    self.role_config["measurementDigest"],
                "attestationReceiptDigest":
                    self.role_config["attestationReceiptDigest"],
            },
            "queryManifestDigest":
                self.configuration.payload["queryManifestDigest"],
            "deadlineMonotonicNs": deadline_monotonic_ns,
            "deadlineEpochNs": deadline_epoch_ns,
            "fence": reservation["fence"],
            "reservedAtEpochNs": issued_at_epoch_ns,
        }
        planner_config = self.configuration.role("planner")
        planned = _socket_request(
            str(planner_config["socketPath"]),
            self._sign_internal(
                "plan-operation",
                {"plannerRequest": planner_request},
                deadline_monotonic_ns=deadline_monotonic_ns,
                fence=reservation["fence"],
                envelope_id=planner_transaction_id,
            ),
            timeout_seconds=min(
                float(planner_config["requestTimeoutSeconds"]),
                max(
                    0.001,
                    (
                        deadline_monotonic_ns - time.monotonic_ns()
                    ) / 1_000_000_000,
                ),
            ),
            expected_peer_uid=int(planner_config["serviceUid"]),
            expected_peer_gid=int(planner_config["serviceGid"]),
        )
        if (
            set(planned) != {
                "signedMeasuredPlan",
                "persistenceReceipt",
            }
            or not isinstance(planned["signedMeasuredPlan"], dict)
            or not isinstance(planned["persistenceReceipt"], dict)
        ):
            raise AuthorityServiceError(
                "measured planner response is not closed"
            )
        signed_plan = dict(planned["signedMeasuredPlan"])
        if (
            set(signed_plan)
            != {"schema", "payload", "signatureBase64Url"}
            or signed_plan.get("schema")
                != authority_planner.SIGNED_MEASURED_PLAN_SCHEMA
            or not isinstance(signed_plan.get("payload"), dict)
        ):
            raise AuthorityServiceError(
                "signed measured plan is invalid"
            )
        planner_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                planner_config["signingPublicKeyBase64Url"],
                size=32,
            )
        )
        try:
            planner_key.verify(
                _b64url_decode(
                    signed_plan["signatureBase64Url"], size=64
                ),
                authority_planner.measured_plan_signature_message(
                    signed_plan["payload"]
                ),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "measured planner signature is invalid"
            ) from exc
        try:
            authority_planner.validate_measured_plan_payload(
                signed_plan["payload"],
                expected_identity=self._planner_identity(),
            )
        except authority_planner.AuthorityPlannerError as exc:
            raise AuthorityServiceError(
                "signed measured plan is not an exact typed plan"
            ) from exc
        plan_payload = signed_plan["payload"]
        measured_plan = plan_payload.get("measuredPlan")
        persistence_receipt = planned["persistenceReceipt"]
        if (
            not isinstance(measured_plan, dict)
            or measured_plan.get("plannerTransactionId")
                != planner_transaction_id
            or measured_plan.get("operation") != operation
            or measured_plan.get("operationId")
                != operation_identifier
            or measured_plan.get("requestDigest") != request_digest
            or measured_plan.get("capabilityId") != capability_id
            or measured_plan.get("deadlineMonotonicNs")
                != deadline_monotonic_ns
            or measured_plan.get("deadlineEpochNs")
                != deadline_epoch_ns
            or measured_plan.get("fence") != reservation["fence"]
            or persistence_receipt
                != self._planner_persistence_receipt(plan_payload)
            or time.monotonic_ns() >= deadline_monotonic_ns
        ):
            raise AuthorityServiceError(
                "measured plan or persistence receipt binding changed"
            )
        witness_reservation_digest = _domain_digest(
            WITNESS_RECEIPT_SCHEMA_V2,
            _canonical(reservation),
        )
        capability = {
            "schema": authority_contract.CAPABILITY_SCHEMA,
            "capabilityId": capability_id,
            "envelopeId": _domain_digest(
                "serverware.policyAuthorityExecutionEnvelope/v1",
                capability_id.encode("ascii"),
                planner_transaction_id.encode("ascii"),
            ),
            "plannerTransactionId": planner_transaction_id,
            "authorizationProjectionDigest":
                measured_plan["authorizationProjectionDigest"],
            "selectedBusinessRowsDigest":
                measured_plan["selectedBusinessRowsDigest"],
            "mutationPlanDigest":
                measured_plan["mutationPlanDigest"],
            "expectedResultDigest":
                plan_payload["expectedResultDigest"],
            "operation": operation,
            "operationId": operation_identifier,
            "handlerName": handler_name,
            "requestDigest": request_digest,
            "operationManifestDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "queryManifestDigest":
                measured_plan["queryManifestDigest"],
            "authorityRootSetDigest":
                measured_plan["authorityRootSetBeforeDigest"],
            "authoritySnapshotDigest":
                measured_plan["authoritySnapshotDigest"],
            "approverPolicyDigest": approver_policy_digest,
            "webauthnReceipt": webauthn_receipt,
            "webauthnReceiptDigest": webauthn_receipt_digest,
            "webauthnTrustHighWaterDigest":
                webauthn_trust_high_water_digest,
            "witnessReservation": reservation,
            "witnessReservationDigest":
                witness_reservation_digest,
            "witnessSequence": reservation["sequence"],
            "witnessHeadDigest": reservation["headDigest"],
            "witnessPredecessorHeadDigest":
                reservation["predecessorHeadDigest"],
            "deadlineMonotonicNs": deadline_monotonic_ns,
            "deadlineEpochNs": deadline_epoch_ns,
            "fence": reservation["fence"],
            "issuedMonotonicNs": issued_monotonic_ns,
            "issuedAtEpochNs": issued_at_epoch_ns,
            "expiresAtEpochNs": deadline_epoch_ns,
            "issuerSessionIdentityDigest":
                self.configuration.payload[
                    "issuerSessionIdentityDigest"
                ],
        }
        capability_digest = _domain_digest(
            authority_contract.CAPABILITY_SCHEMA,
            _canonical(capability),
        )
        issuer = self.configuration.role("issuer")
        issued = _socket_request(
            str(issuer["socketPath"]),
            self._sign_internal(
                "issue-capability",
                {
                    "capability": capability,
                    "capabilityDigest": capability_digest,
                },
                deadline_monotonic_ns=deadline_monotonic_ns,
                fence=reservation["fence"],
                envelope_id=capability_id,
                parent_envelope_id=planner_transaction_id,
            ),
            timeout_seconds=float(issuer["requestTimeoutSeconds"]),
            expected_peer_uid=int(issuer["serviceUid"]),
            expected_peer_gid=int(issuer["serviceGid"]),
        )
        if issued != {"capabilityId": capability_id}:
            raise AuthorityServiceError(
                "v9 capability issuance response changed"
            )
        exact_request_bytes = _canonical(typed_request)
        exact_result_bytes = _canonical(
            plan_payload["expectedResult"]
        )
        planner_writer = self.configuration.role("planner-writer")
        execution_reservation = _socket_request(
            str(planner_writer["socketPath"]),
            self._sign_internal(
                "reserve-execution-envelope",
                {
                    "envelopeId": capability["envelopeId"],
                    "parentEnvelopeId": planner_transaction_id,
                    "operation": operation,
                    "operationId": operation_identifier,
                    "requestDigest": request_digest,
                    "capabilityId": capability_id,
                    "plannerTransactionId":
                        planner_transaction_id,
                    "authorizationProjectionDigest":
                        measured_plan[
                            "authorizationProjectionDigest"
                        ],
                    "exactRequestBase64Url":
                        _b64url_encode(exact_request_bytes),
                    "deadlineMonotonicNs":
                        deadline_monotonic_ns,
                    "deadlineEpochNs": deadline_epoch_ns,
                    "fence": reservation["fence"],
                    "reservedAtEpochNs": issued_at_epoch_ns,
                },
                deadline_monotonic_ns=deadline_monotonic_ns,
                fence=reservation["fence"],
                envelope_id=_domain_digest(
                    "serverware.policyAuthorityExecutionReservationEnvelope/v1",
                    capability["envelopeId"].encode("ascii"),
                    request_digest.encode("ascii"),
                ),
                parent_envelope_id=planner_transaction_id,
            ),
            timeout_seconds=float(
                planner_writer["requestTimeoutSeconds"]
            ),
            expected_peer_uid=int(planner_writer["serviceUid"]),
            expected_peer_gid=int(planner_writer["serviceGid"]),
        )
        if (
            execution_reservation
            != {
                "schema":
                    authority_planner.EXECUTION_RESERVATION_RECEIPT_SCHEMA,
                "envelopeId": capability["envelopeId"],
                "plannerTransactionId": planner_transaction_id,
                "requestDigest": request_digest,
                "exactRequestBytesDigest":
                    _sha256(exact_request_bytes),
                "deadlineMonotonicNs": deadline_monotonic_ns,
                "fence": reservation["fence"],
                "status": "reserved",
            }
        ):
            raise AuthorityServiceError(
                "v9 execution reservation response changed"
            )
        executor = self.configuration.role("executor")
        executed = _socket_request(
            str(executor["socketPath"]),
            self._sign_internal(
                "execute-v9",
                {
                    "capabilityId": capability_id,
                    "envelopeId": capability["envelopeId"],
                    "parentEnvelopeId": planner_transaction_id,
                    "plannerTransactionId": planner_transaction_id,
                    "authorizationProjectionDigest":
                        measured_plan[
                            "authorizationProjectionDigest"
                        ],
                    "exactRequestBase64Url":
                        _b64url_encode(exact_request_bytes),
                    "exactResultBase64Url":
                        _b64url_encode(exact_result_bytes),
                    "deadlineMonotonicNs": deadline_monotonic_ns,
                    "deadlineEpochNs": deadline_epoch_ns,
                    "fence": reservation["fence"],
                    "reservedAtEpochNs": issued_at_epoch_ns,
                },
                deadline_monotonic_ns=deadline_monotonic_ns,
                fence=reservation["fence"],
                envelope_id=capability["envelopeId"],
                parent_envelope_id=planner_transaction_id,
            ),
            timeout_seconds=float(executor["requestTimeoutSeconds"]),
            expected_peer_uid=int(executor["serviceUid"]),
            expected_peer_gid=int(executor["serviceGid"]),
        )
        if (
            set(executed)
            != {
                "receipt",
                "receiptDigest",
                "result",
                "resultDigest",
            }
            or _canonical(executed["result"]) != _canonical(plan_payload["expectedResult"])
            or executed["resultDigest"]
                != plan_payload["expectedResultDigest"]
            or not isinstance(executed["receipt"], dict)
            or executed["receipt"].get("schema")
                != "serverware.policyAuthorityWriterCommitReceipt/v2"
            or executed["receipt"].get("capabilityId") != capability_id
            or executed["receipt"].get("envelopeId") != capability["envelopeId"]
            or executed["receipt"].get("plannerTransactionId") != planner_transaction_id
            or executed["receipt"].get("requestDigest") != request_digest
            or executed["receipt"].get("resultDigest") != plan_payload["expectedResultDigest"]
            or executed["receipt"].get("authoritySnapshotDigest")
                != measured_plan["authoritySnapshotDigest"]
            or executed["receipt"].get("authorityRootSetBeforeDigest")
                != measured_plan["authorityRootSetBeforeDigest"]
            or executed["receipt"].get("authorityRootSetAfterDigest") != _domain_digest(
                "serverware.policyAuthorityRootSet/v1",
                _canonical(plan_payload["rootTransition"]["businessAfterRoots"]),
            )
            or executed["receiptDigest"] != _domain_digest(
                "serverware.policyAuthorityWriterCommitReceipt/v2",
                _canonical(executed["receipt"]),
            )
        ):
            raise AuthorityServiceError(
                "v9 executor result binding changed"
            )
        committed_late = time.monotonic_ns() >= deadline_monotonic_ns
        terminal = self._witness_transition(
            phase="reconcile" if committed_late else "commit",
            operation=operation,
            request_digest=request_digest,
            capability_id=capability_id,
            result_digest=executed["resultDigest"],
            predecessor_receipt=reservation,
            deadline_monotonic_ns=deadline_monotonic_ns,
        )
        witness_commit_digest = self._persist_writer_witness_receipt(
            terminal
        )
        if committed_late:
            raise AuthorityServiceError(
                "authority v9 commit crossed its absolute deadline"
            )
        return {
            "result": executed["result"],
            "resultDigest": executed["resultDigest"],
            "commitReceiptDigest": executed["receiptDigest"],
            "witnessCommitDigest": witness_commit_digest,
            "fence": reservation["fence"],
        }

    @staticmethod
    def _planner_persistence_receipt(
        planner_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        measured_plan = planner_payload["measuredPlan"]
        return {
            "schema": authority_planner.PLANNER_PERSIST_RECEIPT_SCHEMA,
            "plannerTransactionId":
                measured_plan["plannerTransactionId"],
            "authorizationProjectionDigest":
                measured_plan["authorizationProjectionDigest"],
            "authoritySnapshotDigest":
                measured_plan["authoritySnapshotDigest"],
            "expectedResultDigest":
                planner_payload["expectedResultDigest"],
            "plannerTraceDigest":
                planner_payload["plannerTraceDigest"],
            "queryMultiproofsDigest":
                planner_payload["queryMultiproofsDigest"],
        }

    def _handle_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        if set(payload) != {"plannerRequest"} or not isinstance(
            payload["plannerRequest"], dict
        ):
            raise AuthorityServiceError(
                "planner internal request is not closed"
            )
        if self.signing_key is None or self.role_name != "planner":
            raise AuthorityServiceError(
                "measured planner signer is unavailable"
            )
        planner_request = payload["plannerRequest"]
        authority_planner.validate_planner_request(planner_request)
        verifier_config = self.configuration.role("verifier")
        planner = authority_planner.MeasuredPlanner(
            read_dsn=_read_dsn_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"
            ),
            identity=self._planner_identity(),
            connect_timeout_seconds=int(
                self.role_config["databaseConnectTimeoutSeconds"]
            ),
            enabled_operations=tuple(
                self.role_config["enabledOperations"]
            ),
            verifier_public_key=Ed25519PublicKey.from_public_bytes(
                _b64url_decode(verifier_config["signingPublicKeyBase64Url"], size=32)
            ),
            verifier_identity={
                "sessionIdentityDigest": _domain_digest(
                    "serverware.policyAuthorityVerifierSession/v2",
                    self.configuration.digest.encode("ascii"),
                    verifier_config["measurementDigest"].encode("ascii"),
                    verifier_config["attestationReceiptDigest"].encode("ascii"),
                ),
                "measurementDigest": verifier_config["measurementDigest"],
                "attestationReceiptDigest": verifier_config["attestationReceiptDigest"],
            },
            maximum_assertion_age_ns=int(
                self.configuration.payload["webauthn"]["maximumChallengeAgeNs"]
            ),
        )
        # Check the pinned embedded receipt even on a durable-plan replay, and
        # before asking another process for stored planning data.
        planner.verify_assertion_evidence(planner_request)
        writer = self.configuration.role("planner-writer")
        replay = _socket_request(
            str(writer["socketPath"]),
            self._sign_internal(
                "read-persisted-plan",
                {
                    "plannerTransactionId":
                        planner_request["plannerTransactionId"],
                    "operationId": planner_request["operationId"],
                    "requestDigest": planner_request["requestDigest"],
                    "capabilityId": planner_request["capabilityId"],
                },
                deadline_monotonic_ns=planner_request[
                    "deadlineMonotonicNs"
                ],
                fence=planner_request["fence"],
                envelope_id=_domain_digest(
                    "serverware.policyAuthorityPlannerReplayEnvelope/v1",
                    planner_request[
                        "plannerTransactionId"
                    ].encode("ascii"),
                ),
                parent_envelope_id=planner_request[
                    "plannerTransactionId"
                ],
            ),
            timeout_seconds=float(writer["requestTimeoutSeconds"]),
            expected_peer_uid=int(writer["serviceUid"]),
            expected_peer_gid=int(writer["serviceGid"]),
        )
        if (
            set(replay)
            != {
                "schema",
                "plannerTransactionId",
                "found",
                "plannerPayloadBase64Url",
                "plannerPayloadDigest",
            }
            or replay.get("schema")
                != authority_planner.PLANNER_REPLAY_RECEIPT_SCHEMA
            or replay.get("plannerTransactionId")
                != planner_request["plannerTransactionId"]
            or not isinstance(replay.get("found"), bool)
            or replay["found"]
                != (
                    replay.get("plannerPayloadBase64Url") is not None
                    and replay.get("plannerPayloadDigest") is not None
                )
        ):
            raise AuthorityServiceError(
                "planner durable replay receipt is not closed"
            )
        if replay["found"]:
            replay_bytes = authority_planner.decode_base64url(
                replay["plannerPayloadBase64Url"],
                label="durable planner payload",
            )
            if authority_planner.sha256(replay_bytes) != replay[
                "plannerPayloadDigest"
            ]:
                raise AuthorityServiceError(
                    "durable planner payload digest changed"
                )
            try:
                derived = json.loads(replay_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuthorityServiceError(
                    "durable planner payload is not JSON"
                ) from exc
            identity = self._planner_identity()
            authority_planner.validate_measured_plan_payload(
                derived,
                expected_identity=identity,
            )
            measured_plan = derived["measuredPlan"]
            if (
                _canonical(derived) != replay_bytes
                or measured_plan["plannerTransactionId"]
                    != planner_request["plannerTransactionId"]
                or measured_plan["operationId"]
                    != planner_request["operationId"]
                or measured_plan["requestDigest"]
                    != planner_request["requestDigest"]
                or measured_plan["capabilityId"]
                    != planner_request["capabilityId"]
                or planner_request["operation"] == "webauthn.credential.revoke"
                and _canonical(derived["webauthnEvidence"])
                    != _canonical(planner_request["webauthnEvidence"])
            ):
                raise AuthorityServiceError(
                    "durable planner payload identity changed"
                )
            signed_plan = {
                "schema":
                    authority_planner.SIGNED_MEASURED_PLAN_SCHEMA,
                "payload": derived,
                "signatureBase64Url": _b64url_encode(
                    self.signing_key.sign(
                        authority_planner.measured_plan_signature_message(
                            derived
                        )
                    )
                ),
            }
            return {
                "signedMeasuredPlan": signed_plan,
                "persistenceReceipt":
                    self._planner_persistence_receipt(derived),
            }
        derived = planner.derive(planner_request)
        signed_plan = {
            "schema":
                authority_planner.SIGNED_MEASURED_PLAN_SCHEMA,
            "payload": derived,
            "signatureBase64Url": _b64url_encode(
                self.signing_key.sign(
                    authority_planner.measured_plan_signature_message(
                        derived
                    )
                )
            ),
        }
        measured_plan = derived["measuredPlan"]
        persistence = _socket_request(
            str(writer["socketPath"]),
            self._sign_internal(
                "persist-measured-plan",
                {"signedMeasuredPlan": signed_plan},
                deadline_monotonic_ns=measured_plan[
                    "deadlineMonotonicNs"
                ],
                fence=measured_plan["fence"],
                envelope_id=_domain_digest(
                    "serverware.policyAuthorityPlannerPersistenceEnvelope/v1",
                    measured_plan[
                        "plannerTransactionId"
                    ].encode("ascii"),
                    derived["plannerTraceDigest"].encode("ascii"),
                ),
                parent_envelope_id=measured_plan[
                    "plannerTransactionId"
                ],
            ),
            timeout_seconds=float(writer["requestTimeoutSeconds"]),
            expected_peer_uid=int(writer["serviceUid"]),
            expected_peer_gid=int(writer["serviceGid"]),
        )
        return {
            "signedMeasuredPlan": signed_plan,
            "persistenceReceipt": persistence,
        }

    def _handle_read_persisted_plan(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        required = {
            "plannerTransactionId",
            "operationId",
            "requestDigest",
            "capabilityId",
        }
        if set(payload) != required:
            raise AuthorityServiceError(
                "planner replay request is not closed"
            )
        for field in required:
            _require_digest(payload[field], f"planner replay {field}")
        import psycopg
        from psycopg.rows import dict_row
        from serverware import db

        with psycopg.connect(
            _read_dsn_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"
            ),
            row_factory=dict_row,
            connect_timeout=int(
                self.role_config["databaseConnectTimeoutSeconds"]
            ),
            options="-c search_path=pg_catalog",
        ) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
                    )
                facade = db.PostgresMetadataConnection(connection)
                planner_payload = db.read_authority_planner_payload(
                    planner_transaction_id=payload[
                        "plannerTransactionId"
                    ],
                    operation_id=payload["operationId"],
                    request_digest=payload["requestDigest"],
                    capability_id=payload["capabilityId"],
                    connection=facade,
                )
        return {
            "schema": authority_planner.PLANNER_REPLAY_RECEIPT_SCHEMA,
            "plannerTransactionId": payload["plannerTransactionId"],
            "found": planner_payload is not None,
            "plannerPayloadBase64Url": (
                _b64url_encode(planner_payload)
                if planner_payload is not None
                else None
            ),
            "plannerPayloadDigest": (
                _sha256(planner_payload)
                if planner_payload is not None
                else None
            ),
        }

    def _handle_persist_measured_plan(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if set(payload) != {"signedMeasuredPlan"} or not isinstance(
            payload["signedMeasuredPlan"], dict
        ):
            raise AuthorityServiceError(
                "planner persistence request is not closed"
            )
        planner_config = self.configuration.role("planner")
        planner_key = Ed25519PublicKey.from_public_bytes(
            _b64url_decode(
                planner_config["signingPublicKeyBase64Url"],
                size=32,
            )
        )

        def verify(signature: bytes, message: bytes) -> None:
            try:
                planner_key.verify(signature, message)
            except InvalidSignature as exc:
                raise authority_planner.AuthorityPlannerError(
                    "planner persistence signature is invalid"
                ) from exc

        persistence = authority_planner.PlannerPersistence(
            persistence_dsn=_read_dsn_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"
            ),
            connect_timeout_seconds=int(
                self.role_config["databaseConnectTimeoutSeconds"]
            ),
            planner_public_key_verify=verify,
            expected_planner_identity=self._planner_identity(),
        )
        return persistence.persist(payload["signedMeasuredPlan"])

    def _handle_reserve_execution_envelope(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        writer = authority_planner.ExecutionEnvelopePersistence(
            persistence_dsn=_read_dsn_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"
            ),
            connect_timeout_seconds=int(
                self.role_config["databaseConnectTimeoutSeconds"]
            ),
        )
        return writer.reserve(payload)

    def _execute_controlled_writer(
        self,
        *,
        operation: str,
        input_value: dict[str, Any],
        deadline_monotonic_ns: int,
    ) -> dict[str, Any]:
        raise AuthorityServiceError(
            "legacy controlled-writer execution is disabled"
        )

    def _verify_and_apply_policy_operation(
        self,
        *,
        operation: str,
        runtime_input: dict[str, Any],
        deadline_monotonic_ns: int,
    ) -> dict[str, Any]:
        raise AuthorityServiceError(
            "legacy policy-operation verification is disabled"
        )

    def _handle_issue(self, payload: dict[str, Any]) -> dict[str, Any]:
        if set(payload) != {"capability", "capabilityDigest"}:
            raise AuthorityServiceError("issuer payload is not closed")
        capability = payload["capability"]
        if (
            not isinstance(capability, dict)
            or capability.get("schema")
                != authority_contract.CAPABILITY_SCHEMA
            or capability.get("operation")
                not in authority_transition_registry.PLANNABLE_OPERATIONS
            or capability.get("operation")
                not in self.configuration.role("planner")[
                    "enabledOperations"
                ]
            or capability.get("handlerName")
                != authority_contract.operation_spec(
                    str(capability.get("operation"))
                )["handler"]
        ):
            raise AuthorityServiceError("issuer capability is invalid")
        capability_json = _canonical(capability).decode("ascii")
        computed = _domain_digest(
            authority_contract.CAPABILITY_SCHEMA,
            capability_json.encode("ascii"),
        )
        if computed != payload["capabilityDigest"]:
            raise AuthorityServiceError("issuer capability digest changed")
        from serverware import db

        with db._policy_authority_capability_issuer_pg_connect_raw() as connection:
            # Admission already owns the outer SERIALIZABLE writer
            # transaction. This savepoint and the connection context both
            # remain open until the returned identity has been checked.
            with connection.transaction():
                with connection.cursor() as cursor:
                    row = cursor.execute(
                        "SELECT serverware_metadata."
                        "serverware_policy_authority_issue_writer_capability"
                        + "("
                        "%s, %s, %s, %s, %s) AS capability_id",
                        (
                            capability_json,
                            computed,
                            self.role_config["measurementDigest"],
                            self.role_config["attestationReceiptDigest"],
                            self.configuration.payload[
                                "issuerCredentialIssuanceDigest"
                            ],
                        ),
                    ).fetchone()
                if row is None or row["capability_id"] != capability["capabilityId"]:
                    raise AuthorityServiceError(
                        "database capability issuance failed"
                    )
        return {"capabilityId": row["capability_id"]}

    def _handle_record_witness_receipt(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if set(payload) != {
            "witnessReceipt",
            "witnessReceiptDigest",
            "authorizationDeadlineMonotonicNs",
        }:
            raise AuthorityServiceError(
                "witness receipt payload is not closed"
            )
        receipt = payload["witnessReceipt"]
        supplied_digest = payload["witnessReceiptDigest"]
        if (
            not isinstance(receipt, dict)
            or receipt.get("phase") not in {
                "commit",
                "reconcile",
                "abort",
            }
            or _domain_digest(
                WITNESS_RECEIPT_SCHEMA_V2,
                _canonical(receipt),
            )
            != supplied_digest
            or payload["authorizationDeadlineMonotonicNs"]
                != receipt.get("deadlineMonotonicNs")
        ):
            raise AuthorityServiceError(
                "witness receipt payload binding changed"
            )
        receipt_json = _canonical(receipt).decode("ascii")
        from serverware import db

        with db._policy_authority_capability_issuer_pg_connect_raw() as connection:
            # Keep the original admitted transaction through result checking;
            # a mismatched receipt must not be discovered after its commit.
            with connection.transaction():
                with connection.cursor() as cursor:
                    row = cursor.execute(
                        "SELECT serverware_metadata."
                        "serverware_policy_authority_"
                        "record_witness_receipt("
                        "%s, %s, %s, %s) AS witness_receipt_digest",
                        (
                            receipt_json,
                            supplied_digest,
                            self.role_config["measurementDigest"],
                            self.role_config["attestationReceiptDigest"],
                        ),
                    ).fetchone()
                if (
                    row is None
                    or row["witness_receipt_digest"] != supplied_digest
                ):
                    raise AuthorityServiceError(
                        "database witness receipt persistence failed"
                    )
        return {"witnessReceiptDigest": supplied_digest}

    def _handle_execute(
        self, payload: dict[str, Any], *, purpose: str
    ) -> dict[str, Any]:
        required = {
            "capabilityId",
            "envelopeId",
            "parentEnvelopeId",
            "plannerTransactionId",
            "authorizationProjectionDigest",
            "exactRequestBase64Url",
            "exactResultBase64Url",
            "deadlineMonotonicNs",
            "deadlineEpochNs",
            "fence",
            "reservedAtEpochNs",
        }
        if (
            purpose != "execute-v9"
            or set(payload) != required
            or payload.get("parentEnvelopeId")
                != payload.get("plannerTransactionId")
            or any(
                not isinstance(payload.get(field), int)
                or isinstance(payload.get(field), bool)
                for field in (
                    "deadlineMonotonicNs",
                    "deadlineEpochNs",
                    "fence",
                    "reservedAtEpochNs",
                )
            )
            or payload["fence"] < 1
            or time.monotonic_ns()
                >= payload["deadlineMonotonicNs"]
            or time.time_ns() >= payload["deadlineEpochNs"]
        ):
            raise AuthorityServiceError(
                "v9 executor payload is not closed"
            )
        for field in (
            "capabilityId",
            "envelopeId",
            "parentEnvelopeId",
            "plannerTransactionId",
            "authorizationProjectionDigest",
        ):
            _require_digest(payload[field], f"v9 executor {field}")
        exact_request = authority_planner.decode_base64url(
            payload["exactRequestBase64Url"],
            label="v9 executor exact request",
        )
        exact_result = authority_planner.decode_base64url(
            payload["exactResultBase64Url"],
            label="v9 executor exact result",
        )
        if (
            len(exact_request) > authority_contract.MAX_REQUEST_BYTES
            or len(exact_result) > authority_contract.MAX_RESULT_BYTES
        ):
            raise AuthorityServiceError(
                "v9 executor exact bytes exceed their bounds"
            )
        try:
            typed_request = json.loads(exact_request)
            result = json.loads(exact_result)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorityServiceError(
                "v9 executor exact bytes are not JSON"
            ) from exc
        if (
            not isinstance(typed_request, dict)
            or _canonical(typed_request) != exact_request
            or _canonical(result) != exact_result
            or authority_planner.typed_request_digest(typed_request)
                != typed_request.get("requestDigest")
            or typed_request.get("operationId")
                != _domain_digest(
                    "serverware.policyAuthorityOperation/v2",
                    str(typed_request.get("operation")).encode(
                        "ascii"
                    ),
                    str(typed_request.get("requestDigest")).encode(
                        "ascii"
                    ),
                )
        ):
            raise AuthorityServiceError(
                "v9 executor exact byte binding changed"
            )
        from serverware import db

        with db._policy_authority_executor_pg_connect_raw() as raw:
            with raw.transaction():
                with raw.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
                    )
                connection = db.PostgresMetadataConnection(raw)
                receipt_json = db.execute_authority_v9(
                    capability_id=payload["capabilityId"],
                    envelope_id=payload["envelopeId"],
                    planner_transaction_id=payload[
                        "plannerTransactionId"
                    ],
                    exact_request_bytes=exact_request,
                    exact_result_bytes=exact_result,
                    deadline_monotonic_ns=payload[
                        "deadlineMonotonicNs"
                    ],
                    connection=connection,
                )
                if (
                    time.monotonic_ns()
                    >= payload["deadlineMonotonicNs"]
                ):
                    raise AuthorityServiceError(
                        "v9 executor transaction crossed its deadline"
                    )
        try:
            receipt = json.loads(receipt_json)
        except json.JSONDecodeError as exc:
            raise AuthorityServiceError(
                "v9 executor receipt is not JSON"
            ) from exc
        result_digest = db.compute_authority_v9_result_digest(
            exact_result
        )
        if (
            not isinstance(receipt, dict)
            or _canonical(receipt).decode("ascii") != receipt_json
            or receipt.get("schema")
                != "serverware.policyAuthorityWriterCommitReceipt/v2"
            or receipt.get("capabilityId")
                != payload["capabilityId"]
            or receipt.get("envelopeId") != payload["envelopeId"]
            or receipt.get("plannerTransactionId")
                != payload["plannerTransactionId"]
            or receipt.get("authorizationProjectionDigest")
                != payload["authorizationProjectionDigest"]
            or receipt.get("operation")
                != typed_request["operation"]
            or receipt.get("requestDigest")
                != typed_request["requestDigest"]
            or receipt.get("resultDigest") != result_digest
            or receipt.get("deadlineMonotonicNs")
                != payload["deadlineMonotonicNs"]
            or receipt.get("fence") != payload["fence"]
        ):
            raise AuthorityServiceError(
                "v9 executor terminal receipt binding changed"
            )
        return {
            "receipt": receipt,
            "receiptDigest": _domain_digest(
                "serverware.policyAuthorityWriterCommitReceipt/v2",
                receipt_json.encode("ascii"),
            ),
            "result": result,
            "resultDigest": result_digest,
        }

    @staticmethod
    def _execute_sql_contract(
        *,
        cursor: Any,
        payload: dict[str, Any],
        purpose: str,
    ) -> Any:
        del cursor, payload, purpose
        raise AuthorityServiceError(
            "legacy executor SQL contracts are disabled by schema v9"
        )


class AuthorityServer:
    def __init__(
        self,
        *,
        process: AuthorityProcess,
        socket_path: str,
        peer_uid: int,
        peer_gid: int,
        workers: int,
        maximum_in_flight: int,
        timeout_seconds: float,
    ) -> None:
        self.process = process
        self.socket_path = Path(socket_path)
        self.peer_uid = peer_uid
        self.peer_gid = peer_gid
        self.timeout_seconds = timeout_seconds
        self.pool = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix=f"authority-{process.role_name}",
        )
        self.in_flight = threading.BoundedSemaphore(maximum_in_flight)
        self.socket = _activated_listener(
            socket_path=str(self.socket_path),
            service_uid=int(process.role_config["serviceUid"]),
            service_gid=int(process.role_config["serviceGid"]),
        )

    def serve_forever(self) -> None:
        while True:
            connection, _ = self.socket.accept()
            if not self.in_flight.acquire(blocking=False):
                connection.close()
                continue
            future = self.pool.submit(self._serve_connection, connection)
            future.add_done_callback(
                lambda _future: self.in_flight.release()
            )

    def _serve_connection(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(self.timeout_seconds)
            uid, gid, _pid = _peer_identity(connection)
            if uid != self.peer_uid or gid != self.peer_gid:
                raise AuthorityServiceError(
                    "authority socket peer identity is not allowed"
                )
            request = _recv_message(connection)
            response = self.process.handle(request)
            _send_message(connection, response)
        except Exception as exc:
            try:
                _send_message(
                    connection,
                    {
                        "schema": "serverware.policyAuthorityError/v1",
                        "code": "authority_denied",
                        "detailDigest": _sha256(
                            str(exc).encode("utf-8")
                        ),
                    },
                )
            except Exception:
                pass
        finally:
            connection.close()


def runtime_relay_main() -> int:
    if (
        sys.flags.isolated != 1
        or sys.flags.safe_path is not True
        or sys.flags.no_user_site != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or os.environ.get(
            "SERVERWARE_PROCESS_MODE", ""
        ).strip()
        != RUNTIME_RELAY_PROCESS_MODE
    ):
        raise AuthorityServiceError(
            "authority runtime relay lost its measured launch boundary"
        )
    trust = AuthorityRuntimeClient.from_environment(
        hot_runtime=True
    )
    AuthorityRuntimeRelay(trust).serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -I -m serverware.authority_service"
    )
    parser.add_argument("role", choices=sorted(PROCESS_MODES))
    args = parser.parse_args(argv)
    if (
        sys.flags.isolated != 1
        or sys.flags.safe_path is not True
        or sys.flags.no_user_site != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
    ):
        raise AuthorityServiceError(
            "authority service lost its isolated Python launch flags"
        )
    expected_mode = PROCESS_MODES[args.role]
    if os.environ.get("SERVERWARE_PROCESS_MODE", "").strip() != expected_mode:
        raise AuthorityServiceError(
            "authority process mode does not match its executable role"
        )
    if args.role != "verifier" and any(
        os.environ.get(name, "").strip()
        for name in VERIFIER_SIGNING_KEY_ENVIRONMENTS
    ):
        raise AuthorityServiceError(
            "non-verifier process inherited the verifier signer"
        )
    configuration = MeasuredConfiguration.load(role=args.role)
    process = AuthorityProcess(role=args.role, configuration=configuration)
    _close_inherited_descriptors(
        authority_launch_guard.retained_descriptors()
    )
    role_config = configuration.role(args.role)
    workers = int(role_config["workers"])
    maximum_in_flight = int(role_config["maximumInFlight"])
    if (
        not 1 <= workers <= 256
        or not workers <= maximum_in_flight <= 4096
        or not 1 <= int(role_config["listenBacklog"]) <= 4096
        or not 0.05
        <= float(role_config["requestTimeoutSeconds"])
        <= 30.0
    ):
        raise AuthorityServiceError(
            "authority service resource bounds are invalid"
        )
    server = AuthorityServer(
        process=process,
        socket_path=str(role_config["socketPath"]),
        peer_uid=int(role_config["peerUid"]),
        peer_gid=int(role_config["peerGid"]),
        workers=workers,
        maximum_in_flight=maximum_in_flight,
        timeout_seconds=float(role_config["requestTimeoutSeconds"]),
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
