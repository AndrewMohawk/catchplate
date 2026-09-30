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
from serverware import authority_oauth_activation as oauth_activation
from serverware import authority_oauth_activation_policy as oauth_activation_policy
from serverware import authority_oauth_exchange as oauth_exchange
from serverware import authority_oauth_exchange_policy as oauth_exchange_policy
from serverware import authority_oauth_refresh as oauth_refresh
from serverware import authority_oauth_refresh_policy as oauth_refresh_policy
from serverware import authority_oauth_measured_refresh as oauth_measured_refresh
from serverware import authority_oauth_measured_refresh_policy as oauth_measured_refresh_policy
from serverware import authority_oauth_measured_cleanup as oauth_measured_cleanup
from serverware import authority_oauth_measured_cleanup_policy as oauth_measured_cleanup_policy
from serverware import authority_oauth_measured_pending_retirement as oauth_pending_retirement
from serverware import authority_oauth_measured_pending_retirement_policy as oauth_pending_retirement_policy
from serverware import authority_oauth_measured_capture_retirement as oauth_capture_retirement
from serverware import authority_oauth_measured_capture_retirement_policy as oauth_capture_retirement_policy
from serverware import authority_oauth_measured_exchange as oauth_measured_exchange
from serverware import authority_oauth_measured_exchange_policy as oauth_measured_exchange_policy
from serverware import authority_oauth_measured_setup as oauth_measured_setup
from serverware import authority_oauth_setup as oauth_setup
from serverware import authority_policy_candidate as policy_candidate
from serverware import authority_policy_candidate_policy as policy_candidate_policy
from serverware import authority_setup_policy as setup_policy
from serverware import authority_setup_policy_admission as setup_policy_admission
from serverware import authority_setup_native_enrollment as setup_native_enrollment
from serverware import authority_setup_native_enrollment_policy as setup_native_enrollment_policy
from serverware import authority_policy_canary as policy_canary
from serverware import authority_policy_canary_policy as policy_canary_policy
from serverware import authority_policy_canary_heartbeat_policy as heartbeat_policy
from serverware import authority_policy_canary_finalization_policy as finalization_policy
from serverware import authority_policy_canary_native_readiness as native_readiness_policy
from serverware import authority_policy_native_activation as native_activation
from serverware import authority_native_activation_completion as native_activation_completion
from serverware import authority_policy_canary_delivery as canary_delivery
from serverware import authority_policy_canary_delivery_policy as canary_delivery_policy
from serverware import authority_policy_canary_delivery_completion as canary_delivery_completion
from serverware import authority_oauth_measured_setup_policy as oauth_measured_setup_policy
from serverware import authority_oauth_reconnect as oauth_reconnect
from serverware import authority_oauth_reconnect_policy as oauth_reconnect_policy
from serverware import authority_oauth_retirement_succession as oauth_succession
from serverware import authority_oauth_retirement_succession_policy as oauth_succession_policy
from serverware import authority_credential_currentness as credential_currentness
from serverware import authority_credential_currentness_policy as credential_currentness_policy
from serverware import authority_oauth_revocation as oauth_revocation
from serverware import authority_oauth_revocation_policy as oauth_revocation_policy
from serverware import authority_oauth_refresh_cleanup as oauth_refresh_cleanup
from serverware import authority_oauth_refresh_cleanup_policy as oauth_refresh_cleanup_policy
from serverware import authority_planner
from serverware import authority_transition_registry
from serverware import authority_transport
from serverware import authority_custody_caller_transport as custody_caller_transport
from serverware import authority_custody_reconcile_transport as custody_reconcile_transport
from serverware import authority_revocation_planner_custody_transport as custody_transport
from serverware import authority_revocation_custody_read_transport as custody_read_transport
from serverware import authority_revocation_planning_transport as planning_transport
from serverware import authority_revocation_writer_transport as writer_transport
from serverware import authority_webauthn_evidence_custody_transport as evidence_custody_transport
from serverware import authority_webauthn_evidence_custody_read_transport as evidence_custody_read_transport
from serverware import authority_webauthn_evidence_plan_transport as evidence_plan_transport
from serverware import authority_webauthn_registration_source_transport as registration_source_transport
from serverware import authority_webauthn_registration_source_caller as registration_source_caller
from serverware import authority_webauthn_registration_custody_caller as registration_custody_caller
from serverware import authority_webauthn_registration_execution_caller as registration_execution_caller
from serverware import authority_webauthn_registration_finalization_caller as registration_finalization_caller
from serverware import authority_webauthn_registration_finalization_execution_caller as registration_finalization_execution_caller
from serverware import authority_webauthn_transition_transport as transition_plan_transport
from serverware import authority_webauthn_transition_custody_transport as transition_custody_transport
from serverware import authority_webauthn_transition_custody_read_transport as transition_custody_read_transport
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware import authority_webauthn_transition_policy as transition_policy
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_trust
from serverware.authority_store.verifier_read_sql import (
    verifier_read_privilege_check,
)

SOURCE_REVISION = (
    authority_contract.SOURCE_REVISION
)
CONFIG_SCHEMA = "serverware.policyAuthorityServiceConfiguration/v6"
SIGNED_CONFIG_SCHEMA = (
    "serverware.signedPolicyAuthorityServiceConfiguration/v6"
)
ATTESTATION_SCHEMA = (
    "serverware.policyAuthorityCredentialReleaseAttestation/v2"
)
RUNTIME_REQUEST_SCHEMA = authority_contract.REQUEST_SCHEMA
RUNTIME_RESPONSE_SCHEMA = authority_contract.RESULT_SCHEMA
MEASURED_REFRESH_RESPONSE_SCHEMA = "serverware.policyAuthorityMeasuredRefreshRuntimeResponse/v1"
MEASURED_CLEANUP_RESPONSE_SCHEMA = "serverware.policyAuthorityMeasuredCleanupRuntimeResponse/v1"
PENDING_RETIREMENT_RESPONSE_SCHEMA = oauth_pending_retirement.RUNTIME_RESPONSE
CAPTURE_RETIREMENT_RESPONSE_SCHEMA = oauth_capture_retirement.RUNTIME_RESPONSE
MEASURED_EXCHANGE_RESPONSE_SCHEMA = "serverware.policyAuthorityMeasuredExchangeRuntimeResponse/v1"
MEASURED_SETUP_RESPONSE_SCHEMA = "serverware.policyAuthorityMeasuredSetupRuntimeResponse/v1"
MEASURED_RECONNECT_RESPONSE_SCHEMA = "serverware.policyAuthorityMeasuredReconnectRuntimeResponse/v1"
RETIRED_SCOPE_SUCCESSION_RESPONSE_SCHEMA = oauth_succession.RUNTIME_RESPONSE
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
PLANNER_WRITER_SIGNING_KEY_ENVIRONMENTS = {
    "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD",
    "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_PATH",
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


def _revocation_custody_originals(originals, *, relay):
    """Validate fixed raw references before any custody-service callback."""
    if type(originals) is not tuple or any(type(raw) is not bytes for raw in originals):
        raise AuthorityServiceError("revocation custody inputs are not original bytes")
    lengths = tuple(len(raw) for raw in originals)
    if relay:
        custody_transport._validate_relay_lengths(lengths)
    else:
        custody_transport._validate_forward_lengths(lengths)


def _revocation_custody_context(process, *, role_name, work):
    """Hold one admitted role's full configuration and final launch snapshot.

    This returns ordinary owned configuration data, not an admission or proof
    token. Every fixed consumer genuinely maps its configuration and launch
    again on the same work. Original byte references must already be bounded;
    any required signer is held by the caller before these callbacks. No DSN,
    private key, current clock or mutable process method is returned or called.
    """
    if (type(process) is not AuthorityProcess or role_name not in ("verifier", "planner")
            or process.role_name != role_name or process.process_mode != "policy-authority-" + role_name):
        raise AuthorityServiceError("revocation custody process is not configured")
    measured = process.configuration
    if type(measured) is not MeasuredConfiguration:
        raise AuthorityServiceError("revocation custody measured configuration is unavailable")
    payload, digest = measured.payload, measured.digest
    runtime_role_identities = measured.runtime_role_identities
    from serverware import authority_revocation_configuration as configuration

    ledger = configuration.capability.capture._SharedLedger(work)
    configuration.capability.shape._digest(digest)
    if type(payload) is not dict:
        raise AuthorityServiceError("revocation custody configuration is not closed data")
    owned = configuration._ConfigurationCapture(
        ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
    owned_runtime_identities = configuration.capability.capture._JSONCapture(
        ledger, maximum_bytes=8192).visit(runtime_role_identities)
    configuration.production._callback(work, lambda: authority_launch_guard.require_active(role_name))
    generation = configuration.production._callback(work, lambda: dict(authority_launch_guard.generation()))
    return owned, digest, generation, owned_runtime_identities


def _webauthn_evidence_custody_purpose(purpose):
    if type(purpose) is not str or purpose not in ("registration", "installation"):
        raise AuthorityServiceError("WebAuthn evidence custody purpose is not supported")
    return ("webauthn.registration.evidence.admit" if purpose == "registration"
        else "webauthn.trust.installation.admit")


def _webauthn_evidence_custody_context(process, *, role_name, signing, work,
        read_roots=False, planning=False):
    """Hold measured settings and any real signer before native callbacks.

    Invocation originals/history must already be owned. The fixed callers
    choose the role and signing requirement; no request selects a callback,
    public key, descriptor or generation. Returned values are ordinary held
    inputs, not proof of admission. The configured action checks their actual
    commitment and launch bindings again on the same work.
    """
    if (type(process) is not AuthorityProcess
            or role_name not in ("verifier", "planner", "planner-writer")
            or process.role_name != role_name
            or process.process_mode != "policy-authority-" + role_name
            or type(signing) is not bool or signing and role_name == "planner-writer"
            or type(read_roots) is not bool or read_roots and role_name != "verifier"
            or type(planning) is not bool or planning and (role_name != "planner" or not signing)):
        raise AuthorityServiceError("WebAuthn evidence custody process is not configured")
    measured = process.configuration
    if type(measured) is not MeasuredConfiguration:
        raise AuthorityServiceError("WebAuthn evidence custody measured configuration is unavailable")
    payload, digest = measured.payload, measured.digest
    runtime_role_identities = measured.runtime_role_identities
    private_key = process.signing_key if signing else None
    if signing and not isinstance(private_key, Ed25519PrivateKey):
        raise AuthorityServiceError("WebAuthn evidence custody signing key is unavailable")
    from serverware import authority_revocation_configuration as configuration

    ledger = configuration.capability.capture._SharedLedger(work)
    configuration.capability.shape._digest(digest)
    if type(payload) is not dict:
        raise AuthorityServiceError("WebAuthn evidence custody configuration is not closed data")
    owned = configuration._ConfigurationCapture(
        ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
    owned_runtime_identities = configuration.capability.capture._JSONCapture(
        ledger, maximum_bytes=8192).visit(runtime_role_identities)
    configuration.production._callback(work, lambda: authority_launch_guard.require_active(role_name))
    database_dsn = None
    if role_name == "planner-writer":
        database_dsn = configuration.production._callback(work,
            lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"))
    elif read_roots:
        database_dsn = configuration.production._callback(work,
            lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"))
    elif planning:
        database_dsn = configuration.production._callback(work,
            lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"))
    # Capture the actual generation last; no later process/descriptor/signer
    # lookup can interpose before the fixed configured action owns it.
    generation = configuration.production._callback(work, lambda: dict(authority_launch_guard.generation()))
    return owned, digest, generation, database_dsn, private_key, owned_runtime_identities


def _revocation_writer_from_owned_configuration(*, owned_payload, owned_runtime_identities,
        configuration_digest, work):
    """Return the genuine writer and held final launch identity, never self.

    This fixed private continuation accepts no caller-supplied callback and
    rereads no mutable process attributes. The real mapper checks the held configuration and
    launch commitment again; its ordinary return value is not admission proof.
    """
    from serverware import authority_revocation_configuration
    from serverware import authority_revocation_writer_configuration

    authority_revocation_configuration.production._callback(
        work, lambda: authority_launch_guard.require_active("planner-writer"))
    persistence_dsn = authority_revocation_configuration.production._callback(
        work, lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"))
    # Keep the generation snapshot immediately beside its genuine ownership
    # capture; no descriptor or other callback can interpose here.
    generation = authority_revocation_configuration.production._callback(
        work, lambda: dict(authority_launch_guard.generation()))
    held_launch = (generation["sequence"], generation["digest"])
    authority_revocation_configuration.capability.shape._integer(held_launch[0], minimum=1)
    authority_revocation_configuration.capability.shape._digest(held_launch[1])
    persistence = authority_revocation_writer_configuration._persistence_from_configuration_on_work(
        payload=owned_payload, configuration_digest=configuration_digest,
        runtime_role_identities=owned_runtime_identities, generation=generation, persistence_dsn=persistence_dsn, work=work)
    return persistence, held_launch


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
    file_digest: str | None = None
    runtime_role_identities: dict[str, Any] | None = None
    attestation_cohort_bytes: bytes | None = None
    history_archive: Any | None = None
    original_bytes: bytes | None = None

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
        file_digest = "sha256:" + hashlib.sha256(config_value).hexdigest()
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
            "roleBindingDigests",
            "roleRuntimeClosureDigests",
            "packageVersions",
            "launchNonceDigest",
            "queryManifestDigest",
            "generationSequence",
            "generationBindingDigest",
            "generationPredecessorDigest",
            "generationMinimumRollbackSequence",
            "credentialReleaseTrust",
            "replayWitness",
            "webauthn",
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
            set(payload) - {setup_native_enrollment_policy.FIELD, evidence_policy.FIELD, transition_policy.FIELD, enrollment_policy.FIELD, oauth_activation_policy.FIELD, oauth_exchange_policy.FIELD, oauth_revocation_policy.FIELD, oauth_refresh_policy.FIELD, credential_currentness_policy.FIELD, oauth_refresh_cleanup_policy.FIELD, oauth_measured_refresh_policy.FIELD, oauth_measured_exchange_policy.FIELD, oauth_measured_setup_policy.FIELD, oauth_reconnect_policy.FIELD, oauth_measured_cleanup_policy.FIELD, oauth_pending_retirement_policy.FIELD, oauth_capture_retirement_policy.FIELD, policy_candidate_policy.FIELD, setup_policy_admission.FIELD, policy_canary_policy.FIELD, heartbeat_policy.FIELD, finalization_policy.FIELD, native_readiness_policy.FIELD, native_activation.FIELD, canary_delivery_policy.FIELD, oauth_succession_policy.FIELD}
                != required_payload_fields
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
                    "generationBindingDigest",
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
            file_digest=file_digest,
            original_bytes=bytes(config_value),
        )
        configuration._verify_generation_binding()
        configuration._verify_role_topology()
        if evidence_policy.FIELD in payload:
            try:
                evidence_policy.validate_policy(
                    payload[evidence_policy.FIELD], webauthn=payload["webauthn"]
                )
            except ValueError as exc:
                raise AuthorityServiceError(
                    "authority WebAuthn evidence admission policy is invalid"
                ) from exc
        if transition_policy.FIELD in payload:
            try:
                transition_policy.validate_policy(
                    payload[transition_policy.FIELD], webauthn=payload["webauthn"]
                )
            except ValueError as exc:
                raise AuthorityServiceError(
                    "authority WebAuthn transition policy is invalid"
                ) from exc
        if enrollment_policy.FIELD in payload:
            try:
                enrollment_policy.validate_policy(payload[enrollment_policy.FIELD], payload=payload)
            except ValueError as exc:
                raise AuthorityServiceError(
                    "authority WebAuthn enrollment authorization policy is invalid"
                ) from exc
        try:
            oauth_activation_policy.validate_policy(payload.get(oauth_activation_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority OAuth activation policy is invalid") from exc
        try:
            oauth_exchange_policy.validate_policy(payload.get(oauth_exchange_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority OAuth exchange policy is invalid") from exc
        try:
            policy_candidate_policy.validate_policy(payload.get(policy_candidate_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority candidate intake policy is invalid") from exc
        try:
            setup_policy_admission.validate_policy(payload.get(setup_policy_admission.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority Setup policy continuation admission is invalid") from exc
        try:
            setup_native_enrollment_policy.validate_policy(payload.get(setup_native_enrollment_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority native Setup enrollment admission is invalid") from exc
        try:
            policy_canary_policy.validate_policy(payload.get(policy_canary_policy.FIELD), payload=payload, root_key=root_key)
            heartbeat_policy.validate_policy(payload.get(heartbeat_policy.FIELD), payload=payload, root_key=root_key)
            finalization_policy.validate_policy(payload.get(finalization_policy.FIELD), payload=payload, root_key=root_key)
            native_readiness_policy.validate_policy(payload.get(native_readiness_policy.FIELD), payload=payload, root_key=root_key)
            native_activation.validate_policy(payload.get(native_activation.FIELD), payload=payload, root_key=root_key)
            canary_delivery_policy.validate_policy(payload.get(canary_delivery_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority native canary intake policy is invalid") from exc
        try:
            oauth_refresh_policy.validate_policy(payload.get(oauth_refresh_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority OAuth due-refresh policy is invalid") from exc
        try:
            oauth_measured_refresh_policy.validate_policy(payload.get(oauth_measured_refresh_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority measured OAuth refresh policy is invalid") from exc
        try:
            oauth_measured_cleanup_policy.validate_policy(payload.get(oauth_measured_cleanup_policy.FIELD), payload=payload, root_key=root_key)
            oauth_pending_retirement_policy.validate_policy(payload.get(oauth_pending_retirement_policy.FIELD), payload=payload, root_key=root_key)
            oauth_capture_retirement_policy.validate_policy(payload.get(oauth_capture_retirement_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority measured OAuth cleanup policy is invalid") from exc
        try:
            oauth_measured_exchange_policy.validate_policy(payload.get(oauth_measured_exchange_policy.FIELD), payload=payload, root_key=root_key)
            oauth_measured_setup_policy.validate_policy(payload.get(oauth_measured_setup_policy.FIELD), payload=payload, root_key=root_key)
            oauth_reconnect_policy.validate_policy(payload.get(oauth_reconnect_policy.FIELD), payload=payload, root_key=root_key)
            oauth_succession_policy.validate_policy(payload.get(oauth_succession_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority measured initial OAuth issuance policy is invalid") from exc
        try:
            credential_currentness_policy.validate_policy(payload.get(credential_currentness_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority measured credential-currentness policy is invalid") from exc
        try:
            oauth_revocation_policy.validate_policy(payload.get(oauth_revocation_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority OAuth cleanup policy is invalid") from exc
        configuration._verify_runtime_closure()
        try:
            oauth_refresh_cleanup_policy.validate_policy(payload.get(oauth_refresh_cleanup_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise AuthorityServiceError("authority OAuth family retirement policy is invalid") from exc
        configuration._verify_attestation(role=role)
        return configuration

    def _verify_generation_binding(self) -> None:
        generation = dict(authority_launch_guard.generation())
        # Final generation identity is admitted by the launch chain; it must
        # not be equated to the configuration's static metadata commitment.
        _require_digest(generation.get("digest"), "authority launch generation digest")
        file_digest = _require_digest(
            self.file_digest, "authority configuration file digest"
        )
        bindings = generation.get("configurationPayloadBindings")
        expected_binding = {
            "fileDigest": file_digest,
            "payloadDigest": self.digest,
            "payloadSchema": CONFIG_SCHEMA,
            "role": "authority-service",
        }
        if (
            generation.get("schema")
                != "serverware.authorityGenerationLaunchContext/v4"
            or generation.get("sequence")
                != self.payload.get("generationSequence")
            or generation.get("configurationBindingDigest")
                != self.payload.get("generationBindingDigest")
            or generation.get("predecessorDigest")
                != self.payload.get("generationPredecessorDigest")
            or generation.get("minimumRollbackSequence")
                != self.payload.get("generationMinimumRollbackSequence")
            or generation.get("operationManifestDigest")
                != authority_contract.OPERATION_MANIFEST_DIGEST
            or file_digest not in generation.get(
                "configurationDigests", ()
            )
            or type(bindings) is not list
            or not 1 <= len(bindings) <= 4096
            or not any(
                type(binding) is dict and binding == expected_binding
                for binding in bindings
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
        # This is a derived runtime view, never the root-signed payload. The
        # loader uses static roles before evidence admission; process consumers
        # see the separately admitted receipt identity afterward.
        result = dict(value)
        if self.runtime_role_identities is not None:
            result["attestationReceiptDigest"] = self.runtime_role_identities[
                "roles"
            ][role]["attestationReceiptDigest"]
        return result

    def issuer_session_identity_digest(self) -> str:
        if self.runtime_role_identities is None:
            raise AuthorityServiceError("issuer runtime identity is not admitted")
        issuer = self.role("issuer")
        return _domain_digest(
            "serverware.policyAuthorityCapabilityIssuerSession/v1",
            *(value.encode("utf-8") for value in (
                issuer["databaseRole"], issuer["tlsClientDn"],
                issuer["tlsClientSerial"], issuer["tlsIssuerDn"],
                issuer["measurementDigest"], issuer["attestationReceiptDigest"],
                self.payload["issuerCredentialIssuanceDigest"],
            )),
        )

    def _verify_role_topology(self) -> None:
        roles = self.payload.get("roles")
        role_binding_digests = self.payload.get(
            "roleBindingDigests"
        )
        role_runtime_closure_digests = self.payload.get(
            "roleRuntimeClosureDigests"
        )
        admitted_role_bindings = authority_launch_guard.generation().get(
            "roleBindingDigests"
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
            type(role_binding_digests) is not dict
            or set(role_binding_digests) != set(PROCESS_MODES)
            or type(role_runtime_closure_digests) is not dict
            or set(role_runtime_closure_digests) != set(PROCESS_MODES)
            or type(admitted_role_bindings) is not dict
            or len(admitted_role_bindings) > 256
            or any(
                _require_digest(
                    role_binding_digests[role],
                    f"{role} semantic role binding digest",
                ) != role_binding_digests[role]
                or _require_digest(
                    role_runtime_closure_digests[role],
                    f"{role} static runtime closure digest",
                ) != role_runtime_closure_digests[role]
                or admitted_role_bindings.get(role) != role_binding_digests[role]
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
                        "responseSigningPublicKeyBase64Url",
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
                    # This is the configured planning inventory only. Legacy
                    # planning, execution/SQL/witness and socket dispatch keep
                    # their separate narrower operation gates unchanged.
                    or set(enabled_operations)
                        - set(authority_transition_registry.PLANNABLE_OPERATIONS)
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
                response_encoded = role_value["responseSigningPublicKeyBase64Url"]
                if type(response_encoded) is not str or len(response_encoded) != 43:
                    raise AuthorityServiceError(
                        "planner-writer response public key is not canonical raw32"
                    )
                response_raw = _b64url_decode(response_encoded, size=32)
                if _b64url_encode(response_raw) != response_encoded:
                    raise AuthorityServiceError(
                        "planner-writer response public key is not canonical raw32"
                    )
                response_key = Ed25519PublicKey.from_public_bytes(response_raw)
                if _public_spki_digest(response_key) != role_value["responseSigningSpkiDigest"]:
                    raise AuthorityServiceError(
                        "planner-writer response public key differs from its measured pin"
                    )
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
        if planner_writer["responseSigningSpkiDigest"] in {
            roles[name]["responseSigningSpkiDigest"]
            for name in ("verifier", "planner", "issuer", "executor")
        }:
            raise AuthorityServiceError(
                "planner-writer response signing key is not role-separated"
            )
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
        from serverware.authority_artifact_spec import (
            ArtifactContractError, role_runtime_closure_digest,
        )

        packages = self.payload.get("packageVersions")
        measured_packages = dict(
            authority_launch_guard.package_versions()
        )
        _require_digest(authority_launch_guard.require_active(_launch_role),
            "authority active launch manifest digest")
        if (
            not isinstance(packages, dict)
            or packages != measured_packages
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
        try:
            closure_digest = role_runtime_closure_digest(
                self.payload["roleBindingDigests"][_launch_role], measured_packages
            )
        except ArtifactContractError as exc:
            raise AuthorityServiceError("authority static role runtime closure is invalid") from exc
        if closure_digest != self.payload[
            "roleRuntimeClosureDigests"
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
        from serverware import authority_attestation_cohort
        from serverware import authority_historical_archive
        from serverware import authority_revocation_configuration

        try:
            delivery = json.loads(attestation_value)
            if (
                type(delivery) is not dict
                or set(delivery) != {"schema", "currentCohort", "historicalArchive"}
                or delivery["schema"] != "serverware.authorityRuntimeEvidence/v1"
                or attestation_value != _canonical(delivery)
            ):
                raise AuthorityServiceError("runtime evidence delivery is not closed canonical data")
            active_launch = authority_launch_guard.require_active(role)
            generation = dict(authority_launch_guard.generation())
            held_generation = {
                name: generation[name]
                for name in authority_revocation_configuration._GENERATION_FIELDS
            }
            admitted = authority_attestation_cohort._admit_on_current_launch(
                original_bytes=_canonical(delivery["currentCohort"]),
                role=role,
                configuration_payload=self.payload,
                configuration_digest=self.digest,
                root_public_key=self.root_key,
            )
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise AuthorityServiceError("trusted-host-local attestation cohort is invalid") from exc
        runtime_roles = {}
        local_receipt = None
        for receipt_role, receipt_bytes, receipt_digest in admitted.receipts:
            # These are the canonical immutable originals already admitted by
            # the helper, not reconstructed or caller-selected receipt claims.
            envelope = json.loads(receipt_bytes)
            receipt = envelope["payload"]
            runtime_roles[receipt_role] = {
                "measurementDigest": receipt["measurementDigest"],
                "responseSigningSpkiDigest": receipt["responseSigningSpkiDigest"],
                "attestationReceiptDigest": receipt_digest,
            }
            if receipt_role == role:
                local_receipt = envelope
        if local_receipt is None:
            raise AuthorityServiceError("attestation cohort omits the active role")
        runtime_identities = {
            "schema": "serverware.policyAuthorityRuntimeRoleIdentities/v1",
            "configurationDigest": self.digest,
            "generationSequence": admitted.generation_sequence,
            "generationDigest": admitted.generation_digest,
            "cohortDigest": admitted.cohort_digest,
            "roles": runtime_roles,
        }
        if (held_generation["sequence"], held_generation["digest"]) != (
            admitted.generation_sequence, admitted.generation_digest
        ):
            raise AuthorityServiceError("current historical snapshot differs from the active launch")
        try:
            # The archive is explicitly authorized by the CURRENT root and
            # scoped to this current configuration/generation. Stored plans
            # cannot enroll historical keys or manufacture old trust state.
            archive_bytes = _canonical(delivery["historicalArchive"])
            archive_payload = delivery["historicalArchive"]["payload"]
            archive_interval = (
                archive_payload["issuedAtEpochNs"], archive_payload["expiresAtEpochNs"]
            )
            current_snapshot = authority_historical_archive._HistoricalSnapshot(
                payload=self.payload, configuration_digest=self.digest,
                generation=held_generation, runtime_role_identities=runtime_identities,
                valid_from_epoch_ns=max(admitted.valid_from_epoch_ns,
                    authority_attestation_cohort._generation_time_ns(
                        generation["validFrom"], "current generation validFrom")),
                valid_until_epoch_ns=min(admitted.valid_until_epoch_ns,
                    authority_attestation_cohort._generation_time_ns(
                        generation["validUntil"], "current generation validUntil")),
            )
            history_archive = authority_historical_archive._admit_on_startup(
                original_bytes=archive_bytes, current_snapshot=current_snapshot,
                current_root_public_key=self.root_key, now_epoch_ns=time.time_ns(),
            )
            # Cold admission can be expensive. Repeat the genuine live
            # custody and original current intervals after archive verification.
            if authority_launch_guard.require_active(role) != active_launch:
                raise AuthorityServiceError("launch changed during historical archive admission")
            final_now = time.time_ns()
            if not (
                admitted.valid_from_epoch_ns <= final_now < admitted.valid_until_epoch_ns
                and archive_interval[0] <= final_now < archive_interval[1]
            ):
                raise AuthorityServiceError("runtime evidence expired during startup admission")
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise AuthorityServiceError("historical archive admission failed") from exc
        object.__setattr__(self, "history_archive", history_archive)
        object.__setattr__(self, "runtime_role_identities", runtime_identities)
        object.__setattr__(self, "attestation_cohort_bytes", admitted.cohort_bytes)
        # Existing consumption/response protocols continue to use the genuine
        # individual local receipt and its unchanged identity domain.
        object.__setattr__(self, "attestation_evidence", local_receipt)

    def _verify_attestation(self, *, role: str) -> None:
        try:
            identity = authority_launch_guard.runtime_evidence_identity(role)
            if (
                type(identity) is not tuple or len(identity) != 10
                or any(type(value) is not int or value < 0 for value in identity[:9])
                or not 3 <= identity[0] <= 2**31 - 1
                or not 2 <= identity[6] <= 4 * 1024 * 1024
            ):
                raise AuthorityServiceError("attestation custody observation is invalid")
            expected_digest = _require_digest(identity[9], "runtime attestation bytes digest")
            # This is custody of original bytes, not receipt admission. The
            # guard rechecks the separately retained, root-owned sealed file.
            attestation_value = os.pread(identity[0], identity[6], 0)
            if (
                type(attestation_value) is not bytes
                or len(attestation_value) != identity[6]
                or _sha256(attestation_value) != expected_digest
                or authority_launch_guard.runtime_evidence_identity(role) != identity
            ):
                raise AuthorityServiceError("attestation original bytes or custody changed")
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
            if isinstance(exc, AuthorityServiceError):
                raise
            raise AuthorityServiceError("attestation runtime evidence is unavailable") from exc
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


def _send_message_until(connection: socket.socket, value: Mapping[str, Any], *,
        deadline_ns: int) -> None:
    """Legacy canonical response under the accepted connection's deadline."""
    encoded = _canonical(dict(value))
    if not 2 <= len(encoded) <= MAX_MESSAGE_BYTES:
        raise AuthorityServiceError("authority response size is invalid")
    writer_transport._send_exact_until(connection, len(encoded).to_bytes(8, "big"),
        deadline_ns=deadline_ns)
    writer_transport._send_exact_until(connection, encoded, deadline_ns=deadline_ns)


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
    deadline_ns: int | None = None,
    measured_refresh_response: bool = False,
    measured_exchange_response: bool = False,
    measured_setup_response: bool = False,
    measured_pending_retirement_response: bool = False,
    measured_capture_retirement_response: bool = False,
    measured_reconnect_response: bool = False,
    retired_scope_succession_response: bool = False,
    canary_delivery_response: bool = False,
    native_activation_response: bool = False,
    native_activation_result: bool = False,
) -> dict[str, Any] | tuple[bytes, bytes, dict[str, Any]]:
    if native_activation_result and (value.get("operation") not in native_activation.OPERATIONS or deadline_ns is None
            or measured_refresh_response or measured_exchange_response or measured_setup_response
            or measured_pending_retirement_response or measured_capture_retirement_response or measured_reconnect_response
            or retired_scope_succession_response or canary_delivery_response):
        raise AuthorityServiceError("native activation result bound requires its fixed operation owner")
    if native_activation_response and (measured_refresh_response or measured_exchange_response or measured_setup_response
            or measured_pending_retirement_response or measured_capture_retirement_response or measured_reconnect_response
            or retired_scope_succession_response or canary_delivery_response
            or value.get("operation") != native_activation.PREFIX + "consume" or deadline_ns is None):
        raise AuthorityServiceError("native activation proof export requires its exact consume owner")
    if canary_delivery_response and (measured_refresh_response or measured_exchange_response or measured_setup_response
            or measured_pending_retirement_response or measured_capture_retirement_response or measured_reconnect_response
            or retired_scope_succession_response or value.get("operation") not in canary_delivery.OPERATIONS or deadline_ns is None):
        raise AuthorityServiceError("delivery original response requires its separate fixed purpose")
    if retired_scope_succession_response and (measured_setup_response or measured_refresh_response or measured_exchange_response
            or measured_pending_retirement_response or measured_capture_retirement_response or measured_reconnect_response
            or canary_delivery_response or value.get("operation") not in oauth_succession.OPERATIONS or deadline_ns is None):
        raise AuthorityServiceError("succession originals require their separate fixed response purpose")
    if measured_reconnect_response and (measured_setup_response or measured_refresh_response or measured_exchange_response
            or measured_pending_retirement_response or measured_capture_retirement_response
            or value.get("operation") not in oauth_reconnect.OPERATIONS or deadline_ns is None):
        raise AuthorityServiceError("expanded reconnect response requires its independently selected purpose")
    if measured_capture_retirement_response and (measured_refresh_response or measured_exchange_response or measured_setup_response
            or measured_pending_retirement_response or measured_reconnect_response
            or value.get("operation") not in oauth_capture_retirement.OPERATIONS or deadline_ns is None):
        raise AuthorityServiceError("expanded capture retirement originals require their separate exact purpose")
    if measured_setup_response and (measured_refresh_response or measured_exchange_response or measured_pending_retirement_response
            or value.get("operation") not in oauth_measured_setup.OPERATIONS or deadline_ns is None):
        raise AuthorityServiceError("expanded Setup response requires its separate exact purpose")
    if measured_pending_retirement_response and (measured_refresh_response or measured_exchange_response
            or value.get("operation") not in oauth_pending_retirement.OPERATIONS or deadline_ns is None):
        raise AuthorityServiceError("expanded pending retirement response requires its exact purpose")
    if measured_exchange_response and (measured_refresh_response or value.get("operation") not in oauth_measured_exchange.OPERATIONS or deadline_ns is None):
        raise AuthorityServiceError("expanded initial-issuance response requires its exact purpose")
    if measured_refresh_response and (value.get("operation") not in oauth_measured_refresh.OPERATIONS | oauth_measured_cleanup.OPERATIONS or deadline_ns is None):
        raise AuthorityServiceError("expanded response custody requires the fixed measured-refresh purpose")
    if deadline_ns is not None:
        timeout_seconds = min(timeout_seconds, writer_transport._check_deadline(deadline_ns) / 1_000_000_000)
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
        if deadline_ns is None:
            _send_message(connection, value)
            return _recv_message(connection)
        if canary_delivery_response or native_activation_response:
            # This purpose retains the actual sent/received frames. Other
            # callers keep their original mapping-only transport contract.
            request_original = _canonical(dict(value))
            if not 2 <= len(request_original) <= (native_activation.MAX_NATIVE if native_activation_response else canary_delivery.MAX_ARGUMENT):
                raise AuthorityServiceError("delivery runtime original exceeds its closed bound")
            writer_transport._send_exact_until(connection, len(request_original).to_bytes(8, "big"), deadline_ns=deadline_ns)
            writer_transport._send_exact_until(connection, request_original, deadline_ns=deadline_ns)
        else:
            _send_message_until(connection, value, deadline_ns=deadline_ns)
        size = int.from_bytes(writer_transport._recv_exact_until(connection, 8, deadline_ns=deadline_ns), "big")
        maximum = (native_activation.MAX_NATIVE if native_activation_response or native_activation_result else oauth_succession.MAX_RUNTIME_RESPONSE if retired_scope_succession_response else
            6 * 1024 * 1024 if canary_delivery_response or measured_refresh_response or measured_exchange_response or measured_setup_response or measured_pending_retirement_response or measured_capture_retirement_response or measured_reconnect_response else 128 * 1024)
        if not 2 <= size <= maximum:
            raise AuthorityServiceError("publication authority response exceeds its fixed bound")
        raw = writer_transport._recv_exact_until(connection, size, deadline_ns=deadline_ns)
        response = json.loads(raw)
        if type(response) is not dict or _canonical(response) != raw:
            raise AuthorityServiceError("publication authority response is not canonical")
        writer_transport._check_deadline(deadline_ns)
        if canary_delivery_response or native_activation_response:
            return request_original, raw, response
        return response
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
        runtime_root_public_key: Ed25519PublicKey | None = None,
        inherited_descriptors: tuple[int, ...] = (),
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
        # These are retained only by the genuine environment admission path.
        # They do not make a directly constructed client an admitted owner.
        self.runtime_root_public_key = runtime_root_public_key
        self.inherited_descriptors = inherited_descriptors

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
                or name in PLANNER_SIGNING_KEY_ENVIRONMENTS
                or name in PLANNER_WRITER_SIGNING_KEY_ENVIRONMENTS
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
            runtime_root_public_key=root_key,
            inherited_descriptors=tuple(sorted(allowed_descriptors)),
        )

    def request(
        self, *, operation: str, input_value: Mapping[str, Any], deadline_ns: int | None = None
    ) -> Any:
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns,
            measured_originals=False)

    def request_measured_refresh(self, *, operation, input_value, deadline_ns):
        if operation not in oauth_measured_refresh.OPERATIONS or type(deadline_ns) is not int:
            raise AuthorityServiceError("raw response custody is restricted to measured refresh")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns,
            measured_originals=True)

    def request_measured_exchange(self, *, operation, input_value, deadline_ns):
        if operation not in oauth_measured_exchange.OPERATIONS or type(deadline_ns) is not int:
            raise AuthorityServiceError("raw initial-issuance custody has no generic export")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns,
            measured_originals=True)

    def request_measured_setup(self, *, operation, input_value, deadline_ns):
        if operation not in oauth_measured_setup.OPERATIONS or type(deadline_ns) is not int:
            raise AuthorityServiceError("Setup custody requires its independent purpose")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns,
            measured_originals=True)

    def request_measured_cleanup(self, *, operation, input_value, deadline_ns):
        if operation not in oauth_measured_cleanup.OPERATIONS or type(deadline_ns) is not int:
            raise AuthorityServiceError("raw response custody is restricted to measured cleanup")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns,
            measured_originals=True)

    def request_measured_pending_retirement(self, *, operation, input_value, deadline_ns):
        if operation not in oauth_pending_retirement.OPERATIONS or type(deadline_ns) is not int:
            raise AuthorityServiceError("raw original custody is restricted to staged-pending retirement")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns,
            measured_originals=True)

    def request_measured_capture_retirement(self, *, operation, input_value, deadline_ns):
        if operation not in oauth_capture_retirement.OPERATIONS or type(deadline_ns) is not int:
            raise AuthorityServiceError("raw original custody requires the separate provider-wide capture purpose")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns,
            measured_originals=True)

    def request_measured_reconnect(self, *, operation, input_value, deadline_ns):
        if operation not in oauth_reconnect.OPERATIONS or type(deadline_ns) is not int:
            raise AuthorityServiceError("reconnect has no generic signed-original export")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns,
            measured_originals=True)

    def request_retired_scope_succession(self, *, operation, input_value, deadline_ns):
        if operation not in oauth_succession.OPERATIONS or type(deadline_ns) is not int:
            raise AuthorityServiceError("succession has no generic original export or retry purpose")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns,
            measured_originals=True)

    def _request_result(self, *, operation, input_value, deadline_ns, measured_originals):
        delivery = operation in canary_delivery.OPERATIONS
        activation = operation == native_activation.PREFIX + "consume"
        measured = operation in oauth_measured_refresh.OPERATIONS | oauth_measured_exchange.OPERATIONS | oauth_measured_setup.OPERATIONS | oauth_reconnect.OPERATIONS | oauth_measured_cleanup.OPERATIONS | oauth_pending_retirement.OPERATIONS | oauth_capture_retirement.OPERATIONS | oauth_succession.OPERATIONS
        if measured_originals and not (measured or delivery or activation) or (measured or delivery or activation) and type(deadline_ns) is not int:
            raise AuthorityServiceError("generic authority original export is unavailable")
        response_schema = (native_activation.RESPONSE_SCHEMA if activation else canary_delivery.RESPONSE_SCHEMA if delivery else
            RETIRED_SCOPE_SUCCESSION_RESPONSE_SCHEMA if operation in oauth_succession.OPERATIONS else
            CAPTURE_RETIREMENT_RESPONSE_SCHEMA if operation in oauth_capture_retirement.OPERATIONS else
            PENDING_RETIREMENT_RESPONSE_SCHEMA if operation in oauth_pending_retirement.OPERATIONS else
            MEASURED_CLEANUP_RESPONSE_SCHEMA if operation in oauth_measured_cleanup.OPERATIONS else
            MEASURED_EXCHANGE_RESPONSE_SCHEMA if operation in oauth_measured_exchange.OPERATIONS else
            MEASURED_SETUP_RESPONSE_SCHEMA if operation in oauth_measured_setup.OPERATIONS else
            MEASURED_RECONNECT_RESPONSE_SCHEMA if operation in oauth_reconnect.OPERATIONS else
            MEASURED_REFRESH_RESPONSE_SCHEMA if measured else RUNTIME_RESPONSE_SCHEMA)
        if (
            operation
            not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
        ):
            raise AuthorityServiceError(
                "runtime authority operation has no exact transition program"
            )
        started_monotonic_ns = time.monotonic_ns()
        deadline_monotonic_ns = (
            started_monotonic_ns + self.maximum_deadline_ns
        )
        if deadline_ns is not None:
            if type(deadline_ns) is not int or deadline_ns <= started_monotonic_ns:
                raise AuthorityServiceError("inherited authority request deadline expired")
            deadline_monotonic_ns = min(deadline_monotonic_ns, deadline_ns)
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
        if operation in oauth_succession.OPERATIONS and len(_canonical(request)) > oauth_succession.MAX_HTTP_REQUEST:
            raise AuthorityServiceError("complete succession request original exceeds its handoff bound")
        received = _socket_request(
            self.socket_path,
            request,
            timeout_seconds=min(self.timeout_seconds,
                (deadline_monotonic_ns - time.monotonic_ns()) / 1_000_000_000),
            expected_peer_uid=self.server_uid,
            expected_peer_gid=self.server_gid,
            deadline_ns=deadline_monotonic_ns if deadline_ns is not None else None,
            measured_refresh_response=operation in oauth_measured_refresh.OPERATIONS | oauth_measured_cleanup.OPERATIONS,
            measured_exchange_response=operation in oauth_measured_exchange.OPERATIONS,
            measured_setup_response=operation in oauth_measured_setup.OPERATIONS,
            measured_pending_retirement_response=operation in oauth_pending_retirement.OPERATIONS,
            measured_capture_retirement_response=operation in oauth_capture_retirement.OPERATIONS,
            measured_reconnect_response=operation in oauth_reconnect.OPERATIONS,
            retired_scope_succession_response=operation in oauth_succession.OPERATIONS,
            canary_delivery_response=delivery,
            native_activation_response=activation,
            native_activation_result=operation in native_activation.OPERATIONS,
        )
        if delivery or activation:
            request_original, response_original, response = received
            if request_original != _canonical(request) or response_original != _canonical(response):
                raise AuthorityServiceError("delivery actual transport originals changed")
        else:
            response = received
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
            } | ({"authorityConfigurationOriginal"} if measured else set())
                | ({"authorityConfigurationOriginal", "deliveryOriginals"} if delivery else set())
                | ({"authorityConfigurationOriginal", "activationOriginals"} if activation else set())
            or response.get("schema") != response_schema
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
                    response_schema, _canonical(unsigned)
                ).encode("ascii"),
            )
        except InvalidSignature as exc:
            raise AuthorityServiceError(
                "authority runtime response signature is invalid"
            ) from exc
        if deadline_ns is not None:
            # A signed scalar success is insufficient: require the exact result
            # bytes and both nonempty definite-commit observations in this lane.
            if response["resultDigest"] != _domain_digest(
                    "serverware.policyAuthorityControlledWriterResult/v2", _canonical(response["result"])):
                raise AuthorityServiceError("publication authority result original differs")
            for field in ("commitReceiptDigest", "witnessCommitDigest"):
                _require_digest(response[field], "publication authority committed result")
            writer_transport._check_deadline(deadline_ns)
        if measured:
            original = oauth_measured_refresh.decoded(response["authorityConfigurationOriginal"], 1024 * 1024)
            configuration = json.loads(original)
            if (type(configuration) is not dict or set(configuration) != {"schema", "payload", "signature"}
                    or configuration["schema"] != SIGNED_CONFIG_SCHEMA or self.runtime_root_public_key is None
                    or _domain_digest(CONFIG_SCHEMA, _canonical(configuration["payload"])) != self.configuration_digest):
                raise AuthorityServiceError("measured refresh issuer configuration original differs")
            self.runtime_root_public_key.verify(_b64url_decode(configuration["signature"], size=64),
                _domain_digest(SIGNED_CONFIG_SCHEMA, _canonical(configuration["payload"])).encode("ascii"))
            writer_transport._check_deadline(deadline_ns)
        if delivery:
            # This public configuration has its own cold receiver root, not
            # the runtime-trust signer. The actual delivery HTTP owner and
            # native consumer independently verify that original root below
            # their separate admission. This transport exports no verdict.
            original = canary_delivery.decoded(response["authorityConfigurationOriginal"], MAX_CONFIG_BYTES)
            configured = canary_delivery.document(original, MAX_CONFIG_BYTES, exact=False)
            if (set(configured) != {"schema", "payload", "signature"} or configured["schema"] != SIGNED_CONFIG_SCHEMA
                    or _domain_digest(CONFIG_SCHEMA, _canonical(configured["payload"])) != self.configuration_digest
                    or set(response["deliveryOriginals"]) != canary_delivery_completion.ORIGINAL_FIELDS):
                raise AuthorityServiceError("delivery original configuration or completion inventory differs")
            writer_transport._check_deadline(deadline_ns)
        if activation:
            native_activation_completion.emitted(request_original, response_original)
        if measured_originals:
            if delivery or activation:
                return request_original, response_original
            return (_canonical(request), _canonical(response))
        return response["result"]

    def request_canary_delivery(self, *, operation, input_value, deadline_ns):
        if operation not in canary_delivery.OPERATIONS or type(deadline_ns) is not int:
            raise AuthorityServiceError("delivery custody has no generic signed-original export")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns, measured_originals=True)

    def request_native_activation(self, *, operation, input_value, deadline_ns):
        if operation != native_activation.PREFIX + "consume" or type(deadline_ns) is not int:
            raise AuthorityServiceError("native publication originals have no generic export")
        return self._request_result(operation=operation, input_value=input_value, deadline_ns=deadline_ns, measured_originals=True)


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
            try:
                deadline_ns = writer_transport._deadline_ns(self.trust.timeout_seconds)
            except BaseException:
                connection.close()
                raise
            if not self.in_flight.acquire(blocking=False):
                connection.close()
                continue
            try:
                future = self.pool.submit(
                    self._serve_connection, connection, deadline_ns=deadline_ns,
                )
            except BaseException:
                try:
                    connection.close()
                finally:
                    self.in_flight.release()
                raise
            future.add_done_callback(
                lambda _future: self.in_flight.release()
            )

    def _serve_connection(self, connection: socket.socket, *, deadline_ns: int) -> None:
        detached = False
        trust = self.trust
        try:
            writer_transport._check_deadline(deadline_ns)
            uid, gid, _pid = _peer_identity(connection)
            if (
                uid != trust.control_plane_uid
                or gid != trust.control_plane_gid
            ):
                raise AuthorityServiceError(
                    "authority relay peer identity is not allowed"
                )
            prefix = writer_transport._recv_prefix(connection, deadline_ns=deadline_ns)
            from serverware import authority_public_revocation_transport as public_revocation_wire
            if prefix in public_revocation_wire.REQUEST_MAGICS:
                from serverware import authority_public_revocation_service
                detached = True
                authority_public_revocation_service.serve_relay(
                    trust, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            reconciling = prefix in custody_reconcile_transport.REQUEST_MAGICS
            detached = (reconciling or prefix in custody_caller_transport.REQUEST_MAGICS
                or prefix in (registration_source_caller.REQUEST_MAGIC,
                    registration_custody_caller.REQUEST_MAGIC,
                    registration_execution_caller.REQUEST_MAGIC,
                    registration_finalization_caller.REQUEST_MAGIC,
                    registration_finalization_execution_caller.REQUEST_MAGIC))
            if prefix == registration_finalization_execution_caller.REQUEST_MAGIC:
                registration_finalization_execution_caller._serve_relay(
                    trust, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == registration_execution_caller.REQUEST_MAGIC:
                registration_execution_caller._serve_relay(
                    trust, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == registration_finalization_caller.REQUEST_MAGIC:
                registration_finalization_caller._serve_relay(
                    trust, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == registration_custody_caller.REQUEST_MAGIC:
                registration_custody_caller._serve_relay(
                    trust, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == registration_source_caller.REQUEST_MAGIC:
                registration_source_caller._serve_relay(
                    trust, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if detached:
                from serverware import authority_custody_caller_service

                authority_custody_caller_service._serve_relay(
                    trust, connection, deadline_ns=deadline_ns, prefix=prefix,
                    reconciling=reconciling)
                return
            # Preserve legacy canonical JSON framing after reading its length
            # prefix. Detached custody never falls through to this protocol.
            size = int.from_bytes(prefix, "big")
            if not 2 <= size <= MAX_MESSAGE_BYTES:
                raise AuthorityServiceError("authority message size is invalid")
            encoded = writer_transport._recv_exact_until(connection, size, deadline_ns=deadline_ns)
            try:
                request = json.loads(encoded)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuthorityServiceError("authority message is not JSON") from exc
            if not isinstance(request, dict) or _canonical(request) != encoded:
                raise AuthorityServiceError("authority message is not canonical")
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
                    != trust.configuration_digest
                or request.get("operationManifestDigest")
                    != trust.operation_manifest_digest
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
                    > trust.maximum_deadline_ns
                or len(_canonical(request))
                    > authority_contract.MAX_REQUEST_BYTES
            ):
                raise AuthorityServiceError(
                    "authority relay request is not closed"
                )
            remaining_seconds = (
                min(request["deadlineMonotonicNs"], deadline_ns)
                - time.monotonic_ns()
            ) / 1_000_000_000
            if remaining_seconds <= 0:
                raise AuthorityServiceError(
                    "authority relay request deadline expired"
                )
            response = _socket_request(
                trust.verifier_socket_path,
                request,
                timeout_seconds=min(
                    trust.timeout_seconds,
                    remaining_seconds,
                ),
                expected_peer_uid=trust.verifier_uid,
                expected_peer_gid=trust.verifier_gid,
            )
            if time.monotonic_ns() >= request["deadlineMonotonicNs"]:
                raise AuthorityServiceError(
                    "authority relay response was late"
                )
            _send_message_until(connection, response, deadline_ns=deadline_ns)
        except Exception as exc:
            if detached:
                # Response loss after a custody commit is uncertain. Never
                # append a legacy JSON error or retry a detached operation.
                return
            try:
                _send_message_until(
                    connection,
                    {
                        "schema":
                            "serverware.policyAuthorityError/v1",
                        "code": "authority_denied",
                        "detailDigest": _sha256(
                            str(exc).encode("utf-8")
                        ),
                    },
                    deadline_ns=deadline_ns,
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
        if configuration.runtime_role_identities is None or configuration.history_archive is None:
            raise AuthorityServiceError("authority runtime role identities are not admitted")
        self.role_config = configuration.role(role)
        if (
            os.getuid() != int(self.role_config["serviceUid"])
            or os.getgid() != int(self.role_config["serviceGid"])
        ):
            raise AuthorityServiceError(
                "authority service OS identity is not exact"
            )
        self.signing_key: Ed25519PrivateKey | None = None
        # Never make the writer a generic internal-envelope signer. A future
        # ACK path must bind this separate key to its exact custody protocol.
        self.writer_response_signing_key: Ed25519PrivateKey | None = None
        from serverware import authority_stage_zero_contract

        launch_request = dict(authority_launch_guard.stage_zero_request())
        generation = dict(authority_launch_guard.generation())
        launch_assurance = dict(authority_launch_guard.launch_assurance())
        request_role = launch_request.get("role")
        request_generation = launch_request.get("generation")
        generation_sequence = generation.get("sequence")
        generation_digest = _require_digest(
            generation.get("digest"), "active launch generation digest"
        )
        request_digest = _require_digest(
            generation.get("stageZeroRequestDigest"), "active stage-zero request digest"
        )
        if (
            type(request_role) is not dict
            or request_role.get("role") != role
            or request_role.get("processMode") != PROCESS_MODES[role]
            or type(request_generation) is not dict
            or type(generation_sequence) is not int
            or type(request_generation.get("sequence")) is not int
            or request_generation.get("sequence") != generation_sequence
            or request_generation.get("digest") != generation_digest
        ):
            raise AuthorityServiceError("active credential request role or generation changed")
        try:
            actual_credential_set_digest = authority_stage_zero_contract.credential_set_digest(
                launch_request["credentials"]
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorityServiceError("active credential set is invalid") from exc
        # Keep the admitted request identity and actual set outside signed
        # configuration, and hold all expected scalars before key callbacks.
        expected_launch_binding = (
            role, generation_sequence, generation_digest,
            request_digest, actual_credential_set_digest,
        )
        expected_assurance = (
            launch_assurance.get("trustMode"),
            launch_assurance.get("coLocated"),
            launch_assurance.get("hardwareBacked"),
        )
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
        certificate_launch_binding = (
            launch_payload.get("role"), launch_payload.get("generationSequence"),
            launch_payload.get("generationDigest"), launch_payload.get("requestDigest"),
            launch_payload.get("credentialSetDigest"),
        )
        certificate_assurance = (
            launch_payload.get("trustMode"), launch_payload.get("coLocated"),
            launch_payload.get("hardwareBacked"),
        )
        certificate_public_key = _b64url_decode(
            launch_payload.get("launchPublicKeyBase64Url"), size=32
        )
        self.launch_identity_key = _load_ed25519_private_key(
            launch_private_value
        )
        launch_public = self.launch_identity_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if (
            certificate_launch_binding != expected_launch_binding
            or type(certificate_launch_binding[1]) is not int
            or certificate_assurance[0] != expected_assurance[0]
            or certificate_assurance[1] is not expected_assurance[1]
            or certificate_assurance[2] is not expected_assurance[2]
            or certificate_public_key != launch_public
            or _canonical(launch_certificate) != launch_certificate_value
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
        elif role == "planner-writer":
            from serverware import authority_revocation_writer_signer

            # Hold immutable measured pins before this writer-key load.
            # No post-read configuration lookup can retarget this signer.
            response_spki_digest = self.role_config["responseSigningSpkiDigest"]
            other_response_spki_digests = tuple(
                configuration.role(name)["responseSigningSpkiDigest"]
                for name in ("verifier", "planner", "issuer", "executor")
            )
            launch_public_key = self.launch_identity_key.public_key()
            private_value = _read_bounded_descriptor(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY",
                maximum=64 * 1024,
                require_root_owned=True,
                require_descriptor=True,
            )
            self.writer_response_signing_key = (
                authority_revocation_writer_signer._signer_from_pem(
                    private_value, response_spki_digest=response_spki_digest,
                    other_response_spki_digests=other_response_spki_digests,
                    launch_public_key=launch_public_key,
                )
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
        from serverware import control_plane_rbac_currentness as rbac_currentness
        self.rbac_currentness_owner = (rbac_currentness.initialize_authority(self)
            if role in {"verifier", "planner", "executor"} else None)
        from serverware import authority_public_revocation_terminal
        authority_public_revocation_terminal.initialize(self)

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
        writer_signing_descriptor = bool(
            os.environ.get(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD", ""
            ).strip()
        )
        writer_signing_path = bool(
            os.environ.get(
                "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_PATH", ""
            ).strip()
        )
        if (
            self.role_name == "planner-writer"
            and (not writer_signing_descriptor or writer_signing_path)
        ) or (
            self.role_name != "planner-writer"
            and (writer_signing_descriptor or writer_signing_path)
        ):
            raise AuthorityServiceError(
                "authority planner-writer signer credential set is not exact"
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

    def _verify_revocation_plan_handoff(self, *, envelope_bytes, evaluation_context_bytes,
            expected_request, context, root_inventory, work):
        """Private measured-verifier composition, not a serving purpose.

        Main's root-signed configuration load and the active launch establish
        admission. A constructed dataclass or caller-owned inventory is not
        that admission. Capture invocation inputs and the full configuration
        before launch or key callbacks; role identity and age policy come only
        from the captured measured configuration. No DSN or signing key is used.
        """
        if (self.role_name != "verifier"
                or self.process_mode != "policy-authority-verifier"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation plan verifier process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        from serverware import authority_revocation_configuration
        from serverware import authority_revocation_verifier

        owned_request, owned_context, inventory = authority_revocation_verifier._capture_handoff_inputs(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            expected_request=expected_request, context=context, root_inventory=root_inventory, work=work)
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation plan verifier configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("verifier"))
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        verifier = authority_revocation_verifier._verifier_from_configuration_on_work(
            payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities,
            generation=generation, work=work)
        return verifier.verify_handoff(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=owned_request,
            context=owned_context, root_inventory=inventory, work=work)

    def _webauthn_transition_planner(self, *, operation, work):
        """Construct a fixed configured successor reader without opening SQL."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._planner_on_work(self, operation=operation, work=work)

    def _webauthn_transition_plan_producer(self, *, operation, work):
        """Bind a fixed successor producer to measured policy and real signer."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._producer_on_work(self, operation=operation, work=work)

    def _webauthn_transition_plan_verifier(self, *, operation, work):
        """Construct a public-key-only configured successor verifier."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._verifier_on_work(self, operation=operation, work=work)

    def _verify_webauthn_transition_plan_handoff(self, *, operation, envelope_bytes,
            proof_bytes, inputs_bytes, context_bytes, expectations, work):
        """Own independent history before measured callbacks and raw replay."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._verify_handoff_on_work(self, operation=operation,
            envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
            context_bytes=context_bytes, expectations=expectations, work=work)

    def _webauthn_transition_root_reader(self, *, operation, work):
        """Construct a verifier-only root reader from protected configuration."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._root_reader_on_work(self, operation=operation, work=work)

    def _webauthn_transition_plan_persistence(self, *, operation, work):
        """Construct one inert writer-only owner with held public policy pins."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._persistence_on_work(self, operation=operation, work=work)

    def _persist_webauthn_transition_plan(self, *, operation, envelope_bytes, proof_bytes,
            inputs_bytes, context_bytes, expectations, work):
        """Own independent history before measured admission and real raw4 custody."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._persist_plan_on_work(self, operation=operation,
            envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
            context_bytes=context_bytes, expectations=expectations, work=work)

    def _read_webauthn_transition_plan(self, *, operation, retained_record_digest, expectations, work):
        """Genuinely replay retained originals without adopting stored history."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._read_plan_on_work(self, operation=operation,
            retained_record_digest=retained_record_digest, expectations=expectations, work=work)

    def _read_webauthn_transition_root_observations(self, *, operation, request, work):
        """Read primary and counted-root metadata without reserving its state."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._read_roots_on_work(self, operation=operation, request=request, work=work)

    def _prepare_webauthn_registration_finalization(self, *, request_originals,
            response_originals, sibling_challenge_ids, deadline_epoch_ns, work,
            transport_deadline_ns=None):
        """Genuinely replay signer originals before actual transition preparation.

        This returns raw7 only. Complete population proofs and the actual v2
        business evidence row remain planner/kernel prerequisites, not facts
        inferred from a custody digest or the supplied sibling lookup hints.
        """
        from serverware import authority_webauthn_registration_finalization_preparation as preparation

        return preparation._prepare_on_work(self, request_originals=request_originals,
            response_originals=response_originals, sibling_challenge_ids=sibling_challenge_ids,
            deadline_epoch_ns=deadline_epoch_ns, work=work,
            transport_deadline_ns=transport_deadline_ns)

    def _prepare_webauthn_registration_finalization_execution(self, *, request_originals,
            response_originals, sibling_challenge_ids, deadline_epoch_ns, work,
            transport_deadline_ns=None):
        """Prepare finalization raw7 and its actual jointly observed complete vector."""
        from serverware import authority_webauthn_registration_finalization_execution_preparation as preparation

        return preparation._prepare_on_work(self, request_originals=request_originals,
            response_originals=response_originals, sibling_challenge_ids=sibling_challenge_ids,
            deadline_epoch_ns=deadline_epoch_ns, work=work,
            transport_deadline_ns=transport_deadline_ns)

    def _prepare_webauthn_transition_custody(self, *, operation, request, inputs_bytes,
            now_epoch_ns, deadline_epoch_ns, invocation, work, transport_deadline_ns=None):
        """Prepare exact custody originals from an independently admitted invocation.

        The genuine verifier admits the bounded live planning observations as
        history before intent and relay preparation. This is not public request
        admission, current-root authority, reservation or business execution.
        No custody writer is contacted; the caller must journal the returned
        raw-seven originals before any separate potentially committing send.
        """
        from serverware import authority_webauthn_transition_preparation as preparation

        return preparation._prepare_on_work(self, operation=operation, request=request,
            inputs_bytes=inputs_bytes, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, invocation=invocation, work=work,
            transport_deadline_ns=transport_deadline_ns)

    def _produce_webauthn_transition_plan_request(self, *, operation, request, inputs_bytes,
            now_epoch_ns, deadline_epoch_ns, invocation, work):
        """Prepare signed originals using independently read primary/count roots."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._produce_request_on_work(self, operation=operation, request=request,
            inputs_bytes=inputs_bytes, now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns,
            invocation=invocation, work=work)

    def _request_webauthn_transition_plan(self, *, operation, control_bytes,
            context_bytes, inputs_bytes, work, transport_deadline_ns=None):
        """Exchange an original request and replay its signed raw-four response."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._request_plan_on_work(self, operation=operation,
            control_bytes=control_bytes, context_bytes=context_bytes, inputs_bytes=inputs_bytes, work=work,
            transport_deadline_ns=transport_deadline_ns)

    def _produce_webauthn_transition_plan(self, *, operation, control_bytes,
            context_bytes, inputs_bytes, work):
        """Authenticate original request bytes before read-only plan production."""
        from serverware import authority_webauthn_transition_service as transitions

        return transitions._produce_plan_on_work(self, operation=operation,
            control_bytes=control_bytes, context_bytes=context_bytes, inputs_bytes=inputs_bytes, work=work)

    def _produce_webauthn_transition_custody_intent(self, *, operation, envelope_bytes,
            proof_bytes, inputs_bytes, context_bytes, expectations, work):
        """Prepare retain-only intent from independently admitted historical expectations."""
        from serverware import authority_webauthn_transition_custody_service as custody

        return custody._produce_intent_on_work(self, operation=operation,
            envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
            context_bytes=context_bytes, expectations=expectations, work=work)

    def _produce_webauthn_transition_custody_relay(self, *, operation, intent_bytes,
            envelope_bytes, proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work):
        """Prepare a genuine planner relay without contacting the writer."""
        from serverware import authority_webauthn_transition_custody_service as custody

        return custody._produce_relay_on_work(self, operation=operation, intent_bytes=intent_bytes,
            envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
            context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _request_webauthn_transition_custody_relay(self, *, operation, intent_bytes,
            envelope_bytes, proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work,
            transport_deadline_ns=None):
        """Request authenticated relay preparation, not persistence or forwarding."""
        from serverware import authority_webauthn_transition_custody_service as custody

        return custody._request_relay_on_work(self, operation=operation, intent_bytes=intent_bytes,
            envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
            context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes, work=work,
            transport_deadline_ns=transport_deadline_ns)

    def _forward_webauthn_transition_custody(self, *, operation, intent_bytes, relay_bytes,
            envelope_bytes, proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work):
        """Explicit verifier-to-planner forwarding of previously retained originals."""
        from serverware import authority_webauthn_transition_custody_service as custody

        return custody._forward_on_work(self, operation=operation, intent_bytes=intent_bytes,
            relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, proof_bytes=proof_bytes,
            inputs_bytes=inputs_bytes, context_bytes=context_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _send_webauthn_transition_custody(self, *, operation, intent_bytes, relay_bytes,
            envelope_bytes, proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work):
        """Send genuine original custody controls from planner to fixed writer."""
        from serverware import authority_webauthn_transition_custody_service as custody

        return custody._send_on_work(self, operation=operation, intent_bytes=intent_bytes,
            relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, proof_bytes=proof_bytes,
            inputs_bytes=inputs_bytes, context_bytes=context_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _persist_webauthn_transition_custody(self, *, operation, intent_bytes, relay_bytes,
            envelope_bytes, proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes, work):
        """Authenticate complete custody controls before the actual writer transaction."""
        from serverware import authority_webauthn_transition_custody_service as custody

        return custody._persist_on_work(self, operation=operation, intent_bytes=intent_bytes,
            relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, proof_bytes=proof_bytes,
            inputs_bytes=inputs_bytes, context_bytes=context_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _produce_webauthn_transition_custody_read_request(self, *, operation,
            retained_record_digest, expectations, work):
        """Prepare lookup-only authority over independently held identity and history."""
        from serverware import authority_webauthn_transition_custody_read_service as custody_read

        return custody_read._produce_on_work(self, operation=operation,
            retained_record_digest=retained_record_digest, expectations=expectations, work=work)

    def _read_webauthn_transition_custody(self, *, operation, control_bytes,
            historical_expectations_bytes, work):
        """Authenticate original lookup bytes before the actual configured read owner."""
        from serverware import authority_webauthn_transition_custody_read_service as custody_read

        return custody_read._read_on_work(self, operation=operation, control_bytes=control_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _request_webauthn_transition_custody_read(self, *, operation, control_bytes,
            historical_expectations_bytes, work):
        """Retrieve via the planner and genuinely replay historical originals."""
        from serverware import authority_webauthn_transition_custody_read_service as custody_read

        return custody_read._request_on_work(self, operation=operation, control_bytes=control_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _forward_webauthn_transition_custody_read(self, *, operation, control_bytes,
            historical_expectations_bytes, work):
        """Forward the unchanged lookup control and verify the writer's originals."""
        from serverware import authority_webauthn_transition_custody_read_service as custody_read

        return custody_read._forward_on_work(self, operation=operation, control_bytes=control_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _webauthn_evidence_planner(self, *, purpose, work):
        """Construct one private purpose-pinned read owner, without opening SQL.

        The real signed-configuration load and active planner launch remain
        upstream admission requirements; a constructed configuration dataclass
        is not their substitute. Own the full payload before launch/descriptor
        callbacks and take the generation snapshot last. The fixed mapper
        derives evidence keys and policy only from that same owned payload.
        This factory accepts no request, key, target, policy or read override,
        and does not enable an operation, registry entry or serving route.
        """
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise AuthorityServiceError("WebAuthn evidence purpose is not supported")
        if (self.role_name != "planner"
                or self.process_mode != "policy-authority-planner"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("WebAuthn evidence planner process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        from serverware import authority_revocation_configuration
        from serverware import authority_webauthn_evidence_configuration

        mapper = (
            authority_webauthn_evidence_configuration._registration_planner_from_configuration_on_work
            if purpose == "registration" else
            authority_webauthn_evidence_configuration._installation_planner_from_configuration_on_work
        )
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("WebAuthn evidence planner configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("planner"))
        read_dsn = authority_revocation_configuration.production._callback(
            work, lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"))
        # No callback may interpose before the mapper owns the seven actual
        # launch-generation bindings from this final snapshot.
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return mapper(payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities,
            generation=generation, read_dsn=read_dsn, work=work)

    def _read_webauthn_registration_source(self, *, registration_challenge_id,
            published_publication_id, oidc_session_id, business_before_roots,
            authorization_before_roots, now_epoch_ns, deadline_epoch_ns, work):
        """Acquire fixed pre-signing originals through the actual planner owner.

        The selected enrollment and independent root/time expectations require
        prior admission. No caller supplies a DSN, manifest, key, evidence
        digest or signed request to this read-only continuation. The original
        observations return only after normal transaction exit and live launch
        continuity checks; they are not root authority or a signing grant.
        No route, privilege, replacement allowance or custody write is added.
        """
        from serverware import authority_query_reads as reads
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_webauthn_evidence_planning as planning

        if (type(self) is not AuthorityProcess or self.role_name != "planner"
                or self.process_mode != "policy-authority-planner"):
            raise AuthorityServiceError("registration source read requires the actual planner process")
        ledger = configuration.capability.capture._SharedLedger(work)
        owned = reads._CopyBudget(work).copy({
            "challenge": registration_challenge_id, "publication": published_publication_id,
            "session": oidc_session_id, "business": business_before_roots,
            "authorization": authorization_before_roots, "now": now_epoch_ns,
            "deadline": deadline_epoch_ns})
        initial_generation = configuration.capability.capture._JSONCapture(ledger).visit(
            configuration.production._callback(work, lambda: dict(authority_launch_guard.generation())))
        owner = AuthorityProcess._webauthn_evidence_planner(self, purpose="registration", work=work)
        result = planning.EvidenceAdmissionPlanner.acquire_registration_source(owner,
            registration_challenge_id=owned["challenge"], published_publication_id=owned["publication"],
            oidc_session_id=owned["session"], business_before_roots=owned["business"],
            authorization_before_roots=owned["authorization"], now_epoch_ns=owned["now"],
            deadline_epoch_ns=owned["deadline"], work=work)
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("planner"))
        final_generation = configuration.capability.capture._JSONCapture(ledger).visit(
            configuration.production._callback(work, lambda: dict(authority_launch_guard.generation())))
        configuration.capability.plan._same(
            tuple(initial_generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "registration source read launch generation changed")
        return result

    def _produce_webauthn_registration_source_request(self, *, registration_challenge_id,
            published_publication_id, oidc_session_id, deadline_epoch_ns, work):
        """Bind admitted enrollment selectors to actual independent verifier roots.

        This private read request neither accepts caller roots nor establishes
        the user's enrollment/selector authority. Actual live root observations
        do not reserve state or grant registration-evidence signing authority.
        """
        from serverware import authority_query_reads as reads
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_webauthn_evidence_root_configuration as root_configuration
        from serverware import authority_webauthn_evidence_root_reader as root_reader
        from serverware import authority_webauthn_evidence_roots as roots
        from serverware import authority_webauthn_registration_source_actions as actions

        owned = reads._CopyBudget(work).copy({"challenge": registration_challenge_id,
            "publication": published_publication_id, "session": oidc_session_id,
            "deadline": deadline_epoch_ns})
        payload, digest, generation, read_dsn, signer, runtime = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=True, read_roots=True, work=work)
        reader = root_configuration._reader_from_configuration_on_work(purpose="registration",
            payload=payload, configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime, read_dsn=read_dsn, work=work)
        inventory = root_reader.EvidenceRootReader.read(reader, work=work)
        business, authorization = roots._project_on_work(inventory,
            operation="webauthn.registration.evidence.admit", work=work)
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("verifier"))
        final_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        configuration.capability.plan._same(
            tuple(generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "registration source request root-read generation changed")
        return actions._produce_request_on_configuration(payload=payload,
            configuration_digest=digest, generation=final_generation, runtime_role_identities=runtime,
            registration_challenge_id=owned["challenge"], published_publication_id=owned["publication"],
            oidc_session_id=owned["session"], business_before_roots=business,
            authorization_before_roots=authorization, deadline_epoch_ns=owned["deadline"],
            verifier_private_key=signer, work=work)

    def _produce_webauthn_registration_source_response(self, *, control_bytes, context_bytes, work):
        """Authenticate, acquire and sign one original read-only source response."""
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_webauthn_registration_source_actions as actions

        originals = registration_source_transport._validate_request(
            control_bytes=control_bytes, context_bytes=context_bytes)
        payload, digest, generation, read_dsn, signer, runtime = _webauthn_evidence_custody_context(
            self, role_name="planner", signing=True, planning=True, work=work)
        result = actions._produce_response_on_configuration(payload=payload,
            configuration_digest=digest, generation=generation, runtime_role_identities=runtime,
            control_bytes=originals[0], context_bytes=originals[1], read_dsn=read_dsn,
            planner_private_key=signer, work=work)
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("planner"))
        final_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        configuration.capability.plan._same(
            tuple(generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "registration source response generation changed")
        return result

    def _request_webauthn_registration_source(self, *, control_bytes, context_bytes, work,
            transport_deadline_ns=None):
        """Authenticate the exact response before decoding and replaying its proofs.

        The supplied request must be the verifier's genuinely admitted live
        invocation. Raw response originals remain data, not an evidence-signing
        grant, durable receipt or transferable successful-proof carrier.
        """
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_webauthn_registration_source_actions as actions

        originals = registration_source_transport._validate_request(
            control_bytes=control_bytes, context_bytes=context_bytes)
        if transport_deadline_ns is not None:
            registration_source_transport._check_deadline(transport_deadline_ns)
        payload, digest, generation, _dsn, _signer, runtime = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=False, work=work)
        result = actions._request_on_configuration(payload=payload,
            configuration_digest=digest, generation=generation, runtime_role_identities=runtime,
            control_bytes=originals[0], context_bytes=originals[1], work=work,
            transport_deadline_ns=transport_deadline_ns)
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("verifier"))
        final_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        configuration.capability.plan._same(
            tuple(generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "registration source exchange generation changed")
        return result

    def _acquire_webauthn_registration_source(self, *, registration_challenge_id,
            published_publication_id, oidc_session_id, deadline_epoch_ns, work,
            transport_deadline_ns=None):
        """Preserve raw4 from actual root observation through authenticated replay.

        No browser route or independent evidence signer is activated here.
        Enrollment/selector provenance remains upstream. All four originals
        must be retained for any later independent authentication and replay;
        this tuple is not a substitute for that work or for current roots.
        """
        from serverware import authority_query_reads as reads
        from serverware import authority_revocation_configuration as configuration

        initial_configuration = self.configuration
        owned = reads._CopyBudget(work).copy({"challenge": registration_challenge_id,
            "publication": published_publication_id, "session": oidc_session_id,
            "deadline": deadline_epoch_ns, "transportDeadline": transport_deadline_ns})
        if owned["transportDeadline"] is not None:
            registration_source_transport._check_deadline(owned["transportDeadline"])
        initial_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        initial_generation = reads._CopyBudget(work).copy(
            {name: initial_generation[name] for name in configuration._GENERATION_FIELDS})
        request = AuthorityProcess._produce_webauthn_registration_source_request(self,
            registration_challenge_id=owned["challenge"],
            published_publication_id=owned["publication"], oidc_session_id=owned["session"],
            deadline_epoch_ns=owned["deadline"], work=work)
        response = AuthorityProcess._request_webauthn_registration_source(self,
            control_bytes=request.control_bytes, context_bytes=request.context_bytes, work=work,
            transport_deadline_ns=owned["transportDeadline"])
        final_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        configuration.capability.plan._same(
            tuple(initial_generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "registration source acquisition launch generation changed")
        if self.configuration is not initial_configuration:
            raise AuthorityServiceError("registration source acquisition configuration changed")
        if owned["transportDeadline"] is not None:
            registration_source_transport._check_deadline(owned["transportDeadline"])
        return request.control_bytes, request.context_bytes, response[0], response[1]

    def _webauthn_evidence_plan_producer(self, *, purpose, work):
        """Construct one private configured producer without opening SQL.

        The actual signed configuration, descriptor-loaded planner signer and
        active launch remain upstream requirements. Hold the signer and own
        the full payload before launch/descriptor callbacks, then capture
        generation last. The fixed mapper binds the signer and purpose policy
        from that same graph; no caller key, request, clock, DSN or policy
        override is accepted. This does not enable an operation or route.
        """
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise AuthorityServiceError("WebAuthn evidence plan purpose is not supported")
        if (self.role_name != "planner"
                or self.process_mode != "policy-authority-planner"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("WebAuthn evidence plan producer process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        planner_private_key = self.signing_key
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise AuthorityServiceError("WebAuthn evidence plan planner signer is unavailable")
        from serverware import authority_revocation_configuration
        from serverware import authority_webauthn_evidence_plan_configuration

        mapper = (
            authority_webauthn_evidence_plan_configuration._registration_plan_producer_from_configuration_on_work
            if purpose == "registration" else
            authority_webauthn_evidence_plan_configuration._installation_plan_producer_from_configuration_on_work
        )
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("WebAuthn evidence plan configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("planner"))
        read_dsn = authority_revocation_configuration.production._callback(
            work, lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"))
        # The mapper immediately owns this final seven-binding launch snapshot;
        # no subsequent lookup reads the process signer or configuration again.
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return mapper(payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities,
            generation=generation, read_dsn=read_dsn,
            planner_private_key=planner_private_key, work=work)

    def _webauthn_evidence_plan_persistence(self, *, purpose, work):
        """Construct one private purpose-pinned writer without opening SQL.

        The real signed configuration, active writer launch and protected
        descriptor remain upstream admission requirements. Own the complete
        payload before callbacks and capture generation last. The fixed mapper
        derives public keys, evidence policy and database pins from that same
        graph; this factory accepts no request, key, DSN or policy override.
        It does not admit original plans or enable an operation or route.
        """
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise AuthorityServiceError("WebAuthn evidence persistence purpose is not supported")
        if (type(self) is not AuthorityProcess or self.role_name != "planner-writer"
                or self.process_mode != "policy-authority-planner-writer"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("WebAuthn evidence plan writer process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        from serverware import authority_revocation_configuration
        from serverware import authority_webauthn_evidence_plan_writer_configuration

        mapper = (
            authority_webauthn_evidence_plan_writer_configuration._registration_plan_persistence_from_configuration_on_work
            if purpose == "registration" else
            authority_webauthn_evidence_plan_writer_configuration._installation_plan_persistence_from_configuration_on_work
        )
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("WebAuthn evidence plan writer configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("planner-writer"))
        writer_dsn = authority_revocation_configuration.production._callback(
            work, lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"))
        # The fixed mapper immediately owns this last launch snapshot; no
        # process configuration or descriptor is looked up again afterward.
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return mapper(payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities,
            generation=generation, writer_dsn=writer_dsn, work=work)

    def _webauthn_evidence_plan_verifier(self, *, purpose, work):
        """Construct a private verifier from one owned measured configuration.

        The signed configuration and active verifier launch remain real
        upstream requirements. Capture the complete payload before callbacks,
        then take generation last. Only the fixed purpose mapper supplies
        public-key and policy pins; no descriptor, signer or caller override
        is used, and no operation or serving route is enabled.
        """
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise AuthorityServiceError("WebAuthn evidence verification purpose is not supported")
        if (type(self) is not AuthorityProcess or self.role_name != "verifier"
                or self.process_mode != "policy-authority-verifier"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("WebAuthn evidence plan verifier process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        from serverware import authority_revocation_configuration
        from serverware import authority_webauthn_evidence_plan_verifier_configuration

        mapper = (
            authority_webauthn_evidence_plan_verifier_configuration._registration_plan_verifier_from_configuration_on_work
            if purpose == "registration" else
            authority_webauthn_evidence_plan_verifier_configuration._installation_plan_verifier_from_configuration_on_work
        )
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("WebAuthn evidence verifier configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("verifier"))
        # No descriptor or other callback interposes before the fixed mapper
        # owns this final seven-binding launch-generation snapshot.
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return mapper(payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities,
            generation=generation, work=work)

    def _verify_webauthn_evidence_plan_handoff(self, *, purpose, envelope_bytes,
            inputs_bytes, evaluation_context_bytes, expectations, work):
        """Replay raw3 against independently admitted, owned historical inputs.

        Original request, root, input-commitment and time provenance must be
        established upstream. Own all eighteen expectations before factory,
        key or launch callbacks; the stored context never supplies them. This
        handoff samples no new clock and grants no custody or execution claim.
        """
        if type(purpose) is not str or purpose not in ("registration", "installation"):
            raise AuthorityServiceError("WebAuthn evidence handoff purpose is not supported")
        if (type(self) is not AuthorityProcess or self.role_name != "verifier"
                or self.process_mode != "policy-authority-verifier"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("WebAuthn evidence handoff verifier is not configured")
        from serverware import authority_webauthn_evidence_plan_retention as retention
        from serverware import authority_webauthn_evidence_plan_verifier as verifying

        originals = envelope_bytes, inputs_bytes, evaluation_context_bytes
        for raw, maximum in zip(originals, (retention.plan.contract.MAX_BYTES,
                retention.plan.inputs_wire.MAX_BYTES, retention.context_wire.MAX_BYTES)):
            retention.plan.inputs_wire._raw(raw, 2, maximum)
        ledger = retention.evidence.capture._SharedLedger(work)
        retention.evidence.plan.contract._object(
            expectations, retention.plan._EXPECTATION_FIELDS, "independent evidence handoff expectations")
        owned = retention.evidence.capture._JSONCapture(
            ledger, maximum_bytes=retention.plan.contract.MAX_BYTES).visit(expectations)
        operation = ("webauthn.registration.evidence.admit" if purpose == "registration"
            else "webauthn.trust.installation.admit")
        retention.plan._validate_expectations(owned, operation)
        verifier = AuthorityProcess._webauthn_evidence_plan_verifier(self, purpose=purpose, work=work)
        return verifying.EvidencePlanVerifier.verify(verifier, envelope_bytes=originals[0],
            inputs_bytes=originals[1], evaluation_context_bytes=originals[2], expectations=owned, work=work)

    def _prepare_webauthn_evidence_custody(self, *, purpose, request, inputs_bytes,
            deadline_epoch_ns, work, transport_deadline_ns=None):
        """Prepare raw-six originals after genuine live-history admission.

        Typed request and original ceremony/installation provenance must be
        independently admitted upstream. This private composition supplies no
        public authorization, execution capability, writer contact or retry.
        The caller must durably retain all returned originals before forwarding.
        """
        from serverware import authority_webauthn_evidence_preparation as preparation

        return preparation._prepare_on_work(self, purpose=purpose, request=request,
            inputs_bytes=inputs_bytes, deadline_epoch_ns=deadline_epoch_ns, work=work,
            transport_deadline_ns=transport_deadline_ns)

    def _prepare_webauthn_registration_evidence(self, *, envelope_bytes, client_data_json,
            attestation_object, credential_id, transports, scope, verification_context,
            expected_authorization, published_row, oidc_session_row, deadline_epoch_ns, work):
        """Derive the evidence request from admitted originals, then prepare raw6.

        The envelope signer, ceremony/trust context, enrollment authorization
        and selected publication/session rows still require upstream admission.
        This is not a browser API, signing service or successful-proof adapter.
        """
        from serverware import authority_webauthn_evidence_invocation as invocation

        request, inputs_bytes = invocation._registration_on_work(
            envelope_bytes=envelope_bytes, client_data_json=client_data_json,
            attestation_object=attestation_object, credential_id=credential_id,
            transports=transports, scope=scope, verification_context=verification_context,
            expected_authorization=expected_authorization, published_row=published_row,
            oidc_session_row=oidc_session_row, work=work)
        return AuthorityProcess._prepare_webauthn_evidence_custody(self,
            purpose="registration", request=request, inputs_bytes=inputs_bytes,
            deadline_epoch_ns=deadline_epoch_ns, work=work)

    def _prepare_webauthn_installation_evidence(self, *, installation_envelope_bytes,
            installed_bundle_bytes, installed_state_bytes, observed_at,
            expected_committed_stage, publication_row, deadline_epoch_ns, work):
        """Prepare installation raw6 from actual signed originals and admitted stage.

        Installed bytes alone do not establish physical installation or a
        committed stage. Those original observations and the publication row
        remain the independent installer's and upstream owner's responsibility.
        """
        from serverware import authority_webauthn_evidence_invocation as invocation

        request, inputs_bytes = invocation._installation_on_work(
            installation_envelope_bytes=installation_envelope_bytes,
            installed_bundle_bytes=installed_bundle_bytes, installed_state_bytes=installed_state_bytes,
            observed_at=observed_at, expected_committed_stage=expected_committed_stage,
            publication_row=publication_row, work=work)
        return AuthorityProcess._prepare_webauthn_evidence_custody(self,
            purpose="installation", request=request, inputs_bytes=inputs_bytes,
            deadline_epoch_ns=deadline_epoch_ns, work=work)

    def _produce_webauthn_evidence_plan_request(self, *, purpose, request, inputs_bytes,
            deadline_epoch_ns, work):
        """Sign a planning request with an actual independent root snapshot.

        Upstream must admit the typed request and original ceremony or committed
        installation inputs. This private method does not infer that authority
        from supplied JSON. It prepares original controls without sending them.
        """
        operation = _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_webauthn_evidence_plan_actions as actions
        from serverware import authority_webauthn_evidence_plan_request as request_wire
        from serverware import authority_webauthn_evidence_root_configuration as root_configuration
        from serverware import authority_webauthn_evidence_root_reader as root_reader
        from serverware import authority_webauthn_evidence_roots as roots

        request_wire.inputs_wire._raw(inputs_bytes, 2, request_wire.MAX_INPUT_BYTES)
        original_inputs = inputs_bytes
        request_wire.evidence.plan.contract._integer(deadline_epoch_ns, minimum=1)
        deadline = deadline_epoch_ns
        owned = request_wire.evidence.capture._JSONCapture(
            request_wire.evidence.capture._SharedLedger(work),
            maximum_bytes=request_wire.MAX_CONTEXT_BYTES).visit(request)
        request_wire.plan.contract._request(owned, operation, request_wire.plan.contract._SPECS[operation])
        payload, digest, generation, read_dsn, signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=True, read_roots=True, work=work)
        reader = root_configuration._reader_from_configuration_on_work(purpose=purpose,
            payload=payload, configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities,
            read_dsn=read_dsn, work=work)
        inventory = root_reader.EvidenceRootReader.read(reader, work=work)
        business, authorization = roots._project_on_work(inventory, operation=operation, work=work)
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("verifier"))
        final_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        configuration.capability.plan._same(
            tuple(generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "WebAuthn evidence planning root read generation changed")
        return actions._produce_request_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=final_generation, request=owned,
            runtime_role_identities=runtime_role_identities,
            business_before_roots=business, authorization_before_roots=authorization,
            inputs_bytes=original_inputs, deadline_epoch_ns=deadline,
            verifier_private_key=signer, work=work)

    def _request_webauthn_evidence_plan(self, *, purpose, control_bytes,
            context_bytes, inputs_bytes, work, transport_deadline_ns=None):
        """Send original planning inputs; authenticate and replay the response.

        The returned response control and raw3 are observations, not retained
        history admission, business execution authority or a durable receipt.
        """
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_webauthn_evidence_plan_actions as actions

        originals = evidence_plan_transport._validate_request(control_bytes=control_bytes,
            context_bytes=context_bytes, inputs_bytes=inputs_bytes)
        if transport_deadline_ns is not None:
            evidence_plan_transport._check_deadline(transport_deadline_ns)
        payload, digest, generation, _dsn, _signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=False, work=work)
        result = actions._request_plan_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, control_bytes=originals[0],
            context_bytes=originals[1], inputs_bytes=originals[2], work=work,
            transport_deadline_ns=transport_deadline_ns)
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("verifier"))
        final_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        configuration.capability.plan._same(
            tuple(generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "WebAuthn evidence planning response generation changed")
        return result

    def _produce_webauthn_evidence_plan(self, *, purpose, control_bytes,
            context_bytes, inputs_bytes, work):
        """Authenticate the request before actual read/acquire/replay/sign.

        Normal producer connection exit precedes the signed raw3 response.
        No retained-record or business mutation, reservation or retry follows.
        """
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_webauthn_evidence_plan_actions as actions

        originals = evidence_plan_transport._validate_request(control_bytes=control_bytes,
            context_bytes=context_bytes, inputs_bytes=inputs_bytes)
        payload, digest, generation, read_dsn, signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="planner", signing=True, planning=True, work=work)
        result = actions._produce_plan_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, control_bytes=originals[0],
            context_bytes=originals[1], inputs_bytes=originals[2], read_dsn=read_dsn,
            planner_private_key=signer, work=work)
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("planner"))
        final_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        configuration.capability.plan._same(
            tuple(generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "WebAuthn evidence plan production generation changed")
        return result

    def _read_webauthn_evidence_root_observations(self, *, purpose, work):
        """Read actual verifier root metadata, not historical or execution proof.

        The source-fixed read completes its real read-only transaction and
        connection close before returning. A later write may change these roots;
        neither this observation nor its generation check reserves that state.
        """
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_webauthn_evidence_root_configuration as root_configuration
        from serverware import authority_webauthn_evidence_root_reader as root_reader

        payload, digest, generation, read_dsn, _signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=False, read_roots=True, work=work)
        reader = root_configuration._reader_from_configuration_on_work(purpose=purpose,
            payload=payload, configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities,
            read_dsn=read_dsn, work=work)
        inventory = root_reader.EvidenceRootReader.read(reader, work=work)
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("verifier"))
        final_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        configuration.capability.plan._same(
            tuple(generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "WebAuthn evidence root read generation changed")
        return inventory

    def _produce_webauthn_evidence_custody_intent(self, *, purpose, envelope_bytes,
            inputs_bytes, evaluation_context_bytes, expectations, work):
        """Check live roots and genuinely replay independently admitted history.

        Root equality is checked using a completed verifier-owned snapshot. It
        does not hold those roots current through signing or execution. Original
        request/input/time provenance remains upstream; no stored context or
        current observation can create it. Preparation never sends, persists or
        automatically retries the resulting original controls.
        """
        operation = _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_actions as actions
        from serverware import authority_webauthn_evidence_custody_intent as intent
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_webauthn_evidence_root_configuration as root_configuration
        from serverware import authority_webauthn_evidence_root_reader as root_reader
        from serverware import authority_webauthn_evidence_roots as roots

        originals = intent._raw3(envelope_bytes, inputs_bytes, evaluation_context_bytes)
        ledger = intent.evidence.capture._SharedLedger(work)
        intent.evidence.plan.contract._object(expectations,
            intent.retention.plan._EXPECTATION_FIELDS, "independent evidence custody expectations")
        owned = intent.evidence.capture._JSONCapture(
            ledger, maximum_bytes=intent.retention.plan.contract.MAX_BYTES).visit(expectations)
        intent.retention.plan._validate_expectations(owned, operation)
        payload, digest, generation, read_dsn, signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=True, read_roots=True, work=work)
        reader = root_configuration._reader_from_configuration_on_work(purpose=purpose,
            payload=payload, configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities,
            read_dsn=read_dsn, work=work)
        inventory = root_reader.EvidenceRootReader.read(reader, work=work)
        observed_roots = roots._project_on_work(inventory, operation=operation, work=work)
        intent.evidence.plan._same(observed_roots,
            (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"]), work,
            "WebAuthn evidence custody roots differ from verifier database snapshot")
        # Recheck the actual launch after all database scopes have closed. Hold
        # the original configuration and signer; never reread mutable self or
        # retime the independently owned historical context after callbacks.
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("verifier"))
        final_generation = configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        intent.evidence.plan._same(
            tuple(generation[name] for name in configuration._GENERATION_FIELDS),
            tuple(final_generation[name] for name in configuration._GENERATION_FIELDS), work,
            "WebAuthn evidence custody root read generation changed")
        return actions._produce_intent_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=final_generation, envelope_bytes=originals[0],
            runtime_role_identities=runtime_role_identities,
            inputs_bytes=originals[1], evaluation_context_bytes=originals[2], expectations=owned,
            verifier_private_key=signer, work=work)

    def _produce_webauthn_evidence_custody_relay(self, *, purpose, intent_bytes,
            envelope_bytes, inputs_bytes, evaluation_context_bytes,
            historical_expectations_bytes, work):
        """Authenticate originals before planner signing; never send implicitly."""
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_actions as actions

        originals = evidence_custody_transport._validate_relay_originals(intent_bytes=intent_bytes,
            envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes)
        payload, digest, generation, _dsn, signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="planner", signing=True, work=work)
        return actions._produce_relay_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, intent_bytes=originals[0],
            envelope_bytes=originals[1], inputs_bytes=originals[2], evaluation_context_bytes=originals[3],
            historical_expectations_bytes=originals[4], planner_private_key=signer, work=work)

    def _request_webauthn_evidence_custody_relay(self, *, purpose, intent_bytes,
            envelope_bytes, inputs_bytes, evaluation_context_bytes,
            historical_expectations_bytes, work, transport_deadline_ns=None):
        """Ask only for a relay, then genuinely verify its original response."""
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_actions as actions

        originals = evidence_custody_transport._validate_relay_originals(intent_bytes=intent_bytes,
            envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes)
        if transport_deadline_ns is not None:
            evidence_custody_transport._check_deadline(transport_deadline_ns)
        payload, digest, generation, _dsn, _signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=False, work=work)
        return actions._request_relay_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, intent_bytes=originals[0],
            envelope_bytes=originals[1], inputs_bytes=originals[2], evaluation_context_bytes=originals[3],
            historical_expectations_bytes=originals[4], work=work,
            transport_deadline_ns=transport_deadline_ns)

    def _forward_webauthn_evidence_custody(self, *, purpose, intent_bytes, relay_bytes,
            envelope_bytes, inputs_bytes, evaluation_context_bytes,
            historical_expectations_bytes, work):
        """Explicit verifier-to-planner forwarding of already-held originals."""
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_actions as actions

        originals = evidence_custody_transport._validate_originals(intent_bytes=intent_bytes,
            relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes)
        payload, digest, generation, _dsn, _signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=False, work=work)
        return actions._forward_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, intent_bytes=originals[0],
            relay_bytes=originals[1], envelope_bytes=originals[2], inputs_bytes=originals[3],
            evaluation_context_bytes=originals[4], historical_expectations_bytes=originals[5], work=work)

    def _send_webauthn_evidence_custody(self, *, purpose, intent_bytes, relay_bytes,
            envelope_bytes, inputs_bytes, evaluation_context_bytes,
            historical_expectations_bytes, work):
        """Only the admitted planner can send original controls to the writer."""
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_actions as actions

        originals = evidence_custody_transport._validate_originals(intent_bytes=intent_bytes,
            relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes)
        payload, digest, generation, _dsn, _signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="planner", signing=False, work=work)
        return actions._send_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, intent_bytes=originals[0],
            relay_bytes=originals[1], envelope_bytes=originals[2], inputs_bytes=originals[3],
            evaluation_context_bytes=originals[4], historical_expectations_bytes=originals[5], work=work)

    def _persist_webauthn_evidence_custody(self, *, purpose, intent_bytes, relay_bytes,
            envelope_bytes, inputs_bytes, evaluation_context_bytes,
            historical_expectations_bytes, work):
        """Authenticate original controls before the actual writer transaction.

        Normal return follows outer commit/close. A late failure can still
        follow commit; it is not rollback evidence or retry permission.
        """
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_actions as actions

        originals = evidence_custody_transport._validate_originals(intent_bytes=intent_bytes,
            relay_bytes=relay_bytes, envelope_bytes=envelope_bytes, inputs_bytes=inputs_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes)
        payload, digest, generation, writer_dsn, _signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="planner-writer", signing=False, work=work)
        return actions._persist_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, intent_bytes=originals[0],
            relay_bytes=originals[1], envelope_bytes=originals[2], inputs_bytes=originals[3],
            evaluation_context_bytes=originals[4], historical_expectations_bytes=originals[5],
            writer_dsn=writer_dsn, work=work)

    def _produce_webauthn_evidence_custody_read_request(self, *, purpose,
            retained_record_digest, expectations, work):
        """Authorize a bounded lookup, not renewed retention or execution.

        Historical request/root/configuration provenance must already be
        independently admitted. No stored original is available to replay at
        this preparation step; the real returned originals are verified later.
        """
        operation = _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_read_actions as actions
        from serverware import authority_webauthn_evidence_custody_wire as wire

        shape = wire.evidence.plan.contract
        shape._digest(retained_record_digest)
        shape._object(expectations, wire.retention.plan._EXPECTATION_FIELDS,
            "independent evidence custody read history")
        owned = wire.evidence.capture._JSONCapture(wire.evidence.capture._SharedLedger(work),
            maximum_bytes=wire.retention.plan.contract.MAX_BYTES).visit(expectations)
        wire.retention.plan._validate_expectations(owned, operation)
        if type(self) is not AuthorityProcess:
            raise AuthorityServiceError("evidence custody read process is not configured")
        measured = self.configuration
        if type(measured) is not MeasuredConfiguration:
            raise AuthorityServiceError("evidence custody read configuration is unavailable")
        held_archive = measured.history_archive
        payload, digest, generation, _dsn, signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=True, work=work)
        return actions._produce_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, history_archive=held_archive,
            retained_record_digest=retained_record_digest, expectations=owned,
            verifier_private_key=signer, work=work)

    def _request_webauthn_evidence_custody_read(self, *, purpose, control_bytes,
            historical_expectations_bytes, work):
        """Verifier lookup through the planner, with actual original replay."""
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_read_actions as actions

        originals = evidence_custody_read_transport._validate_request(control_bytes=control_bytes,
            historical_expectations_bytes=historical_expectations_bytes)
        if type(self) is not AuthorityProcess:
            raise AuthorityServiceError("evidence custody read process is not configured")
        measured = self.configuration
        if type(measured) is not MeasuredConfiguration:
            raise AuthorityServiceError("evidence custody read configuration is unavailable")
        held_archive = measured.history_archive
        payload, digest, generation, _dsn, _signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="verifier", signing=False, work=work)
        return actions._request_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, history_archive=held_archive,
            control_bytes=originals[0],
            historical_expectations_bytes=originals[1], work=work)

    def _forward_webauthn_evidence_custody_read(self, *, purpose, control_bytes,
            historical_expectations_bytes, work):
        """Only the configured planner can forward a signed lookup to writer."""
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_read_actions as actions

        originals = evidence_custody_read_transport._validate_request(control_bytes=control_bytes,
            historical_expectations_bytes=historical_expectations_bytes)
        if type(self) is not AuthorityProcess:
            raise AuthorityServiceError("evidence custody read process is not configured")
        measured = self.configuration
        if type(measured) is not MeasuredConfiguration:
            raise AuthorityServiceError("evidence custody read configuration is unavailable")
        held_archive = measured.history_archive
        payload, digest, generation, _dsn, _signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="planner", signing=False, work=work)
        return actions._forward_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, history_archive=held_archive,
            control_bytes=originals[0],
            historical_expectations_bytes=originals[1], work=work)

    def _read_webauthn_evidence_custody(self, *, purpose, control_bytes,
            historical_expectations_bytes, work):
        """Authenticate before the real SELECT path and normal owner close.

        Missing custody raises; it does not prove that a prior write failed.
        This read does not insert, reserve, execute or automatically retry.
        """
        _webauthn_evidence_custody_purpose(purpose)
        from serverware import authority_webauthn_evidence_custody_read_actions as actions

        originals = evidence_custody_read_transport._validate_request(control_bytes=control_bytes,
            historical_expectations_bytes=historical_expectations_bytes)
        if type(self) is not AuthorityProcess:
            raise AuthorityServiceError("evidence custody read process is not configured")
        measured = self.configuration
        if type(measured) is not MeasuredConfiguration:
            raise AuthorityServiceError("evidence custody read configuration is unavailable")
        held_archive = measured.history_archive
        payload, digest, generation, writer_dsn, _signer, runtime_role_identities = _webauthn_evidence_custody_context(
            self, role_name="planner-writer", signing=False, work=work)
        return actions._read_on_configuration(purpose=purpose, payload=payload,
            configuration_digest=digest, generation=generation,
            runtime_role_identities=runtime_role_identities, history_archive=held_archive,
            control_bytes=originals[0],
            historical_expectations_bytes=originals[1], writer_dsn=writer_dsn, work=work)

    def _produce_revocation_observed_plan(self, *, request, evidence, context,
            root_inventory, work):
        """Private measured-planner composition, not a serving purpose.

        Root-signed configuration, the descriptor-loaded signer and active
        planner launch remain upstream admission requirements. Own invocation
        graphs and the complete configuration before callbacks. The mapper
        binds the held signer and read identity; the actual owner produces
        original bytes only after its genuine read scopes close. No writer
        credential or authenticated transport is introduced by this adapter.
        """
        if (self.role_name != "planner"
                or self.process_mode != "policy-authority-planner"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation planner process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        planner_private_key = self.signing_key
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise AuthorityServiceError("revocation planner signing key is unavailable")
        from serverware import authority_revocation_configuration
        from serverware import authority_revocation_planning
        from serverware import authority_revocation_planner_configuration

        owned, inventory = authority_revocation_planning._capture_planning_call_inputs(
            request=request, evidence=evidence, context=context,
            root_inventory=root_inventory, work=work)
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation planner configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("planner"))
        read_dsn = authority_revocation_configuration.production._callback(
            work, lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"))
        # No other callback may interpose between this generation snapshot and
        # the factory's real ownership capture of its seven launch bindings.
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        planner = authority_revocation_planner_configuration._planner_from_configuration_on_work(
            payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities,
            generation=generation, read_dsn=read_dsn,
            planner_private_key=planner_private_key, work=work)
        return planner.produce_observed(request=owned["request"], evidence=owned["evidence"],
            context=owned["context"], root_inventory=inventory, work=work)

    def _request_revocation_observed_plan(self, *, request, evidence, context, work):
        """Acquire independent roots and authenticate one planner exchange.

        Request/evidence and the original reservation context must come from
        genuine upstream admission. This adapter accepts no root inventory,
        public key, current clock, prior proof or response expectation. Hold
        service settings and own call graphs before launch/driver callbacks;
        read and close the real verifier inventory before final generation
        capture. The fixed client verifies the original returned plan/context
        against those same independent inputs. No public dispatcher is enabled.
        """
        if (self.role_name != "verifier"
                or self.process_mode != "policy-authority-verifier"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation planning client process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        verifier_private_key = self.signing_key
        if not isinstance(verifier_private_key, Ed25519PrivateKey):
            raise AuthorityServiceError("revocation planning verifier signer is unavailable")
        from serverware import authority_revocation_configuration
        from serverware import authority_revocation_observed
        from serverware import authority_revocation_planning_client
        from serverware import authority_revocation_planning_request
        from serverware import authority_revocation_root_reader

        owned = authority_revocation_planning_request._capture_call_graphs(
            request=request, evidence=evidence, context=context, work=work)
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation planning verifier configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        role = owned_payload["roles"]["verifier"]
        try:
            timeout = role["databaseConnectTimeoutSeconds"]
            if type(timeout) not in (int, float) or not 2 <= timeout <= 300:
                raise AuthorityServiceError("revocation planning verifier read timeout is not bounded")
            pins = (int(timeout), role["databaseRole"], role["tlsClientDn"],
                role["tlsClientSerial"], role["tlsIssuerDn"], owned_payload["queryManifestDigest"])
        except KeyError as exc:
            raise AuthorityServiceError("revocation planning verifier read configuration is incomplete") from exc
        authority_revocation_root_reader._validate_pins(pins)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("verifier"))
        dsn = authority_revocation_configuration.production._callback(
            work, lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"))
        reader = authority_revocation_root_reader.RevocationRootReader(
            dsn=dsn, connect_timeout_seconds=pins[0], database_role=pins[1],
            tls_client_dn=pins[2], tls_client_serial=pins[3], tls_issuer_dn=pins[4],
            query_manifest_digest=pins[5])
        observed_inventory = reader.read(work=work)
        inventory = authority_revocation_observed._capture_root_inventory(observed_inventory, work=work)
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return authority_revocation_planning_client._request_on_configuration(
            payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities, generation=generation,
            request=owned["request"], evidence=owned["evidence"], context=owned["context"],
            root_inventory=inventory, verifier_private_key=verifier_private_key, work=work)

    def _produce_revocation_plan_from_request(self, *, control_bytes, request_bytes,
            evidence_bytes, context_bytes, root_inventory_bytes, work):
        """Authenticate detached originals before the genuine read-only planner.

        Main's measured configuration and active planner launch are mandatory.
        Own configuration and signer once; the read-only descriptor and final
        generation snapshot feed one fixed worker, never a mutable self-method
        chain. Original request authentication precedes opening the read DB.
        Registry closure remains enforced by the actual planner import.
        """
        if (self.role_name != "planner"
                or self.process_mode != "policy-authority-planner"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation planning receiver process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        planner_private_key = self.signing_key
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise AuthorityServiceError("revocation planning receiver signer is unavailable")
        from serverware import authority_revocation_configuration
        from serverware import authority_revocation_planning_receiver

        authority_revocation_planning_receiver._validate_originals(
            control_bytes=control_bytes, request_bytes=request_bytes, evidence_bytes=evidence_bytes,
            context_bytes=context_bytes, root_inventory_bytes=root_inventory_bytes)
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation planning receiver configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("planner"))
        read_dsn = authority_revocation_configuration.production._callback(
            work, lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"))
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return authority_revocation_planning_receiver._produce_on_configuration(
            payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities, generation=generation,
            control_bytes=control_bytes, request_bytes=request_bytes, evidence_bytes=evidence_bytes,
            context_bytes=context_bytes, root_inventory_bytes=root_inventory_bytes,
            read_dsn=read_dsn, planner_private_key=planner_private_key, work=work)

    def _produce_revocation_writer_intent(self, *, envelope_bytes, evaluation_context_bytes,
            expected_request, context, planned_at_epoch_ns, envelope_id,
            planner_transaction_id, work):
        """Verify against this process's independent read before intent signing.

        The admitted request/reservation context and fixed IDs remain upstream
        prerequisites, not caller authority created by this private adapter.
        No caller root inventory or successful handoff is accepted. Hold the
        measured configuration and signer once; own invocation graphs before
        any launch, descriptor or database callback. Acquire actual verifier
        roots and close their read scopes before the configured replay/sign.
        This is not a public purpose or an automatic retry/regeneration path.
        """
        if (self.role_name != "verifier"
                or self.process_mode != "policy-authority-verifier"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation intent verifier process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        verifier_private_key = self.signing_key
        if not isinstance(verifier_private_key, Ed25519PrivateKey):
            raise AuthorityServiceError("revocation intent verifier signing key is unavailable")
        from serverware import authority_revocation_configuration
        from serverware import authority_revocation_observed
        from serverware import authority_revocation_root_reader
        from serverware import authority_revocation_writer_producers

        owned_request, owned_context = authority_revocation_writer_producers._capture_intent_call_inputs(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            expected_request=expected_request, context=context, planned_at_epoch_ns=planned_at_epoch_ns,
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id, work=work)
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation intent verifier configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        if (type(owned_payload.get("roles")) is not dict
                or type(owned_payload["roles"].get("verifier")) is not dict):
            raise AuthorityServiceError("revocation intent verifier role is not closed data")
        role = owned_payload["roles"]["verifier"]
        try:
            timeout = role["databaseConnectTimeoutSeconds"]
            if type(timeout) not in (int, float) or not 2 <= timeout <= 300:
                raise AuthorityServiceError("revocation intent verifier read timeout is not bounded")
            pins = (int(timeout), role["databaseRole"], role["tlsClientDn"],
                role["tlsClientSerial"], role["tlsIssuerDn"], owned_payload["queryManifestDigest"])
        except KeyError as exc:
            raise AuthorityServiceError("revocation intent verifier read configuration is incomplete") from exc
        authority_revocation_root_reader._validate_pins(pins)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("verifier"))
        dsn = authority_revocation_configuration.production._callback(
            work, lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"))
        reader = authority_revocation_root_reader.RevocationRootReader(
            dsn=dsn, connect_timeout_seconds=pins[0], database_role=pins[1],
            tls_client_dn=pins[2], tls_client_serial=pins[3], tls_issuer_dn=pins[4],
            query_manifest_digest=pins[5])
        observed_inventory = reader.read(work=work)
        inventory = authority_revocation_observed._capture_root_inventory(observed_inventory, work=work)
        # The genuine reader has exited. Own its observations before the last
        # callback; the worker then reowns inputs, inventory and launch fields.
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return authority_revocation_writer_producers._produce_intent_on_configuration(
            payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities, generation=generation,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            expected_request=owned_request, context=owned_context, root_inventory=inventory,
            planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id,
            verifier_private_key=verifier_private_key, work=work)

    def _produce_revocation_writer_relay(self, *, intent_bytes, envelope_bytes,
            evaluation_context_bytes, historical_expectations_bytes, work):
        """Sign one relay separately from sending or recovering original bytes.

        Root-signed configuration, descriptor-loaded signer and actual active
        planner launch remain prerequisites. Hold those inputs before callbacks;
        the configured worker binds its keys and authenticates the original
        intent before signing. No ACK, socket or persistence result is accepted.
        """
        if (self.role_name != "planner"
                or self.process_mode != "policy-authority-planner"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation relay planner process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        planner_private_key = self.signing_key
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise AuthorityServiceError("revocation relay planner signing key is unavailable")
        from serverware import authority_revocation_configuration
        from serverware import authority_revocation_writer_commitment
        from serverware import authority_revocation_writer_producers

        authority_revocation_writer_commitment._raw(intent_bytes, authority_contract.MAX_REQUEST_BYTES)
        authority_revocation_writer_commitment._body_bounds(
            envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation relay planner configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("planner"))
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return authority_revocation_writer_producers._produce_relay_on_configuration(
            payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities, generation=generation,
            intent_bytes=intent_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_private_key=planner_private_key, work=work)

    def _request_revocation_writer_relay(self, *, intent_bytes, envelope_bytes,
            evaluation_context_bytes, historical_expectations_bytes, work):
        """Obtain and authenticate original relay bytes without custody I/O.

        This preparatory call never invokes the forwarding method. Its caller
        must retain the returned originals before a separate potentially
        committing request; a stable relay ID alone is not retry authority.
        """
        from serverware import authority_revocation_planner_custody_client as client

        _revocation_custody_originals((intent_bytes, envelope_bytes,
            evaluation_context_bytes, historical_expectations_bytes), relay=True)
        payload, digest, generation, runtime_role_identities = _revocation_custody_context(self, role_name="verifier", work=work)
        return client._request_relay_on_configuration(payload=payload, configuration_digest=digest,
            runtime_role_identities=runtime_role_identities,
            generation=generation, intent_bytes=intent_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _forward_revocation_writer_originals(self, *, intent_bytes, relay_bytes,
            envelope_bytes, evaluation_context_bytes, historical_expectations_bytes, work):
        """Forward retained originals and authenticate the writer's custody ACK.

        No signer is acquired, no relay is generated and no automatic retry is
        made. A failure after dispatch can follow a durable writer commit;
        it never establishes rollback or authorizes replacing these originals.
        """
        from serverware import authority_revocation_planner_custody_client as client

        _revocation_custody_originals((intent_bytes, relay_bytes, envelope_bytes,
            evaluation_context_bytes, historical_expectations_bytes), relay=False)
        payload, digest, generation, runtime_role_identities = _revocation_custody_context(self, role_name="verifier", work=work)
        return client._forward_on_configuration(payload=payload, configuration_digest=digest,
            runtime_role_identities=runtime_role_identities,
            generation=generation, intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _prepare_revocation_writer_relay(self, *, intent_bytes, envelope_bytes,
            evaluation_context_bytes, historical_expectations_bytes, work):
        """Authenticate verifier originals and sign a relay; never forward it."""
        if (type(self) is not AuthorityProcess or self.role_name != "planner"
                or self.process_mode != "policy-authority-planner"):
            raise AuthorityServiceError("revocation custody relay preparation requires the planner role")
        from serverware import authority_revocation_planner_custody_receiver as receiver

        _revocation_custody_originals((intent_bytes, envelope_bytes,
            evaluation_context_bytes, historical_expectations_bytes), relay=True)
        planner_private_key = self.signing_key
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise AuthorityServiceError("revocation custody planner signer is unavailable")
        payload, digest, generation, runtime_role_identities = _revocation_custody_context(self, role_name="planner", work=work)
        return receiver._produce_relay_on_configuration(payload=payload, configuration_digest=digest,
            runtime_role_identities=runtime_role_identities,
            generation=generation, raw4=(intent_bytes, envelope_bytes,
                evaluation_context_bytes, historical_expectations_bytes),
            planner_private_key=planner_private_key, work=work)

    def _forward_revocation_writer_custody(self, *, intent_bytes, relay_bytes,
            envelope_bytes, evaluation_context_bytes, historical_expectations_bytes, work):
        """Authenticate exact held originals and deliver them to the writer.

        Preparation is a separate route. This fixed path has no signer and
        performs genuine configured request replay and ACK verification through
        the existing writer client; it never regenerates an intent or relay.
        """
        from serverware import authority_revocation_planner_custody_receiver as receiver

        _revocation_custody_originals((intent_bytes, relay_bytes, envelope_bytes,
            evaluation_context_bytes, historical_expectations_bytes), relay=False)
        payload, digest, generation, runtime_role_identities = _revocation_custody_context(self, role_name="planner", work=work)
        return receiver._forward_on_configuration(payload=payload, configuration_digest=digest,
            runtime_role_identities=runtime_role_identities,
            generation=generation, raw5=(intent_bytes, relay_bytes, envelope_bytes,
                evaluation_context_bytes, historical_expectations_bytes), work=work)

    def _read_revocation_writer_originals(self, *, execution_envelope_id, planner_transaction_id, work):
        """Retrieve unverified raw6 through the planner, never retry custody.

        The independently held locator must survive the uncertain exchange.
        Returned bytes still need independently trusted historical keys and
        genuine replay; they grant no execution or replacement authority.
        """
        from serverware import authority_revocation_custody_read_client as client

        custody_read_transport._validate_ids(execution_envelope_id, planner_transaction_id)
        payload, digest, generation, runtime_role_identities = _revocation_custody_context(self, role_name="verifier", work=work)
        return client._read_from_planner_on_configuration(payload=payload, configuration_digest=digest,
            generation=generation, execution_envelope_id=execution_envelope_id,
            planner_transaction_id=planner_transaction_id, work=work)

    def _relay_revocation_writer_read(self, *, execution_envelope_id, planner_transaction_id, work):
        """Relay a read-only locator; return unverified originals unchanged."""
        from serverware import authority_revocation_custody_read_client as client

        custody_read_transport._validate_ids(execution_envelope_id, planner_transaction_id)
        payload, digest, generation, runtime_role_identities = _revocation_custody_context(self, role_name="planner", work=work)
        return client._read_from_writer_on_configuration(payload=payload, configuration_digest=digest,
            generation=generation, execution_envelope_id=execution_envelope_id,
            planner_transaction_id=planner_transaction_id, work=work)

    def _read_retained_revocation_writer_originals(self, *, execution_envelope_id, planner_transaction_id, work):
        """Read existing custody under this writer's current admitted identity.

        This is not a write transaction or historical-key admission. Capture
        measured settings before callbacks, acquire only the held writer DSN,
        then snapshot generation last. The configured reader returns only after
        all actual database scopes close normally. Missing rows stay unresolved.
        """
        if (type(self) is not AuthorityProcess or self.role_name != "planner-writer"
                or self.process_mode != "policy-authority-planner-writer"):
            raise AuthorityServiceError("revocation custody read requires the writer role")
        measured = self.configuration
        if type(measured) is not MeasuredConfiguration:
            raise AuthorityServiceError("revocation custody read configuration is unavailable")
        payload, digest = measured.payload, measured.digest
        from serverware import authority_revocation_configuration as configuration
        from serverware import authority_revocation_custody_read as reader

        custody_read_transport._validate_ids(execution_envelope_id, planner_transaction_id)
        ledger = configuration.capability.capture._SharedLedger(work)
        configuration.capability.shape._digest(digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation custody read configuration is not closed data")
        owned = configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        configuration.production._callback(work, lambda: authority_launch_guard.require_active("planner-writer"))
        persistence_dsn = configuration.production._callback(work, lambda: _read_dsn_descriptor(
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"))
        generation = configuration.production._callback(work, lambda: dict(authority_launch_guard.generation()))
        return reader._read_originals_on_configuration(payload=owned, configuration_digest=digest,
            generation=generation, persistence_dsn=persistence_dsn,
            execution_envelope_id=execution_envelope_id, planner_transaction_id=planner_transaction_id, work=work)

    def _send_revocation_writer_commitments(self, *, intent_bytes,
            relay_bytes, envelope_bytes, evaluation_context_bytes,
            historical_expectations_bytes, work):
        """Private planner client, not a configured producer or public purpose.

        Main's signed configuration load and real active planner launch remain
        prerequisites. Own all configuration before callbacks; the generation
        snapshot is last before the client captures its bindings. No incoming
        key, expected ACK fields, DSN, callback, clock or allowance is accepted.
        The client derives expectations by genuine replay before transport and
        verifies the exact reply using the independently measured writer key.
        """
        if (self.role_name != "planner"
                or self.process_mode != "policy-authority-planner"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation writer client process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        from serverware import authority_revocation_configuration
        from serverware import authority_revocation_writer_client
        from serverware import authority_revocation_writer_commitment

        authority_revocation_writer_commitment._raw(intent_bytes, authority_contract.MAX_REQUEST_BYTES)
        authority_revocation_writer_commitment._raw(relay_bytes, authority_contract.MAX_REQUEST_BYTES)
        authority_revocation_writer_commitment._body_bounds(
            envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        writer_transport._validate_lengths((len(intent_bytes), len(relay_bytes), len(envelope_bytes),
            len(evaluation_context_bytes), len(historical_expectations_bytes)))
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation writer client configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("planner"))
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return authority_revocation_writer_client._send_on_configuration(
            payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities,
            generation=generation, intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)

    def _revocation_planner_persistence(self, *, work):
        """Construct the private writer owner from admitted measured settings.

        Root-signed configuration load, active writer launch and the exclusive
        descriptor remain real upstream requirements. Capture the full payload
        before callbacks; the mapper constructs genuine verification keys and
        independent database pins, not a successful-verification token. No
        socket is opened and no plan is accepted by constructing this owner.
        Action adapters must own original bytes and all independent invocation
        expectations before callbacks, and continue from that same captured
        configuration rather than calling this factory to recapture self.
        """
        if (self.role_name != "planner-writer"
                or self.process_mode != "policy-authority-planner-writer"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation writer process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        from serverware import authority_revocation_configuration

        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation writer configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        persistence, _held_launch = _revocation_writer_from_owned_configuration(owned_payload=owned_payload,
            owned_runtime_identities=owned_runtime_identities,
            configuration_digest=configuration_digest, work=work)
        return persistence

    def _persist_and_reserve_revocation_plan(self, *, envelope_bytes, evaluation_context_bytes,
            planned_at_epoch_ns, envelope_id, planner_transaction_id, work, **expectations):
        """Private measured-writer action; not a public dispatch or RPC purpose.

        Own original inputs and the full measured payload before any external
        callback. Historical request, clock and root provenance remain the
        caller's independent prerequisites, not claims derived from a retained
        context. Policy must match this same captured configuration; no caller
        value is replaced. The genuine atomic owner repeats both replays and
        returns only after its common/outer scopes and connection exit. A late
        post-commit rejection cannot promise that durable writes rolled back.
        """
        if (self.role_name != "planner-writer"
                or self.process_mode != "policy-authority-planner-writer"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation writer process is not configured")
        configuration = self.configuration
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        from serverware import authority_revocation_configuration
        from serverware import authority_revocation_writer_action

        arguments, owned = authority_revocation_writer_action._capture_action_inputs(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id, work=work, **expectations)
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation writer configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_writer_action._assert_policy_on_work(owned_payload, owned, work)
        persistence, _held_launch = _revocation_writer_from_owned_configuration(owned_payload=owned_payload,
            owned_runtime_identities=owned_runtime_identities,
            configuration_digest=configuration_digest, work=work)
        return persistence.persist_and_reserve_execution(**arguments, work=work, **owned)

    def _persist_and_reserve_revocation_commitments(self, *, intent_bytes,
            relay_bytes, envelope_bytes, evaluation_context_bytes,
            historical_expectations_bytes, work):
        """Private detached-control composition, not a legacy public purpose.

        Root-signed configuration and active writer launch remain real upstream
        requirements. Hold the original byte references and own the complete
        measured payload before callbacks. The mapper binds its held generation
        fields to the actual generation-last launch snapshot; no second launch
        read or incoming generation claim supplies those expectations.

        The worker authenticates both original controls with this same owner's
        keys, checks historical policy against captured configuration and uses
        the same fixed owner tuple for genuine atomic custody. Neither returned
        claims nor constructed owners are admission tokens. The held dedicated
        response key signs only within exact request/ACK custody's atomic scope;
        original ACK bytes return only after normal owner exits. This does not
        establish execution or current-root authority. The separate fixed
        writer transfer handler may return these bytes, but the configured
        planner producers and authenticated acknowledgment consumption remain
        separate requirements; legacy public purposes are unchanged.
        """
        if (self.role_name != "planner-writer"
                or self.process_mode != "policy-authority-planner-writer"
                or type(self.configuration) is not MeasuredConfiguration):
            raise AuthorityServiceError("revocation writer process is not configured")
        configuration = self.configuration
        writer_private_key = self.writer_response_signing_key
        launch_private_key = self.launch_identity_key
        if (not isinstance(writer_private_key, Ed25519PrivateKey)
                or not isinstance(launch_private_key, Ed25519PrivateKey)):
            raise AuthorityServiceError("revocation writer response or launch key is not configured")
        payload, configuration_digest = configuration.payload, configuration.digest
        runtime_role_identities = configuration.runtime_role_identities
        from serverware import authority_revocation_configuration
        from serverware import authority_revocation_writer_composition

        authority_revocation_writer_composition._validate_originals(
            intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes)
        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation writer configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        if (type(owned_payload.get("roles")) is not dict
                or type(owned_payload["roles"].get("planner-writer")) is not dict):
            raise AuthorityServiceError("revocation writer configuration has no exact writer role")
        maximum_age_ns = owned_payload["roles"]["planner-writer"]["maximumInternalAgeNs"]
        writer_response_spki_digest = owned_payload["roles"]["planner-writer"]["responseSigningSpkiDigest"]
        other_response_spki_digests = tuple(owned_payload["roles"][name]["responseSigningSpkiDigest"]
            for name in ("verifier", "planner", "issuer", "executor"))
        authority_revocation_configuration.capability.shape._integer(maximum_age_ns, minimum=1)
        authority_revocation_configuration.capability.shape._digest(writer_response_spki_digest)
        for pin in other_response_spki_digests:
            authority_revocation_configuration.capability.shape._digest(pin)
        if writer_response_spki_digest in other_response_spki_digests:
            raise AuthorityServiceError("revocation writer response key reuses another role pin")
        launch_public_key = authority_revocation_configuration.production._callback(
            work, lambda: launch_private_key.public_key())
        if not isinstance(launch_public_key, Ed25519PublicKey):
            raise AuthorityServiceError("revocation writer launch key did not derive Ed25519")
        persistence, held_launch = _revocation_writer_from_owned_configuration(owned_payload=owned_payload,
            owned_runtime_identities=owned_runtime_identities,
            configuration_digest=configuration_digest, work=work)
        generation_sequence, generation_digest = held_launch
        configuration_snapshot = persistence._snapshot_configuration()
        return authority_revocation_writer_composition._persist_commitments_on_configuration(
            configuration_snapshot, intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            owned_payload=owned_payload, configuration_digest=configuration_digest,
            generation_sequence=generation_sequence, generation_digest=generation_digest,
            maximum_age_ns=maximum_age_ns, writer_private_key=writer_private_key,
            launch_public_key=launch_public_key, work=work)

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
        runtime_role_identities = configuration.runtime_role_identities
        from serverware import authority_revocation_configuration

        ledger = authority_revocation_configuration.capability.capture._SharedLedger(work)
        authority_revocation_configuration.capability.shape._digest(configuration_digest)
        if type(payload) is not dict:
            raise AuthorityServiceError("revocation issuer configuration is not closed data")
        owned_payload = authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)
        owned_runtime_identities = authority_revocation_configuration.capability.capture._JSONCapture(
            ledger, maximum_bytes=8192).visit(runtime_role_identities)
        authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("issuer"))
        generation = authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))
        return authority_revocation_configuration._issuer_from_configuration_on_work(
            payload=owned_payload, configuration_digest=configuration_digest,
            runtime_role_identities=owned_runtime_identities, generation=generation, work=work)

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
                not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
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
            _delivery_request_original=_canonical(dict(request)) if operation in canary_delivery.OPERATIONS else None,
            _native_activation_request_original=_canonical(dict(request)) if operation == native_activation.PREFIX + "consume" else None,
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
            } | ({"deliveryOriginals"} if operation in canary_delivery.OPERATIONS else set())
              | ({"activationOriginals"} if operation == native_activation.PREFIX + "consume" else set())
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
        response_schema = RUNTIME_RESPONSE_SCHEMA
        if operation == native_activation.PREFIX + "consume":
            original = self.configuration.original_bytes
            if type(original) is not bytes or _sha256(original) != self.configuration.file_digest or len(original) > MAX_CONFIG_BYTES:
                raise AuthorityServiceError("native activation requires the actual admitted configuration original")
            response_schema = native_activation.RESPONSE_SCHEMA
            unsigned["schema"] = response_schema
            unsigned["authorityConfigurationOriginal"] = _b64url_encode(original)
            unsigned["activationOriginals"] = execution["activationOriginals"]
        if operation in canary_delivery.OPERATIONS:
            original = self.configuration.original_bytes
            if type(original) is not bytes or _sha256(original) != self.configuration.file_digest or len(original) > MAX_CONFIG_BYTES:
                raise AuthorityServiceError("delivery requires its actual admitted configuration original")
            response_schema = canary_delivery.RESPONSE_SCHEMA
            unsigned["schema"] = response_schema
            unsigned["authorityConfigurationOriginal"] = _b64url_encode(original)
            unsigned["deliveryOriginals"] = execution["deliveryOriginals"]
        if operation in oauth_measured_refresh.OPERATIONS | oauth_measured_exchange.OPERATIONS | oauth_measured_setup.OPERATIONS | oauth_reconnect.OPERATIONS | oauth_measured_cleanup.OPERATIONS | oauth_pending_retirement.OPERATIONS | oauth_capture_retirement.OPERATIONS | oauth_succession.OPERATIONS:
            original = self.configuration.original_bytes
            if (type(original) is not bytes or not 0 < len(original) <= 1024 * 1024
                    or _sha256(original) != self.configuration.file_digest):
                raise AuthorityServiceError("measured refresh requires the actual admitted configuration original")
            response_schema = (RETIRED_SCOPE_SUCCESSION_RESPONSE_SCHEMA if operation in oauth_succession.OPERATIONS
                else CAPTURE_RETIREMENT_RESPONSE_SCHEMA if operation in oauth_capture_retirement.OPERATIONS
                else PENDING_RETIREMENT_RESPONSE_SCHEMA if operation in oauth_pending_retirement.OPERATIONS
                else MEASURED_CLEANUP_RESPONSE_SCHEMA if operation in oauth_measured_cleanup.OPERATIONS
                else MEASURED_EXCHANGE_RESPONSE_SCHEMA if operation in oauth_measured_exchange.OPERATIONS
                else MEASURED_SETUP_RESPONSE_SCHEMA if operation in oauth_measured_setup.OPERATIONS
                else MEASURED_RECONNECT_RESPONSE_SCHEMA if operation in oauth_reconnect.OPERATIONS
                else MEASURED_REFRESH_RESPONSE_SCHEMA)
            unsigned["schema"] = response_schema
            unsigned["authorityConfigurationOriginal"] = _b64url_encode(original)
        if self.signing_key is None:
            raise AuthorityServiceError("verifier signer is unavailable")
        response = {
            **unsigned,
            "signature": _b64url_encode(
                self.signing_key.sign(
                    _domain_digest(
                        response_schema, _canonical(unsigned)
                    ).encode("ascii")
                )
            ),
        }
        if operation in canary_delivery.OPERATIONS:
            canary_delivery_completion.check_emitted_bounds(operation, _canonical(dict(request)), _canonical(response))
        if operation == native_activation.PREFIX + "consume":
            native_activation_completion.emitted(_canonical(dict(request)), _canonical(response))
        return response

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
                not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
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
                not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
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
        from serverware import authority_publication_approval as publication_approval
        if operation in (setup_native_enrollment.ASSERTION_OPERATIONS | publication_approval.assertion_operations() | oauth_activation.ASSERTION_OPERATIONS | oauth_exchange.ASSERTION_OPERATIONS | oauth_measured_exchange.ASSERTION_OPERATIONS | oauth_measured_setup.ASSERTION_OPERATIONS | oauth_setup.ASSERTION_OPERATIONS | oauth_reconnect.ASSERTION_OPERATIONS | policy_candidate.ASSERTION_OPERATIONS | setup_policy.ASSERTION_OPERATIONS | oauth_succession.ASSERTION_OPERATIONS):
            # This is a new, independently admitted purpose. Legacy argument
            # adapters and physical-evidence receipt families are not relabeled.
            selected_profile = (setup_native_enrollment if operation in setup_native_enrollment.OPERATIONS else
                setup_policy if operation in setup_policy.OPERATIONS else
                policy_candidate if operation in policy_candidate.OPERATIONS else
                oauth_succession if operation in oauth_succession.OPERATIONS else
                oauth_reconnect if operation in oauth_reconnect.OPERATIONS else
                oauth_measured_setup if operation in oauth_measured_setup.OPERATIONS else
                oauth_setup if operation in oauth_setup.OPERATIONS else
                oauth_measured_exchange if operation in oauth_measured_exchange.OPERATIONS else
                oauth_exchange if operation in oauth_exchange.OPERATIONS else
                oauth_activation if operation in oauth_activation.OPERATIONS else publication_approval.operation_profile(operation))
            values = selected_profile.arguments(operation,
                {name: value for name, value in arguments.items() if name != "authn_evidence"})
            if operation in oauth_succession.OPERATIONS:
                oauth_succession_policy.verify_original(operation, values,
                    configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                    now_epoch_ns=time.time_ns())
            if operation in oauth_reconnect.OPERATIONS:
                oauth_reconnect_policy.verify_original(operation, values,
                    configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                    now_epoch_ns=time.time_ns())
            if operation in oauth_measured_setup.OPERATIONS | oauth_setup.OPERATIONS:
                oauth_measured_setup_policy.verify_original(operation, values,
                    configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                    now_epoch_ns=time.time_ns())
            if operation in oauth_activation.OPERATIONS:
                oauth_activation_policy.verify_original(operation, values,
                    configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                    now_epoch_ns=time.time_ns())
            if operation in oauth_exchange.OPERATIONS:
                oauth_exchange_policy.verify_original(operation, values,
                    configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                    now_epoch_ns=time.time_ns())
            if operation in oauth_measured_exchange.OPERATIONS:
                oauth_measured_exchange_policy.verify_original(operation, values,
                    configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                    now_epoch_ns=time.time_ns())
            policy = values["credential_policy"]
            if operation in setup_native_enrollment.OPERATIONS:
                setup_native_enrollment_policy.verify_original(operation, values,
                    configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if operation in setup_policy.OPERATIONS:
                setup_policy_admission.verify_original(operation, values,
                    configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if operation in policy_candidate.OPERATIONS:
                policy_candidate_policy.verify_original(operation, values,
                    configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            classes = {credential.get("authenticatorClass")}
            if "yubikey" in classes:
                classes.add("hardware")
            if (credential.get("userId") != values["actor_id"]
                    or credential.get("attestationTrusted") is not True
                    or not classes.intersection(set(policy["allowedAuthenticatorClasses"]))
                    or not classes.intersection({"hardware", "yubikey"})
                    or challenge.get("rpId") != policy["rpId"]
                    or challenge.get("origin") not in policy["origins"]
                    or time.time_ns() - challenge["issuedAtEpochNs"] > policy["maxAssertionAgeSeconds"] * 1_000_000_000):
                raise AuthorityServiceError("purpose assertion lacks current hardware policy")
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
        _public_revocation=None,
        _delivery_request_original=None,
        _native_activation_request_original=None,
    ) -> dict[str, Any]:
        if operation == native_activation.PREFIX + "consume":
            if type(_native_activation_request_original) is not bytes:
                raise AuthorityServiceError("native PREPARE requires its actual retained runtime request")
            opening = native_activation.canonical_original(_native_activation_request_original.decode("ascii"), native_activation.MAX_NATIVE)
            if (opening.get("operation") != operation or opening.get("input") != runtime_input
                    or opening.get("configurationDigest") != self.configuration.digest
                    or opening.get("deadlineMonotonicNs") != deadline_monotonic_ns):
                raise AuthorityServiceError("native PREPARE runtime opening changed")
        elif _native_activation_request_original is not None:
            raise AuthorityServiceError("native preparation owner cannot select another operation")
        from serverware import authority_public_revocation_approval as public_approval
        from serverware import authority_public_revocation_approval_owner as public_approval_owner
        if operation in public_approval.OPERATIONS:
            if type(_public_revocation) is not public_approval_owner._ApprovalExecution:
                raise AuthorityServiceError("public revocation approval requires its actual original-held caller")
            _public_revocation.consume(self, operation, runtime_input, deadline_monotonic_ns)
        elif _public_revocation is not None:
            raise AuthorityServiceError("public approval owner cannot authorize another operation")
        if operation in canary_delivery.OPERATIONS:
            if type(_delivery_request_original) is not bytes:
                raise AuthorityServiceError("delivery execution requires its actual runtime opening")
            opening = canary_delivery.document(_delivery_request_original, canary_delivery.MAX_ARGUMENT)
            if (opening.get("operation") != operation or opening.get("input") != runtime_input
                    or opening.get("configurationDigest") != self.configuration.digest
                    or opening.get("deadlineMonotonicNs") != deadline_monotonic_ns):
                raise AuthorityServiceError("delivery runtime opening changed")
        elif _delivery_request_original is not None:
            raise AuthorityServiceError("delivery original owner cannot select another operation")
        if (
            operation
                not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
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
        from serverware import authority_publication_approval as publication_approval
        from serverware import authority_policy_file_approval
        if operation in canary_delivery.OPERATIONS:
            canary_delivery_policy.verify_original(operation, arguments, configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if canary_delivery.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("delivery original commitment differs")
        if operation in policy_canary.OPERATIONS:
            policy_canary_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if policy_canary.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("native canary original commitment differs")
        if operation in setup_native_enrollment.OPERATIONS:
            original_values = {name: value for name, value in arguments.items() if name != "authn_evidence"}
            setup_native_enrollment_policy.verify_original(operation, original_values,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if setup_native_enrollment.request_digest(operation, original_values) != request_digest:
                raise AuthorityServiceError("native Setup issuer original commitment differs")
        if operation in setup_policy.OPERATIONS:
            original_values = {name: value for name, value in arguments.items() if name != "authn_evidence"}
            setup_policy_admission.verify_original(operation, original_values,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if setup_policy.request_digest(operation, original_values) != request_digest:
                raise AuthorityServiceError("Setup candidate original commitment differs")
        if operation in native_activation.OPERATIONS:
            original_values = {name: value for name, value in arguments.items() if name != "authn_evidence"}
            native_activation.verify_original(operation, original_values, configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if native_activation.request_digest(operation, original_values) != request_digest:
                raise AuthorityServiceError("native activation original commitment differs")
        if operation in policy_candidate.OPERATIONS:
            original_values = {name: value for name, value in arguments.items() if name != "authn_evidence"}
            policy_candidate_policy.verify_original(operation, original_values,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if policy_candidate.request_digest(operation, original_values) != request_digest:
                raise AuthorityServiceError("candidate intake original commitment differs")
        if operation in publication_approval.OPERATIONS | authority_policy_file_approval.OPERATIONS:
            original_digest = publication_approval.request_digest(operation,
                {name: value for name, value in arguments.items() if name != "authn_evidence"})
            if original_digest != request_digest:
                raise AuthorityServiceError("publication original commitment differs from the actual authority recipe")
        if operation in oauth_activation.OPERATIONS:
            original_digest = oauth_activation.request_digest(operation,
                {name: value for name, value in arguments.items() if name != "authn_evidence"})
            if original_digest != request_digest:
                raise AuthorityServiceError("OAuth activation original commitment differs from actual authority recipe")
        if operation in oauth_exchange.OPERATIONS:
            original_values = {name: value for name, value in arguments.items() if name != "authn_evidence"}
            oauth_exchange_policy.verify_original(operation, original_values,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                now_epoch_ns=time.time_ns())
            if oauth_exchange.request_digest(operation, original_values) != request_digest:
                raise AuthorityServiceError("OAuth exchange original commitment differs from actual authority recipe")
        if operation in oauth_refresh.OPERATIONS:
            oauth_refresh_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                now_epoch_ns=time.time_ns())
            if oauth_refresh.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("OAuth refresh original commitment differs from actual authority recipe")
        if operation in oauth_measured_refresh.OPERATIONS:
            oauth_measured_refresh_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                now_epoch_ns=time.time_ns())
            if oauth_measured_refresh.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("measured OAuth refresh request commitment differs")
        if operation in oauth_measured_cleanup.OPERATIONS:
            oauth_measured_cleanup_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if oauth_measured_cleanup.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("measured OAuth cleanup request commitment differs")
        if operation in oauth_pending_retirement.OPERATIONS:
            oauth_pending_retirement_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if oauth_pending_retirement.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("pending retirement request commitment differs")
        if operation in oauth_capture_retirement.OPERATIONS:
            oauth_capture_retirement_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if oauth_capture_retirement.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("capture retirement request commitment differs")
        if operation in oauth_measured_exchange.OPERATIONS:
            oauth_measured_exchange_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                now_epoch_ns=time.time_ns())
            if oauth_measured_exchange.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("measured initial OAuth issuance request commitment differs")
        if operation in oauth_measured_setup.OPERATIONS | oauth_setup.OPERATIONS:
            original_values = {name: value for name, value in arguments.items() if name != "authn_evidence"}
            oauth_measured_setup_policy.verify_original(operation, original_values,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                now_epoch_ns=time.time_ns())
            selected_profile = oauth_measured_setup if operation in oauth_measured_setup.OPERATIONS else oauth_setup
            if selected_profile.request_digest(operation, original_values) != request_digest:
                raise AuthorityServiceError("Setup purpose original commitment differs")
        if operation in oauth_reconnect.OPERATIONS:
            original_values = {name: value for name, value in arguments.items() if name != "authn_evidence"}
            oauth_reconnect_policy.verify_original(operation, original_values,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if oauth_reconnect.request_digest(operation, original_values) != request_digest:
                raise AuthorityServiceError("reconnect original commitment differs")
        if operation in oauth_succession.OPERATIONS:
            original_values = {name: value for name, value in arguments.items() if name != "authn_evidence"}
            oauth_succession_policy.verify_original(operation, original_values,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if oauth_succession.request_digest(operation, original_values) != request_digest:
                raise AuthorityServiceError("retired-scope succession original commitment differs")
        if operation in credential_currentness.OPERATIONS:
            credential_currentness_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                now_epoch_ns=time.time_ns())
            if credential_currentness.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("credential-currentness original commitment differs from actual authority recipe")
        if operation in oauth_revocation.OPERATIONS:
            oauth_revocation_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key,
                now_epoch_ns=time.time_ns())
            if oauth_revocation.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("OAuth cleanup original commitment differs from actual authority recipe")
        if operation in oauth_refresh_cleanup.OPERATIONS:
            oauth_refresh_cleanup_policy.verify_original(operation, arguments,
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
            if oauth_refresh_cleanup.request_digest(operation, arguments) != request_digest:
                raise AuthorityServiceError("OAuth family retirement commitment differs from actual authority recipe")
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
        from serverware import control_plane_rbac_currentness as rbac_currentness
        if operation in canary_delivery.OPERATIONS:
            canary_delivery_completion.preflight_bounds(operation, request_original=_delivery_request_original,
                signed_plan=signed_plan, configuration_original=self.configuration.original_bytes,
                consumption_original=_canonical(self.attestation_consumption_receipt))
        if operation == native_activation.PREFIX + "consume":
            native_activation_completion.preflight(_native_activation_request_original, signed_plan,
                self.configuration.original_bytes, _canonical(self.attestation_consumption_receipt))
        rbac_attempt = rbac_currentness.reserve_plan(self, plan_payload, request_digest,
            capability_id, deadline_monotonic_ns, deadline_epoch_ns)
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
                self.configuration.issuer_session_identity_digest(),
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
        # Only the genuine validated executor return can terminalize this
        # separate head. A lost/late result leaves the original pending; no
        # absence proof, generic replay witness, or fresh timer clears it.
        rbac_currentness.complete_plan(self, rbac_attempt, executed)
        committed_late = time.monotonic_ns() >= deadline_monotonic_ns
        witness_request_original, witness_response_original, terminal = self._witness_transition_with_originals(
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
        result = {
            "result": executed["result"],
            "resultDigest": executed["resultDigest"],
            "commitReceiptDigest": executed["receiptDigest"],
            "witnessCommitDigest": witness_commit_digest,
            "fence": reservation["fence"],
        }
        if operation in canary_delivery.OPERATIONS:
            result["deliveryOriginals"] = {"signedMeasuredPlanOriginal": _canonical(signed_plan).decode("ascii"),
                "executorCompletionOriginal": _canonical(executed).decode("ascii"),
                "witnessRequestOriginal": witness_request_original.decode("ascii"),
                "witnessResponseOriginal": witness_response_original.decode("ascii")}
        if operation == native_activation.PREFIX + "consume":
            result["activationOriginals"] = {"signedMeasuredPlanOriginal": _canonical(signed_plan).decode("ascii"),
                "executorCompletionOriginal": _canonical(executed).decode("ascii"),
                "witnessRequestOriginal": witness_request_original.decode("ascii"),
                "witnessResponseOriginal": witness_response_original.decode("ascii"),
                "nativeEffectHoldOriginal": native_activation_completion.planned_hold(signed_plan)}
        return result

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
        if planner_request["operation"] in oauth_activation.OPERATIONS:
            # This process independently verifies the exact enrollment before
            # SQL or persisted-plan lookup; a verifier receipt is not its root.
            oauth_activation_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_exchange.OPERATIONS:
            oauth_exchange_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in setup_native_enrollment.OPERATIONS:
            setup_native_enrollment_policy.verify_original(planner_request["operation"], planner_request["typedRequest"]["arguments"],
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in setup_policy.OPERATIONS:
            setup_policy_admission.verify_original(planner_request["operation"], planner_request["typedRequest"]["arguments"],
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in native_activation.OPERATIONS:
            native_activation.verify_original(planner_request["operation"], planner_request["typedRequest"]["arguments"],
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in policy_candidate.OPERATIONS:
            policy_candidate_policy.verify_original(planner_request["operation"], planner_request["typedRequest"]["arguments"],
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in policy_canary.OPERATIONS:
            policy_canary_policy.verify_original(planner_request["operation"], planner_request["typedRequest"]["arguments"],
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in canary_delivery.OPERATIONS:
            canary_delivery_policy.verify_original(planner_request["operation"], planner_request["typedRequest"]["arguments"],
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_refresh.OPERATIONS:
            oauth_refresh_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_measured_refresh.OPERATIONS:
            oauth_measured_refresh_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_measured_cleanup.OPERATIONS:
            oauth_measured_cleanup_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_pending_retirement.OPERATIONS:
            oauth_pending_retirement_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_capture_retirement.OPERATIONS:
            oauth_capture_retirement_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_measured_exchange.OPERATIONS:
            oauth_measured_exchange_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_measured_setup.OPERATIONS | oauth_setup.OPERATIONS:
            oauth_measured_setup_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_reconnect.OPERATIONS:
            oauth_reconnect_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_succession.OPERATIONS:
            oauth_succession_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in credential_currentness.OPERATIONS:
            credential_currentness_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_revocation.OPERATIONS:
            oauth_revocation_policy.verify_original(planner_request["operation"],
                planner_request["typedRequest"]["arguments"], configuration_payload=self.configuration.payload,
                root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
        if planner_request["operation"] in oauth_refresh_cleanup.OPERATIONS:
            oauth_refresh_cleanup_policy.verify_original(planner_request["operation"], planner_request["typedRequest"]["arguments"],
                configuration_payload=self.configuration.payload, root_key=self.configuration.root_key, now_epoch_ns=time.time_ns())
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
                operation for operation in self.role_config["enabledOperations"]
                if operation in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
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
            canary_delivery_admission=(canary_delivery_policy._Admission(self.configuration)
                if set(self.role_config["enabledOperations"]) & canary_delivery.OPERATIONS else None),
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
                not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
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

        from serverware import control_plane_rbac_currentness as rbac_currentness
        with rbac_currentness.execution_guard(typed_request, result, payload["capabilityId"], payload["deadlineMonotonicNs"]) as rbac_guard:
            with db._policy_authority_executor_pg_connect_raw() as raw:
                with raw.transaction():
                    with raw.cursor() as cursor:
                        cursor.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                        if rbac_guard is not None:
                            rbac_owner, rbac_head = rbac_guard
                            rbac_roots = rbac_currentness.metadata_roots(cursor, rbac_owner)
                            rbac_currentness._matching_roots(rbac_head, rbac_roots)
                    connection = db.PostgresMetadataConnection(raw)
                    receipt_json = db.execute_authority_v9(
                        capability_id=payload["capabilityId"], envelope_id=payload["envelopeId"],
                        planner_transaction_id=payload["plannerTransactionId"], exact_request_bytes=exact_request,
                        exact_result_bytes=exact_result, deadline_monotonic_ns=payload["deadlineMonotonicNs"], connection=connection)
                    if time.monotonic_ns() >= payload["deadlineMonotonicNs"]:
                        raise AuthorityServiceError("v9 executor transaction crossed its deadline")
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
            try:
                deadline_ns = writer_transport._deadline_ns(self.timeout_seconds)
            except BaseException:
                try:
                    connection.close()
                except BaseException:
                    pass
                raise
            if not self.in_flight.acquire(blocking=False):
                connection.close()
                continue
            try:
                future = self.pool.submit(
                    self._serve_connection, connection, deadline_ns=deadline_ns,
                )
            except BaseException:
                try:
                    connection.close()
                except BaseException:
                    pass
                self.in_flight.release()
                raise
            future.add_done_callback(
                lambda _future: self.in_flight.release()
            )

    def _serve_revocation_writer(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Fixed raw writer ingress, behind real service and registry admission.

        Peer credentials have already been checked by the sole serving caller.
        The complete five-body request and EOF must precede work or custody.
        One new invocation owns one source-bounded allowance; no subordinate
        component gets a replacement. The actual configured composition must
        return normally through every transaction/connection exit before any
        acknowledgment byte is sent. A later timeout or socket failure means
        uncertain delivery, never permission to undo or retry committed work.
        """
        process = self.process
        if (type(process) is not AuthorityProcess
                or process.role_name != "planner-writer"
                or process.process_mode != "policy-authority-planner-writer"):
            raise AuthorityServiceError("detached writer transfer has the wrong service role")
        originals = writer_transport._recv_request(
            connection, deadline_ns=deadline_ns, prefix=prefix,
        )
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        writer_transport._check_deadline(deadline_ns)
        _receipt, _reservation, acknowledgment_bytes = process._persist_and_reserve_revocation_commitments(
            intent_bytes=originals[0], relay_bytes=originals[1], envelope_bytes=originals[2],
            evaluation_context_bytes=originals[3], historical_expectations_bytes=originals[4],
            work=work,
        )
        writer_transport._check_deadline(deadline_ns)
        writer_transport._send_ack(connection, acknowledgment_bytes, deadline_ns=deadline_ns)

    def _serve_revocation_planning(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Peer-checked raw planning ingress, never a registry shortcut.

        The complete bounded request and EOF precede work allocation or real
        planning. One source-capped allowance follows authentication and the
        actual read owner. No response byte is released until all read scopes
        exit normally and both historical and transport deadlines remain live.
        """
        process = self.process
        if (type(process) is not AuthorityProcess
                or process.role_name != "planner"
                or process.process_mode != "policy-authority-planner"):
            raise AuthorityServiceError("detached planning transfer has the wrong service role")
        originals = planning_transport._recv_request(
            connection, deadline_ns=deadline_ns, prefix=prefix)
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        planning_transport._check_deadline(deadline_ns)
        envelope_bytes, evaluation_context_bytes = process._produce_revocation_plan_from_request(
            control_bytes=originals[0], request_bytes=originals[1], evidence_bytes=originals[2],
            context_bytes=originals[3], root_inventory_bytes=originals[4], work=work)
        planning_transport._check_deadline(deadline_ns)
        planning_transport._send_response(connection, envelope_bytes, evaluation_context_bytes,
            deadline_ns=deadline_ns)

    def _serve_revocation_custody(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Separate relay preparation from forwarding already-held originals.

        The sole caller has checked the verifier peer. Complete bounded input
        and EOF precede the single allowance and fixed service operation. No
        path silently falls through from signing into custody, and forwarding
        failures are uncertain delivery, not proof of rollback.
        """
        process = self.process
        if (type(process) is not AuthorityProcess or process.role_name != "planner"
                or process.process_mode != "policy-authority-planner"):
            raise AuthorityServiceError("detached custody transfer has the wrong service role")
        preparing_relay = prefix == custody_transport.RELAY_REQUEST_MAGIC
        if preparing_relay:
            originals = custody_transport._recv_relay_request(connection, deadline_ns=deadline_ns, prefix=prefix)
        elif prefix == custody_transport.FORWARD_REQUEST_MAGIC:
            originals = custody_transport._recv_forward_request(connection, deadline_ns=deadline_ns, prefix=prefix)
        else:
            raise AuthorityServiceError("detached custody transfer purpose is invalid")
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        custody_transport._check_deadline(deadline_ns)
        if preparing_relay:
            relay_bytes = process._prepare_revocation_writer_relay(intent_bytes=originals[0],
                envelope_bytes=originals[1], evaluation_context_bytes=originals[2],
                historical_expectations_bytes=originals[3], work=work)
            custody_transport._check_deadline(deadline_ns)
            custody_transport._send_relay(connection, relay_bytes, deadline_ns=deadline_ns)
        else:
            acknowledgment_bytes = process._forward_revocation_writer_custody(
                intent_bytes=originals[0], relay_bytes=originals[1], envelope_bytes=originals[2],
                evaluation_context_bytes=originals[3], historical_expectations_bytes=originals[4], work=work)
            custody_transport._check_deadline(deadline_ns)
            custody_transport._send_ack(connection, acknowledgment_bytes, deadline_ns=deadline_ns)

    def _serve_revocation_custody_read(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Peer-checked read-only lookup; no absence-success or mutation route."""
        process = self.process
        if (type(process) is not AuthorityProcess or process.role_name not in ("planner", "planner-writer")
                or process.process_mode != "policy-authority-" + process.role_name):
            raise AuthorityServiceError("detached custody read has the wrong service role")
        execution_id, planner_id = custody_read_transport._recv_request(
            connection, deadline_ns=deadline_ns, prefix=prefix)
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        custody_read_transport._check_deadline(deadline_ns)
        if process.role_name == "planner":
            originals = process._relay_revocation_writer_read(
                execution_envelope_id=execution_id, planner_transaction_id=planner_id, work=work)
        else:
            originals = process._read_retained_revocation_writer_originals(
                execution_envelope_id=execution_id, planner_transaction_id=planner_id, work=work)
        custody_read_transport._check_deadline(deadline_ns)
        custody_read_transport._send_originals(connection, originals, deadline_ns=deadline_ns)

    def _serve_webauthn_evidence_custody(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Fixed peer-checked preparation, forwarding or writer retention.

        The complete bounded originals and EOF precede work allocation. Relay
        preparation cannot fall through into forwarding; only the planner
        contacts the writer. Each invocation retains one original allowance.
        Writer response bytes are sent only after actual outer exit/close.
        The response is informational peer metadata, not a signed receipt or
        execution capability. Post-commit timeout/response loss is uncertain.
        """
        process = self.process
        preparing = prefix in (evidence_custody_transport.REGISTRATION_RELAY_MAGIC,
            evidence_custody_transport.INSTALLATION_RELAY_MAGIC)
        forwarding = prefix in (evidence_custody_transport.REGISTRATION_FORWARD_MAGIC,
            evidence_custody_transport.INSTALLATION_FORWARD_MAGIC)
        retaining = prefix in (evidence_custody_transport.REGISTRATION_REQUEST_MAGIC,
            evidence_custody_transport.INSTALLATION_REQUEST_MAGIC)
        if not (preparing or forwarding or retaining):
            raise AuthorityServiceError("evidence custody transfer purpose is invalid")
        role = "planner-writer" if retaining else "planner"
        if (type(process) is not AuthorityProcess or process.role_name != role
                or process.process_mode != "policy-authority-" + role):
            raise AuthorityServiceError("evidence custody transfer has the wrong service role")
        if preparing:
            purpose, originals = evidence_custody_transport._recv_relay_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        elif forwarding:
            purpose, originals = evidence_custody_transport._recv_forward_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        else:
            purpose, originals = evidence_custody_transport._recv_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        evidence_custody_transport._check_deadline(deadline_ns)
        if preparing:
            relay_bytes = AuthorityProcess._produce_webauthn_evidence_custody_relay(process,
                purpose=purpose, intent_bytes=originals[0], envelope_bytes=originals[1],
                inputs_bytes=originals[2], evaluation_context_bytes=originals[3],
                historical_expectations_bytes=originals[4], work=work)
            evidence_custody_transport._check_deadline(deadline_ns)
            evidence_custody_transport._send_relay(connection, relay_bytes, deadline_ns=deadline_ns)
            return
        arguments = {"purpose": purpose, "intent_bytes": originals[0], "relay_bytes": originals[1],
            "envelope_bytes": originals[2], "inputs_bytes": originals[3],
            "evaluation_context_bytes": originals[4], "historical_expectations_bytes": originals[5]}
        if forwarding:
            record_digest, retained_at = AuthorityProcess._send_webauthn_evidence_custody(
                process, **arguments, work=work)
        else:
            result = AuthorityProcess._persist_webauthn_evidence_custody(process, **arguments, work=work)
            record_digest, retained_at = result["retained_record_digest"], result["retained_at_epoch_ns"]
        evidence_custody_transport._check_deadline(deadline_ns)
        evidence_custody_transport._send_response(connection, record_digest, retained_at, deadline_ns=deadline_ns)

    def _serve_webauthn_evidence_custody_read(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Peer-checked signed read, separate from all retaining operations.

        The signed control and history must be fully received with exact EOF
        before the one source allowance is allocated. Missing/invalid records
        close the exchange, never return absence, rollback or retry authority.
        Returned originals remain historical evidence, not current permission.
        """
        process = self.process
        forwarded = prefix in (evidence_custody_read_transport.REGISTRATION_FORWARD_MAGIC,
            evidence_custody_read_transport.INSTALLATION_FORWARD_MAGIC)
        direct = prefix in (evidence_custody_read_transport.REGISTRATION_REQUEST_MAGIC,
            evidence_custody_read_transport.INSTALLATION_REQUEST_MAGIC)
        if not (forwarded or direct):
            raise AuthorityServiceError("evidence custody read purpose is invalid")
        role = "planner-writer" if forwarded else "planner"
        if (type(process) is not AuthorityProcess or process.role_name != role
                or process.process_mode != "policy-authority-" + role):
            raise AuthorityServiceError("evidence custody read has the wrong service role")
        if forwarded:
            purpose, originals = evidence_custody_read_transport._recv_forward_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        else:
            purpose, originals = evidence_custody_read_transport._recv_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        evidence_custody_read_transport._check_deadline(deadline_ns)
        if forwarded:
            result = AuthorityProcess._read_webauthn_evidence_custody(process,
                purpose=purpose, control_bytes=originals[0],
                historical_expectations_bytes=originals[1], work=work)
            response = (result["envelope_bytes"], result["inputs_bytes"], result["evaluation_context_bytes"],
                result["retained_record_digest"], result["retained_at_epoch_ns"])
        else:
            response = AuthorityProcess._forward_webauthn_evidence_custody_read(process,
                purpose=purpose, control_bytes=originals[0],
                historical_expectations_bytes=originals[1], work=work)
        evidence_custody_read_transport._check_deadline(deadline_ns)
        evidence_custody_read_transport._send_response(connection, response, deadline_ns=deadline_ns)

    def _serve_webauthn_registration_source(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Serve one verifier-peer source read without custody or evidence signing."""
        process = self.process
        if (type(process) is not AuthorityProcess or process.role_name != "planner"
                or process.process_mode != "policy-authority-planner"):
            raise AuthorityServiceError("registration source request has the wrong service role")
        originals = registration_source_transport._recv_request(
            connection, prefix=prefix, deadline_ns=deadline_ns)
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        # The sole router already checked the configured verifier peer.
        # Both bounded original bodies and EOF precede this single allowance.
        work = _ValidationWork(QueryReadValidationLimits())
        registration_source_transport._check_deadline(deadline_ns)
        response = AuthorityProcess._produce_webauthn_registration_source_response(
            process, control_bytes=originals[0], context_bytes=originals[1], work=work)
        registration_source_transport._check_deadline(deadline_ns)
        registration_source_transport._send_response(connection, response, deadline_ns=deadline_ns)

    def _serve_webauthn_evidence_plan(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Serve one peer-checked, signed planning request without custody."""
        process = self.process
        if (type(process) is not AuthorityProcess or process.role_name != "planner"
                or process.process_mode != "policy-authority-planner"):
            raise AuthorityServiceError("evidence planning request has the wrong service role")
        purpose, originals = evidence_plan_transport._recv_request(
            connection, prefix=prefix, deadline_ns=deadline_ns)
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        # The complete bounded request and EOF precede the one source work
        # allocation. Every authentication/acquisition/replay step shares it.
        work = _ValidationWork(QueryReadValidationLimits())
        evidence_plan_transport._check_deadline(deadline_ns)
        response = AuthorityProcess._produce_webauthn_evidence_plan(process,
            purpose=purpose, control_bytes=originals[0], context_bytes=originals[1],
            inputs_bytes=originals[2], work=work)
        evidence_plan_transport._check_deadline(deadline_ns)
        evidence_plan_transport._send_response(connection, response, deadline_ns=deadline_ns)

    def _serve_webauthn_transition_plan(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Serve a peer-checked successor request without legacy JSON routing."""
        process = self.process
        if (type(process) is not AuthorityProcess or process.role_name != "planner"
                or process.process_mode != "policy-authority-planner"):
            raise AuthorityServiceError("transition planning request has the wrong service role")
        operation, originals = transition_plan_transport._recv_request(
            connection, prefix=prefix, deadline_ns=deadline_ns)
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        # Fixed bounded framing and EOF precede this one source allowance.
        # Configuration, authentication, read, proof and signing share it.
        work = _ValidationWork(QueryReadValidationLimits())
        transition_plan_transport._check_deadline(deadline_ns)
        response = AuthorityProcess._produce_webauthn_transition_plan(process,
            operation=operation, control_bytes=originals[0], context_bytes=originals[1],
            inputs_bytes=originals[2], work=work)
        transition_plan_transport._check_deadline(deadline_ns)
        transition_plan_transport._send_response(connection, response, deadline_ns=deadline_ns)

    def _serve_webauthn_transition_custody(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Keep relay preparation separate from explicit possibly committing delivery.

        Peer admission precedes this method. Complete bounded framing and EOF
        precede the one fixed work allowance, and writer results follow normal
        outer transaction exit and connection close. A missing response does
        not prove rollback; returned digest/time bytes are unsigned observations.
        """
        process = self.process
        preparing = prefix in transition_custody_transport.RELAY_REQUEST_MAGICS
        forwarding = prefix in transition_custody_transport.FORWARD_REQUEST_MAGICS
        retaining = prefix in transition_custody_transport.REQUEST_MAGICS
        if not (preparing or forwarding or retaining):
            raise AuthorityServiceError("transition custody transfer purpose is invalid")
        role = "planner-writer" if retaining else "planner"
        if (type(process) is not AuthorityProcess or process.role_name != role
                or process.process_mode != "policy-authority-" + role):
            raise AuthorityServiceError("transition custody transfer has the wrong service role")
        if preparing:
            operation, originals = transition_custody_transport._recv_relay_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        elif forwarding:
            operation, originals = transition_custody_transport._recv_forward_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        else:
            operation, originals = transition_custody_transport._recv_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        transition_custody_transport._check_deadline(deadline_ns)
        if preparing:
            relay_bytes = AuthorityProcess._produce_webauthn_transition_custody_relay(process,
                operation=operation, intent_bytes=originals[0], envelope_bytes=originals[1],
                proof_bytes=originals[2], inputs_bytes=originals[3], context_bytes=originals[4],
                historical_expectations_bytes=originals[5], work=work)
            transition_custody_transport._check_deadline(deadline_ns)
            transition_custody_transport._send_relay(connection, relay_bytes, deadline_ns=deadline_ns)
            return
        arguments = {"operation": operation, "intent_bytes": originals[0], "relay_bytes": originals[1],
            "envelope_bytes": originals[2], "proof_bytes": originals[3], "inputs_bytes": originals[4],
            "context_bytes": originals[5], "historical_expectations_bytes": originals[6]}
        if forwarding:
            record_digest, retained_at = AuthorityProcess._send_webauthn_transition_custody(
                process, **arguments, work=work)
        else:
            result = AuthorityProcess._persist_webauthn_transition_custody(process, **arguments, work=work)
            record_digest, retained_at = result["retained_record_digest"], result["retained_at_epoch_ns"]
        transition_custody_transport._check_deadline(deadline_ns)
        transition_custody_transport._send_response(connection, record_digest, retained_at, deadline_ns=deadline_ns)

    def _serve_webauthn_transition_custody_read(self, connection: socket.socket, *,
            deadline_ns: int, prefix: bytes) -> None:
        """Serve a signed lookup without renewal, mutation or absence success.

        The peer was admitted before prefix routing. Complete bounded raw2 and
        exact EOF precede one original allowance. The writer closes its actual
        read owner before returning raw4 plus unsigned digest/time observations.
        The planner genuinely replays those originals before forwarding them.
        """
        process = self.process
        forwarded = prefix in transition_custody_read_transport.FORWARD_REQUEST_MAGICS
        direct = prefix in transition_custody_read_transport.REQUEST_MAGICS
        if not (forwarded or direct):
            raise AuthorityServiceError("transition custody read purpose is invalid")
        role = "planner-writer" if forwarded else "planner"
        if (type(process) is not AuthorityProcess or process.role_name != role
                or process.process_mode != "policy-authority-" + role):
            raise AuthorityServiceError("transition custody read has the wrong service role")
        if forwarded:
            operation, originals = transition_custody_read_transport._recv_forward_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        else:
            operation, originals = transition_custody_read_transport._recv_request(
                connection, deadline_ns=deadline_ns, prefix=prefix)
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        transition_custody_read_transport._check_deadline(deadline_ns)
        if forwarded:
            result = AuthorityProcess._read_webauthn_transition_custody(process,
                operation=operation, control_bytes=originals[0],
                historical_expectations_bytes=originals[1], work=work)
            response = (result["envelope_bytes"], result["proof_bytes"], result["inputs_bytes"],
                result["context_bytes"], result["retained_record_digest"], result["retained_at_epoch_ns"])
        else:
            response = AuthorityProcess._forward_webauthn_transition_custody_read(process,
                operation=operation, control_bytes=originals[0],
                historical_expectations_bytes=originals[1], work=work)
        transition_custody_read_transport._check_deadline(deadline_ns)
        transition_custody_read_transport._send_response(connection, response, deadline_ns=deadline_ns)

    def _serve_connection(self, connection: socket.socket, *, deadline_ns: int) -> None:
        detached = False
        try:
            writer_transport._check_deadline(deadline_ns)
            uid, gid, _pid = _peer_identity(connection)
            if uid != self.peer_uid or gid != self.peer_gid:
                raise AuthorityServiceError(
                    "authority socket peer identity is not allowed"
                )
            prefix = writer_transport._recv_prefix(connection, deadline_ns=deadline_ns)
            detached = prefix in (writer_transport.REQUEST_MAGIC, planning_transport.REQUEST_MAGIC,
                *custody_caller_transport.REQUEST_MAGICS,
                *custody_reconcile_transport.REQUEST_MAGICS,
                custody_transport.RELAY_REQUEST_MAGIC, custody_transport.FORWARD_REQUEST_MAGIC,
                custody_read_transport.REQUEST_MAGIC,
                evidence_custody_transport.REGISTRATION_REQUEST_MAGIC,
                evidence_custody_transport.INSTALLATION_REQUEST_MAGIC,
                evidence_custody_transport.REGISTRATION_RELAY_MAGIC,
                evidence_custody_transport.INSTALLATION_RELAY_MAGIC,
                evidence_custody_transport.REGISTRATION_FORWARD_MAGIC,
                evidence_custody_transport.INSTALLATION_FORWARD_MAGIC,
                evidence_custody_read_transport.REGISTRATION_REQUEST_MAGIC,
                evidence_custody_read_transport.INSTALLATION_REQUEST_MAGIC,
                evidence_custody_read_transport.REGISTRATION_FORWARD_MAGIC,
                evidence_custody_read_transport.INSTALLATION_FORWARD_MAGIC,
                evidence_plan_transport.REGISTRATION_REQUEST_MAGIC,
                evidence_plan_transport.INSTALLATION_REQUEST_MAGIC,
                registration_source_transport.REQUEST_MAGIC,
                registration_source_caller.REQUEST_MAGIC,
                registration_custody_caller.REQUEST_MAGIC,
                registration_execution_caller.REQUEST_MAGIC,
                registration_finalization_caller.REQUEST_MAGIC,
                registration_finalization_execution_caller.REQUEST_MAGIC,
                *transition_plan_transport.REQUEST_MAGICS,
                *transition_custody_transport.REQUEST_MAGICS,
                *transition_custody_transport.RELAY_REQUEST_MAGICS,
                *transition_custody_transport.FORWARD_REQUEST_MAGICS,
                *transition_custody_read_transport.REQUEST_MAGICS,
                *transition_custody_read_transport.FORWARD_REQUEST_MAGICS)
            from serverware import authority_public_revocation_transport as public_revocation_wire
            if prefix in public_revocation_wire.REQUEST_MAGICS:
                from serverware import authority_public_revocation_service
                detached = True
                authority_public_revocation_service.serve_process(
                    self.process, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            reconciling = prefix in custody_reconcile_transport.REQUEST_MAGICS
            if prefix == registration_finalization_execution_caller.REQUEST_MAGIC:
                registration_finalization_execution_caller._serve_verifier(
                    self.process, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == registration_execution_caller.REQUEST_MAGIC:
                registration_execution_caller._serve_verifier(
                    self.process, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == registration_finalization_caller.REQUEST_MAGIC:
                registration_finalization_caller._serve_verifier(
                    self.process, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == registration_custody_caller.REQUEST_MAGIC:
                registration_custody_caller._serve_verifier(
                    self.process, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == registration_source_caller.REQUEST_MAGIC:
                registration_source_caller._serve_verifier(
                    self.process, connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if reconciling or prefix in custody_caller_transport.REQUEST_MAGICS:
                from serverware import authority_custody_caller_service

                authority_custody_caller_service._serve_verifier(
                    self.process, connection, deadline_ns=deadline_ns, prefix=prefix,
                    reconciling=reconciling)
                return
            if prefix == writer_transport.REQUEST_MAGIC:
                self._serve_revocation_writer(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == planning_transport.REQUEST_MAGIC:
                self._serve_revocation_planning(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix in (custody_transport.RELAY_REQUEST_MAGIC, custody_transport.FORWARD_REQUEST_MAGIC):
                self._serve_revocation_custody(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == custody_read_transport.REQUEST_MAGIC:
                self._serve_revocation_custody_read(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix in (evidence_custody_transport.REGISTRATION_REQUEST_MAGIC,
                    evidence_custody_transport.INSTALLATION_REQUEST_MAGIC,
                    evidence_custody_transport.REGISTRATION_RELAY_MAGIC,
                    evidence_custody_transport.INSTALLATION_RELAY_MAGIC,
                    evidence_custody_transport.REGISTRATION_FORWARD_MAGIC,
                    evidence_custody_transport.INSTALLATION_FORWARD_MAGIC):
                self._serve_webauthn_evidence_custody(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix in (evidence_custody_read_transport.REGISTRATION_REQUEST_MAGIC,
                    evidence_custody_read_transport.INSTALLATION_REQUEST_MAGIC,
                    evidence_custody_read_transport.REGISTRATION_FORWARD_MAGIC,
                    evidence_custody_read_transport.INSTALLATION_FORWARD_MAGIC):
                self._serve_webauthn_evidence_custody_read(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix == registration_source_transport.REQUEST_MAGIC:
                self._serve_webauthn_registration_source(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix in (evidence_plan_transport.REGISTRATION_REQUEST_MAGIC,
                    evidence_plan_transport.INSTALLATION_REQUEST_MAGIC):
                self._serve_webauthn_evidence_plan(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix in transition_plan_transport.REQUEST_MAGICS:
                self._serve_webauthn_transition_plan(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix in (*transition_custody_transport.REQUEST_MAGICS,
                    *transition_custody_transport.RELAY_REQUEST_MAGICS,
                    *transition_custody_transport.FORWARD_REQUEST_MAGICS):
                self._serve_webauthn_transition_custody(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            if prefix in (*transition_custody_read_transport.REQUEST_MAGICS,
                    *transition_custody_read_transport.FORWARD_REQUEST_MAGICS):
                self._serve_webauthn_transition_custody_read(connection, deadline_ns=deadline_ns, prefix=prefix)
                return
            # Preserve the legacy canonical mapping and 64 MiB whole-frame
            # ceiling. Its first eight bytes have only been read, not parsed
            # as JSON or re-encoded into a successor control.
            size = int.from_bytes(prefix, "big")
            if not 2 <= size <= MAX_MESSAGE_BYTES:
                raise AuthorityServiceError("authority message size is invalid")
            encoded = writer_transport._recv_exact_until(connection, size, deadline_ns=deadline_ns)
            try:
                request = json.loads(encoded)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuthorityServiceError("authority message is not JSON") from exc
            if not isinstance(request, dict) or _canonical(request) != encoded:
                raise AuthorityServiceError("authority message is not canonical")
            response = self.process.handle(request)
            writer_transport._check_deadline(deadline_ns)
            _send_message_until(connection, response, deadline_ns=deadline_ns)
        except Exception as exc:
            # There is no detached error/success union. A missing, partial or
            # late ACK is uncertain delivery; never send a legacy error frame
            # after any detached response bytes or retry either operation.
            if detached:
                return
            try:
                writer_transport._check_deadline(deadline_ns)
                _send_message_until(
                    connection,
                    {
                        "schema": "serverware.policyAuthorityError/v1",
                        "code": "authority_denied",
                        "detailDigest": _sha256(
                            str(exc).encode("utf-8")
                        ),
                    },
                    deadline_ns=deadline_ns,
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
    if args.role != "planner-writer" and any(
        os.environ.get(name, "").strip()
        for name in PLANNER_WRITER_SIGNING_KEY_ENVIRONMENTS
    ):
        raise AuthorityServiceError(
            "non-writer process inherited the writer response signer"
        )
    configuration = MeasuredConfiguration.load(role=args.role)
    process = AuthorityProcess(role=args.role, configuration=configuration)
    _close_inherited_descriptors(
        authority_launch_guard.retained_descriptors()
    )
    if process.rbac_currentness_owner is not None and process.rbac_currentness_owner.recovery is not None:
        # The separately authorized recovery launch never opens an authority
        # listener or reenters metadata execution, even after a known outcome.
        from serverware import control_plane_rbac_recovery, control_plane_rbac_currentness
        try:
            observation = control_plane_rbac_recovery.run(process)
            sys.stdout.write(_canonical(observation).decode("ascii") + "\n")
            sys.stdout.flush()
        finally:
            control_plane_rbac_currentness.close()
        return 0
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
