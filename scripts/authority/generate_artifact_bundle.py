from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_contract
from serverware import authority_launcher
from serverware import authority_transition_registry
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware import authority_webauthn_transition_policy as transition_policy
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_oauth_activation_policy as oauth_activation_policy
from serverware import authority_oauth_exchange_policy as oauth_exchange_policy
from serverware import authority_policy_candidate_policy as policy_candidate_policy
from serverware import authority_transition_policy_genesis as genesis_policy
from serverware import authority_setup_policy_admission as setup_policy_admission
from serverware import authority_policy_canary_policy as policy_canary_policy
from serverware import authority_policy_canary_heartbeat_policy as heartbeat_policy
from serverware import authority_policy_canary_finalization_policy as finalization_policy
from serverware import authority_policy_canary_native_readiness as native_readiness_policy
from serverware import authority_policy_native_activation as native_activation
from serverware import authority_policy_canary_delivery_policy as canary_delivery_policy
from serverware import authority_oauth_measured_exchange_policy as oauth_measured_exchange_policy
from serverware import authority_oauth_measured_setup_policy as oauth_measured_setup_policy
from serverware import authority_oauth_reconnect_policy as oauth_reconnect_policy
from serverware import authority_oauth_retirement_succession_policy as oauth_succession_policy
from serverware import authority_oauth_refresh_policy as oauth_refresh_policy
from serverware import authority_oauth_refresh_cleanup_policy as oauth_refresh_cleanup_policy
from serverware import authority_oauth_measured_refresh_policy as oauth_measured_refresh_policy
from serverware import authority_oauth_measured_cleanup_policy as oauth_measured_cleanup_policy
from serverware import authority_oauth_measured_pending_retirement_policy as oauth_pending_retirement_policy
from serverware import authority_oauth_measured_capture_retirement_policy as oauth_capture_retirement_policy
from serverware import authority_credential_currentness_policy as credential_currentness_policy
from serverware import authority_oauth_revocation_policy as oauth_revocation_policy
from serverware import authority_recovery_configuration as recovery_configuration
from serverware import authority_challenge_policy as challenge_maintenance_policy
from serverware.authority_artifact_spec import (
    ARTIFACT_BUNDLE_SCHEMA,
    AUTHORITY_SCHEMA_VERSION,
    GENERATION_STATEMENT_SCHEMA,
    KEY_AUTHORIZATION_SCHEMA,
    KEY_REVOCATION_SCHEMA,
    UNSIGNED_PACKAGE_SCHEMA,
    ArtifactContractError,
    LOCAL_STAGE_ZERO_INTERFACE_SCHEMA,
    VerifiedAuthorityKey,
    artifact_bundle_digest,
    canonical_json_bytes,
    closure_receipt_digest,
    closure_signature_domain,
    configuration_generation_binding,
    configuration_generation_binding_digest,
    configuration_payload_bindings,
    domain_digest,
    package_signature_message,
    role_binding_digests,
    role_runtime_closure_digest,
    snapshot_receipt_digest,
    strict_base64url_decode,
    strict_base64url_encode,
    trust_document_digest,
    validate_closure_receipt,
    validate_selected_closure_receipt,
    validate_generation_core,
    validate_snapshot_receipt,
    validate_trust_state,
    validate_unsigned_artifact_package,
    verify_ed25519_signature,
    _verify_key_documents,
    _require_timestamp,
    _strict_json_document,
)


INPUT_SCHEMA = "serverware.authorityArtifactBundleGeneratorInput/v3"
INPUT_FIELDS = frozenset({
    "schema", "artifactRoot", "sourceRevision", "sourceCommitDigest", "authoritySchemaVersion",
    "trustMode", "files", "stableSnapshotReceipt", "closureReceipt", "schemas", "migrations",
    "configurations", "roleManifests", "sbom", "provenance", "ociImage", "operationManifest",
    "trustMaterial", "generation", "signingKeys",
})
SOURCE_TREE_DIGEST_DOMAIN = "serverware.authoritySourceTree/v1"
ENUMERATED_TREE_DIGEST_DOMAIN = "serverware.authorityEnumeratedTree/v1"
SNAPSHOT_SIGNATURE_DOMAIN = (
    "serverware.authorityStableSnapshotReceiptSignature/v1"
)
CLOSURE_SIGNATURE_DOMAIN = (
    "serverware.authorityCompleteClosureReceiptSignature/v1"
)
ROLE_SET_DIGEST_DOMAIN = "serverware.authorityRoleSet/v1"
SERVICE_CONFIGURATION_SCHEMA = (
    "serverware.signedPolicyAuthorityServiceConfiguration/v6"
)
SERVICE_CONFIGURATION_PAYLOAD_SCHEMA = (
    "serverware.policyAuthorityServiceConfiguration/v6"
)
WITNESS_CONFIGURATION_SCHEMA = (
    "serverware.signedPolicyAuthorityReplayWitnessConfiguration/v4"
)
WITNESS_CONFIGURATION_PAYLOAD_SCHEMA = (
    "serverware.policyAuthorityReplayWitnessConfiguration/v4"
)
SERVICE_CONFIGURATION_ROLES = frozenset(
    {"verifier", "planner", "planner-writer", "issuer", "executor"}
)
AUTHORITY_SERVICE_CONFIGURATION_ROLE = "authority-service"
SERVICE_PROCESS_MODES = {
    role: f"policy-authority-{role}"
    for role in SERVICE_CONFIGURATION_ROLES
}
SERVICE_CONFIGURATION_FIELDS = frozenset(
    {
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
        "verifierCredentialIssuanceDigest",
        "issuerCredentialIssuanceDigest",
        "executorCredentialIssuanceDigest",
    }
)
SERVICE_ROLE_COMMON_FIELDS = frozenset(
    {
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
)
SERVICE_ROLE_EXTRA_FIELDS = {
    "verifier": frozenset(
        {
            "runtimeSocketPath",
            "signingSpkiDigest",
            "signingPublicKeyBase64Url",
            "maximumEndToEndDeadlineNs",
        }
    ),
    "planner": frozenset(
        {
            "enabledOperations",
            "plannerSessionIdentityDigest",
            "signingSpkiDigest",
            "signingPublicKeyBase64Url",
        }
    ),
    "planner-writer": frozenset(
        {
            "plannerSessionIdentityDigest",
            "plannerSigningSpkiDigest",
            "plannerSigningPublicKeyBase64Url",
            "responseSigningPublicKeyBase64Url",
        }
    ),
    "issuer": frozenset(),
    "executor": frozenset(),
}
WITNESS_CONFIGURATION_FIELDS = frozenset(
    {
        "schema",
        "sourceRevision",
        "roleBindingDigest",
        "generationBindingDigest",
        "operationManifestDigest",
        "authorityConfigurationDigests",
        "identityDigest",
        "signingSpkiDigest",
        "verifierSigningPublicKeyBase64Url",
        "serviceUid",
        "serviceGid",
        "peerUid",
        "peerGid",
        "socketPath",
        "socketActivationName",
        "listenBacklog",
        "workers",
        "maximumInFlight",
        "requestTimeoutSeconds",
        "maximumRequestAgeNs",
        "releaseConsumerPeers",
        "minimumSequence",
        "minimumReceiptDigest",
    }
)
ROLE_REQUIREMENTS = {
    # The package and launcher require the same exact roster, including the
    # planner's RBAC witness credentials. A stale parallel five-FD list refused
    # genuine current role manifests before package assembly could proceed.
    role: {
        "runtimeUid": authority_launcher.ROLE_IDENTITIES[role][0],
        "runtimeGid": authority_launcher.ROLE_IDENTITIES[role][1],
        "processMode": authority_launcher.PROCESS_MODES[role],
        "listenerName": authority_launcher.ROLE_LISTENER_NAMES[role],
        "credentialNames": sorted(authority_launcher.ROLE_CREDENTIAL_DESCRIPTOR_NAMES[role]),
    }
    for role in ("planner", "planner-writer")
}
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_TARGET_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
MAX_FILES = 32768


class GeneratorError(RuntimeError):
    pass


def _closed(
    value: object,
    *,
    name: str,
    keys: set[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise GeneratorError(f"{name} is not a closed object")
    return value


def _bounded_list(
    value: object,
    *,
    name: str,
    maximum: int,
    minimum: int = 0,
) -> Sequence[Any]:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
    ):
        raise GeneratorError(f"{name} has an invalid item count")
    return value


def _ascii(
    value: object,
    *,
    name: str,
    maximum: int = 4096,
    allow_empty: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or len(value) > maximum
        or (not allow_empty and not value)
    ):
        raise GeneratorError(f"{name} must be bounded ASCII")
    return value


def _integer(
    value: object,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise GeneratorError(f"{name} is outside its integer bound")
    return value


def _relative_path(value: object, *, name: str) -> str:
    text = _ascii(value, name=name)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or text != path.as_posix()
        or text in {".", ".."}
        or any(part in {"", ".", ".."} for part in path.parts)
        or text.startswith("-")
    ):
        raise GeneratorError(f"{name} is not a canonical relative path")
    return text


def _runtime_path(value: object, *, name: str) -> str:
    text = _ascii(value, name=name)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or text != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise GeneratorError(f"{name} is not a canonical runtime path")
    return text


def _digest(value: object, *, name: str) -> str:
    text = _ascii(value, name=name, maximum=71)
    if (
        len(text) != 71
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise GeneratorError(f"{name} is not a SHA-256 digest")
    return text


def _sorted_unique(values: Sequence[Any], *, name: str, key) -> None:
    observed = [key(value) for value in values]
    if observed != sorted(observed) or len(observed) != len(set(observed)):
        raise GeneratorError(f"{name} is not sorted and unique")


def _stable_stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_json(path: str, *, maximum: int) -> Mapping[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise GeneratorError("JSON input is not a bounded regular file")
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, before.st_size - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or _stable_stat_identity(before) != _stable_stat_identity(after)
        ):
            raise GeneratorError("JSON input changed while reading")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(data))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GeneratorError("JSON input is invalid") from exc
    if not isinstance(value, Mapping):
        raise GeneratorError("JSON input is not an object")
    return value


def _open_beneath(root_fd: int, relative_path: str) -> int:
    parts = PurePosixPath(relative_path).parts
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_DIRECTORY
                | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = next_descriptor
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=current,
        )
    finally:
        os.close(current)
    return descriptor


def _measure_file(
    root_fd: int,
    value: Mapping[str, Any],
) -> dict[str, Any]:
    entry = _closed(
        value,
        name="file input",
        keys={"path", "kind", "mode", "uid", "gid"},
    )
    path = _relative_path(entry["path"], name="file path")
    expected_mode = _integer(
        entry["mode"], name=f"{path} mode", minimum=0, maximum=0o7777
    )
    expected_uid = _integer(
        entry["uid"], name=f"{path} uid", minimum=0, maximum=2**32 - 2
    )
    expected_gid = _integer(
        entry["gid"], name=f"{path} gid", minimum=0, maximum=2**32 - 2
    )
    descriptor = _open_beneath(root_fd, path)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > MAX_FILE_BYTES
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_uid != expected_uid
            or before.st_gid != expected_gid
        ):
            raise GeneratorError(f"{path} metadata differs from the spec")
        digest = hashlib.sha256()
        observed = 0
        while observed < before.st_size:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, before.st_size - observed),
            )
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            observed != before.st_size
            or _stable_stat_identity(before) != _stable_stat_identity(after)
        ):
            raise GeneratorError(f"{path} changed while being measured")
    finally:
        os.close(descriptor)
    return {
        "path": path,
        "kind": _ascii(entry["kind"], name=f"{path} kind", maximum=128),
        "mode": expected_mode,
        "uid": expected_uid,
        "gid": expected_gid,
        "size": before.st_size,
        "sha256": "sha256:" + digest.hexdigest(),
    }


def _read_exact_bundle_file(
    root_fd: int,
    path: str,
    file_entry: Mapping[str, Any],
    *,
    maximum: int,
) -> bytes:
    if file_entry["size"] > maximum:
        raise GeneratorError(f"{path} exceeds its document byte limit")
    descriptor = _open_beneath(root_fd, path)
    try:
        before = os.fstat(descriptor)
        if before.st_size != file_entry["size"] or before.st_size > maximum:
            raise GeneratorError(f"{path} size changed before its bounded document read")
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, before.st_size - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or _stable_stat_identity(before) != _stable_stat_identity(after)
            or "sha256:" + hashlib.sha256(data).hexdigest()
            != file_entry["sha256"]
        ):
            raise GeneratorError(f"{path} changed while being read")
    finally:
        os.close(descriptor)
    return bytes(data)


def _receipt_signature_message(domain: str, payload: Mapping[str, Any]) -> bytes:
    return domain_digest(domain, canonical_json_bytes(payload)).encode("ascii")


def _verification_key(
    trust: Mapping[str, Any],
    *,
    key_id: str,
    purpose: str,
    validation_time: str,
) -> VerifiedAuthorityKey:
    keys = {**trust["rootKeys"], **trust["currentKeys"]}
    try:
        key = keys[key_id]
    except KeyError as exc:
        raise GeneratorError(
            f"{purpose} signer is not generation-authorized"
        ) from exc
    if (
        purpose not in key.purposes
        or key_id in trust["revokedKeyIds"]
        or not key.not_before <= validation_time <= key.not_after
    ):
        raise GeneratorError(
            f"{purpose} signer is unauthorized, revoked, or expired"
        )
    return key


def _verify_snapshot_and_closure(
    snapshot: Mapping[str, Any],
    closure: Mapping[str, Any],
    *,
    trust: Mapping[str, Any],
    validation_time: str,
    trust_mode: str | None = None,
) -> tuple[str, str]:
    validate_snapshot_receipt(snapshot)
    validate_selected_closure_receipt(closure, trust_mode=trust_mode,
                                     stage_zero=closure.get("payload", {}).get("stageZero", {}))
    snapshot_key = _verification_key(
        trust,
        key_id=snapshot["signerKeyId"],
        purpose="stable-snapshot-verifier",
        validation_time=validation_time,
    )
    closure_key = _verification_key(
        trust,
        key_id=closure["signerKeyId"],
        purpose="closure-verifier",
        validation_time=validation_time,
    )
    verify_ed25519_signature(
        snapshot_key.public_key,
        snapshot["signatureBase64Url"],
        _receipt_signature_message(
            SNAPSHOT_SIGNATURE_DOMAIN, snapshot["payload"]
        ),
        name="stable snapshot",
    )
    verify_ed25519_signature(
        closure_key.public_key,
        closure["signatureBase64Url"],
        _receipt_signature_message(
            closure_signature_domain(closure), closure["payload"]
        ),
        name="complete closure",
    )
    snapshot_digest = snapshot_receipt_digest(snapshot)
    closure_digest = closure_receipt_digest(closure)
    if (
        snapshot_digest in trust["acceptedEvidenceDigests"]
        or closure_digest in trust["acceptedEvidenceDigests"]
    ):
        raise GeneratorError("snapshot or closure receipt was already consumed")
    if not (
        snapshot["payload"]["createdAt"]
        <= validation_time
        <= snapshot["payload"]["expiresAt"]
        and closure["payload"]["createdAt"]
        <= validation_time
        <= closure["payload"]["expiresAt"]
    ):
        raise GeneratorError("snapshot or closure receipt is expired")
    if closure["payload"]["snapshotReceiptDigest"] != snapshot_digest:
        raise GeneratorError("closure receipt binds another snapshot")
    return snapshot_digest, closure_digest


def _digest_reference(
    value: Mapping[str, Any],
    *,
    name: str,
    keys: set[str],
    files: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    entry = dict(_closed(value, name=name, keys=keys | {"path"}))
    path = _relative_path(entry["path"], name=f"{name} path")
    try:
        measured = files[path]
    except KeyError as exc:
        raise GeneratorError(f"{name} is outside the measured tree") from exc
    entry["path"] = path
    entry["sha256"] = measured["sha256"]
    return entry


def _canonical_embedded_document(
    root_fd: int,
    path: str,
    file_entry: Mapping[str, Any],
    document: Mapping[str, Any],
) -> str:
    expected = canonical_json_bytes(document)
    observed = _read_exact_bundle_file(
        root_fd,
        path,
        file_entry,
        maximum=MAX_TARGET_DOCUMENT_BYTES,
    )
    if observed != expected:
        raise GeneratorError(
            f"{path} bytes are not the exact canonical signed document"
        )
    return "sha256:" + hashlib.sha256(observed).hexdigest()


def _canonical_json_document(
    root_fd: int,
    path: str,
    file_entry: Mapping[str, Any],
    *,
    name: str,
) -> tuple[bytes, Mapping[str, Any]]:
    observed = _read_exact_bundle_file(
        root_fd,
        path,
        file_entry,
        maximum=MAX_TARGET_DOCUMENT_BYTES,
    )
    try:
        document = json.loads(observed)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GeneratorError(f"{name} is not JSON") from exc
    if (
        not isinstance(document, Mapping)
        or canonical_json_bytes(document) != observed
    ):
        raise GeneratorError(f"{name} is not canonical closed JSON")
    return observed, document


def _validate_configuration_document(
    root_fd: int,
    reference: Mapping[str, Any],
    file_entry: Mapping[str, Any],
    *,
    source_revision: str,
    expected_generation_binding: Mapping[str, Any],
    expected_generation_binding_digest: str,
    expected_role_bindings: Mapping[str, str],
) -> tuple[str | None, str | None]:
    role = reference["role"]
    if role not in {AUTHORITY_SERVICE_CONFIGURATION_ROLE, "witness"}:
        return None, None
    _, document = _canonical_json_document(
        root_fd,
        reference["path"],
        file_entry,
        name=f"{reference['role']} configuration",
    )
    envelope = _closed(
        document,
        name=f"{reference['role']} configuration envelope",
        keys={"schema", "payload", "signature"},
    )
    strict_base64url_decode(
        envelope["signature"],
        name=f"{reference['role']} configuration signature",
        decoded_size=64,
    )
    expected_schema = (WITNESS_CONFIGURATION_SCHEMA if role == "witness"
                       else SERVICE_CONFIGURATION_SCHEMA)
    if envelope["schema"] != expected_schema:
        raise GeneratorError(f"{role} configuration schema changed")
    return validate_configuration_payload(envelope["payload"], role=role,
        source_revision=source_revision,
        expected_generation_binding=expected_generation_binding,
        expected_generation_binding_digest=expected_generation_binding_digest,
        expected_role_bindings=expected_role_bindings)


def validate_configuration_payload(
    value: Mapping[str, Any], *, role: str, source_revision: str,
    expected_generation_binding: Mapping[str, Any], expected_generation_binding_digest: str,
    expected_role_bindings: Mapping[str, str],
    root_key: Ed25519PublicKey | None = None,
) -> tuple[str, str]:
    """Existing static configuration checks, without inventing a signature/owner.

    The immutable file reader delegates here. A separately authorized local
    producer can validate its actual unsigned selection before private-key use;
    launch, installed-package and live attestation admission remain downstream.
    """
    if root_key is not None and not isinstance(root_key, Ed25519PublicKey):
        raise GeneratorError("configuration root is not authenticated Ed25519")
    if role not in {AUTHORITY_SERVICE_CONFIGURATION_ROLE, "witness"}:
        raise GeneratorError("configuration role is not closed")
    if role == "witness":
        expected_payload_schema = WITNESS_CONFIGURATION_PAYLOAD_SCHEMA
        expected_fields = WITNESS_CONFIGURATION_FIELDS
    else:
        expected_payload_schema = SERVICE_CONFIGURATION_PAYLOAD_SCHEMA
        expected_fields = SERVICE_CONFIGURATION_FIELDS
        if isinstance(value, Mapping) and recovery_configuration.FIELD in value:
            expected_fields = expected_fields | {recovery_configuration.FIELD}
        if isinstance(value, Mapping) and challenge_maintenance_policy.FIELD in value:
            expected_fields = expected_fields | {challenge_maintenance_policy.FIELD}
        if isinstance(value, Mapping):
            for optional_field in (genesis_policy.FIELD, evidence_policy.FIELD, transition_policy.FIELD, enrollment_policy.FIELD, oauth_activation_policy.FIELD, oauth_exchange_policy.FIELD, oauth_measured_exchange_policy.FIELD, oauth_measured_setup_policy.FIELD, oauth_reconnect_policy.FIELD, oauth_revocation_policy.FIELD, oauth_refresh_policy.FIELD, credential_currentness_policy.FIELD, oauth_refresh_cleanup_policy.FIELD, oauth_measured_refresh_policy.FIELD, oauth_measured_cleanup_policy.FIELD, oauth_pending_retirement_policy.FIELD, oauth_capture_retirement_policy.FIELD, policy_candidate_policy.FIELD, setup_policy_admission.FIELD, policy_canary_policy.FIELD, heartbeat_policy.FIELD, finalization_policy.FIELD, native_readiness_policy.FIELD, native_activation.FIELD, canary_delivery_policy.FIELD, oauth_succession_policy.FIELD):
                if optional_field in value:
                    expected_fields = expected_fields | {optional_field}
    payload = _closed(
        value,
        name=f"{role} configuration payload",
        keys=set(expected_fields),
    )
    if (
        payload["schema"] != expected_payload_schema
        or payload["sourceRevision"] != source_revision
    ):
        raise GeneratorError(f"{role} configuration schema changed")
    if (
        _digest(payload["generationBindingDigest"], name="configuration generation binding")
        != expected_generation_binding_digest
    ):
        raise GeneratorError(f"{role} configuration binds another generation intent")
    if role == "witness":
        authority_configuration_digests = payload[
            "authorityConfigurationDigests"
        ]
        release_consumers = payload["releaseConsumerPeers"]
        if (
            payload["operationManifestDigest"]
            != authority_contract.OPERATION_MANIFEST_DIGEST
            or _digest(payload["roleBindingDigest"], name="witness role binding")
                != expected_role_bindings.get("witness")
            or payload["socketPath"]
            != "/run/serverware/authority-witness/authority.sock"
            or payload["socketActivationName"]
            != "serverware-authority-witness"
            or not isinstance(authority_configuration_digests, list)
            or any(
                not isinstance(value, str)
                for value in authority_configuration_digests
            )
            or authority_configuration_digests
            != sorted(set(authority_configuration_digests))
            or any(
                _digest(value, name="authority configuration digest")
                != value
                for value in authority_configuration_digests
            )
            or not isinstance(release_consumers, Mapping)
            or set(release_consumers)
            != SERVICE_CONFIGURATION_ROLES
            or any(
                not isinstance(identity, Mapping)
                or set(identity) != {"uid", "gid"}
                or any(
                    not isinstance(identity[field], int)
                    or isinstance(identity[field], bool)
                    or identity[field] < 0
                    for field in ("uid", "gid")
                )
                for identity in release_consumers.values()
            )
        ):
            raise GeneratorError(
                "witness-v4 configuration topology is not exact"
            )
    else:
        if (
            type(payload["generationSequence"]) is not int
            or type(payload["generationMinimumRollbackSequence"]) is not int
            or payload["generationSequence"] != expected_generation_binding["sequence"]
            or payload["generationPredecessorDigest"]
                != expected_generation_binding["predecessorDigest"]
            or payload["generationMinimumRollbackSequence"]
                != expected_generation_binding["minimumRollbackSequence"]
        ):
            raise GeneratorError("authority service generation metadata changed")
        role_bindings = _closed(
            payload["roleBindingDigests"],
            name="authority service role bindings",
            keys=set(SERVICE_CONFIGURATION_ROLES),
        )
        role_closures = _closed(
            payload["roleRuntimeClosureDigests"],
            name="authority service static role closures",
            keys=set(SERVICE_CONFIGURATION_ROLES),
        )
        for configured_role in sorted(SERVICE_CONFIGURATION_ROLES):
            binding = _digest(role_bindings[configured_role], name="service role binding")
            if (
                binding != expected_role_bindings.get(configured_role)
                or _digest(role_closures[configured_role], name="service static role closure")
                != role_runtime_closure_digest(binding, payload["packageVersions"])
            ):
                raise GeneratorError("authority service static role binding changed")
        roles = payload["roles"]
        if (
            not isinstance(roles, Mapping)
            or set(roles) != SERVICE_CONFIGURATION_ROLES
        ):
            raise GeneratorError(
                "authority service configuration role set is not closed"
            )
        for configured_role, configured_role_value in roles.items():
            expected_role_fields = (
                SERVICE_ROLE_COMMON_FIELDS
                | SERVICE_ROLE_EXTRA_FIELDS[configured_role]
            )
            if (
                not isinstance(configured_role_value, Mapping)
                or set(configured_role_value) != expected_role_fields
                or configured_role_value["processMode"]
                != SERVICE_PROCESS_MODES[configured_role]
            ):
                raise GeneratorError(
                    f"{configured_role} service role is not closed"
                )
            for digest_field in (
                "measurementDigest",
                "responseSigningSpkiDigest",
            ):
                _digest(
                    configured_role_value[digest_field],
                    name=f"{configured_role} {digest_field}",
                )
        planner = roles["planner"]
        planner_writer = roles["planner-writer"]
        response_encoded = planner_writer["responseSigningPublicKeyBase64Url"]
        if type(response_encoded) is not str or len(response_encoded) != 43:
            raise GeneratorError(
                "planner-writer response public key is not canonical raw32"
            )
        response_raw = strict_base64url_decode(
            response_encoded, name="planner-writer response public key", decoded_size=32,
        )
        response_key = Ed25519PublicKey.from_public_bytes(response_raw)
        response_der = response_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if "sha256:" + hashlib.sha256(response_der).hexdigest() != planner_writer["responseSigningSpkiDigest"]:
            raise GeneratorError(
                "planner-writer response public key differs from its measured pin"
            )
        if any(
            planner_writer["responseSigningSpkiDigest"]
            == roles[other_role]["responseSigningSpkiDigest"]
            for other_role in ("verifier", "planner", "issuer", "executor")
        ):
            raise GeneratorError(
                "planner-writer response signing key is not distinct"
            )
        enabled_operations = planner["enabledOperations"]
        if (
            not isinstance(enabled_operations, list)
            or any(
                not isinstance(operation, str)
                for operation in enabled_operations
            )
            or enabled_operations != sorted(set(enabled_operations))
            or set(enabled_operations)
            - set(authority_transition_registry.PLANNABLE_OPERATIONS)
            or _digest(
                planner["plannerSessionIdentityDigest"],
                name="planner session identity digest",
            )
            != planner["plannerSessionIdentityDigest"]
            or planner_writer["plannerSessionIdentityDigest"]
            != planner["plannerSessionIdentityDigest"]
            or planner_writer["plannerSigningSpkiDigest"]
            != planner["signingSpkiDigest"]
        ):
            raise GeneratorError(
                "planner and planner-writer configuration is not exact"
            )
        issuer = roles.get("issuer")
        executor = roles.get("executor")
        if (
            not isinstance(issuer, Mapping)
            or not isinstance(executor, Mapping)
            or _digest(
                payload["verifierCredentialIssuanceDigest"],
                name="verifier credential-issuance digest",
            )
            != payload["verifierCredentialIssuanceDigest"]
            or _digest(
                payload["issuerCredentialIssuanceDigest"],
                name="issuer credential-issuance digest",
            )
            != payload["issuerCredentialIssuanceDigest"]
            or _digest(
                payload["executorCredentialIssuanceDigest"],
                name="executor credential-issuance digest",
            )
            != payload["executorCredentialIssuanceDigest"]
            or len({payload[role + "CredentialIssuanceDigest"]
                    for role in ("verifier", "issuer", "executor")}) != 3
        ):
            raise GeneratorError(
                "credential-issuance digests are invalid or not distinct"
            )
        if evidence_policy.FIELD in payload:
            try:
                evidence_policy.validate_policy(
                    payload[evidence_policy.FIELD], webauthn=payload["webauthn"]
                )
            except ValueError as exc:
                raise GeneratorError(
                    "authority WebAuthn evidence admission policy is invalid"
                ) from exc
        if transition_policy.FIELD in payload:
            try:
                transition_policy.validate_policy(
                    payload[transition_policy.FIELD], webauthn=payload["webauthn"]
                )
            except ValueError as exc:
                raise GeneratorError(
                    "authority WebAuthn transition policy is invalid"
                ) from exc
        if enrollment_policy.FIELD in payload:
            try:
                enrollment_policy.validate_policy(payload[enrollment_policy.FIELD], payload=payload)
            except ValueError as exc:
                raise GeneratorError(
                    "authority WebAuthn enrollment authorization policy is invalid"
                ) from exc
        try:
            if challenge_maintenance_policy.FIELD in payload:
                challenge_maintenance_policy._shape(payload[challenge_maintenance_policy.FIELD])
            recovery = recovery_configuration.configuration(payload.get(recovery_configuration.FIELD),
                webauthn=payload["webauthn"])
            if recovery_configuration.FIELD in payload and recovery is None:
                raise GeneratorError("explicit recovery selection is null")
            oauth_activation_policy.validate_policy(payload.get(oauth_activation_policy.FIELD), payload=payload, root_key=root_key)
            oauth_exchange_policy.validate_policy(payload.get(oauth_exchange_policy.FIELD), payload=payload, root_key=root_key)
            policy_candidate_policy.validate_policy(payload.get(policy_candidate_policy.FIELD), payload=payload, root_key=root_key)
            root_digest = None if root_key is None else "sha256:" + hashlib.sha256(root_key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            genesis_policy.configuration(payload.get(genesis_policy.FIELD), root_digest=root_digest)
            setup_policy_admission.validate_policy(payload.get(setup_policy_admission.FIELD), payload=payload, root_key=root_key)
            policy_canary_policy.validate_policy(payload.get(policy_canary_policy.FIELD), payload=payload, root_key=root_key)
            heartbeat_policy.validate_policy(payload.get(heartbeat_policy.FIELD), payload=payload, root_key=root_key)
            finalization_policy.validate_policy(payload.get(finalization_policy.FIELD), payload=payload, root_key=root_key)
            native_readiness_policy.validate_policy(payload.get(native_readiness_policy.FIELD), payload=payload, root_key=root_key)
            native_activation.validate_policy(payload.get(native_activation.FIELD), payload=payload, root_key=root_key)
            canary_delivery_policy.validate_policy(payload.get(canary_delivery_policy.FIELD), payload=payload, root_key=root_key)
            oauth_measured_exchange_policy.validate_policy(payload.get(oauth_measured_exchange_policy.FIELD), payload=payload, root_key=root_key)
            oauth_measured_setup_policy.validate_policy(payload.get(oauth_measured_setup_policy.FIELD), payload=payload, root_key=root_key)
            oauth_reconnect_policy.validate_policy(payload.get(oauth_reconnect_policy.FIELD), payload=payload, root_key=root_key)
            oauth_succession_policy.validate_policy(payload.get(oauth_succession_policy.FIELD), payload=payload, root_key=root_key)
            oauth_refresh_policy.validate_policy(payload.get(oauth_refresh_policy.FIELD), payload=payload, root_key=root_key)
            oauth_refresh_cleanup_policy.validate_policy(payload.get(oauth_refresh_cleanup_policy.FIELD), payload=payload, root_key=root_key)
            oauth_measured_refresh_policy.validate_policy(payload.get(oauth_measured_refresh_policy.FIELD), payload=payload, root_key=root_key)
            oauth_measured_cleanup_policy.validate_policy(payload.get(oauth_measured_cleanup_policy.FIELD), payload=payload, root_key=root_key)
            oauth_pending_retirement_policy.validate_policy(payload.get(oauth_pending_retirement_policy.FIELD), payload=payload, root_key=root_key)
            oauth_capture_retirement_policy.validate_policy(payload.get(oauth_capture_retirement_policy.FIELD), payload=payload, root_key=root_key)
            credential_currentness_policy.validate_policy(payload.get(credential_currentness_policy.FIELD), payload=payload, root_key=root_key)
            oauth_revocation_policy.validate_policy(payload.get(oauth_revocation_policy.FIELD), payload=payload, root_key=root_key)
        except (TypeError, ValueError) as exc:
            raise GeneratorError("authority OAuth purpose policy is invalid") from exc
    payload_bytes = canonical_json_bytes(payload)
    if expected_payload_schema == SERVICE_CONFIGURATION_PAYLOAD_SCHEMA:
        # Service configuration identity uses the service protocol's NUL
        # domain framing. Witness configuration deliberately uses artifact
        # length-prefixed domain framing; these are not interchangeable.
        digest = hashlib.sha256()
        digest.update(expected_payload_schema.encode("ascii") + b"\x00")
        digest.update(len(payload_bytes).to_bytes(8, "big"))
        digest.update(payload_bytes)
        return expected_payload_schema, "sha256:" + digest.hexdigest()
    return expected_payload_schema, domain_digest(expected_payload_schema, payload_bytes)


def _validate_required_role_manifests(
    roles: Sequence[Mapping[str, Any]],
) -> None:
    by_role = {entry["role"]: entry for entry in roles}
    for role, requirements in ROLE_REQUIREMENTS.items():
        manifest = by_role.get(role)
        if manifest is None or any(
            manifest[field] != expected
            for field, expected in requirements.items()
        ):
            raise GeneratorError(
                f"{role} role manifest or credential set is not exact"
            )


def _oci_document(
    root_fd: int,
    file_by_path: Mapping[str, Mapping[str, Any]],
    path_value: object,
    *,
    name: str,
) -> tuple[str, Mapping[str, Any], bytes]:
    path = _relative_path(path_value, name=f"{name} path")
    try:
        measured = file_by_path[path]
    except KeyError as exc:
        raise GeneratorError(
            f"{name} is outside the measured tree"
        ) from exc
    # OCI digests identify the original external encoding, not Serverware's
    # canonical JSON encoding. Match the artifact verifier's strict parser
    # without rewriting key order, whitespace or escaped string characters.
    document_bytes = _read_exact_bundle_file(
        root_fd,
        path,
        measured,
        maximum=MAX_TARGET_DOCUMENT_BYTES,
    )
    try:
        _strict_json_document(
            strict_base64url_encode(document_bytes),
            name=name,
            maximum_bytes=MAX_TARGET_DOCUMENT_BYTES,
        )
    except ArtifactContractError as exc:
        raise GeneratorError(f"{name} is not strict JSON") from exc
    return path, measured, document_bytes


def _build_bundle(
    spec: Mapping[str, Any],
    *,
    trust: Mapping[str, Any],
    validation_time: str,
    before_checkpoint: bool = False,
) -> tuple[dict[str, Any], int]:
    generation_input = _closed(
        spec["generation"],
        name="generation input",
        keys={
            "sequence", "generationId", "predecessorDigest",
            "minimumRollbackSequence", "validFrom", "validUntil",
        } | (set() if before_checkpoint else {"witnessCheckpoint"}),
    )
    generation_metadata = {
        field: generation_input[field]
        for field in (
            "generationId", "sequence", "predecessorDigest",
            "minimumRollbackSequence", "validFrom", "validUntil",
        )
    }
    generation_metadata["operationManifestDigest"] = authority_contract.OPERATION_MANIFEST_DIGEST
    generation_metadata["trustMode"] = spec["trustMode"]
    expected_generation_binding = configuration_generation_binding(generation_metadata)
    expected_generation_binding_digest = configuration_generation_binding_digest(generation_metadata)
    artifact_root = _runtime_path(
        spec["artifactRoot"], name="artifact root"
    )
    root_fd = os.open(
        artifact_root,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        root_metadata = os.fstat(root_fd)
        snapshot = spec["stableSnapshotReceipt"]
        closure = spec["closureReceipt"]
        snapshot_digest, closure_digest = _verify_snapshot_and_closure(
            snapshot,
            closure,
            trust=trust,
            validation_time=validation_time,
            trust_mode=spec["trustMode"]["mode"],
        )
        root_identity = snapshot["payload"]["rootIdentity"]
        if (
            root_identity["runtimePath"] != artifact_root
            or root_identity["device"] != root_metadata.st_dev
            or root_identity["inode"] != root_metadata.st_ino
            or root_identity["mode"] != stat.S_IMODE(root_metadata.st_mode)
            or root_identity["uid"] != root_metadata.st_uid
            or root_identity["gid"] != root_metadata.st_gid
        ):
            raise GeneratorError(
                "retained artifact-root FD differs from snapshot receipt"
            )

        file_inputs = _bounded_list(
            spec["files"],
            name="files",
            minimum=1,
            maximum=MAX_FILES,
        )
        for entry in file_inputs:
            _closed(
                entry,
                name="file input",
                keys={"path", "kind", "mode", "uid", "gid"},
            )
        _sorted_unique(
            file_inputs, name="files", key=lambda entry: entry["path"]
        )
        files = []
        total_bytes = 0
        for entry in file_inputs:
            measured = _measure_file(root_fd, entry)
            total_bytes += measured["size"]
            if total_bytes > MAX_TOTAL_BYTES:
                raise GeneratorError(
                    "artifact tree exceeds its aggregate byte limit"
                )
            files.append(measured)
        file_by_path = {entry["path"]: entry for entry in files}
        tree_digest = domain_digest(
            SOURCE_TREE_DIGEST_DOMAIN,
            canonical_json_bytes(files),
        )
        enumerated_tree_digest = domain_digest(
            ENUMERATED_TREE_DIGEST_DOMAIN,
            canonical_json_bytes(files),
        )
        snapshot_payload = snapshot["payload"]
        if (
            snapshot_payload["treeDigest"] != tree_digest
            or snapshot_payload["enumeratedTreeDigest"]
            != enumerated_tree_digest
            or snapshot_payload["treeEntryCount"] != len(files)
            or snapshot_payload["totalBytes"] != total_bytes
        ):
            raise GeneratorError(
                "native snapshot receipt does not match measured tree"
            )
        closure_payload = closure["payload"]
        if (
            closure_payload["treeDigest"] != tree_digest
            or closure_payload["treeEntryCount"] != len(files)
            or closure_payload["totalBytes"] != total_bytes
        ):
            raise GeneratorError(
                "native closure receipt does not match measured tree"
            )

        schemas = [
            _digest_reference(
                entry,
                name="schema",
                keys={"schemaId"},
                files=file_by_path,
            )
            for entry in _bounded_list(
                spec["schemas"], name="schemas", maximum=4096
            )
        ]
        _sorted_unique(
            schemas, name="schemas", key=lambda entry: entry["schemaId"]
        )
        roles = [
            _digest_reference(
                entry,
                name="role manifest",
                keys={
                    "role",
                    "runtimeUid",
                    "runtimeGid",
                    "processMode",
                    "entrypointPath",
                    "listenerName",
                    "credentialNames",
                    "cwd",
                    "pathEntries",
                    "argv",
                    "environmentAllowlist",
                    "mutableStateDescriptors",
                },
                files=file_by_path,
            )
            for entry in _bounded_list(
                spec["roleManifests"],
                name="role manifests",
                minimum=1,
                maximum=256,
            )
        ]
        _sorted_unique(
            roles, name="role manifests", key=lambda entry: entry["role"]
        )
        _validate_required_role_manifests(roles)
        expected_role_bindings = role_binding_digests(roles)
        configurations = []
        for entry in _bounded_list(
            spec["configurations"],
            name="configurations",
            minimum=1,
            maximum=4096,
        ):
            configuration = _digest_reference(
                entry,
                name="configuration",
                keys={"name", "role"},
                files=file_by_path,
            )
            payload_schema, payload_digest = _validate_configuration_document(
                root_fd,
                configuration,
                file_by_path[configuration["path"]],
                source_revision=spec["sourceRevision"],
                expected_generation_binding=expected_generation_binding,
                expected_generation_binding_digest=expected_generation_binding_digest,
                expected_role_bindings=expected_role_bindings,
            )
            configuration["payloadSchema"] = payload_schema
            configuration["payloadDigest"] = payload_digest
            configurations.append(configuration)
        _sorted_unique(
            configurations,
            name="configurations",
            key=lambda entry: (
                entry["role"],
                entry["name"],
                entry["path"],
            ),
        )
        configuration_counts = {
            role: sum(
                entry["role"] == role for entry in configurations
            )
            for role in (
                AUTHORITY_SERVICE_CONFIGURATION_ROLE,
                "witness",
            )
        }
        if any(count != 1 for count in configuration_counts.values()):
            raise GeneratorError(
                "authority service and witness configurations are not unique"
            )
        operation_manifest = _digest_reference(
            spec["operationManifest"],
            name="operation manifest",
            keys={"manifestSchema"},
            files=file_by_path,
        )
        operation_bytes, _operation_document = _canonical_json_document(
            root_fd,
            operation_manifest["path"],
            file_by_path[operation_manifest["path"]],
            name="operation contract document",
        )
        if (
            operation_manifest["manifestSchema"] != authority_contract.CONTRACT_SCHEMA
            or operation_bytes
            != canonical_json_bytes(authority_contract.operation_contract_document())
        ):
            raise GeneratorError(
                "operation manifest is not the complete canonical source contract"
            )
        # Keep the measured raw-file SHA256 in sha256. The separate semantic
        # commitment frames these actual canonical bytes with CONTRACT_SCHEMA;
        # neither input metadata nor the smaller operation-only map supplies it.
        contract_digest = domain_digest(authority_contract.CONTRACT_SCHEMA, operation_bytes)
        if contract_digest != authority_contract.OPERATION_MANIFEST_DIGEST:
            raise GeneratorError("operation manifest semantic digest differs from the source contract")
        operation_manifest["contractDigest"] = contract_digest

        migrations = []
        migration_inputs = _bounded_list(
            spec["migrations"], name="migrations", maximum=256
        )
        for raw in migration_inputs:
            entry = _closed(
                raw,
                name="migration",
                keys={
                    "name",
                    "fromVersion",
                    "toVersion",
                    "path",
                    "receiptPath",
                    "receipt",
                },
            )
            path = _relative_path(entry["path"], name="migration path")
            receipt_path = _relative_path(
                entry["receiptPath"], name="migration receipt path"
            )
            try:
                migration_file = file_by_path[path]
                receipt_file = file_by_path[receipt_path]
            except KeyError as exc:
                raise GeneratorError(
                    "migration or receipt is outside the measured tree"
                ) from exc
            receipt = _closed(
                entry["receipt"],
                name="migration receipt",
                keys={
                    "schema",
                    "payload",
                    "signerKeyId",
                    "algorithm",
                    "signatureBase64Url",
                },
            )
            receipt_payload = _closed(
                receipt["payload"],
                name="migration receipt payload",
                keys={
                    "schema",
                    "contractId",
                    "migrationName",
                    "sourceVersion",
                    "targetVersion",
                    "migrationSha256",
                    "sourceRevision",
                    "operationContractDigest",
                    "signerIdentityDigest",
                    "beforeManifestDigest",
                    "beforeRowCountsDigest",
                    "afterManifestDigest",
                    "afterRowCountsDigest",
                    "terminal",
                    "status",
                    "completedAt",
                },
            )
            _canonical_embedded_document(
                root_fd, receipt_path, receipt_file, receipt_payload
            )
            if (
                receipt["schema"] != authority_contract.MIGRATION_RECEIPT_SCHEMA
                or receipt_payload["schema"]
                != authority_contract.MIGRATION_RECEIPT_SCHEMA
                or receipt_payload["contractId"]
                != authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID
                or receipt_payload["migrationName"]
                != authority_contract.V8_TO_V9_MIGRATION_NAME
                or receipt_payload["migrationName"] != entry["name"]
                or receipt_payload["sourceVersion"] != entry["fromVersion"]
                or receipt_payload["targetVersion"] != entry["toVersion"]
                or receipt_payload["migrationSha256"]
                != migration_file["sha256"]
                or receipt_payload["sourceRevision"]
                != spec["sourceRevision"]
                or receipt_payload["operationContractDigest"]
                != operation_manifest["contractDigest"]
                or receipt_payload["terminal"] is not True
                or receipt_payload["status"] != "completed"
                or receipt["algorithm"] != "Ed25519"
            ):
                raise GeneratorError(
                    "migration receipt does not bind the measured migration"
                )
            receipt_signature = strict_base64url_decode(
                receipt["signatureBase64Url"],
                name="migration receipt signature",
                decoded_size=64,
            )
            receipt_digest = domain_digest(
                authority_contract.MIGRATION_RECEIPT_DIGEST_DOMAIN,
                canonical_json_bytes(receipt_payload),
            )
            migrations.append(
                {
                    "name": entry["name"],
                    "fromVersion": entry["fromVersion"],
                    "toVersion": entry["toVersion"],
                    "path": path,
                    "sha256": migration_file["sha256"],
                    "receiptSchema": receipt_payload["schema"],
                    "receiptPath": receipt_path,
                    "receiptDigest": receipt_digest,
                    "receiptPayload": receipt_payload,
                    "receiptSignerKeyId": receipt["signerKeyId"],
                    "receiptAlgorithm": receipt["algorithm"],
                    "receiptSignatureBase64Url": receipt[
                        "signatureBase64Url"
                    ],
                    "receiptSignatureDigest": (
                        "sha256:"
                        + hashlib.sha256(receipt_signature).hexdigest()
                    ),
                }
            )
        _sorted_unique(
            migrations,
            name="migrations",
            key=lambda entry: (
                entry["fromVersion"],
                entry["toVersion"],
                entry["name"],
            ),
        )

        sbom = _digest_reference(
            spec["sbom"],
            name="SBOM",
            keys={"format", "mediaType"},
            files=file_by_path,
        )
        provenance_input = dict(
            _closed(
                spec["provenance"],
                name="provenance",
                keys={
                    "path",
                    "predicateType",
                    "mediaType",
                    "builderId",
                    "statementDigest",
                    "signerKeyId",
                    "algorithm",
                    "signatureBase64Url",
                },
            )
        )
        provenance = _digest_reference(
            provenance_input,
            name="provenance",
            keys={
                "predicateType",
                "mediaType",
                "builderId",
                "statementDigest",
                "signerKeyId",
                "algorithm",
                "signatureBase64Url",
            },
            files=file_by_path,
        )

        oci_input = _closed(
            spec["ociImage"],
            name="OCI image",
            keys={
                "reference",
                "rootPath",
                "rootMediaType",
                "indexPath",
                "indexMediaType",
                "manifestPath",
                "manifestMediaType",
                "configPath",
                "configMediaType",
                "platform",
                "layers",
            },
        )
        root_path, root_file, root_bytes = _oci_document(
            root_fd,
            file_by_path,
            oci_input["rootPath"],
            name="OCI root descriptor",
        )
        manifest_path, manifest_file, manifest_bytes = _oci_document(
            root_fd,
            file_by_path,
            oci_input["manifestPath"],
            name="OCI manifest",
        )
        config_path, config_file, config_bytes = _oci_document(
            root_fd,
            file_by_path,
            oci_input["configPath"],
            name="OCI configuration",
        )
        index_path_value = oci_input["indexPath"]
        index_media_type_value = oci_input["indexMediaType"]
        if (index_path_value is None) != (index_media_type_value is None):
            raise GeneratorError(
                "OCI index path and media type are only partially present"
            )
        if index_path_value is None:
            index_path = None
            index_file = None
            index_bytes = None
            index_media_type = None
        else:
            index_path, index_file, index_bytes = _oci_document(
                root_fd,
                file_by_path,
                index_path_value,
                name="OCI index",
            )
            index_media_type = _ascii(
                index_media_type_value,
                name="OCI index media type",
                maximum=256,
            )
        platform = _closed(
            oci_input["platform"],
            name="OCI platform",
            keys={"os", "architecture", "variant"},
        )
        _ascii(platform["os"], name="OCI operating system", maximum=128)
        _ascii(
            platform["architecture"],
            name="OCI architecture",
            maximum=128,
        )
        if platform["variant"] is not None:
            _ascii(
                platform["variant"], name="OCI variant", maximum=128
            )
        layers = []
        for raw in _bounded_list(
            oci_input["layers"], name="OCI layers", maximum=4096
        ):
            layer = _closed(
                raw, name="OCI layer", keys={"path", "mediaType"}
            )
            path = _relative_path(layer["path"], name="OCI layer path")
            try:
                measured = file_by_path[path]
            except KeyError as exc:
                raise GeneratorError(
                    "OCI layer is outside the measured tree"
                ) from exc
            if measured["size"] < 1:
                raise GeneratorError("OCI layer is empty")
            layers.append(
                {
                    "path": path,
                    "digest": measured["sha256"],
                    "size": measured["size"],
                    "mediaType": _ascii(
                        layer["mediaType"],
                        name="OCI layer media type",
                        maximum=256,
                    ),
                }
            )
        oci = {
            "reference": _ascii(
                oci_input["reference"],
                name="OCI reference",
                maximum=512,
            ),
            "rootPath": root_path,
            "rootDigest": root_file["sha256"],
            "rootSize": root_file["size"],
            "rootMediaType": _ascii(
                oci_input["rootMediaType"],
                name="OCI root media type",
                maximum=256,
            ),
            "rootDocumentBase64Url": strict_base64url_encode(root_bytes),
            "indexPath": index_path,
            "indexDigest": (
                None if index_file is None else index_file["sha256"]
            ),
            "indexSize": None if index_file is None else index_file["size"],
            "indexMediaType": index_media_type,
            "indexDocumentBase64Url": (
                None
                if index_bytes is None
                else strict_base64url_encode(index_bytes)
            ),
            "manifestPath": manifest_path,
            "manifestDigest": manifest_file["sha256"],
            "manifestSize": manifest_file["size"],
            "manifestMediaType": _ascii(
                oci_input["manifestMediaType"],
                name="OCI manifest media type",
                maximum=256,
            ),
            "manifestDocumentBase64Url": strict_base64url_encode(
                manifest_bytes
            ),
            "configPath": config_path,
            "configDigest": config_file["sha256"],
            "configSize": config_file["size"],
            "configMediaType": _ascii(
                oci_input["configMediaType"],
                name="OCI configuration media type",
                maximum=256,
            ),
            "configDocumentBase64Url": strict_base64url_encode(config_bytes),
            "platform": platform,
            "layers": layers,
        }
        if index_path is None and (
            root_path,
            root_file["sha256"],
            root_file["size"],
            root_bytes,
        ) != (
            manifest_path,
            manifest_file["sha256"],
            manifest_file["size"],
            manifest_bytes,
        ):
            raise GeneratorError(
                "OCI root must be the manifest when no index is present"
            )
        if index_path is not None and (
            root_path,
            root_file["sha256"],
            root_file["size"],
            root_bytes,
        ) != (
            index_path,
            index_file["sha256"],
            index_file["size"],
            index_bytes,
        ):
            raise GeneratorError(
                "OCI root must be the exact selected index"
            )
        provenance["sourceRevision"] = spec["sourceRevision"]
        provenance["sourceCommitDigest"] = spec["sourceCommitDigest"]
        provenance["sourceTreeDigest"] = tree_digest
        provenance["ociRootDigest"] = oci["rootDigest"]

        stage_zero = dict(closure_payload["stageZero"])
        if (stage_zero["interfaceSchema"] == LOCAL_STAGE_ZERO_INTERFACE_SCHEMA
                and spec["trustMode"]["mode"] != "trusted-host-local"):
            raise GeneratorError("Python bootstrap evidence requires explicit trusted-host-local selection")
        bundle = {
            "schema": ARTIFACT_BUNDLE_SCHEMA,
            "bundleVersion": 1,
            "authoritySchemaVersion": AUTHORITY_SCHEMA_VERSION,
            "sourceRevision": spec["sourceRevision"],
            "sourceCommitDigest": spec["sourceCommitDigest"],
            "trustMode": spec["trustMode"],
            "sourceTree": {
                "algorithm": "canonical-path-tree-sha256-v1",
                "digest": tree_digest,
                "entryCount": len(files),
                "snapshotKind": snapshot_payload["snapshotKind"],
                "snapshotIdentityDigest": domain_digest(
                    "serverware.authoritySnapshotRootIdentity/v1",
                    canonical_json_bytes(root_identity),
                ),
                "readOnly": True,
            },
            "stableSnapshotReceipt": snapshot,
            "closureReceipt": closure,
            "files": files,
            "pythonImportClosure": closure_payload[
                "pythonImportClosure"
            ],
            "nativeClosure": closure_payload["nativeClosure"],
            "schemas": schemas,
            "migrations": migrations,
            "configurations": configurations,
            "roleManifests": roles,
            "sbom": sbom,
            "provenance": provenance,
            "ociImage": oci,
            "stageZero": stage_zero,
            "operationManifest": operation_manifest,
        }
        if (
            snapshot_digest != snapshot_receipt_digest(snapshot)
            or closure_digest != closure_receipt_digest(closure)
        ):
            raise GeneratorError("evidence digest changed during generation")
        return bundle, root_fd
    except Exception:
        os.close(root_fd)
        raise


def _generation_core(value: Mapping[str, Any], bundle: Mapping[str, Any]) -> dict[str, Any]:
    """One derivation shared by pre-checkpoint preparation and final assembly."""
    intent = value["generation"]
    material = value["trustMaterial"]
    core = {
        "schema": GENERATION_STATEMENT_SCHEMA,
        "sequence": intent["sequence"],
        "generationId": intent["generationId"],
        "predecessorDigest": intent["predecessorDigest"],
        "minimumRollbackSequence": intent["minimumRollbackSequence"],
        "validFrom": intent["validFrom"],
        "validUntil": intent["validUntil"],
        "artifactBundleDigest": artifact_bundle_digest(bundle),
        "operationManifestDigest": bundle["operationManifest"]["contractDigest"],
        "stageZeroDigest": bundle["stageZero"]["sha256"],
        "stageZeroContract": bundle["stageZero"]["interfaceSchema"],
        "roleSetDigest": domain_digest(ROLE_SET_DIGEST_DOMAIN, canonical_json_bytes(bundle["roleManifests"])),
        "snapshotReceiptDigest": snapshot_receipt_digest(bundle["stableSnapshotReceipt"]),
        "closureReceiptDigest": closure_receipt_digest(bundle["closureReceipt"]),
        "provenanceStatementDigest": bundle["provenance"]["statementDigest"],
        "sourceTreeDigest": bundle["sourceTree"]["digest"],
        "ociManifestDigest": bundle["ociImage"]["rootDigest"],
        "migrationReceiptDigests": sorted(row["receiptDigest"] for row in bundle["migrations"]),
        "roleManifestDigests": sorted(row["sha256"] for row in bundle["roleManifests"]),
        "configurationDigests": sorted(row["sha256"] for row in bundle["configurations"]),
        "configurationPayloadBindings": configuration_payload_bindings(bundle["configurations"]),
        "keyAuthorizationsDigest": trust_document_digest(material["keyAuthorizations"]),
        "keyRevocationsDigest": trust_document_digest(material["keyRevocations"]),
        "trustMode": value["trustMode"],
    }
    validate_generation_core(core)
    return core


def prepare_local_generation_core(
    spec: Mapping[str, Any], *, trust_state: Mapping[str, Any], validation_time: str,
) -> dict[str, Any]:
    """Measure/authenticate the existing local input before a real witness append.

    The input is the existing generator selection with the checkpoint field
    absent, not null or replaced by a fabricated envelope. This produces public
    data, not a package, approval, checkpoint or trust-state advance.
    """
    value = _closed(spec, name="generator input", keys=INPUT_FIELDS)
    if (value["schema"] != INPUT_SCHEMA
            or value["authoritySchemaVersion"] != AUTHORITY_SCHEMA_VERSION
            or value["sourceRevision"] != authority_contract.SOURCE_REVISION):
        raise GeneratorError("generator source contract changed")
    if value["trustMode"] != {
        "mode": "trusted-host-local", "hardwareBacked": False,
        "externalWitnessRequired": False, "teeQuoteRequired": False,
        "imaAppraisalRequired": False,
    }:
        raise GeneratorError("core preparation is only for explicit trusted-host-local")
    _digest(value["sourceCommitDigest"], name="source commit digest")
    _require_timestamp(validation_time, name="core preparation time")
    intent = _closed(value["generation"], name="pre-checkpoint generation input", keys={
        "sequence", "generationId", "predecessorDigest", "minimumRollbackSequence", "validFrom", "validUntil",
    })
    trust = validate_trust_state(trust_state)
    if (type(intent["sequence"]) is not int
            or intent["sequence"] != trust["currentSequence"] + 1
            or intent["predecessorDigest"] != trust["currentGenerationDigest"]
            or type(intent["minimumRollbackSequence"]) is not int
            or intent["minimumRollbackSequence"] < trust["minimumRollbackSequence"]):
        raise GeneratorError("core is not the next admitted trust-state generation")
    _require_timestamp(intent["validFrom"], name="generation validFrom")
    _require_timestamp(intent["validUntil"], name="generation validUntil")
    if not intent["validFrom"] <= validation_time < intent["validUntil"]:
        raise GeneratorError("core preparation is outside the original generation interval")
    bundle, retained_root_fd = _build_bundle(value, trust=trust, validation_time=validation_time, before_checkpoint=True)
    try:
        if bundle["stageZero"]["interfaceSchema"] != LOCAL_STAGE_ZERO_INTERFACE_SCHEMA:
            raise GeneratorError("core preparation requires the local Python bootstrap")
        core = _generation_core(value, bundle)
        _verify_key_documents(value["trustMaterial"], bundle=bundle, generation=core,
                              trust_state=trust, validation_time=validation_time)
        return core
    finally:
        os.close(retained_root_fd)


def _build_package(
    spec: Mapping[str, Any],
    *,
    trust_state: Mapping[str, Any],
    validation_time: str,
) -> dict[str, Any]:
    value = _closed(
        spec,
        name="generator input",
        keys=INPUT_FIELDS,
    )
    if value["schema"] != INPUT_SCHEMA:
        raise GeneratorError("generator input schema changed")
    if value["authoritySchemaVersion"] != AUTHORITY_SCHEMA_VERSION:
        raise GeneratorError("authority schema version changed")
    if value["sourceRevision"] != authority_contract.SOURCE_REVISION:
        raise GeneratorError("authority source revision changed")
    _digest(value["sourceCommitDigest"], name="source commit digest")
    trust = validate_trust_state(trust_state)
    bundle, retained_root_fd = _build_bundle(
        value, trust=trust, validation_time=validation_time
    )
    try:
        generation_input = _closed(
            value["generation"],
            name="generation input",
            keys={
                "sequence",
                "generationId",
                "predecessorDigest",
                "minimumRollbackSequence",
                "validFrom",
                "validUntil",
                "witnessCheckpoint",
            },
        )
        trust_mode = _closed(
            value["trustMode"],
            name="trust mode",
            keys={
                "mode",
                "hardwareBacked",
                "externalWitnessRequired",
                "teeQuoteRequired",
                "imaAppraisalRequired",
            },
        )
        checkpoint = _closed(
            generation_input["witnessCheckpoint"],
            name="witness checkpoint",
            keys={
                "schema",
                "payload",
                "signerKeyId",
                "algorithm",
                "signatureBase64Url",
            },
        )
        checkpoint_payload = checkpoint["payload"]
        if (
            trust_mode["mode"] == "trusted-host-local"
            and (
                not isinstance(checkpoint_payload, Mapping)
                or checkpoint_payload.get("coLocated") is not True
                or checkpoint_payload.get("hardwareBacked") is not False
            )
        ):
            raise GeneratorError(
                "trusted-host-local witness assurance is not co-located"
            )
        material = _closed(
            value["trustMaterial"],
            name="trust material",
            keys={"keyAuthorizations", "keyRevocations"},
        )
        for name, expected_schema in (
            ("keyAuthorizations", KEY_AUTHORIZATION_SCHEMA),
            ("keyRevocations", KEY_REVOCATION_SCHEMA),
        ):
            document = _closed(
                material[name],
                name=name,
                keys={
                    "schema",
                    "payload",
                    "signerKeyId",
                    "algorithm",
                    "signatureBase64Url",
                },
            )
            if document["schema"] != expected_schema:
                raise GeneratorError(f"{name} schema changed")
        generation = dict(_generation_core(value, bundle),
                          witnessCheckpoint=generation_input["witnessCheckpoint"])
        signing_keys = _closed(
            value["signingKeys"],
            name="signing keys",
            keys={"artifactBundleKeyId", "generationKeyId"},
        )
        requests = []
        for purpose, key_field in (
            ("artifact-bundle", "artifactBundleKeyId"),
            ("generation", "generationKeyId"),
        ):
            message = package_signature_message(purpose, bundle, generation)
            requests.append(
                {
                    "purpose": purpose,
                    "algorithm": "Ed25519",
                    "keyId": signing_keys[key_field],
                    "messageBase64Url": strict_base64url_encode(message),
                }
            )
        package = {
            "schema": UNSIGNED_PACKAGE_SCHEMA,
            "bundle": bundle,
            "generation": generation,
            "trustMaterial": material,
            "signatureRequests": requests,
        }
        validate_unsigned_artifact_package(package)
        return package
    finally:
        os.close(retained_root_fd)


def _atomic_write(path: str, data: bytes) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    name = os.path.basename(path)
    if not name or name in {".", ".."}:
        raise GeneratorError("output path has no canonical filename")
    parent_fd = os.open(
        parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    temporary = f".{name}.tmp.{os.getpid()}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise GeneratorError("package write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(parent_fd)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a deterministic unsigned authority artifact package "
            "from native-verifier signed snapshot and closure receipts."
        )
    )
    parser.add_argument("--spec", required=True)
    parser.add_argument("--trust-state", required=True)
    parser.add_argument("--validation-time", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)
    spec = _read_json(arguments.spec, maximum=MAX_INPUT_BYTES)
    trust_state = _read_json(
        arguments.trust_state, maximum=MAX_INPUT_BYTES
    )
    package = _build_package(
        spec,
        trust_state=trust_state,
        validation_time=arguments.validation_time,
    )
    _atomic_write(
        arguments.output,
        canonical_json_bytes(package) + b"\n",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ArtifactContractError, GeneratorError, OSError) as exc:
        print(f"authority artifact generation failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
