from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from serverware import authority_contract

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # The contract fails closed when crypto is unavailable.
    InvalidSignature = None
    serialization = None
    Ed25519PrivateKey = None
    Ed25519PublicKey = None


ARTIFACT_BUNDLE_SCHEMA = "serverware.authorityArtifactBundle/v6"
GENERATION_STATEMENT_SCHEMA = "serverware.authorityGenerationStatement/v6"
SIGNED_PACKAGE_SCHEMA = "serverware.signedAuthorityArtifactPackage/v6"
UNSIGNED_PACKAGE_SCHEMA = "serverware.unsignedAuthorityArtifactPackage/v6"
ROLE_BINDING_DOMAIN = "serverware.authorityRoleBinding/v1"
ROLE_RUNTIME_CLOSURE_SCHEMA = "serverware.policyAuthorityRoleRuntimeClosure/v1"
CONFIGURATION_GENERATION_BINDING_SCHEMA = (
    "serverware.authorityConfigurationGenerationBinding/v1"
)
CONFIGURATION_PAYLOAD_SCHEMAS = MappingProxyType(
    {
        "authority-service": "serverware.policyAuthorityServiceConfiguration/v4",
        "witness": "serverware.policyAuthorityReplayWitnessConfiguration/v4",
    }
)
KEY_AUTHORIZATION_SCHEMA = "serverware.authorityKeyAuthorizations/v1"
KEY_REVOCATION_SCHEMA = "serverware.authorityKeyRevocations/v1"
TRUST_STATE_SCHEMA = "serverware.authorityArtifactTrustState/v1"
SNAPSHOT_RECEIPT_SCHEMA = "serverware.authorityStableSnapshotReceipt/v1"
CLOSURE_RECEIPT_SCHEMA = "serverware.authorityCompleteClosureReceipt/v1"
PROVENANCE_STATEMENT_SCHEMA = (
    "serverware.authoritySupplyChainProvenanceStatement/v2"
)
PROVENANCE_PAYLOAD_DIGEST_DOMAIN = (
    "serverware.authoritySupplyChainProvenancePayload/v2"
)
PROVENANCE_SIGNATURE_DOMAIN = (
    "serverware.authoritySupplyChainProvenanceSignature/v2"
)
ARTIFACT_BUNDLE_DIGEST_DOMAIN = (
    "serverware.authorityArtifactBundleDigest/v1"
)
GENERATION_DIGEST_DOMAIN = "serverware.authorityGenerationDigest/v1"
PACKAGE_SIGNATURE_DOMAIN = "serverware.authorityArtifactPackageSignature/v1"
SIGNED_PACKAGE_DIGEST_DOMAIN = (
    "serverware.authoritySignedArtifactPackageDigest/v1"
)
SOURCE_TREE_DIGEST_DOMAIN = "serverware.authoritySourceTree/v1"
KEY_AUTHORIZATION_SIGNATURE_DOMAIN = (
    "serverware.authorityKeyAuthorizationsSignature/v1"
)
KEY_REVOCATION_SIGNATURE_DOMAIN = (
    "serverware.authorityKeyRevocationsSignature/v1"
)
TRUST_DOCUMENT_DIGEST_DOMAIN = "serverware.authorityTrustDocumentDigest/v1"
GENERATION_CORE_DIGEST_DOMAIN = "serverware.authorityGenerationCoreDigest/v1"
WITNESS_LEAF_DIGEST_DOMAIN = "serverware.authorityWitnessLeaf/v1"
WITNESS_CHAIN_ROOT_DOMAIN = "serverware.authorityWitnessChainRoot/v1"
WITNESS_CHECKPOINT_SIGNATURE_DOMAIN = (
    "serverware.authorityWitnessCheckpointSignature/v1"
)
WITNESS_CHECKPOINT_DIGEST_DOMAIN = (
    "serverware.authorityWitnessCheckpointDigest/v1"
)
AUTHORITY_SCHEMA_VERSION = 9
MAX_BUNDLE_FILES = 32768
MAX_IMPORTS = 16384
MAX_NATIVE_OBJECTS = 8192
MAX_SCHEMAS = 4096
MAX_MIGRATIONS = 256
MAX_ROLE_MANIFESTS = 256
MAX_LAYER_DIGESTS = 4096
MAX_CONFIGURATION_DIGESTS = 4096
MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOTAL_BUNDLE_BYTES = 64 * 1024 * 1024 * 1024
TRUST_MODES = frozenset(
    {"trusted-host-local", "external-production", "tee-hardware"}
)
ALLOWED_MUTABLE_STATE_PROTOCOLS = frozenset(
    {
        (
            "append-canonical-record-fdatasync-renameat2-noreplace-"
            "fsyncdir-v1"
        ),
    }
)
FILE_KINDS = frozenset(
    {
        "authority-source",
        "authority-bytecode",
        "configuration",
        "data",
        "elf-executable",
        "elf-shared-object",
        "migration",
        "native-stage-zero",
        "operation-manifest",
        "provenance",
        "python-extension",
        "role-manifest",
        "sbom",
        "schema",
    }
)
SIGNATURE_PURPOSES = frozenset({"artifact-bundle", "generation"})
KEY_PURPOSES = frozenset(
    {
        "artifact-bundle",
        "generation",
        "trust-document",
        "stable-snapshot-verifier",
        "closure-verifier",
        "artifact-verifier",
        "artifact-provisioner",
        "provisioning-reconciler",
        "provisioning-cleanup",
        "launch-certificate-issuer",
        "migration-receipt",
        "provenance",
        "witness-checkpoint",
    }
)
EXTERNAL_SECURITY_PREREQUISITES = (
    "A reviewed native static stage-zero binary implementing the interface.",
    "Generation, role, and launch-certificate keys held in an HSM, TPM, or "
    "equivalent independently protected signing boundary.",
    "An independently operated monotonic rollback witness for production.",
    "Verified boot with enforcing IMA/EVM or equivalent measured execution "
    "when external-production trust is claimed.",
    "TEE quote, endorsement, freshness, revocation, and secret-release "
    "verification when tee-hardware trust is claimed.",
    "Digest-pinned OCI publication, SBOM, provenance, migration receipts, "
    "and complete Python and native closure analysis.",
)


class ArtifactContractError(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedAuthorityKey:
    key_id: str
    purposes: frozenset[str]
    public_key: bytes
    key_file_path: str
    key_file_sha256: str
    authorization_digest: str
    not_before: str
    not_after: str


@dataclass(frozen=True)
class VerifiedArtifactPackage:
    package_digest: str
    artifact_bundle_digest: str
    generation_digest: str
    generation_sequence: int
    predecessor_digest: str | None
    minimum_rollback_sequence: int
    trust_mode: str
    operation_manifest_digest: str
    stage_zero_digest: str
    stage_zero_contract: str
    role_set_digest: str
    key_authorizations_digest: str
    key_revocations_digest: str
    witness_checkpoint_digest: str
    witness_root_digest: str
    witness_tree_size: int
    disposition: str
    keys: Mapping[str, VerifiedAuthorityKey]
    revoked_key_ids: frozenset[str]
    package: Mapping[str, Any]

    def require_key(
        self,
        key_id: str,
        purpose: str,
        *,
        at: str,
    ) -> VerifiedAuthorityKey:
        if purpose not in KEY_PURPOSES:
            raise ArtifactContractError("key purpose is not recognized")
        try:
            key = self.keys[key_id]
        except KeyError as exc:
            raise ArtifactContractError(
                "signing key is not generation-authorized"
            ) from exc
        if (
            purpose not in key.purposes
            or key_id in self.revoked_key_ids
            or not key.not_before <= at <= key.not_after
        ):
            raise ArtifactContractError(
                "signing key is unauthorized, revoked, or outside validity"
            )
        return key


def strict_base64url_decode(
    value: object,
    *,
    name: str,
    decoded_size: int | None = None,
    maximum_decoded_size: int | None = None,
) -> bytes:
    if not isinstance(value, str) or not value or not value.isascii():
        raise ArtifactContractError(f"{name} is not base64url")
    if "=" in value or any(
        character
        not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise ArtifactContractError(
            f"{name} is not strict unpadded base64url"
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ArtifactContractError(f"{name} is not base64url") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ArtifactContractError(f"{name} is not canonical base64url")
    if decoded_size is not None and len(decoded) != decoded_size:
        raise ArtifactContractError(f"{name} has the wrong size")
    if (
        maximum_decoded_size is not None
        and len(decoded) > maximum_decoded_size
    ):
        raise ArtifactContractError(f"{name} exceeds its size limit")
    return decoded


def strict_base64url_encode(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise ArtifactContractError("base64url input must be bytes")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _strict_json_document(
    value: object,
    *,
    name: str,
    maximum_bytes: int,
) -> tuple[bytes, Mapping[str, Any]]:
    encoded = strict_base64url_decode(
        value,
        name=f"{name} bytes",
        maximum_decoded_size=maximum_bytes,
    )

    def reject_duplicate_pairs(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ArtifactContractError(
                    f"{name} contains a duplicate JSON member"
                )
            result[key] = item
        return result

    def reject_constant(constant: str) -> None:
        raise ArtifactContractError(
            f"{name} contains non-finite JSON number {constant}"
        )

    try:
        parsed = json.loads(
            encoded,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ArtifactContractError,
    ) as exc:
        if isinstance(exc, ArtifactContractError):
            raise
        raise ArtifactContractError(f"{name} is not strict JSON") from exc
    if not isinstance(parsed, dict):
        raise ArtifactContractError(f"{name} root is not an object")
    return encoded, parsed


def ed25519_public_key_from_seed(seed: bytes) -> bytes:
    if Ed25519PrivateKey is None or serialization is None:
        raise ArtifactContractError(
            "cryptography Ed25519 support is unavailable"
        )
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ArtifactContractError("Ed25519 seed must be 32 bytes")
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def verify_ed25519_signature(
    public_key: bytes,
    signature_base64url: object,
    message: bytes,
    *,
    name: str,
) -> None:
    if Ed25519PublicKey is None or InvalidSignature is None:
        raise ArtifactContractError(
            "cryptography Ed25519 support is unavailable"
        )
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ArtifactContractError(f"{name} public key has the wrong size")
    if not isinstance(message, bytes):
        raise ArtifactContractError(f"{name} message is not bytes")
    signature = strict_base64url_decode(
        signature_base64url,
        name=f"{name} signature",
        decoded_size=64,
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, message
        )
    except (InvalidSignature, ValueError) as exc:
        raise ArtifactContractError(
            f"{name} signature verification failed"
        ) from exc


def canonical_json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactContractError("value is not canonical JSON") from exc
    return encoded.encode("ascii")


def domain_digest(domain: str, *frames: bytes) -> str:
    if not isinstance(domain, str) or not domain.isascii() or not domain:
        raise ArtifactContractError("digest domain must be nonempty ASCII")
    digest = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    digest.update(len(encoded_domain).to_bytes(8, "big"))
    digest.update(encoded_domain)
    for frame in frames:
        if not isinstance(frame, bytes):
            raise ArtifactContractError("digest frames must be bytes")
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def artifact_bundle_digest(bundle: Mapping[str, Any]) -> str:
    validate_artifact_bundle(bundle)
    return domain_digest(
        ARTIFACT_BUNDLE_DIGEST_DOMAIN,
        canonical_json_bytes(bundle),
    )


def generation_statement_digest(statement: Mapping[str, Any]) -> str:
    validate_generation_statement(statement)
    return domain_digest(
        GENERATION_DIGEST_DOMAIN,
        canonical_json_bytes(statement),
    )


def signed_artifact_package_digest(package: Mapping[str, Any]) -> str:
    validate_signed_artifact_package(package)
    return domain_digest(
        SIGNED_PACKAGE_DIGEST_DOMAIN,
        canonical_json_bytes(package),
    )


def package_signature_message(
    purpose: str,
    bundle: Mapping[str, Any],
    generation: Mapping[str, Any],
) -> bytes:
    if purpose not in SIGNATURE_PURPOSES:
        raise ArtifactContractError("signature purpose is not recognized")
    validate_artifact_bundle(bundle)
    validate_generation_statement(
        generation,
        expected_bundle_digest=artifact_bundle_digest(bundle),
    )
    bound = {
        "schema": SIGNED_PACKAGE_SCHEMA,
        "purpose": purpose,
        "artifactBundleDigest": artifact_bundle_digest(bundle),
        "generationDigest": generation_statement_digest(generation),
    }
    return domain_digest(
        PACKAGE_SIGNATURE_DOMAIN,
        canonical_json_bytes(bound),
    ).encode("ascii")


def _require_mapping(
    value: object,
    *,
    name: str,
    keys: set[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ArtifactContractError(f"{name} is not a closed object")
    if any(not isinstance(key, str) for key in value):
        raise ArtifactContractError(f"{name} has a non-string key")
    return value


def _require_list(
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
        raise ArtifactContractError(f"{name} has an invalid item count")
    return value


def _require_ascii(
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
        raise ArtifactContractError(f"{name} must be bounded ASCII")
    return value


def _require_identifier(value: object, *, name: str) -> str:
    text = _require_ascii(value, name=name, maximum=256)
    if (
        text[0]
        not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        or any(
            character
            not in (
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789._-:/"
            )
            for character in text
        )
    ):
        raise ArtifactContractError(f"{name} is not a canonical identifier")
    return text


def _require_int(
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
        raise ArtifactContractError(f"{name} is outside its integer bound")
    return value


def _require_digest(value: object, *, name: str) -> str:
    text = _require_ascii(value, name=name, maximum=71)
    if (
        len(text) != 71
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise ArtifactContractError(f"{name} is not a SHA-256 digest")
    return text


def _require_relative_path(value: object, *, name: str) -> str:
    text = _require_ascii(value, name=name, maximum=4096)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or text != path.as_posix()
        or text in {".", ".."}
        or any(part in {"", ".", ".."} for part in path.parts)
        or text.startswith("-")
    ):
        raise ArtifactContractError(f"{name} is not a canonical relative path")
    return text


def _require_runtime_path(value: object, *, name: str) -> str:
    text = _require_ascii(value, name=name, maximum=4096)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or text != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ArtifactContractError(f"{name} is not a canonical runtime path")
    return text


def _require_timestamp(value: object, *, name: str) -> datetime:
    text = _require_ascii(value, name=name, maximum=64)
    if not text.endswith("Z"):
        raise ArtifactContractError(f"{name} must be UTC with a Z suffix")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ArtifactContractError(f"{name} is not RFC3339") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond != 0:
        raise ArtifactContractError(
            f"{name} must be whole-second canonical UTC"
        )
    if text != parsed.strftime("%Y-%m-%dT%H:%M:%SZ"):
        raise ArtifactContractError(f"{name} is not canonical RFC3339")
    return parsed


def _require_sorted_unique(
    values: Sequence[Any],
    *,
    name: str,
    key,
) -> None:
    observed = [key(item) for item in values]
    if observed != sorted(observed) or len(observed) != len(set(observed)):
        raise ArtifactContractError(f"{name} is not sorted and unique")


def _signature_message(domain: str, payload: Mapping[str, Any]) -> bytes:
    return domain_digest(domain, canonical_json_bytes(payload)).encode("ascii")


def trust_document_digest(document: Mapping[str, Any]) -> str:
    return domain_digest(
        TRUST_DOCUMENT_DIGEST_DOMAIN,
        canonical_json_bytes(document),
    )


def generation_core_digest(statement: Mapping[str, Any]) -> str:
    value = dict(statement)
    checkpoint = value.pop("witnessCheckpoint", None)
    if checkpoint is None:
        raise ArtifactContractError(
            "generation statement has no witness checkpoint"
        )
    return domain_digest(
        GENERATION_CORE_DIGEST_DOMAIN,
        canonical_json_bytes(value),
    )


def witness_checkpoint_digest(checkpoint: Mapping[str, Any]) -> str:
    value = _require_mapping(
        checkpoint,
        name="witness checkpoint",
        keys={
            "schema",
            "payload",
            "signerKeyId",
            "algorithm",
            "signatureBase64Url",
        },
    )
    return domain_digest(
        WITNESS_CHECKPOINT_DIGEST_DOMAIN,
        canonical_json_bytes(value),
    )


def _validate_external_trust_key(
    value: object,
    *,
    name: str,
) -> VerifiedAuthorityKey:
    entry = _require_mapping(
        value,
        name=name,
        keys={
            "keyId",
            "purposes",
            "publicKeyBase64Url",
            "keyFileSha256",
            "authorizationDigest",
            "notBefore",
            "notAfter",
        },
    )
    key_id = _require_identifier(entry["keyId"], name=f"{name} key ID")
    purposes = _require_list(
        entry["purposes"], name=f"{name} purposes", maximum=len(KEY_PURPOSES)
    )
    if (
        list(purposes) != sorted(set(purposes))
        or any(purpose not in KEY_PURPOSES for purpose in purposes)
    ):
        raise ArtifactContractError(
            f"{name} purposes are not closed and canonical"
        )
    public_key = strict_base64url_decode(
        entry["publicKeyBase64Url"],
        name=f"{name} public key",
        decoded_size=32,
    )
    key_file_sha256 = _require_digest(
        entry["keyFileSha256"], name=f"{name} key file digest"
    )
    if key_file_sha256 != "sha256:" + hashlib.sha256(public_key).hexdigest():
        raise ArtifactContractError(
            f"{name} public key does not match its exact key file"
        )
    authorization_digest = _require_digest(
        entry["authorizationDigest"],
        name=f"{name} authorization digest",
    )
    not_before = _require_ascii(
        entry["notBefore"], name=f"{name} notBefore", maximum=64
    )
    not_after = _require_ascii(
        entry["notAfter"], name=f"{name} notAfter", maximum=64
    )
    if _require_timestamp(
        not_after, name=f"{name} notAfter"
    ) <= _require_timestamp(not_before, name=f"{name} notBefore"):
        raise ArtifactContractError(f"{name} validity is not increasing")
    return VerifiedAuthorityKey(
        key_id=key_id,
        purposes=frozenset(purposes),
        public_key=public_key,
        key_file_path="",
        key_file_sha256=key_file_sha256,
        authorization_digest=authorization_digest,
        not_before=not_before,
        not_after=not_after,
    )


def validate_trust_state(state: Mapping[str, Any]) -> dict[str, Any]:
    value = _require_mapping(
        state,
        name="artifact trust state",
        keys={
            "schema",
            "currentGenerationSequence",
            "currentGenerationDigest",
            "currentPackageDigest",
            "minimumRollbackSequence",
            "acceptedPackageDigests",
            "acceptedGenerationDigests",
            "acceptedEvidenceDigests",
            "rootKeys",
            "currentKeys",
            "revokedKeyIds",
            "witness",
        },
    )
    if value["schema"] != TRUST_STATE_SCHEMA:
        raise ArtifactContractError("artifact trust-state schema changed")
    current_sequence = _require_int(
        value["currentGenerationSequence"],
        name="current generation sequence",
        minimum=-1,
        maximum=2**63 - 1,
    )
    if current_sequence == -1:
        if (
            value["currentGenerationDigest"] is not None
            or value["currentPackageDigest"] is not None
        ):
            raise ArtifactContractError(
                "genesis trust state carries a current generation"
            )
    else:
        _require_digest(
            value["currentGenerationDigest"],
            name="current generation digest",
        )
        _require_digest(
            value["currentPackageDigest"], name="current package digest"
        )
    rollback_floor = _require_int(
        value["minimumRollbackSequence"],
        name="trust-state rollback floor",
        minimum=0,
        maximum=2**63 - 1,
    )
    if current_sequence >= 0 and rollback_floor > current_sequence:
        raise ArtifactContractError(
            "trust-state rollback floor exceeds current generation"
        )
    accepted_packages = _require_list(
        value["acceptedPackageDigests"],
        name="accepted package digests",
        maximum=65536,
    )
    accepted_generations = _require_list(
        value["acceptedGenerationDigests"],
        name="accepted generation digests",
        maximum=65536,
    )
    accepted_evidence = _require_list(
        value["acceptedEvidenceDigests"],
        name="accepted evidence digests",
        maximum=262144,
    )
    for digest in [
        *accepted_packages,
        *accepted_generations,
        *accepted_evidence,
    ]:
        _require_digest(digest, name="accepted digest")
    if (
        list(accepted_packages) != sorted(set(accepted_packages))
        or list(accepted_generations)
        != sorted(set(accepted_generations))
        or list(accepted_evidence) != sorted(set(accepted_evidence))
    ):
        raise ArtifactContractError(
            "accepted replay sets are not sorted and unique"
        )
    if current_sequence >= 0 and (
        value["currentPackageDigest"] not in accepted_packages
        or value["currentGenerationDigest"] not in accepted_generations
    ):
        raise ArtifactContractError(
            "trust-state high-water is absent from its replay ledger"
        )
    root_entries = _require_list(
        value["rootKeys"], name="root keys", minimum=1, maximum=64
    )
    root_keys = {
        key.key_id: key
        for key in (
            _validate_external_trust_key(entry, name="root key")
            for entry in root_entries
        )
    }
    if len(root_keys) != len(root_entries) or list(root_keys) != sorted(
        root_keys
    ):
        raise ArtifactContractError("root keys are not sorted and unique")
    if not any("trust-document" in key.purposes for key in root_keys.values()):
        raise ArtifactContractError(
            "trust state has no trust-document authority"
        )
    current_entries = _require_list(
        value["currentKeys"],
        name="current generation keys",
        maximum=4096,
    )
    current_keys = {
        key.key_id: key
        for key in (
            _validate_external_trust_key(
                entry, name="current generation key"
            )
            for entry in current_entries
        )
    }
    if len(current_keys) != len(current_entries) or list(
        current_keys
    ) != sorted(current_keys):
        raise ArtifactContractError(
            "current generation keys are not sorted and unique"
        )
    revoked = _require_list(
        value["revokedKeyIds"],
        name="trust-state revoked keys",
        maximum=65536,
    )
    for key_id in revoked:
        _require_identifier(key_id, name="revoked key ID")
    if list(revoked) != sorted(set(revoked)):
        raise ArtifactContractError(
            "trust-state revocations are not sorted and unique"
        )
    witness = _require_mapping(
        value["witness"],
        name="trust-state witness",
        keys={
            "identity",
            "keyId",
            "publicKeyBase64Url",
            "keyFileSha256",
            "authorizationDigest",
            "currentSequence",
            "currentCheckpointDigest",
            "currentRootDigest",
            "currentTreeSize",
        },
    )
    _require_identifier(witness["identity"], name="witness identity")
    witness_key_id = _require_identifier(
        witness["keyId"], name="witness key ID"
    )
    witness_public_key = strict_base64url_decode(
        witness["publicKeyBase64Url"],
        name="witness public key",
        decoded_size=32,
    )
    witness_key_digest = _require_digest(
        witness["keyFileSha256"], name="witness key file digest"
    )
    if witness_key_digest != (
        "sha256:" + hashlib.sha256(witness_public_key).hexdigest()
    ):
        raise ArtifactContractError(
            "witness public key does not match its key file"
        )
    _require_digest(
        witness["authorizationDigest"],
        name="witness authorization digest",
    )
    witness_sequence = _require_int(
        witness["currentSequence"],
        name="witness current sequence",
        minimum=-1,
        maximum=2**63 - 1,
    )
    tree_size = _require_int(
        witness["currentTreeSize"],
        name="witness tree size",
        minimum=0,
        maximum=2**63 - 1,
    )
    for field in ("currentCheckpointDigest", "currentRootDigest"):
        _require_digest(witness[field], name=f"witness {field}")
    if witness_sequence != current_sequence or tree_size != current_sequence + 1:
        raise ArtifactContractError(
            "witness and generation high-water disagree"
        )
    return {
        "currentSequence": current_sequence,
        "currentGenerationDigest": value["currentGenerationDigest"],
        "currentPackageDigest": value["currentPackageDigest"],
        "minimumRollbackSequence": rollback_floor,
        "acceptedPackageDigests": frozenset(accepted_packages),
        "acceptedGenerationDigests": frozenset(accepted_generations),
        "acceptedEvidenceDigests": frozenset(accepted_evidence),
        "rootKeys": root_keys,
        "currentKeys": current_keys,
        "revokedKeyIds": frozenset(revoked),
        "witness": {
            **dict(witness),
            "publicKey": witness_public_key,
            "keyId": witness_key_id,
            "currentTreeSize": tree_size,
        },
    }


def _validate_signed_trust_document(
    document: Mapping[str, Any],
    *,
    expected_schema: str,
    signature_domain: str,
    trust_state: Mapping[str, Any],
    validation_time: str,
) -> Mapping[str, Any]:
    envelope = _require_mapping(
        document,
        name="signed trust document",
        keys={
            "schema",
            "payload",
            "signerKeyId",
            "algorithm",
            "signatureBase64Url",
        },
    )
    if envelope["schema"] != expected_schema:
        raise ArtifactContractError("trust-document schema changed")
    if envelope["algorithm"] != "Ed25519":
        raise ArtifactContractError("trust-document algorithm changed")
    signer_key_id = _require_identifier(
        envelope["signerKeyId"], name="trust-document signer"
    )
    roots = trust_state["rootKeys"]
    try:
        signer = roots[signer_key_id]
    except KeyError as exc:
        raise ArtifactContractError(
            "trust document is not signed by a pinned root"
        ) from exc
    if (
        "trust-document" not in signer.purposes
        or signer_key_id in trust_state["revokedKeyIds"]
        or not signer.not_before <= validation_time <= signer.not_after
    ):
        raise ArtifactContractError(
            "trust-document signer is unauthorized or revoked"
        )
    if not isinstance(envelope["payload"], Mapping):
        raise ArtifactContractError("trust-document payload is not an object")
    verify_ed25519_signature(
        signer.public_key,
        envelope["signatureBase64Url"],
        _signature_message(signature_domain, envelope["payload"]),
        name="trust document",
    )
    return envelope["payload"]


def _verify_key_documents(
    trust_material: Mapping[str, Any],
    *,
    bundle: Mapping[str, Any],
    generation: Mapping[str, Any],
    trust_state: Mapping[str, Any],
    validation_time: str,
) -> tuple[dict[str, VerifiedAuthorityKey], frozenset[str]]:
    material = _require_mapping(
        trust_material,
        name="package trust material",
        keys={"keyAuthorizations", "keyRevocations"},
    )
    authorization_document = material["keyAuthorizations"]
    revocation_document = material["keyRevocations"]
    if trust_document_digest(authorization_document) != generation[
        "keyAuthorizationsDigest"
    ] or trust_document_digest(revocation_document) != generation[
        "keyRevocationsDigest"
    ]:
        raise ArtifactContractError(
            "generation does not bind its trust documents"
        )
    authorization_payload = _validate_signed_trust_document(
        authorization_document,
        expected_schema=KEY_AUTHORIZATION_SCHEMA,
        signature_domain=KEY_AUTHORIZATION_SIGNATURE_DOMAIN,
        trust_state=trust_state,
        validation_time=validation_time,
    )
    revocation_payload = _validate_signed_trust_document(
        revocation_document,
        expected_schema=KEY_REVOCATION_SCHEMA,
        signature_domain=KEY_REVOCATION_SIGNATURE_DOMAIN,
        trust_state=trust_state,
        validation_time=validation_time,
    )
    predecessor = generation["predecessorDigest"]
    for payload, name in (
        (authorization_payload, "key authorizations"),
        (revocation_payload, "key revocations"),
    ):
        expected_keys = (
            {
                "schema",
                "generationSequence",
                "predecessorGenerationDigest",
                "keys",
            }
            if name == "key authorizations"
            else {
                "schema",
                "generationSequence",
                "predecessorGenerationDigest",
                "revocationHighWater",
                "revocations",
            }
        )
        _require_mapping(payload, name=name, keys=expected_keys)
        if (
            payload["generationSequence"] != generation["sequence"]
            or payload["predecessorGenerationDigest"] != predecessor
        ):
            raise ArtifactContractError(
                f"{name} is for another generation"
            )
    if authorization_payload["schema"] != (
        "serverware.authorityKeyAuthorizationPayload/v1"
    ) or revocation_payload["schema"] != (
        "serverware.authorityKeyRevocationPayload/v1"
    ):
        raise ArtifactContractError("trust-document payload schema changed")
    files = {entry["path"]: entry for entry in bundle["files"]}
    authorized_entries = _require_list(
        authorization_payload["keys"],
        name="authorized keys",
        minimum=1,
        maximum=4096,
    )
    keys: dict[str, VerifiedAuthorityKey] = {}
    for raw in authorized_entries:
        entry = _require_mapping(
            raw,
            name="authorized key",
            keys={
                "keyId",
                "purposes",
                "publicKeyBase64Url",
                "keyFile",
                "authorizationDigest",
                "notBefore",
                "notAfter",
            },
        )
        key_id = _require_identifier(entry["keyId"], name="authorized key ID")
        purposes = _require_list(
            entry["purposes"],
            name="authorized key purposes",
            minimum=1,
            maximum=len(KEY_PURPOSES),
        )
        if (
            list(purposes) != sorted(set(purposes))
            or any(purpose not in KEY_PURPOSES for purpose in purposes)
        ):
            raise ArtifactContractError(
                "authorized key purposes are not closed and canonical"
            )
        public_key = strict_base64url_decode(
            entry["publicKeyBase64Url"],
            name="authorized public key",
            decoded_size=32,
        )
        key_file = _require_mapping(
            entry["keyFile"],
            name="authorized key file",
            keys={"path", "sha256", "size", "mode", "uid", "gid"},
        )
        path = _require_relative_path(
            key_file["path"], name="authorized key file path"
        )
        digest = _require_digest(
            key_file["sha256"], name="authorized key file digest"
        )
        if (
            key_file["size"] != 32
            or digest != "sha256:" + hashlib.sha256(public_key).hexdigest()
            or files.get(path) != {
                "path": path,
                "kind": "configuration",
                "mode": key_file["mode"],
                "uid": key_file["uid"],
                "gid": key_file["gid"],
                "size": 32,
                "sha256": digest,
            }
        ):
            raise ArtifactContractError(
                "authorized key does not match its exact bundle file"
            )
        not_before = _require_ascii(
            entry["notBefore"], name="key notBefore", maximum=64
        )
        not_after = _require_ascii(
            entry["notAfter"], name="key notAfter", maximum=64
        )
        if _require_timestamp(
            not_after, name="key notAfter"
        ) <= _require_timestamp(not_before, name="key notBefore"):
            raise ArtifactContractError("key validity is not increasing")
        authorization_digest = _require_digest(
            entry["authorizationDigest"],
            name="key authorization digest",
        )
        expected_authorization_digest = domain_digest(
            "serverware.authorityKeyAuthorizationEntry/v1",
            canonical_json_bytes(
                {
                    key: entry[key]
                    for key in (
                        "keyId",
                        "purposes",
                        "publicKeyBase64Url",
                        "keyFile",
                        "notBefore",
                        "notAfter",
                    )
                }
            ),
        )
        if authorization_digest != expected_authorization_digest:
            raise ArtifactContractError(
                "key authorization digest is not canonical"
            )
        if key_id in keys:
            raise ArtifactContractError("authorized key ID is repeated")
        keys[key_id] = VerifiedAuthorityKey(
            key_id=key_id,
            purposes=frozenset(purposes),
            public_key=public_key,
            key_file_path=path,
            key_file_sha256=digest,
            authorization_digest=authorization_digest,
            not_before=not_before,
            not_after=not_after,
        )
    if list(keys) != sorted(keys):
        raise ArtifactContractError("authorized keys are not sorted")
    revocations = _require_list(
        revocation_payload["revocations"],
        name="key revocations",
        maximum=4096,
    )
    revoked: set[str] = set(trust_state["revokedKeyIds"])
    previous_sequence = -1
    for raw in revocations:
        entry = _require_mapping(
            raw,
            name="key revocation",
            keys={"sequence", "keyId", "revokedAt", "reason"},
        )
        sequence = _require_int(
            entry["sequence"],
            name="key revocation sequence",
            minimum=0,
            maximum=2**63 - 1,
        )
        if sequence <= previous_sequence:
            raise ArtifactContractError(
                "key revocations are not strictly ordered"
            )
        previous_sequence = sequence
        key_id = _require_identifier(
            entry["keyId"], name="revoked key ID"
        )
        _require_timestamp(entry["revokedAt"], name="revokedAt")
        _require_ascii(entry["reason"], name="revocation reason", maximum=512)
        revoked.add(key_id)
    high_water = _require_int(
        revocation_payload["revocationHighWater"],
        name="revocation high-water",
        minimum=0,
        maximum=2**63 - 1,
    )
    if high_water < previous_sequence:
        raise ArtifactContractError(
            "revocation high-water is below its final entry"
        )
    if not any(
        "artifact-bundle" in key.purposes and key.key_id not in revoked
        for key in keys.values()
    ) or not any(
        "generation" in key.purposes and key.key_id not in revoked
        for key in keys.values()
    ):
        raise ArtifactContractError(
            "generation lacks nonrevoked package signing authorities"
        )
    return keys, frozenset(revoked)


def _validate_signed_evidence_envelope(
    receipt: Mapping[str, Any],
    *,
    schema: str,
    payload_schema: str,
    payload_keys: set[str],
    name: str,
) -> Mapping[str, Any]:
    envelope = _require_mapping(
        receipt,
        name=name,
        keys={
            "schema",
            "payload",
            "signerKeyId",
            "algorithm",
            "signatureBase64Url",
        },
    )
    if envelope["schema"] != schema or envelope["algorithm"] != "Ed25519":
        raise ArtifactContractError(f"{name} envelope changed")
    _require_identifier(envelope["signerKeyId"], name=f"{name} signer")
    strict_base64url_decode(
        envelope["signatureBase64Url"],
        name=f"{name} signature",
        decoded_size=64,
    )
    payload = _require_mapping(
        envelope["payload"], name=f"{name} payload", keys=payload_keys
    )
    if payload["schema"] != payload_schema:
        raise ArtifactContractError(f"{name} payload schema changed")
    return payload


def validate_snapshot_receipt(receipt: Mapping[str, Any]) -> None:
    payload = _validate_signed_evidence_envelope(
        receipt,
        schema=SNAPSHOT_RECEIPT_SCHEMA,
        payload_schema="serverware.authorityStableSnapshotReceiptPayload/v1",
        payload_keys={
            "schema",
            "receiptId",
            "rootIdentity",
            "snapshotKind",
            "readOnly",
            "treeAlgorithm",
            "treeDigest",
            "treeEntryCount",
            "totalBytes",
            "enumeratedTreeDigest",
            "createdAt",
            "expiresAt",
        },
        name="stable snapshot receipt",
    )
    _require_digest(payload["receiptId"], name="snapshot receipt ID")
    root = _require_mapping(
        payload["rootIdentity"],
        name="snapshot root identity",
        keys={
            "runtimePath",
            "device",
            "inode",
            "generation",
            "mountId",
            "mode",
            "uid",
            "gid",
        },
    )
    _require_runtime_path(root["runtimePath"], name="snapshot root path")
    for field, minimum, maximum in (
        ("device", 0, 2**64 - 1),
        ("inode", 1, 2**64 - 1),
        ("generation", 1, 2**64 - 1),
        ("mountId", 1, 2**64 - 1),
        ("mode", 0, 0o7777),
        ("uid", 0, 2**32 - 2),
        ("gid", 0, 2**32 - 2),
    ):
        _require_int(
            root[field],
            name=f"snapshot root {field}",
            minimum=minimum,
            maximum=maximum,
        )
    if payload["snapshotKind"] not in {
        "atomic-filesystem-snapshot",
        "content-addressed-cas",
    } or payload["readOnly"] is not True:
        raise ArtifactContractError(
            "snapshot receipt does not prove a stable read-only root"
        )
    if payload["treeAlgorithm"] != "canonical-path-tree-sha256-v1":
        raise ArtifactContractError("snapshot tree algorithm changed")
    for field in ("treeDigest", "enumeratedTreeDigest"):
        _require_digest(payload[field], name=f"snapshot {field}")
    _require_int(
        payload["treeEntryCount"],
        name="snapshot tree entry count",
        minimum=1,
        maximum=MAX_BUNDLE_FILES,
    )
    _require_int(
        payload["totalBytes"],
        name="snapshot total bytes",
        minimum=1,
        maximum=MAX_FILE_BYTES * MAX_BUNDLE_FILES,
    )
    created_at = _require_timestamp(
        payload["createdAt"], name="snapshot createdAt"
    )
    expires_at = _require_timestamp(
        payload["expiresAt"], name="snapshot expiresAt"
    )
    if expires_at <= created_at:
        raise ArtifactContractError(
            "snapshot receipt validity is not increasing"
        )
    receipt_body = {
        key: payload[key] for key in payload if key != "receiptId"
    }
    if payload["receiptId"] != domain_digest(
        "serverware.authorityStableSnapshotReceiptId/v1",
        canonical_json_bytes(receipt_body),
    ):
        raise ArtifactContractError("snapshot receipt ID is not canonical")


def snapshot_receipt_digest(receipt: Mapping[str, Any]) -> str:
    validate_snapshot_receipt(receipt)
    return domain_digest(
        "serverware.authorityStableSnapshotReceiptDigest/v1",
        canonical_json_bytes(receipt),
    )


def validate_closure_receipt(receipt: Mapping[str, Any]) -> None:
    payload = _validate_signed_evidence_envelope(
        receipt,
        schema=CLOSURE_RECEIPT_SCHEMA,
        payload_schema="serverware.authorityCompleteClosureReceiptPayload/v1",
        payload_keys={
            "schema",
            "receiptId",
            "snapshotReceiptDigest",
            "treeDigest",
            "treeEntryCount",
            "totalBytes",
            "pythonImportClosure",
            "nativeClosure",
            "stageZero",
            "coverage",
            "rootfs",
            "createdAt",
            "expiresAt",
        },
        name="complete closure receipt",
    )
    _require_digest(payload["receiptId"], name="closure receipt ID")
    _require_digest(
        payload["snapshotReceiptDigest"],
        name="closure snapshot receipt digest",
    )
    _require_digest(payload["treeDigest"], name="closure tree digest")
    _require_int(
        payload["treeEntryCount"],
        name="closure tree entry count",
        minimum=1,
        maximum=MAX_BUNDLE_FILES,
    )
    _require_int(
        payload["totalBytes"],
        name="closure total bytes",
        minimum=1,
        maximum=MAX_FILE_BYTES * MAX_BUNDLE_FILES,
    )
    imports = _require_list(
        payload["pythonImportClosure"],
        name="verified Python import closure",
        maximum=MAX_IMPORTS,
    )
    for entry in imports:
        _validate_python_import(entry)
    _require_sorted_unique(
        imports,
        name="verified Python import closure",
        key=lambda entry: (entry["module"], entry["path"]),
    )
    native = _require_mapping(
        payload["nativeClosure"],
        name="verified native closure",
        keys={"executables", "objects"},
    )
    executables = _require_list(
        native["executables"],
        name="verified native executables",
        maximum=MAX_NATIVE_OBJECTS,
    )
    objects = _require_list(
        native["objects"],
        name="verified native objects",
        maximum=MAX_NATIVE_OBJECTS,
    )
    for entry in executables:
        _validate_native_executable(entry)
    for entry in objects:
        _validate_native_object(entry)
    _require_sorted_unique(
        executables,
        name="verified native executables",
        key=lambda entry: entry["runtimePath"],
    )
    _require_sorted_unique(
        objects,
        name="verified native objects",
        key=lambda entry: entry["runtimePath"],
    )
    stage_zero = _require_mapping(
        payload["stageZero"],
        name="closure stage zero",
        keys={
            "path",
            "sha256",
            "size",
            "interfaceSchema",
            "runtimePath",
            "staticElf",
            "ptInterp",
            "needed",
            "elfEvidenceDigest",
        },
    )
    _require_relative_path(stage_zero["path"], name="stage-zero path")
    _require_digest(stage_zero["sha256"], name="stage-zero digest")
    _require_int(
        stage_zero["size"],
        name="stage-zero size",
        minimum=1,
        maximum=MAX_FILE_BYTES,
    )
    _require_identifier(
        stage_zero["interfaceSchema"], name="stage-zero interface schema"
    )
    _require_runtime_path(
        stage_zero["runtimePath"], name="stage-zero runtime path"
    )
    if (
        stage_zero["staticElf"] is not True
        or stage_zero["ptInterp"] is not None
        or stage_zero["needed"] != []
    ):
        raise ArtifactContractError(
            "closure verifier did not prove a static stage zero"
        )
    _require_digest(
        stage_zero["elfEvidenceDigest"],
        name="stage-zero ELF evidence digest",
    )
    coverage = _require_mapping(
        payload["coverage"],
        name="closure coverage",
        keys={
            "pythonStaticImports",
            "pythonDynamicImports",
            "ptInterp",
            "dtNeeded",
            "rpath",
            "runpath",
            "audit",
            "depaudit",
            "filter",
            "auxiliary",
            "dlopen",
            "nss",
            "plugins",
            "ifunc",
            "hwcap",
            "coverageEvidenceDigest",
        },
    )
    for field in (
        "pythonStaticImports",
        "pythonDynamicImports",
        "ptInterp",
        "dtNeeded",
        "rpath",
        "runpath",
        "audit",
        "depaudit",
        "filter",
        "auxiliary",
        "dlopen",
        "nss",
        "plugins",
        "ifunc",
        "hwcap",
    ):
        if coverage[field] is not True:
            raise ArtifactContractError(
                f"closure verifier did not cover {field}"
            )
    _require_digest(
        coverage["coverageEvidenceDigest"],
        name="closure coverage evidence digest",
    )
    rootfs = _require_mapping(
        payload["rootfs"],
        name="closure rootfs enforcement",
        keys={
            "imageDigest",
            "verityRootDigest",
            "mountPolicyDigest",
            "pivotRootRequired",
            "oldRootDetached",
            "enforcementEvidenceDigest",
        },
    )
    for field in (
        "imageDigest",
        "verityRootDigest",
        "mountPolicyDigest",
        "enforcementEvidenceDigest",
    ):
        _require_digest(rootfs[field], name=f"rootfs {field}")
    if (
        rootfs["pivotRootRequired"] is not True
        or rootfs["oldRootDetached"] is not True
    ):
        raise ArtifactContractError(
            "closure receipt lacks rootfs pivot enforcement"
        )
    created_at = _require_timestamp(
        payload["createdAt"], name="closure createdAt"
    )
    expires_at = _require_timestamp(
        payload["expiresAt"], name="closure expiresAt"
    )
    if expires_at <= created_at:
        raise ArtifactContractError(
            "closure receipt validity is not increasing"
        )
    receipt_body = {
        key: payload[key] for key in payload if key != "receiptId"
    }
    if payload["receiptId"] != domain_digest(
        "serverware.authorityCompleteClosureReceiptId/v1",
        canonical_json_bytes(receipt_body),
    ):
        raise ArtifactContractError("closure receipt ID is not canonical")


def closure_receipt_digest(receipt: Mapping[str, Any]) -> str:
    validate_closure_receipt(receipt)
    return domain_digest(
        "serverware.authorityCompleteClosureReceiptDigest/v1",
        canonical_json_bytes(receipt),
    )


def verify_external_evidence_receipt(
    receipt: Mapping[str, Any],
    *,
    receipt_kind: str,
    verified_package: VerifiedArtifactPackage,
    validation_time: str,
    replay_digests: frozenset[str],
    allow_exact_digest: str | None = None,
) -> str:
    if receipt_kind == "stable-snapshot":
        validate_snapshot_receipt(receipt)
        purpose = "stable-snapshot-verifier"
        signature_domain = "serverware.authorityStableSnapshotReceiptSignature/v1"
        digest = snapshot_receipt_digest(receipt)
    elif receipt_kind == "complete-closure":
        validate_closure_receipt(receipt)
        purpose = "closure-verifier"
        signature_domain = "serverware.authorityCompleteClosureReceiptSignature/v1"
        digest = closure_receipt_digest(receipt)
    else:
        raise ArtifactContractError("external evidence kind is not recognized")
    _require_timestamp(validation_time, name="evidence validation time")
    payload = receipt["payload"]
    if not payload["createdAt"] <= validation_time <= payload["expiresAt"]:
        raise ArtifactContractError(
            "external evidence is outside its validity interval"
        )
    key = verified_package.require_key(
        receipt["signerKeyId"], purpose, at=validation_time
    )
    verify_ed25519_signature(
        key.public_key,
        receipt["signatureBase64Url"],
        _signature_message(signature_domain, payload),
        name=receipt_kind,
    )
    if digest in replay_digests and digest != allow_exact_digest:
        raise ArtifactContractError(
            "external evidence receipt was already consumed"
        )
    return digest


def _validate_file_entry(value: object) -> None:
    entry = _require_mapping(
        value,
        name="file entry",
        keys={
            "path",
            "kind",
            "mode",
            "uid",
            "gid",
            "size",
            "sha256",
        },
    )
    _require_relative_path(entry["path"], name="file path")
    if entry["kind"] not in FILE_KINDS:
        raise ArtifactContractError("file kind is not recognized")
    mode = _require_int(
        entry["mode"], name="file mode", minimum=0, maximum=0o7777
    )
    if mode & 0o7000 or mode & 0o022:
        raise ArtifactContractError(
            "artifact files cannot be special-mode or group/world-writable"
        )
    _require_int(entry["uid"], name="file uid", minimum=0, maximum=2**32 - 2)
    _require_int(entry["gid"], name="file gid", minimum=0, maximum=2**32 - 2)
    _require_int(
        entry["size"], name="file size", minimum=0, maximum=MAX_FILE_BYTES
    )
    _require_digest(entry["sha256"], name="file digest")


def _validate_python_import(value: object) -> None:
    entry = _require_mapping(
        value,
        name="Python import entry",
        keys={"module", "path", "kind", "isPackage", "sha256"},
    )
    module = _require_ascii(entry["module"], name="module", maximum=512)
    if any(
        not part
        or part[0].isdigit()
        or not part.replace("_", "a").isalnum()
        for part in module.split(".")
    ):
        raise ArtifactContractError("Python module name is not canonical")
    _require_relative_path(entry["path"], name="Python import path")
    if entry["kind"] not in {"source", "bytecode", "extension"}:
        raise ArtifactContractError("Python import kind is not recognized")
    if not isinstance(entry["isPackage"], bool):
        raise ArtifactContractError("isPackage must be boolean")
    _require_digest(entry["sha256"], name="Python import digest")


def _validate_native_object(value: object) -> None:
    entry = _require_mapping(
        value,
        name="native object",
        keys={
            "path",
            "runtimePath",
            "soname",
            "elfClass",
            "machine",
            "needed",
            "sha256",
        },
    )
    _require_relative_path(entry["path"], name="native object path")
    _require_runtime_path(entry["runtimePath"], name="native runtime path")
    if entry["soname"] is not None:
        _require_ascii(entry["soname"], name="SONAME", maximum=512)
        if "/" in entry["soname"]:
            raise ArtifactContractError("SONAME cannot contain a slash")
    if entry["elfClass"] not in {"ELF32", "ELF64"}:
        raise ArtifactContractError("ELF class is not recognized")
    _require_int(
        entry["machine"], name="ELF machine", minimum=0, maximum=65535
    )
    needed = _require_list(
        entry["needed"], name="native dependency list", maximum=4096
    )
    for dependency in needed:
        _require_runtime_path(dependency, name="native dependency")
    if list(needed) != sorted(set(needed)):
        raise ArtifactContractError(
            "native dependency list is not sorted and unique"
        )
    _require_digest(entry["sha256"], name="native object digest")


def _validate_native_executable(value: object) -> None:
    entry = _require_mapping(
        value,
        name="native executable",
        keys={
            "path",
            "runtimePath",
            "elfClass",
            "machine",
            "ptInterp",
            "needed",
            "sha256",
        },
    )
    _require_relative_path(entry["path"], name="native executable path")
    _require_runtime_path(entry["runtimePath"], name="runtime executable path")
    if entry["elfClass"] not in {"ELF32", "ELF64"}:
        raise ArtifactContractError("ELF class is not recognized")
    _require_int(
        entry["machine"], name="ELF machine", minimum=0, maximum=65535
    )
    if entry["ptInterp"] is not None:
        _require_runtime_path(entry["ptInterp"], name="PT_INTERP")
    needed = _require_list(
        entry["needed"], name="native executable dependencies", maximum=4096
    )
    for dependency in needed:
        _require_runtime_path(dependency, name="native dependency")
    if list(needed) != sorted(set(needed)):
        raise ArtifactContractError(
            "native executable dependencies are not sorted and unique"
        )
    _require_digest(entry["sha256"], name="native executable digest")


def _validate_digest_file_reference(
    value: object,
    *,
    name: str,
    extra_keys: set[str],
) -> Mapping[str, Any]:
    reference = _require_mapping(
        value,
        name=name,
        keys={"path", "sha256"} | extra_keys,
    )
    _require_relative_path(reference["path"], name=f"{name} path")
    _require_digest(reference["sha256"], name=f"{name} digest")
    return reference


def _configuration_payload_binding_key(value: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        value[field]
        for field in ("fileDigest", "role", "payloadDigest", "payloadSchema")
    )


def validate_configuration_payload_bindings(
    bindings: object,
    *,
    configuration_digests: object,
) -> None:
    """Validate identity declarations, not configuration signatures or authority."""
    raw_digests = _require_list(
        configuration_digests,
        name="configuration digests",
        maximum=MAX_CONFIGURATION_DIGESTS,
    )
    previous_digest = None
    for digest in raw_digests:
        _require_digest(digest, name="configuration file digest")
        if previous_digest is not None and digest <= previous_digest:
            raise ArtifactContractError(
                "configuration digests are not sorted and unique"
            )
        previous_digest = digest
    values = _require_list(
        bindings,
        name="configuration payload bindings",
        maximum=MAX_CONFIGURATION_DIGESTS,
    )
    previous_key = None
    file_offset = 0
    for raw in values:
        binding = _require_mapping(
            raw,
            name="configuration payload binding",
            keys={"fileDigest", "payloadDigest", "payloadSchema", "role"},
        )
        role = _require_identifier(binding["role"], name="configuration payload role")
        if (
            role not in CONFIGURATION_PAYLOAD_SCHEMAS
            or binding["payloadSchema"] != CONFIGURATION_PAYLOAD_SCHEMAS[role]
        ):
            raise ArtifactContractError("configuration payload schema or role changed")
        file_digest = _require_digest(
            binding["fileDigest"], name="configuration binding file digest"
        )
        _require_digest(binding["payloadDigest"], name="configuration payload digest")
        key = _configuration_payload_binding_key(binding)
        if previous_key is not None and (
            key <= previous_key or file_digest == previous_key[0]
        ):
            raise ArtifactContractError(
                "configuration payload bindings repeat a file or are not sorted"
            )
        while file_offset < len(raw_digests) and raw_digests[file_offset] < file_digest:
            file_offset += 1
        if file_offset == len(raw_digests) or raw_digests[file_offset] != file_digest:
            raise ArtifactContractError(
                "configuration payload binding is outside the raw configuration inventory"
            )
        previous_key = key


def configuration_payload_bindings(configurations: object) -> list[dict[str, str]]:
    """Project supported semantic identities while retaining separate raw hashes."""
    references = _require_list(
        configurations,
        name="configuration files",
        minimum=1,
        maximum=MAX_CONFIGURATION_DIGESTS,
    )
    bindings = []
    for entry in references:
        reference = _validate_digest_file_reference(
            entry,
            name="configuration file",
            extra_keys={"name", "role", "payloadSchema", "payloadDigest"},
        )
        _require_identifier(reference["name"], name="configuration name")
        role = _require_identifier(reference["role"], name="configuration role")
        if role not in CONFIGURATION_PAYLOAD_SCHEMAS:
            if reference["payloadSchema"] is not None or reference["payloadDigest"] is not None:
                raise ArtifactContractError(
                    "non-authority configuration cannot declare a payload identity"
                )
            continue
        if reference["payloadSchema"] != CONFIGURATION_PAYLOAD_SCHEMAS[role]:
            raise ArtifactContractError("configuration payload schema changed")
        _require_digest(reference["payloadDigest"], name="configuration payload digest")
        bindings.append({
            "fileDigest": reference["sha256"],
            "payloadDigest": reference["payloadDigest"],
            "payloadSchema": reference["payloadSchema"],
            "role": role,
        })
    bindings.sort(key=_configuration_payload_binding_key)
    validate_configuration_payload_bindings(
        bindings,
        configuration_digests=sorted({entry["sha256"] for entry in references}),
    )
    return bindings


def _validate_trust_mode(value: object) -> None:
    trust = _require_mapping(
        value,
        name="trust mode",
        keys={
            "mode",
            "hardwareBacked",
            "externalWitnessRequired",
            "teeQuoteRequired",
            "imaAppraisalRequired",
        },
    )
    mode = trust["mode"]
    if mode not in TRUST_MODES:
        raise ArtifactContractError("trust mode is not recognized")
    flags = (
        trust["hardwareBacked"],
        trust["externalWitnessRequired"],
        trust["teeQuoteRequired"],
        trust["imaAppraisalRequired"],
    )
    if any(not isinstance(flag, bool) for flag in flags):
        raise ArtifactContractError("trust-mode claims must be boolean")
    expected = {
        "trusted-host-local": (False, False, False, False),
        "external-production": (False, True, False, True),
        "tee-hardware": (True, True, True, True),
    }[mode]
    if flags != expected:
        raise ArtifactContractError("trust-mode claims are contradictory")


def configuration_generation_binding(generation: Mapping[str, Any]) -> dict[str, Any]:
    """Project preconfiguration intent, without admitting a generation statement.

    Full statements and predeclared metadata may carry other fields. Only these
    scalar commitments and the exact trust-mode claims participate; no final
    package, configuration, generation, launch, or attestation digest is read.
    The recorded operation contract is shape-checked, not enrolled or replaced
    by the current source contract; current admission keeps its separate pin.
    """
    fields = {
        "generationId", "sequence", "predecessorDigest",
        "minimumRollbackSequence", "validFrom", "validUntil",
        "operationManifestDigest", "trustMode",
    }
    if not isinstance(generation, Mapping) or not fields.issubset(generation):
        raise ArtifactContractError("configuration generation metadata is incomplete")
    generation_id = _require_identifier(
        generation["generationId"], name="configuration generation identifier"
    )
    sequence = _require_int(
        generation["sequence"], name="configuration generation sequence",
        minimum=0, maximum=2**63 - 1,
    )
    predecessor = generation["predecessorDigest"]
    if predecessor is not None:
        _require_digest(predecessor, name="configuration predecessor digest")
    if (sequence == 0) != (predecessor is None):
        raise ArtifactContractError("only the genesis binding can omit its predecessor")
    minimum_rollback = _require_int(
        generation["minimumRollbackSequence"], name="configuration rollback floor",
        minimum=0, maximum=sequence,
    )
    valid_from = _require_timestamp(generation["validFrom"], name="configuration validFrom")
    valid_until = _require_timestamp(generation["validUntil"], name="configuration validUntil")
    if valid_until <= valid_from:
        raise ArtifactContractError("configuration generation validity is not increasing")
    operation_digest = _require_digest(
        generation["operationManifestDigest"], name="configuration operation contract"
    )
    trust_mode = _require_mapping(
        generation["trustMode"], name="configuration trust mode",
        keys={
            "mode", "hardwareBacked", "externalWitnessRequired",
            "teeQuoteRequired", "imaAppraisalRequired",
        },
    )
    _require_identifier(trust_mode["mode"], name="configuration trust mode")
    _validate_trust_mode(trust_mode)
    return {
        "schema": CONFIGURATION_GENERATION_BINDING_SCHEMA,
        "generationId": generation_id,
        "sequence": sequence,
        "predecessorDigest": predecessor,
        "minimumRollbackSequence": minimum_rollback,
        "validFrom": generation["validFrom"],
        "validUntil": generation["validUntil"],
        "operationManifestDigest": operation_digest,
        "trustMode": trust_mode["mode"],
    }


def configuration_generation_binding_digest(generation: Mapping[str, Any]) -> str:
    return domain_digest(
        CONFIGURATION_GENERATION_BINDING_SCHEMA,
        canonical_json_bytes(configuration_generation_binding(generation)),
    )


def validate_role_reference(reference: object) -> None:
    """Validate the complete static role entry, without admitting its bundle."""
    role = _validate_digest_file_reference(
        reference,
        name="role manifest",
        extra_keys={
            "role", "runtimeUid", "runtimeGid", "processMode",
            "entrypointPath", "listenerName", "credentialNames", "cwd",
            "pathEntries", "argv", "environmentAllowlist", "mutableStateDescriptors",
        },
    )
    _require_identifier(role["role"], name="role")
    _require_int(role["runtimeUid"], name="role uid", minimum=1, maximum=2**32 - 2)
    _require_int(role["runtimeGid"], name="role gid", minimum=1, maximum=2**32 - 2)
    _require_identifier(role["processMode"], name="process mode")
    _require_runtime_path(role["entrypointPath"], name="role entrypoint path")
    _require_identifier(role["listenerName"], name="listener name")
    _require_runtime_path(role["cwd"], name="role working directory")
    path_entries = _require_list(
        role["pathEntries"], name="role PATH entries", minimum=1, maximum=64,
    )
    for path_entry in path_entries:
        _require_runtime_path(path_entry, name="role PATH entry")
    if list(path_entries) != list(dict.fromkeys(path_entries)):
        raise ArtifactContractError("role PATH entries are repeated")
    argv = _require_list(role["argv"], name="role argv", minimum=1, maximum=256)
    for argument in argv:
        _require_ascii(argument, name="role argv value", maximum=4096)
    environment_allowlist = _require_list(
        role["environmentAllowlist"], name="role environment allowlist", maximum=256,
    )
    for environment_name in environment_allowlist:
        _require_ascii(environment_name, name="role environment name", maximum=256)
    if list(environment_allowlist) != sorted(set(environment_allowlist)):
        raise ArtifactContractError("role environment allowlist is not sorted and unique")
    mutable_state = _require_list(
        role["mutableStateDescriptors"], name="role mutable-state descriptors", maximum=16,
    )
    for raw_state in mutable_state:
        state = _require_mapping(
            raw_state,
            name="mutable-state descriptor policy",
            keys={
                "name", "runtimePath", "atomicRecordProtocol", "quotaBytes",
                "singletonLeaseRequired", "networkAllowed",
            },
        )
        _require_identifier(state["name"], name="mutable-state descriptor name")
        _require_runtime_path(state["runtimePath"], name="mutable-state runtime path")
        if state["atomicRecordProtocol"] not in ALLOWED_MUTABLE_STATE_PROTOCOLS:
            raise ArtifactContractError("mutable-state atomic record protocol is not allowed")
        _require_int(state["quotaBytes"], name="mutable-state quota", minimum=1, maximum=64 * 1024**3)
        if state["singletonLeaseRequired"] is not True or state["networkAllowed"] is not False:
            raise ArtifactContractError("mutable state requires singleton lease and no network")
    _require_sorted_unique(
        mutable_state, name="mutable-state descriptor policies", key=lambda entry: entry["name"],
    )
    if (role["role"] == "witness") != bool(mutable_state):
        raise ArtifactContractError("only the witness role requires mutable state")
    credential_names = _require_list(
        role["credentialNames"], name="role credential names", maximum=256,
    )
    for credential_name in credential_names:
        _require_identifier(credential_name, name="role credential name")
    if list(credential_names) != sorted(set(credential_names)):
        raise ArtifactContractError("role credential names are not sorted and unique")


def role_binding_digest(reference: Mapping[str, Any]) -> str:
    validate_role_reference(reference)
    return domain_digest(ROLE_BINDING_DOMAIN, canonical_json_bytes(reference))


def role_binding_digests(roles: object) -> dict[str, str]:
    references = _require_list(
        roles, name="role manifests", minimum=1, maximum=MAX_ROLE_MANIFESTS,
    )
    bindings = {}
    previous_role = None
    for reference in references:
        validate_role_reference(reference)
        role = reference["role"]
        if previous_role is not None and role <= previous_role:
            raise ArtifactContractError("role manifests are not sorted and unique")
        bindings[role] = domain_digest(ROLE_BINDING_DOMAIN, canonical_json_bytes(reference))
        previous_role = role
    return bindings


def role_runtime_closure_digest(role_digest: str, package_versions: object) -> str:
    """Bind static role metadata and package versions, never a final launch."""
    _require_digest(role_digest, name="role binding digest")
    if type(package_versions) is not dict or not 1 <= len(package_versions) <= 4096:
        raise ArtifactContractError("role package versions have an invalid item count")
    packages = {}
    for name, version in package_versions.items():
        if type(name) is not str or type(version) is not str:
            raise ArtifactContractError("role package names and versions must be exact strings")
        _require_ascii(name, name="role package name", maximum=256)
        _require_ascii(version, name="role package version", maximum=256)
        packages[name] = version
    return domain_digest(
        ROLE_RUNTIME_CLOSURE_SCHEMA,
        canonical_json_bytes({
            "schema": ROLE_RUNTIME_CLOSURE_SCHEMA,
            "roleBindingDigest": role_digest,
            "packageVersions": packages,
        }),
    )


def validate_artifact_bundle(bundle: Mapping[str, Any]) -> None:
    value = _require_mapping(
        bundle,
        name="artifact bundle",
        keys={
            "schema",
            "bundleVersion",
            "authoritySchemaVersion",
            "sourceRevision",
            "sourceCommitDigest",
            "trustMode",
            "sourceTree",
            "stableSnapshotReceipt",
            "closureReceipt",
            "files",
            "pythonImportClosure",
            "nativeClosure",
            "schemas",
            "migrations",
            "configurations",
            "roleManifests",
            "sbom",
            "provenance",
            "ociImage",
            "stageZero",
            "operationManifest",
        },
    )
    if value["schema"] != ARTIFACT_BUNDLE_SCHEMA:
        raise ArtifactContractError("artifact bundle schema changed")
    if value["bundleVersion"] != 1:
        raise ArtifactContractError("artifact bundle version changed")
    if value["authoritySchemaVersion"] != AUTHORITY_SCHEMA_VERSION:
        raise ArtifactContractError("authority schema version changed")
    _require_identifier(value["sourceRevision"], name="source revision")
    _require_digest(
        value["sourceCommitDigest"], name="source commit digest"
    )
    _validate_trust_mode(value["trustMode"])

    source_tree = _require_mapping(
        value["sourceTree"],
        name="source tree",
        keys={
            "algorithm",
            "digest",
            "entryCount",
            "snapshotKind",
            "snapshotIdentityDigest",
            "readOnly",
        },
    )
    if source_tree["algorithm"] != "canonical-path-tree-sha256-v1":
        raise ArtifactContractError("source tree algorithm changed")
    _require_digest(source_tree["digest"], name="source tree digest")
    if source_tree["snapshotKind"] not in {
        "atomic-filesystem-snapshot",
        "content-addressed-cas",
    }:
        raise ArtifactContractError("source tree is not a stable snapshot")
    _require_digest(
        source_tree["snapshotIdentityDigest"],
        name="source snapshot identity digest",
    )
    if source_tree["readOnly"] is not True:
        raise ArtifactContractError("source snapshot is not read-only")
    _require_int(
        source_tree["entryCount"],
        name="source tree entry count",
        minimum=1,
        maximum=MAX_BUNDLE_FILES,
    )

    files = _require_list(
        value["files"],
        name="bundle files",
        minimum=1,
        maximum=MAX_BUNDLE_FILES,
    )
    for entry in files:
        _validate_file_entry(entry)
    _require_sorted_unique(
        files, name="bundle files", key=lambda entry: entry["path"]
    )
    total_bytes = sum(entry["size"] for entry in files)
    if total_bytes <= 0 or total_bytes > MAX_TOTAL_BUNDLE_BYTES:
        raise ArtifactContractError(
            "bundle exceeds its aggregate byte limit"
        )
    file_by_path = {entry["path"]: entry for entry in files}
    if source_tree["entryCount"] != len(files):
        raise ArtifactContractError("source tree entry count changed")
    if source_tree["digest"] != domain_digest(
        SOURCE_TREE_DIGEST_DOMAIN,
        canonical_json_bytes(list(files)),
    ):
        raise ArtifactContractError("source tree digest changed")
    validate_snapshot_receipt(value["stableSnapshotReceipt"])
    snapshot_payload = value["stableSnapshotReceipt"]["payload"]
    if (
        snapshot_payload["treeDigest"] != source_tree["digest"]
        or snapshot_payload["treeEntryCount"] != len(files)
        or snapshot_payload["totalBytes"] != total_bytes
        or snapshot_payload["snapshotKind"]
        != source_tree["snapshotKind"]
        or snapshot_payload["readOnly"] is not True
        or snapshot_payload["enumeratedTreeDigest"]
        != domain_digest(
            "serverware.authorityEnumeratedTree/v1",
            canonical_json_bytes(list(files)),
        )
        or source_tree["snapshotIdentityDigest"]
        != domain_digest(
            "serverware.authoritySnapshotRootIdentity/v1",
            canonical_json_bytes(snapshot_payload["rootIdentity"]),
        )
    ):
        raise ArtifactContractError(
            "stable snapshot receipt does not match the enumerated tree"
        )

    imports = _require_list(
        value["pythonImportClosure"],
        name="Python import closure",
        maximum=MAX_IMPORTS,
    )
    for entry in imports:
        _validate_python_import(entry)
        if (
            entry["path"] not in file_by_path
            or entry["sha256"] != file_by_path[entry["path"]]["sha256"]
            or file_by_path[entry["path"]]["kind"]
            not in {
                "authority-source",
                "authority-bytecode",
                "python-extension",
            }
        ):
            raise ArtifactContractError(
                "Python import is outside the measured bundle"
            )
    _require_sorted_unique(
        imports,
        name="Python import closure",
        key=lambda entry: (entry["module"], entry["path"]),
    )
    validate_closure_receipt(value["closureReceipt"])
    closure_payload = value["closureReceipt"]["payload"]
    if (
        closure_payload["snapshotReceiptDigest"]
        != snapshot_receipt_digest(value["stableSnapshotReceipt"])
        or closure_payload["treeDigest"] != source_tree["digest"]
        or closure_payload["treeEntryCount"] != len(files)
        or closure_payload["totalBytes"] != total_bytes
        or closure_payload["pythonImportClosure"] != list(imports)
    ):
        raise ArtifactContractError(
            "closure receipt does not match the stable snapshot"
        )

    native = _require_mapping(
        value["nativeClosure"],
        name="native closure",
        keys={"executables", "objects"},
    )
    executables = _require_list(
        native["executables"],
        name="native executables",
        maximum=MAX_NATIVE_OBJECTS,
    )
    objects = _require_list(
        native["objects"],
        name="native objects",
        maximum=MAX_NATIVE_OBJECTS,
    )
    if closure_payload["nativeClosure"] != native:
        raise ArtifactContractError(
            "native closure is not the externally verified closure"
        )
    for entry in executables:
        _validate_native_executable(entry)
    for entry in objects:
        _validate_native_object(entry)
    _require_sorted_unique(
        executables,
        name="native executables",
        key=lambda entry: entry["runtimePath"],
    )
    _require_sorted_unique(
        objects,
        name="native objects",
        key=lambda entry: entry["runtimePath"],
    )
    native_by_runtime_path = {
        entry["runtimePath"]: entry for entry in [*executables, *objects]
    }
    if len(native_by_runtime_path) != len(executables) + len(objects):
        raise ArtifactContractError("native runtime path is ambiguous")
    for entry in [*executables, *objects]:
        file_entry = file_by_path.get(entry["path"])
        if (
            file_entry is None
            or file_entry["sha256"] != entry["sha256"]
            or file_entry["kind"]
            not in {
                "elf-executable",
                "elf-shared-object",
                "native-stage-zero",
                "python-extension",
            }
        ):
            raise ArtifactContractError(
                "native closure member is outside the measured bundle"
            )
        dependencies = list(entry["needed"])
        if entry in executables and entry["ptInterp"] is not None:
            dependencies.append(entry["ptInterp"])
        for dependency in dependencies:
            if dependency not in native_by_runtime_path:
                raise ArtifactContractError(
                    "native dependency closure is incomplete"
                )

    schemas = _require_list(
        value["schemas"], name="schemas", maximum=MAX_SCHEMAS
    )
    for entry in schemas:
        reference = _validate_digest_file_reference(
            entry, name="schema reference", extra_keys={"schemaId"}
        )
        _require_identifier(reference["schemaId"], name="schema identifier")
    _require_sorted_unique(
        schemas, name="schemas", key=lambda entry: entry["schemaId"]
    )

    migrations = _require_list(
        value["migrations"], name="migrations", maximum=MAX_MIGRATIONS
    )
    for entry in migrations:
        migration = _require_mapping(
            entry,
            name="migration",
            keys={
                "name",
                "fromVersion",
                "toVersion",
                "path",
                "sha256",
                "receiptSchema",
                "receiptPath",
                "receiptDigest",
                "receiptPayload",
                "receiptSignerKeyId",
                "receiptAlgorithm",
                "receiptSignatureBase64Url",
                "receiptSignatureDigest",
            },
        )
        _require_identifier(migration["name"], name="migration name")
        source_version = _require_int(
            migration["fromVersion"],
            name="migration source version",
            minimum=0,
            maximum=2**31 - 1,
        )
        target_version = _require_int(
            migration["toVersion"],
            name="migration target version",
            minimum=1,
            maximum=2**31 - 1,
        )
        if target_version <= source_version:
            raise ArtifactContractError("migration version does not advance")
        _require_relative_path(migration["path"], name="migration path")
        _require_digest(migration["sha256"], name="migration digest")
        _require_identifier(
            migration["receiptSchema"], name="migration receipt schema"
        )
        _require_relative_path(
            migration["receiptPath"], name="migration receipt path"
        )
        _require_digest(
            migration["receiptDigest"], name="migration receipt digest"
        )
        receipt_payload = _require_mapping(
            migration["receiptPayload"],
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
        if (
            migration["receiptSchema"]
                != authority_contract.MIGRATION_RECEIPT_SCHEMA
            or receipt_payload["schema"]
                != authority_contract.MIGRATION_RECEIPT_SCHEMA
            or receipt_payload["contractId"]
                != authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID
            or receipt_payload["migrationName"]
                != authority_contract.V8_TO_V9_MIGRATION_NAME
            or migration["name"] != receipt_payload["migrationName"]
            or receipt_payload["sourceVersion"] != source_version
            or receipt_payload["targetVersion"] != target_version
            or source_version != 8
            or target_version != 9
            or receipt_payload["migrationSha256"] != migration["sha256"]
            or receipt_payload["sourceRevision"]
                != value["sourceRevision"]
            or receipt_payload["operationContractDigest"]
                != value["operationManifest"]["contractDigest"]
            or receipt_payload["terminal"] is not True
            or receipt_payload["status"] != "completed"
        ):
            raise ArtifactContractError(
                "migration receipt does not bind the migration"
            )
        _require_digest(
            receipt_payload["signerIdentityDigest"],
            name="migration signer identity",
        )
        _require_digest(
            receipt_payload["beforeManifestDigest"],
            name="migration before manifest",
        )
        _require_digest(
            receipt_payload["afterManifestDigest"],
            name="migration after manifest",
        )
        _require_digest(
            receipt_payload["beforeRowCountsDigest"],
            name="migration before row counts",
        )
        _require_digest(
            receipt_payload["afterRowCountsDigest"],
            name="migration after row counts",
        )
        _require_timestamp(
            receipt_payload["completedAt"],
            name="migration receipt completedAt",
        )
        _require_identifier(
            migration["receiptSignerKeyId"],
            name="migration receipt signer",
        )
        if migration["receiptAlgorithm"] != "Ed25519":
            raise ArtifactContractError(
                "migration receipt algorithm changed"
            )
        receipt_signature = strict_base64url_decode(
            migration["receiptSignatureBase64Url"],
            name="migration receipt signature",
            decoded_size=64,
        )
        if migration["receiptSignatureDigest"] != (
            "sha256:" + hashlib.sha256(receipt_signature).hexdigest()
        ):
            raise ArtifactContractError(
                "migration receipt signature digest changed"
            )
        canonical_receipt = canonical_json_bytes(receipt_payload)
        if migration["receiptDigest"] != domain_digest(
            authority_contract.MIGRATION_RECEIPT_DIGEST_DOMAIN,
            canonical_receipt,
        ):
            raise ArtifactContractError(
                "migration receipt bytes are not canonical"
            )
    _require_sorted_unique(
        migrations,
        name="migrations",
        key=lambda entry: (
            entry["fromVersion"],
            entry["toVersion"],
            entry["name"],
        ),
    )

    configurations = _require_list(
        value["configurations"],
        name="configuration files",
        minimum=1,
        maximum=MAX_CONFIGURATION_DIGESTS,
    )
    configuration_payload_bindings(configurations)
    _require_sorted_unique(
        configurations,
        name="configuration files",
        key=lambda entry: (entry["role"], entry["name"], entry["path"]),
    )

    roles = _require_list(
        value["roleManifests"],
        name="role manifests",
        minimum=1,
        maximum=MAX_ROLE_MANIFESTS,
    )
    for entry in roles:
        validate_role_reference(entry)
    _require_sorted_unique(
        roles, name="role manifests", key=lambda entry: entry["role"]
    )
    native_entrypoints = {
        entry["runtimePath"] for entry in executables
    }
    if any(
        role["entrypointPath"] not in native_entrypoints
        for role in roles
    ):
        raise ArtifactContractError(
            "role entrypoint is outside the native executable closure"
        )

    sbom = _validate_digest_file_reference(
        value["sbom"],
        name="SBOM",
        extra_keys={"format", "mediaType"},
    )
    _require_identifier(sbom["format"], name="SBOM format")
    _require_ascii(sbom["mediaType"], name="SBOM media type", maximum=256)

    provenance = _validate_digest_file_reference(
        value["provenance"],
        name="provenance",
        extra_keys={
            "predicateType",
            "mediaType",
            "builderId",
            "sourceRevision",
            "sourceCommitDigest",
            "sourceTreeDigest",
            "ociRootDigest",
            "statementDigest",
            "signerKeyId",
            "algorithm",
            "signatureBase64Url",
        },
    )
    _require_ascii(
        provenance["predicateType"],
        name="provenance predicate type",
        maximum=1024,
    )
    _require_ascii(
        provenance["mediaType"],
        name="provenance media type",
        maximum=256,
    )
    _require_identifier(
        provenance["builderId"], name="provenance builder identifier"
    )
    _require_identifier(
        provenance["sourceRevision"], name="provenance source revision"
    )
    _require_digest(
        provenance["sourceCommitDigest"], name="source commit digest"
    )
    for field in (
        "sourceTreeDigest",
        "ociRootDigest",
        "statementDigest",
    ):
        _require_digest(provenance[field], name=f"provenance {field}")
    _require_identifier(
        provenance["signerKeyId"], name="provenance signer"
    )
    if provenance["algorithm"] != "Ed25519":
        raise ArtifactContractError("provenance signature algorithm changed")
    strict_base64url_decode(
        provenance["signatureBase64Url"],
        name="provenance signature",
        decoded_size=64,
    )

    oci = _require_mapping(
        value["ociImage"],
        name="OCI image",
        keys={
            "reference",
            "rootPath",
            "rootDigest",
            "rootSize",
            "rootMediaType",
            "rootDocumentBase64Url",
            "indexPath",
            "indexDigest",
            "indexSize",
            "indexMediaType",
            "indexDocumentBase64Url",
            "manifestPath",
            "manifestDigest",
            "manifestSize",
            "manifestMediaType",
            "manifestDocumentBase64Url",
            "configPath",
            "configDigest",
            "configSize",
            "configMediaType",
            "configDocumentBase64Url",
            "platform",
            "layers",
        },
    )
    reference = _require_ascii(
        oci["reference"], name="OCI reference", maximum=512
    )
    root_path = _require_relative_path(
        oci["rootPath"], name="OCI root descriptor path"
    )
    root_digest = _require_digest(
        oci["rootDigest"], name="OCI root descriptor digest"
    )
    root_size = _require_int(
        oci["rootSize"],
        name="OCI root descriptor size",
        minimum=1,
        maximum=MAX_FILE_BYTES,
    )
    root_media_type = _require_ascii(
        oci["rootMediaType"],
        name="OCI root descriptor media type",
        maximum=256,
    )
    root_bytes, root_document = _strict_json_document(
        oci["rootDocumentBase64Url"],
        name="OCI root descriptor",
        maximum_bytes=MAX_FILE_BYTES,
    )
    if (
        not reference.endswith("@" + root_digest)
        or len(root_bytes) != root_size
        or "sha256:" + hashlib.sha256(root_bytes).hexdigest()
            != root_digest
    ):
        raise ArtifactContractError(
            "OCI reference is not pinned to its exact root descriptor"
        )
    manifest_path = _require_relative_path(
        oci["manifestPath"], name="OCI manifest path"
    )
    manifest_digest = _require_digest(
        oci["manifestDigest"], name="OCI manifest digest"
    )
    manifest_size = _require_int(
        oci["manifestSize"],
        name="OCI manifest size",
        minimum=1,
        maximum=MAX_FILE_BYTES,
    )
    manifest_media_type = _require_ascii(
        oci["manifestMediaType"],
        name="OCI manifest media type",
        maximum=256,
    )
    manifest_bytes, manifest_document = _strict_json_document(
        oci["manifestDocumentBase64Url"],
        name="OCI manifest",
        maximum_bytes=MAX_FILE_BYTES,
    )
    if (
        len(manifest_bytes) != manifest_size
        or "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
            != manifest_digest
    ):
        raise ArtifactContractError(
            "OCI manifest bytes do not match their descriptor"
        )
    config_path = _require_relative_path(
        oci["configPath"], name="OCI config path"
    )
    config_digest = _require_digest(
        oci["configDigest"], name="OCI config digest"
    )
    config_size = _require_int(
        oci["configSize"],
        name="OCI config size",
        minimum=1,
        maximum=MAX_FILE_BYTES,
    )
    config_media_type = _require_ascii(
        oci["configMediaType"],
        name="OCI config media type",
        maximum=256,
    )
    config_bytes, config_document = _strict_json_document(
        oci["configDocumentBase64Url"],
        name="OCI config",
        maximum_bytes=MAX_FILE_BYTES,
    )
    if (
        len(config_bytes) != config_size
        or "sha256:" + hashlib.sha256(config_bytes).hexdigest()
            != config_digest
    ):
        raise ArtifactContractError(
            "OCI config bytes do not match their descriptor"
        )
    platform = _require_mapping(
        oci["platform"],
        name="OCI platform",
        keys={"os", "architecture", "variant"},
    )
    _require_identifier(platform["os"], name="OCI operating system")
    _require_identifier(
        platform["architecture"], name="OCI architecture"
    )
    if platform["variant"] is not None:
        _require_identifier(platform["variant"], name="OCI variant")
    layers = _require_list(
        oci["layers"],
        name="OCI layers",
        maximum=MAX_LAYER_DIGESTS,
    )
    layer_digests = []
    for raw in layers:
        layer = _require_mapping(
            raw,
            name="OCI layer",
            keys={"path", "digest", "size", "mediaType"},
        )
        _require_relative_path(layer["path"], name="OCI layer path")
        layer_digests.append(
            _require_digest(layer["digest"], name="OCI layer digest")
        )
        _require_int(
            layer["size"],
            name="OCI layer size",
            minimum=1,
            maximum=MAX_FILE_BYTES,
        )
        _require_ascii(
            layer["mediaType"], name="OCI layer media type", maximum=256
        )
    if len(layer_digests) != len(set(layer_digests)):
        raise ArtifactContractError("OCI layer digest is repeated")

    index_fields = (
        "indexPath",
        "indexDigest",
        "indexSize",
        "indexMediaType",
        "indexDocumentBase64Url",
    )
    has_index = all(oci[field] is not None for field in index_fields)
    if has_index != any(oci[field] is not None for field in index_fields):
        raise ArtifactContractError(
            "OCI index descriptor is only partially present"
        )
    if has_index:
        index_path = _require_relative_path(
            oci["indexPath"], name="OCI index path"
        )
        index_digest = _require_digest(
            oci["indexDigest"], name="OCI index digest"
        )
        index_size = _require_int(
            oci["indexSize"],
            name="OCI index size",
            minimum=1,
            maximum=MAX_FILE_BYTES,
        )
        index_media_type = _require_ascii(
            oci["indexMediaType"],
            name="OCI index media type",
            maximum=256,
        )
        index_bytes, index_document = _strict_json_document(
            oci["indexDocumentBase64Url"],
            name="OCI index",
            maximum_bytes=MAX_FILE_BYTES,
        )
        manifests = index_document.get("manifests")
        matches = (
            [
                descriptor
                for descriptor in manifests
                if isinstance(descriptor, Mapping)
                and descriptor.get("digest") == manifest_digest
                and descriptor.get("size") == manifest_size
                and descriptor.get("mediaType") == manifest_media_type
                and descriptor.get("platform") == dict(platform)
            ]
            if isinstance(manifests, list)
            else []
        )
        if (
            index_document.get("schemaVersion") != 2
            or index_document.get("mediaType") != index_media_type
            or len(index_bytes) != index_size
            or "sha256:" + hashlib.sha256(index_bytes).hexdigest()
                != index_digest
            or len(matches) != 1
            or (
                root_path,
                root_digest,
                root_size,
                root_media_type,
                root_bytes,
            )
            != (
                index_path,
                index_digest,
                index_size,
                index_media_type,
                index_bytes,
            )
        ):
            raise ArtifactContractError(
                "OCI index does not select the exact platform manifest"
            )
    elif (
        root_path,
        root_digest,
        root_size,
        root_media_type,
        root_bytes,
    ) != (
        manifest_path,
        manifest_digest,
        manifest_size,
        manifest_media_type,
        manifest_bytes,
    ):
        raise ArtifactContractError(
            "OCI manifest root descriptor is not exact"
        )

    manifest_config = manifest_document.get("config")
    manifest_layers = manifest_document.get("layers")
    expected_layer_descriptors = [
        {
            "mediaType": layer["mediaType"],
            "digest": layer["digest"],
            "size": layer["size"],
        }
        for layer in layers
    ]
    if (
        manifest_document.get("schemaVersion") != 2
        or manifest_document.get("mediaType") != manifest_media_type
        or not isinstance(manifest_config, Mapping)
        or {
            key: manifest_config.get(key)
            for key in ("mediaType", "digest", "size")
        }
        != {
            "mediaType": config_media_type,
            "digest": config_digest,
            "size": config_size,
        }
        or not isinstance(manifest_layers, list)
        or [
            {
                key: descriptor.get(key)
                for key in ("mediaType", "digest", "size")
            }
            for descriptor in manifest_layers
            if isinstance(descriptor, Mapping)
        ]
            != expected_layer_descriptors
        or len(manifest_layers) != len(expected_layer_descriptors)
    ):
        raise ArtifactContractError(
            "OCI manifest does not select the exact config and layers"
        )
    config_rootfs = config_document.get("rootfs")
    if (
        config_document.get("architecture") != platform["architecture"]
        or config_document.get("os") != platform["os"]
        or config_document.get("variant") != platform["variant"]
        or not isinstance(config_rootfs, Mapping)
        or config_rootfs.get("type") != "layers"
        or not isinstance(config_rootfs.get("diff_ids"), list)
        or len(config_rootfs["diff_ids"]) != len(layers)
        or any(
            _require_digest(digest, name="OCI config diff ID")
                != digest
            for digest in config_rootfs["diff_ids"]
        )
    ):
        raise ArtifactContractError(
            "OCI config does not bind the claimed platform and layer count"
        )

    root_file = file_by_path.get(root_path)
    manifest_file = file_by_path.get(manifest_path)
    config_file = file_by_path.get(config_path)
    if (
        root_file is None
        or root_file["sha256"] != root_digest
        or root_file["size"] != root_size
        or manifest_file is None
        or manifest_file["sha256"] != manifest_digest
        or manifest_file["size"] != manifest_size
        or config_file is None
        or config_file["sha256"] != config_digest
        or config_file["size"] != config_size
    ):
        raise ArtifactContractError(
            "OCI manifest or configuration bytes are not in the bundle"
        )
    for layer in layers:
        layer_file = file_by_path.get(layer["path"])
        if (
            layer_file is None
            or layer_file["sha256"] != layer["digest"]
            or layer_file["size"] != layer["size"]
        ):
            raise ArtifactContractError(
                "OCI layer bytes are not in the bundle"
            )
    if (
        provenance["sourceRevision"] != value["sourceRevision"]
        or provenance["sourceCommitDigest"]
            != value["sourceCommitDigest"]
        or provenance["sourceTreeDigest"] != source_tree["digest"]
        or provenance["ociRootDigest"] != root_digest
    ):
        raise ArtifactContractError(
            "provenance does not bind revision, tree, and OCI root"
        )
    provenance_payload = {
        key: provenance[key]
        for key in (
            "path",
            "sha256",
            "predicateType",
            "mediaType",
            "builderId",
            "sourceRevision",
            "sourceCommitDigest",
            "sourceTreeDigest",
            "ociRootDigest",
        )
    }
    if provenance["statementDigest"] != domain_digest(
        PROVENANCE_PAYLOAD_DIGEST_DOMAIN,
        canonical_json_bytes(provenance_payload),
    ):
        raise ArtifactContractError(
            "provenance statement digest is not canonical"
        )

    stage_zero = _validate_digest_file_reference(
        value["stageZero"],
        name="native stage zero",
        extra_keys={
            "size",
            "interfaceSchema",
            "runtimePath",
            "staticElf",
            "ptInterp",
            "needed",
            "elfEvidenceDigest",
        },
    )
    _require_identifier(
        stage_zero["interfaceSchema"], name="stage-zero interface schema"
    )
    _require_runtime_path(
        stage_zero["runtimePath"], name="stage-zero runtime path"
    )
    if stage_zero["staticElf"] is not True:
        raise ArtifactContractError("stage zero must be a static ELF")
    if stage_zero["ptInterp"] is not None or stage_zero["needed"] != []:
        raise ArtifactContractError(
            "stage zero cannot have an interpreter or dynamic dependencies"
        )
    _require_digest(
        stage_zero["elfEvidenceDigest"],
        name="stage-zero ELF evidence digest",
    )
    if stage_zero != closure_payload["stageZero"]:
        raise ArtifactContractError(
            "stage zero is not the externally verified static image"
        )

    operation_manifest = _validate_digest_file_reference(
        value["operationManifest"],
        name="operation manifest",
        extra_keys={"manifestSchema", "contractDigest"},
    )
    _require_identifier(
        operation_manifest["manifestSchema"],
        name="operation manifest schema",
    )
    _require_digest(
        operation_manifest["contractDigest"],
        name="operation manifest contract digest",
    )
    if (
        operation_manifest["manifestSchema"] != authority_contract.CONTRACT_SCHEMA
        or operation_manifest["contractDigest"]
            != authority_contract.OPERATION_MANIFEST_DIGEST
    ):
        raise ArtifactContractError(
            "operation manifest does not match the source contract"
        )

    referenced = [
        *schemas,
        *migrations,
        *configurations,
        *roles,
        sbom,
        provenance,
        stage_zero,
        operation_manifest,
    ]
    for reference in referenced:
        file_entry = file_by_path.get(reference["path"])
        if (
            file_entry is None
            or file_entry["sha256"] != reference["sha256"]
        ):
            raise ArtifactContractError(
                "bundle reference is outside the measured file set"
            )
    for migration in migrations:
        receipt_file = file_by_path.get(migration["receiptPath"])
        receipt_bytes = canonical_json_bytes(
            migration["receiptPayload"]
        )
        if (
            receipt_file is None
            or receipt_file["sha256"]
                != "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()
            or receipt_file["size"] != len(receipt_bytes)
            or receipt_file["kind"] != "data"
        ):
            raise ArtifactContractError(
                "migration receipt file is outside the measured bundle"
            )
    expected_kinds = (
        [(entry, "schema") for entry in schemas]
        + [(entry, "migration") for entry in migrations]
        + [(entry, "configuration") for entry in configurations]
        + [(entry, "role-manifest") for entry in roles]
        + [
            (sbom, "sbom"),
            (provenance, "provenance"),
            (stage_zero, "native-stage-zero"),
            (operation_manifest, "operation-manifest"),
        ]
    )
    for reference, expected_kind in expected_kinds:
        if file_by_path[reference["path"]]["kind"] != expected_kind:
            raise ArtifactContractError(
                f"{expected_kind} reference has the wrong file kind"
            )


def validate_generation_statement(
    statement: Mapping[str, Any],
    *,
    expected_bundle_digest: str | None = None,
) -> None:
    value = _require_mapping(
        statement,
        name="generation statement",
        keys={
            "schema",
            "sequence",
            "generationId",
            "predecessorDigest",
            "minimumRollbackSequence",
            "validFrom",
            "validUntil",
            "artifactBundleDigest",
            "operationManifestDigest",
            "stageZeroDigest",
            "stageZeroContract",
            "roleSetDigest",
            "snapshotReceiptDigest",
            "closureReceiptDigest",
            "provenanceStatementDigest",
            "sourceTreeDigest",
            "ociManifestDigest",
            "migrationReceiptDigests",
            "roleManifestDigests",
            "configurationDigests",
            "configurationPayloadBindings",
            "keyAuthorizationsDigest",
            "keyRevocationsDigest",
            "witnessCheckpoint",
            "trustMode",
        },
    )
    if value["schema"] != GENERATION_STATEMENT_SCHEMA:
        raise ArtifactContractError("generation schema changed")
    sequence = _require_int(
        value["sequence"],
        name="generation sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    _require_identifier(value["generationId"], name="generation identifier")
    predecessor = value["predecessorDigest"]
    if predecessor is not None:
        _require_digest(predecessor, name="predecessor generation digest")
    if (sequence == 0) != (predecessor is None):
        raise ArtifactContractError(
            "only the genesis generation can omit its predecessor"
        )
    minimum_rollback = _require_int(
        value["minimumRollbackSequence"],
        name="minimum rollback sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    if minimum_rollback > sequence:
        raise ArtifactContractError("rollback floor exceeds generation")
    valid_from = _require_timestamp(value["validFrom"], name="validFrom")
    valid_until = _require_timestamp(value["validUntil"], name="validUntil")
    if valid_until <= valid_from:
        raise ArtifactContractError(
            "generation validity interval is not increasing"
        )
    bundle_digest = _require_digest(
        value["artifactBundleDigest"], name="artifact bundle digest"
    )
    if (
        expected_bundle_digest is not None
        and bundle_digest != expected_bundle_digest
    ):
        raise ArtifactContractError(
            "generation does not bind the artifact bundle"
        )
    _require_digest(
        value["operationManifestDigest"],
        name="operation manifest digest",
    )
    _require_digest(value["stageZeroDigest"], name="stage-zero digest")
    _require_identifier(
        value["stageZeroContract"], name="stage-zero contract"
    )
    for field in (
        "roleSetDigest",
        "snapshotReceiptDigest",
        "closureReceiptDigest",
        "provenanceStatementDigest",
        "sourceTreeDigest",
        "ociManifestDigest",
    ):
        _require_digest(value[field], name=field)
    for field, maximum in (
        ("migrationReceiptDigests", MAX_MIGRATIONS),
        ("roleManifestDigests", MAX_ROLE_MANIFESTS),
        ("configurationDigests", MAX_CONFIGURATION_DIGESTS),
    ):
        digests = _require_list(
            value[field], name=field, maximum=maximum
        )
        for digest in digests:
            _require_digest(digest, name=field)
        if list(digests) != sorted(set(digests)):
            raise ArtifactContractError(f"{field} is not sorted and unique")
    validate_configuration_payload_bindings(
        value["configurationPayloadBindings"],
        configuration_digests=value["configurationDigests"],
    )
    _require_digest(
        value["keyAuthorizationsDigest"],
        name="key authorizations digest",
    )
    _require_digest(
        value["keyRevocationsDigest"], name="key revocations digest"
    )
    checkpoint = _require_mapping(
        value["witnessCheckpoint"],
        name="witness checkpoint",
        keys={
            "schema",
            "payload",
            "signerKeyId",
            "algorithm",
            "signatureBase64Url",
        },
    )
    if checkpoint["schema"] != (
        "serverware.signedAuthorityWitnessCheckpoint/v1"
    ) or checkpoint["algorithm"] != "Ed25519":
        raise ArtifactContractError("witness checkpoint envelope changed")
    _require_identifier(
        checkpoint["signerKeyId"], name="witness checkpoint signer"
    )
    strict_base64url_decode(
        checkpoint["signatureBase64Url"],
        name="witness checkpoint signature",
        decoded_size=64,
    )
    checkpoint_payload = _require_mapping(
        checkpoint["payload"],
        name="witness checkpoint payload",
        keys={
            "schema",
            "identity",
            "sequence",
            "previousCheckpointDigest",
            "previousRootDigest",
            "previousTreeSize",
            "treeSize",
            "generationCoreDigest",
            "leafDigest",
            "rootDigest",
            "issuedAt",
            "coLocated",
            "hardwareBacked",
        },
    )
    if checkpoint_payload["schema"] != (
        "serverware.authorityWitnessCheckpointPayload/v1"
    ):
        raise ArtifactContractError(
            "witness checkpoint payload schema changed"
        )
    checkpoint_sequence = _require_int(
        checkpoint_payload["sequence"],
        name="witness checkpoint sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    if checkpoint_sequence != sequence:
        raise ArtifactContractError(
            "witness checkpoint is for another generation"
        )
    _require_identifier(
        checkpoint_payload["identity"], name="witness identity"
    )
    for field in (
        "previousCheckpointDigest",
        "previousRootDigest",
        "generationCoreDigest",
        "leafDigest",
        "rootDigest",
    ):
        _require_digest(checkpoint_payload[field], name=field)
    previous_tree_size = _require_int(
        checkpoint_payload["previousTreeSize"],
        name="previous witness tree size",
        minimum=0,
        maximum=2**63 - 1,
    )
    tree_size = _require_int(
        checkpoint_payload["treeSize"],
        name="witness tree size",
        minimum=1,
        maximum=2**63 - 1,
    )
    if tree_size != previous_tree_size + 1:
        raise ArtifactContractError(
            "witness checkpoint is not an append-only successor"
        )
    _require_timestamp(checkpoint_payload["issuedAt"], name="witness issuedAt")
    if (
        not isinstance(checkpoint_payload["coLocated"], bool)
        or not isinstance(checkpoint_payload["hardwareBacked"], bool)
    ):
        raise ArtifactContractError("witness claims must be boolean")
    _validate_trust_mode(value["trustMode"])
    mode = value["trustMode"]["mode"]
    if mode == "trusted-host-local" and (
        checkpoint_payload["coLocated"] is not True
        or checkpoint_payload["hardwareBacked"] is not False
    ):
        raise ArtifactContractError(
            "local trusted-host witness claims are contradictory"
        )
    if mode != "trusted-host-local" and checkpoint_payload["coLocated"]:
        raise ArtifactContractError(
            "production witness cannot be co-located"
        )
    if (
        mode == "tee-hardware"
        and checkpoint_payload["hardwareBacked"] is not True
    ):
        raise ArtifactContractError(
            "TEE generation requires a hardware-backed checkpoint"
        )
    expected_core_digest = generation_core_digest(value)
    expected_leaf_digest = domain_digest(
        WITNESS_LEAF_DIGEST_DOMAIN,
        expected_core_digest.encode("ascii"),
    )
    expected_root_digest = domain_digest(
        WITNESS_CHAIN_ROOT_DOMAIN,
        checkpoint_payload["previousRootDigest"].encode("ascii"),
        str(tree_size).encode("ascii"),
        expected_leaf_digest.encode("ascii"),
    )
    if (
        checkpoint_payload["generationCoreDigest"] != expected_core_digest
        or checkpoint_payload["leafDigest"] != expected_leaf_digest
        or checkpoint_payload["rootDigest"] != expected_root_digest
    ):
        raise ArtifactContractError(
            "witness checkpoint consistency proof is invalid"
        )


def validate_signed_artifact_package(package: Mapping[str, Any]) -> None:
    value = _require_mapping(
        package,
        name="signed artifact package",
        keys={
            "schema",
            "bundle",
            "generation",
            "trustMaterial",
            "signatures",
        },
    )
    if value["schema"] != SIGNED_PACKAGE_SCHEMA:
        raise ArtifactContractError("signed package schema changed")
    validate_artifact_bundle(value["bundle"])
    validate_generation_statement(
        value["generation"],
        expected_bundle_digest=artifact_bundle_digest(value["bundle"]),
    )
    _validate_generation_bundle_bindings(
        value["bundle"], value["generation"], value["trustMaterial"]
    )
    signatures = _require_list(
        value["signatures"],
        name="package signatures",
        minimum=len(SIGNATURE_PURPOSES),
        maximum=len(SIGNATURE_PURPOSES),
    )
    for signature in signatures:
        entry = _require_mapping(
            signature,
            name="package signature",
            keys={"purpose", "algorithm", "keyId", "signatureBase64Url"},
        )
        if entry["purpose"] not in SIGNATURE_PURPOSES:
            raise ArtifactContractError("signature purpose is not recognized")
        if entry["algorithm"] != "Ed25519":
            raise ArtifactContractError("signature algorithm changed")
        _require_identifier(entry["keyId"], name="signature key identifier")
        encoded = _require_ascii(
            entry["signatureBase64Url"],
            name="signature",
            maximum=86,
        )
        strict_base64url_decode(
            encoded,
            name="signature",
            decoded_size=64,
        )
    purposes = [entry["purpose"] for entry in signatures]
    if purposes != ["artifact-bundle", "generation"]:
        raise ArtifactContractError(
            "signed package signatures are not in canonical order"
        )


def verify_signed_artifact_package(
    package: Mapping[str, Any],
    *,
    trust_state: Mapping[str, Any],
    validation_time: str,
) -> VerifiedArtifactPackage:
    validate_signed_artifact_package(package)
    state = validate_trust_state(trust_state)
    _require_timestamp(validation_time, name="package validation time")
    bundle = package["bundle"]
    generation = package["generation"]
    generation_digest = generation_statement_digest(generation)
    package_digest = signed_artifact_package_digest(package)
    sequence = generation["sequence"]
    current_sequence = state["currentSequence"]
    if sequence == current_sequence:
        if (
            generation_digest != state["currentGenerationDigest"]
            or package_digest != state["currentPackageDigest"]
            or generation_digest
            not in state["acceptedGenerationDigests"]
            or package_digest not in state["acceptedPackageDigests"]
        ):
            raise ArtifactContractError(
                "current-generation replay differs from accepted bytes"
            )
        disposition = "CurrentExactRetry"
    elif sequence == current_sequence + 1:
        expected_predecessor = (
            None
            if current_sequence == -1
            else state["currentGenerationDigest"]
        )
        if generation["predecessorDigest"] != expected_predecessor:
            raise ArtifactContractError(
                "generation predecessor does not match current high-water"
            )
        if (
            generation_digest in state["acceptedGenerationDigests"]
            or package_digest in state["acceptedPackageDigests"]
        ):
            raise ArtifactContractError(
                "successor package reuses an accepted replay identity"
            )
        disposition = "Successor"
    else:
        raise ArtifactContractError(
            "generation is stale or skips the current high-water"
        )
    if generation["minimumRollbackSequence"] < state[
        "minimumRollbackSequence"
    ]:
        raise ArtifactContractError("generation lowers the rollback floor")
    if not generation["validFrom"] <= validation_time <= generation[
        "validUntil"
    ]:
        raise ArtifactContractError(
            "generation is outside its validity interval"
        )

    keys, revoked = _verify_key_documents(
        package["trustMaterial"],
        bundle=bundle,
        generation=generation,
        trust_state=state,
        validation_time=validation_time,
    )
    for signature in package["signatures"]:
        purpose = signature["purpose"]
        key_id = signature["keyId"]
        try:
            key = keys[key_id]
        except KeyError as exc:
            raise ArtifactContractError(
                "package signer is not generation-authorized"
            ) from exc
        if (
            purpose not in key.purposes
            or key_id in revoked
            or not key.not_before <= validation_time <= key.not_after
        ):
            raise ArtifactContractError(
                "package signer is unauthorized, revoked, or expired"
            )
        verify_ed25519_signature(
            key.public_key,
            signature["signatureBase64Url"],
            package_signature_message(purpose, bundle, generation),
            name=f"{purpose} package",
        )

    evidence_specs = (
        (
            bundle["stableSnapshotReceipt"],
            "stable-snapshot-verifier",
            "serverware.authorityStableSnapshotReceiptSignature/v1",
            snapshot_receipt_digest(bundle["stableSnapshotReceipt"]),
            "stable snapshot",
        ),
        (
            bundle["closureReceipt"],
            "closure-verifier",
            "serverware.authorityCompleteClosureReceiptSignature/v1",
            closure_receipt_digest(bundle["closureReceipt"]),
            "complete closure",
        ),
    )
    for receipt, purpose, signature_domain, digest, name in evidence_specs:
        if not receipt["payload"]["createdAt"] <= validation_time <= receipt[
            "payload"
        ]["expiresAt"]:
            raise ArtifactContractError(
                f"{name} receipt is outside its validity interval"
            )
        signer_id = receipt["signerKeyId"]
        try:
            key = keys[signer_id]
        except KeyError as exc:
            raise ArtifactContractError(
                f"{name} signer is not generation-authorized"
            ) from exc
        if (
            purpose not in key.purposes
            or signer_id in revoked
            or not key.not_before <= validation_time <= key.not_after
        ):
            raise ArtifactContractError(
                f"{name} signer is unauthorized or revoked"
            )
        verify_ed25519_signature(
            key.public_key,
            receipt["signatureBase64Url"],
            _signature_message(signature_domain, receipt["payload"]),
            name=name,
        )
        if disposition == "Successor" and digest in state[
            "acceptedEvidenceDigests"
        ]:
            raise ArtifactContractError(
                f"{name} evidence was already consumed"
            )
        if disposition == "CurrentExactRetry" and digest not in state[
            "acceptedEvidenceDigests"
        ]:
            raise ArtifactContractError(
                f"{name} is absent from current replay high-water"
            )

    provenance = bundle["provenance"]
    provenance_key = keys.get(provenance["signerKeyId"])
    if (
        provenance_key is None
        or "provenance" not in provenance_key.purposes
        or provenance_key.key_id in revoked
        or not provenance_key.not_before
        <= validation_time
        <= provenance_key.not_after
    ):
        raise ArtifactContractError(
            "provenance signer is unauthorized or revoked"
        )
    provenance_payload = {
        key: provenance[key]
        for key in (
            "path",
            "sha256",
            "predicateType",
            "mediaType",
            "builderId",
            "sourceRevision",
            "sourceCommitDigest",
            "sourceTreeDigest",
            "ociRootDigest",
            "statementDigest",
        )
    }
    verify_ed25519_signature(
        provenance_key.public_key,
        provenance["signatureBase64Url"],
        _signature_message(
            PROVENANCE_SIGNATURE_DOMAIN,
            provenance_payload,
        ),
        name="supply-chain provenance",
    )
    for migration in bundle["migrations"]:
        migration_key = keys.get(migration["receiptSignerKeyId"])
        if (
            migration_key is None
            or "migration-receipt" not in migration_key.purposes
            or migration_key.key_id in revoked
            or not migration_key.not_before
            <= validation_time
            <= migration_key.not_after
        ):
            raise ArtifactContractError(
                "migration receipt signer is unauthorized or revoked"
            )
        if migration["receiptPayload"]["signerIdentityDigest"] != (
            domain_digest(
                authority_contract.MIGRATION_SIGNER_IDENTITY_DOMAIN,
                migration_key.public_key,
            )
        ):
            raise ArtifactContractError(
                "migration receipt signer identity changed"
            )
        verify_ed25519_signature(
            migration_key.public_key,
            migration["receiptSignatureBase64Url"],
            _signature_message(
                authority_contract.MIGRATION_RECEIPT_SIGNATURE_DOMAIN,
                migration["receiptPayload"],
            ),
            name=f"migration {migration['name']}",
        )

    checkpoint = generation["witnessCheckpoint"]
    checkpoint_payload = checkpoint["payload"]
    witness = state["witness"]
    checkpoint_digest = witness_checkpoint_digest(checkpoint)
    if (
        checkpoint["signerKeyId"] != witness["keyId"]
        or checkpoint_payload["identity"] != witness["identity"]
    ):
        raise ArtifactContractError(
            "witness checkpoint signer or identity changed"
        )
    verify_ed25519_signature(
        witness["publicKey"],
        checkpoint["signatureBase64Url"],
        _signature_message(
            WITNESS_CHECKPOINT_SIGNATURE_DOMAIN,
            checkpoint_payload,
        ),
        name="witness checkpoint",
    )
    if checkpoint_payload["issuedAt"] > validation_time:
        raise ArtifactContractError(
            "witness checkpoint is from the future"
        )
    if disposition == "Successor":
        if (
            checkpoint_payload["previousCheckpointDigest"]
            != witness["currentCheckpointDigest"]
            or checkpoint_payload["previousRootDigest"]
            != witness["currentRootDigest"]
            or checkpoint_payload["previousTreeSize"]
            != witness["currentTreeSize"]
            or checkpoint_payload["treeSize"]
            != witness["currentTreeSize"] + 1
        ):
            raise ArtifactContractError(
                "witness checkpoint is not consistent with high-water"
            )
    elif (
        checkpoint_digest != witness["currentCheckpointDigest"]
        or checkpoint_payload["rootDigest"] != witness["currentRootDigest"]
        or checkpoint_payload["treeSize"] != witness["currentTreeSize"]
    ):
        raise ArtifactContractError(
            "current-generation checkpoint replay changed"
        )

    role_set_digest = domain_digest(
        "serverware.authorityRoleSet/v1",
        canonical_json_bytes(bundle["roleManifests"]),
    )
    if generation["roleSetDigest"] != role_set_digest:
        raise ArtifactContractError("generation role set changed")
    return VerifiedArtifactPackage(
        package_digest=package_digest,
        artifact_bundle_digest=artifact_bundle_digest(bundle),
        generation_digest=generation_digest,
        generation_sequence=sequence,
        predecessor_digest=generation["predecessorDigest"],
        minimum_rollback_sequence=generation["minimumRollbackSequence"],
        trust_mode=generation["trustMode"]["mode"],
        operation_manifest_digest=generation["operationManifestDigest"],
        stage_zero_digest=generation["stageZeroDigest"],
        stage_zero_contract=generation["stageZeroContract"],
        role_set_digest=role_set_digest,
        key_authorizations_digest=generation["keyAuthorizationsDigest"],
        key_revocations_digest=generation["keyRevocationsDigest"],
        witness_checkpoint_digest=checkpoint_digest,
        witness_root_digest=checkpoint_payload["rootDigest"],
        witness_tree_size=checkpoint_payload["treeSize"],
        disposition=disposition,
        keys=MappingProxyType(dict(keys)),
        revoked_key_ids=revoked,
        package=MappingProxyType(dict(package)),
    )


def _validate_generation_bundle_bindings(
    bundle: Mapping[str, Any],
    generation: Mapping[str, Any],
    trust_material: Mapping[str, Any],
) -> None:
    configuration_digests = sorted(
        entry["sha256"] for entry in bundle["configurations"]
    )
    role_set_digest = domain_digest(
        "serverware.authorityRoleSet/v1",
        canonical_json_bytes(bundle["roleManifests"]),
    )
    if (
        generation["operationManifestDigest"]
        != bundle["operationManifest"]["contractDigest"]
        or generation["stageZeroDigest"] != bundle["stageZero"]["sha256"]
        or generation["migrationReceiptDigests"]
        != sorted(
            migration["receiptDigest"]
            for migration in bundle["migrations"]
        )
        or generation["roleManifestDigests"]
        != sorted(role["sha256"] for role in bundle["roleManifests"])
        or generation["trustMode"] != bundle["trustMode"]
        or generation["configurationDigests"] != configuration_digests
        or generation["configurationPayloadBindings"]
        != configuration_payload_bindings(bundle["configurations"])
        or generation["roleSetDigest"] != role_set_digest
        or generation["stageZeroContract"]
        != bundle["stageZero"]["interfaceSchema"]
        or generation["snapshotReceiptDigest"]
        != snapshot_receipt_digest(bundle["stableSnapshotReceipt"])
        or generation["closureReceiptDigest"]
        != closure_receipt_digest(bundle["closureReceipt"])
        or generation["provenanceStatementDigest"]
        != bundle["provenance"]["statementDigest"]
        or generation["sourceTreeDigest"] != bundle["sourceTree"]["digest"]
        or generation["ociManifestDigest"]
        != bundle["ociImage"]["rootDigest"]
        or trust_document_digest(trust_material["keyAuthorizations"])
        != generation["keyAuthorizationsDigest"]
        or trust_document_digest(trust_material["keyRevocations"])
        != generation["keyRevocationsDigest"]
    ):
        raise ArtifactContractError(
            "generation references do not match the artifact bundle"
        )


def validate_unsigned_artifact_package(package: Mapping[str, Any]) -> None:
    value = _require_mapping(
        package,
        name="unsigned artifact package",
        keys={
            "schema",
            "bundle",
            "generation",
            "trustMaterial",
            "signatureRequests",
        },
    )
    if value["schema"] != UNSIGNED_PACKAGE_SCHEMA:
        raise ArtifactContractError("unsigned package schema changed")
    validate_artifact_bundle(value["bundle"])
    validate_generation_statement(
        value["generation"],
        expected_bundle_digest=artifact_bundle_digest(value["bundle"]),
    )
    _validate_generation_bundle_bindings(
        value["bundle"], value["generation"], value["trustMaterial"]
    )
    requests = _require_list(
        value["signatureRequests"],
        name="signature requests",
        minimum=len(SIGNATURE_PURPOSES),
        maximum=len(SIGNATURE_PURPOSES),
    )
    for request in requests:
        entry = _require_mapping(
            request,
            name="signature request",
            keys={"purpose", "algorithm", "keyId", "messageBase64Url"},
        )
        if entry["purpose"] not in SIGNATURE_PURPOSES:
            raise ArtifactContractError("signature purpose is not recognized")
        if entry["algorithm"] != "Ed25519":
            raise ArtifactContractError("signature algorithm changed")
        _require_identifier(entry["keyId"], name="signature key identifier")
        encoded = _require_ascii(
            entry["messageBase64Url"],
            name="signature request message",
            maximum=512,
        )
        decoded = strict_base64url_decode(
            encoded,
            name="signature request",
            maximum_decoded_size=512,
        )
        expected = package_signature_message(
            entry["purpose"], value["bundle"], value["generation"]
        )
        if decoded != expected:
            raise ArtifactContractError(
                "signature request message is not canonical"
            )
    purposes = [entry["purpose"] for entry in requests]
    if purposes != ["artifact-bundle", "generation"]:
        raise ArtifactContractError(
            "signature requests are not in canonical order"
        )


def assemble_signed_artifact_package(
    unsigned_package: Mapping[str, Any],
    signatures: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    validate_unsigned_artifact_package(unsigned_package)
    package = {
        "schema": SIGNED_PACKAGE_SCHEMA,
        "bundle": unsigned_package["bundle"],
        "generation": unsigned_package["generation"],
        "trustMaterial": unsigned_package["trustMaterial"],
        "signatures": [dict(signature) for signature in signatures],
    }
    validate_signed_artifact_package(package)
    for request, signature in zip(
        unsigned_package["signatureRequests"],
        package["signatures"],
        strict=True,
    ):
        if (
            request["purpose"] != signature["purpose"]
            or request["algorithm"] != signature["algorithm"]
            or request["keyId"] != signature["keyId"]
        ):
            raise ArtifactContractError(
                "signature does not answer its canonical signing request"
            )
    return package


def _closed_object_schema(
    properties: Mapping[str, Any],
    *,
    required: Sequence[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(required or properties),
        "properties": dict(properties),
    }


SHA256_JSON_SCHEMA = {
    "type": "string",
    "pattern": "^sha256:[0-9a-f]{64}$",
}
RELATIVE_PATH_JSON_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 4096,
    "pattern": "^(?!/)(?!.*(?:^|/)\\.\\.?/)(?!-).+$",
}
ARTIFACT_FILE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "kind": {"enum": sorted(FILE_KINDS)},
        "mode": {"type": "integer", "minimum": 0, "maximum": 4095},
        "uid": {"type": "integer", "minimum": 0, "maximum": 4294967294},
        "gid": {"type": "integer", "minimum": 0, "maximum": 4294967294},
        "size": {"type": "integer", "minimum": 0, "maximum": MAX_FILE_BYTES},
        "sha256": SHA256_JSON_SCHEMA,
    }
)
TEXT_JSON_SCHEMA = {"type": "string"}
INTEGER_JSON_SCHEMA = {"type": "integer"}
TIMESTAMP_JSON_SCHEMA = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
STRING_ARRAY_JSON_SCHEMA = {
    "type": "array",
    "items": TEXT_JSON_SCHEMA,
}
CONFIGURATION_GENERATION_BINDING_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": CONFIGURATION_GENERATION_BINDING_SCHEMA},
        "generationId": {
            "type": "string", "minLength": 1, "maxLength": 256,
            "pattern": "^[A-Za-z][A-Za-z0-9._:/-]*$",
        },
        "sequence": {"type": "integer", "minimum": 0, "maximum": 2**63 - 1},
        "predecessorDigest": {"anyOf": [SHA256_JSON_SCHEMA, {"type": "null"}]},
        "minimumRollbackSequence": {
            "type": "integer", "minimum": 0, "maximum": 2**63 - 1,
        },
        "validFrom": TIMESTAMP_JSON_SCHEMA,
        "validUntil": TIMESTAMP_JSON_SCHEMA,
        "operationManifestDigest": SHA256_JSON_SCHEMA,
        "trustMode": {"enum": sorted(TRUST_MODES)},
    }
)
ROLE_RUNTIME_CLOSURE_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": ROLE_RUNTIME_CLOSURE_SCHEMA},
        "roleBindingDigest": SHA256_JSON_SCHEMA,
        "packageVersions": {
            "type": "object", "minProperties": 1, "maxProperties": 4096,
            "propertyNames": {
                "type": "string", "minLength": 1, "maxLength": 256,
                "pattern": "^[\\u0000-\\u007f]+$",
            },
            "additionalProperties": {
                "type": "string", "minLength": 1, "maxLength": 256,
                "pattern": "^[\\u0000-\\u007f]+$",
            },
        },
    }
)
ROOT_IDENTITY_JSON_SCHEMA = _closed_object_schema(
    {
        "runtimePath": TEXT_JSON_SCHEMA,
        "device": INTEGER_JSON_SCHEMA,
        "inode": INTEGER_JSON_SCHEMA,
        "generation": INTEGER_JSON_SCHEMA,
        "mountId": INTEGER_JSON_SCHEMA,
        "mode": INTEGER_JSON_SCHEMA,
        "uid": INTEGER_JSON_SCHEMA,
        "gid": INTEGER_JSON_SCHEMA,
    }
)
PYTHON_IMPORT_JSON_SCHEMA = _closed_object_schema(
    {
        "module": TEXT_JSON_SCHEMA,
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "kind": {"enum": ["source", "bytecode", "extension"]},
        "isPackage": {"type": "boolean"},
        "sha256": SHA256_JSON_SCHEMA,
    }
)
NATIVE_OBJECT_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "runtimePath": TEXT_JSON_SCHEMA,
        "soname": {
            "anyOf": [{"type": "null"}, TEXT_JSON_SCHEMA]
        },
        "elfClass": {"enum": ["ELF32", "ELF64"]},
        "machine": INTEGER_JSON_SCHEMA,
        "needed": STRING_ARRAY_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
    }
)
NATIVE_EXECUTABLE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "runtimePath": TEXT_JSON_SCHEMA,
        "elfClass": {"enum": ["ELF32", "ELF64"]},
        "machine": INTEGER_JSON_SCHEMA,
        "ptInterp": {
            "anyOf": [{"type": "null"}, TEXT_JSON_SCHEMA]
        },
        "needed": STRING_ARRAY_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
    }
)
STAGE_ZERO_REFERENCE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "size": INTEGER_JSON_SCHEMA,
        "interfaceSchema": TEXT_JSON_SCHEMA,
        "runtimePath": TEXT_JSON_SCHEMA,
        "staticElf": {"const": True},
        "ptInterp": {"type": "null"},
        "needed": {"type": "array", "maxItems": 0},
        "elfEvidenceDigest": SHA256_JSON_SCHEMA,
    }
)
SIGNED_EVIDENCE_ENVELOPE_FIELDS = {
    "signerKeyId": TEXT_JSON_SCHEMA,
    "algorithm": {"const": "Ed25519"},
    "signatureBase64Url": {
        "type": "string",
        "pattern": "^[A-Za-z0-9_-]{86}$",
    },
}
SNAPSHOT_RECEIPT_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": SNAPSHOT_RECEIPT_SCHEMA},
        "payload": _closed_object_schema(
            {
                "schema": {
                    "const": (
                        "serverware.authorityStableSnapshotReceiptPayload/v1"
                    )
                },
                "receiptId": SHA256_JSON_SCHEMA,
                "rootIdentity": ROOT_IDENTITY_JSON_SCHEMA,
                "snapshotKind": {
                    "enum": [
                        "atomic-filesystem-snapshot",
                        "content-addressed-cas",
                    ]
                },
                "readOnly": {"const": True},
                "treeAlgorithm": {
                    "const": "canonical-path-tree-sha256-v1"
                },
                "treeDigest": SHA256_JSON_SCHEMA,
                "treeEntryCount": INTEGER_JSON_SCHEMA,
                "totalBytes": INTEGER_JSON_SCHEMA,
                "enumeratedTreeDigest": SHA256_JSON_SCHEMA,
                "createdAt": TIMESTAMP_JSON_SCHEMA,
                "expiresAt": TIMESTAMP_JSON_SCHEMA,
            }
        ),
        **SIGNED_EVIDENCE_ENVELOPE_FIELDS,
    }
)
CLOSURE_COVERAGE_JSON_SCHEMA = _closed_object_schema(
    {
        **{
            field: {"const": True}
            for field in (
                "pythonStaticImports",
                "pythonDynamicImports",
                "ptInterp",
                "dtNeeded",
                "rpath",
                "runpath",
                "audit",
                "depaudit",
                "filter",
                "auxiliary",
                "dlopen",
                "nss",
                "plugins",
                "ifunc",
                "hwcap",
            )
        },
        "coverageEvidenceDigest": SHA256_JSON_SCHEMA,
    }
)
CLOSURE_RECEIPT_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": CLOSURE_RECEIPT_SCHEMA},
        "payload": _closed_object_schema(
            {
                "schema": {
                    "const": (
                        "serverware.authorityCompleteClosureReceiptPayload/v1"
                    )
                },
                "receiptId": SHA256_JSON_SCHEMA,
                "snapshotReceiptDigest": SHA256_JSON_SCHEMA,
                "treeDigest": SHA256_JSON_SCHEMA,
                "treeEntryCount": INTEGER_JSON_SCHEMA,
                "totalBytes": INTEGER_JSON_SCHEMA,
                "pythonImportClosure": {
                    "type": "array",
                    "maxItems": MAX_IMPORTS,
                    "items": PYTHON_IMPORT_JSON_SCHEMA,
                },
                "nativeClosure": _closed_object_schema(
                    {
                        "executables": {
                            "type": "array",
                            "maxItems": MAX_NATIVE_OBJECTS,
                            "items": NATIVE_EXECUTABLE_JSON_SCHEMA,
                        },
                        "objects": {
                            "type": "array",
                            "maxItems": MAX_NATIVE_OBJECTS,
                            "items": NATIVE_OBJECT_JSON_SCHEMA,
                        },
                    }
                ),
                "stageZero": STAGE_ZERO_REFERENCE_JSON_SCHEMA,
                "coverage": CLOSURE_COVERAGE_JSON_SCHEMA,
                "rootfs": _closed_object_schema(
                    {
                        "imageDigest": SHA256_JSON_SCHEMA,
                        "verityRootDigest": SHA256_JSON_SCHEMA,
                        "mountPolicyDigest": SHA256_JSON_SCHEMA,
                        "pivotRootRequired": {"const": True},
                        "oldRootDetached": {"const": True},
                        "enforcementEvidenceDigest": SHA256_JSON_SCHEMA,
                    }
                ),
                "createdAt": TIMESTAMP_JSON_SCHEMA,
                "expiresAt": TIMESTAMP_JSON_SCHEMA,
            }
        ),
        **SIGNED_EVIDENCE_ENVELOPE_FIELDS,
    }
)
SCHEMA_REFERENCE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "schemaId": TEXT_JSON_SCHEMA,
    }
)
CONFIGURATION_REFERENCE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "name": TEXT_JSON_SCHEMA,
        "role": TEXT_JSON_SCHEMA,
        "payloadSchema": {"type": ["string", "null"]},
        "payloadDigest": {"anyOf": [SHA256_JSON_SCHEMA, {"type": "null"}]},
    }
)
CONFIGURATION_REFERENCE_JSON_SCHEMA["oneOf"] = [
    {
        "properties": {
            "role": {"const": role},
            "payloadSchema": {"const": schema},
            "payloadDigest": SHA256_JSON_SCHEMA,
        }
    }
    for role, schema in CONFIGURATION_PAYLOAD_SCHEMAS.items()
] + [
    {
        "properties": {
            "role": {"not": {"enum": sorted(CONFIGURATION_PAYLOAD_SCHEMAS)}},
            "payloadSchema": {"type": "null"},
            "payloadDigest": {"type": "null"},
        }
    }
]
CONFIGURATION_PAYLOAD_BINDING_JSON_SCHEMA = _closed_object_schema(
    {
        "fileDigest": SHA256_JSON_SCHEMA,
        "payloadDigest": SHA256_JSON_SCHEMA,
        "payloadSchema": TEXT_JSON_SCHEMA,
        "role": {"enum": sorted(CONFIGURATION_PAYLOAD_SCHEMAS)},
    }
)
CONFIGURATION_PAYLOAD_BINDING_JSON_SCHEMA["oneOf"] = [
    {"properties": {"role": {"const": role}, "payloadSchema": {"const": schema}}}
    for role, schema in CONFIGURATION_PAYLOAD_SCHEMAS.items()
]
ROLE_MANIFEST_REFERENCE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "role": TEXT_JSON_SCHEMA,
        "runtimeUid": INTEGER_JSON_SCHEMA,
        "runtimeGid": INTEGER_JSON_SCHEMA,
        "processMode": TEXT_JSON_SCHEMA,
        "entrypointPath": TEXT_JSON_SCHEMA,
        "listenerName": TEXT_JSON_SCHEMA,
        "credentialNames": STRING_ARRAY_JSON_SCHEMA,
        "cwd": TEXT_JSON_SCHEMA,
        "pathEntries": STRING_ARRAY_JSON_SCHEMA,
        "argv": STRING_ARRAY_JSON_SCHEMA,
        "environmentAllowlist": STRING_ARRAY_JSON_SCHEMA,
        "mutableStateDescriptors": {
            "type": "array",
            "maxItems": 16,
            "items": _closed_object_schema(
                {
                    "name": TEXT_JSON_SCHEMA,
                    "runtimePath": TEXT_JSON_SCHEMA,
                    "atomicRecordProtocol": {
                        "enum": sorted(ALLOWED_MUTABLE_STATE_PROTOCOLS)
                    },
                    "quotaBytes": INTEGER_JSON_SCHEMA,
                    "singletonLeaseRequired": {"const": True},
                    "networkAllowed": {"const": False},
                }
            ),
        },
    }
)
MIGRATION_RECEIPT_PAYLOAD_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {
            "const": authority_contract.MIGRATION_RECEIPT_SCHEMA
        },
        "contractId": {
            "const": authority_contract.V8_TO_V9_MIGRATION_CONTRACT_ID
        },
        "migrationName": TEXT_JSON_SCHEMA,
        "sourceVersion": {"const": 8},
        "targetVersion": {"const": 9},
        "migrationSha256": SHA256_JSON_SCHEMA,
        "sourceRevision": TEXT_JSON_SCHEMA,
        "operationContractDigest": SHA256_JSON_SCHEMA,
        "signerIdentityDigest": SHA256_JSON_SCHEMA,
        "beforeManifestDigest": SHA256_JSON_SCHEMA,
        "beforeRowCountsDigest": SHA256_JSON_SCHEMA,
        "afterManifestDigest": SHA256_JSON_SCHEMA,
        "afterRowCountsDigest": SHA256_JSON_SCHEMA,
        "terminal": {"const": True},
        "status": {"const": "completed"},
        "completedAt": TIMESTAMP_JSON_SCHEMA,
    }
)
MIGRATION_REFERENCE_JSON_SCHEMA = _closed_object_schema(
    {
        "name": TEXT_JSON_SCHEMA,
        "fromVersion": INTEGER_JSON_SCHEMA,
        "toVersion": INTEGER_JSON_SCHEMA,
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "receiptSchema": {
            "const": authority_contract.MIGRATION_RECEIPT_SCHEMA
        },
        "receiptPath": RELATIVE_PATH_JSON_SCHEMA,
        "receiptDigest": SHA256_JSON_SCHEMA,
        "receiptPayload": MIGRATION_RECEIPT_PAYLOAD_JSON_SCHEMA,
        "receiptSignerKeyId": TEXT_JSON_SCHEMA,
        "receiptAlgorithm": {"const": "Ed25519"},
        "receiptSignatureBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{86}$",
        },
        "receiptSignatureDigest": SHA256_JSON_SCHEMA,
    }
)
SBOM_REFERENCE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "format": TEXT_JSON_SCHEMA,
        "mediaType": TEXT_JSON_SCHEMA,
    }
)
PROVENANCE_REFERENCE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "predicateType": TEXT_JSON_SCHEMA,
        "mediaType": TEXT_JSON_SCHEMA,
        "builderId": TEXT_JSON_SCHEMA,
        "sourceRevision": TEXT_JSON_SCHEMA,
        "sourceCommitDigest": SHA256_JSON_SCHEMA,
        "sourceTreeDigest": SHA256_JSON_SCHEMA,
        "ociRootDigest": SHA256_JSON_SCHEMA,
        "statementDigest": SHA256_JSON_SCHEMA,
        "signerKeyId": TEXT_JSON_SCHEMA,
        "algorithm": {"const": "Ed25519"},
        "signatureBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{86}$",
        },
    }
)
OCI_IMAGE_JSON_SCHEMA = _closed_object_schema(
    {
        "reference": TEXT_JSON_SCHEMA,
        "rootPath": RELATIVE_PATH_JSON_SCHEMA,
        "rootDigest": SHA256_JSON_SCHEMA,
        "rootSize": INTEGER_JSON_SCHEMA,
        "rootMediaType": TEXT_JSON_SCHEMA,
        "rootDocumentBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]+$",
        },
        "indexPath": {
            "anyOf": [{"type": "null"}, RELATIVE_PATH_JSON_SCHEMA]
        },
        "indexDigest": {
            "anyOf": [{"type": "null"}, SHA256_JSON_SCHEMA]
        },
        "indexSize": {
            "anyOf": [{"type": "null"}, INTEGER_JSON_SCHEMA]
        },
        "indexMediaType": {
            "anyOf": [{"type": "null"}, TEXT_JSON_SCHEMA]
        },
        "indexDocumentBase64Url": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9_-]+$",
                },
            ]
        },
        "manifestPath": RELATIVE_PATH_JSON_SCHEMA,
        "manifestDigest": SHA256_JSON_SCHEMA,
        "manifestSize": INTEGER_JSON_SCHEMA,
        "manifestMediaType": TEXT_JSON_SCHEMA,
        "manifestDocumentBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]+$",
        },
        "configPath": RELATIVE_PATH_JSON_SCHEMA,
        "configDigest": SHA256_JSON_SCHEMA,
        "configSize": INTEGER_JSON_SCHEMA,
        "configMediaType": TEXT_JSON_SCHEMA,
        "configDocumentBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]+$",
        },
        "platform": _closed_object_schema(
            {
                "os": TEXT_JSON_SCHEMA,
                "architecture": TEXT_JSON_SCHEMA,
                "variant": {
                    "anyOf": [{"type": "null"}, TEXT_JSON_SCHEMA]
                },
            }
        ),
        "layers": {
            "type": "array",
            "maxItems": MAX_LAYER_DIGESTS,
            "items": _closed_object_schema(
                {
                    "path": RELATIVE_PATH_JSON_SCHEMA,
                    "digest": SHA256_JSON_SCHEMA,
                    "size": INTEGER_JSON_SCHEMA,
                    "mediaType": TEXT_JSON_SCHEMA,
                }
            ),
        },
    }
)
OPERATION_MANIFEST_REFERENCE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "manifestSchema": {"const": authority_contract.CONTRACT_SCHEMA},
        "contractDigest": {
            "const": authority_contract.OPERATION_MANIFEST_DIGEST
        },
    }
)
ARTIFACT_BUNDLE_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": ARTIFACT_BUNDLE_SCHEMA},
        "bundleVersion": {"const": 1},
        "authoritySchemaVersion": {"const": AUTHORITY_SCHEMA_VERSION},
        "sourceRevision": {"type": "string", "minLength": 1},
        "sourceCommitDigest": SHA256_JSON_SCHEMA,
        "trustMode": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "mode",
                "hardwareBacked",
                "externalWitnessRequired",
                "teeQuoteRequired",
                "imaAppraisalRequired",
            ],
            "properties": {
                "mode": {"enum": sorted(TRUST_MODES)},
                "hardwareBacked": {"type": "boolean"},
                "externalWitnessRequired": {"type": "boolean"},
                "teeQuoteRequired": {"type": "boolean"},
                "imaAppraisalRequired": {"type": "boolean"},
            },
        },
        "sourceTree": _closed_object_schema(
            {
                "algorithm": {"const": "canonical-path-tree-sha256-v1"},
                "digest": SHA256_JSON_SCHEMA,
                "entryCount": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_BUNDLE_FILES,
                },
                "snapshotKind": {
                    "enum": [
                        "atomic-filesystem-snapshot",
                        "content-addressed-cas",
                    ]
                },
                "snapshotIdentityDigest": SHA256_JSON_SCHEMA,
                "readOnly": {"const": True},
            }
        ),
        "stableSnapshotReceipt": SNAPSHOT_RECEIPT_JSON_SCHEMA,
        "closureReceipt": CLOSURE_RECEIPT_JSON_SCHEMA,
        "files": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_BUNDLE_FILES,
            "items": ARTIFACT_FILE_JSON_SCHEMA,
        },
        "pythonImportClosure": {
            "type": "array",
            "maxItems": MAX_IMPORTS,
            "items": PYTHON_IMPORT_JSON_SCHEMA,
        },
        "nativeClosure": _closed_object_schema(
            {
                "executables": {
                    "type": "array",
                    "maxItems": MAX_NATIVE_OBJECTS,
                    "items": NATIVE_EXECUTABLE_JSON_SCHEMA,
                },
                "objects": {
                    "type": "array",
                    "maxItems": MAX_NATIVE_OBJECTS,
                    "items": NATIVE_OBJECT_JSON_SCHEMA,
                },
            }
        ),
        "schemas": {
            "type": "array",
            "maxItems": MAX_SCHEMAS,
            "items": SCHEMA_REFERENCE_JSON_SCHEMA,
        },
        "migrations": {
            "type": "array",
            "maxItems": MAX_MIGRATIONS,
            "items": MIGRATION_REFERENCE_JSON_SCHEMA,
        },
        "configurations": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_CONFIGURATION_DIGESTS,
            "items": CONFIGURATION_REFERENCE_JSON_SCHEMA,
        },
        "roleManifests": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_ROLE_MANIFESTS,
            "items": ROLE_MANIFEST_REFERENCE_JSON_SCHEMA,
        },
        "sbom": SBOM_REFERENCE_JSON_SCHEMA,
        "provenance": PROVENANCE_REFERENCE_JSON_SCHEMA,
        "ociImage": OCI_IMAGE_JSON_SCHEMA,
        "stageZero": STAGE_ZERO_REFERENCE_JSON_SCHEMA,
        "operationManifest": OPERATION_MANIFEST_REFERENCE_JSON_SCHEMA,
    }
)
TRUST_MODE_JSON_SCHEMA = _closed_object_schema(
    {
        "mode": {"enum": sorted(TRUST_MODES)},
        "hardwareBacked": {"type": "boolean"},
        "externalWitnessRequired": {"type": "boolean"},
        "teeQuoteRequired": {"type": "boolean"},
        "imaAppraisalRequired": {"type": "boolean"},
    }
)
WITNESS_CHECKPOINT_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {
            "const": "serverware.signedAuthorityWitnessCheckpoint/v1"
        },
        "payload": _closed_object_schema(
            {
                "schema": {
                    "const": "serverware.authorityWitnessCheckpointPayload/v1"
                },
                "identity": TEXT_JSON_SCHEMA,
                "sequence": INTEGER_JSON_SCHEMA,
                "previousCheckpointDigest": {
                    "anyOf": [{"type": "null"}, SHA256_JSON_SCHEMA]
                },
                "previousRootDigest": {
                    "anyOf": [{"type": "null"}, SHA256_JSON_SCHEMA]
                },
                "previousTreeSize": INTEGER_JSON_SCHEMA,
                "treeSize": INTEGER_JSON_SCHEMA,
                "generationCoreDigest": SHA256_JSON_SCHEMA,
                "leafDigest": SHA256_JSON_SCHEMA,
                "rootDigest": SHA256_JSON_SCHEMA,
                "issuedAt": TIMESTAMP_JSON_SCHEMA,
                "coLocated": {"type": "boolean"},
                "hardwareBacked": {"type": "boolean"},
            }
        ),
        "signerKeyId": TEXT_JSON_SCHEMA,
        "algorithm": {"const": "Ed25519"},
        "signatureBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{86}$",
        },
    }
)
GENERATION_STATEMENT_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": GENERATION_STATEMENT_SCHEMA},
        "sequence": {
            "type": "integer",
            "minimum": 0,
            "maximum": 9223372036854775807,
        },
        "generationId": {"type": "string", "minLength": 1},
        "predecessorDigest": {
            "anyOf": [{"type": "null"}, SHA256_JSON_SCHEMA]
        },
        "minimumRollbackSequence": {
            "type": "integer",
            "minimum": 0,
            "maximum": 9223372036854775807,
        },
        "validFrom": {"type": "string"},
        "validUntil": {"type": "string"},
        "artifactBundleDigest": SHA256_JSON_SCHEMA,
        "operationManifestDigest": SHA256_JSON_SCHEMA,
        "stageZeroDigest": SHA256_JSON_SCHEMA,
        "stageZeroContract": TEXT_JSON_SCHEMA,
        "roleSetDigest": SHA256_JSON_SCHEMA,
        "snapshotReceiptDigest": SHA256_JSON_SCHEMA,
        "closureReceiptDigest": SHA256_JSON_SCHEMA,
        "provenanceStatementDigest": SHA256_JSON_SCHEMA,
        "sourceTreeDigest": SHA256_JSON_SCHEMA,
        "ociManifestDigest": SHA256_JSON_SCHEMA,
        "migrationReceiptDigests": {
            "type": "array",
            "maxItems": MAX_MIGRATIONS,
            "items": SHA256_JSON_SCHEMA,
        },
        "roleManifestDigests": {
            "type": "array",
            "maxItems": MAX_ROLE_MANIFESTS,
            "items": SHA256_JSON_SCHEMA,
        },
        "configurationDigests": {
            "type": "array",
            "maxItems": MAX_CONFIGURATION_DIGESTS,
            "items": SHA256_JSON_SCHEMA,
        },
        "configurationPayloadBindings": {
            "type": "array",
            "maxItems": MAX_CONFIGURATION_DIGESTS,
            "uniqueItems": True,
            "items": CONFIGURATION_PAYLOAD_BINDING_JSON_SCHEMA,
        },
        "keyAuthorizationsDigest": SHA256_JSON_SCHEMA,
        "keyRevocationsDigest": SHA256_JSON_SCHEMA,
        "witnessCheckpoint": WITNESS_CHECKPOINT_JSON_SCHEMA,
        "trustMode": TRUST_MODE_JSON_SCHEMA,
    }
)
KEY_FILE_JSON_SCHEMA = _closed_object_schema(
    {
        "path": RELATIVE_PATH_JSON_SCHEMA,
        "sha256": SHA256_JSON_SCHEMA,
        "size": {"const": 32},
        "mode": INTEGER_JSON_SCHEMA,
        "uid": INTEGER_JSON_SCHEMA,
        "gid": INTEGER_JSON_SCHEMA,
    }
)
AUTHORIZED_KEY_JSON_SCHEMA = _closed_object_schema(
    {
        "keyId": TEXT_JSON_SCHEMA,
        "purposes": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(KEY_PURPOSES),
            "items": {"enum": sorted(KEY_PURPOSES)},
        },
        "publicKeyBase64Url": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{43}$",
        },
        "keyFile": KEY_FILE_JSON_SCHEMA,
        "authorizationDigest": SHA256_JSON_SCHEMA,
        "notBefore": TIMESTAMP_JSON_SCHEMA,
        "notAfter": TIMESTAMP_JSON_SCHEMA,
    }
)
KEY_AUTHORIZATION_DOCUMENT_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": KEY_AUTHORIZATION_SCHEMA},
        "payload": _closed_object_schema(
            {
                "schema": {
                    "const": (
                        "serverware.authorityKeyAuthorizationPayload/v1"
                    )
                },
                "generationSequence": INTEGER_JSON_SCHEMA,
                "predecessorGenerationDigest": {
                    "anyOf": [{"type": "null"}, SHA256_JSON_SCHEMA]
                },
                "keys": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4096,
                    "items": AUTHORIZED_KEY_JSON_SCHEMA,
                },
            }
        ),
        **SIGNED_EVIDENCE_ENVELOPE_FIELDS,
    }
)
KEY_REVOCATION_DOCUMENT_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": KEY_REVOCATION_SCHEMA},
        "payload": _closed_object_schema(
            {
                "schema": {
                    "const": "serverware.authorityKeyRevocationPayload/v1"
                },
                "generationSequence": INTEGER_JSON_SCHEMA,
                "predecessorGenerationDigest": {
                    "anyOf": [{"type": "null"}, SHA256_JSON_SCHEMA]
                },
                "revocationHighWater": INTEGER_JSON_SCHEMA,
                "revocations": {
                    "type": "array",
                    "maxItems": 4096,
                    "items": _closed_object_schema(
                        {
                            "sequence": INTEGER_JSON_SCHEMA,
                            "keyId": TEXT_JSON_SCHEMA,
                            "revokedAt": TIMESTAMP_JSON_SCHEMA,
                            "reason": TEXT_JSON_SCHEMA,
                        }
                    ),
                },
            }
        ),
        **SIGNED_EVIDENCE_ENVELOPE_FIELDS,
    }
)
TRUST_MATERIAL_JSON_SCHEMA = _closed_object_schema(
    {
        "keyAuthorizations": KEY_AUTHORIZATION_DOCUMENT_JSON_SCHEMA,
        "keyRevocations": KEY_REVOCATION_DOCUMENT_JSON_SCHEMA,
    }
)
SIGNED_ARTIFACT_PACKAGE_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": SIGNED_PACKAGE_SCHEMA},
        "bundle": ARTIFACT_BUNDLE_JSON_SCHEMA,
        "generation": GENERATION_STATEMENT_JSON_SCHEMA,
        "trustMaterial": TRUST_MATERIAL_JSON_SCHEMA,
        "signatures": {
            "type": "array",
            "minItems": 2,
            "maxItems": 2,
            "items": _closed_object_schema(
                {
                    "purpose": {"enum": sorted(SIGNATURE_PURPOSES)},
                    "algorithm": {"const": "Ed25519"},
                    "keyId": {"type": "string", "minLength": 1},
                    "signatureBase64Url": {
                        "type": "string",
                        "pattern": "^[A-Za-z0-9_-]{86}$",
                    },
                }
            ),
        },
    }
)
UNSIGNED_ARTIFACT_PACKAGE_JSON_SCHEMA = _closed_object_schema(
    {
        "schema": {"const": UNSIGNED_PACKAGE_SCHEMA},
        "bundle": ARTIFACT_BUNDLE_JSON_SCHEMA,
        "generation": GENERATION_STATEMENT_JSON_SCHEMA,
        "trustMaterial": TRUST_MATERIAL_JSON_SCHEMA,
        "signatureRequests": {
            "type": "array",
            "minItems": 2,
            "maxItems": 2,
            "items": _closed_object_schema(
                {
                    "purpose": {"enum": sorted(SIGNATURE_PURPOSES)},
                    "algorithm": {"const": "Ed25519"},
                    "keyId": {"type": "string", "minLength": 1},
                    "messageBase64Url": {
                        "type": "string",
                        "pattern": "^[A-Za-z0-9_-]+$",
                    },
                }
            ),
        },
    }
)


__all__ = [
    "ARTIFACT_BUNDLE_SCHEMA",
    "GENERATION_STATEMENT_SCHEMA",
    "SIGNED_PACKAGE_SCHEMA",
    "UNSIGNED_PACKAGE_SCHEMA",
    "ROLE_BINDING_DOMAIN",
    "ROLE_RUNTIME_CLOSURE_SCHEMA",
    "CONFIGURATION_GENERATION_BINDING_SCHEMA",
    "CONFIGURATION_PAYLOAD_SCHEMAS",
    "KEY_AUTHORIZATION_SCHEMA",
    "KEY_REVOCATION_SCHEMA",
    "TRUST_STATE_SCHEMA",
    "SNAPSHOT_RECEIPT_SCHEMA",
    "CLOSURE_RECEIPT_SCHEMA",
    "AUTHORITY_SCHEMA_VERSION",
    "TRUST_MODES",
    "ALLOWED_MUTABLE_STATE_PROTOCOLS",
    "EXTERNAL_SECURITY_PREREQUISITES",
    "ArtifactContractError",
    "VerifiedAuthorityKey",
    "VerifiedArtifactPackage",
    "ARTIFACT_FILE_JSON_SCHEMA",
    "CONFIGURATION_GENERATION_BINDING_JSON_SCHEMA",
    "CONFIGURATION_REFERENCE_JSON_SCHEMA",
    "CONFIGURATION_PAYLOAD_BINDING_JSON_SCHEMA",
    "ROLE_MANIFEST_REFERENCE_JSON_SCHEMA",
    "ROLE_RUNTIME_CLOSURE_JSON_SCHEMA",
    "ARTIFACT_BUNDLE_JSON_SCHEMA",
    "GENERATION_STATEMENT_JSON_SCHEMA",
    "SIGNED_ARTIFACT_PACKAGE_JSON_SCHEMA",
    "UNSIGNED_ARTIFACT_PACKAGE_JSON_SCHEMA",
    "artifact_bundle_digest",
    "assemble_signed_artifact_package",
    "canonical_json_bytes",
    "closure_receipt_digest",
    "configuration_generation_binding",
    "configuration_generation_binding_digest",
    "configuration_payload_bindings",
    "domain_digest",
    "ed25519_public_key_from_seed",
    "generation_statement_digest",
    "package_signature_message",
    "role_binding_digest",
    "role_binding_digests",
    "role_runtime_closure_digest",
    "signed_artifact_package_digest",
    "snapshot_receipt_digest",
    "strict_base64url_decode",
    "strict_base64url_encode",
    "validate_artifact_bundle",
    "validate_generation_statement",
    "validate_configuration_payload_bindings",
    "validate_role_reference",
    "validate_closure_receipt",
    "validate_snapshot_receipt",
    "validate_signed_artifact_package",
    "validate_trust_state",
    "validate_unsigned_artifact_package",
    "verify_ed25519_signature",
    "verify_external_evidence_receipt",
    "verify_signed_artifact_package",
]
