from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from serverware.authority_artifact_spec import (
    ArtifactContractError,
    LOCAL_STAGE_ZERO_INTERFACE_SCHEMA,
    VerifiedArtifactPackage,
    artifact_bundle_digest,
    canonical_json_bytes,
    domain_digest,
    generation_statement_digest,
    package_signature_message,
    signed_artifact_package_digest,
    strict_base64url_decode,
    validate_signed_artifact_package,
    verify_ed25519_signature,
    verify_signed_artifact_package,
)


VERIFICATION_RECEIPT_SCHEMA = (
    "serverware.authorityArtifactVerificationReceipt/v1"
)
PROVISIONING_PLAN_SCHEMA = "serverware.authorityAtomicProvisioningPlan/v1"
LOCAL_PROVISIONING_PLAN_SCHEMA = "serverware.authorityTrustedHostLocalProvisioningPlan/v1"
LOCAL_PROVISIONING_RECEIPT_SCHEMA = "serverware.authorityTrustedHostLocalProvisioningReceipt/v1"
LOCAL_PROVISIONING_RECEIPT_SIGNATURE_DOMAIN = "serverware.authorityTrustedHostLocalProvisioningReceiptSignature/v1"
LOCAL_PROVISIONING_RECEIPT_DIGEST_DOMAIN = "serverware.authorityTrustedHostLocalProvisioningReceiptDigest/v1"
PROVISIONING_RECEIPT_SCHEMA = (
    "serverware.authorityAtomicProvisioningReceipt/v2"
)
PROVISIONING_STATE_SCHEMA = "serverware.authorityProvisioningState/v1"
RECONCILIATION_RECEIPT_SCHEMA = (
    "serverware.authorityProvisioningReconciliationReceipt/v1"
)
CLEANUP_RECEIPT_SCHEMA = "serverware.authorityProvisioningCleanupReceipt/v1"
PACKAGE_DIGEST_DOMAIN = "serverware.authoritySignedArtifactPackageDigest/v1"
VERIFICATION_RECEIPT_DIGEST_DOMAIN = (
    "serverware.authorityArtifactVerificationReceiptDigest/v1"
)
PROVISIONING_PLAN_DIGEST_DOMAIN = (
    "serverware.authorityAtomicProvisioningPlanDigest/v1"
)
PROVISIONING_RECEIPT_SIGNATURE_DOMAIN = (
    "serverware.authorityAtomicProvisioningReceiptSignature/v2"
)
PROVISIONING_RECEIPT_DIGEST_DOMAIN = (
    "serverware.authorityAtomicProvisioningReceiptDigest/v2"
)
RECONCILIATION_RECEIPT_SIGNATURE_DOMAIN = (
    "serverware.authorityProvisioningReconciliationReceiptSignature/v1"
)
CLEANUP_RECEIPT_SIGNATURE_DOMAIN = (
    "serverware.authorityProvisioningCleanupReceiptSignature/v1"
)
PROVISIONING_STATE_DIGEST_DOMAIN = (
    "serverware.authorityProvisioningStateDigest/v1"
)
PROVISIONING_STEP_CONTRACT_DOMAIN = (
    "serverware.authorityAtomicProvisioningSteps/v1"
)
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_FILES = 32768
TRUST_MODES = frozenset(
    {"trusted-host-local", "external-production", "tee-hardware"}
)
ATOMIC_PROVISIONING_STEPS = (
    "open-root-no-symlink",
    "acquire-exclusive-generation-lock",
    "verify-external-receipt-signature-and-authorization",
    "verify-generation-chain-and-external-rollback-high-water",
    "create-private-staging-directory",
    "open-package-files-by-retained-descriptor",
    "copy-measure-and-fsync-each-file",
    "apply-owner-mode-and-fs-verity",
    "verify-complete-python-and-native-closure",
    "fsync-staging-tree-bottom-up",
    "set-generation-tree-immutable",
    "renameat2-generation-noreplace",
    "fsync-generations-directory",
    "write-sign-fsync-terminal-receipt",
    "release-generation-lock",
)
LOCAL_PROVISIONING_STEPS = (
    *ATOMIC_PROVISIONING_STEPS[:10],
    "set-generation-descendants-immutable",
    "renameat2-generation-noreplace",
    "set-published-generation-root-immutable",
    "fsync-generations-directory",
    "write-sign-fsync-terminal-receipt",
)


class ProvisioningContractError(RuntimeError):
    pass


def _closed(
    value: object,
    *,
    name: str,
    keys: set[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ProvisioningContractError(f"{name} is not a closed object")
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
        raise ProvisioningContractError(
            f"{name} has an invalid item count"
        )
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
        raise ProvisioningContractError(f"{name} must be bounded ASCII")
    return value


def _identifier(value: object, *, name: str) -> str:
    text = _ascii(value, name=name, maximum=256)
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
        raise ProvisioningContractError(
            f"{name} is not a canonical identifier"
        )
    return text


def _digest(value: object, *, name: str) -> str:
    text = _ascii(value, name=name, maximum=71)
    if (
        len(text) != 71
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise ProvisioningContractError(
            f"{name} is not a SHA-256 digest"
        )
    return text


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
        raise ProvisioningContractError(
            f"{name} is outside its integer bound"
        )
    return value


def _timestamp(value: object, *, name: str) -> datetime:
    text = _ascii(value, name=name, maximum=64)
    if not text.endswith("Z"):
        raise ProvisioningContractError(f"{name} must use canonical UTC")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ProvisioningContractError(f"{name} is not RFC3339") from exc
    if (
        parsed.tzinfo != timezone.utc
        or parsed.microsecond != 0
        or text != parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    ):
        raise ProvisioningContractError(
            f"{name} is not canonical RFC3339"
        )
    return parsed


def _runtime_path(value: object, *, name: str) -> str:
    text = _ascii(value, name=name)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or path.as_posix() != text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ProvisioningContractError(
            f"{name} is not a canonical runtime path"
        )
    return text


def _relative_path(value: object, *, name: str) -> str:
    text = _ascii(value, name=name)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or path.as_posix() != text
        or text in {".", ".."}
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ProvisioningContractError(
            f"{name} is not a canonical relative path"
        )
    return text


def _base64url(
    value: object,
    *,
    name: str,
    decoded_size: int,
) -> bytes:
    try:
        return strict_base64url_decode(
            value,
            name=name,
            decoded_size=decoded_size,
        )
    except ArtifactContractError as exc:
        raise ProvisioningContractError(str(exc)) from exc


def _document_digest(domain: str, value: Mapping[str, Any]) -> str:
    return domain_digest(domain, canonical_json_bytes(value))


def signed_package_digest(package: Mapping[str, Any]) -> str:
    # VerifiedArtifactPackage exposes its outer mapping as read-only. Preserve
    # all existing validation while passing an ordinary JSON object to hashing.
    return signed_artifact_package_digest(dict(package))


def verification_receipt_digest(receipt: Mapping[str, Any]) -> str:
    validate_verification_receipt(receipt)
    return _document_digest(VERIFICATION_RECEIPT_DIGEST_DOMAIN, receipt)


def provisioning_plan_digest(plan: Mapping[str, Any]) -> str:
    validate_provisioning_plan(plan)
    return _document_digest(PROVISIONING_PLAN_DIGEST_DOMAIN, plan)


def provisioning_receipt_digest(receipt: Mapping[str, Any]) -> str:
    validate_provisioning_receipt(receipt)
    return _document_digest(LOCAL_PROVISIONING_RECEIPT_DIGEST_DOMAIN
        if receipt["schema"] == LOCAL_PROVISIONING_RECEIPT_SCHEMA else PROVISIONING_RECEIPT_DIGEST_DOMAIN, receipt)


def _validate_verified_signature(
    value: object,
    *,
    package: Mapping[str, Any] | None,
) -> None:
    entry = _closed(
        value,
        name="verified signature",
        keys={
            "purpose",
            "keyId",
            "algorithm",
            "messageDigest",
            "signatureDigest",
            "authorizationDigest",
            "revocationCheckpointDigest",
        },
    )
    if entry["purpose"] not in {"artifact-bundle", "generation"}:
        raise ProvisioningContractError(
            "verified signature purpose is not recognized"
        )
    _identifier(entry["keyId"], name="verified signature key")
    if entry["algorithm"] != "Ed25519":
        raise ProvisioningContractError(
            "verified signature algorithm changed"
        )
    for field in (
        "messageDigest",
        "signatureDigest",
        "authorizationDigest",
        "revocationCheckpointDigest",
    ):
        _digest(entry[field], name=field)
    if package is not None:
        expected_message = package_signature_message(
            entry["purpose"], package["bundle"], package["generation"]
        )
        expected_digest = domain_digest(
            "serverware.authoritySignatureMessageDigest/v1",
            expected_message,
        )
        if entry["messageDigest"] != expected_digest:
            raise ProvisioningContractError(
                "verified signature message changed"
            )
        matching = [
            signature
            for signature in package["signatures"]
            if signature["purpose"] == entry["purpose"]
            and signature["keyId"] == entry["keyId"]
            and signature["algorithm"] == entry["algorithm"]
        ]
        if len(matching) != 1:
            raise ProvisioningContractError(
                "verification receipt refers to another signature"
            )
        signature_bytes = _base64url(
            matching[0]["signatureBase64Url"],
            name="package signature",
            decoded_size=64,
        )
        expected_signature_digest = domain_digest(
            "serverware.authoritySignatureBytesDigest/v1",
            signature_bytes,
        )
        if entry["signatureDigest"] != expected_signature_digest:
            raise ProvisioningContractError(
                "verification receipt signature digest changed"
            )


def validate_verification_receipt(
    receipt: Mapping[str, Any],
    *,
    package: Mapping[str, Any] | None = None,
) -> None:
    value = _closed(
        receipt,
        name="verification receipt",
        keys={
            "schema",
            "packageDigest",
            "artifactBundleDigest",
            "generationDigest",
            "generationSequence",
            "minimumRollbackSequence",
            "trustMode",
            "verifiedSignatures",
            "stageZeroVerification",
            "closureVerification",
            "rollbackWitness",
            "verifierIdentity",
            "verificationPolicyDigest",
            "verifiedAt",
            "validUntil",
            "receiptSignerKeyId",
            "receiptSignerAuthorizationDigest",
            "receiptSignatureAlgorithm",
            "receiptSignatureBase64Url",
        },
    )
    if value["schema"] != VERIFICATION_RECEIPT_SCHEMA:
        raise ProvisioningContractError(
            "verification receipt schema changed"
        )
    for field in (
        "packageDigest",
        "artifactBundleDigest",
        "generationDigest",
        "verificationPolicyDigest",
    ):
        _digest(value[field], name=field)
    sequence = _integer(
        value["generationSequence"],
        name="generation sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    rollback = _integer(
        value["minimumRollbackSequence"],
        name="minimum rollback sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    if rollback > sequence:
        raise ProvisioningContractError(
            "rollback floor exceeds generation"
        )
    if value["trustMode"] not in TRUST_MODES:
        raise ProvisioningContractError("trust mode is not recognized")
    signatures = _bounded_list(
        value["verifiedSignatures"],
        name="verified signatures",
        minimum=2,
        maximum=2,
    )
    for signature in signatures:
        _validate_verified_signature(signature, package=package)
    purposes = [signature["purpose"] for signature in signatures]
    if purposes != ["artifact-bundle", "generation"]:
        raise ProvisioningContractError(
            "verified signatures are not in canonical order"
        )

    local_bootstrap = (isinstance(value["stageZeroVerification"], Mapping)
        and value["stageZeroVerification"].get("interfaceSchema") == LOCAL_STAGE_ZERO_INTERFACE_SCHEMA)
    stage_zero = _closed(
        value["stageZeroVerification"],
        name="stage-zero verification",
        keys={
            "artifactDigest",
            "interfaceSchema",
            "verifierDigest",
        } | ({"interpreterDigest", "interpreterRuntimePath"} if local_bootstrap
            else {"staticElf", "ptInterp", "needed"}),
    )
    _digest(stage_zero["artifactDigest"], name="stage-zero artifact digest")
    _identifier(
        stage_zero["interfaceSchema"],
        name="stage-zero interface schema",
    )
    if local_bootstrap:
        if value["trustMode"] != "trusted-host-local":
            raise ProvisioningContractError("Python bootstrap verification cannot claim production trust")
        _digest(stage_zero["interpreterDigest"], name="local interpreter digest")
        _runtime_path(stage_zero["interpreterRuntimePath"], name="local interpreter runtime path")
    elif (
        stage_zero["staticElf"] is not True
        or stage_zero["ptInterp"] is not None
        or stage_zero["needed"] != []
    ):
        raise ProvisioningContractError(
            "stage-zero verification does not prove a static ELF"
        )
    _digest(stage_zero["verifierDigest"], name="stage-zero verifier digest")

    local_roster = (isinstance(value["closureVerification"], Mapping)
        and "assurance" in value["closureVerification"])
    closure = _closed(
        value["closureVerification"],
        name="closure verification",
        keys={
            "fileCount",
            "pythonImportCount",
            "nativeExecutableCount",
            "nativeObjectCount",
            "snapshotIdentityDigest",
            "complete",
            "verifierDigest",
        } | ({"assurance"} if local_roster else set()),
    )
    for field in (
        "fileCount",
        "pythonImportCount",
        "nativeExecutableCount",
        "nativeObjectCount",
    ):
        _integer(
            closure[field],
            name=field,
            minimum=0,
            maximum=MAX_FILES,
        )
    if local_roster:
        from serverware.authority_artifact_spec import LOCAL_CLOSURE_ASSURANCE
        if not local_bootstrap or value["trustMode"] != "trusted-host-local" or closure["complete"] is not False or closure["assurance"] != LOCAL_CLOSURE_ASSURANCE:
            raise ProvisioningContractError("measured roster verification cannot claim complete/native closure")
    elif closure["complete"] is not True:
        raise ProvisioningContractError("artifact closure is incomplete")
    _digest(
        closure["snapshotIdentityDigest"],
        name="verified snapshot identity digest",
    )
    _digest(closure["verifierDigest"], name="closure verifier digest")

    witness = _closed(
        value["rollbackWitness"],
        name="rollback witness",
        keys={
            "identity",
            "sequence",
            "generationDigest",
            "checkpointDigest",
            "coLocated",
            "hardwareBacked",
            "signatureDigest",
        },
    )
    _identifier(witness["identity"], name="rollback witness identity")
    witness_sequence = _integer(
        witness["sequence"],
        name="rollback witness sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    if witness_sequence != sequence:
        raise ProvisioningContractError(
            "rollback witness has not committed this exact generation"
        )
    for field in (
        "generationDigest",
        "checkpointDigest",
        "signatureDigest",
    ):
        _digest(witness[field], name=field)
    if (
        not isinstance(witness["coLocated"], bool)
        or not isinstance(witness["hardwareBacked"], bool)
    ):
        raise ProvisioningContractError(
            "rollback witness claims must be boolean"
        )
    if value["trustMode"] == "trusted-host-local":
        if not witness["coLocated"] or witness["hardwareBacked"]:
            raise ProvisioningContractError(
                "trusted-host witness claims are contradictory"
            )
    elif witness["coLocated"]:
        raise ProvisioningContractError(
            "production rollback witness is co-located"
        )
    if value["trustMode"] == "tee-hardware" and not witness[
        "hardwareBacked"
    ]:
        raise ProvisioningContractError(
            "TEE rollback witness is not hardware-backed"
        )

    _identifier(value["verifierIdentity"], name="verifier identity")
    verified_at = _timestamp(value["verifiedAt"], name="verifiedAt")
    valid_until = _timestamp(value["validUntil"], name="validUntil")
    if valid_until <= verified_at:
        raise ProvisioningContractError(
            "verification validity is not increasing"
        )
    _identifier(
        value["receiptSignerKeyId"], name="receipt signer key"
    )
    _digest(
        value["receiptSignerAuthorizationDigest"],
        name="receipt signer authorization",
    )
    if value["receiptSignatureAlgorithm"] != "Ed25519":
        raise ProvisioningContractError(
            "verification receipt signature algorithm changed"
        )
    _base64url(
        value["receiptSignatureBase64Url"],
        name="verification receipt signature",
        decoded_size=64,
    )

    if package is not None:
        validate_signed_artifact_package(package)
        bundle = package["bundle"]
        generation = package["generation"]
        from serverware.authority_artifact_spec import LOCAL_CLOSURE_RECEIPT_SCHEMA
        if local_roster != (bundle["closureReceipt"]["schema"] == LOCAL_CLOSURE_RECEIPT_SCHEMA):
            raise ProvisioningContractError("verification assurance differs from the exact signed closure receipt")
        if local_bootstrap and (bundle["stageZero"]["interfaceSchema"] != LOCAL_STAGE_ZERO_INTERFACE_SCHEMA
                or stage_zero["interpreterDigest"] != bundle["stageZero"]["interpreter"]["sha256"]
                or stage_zero["interpreterRuntimePath"] != bundle["stageZero"]["interpreter"]["runtimePath"]):
            raise ProvisioningContractError("local verification receipt binds another interpreter")
        if (
            value["packageDigest"] != signed_package_digest(package)
            or value["artifactBundleDigest"]
            != artifact_bundle_digest(bundle)
            or value["generationDigest"]
            != generation_statement_digest(generation)
            or value["generationSequence"] != generation["sequence"]
            or value["minimumRollbackSequence"]
            != generation["minimumRollbackSequence"]
            or value["trustMode"] != generation["trustMode"]["mode"]
            or stage_zero["artifactDigest"]
            != bundle["stageZero"]["sha256"]
            or stage_zero["interfaceSchema"]
            != bundle["stageZero"]["interfaceSchema"]
            or closure["fileCount"] != len(bundle["files"])
            or closure["pythonImportCount"]
            != len(bundle["pythonImportClosure"])
            or closure["nativeExecutableCount"]
            != len(bundle["nativeClosure"]["executables"])
            or closure["nativeObjectCount"]
            != len(bundle["nativeClosure"]["objects"])
            or closure["snapshotIdentityDigest"]
            != bundle["sourceTree"]["snapshotIdentityDigest"]
            or witness["generationDigest"]
            != generation_statement_digest(generation)
        ):
            raise ProvisioningContractError(
                "verification receipt does not bind the package"
            )


def _generation_directory_name(
    sequence: int,
    generation_digest: str,
) -> str:
    _integer(
        sequence,
        name="generation sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    _digest(generation_digest, name="generation digest")
    return f"{sequence:020d}-{generation_digest[7:]}"


def build_provisioning_plan(
    verified_package: VerifiedArtifactPackage,
    receipt: Mapping[str, Any],
    *,
    validation_time: str,
    source_root_fd: int,
    destination_root: str,
    owner_uid: int,
    owner_gid: int,
    trusted_host_local: bool = False,
) -> dict[str, Any]:
    if not isinstance(verified_package, VerifiedArtifactPackage):
        raise ProvisioningContractError(
            "planning requires a cryptographically verified package"
        )
    package = verified_package.package
    if type(trusted_host_local) is not bool or trusted_host_local and (
            verified_package.trust_mode != "trusted-host-local" or
            verified_package.stage_zero_contract != LOCAL_STAGE_ZERO_INTERFACE_SCHEMA):
        raise ProvisioningContractError("local provisioning requires the explicit local package")
    if not trusted_host_local and verified_package.stage_zero_contract == LOCAL_STAGE_ZERO_INTERFACE_SCHEMA:
        raise ProvisioningContractError("local Python package requires explicit local provisioning selection")
    verify_verification_receipt(
        receipt,
        verified_package=verified_package,
        validation_time=validation_time,
        accepted_receipt_digests=(),
    )
    source_fd = _integer(
        source_root_fd,
        name="retained source root fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    root = _runtime_path(destination_root, name="destination root")
    uid = _integer(
        owner_uid, name="provisioning owner uid", minimum=0, maximum=2**32 - 2
    )
    gid = _integer(
        owner_gid, name="provisioning owner gid", minimum=0, maximum=2**32 - 2
    )
    bundle = package["bundle"]
    generation = package["generation"]
    generation_digest = generation_statement_digest(generation)
    directory_name = _generation_directory_name(
        generation["sequence"], generation_digest
    )
    entries = [
        {
            "path": entry["path"],
            "sourceSha256": entry["sha256"],
            "size": entry["size"],
            "mode": entry["mode"],
            "uid": entry["uid"],
            "gid": entry["gid"],
            "requireFsVerity": True,
            "requireImmutable": True,
        }
        for entry in bundle["files"]
    ]
    steps = [
        {"ordinal": index, "step": step}
        for index, step in enumerate(LOCAL_PROVISIONING_STEPS if trusted_host_local else ATOMIC_PROVISIONING_STEPS, start=1)
    ]
    step_contract_digest = domain_digest(
        PROVISIONING_STEP_CONTRACT_DOMAIN,
        canonical_json_bytes(steps),
    )
    plan_without_id = {
        "schema": LOCAL_PROVISIONING_PLAN_SCHEMA if trusted_host_local else PROVISIONING_PLAN_SCHEMA,
        "packageDigest": signed_package_digest(package),
        "artifactBundleDigest": artifact_bundle_digest(bundle),
        "generationDigest": generation_digest,
        "generationSequence": generation["sequence"],
        "minimumRollbackSequence": generation[
            "minimumRollbackSequence"
        ],
        "verificationReceiptDigest": verification_receipt_digest(receipt),
        "sourceRoot": {
            "fd": source_fd,
            "fdCustody": "retained-by-local-installer-through-publish" if trusted_host_local else "retained-by-native-parent-through-publish",
            **dict(
                bundle["stableSnapshotReceipt"]["payload"]["rootIdentity"]
            ),
        },
        "destination": {
            "root": root,
            "generationsDirectory": "generations",
            "generationDirectory": directory_name,
            "stagingDirectory": f".incoming/{directory_name}",
            "lockFile": ".authority-generation.lock",
            "terminalReceiptDirectory": "receipts",
            "ownerUid": uid,
            "ownerGid": gid,
            "directoryMode": 0o750,
            "renameFlags": ["RENAME_NOREPLACE"],
        },
        "entries": entries,
        "steps": steps,
        "stepContractDigest": step_contract_digest,
        "activation": {
            "performedByThisPlan": False,
            "requiredSuccessorProtocol": (
                "stop-drain-reconcile-witness-activate-restart-v1"
            ),
            "mutableCurrentSymlinkAllowed": False,
            "runtimeMustOpenExactGenerationDirectory": True,
        },
        "nativeExecutor": {
            "required": True,
            "pythonExecutionAuthorized": False,
            "requiredCapabilities": [
                "CAP_CHOWN",
                "CAP_DAC_OVERRIDE",
                "CAP_FOWNER",
                "CAP_LINUX_IMMUTABLE",
            ],
            "requiredSyscalls": [
                "flock",
                "fsync",
                "openat2",
                "renameat2",
            ],
            "requiredFilesystemFeatures": [
                "filesystem-generation",
                "fs-verity",
                "immutable-flag",
            ],
        },
    }
    if trusted_host_local:
        executor = plan_without_id.pop("nativeExecutor")
        executor.update(pythonExecutionAuthorized=True)
        plan_without_id["localExecutor"] = executor
    plan = {
        **plan_without_id,
        "planId": domain_digest(
            PROVISIONING_PLAN_DIGEST_DOMAIN,
            canonical_json_bytes(plan_without_id),
        ),
    }
    validate_provisioning_plan(plan)
    return plan


def validate_provisioning_plan(plan: Mapping[str, Any]) -> None:
    local = isinstance(plan, Mapping) and plan.get("schema") == LOCAL_PROVISIONING_PLAN_SCHEMA
    value = _closed(
        plan,
        name="provisioning plan",
        keys={
            "schema",
            "planId",
            "packageDigest",
            "artifactBundleDigest",
            "generationDigest",
            "generationSequence",
            "minimumRollbackSequence",
            "verificationReceiptDigest",
            "sourceRoot",
            "destination",
            "entries",
            "steps",
            "stepContractDigest",
            "activation",
            "localExecutor" if local else "nativeExecutor",
        },
    )
    if value["schema"] not in {PROVISIONING_PLAN_SCHEMA, LOCAL_PROVISIONING_PLAN_SCHEMA}:
        raise ProvisioningContractError("provisioning plan schema changed")
    for field in (
        "planId",
        "packageDigest",
        "artifactBundleDigest",
        "generationDigest",
        "verificationReceiptDigest",
        "stepContractDigest",
    ):
        _digest(value[field], name=field)
    sequence = _integer(
        value["generationSequence"],
        name="generation sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    rollback = _integer(
        value["minimumRollbackSequence"],
        name="minimum rollback sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    if rollback > sequence:
        raise ProvisioningContractError(
            "rollback floor exceeds generation"
        )
    source_root = _closed(
        value["sourceRoot"],
        name="retained source root",
        keys={
            "fd",
            "fdCustody",
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
    _integer(
        source_root["fd"],
        name="retained source root fd",
        minimum=3,
        maximum=2**31 - 1,
    )
    if source_root["fdCustody"] != ("retained-by-local-installer-through-publish" if local
            else "retained-by-native-parent-through-publish"):
        raise ProvisioningContractError(
            "source-root descriptor custody contract changed"
        )
    _runtime_path(
        source_root["runtimePath"],
        name="retained source root path",
    )
    for field, minimum, maximum in (
        ("device", 0, 2**64 - 1),
        ("inode", 1, 2**64 - 1),
        ("generation", 1, 2**64 - 1),
        ("mountId", 1, 2**64 - 1),
        ("mode", 0, 0o7777),
        ("uid", 0, 2**32 - 2),
        ("gid", 0, 2**32 - 2),
    ):
        _integer(
            source_root[field],
            name=f"retained source root {field}",
            minimum=minimum,
            maximum=maximum,
        )
    destination = _closed(
        value["destination"],
        name="provisioning destination",
        keys={
            "root",
            "generationsDirectory",
            "generationDirectory",
            "stagingDirectory",
            "lockFile",
            "terminalReceiptDirectory",
            "ownerUid",
            "ownerGid",
            "directoryMode",
            "renameFlags",
        },
    )
    _runtime_path(destination["root"], name="destination root")
    for field in (
        "generationsDirectory",
        "generationDirectory",
        "stagingDirectory",
        "lockFile",
        "terminalReceiptDirectory",
    ):
        _relative_path(destination[field], name=field)
    if destination["generationDirectory"] != _generation_directory_name(
        sequence, value["generationDigest"]
    ):
        raise ProvisioningContractError(
            "generation directory name changed"
        )
    _integer(
        destination["ownerUid"],
        name="destination uid",
        minimum=0,
        maximum=2**32 - 2,
    )
    _integer(
        destination["ownerGid"],
        name="destination gid",
        minimum=0,
        maximum=2**32 - 2,
    )
    if destination["directoryMode"] != 0o750:
        raise ProvisioningContractError(
            "generation directory mode changed"
        )
    if destination["renameFlags"] != ["RENAME_NOREPLACE"]:
        raise ProvisioningContractError("rename policy changed")

    entries = _bounded_list(
        value["entries"],
        name="provisioning entries",
        minimum=1,
        maximum=MAX_FILES,
    )
    for raw in entries:
        entry = _closed(
            raw,
            name="provisioning entry",
            keys={
                "path",
                "sourceSha256",
                "size",
                "mode",
                "uid",
                "gid",
                "requireFsVerity",
                "requireImmutable",
            },
        )
        _relative_path(entry["path"], name="provisioning path")
        _digest(entry["sourceSha256"], name="provisioning source digest")
        _integer(
            entry["size"],
            name="provisioning size",
            minimum=0,
            maximum=8 * 1024 * 1024 * 1024,
        )
        _integer(
            entry["mode"],
            name="provisioning mode",
            minimum=0,
            maximum=0o7777,
        )
        _integer(
            entry["uid"],
            name="provisioning uid",
            minimum=0,
            maximum=2**32 - 2,
        )
        _integer(
            entry["gid"],
            name="provisioning gid",
            minimum=0,
            maximum=2**32 - 2,
        )
        if (
            entry["requireFsVerity"] is not True
            or entry["requireImmutable"] is not True
        ):
            raise ProvisioningContractError(
                "provisioning entry is not immutable"
            )
    paths = [entry["path"] for entry in entries]
    if paths != sorted(set(paths)):
        raise ProvisioningContractError(
            "provisioning entries are not sorted and unique"
        )
    if sum(entry["size"] for entry in entries) > 64 * 1024**3:
        raise ProvisioningContractError(
            "aggregate provisioning bytes exceed the streaming limit"
        )

    steps = _bounded_list(
        value["steps"],
        name="provisioning steps",
        minimum=len(LOCAL_PROVISIONING_STEPS if local else ATOMIC_PROVISIONING_STEPS),
        maximum=len(LOCAL_PROVISIONING_STEPS if local else ATOMIC_PROVISIONING_STEPS),
    )
    expected_steps = [
        {"ordinal": index, "step": step}
        for index, step in enumerate(LOCAL_PROVISIONING_STEPS if local else ATOMIC_PROVISIONING_STEPS, start=1)
    ]
    if list(steps) != expected_steps:
        raise ProvisioningContractError(
            "provisioning step contract changed"
        )
    if value["stepContractDigest"] != domain_digest(
        PROVISIONING_STEP_CONTRACT_DOMAIN,
        canonical_json_bytes(expected_steps),
    ):
        raise ProvisioningContractError(
            "provisioning step digest changed"
        )

    activation = _closed(
        value["activation"],
        name="activation policy",
        keys={
            "performedByThisPlan",
            "requiredSuccessorProtocol",
            "mutableCurrentSymlinkAllowed",
            "runtimeMustOpenExactGenerationDirectory",
        },
    )
    if (
        activation["performedByThisPlan"] is not False
        or activation["requiredSuccessorProtocol"]
        != "stop-drain-reconcile-witness-activate-restart-v1"
        or activation["mutableCurrentSymlinkAllowed"] is not False
        or activation["runtimeMustOpenExactGenerationDirectory"] is not True
    ):
        raise ProvisioningContractError("activation policy changed")

    executor = _closed(
        value["localExecutor" if local else "nativeExecutor"],
        name="native executor policy",
        keys={
            "required",
            "pythonExecutionAuthorized",
            "requiredCapabilities",
            "requiredSyscalls",
            "requiredFilesystemFeatures",
        },
    )
    if (
        executor["required"] is not True
        or executor["pythonExecutionAuthorized"] is not local
        or executor["requiredCapabilities"]
        != [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_LINUX_IMMUTABLE",
        ]
        or executor["requiredSyscalls"]
        != ["flock", "fsync", "openat2", "renameat2"]
        or executor["requiredFilesystemFeatures"]
        != ["filesystem-generation", "fs-verity", "immutable-flag"]
    ):
        raise ProvisioningContractError("native executor policy changed")

    body = dict(value)
    plan_id = body.pop("planId")
    expected_plan_id = domain_digest(
        PROVISIONING_PLAN_DIGEST_DOMAIN,
        canonical_json_bytes(body),
    )
    if plan_id != expected_plan_id:
        raise ProvisioningContractError("provisioning plan ID changed")


def validate_provisioning_receipt(
    receipt: Mapping[str, Any],
    *,
    plan: Mapping[str, Any] | None = None,
) -> None:
    local = isinstance(receipt, Mapping) and receipt.get("schema") == LOCAL_PROVISIONING_RECEIPT_SCHEMA
    value = _closed(
        receipt,
        name="provisioning receipt",
        keys={
            "schema",
            "planDigest",
            "planId",
            "generationDigest",
            "generationSequence",
            "destinationRootIdentity",
            "generationDirectoryIdentity",
            "installedEntries",
            "stepContractDigest",
            "completedSteps",
            "activated",
            "completedAt",
            "executorIdentity",
            "executorMeasurementDigest",
            "signatureKeyId",
            "signatureAuthorizationDigest",
            "signatureAlgorithm",
            "signatureBase64Url",
        },
    )
    if value["schema"] not in {PROVISIONING_RECEIPT_SCHEMA, LOCAL_PROVISIONING_RECEIPT_SCHEMA}:
        raise ProvisioningContractError(
            "provisioning receipt schema changed"
        )
    for field in (
        "planDigest",
        "planId",
        "generationDigest",
        "stepContractDigest",
        "executorMeasurementDigest",
    ):
        _digest(value[field], name=field)
    _integer(
        value["generationSequence"],
        name="generation sequence",
        minimum=0,
        maximum=2**63 - 1,
    )
    for identity_name in (
        "destinationRootIdentity",
        "generationDirectoryIdentity",
    ):
        identity = _closed(
            value[identity_name],
            name=identity_name,
            keys={"device", "inode", "generation", "mode", "uid", "gid"},
        )
        for field, minimum, maximum in (
            ("device", 0, 2**64 - 1),
            ("inode", 1, 2**64 - 1),
            ("generation", 1, 2**64 - 1),
            ("mode", 0, 0o7777),
            ("uid", 0, 2**32 - 2),
            ("gid", 0, 2**32 - 2),
        ):
            _integer(
                identity[field],
                name=f"{identity_name} {field}",
                minimum=minimum,
                maximum=maximum,
            )
    installed = _bounded_list(
        value["installedEntries"],
        name="installed entries",
        minimum=1,
        maximum=MAX_FILES,
    )
    for raw in installed:
        entry = _closed(
            raw,
            name="installed entry",
            keys={
                "path",
                "sha256",
                "fsVerityDigest",
                "device",
                "inode",
                "generation",
                "mode",
                "uid",
                "gid",
                "size",
                "immutable",
            },
        )
        _relative_path(entry["path"], name="installed path")
        _digest(entry["sha256"], name="installed digest")
        _digest(entry["fsVerityDigest"], name="installed fs-verity digest")
        for field, minimum, maximum in (
            ("device", 0, 2**64 - 1),
            ("inode", 1, 2**64 - 1),
            ("generation", 1, 2**64 - 1),
            ("mode", 0, 0o7777),
            ("uid", 0, 2**32 - 2),
            ("gid", 0, 2**32 - 2),
            ("size", 0, 8 * 1024 * 1024 * 1024),
        ):
            _integer(
                entry[field],
                name=f"installed {field}",
                minimum=minimum,
                maximum=maximum,
            )
        if entry["immutable"] is not True:
            raise ProvisioningContractError(
                "installed entry is not immutable"
            )
    paths = [entry["path"] for entry in installed]
    if paths != sorted(set(paths)):
        raise ProvisioningContractError(
            "installed entries are not sorted and unique"
        )
    completed_steps = _bounded_list(
        value["completedSteps"],
        name="completed steps",
        minimum=len(LOCAL_PROVISIONING_STEPS if local else ATOMIC_PROVISIONING_STEPS),
        maximum=len(LOCAL_PROVISIONING_STEPS if local else ATOMIC_PROVISIONING_STEPS),
    )
    if list(completed_steps) != list(LOCAL_PROVISIONING_STEPS if local else ATOMIC_PROVISIONING_STEPS):
        raise ProvisioningContractError(
            "provisioning receipt is not terminal"
        )
    if value["activated"] is not False:
        raise ProvisioningContractError(
            "provisioning receipt cannot claim activation"
        )
    _timestamp(value["completedAt"], name="completedAt")
    _identifier(value["executorIdentity"], name="executor identity")
    _identifier(value["signatureKeyId"], name="receipt signature key")
    _digest(
        value["signatureAuthorizationDigest"],
        name="receipt signer authorization",
    )
    if value["signatureAlgorithm"] != "Ed25519":
        raise ProvisioningContractError(
            "provisioning receipt signature algorithm changed"
        )
    _base64url(
        value["signatureBase64Url"],
        name="provisioning receipt signature",
        decoded_size=64,
    )

    if plan is not None:
        validate_provisioning_plan(plan)
        if (
            local != (plan["schema"] == LOCAL_PROVISIONING_PLAN_SCHEMA)
            or
            value["planDigest"] != provisioning_plan_digest(plan)
            or value["planId"] != plan["planId"]
            or value["generationDigest"] != plan["generationDigest"]
            or value["generationSequence"] != plan["generationSequence"]
            or value["stepContractDigest"] != plan["stepContractDigest"]
            or [
                (
                    entry["path"],
                    entry["sha256"],
                    entry["size"],
                    entry["mode"],
                    entry["uid"],
                    entry["gid"],
                )
                for entry in installed
            ]
            != [
                (
                    entry["path"],
                    entry["sourceSha256"],
                    entry["size"],
                    entry["mode"],
                    entry["uid"],
                    entry["gid"],
                )
                for entry in plan["entries"]
            ]
        ):
            raise ProvisioningContractError(
                "provisioning receipt does not bind the plan"
            )


def provisioning_receipt_signature_message(
    receipt: Mapping[str, Any],
) -> bytes:
    payload = dict(receipt)
    if "signatureBase64Url" not in payload:
        raise ProvisioningContractError(
            "provisioning receipt signature is absent"
        )
    payload.pop("signatureBase64Url")
    return domain_digest(
        LOCAL_PROVISIONING_RECEIPT_SIGNATURE_DOMAIN if receipt.get("schema") == LOCAL_PROVISIONING_RECEIPT_SCHEMA
        else PROVISIONING_RECEIPT_SIGNATURE_DOMAIN,
        canonical_json_bytes(payload),
    ).encode("ascii")


def verification_receipt_signature_message(
    receipt: Mapping[str, Any],
) -> bytes:
    value = dict(receipt)
    if set(value) != {
        "schema",
        "packageDigest",
        "artifactBundleDigest",
        "generationDigest",
        "generationSequence",
        "minimumRollbackSequence",
        "trustMode",
        "verifiedSignatures",
        "stageZeroVerification",
        "closureVerification",
        "rollbackWitness",
        "verifierIdentity",
        "verificationPolicyDigest",
        "verifiedAt",
        "validUntil",
        "receiptSignerKeyId",
        "receiptSignerAuthorizationDigest",
        "receiptSignatureAlgorithm",
        "receiptSignatureBase64Url",
    }:
        raise ProvisioningContractError(
            "verification receipt is not a closed object"
        )
    value.pop("receiptSignatureBase64Url")
    return domain_digest(
        "serverware.authorityArtifactVerificationReceiptSignature/v1",
        canonical_json_bytes(value),
    ).encode("ascii")


def verify_verification_receipt(
    receipt: Mapping[str, Any],
    *,
    verified_package: VerifiedArtifactPackage,
    validation_time: str,
    accepted_receipt_digests: Sequence[str],
    exact_retry_digest: str | None = None,
) -> str:
    if not isinstance(verified_package, VerifiedArtifactPackage):
        raise ProvisioningContractError(
            "verification receipt requires a verified package"
        )
    package = verified_package.package
    validate_verification_receipt(receipt, package=package)
    validation_instant = _timestamp(
        validation_time,
        name="verification receipt validation time",
    )
    if not (
        _timestamp(receipt["verifiedAt"], name="verifiedAt")
        <= validation_instant
        <= _timestamp(receipt["validUntil"], name="validUntil")
    ):
        raise ProvisioningContractError(
            "verification receipt is outside its validity interval"
        )
    try:
        signer = verified_package.require_key(
            receipt["receiptSignerKeyId"],
            "artifact-verifier",
            at=validation_time,
        )
    except ArtifactContractError as exc:
        raise ProvisioningContractError(str(exc)) from exc
    if signer.authorization_digest != receipt[
        "receiptSignerAuthorizationDigest"
    ]:
        raise ProvisioningContractError(
            "verification receipt signer authorization changed"
        )
    try:
        verify_ed25519_signature(
            signer.public_key,
            receipt["receiptSignatureBase64Url"],
            verification_receipt_signature_message(receipt),
            name="artifact verification receipt",
        )
    except ArtifactContractError as exc:
        raise ProvisioningContractError(str(exc)) from exc
    digest = verification_receipt_digest(receipt)
    accepted = list(accepted_receipt_digests)
    for accepted_digest in accepted:
        _digest(accepted_digest, name="accepted verification receipt")
    if accepted != sorted(set(accepted)):
        raise ProvisioningContractError(
            "accepted verification receipts are not sorted and unique"
        )
    if digest in accepted and digest != exact_retry_digest:
        raise ProvisioningContractError(
            "verification receipt replay is not an exact authorized retry"
        )
    return "ExactRetry" if digest == exact_retry_digest else "New"


def verify_provisioning_receipt(
    receipt: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    verified_package: VerifiedArtifactPackage,
    validation_time: str,
    accepted_receipt_digests: Sequence[str] = (),
    exact_retry_digest: str | None = None,
) -> str:
    validate_provisioning_receipt(receipt, plan=plan)
    if plan["schema"] == LOCAL_PROVISIONING_PLAN_SCHEMA and (
            verified_package.trust_mode != "trusted-host-local" or
            verified_package.stage_zero_contract != LOCAL_STAGE_ZERO_INTERFACE_SCHEMA):
        raise ProvisioningContractError("local provisioning cannot admit a native or production package")
    if plan["schema"] != LOCAL_PROVISIONING_PLAN_SCHEMA and verified_package.stage_zero_contract == LOCAL_STAGE_ZERO_INTERFACE_SCHEMA:
        raise ProvisioningContractError("local package cannot claim native provisioning")
    if _timestamp(receipt["completedAt"], name="completedAt") > _timestamp(
        validation_time,
        name="provisioning receipt validation time",
    ):
        raise ProvisioningContractError(
            "provisioning receipt is from the future"
        )
    if (
        plan["packageDigest"] != verified_package.package_digest
        or plan["generationDigest"] != verified_package.generation_digest
    ):
        raise ProvisioningContractError(
            "provisioning plan differs from verified package"
        )
    try:
        signer = verified_package.require_key(
            receipt["signatureKeyId"],
            "artifact-provisioner",
            at=validation_time,
        )
    except ArtifactContractError as exc:
        raise ProvisioningContractError(str(exc)) from exc
    if signer.authorization_digest != receipt[
        "signatureAuthorizationDigest"
    ]:
        raise ProvisioningContractError(
            "provisioning signer authorization changed"
        )
    try:
        verify_ed25519_signature(
            signer.public_key,
            receipt["signatureBase64Url"],
            provisioning_receipt_signature_message(receipt),
            name="atomic provisioning receipt",
        )
    except ArtifactContractError as exc:
        raise ProvisioningContractError(str(exc)) from exc
    digest = provisioning_receipt_digest(receipt)
    accepted = list(accepted_receipt_digests)
    for accepted_digest in accepted:
        _digest(accepted_digest, name="accepted provisioning receipt")
    if accepted != sorted(set(accepted)):
        raise ProvisioningContractError(
            "accepted provisioning receipts are not sorted and unique"
        )
    if digest in accepted and digest != exact_retry_digest:
        raise ProvisioningContractError(
            "provisioning receipt replay is not an exact authorized retry"
        )
    return "ExactRetry" if digest == exact_retry_digest else "New"


def validate_provisioning_state(state: Mapping[str, Any]) -> None:
    value = _closed(
        state,
        name="provisioning state",
        keys={
            "schema",
            "stateId",
            "recordDigest",
            "revision",
            "status",
            "requestId",
            "transitionId",
            "packageDigest",
            "generationDigest",
            "planDigest",
            "sourceRootIdentityDigest",
            "previousStateDigest",
            "preparedAt",
            "publishedAt",
            "terminalAt",
            "publishedIdentityDigest",
            "terminalReceiptDigest",
            "terminalReceiptBytesBase64Url",
            "abortReasonDigest",
        },
    )
    if value["schema"] != PROVISIONING_STATE_SCHEMA:
        raise ProvisioningContractError("provisioning state schema changed")
    for field in (
        "stateId",
        "recordDigest",
        "packageDigest",
        "generationDigest",
        "planDigest",
        "sourceRootIdentityDigest",
    ):
        _digest(value[field], name=field)
    revision = _integer(
        value["revision"],
        name="provisioning state revision",
        minimum=0,
        maximum=2**63 - 1,
    )
    _identifier(value["requestId"], name="provisioning request")
    _identifier(value["transitionId"], name="provisioning transition")
    _timestamp(value["preparedAt"], name="preparedAt")
    for field in (
        "previousStateDigest",
        "publishedIdentityDigest",
        "terminalReceiptDigest",
        "abortReasonDigest",
    ):
        if value[field] is not None:
            _digest(value[field], name=field)
    for field in ("publishedAt", "terminalAt"):
        if value[field] is not None:
            _timestamp(value[field], name=field)
    status = value["status"]
    if status not in {"Prepared", "Published", "Receipted", "Aborted"}:
        raise ProvisioningContractError(
            "provisioning state status is not recognized"
        )
    if (revision == 0) != (value["previousStateDigest"] is None):
        raise ProvisioningContractError(
            "provisioning state predecessor is inconsistent"
        )
    terminal_bytes = value["terminalReceiptBytesBase64Url"]
    if status == "Prepared":
        expected_null = (
            "publishedAt",
            "terminalAt",
            "publishedIdentityDigest",
            "terminalReceiptDigest",
            "terminalReceiptBytesBase64Url",
            "abortReasonDigest",
        )
    elif status == "Published":
        expected_null = (
            "terminalAt",
            "terminalReceiptDigest",
            "terminalReceiptBytesBase64Url",
            "abortReasonDigest",
        )
        if (
            value["publishedAt"] is None
            or value["publishedIdentityDigest"] is None
        ):
            raise ProvisioningContractError(
                "published state lacks published identity"
            )
    else:
        expected_null = ()
        if (
            value["terminalAt"] is None
            or value["terminalReceiptDigest"] is None
            or terminal_bytes is None
        ):
            raise ProvisioningContractError(
                "terminal state lacks exact receipt bytes"
            )
        try:
            decoded = strict_base64url_decode(
                terminal_bytes,
                name="terminal receipt bytes",
                maximum_decoded_size=MAX_DOCUMENT_BYTES,
            )
        except ArtifactContractError as exc:
            raise ProvisioningContractError(str(exc)) from exc
        if value["terminalReceiptDigest"] != domain_digest(
            "serverware.authorityExactTerminalReceiptBytes/v1",
            decoded,
        ):
            raise ProvisioningContractError(
                "terminal receipt digest differs from exact bytes"
            )
        if status == "Receipted" and (
            value["publishedAt"] is None
            or value["publishedIdentityDigest"] is None
            or value["abortReasonDigest"] is not None
        ):
            raise ProvisioningContractError(
                "receipted state is incomplete"
            )
        if status == "Aborted" and value["abortReasonDigest"] is None:
            raise ProvisioningContractError(
                "aborted state lacks a reason digest"
            )
    if any(value[field] is not None for field in expected_null):
        raise ProvisioningContractError(
            "provisioning state contains fields invalid for its status"
        )
    body = dict(value)
    record_digest = body.pop("recordDigest")
    if record_digest != domain_digest(
        PROVISIONING_STATE_DIGEST_DOMAIN,
        canonical_json_bytes(body),
    ):
        raise ProvisioningContractError(
            "provisioning state record digest changed"
        )


def provisioning_state_digest(state: Mapping[str, Any]) -> str:
    validate_provisioning_state(state)
    return state["recordDigest"]


def validate_provisioning_transition(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
) -> None:
    validate_provisioning_state(previous)
    validate_provisioning_state(current)
    for field in (
        "stateId",
        "requestId",
        "transitionId",
        "packageDigest",
        "generationDigest",
        "planDigest",
        "sourceRootIdentityDigest",
        "preparedAt",
    ):
        if previous[field] != current[field]:
            raise ProvisioningContractError(
                f"provisioning transition changed immutable {field}"
            )
    if (
        current["revision"] != previous["revision"] + 1
        or current["previousStateDigest"]
        != provisioning_state_digest(previous)
    ):
        raise ProvisioningContractError(
            "provisioning transition does not use exact CAS predecessor"
        )
    allowed = {
        "Prepared": {"Published", "Aborted"},
        "Published": {"Receipted", "Aborted"},
        "Receipted": set(),
        "Aborted": set(),
    }
    if current["status"] not in allowed[previous["status"]]:
        raise ProvisioningContractError(
            "provisioning state transition is not allowed"
        )


def exact_retry_receipt_bytes(
    state: Mapping[str, Any],
    *,
    request_id: str,
    transition_id: str,
    package_digest: str,
) -> bytes | None:
    validate_provisioning_state(state)
    if (
        state["requestId"] != request_id
        or state["transitionId"] != transition_id
        or state["packageDigest"] != package_digest
    ):
        raise ProvisioningContractError(
            "retry identity differs from durable provisioning state"
        )
    if state["status"] not in {"Receipted", "Aborted"}:
        return None
    try:
        return strict_base64url_decode(
            state["terminalReceiptBytesBase64Url"],
            name="terminal receipt bytes",
            maximum_decoded_size=MAX_DOCUMENT_BYTES,
        )
    except ArtifactContractError as exc:
        raise ProvisioningContractError(str(exc)) from exc


def _verify_recovery_receipt(
    receipt: Mapping[str, Any],
    *,
    schema: str,
    purpose: str,
    signature_domain: str,
    payload_keys: set[str],
    verified_package: VerifiedArtifactPackage,
    validation_time: str,
) -> None:
    envelope = _closed(
        receipt,
        name="recovery receipt",
        keys={
            "schema",
            "payload",
            "signerKeyId",
            "signerAuthorizationDigest",
            "algorithm",
            "signatureBase64Url",
        },
    )
    if envelope["schema"] != schema or envelope["algorithm"] != "Ed25519":
        raise ProvisioningContractError("recovery receipt envelope changed")
    _identifier(envelope["signerKeyId"], name="recovery signer key")
    _digest(
        envelope["signerAuthorizationDigest"],
        name="recovery signer authorization",
    )
    _base64url(
        envelope["signatureBase64Url"],
        name="recovery receipt signature",
        decoded_size=64,
    )
    payload = _closed(
        envelope["payload"],
        name="recovery receipt payload",
        keys=payload_keys,
    )
    if (
        payload["packageDigest"] != verified_package.package_digest
        or payload["generationDigest"]
        != verified_package.generation_digest
    ):
        raise ProvisioningContractError(
            "recovery receipt differs from verified package"
        )
    if _timestamp(
        payload["completedAt"],
        name="recovery completedAt",
    ) > _timestamp(
        validation_time,
        name="recovery receipt validation time",
    ):
        raise ProvisioningContractError(
            "recovery receipt is from the future"
        )
    try:
        signer = verified_package.require_key(
            envelope["signerKeyId"],
            purpose,
            at=validation_time,
        )
    except ArtifactContractError as exc:
        raise ProvisioningContractError(str(exc)) from exc
    if signer.authorization_digest != envelope[
        "signerAuthorizationDigest"
    ]:
        raise ProvisioningContractError(
            "recovery signer authorization changed"
        )
    try:
        verify_ed25519_signature(
            signer.public_key,
            envelope["signatureBase64Url"],
            domain_digest(
                signature_domain,
                canonical_json_bytes(payload),
            ).encode("ascii"),
            name="provisioning recovery receipt",
        )
    except ArtifactContractError as exc:
        raise ProvisioningContractError(str(exc)) from exc


def verify_reconciliation_receipt(
    receipt: Mapping[str, Any],
    *,
    verified_package: VerifiedArtifactPackage,
    validation_time: str,
) -> None:
    _verify_recovery_receipt(
        receipt,
        schema=RECONCILIATION_RECEIPT_SCHEMA,
        purpose="provisioning-reconciler",
        signature_domain=RECONCILIATION_RECEIPT_SIGNATURE_DOMAIN,
        payload_keys={
            "packageDigest",
            "generationDigest",
            "planDigest",
            "stateBeforeDigest",
            "stateAfterDigest",
            "outcome",
            "publishedIdentityDigest",
            "terminalReceiptDigest",
            "completedAt",
        },
        verified_package=verified_package,
        validation_time=validation_time,
    )
    payload = receipt["payload"]
    for field in (
        "planDigest",
        "stateBeforeDigest",
        "stateAfterDigest",
        "terminalReceiptDigest",
    ):
        _digest(payload[field], name=field)
    if payload["publishedIdentityDigest"] is not None:
        _digest(
            payload["publishedIdentityDigest"],
            name="published identity digest",
        )
    if payload["outcome"] not in {"Receipted", "Aborted"}:
        raise ProvisioningContractError(
            "reconciliation outcome is not terminal"
        )
    if (
        payload["outcome"] == "Receipted"
        and payload["publishedIdentityDigest"] is None
    ):
        raise ProvisioningContractError(
            "receipted reconciliation lacks published identity"
        )


def verify_cleanup_receipt(
    receipt: Mapping[str, Any],
    *,
    verified_package: VerifiedArtifactPackage,
    validation_time: str,
) -> None:
    _verify_recovery_receipt(
        receipt,
        schema=CLEANUP_RECEIPT_SCHEMA,
        purpose="provisioning-cleanup",
        signature_domain=CLEANUP_RECEIPT_SIGNATURE_DOMAIN,
        payload_keys={
            "packageDigest",
            "generationDigest",
            "planDigest",
            "stateBeforeDigest",
            "stateAfterDigest",
            "stagingIdentityDigest",
            "removed",
            "terminalReceiptDigest",
            "completedAt",
        },
        verified_package=verified_package,
        validation_time=validation_time,
    )
    payload = receipt["payload"]
    for field in (
        "planDigest",
        "stateBeforeDigest",
        "stateAfterDigest",
        "stagingIdentityDigest",
        "terminalReceiptDigest",
    ):
        _digest(payload[field], name=field)
    if payload["removed"] is not True:
        raise ProvisioningContractError(
            "cleanup receipt does not prove staging removal"
        )


def _load_json(path: str) -> Mapping[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_DOCUMENT_BYTES
        ):
            raise ProvisioningContractError(
                "contract document is not a bounded file"
            )
        data = bytearray()
        while len(data) < metadata.st_size:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, metadata.st_size - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if len(data) != metadata.st_size or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ProvisioningContractError(
                "contract document changed while reading"
            )
    finally:
        os.close(descriptor)
    try:
        value = json.loads(bytes(data))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvisioningContractError(
            "contract document is not JSON"
        ) from exc
    if not isinstance(value, Mapping):
        raise ProvisioningContractError(
            "contract document is not an object"
        )
    return value


def _atomic_write(path: str, data: bytes) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    name = os.path.basename(path)
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
                raise ProvisioningContractError(
                    "plan write made no progress"
                )
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
            "Build the closed plan consumed by the native atomic authority "
            "artifact provisioner. This command does not provision or activate."
        )
    )
    parser.add_argument("--package", required=True)
    parser.add_argument("--trust-state", required=True)
    parser.add_argument("--validation-time", required=True)
    parser.add_argument("--verification-receipt", required=True)
    parser.add_argument("--source-root-fd", required=True, type=int)
    parser.add_argument("--destination-root", required=True)
    parser.add_argument("--owner-uid", required=True, type=int)
    parser.add_argument("--owner-gid", required=True, type=int)
    parser.add_argument("--output-plan", required=True)
    arguments = parser.parse_args(argv)
    package = _load_json(arguments.package)
    trust_state = _load_json(arguments.trust_state)
    receipt = _load_json(arguments.verification_receipt)
    verified_package = verify_signed_artifact_package(
        package,
        trust_state=trust_state,
        validation_time=arguments.validation_time,
    )
    plan = build_provisioning_plan(
        verified_package,
        receipt,
        validation_time=arguments.validation_time,
        source_root_fd=arguments.source_root_fd,
        destination_root=arguments.destination_root,
        owner_uid=arguments.owner_uid,
        owner_gid=arguments.owner_gid,
    )
    _atomic_write(
        arguments.output_plan,
        canonical_json_bytes(plan) + b"\n",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ArtifactContractError,
        ProvisioningContractError,
        OSError,
    ) as exc:
        print(f"authority provisioning plan failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
