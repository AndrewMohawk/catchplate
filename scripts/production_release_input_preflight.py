#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_aws_kms_materials  # noqa: E402
import publish_production_images  # noqa: E402
import run_production_readiness  # noqa: E402
import verify_reproducible_builds  # noqa: E402
import verify_production_readiness  # noqa: E402
import verify_production_policy_identity  # noqa: E402

NOOP_DEPLOY_COMMANDS = {":", "echo", "false", "true", "/bin/false", "/bin/true"}
PLACEHOLDER_MARKERS = ("change-me", "changeme", "example command", "replace-me", "todo")
EXTERNAL_SIGNATURE_API_VERSION = "serverware.externalArtifactSignature/v1"
EXTERNAL_SIGNATURE_KIND = "ExternalArtifactSignature"
ACTIVATION_PURPOSE = "policy-activation-verification"
REPRODUCIBILITY_PURPOSE = "reproducible-build-verification"
ACTIVATION_API_VERSION = "serverware.policyActivationEvidenceVerification/v1"
ACTIVATION_KIND = "PolicyActivationEvidenceVerification"
REPRODUCIBILITY_API_VERSION = verify_reproducible_builds.VERIFICATION_API_VERSION
REPRODUCIBILITY_KIND = verify_reproducible_builds.VERIFICATION_KIND
PRE_PUBLISH_CONFIG_CHECKS = (
    verify_production_readiness.check_no_dev_or_fixture,
    verify_production_readiness.check_control_plane_security,
    verify_production_readiness.check_internal_service_auth,
    verify_production_readiness.check_nitro,
    verify_production_readiness.check_attested_credential_delivery,
    verify_production_readiness.check_cosign,
    verify_production_readiness.check_transparency,
    verify_production_readiness.check_apparmor,
    verify_production_readiness.check_shared_stores,
    verify_production_readiness.check_agent_egress,
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def file_digest(path: Path) -> str:
    return sha256_prefixed(path.read_bytes())


def strict_json(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{label} could not be read: {path}") from exc
    return strict_json_bytes(raw, label)


def strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"{label} must use strict JSON values")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def external_signature_payload(*, purpose: str, artifact_sha256: str) -> bytes:
    return canonical_json(
        {
            "apiVersion": EXTERNAL_SIGNATURE_API_VERSION,
            "artifactSha256": artifact_sha256,
            "purpose": purpose,
        }
    ).encode("utf-8")


def public_key(path: Path, label: str) -> tuple[Ed25519PublicKey, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{label} is not a valid Ed25519 public key") from exc
    return public_key_bytes(raw, label)


def public_key_bytes(raw: bytes, label: str) -> tuple[Ed25519PublicKey, str]:
    try:
        if b"PRIVATE KEY" in raw:
            raise ValueError(f"{label} must contain public key material only")
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not a valid Ed25519 public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{label} must be an Ed25519 public key")
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, sha256_prefixed(der)


def verify_externally_signed_report(
    *,
    report_path: Path,
    signature_path: Path,
    trusted_public_key_path: Path,
    purpose: str,
    api_version: str,
    kind: str,
) -> dict[str, Any]:
    # Parsing, signature verification, and returned digests share these bytes.
    # Callers with an existing input snapshot use the bytes entry point below.
    try:
        report_bytes = report_path.read_bytes()
        signature_bytes = signature_path.read_bytes()
        trusted_public_key_bytes = trusted_public_key_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{purpose} evidence could not be read") from exc
    return verify_externally_signed_report_bytes(
        report_bytes=report_bytes,
        signature_bytes=signature_bytes,
        trusted_public_key_bytes=trusted_public_key_bytes,
        purpose=purpose,
        api_version=api_version,
        kind=kind,
    )


def verify_externally_signed_report_bytes(
    *,
    report_bytes: bytes,
    signature_bytes: bytes,
    trusted_public_key_bytes: bytes,
    purpose: str,
    api_version: str,
    kind: str,
) -> dict[str, Any]:
    report = strict_json_bytes(report_bytes, f"{purpose} report")
    if report.get("apiVersion") != api_version or report.get("kind") != kind or report.get("ok") is not True:
        raise ValueError(f"{purpose} report is not a successful {api_version} artifact")
    signature_document = strict_json_bytes(signature_bytes, f"{purpose} detached signature")
    expected_fields = {
        "apiVersion",
        "kind",
        "algorithm",
        "purpose",
        "artifactSha256",
        "signerKeyId",
        "signature",
    }
    if set(signature_document) != expected_fields:
        raise ValueError(f"{purpose} detached signature has unexpected or missing fields")
    artifact_sha256 = sha256_prefixed(report_bytes)
    key, key_id = public_key_bytes(trusted_public_key_bytes, f"{purpose} trusted public key")
    if (
        signature_document.get("apiVersion") != EXTERNAL_SIGNATURE_API_VERSION
        or signature_document.get("kind") != EXTERNAL_SIGNATURE_KIND
        or signature_document.get("algorithm") != "Ed25519"
        or signature_document.get("purpose") != purpose
        or signature_document.get("artifactSha256") != artifact_sha256
        or signature_document.get("signerKeyId") != key_id
    ):
        raise ValueError(f"{purpose} detached signature binding is invalid")
    encoded = signature_document.get("signature")
    if not isinstance(encoded, str) or not encoded.startswith("ed25519:"):
        raise ValueError(f"{purpose} detached signature encoding is invalid")
    try:
        signature = base64.urlsafe_b64decode(encoded.split(":", 1)[1] + "==")
        key.verify(signature, external_signature_payload(purpose=purpose, artifact_sha256=artifact_sha256))
    except Exception as exc:
        raise ValueError(f"{purpose} detached signature verification failed") from exc
    return {
        "ok": True,
        "purpose": purpose,
        "reportSha256": artifact_sha256,
        "signatureSha256": sha256_prefixed(signature_bytes),
        "trustedPublicKeySha256": sha256_prefixed(trusted_public_key_bytes),
        "signerKeyId": key_id,
        "report": report,
    }


def require_private_file(path: Path, label: str) -> None:
    if not path.exists() or not path.is_file():
        raise ValueError(f"{label} is not a file: {path}")
    if path.stat().st_mode & 0o077:
        raise ValueError(f"{label} must not be group/world accessible: {path}")


def validate_deploy_command(value: str) -> str:
    command = value.strip()
    lowered = command.lower()
    if not command:
        raise ValueError("production deploy command is required")
    if lowered in NOOP_DEPLOY_COMMANDS or any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        raise ValueError("production deploy command must not be a no-op or placeholder")
    return command


def git_state(repo_root: Path) -> tuple[str, bool]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if revision.returncode != 0:
        raise ValueError("production release input must be a Git checkout")
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if status.returncode != 0:
        raise ValueError("could not inspect production release Git state")
    return revision.stdout.strip(), not bool(status.stdout.strip())


def material_summary(spec: dict[str, Any]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for material in sorted(spec):
        key_id, plaintext_path, context = prepare_aws_kms_materials.material_config(spec[material])
        require_private_file(plaintext_path, f"{material} plaintext source")
        summary.append(
            {
                "material": material,
                "key_id_sha256": sha256_prefixed(key_id.encode("utf-8")),
                "plaintext_path_sha256": sha256_prefixed(str(plaintext_path).encode("utf-8")),
                "plaintext_bytes": plaintext_path.stat().st_size,
                "encryption_context_sha256": sha256_prefixed(canonical_json(context).encode("utf-8")),
            }
        )
    return summary


def verify_inputs(
    *,
    repo_root: Path,
    env_file: Path,
    kms_spec: Path,
    registry_prefix: str,
    deploy_command: str,
    policy_bundle: Path,
    policy_trusted_public_key: Path,
    policy_identity_verification: Path,
    policy_activation_verification: Path,
    policy_activation_signature: Path,
    policy_activation_trusted_public_key: Path,
    reproducible_build_verification: Path,
    reproducible_build_signature: Path,
    reproducible_build_trusted_public_key: Path,
) -> dict[str, Any]:
    for command in ("docker", "git"):
        if shutil.which(command) is None:
            raise ValueError(f"required release command is unavailable: {command}")
    if env_file.name.endswith(".example"):
        raise ValueError("production release must not use an example environment file")
    require_private_file(env_file, "production readiness env file")
    loaded_env = run_production_readiness.load_env_file(env_file)
    if not loaded_env:
        raise ValueError("production readiness env file is empty")
    effective_env = os.environ.copy()
    effective_env.update(loaded_env)
    failures: list[str] = []
    for check in PRE_PUBLISH_CONFIG_CHECKS:
        try:
            check(effective_env, failures)
        except Exception as exc:
            failures.append(str(exc))
    if failures:
        raise ValueError("production configuration failed pre-publish checks: " + "; ".join(failures))
    if not kms_spec.exists() or not kms_spec.is_file():
        raise ValueError(f"AWS KMS materials spec is not a file: {kms_spec}")
    spec = prepare_aws_kms_materials.load_spec(kms_spec, require_plaintext_files=True)
    prefix = publish_production_images.validate_registry_prefix(registry_prefix)
    command = validate_deploy_command(deploy_command)
    policy_identity = verify_production_policy_identity.verify_persisted_report(
        bundle_path=policy_bundle,
        trusted_public_key_path=policy_trusted_public_key,
        report_path=policy_identity_verification,
    )
    activation = verify_externally_signed_report(
        report_path=policy_activation_verification,
        signature_path=policy_activation_signature,
        trusted_public_key_path=policy_activation_trusted_public_key,
        purpose=ACTIVATION_PURPOSE,
        api_version=ACTIVATION_API_VERSION,
        kind=ACTIVATION_KIND,
    )
    if activation["report"].get("production_mode") is not True or activation["report"].get("environment") != "production":
        raise ValueError("policy activation verification is not production evidence")
    if activation["report"].get("candidate_policy_hash") != policy_identity["policyHash"]:
        raise ValueError("policy activation candidate hash does not match the identity-verified policy")
    reproducibility = verify_externally_signed_report(
        report_path=reproducible_build_verification,
        signature_path=reproducible_build_signature,
        trusted_public_key_path=reproducible_build_trusted_public_key,
        purpose=REPRODUCIBILITY_PURPOSE,
        api_version=REPRODUCIBILITY_API_VERSION,
        kind=REPRODUCIBILITY_KIND,
    )
    if reproducibility["report"].get("reproducible") is not True:
        raise ValueError("reproducible-build verification did not prove matching artifacts")
    reproducibility_scope = reproducibility["report"].get("scope")
    if not isinstance(reproducibility_scope, dict) or reproducibility_scope.get("independent_execution_proven") is not True:
        raise ValueError("reproducible-build verification did not prove two independent trusted builders")
    revision, clean = git_state(repo_root)
    if not clean:
        raise ValueError("production release requires a clean Git checkout")
    return {
        "apiVersion": "serverware.productionReleaseInputPreflight/v1",
        "kind": "ProductionReleaseInputPreflight",
        "ok": True,
        "source": {"revision": revision, "clean": True},
        "inputs": {
            "env_file_sha256": file_digest(env_file),
            "env_keys": sorted(loaded_env),
            "semantic_config_checks": [check.__name__ for check in PRE_PUBLISH_CONFIG_CHECKS],
            "kms_spec_sha256": file_digest(kms_spec),
            "materials": material_summary(spec),
            "registry_prefix_sha256": sha256_prefixed(prefix.encode("utf-8")),
            "deploy_command_sha256": sha256_prefixed(command.encode("utf-8")),
            "policy_identity": policy_identity,
            "policy_activation": {key: value for key, value in activation.items() if key != "report"},
            "reproducible_builds": {
                **{key: value for key, value in reproducibility.items() if key != "report"},
                "scope": reproducibility_scope,
                "sourceTreeDigest": reproducibility["report"].get("source_tree_digest"),
            },
        },
    }


def write_private(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate immutable production release inputs before any publish or deploy mutation.")
    parser.add_argument("--repo-root", default=str(ROOT))
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--kms-spec", required=True)
    parser.add_argument("--registry-prefix", required=True)
    parser.add_argument("--deploy-command", required=True)
    parser.add_argument("--policy-bundle", required=True)
    parser.add_argument("--policy-trusted-public-key", required=True)
    parser.add_argument("--policy-identity-verification", required=True)
    parser.add_argument("--policy-activation-verification", required=True)
    parser.add_argument("--policy-activation-signature", required=True)
    parser.add_argument("--policy-activation-trusted-public-key", required=True)
    parser.add_argument("--reproducible-build-verification", required=True)
    parser.add_argument("--reproducible-build-signature", required=True)
    parser.add_argument("--reproducible-build-trusted-public-key", required=True)
    parser.add_argument("--out", default=".tmp/production-release-input-preflight.json")
    args = parser.parse_args()
    try:
        result = verify_inputs(
            repo_root=Path(args.repo_root).resolve(),
            env_file=Path(args.env_file).resolve(),
            kms_spec=Path(args.kms_spec).resolve(),
            registry_prefix=args.registry_prefix,
            deploy_command=args.deploy_command,
            policy_bundle=Path(args.policy_bundle).resolve(),
            policy_trusted_public_key=Path(args.policy_trusted_public_key).resolve(),
            policy_identity_verification=Path(args.policy_identity_verification).resolve(),
            policy_activation_verification=Path(args.policy_activation_verification).resolve(),
            policy_activation_signature=Path(args.policy_activation_signature).resolve(),
            policy_activation_trusted_public_key=Path(args.policy_activation_trusted_public_key).resolve(),
            reproducible_build_verification=Path(args.reproducible_build_verification).resolve(),
            reproducible_build_signature=Path(args.reproducible_build_signature).resolve(),
            reproducible_build_trusted_public_key=Path(args.reproducible_build_trusted_public_key).resolve(),
        )
        write_private(Path(args.out), result)
        print(canonical_json(result))
    except Exception as exc:
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
