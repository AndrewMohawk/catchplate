#!/usr/bin/env python3
from __future__ import annotations

import json
import shlex
import subprocess
import sys
import tempfile
import time
import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import test_production_readiness  # noqa: E402
import test_production_policy_identity  # noqa: E402
import production_release_input_preflight  # noqa: E402
import verify_production_policy_identity  # noqa: E402


def signed_report(
    tmp: Path,
    *,
    name: str,
    purpose: str,
    report: dict[str, object],
) -> tuple[Path, Path, Path]:
    report_path = tmp / f"{name}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    private_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(name.encode("ascii")).digest())
    public_key = private_key.public_key()
    public_path = tmp / f"{name}.pub.pem"
    public_path.write_bytes(
        public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    artifact_digest = production_release_input_preflight.file_digest(report_path)
    signature = private_key.sign(
        production_release_input_preflight.external_signature_payload(
            purpose=purpose,
            artifact_sha256=artifact_digest,
        )
    )
    signature_path = tmp / f"{name}.signature.json"
    signature_path.write_text(
        json.dumps(
            {
                "apiVersion": production_release_input_preflight.EXTERNAL_SIGNATURE_API_VERSION,
                "kind": production_release_input_preflight.EXTERNAL_SIGNATURE_KIND,
                "algorithm": "Ed25519",
                "purpose": purpose,
                "artifactSha256": artifact_digest,
                "signerKeyId": "sha256:" + hashlib.sha256(der).hexdigest(),
                "signature": "ed25519:" + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report_path, signature_path, public_path


def release_security_fixture(
    tmp: Path,
    *,
    source_tree_digest: str = "sha256:" + "a" * 64,
    images: list[dict[str, str]] | None = None,
) -> tuple[dict[str, Path], str]:
    fixture = test_production_policy_identity.ProductionPolicyIdentityVerifierTests(methodName="runTest")
    fixture.setUp()
    fixture.now_ms = int(time.time() * 1000)
    bundle = fixture.bundle()
    bundle_path = tmp / "policy-bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    policy_key_path = tmp / "policy-signing.pub.pem"
    policy_key_path.write_text(fixture.public_key_pem, encoding="ascii")
    identity_result = fixture.verify(bundle)
    if identity_result.get("ok") is not True:
        raise AssertionError(f"release security fixture policy identity was rejected: {identity_result}")
    identity_path = tmp / "production-policy-identity-verification.json"
    verify_production_policy_identity.write_private(
        identity_path,
        verify_production_policy_identity.persisted_report(
            identity_result,
            bundle_path=bundle_path,
            trusted_public_key_path=policy_key_path,
            trusted_public_key_hash=fixture.public_key_hash,
        ),
    )
    policy_hash = identity_result["policy"]["hash"]
    activation = signed_report(
        tmp,
        name="policy-activation-verification",
        purpose=production_release_input_preflight.ACTIVATION_PURPOSE,
        report={
            "apiVersion": production_release_input_preflight.ACTIVATION_API_VERSION,
            "kind": production_release_input_preflight.ACTIVATION_KIND,
            "ok": True,
            "production_mode": True,
            "environment": "production",
            "candidate_policy_hash": policy_hash,
        },
    )
    reproducibility = signed_report(
        tmp,
        name="reproducible-build-verification",
        purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
        report={
            "apiVersion": production_release_input_preflight.REPRODUCIBILITY_API_VERSION,
            "kind": production_release_input_preflight.REPRODUCIBILITY_KIND,
            "ok": True,
            "reproducible": True,
            "scope": {
                "artifact_reproducibility_only": True,
                "independent_execution_proven": True,
                "hardware_proof": False,
            },
            "source_tree_digest": source_tree_digest,
            "images": images or [],
        },
    )
    return {
        "policy_bundle": bundle_path,
        "policy_key": policy_key_path,
        "policy_identity": identity_path,
        "activation_report": activation[0],
        "activation_signature": activation[1],
        "activation_key": activation[2],
        "reproducibility_report": reproducibility[0],
        "reproducibility_signature": reproducibility[1],
        "reproducibility_key": reproducibility[2],
    }, policy_hash


def run(command: list[str], cwd: Path) -> None:
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)


def invoke(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "scripts/production_release_input_preflight.py", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")


def env_text(values: dict[str, str]) -> str:
    return "".join(f"{key}={shlex.quote(value)}\n" for key, value in sorted(values.items()))


def main() -> None:
    if (
        production_release_input_preflight.REPRODUCIBILITY_API_VERSION
        != "serverware.reproducibleBuildVerification/v3"
    ):
        raise AssertionError("production preflight is not using the canonical reproducibility v3 contract")

    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        repo = tmp / "repo"
        repo.mkdir()
        run(["git", "init", "-q"], repo)
        run(["git", "config", "user.email", "test@serverware.invalid"], repo)
        run(["git", "config", "user.name", "Serverware Test"], repo)
        env_file = repo / "production.env"
        valid_env = {
            key: value
            for key, value in test_production_readiness.good_env().items()
            if key.startswith("SERVERWARE_")
        }
        env_file.write_text(env_text(valid_env), encoding="utf-8")
        broker = repo / "broker.bin"
        broker.write_bytes(b"b" * 32)
        ca = repo / "ca.pem"
        ca.write_bytes(b"c" * 32)
        for private in (env_file, broker, ca):
            private.chmod(0o600)
        spec = repo / "kms-spec.json"
        spec.write_text(
            json.dumps(
                {
                    "broker-kek": {"key_id": "arn:aws:kms:us-east-1:111122223333:key/broker", "plaintext_path": str(broker)},
                    "decision-gate-ca": {"key_id": "arn:aws:kms:us-east-1:111122223333:key/ca", "plaintext_path": str(ca)},
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        run(["git", "add", "."], repo)
        run(["git", "commit", "-qm", "fixture"], repo)
        out = tmp / "preflight.json"
        security, _ = release_security_fixture(tmp)
        base_args = (
            "--repo-root",
            str(repo),
            "--env-file",
            str(env_file),
            "--kms-spec",
            str(spec),
            "--registry-prefix",
            "registry.serverware.test/team/serverware",
            "--deploy-command",
            "deploy-serverware --immutable",
            "--policy-bundle",
            str(security["policy_bundle"]),
            "--policy-trusted-public-key",
            str(security["policy_key"]),
            "--policy-identity-verification",
            str(security["policy_identity"]),
            "--policy-activation-verification",
            str(security["activation_report"]),
            "--policy-activation-signature",
            str(security["activation_signature"]),
            "--policy-activation-trusted-public-key",
            str(security["activation_key"]),
            "--reproducible-build-verification",
            str(security["reproducibility_report"]),
            "--reproducible-build-signature",
            str(security["reproducibility_signature"]),
            "--reproducible-build-trusted-public-key",
            str(security["reproducibility_key"]),
            "--out",
            str(out),
        )
        accepted = invoke(*base_args)
        if accepted.returncode != 0:
            raise AssertionError(f"valid unpatched reproducibility v3 inputs failed: {detail(accepted)}")
        evidence = json.loads(out.read_text(encoding="utf-8"))
        if evidence.get("ok") is not True or evidence.get("source", {}).get("clean") is not True:
            raise AssertionError(f"invalid accepted evidence: {evidence}")
        checks = evidence.get("inputs", {}).get("semantic_config_checks", [])
        if "check_internal_service_auth" not in checks:
            raise AssertionError(f"preflight omitted internal service authentication checks: {checks}")
        serialized = out.read_text(encoding="utf-8")
        if "deploy-serverware" in serialized or str(broker) in serialized or "111122223333" in serialized:
            raise AssertionError("preflight evidence exposed sensitive release input")

        legacy_reproducibility = json.loads(security["reproducibility_report"].read_text(encoding="utf-8"))
        legacy_reproducibility["apiVersion"] = "serverware.reproducibleBuildVerification/v1"
        signed_report(
            tmp,
            name="reproducible-build-verification",
            purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
            report=legacy_reproducibility,
        )
        rejected_legacy = invoke(*base_args)
        expected_legacy_error = "not a successful serverware.reproducibleBuildVerification/v3 artifact"
        if rejected_legacy.returncode == 0 or expected_legacy_error not in detail(rejected_legacy):
            raise AssertionError(f"legacy reproducibility v1 evidence was accepted: {detail(rejected_legacy)}")
        security, _ = release_security_fixture(tmp)

        forged_signature = json.loads(security["activation_signature"].read_text(encoding="utf-8"))
        forged_signature["artifactSha256"] = "sha256:" + "0" * 64
        security["activation_signature"].write_text(json.dumps(forged_signature), encoding="utf-8")
        rejected_forgery = invoke(*base_args)
        if rejected_forgery.returncode == 0 or "signature binding is invalid" not in detail(rejected_forgery):
            raise AssertionError(f"forged activation signature was accepted: {detail(rejected_forgery)}")
        security, _ = release_security_fixture(tmp)

        non_independent = json.loads(security["reproducibility_report"].read_text(encoding="utf-8"))
        non_independent["scope"]["independent_execution_proven"] = False
        signed_report(
            tmp,
            name="reproducible-build-verification",
            purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
            report=non_independent,
        )
        rejected_non_independent = invoke(*base_args)
        if rejected_non_independent.returncode == 0 or "two independent trusted builders" not in detail(
            rejected_non_independent
        ):
            raise AssertionError(f"non-independent reproducibility evidence was accepted: {detail(rejected_non_independent)}")
        security, _ = release_security_fixture(tmp)

        (repo / "dirty.txt").write_text("dirty", encoding="utf-8")
        dirty = invoke(*base_args)
        if dirty.returncode == 0 or "clean Git checkout" not in detail(dirty):
            raise AssertionError(f"dirty checkout was accepted: {detail(dirty)}")
        (repo / "dirty.txt").unlink()

        placeholder_env = dict(valid_env)
        placeholder_env["SERVERWARE_PUBLIC_URL"] = "https://serverware.example"
        env_file.write_text(env_text(placeholder_env), encoding="utf-8")
        placeholder = invoke(*base_args)
        if placeholder.returncode == 0 or "placeholder" not in detail(placeholder):
            raise AssertionError(f"placeholder environment was accepted: {detail(placeholder)}")
        run(["git", "checkout", "--", "production.env"], repo)
        env_file.chmod(0o600)

        broker.unlink()
        missing_material = invoke(*base_args)
        if missing_material.returncode == 0 or "plaintext_path is not a file" not in detail(missing_material):
            raise AssertionError(f"missing KMS plaintext was accepted: {detail(missing_material)}")
        run(["git", "checkout", "--", "broker.bin"], repo)
        broker.chmod(0o600)

        bad_registry = list(base_args)
        bad_registry[bad_registry.index("registry.serverware.test/team/serverware")] = "registry.example/team"
        rejected_registry = invoke(*bad_registry)
        if rejected_registry.returncode == 0 or "placeholder" not in detail(rejected_registry):
            raise AssertionError(f"placeholder registry was accepted: {detail(rejected_registry)}")

        noop = list(base_args)
        noop[noop.index("deploy-serverware --immutable")] = "true"
        rejected_noop = invoke(*noop)
        if rejected_noop.returncode == 0 or "no-op or placeholder" not in detail(rejected_noop):
            raise AssertionError(f"no-op deploy command was accepted: {detail(rejected_noop)}")

        env_file.chmod(0o644)
        public_env = invoke(*base_args)
        if public_env.returncode == 0 or "group/world accessible" not in detail(public_env):
            raise AssertionError(f"public production env was accepted: {detail(public_env)}")

    print(json.dumps({"ok": True, "production_release_input_preflight": "pass"}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
