#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import test_production_handoff  # noqa: E402
import test_production_release_input_preflight  # noqa: E402
import test_production_readiness  # noqa: E402
import generate_release_provenance  # noqa: E402
import production_host_preflight  # noqa: E402


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def write_env(path: Path, env: dict[str, str]) -> None:
    production_env = {key: value for key, value in env.items() if key.startswith("SERVERWARE_")}
    path.write_text("\n".join(f"{key}={shlex.quote(value)}" for key, value in sorted(production_env.items())) + "\n", encoding="utf-8")


def set_production_images(env: dict[str, str], images_env: Path) -> None:
    images = images_env.read_text(encoding="utf-8").split("=", 1)[1].strip().split(",")
    by_name = {image.rsplit("/", 1)[-1].split("@", 1)[0]: image for image in images}
    env["SERVERWARE_PRODUCTION_IMAGES"] = ",".join(images)
    env["SERVERWARE_CONTROL_PLANE_IMAGE"] = by_name["control"]
    env["SERVERWARE_DECISION_GATE_IMAGE"] = by_name["decision-gate"]


def set_release_artifacts(env: dict[str, str], paths: dict[str, Path]) -> None:
    env["SERVERWARE_RELEASE_PROVENANCE_FILE"] = str(paths["provenance"].resolve())
    env["SERVERWARE_IMAGE_SIGNATURES_FILE"] = str(paths["image_signatures"].resolve())


def write_kms_materials(path: Path, *, mode: int = 0o600) -> None:
    path.write_text(
        json.dumps(
            {
                "broker-kek": {
                    "key_id": "arn:aws:kms:us-east-1:111122223333:key/broker",
                    "ciphertext_blob_b64": base64.b64encode(b"broker-ciphertext").decode("ascii"),
                    "encryption_context": {"material": "broker-kek", "service": "serverware"},
                },
                "decision-gate-ca": {
                    "key_id": "arn:aws:kms:us-east-1:111122223333:key/ca",
                    "ciphertext_blob_b64": base64.b64encode(b"ca-ciphertext").decode("ascii"),
                    "encryption_context": {"material": "decision-gate-ca", "service": "serverware"},
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(mode)


def verify_runtime_trust_materials(tmp: Path) -> None:
    tls_dir = tmp / "tls"
    anchor_tls_dir = tmp / "anchor-tls"
    helper_dir = tmp / "helpers"
    tls_dir.mkdir()
    anchor_tls_dir.mkdir()
    helper_dir.mkdir()
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Serverware test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "serverware")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("serverware")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (tls_dir / "serverware.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    (tls_dir / "serverware.key").write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (tls_dir / "serverware.key").chmod(0o600)
    (tls_dir / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    anchor_key = ec.generate_private_key(ec.SECP256R1())
    anchor_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "audit-anchor")])
    anchor_cert = (
        x509.CertificateBuilder()
        .subject_name(anchor_name)
        .issuer_name(ca_name)
        .public_key(anchor_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("audit-anchor")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (anchor_tls_dir / "audit-anchor.crt").write_bytes(anchor_cert.public_bytes(serialization.Encoding.PEM))
    (anchor_tls_dir / "audit-anchor.key").write_bytes(
        anchor_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (anchor_tls_dir / "audit-anchor.key").chmod(0o600)
    for name in (
        "nsm-attest",
        "nsm-unseal",
        "lease-recipient-attest",
        "response-proof-attest",
        "lease-recipient-verify",
        "control-plane-attestation-verify",
        "serverware-proof-client",
    ):
        helper = helper_dir / name
        helper.write_bytes(b"test helper\n")
        helper.chmod(0o755)
    env = test_production_readiness.good_env()
    env["SERVERWARE_CONTROL_PLANE_TLS_DIR"] = str(tls_dir)
    env["SERVERWARE_AUDIT_ANCHOR_TLS_DIR"] = str(anchor_tls_dir)
    env["SERVERWARE_ATTESTATION_HELPER_DIR"] = str(helper_dir)
    proof_ca = tmp / "proxy-ca.pem"
    proof_ca.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    collector_private = Ed25519PrivateKey.generate()
    collector_private_path = tmp / "proof-collector.key.pem"
    collector_public_path = tmp / "proof-collector.pub.pem"
    verifier_public_path = tmp / "proxy-proof-verifier.pub.pem"
    collector_private_path.write_bytes(
        collector_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    collector_private_path.chmod(0o600)
    collector_public_der = collector_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    collector_public_path.write_bytes(
        collector_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    verifier_private = Ed25519PrivateKey.generate()
    verifier_public_der = verifier_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier_public_path.write_bytes(
        verifier_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    env["SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND"] = "/opt/serverware/bin/serverware-proof-client"
    env["SERVERWARE_PROXY_PROOF_CA_BUNDLE"] = str(proof_ca)
    env["SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY"] = str(collector_private_path)
    env["SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY"] = str(collector_public_path)
    env["SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY"] = str(verifier_public_path)
    env["SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID"] = sha256_prefixed(collector_public_der)
    env["SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID"] = sha256_prefixed(verifier_public_der)
    status, failures = production_host_preflight.runtime_trust_materials_check(env, skip_host_check=False)
    if failures or status.get("ok") is not True:
        raise AssertionError(f"valid runtime trust materials failed: {status} {failures}")
    if status.get("proof_collector_key_id") != env["SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID"]:
        raise AssertionError(f"response-proof collector key was not bound: {status}")
    mismatched_proof_env = {**env, "SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID": "sha256:" + "0" * 64}
    _, proof_key_failures = production_host_preflight.runtime_trust_materials_check(
        mismatched_proof_env,
        skip_host_check=False,
    )
    if not any("collector public key does not match" in failure for failure in proof_key_failures):
        raise AssertionError(f"mismatched response-proof collector key pin was accepted: {proof_key_failures}")
    collector_private_path.chmod(0o644)
    _, proof_mode_failures = production_host_preflight.runtime_trust_materials_check(env, skip_host_check=False)
    if not any("collector private key must not be readable" in failure for failure in proof_mode_failures):
        raise AssertionError(f"weak response-proof collector private-key mode was accepted: {proof_mode_failures}")
    collector_private_path.chmod(0o600)
    missing_san_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(ca_key, hashes.SHA256())
    )
    (tls_dir / "serverware.crt").write_bytes(missing_san_cert.public_bytes(serialization.Encoding.PEM))
    _, san_failures = production_host_preflight.runtime_trust_materials_check(env, skip_host_check=False)
    if not any("DNS SAN serverware" in failure for failure in san_failures):
        raise AssertionError(f"certificate without the internal DNS SAN was accepted: {san_failures}")
    (tls_dir / "serverware.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    (helper_dir / "lease-recipient-verify").chmod(0o777)
    _, weak_failures = production_host_preflight.runtime_trust_materials_check(env, skip_host_check=False)
    if not any("must not be writable" in failure for failure in weak_failures):
        raise AssertionError(f"writable attestation helper was accepted: {weak_failures}")


def run_preflight(paths: dict[str, Path], *extra: str, allow_test_bypass: bool = True) -> subprocess.CompletedProcess[bytes]:
    if "policy_bundle" not in paths:
        build = json.loads(paths["build"].read_text(encoding="utf-8"))
        reproduced_images = []
        for image in build["images"]:
            item = {"service": image["service"], "image_id": image["image_id"]}
            if image["service"] == "serverware-decision-gate":
                item["rust_binary_sha256"] = image["binary_digest"]
            reproduced_images.append(item)
        security, policy_hash = test_production_release_input_preflight.release_security_fixture(
            paths["build"].parent,
            source_tree_digest=build["metadata"]["source_tree_digest"],
            images=reproduced_images,
        )
        paths.update(security)
        bench = json.loads(paths["bench"].read_text(encoding="utf-8"))
        bench["policy_hash"] = policy_hash
        paths["bench"].write_text(json.dumps(bench, sort_keys=True) + "\n", encoding="utf-8")
    env = os.environ.copy()
    if allow_test_bypass:
        env["SERVERWARE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "scripts/production_host_preflight.py",
            "--skip-host-check",
            "--env-file",
            str(paths["env"]),
            "--production-images-env",
            str(paths["images_env"]),
            "--production-images-published",
            str(paths["published"]),
            "--production-images-build",
            str(paths["build"]),
            "--release-provenance-summary",
            str(paths["provenance_summary"]),
            "--release-provenance",
            str(paths["provenance"]),
            "--image-signatures-summary",
            str(paths["image_signatures_summary"]),
            "--image-signatures",
            str(paths["image_signatures"]),
            "--bench",
            str(paths["bench"]),
            "--policy-bundle",
            str(paths["policy_bundle"]),
            "--policy-trusted-public-key",
            str(paths["policy_key"]),
            "--policy-identity-verification",
            str(paths["policy_identity"]),
            "--policy-activation-verification",
            str(paths["activation_report"]),
            "--policy-activation-signature",
            str(paths["activation_signature"]),
            "--policy-activation-trusted-public-key",
            str(paths["activation_key"]),
            "--reproducible-build-verification",
            str(paths["reproducibility_report"]),
            "--reproducible-build-signature",
            str(paths["reproducibility_signature"]),
            "--reproducible-build-trusted-public-key",
            str(paths["reproducibility_key"]),
            "--kms-materials",
            str(paths["kms_materials"]),
            "--config-out",
            str(paths["build"].parent / "preflight-config.json"),
            "--out",
            str(paths["build"].parent / "preflight.json"),
            *extra,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def verify_oauth_secret_mounts(tmp: Path) -> None:
    google = tmp / "google-oauth-secret"
    x_secret = tmp / "x-oauth-secret"
    google.write_text("google-secret-0123456789", encoding="utf-8")
    x_secret.write_text("x-secret-0123456789", encoding="utf-8")
    google.chmod(0o600)
    x_secret.chmod(0o400)
    env = {
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": str(google),
        "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE": str(x_secret),
    }
    original_uid = production_host_preflight.CONTROL_PLANE_RUNTIME_UID
    if original_uid != 65532:
        raise AssertionError(f"production control-plane UID drifted: {original_uid}")
    try:
        production_host_preflight.CONTROL_PLANE_RUNTIME_UID = os.getuid()
        status, failures = production_host_preflight.oauth_secret_mounts_check(
            env,
            skip_host_check=False,
        )
        if failures or status.get("ok") is not True:
            raise AssertionError(f"readable OAuth secret mounts failed: {status} {failures}")
        production_host_preflight.CONTROL_PLANE_RUNTIME_UID = os.getuid() + 1
        _, owner_failures = production_host_preflight.oauth_secret_mounts_check(
            env,
            skip_host_check=False,
        )
        if not any("must be owned by UID" in failure for failure in owner_failures):
            raise AssertionError(f"unreadable OAuth secret ownership was accepted: {owner_failures}")
    finally:
        production_host_preflight.CONTROL_PLANE_RUNTIME_UID = original_uid


def main() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    run_target = makefile.split("run-production-readiness:", 1)[1].split("\n\n", 1)[0]
    if "production-host-preflight" not in run_target:
        raise AssertionError("make run-production-readiness does not enforce production-host-preflight first")

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_runtime_trust_materials(Path(tmp_raw))

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_oauth_secret_mounts(Path(tmp_raw))

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = test_production_readiness.good_env()
        set_release_artifacts(env, paths)
        set_production_images(env, paths["images_env"])
        write_env(paths["env"], env)
        write_kms_materials(paths["kms_materials"])
        source_digest = json.loads(paths["build"].read_text(encoding="utf-8"))["metadata"]["source_tree_digest"]
        production_images = generate_release_provenance.production_image_inventory(
            build_path=paths["build"],
            published_path=paths["published"],
            images_env_path=paths["images_env"],
            expected_source_tree_digest=source_digest,
        )
        _, compose_summary = generate_release_provenance.production_compose_model(
            compose_file=ROOT / "docker-compose.production.yml",
            env_file=paths["env"],
            images=production_images,
        )
        if set(compose_summary.get("images", {}).values()) != {
            env["SERVERWARE_CONTROL_PLANE_IMAGE"],
            env["SERVERWARE_DECISION_GATE_IMAGE"],
        }:
            raise AssertionError(f"production Compose proof did not bind immutable images: {compose_summary}")
        expected_images = generate_release_provenance.merge_production_images_env.validate_production_images(
            env["SERVERWARE_PRODUCTION_IMAGES"]
        )
        compose_status, compose_failures = production_host_preflight.production_compose_check(
            compose_file=ROOT / "docker-compose.production.yml",
            env_file=paths["env"],
            expected_images=expected_images,
            expected_digest=compose_summary["sha256"],
            skip_host_check=False,
        )
        if compose_failures or compose_status.get("ok") is not True:
            raise AssertionError(f"valid production Compose proof failed: {compose_status} {compose_failures}")
        _, mismatch_failures = production_host_preflight.production_compose_check(
            compose_file=ROOT / "docker-compose.production.yml",
            env_file=paths["env"],
            expected_images=expected_images,
            expected_digest="sha256:" + "0" * 64,
            skip_host_check=False,
        )
        if not any("does not match signed release provenance" in failure for failure in mismatch_failures):
            raise AssertionError(f"production Compose digest mismatch was accepted: {mismatch_failures}")
        rejected_bypass = run_preflight(paths, allow_test_bypass=False)
        if rejected_bypass.returncode == 0 or "test-only" not in detail(rejected_bypass):
            raise AssertionError(f"preflight accepted a bypass flag without test-only opt-in: {detail(rejected_bypass)}")

        result = run_preflight(paths)
        if result.returncode != 0:
            raise AssertionError(f"preflight failed: {detail(result)}")
        output = json.loads(result.stdout.decode("utf-8"))
        if output.get("ok") is not True:
            raise AssertionError(f"preflight did not return ok: {output}")
        if "prod-admin-token-32-bytes-minimum-value" in detail(result):
            raise AssertionError("preflight leaked env secrets")
        if output.get("checks", {}).get("release_artifacts", {}).get("image_signatures", {}).get("covers_published_production_images") is not True:
            raise AssertionError(f"preflight did not check published image signature coverage: {output}")
        if output.get("checks", {}).get("release_artifacts", {}).get("production_images_published", {}).get("ok") is not True:
            raise AssertionError(f"preflight did not validate published image provenance: {output}")
        if output.get("checks", {}).get("release_artifacts", {}).get("bench", {}).get("p99_ms") != 6.0:
            raise AssertionError(f"preflight did not include benchmark evidence: {output}")
        production_env_file = output.get("checks", {}).get("production_env", {}).get("file", {})
        if production_env_file.get("sha256") != sha256_prefixed(paths["env"].read_bytes()):
            raise AssertionError(f"preflight did not bind production env file digest: {output}")
        config_gate = output.get("checks", {}).get("production_env", {}).get("config_gate", {})
        config_file = config_gate.get("file", {})
        if config_gate.get("result_sha256") != config_file.get("sha256"):
            raise AssertionError(f"preflight did not bind config gate result digest to its artifact: {output}")
        if not str(config_gate.get("semantic_sha256", "")).startswith("sha256:"):
            raise AssertionError(f"preflight did not record config gate semantic digest: {output}")
        images_env_file = output.get("checks", {}).get("production_images_env", {}).get("file", {})
        if images_env_file.get("sha256") != sha256_prefixed(paths["images_env"].read_bytes()):
            raise AssertionError(f"preflight did not bind production images env file digest: {output}")
        materials = {
            item.get("material"): item
            for item in output.get("checks", {}).get("kms_materials", {}).get("materials", [])
            if isinstance(item, dict)
        }
        if materials.get("broker-kek", {}).get("ciphertext_blob_sha256") != sha256_prefixed(b"broker-ciphertext"):
            raise AssertionError(f"preflight did not bind broker-kek ciphertext digest: {output}")
        if materials.get("decision-gate-ca", {}).get("ciphertext_blob_sha256") != sha256_prefixed(b"ca-ciphertext"):
            raise AssertionError(f"preflight did not bind decision-gate-ca ciphertext digest: {output}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = test_production_readiness.good_env()
        set_release_artifacts(env, paths)
        set_production_images(env, paths["images_env"])
        write_env(paths["env"], env)
        write_kms_materials(paths["kms_materials"], mode=0o644)
        rejected = run_preflight(paths)
        if rejected.returncode == 0 or "KMS materials file must not be readable" not in detail(rejected):
            raise AssertionError(f"preflight accepted weak KMS material permissions: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = test_production_readiness.good_env()
        set_release_artifacts(env, paths)
        set_production_images(env, paths["images_env"])
        write_env(paths["env"], env)
        write_kms_materials(paths["kms_materials"])
        materials = json.loads(paths["kms_materials"].read_text(encoding="utf-8"))
        materials["broker-kek"]["ciphertext_blob_b64"] = "not-valid-@@@@"
        paths["kms_materials"].write_text(json.dumps(materials, sort_keys=True) + "\n", encoding="utf-8")
        paths["kms_materials"].chmod(0o600)
        rejected = run_preflight(paths)
        if rejected.returncode == 0 or "ciphertext blob is invalid base64" not in detail(rejected):
            raise AssertionError(f"preflight accepted malformed KMS ciphertext base64: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = test_production_readiness.good_env()
        set_release_artifacts(env, paths)
        set_production_images(env, paths["images_env"])
        write_env(paths["env"], env)
        write_kms_materials(paths["kms_materials"])
        materials = json.loads(paths["kms_materials"].read_text(encoding="utf-8"))
        materials["debug-material"] = {
            "key_id": "arn:aws:kms:us-east-1:111122223333:key/debug",
            "ciphertext_blob_b64": base64.b64encode(b"debug-ciphertext").decode("ascii"),
            "encryption_context": {"material": "debug-material", "service": "serverware"},
        }
        paths["kms_materials"].write_text(json.dumps(materials, sort_keys=True) + "\n", encoding="utf-8")
        paths["kms_materials"].chmod(0o600)
        rejected = run_preflight(paths)
        if rejected.returncode == 0 or "unauthorized materials" not in detail(rejected):
            raise AssertionError(f"preflight accepted unauthorized KMS materials: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = test_production_readiness.good_env()
        set_release_artifacts(env, paths)
        env["SERVERWARE_PRODUCTION_IMAGES"] = "registry.prod.serverware.dev/serverware/control@sha256:" + "c" * 64
        write_env(paths["env"], env)
        write_kms_materials(paths["kms_materials"])
        rejected = run_preflight(paths)
        if rejected.returncode == 0 or "does not match .tmp/production-images.env" not in detail(rejected):
            raise AssertionError(f"preflight accepted env/image fragment mismatch: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = test_production_readiness.good_env()
        set_release_artifacts(env, paths)
        set_production_images(env, paths["images_env"])
        write_env(paths["env"], env)
        paths["images_env"].unlink()
        write_kms_materials(paths["kms_materials"])
        rejected = run_preflight(paths)
        if rejected.returncode == 0 or "production images env is missing" not in detail(rejected):
            raise AssertionError(f"preflight accepted missing production images env: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = test_production_readiness.good_env()
        set_release_artifacts(env, paths)
        set_production_images(env, paths["images_env"])
        write_env(paths["env"], env)
        write_kms_materials(paths["kms_materials"])
        published = json.loads(paths["published"].read_text(encoding="utf-8"))
        published["images"][0]["local_image_id"] = "sha256:" + "9" * 64
        paths["published"].write_text(json.dumps(published, sort_keys=True) + "\n", encoding="utf-8")
        rejected = run_preflight(paths)
        if rejected.returncode == 0 or "published production images do not match current no-shell build" not in detail(rejected):
            raise AssertionError(f"preflight accepted a published image artifact from a different build: {detail(rejected)}")

    print(json.dumps({"ok": True, "production_host_preflight": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
