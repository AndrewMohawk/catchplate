#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import shlex
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

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
import run_production_readiness  # noqa: E402
import verify_production_policy_identity  # noqa: E402


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def public_key_spki_id(path: Path) -> str:
    public_key = serialization.load_pem_public_key(path.read_bytes())
    return sha256_prefixed(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def write_env(path: Path, env: dict[str, str]) -> None:
    production_env = {key: value for key, value in env.items() if key.startswith("SERVERWARE_")}
    path.write_text("\n".join(f"{key}={shlex.quote(value)}" for key, value in sorted(production_env.items())) + "\n", encoding="utf-8")
    path.chmod(0o600)


def set_production_images(env: dict[str, str], images_env: Path) -> None:
    images = images_env.read_text(encoding="utf-8").split("=", 1)[1].strip().split(",")
    by_name = {image.rsplit("/", 1)[-1].split("@", 1)[0]: image for image in images}
    env["SERVERWARE_PRODUCTION_IMAGES"] = ",".join(images)
    env["SERVERWARE_CONTROL_PLANE_IMAGE"] = by_name["control"]
    env["SERVERWARE_DECISION_GATE_IMAGE"] = by_name["decision-gate"]


def set_release_artifacts(env: dict[str, str], paths: dict[str, Path]) -> None:
    env["SERVERWARE_RELEASE_PROVENANCE_FILE"] = str(paths["provenance"].resolve())
    env["SERVERWARE_IMAGE_SIGNATURES_FILE"] = str(paths["image_signatures"].resolve())


def fixture_release_env(paths: dict[str, Path]) -> dict[str, str]:
    env = test_production_readiness.good_env()
    env.update(test_production_handoff.fixture_release_trust_env(paths))
    fixture_dir = paths["build"].parent.resolve()
    production_python_path = fixture_dir / "production-python"
    production_python_path.write_bytes(Path(sys.executable).resolve().read_bytes())
    production_python_path.chmod(0o700)
    docker_source = shutil.which("docker")
    if docker_source is None:
        raise AssertionError("Docker is required for the production preflight fixture")
    production_docker_path = fixture_dir / "production-docker"
    production_docker_path.write_bytes(Path(docker_source).resolve().read_bytes())
    production_docker_path.chmod(0o700)
    production_python = str(production_python_path)
    production_python_digest = sha256_prefixed(production_python_path.read_bytes())
    production_docker_digest = sha256_prefixed(production_docker_path.read_bytes())
    plugin_inventory = json.loads(
        subprocess.run(
            [docker_source, "info", "--format", "{{json .ClientInfo.Plugins}}"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout
    )
    compose_plugin_source = Path(
        next(item["Path"] for item in plugin_inventory if item.get("Name") == "compose")
    ).resolve()
    compose_plugin_path = fixture_dir / "production-docker-compose"
    compose_plugin_path.write_bytes(compose_plugin_source.read_bytes())
    compose_plugin_path.chmod(0o700)
    docker_host = subprocess.run(
        [docker_source, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if not docker_host.startswith("unix://"):
        raise AssertionError(f"Docker fixture requires a local Unix endpoint: {docker_host}")
    docker_daemon_id = subprocess.run(
        [docker_source, "info", "--format", "{{.ID}}"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    env[production_host_preflight.PRODUCTION_PYTHON_EXECUTABLE_SETTING] = production_python
    env[production_host_preflight.PRODUCTION_DOCKER_EXECUTABLE_SETTING] = str(production_docker_path)
    env[run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV] = str(compose_plugin_path)
    env[run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV] = sha256_prefixed(
        compose_plugin_path.read_bytes()
    )
    env[run_production_readiness.DOCKER_UNIX_SOCKET_ENV] = docker_host.removeprefix("unix://")
    env[run_production_readiness.DOCKER_DAEMON_ID_ENV] = docker_daemon_id
    env[run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV] = (
        "serverware-production"
    )
    env[production_host_preflight.ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV] = json.dumps(
        {
            setting: production_python_digest
            if setting == production_host_preflight.PRODUCTION_PYTHON_EXECUTABLE_SETTING
            else production_docker_digest
            if setting == production_host_preflight.PRODUCTION_DOCKER_EXECUTABLE_SETTING
            else "sha256:" + "0" * 64
            for setting in production_host_preflight.PINNED_EXECUTABLE_COMMAND_SETTINGS
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return env


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
    tmp = tmp.resolve()
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
    production_python = tmp / "production-python"
    production_python.write_bytes(Path(sys.executable).resolve().read_bytes())
    production_python.chmod(0o755)
    production_docker = tmp / "production-docker"
    production_docker.write_bytes(b"#!/bin/sh\nexit 0\n")
    production_docker.chmod(0o755)
    env[production_host_preflight.PRODUCTION_PYTHON_EXECUTABLE_SETTING] = str(
        production_python
    )
    env[production_host_preflight.PRODUCTION_DOCKER_EXECUTABLE_SETTING] = str(
        production_docker
    )
    executable_digest_manifest = {}
    for setting in sorted(
        production_host_preflight.PINNED_EXECUTABLE_COMMAND_SETTINGS
    ):
        words = shlex.split(env[setting])
        executable_path = (
            Path(words[0])
            if setting
            in {
                production_host_preflight.PRODUCTION_PYTHON_EXECUTABLE_SETTING,
                production_host_preflight.PRODUCTION_DOCKER_EXECUTABLE_SETTING,
            }
            else helper_dir / Path(words[0]).name
        )
        executable_digest_manifest[setting] = sha256_prefixed(
            executable_path.read_bytes()
        )
    env[
        production_host_preflight.ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV
    ] = json.dumps(executable_digest_manifest, sort_keys=True, separators=(",", ":"))
    status, failures = production_host_preflight.runtime_trust_materials_check(env, skip_host_check=False)
    if failures or status.get("ok") is not True:
        raise AssertionError(f"valid runtime trust materials failed: {status} {failures}")
    if status.get("proof_collector_key_id") != env["SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID"]:
        raise AssertionError(f"response-proof collector key was not bound: {status}")
    executable_digests = status.get("executable_digests") or []
    if (
        len(executable_digests)
        != len(production_host_preflight.PINNED_EXECUTABLE_COMMAND_SETTINGS)
        or not all(item.get("verified") is True for item in executable_digests)
    ):
        raise AssertionError(f"preflight did not report every verified executable digest: {status}")
    docker_report = next(
        item
        for item in executable_digests
        if item["setting"] == production_host_preflight.PRODUCTION_DOCKER_EXECUTABLE_SETTING
    )
    if docker_report.get("host_path") != str(production_docker):
        raise AssertionError(
            f"Docker absolute path was incorrectly constrained to the helper directory: {docker_report}"
        )

    missing_manifest = dict(executable_digest_manifest)
    missing_manifest.pop("SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE")
    missing_manifest_env = {
        **env,
        production_host_preflight.ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV: json.dumps(
            missing_manifest, sort_keys=True, separators=(",", ":")
        ),
    }
    _, missing_manifest_failures = production_host_preflight.runtime_trust_materials_check(
        missing_manifest_env,
        skip_host_check=False,
    )
    if not any("is missing entries" in failure for failure in missing_manifest_failures):
        raise AssertionError(f"incomplete executable digest manifest was accepted: {missing_manifest_failures}")

    extra_manifest_env = {
        **env,
        production_host_preflight.ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV: json.dumps(
            {**executable_digest_manifest, "SERVERWARE_UNEXPECTED_HELPER_COMMAND": sha256_prefixed(b"extra")},
            sort_keys=True,
            separators=(",", ":"),
        ),
    }
    _, extra_manifest_failures = production_host_preflight.runtime_trust_materials_check(
        extra_manifest_env,
        skip_host_check=False,
    )
    if not any("contains extra entries" in failure for failure in extra_manifest_failures):
        raise AssertionError(f"open executable digest manifest was accepted: {extra_manifest_failures}")

    invalid_manifest = dict(executable_digest_manifest)
    invalid_manifest["SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE"] = "sha256:INVALID"
    invalid_manifest_env = {
        **env,
        production_host_preflight.ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV: json.dumps(
            invalid_manifest, sort_keys=True, separators=(",", ":")
        ),
    }
    _, invalid_manifest_failures = production_host_preflight.runtime_trust_materials_check(
        invalid_manifest_env,
        skip_host_check=False,
    )
    if not any("64 lowercase hex" in failure for failure in invalid_manifest_failures):
        raise AssertionError(f"invalid executable digest manifest was accepted: {invalid_manifest_failures}")

    changed_helper = helper_dir / "lease-recipient-verify"
    original_helper_bytes = changed_helper.read_bytes()
    changed_helper.write_bytes(b"changed helper bytes\n")
    changed_helper.chmod(0o755)
    _, changed_helper_failures = production_host_preflight.runtime_trust_materials_check(
        env,
        skip_host_check=False,
    )
    if not any("attestation helper SHA-256 does not match" in failure for failure in changed_helper_failures):
        raise AssertionError(f"changed attestation helper bytes were accepted: {changed_helper_failures}")
    changed_helper.write_bytes(original_helper_bytes)
    changed_helper.chmod(0o755)

    changed_collector = helper_dir / "serverware-proof-client"
    original_collector_bytes = changed_collector.read_bytes()
    changed_collector.write_bytes(b"changed collector bytes\n")
    changed_collector.chmod(0o755)
    _, changed_collector_failures = production_host_preflight.runtime_trust_materials_check(
        env,
        skip_host_check=False,
    )
    if not any("response-proof collector SHA-256 does not match" in failure for failure in changed_collector_failures):
        raise AssertionError(f"changed response-proof collector bytes were accepted: {changed_collector_failures}")
    changed_collector.write_bytes(original_collector_bytes)
    changed_collector.chmod(0o755)

    original_python_bytes = production_python.read_bytes()
    production_python.write_bytes(b"changed python bytes\n")
    production_python.chmod(0o755)
    _, changed_python_failures = production_host_preflight.runtime_trust_materials_check(
        env,
        skip_host_check=False,
    )
    if not any("production Python executable SHA-256 does not match" in failure for failure in changed_python_failures):
        raise AssertionError(f"changed production Python bytes were accepted: {changed_python_failures}")
    production_python.write_bytes(original_python_bytes)
    production_python.chmod(0o755)

    original_docker_bytes = production_docker.read_bytes()
    production_docker.write_bytes(b"#!/bin/sh\nexit 8\n")
    production_docker.chmod(0o755)
    _, changed_docker_failures = production_host_preflight.runtime_trust_materials_check(
        env,
        skip_host_check=False,
    )
    if not any("Docker executable SHA-256 does not match" in failure for failure in changed_docker_failures):
        raise AssertionError(f"changed Docker bytes were accepted: {changed_docker_failures}")
    production_docker.write_bytes(original_docker_bytes)
    production_docker.chmod(0o755)

    helper_dir.chmod(0o777)
    _, writable_directory_failures = production_host_preflight.runtime_trust_materials_check(
        env,
        skip_host_check=False,
    )
    if not any("helper directory must not be writable" in failure for failure in writable_directory_failures):
        raise AssertionError(f"writable helper directory was accepted: {writable_directory_failures}")
    helper_dir.chmod(0o755)

    symlink_helper_dir = tmp / "helpers-link"
    symlink_helper_dir.symlink_to(helper_dir, target_is_directory=True)
    _, symlink_directory_failures = production_host_preflight.runtime_trust_materials_check(
        {**env, "SERVERWARE_ATTESTATION_HELPER_DIR": str(symlink_helper_dir)},
        skip_host_check=False,
    )
    if not any("non-symlink directories" in failure for failure in symlink_directory_failures):
        raise AssertionError(f"symlink helper directory was accepted: {symlink_directory_failures}")

    mismatched_proof_env = {**env, "SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID": "sha256:" + "0" * 64}
    _, proof_key_failures = production_host_preflight.runtime_trust_materials_check(
        mismatched_proof_env,
        skip_host_check=False,
    )
    if not any("collector public key does not match" in failure for failure in proof_key_failures):
        raise AssertionError(f"mismatched response-proof collector key pin was accepted: {proof_key_failures}")
    collector_private_path.chmod(0o644)
    _, proof_mode_failures = production_host_preflight.runtime_trust_materials_check(env, skip_host_check=False)
    if not any("collector private key must not grant group/world access" in failure for failure in proof_mode_failures):
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
    original_ca = tls_dir / "ca.pem"
    replacement_ca = tls_dir / "ca-real.pem"
    original_ca.replace(replacement_ca)
    original_ca.symlink_to(replacement_ca)
    _, symlink_ca_failures = production_host_preflight.runtime_trust_materials_check(
        env,
        skip_host_check=False,
    )
    if not any("could not be opened without following symlinks" in failure for failure in symlink_ca_failures):
        raise AssertionError(f"symlinked TLS CA bundle was accepted: {symlink_ca_failures}")
    original_ca.unlink()
    replacement_ca.replace(original_ca)
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
        security, _ = test_production_release_input_preflight.release_security_fixture(
            paths["build"].parent,
            source_tree_digest=build["metadata"]["source_tree_digest"],
            images=reproduced_images,
        )
        paths.update(security)
        identity = verify_production_policy_identity.verify_persisted_report(
            bundle_path=paths["policy_bundle"],
            trusted_public_key_path=paths["policy_key"],
            report_path=paths["policy_identity"],
        )
        policy_hash = identity.get("policyHash")
        if not isinstance(policy_hash, str) or not policy_hash.startswith("sha256:"):
            raise AssertionError(f"identity verification did not return a policy hash: {identity}")
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
            "--expected-control-plane-uid",
            str(os.getuid()),
            "--expected-control-plane-gid",
            str(os.getgid()),
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
    tmp = tmp.resolve()
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


def verify_docker_binding_helpers() -> None:
    try:
        run_production_readiness.validate_docker_unix_socket(Path("/var/run/docker.sock"))
    except ValueError as exc:
        if "exactly /run/docker.sock" not in str(exc):
            raise
    else:
        raise AssertionError("symlink-prone /var/run Docker socket path was accepted")

    try:
        run_production_readiness.require_root_owned_docker_socket_ancestor(
            SimpleNamespace(st_uid=12345, st_mode=stat.S_IFDIR | 0o755),
            Path("/run"),
        )
    except ValueError as exc:
        if "owned by UID 0" not in str(exc):
            raise
    else:
        raise AssertionError("user-owned Docker socket ancestor was accepted")

    for metadata, expected_error in (
        (
            SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755),
            "non-symlink directory",
        ),
        (
            SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o775),
            "must not be writable by group/other",
        ),
    ):
        try:
            run_production_readiness.require_root_owned_docker_socket_ancestor(
                metadata,
                Path("/"),
            )
        except ValueError as exc:
            if expected_error not in str(exc):
                raise
        else:
            raise AssertionError(
                f"unsafe Docker socket root ancestor was accepted: {metadata}"
            )

    before = {
        "daemon_id": "daemon-a",
        "socket": {"path": "/run/docker.sock", "device": 1, "inode": 10},
    }
    after = {
        "daemon_id": "daemon-a",
        "socket": {"path": "/run/docker.sock", "device": 1, "inode": 11},
    }
    try:
        run_production_readiness.require_stable_docker_daemon_binding(before, after)
    except ValueError as exc:
        if "changed during runtime inspection" not in str(exc):
            raise
    else:
        raise AssertionError("Docker socket replacement during inspection was accepted")

    original_socket_validation = run_production_readiness.validate_docker_unix_socket
    original_run = run_production_readiness.run_measured_command
    run_production_readiness.validate_docker_unix_socket = lambda _path: {
        "path": "/run/docker.sock",
        "device": 1,
        "inode": 10,
    }
    run_production_readiness.run_measured_command = lambda *_args, **_kwargs: subprocess.CompletedProcess(
        _args[0] if _args else [],
        0,
        stdout="wrong-daemon\n",
        stderr="",
    )
    try:
        try:
            run_production_readiness.verify_docker_daemon_identity(
                docker_executable=Path("/usr/bin/docker"),
                docker_sha256="sha256:" + "0" * 64,
                socket_path=Path("/run/docker.sock"),
                expected_daemon_id="expected-daemon",
                base_env={},
            )
        except ValueError as exc:
            if "daemon ID" not in str(exc):
                raise
        else:
            raise AssertionError("wrong Docker daemon identity was accepted")
    finally:
        run_production_readiness.validate_docker_unix_socket = original_socket_validation
        run_production_readiness.run_measured_command = original_run


def verify_preflight_script_descriptor_race(tmp: Path) -> None:
    if not sys.platform.startswith("linux"):
        return
    measured_script = tmp / "production_host_preflight.py"
    replacement_script = tmp / "replacement-production_host_preflight.py"
    measured_script.write_text("print('measured-preflight-bytes')\n", encoding="ascii")
    replacement_script.write_text("print('replacement-preflight-bytes')\n", encoding="ascii")
    expected_digest = sha256_prefixed(measured_script.read_bytes())

    def replace_after_open(_measured: run_production_readiness.MeasuredScript) -> None:
        os.replace(replacement_script, measured_script)

    python_path = Path(sys.executable).resolve()
    result = run_production_readiness.run_measured_python_script(
        [str(python_path), str(measured_script)],
        python_setting=run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV,
        python_expected_digest=sha256_prefixed(python_path.read_bytes()),
        script_setting=(
            run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV
        ),
        script_expected_digest=expected_digest,
        after_script_open=replace_after_open,
        cwd=ROOT,
        env=dict(run_production_readiness.FINAL_CHILD_FIXED_ENV),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if result.returncode != 0 or result.stdout != "measured-preflight-bytes\n":
        raise AssertionError(
            "production host preflight execution reopened pathname replacement bytes: "
            f"returncode={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def verify_launcher_authentication_precedes_env_parse(tmp: Path) -> None:
    env_path = tmp / "production-readiness.env"
    env_path.write_text(
        "SERVERWARE_COMPLETION_VERIFICATION_MODE=final\n",
        encoding="ascii",
    )
    env_path.chmod(0o600)
    parser_reached = False
    original_loader = run_production_readiness.load_env_bytes

    def record_parse(_data: bytes, _path: Path) -> dict[str, str]:
        nonlocal parser_reached
        parser_reached = True
        return {"SERVERWARE_COMPLETION_VERIFICATION_MODE": "final"}

    run_production_readiness.load_env_bytes = record_parse
    try:
        try:
            production_host_preflight.reexec_final_preflight_from_measured_descriptors(
                SimpleNamespace(
                    env_file=str(env_path),
                    launcher_trusted_production_env_path=str(env_path),
                    launcher_trusted_production_env_sha256="sha256:" + "0" * 64,
                    skip_host_check=False,
                )
            )
        except ValueError as exc:
            if "out-of-band launcher trust digest" not in str(exc):
                raise
        else:
            raise AssertionError("preflight accepted an unauthenticated production env")
    finally:
        run_production_readiness.load_env_bytes = original_loader
    if parser_reached:
        raise AssertionError(
            "production host preflight parsed env bytes before launcher authentication"
        )


def main() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    run_target = makefile.split("run-production-readiness:", 1)[1].split("\n\n", 1)[0]
    if "production-host-preflight" not in run_target:
        raise AssertionError("make run-production-readiness does not enforce production-host-preflight first")

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_runtime_trust_materials(Path(tmp_raw))

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_oauth_secret_mounts(Path(tmp_raw))

    verify_docker_binding_helpers()

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_preflight_script_descriptor_race(Path(tmp_raw).resolve())

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_launcher_authentication_precedes_env_parse(Path(tmp_raw).resolve())

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = fixture_release_env(paths)
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
        measured_commands: list[list[str]] = []
        original_measured_command = run_production_readiness.run_measured_command

        def recording_measured_command(
            argv: list[str],
            **kwargs: object,
        ) -> subprocess.CompletedProcess[object]:
            measured_commands.append(list(argv))
            return original_measured_command(argv, **kwargs)

        run_production_readiness.run_measured_command = recording_measured_command
        try:
            compose_status, compose_failures = production_host_preflight.production_compose_check(
                compose_file=ROOT / "docker-compose.production.yml",
                env_file=paths["env"],
                expected_images=expected_images,
                expected_digest=compose_summary["sha256"],
                skip_host_check=False,
            )
        finally:
            run_production_readiness.run_measured_command = original_measured_command
        if compose_failures or compose_status.get("ok") is not True:
            raise AssertionError(f"valid production Compose proof failed: {compose_status} {compose_failures}")
        expected_plugin = env[run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV]
        if (
            compose_status.get("compose_plugin_executable") != expected_plugin
            or compose_status.get("compose_plugin_sha256")
            != env[run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV]
        ):
            raise AssertionError(
                f"production preflight did not retain the exact Compose renderer binding: {compose_status}"
            )
        runtime_model = compose_status.get("runtime_model")
        if (
            compose_status.get("compose_project_name")
            != env[run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV]
            or not isinstance(runtime_model, dict)
            or runtime_model.get("sha256")
            != compose_status.get("runtime_model_sha256")
            or set(runtime_model.get("services") or {})
            != set(run_production_readiness.FINAL_SERVICE_USERS)
            or (runtime_model["services"]["serverware"]).get("compose_user")
            != "65532:65532"
        ):
            raise AssertionError(
                f"production preflight did not bind the closed normalized runtime model: {compose_status}"
            )
        if (
            not measured_commands
            or any(command[0] != expected_plugin for command in measured_commands)
            or any(command[1:3] != ["--host", f"unix://{env[run_production_readiness.DOCKER_UNIX_SOCKET_ENV]}"] for command in measured_commands)
            or any(len(command) > 1 and command[0].endswith("docker") and command[1] == "compose" for command in measured_commands)
        ):
            raise AssertionError(
                f"final Compose proof path did not directly execute the measured plugin: {measured_commands}"
            )
        _, mismatch_failures = production_host_preflight.production_compose_check(
            compose_file=ROOT / "docker-compose.production.yml",
            env_file=paths["env"],
            expected_images=expected_images,
            expected_digest="sha256:" + "0" * 64,
            skip_host_check=False,
        )
        if not any("does not match signed release provenance" in failure for failure in mismatch_failures):
            raise AssertionError(f"production Compose digest mismatch was accepted: {mismatch_failures}")
        compose_plugin = Path(expected_plugin)
        original_plugin_bytes = compose_plugin.read_bytes()
        compose_plugin.write_bytes(b"replaced Compose plugin bytes\n")
        compose_plugin.chmod(0o700)
        _, replaced_plugin_failures = production_host_preflight.production_compose_check(
            compose_file=ROOT / "docker-compose.production.yml",
            env_file=paths["env"],
            expected_images=expected_images,
            expected_digest=compose_summary["sha256"],
            skip_host_check=False,
        )
        if not any("executable pin" in failure for failure in replaced_plugin_failures):
            raise AssertionError(
                f"replaced/shadowed Compose plugin bytes were accepted: {replaced_plugin_failures}"
            )
        compose_plugin.write_bytes(original_plugin_bytes)
        compose_plugin.chmod(0o700)
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

        final_security_env = {
            **env,
            "SERVERWARE_COMPLETION_VERIFICATION_MODE": "final",
            run_production_readiness.POLICY_TRUST_ROOT_ENV: str(paths["policy_key"]),
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV: public_key_spki_id(
                paths["policy_key"]
            ),
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV: str(
                paths["activation_key"]
            ),
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV: public_key_spki_id(
                paths["activation_key"]
            ),
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV: str(
                paths["reproducibility_key"]
            ),
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV: public_key_spki_id(
                paths["reproducibility_key"]
            ),
        }
        security_args = SimpleNamespace(
            policy_bundle=str(paths["policy_bundle"]),
            policy_trusted_public_key=str(paths["policy_key"]),
            policy_trusted_public_key_id=final_security_env[
                run_production_readiness.POLICY_TRUST_ROOT_ID_ENV
            ],
            policy_identity_verification=str(paths["policy_identity"]),
            policy_activation_verification=str(paths["activation_report"]),
            policy_activation_signature=str(paths["activation_signature"]),
            policy_activation_trusted_public_key=str(paths["activation_key"]),
            policy_activation_trusted_public_key_id=final_security_env[
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV
            ],
            reproducible_build_verification=str(paths["reproducibility_report"]),
            reproducible_build_signature=str(paths["reproducibility_signature"]),
            reproducible_build_trusted_public_key=str(paths["reproducibility_key"]),
            reproducible_build_trusted_public_key_id=final_security_env[
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV
            ],
        )
        security_status, security_failures = (
            production_host_preflight.release_security_evidence_check(
                security_args,
                output["checks"]["release_artifacts"],
                final_security_env,
            )
        )
        if security_failures or security_status.get("ok") is not True:
            raise AssertionError(
                f"final preflight rejected env-bound verifier trust roots: {security_status} {security_failures}"
            )
        alternate_args = SimpleNamespace(**vars(security_args))
        alternate_args.policy_trusted_public_key = str(tmp / "caller-policy.pub.pem")
        _, alternate_failures = production_host_preflight.release_security_evidence_check(
            alternate_args,
            output["checks"]["release_artifacts"],
            final_security_env,
        )
        if not any("does not exactly match" in failure for failure in alternate_failures):
            raise AssertionError(
                f"final preflight accepted a caller-selected policy trust root: {alternate_failures}"
            )
        wrong_spki_env = {
            **final_security_env,
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV: "sha256:" + "0" * 64,
        }
        wrong_spki_args = SimpleNamespace(**vars(security_args))
        wrong_spki_args.policy_trusted_public_key_id = wrong_spki_env[
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV
        ]
        _, wrong_spki_failures = production_host_preflight.release_security_evidence_check(
            wrong_spki_args,
            output["checks"]["release_artifacts"],
            wrong_spki_env,
        )
        if not any("SPKI pin" in failure for failure in wrong_spki_failures):
            raise AssertionError(
                f"final preflight accepted trust-root bytes under a wrong SPKI pin: {wrong_spki_failures}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = fixture_release_env(paths)
        set_release_artifacts(env, paths)
        set_production_images(env, paths["images_env"])
        write_env(paths["env"], env)
        write_kms_materials(paths["kms_materials"], mode=0o644)
        rejected = run_preflight(paths)
        if rejected.returncode == 0 or "KMS materials file must not grant group/world access" not in detail(rejected):
            raise AssertionError(f"preflight accepted weak KMS material permissions: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = fixture_release_env(paths)
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
        tmp = Path(tmp_raw).resolve()
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = fixture_release_env(paths)
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
        tmp = Path(tmp_raw).resolve()
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = fixture_release_env(paths)
        set_release_artifacts(env, paths)
        env["SERVERWARE_PRODUCTION_IMAGES"] = "registry.prod.serverware.dev/serverware/control@sha256:" + "c" * 64
        write_env(paths["env"], env)
        write_kms_materials(paths["kms_materials"])
        rejected = run_preflight(paths)
        if rejected.returncode == 0 or "does not match .tmp/production-images.env" not in detail(rejected):
            raise AssertionError(f"preflight accepted env/image fragment mismatch: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = fixture_release_env(paths)
        set_release_artifacts(env, paths)
        set_production_images(env, paths["images_env"])
        write_env(paths["env"], env)
        paths["images_env"].unlink()
        write_kms_materials(paths["kms_materials"])
        rejected = run_preflight(paths)
        if rejected.returncode == 0 or "production images env is missing" not in detail(rejected):
            raise AssertionError(f"preflight accepted missing production images env: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = fixture_release_env(paths)
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
