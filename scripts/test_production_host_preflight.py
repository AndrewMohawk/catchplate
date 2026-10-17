#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import test_production_handoff  # noqa: E402
import test_production_image_builds  # noqa: E402
import test_production_release_input_preflight  # noqa: E402
import test_production_readiness  # noqa: E402
import build_production_images  # noqa: E402
import generate_release_provenance  # noqa: E402
import production_host_preflight  # noqa: E402
import run_production_readiness  # noqa: E402
import verify_production_policy_identity  # noqa: E402

CODER_PREFLIGHT_DOCKER_EXECUTABLE_ENV = (
    "CATCHPLATE_CODER_PREFLIGHT_DOCKER_EXECUTABLE"
)
CODER_PREFLIGHT_COMPOSE_PLUGIN_EXECUTABLE_ENV = (
    "CATCHPLATE_CODER_PREFLIGHT_COMPOSE_PLUGIN_EXECUTABLE"
)
CODER_PREFLIGHT_DOCKER_UNIX_SOCKET_ENV = (
    "CATCHPLATE_CODER_PREFLIGHT_DOCKER_UNIX_SOCKET"
)
CODER_PREFLIGHT_DOCKER_DAEMON_ID_ENV = (
    "CATCHPLATE_CODER_PREFLIGHT_DOCKER_DAEMON_ID"
)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def fixture_static_amd64_elf() -> bytes:
    """A minimal static ELF for byte-shape/pin checks; never execute it as a verifier."""
    code = b"\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05"  # exit(0)
    size = 64 + 56 + len(code)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\0" * 9,
        2, 62, 1, 0x400000 + 120, 64, 0, 0, 64, 56, 1, 0, 0, 0,
    )
    segment = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, size, size, 4096)
    return header + segment + code


def fixture_ed25519_spki(seed_byte: int) -> tuple[str, str]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return (
        base64.urlsafe_b64encode(spki).decode("ascii").rstrip("="),
        sha256_prefixed(spki),
    )


def fixture_global_role_registry(
    roles: dict[str, str],
) -> dict[str, object]:
    return {
        "apiVersion": (
            production_host_preflight.GLOBAL_ROLE_REGISTRY_API_VERSION
        ),
        "claimScope": (
            production_host_preflight.GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE
        ),
        "roles": {role: roles[role] for role in sorted(roles)},
        "rolesOutsideClaim": list(
            production_host_preflight.GLOBAL_ROLES_OUTSIDE_CLAIM
        ),
    }


def public_key_spki_id(path: Path) -> str:
    public_key = serialization.load_pem_public_key(path.read_bytes())
    return sha256_prefixed(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def write_env(path: Path, env: dict[str, str]) -> None:
    production_env = {key: value for key, value in env.items() if key.startswith("CATCHPLATE_")}
    path.write_text("\n".join(f"{key}={shlex.quote(value)}" for key, value in sorted(production_env.items())) + "\n", encoding="utf-8")
    path.chmod(0o600)


def set_production_images(env: dict[str, str], images_env: Path) -> None:
    images = images_env.read_text(encoding="utf-8").split("=", 1)[1].strip().split(",")
    by_name = {image.rsplit("/", 1)[-1].split("@", 1)[0]: image for image in images}
    env["CATCHPLATE_PRODUCTION_IMAGES"] = ",".join(images)
    env["CATCHPLATE_CONTROL_PLANE_IMAGE"] = by_name["control"]
    env["CATCHPLATE_DECISION_GATE_IMAGE"] = by_name["decision-gate"]


def set_release_artifacts(env: dict[str, str], paths: dict[str, Path]) -> None:
    env["CATCHPLATE_RELEASE_PROVENANCE_FILE"] = str(paths["provenance"].resolve())
    env["CATCHPLATE_IMAGE_SIGNATURES_FILE"] = str(paths["image_signatures"].resolve())


def coder_preflight_toolchain() -> tuple[Path, Path, str, str]:
    settings = {
        CODER_PREFLIGHT_DOCKER_EXECUTABLE_ENV: os.environ.get(
            CODER_PREFLIGHT_DOCKER_EXECUTABLE_ENV, ""
        ),
        CODER_PREFLIGHT_COMPOSE_PLUGIN_EXECUTABLE_ENV: os.environ.get(
            CODER_PREFLIGHT_COMPOSE_PLUGIN_EXECUTABLE_ENV, ""
        ),
        CODER_PREFLIGHT_DOCKER_UNIX_SOCKET_ENV: os.environ.get(
            CODER_PREFLIGHT_DOCKER_UNIX_SOCKET_ENV, ""
        ),
        CODER_PREFLIGHT_DOCKER_DAEMON_ID_ENV: os.environ.get(
            CODER_PREFLIGHT_DOCKER_DAEMON_ID_ENV, ""
        ),
    }
    supplied = [bool(value) for value in settings.values()]
    if not all(supplied):
        missing = sorted(name for name, value in settings.items() if not value)
        raise AssertionError(
            "Offline production-preflight toolchain must be explicitly prepared; "
            "no live Docker fallback is permitted. Missing: " + ", ".join(missing)
        )

    executables: list[Path] = []
    for setting in (
        CODER_PREFLIGHT_DOCKER_EXECUTABLE_ENV,
        CODER_PREFLIGHT_COMPOSE_PLUGIN_EXECUTABLE_ENV,
    ):
        path = Path(settings[setting])
        if not path.is_absolute():
            raise AssertionError(f"{setting} must be absolute")
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise AssertionError(f"{setting} must be a canonical regular file")
        if not os.access(path, os.X_OK):
            raise AssertionError(f"{setting} must be executable")
        executables.append(path)

    socket_path = Path(settings[CODER_PREFLIGHT_DOCKER_UNIX_SOCKET_ENV])
    if not socket_path.is_absolute():
        raise AssertionError(
            f"{CODER_PREFLIGHT_DOCKER_UNIX_SOCKET_ENV} must be absolute"
        )
    if socket_path.exists() or socket_path.is_symlink():
        raise AssertionError(
            "Coder production-preflight diagnostics must use a nonexistent Docker socket"
        )

    return (
        executables[0],
        executables[1],
        str(socket_path),
        settings[CODER_PREFLIGHT_DOCKER_DAEMON_ID_ENV],
    )


def fixture_release_env(paths: dict[str, Path]) -> dict[str, str]:
    env = test_production_readiness.good_env()
    env["CATCHPLATE_RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND"] = (
        "/opt/catchplate/bin/response-v2-tee-verify"
    )
    env.update(test_production_handoff.fixture_release_trust_env(paths))
    env["CATCHPLATE_COMPLETION_VERIFICATION_MODE"] = "readiness"
    fixture_dir = paths["build"].parent.resolve()
    production_python_path = fixture_dir / "production-python"
    production_python_path.write_bytes(Path(sys.executable).resolve().read_bytes())
    production_python_path.chmod(0o700)
    (
        docker_source_path,
        compose_plugin_source,
        docker_socket,
        docker_daemon_id,
    ) = coder_preflight_toolchain()
    production_docker_path = fixture_dir / "production-docker"
    production_docker_path.write_bytes(docker_source_path.read_bytes())
    production_docker_path.chmod(0o700)
    production_python = str(production_python_path)
    production_python_digest = sha256_prefixed(production_python_path.read_bytes())
    production_docker_digest = sha256_prefixed(production_docker_path.read_bytes())
    compose_plugin_path = fixture_dir / "production-docker-compose"
    compose_plugin_path.write_bytes(compose_plugin_source.read_bytes())
    compose_plugin_path.chmod(0o700)
    env[production_host_preflight.PRODUCTION_PYTHON_EXECUTABLE_SETTING] = production_python
    env[production_host_preflight.PRODUCTION_DOCKER_EXECUTABLE_SETTING] = str(production_docker_path)
    env[run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV] = str(compose_plugin_path)
    env[run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV] = sha256_prefixed(
        compose_plugin_path.read_bytes()
    )
    env[run_production_readiness.DOCKER_UNIX_SOCKET_ENV] = docker_socket
    env[run_production_readiness.DOCKER_DAEMON_ID_ENV] = docker_daemon_id
    env[run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV] = (
        "catchplate-production"
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
                    "encryption_context": {"material": "broker-kek", "service": "catchplate"},
                },
                "decision-gate-ca": {
                    "key_id": "arn:aws:kms:us-east-1:111122223333:key/ca",
                    "ciphertext_blob_b64": base64.b64encode(b"ca-ciphertext").decode("ascii"),
                    "encryption_context": {"material": "decision-gate-ca", "service": "catchplate"},
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
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Catchplate test CA")])
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
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "catchplate")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("catchplate")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (tls_dir / "catchplate.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    (tls_dir / "catchplate.key").write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (tls_dir / "catchplate.key").chmod(0o600)
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
        "catchplate-proof-client",
    ):
        helper = helper_dir / name
        helper.write_bytes(b"test helper\n")
        helper.chmod(0o755)
    env = test_production_readiness.good_env()
    tee_verifier = helper_dir / "response-v2-tee-verify"
    tee_verifier.write_bytes(fixture_static_amd64_elf())
    tee_verifier.chmod(0o755)
    tee_verifier_setting = "CATCHPLATE_RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND"
    env[tee_verifier_setting] = "/opt/catchplate/bin/response-v2-tee-verify"
    env["CATCHPLATE_CONTROL_PLANE_TLS_DIR"] = str(tls_dir)
    env["CATCHPLATE_AUDIT_ANCHOR_TLS_DIR"] = str(anchor_tls_dir)
    env["CATCHPLATE_ATTESTATION_HELPER_DIR"] = str(helper_dir)
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
    env["CATCHPLATE_PROXY_PROOF_COLLECTOR_COMMAND"] = "/opt/catchplate/bin/catchplate-proof-client"
    env["CATCHPLATE_PROXY_PROOF_CA_BUNDLE"] = str(proof_ca)
    env["CATCHPLATE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY"] = str(collector_private_path)
    env["CATCHPLATE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY"] = str(collector_public_path)
    env["CATCHPLATE_PROXY_PROOF_VERIFIER_PUBLIC_KEY"] = str(verifier_public_path)
    env["CATCHPLATE_PROXY_PROOF_COLLECTOR_KEY_ID"] = sha256_prefixed(collector_public_der)
    env["CATCHPLATE_PROXY_PROOF_VERIFIER_KEY_ID"] = sha256_prefixed(verifier_public_der)
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
    if status.get("proof_collector_key_id") != env["CATCHPLATE_PROXY_PROOF_COLLECTOR_KEY_ID"]:
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

    for command in ("", "/opt/catchplate/bin/response-v2-tee-verify --skip-checks"):
        _, failures = production_host_preflight.runtime_trust_materials_check(
            {**env, tee_verifier_setting: command}, skip_host_check=False
        )
        if not any(tee_verifier_setting in failure for failure in failures):
            raise AssertionError(f"invalid response-v2 verifier command accepted: {failures}")

    static_verifier = tee_verifier.read_bytes()
    try:
        # Update the pin too: this control must fail on ELF shape, not a stale hash.
        tee_verifier.write_bytes(b"#!/bin/sh\nexit 0\n")
        shell_manifest = {**executable_digest_manifest, tee_verifier_setting: sha256_prefixed(tee_verifier.read_bytes())}
        _, failures = production_host_preflight.runtime_trust_materials_check(
            {**env, production_host_preflight.ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV: json.dumps(shell_manifest)},
            skip_host_check=False,
        )
        if not any("response-v2 TEE verifier must be a 64-bit" in failure for failure in failures):
            raise AssertionError(f"non-ELF response-v2 verifier accepted: {failures}")
        tee_verifier.write_bytes(static_verifier[:-1] + b"\x00")
        _, failures = production_host_preflight.runtime_trust_materials_check(env, skip_host_check=False)
        if not any(tee_verifier_setting in failure and "SHA-256 does not match" in failure for failure in failures):
            raise AssertionError(f"changed static response-v2 verifier accepted: {failures}")
    finally:
        tee_verifier.write_bytes(static_verifier)

    missing_manifest = dict(executable_digest_manifest)
    missing_manifest.pop("CATCHPLATE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE")
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
            {**executable_digest_manifest, "CATCHPLATE_UNEXPECTED_HELPER_COMMAND": sha256_prefixed(b"extra")},
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
    invalid_manifest["CATCHPLATE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE"] = "sha256:INVALID"
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

    changed_collector = helper_dir / "catchplate-proof-client"
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
        {**env, "CATCHPLATE_ATTESTATION_HELPER_DIR": str(symlink_helper_dir)},
        skip_host_check=False,
    )
    if not any("non-symlink directories" in failure for failure in symlink_directory_failures):
        raise AssertionError(f"symlink helper directory was accepted: {symlink_directory_failures}")

    mismatched_proof_env = {**env, "CATCHPLATE_PROXY_PROOF_COLLECTOR_KEY_ID": "sha256:" + "0" * 64}
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
    (tls_dir / "catchplate.crt").write_bytes(missing_san_cert.public_bytes(serialization.Encoding.PEM))
    _, san_failures = production_host_preflight.runtime_trust_materials_check(env, skip_host_check=False)
    if not any("DNS SAN catchplate" in failure for failure in san_failures):
        raise AssertionError(f"certificate without the internal DNS SAN was accepted: {san_failures}")
    (tls_dir / "catchplate.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
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
            if image["service"] == "catchplate-decision-gate":
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
        env["CATCHPLATE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS"] = "1"
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
        "CATCHPLATE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": str(google),
        "CATCHPLATE_X_OAUTH_CLIENT_SECRET_FILE": str(x_secret),
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


def verify_response_signing_key_custody(tmp: Path) -> None:
    tmp = tmp.resolve()
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp / "response-signing-private.pem"
    public_path = tmp / "response-signing-public.pem"
    key_id_path = tmp / "response-signing-key-id"
    key_id = sha256_prefixed(
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    key_id_path.write_text(key_id + "\n", encoding="ascii")
    private_path.chmod(0o600)
    public_path.chmod(0o644)
    key_id_path.chmod(0o644)
    env = {
        "CATCHPLATE_RESPONSE_SIGNING_PRIVATE_KEY_FILE": str(private_path),
        "CATCHPLATE_RESPONSE_SIGNING_PUBLIC_KEY": str(public_path),
        "CATCHPLATE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY": str(public_path),
        "CATCHPLATE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID": key_id,
    }

    status, failures = production_host_preflight.response_signing_key_custody_check(
        env,
        skip_host_check=False,
        expected_control_plane_uid=os.getuid(),
    )
    if failures or status.get("ok") is not True or status.get("key_id") != key_id:
        raise AssertionError(f"valid response-signing custody failed: {status} {failures}")

    fifo_path = tmp / "response-signing-private.fifo"
    os.mkfifo(fifo_path, 0o600)
    fifo_env = {**env, "CATCHPLATE_RESPONSE_SIGNING_PRIVATE_KEY_FILE": str(fifo_path)}
    fifo_probe_code = (
        "import json,os,sys; "
        "from pathlib import Path; "
        "sys.path.insert(0,'scripts'); "
        "import production_host_preflight; "
        "from catchplate.response_identity import "
        "ResponseIdentityPublicationError,validate_response_signing_key_custody; "
        f"env=json.loads({json.dumps(json.dumps(fifo_env))}); "
        "status,failures=production_host_preflight.response_signing_key_custody_check("
        f"env,skip_host_check=False,expected_control_plane_uid={os.getuid()}); "
        "failures or sys.exit('host preflight accepted a FIFO response key'); "
        "rejected=False; "
        "\ntry:\n "
        f" validate_response_signing_key_custody(Path({str(fifo_path)!r}),"
        f"Path({str(public_path)!r}),Path({str(key_id_path)!r}))"
        "\nexcept ResponseIdentityPublicationError:\n rejected=True"
        "\nrejected or sys.exit('runtime accepted a FIFO response key')"
    )
    try:
        fifo_probe = subprocess.run(
            [sys.executable, "-c", fifo_probe_code],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError("response-key validation blocked while opening a FIFO") from exc
    if fifo_probe.returncode != 0:
        raise AssertionError(
            "response-key FIFO rejection probe failed: "
            + (fifo_probe.stderr or fifo_probe.stdout).strip()
        )

    hardlink = tmp / "response-signing-private-hardlink.pem"
    os.link(private_path, hardlink)
    _, hardlink_failures = production_host_preflight.response_signing_key_custody_check(
        env,
        skip_host_check=False,
        expected_control_plane_uid=os.getuid(),
    )
    hardlink.unlink()
    if not any("single-link" in failure for failure in hardlink_failures):
        raise AssertionError(f"hard-linked response key was accepted: {hardlink_failures}")

    symlink = tmp / "response-signing-private-symlink.pem"
    symlink.symlink_to(private_path)
    symlink_env = {**env, "CATCHPLATE_RESPONSE_SIGNING_PRIVATE_KEY_FILE": str(symlink)}
    _, symlink_failures = production_host_preflight.response_signing_key_custody_check(
        symlink_env,
        skip_host_check=False,
        expected_control_plane_uid=os.getuid(),
    )
    if not symlink_failures:
        raise AssertionError("symlinked response key was accepted")

    private_path.chmod(0o644)
    _, mode_failures = production_host_preflight.response_signing_key_custody_check(
        env,
        skip_host_check=False,
        expected_control_plane_uid=os.getuid(),
    )
    private_path.chmod(0o600)
    if not any("mode 0400 or 0600" in failure for failure in mode_failures):
        raise AssertionError(f"permissive response key was accepted: {mode_failures}")

    wrong_private = ec.generate_private_key(ec.SECP256R1())
    private_path.write_bytes(
        wrong_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    _, type_failures = production_host_preflight.response_signing_key_custody_check(
        env,
        skip_host_check=False,
        expected_control_plane_uid=os.getuid(),
    )
    if not any("Ed25519 PKCS8" in failure for failure in type_failures):
        raise AssertionError(f"wrong response key type was accepted: {type_failures}")

    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    other_key = Ed25519PrivateKey.generate()
    public_path.write_bytes(
        other_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    _, mismatch_failures = production_host_preflight.response_signing_key_custody_check(
        env,
        skip_host_check=False,
        expected_control_plane_uid=os.getuid(),
    )
    if not any("does not match" in failure for failure in mismatch_failures):
        raise AssertionError(f"mismatched response public key was accepted: {mismatch_failures}")

    optimized_probe = subprocess.run(
        [
            sys.executable,
            "-O",
            "-c",
            (
                "from pathlib import Path; "
                "from catchplate.response_identity import validate_response_signing_key_custody; "
                f"validate_response_signing_key_custody(Path({str(private_path)!r}),"
                f"Path({str(public_path)!r}),Path({str(key_id_path)!r}))"
            ),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if optimized_probe.returncode == 0:
        raise AssertionError("optimized Python erased response-key custody validation")


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
        "CATCHPLATE_COMPLETION_VERIFICATION_MODE=readiness\n"
        "CATCHPLATE_FINAL_LAUNCHER_CONTRACT=descriptor-sealed-bootstrap-v3\n",
        encoding="ascii",
    )
    env_path.chmod(0o600)
    parser_reached = False
    original_loader = run_production_readiness.load_env_bytes

    def record_parse(_data: bytes, _path: Path) -> dict[str, str]:
        nonlocal parser_reached
        parser_reached = True
        return {
            "CATCHPLATE_COMPLETION_VERIFICATION_MODE": "readiness",
            "CATCHPLATE_FINAL_LAUNCHER_CONTRACT": (
                "descriptor-sealed-bootstrap-v3"
            ),
        }

    run_production_readiness.load_env_bytes = record_parse
    try:
        try:
            production_host_preflight.enforce_readiness_only_preflight_boundary(
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


def verify_launcher_import_and_alias_boundary() -> None:
    if hasattr(production_host_preflight, "sign_final_preflight"):
        raise AssertionError(
            "production host preflight retained the obsolete final-signing alias"
        )
    source = (ROOT / "scripts" / "production_host_preflight.py").read_text(
        encoding="utf-8"
    )
    if (
        "def sign_final_preflight" in source
        or 'sys.path.insert(0, str(ROOT / "scripts"))' in source
    ):
        raise AssertionError(
            "production host preflight retained an obsolete final alias or "
            "unconditional live release-path import"
        )
    if production_host_preflight.PROJECT_IMPORT_MODE != "direct-fixture-paths":
        raise AssertionError(
            "direct fixture import did not use the explicit non-launch path"
        )
    retained_roots = ("/proc/self/fd/201", "/proc/self/fd/202")
    if not all(
        production_host_preflight._is_retained_import_root(path)
        for path in retained_roots
    ):
        raise AssertionError("valid retained launcher import roots were rejected")
    for path in (
        "",
        ".",
        "scripts",
        str(ROOT),
        "/proc/self/fd/2",
        "/proc/self/fd/201/scripts",
        "/proc/self/fd/not-a-descriptor",
    ):
        if production_host_preflight._is_retained_import_root(path):
            raise AssertionError(
                f"launcher import boundary accepted a live or malformed path: {path!r}"
            )
    retained_origins = (
        "/proc/self/fd/201/run_production_readiness.py",
        "/proc/self/fd/202/catchplate/module.py",
    )
    if not all(
        production_host_preflight._is_retained_import_origin(
            path,
            retained_roots,
        )
        for path in retained_origins
    ):
        raise AssertionError("valid retained launcher module origins were rejected")
    for path in (
        "/proc/self/fd/201",
        "/proc/self/fd/2/module.py",
        "/proc/self/fd/203/module.py",
        "/proc/self/fd/201/../release/module.py",
        "/proc/self/fd/not-a-descriptor/module.py",
        str(ROOT / "scripts" / "run_production_readiness.py"),
    ):
        if production_host_preflight._is_retained_import_origin(
            path,
            retained_roots,
        ):
            raise AssertionError(
                "launcher import boundary accepted a live or malformed "
                f"module origin: {path!r}"
            )
    guarded = production_host_preflight._RetainedImportPath(retained_roots)
    guarded.insert(0, str(ROOT / "scripts"))
    guarded[:0] = [str(ROOT), "scripts"]
    guarded.extend([".", "/proc/self/fd/203"])
    guarded.append("/proc/self/fd/204")
    guarded[0] = "/proc/self/fd/205"
    if (
        guarded.allowed_roots != retained_roots
        or guarded
        != [
            "/proc/self/fd/201",
            "/proc/self/fd/202",
        ]
    ):
        raise AssertionError(
            "launcher import-path guard accepted a live or later descriptor "
            f"root, changed its allowlist, or dropped retained roots: {guarded}"
        )


def verify_nonce_rollback_assurance_argv_binding(tmp: Path) -> None:
    env_path = tmp / "nonce-production-readiness.env"
    env_path.write_text(
        "CATCHPLATE_COMPLETION_VERIFICATION_MODE=readiness\n"
        "CATCHPLATE_FINAL_LAUNCHER_CONTRACT=descriptor-sealed-bootstrap-v3\n",
        encoding="ascii",
    )
    env_path.chmod(0o600)
    env_sha256 = sha256_prefixed(env_path.read_bytes())
    witness_key_id = "sha256:" + "8" * 64
    witness_identity = "sha256:" + "9" * 64
    witness_domain = "sha256:" + "a" * 64
    witness_store_assurance = "sha256:" + "b" * 64
    fixture_now = int(datetime.now(timezone.utc).timestamp())
    issued_at = fixture_now - 1
    expires_at = fixture_now + 30
    witness_spki, witness_spki_sha256 = fixture_ed25519_spki(1)
    verifier_state_spki, verifier_state_spki_sha256 = fixture_ed25519_spki(2)
    verifier_store_spki, verifier_store_spki_sha256 = fixture_ed25519_spki(3)
    _witness_tls_spki, witness_tls_spki_sha256 = fixture_ed25519_spki(4)
    witness_key_id = witness_spki_sha256
    role_values = {
        role: sha256_prefixed(f"fixture-role:{role}".encode("ascii"))
        for role in production_host_preflight.GLOBAL_ROLE_NAMES
    }
    role_values["launchAuthorityWitness"] = witness_spki_sha256
    role_values["launchAuthorityWitnessTls"] = witness_tls_spki_sha256
    role_values["nonceAuthorityVerifierState"] = verifier_state_spki_sha256
    role_values[
        "nonceAuthorityVerifierStateStoreAttestation"
    ] = verifier_store_spki_sha256
    global_role_registry = fixture_global_role_registry(role_values)
    registry_sha256 = sha256_prefixed(
        production_host_preflight.canonical_json(
            global_role_registry
        ).encode("ascii")
    )
    registry_pins_sha256 = sha256_prefixed(
        b"fixture-global-role-registry-pins"
    )
    launcher_nonce = "d" * 64
    witness_challenge = "e" * 64
    boot_id_sha256 = "sha256:" + "f" * 64
    manifest_sha256 = "sha256:" + "0" * 64
    request = {
        "apiVersion": "catchplate.launchAuthorizationRequest/v2",
        "launcherNonce": launcher_nonce,
        "bootIdSha256": boot_id_sha256,
        "manifestSha256": manifest_sha256,
        "authorizationScope": "trusted-host-readiness",
        "freshnessAuthority": "trusted-host-wall-clock",
        "launchAuthorityWitnessChallenge": witness_challenge,
        "launchAuthorityWitnessKeyId": witness_key_id,
        "launchAuthorityWitnessIdentitySha256": witness_identity,
        "launchAuthorityWitnessAdministrativeDomainSha256": witness_domain,
        "launchAuthorityWitnessStoreAssuranceSha256": witness_store_assurance,
        "globalRoleRegistry": global_role_registry,
        "globalRoleRegistrySha256": registry_sha256,
        "globalRoleRegistryPinsSha256": registry_pins_sha256,
        "launchAttemptJournalDomain": (
            production_host_preflight.LAUNCH_ATTEMPT_JOURNAL_DOMAIN
        ),
        "launchAttemptRecoveryIdentitySha256": "",
    }
    request["launchAttemptRecoveryIdentitySha256"] = (
        production_host_preflight._launch_attempt_recovery_identity_sha256(
            request
        )
    )
    witness_statement = {
        "operation": "authorize-trusted-host-readiness",
        "issuedAtUnixSeconds": issued_at,
        "expiresAtUnixSeconds": expires_at,
        "witnessKeyId": witness_key_id,
        "witnessIdentitySha256": witness_identity,
        "witnessAdministrativeDomainSha256": witness_domain,
        "storeAssuranceSha256": witness_store_assurance,
        "stateTransitionCommitted": True,
    }
    expected_path = "/proc/self/fd/211"
    expected_pins_sha256 = "sha256:" + "1" * 64
    expected_contract_sha256 = "sha256:" + "2" * 64
    expected_summary = {
        "apiVersion": (
            run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
        ),
        "contractSha256": expected_contract_sha256,
        "enforcement": "native-launcher-measured-retained-snapshot",
        "retainedSnapshotFd": 211,
        "retainedSnapshotSha256": expected_pins_sha256,
        "verifierStateService": {
            "signingPublicKeySpkiDerBase64url": "fixture-verifier-key",
            "storeAdministrativeDomainSha256": "sha256:" + "5" * 64,
            "storeAssuranceEvidenceSha256": "sha256:" + "6" * 64,
            "storeAttestationPublicKeySpkiDerBase64url": "fixture-store-key",
            "storeIdentitySha256": "sha256:" + "7" * 64,
        },
        "verified": True,
    }
    expected_summary["verifierStateService"][
        "signingPublicKeySpkiDerBase64url"
    ] = verifier_state_spki
    expected_summary["verifierStateService"][
        "storeAttestationPublicKeySpkiDerBase64url"
    ] = verifier_store_spki
    summary_metadata = {
        "device": 1,
        "inode": 1,
        "mode": 0o400,
        "ownerUid": 0,
        "ownerGid": 0,
        "linkCount": 1,
        "size": 1,
        "modifiedUnixNanos": 1,
        "changedUnixNanos": 1,
    }
    receipt = {
        "apiVersion": "catchplate.bootstrapReceipt/v3",
        "kind": "ProductionBootstrapReceipt",
        "launchId": launcher_nonce,
        "sha256": "sha256:" + "3" * 64,
        "bootIdSha256": boot_id_sha256,
        "sourceTreeDigest": "sha256:" + "4" * 64,
        "launchAuthorization": {
            "request": request,
            "requestSha256": "sha256:" + "5" * 64,
            "envelope": {
                "apiVersion": "catchplate.launchAuthorization/v2",
                "kind": "ProductionLaunchAuthorization",
                "statement": {
                    "authorityKeyId": role_values["launchAuthority"],
                    "authorizationScope": "trusted-host-readiness",
                    "freshnessAuthority": "trusted-host-wall-clock",
                    "issuedAtUnixSeconds": issued_at,
                    "expiresAtUnixSeconds": expires_at,
                    "globalRoleRegistrySha256": registry_sha256,
                    "capabilitySemantics": (
                        "time-bounded-idempotent-readiness-authorization"
                    ),
                    "monotonicWitness": {"statement": witness_statement},
                },
                "signature": "fixture-authority-signature",
            },
            "authorizationSha256": "sha256:" + "6" * 64,
            "witnessPublicKeySpkiDerBase64url": witness_spki,
            "verifiedAtUnixSeconds": fixture_now,
        },
        "launchAuthorityKeyId": role_values["launchAuthority"],
        "launchAuthorityRootSha256": "sha256:" + "7" * 64,
        "launcher": {
            "path": "/opt/catchplate/launchers/fixture/launcher",
            "sha256": "sha256:" + "8" * 64,
            "metadata": dict(summary_metadata),
        },
        "manifest": {
            "path": "/etc/catchplate/production-launch.json",
            "sha256": manifest_sha256,
            "metadata": dict(summary_metadata),
        },
        "nonceRollbackAssurance": {
            "apiVersion": (
                run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
            ),
            "contractSha256": expected_contract_sha256,
            "pinsFile": {
                "path": "/etc/catchplate/nonce-pins.json",
                "sha256": expected_pins_sha256,
                "metadata": dict(summary_metadata),
            },
            "retainedSnapshotFd": 211,
            "retainedSnapshotSha256": expected_pins_sha256,
            "verifierStateService": dict(
                expected_summary["verifierStateService"]
            ),
        },
        "argv": {
            "preflightSha256": "sha256:" + "9" * 64,
            "readinessSha256": "sha256:" + "a" * 64,
        },
        "environment": {
            "names": list(
                run_production_readiness.BOOTSTRAP_RECEIPT_COMMITTED_ENV_NAMES
            ),
            "sha256": "sha256:" + "b" * 64,
        },
        "sealed": True,
        "sealMask": 0xF,
    }
    if set(receipt) != {
        "apiVersion",
        "kind",
        "launchId",
        "sha256",
        "bootIdSha256",
        "sourceTreeDigest",
        "launchAuthorization",
        "launchAuthorityKeyId",
        "launchAuthorityRootSha256",
        "launcher",
        "manifest",
        "nonceRollbackAssurance",
        "argv",
        "environment",
        "sealed",
        "sealMask",
    }:
        raise AssertionError(
            "host-preflight fixture does not match the real sealed-receipt "
            "loader summary shape"
        )
    originals = {
        "load_env_bytes": run_production_readiness.load_env_bytes,
        "validate_final_launcher_contract": (
            run_production_readiness.validate_final_launcher_contract
        ),
        "load_sealed_bootstrap_receipt": (
            run_production_readiness.load_sealed_bootstrap_receipt
        ),
        "validate_retained_nonce_rollback_assurance": (
            run_production_readiness.validate_retained_nonce_rollback_assurance
        ),
        "verify_current_preflight_script_binding": (
            production_host_preflight.verify_current_preflight_script_binding
        ),
    }

    def validate_retained(**kwargs: object) -> dict[str, object]:
        if (
            kwargs.get("retained_path") != expected_path
            or kwargs.get("expected_pins_sha256") != expected_pins_sha256
            or kwargs.get("expected_contract_sha256")
            != expected_contract_sha256
            or kwargs.get("bootstrap_receipt") != receipt
            or kwargs.get("required") is not True
        ):
            raise ValueError(
                "fixture rejected missing, malformed, or substituted launcher nonce assurance argv"
            )
        return expected_summary

    run_production_readiness.load_env_bytes = lambda _data, _path: {
        "CATCHPLATE_COMPLETION_VERIFICATION_MODE": "readiness",
        "CATCHPLATE_FINAL_LAUNCHER_CONTRACT": (
            "descriptor-sealed-bootstrap-v3"
        ),
    }
    run_production_readiness.validate_final_launcher_contract = (
        lambda _loaded: {"verified": True}
    )
    run_production_readiness.load_sealed_bootstrap_receipt = (
        lambda *, required: (receipt, 198)
        if required
        else (_ for _ in ()).throw(AssertionError("receipt must be required"))
    )
    run_production_readiness.validate_retained_nonce_rollback_assurance = (
        validate_retained
    )
    production_host_preflight.verify_current_preflight_script_binding = (
        lambda _loaded: {"matches_pinned_path_inode": True}
    )
    try:
        status, _loaded, failures = production_host_preflight.env_check(
            env_path,
            production_images_env=tmp / "unused-images.env",
            config_out=tmp / "unused-config.json",
            skip_config_gate=True,
            launcher_trusted_env_path=str(env_path),
            launcher_trusted_env_sha256=env_sha256,
            launcher_nonce_rollback_assurance_pins=expected_path,
            launcher_nonce_rollback_assurance_pins_sha256=(
                expected_pins_sha256
            ),
            launcher_nonce_rollback_assurance_contract_sha256=(
                expected_contract_sha256
            ),
        )
        if (
            failures
            or status.get("nonce_rollback_assurance") != expected_summary
            or status.get("authority_boundary")
            != production_host_preflight.readiness_authority_boundary(
                launcher_evidence_verified=True
            )
            or status.get("launcher_trust", {}).get(
                "nonce_rollback_assurance"
            )
            != expected_summary
            or status.get("launcher_trust", {}).get(
                "current_freshness_verified"
            )
            is not True
            or status.get("launcher_trust", {}).get("secure_time_proven")
            is not False
        ):
            raise AssertionError(
                f"preflight did not bind retained nonce assurance argv: {status} {failures}"
            )
        for label, selected_path, selected_pins, selected_contract in (
            ("missing descriptor", None, expected_pins_sha256, expected_contract_sha256),
            (
                "malformed descriptor",
                "/tmp/pins.json",
                expected_pins_sha256,
                expected_contract_sha256,
            ),
            (
                "pins digest substitution",
                expected_path,
                "sha256:" + "3" * 64,
                expected_contract_sha256,
            ),
            (
                "contract digest substitution",
                expected_path,
                expected_pins_sha256,
                "sha256:" + "4" * 64,
            ),
        ):
            rejected, _loaded, rejected_failures = (
                production_host_preflight.env_check(
                    env_path,
                    production_images_env=tmp / "unused-images.env",
                    config_out=tmp / "unused-config.json",
                    skip_config_gate=True,
                    launcher_trusted_env_path=str(env_path),
                    launcher_trusted_env_sha256=env_sha256,
                    launcher_nonce_rollback_assurance_pins=selected_path,
                    launcher_nonce_rollback_assurance_pins_sha256=selected_pins,
                    launcher_nonce_rollback_assurance_contract_sha256=(
                        selected_contract
                    ),
                )
            )
            if rejected.get("ok") is True or not rejected_failures:
                raise AssertionError(
                    f"preflight accepted {label}: {rejected}"
                )

        run_production_readiness.load_sealed_bootstrap_receipt = (
            lambda *, required: (receipt, 197)
            if required
            else (_ for _ in ()).throw(AssertionError("receipt must be required"))
        )
        wrong_fd, _loaded, wrong_fd_failures = (
            production_host_preflight.env_check(
                env_path,
                production_images_env=tmp / "unused-images.env",
                config_out=tmp / "unused-config.json",
                skip_config_gate=True,
                launcher_trusted_env_path=str(env_path),
                launcher_trusted_env_sha256=env_sha256,
                launcher_nonce_rollback_assurance_pins=expected_path,
                launcher_nonce_rollback_assurance_pins_sha256=(
                    expected_pins_sha256
                ),
                launcher_nonce_rollback_assurance_contract_sha256=(
                    expected_contract_sha256
                ),
            )
        )
        if (
            run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD != 198
            or wrong_fd.get("ok") is True
            or not any("exact sealed descriptor 198" in item for item in wrong_fd_failures)
        ):
            raise AssertionError(
                "production host readiness did not enforce exact bootstrap "
                f"receipt FD 198: {wrong_fd} {wrong_fd_failures}"
            )

        for label, selected_receipt, selected_assurance in (
            (
                "absent monotonic witness",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "envelope": {
                            **receipt["launchAuthorization"]["envelope"],
                            "statement": {
                                key: value
                                for key, value in receipt["launchAuthorization"][
                                    "envelope"
                                ]["statement"].items()
                                if key != "monotonicWitness"
                            },
                        },
                    },
                },
                expected_summary,
            ),
            (
                "tampered witness store assurance",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "envelope": {
                            **receipt["launchAuthorization"]["envelope"],
                            "statement": {
                                **receipt["launchAuthorization"]["envelope"][
                                    "statement"
                                ],
                                "monotonicWitness": {
                                    "statement": {
                                        **witness_statement,
                                        "storeAssuranceSha256": (
                                            "sha256:" + "c" * 64
                                        ),
                                    }
                                },
                            },
                        },
                    },
                },
                expected_summary,
            ),
            (
                "absent verifier-state store assurance",
                receipt,
                {
                    key: value
                    for key, value in expected_summary.items()
                    if key != "verifierStateService"
                },
            ),
            (
                "tampered verifier-state store assurance",
                receipt,
                {
                    **expected_summary,
                    "verifierStateService": {
                        **expected_summary["verifierStateService"],
                        "storeAssuranceEvidenceSha256": "not-a-digest",
                    },
                },
            ),
            (
                "obsolete useLimit",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "envelope": {
                            **receipt["launchAuthorization"]["envelope"],
                            "statement": {
                                **receipt["launchAuthorization"]["envelope"][
                                    "statement"
                                ],
                                "useLimit": 1,
                            },
                        },
                    },
                },
                expected_summary,
            ),
            (
                "absent signed-request global role registry",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "request": {
                            key: value
                            for key, value in request.items()
                            if key != "globalRoleRegistry"
                        },
                    },
                },
                expected_summary,
            ),
            (
                "tampered global role registry digest",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "request": {
                            **request,
                            "globalRoleRegistrySha256": "sha256:" + "0" * 64,
                        },
                    },
                },
                expected_summary,
            ),
            (
                "witness TLS global role collision",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "request": {
                            **request,
                            "globalRoleRegistry": {
                                **global_role_registry,
                                "roles": {
                                    **global_role_registry["roles"],
                                    "launchAuthorityWitnessTls": (
                                        global_role_registry["roles"][
                                            "policyActivation"
                                        ]
                                    ),
                                },
                            },
                        },
                    },
                },
                expected_summary,
            ),
            (
                "omitted witness TLS global role",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "request": {
                            **request,
                            "globalRoleRegistry": {
                                **global_role_registry,
                                "roles": {
                                    key: value
                                    for key, value in global_role_registry[
                                        "roles"
                                    ].items()
                                    if key != "launchAuthorityWitnessTls"
                                },
                            },
                        },
                    },
                },
                expected_summary,
            ),
            (
                "absent signed-request journal domain",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "request": {
                            key: value
                            for key, value in request.items()
                            if key != "launchAttemptJournalDomain"
                        },
                    },
                },
                expected_summary,
            ),
            (
                "tampered launch-attempt recovery identity",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "request": {
                            **request,
                            "launchAttemptRecoveryIdentitySha256": (
                                "sha256:" + "e" * 64
                            ),
                        },
                    },
                },
                expected_summary,
            ),
            (
                "tampered launch-attempt journal domain",
                {
                    **receipt,
                    "launchAuthorization": {
                        **receipt["launchAuthorization"],
                        "request": {
                            **request,
                            "launchAttemptJournalDomain": (
                                "catchplate.wrongAttemptJournal/v1"
                            ),
                        },
                    },
                },
                expected_summary,
            ),
            (
                "manifest digest outside signed request",
                {
                    **receipt,
                    "manifest": {
                        **receipt["manifest"],
                        "sha256": "sha256:" + "c" * 64,
                    },
                },
                expected_summary,
            ),
        ):
            try:
                production_host_preflight.validate_launcher_readiness_evidence(
                    selected_receipt,
                    selected_assurance,
                )
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"production host readiness accepted {label}"
                )

        crosswired_roles = dict(role_values)
        crosswired_roles["launchAuthority"] = role_values["policyIdentity"]
        crosswired_roles["policyIdentity"] = role_values["launchAuthority"]
        crosswired_registry = fixture_global_role_registry(crosswired_roles)
        crosswired_registry_sha256 = sha256_prefixed(
            production_host_preflight.canonical_json(
                crosswired_registry
            ).encode("ascii")
        )
        crosswired_request = {
            **request,
            "globalRoleRegistry": crosswired_registry,
            "globalRoleRegistrySha256": crosswired_registry_sha256,
        }
        crosswired_request["launchAttemptRecoveryIdentitySha256"] = (
            production_host_preflight._launch_attempt_recovery_identity_sha256(
                crosswired_request
            )
        )
        crosswired_receipt = {
            **receipt,
            "launchAuthorization": {
                **receipt["launchAuthorization"],
                "request": crosswired_request,
                "envelope": {
                    **receipt["launchAuthorization"]["envelope"],
                    "statement": {
                        **receipt["launchAuthorization"]["envelope"]["statement"],
                        "globalRoleRegistrySha256": (
                            crosswired_registry_sha256
                        ),
                    },
                },
            },
        }
        try:
            production_host_preflight.validate_launcher_readiness_evidence(
                crosswired_receipt,
                expected_summary,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "production host readiness accepted a validly digested but "
                "cross-wired global role registry"
            )

        try:
            production_host_preflight.validate_launcher_readiness_evidence(
                receipt,
                expected_summary,
                now_unix_seconds=expires_at,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "production host readiness accepted an authorization after "
                "exact recovery completed at or beyond expiry"
            )

        run_production_readiness.load_sealed_bootstrap_receipt = (
            lambda *, required: (receipt, 198)
            if required
            else (_ for _ in ()).throw(AssertionError("receipt must be required"))
        )
        try:
            production_host_preflight.revalidate_launcher_readiness_at_publication(
                initial_receipt=receipt,
                nonce_rollback_assurance=expected_summary,
                now_unix_seconds=expires_at,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "production host readiness publication accepted an expired "
                "authorization recovered on exact FD 198"
            )
    finally:
        run_production_readiness.load_env_bytes = originals["load_env_bytes"]
        run_production_readiness.validate_final_launcher_contract = originals[
            "validate_final_launcher_contract"
        ]
        run_production_readiness.load_sealed_bootstrap_receipt = originals[
            "load_sealed_bootstrap_receipt"
        ]
        run_production_readiness.validate_retained_nonce_rollback_assurance = (
            originals["validate_retained_nonce_rollback_assurance"]
        )
        production_host_preflight.verify_current_preflight_script_binding = (
            originals["verify_current_preflight_script_binding"]
        )


def verify_readiness_only_authority_boundary(tmp: Path) -> None:
    final_env_path = tmp / "final-mode.env"
    final_env_path.write_text(
        "CATCHPLATE_COMPLETION_VERIFICATION_MODE=final\n"
        "CATCHPLATE_FINAL_LAUNCHER_CONTRACT=descriptor-sealed-bootstrap-v3\n",
        encoding="ascii",
    )
    final_env_path.chmod(0o600)
    final_env_sha256 = sha256_prefixed(final_env_path.read_bytes())

    status, _loaded, failures = production_host_preflight.env_check(
        final_env_path,
        production_images_env=tmp / "unused-images.env",
        config_out=tmp / "unused-config.json",
        skip_config_gate=True,
    )
    if (
        status.get("ok") is True
        or not any("accepts only" in item for item in failures)
    ):
        raise AssertionError(
            f"production host preflight accepted final mode: {status} {failures}"
        )

    original_launcher_env_validation = (
        run_production_readiness.validate_launcher_trusted_env
    )
    run_production_readiness.validate_launcher_trusted_env = (
        lambda *_args, **_kwargs: {"verified": True}
    )
    try:
        try:
            production_host_preflight.enforce_readiness_only_preflight_boundary(
                SimpleNamespace(
                    env_file=str(final_env_path),
                    launcher_trusted_production_env_path=str(final_env_path),
                    launcher_trusted_production_env_sha256=final_env_sha256,
                    skip_host_check=False,
                )
            )
        except ValueError as exc:
            if (
                "requires CATCHPLATE_COMPLETION_VERIFICATION_MODE=readiness"
                not in str(exc)
            ):
                raise
        else:
            raise AssertionError(
                "launcher boundary cross-wired final mode into host readiness"
            )
    finally:
        run_production_readiness.validate_launcher_trusted_env = (
            original_launcher_env_validation
        )

    boundary = production_host_preflight.readiness_authority_boundary(
        launcher_evidence_verified=True
    )
    mutations = {
        "final verification mode": {"verificationMode": "final"},
        "trusted-host wall clock as secure time": {"secureTimeProven": True},
        "secure-time freshness authority": {
            "freshnessAuthority": "tee-secure-time"
        },
        "host bootstrap as Nitro proof": {"finalNitroExecutionProven": True},
        "host bootstrap as action authority": {"actionAuthority": True},
        "host bootstrap as authoritative TEE provenance": {
            "hostBootstrapEvidenceClassification": (
                "authoritative-final-tee-proof"
            )
        },
    }
    for label, mutation in mutations.items():
        try:
            production_host_preflight.validate_readiness_authority_boundary(
                {**boundary, **mutation}
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"production host readiness accepted {label}"
            )

    try:
        production_host_preflight.sign_readiness_preflight(
            {
                "verification_mode": "readiness",
                "readiness_only": True,
                "final_nitro_execution_proven": False,
                "ok_for_action": False,
                "authority_boundary": {
                    **boundary,
                    "finalNitroExecutionProven": True,
                },
            },
            {},
        )
    except ValueError as exc:
        if "cannot claim secure time" not in str(exc):
            raise
    else:
        raise AssertionError(
            "host-bootstrap evidence was signed after elevation to TEE proof"
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

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_response_signing_key_custody(Path(tmp_raw))

    verify_docker_binding_helpers()

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_preflight_script_descriptor_race(Path(tmp_raw).resolve())

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_launcher_authentication_precedes_env_parse(Path(tmp_raw).resolve())

    verify_launcher_import_and_alias_boundary()

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_nonce_rollback_assurance_argv_binding(Path(tmp_raw).resolve())

    with tempfile.TemporaryDirectory() as tmp_raw:
        verify_readiness_only_authority_boundary(Path(tmp_raw).resolve())

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = fixture_release_env(paths)
        set_release_artifacts(env, paths)
        set_production_images(env, paths["images_env"])
        write_env(paths["env"], env)
        # The real Compose renderer needs the complete current topology. These
        # nonexistent socket/key paths are render-only fixture inputs, not
        # provisioned authority or a passing runtime/readiness configuration.
        compose_env_path = tmp / "compose-fixture.env"
        compose_env = test_production_image_builds.production_compose_fixture_environment(env)
        write_env(compose_env_path, compose_env)
        write_kms_materials(paths["kms_materials"])
        source_digest = json.loads(paths["build"].read_text(encoding="utf-8"))["metadata"]["source_tree_digest"]
        with test_production_handoff.fixture_image_measurements():
            production_images = generate_release_provenance.production_image_inventory(
                build_path=paths["build"],
                published_path=paths["published"],
                images_env_path=paths["images_env"],
                expected_source_tree_digest=source_digest,
                expected_source_contract=build_production_images.source_contract(
                    development_dirty_tree=False
                ),
            )
        def offline_compose_run(command: list[str]) -> str:
            expected_command = [
                "docker", "compose", "--env-file", str(compose_env_path),
                "-f", str(ROOT / "docker-compose.production.yml"),
                "config", "--format", "json",
            ]
            if command != expected_command:
                raise AssertionError(f"unexpected fixture Compose command: {command!r}")
            # Render the actual YAML with the prepared, digest-pinned plugin. No
            # model is mocked, and Docker discovery/daemon calls are not allowed.
            result = run_production_readiness.run_measured_command(
                [env[run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV],
                 "--host", f"unix://{env[run_production_readiness.DOCKER_UNIX_SOCKET_ENV]}",
                 *command[2:]],
                setting=run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV,
                expected_digest=env[run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV],
                cwd=ROOT,
                env=run_production_readiness.docker_subprocess_environment(
                    {name: value for name, value in os.environ.items() if not name.startswith("CATCHPLATE_")},
                    Path(env[run_production_readiness.DOCKER_UNIX_SOCKET_ENV]),
                ),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True,
            )
            return result.stdout.strip()

        with patch.object(generate_release_provenance, "run", offline_compose_run):
            compose_canonical, compose_summary = generate_release_provenance.production_compose_model(
                compose_file=ROOT / "docker-compose.production.yml",
                env_file=compose_env_path,
                images=production_images,
            )
        compose_images = compose_summary.get("images", {})
        if set(compose_images) != {
            "catchplate",
            "audit-anchor",
            "policy-authority-runtime",
            "policy-authority-verifier",
            "policy-authority-issuer",
            "policy-authority-executor",
            "policy-authority-external-witness-ready",
            "custody-runtime",
            "decision-gate-rs",
            "response-v2-generation-bootstrap",
            "response-v2-state-authority",
            "response-v2-credential-transport",
            "response-v2-policy-proof-verifier",
            "response-v2-immutable-artifact-ledger",
            "response-v2-release-attestor-publisher",
            "response-v2-cleanup-watchdog",
            "response-v2-custody-router",
            "response-v2-generation-activation",
        }:
            raise AssertionError(
                f"production Compose proof did not retain the exact service set: {compose_summary}"
            )
        if compose_images["custody-runtime"] != compose_images["decision-gate-rs"]:
            raise AssertionError(
                "production custody is not bound to the immutable decision-gate image"
            )
        if set(compose_images.values()) != {
            env["CATCHPLATE_CONTROL_PLANE_IMAGE"],
            env["CATCHPLATE_DECISION_GATE_IMAGE"],
        }:
            raise AssertionError(f"production Compose proof did not bind immutable images: {compose_summary}")
        for service, image in compose_images.items():
            control_image = service in {"catchplate", "audit-anchor"} or service.startswith("policy-authority-")
            expected_image = env["CATCHPLATE_CONTROL_PLANE_IMAGE" if control_image else "CATCHPLATE_DECISION_GATE_IMAGE"]
            if image != expected_image:
                raise AssertionError(f"production service uses the wrong image family: {service}")
        rendered_model = json.loads(compose_canonical)
        # Only negative inputs are supplied by this stub; the positive model
        # above came from the actual digest-pinned, daemon-disconnected renderer.
        for label, mutate, expected_error in (
            ("missing authority service", lambda model: model["services"].pop("policy-authority-issuer"), "services must be exactly"),
            ("extra service", lambda model: model["services"].__setitem__("unreviewed-service", {}), "services must be exactly"),
            ("wrong authority image", lambda model: model["services"]["policy-authority-issuer"].__setitem__("image", env["CATCHPLATE_DECISION_GATE_IMAGE"]), "does not use its immutable published image"),
            ("wrong custody image", lambda model: model["services"]["response-v2-state-authority"].__setitem__("image", env["CATCHPLATE_CONTROL_PLANE_IMAGE"]), "does not use its immutable published image"),
            ("build override", lambda model: model["services"]["policy-authority-executor"].__setitem__("build", {"context": "."}), "must not contain a build directive"),
        ):
            candidate = copy.deepcopy(rendered_model)
            mutate(candidate)
            with patch.object(generate_release_provenance, "run", return_value=json.dumps(candidate)):
                try:
                    generate_release_provenance.production_compose_model(
                        compose_file=ROOT / "docker-compose.production.yml",
                        env_file=compose_env_path,
                        images=production_images,
                    )
                except ValueError as exc:
                    if expected_error not in str(exc):
                        raise AssertionError(f"{label} reached the wrong guard: {exc}") from exc
                else:
                    raise AssertionError(f"production Compose accepted {label}")
        expected_images = generate_release_provenance.merge_production_images_env.validate_production_images(
            env["CATCHPLATE_PRODUCTION_IMAGES"]
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
                env_file=compose_env_path,
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
            or (runtime_model["services"]["catchplate"]).get("compose_user")
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
                "trusted-host readiness Compose path did not directly execute "
                f"the measured plugin: {measured_commands}"
            )
        _, mismatch_failures = production_host_preflight.production_compose_check(
            compose_file=ROOT / "docker-compose.production.yml",
            env_file=compose_env_path,
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
            env_file=compose_env_path,
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
        if (
            output.get("verification_mode") != "readiness"
            or output.get("readiness_only") is not True
            or output.get("final_nitro_execution_proven") is not False
            or output.get("ok_for_action") is not False
            or output.get("authority_boundary")
            != production_host_preflight.readiness_authority_boundary(
                launcher_evidence_verified=False
            )
            or "authenticity" in output
        ):
            raise AssertionError(
                "manual host preflight crossed the readiness-only authority "
                f"boundary: {output}"
            )
        if "prod-admin-token-32-bytes-minimum-value" in detail(result):
            raise AssertionError("preflight leaked env secrets")
        if output.get("checks", {}).get("release_artifacts", {}).get("image_signatures", {}).get("covers_published_production_images") is not True:
            raise AssertionError(f"preflight did not check published image signature coverage: {output}")
        if output.get("checks", {}).get("release_artifacts", {}).get("production_images_published", {}).get("ok") is not True:
            raise AssertionError(f"preflight did not validate published image provenance: {output}")
        if output.get("checks", {}).get("release_artifacts", {}).get("bench", {}).get("p99_ms") != 6.0:
            raise AssertionError(f"preflight did not include benchmark evidence: {output}")
        production_env_file = output.get("checks", {}).get("production_env", {}).get("file", {})
        nonce_assurance = output.get("checks", {}).get(
            "nonce_rollback_assurance"
        )
        if nonce_assurance != {
            "apiVersion": (
                run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
            ),
            "enforcement": "not-native-launcher-enforced",
            "verified": False,
        }:
            raise AssertionError(
                f"manual preflight claimed launcher nonce assurance: {nonce_assurance}"
            )
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

        launcher_readiness_security_env = {
            **env,
            "CATCHPLATE_COMPLETION_VERIFICATION_MODE": "readiness",
            "CATCHPLATE_FINAL_LAUNCHER_CONTRACT": (
                "descriptor-sealed-bootstrap-v3"
            ),
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
            policy_trusted_public_key_id=launcher_readiness_security_env[
                run_production_readiness.POLICY_TRUST_ROOT_ID_ENV
            ],
            policy_identity_verification=str(paths["policy_identity"]),
            policy_activation_verification=str(paths["activation_report"]),
            policy_activation_signature=str(paths["activation_signature"]),
            policy_activation_trusted_public_key=str(paths["activation_key"]),
            policy_activation_trusted_public_key_id=launcher_readiness_security_env[
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV
            ],
            reproducible_build_verification=str(paths["reproducibility_report"]),
            reproducible_build_signature=str(paths["reproducibility_signature"]),
            reproducible_build_trusted_public_key=str(paths["reproducibility_key"]),
            reproducible_build_trusted_public_key_id=launcher_readiness_security_env[
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV
            ],
        )
        security_status, security_failures = (
            production_host_preflight.release_security_evidence_check(
                security_args,
                output["checks"]["release_artifacts"],
                launcher_readiness_security_env,
            )
        )
        if security_failures or security_status.get("ok") is not True:
            raise AssertionError(
                "launcher-bound readiness preflight rejected env-bound verifier "
                f"trust roots: {security_status} {security_failures}"
            )
        alternate_args = SimpleNamespace(**vars(security_args))
        alternate_args.policy_trusted_public_key = str(tmp / "caller-policy.pub.pem")
        _, alternate_failures = production_host_preflight.release_security_evidence_check(
            alternate_args,
            output["checks"]["release_artifacts"],
            launcher_readiness_security_env,
        )
        if not any("does not exactly match" in failure for failure in alternate_failures):
            raise AssertionError(
                "launcher-bound readiness accepted a caller-selected policy "
                f"trust root: {alternate_failures}"
            )
        wrong_spki_env = {
            **launcher_readiness_security_env,
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
                "launcher-bound readiness accepted trust-root bytes under a "
                f"wrong SPKI pin: {wrong_spki_failures}"
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
            "encryption_context": {"material": "debug-material", "service": "catchplate"},
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
        env["CATCHPLATE_PRODUCTION_IMAGES"] = "registry.prod.catchplate.dev/catchplate/control@sha256:" + "c" * 64
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
