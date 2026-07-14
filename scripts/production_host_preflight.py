#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import shlex
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import generate_production_handoff as handoff  # noqa: E402
import generate_release_provenance  # noqa: E402
import merge_production_images_env  # noqa: E402
import prepare_aws_kms_materials  # noqa: E402
import production_release_input_preflight  # noqa: E402
import run_production_readiness  # noqa: E402
import verify_production_policy_identity  # noqa: E402

REQUIRED_MATERIALS = {"broker-kek", "decision-gate-ca"}
TEST_ONLY_BYPASS_ENV = "SERVERWARE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def write_result(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def semantic_result_digest(path: Path) -> str:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"config gate result must be a JSON object: {path}")
    payload = dict(parsed)
    payload.pop("result_path", None)
    payload.pop("result_sha256", None)
    return handoff.sha256_prefixed_bytes(canonical_json(payload).encode("utf-8"))


def set_readiness_env_metadata(env: dict[str, str], *, env_file: Path, production_images_env: Path) -> None:
    env["SERVERWARE_PRODUCTION_READINESS_ENV_PATH"] = str(env_file)
    env["SERVERWARE_PRODUCTION_READINESS_ENV_SHA256"] = handoff.file_summary(env_file, "production-readiness-env")["sha256"]
    env["SERVERWARE_PRODUCTION_IMAGES_ENV_PATH"] = str(production_images_env)
    if production_images_env.exists():
        env["SERVERWARE_PRODUCTION_IMAGES_ENV_SHA256"] = handoff.file_summary(production_images_env, "production-images-env")["sha256"]


def enforce_test_only_bypass(args: argparse.Namespace) -> None:
    if not (args.skip_host_check or args.skip_config_gate):
        return
    if os.environ.get(TEST_ONLY_BYPASS_ENV) == "1":
        return
    raise SystemExit(
        f"--skip-host-check and --skip-config-gate are test-only; set {TEST_ONLY_BYPASS_ENV}=1 in fixture tests"
    )


def host_check(*, skip_host_check: bool) -> tuple[dict[str, Any], list[str]]:
    system = platform.system()
    status = {
        "ok": True,
        "skipped": skip_host_check,
        "system": system,
        "machine": platform.machine(),
        "linux": system == "Linux",
        "nitro_nsm_device": Path("/dev/nsm").exists(),
        "apparmor_sysfs": Path("/sys/module/apparmor").exists(),
    }
    failures = []
    if not skip_host_check:
        for key, message in (
            ("linux", "production host must be Linux"),
            ("nitro_nsm_device", "production host must expose /dev/nsm"),
            ("apparmor_sysfs", "production host must expose AppArmor sysfs"),
        ):
            if status[key] is not True:
                failures.append(message)
    status["ok"] = not failures
    return status, failures


def runtime_trust_materials_check(
    env: dict[str, str],
    *,
    skip_host_check: bool,
) -> tuple[dict[str, Any], list[str]]:
    tls_dir = Path(env.get("SERVERWARE_CONTROL_PLANE_TLS_DIR", ""))
    anchor_tls_dir = Path(env.get("SERVERWARE_AUDIT_ANCHOR_TLS_DIR", ""))
    helper_dir = Path(env.get("SERVERWARE_ATTESTATION_HELPER_DIR", ""))
    status: dict[str, Any] = {
        "ok": False,
        "skipped": skip_host_check,
        "tls_dir": str(tls_dir),
        "anchor_tls_dir": str(anchor_tls_dir),
        "helper_dir": str(helper_dir),
        "tls_files": [],
        "helper_files": [],
        "anchor_tls_files": [],
        "proof_files": [],
        "proof_collector_files": [],
        "secret_values_redacted": True,
    }
    if skip_host_check:
        status["ok"] = True
        return status, []

    failures: list[str] = []
    tls_files = {
        "certificate": tls_dir / "serverware.crt",
        "private_key": tls_dir / "serverware.key",
        "ca_bundle": tls_dir / "ca.pem",
    }
    for label, path in tls_files.items():
        if not path.is_file() or path.stat().st_size == 0:
            failures.append(f"control-plane TLS {label} is missing or empty: {path}")
        else:
            status["tls_files"].append(path.name)

    key_path = tls_files["private_key"]
    if key_path.is_file():
        key_mode = stat.S_IMODE(key_path.stat().st_mode)
        status["private_key_mode"] = oct(key_mode)
        if key_mode & 0o077:
            failures.append("control-plane TLS private key must not be readable or writable by group/other")

    if all(path.is_file() and path.stat().st_size > 0 for path in tls_files.values()):
        try:
            certificate = x509.load_pem_x509_certificate(tls_files["certificate"].read_bytes())
            private_key = serialization.load_pem_private_key(tls_files["private_key"].read_bytes(), password=None)
            cert_public = certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            key_public = private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if cert_public != key_public:
                failures.append("control-plane TLS certificate does not match its private key")
            now = datetime.now(timezone.utc)
            if not (certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc):
                failures.append("control-plane TLS certificate is not currently valid")
            try:
                dns_names = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                dns_names = []
            status["certificate_dns_names"] = sorted(dns_names)
            if "serverware" not in dns_names:
                failures.append("control-plane TLS certificate must include the internal DNS SAN serverware")
            issuers = x509.load_pem_x509_certificates(tls_files["ca_bundle"].read_bytes())
            if not issuers:
                failures.append("control-plane TLS CA bundle contains no certificates")
            elif not any(_directly_issued_by(certificate, issuer) for issuer in issuers):
                failures.append("control-plane TLS certificate is not directly issued by the supplied CA bundle")
            status["certificate_not_after"] = certificate.not_valid_after_utc.isoformat()
            status["ca_certificates"] = len(issuers)
        except Exception as exc:
            failures.append(f"control-plane TLS material is invalid: {exc}")

    anchor_tls_files = {
        "certificate": anchor_tls_dir / "audit-anchor.crt",
        "private_key": anchor_tls_dir / "audit-anchor.key",
    }
    for label, path in anchor_tls_files.items():
        if not path.is_file() or path.stat().st_size == 0:
            failures.append(f"audit-anchor TLS {label} is missing or empty: {path}")
        else:
            status["anchor_tls_files"].append(path.name)
    anchor_key_path = anchor_tls_files["private_key"]
    if anchor_key_path.is_file():
        anchor_key_mode = stat.S_IMODE(anchor_key_path.stat().st_mode)
        status["anchor_private_key_mode"] = oct(anchor_key_mode)
        if anchor_key_mode & 0o077:
            failures.append("audit-anchor TLS private key must not be readable or writable by group/other")
    if all(path.is_file() and path.stat().st_size > 0 for path in anchor_tls_files.values()):
        try:
            certificate = x509.load_pem_x509_certificate(anchor_tls_files["certificate"].read_bytes())
            private_key = serialization.load_pem_private_key(anchor_tls_files["private_key"].read_bytes(), password=None)
            cert_public = certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            key_public = private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if cert_public != key_public:
                failures.append("audit-anchor TLS certificate does not match its private key")
            now = datetime.now(timezone.utc)
            if not (certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc):
                failures.append("audit-anchor TLS certificate is not currently valid")
            try:
                dns_names = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                dns_names = []
            status["anchor_certificate_dns_names"] = sorted(dns_names)
            if "audit-anchor" not in dns_names:
                failures.append("audit-anchor TLS certificate must include the internal DNS SAN audit-anchor")
            if tls_files["ca_bundle"].is_file():
                issuers = x509.load_pem_x509_certificates(tls_files["ca_bundle"].read_bytes())
                if not any(_directly_issued_by(certificate, issuer) for issuer in issuers):
                    failures.append("audit-anchor TLS certificate is not directly issued by the control-plane CA bundle")
            status["anchor_certificate_not_after"] = certificate.not_valid_after_utc.isoformat()
        except Exception as exc:
            failures.append(f"audit-anchor TLS material is invalid: {exc}")

    helper_settings = (
        "SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE",
        "SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE",
        "SERVERWARE_DATA_PLANE_RECIPIENT_ATTESTATION_COMMAND",
        "SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND",
        "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND",
        "SERVERWARE_CONTROL_PLANE_ATTESTATION_VERIFY_COMMAND",
    )
    for name in helper_settings:
        try:
            words = shlex.split(env.get(name, ""))
        except ValueError:
            words = []
        if not words or not Path(words[0]).is_absolute() or Path(words[0]).parent != Path("/opt/serverware/bin"):
            failures.append(f"{name} must name an absolute executable under /opt/serverware/bin")
            continue
        host_path = helper_dir / Path(words[0]).name
        if not host_path.is_file() or not os.access(host_path, os.X_OK):
            failures.append(f"attestation helper is missing or not executable: {host_path}")
            continue
        helper_mode = stat.S_IMODE(host_path.stat().st_mode)
        if helper_mode & 0o022:
            failures.append(f"attestation helper must not be writable by group/other: {host_path}")
        status["helper_files"].append(host_path.name)

    try:
        collector_words = shlex.split(env.get("SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND", ""))
    except ValueError:
        collector_words = []
    if (
        len(collector_words) != 1
        or not Path(collector_words[0]).is_absolute()
        or Path(collector_words[0]).parent != Path("/opt/serverware/bin")
    ):
        failures.append("SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND must name one absolute executable under /opt/serverware/bin")
    else:
        collector_path = helper_dir / Path(collector_words[0]).name
        if not collector_path.is_file() or not os.access(collector_path, os.X_OK):
            failures.append(f"response-proof collector is missing or not executable: {collector_path}")
        else:
            collector_mode = stat.S_IMODE(collector_path.stat().st_mode)
            if collector_mode & 0o022:
                failures.append(f"response-proof collector must not be writable by group/other: {collector_path}")
            status["proof_collector_files"].append(collector_path.name)

    proof_paths = {
        "ca_bundle": Path(env.get("SERVERWARE_PROXY_PROOF_CA_BUNDLE", "")),
        "collector_private_key": Path(env.get("SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY", "")),
        "collector_public_key": Path(env.get("SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY", "")),
        "verifier_public_key": Path(env.get("SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY", "")),
    }
    for label, path in proof_paths.items():
        if not path.is_file() or path.stat().st_size == 0:
            failures.append(f"response-proof {label} is missing or empty: {path}")
        else:
            status["proof_files"].append(path.name)
    collector_private_path = proof_paths["collector_private_key"]
    if collector_private_path.is_file():
        private_mode = stat.S_IMODE(collector_private_path.stat().st_mode)
        status["proof_collector_private_key_mode"] = oct(private_mode)
        if private_mode & 0o077:
            failures.append("response-proof collector private key must not be readable or writable by group/other")
    for label in ("collector_public_key", "verifier_public_key", "ca_bundle"):
        path = proof_paths[label]
        if path.is_file() and stat.S_IMODE(path.stat().st_mode) & 0o022:
            failures.append(f"response-proof {label} must not be writable by group/other")

    if proof_paths["ca_bundle"].is_file():
        try:
            proof_ca_certificates = x509.load_pem_x509_certificates(proof_paths["ca_bundle"].read_bytes())
            if not proof_ca_certificates:
                raise ValueError("contains no certificates")
            status["proof_ca_certificates"] = len(proof_ca_certificates)
        except Exception as exc:
            failures.append(f"response-proof CA bundle is invalid: {exc}")

    if all(proof_paths[label].is_file() for label in ("collector_private_key", "collector_public_key", "verifier_public_key")):
        try:
            collector_private = serialization.load_pem_private_key(
                proof_paths["collector_private_key"].read_bytes(),
                password=None,
            )
            collector_public = serialization.load_pem_public_key(proof_paths["collector_public_key"].read_bytes())
            verifier_public = serialization.load_pem_public_key(proof_paths["verifier_public_key"].read_bytes())
            if not isinstance(collector_private, Ed25519PrivateKey):
                raise ValueError("collector private key is not Ed25519")
            if not isinstance(collector_public, Ed25519PublicKey):
                raise ValueError("collector public key is not Ed25519")
            if not isinstance(verifier_public, Ed25519PublicKey):
                raise ValueError("vendor verifier public key is not Ed25519")
            collector_private_der = collector_private.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            collector_public_der = collector_public.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if collector_private_der != collector_public_der:
                raise ValueError("collector private and public keys do not match")
            verifier_public_der = verifier_public.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            collector_key_id = "sha256:" + hashlib.sha256(collector_public_der).hexdigest()
            verifier_key_id = "sha256:" + hashlib.sha256(verifier_public_der).hexdigest()
            if collector_key_id != env.get("SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID"):
                raise ValueError("collector public key does not match SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID")
            if verifier_key_id != env.get("SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID"):
                raise ValueError("vendor verifier public key does not match SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID")
            status["proof_collector_key_id"] = collector_key_id
            status["proof_verifier_key_id"] = verifier_key_id
        except Exception as exc:
            failures.append(f"response-proof signing material is invalid: {exc}")

    status["tls_files"] = sorted(status["tls_files"])
    status["anchor_tls_files"] = sorted(status["anchor_tls_files"])
    status["helper_files"] = sorted(status["helper_files"])
    status["proof_files"] = sorted(status["proof_files"])
    status["proof_collector_files"] = sorted(status["proof_collector_files"])
    status["ok"] = not failures
    return status, failures


def _directly_issued_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        certificate.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


def env_check(
    path: Path,
    *,
    production_images_env: Path,
    config_out: Path,
    skip_config_gate: bool,
) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "path": str(path),
        "env_keys": [],
        "config_gate": {"skipped": skip_config_gate},
        "secret_values_redacted": True,
    }
    if path.exists():
        status["file"] = handoff.file_summary(path, "production-readiness-env")
    failures: list[str] = []
    try:
        loaded = run_production_readiness.load_env_file(path)
    except Exception as exc:
        status["error"] = str(exc)
        return status, {}, [f"production readiness env is invalid: {exc}"]
    status["env_keys"] = sorted(loaded)
    if skip_config_gate:
        status["ok"] = True
        return status, loaded, failures
    env = os.environ.copy()
    env.update(loaded)
    set_readiness_env_metadata(env, env_file=path, production_images_env=production_images_env)
    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_production_readiness.py",
            "--mode",
            "config",
            "--out",
            str(config_out),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    config_gate: dict[str, Any] = {
        "ok": result.returncode == 0,
        "out": str(config_out),
        "secret_values_redacted": True,
    }
    if config_out.exists():
        config_gate["file"] = handoff.file_summary(config_out, "production-readiness-config")
        try:
            config_gate["semantic_sha256"] = semantic_result_digest(config_out)
        except Exception:
            config_gate["semantic_sha256"] = None
    if result.returncode == 0:
        try:
            parsed = json.loads(result.stdout)
            config_gate["result_sha256"] = parsed.get("result_sha256")
        except json.JSONDecodeError:
            config_gate["result_sha256"] = None
    else:
        config_gate["error"] = "production readiness config gate failed; see config output artifact"
        failures.append("production readiness config gate failed")
    status["config_gate"] = config_gate
    status["ok"] = not failures
    return status, loaded, failures


def production_images_env_check(path: Path) -> tuple[dict[str, Any], str, list[str]]:
    status = handoff.production_images_env_status(path)
    if path.exists():
        status["file"] = handoff.file_summary(path, "production-images-env")
    status["ok"] = status["status"] == "valid"
    if status["ok"]:
        raw = merge_production_images_env.load_images_fragment(path)
        return status, raw, []
    return status, "", [f"production images env is {status['status']}: {status.get('error', path)}"]


def env_merge_check(loaded_env: dict[str, str], production_images_value: str) -> tuple[dict[str, Any], list[str]]:
    env_value = loaded_env.get(merge_production_images_env.KEY, "")
    status = {
        "ok": env_value == production_images_value,
        "key": merge_production_images_env.KEY,
        "production_env_has_key": bool(env_value),
        "matches_images_env": env_value == production_images_value,
        "secret_values_redacted": True,
    }
    if status["ok"]:
        return status, []
    return status, ["production readiness env does not match .tmp/production-images.env SERVERWARE_PRODUCTION_IMAGES"]


def published_images_check(
    path: Path,
    *,
    production_images: dict[str, Any],
    expected_images: list[dict[str, str]],
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "path": str(path),
        "exists": path.exists(),
        "secret_values_redacted": True,
    }
    if not path.exists():
        return status, [f"production images published artifact does not exist: {path}"]
    failures: list[str] = []
    try:
        published = handoff.load_json(path, "production images published artifact")
        if published.get("ok") is not True:
            raise ValueError("production images published artifact is not ok")
        build_by_service = {
            str(item["service"]): item
            for item in production_images.get("images", [])
            if isinstance(item, dict) and item.get("service") and item.get("image_id")
        }
        expected_refs = sorted(item["ref"] for item in expected_images)
        expected_digests = sorted(item["digest"] for item in expected_images)
        images = published.get("images")
        if not isinstance(images, list) or not images:
            raise ValueError("production images published artifact has no images")
        published_refs: list[str] = []
        published_digests: list[str] = []
        published_services: list[str] = []
        for item in images:
            if not isinstance(item, dict):
                raise ValueError(f"published image entry must be an object: {item!r}")
            service = str(item.get("service") or "")
            if not service:
                raise ValueError("published image entry is missing service")
            local_image_id = handoff.require_sha256(item.get("local_image_id"), f"{service} local_image_id")
            expected_build = build_by_service.get(service)
            if expected_build is None:
                raise ValueError(f"published image service is not in current build artifact: {service}")
            if local_image_id != str(expected_build["image_id"]):
                raise ValueError(
                    "published production images do not match current no-shell build: "
                    f"service={service} published={local_image_id} build={expected_build['image_id']}"
                )
            handoff.require_sha256(item.get("remote_image_id"), f"{service} remote_image_id")
            if service == "serverware-decision-gate":
                published_binary = handoff.require_sha256(item.get("binary_digest"), "published decision-gate binary digest")
                expected_binary = handoff.require_sha256(expected_build.get("binary_digest"), "built decision-gate binary digest")
                if published_binary != expected_binary:
                    raise ValueError("published decision-gate executable does not match the measured build executable")
            repo_digest = item.get("repo_digest")
            if not isinstance(repo_digest, str):
                raise ValueError(f"{service} repo_digest must be a digest-pinned ref")
            parsed = merge_production_images_env.validate_production_images(repo_digest)
            published_refs.append(parsed[0]["ref"])
            published_digests.append(parsed[0]["digest"])
            published_services.append(service)
        if sorted(published_services) != sorted(build_by_service):
            raise ValueError(
                "published production image services do not match current build artifact: "
                f"published={sorted(published_services)} build={sorted(build_by_service)}"
            )
        if sorted(published_refs) != expected_refs:
            raise ValueError(
                "published production image refs do not match .tmp/production-images.env: "
                f"published={sorted(published_refs)} env={expected_refs}"
            )
        remote_no_shell = published.get("remote_no_shell")
        if not isinstance(remote_no_shell, dict) or remote_no_shell.get("ok") is not True:
            raise ValueError("published production images did not pass remote no-shell verification")
        env_value = published.get("env") if isinstance(published.get("env"), dict) else {}
        if env_value.get(merge_production_images_env.KEY) and env_value[merge_production_images_env.KEY] != ",".join(expected_refs):
            raise ValueError("published artifact env value does not match .tmp/production-images.env")
        status.update(
            {
                "file": handoff.file_summary(path, "production-images-published"),
                "source_build_file": published.get("source_build_file"),
                "services": sorted(published_services),
                "repo_digests": sorted(published_refs),
                "image_digests": sorted(published_digests),
                "expected_image_digests": expected_digests,
            }
        )
    except Exception as exc:
        failures.append(f"production images published artifact is invalid: {exc}")
        status["error"] = str(exc)
    status["ok"] = not failures
    return status, failures


def artifact_check(
    args: argparse.Namespace,
    expected_images: list[dict[str, str]],
    expected_binary_digest: str | None,
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    status: dict[str, Any] = {"ok": False}
    try:
        production_images = handoff.verify_production_images_build(Path(args.production_images_build), check_current_tree=True)
        published_images, published_failures = published_images_check(
            Path(args.production_images_published),
            production_images=production_images,
            expected_images=expected_images,
        )
        failures.extend(published_failures)
        release_summary = handoff.verify_summary(
            Path(args.release_provenance_summary),
            label="release provenance summary",
            pass_key="release_provenance",
            digest_key="provenance_digest",
        )
        image_summary = handoff.verify_summary(
            Path(args.image_signatures_summary),
            label="image signatures summary",
            pass_key="image_signatures",
            digest_key="image_signature_bundle_digest",
        )
        bench = handoff.verify_bench(Path(args.bench))
        production_gate_binary = next(
            (
                item.get("binary_digest")
                for item in production_images["images"]
                if item.get("service") == "serverware-decision-gate"
            ),
            None,
        )
        if production_gate_binary != bench["data_plane_binary_digest"]:
            raise ValueError("decision-gate benchmark binary digest does not match the production image binary")
        if not expected_binary_digest:
            raise ValueError("production env is missing SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST")
        if bench["data_plane_binary_digest"] != expected_binary_digest:
            raise ValueError(
                "decision-gate benchmark binary digest does not match "
                "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"
            )
        release_document = handoff.verify_release_provenance_document(
            Path(args.release_provenance),
            summary_digest=release_summary["digest"],
            expected_source_tree_digest=production_images["source_tree_digest"],
        )
        signatures = handoff.image_signature_scope(
            Path(args.image_signatures),
            [item["image_id"] for item in production_images["images"]],
            summary_digest=image_summary["digest"],
            expected_provenance_digest=release_summary["digest"],
            expected_published_image_digests=[item["digest"] for item in expected_images],
            expected_published_image_refs=[item["ref"] for item in expected_images],
            expected_release_bindings=release_document,
        )
        if signatures["covers_published_production_images"] is not True:
            failures.append("image signatures do not cover the published production image digests")
        if signatures["covers_published_production_image_refs"] is not True:
            failures.append("image signatures do not cover the published production image refs")
        status.update(
            {
                "production_images": production_images,
                "production_images_published": published_images,
                "release_provenance": release_summary,
                "release_provenance_document": release_document,
                "image_signatures_summary": image_summary,
                "image_signatures": signatures,
                "bench": bench,
            }
        )
    except Exception as exc:
        failures.append(f"release artifact check failed: {exc}")
        status["error"] = str(exc)
    status["ok"] = not failures
    return status, failures


def release_security_evidence_check(
    args: argparse.Namespace,
    release_artifacts: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {"ok": False, "secret_values_redacted": True}
    failures: list[str] = []
    try:
        identity = verify_production_policy_identity.verify_persisted_report(
            bundle_path=Path(args.policy_bundle),
            trusted_public_key_path=Path(args.policy_trusted_public_key),
            report_path=Path(args.policy_identity_verification),
        )
        bench = release_artifacts.get("bench") or {}
        if bench.get("policy_hash") != identity["policyHash"]:
            raise ValueError("decision-gate benchmark policy hash does not match the identity-verified policy")

        activation = production_release_input_preflight.verify_externally_signed_report(
            report_path=Path(args.policy_activation_verification),
            signature_path=Path(args.policy_activation_signature),
            trusted_public_key_path=Path(args.policy_activation_trusted_public_key),
            purpose=production_release_input_preflight.ACTIVATION_PURPOSE,
            api_version=production_release_input_preflight.ACTIVATION_API_VERSION,
            kind=production_release_input_preflight.ACTIVATION_KIND,
        )
        if activation["report"].get("production_mode") is not True or activation["report"].get("environment") != "production":
            raise ValueError("policy activation verification is not production evidence")
        if activation["report"].get("candidate_policy_hash") != identity["policyHash"]:
            raise ValueError("policy activation candidate hash does not match the identity-verified policy")

        reproducibility = production_release_input_preflight.verify_externally_signed_report(
            report_path=Path(args.reproducible_build_verification),
            signature_path=Path(args.reproducible_build_signature),
            trusted_public_key_path=Path(args.reproducible_build_trusted_public_key),
            purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
            api_version=production_release_input_preflight.REPRODUCIBILITY_API_VERSION,
            kind=production_release_input_preflight.REPRODUCIBILITY_KIND,
        )
        reproducibility_report = reproducibility["report"]
        if reproducibility_report.get("reproducible") is not True:
            raise ValueError("reproducible-build verification did not prove matching artifacts")
        reproducibility_scope = reproducibility_report.get("scope")
        if not isinstance(reproducibility_scope, dict) or reproducibility_scope.get("independent_execution_proven") is not True:
            raise ValueError("reproducible-build verification did not prove two independent trusted builders")
        production_images = release_artifacts.get("production_images") or {}
        if reproducibility_report.get("source_tree_digest") != production_images.get("source_tree_digest"):
            raise ValueError("reproducible-build source digest does not match the production build")
        expected_images = {
            item.get("service"): item.get("image_id")
            for item in production_images.get("images") or []
            if isinstance(item, dict)
        }
        reproduced_images = {
            item.get("service"): item.get("image_id")
            for item in reproducibility_report.get("images") or []
            if isinstance(item, dict)
        }
        if reproduced_images != expected_images:
            raise ValueError("reproducible-build image IDs do not match the production build")
        production_gate = next(
            (item for item in production_images.get("images") or [] if item.get("service") == "serverware-decision-gate"),
            {},
        )
        reproduced_gate = next(
            (item for item in reproducibility_report.get("images") or [] if item.get("service") == "serverware-decision-gate"),
            {},
        )
        if reproduced_gate.get("rust_binary_sha256") != production_gate.get("binary_digest"):
            raise ValueError("reproducible-build Rust binary digest does not match the production build")
        status.update(
            {
                "policy_identity": identity,
                "policy_activation": {key: value for key, value in activation.items() if key != "report"},
                "reproducible_builds": {
                    **{key: value for key, value in reproducibility.items() if key != "report"},
                    "scope": reproducibility_scope,
                    "sourceTreeDigest": reproducibility_report.get("source_tree_digest"),
                    "productionBuildBound": True,
                },
                "benchmarkPolicyBound": True,
            }
        )
    except Exception as exc:
        failures.append(f"release security evidence check failed: {exc}")
        status["error"] = str(exc)
    status["ok"] = not failures
    return status, failures


def release_artifact_mounts_check(
    env: dict[str, str],
    *,
    release_provenance: Path,
    image_signatures: Path,
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {"ok": False, "artifacts": [], "secret_values_redacted": True}
    failures: list[str] = []
    expected = {
        "release-provenance": (
            Path(env.get("SERVERWARE_RELEASE_PROVENANCE_FILE", "")),
            release_provenance,
        ),
        "image-signatures": (
            Path(env.get("SERVERWARE_IMAGE_SIGNATURES_FILE", "")),
            image_signatures,
        ),
    }
    for label, (mounted_path, approved_path) in expected.items():
        item: dict[str, Any] = {
            "label": label,
            "mounted_path": str(mounted_path),
            "approved_path": str(approved_path),
        }
        if not mounted_path.is_absolute():
            failures.append(f"{label} production mount path must be absolute")
        elif mounted_path.is_symlink():
            failures.append(f"{label} production mount path must not be a symlink: {mounted_path}")
        elif not mounted_path.is_file() or mounted_path.stat().st_size == 0:
            failures.append(f"{label} production mount artifact is missing or empty: {mounted_path}")
        elif not approved_path.is_file():
            failures.append(f"{label} approved release artifact is missing: {approved_path}")
        else:
            mounted_summary = handoff.file_summary(mounted_path, f"mounted-{label}")
            approved_summary = handoff.file_summary(approved_path, f"approved-{label}")
            mode = stat.S_IMODE(mounted_path.stat().st_mode)
            item.update(
                {
                    "sha256": mounted_summary["sha256"],
                    "bytes": mounted_summary["bytes"],
                    "mode": oct(mode),
                    "matches_approved_artifact": mounted_summary["sha256"] == approved_summary["sha256"],
                }
            )
            if mode & 0o022:
                failures.append(f"{label} production mount artifact must not be writable by group/other")
            if mounted_summary["sha256"] != approved_summary["sha256"]:
                failures.append(f"{label} production mount artifact does not match the approved release artifact")
        status["artifacts"].append(item)
    status["ok"] = not failures
    return status, failures


def production_compose_check(
    *,
    compose_file: Path,
    env_file: Path,
    expected_images: list[dict[str, str]],
    expected_digest: str | None,
    skip_host_check: bool,
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "skipped": skip_host_check,
        "file": str(compose_file),
        "secret_values_redacted": True,
    }
    if skip_host_check:
        status["ok"] = True
        return status, []
    try:
        refs = {item.get("name"): item.get("ref") for item in expected_images}
        images = {
            "serverware-control": {"repo_digests": [refs["control"]]},
            "serverware-decision-gate": {"repo_digests": [refs["decision-gate"]]},
        }
        _, summary = generate_release_provenance.production_compose_model(
            compose_file=compose_file,
            env_file=env_file,
            images=images,
        )
        status.update(summary)
        if summary["sha256"] != expected_digest:
            raise ValueError(
                "rendered production Compose digest does not match signed release provenance: "
                f"rendered={summary['sha256']} provenance={expected_digest}"
            )
        status["ok"] = True
        return status, []
    except Exception as exc:
        status["error"] = str(exc)
        return status, [f"production Compose check failed: {exc}"]


def ciphertext_blob(config: dict[str, Any], material: str) -> bytes:
    path = config.get("ciphertext_blob_path") or config.get("ciphertextBlobPath")
    if isinstance(path, str) and path:
        if not Path(path).is_file():
            raise ValueError(f"material {material} ciphertext blob path is not a file")
        return Path(path).read_bytes()
    raw = config.get("ciphertext_blob_b64") or config.get("ciphertextBlobB64")
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"material {material} missing ciphertext blob")
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except Exception as exc:
        raise ValueError(f"material {material} ciphertext blob is invalid base64") from exc


def kms_materials_check(path: Path) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "path": str(path),
        "exists": path.exists(),
        "materials": [],
        "secret_values_redacted": True,
    }
    failures: list[str] = []
    if not path.exists():
        return status, [f"KMS materials file does not exist: {path}"]
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        status["mode"] = oct(mode)
        if mode & 0o077:
            failures.append("KMS materials file must not be readable by group/other")
        parsed = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("KMS materials file must be a JSON object")
        prepare_aws_kms_materials.reject_secret_fields(parsed)
        missing = sorted(REQUIRED_MATERIALS - set(parsed))
        if missing:
            failures.append(f"KMS materials file is missing required materials: {missing}")
        unexpected = sorted(set(parsed) - REQUIRED_MATERIALS)
        if unexpected:
            failures.append(f"KMS materials file contains unauthorized materials: {unexpected}")
        materials = []
        for material in sorted(parsed):
            config = parsed[material]
            if not isinstance(config, dict):
                raise ValueError(f"material {material} config must be an object")
            key_id = config.get("key_id") or config.get("keyId") or config.get("kms_key_id")
            if not isinstance(key_id, str) or not key_id:
                raise ValueError(f"material {material} missing key_id")
            ciphertext = ciphertext_blob(config, material)
            context = config.get("encryption_context") or config.get("encryptionContext") or {}
            if not isinstance(context, dict):
                raise ValueError(f"material {material} encryption_context must be an object")
            materials.append(
                {
                    "material": material,
                    "key_id_sha256": handoff.sha256_prefixed_bytes(key_id.encode("utf-8")),
                    "ciphertext_blob_sha256": handoff.sha256_prefixed_bytes(ciphertext),
                    "encryption_context_sha256": handoff.sha256_prefixed_bytes(canonical_json(context).encode("utf-8")),
                }
            )
        status["materials"] = materials
        status["file"] = handoff.file_summary(path, "kms-materials")
    except Exception as exc:
        failures.append(f"KMS materials file is invalid: {exc}")
    status["ok"] = not failures
    return status, failures


def main() -> None:
    parser = argparse.ArgumentParser(description="Preflight the production host before running Serverware's final readiness proof.")
    parser.add_argument("--env-file", default="ops/production-readiness.env")
    parser.add_argument("--compose-file", default="docker-compose.production.yml")
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument("--production-images-published", default=".tmp/production-images-published.json")
    parser.add_argument("--production-images-build", default=".tmp/production-images-build.json")
    parser.add_argument("--release-provenance-summary", default=".tmp/release-provenance-summary.json")
    parser.add_argument("--release-provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
    parser.add_argument("--policy-bundle", required=True)
    parser.add_argument("--policy-trusted-public-key", required=True)
    parser.add_argument("--policy-identity-verification", required=True)
    parser.add_argument("--policy-activation-verification", required=True)
    parser.add_argument("--policy-activation-signature", required=True)
    parser.add_argument("--policy-activation-trusted-public-key", required=True)
    parser.add_argument("--reproducible-build-verification", required=True)
    parser.add_argument("--reproducible-build-signature", required=True)
    parser.add_argument("--reproducible-build-trusted-public-key", required=True)
    parser.add_argument("--kms-materials", default="/etc/serverware/kms-materials.json")
    parser.add_argument("--config-out", default=".tmp/production-host-preflight-config.json")
    parser.add_argument("--out", default=".tmp/production-host-preflight.json")
    parser.add_argument("--skip-host-check", action="store_true", help="Test-only bypass for non-Nitro local fixture checks.")
    parser.add_argument("--skip-config-gate", action="store_true", help="Only validate env parsing, not the production config gate.")
    args = parser.parse_args()
    enforce_test_only_bypass(args)

    failures: list[str] = []
    host, host_failures = host_check(skip_host_check=args.skip_host_check)
    failures.extend(host_failures)
    env, loaded_env, env_failures = env_check(
        Path(args.env_file),
        production_images_env=Path(args.production_images_env),
        config_out=Path(args.config_out),
        skip_config_gate=args.skip_config_gate,
    )
    failures.extend(env_failures)
    runtime_trust, runtime_trust_failures = runtime_trust_materials_check(
        loaded_env,
        skip_host_check=args.skip_host_check,
    )
    failures.extend(runtime_trust_failures)
    images_env, images_value, images_failures = production_images_env_check(Path(args.production_images_env))
    failures.extend(images_failures)
    merge_status, merge_failures = env_merge_check(loaded_env, images_value) if loaded_env and images_value else (
        {"ok": False, "secret_values_redacted": True},
        ["production image env merge cannot be verified"],
    )
    failures.extend(merge_failures)
    expected_images = images_env.get("images") if isinstance(images_env.get("images"), list) else []
    artifacts, artifact_failures = artifact_check(
        args,
        [item for item in expected_images if isinstance(item, dict)],
        loaded_env.get("SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST") if loaded_env else None,
    )
    failures.extend(artifact_failures)
    release_security, release_security_failures = release_security_evidence_check(args, artifacts)
    failures.extend(release_security_failures)
    compose_status, compose_failures = production_compose_check(
        compose_file=Path(args.compose_file),
        env_file=Path(args.env_file),
        expected_images=[item for item in expected_images if isinstance(item, dict)],
        expected_digest=(artifacts.get("release_provenance_document") or {}).get("compose_config_sha256"),
        skip_host_check=args.skip_host_check,
    )
    failures.extend(compose_failures)
    artifact_mounts, artifact_mount_failures = release_artifact_mounts_check(
        loaded_env,
        release_provenance=Path(args.release_provenance),
        image_signatures=Path(args.image_signatures),
    )
    failures.extend(artifact_mount_failures)
    kms, kms_failures = kms_materials_check(Path(args.kms_materials))
    failures.extend(kms_failures)

    result = {
        "apiVersion": "serverware.productionHostPreflight/v1",
        "kind": "ProductionHostPreflight",
        "ok": not failures,
        "generated_at_unix": int(time.time()),
        "checks": {
            "host": host,
            "production_env": env,
            "runtime_trust_materials": runtime_trust,
            "production_images_env": images_env,
            "production_images_env_merge": merge_status,
            "production_compose": compose_status,
            "release_artifacts": artifacts,
            "release_security_evidence": release_security,
            "release_artifact_mounts": artifact_mounts,
            "kms_materials": kms,
        },
        "failures": failures,
        "next_command": "make run-production-readiness PRODUCTION_READINESS_ENV=ops/production-readiness.env" if not failures else None,
        "secret_values_redacted": True,
    }
    write_result(Path(args.out), result)
    print(canonical_json(result))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
