#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import generate_production_handoff as handoff  # noqa: E402
import merge_production_images_env  # noqa: E402
import prepare_aws_kms_materials  # noqa: E402
import run_production_readiness  # noqa: E402

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
            str(item["service"]): str(item["image_id"])
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
            expected_local_id = build_by_service.get(service)
            if expected_local_id is None:
                raise ValueError(f"published image service is not in current build artifact: {service}")
            if local_image_id != expected_local_id:
                raise ValueError(
                    "published production images do not match current no-shell build: "
                    f"service={service} published={local_image_id} build={expected_local_id}"
                )
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


def artifact_check(args: argparse.Namespace, expected_images: list[dict[str, str]]) -> tuple[dict[str, Any], list[str]]:
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
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument("--production-images-published", default=".tmp/production-images-published.json")
    parser.add_argument("--production-images-build", default=".tmp/production-images-build.json")
    parser.add_argument("--release-provenance-summary", default=".tmp/release-provenance-summary.json")
    parser.add_argument("--release-provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
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
    images_env, images_value, images_failures = production_images_env_check(Path(args.production_images_env))
    failures.extend(images_failures)
    merge_status, merge_failures = env_merge_check(loaded_env, images_value) if loaded_env and images_value else (
        {"ok": False, "secret_values_redacted": True},
        ["production image env merge cannot be verified"],
    )
    failures.extend(merge_failures)
    expected_images = images_env.get("images") if isinstance(images_env.get("images"), list) else []
    artifacts, artifact_failures = artifact_check(args, [item for item in expected_images if isinstance(item, dict)])
    failures.extend(artifact_failures)
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
            "production_images_env": images_env,
            "production_images_env_merge": merge_status,
            "release_artifacts": artifacts,
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
