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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import test_production_handoff  # noqa: E402
import test_production_readiness  # noqa: E402


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def write_env(path: Path, env: dict[str, str]) -> None:
    production_env = {key: value for key, value in env.items() if key.startswith("SERVERWARE_")}
    path.write_text("\n".join(f"{key}={shlex.quote(value)}" for key, value in sorted(production_env.items())) + "\n", encoding="utf-8")


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


def run_preflight(paths: dict[str, Path], *extra: str, allow_test_bypass: bool = True) -> subprocess.CompletedProcess[bytes]:
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


def main() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    run_target = makefile.split("run-production-readiness:", 1)[1].split("\n\n", 1)[0]
    if "production-host-preflight" not in run_target:
        raise AssertionError("make run-production-readiness does not enforce production-host-preflight first")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        paths = test_production_handoff.write_fixture_artifacts(tmp)
        paths["kms_materials"] = tmp / "kms-materials.json"
        env = test_production_readiness.good_env()
        env["SERVERWARE_PRODUCTION_IMAGES"] = paths["images_env"].read_text(encoding="utf-8").split("=", 1)[1].strip()
        write_env(paths["env"], env)
        write_kms_materials(paths["kms_materials"])
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
        env["SERVERWARE_PRODUCTION_IMAGES"] = paths["images_env"].read_text(encoding="utf-8").split("=", 1)[1].strip()
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
        env["SERVERWARE_PRODUCTION_IMAGES"] = paths["images_env"].read_text(encoding="utf-8").split("=", 1)[1].strip()
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
        env["SERVERWARE_PRODUCTION_IMAGES"] = paths["images_env"].read_text(encoding="utf-8").split("=", 1)[1].strip()
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
        env["SERVERWARE_PRODUCTION_IMAGES"] = paths["images_env"].read_text(encoding="utf-8").split("=", 1)[1].strip()
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
        env["SERVERWARE_PRODUCTION_IMAGES"] = paths["images_env"].read_text(encoding="utf-8").split("=", 1)[1].strip()
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
