#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def digest(char: str) -> str:
    return "sha256:" + char * 64


def images_value() -> str:
    return ",".join(
        [
            "registry.prod.serverware.dev/serverware/control@" + digest("a"),
            "registry.prod.serverware.dev/serverware/decision-gate@" + digest("b"),
        ]
    )


def run_script(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "scripts/merge_production_images_env.py", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def write_images_env(path: Path, value: str | None = None, *, extra: bool = False) -> None:
    lines = ["SERVERWARE_PRODUCTION_IMAGES=" + (value if value is not None else images_value())]
    if extra:
        lines.append("SERVERWARE_ADMIN_TOKEN=should-not-be-here")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        images_env = tmp / "production-images.env"
        env = tmp / "production-readiness.env"
        write_images_env(images_env)
        env.write_text(
            "\n".join(
                [
                    "# production values",
                    "SERVERWARE_ADMIN_TOKEN=prod-admin-token-32-byte-secret-value",
                    "SERVERWARE_PRODUCTION_IMAGE_NO_SHELL_REQUIRED=1",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        dry_run = run_script("--images-env", str(images_env), "--env-file", str(env), "--dry-run")
        if dry_run.returncode != 0:
            raise AssertionError(f"dry-run merge failed: {detail(dry_run)}")
        if "prod-admin-token-32-byte-secret-value" in detail(dry_run):
            raise AssertionError("dry-run leaked a target env secret")
        summary = json.loads(dry_run.stdout.decode("utf-8"))
        if summary.get("changed") is not True or summary.get("production_images_count") != 2:
            raise AssertionError(f"dry-run summary did not describe the merge: {summary}")
        if "SERVERWARE_PRODUCTION_IMAGES" in env.read_text(encoding="utf-8"):
            raise AssertionError("dry-run modified the target env file")

        merged = run_script("--images-env", str(images_env), "--env-file", str(env))
        if merged.returncode != 0:
            raise AssertionError(f"merge failed: {detail(merged)}")
        if "prod-admin-token-32-byte-secret-value" in detail(merged):
            raise AssertionError("merge leaked a target env secret")
        merged_text = env.read_text(encoding="utf-8")
        if "SERVERWARE_ADMIN_TOKEN=prod-admin-token-32-byte-secret-value" not in merged_text:
            raise AssertionError("merge did not preserve existing env values")
        if "SERVERWARE_PRODUCTION_IMAGES=" + images_value() not in merged_text:
            raise AssertionError(f"merge did not append production images: {merged_text}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        images_env = tmp / "production-images.env"
        env = tmp / "production-readiness.env"
        write_images_env(images_env)
        old = "registry.prod.serverware.dev/serverware/control@" + digest("c")
        env.write_text("export SERVERWARE_PRODUCTION_IMAGES=" + old + "\nSERVERWARE_ADMIN_TOKEN=secret\n", encoding="utf-8")
        replaced = run_script("--images-env", str(images_env), "--env-file", str(env))
        if replaced.returncode != 0:
            raise AssertionError(f"replace merge failed: {detail(replaced)}")
        replaced_text = env.read_text(encoding="utf-8")
        if old in replaced_text or replaced_text.count("SERVERWARE_PRODUCTION_IMAGES=") != 1:
            raise AssertionError(f"merge did not replace the existing image refs cleanly: {replaced_text}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        images_env = tmp / "production-images.env"
        env = tmp / "production-readiness.env"
        write_images_env(images_env, "registry.prod.serverware.dev/serverware/control:latest")
        env.write_text("SERVERWARE_ADMIN_TOKEN=secret\n", encoding="utf-8")
        rejected = run_script("--images-env", str(images_env), "--env-file", str(env))
        if rejected.returncode == 0 or "@sha256" not in detail(rejected):
            raise AssertionError(f"merge accepted a mutable image ref: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        images_env = tmp / "production-images.env"
        env = tmp / "production-readiness.env"
        write_images_env(images_env, extra=True)
        env.write_text("SERVERWARE_ADMIN_TOKEN=secret\n", encoding="utf-8")
        rejected = run_script("--images-env", str(images_env), "--env-file", str(env))
        if rejected.returncode == 0 or "must contain only SERVERWARE_PRODUCTION_IMAGES" not in detail(rejected):
            raise AssertionError(f"merge accepted extra fragment keys: {detail(rejected)}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        images_env = tmp / "production-images.env"
        env = tmp / "production-readiness.env"
        write_images_env(images_env)
        env.write_text(
            "SERVERWARE_PRODUCTION_IMAGES=registry.prod.serverware.dev/serverware/control@"
            + digest("c")
            + "\nSERVERWARE_PRODUCTION_IMAGES=registry.prod.serverware.dev/serverware/decision-gate@"
            + digest("d")
            + "\n",
            encoding="utf-8",
        )
        rejected = run_script("--images-env", str(images_env), "--env-file", str(env))
        if rejected.returncode == 0 or "duplicate environment key SERVERWARE_PRODUCTION_IMAGES" not in detail(rejected):
            raise AssertionError(f"merge accepted duplicate target keys: {detail(rejected)}")

    print(json.dumps({"ok": True, "merge_production_images_env": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
