#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import publish_production_images as publisher  # noqa: E402


def build_artifact() -> dict:
    return {
        "apiVersion": "serverware.productionImagesBuild/v1",
        "kind": "ProductionImagesBuild",
        "ok": True,
        "no_shell": {"ok": True},
        "images": [
            {
                "service": "serverware-control",
                "tag": "serverware/control:production-local",
                "image_id": "sha256:" + "a" * 64,
            },
            {
                "service": "serverware-decision-gate",
                "tag": "serverware/decision-gate:production-local",
                "image_id": "sha256:" + "b" * 64,
            },
        ],
    }


def run_script(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "scripts/publish_production_images.py", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def main() -> None:
    if publisher.service_repo_name("serverware-decision-gate") != "decision-gate":
        raise AssertionError("service repo mapping did not strip serverware prefix")
    ref = publisher.repo_digest_from_inspect(
        "registry.prod.serverware.dev/serverware/control",
        [
            "registry.other.serverware.dev/control@sha256:" + "0" * 64,
            "registry.prod.serverware.dev/serverware/control@sha256:" + "1" * 64,
        ],
    )
    if ref != "registry.prod.serverware.dev/serverware/control@sha256:" + "1" * 64:
        raise AssertionError(f"repo digest extraction failed: {ref}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        build_file = tmp / "production-images-build.json"
        build_file.write_text(json.dumps(build_artifact(), sort_keys=True) + "\n", encoding="utf-8")
        result = run_script(
            "--build-file",
            str(build_file),
            "--registry-prefix",
            "registry.prod.serverware.dev/serverware",
            "--tag",
            "2026-05-25",
            "--dry-run",
        )
        if result.returncode != 0:
            raise AssertionError(f"publish dry-run failed: {detail(result)}")
        plan = json.loads(result.stdout.decode("utf-8"))
        tags = [item["tag"] for item in plan.get("commands") or []]
        if tags != [
            "registry.prod.serverware.dev/serverware/control:2026-05-25",
            "registry.prod.serverware.dev/serverware/decision-gate:2026-05-25",
        ]:
            raise AssertionError(f"publish dry-run planned wrong tags: {plan}")

        bad_file = tmp / "bad.json"
        bad = build_artifact()
        bad["no_shell"] = {"ok": False}
        bad_file.write_text(json.dumps(bad, sort_keys=True) + "\n", encoding="utf-8")
        rejected = run_script("--build-file", str(bad_file), "--registry-prefix", "registry.prod.serverware.dev/serverware", "--dry-run")
        if rejected.returncode == 0 or "no-shell" not in detail(rejected):
            raise AssertionError(f"publisher accepted an unverified build artifact: {detail(rejected)}")

        placeholder = run_script("--build-file", str(build_file), "--registry-prefix", "registry.example/serverware", "--dry-run")
        if placeholder.returncode == 0 or "placeholder .example registry" not in detail(placeholder):
            raise AssertionError(f"publisher accepted a placeholder registry prefix: {detail(placeholder)}")

    print(json.dumps({"ok": True, "publish_production_images": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
