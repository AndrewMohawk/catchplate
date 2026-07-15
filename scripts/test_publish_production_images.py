#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

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
                "binary_digest": "sha256:" + "1" * 64,
                "launcher_binary_digest": "sha256:" + "2" * 64,
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


def assert_remote_launcher_verification() -> None:
    image = build_artifact()["images"][1]
    repo_digest = "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "3" * 64
    remote_image_id = "sha256:" + "4" * 64
    with (
        mock.patch.object(publisher, "inspect_repo_digest", return_value=repo_digest),
        mock.patch.object(publisher, "run", side_effect=["", "", "", remote_image_id]),
        mock.patch.object(
            publisher.build_production_images,
            "image_file_sha256",
            side_effect=[image["binary_digest"], image["launcher_binary_digest"]],
        ) as measured,
    ):
        published = publisher.publish_image(
            image,
            registry_prefix="registry.prod.serverware.dev/serverware",
            tag="candidate",
            use_imagetools=True,
        )
    if published.get("launcher_binary_digest") != image["launcher_binary_digest"]:
        raise AssertionError(f"published image result omitted the remote launcher digest: {published}")
    measured_paths = [call.args[1] for call in measured.call_args_list]
    if measured_paths != list(publisher.build_production_images.DECISION_GATE_BINARY_PATHS.values()):
        raise AssertionError(f"publisher did not remeasure both remote decision-gate binaries: {measured_paths}")

    with (
        mock.patch.object(publisher, "inspect_repo_digest", return_value=repo_digest),
        mock.patch.object(publisher, "run", side_effect=["", "", "", remote_image_id]),
        mock.patch.object(
            publisher.build_production_images,
            "image_file_sha256",
            side_effect=[image["binary_digest"], "sha256:" + "9" * 64],
        ),
    ):
        try:
            publisher.publish_image(
                image,
                registry_prefix="registry.prod.serverware.dev/serverware",
                tag="candidate",
                use_imagetools=True,
            )
        except RuntimeError as exc:
            if "launcher_binary_digest mismatch" not in str(exc):
                raise AssertionError(f"remote launcher mismatch failed ambiguously: {exc}") from exc
        else:
            raise AssertionError("publisher accepted a remote launcher digest mismatch")


def main() -> None:
    assert_remote_launcher_verification()
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

        missing_launcher_file = tmp / "missing-launcher.json"
        missing_launcher = build_artifact()
        missing_launcher["images"][1].pop("launcher_binary_digest")
        missing_launcher_file.write_text(json.dumps(missing_launcher, sort_keys=True) + "\n", encoding="utf-8")
        rejected = run_script(
            "--build-file",
            str(missing_launcher_file),
            "--registry-prefix",
            "registry.prod.serverware.dev/serverware",
            "--dry-run",
        )
        if rejected.returncode == 0 or "launcher_binary_digest" not in detail(rejected):
            raise AssertionError(f"publisher accepted a build missing its launcher digest: {detail(rejected)}")

        placeholder = run_script("--build-file", str(build_file), "--registry-prefix", "registry.example/serverware", "--dry-run")
        if placeholder.returncode == 0 or "placeholder .example registry" not in detail(placeholder):
            raise AssertionError(f"publisher accepted a placeholder registry prefix: {detail(placeholder)}")

    print(json.dumps({"ok": True, "publish_production_images": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
