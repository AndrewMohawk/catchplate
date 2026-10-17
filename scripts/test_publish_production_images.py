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

LAUNCH_AUTHORITY_KEY_ID = "sha256:" + "5" * 64
LAUNCH_AUTHORITY_ROOT_SHA256 = "sha256:" + "6" * 64


def build_artifact() -> dict:
    images = [
        {
            "service": "catchplate-control",
            "tag": "catchplate/control:production-local",
            "dockerfile": "Dockerfile.production",
            "image_id": "sha256:" + "a" * 64,
        },
        {
            "service": "catchplate-decision-gate",
            "tag": "catchplate/decision-gate:production-local",
            "dockerfile": "data-plane/decision-gate-rs/Dockerfile.production",
            "image_id": "sha256:" + "b" * 64,
            "binary_digest": "sha256:" + "1" * 64,
            "launcher_binary_digest": "sha256:" + "2" * 64,
            "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
            "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
        },
    ]
    return {
        "apiVersion": publisher.build_production_images.BUILD_API_VERSION,
        "kind": "ProductionImagesBuild",
        "ok": True,
        "generated_at_unix": 1,
        "metadata": {
            "source": "https://github.com/example/private-deployment",
            "revision": "7" * 40,
            "created": "1970-01-01T00:00:00Z",
            "source_date_epoch": "0",
            "source_tree_digest": "sha256:" + "8" * 64,
            "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
            "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
        },
        "no_shell": {
            "ok": True,
            "production_images_no_shell": "pass",
            "results": [
                {"image": image["image_id"], "ok": True, "forbidden_shell_paths": []}
                for image in images
            ],
            "failures": [],
        },
        "images": images,
        "publish_requirement": "digest-pinned production images required",
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
    expected_authority = {
        "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
        "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
    }
    repo_digest = "registry.prod.catchplate.dev/catchplate/decision-gate@sha256:" + "3" * 64
    remote_image_id = image["image_id"]
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
            registry_prefix="registry.prod.catchplate.dev/catchplate",
            tag="candidate",
            use_imagetools=True,
            expected_launch_authority=expected_authority,
        )
    if published.get("launcher_binary_digest") != image["launcher_binary_digest"]:
        raise AssertionError(f"published image result omitted the remote launcher digest: {published}")
    if published.get("config_id") != image["image_id"]:
        raise AssertionError(f"published image result omitted the approved config ID: {published}")
    for field, expected in expected_authority.items():
        if published.get(field) != expected:
            raise AssertionError(f"published image result omitted {field}: {published}")
    measured_paths = [call.args[1] for call in measured.call_args_list]
    if measured_paths != list(publisher.build_production_images.DECISION_GATE_BINARY_PATHS.values()):
        raise AssertionError(f"publisher did not remeasure both remote decision-gate binaries: {measured_paths}")

    with (
        mock.patch.object(publisher, "inspect_repo_digest", return_value=repo_digest),
        mock.patch.object(
            publisher,
            "run",
            side_effect=["", "", "", "sha256:" + "4" * 64],
        ),
    ):
        try:
            publisher.publish_image(
                image,
                registry_prefix="registry.prod.catchplate.dev/catchplate",
                tag="candidate",
                use_imagetools=True,
                expected_launch_authority=expected_authority,
            )
        except RuntimeError as exc:
            if "config ID mismatch" not in str(exc):
                raise AssertionError(
                    f"remote config mismatch failed ambiguously: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "publisher accepted a registry image with another config ID"
            )

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
                registry_prefix="registry.prod.catchplate.dev/catchplate",
                tag="candidate",
                use_imagetools=True,
                expected_launch_authority=expected_authority,
            )
        except RuntimeError as exc:
            if "launcher_binary_digest mismatch" not in str(exc):
                raise AssertionError(f"remote launcher mismatch failed ambiguously: {exc}") from exc
        else:
            raise AssertionError("publisher accepted a remote launcher digest mismatch")

    mutated = build_artifact()["images"][1]

    def mutate_after_measurement(_image: str, path: str) -> str:
        if path.endswith("catchplate-decision-gate"):
            return str(mutated["binary_digest"])
        mutated["launch_authority_root_sha256"] = "sha256:" + "9" * 64
        return str(mutated["launcher_binary_digest"])

    with (
        mock.patch.object(publisher, "inspect_repo_digest", return_value=repo_digest),
        mock.patch.object(publisher, "run", side_effect=["", "", "", remote_image_id]),
        mock.patch.object(
            publisher.build_production_images,
            "image_file_sha256",
            side_effect=mutate_after_measurement,
        ),
    ):
        try:
            publisher.publish_image(
                mutated,
                registry_prefix="registry.prod.catchplate.dev/catchplate",
                tag="candidate",
                use_imagetools=True,
                expected_launch_authority=expected_authority,
            )
        except RuntimeError as exc:
            if "changed during remote launcher remeasurement" not in str(exc):
                raise AssertionError(f"post-measurement authority mismatch failed ambiguously: {exc}") from exc
        else:
            raise AssertionError("publisher accepted a launch-authority mutation during remote remeasurement")


def main() -> None:
    if publisher.PUBLISHED_API_VERSION != "catchplate.productionImagesPublished/v2":
        raise AssertionError(f"published image contract was not promoted to v2: {publisher.PUBLISHED_API_VERSION}")
    assert_remote_launcher_verification()
    if publisher.service_repo_name("catchplate-decision-gate") != "decision-gate":
        raise AssertionError("service repo mapping did not strip catchplate prefix")
    ref = publisher.repo_digest_from_inspect(
        "registry.prod.catchplate.dev/catchplate/control",
        [
            "registry.other.catchplate.dev/control@sha256:" + "0" * 64,
            "registry.prod.catchplate.dev/catchplate/control@sha256:" + "1" * 64,
        ],
    )
    if ref != "registry.prod.catchplate.dev/catchplate/control@sha256:" + "1" * 64:
        raise AssertionError(f"repo digest extraction failed: {ref}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        build_file = tmp / "production-images-build.json"
        build_file.write_text(json.dumps(build_artifact(), sort_keys=True) + "\n", encoding="utf-8")
        result = run_script(
            "--build-file",
            str(build_file),
            "--registry-prefix",
            "registry.prod.catchplate.dev/catchplate",
            "--tag",
            "2026-05-25",
            "--dry-run",
        )
        if result.returncode != 0:
            raise AssertionError(f"publish dry-run failed: {detail(result)}")
        plan = json.loads(result.stdout.decode("utf-8"))
        tags = [item["tag"] for item in plan.get("commands") or []]
        if tags != [
            "registry.prod.catchplate.dev/catchplate/control:2026-05-25",
            "registry.prod.catchplate.dev/catchplate/decision-gate:2026-05-25",
        ]:
            raise AssertionError(f"publish dry-run planned wrong tags: {plan}")

        bad_file = tmp / "bad.json"
        bad = build_artifact()
        bad["no_shell"] = {"ok": False}
        bad_file.write_text(json.dumps(bad, sort_keys=True) + "\n", encoding="utf-8")
        rejected = run_script("--build-file", str(bad_file), "--registry-prefix", "registry.prod.catchplate.dev/catchplate", "--dry-run")
        if rejected.returncode == 0 or "no_shell" not in detail(rejected):
            raise AssertionError(f"publisher accepted an unverified build artifact: {detail(rejected)}")

        missing_launcher_file = tmp / "missing-launcher.json"
        missing_launcher = build_artifact()
        missing_launcher["images"][1].pop("launcher_binary_digest")
        missing_launcher_file.write_text(json.dumps(missing_launcher, sort_keys=True) + "\n", encoding="utf-8")
        rejected = run_script(
            "--build-file",
            str(missing_launcher_file),
            "--registry-prefix",
            "registry.prod.catchplate.dev/catchplate",
            "--dry-run",
        )
        if rejected.returncode == 0 or "launcher_binary_digest" not in detail(rejected):
            raise AssertionError(f"publisher accepted a build missing its launcher digest: {detail(rejected)}")

        for fixture_name, mutate, expected_error in (
            (
                "old-version",
                lambda value: value.__setitem__("apiVersion", "catchplate.productionImagesBuild/v1"),
                "productionImagesBuild/v2",
            ),
            (
                "missing-authority-metadata",
                lambda value: value["metadata"].pop("launch_authority_key_id"),
                "launch_authority_key_id",
            ),
            (
                "missing-authority-image",
                lambda value: value["images"][1].pop("launch_authority_root_sha256"),
                "launch_authority_root_sha256",
            ),
            (
                "mismatched-authority",
                lambda value: value["images"][1].__setitem__(
                    "launch_authority_key_id", "sha256:" + "9" * 64
                ),
                "does not match build metadata",
            ),
        ):
            mutated = build_artifact()
            mutate(mutated)
            mutated_file = tmp / f"{fixture_name}.json"
            mutated_file.write_text(json.dumps(mutated, sort_keys=True) + "\n", encoding="utf-8")
            rejected = run_script(
                "--build-file",
                str(mutated_file),
                "--registry-prefix",
                "registry.prod.catchplate.dev/catchplate",
                "--dry-run",
            )
            if rejected.returncode == 0 or expected_error not in detail(rejected):
                raise AssertionError(f"publisher accepted {fixture_name}: {detail(rejected)}")

        placeholder = run_script("--build-file", str(build_file), "--registry-prefix", "registry.example/catchplate", "--dry-run")
        if placeholder.returncode == 0 or "placeholder .example registry" not in detail(placeholder):
            raise AssertionError(f"publisher accepted a placeholder registry prefix: {detail(placeholder)}")

    print(json.dumps({"ok": True, "publish_production_images": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
