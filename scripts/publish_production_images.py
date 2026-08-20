#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hmac
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import build_production_images

ROOT = Path(__file__).resolve().parent.parent
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PUBLISHED_API_VERSION = "serverware.productionImagesPublished/v2"
PUBLISHED_KIND = "ProductionImagesPublished"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def run(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed with exit {result.returncode}: {detail}")
    return result.stdout.strip()


def require_exact_fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{label} fields do not match the closed contract: missing={missing} extra={extra}")
    return value


def launch_authority_binding(value: Any, label: str) -> dict[str, str]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    return {
        field: validate_digest(value.get(field), f"{label} {field}")
        for field in build_production_images.LAUNCH_AUTHORITY_METADATA_FIELDS
    }


def load_build(path: Path) -> dict[str, Any]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    require_exact_fields(
        parsed,
        {
            "apiVersion",
            "kind",
            "ok",
            "identity_mode",
            "production_release_eligible",
            "generated_at_unix",
            "metadata",
            "images",
            "no_shell",
            "publish_requirement",
        },
        "production image build artifact",
    )
    if (
        parsed.get("apiVersion") != build_production_images.BUILD_API_VERSION
        or parsed.get("kind") != build_production_images.BUILD_KIND
    ):
        raise ValueError(
            f"production image build artifact must use {build_production_images.BUILD_API_VERSION}"
        )
    if parsed.get("ok") is not True:
        raise ValueError(f"production image build artifact is not ok: {parsed}")
    if (
        parsed.get("identity_mode") != build_production_images.serverware_source_tree.PRODUCTION_IDENTITY_MODE
        or parsed.get("production_release_eligible") is not True
    ):
        raise ValueError("production image build artifact is not bound to a clean production commit")
    generated_at = parsed.get("generated_at_unix")
    if type(generated_at) is not int or generated_at < 0:
        raise ValueError("production image build generated_at_unix must be a non-negative integer")
    metadata = require_exact_fields(
        parsed.get("metadata"),
        {
            "source",
            "revision",
            "created",
            "source_date_epoch",
            "source_tree_digest",
            "source_archive_digest",
            "source_archive_path",
            "source_manifest_digest",
            "source_manifest_path",
            "source_file_list_digest",
            "source_file_list_path",
            "source_file_hashes_digest",
            "source_file_hashes_path",
            "source_file_modes_digest",
            "source_file_modes_path",
            "source_identity_mode",
            "production_release_eligible",
            "image_title_suffix",
            "source_contract",
            *build_production_images.LAUNCH_AUTHORITY_METADATA_FIELDS,
        },
        "production image build metadata",
    )
    validate_digest(metadata.get("source_tree_digest"), "production image build metadata source_tree_digest")
    for field in (
        "source_archive_digest",
        "source_manifest_digest",
        "source_file_list_digest",
        "source_file_hashes_digest",
        "source_file_modes_digest",
    ):
        validate_digest(metadata.get(field), f"production image build metadata {field}")
    if (
        metadata.get("source_identity_mode")
        != build_production_images.serverware_source_tree.PRODUCTION_IDENTITY_MODE
        or metadata.get("production_release_eligible") is not True
        or metadata.get("image_title_suffix") != "production"
        or not isinstance(metadata.get("source_contract"), dict)
    ):
        raise ValueError("production image build metadata does not carry a production source contract")
    expected_authority = launch_authority_binding(metadata, "production image build metadata")
    no_shell = require_exact_fields(
        parsed.get("no_shell"),
        {"ok", "production_images_no_shell", "results", "failures"},
        "production image build no_shell",
    )
    if no_shell.get("ok") is not True or no_shell.get("production_images_no_shell") != "pass":
        raise ValueError("production image build artifact did not pass no-shell verification")
    if no_shell.get("failures") != []:
        raise ValueError("production image build artifact contains no-shell failures")
    images = parsed.get("images")
    if not isinstance(images, list) or len(images) != 2:
        raise ValueError("production image build artifact must contain exactly two images")
    seen_services: set[str] = set()
    image_ids: set[str] = set()
    for index, image in enumerate(images):
        if type(image) is not dict:
            raise ValueError(f"production image build images[{index}] must be a JSON object")
        service = image.get("service")
        if service not in {"serverware-control", "serverware-decision-gate"} or service in seen_services:
            raise ValueError(f"production image build has unexpected or duplicate service: {service!r}")
        seen_services.add(str(service))
        expected_fields = {"service", "tag", "dockerfile", "image_id"}
        if service == "serverware-decision-gate":
            expected_fields |= {
                *build_production_images.DECISION_GATE_BINARY_PATHS,
                *build_production_images.LAUNCH_AUTHORITY_METADATA_FIELDS,
            }
        require_exact_fields(image, expected_fields, f"production image build {service}")
        image_ids.add(validate_image_id(image.get("image_id")))
        if service == "serverware-decision-gate":
            decision_gate_declared_digests(image)
            if launch_authority_binding(image, "production image build decision-gate") != expected_authority:
                raise ValueError(
                    "production image build decision-gate launch-authority binding does not match build metadata"
                )
    if seen_services != {"serverware-control", "serverware-decision-gate"}:
        raise ValueError("production image build service set is incomplete")
    results = no_shell.get("results")
    if not isinstance(results, list) or len(results) != len(images):
        raise ValueError("production image build no-shell results do not cover both images")
    measured_ids = {
        result.get("image")
        for result in results
        if isinstance(result, dict)
        and result.get("ok") is True
        and result.get("forbidden_shell_paths") == []
    }
    if measured_ids != image_ids:
        raise ValueError("production image build no-shell results do not match the built image IDs")
    return parsed


def service_repo_name(service: str) -> str:
    name = service.strip().lower().replace("_", "-")
    if name.startswith("serverware-"):
        name = name[len("serverware-") :]
    return name or "image"


def registry_host(registry_prefix: str) -> str:
    prefix = registry_prefix.strip().rstrip("/")
    if not prefix:
        raise ValueError("--registry-prefix is required")
    if "://" in prefix or any(char.isspace() for char in prefix) or "@" in prefix:
        raise ValueError("--registry-prefix must be a registry/repository prefix, not a URL, tag, or digest ref")
    parts = prefix.split("/")
    if any(not part for part in parts):
        raise ValueError("--registry-prefix contains an empty path segment")
    host = parts[0]
    if host.startswith("["):
        return host.strip("[]").lower()
    return host.split(":", 1)[0].lower()


def placeholder_hostname(hostname: str) -> bool:
    lowered = hostname.rstrip(".").lower()
    return lowered == "example" or lowered.endswith(".example")


def validate_registry_prefix(registry_prefix: str) -> str:
    prefix = registry_prefix.strip().rstrip("/")
    host = registry_host(prefix)
    if placeholder_hostname(host):
        raise ValueError(f"--registry-prefix must not use a placeholder .example registry domain: {registry_prefix}")
    return prefix


def target_repo(registry_prefix: str, service: str) -> str:
    prefix = validate_registry_prefix(registry_prefix)
    return f"{prefix}/{service_repo_name(service)}"


def validate_image_id(value: Any) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"local image_id must be sha256:<64 hex>: {value!r}")
    return value


def validate_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be sha256:<64 hex>")
    return value


def decision_gate_declared_digests(image: dict[str, Any]) -> dict[str, str]:
    return {
        field: validate_digest(image.get(field), f"decision-gate {field}")
        for field in build_production_images.DECISION_GATE_BINARY_PATHS
    }


def repo_digest_from_inspect(repo: str, repo_digests: list[Any]) -> str | None:
    prefix = repo + "@sha256:"
    candidates = [item for item in repo_digests if isinstance(item, str) and item.startswith(prefix)]
    if not candidates:
        return None
    return sorted(candidates)[-1]


def inspect_repo_digest(repo: str, tag: str) -> str | None:
    raw = run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", tag])
    try:
        repo_digests = json.loads(raw)
    except json.JSONDecodeError:
        repo_digests = []
    if not isinstance(repo_digests, list):
        repo_digests = []
    return repo_digest_from_inspect(repo, repo_digests)


def imagetools_repo_digest(repo: str, tag: str) -> str:
    raw = run(["docker", "buildx", "imagetools", "inspect", tag, "--format", "{{json .Manifest.Digest}}"])
    try:
        digest = json.loads(raw)
    except json.JSONDecodeError:
        digest = raw.strip().strip('"')
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise RuntimeError(f"could not recover remote manifest digest for {tag}: {raw}")
    return f"{repo}@{digest}"


def publish_image(
    image: dict[str, Any],
    *,
    registry_prefix: str,
    tag: str,
    use_imagetools: bool,
    expected_launch_authority: dict[str, str],
) -> dict[str, Any]:
    service = str(image.get("service") or "")
    local_id = validate_image_id(image.get("image_id"))
    declared_digests = decision_gate_declared_digests(image) if service == "serverware-decision-gate" else {}
    if service == "serverware-decision-gate":
        declared_authority = launch_authority_binding(image, "decision-gate build image")
        if declared_authority != expected_launch_authority:
            raise ValueError("decision-gate build image launch-authority binding does not match build metadata")
    repo = target_repo(registry_prefix, service)
    target = f"{repo}:{tag}"
    run(["docker", "tag", local_id, target])
    run(["docker", "push", target])
    digest_ref = inspect_repo_digest(repo, target)
    if digest_ref is None and use_imagetools:
        digest_ref = imagetools_repo_digest(repo, target)
    if digest_ref is None:
        raise RuntimeError(f"docker push did not expose a repo digest for {target}")
    run(["docker", "pull", digest_ref])
    remote_image_id = validate_image_id(
        run(["docker", "image", "inspect", "--format", "{{.Id}}", digest_ref])
    )
    if not hmac.compare_digest(remote_image_id, local_id):
        raise RuntimeError(
            f"published {service} config ID mismatch: local build has {local_id}, "
            f"registry digest resolves to {remote_image_id}"
        )
    measured_digests: dict[str, str] = {}
    if service == "serverware-decision-gate":
        for field, path in build_production_images.DECISION_GATE_BINARY_PATHS.items():
            measured = build_production_images.image_file_sha256(digest_ref, path)
            expected = declared_digests[field]
            if measured != expected:
                raise RuntimeError(
                    f"published decision-gate {field} mismatch: build has {expected}, registry has {measured}"
                )
            measured_digests[field] = measured
        if launch_authority_binding(image, "decision-gate build image after remote remeasurement") != expected_launch_authority:
            raise RuntimeError(
                "decision-gate launch-authority binding changed during remote launcher remeasurement"
            )
        measured_digests.update(expected_launch_authority)
    return {
        "service": service,
        "local_image_id": local_id,
        "tag": target,
        "repo_digest": digest_ref,
        "config_id": local_id,
        "remote_image_id": remote_image_id,
        **measured_digests,
    }


def verify_published_no_shell(images: list[dict[str, Any]]) -> dict[str, Any]:
    command = [sys.executable, "scripts/verify_production_images_no_shell.py", "--pull"]
    for item in images:
        command.extend(["--image", str(item["repo_digest"])])
    parsed = json.loads(run(command))
    if not isinstance(parsed, dict) or parsed.get("ok") is not True:
        raise RuntimeError(f"published production image no-shell verification failed: {parsed}")
    return parsed


def command_plan(build: dict[str, Any], *, registry_prefix: str, tag: str) -> list[dict[str, Any]]:
    commands = []
    for image in build["images"]:
        if not isinstance(image, dict):
            raise ValueError(f"invalid image entry: {image}")
        service = str(image.get("service") or "")
        local_id = validate_image_id(image.get("image_id"))
        repo = target_repo(registry_prefix, service)
        target = f"{repo}:{tag}"
        commands.append(
            {
                "service": service,
                "local_image_id": local_id,
                "repo": repo,
                "tag": target,
                "commands": [
                    ["docker", "tag", local_id, target],
                    ["docker", "push", target],
                    ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", target],
                ],
            }
        )
    return commands


def write_env(path: Path, production_images: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("SERVERWARE_PRODUCTION_IMAGES=" + ",".join(production_images) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Push shell-free production image candidates and emit digest-pinned refs.")
    parser.add_argument("--build-file", default=".tmp/production-images-build.json")
    parser.add_argument("--registry-prefix", required=True, help="Registry/repository prefix, for example registry.prod.serverware.dev/serverware")
    parser.add_argument("--tag", default="production-candidate")
    parser.add_argument("--out", default=".tmp/production-images-published.json")
    parser.add_argument("--env-out", default=".tmp/production-images.env")
    parser.add_argument("--no-imagetools-fallback", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        build = load_build(Path(args.build_file))
        expected_launch_authority = launch_authority_binding(
            build["metadata"], "production image build metadata"
        )
        plan = command_plan(build, registry_prefix=args.registry_prefix, tag=args.tag)
        if args.dry_run:
            print(canonical_json({"ok": True, "build_file": args.build_file, "commands": plan, "out": args.out, "env_out": args.env_out}))
            return

        images = [
            publish_image(
                image,
                registry_prefix=args.registry_prefix,
                tag=args.tag,
                use_imagetools=not args.no_imagetools_fallback,
                expected_launch_authority=expected_launch_authority,
            )
            for image in build["images"]
            if isinstance(image, dict)
        ]
        remote_no_shell = verify_published_no_shell(images)
        production_images = [item["repo_digest"] for item in images]
        result = {
            "apiVersion": PUBLISHED_API_VERSION,
            "kind": PUBLISHED_KIND,
            "ok": True,
            "generated_at_unix": int(time.time()),
            "source_build_file": args.build_file,
            "images": images,
            "remote_no_shell": remote_no_shell,
            "env": {"SERVERWARE_PRODUCTION_IMAGES": ",".join(production_images)},
        }
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_env(Path(args.env_out), production_images)
        print(canonical_json(result))
    except Exception as exc:
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
