#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def run(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed with exit {result.returncode}: {detail}")
    return result.stdout.strip()


def load_build(path: Path) -> dict[str, Any]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("production image build artifact must be a JSON object")
    if parsed.get("ok") is not True:
        raise ValueError(f"production image build artifact is not ok: {parsed}")
    no_shell = parsed.get("no_shell") if isinstance(parsed.get("no_shell"), dict) else {}
    if no_shell.get("ok") is not True:
        raise ValueError("production image build artifact did not pass no-shell verification")
    images = parsed.get("images")
    if not isinstance(images, list) or not images:
        raise ValueError("production image build artifact has no images")
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


def publish_image(image: dict[str, Any], *, registry_prefix: str, tag: str, use_imagetools: bool) -> dict[str, Any]:
    service = str(image.get("service") or "")
    local_id = validate_image_id(image.get("image_id"))
    repo = target_repo(registry_prefix, service)
    target = f"{repo}:{tag}"
    run(["docker", "tag", local_id, target])
    run(["docker", "push", target])
    digest_ref = inspect_repo_digest(repo, target)
    if digest_ref is None and use_imagetools:
        digest_ref = imagetools_repo_digest(repo, target)
    if digest_ref is None:
        raise RuntimeError(f"docker push did not expose a repo digest for {target}")
    return {
        "service": service,
        "local_image_id": local_id,
        "tag": target,
        "repo_digest": digest_ref,
    }


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
            )
            for image in build["images"]
            if isinstance(image, dict)
        ]
        production_images = [item["repo_digest"] for item in images]
        result = {
            "apiVersion": "serverware.productionImagesPublished/v1",
            "kind": "ProductionImagesPublished",
            "ok": True,
            "generated_at_unix": int(time.time()),
            "source_build_file": args.build_file,
            "images": images,
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
