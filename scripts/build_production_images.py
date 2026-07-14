#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import serverware_source_tree

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGES = (
    ("serverware-control", "Dockerfile.production", "serverware/control:production-local"),
    ("serverware-decision-gate", "data-plane/decision-gate-rs/Dockerfile.production", "serverware/decision-gate:production-local"),
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def run(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed with exit {result.returncode}: {detail}")
    return result.stdout.strip()


def image_id(tag: str) -> str:
    return run(["docker", "image", "inspect", "--format", "{{.Id}}", tag])


def maybe_run(command: list[str]) -> str | None:
    try:
        return run(command)
    except Exception:
        return None


def source_tree_digest() -> str:
    return serverware_source_tree.source_tree_digest(ROOT)


def build_metadata() -> dict[str, str]:
    raw_epoch = os.getenv("SOURCE_DATE_EPOCH") or maybe_run(["git", "show", "-s", "--format=%ct", "HEAD"]) or "0"
    try:
        source_date_epoch = int(raw_epoch)
    except ValueError as exc:
        raise RuntimeError("SOURCE_DATE_EPOCH must be an integer") from exc
    if source_date_epoch < 0:
        raise RuntimeError("SOURCE_DATE_EPOCH must be non-negative")
    return {
        "source": "https://github.com/example/private-deployment",
        "revision": maybe_run(["git", "rev-parse", "HEAD"]) or "unknown",
        "created": datetime.fromtimestamp(source_date_epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_date_epoch": str(source_date_epoch),
        "source_tree_digest": source_tree_digest(),
    }


def build_command(dockerfile: str, tag: str, *, platform: str | None, metadata: dict[str, str]) -> list[str]:
    command = ["docker", "build", "-f", dockerfile, "-t", tag]
    if platform:
        command.extend(["--platform", platform])
    command.extend(
        [
            "--build-arg",
            f"SERVERWARE_IMAGE_SOURCE={metadata['source']}",
            "--build-arg",
            f"SERVERWARE_IMAGE_REVISION={metadata['revision']}",
            "--build-arg",
            f"SERVERWARE_IMAGE_CREATED={metadata['created']}",
            "--build-arg",
            f"SERVERWARE_SOURCE_TREE_DIGEST={metadata['source_tree_digest']}",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={metadata['source_date_epoch']}",
        ]
    )
    command.append(".")
    return command


def verify_no_shell(image_ids: list[str]) -> dict[str, Any]:
    command = [sys.executable, "scripts/verify_production_images_no_shell.py"]
    for image in image_ids:
        command.extend(["--local-image-id", image])
    raw = run(command)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("no-shell verifier returned non-object JSON")
    if parsed.get("ok") is not True:
        raise RuntimeError(f"production image no-shell verification failed: {raw}")
    return parsed


def image_file_sha256(image: str, path: str) -> str:
    container_id = run(["docker", "create", image])
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            ["docker", "export", container_id],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None:
            raise RuntimeError("docker export did not provide stdout")
        wanted = path.lstrip("/")
        digest: str | None = None
        with tarfile.open(fileobj=process.stdout, mode="r|*") as archive:
            for member in archive:
                if member.name.lstrip("./") != wanted:
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"production image path is not a regular file: {path}")
                hasher = hashlib.sha256()
                while chunk := extracted.read(1024 * 1024):
                    hasher.update(chunk)
                digest = "sha256:" + hasher.hexdigest()
        _, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"docker export failed for {image}: {stderr.decode(errors='replace').strip()}")
        if digest is None:
            raise RuntimeError(f"production image does not contain required file: {path}")
        return digest
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        maybe_run(["docker", "rm", "-f", container_id])


def main() -> None:
    parser = argparse.ArgumentParser(description="Build local shell-free Serverware production image candidates.")
    parser.add_argument("--control-tag", default="serverware/control:production-local")
    parser.add_argument("--decision-gate-tag", default="serverware/decision-gate:production-local")
    parser.add_argument("--platform", default=None)
    parser.add_argument("--out", default=".tmp/production-images-build.json")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    image_specs = [
        ("serverware-control", "Dockerfile.production", args.control_tag),
        ("serverware-decision-gate", "data-plane/decision-gate-rs/Dockerfile.production", args.decision_gate_tag),
    ]
    metadata = build_metadata()
    commands = [
        {
            "service": service,
            "dockerfile": dockerfile,
            "tag": tag,
            "argv": build_command(dockerfile, tag, platform=args.platform, metadata=metadata),
        }
        for service, dockerfile, tag in image_specs
    ]
    if args.dry_run:
        print(canonical_json({"ok": True, "commands": commands, "metadata": metadata, "out": args.out}))
        return

    images: list[dict[str, Any]] = []
    for spec in commands:
        print(f"==> building {spec['service']} with {spec['dockerfile']}", file=sys.stderr)
        run(spec["argv"])
        built_image_id = image_id(spec["tag"])
        binary_digest = None
        if spec["service"] == "serverware-decision-gate":
            binary_digest = image_file_sha256(
                built_image_id,
                "/usr/local/bin/serverware-decision-gate",
            )
        images.append(
            {
                "service": spec["service"],
                "tag": spec["tag"],
                "dockerfile": spec["dockerfile"],
                "image_id": built_image_id,
                **({"binary_digest": binary_digest} if binary_digest else {}),
            }
        )
    no_shell = verify_no_shell([str(item["image_id"]) for item in images])
    result = {
        "apiVersion": "serverware.productionImagesBuild/v1",
        "kind": "ProductionImagesBuild",
        "ok": True,
        "generated_at_unix": int(time.time()),
        "metadata": metadata,
        "images": images,
        "no_shell": no_shell,
        "publish_requirement": "push these images to a registry and set SERVERWARE_PRODUCTION_IMAGES to immutable @sha256 digest refs before live readiness",
    }
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(canonical_json(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc
