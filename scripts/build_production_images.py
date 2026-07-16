#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import serverware_source_tree

ROOT = Path(__file__).resolve().parent.parent
BUILD_API_VERSION = "serverware.productionImagesBuild/v2"
BUILD_KIND = "ProductionImagesBuild"
PRODUCTION_PLATFORM = "linux/amd64"
DEFAULT_IMAGES = (
    ("serverware-control", "Dockerfile.production", "serverware/control:production-local"),
    ("serverware-decision-gate", "data-plane/decision-gate-rs/Dockerfile.production", "serverware/decision-gate:production-local"),
)
DECISION_GATE_BINARY_PATHS = {
    "binary_digest": "/usr/local/bin/serverware-decision-gate",
    "launcher_binary_digest": "/usr/local/libexec/serverware-production-launcher",
}
LAUNCH_AUTHORITY_ROOT = ROOT / "data-plane/decision-gate-rs/trust/launch-authority-root.ed25519.hex"
ED25519_SPKI_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
LAUNCH_AUTHORITY_METADATA_FIELDS = (
    "launch_authority_key_id",
    "launch_authority_root_sha256",
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


def _decode_ed25519_point(public_key: bytes) -> tuple[int, int]:
    prime = (1 << 255) - 19
    encoded = int.from_bytes(public_key, "little")
    x_sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= prime:
        raise ValueError("non-canonical point encoding")

    d = (-121665 * pow(121666, prime - 2, prime)) % prime
    y_squared = y * y % prime
    denominator = (d * y_squared + 1) % prime
    if denominator == 0:
        raise ValueError("point is not on the Ed25519 curve")
    x_squared = (y_squared - 1) * pow(denominator, prime - 2, prime) % prime
    x = pow(x_squared, (prime + 3) // 8, prime)
    if x * x % prime != x_squared:
        x = x * pow(2, (prime - 1) // 4, prime) % prime
    if x * x % prime != x_squared:
        raise ValueError("point is not on the Ed25519 curve")
    if x & 1 != x_sign:
        x = prime - x
    if x == 0 and x_sign:
        raise ValueError("non-canonical point encoding")
    return x, y


def _ed25519_point_add(first: tuple[int, int], second: tuple[int, int]) -> tuple[int, int]:
    prime = (1 << 255) - 19
    d = (-121665 * pow(121666, prime - 2, prime)) % prime
    x1, y1 = first
    x2, y2 = second
    product = d * x1 * x2 * y1 * y2 % prime
    x_denominator = (1 + product) % prime
    y_denominator = (1 - product) % prime
    if x_denominator == 0 or y_denominator == 0:
        raise ValueError("invalid Ed25519 point")
    return (
        (x1 * y2 + y1 * x2) * pow(x_denominator, prime - 2, prime) % prime,
        (y1 * y2 + x1 * x2) * pow(y_denominator, prime - 2, prime) % prime,
    )


def _validate_ed25519_public_key(public_key: bytes) -> None:
    if len(public_key) != 32:
        raise ValueError("Ed25519 public keys must contain 32 bytes")
    point = _decode_ed25519_point(public_key)
    multiplied = point
    for _ in range(3):
        multiplied = _ed25519_point_add(multiplied, multiplied)
    if multiplied == (0, 1):
        raise ValueError("weak Ed25519 public key")


def launch_authority_metadata(path: Path = LAUNCH_AUTHORITY_ROOT) -> dict[str, str]:
    try:
        path_metadata = path.lstat()
        if not stat.S_ISREG(path_metadata.st_mode):
            raise RuntimeError(f"launch authority trust root is not a regular file: {path}")
        tracked_bytes = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"could not read launch authority trust root {path}: {exc}") from exc
    if re.fullmatch(rb"[0-9a-f]{64}\n", tracked_bytes) is None:
        raise RuntimeError(
            "launch authority trust root must be exactly 64 lowercase hex characters followed by LF"
        )
    public_key = bytes.fromhex(tracked_bytes[:-1].decode("ascii"))
    try:
        _validate_ed25519_public_key(public_key)
    except ValueError as exc:
        raise RuntimeError(f"launch authority trust root is not a valid Ed25519 public key: {exc}") from exc
    return {
        "launch_authority_key_id": "sha256:"
        + hashlib.sha256(ED25519_SPKI_DER_PREFIX + public_key).hexdigest(),
        "launch_authority_root_sha256": "sha256:" + hashlib.sha256(tracked_bytes).hexdigest(),
    }


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
        **launch_authority_metadata(),
    }


def build_command(dockerfile: str, tag: str, *, platform: str, metadata: dict[str, str]) -> list[str]:
    if platform != PRODUCTION_PLATFORM:
        raise RuntimeError(f"production image platform must be {PRODUCTION_PLATFORM}")
    command = [
        "docker",
        "build",
        "--network=none",
        "-f",
        dockerfile,
        "-t",
        tag,
        "--platform",
        platform,
    ]
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
                member_path = member.name
                while member_path.startswith("./"):
                    member_path = member_path[2:]
                if member_path != wanted:
                    continue
                if digest is not None:
                    raise RuntimeError(f"production image contains duplicate path: {path}")
                if not member.isfile():
                    raise RuntimeError(f"production image path is not a regular file: {path}")
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


def verify_image_platform(image: str, expected: str) -> None:
    actual = run(["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image])
    if actual != expected:
        raise RuntimeError(f"production image platform mismatch: expected {expected}, got {actual}")


def decision_gate_binary_digests(image: str) -> dict[str, str]:
    return {
        field: image_file_sha256(image, path)
        for field, path in DECISION_GATE_BINARY_PATHS.items()
    }


def image_launch_authority_binding(service: str, metadata: dict[str, str]) -> dict[str, str]:
    if service != "serverware-decision-gate":
        return {}
    return {field: metadata[field] for field in LAUNCH_AUTHORITY_METADATA_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build local shell-free Serverware production image candidates.")
    parser.add_argument("--control-tag", default="serverware/control:production-local")
    parser.add_argument("--decision-gate-tag", default="serverware/decision-gate:production-local")
    parser.add_argument("--platform", default=PRODUCTION_PLATFORM, choices=(PRODUCTION_PLATFORM,))
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
        print(
            canonical_json(
                {
                    "ok": True,
                    "commands": commands,
                    "metadata": metadata,
                    "platform": args.platform,
                    "out": args.out,
                }
            )
        )
        return

    images: list[dict[str, Any]] = []
    for spec in commands:
        print(f"==> building {spec['service']} with {spec['dockerfile']}", file=sys.stderr)
        run(spec["argv"])
        built_image_id = image_id(spec["tag"])
        verify_image_platform(built_image_id, args.platform)
        binary_digests: dict[str, str] = {}
        if spec["service"] == "serverware-decision-gate":
            binary_digests = decision_gate_binary_digests(built_image_id)
        images.append(
            {
                "service": spec["service"],
                "tag": spec["tag"],
                "dockerfile": spec["dockerfile"],
                "image_id": built_image_id,
                **binary_digests,
                **image_launch_authority_binding(spec["service"], metadata),
            }
        )
    no_shell = verify_no_shell([str(item["image_id"]) for item in images])
    result = {
        "apiVersion": BUILD_API_VERSION,
        "kind": BUILD_KIND,
        "ok": True,
        "generated_at_unix": int(time.time()),
        "metadata": metadata,
        "images": images,
        "no_shell": no_shell,
        "publish_requirement": "publish these verified linux/amd64 image IDs unchanged, then set SERVERWARE_PRODUCTION_IMAGES to immutable @sha256 digest refs before live readiness",
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
