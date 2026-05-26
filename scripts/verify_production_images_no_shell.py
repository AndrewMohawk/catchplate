#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, BinaryIO


SHELL_NAMES = {"sh", "bash", "dash", "ash", "zsh", "ksh", "csh", "tcsh", "busybox"}
SHELL_DIRS = {"bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin", "usr/local/sbin"}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def image_refs_from_env() -> list[str]:
    raw = os.getenv("SERVERWARE_PRODUCTION_IMAGES", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def normalize_member(name: str) -> str:
    return name.strip("/").replace("\\", "/")


def shell_hit(path: str) -> bool:
    normalized = normalize_member(path)
    parts = normalized.split("/")
    if not parts:
        return False
    basename = parts[-1]
    parent = "/".join(parts[:-1])
    if basename not in SHELL_NAMES:
        return False
    return parent in SHELL_DIRS or basename == "busybox"


def scan_tar_stream(stream: BinaryIO) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            name = normalize_member(member.name)
            if shell_hit(name):
                hits.append({"path": "/" + name, "type": "symlink" if member.issym() else "file"})
            if member.issym() and shell_hit(member.linkname):
                hits.append({"path": "/" + name, "type": "symlink", "target": member.linkname})
    return hits


def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def docker_image_exists(image: str) -> bool:
    return run(["docker", "image", "inspect", image]).returncode == 0


def scan_docker_image(image: str, *, pull: bool = False) -> dict[str, Any]:
    if pull and not docker_image_exists(image):
        pulled = subprocess.run(["docker", "pull", image], check=False)
        if pulled.returncode != 0:
            return {"image": image, "ok": False, "error": f"docker pull failed with exit {pulled.returncode}"}
    if not docker_image_exists(image):
        return {"image": image, "ok": False, "error": "image is not available locally; pull it or enable SERVERWARE_PRODUCTION_IMAGE_PULL=1"}

    created = run(["docker", "create", "--entrypoint", "/__serverware_noop__", image])
    if created.returncode != 0:
        return {"image": image, "ok": False, "error": created.stderr.decode("utf-8", errors="replace").strip()}
    container_id = created.stdout.decode("utf-8").strip()
    try:
        exported = subprocess.Popen(["docker", "export", container_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert exported.stdout is not None
        hits = scan_tar_stream(exported.stdout)
        _, stderr = exported.communicate()
        if exported.returncode != 0:
            return {"image": image, "ok": False, "error": stderr.decode("utf-8", errors="replace").strip()}
        return {"image": image, "ok": not hits, "forbidden_shell_paths": hits}
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def scan_rootfs_tar(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        hits = scan_tar_stream(handle)
    return {"rootfs_tar": str(path), "ok": not hits, "forbidden_shell_paths": hits}


def validate_image_ref(image: str) -> str | None:
    if not re.search(r"@sha256:[0-9a-f]{64}$", image):
        return "image reference must be immutable and include @sha256:<64 hex>"
    lowered = image.lower()
    for marker in ("fixture", ":dev", ":local", ":test"):
        if marker in lowered:
            return f"image reference must not contain {marker}"
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify production image root filesystems contain no shell binaries.")
    parser.add_argument("--image", action="append", default=[], help="Production image reference to inspect.")
    parser.add_argument("--local-image-id", action="append", default=[], help="Local image ID to inspect during production image builds.")
    parser.add_argument("--rootfs-tar", action="append", default=[], help="Rootfs tar archive to inspect, used by tests.")
    parser.add_argument("--pull", action="store_true", default=False, help="Pull missing images before inspection.")
    parser.add_argument("--validate-refs-only", action="store_true", default=False)
    args = parser.parse_args()

    images = args.image or image_refs_from_env()
    pull = args.pull or os.getenv("SERVERWARE_PRODUCTION_IMAGE_PULL", "").lower() in {"1", "true", "yes", "on"}
    failures: list[str] = []
    for image in images:
        error = validate_image_ref(image)
        if error:
            failures.append(f"{image}: {error}")
    if args.validate_refs_only:
        ok = bool(images) and not failures
        print(canonical_json({"ok": ok, "images": images, "failures": failures}))
        raise SystemExit(0 if ok else 1)

    results: list[dict[str, Any]] = []
    for path in args.rootfs_tar:
        results.append(scan_rootfs_tar(Path(path)))
    for image in args.local_image_id:
        results.append(scan_docker_image(image, pull=False))
    for image in images:
        if validate_image_ref(image) is None:
            results.append(scan_docker_image(image, pull=pull))

    if not results:
        failures.append("no images or rootfs tar archives were provided")
    for result in results:
        if not result.get("ok"):
            failures.append(canonical_json(result))

    ok = not failures
    print(canonical_json({"ok": ok, "production_images_no_shell": "pass" if ok else "fail", "results": results, "failures": failures}))
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
