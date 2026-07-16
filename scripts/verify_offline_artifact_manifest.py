#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


API_VERSION = "serverware.offlineArtifactManifest/v1"
KIND = "OfflineArtifactManifest"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_MANIFEST_BYTES = 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"manifest contains duplicate key: {key}")
        result[key] = value
    return result


def file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def artifact_metadata(path: Path) -> tuple[int, str]:
    if not hasattr(os, "O_NOFOLLOW"):
        fail("artifact files cannot be opened without following symlinks")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
    )
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"offline artifact is not a regular file: {path.name}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if file_identity(before) != file_identity(after):
            fail(f"offline artifact changed while it was hashed: {path.name}")
        return before.st_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def reject_constant(value: str) -> Any:
    fail(f"manifest contains non-standard JSON constant: {value}")


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    if not hasattr(os, "O_NOFOLLOW"):
        fail("manifest cannot be opened without following symlinks")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"manifest must be a regular file: {path}")
        if before.st_size > MAX_MANIFEST_BYTES:
            fail("manifest exceeds the 1 MiB size limit")
        raw = bytearray()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_MANIFEST_BYTES:
                fail("manifest exceeds the 1 MiB size limit")
        after = os.fstat(descriptor)
        if file_identity(before) != file_identity(after) or len(raw) != before.st_size:
            fail("manifest changed while it was read")
        document = json.loads(
            bytes(raw).decode("ascii"),
            object_pairs_hook=strict_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"manifest is not strict ASCII JSON: {exc}")
    finally:
        os.close(descriptor)
    if not isinstance(document, dict):
        fail("manifest root must be an object")
    return document, hashlib.sha256(bytes(raw)).hexdigest()


def validate_entry(entry: Any) -> tuple[str, int, str]:
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
        fail("each manifest file entry must contain only path, sha256, and size")
    path = entry["path"]
    size = entry["size"]
    digest = entry["sha256"]
    if not isinstance(path, str) or PurePosixPath(path).name != path or path in ("", ".", ".."):
        fail(f"manifest contains an unsafe artifact path: {path!r}")
    if "\\" in path:
        fail(f"manifest contains an unsafe artifact path: {path!r}")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        fail(f"manifest contains an invalid size for {path}")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        fail(f"manifest contains an invalid SHA-256 for {path}")
    return path, size, digest


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a strict offline artifact manifest.")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--python-tag", required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--architecture", required=True)
    args = parser.parse_args()

    if args.root.is_symlink() or not args.root.is_dir():
        fail(f"offline artifact root must be a real directory: {args.root}")
    root = args.root.resolve()
    manifest = args.manifest.absolute()
    if manifest.parent.resolve() != root:
        fail("manifest must be directly inside the offline artifact root")
    document, manifest_digest = load_manifest(manifest)
    if set(document) != {"api_version", "files", "kind", "label", "target"}:
        fail("manifest contains missing or unknown top-level fields")
    if document["api_version"] != API_VERSION or document["kind"] != KIND:
        fail("manifest API version or kind is unsupported")
    if document["label"] != args.label:
        fail("manifest label does not match the required label")
    expected_target = {
        "implementation": "cp",
        "python_tag": args.python_tag,
        "platform_tag": args.platform_tag,
        "architecture": args.architecture,
    }
    if document["target"] != expected_target:
        fail("manifest target does not match the required Python platform")
    if not isinstance(document["files"], list) or not document["files"]:
        fail("manifest files must be a non-empty array")

    entries = [validate_entry(entry) for entry in document["files"]]
    names = [entry[0] for entry in entries]
    if names != sorted(names) or len(names) != len(set(names)):
        fail("manifest artifact paths must be sorted and unique")

    actual_names: list[str] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.name == manifest.name:
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            fail(f"offline artifact root contains a non-regular file: {path.name}")
        actual_names.append(path.name)
    if actual_names != names:
        fail(f"offline artifact set differs from manifest: expected {names}, found {actual_names}")

    for name, expected_size, expected_digest in entries:
        artifact = root / name
        actual_size, actual_digest = artifact_metadata(artifact)
        if actual_size != expected_size:
            fail(f"offline artifact size mismatch: {name}")
        if not hmac.compare_digest(actual_digest, expected_digest):
            fail(f"offline artifact SHA-256 mismatch: {name}")
    print(
        json.dumps(
            {
                "files": len(entries),
                "manifest_sha256": "sha256:" + manifest_digest,
                "ok": True,
                "target": expected_target,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
