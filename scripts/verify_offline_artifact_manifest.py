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


API_VERSION = "catchplate.offlineArtifactManifest/v1"
KIND = "OfflineArtifactManifest"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_BASENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
CHECKSUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,254})$")
CHECKSUMS_NAME = "SHA256SUMS"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CHECKSUMS_BYTES = 1024 * 1024


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


def load_checksums(path: Path) -> tuple[dict[str, str], str]:
    if not hasattr(os, "O_NOFOLLOW"):
        fail("SHA256SUMS cannot be opened without following symlinks")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
        )
    except FileNotFoundError:
        fail(f"SHA256SUMS is missing: {path}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"SHA256SUMS must be a regular file: {path}")
        if before.st_size > MAX_CHECKSUMS_BYTES:
            fail("SHA256SUMS exceeds the 1 MiB size limit")
        raw = bytearray()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_CHECKSUMS_BYTES:
                fail("SHA256SUMS exceeds the 1 MiB size limit")
        after = os.fstat(descriptor)
        if file_identity(before) != file_identity(after) or len(raw) != before.st_size:
            fail("SHA256SUMS changed while it was read")
    finally:
        os.close(descriptor)
    try:
        text = bytes(raw).decode("ascii")
    except UnicodeDecodeError as exc:
        fail(f"SHA256SUMS is not ASCII: {exc}")
    if not text or not text.endswith("\n") or "\r" in text:
        fail("SHA256SUMS must be non-empty ASCII with LF line endings and a final newline")
    lines = text[:-1].split("\n")
    entries: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if match is None:
            fail(f"SHA256SUMS contains a non-canonical line: {line!r}")
        digest, name = match.groups()
        if name in entries:
            fail(f"SHA256SUMS contains a duplicate artifact: {name}")
        entries[name] = digest
    if list(entries) != sorted(entries):
        fail("SHA256SUMS artifact names must be sorted")
    return entries, hashlib.sha256(bytes(raw)).hexdigest()


def validate_entry(entry: Any) -> tuple[str, int, str]:
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
        fail("each manifest file entry must contain only path, sha256, and size")
    path = entry["path"]
    size = entry["size"]
    digest = entry["sha256"]
    if (
        not isinstance(path, str)
        or PurePosixPath(path).name != path
        or path in ("", ".", "..")
        or not SAFE_BASENAME_RE.fullmatch(path)
    ):
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
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--python-tag", required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--architecture", required=True)
    args = parser.parse_args()

    if args.root.is_symlink() or not args.root.is_dir():
        fail(f"offline artifact root must be a real directory: {args.root}")
    root = args.root.resolve()
    manifest = args.manifest.absolute()
    checksums = args.checksums.absolute()
    if manifest.parent.resolve() != root or checksums.parent.resolve() != root:
        fail("manifest and SHA256SUMS must be directly inside the offline artifact root")
    if not SAFE_BASENAME_RE.fullmatch(manifest.name):
        fail("manifest has an unsafe basename")
    if checksums.name != CHECKSUMS_NAME:
        fail(f"checksum file must be named {CHECKSUMS_NAME}")
    if manifest.resolve(strict=False) == checksums.resolve(strict=False):
        fail("manifest and SHA256SUMS must be different files")
    document, manifest_digest = load_manifest(manifest)
    checksum_entries, checksums_digest = load_checksums(checksums)
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

    expected_checksums = {name: digest for name, _, digest in entries}
    expected_checksums[manifest.name] = manifest_digest
    expected_checksum_names = sorted(expected_checksums)
    if list(checksum_entries) != expected_checksum_names:
        fail(
            "SHA256SUMS artifact set differs from the manifest closure: "
            f"expected {expected_checksum_names}, found {list(checksum_entries)}"
        )
    for name in expected_checksum_names:
        if not hmac.compare_digest(checksum_entries[name], expected_checksums[name]):
            fail(f"SHA256SUMS digest does not match the manifest closure: {name}")

    actual_names: list[str] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.name in (manifest.name, checksums.name):
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
                "checksums_sha256": "sha256:" + checksums_digest,
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
