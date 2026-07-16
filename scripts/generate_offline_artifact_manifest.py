#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path


API_VERSION = "serverware.offlineArtifactManifest/v1"
KIND = "OfflineArtifactManifest"
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def fail(message: str) -> None:
    raise SystemExit(message)


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


def artifact_files(root: Path, output: Path) -> list[Path]:
    output_path = output.resolve(strict=False)
    files: list[Path] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.resolve(strict=False) == output_path:
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            fail(f"offline artifact root contains a non-regular file: {path.name}")
        files.append(path)
    if not files:
        fail("offline artifact root contains no files")
    return files


def validate_requirements(files: list[Path], patterns: list[str]) -> None:
    if not patterns or len(patterns) != len(set(patterns)):
        fail("required artifact patterns must be non-empty and unique")
    names = [path.name for path in files]
    for pattern in patterns:
        if not pattern or "/" in pattern or "\\" in pattern or pattern in (".", ".."):
            fail(f"invalid required artifact pattern: {pattern!r}")
        matches = [name for name in names if fnmatch.fnmatchcase(name, pattern)]
        if len(matches) != 1:
            fail(f"required artifact pattern must match exactly once: {pattern!r} matched {matches}")


def write_manifest(output: Path, document: dict[str, object]) -> None:
    try:
        metadata = output.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None and (
        stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
    ):
        fail(f"manifest output must be a regular non-symlink file: {output}")
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii")
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix=f".{output.name}.", delete=False) as temp:
        temporary = Path(temp.name)
        temp.write(payload)
        temp.flush()
        os.fsync(temp.fileno())
    try:
        temporary.chmod(0o644)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a strict offline artifact manifest.")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require", action="append", default=[])
    parser.add_argument("--label", required=True)
    parser.add_argument("--python-tag", required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--architecture", required=True)
    args = parser.parse_args()

    if not LABEL_RE.fullmatch(args.label):
        fail("manifest label must match [a-z0-9][a-z0-9._-]{0,127}")
    if args.root.is_symlink() or not args.root.is_dir():
        fail(f"offline artifact root must be a real directory: {args.root}")

    root = args.root.resolve()
    output = args.output.absolute()
    if output.parent.resolve() != root:
        fail("manifest output must be directly inside the offline artifact root")
    files = artifact_files(root, output)
    validate_requirements(files, args.require)
    entries = []
    for path in files:
        size, digest = artifact_metadata(path)
        entries.append({"path": path.name, "sha256": digest, "size": size})
    target = {
        "implementation": "cp",
        "python_tag": args.python_tag,
        "platform_tag": args.platform_tag,
        "architecture": args.architecture,
    }
    write_manifest(
        output,
        {
            "api_version": API_VERSION,
            "files": entries,
            "kind": KIND,
            "label": args.label,
            "target": target,
        },
    )
    print(
        json.dumps(
            {
                "files": len(entries),
                "manifest_sha256": "sha256:" + artifact_metadata(output)[1],
                "ok": True,
                "target": target,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
