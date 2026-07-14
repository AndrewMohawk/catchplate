#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_VERSION = "serverware.sourceTree/v2"
SOURCE_SUFFIXES = {
    ".cfg",
    ".conf",
    ".css",
    ".env",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".lock",
    ".md",
    ".png",
    ".py",
    ".rs",
    ".sh",
    ".sql",
    ".svg",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SOURCE_NAMES = {
    ".dockerignore",
    ".gitignore",
    "Dockerfile",
    "Dockerfile.production",
    "Justfile",
    "Makefile",
    "Procfile",
    "requirements.txt",
}
SOURCE_ROOTS = {"data-plane", "schemas", "scripts", "security", "serverware"}
EXCLUDED_PARTS = (
    ".git",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tmp",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
)
UNTRACKED_RUNTIME_FILES = {"ops/production-readiness.env"}


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def is_source_file(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    rel_text = rel.as_posix()
    if rel_text in UNTRACKED_RUNTIME_FILES or any(part in EXCLUDED_PARTS for part in rel.parts):
        return False
    if path.name.startswith(".") or path.name in SOURCE_NAMES or path.name.startswith("Dockerfile."):
        return True
    if path.name.endswith(".env.example") or path.suffix in SOURCE_SUFFIXES:
        return True
    return bool(rel.parts and rel.parts[0] in SOURCE_ROOTS)


def _git_tracked_entries(root: Path) -> dict[str, tuple[str, str]] | None:
    try:
        top_level = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        ).stdout.decode("utf-8", errors="surrogateescape").strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    if Path(top_level).resolve() != root.resolve():
        return None

    try:
        raw = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--stage", "-z"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"could not enumerate tracked source-tree entries: {detail}") from exc

    tracked: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, path_raw = record.partition(b"\t")
        if not separator:
            raise ValueError("git returned a malformed tracked source-tree entry")
        fields = metadata.split()
        if len(fields) != 3:
            raise ValueError("git returned malformed tracked source-tree metadata")
        mode_raw, object_id_raw, stage_raw = fields
        path = path_raw.decode("utf-8", errors="surrogateescape")
        if stage_raw != b"0":
            raise ValueError(f"source tree contains an unmerged tracked entry: {path}")
        if path in tracked:
            raise ValueError(f"source tree contains a duplicate tracked entry: {path}")
        tracked[path] = (mode_raw.decode("ascii"), object_id_raw.decode("ascii"))
    return tracked


def _filesystem_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for current_raw, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_raw)
        directory_names.sort()
        file_names.sort()
        kept_directories: list[str] = []
        for name in directory_names:
            path = current / name
            if name in EXCLUDED_PARTS:
                continue
            if path.is_symlink():
                paths.append(path)
            else:
                kept_directories.append(name)
        directory_names[:] = kept_directories
        paths.extend(current / name for name in file_names)
    return paths


def _normalized_mode(value: int, entry_type: str) -> str:
    if entry_type == "file":
        return "100755" if value & 0o111 else "100644"
    if entry_type == "symlink":
        return "120000"
    return f"{value:06o}"


def _entry_for_path(path: Path, root: Path, *, tracked: tuple[str, str] | None) -> dict[str, Any]:
    rel = path.relative_to(root).as_posix()
    if tracked is not None and tracked[0] == "160000":
        return {"path": rel, "type": "gitlink", "mode": "160000", "target": tracked[1]}
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if tracked is None:
            raise
        return {"path": rel, "type": "missing", "mode": tracked[0]}

    if stat.S_ISLNK(metadata.st_mode):
        target = os.readlink(path)
        target_raw = os.fsencode(target)
        return {
            "path": rel,
            "type": "symlink",
            "mode": _normalized_mode(metadata.st_mode, "symlink"),
            "target": target,
            "target_bytes": len(target_raw),
            "target_sha256": sha256_prefixed_bytes(target_raw),
        }
    if stat.S_ISREG(metadata.st_mode):
        raw = path.read_bytes()
        return {
            "path": rel,
            "type": "file",
            "mode": _normalized_mode(metadata.st_mode, "file"),
            "bytes": len(raw),
            "sha256": sha256_prefixed_bytes(raw),
        }
    if stat.S_ISDIR(metadata.st_mode):
        return {"path": rel, "type": "directory", "mode": _normalized_mode(metadata.st_mode, "directory")}
    raise ValueError(f"source-tree entry has unsupported file type: {rel}")


def source_tree_files(root: Path = ROOT) -> list[dict[str, Any]]:
    root = root.resolve()
    tracked = _git_tracked_entries(root)
    selected: dict[str, tuple[Path, tuple[str, str] | None]] = {}
    if tracked is not None:
        for rel, metadata in tracked.items():
            selected[rel] = (root / rel, metadata)

    for path in _filesystem_paths(root):
        rel = path.relative_to(root).as_posix()
        if rel in selected:
            continue
        if is_source_file(path, root):
            selected[rel] = (path, None)

    return [
        _entry_for_path(path, root, tracked=metadata)
        for _, (path, metadata) in sorted(selected.items())
    ]


def _manifest(files: list[dict[str, Any]]) -> dict[str, Any]:
    return {"version": MANIFEST_VERSION, "files": files}


def source_tree_digest(root: Path = ROOT) -> str:
    files = source_tree_files(root)
    return sha256_prefixed_bytes(canonical_json(_manifest(files)).encode("utf-8"))


def source_tree_summary(root: Path = ROOT) -> dict[str, Any]:
    files = source_tree_files(root)
    return {
        "version": MANIFEST_VERSION,
        "files": files,
        "digest": sha256_prefixed_bytes(canonical_json(_manifest(files)).encode("utf-8")),
        "exclusions": list(EXCLUDED_PARTS),
        "selection": "all tracked entries plus relevant untracked source/build/config inputs; relevant filesystem inputs without Git",
    }
