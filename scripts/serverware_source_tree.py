#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SOURCE_SUFFIXES = {".py", ".sh", ".json", ".toml", ".lock", ".md", ".yml", ".yaml"}
SOURCE_NAMES = {"Dockerfile", "Dockerfile.production", "Makefile", "requirements.txt", ".dockerignore"}
EXCLUDED_PARTS = (".git", ".tmp", "__pycache__", "target")


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def is_source_file(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if any(part in EXCLUDED_PARTS for part in rel.parts):
        return False
    return path.suffix in SOURCE_SUFFIXES or path.name in SOURCE_NAMES or bool(rel.parts and rel.parts[0] == "security")


def source_tree_files(root: Path = ROOT) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or not is_source_file(path, root):
            continue
        rel = path.relative_to(root)
        raw = path.read_bytes()
        files.append({"path": str(rel), "bytes": len(raw), "sha256": sha256_prefixed_bytes(raw)})
    return files


def source_tree_digest(root: Path = ROOT) -> str:
    return sha256_prefixed_bytes(canonical_json(source_tree_files(root)).encode("utf-8"))


def source_tree_summary(root: Path = ROOT) -> dict[str, Any]:
    files = source_tree_files(root)
    return {
        "files": files,
        "digest": sha256_prefixed_bytes(canonical_json(files).encode("utf-8")),
        "exclusions": list(EXCLUDED_PARTS),
    }
