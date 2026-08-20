#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_VERSION = "serverware.sourceTree/v3"
ARCHIVE_CONTRACT_VERSION = "serverware.sourceArchive/v1"
PRODUCTION_IDENTITY_MODE = "production-commit"
DEVELOPMENT_IDENTITY_MODE = "development-dirty-tree"
DEFAULT_CONTRACT_DIR = ROOT / "production-dependencies/cache/source-contract"
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
SOURCE_ROOTS = {
    "data-plane",
    "ops",
    "policies",
    "production-dependencies",
    "schemas",
    "scripts",
    "security",
    "serverware",
}
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
    "cache",
    "dist",
    "node_modules",
    "target",
    "venv",
)
UNTRACKED_RUNTIME_FILES = {"ops/production-readiness.env"}
SAFE_SOURCE_PATH = re.compile(r"\A[A-Za-z0-9._@+/-]+\Z")
GIT_EXECUTABLE = Path("/usr/bin/git")
GIT_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _require_safe_source_path(path: str) -> None:
    if (
        not path
        or not path.isascii()
        or SAFE_SOURCE_PATH.fullmatch(path) is None
        or path.startswith("/")
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ValueError(f"source contains an ambiguous path: {path!r}")


def _repository_git_dir(root: Path) -> Path:
    git_dir = root / ".git"
    try:
        metadata = git_dir.lstat()
    except FileNotFoundError as exc:
        raise ValueError("source root does not contain a Git metadata directory") from exc
    if not stat.S_ISDIR(metadata.st_mode) or git_dir.is_symlink():
        raise ValueError("production source requires a non-symlink .git directory")
    for relative in ("info/grafts", "objects/info/alternates"):
        candidate = git_dir / relative
        if candidate.exists() or candidate.is_symlink():
            raise ValueError(f"production source forbids Git object indirection: .git/{relative}")
    return git_dir


def _git(root: Path, args: list[str], *, input_bytes: bytes | None = None) -> bytes:
    git_dir = _repository_git_dir(root)
    if not GIT_EXECUTABLE.is_file() or GIT_EXECUTABLE.is_symlink():
        raise ValueError(f"required Git executable is unavailable: {GIT_EXECUTABLE}")
    result = subprocess.run(
        [
            str(GIT_EXECUTABLE),
            "--no-pager",
            f"--git-dir={git_dir}",
            f"--work-tree={root}",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
            *args,
        ],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd="/",
        env=GIT_ENVIRONMENT,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def _git_text(root: Path, args: list[str]) -> str:
    return _git(root, args).decode("utf-8", errors="strict").strip()


def _require_repository_root(root: Path) -> Path:
    root = root.resolve()
    _repository_git_dir(root)
    top_level = Path(_git_text(root, ["rev-parse", "--show-toplevel"])).resolve()
    if top_level != root:
        raise ValueError(f"source root is not the Git worktree root: {root}")
    git_common_dir = Path(
        _git_text(root, ["rev-parse", "--path-format=absolute", "--git-common-dir"])
    ).resolve()
    if git_common_dir != (root / ".git").resolve():
        raise ValueError("production source Git common directory is not the repository .git directory")
    return root


def _production_git_identity(root: Path) -> dict[str, str]:
    root = _require_repository_root(root)
    object_format = _git_text(root, ["rev-parse", "--show-object-format"])
    if object_format != "sha1":
        raise ValueError(f"unsupported Git object format for production source: {object_format}")
    replacement_refs = _git_text(root, ["for-each-ref", "--format=%(refname)", "refs/replace"])
    if replacement_refs:
        raise ValueError("production source forbids Git replacement refs")
    commit = _git_text(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ValueError("production source commit is not a canonical SHA-1 object ID")
    commit_object = _git(root, ["cat-file", "commit", commit])
    committer_lines = [line for line in commit_object.splitlines() if line.startswith(b"committer ")]
    if len(committer_lines) != 1:
        raise ValueError("production source commit has an invalid committer identity")
    timestamp_fields = committer_lines[0].rsplit(b" ", 2)
    if len(timestamp_fields) != 3 or not timestamp_fields[1].isdigit():
        raise ValueError("production source commit has an invalid committer timestamp")
    commit_timestamp = timestamp_fields[1].decode("ascii")
    tree = _git_text(root, ["rev-parse", "--verify", f"{commit}^{{tree}}"])
    index_tree = _git_text(root, ["write-tree"])
    if index_tree != tree:
        raise ValueError("production source index differs from the exact HEAD tree")
    status = _git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if status:
        changed = [
            item.decode("utf-8", errors="replace")
            for item in status.split(b"\0")
            if item
        ]
        preview = ", ".join(changed[:8])
        suffix = " ..." if len(changed) > 8 else ""
        raise ValueError(
            "production source requires a clean index and worktree at the exact commit: "
            f"{preview}{suffix}"
        )
    return {"commit": commit, "commitTimestamp": commit_timestamp, "gitTree": tree}


def _commit_entries(root: Path, commit: str) -> list[dict[str, Any]]:
    raw = _git(root, ["ls-tree", "-r", "-z", "--full-tree", commit])
    entries: list[dict[str, Any]] = []
    observed: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, path_raw = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise ValueError("git returned a malformed source-tree entry")
        mode_raw, object_type_raw, object_id_raw = fields
        path = path_raw.decode("utf-8", errors="strict")
        _require_safe_source_path(path)
        if path in observed:
            raise ValueError(f"production source contains an unsafe or duplicate path: {path}")
        observed.add(path)
        mode = mode_raw.decode("ascii")
        object_type = object_type_raw.decode("ascii")
        object_id = object_id_raw.decode("ascii")
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(
                "production source must contain only regular tracked files; symlinks, submodules, "
                "and special Git entries are forbidden: "
                f"{path} ({mode} {object_type})"
            )
        content = _git(root, ["cat-file", "blob", object_id])
        entry = {
            "path": path,
            "type": "file",
            "mode": mode,
            "gitBlob": object_id,
            "bytes": len(content),
            "sha256": sha256_prefixed_bytes(content),
        }
        entry["_content"] = content
        entries.append(entry)
    if not entries:
        raise ValueError("production source commit contains no tracked files")
    return entries


def _public_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key != "_content"}


def _verify_worktree_matches_commit(root: Path, entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        path = root / entry["path"]
        try:
            metadata = path.lstat()
        except FileNotFoundError as exc:
            raise ValueError(
                f"production worktree is missing tracked input {entry['path']}"
            ) from exc
        expected_executable = entry["mode"] == "100755"
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or bool(metadata.st_mode & 0o111) != expected_executable
            or path.read_bytes() != entry["_content"]
        ):
            raise ValueError(
                f"production worktree file bytes or mode differ from commit: {entry['path']}"
            )


def _tree_manifest(
    entries: list[dict[str, Any]],
    *,
    identity_mode: str,
    commit: str | None,
    commit_timestamp: str | None,
    git_tree: str | None,
) -> dict[str, Any]:
    return {
        "version": MANIFEST_VERSION,
        "identityMode": identity_mode,
        "productionReleaseEligible": identity_mode == PRODUCTION_IDENTITY_MODE,
        "commit": commit,
        "commitTimestamp": commit_timestamp,
        "gitTree": git_tree,
        "files": [_public_entry(entry) for entry in entries],
    }


def _hash_open_descriptor(descriptor: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    return total, "sha256:" + digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _prepare_output_directory(root: Path, output_dir: Path) -> Path:
    root = root.resolve()
    raw_candidate = output_dir if output_dir.is_absolute() else root / output_dir
    candidate = Path(os.path.abspath(raw_candidate))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("source contract output directory must remain inside the worktree") from exc
    if not relative.parts:
        raise ValueError("source contract output directory must not be the worktree root")
    if not any(part in EXCLUDED_PARTS for part in relative.parts):
        raise ValueError(
            "source contract output directory must be under a source-excluded directory"
        )

    current = root
    for part in relative.parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(
                f"source contract output path component must be a non-symlink directory: {current}"
            )
    return candidate


def _write_deterministic_archive(path: Path, entries: list[dict[str, Any]]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "w+b", closefd=False) as archive_file:
            with tarfile.open(fileobj=archive_file, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for entry in entries:
                    info = tarfile.TarInfo(entry["path"])
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    content = entry["_content"]
                    info.type = tarfile.REGTYPE
                    info.mode = 0o755 if entry["mode"] == "100755" else 0o644
                    info.size = len(content)
                    with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as source:
                        source.write(content)
                        source.seek(0)
                        archive.addfile(info, source)
            archive_file.flush()
            os.fsync(descriptor)
        before = os.fstat(descriptor)
        archive_bytes, archive_sha256 = _hash_open_descriptor(descriptor)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ) or archive_bytes != after.st_size:
            raise ValueError("source archive changed while it was being authenticated")
        os.replace(temporary, path)
        _fsync_directory(path.parent)
        final_descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            final_metadata = os.fstat(final_descriptor)
            final_bytes, final_sha256 = _hash_open_descriptor(final_descriptor)
        finally:
            os.close(final_descriptor)
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or (final_metadata.st_dev, final_metadata.st_ino) != (after.st_dev, after.st_ino)
            or final_bytes != archive_bytes
            or final_sha256 != archive_sha256
        ):
            raise ValueError("published source archive does not match the authenticated archive")
        return {"bytes": archive_bytes, "sha256": archive_sha256}
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)


def _write_canonical_json(path: Path, value: dict[str, Any]) -> bytes:
    raw = canonical_json(value).encode("ascii") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return raw


def _write_contract_text(path: Path, raw: bytes) -> dict[str, Any]:
    if not raw or not raw.endswith(b"\n"):
        raise ValueError(f"contract text must be non-empty and newline terminated: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return {"name": path.name, "bytes": len(raw), "sha256": sha256_prefixed_bytes(raw)}


def _verification_contracts(
    output_dir: Path,
    tree_digest: str,
    entries: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    stem = f"source-{tree_digest.removeprefix('sha256:')}"
    file_list = "".join(f"{entry['path']}\n" for entry in entries).encode("ascii")
    file_hashes = "".join(
        f"{entry['sha256'].removeprefix('sha256:')}  {entry['path']}\n" for entry in entries
    ).encode("ascii")
    file_modes = "".join(
        f"{'755' if entry['mode'] == '100755' else '644'}  {entry['path']}\n"
        for entry in entries
    ).encode("ascii")
    return {
        "fileList": _write_contract_text(output_dir / f"{stem}.files", file_list),
        "fileHashes": _write_contract_text(output_dir / f"{stem}.files.sha256", file_hashes),
        "fileModes": _write_contract_text(output_dir / f"{stem}.files.mode", file_modes),
    }


def _source_contract(
    root: Path,
    output_dir: Path,
    *,
    identity_mode: str,
    entries: list[dict[str, Any]],
    commit: str | None,
    commit_timestamp: str | None,
    git_tree: str | None,
) -> dict[str, Any]:
    output_dir = _prepare_output_directory(root, output_dir)
    tree_manifest = _tree_manifest(
        entries,
        identity_mode=identity_mode,
        commit=commit,
        commit_timestamp=commit_timestamp,
        git_tree=git_tree,
    )
    tree_digest = sha256_prefixed_bytes(canonical_json(tree_manifest).encode("ascii"))
    archive_name = f"source-{tree_digest.removeprefix('sha256:')}.tar"
    archive_path = output_dir / archive_name
    archive_metadata = _write_deterministic_archive(archive_path, entries)
    verification = _verification_contracts(output_dir, tree_digest, entries)
    contract = {
        "apiVersion": ARCHIVE_CONTRACT_VERSION,
        "identityMode": identity_mode,
        "productionReleaseEligible": identity_mode == PRODUCTION_IDENTITY_MODE,
        "repository": "https://github.com/example/private-deployment",
        "commit": commit,
        "commitTimestamp": commit_timestamp,
        "gitTree": git_tree,
        "sourceTreeDigest": tree_digest,
        "sourceTreeManifest": tree_manifest,
        "archive": {
            "format": "tar-ustar-deterministic-v1",
            "name": archive_name,
            **archive_metadata,
        },
        "verification": verification,
        "reconstruction": {
            "requiresExactCommit": identity_mode == PRODUCTION_IDENTITY_MODE,
            "trackedFilesOnly": identity_mode == PRODUCTION_IDENTITY_MODE,
            "mtime": 0,
            "uid": 0,
            "gid": 0,
            "entryOrder": "sourceTreeManifest.files order",
        },
    }
    manifest_name = f"source-{tree_digest.removeprefix('sha256:')}.manifest.json"
    manifest_path = output_dir / manifest_name
    manifest_raw = _write_canonical_json(manifest_path, contract)
    return {
        **contract,
        "digest": tree_digest,
        "manifest": {
            "name": manifest_name,
            "sha256": sha256_prefixed_bytes(manifest_raw),
            "bytes": len(manifest_raw),
        },
        "archivePath": archive_path.relative_to(root).as_posix(),
        "manifestPath": manifest_path.relative_to(root).as_posix(),
        "verificationPaths": {
            key: (output_dir / metadata["name"]).relative_to(root).as_posix()
            for key, metadata in verification.items()
        },
    }


def production_source_contract(
    root: Path = ROOT,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    root = _require_repository_root(root)
    selected_output = output_dir or root / "production-dependencies/cache/source-contract"
    identity = _production_git_identity(root)
    entries = _commit_entries(root, identity["commit"])
    _verify_worktree_matches_commit(root, entries)
    return _source_contract(
        root,
        selected_output,
        identity_mode=PRODUCTION_IDENTITY_MODE,
        entries=entries,
        commit=identity["commit"],
        commit_timestamp=identity["commitTimestamp"],
        git_tree=identity["gitTree"],
    )


def is_source_file(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    rel_text = rel.as_posix()
    if rel_text in UNTRACKED_RUNTIME_FILES or any(part in EXCLUDED_PARTS for part in rel.parts):
        return False
    if path.name in SOURCE_NAMES or path.name.startswith("Dockerfile."):
        return True
    if path.name.endswith(".env.example") or path.suffix in SOURCE_SUFFIXES:
        return True
    return bool(rel.parts and rel.parts[0] in SOURCE_ROOTS)


def _development_entries(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for current_raw, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_raw)
        directory_names[:] = sorted(
            name for name in directory_names if name not in EXCLUDED_PARTS
        )
        for name in sorted(file_names):
            path = current / name
            if not is_source_file(path, root):
                continue
            relative = path.relative_to(root).as_posix()
            _require_safe_source_path(relative)
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"development source forbids symlinks: {relative}")
            elif stat.S_ISREG(metadata.st_mode):
                content = path.read_bytes()
                entry = {
                    "path": relative,
                    "type": "file",
                    "mode": "100755" if metadata.st_mode & 0o111 else "100644",
                    "bytes": len(content),
                    "sha256": sha256_prefixed_bytes(content),
                }
            else:
                raise ValueError(f"development source contains an unsupported file: {relative}")
            entry["_content"] = content
            entries.append(entry)
    if not entries:
        raise ValueError("development source tree contains no files")
    return entries


def development_source_contract(
    root: Path = ROOT,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    selected_output = output_dir or root / "production-dependencies/cache/source-contract"
    return _source_contract(
        root,
        selected_output,
        identity_mode=DEVELOPMENT_IDENTITY_MODE,
        entries=_development_entries(root),
        commit=None,
        commit_timestamp=None,
        git_tree=None,
    )


def source_tree_files(root: Path = ROOT) -> list[dict[str, Any]]:
    return [_public_entry(entry) for entry in _development_entries(root.resolve())]


def source_tree_digest(root: Path = ROOT, *, production: bool = True) -> str:
    if production:
        return production_source_contract(root)["digest"]
    manifest = _tree_manifest(
        _development_entries(root.resolve()),
        identity_mode=DEVELOPMENT_IDENTITY_MODE,
        commit=None,
        commit_timestamp=None,
        git_tree=None,
    )
    return sha256_prefixed_bytes(canonical_json(manifest).encode("ascii"))


def source_tree_summary(root: Path = ROOT, *, production: bool = False) -> dict[str, Any]:
    if production:
        return production_source_contract(root)
    entries = _development_entries(root.resolve())
    manifest = _tree_manifest(
        entries,
        identity_mode=DEVELOPMENT_IDENTITY_MODE,
        commit=None,
        commit_timestamp=None,
        git_tree=None,
    )
    return {
        **manifest,
        "digest": sha256_prefixed_bytes(canonical_json(manifest).encode("ascii")),
        "selection": "explicit non-production filesystem snapshot including relevant untracked files",
    }
