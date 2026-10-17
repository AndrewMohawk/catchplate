#!/usr/bin/env python3
"""Read-only verification of an immutable operator Git source snapshot.

No application imports, lifecycle actions, private environment reads or writes.
The caller creates the archive separately; verification is not deployment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


def source_root(repo, commit, source_directory=None):
    root = repo.parent / ("catchplate-operator-artifacts/source-" + commit) if source_directory is None else Path(source_directory)
    if source_directory is not None and (type(source_directory) is not str or
            len(source_directory) > 4096 or str(root) != source_directory):
        raise ValueError("exact source directory required")
    if not root.is_absolute() or root.name != "source-" + commit or root.resolve(strict=True) != root or \
            not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("exact source directory required")
    return root


def verify(commit, source_directory=None):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("exact commit required")
    repo = Path(__file__).resolve().parents[1]
    root = source_root(repo, commit, source_directory)
    raw = subprocess.check_output(["git", "-C", str(repo), "ls-tree", "-rz", commit], timeout=30)
    assert len(raw) <= 8 * 1024 * 1024
    expected, manifest, total = set(), [], 0
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, relative = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split(" ")
        assert kind == "blob" and mode in {"100644", "100755"}
        name = os.fsdecode(relative)
        path = root / name
        assert path.resolve() == path and not Path(name).is_absolute()
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == (0o555 if mode == "100755" else 0o444)
        total += info.st_size
        assert info.st_size <= 64 * 1024 * 1024 and total <= 1024 * 1024 * 1024
        content = path.read_bytes()
        assert hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest() == oid
        expected.add(name)
        assert len(expected) <= 16384
        manifest.append([name, mode, hashlib.sha256(content).hexdigest()])
    observed = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        info = Path(directory).lstat()
        assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555
        assert all(not (Path(directory) / name).is_symlink() for name in dirs)
        observed.update(str((Path(directory) / name).relative_to(root)) for name in files)
        assert len(observed) <= 16384
    assert expected and observed == expected
    return {"ok": True, "commit": commit, "source": str(root), "files": len(expected),
        "git_blob_equality": True, "world_readable_and_nonwritable": True,
        "manifest_sha256": hashlib.sha256(json.dumps(sorted(manifest), separators=(",", ":")).encode()).hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-directory", help="Exact absolute immutable source-COMMIT directory; default remains beside the repository")
    try:
        args = parser.parse_args()
        print(json.dumps(verify(args.commit, args.source_directory), sort_keys=True))
    except Exception:
        print('{"ok":false,"error":"source snapshot verification refused"}')
        raise SystemExit(1) from None
