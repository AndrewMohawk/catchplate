"""Measure an already frozen local source tree, without issuing authority.

No flags are set here. A read-only mount or actual immutable inode flags must
already protect every object. A successful scan is not closure/rootfs analysis,
provenance, installation, or hostile-root protection.
"""
from __future__ import annotations

import array
import fcntl
import hashlib
import os
from pathlib import PurePosixPath
import stat

from serverware import authority_artifact_spec as spec

FS_IOC_GETFLAGS = 0x80086601
FS_IOC_GETVERSION = 0x80087601
FS_IMMUTABLE_FL = 0x10
FIELDS = frozenset({"path", "kind", "mode", "uid", "gid"})


def _require(value):
    if not value:
        raise ValueError("local artifact source measurement refused")


def _ioctl_number(fd, request):
    result = array.array("l", [0])
    _require(result.itemsize == 8)
    fcntl.ioctl(fd, request, result, True)
    return result[0]


def _frozen(fd):
    if not os.fstatvfs(fd).f_flag & os.ST_RDONLY:
        _require(_ioctl_number(fd, FS_IOC_GETFLAGS) & FS_IMMUTABLE_FL)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _named_root(runtime_path):
    _require(isinstance(runtime_path, str) and runtime_path.isascii()
             and runtime_path.startswith("/") and runtime_path != "/"
             and str(PurePosixPath(runtime_path)) == runtime_path
             and all(part not in (".", "..") for part in runtime_path.split("/")[1:]))
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in runtime_path.split("/")[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def root_identity(root_fd, runtime_path):
    """Actual root identity; refuse unavailable/zero inode generation."""
    _require(type(root_fd) is int and root_fd >= 3)
    info = os.fstat(root_fd)
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and not stat.S_IMODE(info.st_mode) & 0o022)
    _frozen(root_fd)
    named = _named_root(runtime_path)
    try:
        _require(_identity(os.fstat(named)) == _identity(info))
    finally:
        os.close(named)
    with open(f"/proc/self/fdinfo/{root_fd}", "rt", encoding="ascii") as stream:
        text = stream.read(16385)
    _require(len(text) <= 16384)
    mounts = [line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("mnt_id:")]
    _require(len(mounts) == 1 and mounts[0].isdigit() and int(mounts[0]) > 0)
    generation = _ioctl_number(root_fd, FS_IOC_GETVERSION)
    _require(generation > 0)
    return dict(runtimePath=runtime_path, device=info.st_dev, inode=info.st_ino,
                generation=generation, mountId=int(mounts[0]), mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid, gid=info.st_gid)


def _enumerate(root_fd, paths, *, check):
    """Bound work by the selected roster, rejecting the first extra entry."""
    directories = {""}
    for path in paths:
        parts = path.split("/")
        _require(len(parts) <= 64)
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    _require(not set(paths) & directories and len(directories) <= spec.MAX_BUNDLE_FILES)
    found = set()
    visited = set()

    def visit(fd, prefix):
        check()
        info = os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                 and not stat.S_IMODE(info.st_mode) & 0o022)
        _frozen(fd)
        before = _identity(info)
        visited.add(prefix)
        with os.scandir(fd) as entries:
            for entry in entries:
                check()
                name = prefix + "/" + entry.name if prefix else entry.name
                _require(name in paths or name in directories)
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
                if name in directories:
                    flags |= os.O_DIRECTORY
                child = os.open(entry.name, flags, dir_fd=fd)
                try:
                    child_info = os.fstat(child)
                    if name in directories:
                        visit(child, name)
                    else:
                        _require(stat.S_ISREG(child_info.st_mode) and child_info.st_nlink == 1
                                 and child_info.st_uid == child_info.st_gid == 0
                                 and not stat.S_IMODE(child_info.st_mode) & 0o022)
                        _frozen(child)
                        found.add(name)
                finally:
                    os.close(child)
        _require(_identity(os.fstat(fd)) == before)

    visit(root_fd, "")
    _require(found == set(paths) and visited == directories)


def measure_file(root_fd, entry, *, check):
    """Nofollow/nonblocking, chunk-checked real file measurement."""
    _require(isinstance(entry, dict) and set(entry) == FIELDS)
    path = spec._require_relative_path(entry["path"], name="source path")
    current = os.dup(root_fd)
    try:
        for part in path.split("/")[:-1]:
            check()
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        check()
        descriptor = os.open(path.split("/")[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                             dir_fd=current)
    finally:
        os.close(current)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 <= before.st_size <= spec.MAX_FILE_BYTES
                 and stat.S_IMODE(before.st_mode) == entry["mode"]
                 and before.st_uid == entry["uid"] and before.st_gid == entry["gid"])
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            check()
            raw = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            _require(bool(raw))
            digest.update(raw)
            offset += len(raw)
        check()
        _require(not os.pread(descriptor, 1, offset) and _identity(os.fstat(descriptor)) == _identity(before))
        result = dict(entry, size=before.st_size, sha256="sha256:" + digest.hexdigest())
        spec._validate_file_entry(result)
        return result
    finally:
        os.close(descriptor)


def measure_tree(root_fd, file_inputs, *, runtime_path, check):
    """Measure exact metadata-selected files from a genuinely frozen root FD."""
    _require(callable(check) and isinstance(file_inputs, (list, tuple))
             and 0 < len(file_inputs) <= spec.MAX_BUNDLE_FILES)
    paths = []
    for entry in file_inputs:
        _require(isinstance(entry, dict) and set(entry) == FIELDS)
        paths.append(spec._require_relative_path(entry["path"], name="source path"))
    _require(paths == sorted(set(paths)))
    check()
    before = root_identity(root_fd, runtime_path)
    _enumerate(root_fd, set(paths), check=check)
    files = []
    total = 0
    for entry in file_inputs:
        check()
        measured = measure_file(root_fd, entry, check=check)
        total += measured["size"]
        _require(total <= spec.MAX_TOTAL_BUNDLE_BYTES)
        files.append(measured)
    _enumerate(root_fd, set(paths), check=check)
    _require(before == root_identity(root_fd, runtime_path))
    check()
    return dict(rootIdentity=before, files=files, totalBytes=total,
                treeDigest=spec.domain_digest(spec.SOURCE_TREE_DIGEST_DOMAIN, spec.canonical_json_bytes(files)),
                enumeratedTreeDigest=spec.domain_digest("serverware.authorityEnumeratedTree/v1",
                                                       spec.canonical_json_bytes(files)))
