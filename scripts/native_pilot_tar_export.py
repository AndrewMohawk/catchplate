"""Materialize one bounded raw runtime TAR into NEW caller-owned staging.

This handles the local exporter's inability to populate already-read-only
directories. It is not a privileged installer, source verifier or approval:
archive ownership is not applied, and the existing strict runtime inventory
and package checks must still run on the resulting tree. Partials are retained.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tarfile

import native_pilot_runtime_artifacts as runtime
from package_native_pilot_runtime import MAX_ARCHIVE_BYTES, directory, entry_parent

_BLOCK = 512
_CHUNK = 1024 * 1024
_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_PAX_FIELDS = frozenset(("path", "linkpath", "mtime", "atime", "ctime", "uname", "gname"))


def _require(value, message):
    if not value:
        raise ValueError(message)


def _read(fd, offset, size):
    result = bytearray()
    while len(result) < size:
        part = os.pread(fd, size - len(result), offset + len(result))
        _require(bool(part), "raw runtime archive is truncated")
        result.extend(part)
    return bytes(result)


def _hash(fd, size):
    digest = hashlib.sha256()
    for offset in range(0, size, _CHUNK):
        digest.update(_read(fd, offset, min(_CHUNK, size - offset)))
    _require(not os.pread(fd, 1, size), "raw runtime archive grew")
    return "sha256:" + digest.hexdigest()


def _pax(raw):
    """Only bounded local POSIX path/link/time metadata, never sparse/xattrs."""
    result, offset = {}, 0
    while offset < len(raw):
        space = raw.find(b" ", offset, offset + 9)
        number = raw[offset:space] if space >= 0 else b""
        _require(number.isdigit() and not number.startswith(b"0"), "invalid bounded PAX length")
        length = int(number)
        _require(length >= 5 and offset + length <= len(raw), "PAX record exceeds its member")
        record = raw[space + 1:offset + length]
        _require(record.endswith(b"\n") and b"=" in record, "invalid PAX record")
        key, value = record[:-1].split(b"=", 1)
        key, value = key.decode("ascii"), value.decode("ascii")
        _require(key in _PAX_FIELDS and key not in result and len(value) <= runtime.MAX_PATH_BYTES,
                 "unsupported, duplicate or oversized PAX field")
        result[key] = value
        offset += length
    return result


def _records(fd, size):
    records, offset, total, metadata, headers = {}, 0, 0, 0, 0
    pending = None
    while offset + _BLOCK <= size:
        raw = _read(fd, offset, _BLOCK)
        if raw == bytes(_BLOCK):
            _require(pending is None and offset + 2 * _BLOCK <= size
                     and _read(fd, offset + _BLOCK, _BLOCK) == bytes(_BLOCK),
                     "raw runtime archive lacks its complete terminator")
            for position in range(offset + 2 * _BLOCK, size, _CHUNK):
                _require(not any(_read(fd, position, min(_CHUNK, size - position))),
                         "raw runtime archive has trailing content")
            break
        headers += 1
        _require(headers <= 2 * runtime.MAX_ENTRIES and raw[257:263] in (b"ustar\0", b"ustar "),
                 "raw runtime archive header format/count is unsupported")
        info = tarfile.TarInfo.frombuf(raw, "ascii", "strict")
        _require(type(info.size) is int and 0 <= info.size <= runtime.MAX_FILE_BYTES,
                 "raw runtime member exceeds its byte bound")
        data_offset = offset + _BLOCK
        successor = data_offset + ((info.size + _BLOCK - 1) // _BLOCK) * _BLOCK
        _require(successor <= size, "raw runtime member extends beyond the archive")
        if info.type == tarfile.XHDTYPE:
            _require(pending is None and 0 < info.size <= 4 * runtime.MAX_PATH_BYTES,
                     "local PAX metadata exceeds its bound or is nested")
            pending = _pax(_read(fd, data_offset, info.size))
            metadata += info.size
            _require(metadata <= runtime.MAX_MANIFEST_BYTES, "raw runtime metadata exceeds its aggregate bound")
            offset = successor
            continue
        _require(info.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE),
                 "raw runtime archive contains a hardlink, sparse or special member")
        # Read the spelling before TarInfo strips directory slashes. One TAR
        # directory terminator is permitted; ambiguous path components are not.
        name = raw[:100].split(b"\0", 1)[0].decode("ascii")
        prefix = raw[345:500].split(b"\0", 1)[0].decode("ascii")
        name = prefix + "/" + name if prefix else name
        extra = pending or {}
        name = extra.get("path", name)
        if info.isdir() and name.endswith("/"):
            name = name[:-1]
        runtime._path(name)
        _require(name not in records and len(records) < runtime.MAX_ENTRIES,
                 "raw runtime archive repeats a path or exceeds its entry bound")
        _require(type(info.mode) is int and 0 <= info.mode <= 0o7777 and info.mode & 0o6000 == 0,
                 "raw runtime member has unsupported or set-id mode")
        kind = "directory" if info.isdir() else "symlink" if info.issym() else "file"
        link = extra.get("linkpath", info.linkname)
        _require(kind == "symlink" or not link, "non-symlink runtime member supplies a link target")
        record = {"path": name, "type": kind, "mode": info.mode, "bytes": info.size, "offset": data_offset}
        if kind == "file":
            total += info.size
            _require(total <= runtime.MAX_TOTAL_BYTES, "raw runtime regular bytes exceed their aggregate bound")
        else:
            _require(info.size == 0, "runtime directory or symlink carries data")
        if kind == "symlink":
            _require(info.mode == 0o777 and runtime._text(link), "unsupported symlink mode or target")
            record["target"] = link
        metadata += len(name) + len(link) + 128
        _require(metadata <= runtime.MAX_MANIFEST_BYTES, "runtime record metadata exceeds its bound")
        records[name] = record
        pending, offset = None, successor
    else:
        raise ValueError("raw runtime archive lacks a bounded terminator")
    _require(bool(records), "raw runtime archive is empty")
    for name in records:
        parent = name.rpartition("/")[0]
        _require(not parent or records.get(parent, {}).get("type") == "directory",
                 "runtime member lacks an explicit real-directory parent")
    resolver = runtime._Inventory()
    resolver.records = records
    for name, record in records.items():
        if record["type"] == "symlink":
            resolver.resolve(name)  # Logical rootfs resolution only; no host traversal.
    return records, total


def _write_file(archive_fd, root_fd, record):
    with entry_parent(root_fd, record["path"]) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            initial = os.fstat(fd)
            digest = hashlib.sha256()
            for offset in range(0, record["bytes"], _CHUNK):
                raw = _read(archive_fd, record["offset"] + offset, min(_CHUNK, record["bytes"] - offset))
                digest.update(raw)
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    _require(written > 0, "runtime staging write made no progress")
                    view = view[written:]
            os.fchmod(fd, record["mode"])
            os.fsync(fd)
            after = os.fstat(fd)
            _require(stat.S_ISREG(after.st_mode) and after.st_nlink == 1
                     and (after.st_dev, after.st_ino) == (initial.st_dev, initial.st_ino)
                     and after.st_size == record["bytes"] and stat.S_IMODE(after.st_mode) == record["mode"]
                     and _hash(fd, record["bytes"]) == "sha256:" + digest.hexdigest()
                     and runtime._identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == runtime._identity(after),
                     "runtime staging file failed exact readback")
            os.fsync(parent)
        finally:
            os.close(fd)


def materialize(archive: Path, destination: Path) -> dict:
    """Read one stable TAR and create a fresh private tree; never clean partials.

    Host UID/GID remain the caller's. Files and directories receive the exact
    archive modes, but ownership, timestamps and PAX attributes are not installed.
    The caller must perform unchanged strict source inventory/package admission.
    """
    _require(isinstance(archive, Path) and isinstance(destination, Path)
             and archive.is_absolute() and destination.is_absolute()
             and destination != Path("/") and archive != destination
             and destination not in archive.parents,
             "runtime materialization requires distinct absolute archive/new-tree paths")
    with directory(archive.parent) as archive_parent, directory(destination.parent) as parent:
        fd = os.open(archive.name, _FLAGS, dir_fd=archive_parent)
        try:
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                     and 0 < before.st_size <= MAX_ARCHIVE_BYTES and before.st_size % _BLOCK == 0,
                     "raw runtime archive type, links or size is unsupported")
            records, total = _records(fd, before.st_size)
            digest = _hash(fd, before.st_size)
            _require(runtime._identity(os.fstat(fd)) == runtime._identity(before), "raw runtime archive changed during validation")
            # Validate everything before the first filesystem write. mkdir is
            # exclusive; there is no adoption, overwrite, cleanup or retry.
            os.mkdir(destination.name, 0o700, dir_fd=parent)
            root = os.open(destination.name, _FLAGS | os.O_DIRECTORY, dir_fd=parent)
            try:
                os.fchmod(root, 0o700)
                root_identity = os.fstat(root)
                os.fsync(parent)
                directories = sorted((r for r in records.values() if r["type"] == "directory"),
                                     key=lambda r: (r["path"].count("/"), r["path"]))
                for record in directories:
                    with entry_parent(root, record["path"]) as (held, name):
                        os.mkdir(name, 0o700, dir_fd=held)
                        child = os.open(name, _FLAGS | os.O_DIRECTORY, dir_fd=held)
                        try:
                            os.fchmod(child, 0o700)
                        finally:
                            os.close(child)
                for record in records.values():
                    if record["type"] == "file":
                        _write_file(fd, root, record)
                # No operation below traverses a runtime symlink. All real
                # directories/files exist before any runtime link is created.
                for record in records.values():
                    if record["type"] == "symlink":
                        with entry_parent(root, record["path"]) as (held, name):
                            os.symlink(record["target"], name, dir_fd=held)
                            info = os.stat(name, dir_fd=held, follow_symlinks=False)
                            _require(stat.S_ISLNK(info.st_mode) and info.st_nlink == 1
                                     and stat.S_IMODE(info.st_mode) == record["mode"]
                                     and os.readlink(name, dir_fd=held) == record["target"], "runtime symlink changed during staging")
                            os.fsync(held)
                for record in reversed(directories):
                    with entry_parent(root, record["path"]) as (held, name):
                        child = os.open(name, _FLAGS | os.O_DIRECTORY, dir_fd=held)
                        try:
                            os.fchmod(child, record["mode"])
                            os.fsync(child)
                            _require(stat.S_IMODE(os.fstat(child).st_mode) == record["mode"], "runtime directory mode changed")
                        finally:
                            os.close(child)
                os.fsync(root)
                _require(_hash(fd, before.st_size) == digest
                         and runtime._identity(os.fstat(fd)) == runtime._identity(before)
                         and runtime._identity(os.stat(archive.name, dir_fd=archive_parent, follow_symlinks=False)) == runtime._identity(before),
                         "raw runtime archive changed during materialization")
                named = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
                _require((named.st_dev, named.st_ino) == (root_identity.st_dev, root_identity.st_ino)
                         and stat.S_ISDIR(named.st_mode) and stat.S_IMODE(named.st_mode) == 0o700,
                         "private runtime staging root changed")
            finally:
                os.close(root)
        finally:
            os.close(fd)
    return {"apiVersion": "catchplate.nativePilotRawRuntimeMaterialization/v1",
            "archiveSha256": digest, "archiveBytes": before.st_size,
            "entryCount": len(records), "regularBytes": total,
            "hostOwnership": "caller-owned staging; archive UID/GID not installed",
            "releaseAuthority": False, "installed": False, "executionAccepted": False,
            "boundary": "Raw build-output staging only; unchanged strict source inventory and package checks remain required."}
