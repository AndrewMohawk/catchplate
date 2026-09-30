#!/usr/bin/env python3
"""Package the fixed, inventoried conductor rootfs without installing or running it.

The build wrapper supplies the actual exported root and the complete result of
native_pilot_runtime_artifacts.inventory. This consumer re-inventories before
and after streaming the exact originals into a deterministic uncompressed tar.
An independently authenticated package hash and an actual privileged installer
remain external requirements; this unsigned package confers no authority.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile

import native_pilot_runtime_artifacts as runtime

MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def directory(path: Path):
    """Open an absolute directory without following any ancestor symlink."""
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)),
            "package paths must be absolute and normalized")
    descriptor = os.open("/", DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            successor = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = successor
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def entry_parent(root_fd: int, relative: str):
    parts = relative.split("/")
    require(all(part not in ("", ".", "..") for part in parts),
            "inventory contains a non-relative archive member")
    descriptor = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            successor = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = successor
        yield descriptor, parts[-1]
    finally:
        os.close(descriptor)


class ArchiveWriter:
    def __init__(self, stream) -> None:
        self.stream = stream
        self.size = 0
        self.digest = hashlib.sha256()

    def write(self, data: bytes) -> int:
        require(self.size + len(data) <= MAX_ARCHIVE_BYTES,
                "runtime tar exceeds the complete archive bound")
        view = memoryview(data)
        while view:
            written = self.stream.write(view)
            require(written is not None and written > 0, "runtime tar write failed")
            view = view[written:]
        self.size += len(data)
        self.digest.update(data)
        return len(data)


class OriginalReader:
    def __init__(self, stream, size: int) -> None:
        self.stream, self.maximum = stream, size
        self.size = 0
        self.digest = hashlib.sha256()

    def read(self, size: int) -> bytes:
        require(type(size) is int and 0 <= size <= self.maximum - self.size,
                "archive requested bytes outside the pinned original")
        data = self.stream.read(size)
        self.size += len(data)
        self.digest.update(data)
        return data


def add_record(archive, root_fd: int, record: dict, epoch: int) -> None:
    relative = record["path"]
    member = tarfile.TarInfo(relative)
    member.mode = int(record["mode"], 8)
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    member.mtime = epoch
    with entry_parent(root_fd, relative) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_IMODE(before.st_mode) == member.mode,
                "runtime original mode changed before packaging")
        if record["type"] == "file":
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_size == record["bytes"],
                    "runtime original type or size changed before packaging")
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                                 | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(descriptor, "rb", buffering=0) as source:
                require(identity(os.fstat(source.fileno())) == identity(before),
                        "runtime original changed while opening")
                member.size = record["bytes"]
                reader = OriginalReader(source, member.size)
                archive.addfile(member, reader)
                require(reader.size == member.size and source.read(1) == b""
                        and "sha256:" + reader.digest.hexdigest() == record["sha256"]
                        and identity(os.fstat(source.fileno())) == identity(before),
                        "runtime original bytes changed during packaging")
        elif record["type"] == "directory":
            require(stat.S_ISDIR(before.st_mode), "runtime directory changed type")
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
        elif record["type"] == "symlink":
            require(stat.S_ISLNK(before.st_mode)
                    and os.readlink(name, dir_fd=parent) == record["target"],
                    "runtime symlink changed before packaging")
            # A's inventory resolves this in the logical rootfs. In particular,
            # an absolute distro link must never be opened against the host.
            member.type = tarfile.SYMTYPE
            member.linkname = record["target"]
            archive.addfile(member)
            require(os.readlink(name, dir_fd=parent) == record["target"],
                    "runtime symlink changed during packaging")
        else:
            raise ValueError("runtime inventory contains an unsupported entry")
        require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                == identity(before), "runtime original name changed during packaging")


def readback(directory_fd: int, name: str, expected_size: int, expected_digest: str) -> None:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                         | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(descriptor, "rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == expected_size and stat.S_IMODE(before.st_mode) == 0o444,
                "written package original differs from its expected shape")
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            data = stream.read(min(1024 * 1024, remaining))
            require(bool(data), "written package original is truncated")
            digest.update(data)
            remaining -= len(data)
        require(stream.read(1) == b"" and "sha256:" + digest.hexdigest() == expected_digest
                and identity(os.fstat(stream.fileno())) == identity(before)
                and identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
                == identity(before), "written package original failed exact readback")


def package(root: Path, inventory: dict, output: Path) -> dict:
    """Create NEW output/runtime-rootfs.tar and package.json; preserve partials.

    Inputs are a root returned by the fixed artifact target and A's full
    source-bound inventory, not arbitrary archive instructions. No output is
    adopted, overwritten, removed, installed, mounted or executed. A successful
    package.json is written only after the tar and final inventory agree.
    """
    return _package(root, inventory, output, authority=False)


def package_authority(root: Path, inventory: dict, output: Path) -> dict:
    """Package only the fixed authority inventory; never project it to conductor approval."""
    return _package(root, inventory, output, authority=True)


def _package(root: Path, inventory: dict, output: Path, *, authority: bool) -> dict:
    inventory_api = runtime.AUTHORITY_API_VERSION if authority else runtime.API_VERSION
    observe = runtime.authority_inventory if authority else runtime.inventory
    require(type(inventory) is dict
            and inventory.get("apiVersion") == inventory_api
            and type(inventory.get("source")) is dict,
            "expected the selected fixed runtime inventory")
    raw_epoch = inventory["source"].get("source_date_epoch")
    require(type(raw_epoch) is str and re.fullmatch(r"0|[1-9][0-9]{0,11}", raw_epoch) is not None
            and int(raw_epoch) <= 253402300799,
            "source epoch must be a canonical bounded nonnegative integer")
    epoch = int(raw_epoch)
    require(root.is_absolute() and output.is_absolute() and output != root
            and root not in output.parents and output not in root.parents,
            "package output must be a new directory outside the exported root")
    require(observe(root, inventory["source"]) == inventory,
            "runtime export differs from the supplied source-bound inventory")
    inventory_original = canonical(inventory)
    require(len(inventory_original) <= MAX_METADATA_BYTES, "runtime inventory exceeds metadata bound")
    with directory(root) as root_fd, directory(output.parent) as parent_fd:
        root_identity = identity(os.fstat(root_fd))
        require(identity(root.lstat()) == root_identity,
                "runtime root name changed while opening")
        # mkdir is exclusive. No retry, overwrite or removal follows any error.
        os.mkdir(output.name, 0o700, dir_fd=parent_fd)
        output_fd = os.open(output.name, DIRECTORY_FLAGS, dir_fd=parent_fd)
        try:
            os.fchmod(output_fd, 0o700)
            os.fsync(parent_fd)
            descriptor = os.open("runtime-rootfs.tar", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=output_fd)
            with os.fdopen(descriptor, "wb", buffering=0) as stream:
                writer = ArchiveWriter(stream)
                with tarfile.open(fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                    for record in inventory["records"]:
                        add_record(archive, root_fd, record, epoch)
                os.fchmod(stream.fileno(), 0o444)
                os.fsync(stream.fileno())
            os.fsync(output_fd)
            archive_digest = "sha256:" + writer.digest.hexdigest()
            readback(output_fd, "runtime-rootfs.tar", writer.size, archive_digest)
            require(identity(os.fstat(root_fd)) == root_identity
                    and identity(root.lstat()) == root_identity
                    and identity(os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False))
                    == identity(os.fstat(output_fd))
                    and observe(root, inventory["source"]) == inventory,
                    "runtime export changed before package completion")
            report = {
                "apiVersion": "serverware.nativePilotConductorPackage/v1",
                "source": inventory["source"],
                "inventorySha256": "sha256:" + hashlib.sha256(inventory_original).hexdigest(),
                "inventory": inventory,
                "archive": {"path": "runtime-rootfs.tar", "format": "pax-tar",
                            "sha256": archive_digest, "bytes": writer.size},
                "normalization": {"uid": 0, "gid": 0, "mtime": epoch, "order": "path"},
                "releaseAuthority": False, "liveReady": False, "installed": False,
                "executionAccepted": False,
                "boundary": "Unsigned transferable rootfs bytes only. Independently authenticate the exact package hash before any later privileged installation. No installer, mounted execution root, native services, protected configurations, credentials, independent authority coordinator or acceptance evidence is supplied by this package.",
            }
            if authority:
                report.update(apiVersion="serverware.nativePilotAuthorityPackage/v1",
                    boundary="Unsigned transferable authority-coordinator rootfs bytes only. Independent package approval, protected installation, the separate approved conductor inventory, all purpose-key capabilities and per-job approvals remain required. No provisioning, signing, execution or pilot acceptance occurred.")
            raw = canonical(report)
            require(len(raw) <= MAX_METADATA_BYTES, "runtime package metadata exceeds its bound")
            descriptor = os.open("package.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=output_fd)
            with os.fdopen(descriptor, "wb", buffering=0) as stream:
                writer_metadata = ArchiveWriter(stream)
                writer_metadata.write(raw)
                os.fchmod(stream.fileno(), 0o444)
                os.fsync(stream.fileno())
            os.fsync(output_fd)
            readback(output_fd, "package.json", len(raw), "sha256:" + hashlib.sha256(raw).hexdigest())
            return report
        finally:
            os.close(output_fd)
