"""Bounded operator-side fs-verity installation, separate from guest authority.

Only new content-addressed files in an explicitly selected empty root-owned
directory are written. Failures preserve partial state; no repair, overwrite,
cleanup, feature enabling, mount operation, key creation, or service start.
"""
from __future__ import annotations

import fcntl
import os
import stat
import struct
import sys
from contextlib import contextmanager

from serverware import native_shadow_retrieval_artifacts as a

p = a.p
ENABLE_VERITY = 0x40806685
MEASURE_VERITY = 0xC0046686
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _names(fd):
    names = []
    with os.scandir(fd) as entries:
        for item in entries:
            names.append(item.name)
            p.require(len(names) <= a.MAX_OBJECTS)
    return sorted(names)


@contextmanager
def _directory(path):
    p.require(type(path) is str and path.startswith("/") and len(path) <= 4096)
    parts = path.split("/")[1:]
    p.require(3 <= len(parts) <= 32 and all(part not in ("", ".", "..") and len(part) <= 255 for part in parts))
    retained, links = [], []
    try:
        fd = os.open("/", READ_FLAGS | os.O_DIRECTORY)
        retained.append(fd)
        for part in parts:
            info = os.fstat(fd)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0)
            child = os.open(part, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
            retained.append(child)
            links.append((fd, part, child))
            fd = child
        info = os.fstat(fd)
        p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def check(mode):
            for parent, name, child in links:
                parent_info = os.fstat(parent)
                actual, named = os.fstat(child), os.stat(name, dir_fd=parent, follow_symlinks=False)
                p.require(parent_info.st_uid == 0 and parent_info.st_mode & 0o022 == 0
                    and stat.S_ISDIR(actual.st_mode) and actual.st_uid == 0 and actual.st_mode & 0o022 == 0
                    and _identity(actual) == _identity(named))
            actual = os.fstat(fd)
            p.require(actual.st_dev == info.st_dev and actual.st_ino == info.st_ino
                and actual.st_uid == actual.st_gid == 0 and stat.S_IMODE(actual.st_mode) == mode)

        check(0o700)
        p.require(_names(fd) == [])
        yield fd, check
    finally:
        for owned in reversed(retained):
            os.close(owned)


def _measure(fd):
    buffer = bytearray(struct.pack("<HH32s", 0, 32, bytes(32)))
    fcntl.ioctl(fd, MEASURE_VERITY, buffer, True)
    algorithm, length, digest = struct.unpack("<HH32s", buffer)
    p.require(algorithm == 1 and length == 32 and digest != bytes(32))
    return "sha256:" + digest.hex()


def _file(fd, size):
    info = os.fstat(fd)
    p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o444 and info.st_size == size
        and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
    return info


def _observe(directory, locator, original):
    fd = os.open(locator["filename"], READ_FLAGS, dir_fd=directory)
    try:
        before = _identity(_file(fd, len(original)))
        measured = _measure(fd)
        p.require(os.pread(fd, len(original) + 1, 0) == original)
        p.require(_measure(fd) == measured and _identity(_file(fd, len(original))) == before
            and _identity(os.stat(locator["filename"], dir_fd=directory, follow_symlinks=False)) == before)
        return dict(locator, fsVeritySha256=measured, byteLength=len(original),
            device=before[0], inode=before[1], mode=0o444)
    finally:
        os.close(fd)


def _create(directory, locator, original):
    name = locator["filename"]
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        value = os.fstat(fd)
        p.require(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 0
            and value.st_nlink == 1 and stat.S_IMODE(value.st_mode) == 0o600)
        remaining = memoryview(original)
        while remaining:
            count = os.write(fd, remaining)
            p.require(count > 0)
            remaining = remaining[count:]
        os.fsync(fd)
        identity = _identity(os.fstat(fd))
    finally:
        os.close(fd)
    # Linux requires an O_RDONLY descriptor and no open writer for enabling
    # fs-verity. All other enable_arg fields are reserved and remain zero.
    fd = os.open(name, READ_FLAGS, dir_fd=directory)
    try:
        p.require(_identity(os.fstat(fd)) == identity and os.pread(fd, len(original) + 1, 0) == original)
        argument = struct.pack("<IIIIQIIQ11Q", 1, 1, 4096, 0, 0, 0, 0, 0, *([0] * 11))
        fcntl.ioctl(fd, ENABLE_VERITY, argument)
        _measure(fd)
        os.fchmod(fd, 0o444)
        os.fsync(fd)
    finally:
        os.close(fd)
    return _observe(directory, locator, original)


def install(*, target_directory, manifest_original, manifest_sha256):
    """Install at most 16 MiB; return observations, never activation authority.

    The operator must supply an external process watchdog. Kernel fs-verity
    setup is synchronous; a Python elapsed-time check is not a hard deadline.
    """
    p.require(sys.platform == "linux" and os.uname().machine == "x86_64"
        and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
    # Validate the entire pinned inventory before the first filesystem effect.
    objects = a.manifest_objects(manifest_original, manifest_sha256)
    expected_names = sorted(locator["filename"] for locator, _ in objects)
    with _directory(target_directory) as (directory, check):
        observations = []
        for locator, original in objects:
            check(0o700)
            observations.append(_create(directory, locator, original))
            check(0o700)
        p.require(_names(directory) == expected_names)
        os.fsync(directory)
        os.fchmod(directory, 0o555)
        os.fsync(directory)
        check(0o555)
        frozen = _identity(os.fstat(directory))
        for (locator, original), expected in zip(objects, observations):
            p.require(_observe(directory, locator, original) == expected)
        check(0o555)
        p.require(_identity(os.fstat(directory)) == frozen and _names(directory) == expected_names)
        return p.canonical({"apiVersion": "serverware.nativeShadowRetrievalStoreInstalled/v1",
            "manifestSha256": manifest_sha256, "releaseAuthority": False, "serviceReady": False,
            "directoryDevice": frozen[0], "directoryInode": frozen[1], "directoryMode": 0o555,
            "objects": observations})


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Install a new bounded native retrieval object store; no service activation.")
    parser.add_argument("--directory", required=True, help="Existing empty root:root0700 directory, protected ancestors required")
    parser.add_argument("--manifest-sha256", required=True, help="Independent digest of the exact public manifest on FD3")
    args = parser.parse_args()
    try:
        p.require(sys.flags.isolated == 1)
        info = _file(3, os.fstat(3).st_size)
        p.require(1 <= info.st_size <= a.MAX_MANIFEST)
        raw = os.pread(3, info.st_size + 1, 0)
        p.require(len(raw) == info.st_size and _identity(os.fstat(3)) == _identity(info))
        output = install(target_directory=args.directory, manifest_original=raw,
            manifest_sha256=args.manifest_sha256)
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
    except Exception:
        print("Retrieval store installation refused; preserve any partial directory and do not automatically retry.", file=sys.stderr)
        return 1
    return 0
