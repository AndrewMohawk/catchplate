"""Private bounded mechanisms for the fixed cold-genesis controller owner.

These are descriptor/source checks, not approval, service admission or process
ownership constructors. The caller retains every acquired FD before unmasking
cancellation, and supplies its original immutable deadline to each wait.
"""
from __future__ import annotations

import array
import contextlib
import fcntl
import hashlib
import os
import signal
import socket
import stat
import struct

from scripts.authority import native_pilot_authority_io as public_io
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_nitro_profile as p
from serverware.native_shadow_proof_cohort_control import _Original, _structural

MAX_EXECUTABLE = 64 * 1024 * 1024
MAX_IMAGE = 512 * 1024 * 1024
CANCELLATION = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_UCRED = struct.Struct("=iII")


@contextlib.contextmanager
def owning():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, CANCELLATION)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def original_identity(original):
    for parent, name, child, expected in original.parents:
        p.require(_structural(os.fstat(child)) == expected
            and _structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
    p.require(originals._identity(os.fstat(original.fd)) == original.identity
        and originals._identity(os.stat(original.name, dir_fd=original.parent, follow_symlinks=False)) == original.identity
        and all(not os.get_inheritable(fd) for fd in original.fds))


class PublicInput:
    """An owned duplicate of one independently pinned protected public FD."""
    def __init__(self, fd, maximum, digest):
        self.fd = None
        self.maximum = maximum
        with owning():
            expected = public_io._input(fd, maximum)
            self.fd = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128)
            try:
                self.identity = public_io._input(self.fd, maximum)
                self.raw = public_io.read_public(self.fd, maximum)
                p.require(self.identity == expected and p.sha(self.raw) == p.digest(digest)
                    and public_io.read_public(fd, maximum) == self.raw)
            except BaseException:
                os.close(self.fd)
                self.fd = None
                raise

    def check_identity(self):
        p.require(self.fd is not None and public_io._input(self.fd, self.maximum) == self.identity)

    def check(self):
        self.check_identity()
        p.require(public_io.read_public(self.fd, self.maximum) == self.raw)
        self.check_identity()

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)


class ImageOriginal:
    """The protected image pin, streamed instead of caching up to 512 MiB."""
    def __init__(self, path, digest):
        self.fds, self.parents = [], []
        self.digest = p.digest(digest)
        p.require(type(path) is str and path.isascii() and path.startswith("/")
            and 1 < len(path) <= 4096 and "\0" not in path
            and all(v not in {"", ".", ".."} for v in path[1:].split("/")))
        try:
            parent = os.open("/", _READ | os.O_DIRECTORY)
            self.fds.append(parent)
            parts = path[1:].split("/")
            for name in parts[:-1]:
                info = os.fstat(parent)
                p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                    and not info.st_mode & 0o022)
                child = os.open(name, _READ | os.O_DIRECTORY, dir_fd=parent)
                self.fds.append(child)
                self.parents.append((parent, name, child, _structural(os.fstat(child))))
                parent = child
            info = os.fstat(parent)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
            self.parent, self.name = parent, parts[-1]
            self.fd = os.open(self.name, _READ, dir_fd=parent)
            self.fds.append(self.fd)
            info = os.fstat(self.fd)
            p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o400 and info.st_nlink == 1 and 0 < info.st_size <= MAX_IMAGE)
            self.identity = originals._identity(info)
            self.check()
        except BaseException:
            self.close()
            raise

    def check_identity(self):
        original_identity(self)

    def check(self):
        self.check_identity()
        digest, offset = hashlib.sha256(), 0
        while offset < self.identity[6]:
            raw = os.pread(self.fd, min(65536, self.identity[6] - offset), offset)
            p.require(raw)
            digest.update(raw)
            offset += len(raw)
        p.require(not os.pread(self.fd, 1, offset) and "sha256:" + digest.hexdigest() == self.digest)
        self.check_identity()

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


def require_static_elf(raw):
    p.require(type(raw) is bytes and 64 <= len(raw) <= MAX_EXECUTABLE
        and raw[:7] == b"\x7fELF\x02\x01\x01"
        and int.from_bytes(raw[16:18], "little") in (2, 3)
        and int.from_bytes(raw[18:20], "little") == 62
        and int.from_bytes(raw[20:24], "little") == 1)
    table, stride, count = (int.from_bytes(raw[a:b], "little") for a, b in ((32, 40), (54, 56), (56, 58)))
    p.require(stride == 56 and 1 <= count <= 256 and 0 <= table <= len(raw)
        and table + stride * count <= len(raw))
    loaded = False
    for index in range(count):
        row = raw[table + stride * index:table + stride * (index + 1)]
        kind = int.from_bytes(row[:4], "little")
        p.require(kind != 3)
        if kind == 1:
            loaded = True
        if kind == 2:
            offset, length = (int.from_bytes(row[a:b], "little") for a, b in ((8, 16), (32, 40)))
            p.require(offset <= len(raw) and length <= len(raw) - offset and length % 16 == 0)
            for cursor in range(offset, offset + length, 16):
                tag = int.from_bytes(raw[cursor:cursor + 8], "little")
                p.require(tag != 1)
                if tag == 0:
                    break
    p.require(loaded)


def pidfd_pid(fd):
    with open("/proc/self/fdinfo/" + str(fd), "rt", encoding="ascii") as stream:
        raw = stream.read(4097)
    p.require(len(raw) <= 4096)
    values = [v[4:].strip() for v in raw.splitlines() if v.startswith("Pid:")]
    p.require(len(values) == 1 and (values[0] == "-1" or values[0].isdigit()))
    return int(values[0])


def receive_observation(channel, retained):
    """Collect ALL kernel-delivered FDs before validation/unmasking signals."""
    with owning():
        try:
            raw, ancillary, flags, _ = channel.recvmsg(32768,
                socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4) + socket.CMSG_SPACE(4),
                socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
        except (BlockingIOError, InterruptedError):
            return None
        rights, pidfds, credentials, valid = [], [], None, True
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, 4):
                valid &= len(data) % array.array("i").itemsize == 0
                values = array.array("i")
                values.frombytes(data[:len(data) - len(data) % values.itemsize])
                for fd in values:
                    if fd < 0:
                        valid = False
                    else:
                        retained.append(fd)
                        (rights if kind == socket.SCM_RIGHTS else pidfds).append(fd)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if credentials is not None or len(data) != _UCRED.size:
                    valid = False
                else:
                    credentials = _UCRED.unpack(data)
            else:
                valid = False
        p.require(valid and raw and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0
            and credentials is not None and len(rights) == len(pidfds) == 1)
        return bytes(raw), credentials, pidfds[0], rights[0]
