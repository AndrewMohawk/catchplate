"""Private retained kernel resources for genuine peer-preparation owners.

Only the owner adapter calls these mechanics with its actual PIDFD. No wire,
PID, callback, or public DTO constructs a preparation capability.
"""
from __future__ import annotations

import ctypes
import fcntl
import hashlib
import os
import stat

from serverware import custody_generation_originals as o
from serverware import native_pilot_peer_preparation as wire

p = wire.p
_TOKEN = object()
_PATH_FLAGS = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def _read(path, maximum):
    fd = os.open(path, o.FLAGS)
    try:
        raw = os.read(fd, maximum + 1)
        p.require(0 < len(raw) <= maximum)
        return raw
    finally:
        os.close(fd)


def _membership(pid):
    return wire.cgroup_path(_read(f"/proc/{pid}/cgroup", 16384))


def _open_cgroup(root, path):
    class How(ctypes.Structure):
        _fields_ = (("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64))
    how = How(_PATH_FLAGS, 0, 0x08 | 0x04 | 0x02)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    raw = libc.syscall(ctypes.c_long(437), ctypes.c_int(root),
        ctypes.c_char_p((path[1:] or ".").encode("utf-8")), ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)))
    if raw < 0:
        raise OSError(ctypes.get_errno(), "peer cgroup openat2 failed")
    return raw


def _cgroup_identity(fd, path):
    # Existing descriptor recipe reads kernel mnt_id for this exact retained FD.
    value = o.directory_identity(fd)
    return dict(pathSha256=p.sha(path.encode("utf-8")), mountId=value["mountId"], inode=value["inode"])


def _metadata(fd):
    info = os.fstat(fd)
    p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
        and info.st_mode & 0o022 == 0 and 0 < info.st_size <= 256 * 1024 * 1024
        and fcntl.fcntl(fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
    return info


def _hash(fd, check):
    before = o.identity(_metadata(fd))
    digest, offset = hashlib.sha256(), 0
    while offset < before[6]:
        check()
        part = os.pread(fd, min(1024 * 1024, before[6] - offset), offset)
        p.require(bool(part)); digest.update(part); offset += len(part)
    p.require(o.identity(_metadata(fd)) == before)
    return "sha256:" + digest.hexdigest()


def _parked_target(pid, expected, check):
    """Bounded scan of ONE owned child's kernel FD table, never /proc/pid/exe.

    The authenticated cohort original selected this exact target inode before
    this lookup; mandatory seals and content SHA independently check the open.
    """
    root = os.open(f"/proc/{pid}/fd", o.FLAGS | os.O_DIRECTORY)
    try:
        names = []
        with os.scandir(root) as entries:
            for entry in entries:
                p.require(len(names) < 512 and entry.name.isascii() and entry.name.isdecimal())
                names.append(entry.name)
        for name in sorted(names, key=int):
            check()
            try:
                info = os.stat(name, dir_fd=root)
            except FileNotFoundError:
                continue
            if (info.st_dev, info.st_ino, info.st_size) != tuple(expected[k] for k in ("device", "inode", "length")):
                continue
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=root)
            try:
                info = _metadata(fd)
                p.require((info.st_dev, info.st_ino, info.st_size) == tuple(expected[k] for k in ("device", "inode", "length"))
                    and fcntl.fcntl(fd, fcntl.F_GET_SEALS) & 15 == 15)
                check()
                return fd
            except BaseException:
                os.close(fd)
                raise
        raise ValueError("owned parked target descriptor missing")
    finally:
        os.close(root)


class _Peer:
    def __init__(self, token, *, pidfd, pid, start, parent, executable_fd, expected, kind, check):
        p.require(token is _TOKEN)
        self.fds = []
        self.pid, self.start, self.parent, self.kind = pid, start, parent, kind
        self.pidfd = fcntl.fcntl(pidfd, fcntl.F_DUPFD_CLOEXEC, 128); self.fds.append(self.pidfd)
        info = os.fstat(self.pidfd)
        self.pidfd_identity = (info.st_dev, info.st_ino)
        try:
            self.live(); check()
            if kind == "native-endpoints":
                self.executable = _parked_target(pid, expected, self.live)
            elif kind == "gate":
                # Fixed kernel link of the genuine already executing gate.
                self.executable = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
            else:
                self.executable = fcntl.fcntl(executable_fd, fcntl.F_DUPFD_CLOEXEC, 128)
            self.fds.append(self.executable)
            info = _metadata(self.executable)
            self.executable_identity = o.identity(info)
            target = dict(device=info.st_dev, inode=info.st_ino, length=info.st_size,
                sha256=_hash(self.executable, lambda: (self.live(), check())))
            p.require(target == expected if kind != "gate" else target["sha256"] == expected["sha256"])
            self.root = os.open("/sys/fs/cgroup", _PATH_FLAGS); self.fds.append(self.root)
            self.root_identity = o.directory_identity(self.root)
            self.path = _membership(pid)
            self.cgroup = _open_cgroup(self.root, self.path); self.fds.append(self.cgroup)
            self.cgroup_identity = _cgroup_identity(self.cgroup, self.path)
            wire.cgroup(self.cgroup_identity)
            self.value = dict(processId=pid, startTimeTicks=start,
                pidfd=dict(zip(("device", "inode"), self.pidfd_identity)), targetExecutable=target,
                cgroup=self.cgroup_identity.copy())
            self.check(); check()
        except BaseException:
            self.close()
            raise

    def live(self):
        o.live(self.pidfd, self.pid, self.start, self.parent)
        info = os.fstat(self.pidfd)
        p.require((info.st_dev, info.st_ino) == self.pidfd_identity)

    def check(self):
        self.live()
        p.require(all(not os.get_inheritable(fd) for fd in self.fds)
            and o.identity(_metadata(self.executable)) == self.executable_identity
            and o.directory_identity(self.root) == self.root_identity)
        named_root = os.open("/sys/fs/cgroup", _PATH_FLAGS)
        try:
            p.require(o.directory_identity(named_root) == self.root_identity)
        finally:
            os.close(named_root)
        if self.kind == "native-endpoints":
            p.require(fcntl.fcntl(self.executable, fcntl.F_GET_SEALS) & 15 == 15)
        if self.kind == "gate":
            current = os.stat(f"/proc/{self.pid}/exe")
            p.require((current.st_dev, current.st_ino, current.st_size) ==
                (self.executable_identity[0], self.executable_identity[1], self.executable_identity[6]))
        p.require(_membership(self.pid) == self.path)
        wire.require_same_cgroup(self.cgroup_identity, _cgroup_identity(self.cgroup, self.path))
        fresh = _open_cgroup(self.root, self.path)
        try:
            wire.require_same_cgroup(self.cgroup_identity, _cgroup_identity(fresh, self.path))
        finally:
            os.close(fresh)
        self.live()

    def close(self):
        while self.fds:
            os.close(self.fds[-1]); self.fds.pop()
