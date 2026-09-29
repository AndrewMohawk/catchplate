"""Actual one-shot protected-input ownership for the external Nitro verifier.

Fixed FD3 configuration is matched to its real protected named file; FD4/5 are
separate sealed seed/request originals. There is no arbitrary path/FD constructor.
"""
from __future__ import annotations

import ctypes
import fcntl
import os
import resource
import stat
import sys
import time
import uuid

from serverware import native_shadow_nitro_profile as p

CONFIG_NAME = "native-shadow-nitro-verifier.json"
_TOKEN = object()


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _start():
    with open("/proc/self/stat", "rb") as stream:
        raw = stream.read(4097)
    p.require(len(raw) <= 4096)
    _, tail = raw.rsplit(b") ", 1)
    return p.integer(int(tail.split()[19]))


def _boot():
    with open("/proc/sys/kernel/random/boot_id", "rt", encoding="ascii") as stream:
        text = stream.read(65)
    p.require(len(text) == 37 and text.endswith("\n"))
    value = uuid.UUID(text[:-1])
    p.require(str(value) == text[:-1] and value.int != 0)
    namespace = os.stat("/proc/self/ns/time")
    return p.encoded(value.bytes), namespace.st_dev, namespace.st_ino


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _hardening():
    p.require(sys.flags.isolated == 1 and sys.flags.ignore_environment == 1
        and os.getresuid() == (os.getuid(),) * 3 and os.getresgid() == (os.getgid(),) * 3
        and os.getuid() > 0 and os.getgid() > 0 and os.getgroups() == [])
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    p.require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(38, 1, 0, 0, 0) == 0)
    return libc


def _security(libc):
    p.require(libc.prctl(3, 0, 0, 0, 0) == 0 and libc.prctl(39, 0, 0, 0, 0) == 1
        and resource.getrlimit(resource.RLIMIT_CORE) == (0, 0))
    with open("/proc/self/status", "rt", encoding="ascii") as stream:
        text = stream.read(16385)
    p.require(len(text) <= 16384)
    values = {}
    for line in text.splitlines():
        name, _, value = line.partition(":")
        if name in {"CapInh", "CapPrm", "CapEff", "CapAmb", "Threads"}:
            p.require(name not in values)
            values[name] = value.strip()
    p.require(set(values) == {"CapInh", "CapPrm", "CapEff", "CapAmb", "Threads"}
        and values["Threads"] == "1" and all(int(values[name], 16) == 0 for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")))


class _File:
    def __init__(self, fd, maximum, *, uid, gid, sealed):
        self.fd, self.maximum, self.sealed = fd, maximum, sealed
        value = os.fstat(fd)
        p.require(stat.S_ISREG(value.st_mode) and value.st_uid == uid and value.st_gid == gid
            and value.st_mode & 0o7777 == (0o600 if sealed else 0o400)
            and value.st_nlink == (0 if sealed else 1) and 1 <= value.st_size <= maximum)
        self.identity = _identity(value)
        self.flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        access = self.flags & os.O_ACCMODE
        p.require(access in (os.O_RDONLY, os.O_RDWR) if sealed else access == os.O_RDONLY)
        p.require(not self.flags & (os.O_APPEND | os.O_ASYNC | os.O_PATH))
        os.set_inheritable(fd, False)
        self.check()

    def check(self):
        p.require(_identity(os.fstat(self.fd)) == self.identity and fcntl.fcntl(self.fd, fcntl.F_GETFL) == self.flags
            and not os.get_inheritable(self.fd))
        if self.sealed:
            p.require(fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) & 15 == 15)

    def read(self):
        self.check()
        raw = os.pread(self.fd, self.maximum + 1, 0)
        p.require(len(raw) == self.identity[6])
        self.check()
        return raw


class Originals:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds = []
        self._attempted = False
        self._closed = False

    @classmethod
    def open(cls):
        owner = cls(_TOKEN)
        try:
            # Reserve the genuine inherited slots before any owned opens can
            # reuse a missing slot. They are consumed even on admission failure.
            for fd in (3, 4, 5):
                os.fstat(fd)
                owner._fds.append(fd)
            owner.libc = _hardening()
            _security(owner.libc)
            owner.pid, owner.start = os.getpid(), _start()
            owner.pidfd = os.pidfd_open(owner.pid, 0)
            owner._fds.append(owner.pidfd)
            os.set_inheritable(owner.pidfd, False)
            owner.pidfd_identity = _identity(os.fstat(owner.pidfd))
            owner.pidfd_flags = fcntl.fcntl(owner.pidfd, fcntl.F_GETFL)
            owner.uid, owner.gid = os.getuid(), os.getgid()
            p.require(owner.uid not in {64988, 64989, 64990, 65534} and owner.gid not in {64988, 64989, 64990, 65534})
            # No environment, caller path, or sealed copy can select authority.
            # Retain each protected ancestor and the actual named file identity.
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            owner._fds.append(parent)
            owner.directories = []
            for component in ("etc", "serverware"):
                before = os.fstat(parent)
                p.require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0 and before.st_mode & 0o022 == 0)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                owner._fds.append(child)
                owner.directories.append((parent, component, child, _identity(os.fstat(child))))
                parent = child
            directory = os.fstat(parent)
            p.require(directory.st_uid == 0 and directory.st_mode & 0o022 == 0)
            owner.directory = parent
            owner.config_original = _File(3, p.MAX_CONFIG, uid=0, gid=0, sealed=False)
            owner.seed_original = _File(4, 32, uid=owner.uid, gid=owner.gid, sealed=True)
            owner.request_original = _File(5, p.MAX_REQUEST, uid=owner.uid, gid=owner.gid, sealed=True)
            p.require(owner.seed_original.identity[6] == 32)
            identities = [original.identity[:2] for original in (owner.config_original, owner.seed_original, owner.request_original)]
            p.require(len(set(identities)) == 3)
            owner.config_raw = owner.config_original.read()
            owner.configuration = p.document(owner.config_raw, p.MAX_CONFIG)
            if owner.configuration.get("apiVersion") == "serverware.nativeShadowNitroVerifierConfiguration/v2":
                from serverware import native_shadow_key_admission_profile as admission
                p.fields(owner.configuration, admission.CONFIG_FIELDS)
                scope_name = "expectedScope"
            else:
                p.require(owner.configuration.get("apiVersion") == "serverware.nativeShadowNitroVerifierConfiguration/v1")
                p.fields(owner.configuration, p.CONFIG_FIELDS)
                scope_name = "expectedStatement"
            p.require(p.integer(owner.configuration["uid"], maximum=(1 << 32) - 2) == owner.uid
                and p.integer(owner.configuration["gid"], maximum=(1 << 32) - 2) == owner.gid)
            operation = p.fields(owner.configuration["operation"], ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                "issuedAtBoottimeNs", "deadlineBoottimeNs"))
            owner.boot = _boot()
            p.integer(operation["timeNamespaceDevice"]); p.integer(operation["timeNamespaceInode"])
            p.require(owner.boot == (operation["bootIdBase64url"], operation["timeNamespaceDevice"], operation["timeNamespaceInode"]))
            owner.issued, owner.deadline = p.ns(operation["issuedAtBoottimeNs"]), p.ns(operation["deadlineBoottimeNs"])
            p.require(0 < owner.deadline - owner.issued <= 30_000_000_000)
            owner.wall = 0
            owner.check()
            owner.request_raw = owner.request_original.read()
            owner.request = p.document(owner.request_raw, p.MAX_REQUEST)
            p.require(owner.uid != owner.configuration[scope_name]["guest"]["uid"]
                and owner.gid != owner.configuration[scope_name]["guest"]["gid"])
            owner.check()
            return owner
        except BaseException:
            owner.close()
            raise

    def check(self):
        p.require(not self._closed and os.getpid() == self.pid and _start() == self.start
            and os.getresuid() == (self.uid,) * 3 and os.getresgid() == (self.gid,) * 3 and os.getgroups() == [] and _boot() == self.boot)
        _security(self.libc)
        p.require(_identity(os.fstat(self.pidfd)) == self.pidfd_identity
            and fcntl.fcntl(self.pidfd, fcntl.F_GETFL) == self.pidfd_flags and not os.get_inheritable(self.pidfd))
        import select
        poll = select.poll()
        poll.register(self.pidfd, select.POLLIN)
        p.require(poll.poll(0) == [])
        with open("/proc/self/fdinfo/" + str(self.pidfd), "rt", encoding="ascii") as stream:
            lines = stream.read(4097)
        p.require(len(lines) <= 4096 and [line for line in lines.splitlines() if line.startswith("Pid:")]
            == ["Pid:\t" + str(self.pid)])
        for parent, name, child, expected in self.directories:
            p.require(_identity(os.fstat(child)) == expected
                and _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        p.require(_identity(os.stat(CONFIG_NAME, dir_fd=self.directory, follow_symlinks=False)) == self.config_original.identity)
        for original in (self.config_original, self.seed_original, self.request_original):
            original.check()
        p.require(self.config_original.read() == self.config_raw and p.canonical(self.configuration) == self.config_raw)
        if hasattr(self, "request"):
            p.require(self.request_original.read() == self.request_raw and p.canonical(self.request) == self.request_raw)
        p.require(self.issued <= _clock() < self.deadline)
        wall = time.time_ns()
        p.integer(wall)
        p.require(wall >= self.wall)
        self.wall = wall
        return wall

    def remaining(self):
        self.check()
        remaining = self.deadline - _clock()
        p.require(remaining > 0)
        return remaining

    def take_seed(self):
        self.check()
        p.require(not self._attempted)
        self._attempted = True
        # The real public-key comparison happens before the sole fixed signature.
        value = bytearray(self.seed_original.read())
        try:
            self.check()
            return value
        except BaseException:
            value[:] = b"\0" * len(value)
            raise

    def close(self):
        if not self._closed:
            self._closed = True
            for fd in set(self._fds):
                try:
                    os.close(fd)
                except OSError:
                    pass
            self._fds.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
