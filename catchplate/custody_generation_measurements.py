"""Retained parked-child and intended executable preparation observations.

The child is still the parked launcher, not the target service. Planned UID/GID
come from its cold configuration; target IMA/verity come from the actual held
executable FD. These bytes are neither a final-role process identity nor an
authorization, exec acknowledgement, service receipt or readiness result.
Missing kernel evidence refuses. No measurement, key, deadline or file is made
up. Blocking filesystem calls still need an independent process watchdog.
"""
from __future__ import annotations

import ctypes
import fcntl
import hashlib
import os
import stat
import struct
import threading

from catchplate import custody_generation_grants as g
from catchplate import custody_generation_originals as o
from catchplate.native_pilot_ordinary_key_profile import pidfd_stat_sha256

p = g.p
API = "catchplate.custodyFiveServicePreparation/v1"
FIELDS = ("apiVersion", "phase", "configurationSha256", "bootIdBase64url",
    "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId", "services")
SERVICE_FIELDS = ("configurationSha256", "plannedUid", "plannedGid", "processId",
    "startTimeTicks", "pidfdStat", "targetExecutable")
STAT_FIELDS = ("device", "inode", "mode", "uid", "gid")
PIDFD_FIELDS = STAT_FIELDS + ("sha256",)
EXECUTABLE_FIELDS = ("device", "inode", "length", "sha256", "imaSha256", "fsVeritySha256")
MAX_BYTES = 65536
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_IMA_BYTES = 4096
_TOKEN = object()


def _pidfd(fd):
    info = os.fstat(fd)
    value = dict(device=info.st_dev, inode=info.st_ino, mode=info.st_mode,
        uid=info.st_uid, gid=info.st_gid)
    value["sha256"] = pidfd_stat_sha256(value)
    p.require(not os.get_inheritable(fd))
    return value


def _ima(fd):
    # Same fgetxattr length/read and SHA-256 recipe as endpoint_clients.rs.
    # A fixed buffer prevents unbounded allocation from a changed xattr size.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fgetxattr.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
    libc.fgetxattr.restype = ctypes.c_ssize_t
    size = libc.fgetxattr(fd, b"security.ima", None, 0)
    p.require(0 < size <= MAX_IMA_BYTES)
    buffer = ctypes.create_string_buffer(size)
    p.require(libc.fgetxattr(fd, b"security.ima", buffer, size) == size)
    return p.digest(p.sha(buffer.raw))


def _verity(fd):
    # FS_IOC_MEASURE_VERITY: only actual SHA-256 digest bytes are accepted.
    buffer = bytearray(struct.pack("<HH64s", 0, 64, bytes(64)))
    fcntl.ioctl(fd, 0xC0046686, buffer, True)
    algorithm, size, digest = struct.unpack("<HH64s", buffer)
    p.require(algorithm == 1 and size == 32)
    return p.digest("sha256:" + digest[:32].hex())


class _Preparation:
    def __init__(self, token, launch):
        p.require(token is _TOKEN)
        self.launch = launch
        self.fds, self.links, self.names = [], [], []
        self.raw = self.value = None
        self.failed = self.closed = False
        self.previous = self.issued = o.clock()

    def _clock(self):
        now = o.clock()
        p.require(self.launch._issued <= self.issued <= self.previous <= now < self.launch._startup
            <= self.launch._lifetime)
        self.previous = now

    def _origin(self):
        p.require(not self.closed and not self.failed
            and threading.current_thread() is threading.main_thread()
            and os.uname().machine == "x86_64" and ctypes.sizeof(ctypes.c_void_p) == 8)
        self.launch.check()
        p.require(not self.launch._attempted and not self.launch._stop.is_set()
            and tuple(self.launch._children) == g.ROLES
            and all(item["phase"] == "parked" and not item["reaped"]
                for item in self.launch._children.values()))
        self._clock()

    def _pin_name(self, original):
        # The launcher already owns the leaf. Retain every protected named
        # ancestor too, without replacing that actual descriptor with a path.
        path = original.path
        p.require(type(path) is str and path.isascii() and path.startswith("/")
            and len(path) <= 4096 and "\0" not in path)
        parts = path[1:].split("/")
        p.require(1 <= len(parts) <= 16 and all(part not in ("", ".", "..") and len(part) <= 255 for part in parts))
        parent = os.open("/", o.FLAGS | os.O_DIRECTORY)
        self.fds.append(parent)
        for name in parts[:-1]:
            p.require(len(self.fds) < 192)
            info = os.fstat(parent)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
            child = os.open(name, o.FLAGS | os.O_DIRECTORY, dir_fd=parent)
            self.fds.append(child)
            self.links.append((parent, name, child, o.structural(os.fstat(child))))
            parent = child
        self.names.append((parent, parts[-1], original))
        self._names()

    def _names(self):
        for fd in self.fds:
            info = os.fstat(fd)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_mode & 0o022 == 0 and not os.get_inheritable(fd))
        for parent, name, child, expected in self.links:
            p.require(o.structural(os.fstat(child)) == expected
                == o.structural(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        for parent, name, original in self.names:
            original.check()
            p.require(o.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original.expected)

    def _executable(self, original, *, previous=None):
        original.check()
        info = os.fstat(original.fd)
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o755 and info.st_nlink == 1
            and 0 < info.st_size <= MAX_EXECUTABLE_BYTES
            and fcntl.fcntl(original.fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
        before = o.identity(info)
        verity = _verity(original.fd)
        ima = _ima(original.fd)
        self._clock()
        if previous is None:
            hasher, offset = hashlib.sha256(), 0
            while offset < info.st_size:
                part = os.pread(original.fd, min(1024 * 1024, info.st_size - offset), offset)
                p.require(bool(part))
                hasher.update(part); offset += len(part)
                self._clock()
            digest = p.digest("sha256:" + hasher.hexdigest())
            p.require(digest == original.sha)
        else:
            # Actual initial content was hashed above. Unchanged fs-verity on
            # this same retained inode protects those bytes; remeasure rather
            # than allocate/read all five executable images on every access.
            p.require(previous["fsVeritySha256"] == verity)
            digest = previous["sha256"]
            p.require(digest == original.sha)
        p.require(_verity(original.fd) == verity and _ima(original.fd) == ima
            and o.identity(os.fstat(original.fd)) == before)
        original.check()
        return dict(device=info.st_dev, inode=info.st_ino, length=info.st_size,
            sha256=digest, imaSha256=ima, fsVeritySha256=verity)

    def _observe(self):
        self._origin(); self._names()
        launch_raw = self.launch._originals[0].read()
        cold_launch = p.fields(g.document(launch_raw, MAX_BYTES),
            ("apiVersion", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId", "services"))
        p.require(tuple(cold_launch[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"))
            == self.launch._boot and cold_launch["invocationId"] == self.launch._invocation
            and p.ns(cold_launch["startupDeadlineBoottimeNs"]) == self.launch._startup
            and p.ns(cold_launch["lifetimeDeadlineBoottimeNs"]) == self.launch._lifetime)
        services = {}
        for role in g.ROLES:
            self._origin()
            child = self.launch._children[role]
            configuration, cold, executable = self.launch._configurations[role]
            cold_raw = configuration.read()
            p.require(g.configuration(cold_raw, configuration.sha, role) == cold
                and cold_launch["services"][role]["deliveryConfiguration"] ==
                    {"path": configuration.path, "sha256": configuration.sha}
                and cold_launch["services"][role]["executableSha256"] == executable.sha)
            o.live(child["pidfd"], child["pid"], child["start"], self.launch._pid)
            pidfd = _pidfd(child["pidfd"])
            target = self._executable(executable, previous=None if self.value is None
                else self.value["services"][role]["targetExecutable"])
            o.live(child["pidfd"], child["pid"], child["start"], self.launch._pid)
            p.require(_pidfd(child["pidfd"]) == pidfd)
            services[role] = dict(configurationSha256=configuration.sha, plannedUid=cold["uid"], plannedGid=cold["gid"],
                processId=child["pid"], startTimeTicks=child["start"], pidfdStat=pidfd, targetExecutable=target)
        value = dict(apiVersion=API, phase="parked-pre-exec", configurationSha256=p.sha(launch_raw),
            bootIdBase64url=self.launch._boot[0], timeNamespaceDevice=self.launch._boot[1],
            timeNamespaceInode=self.launch._boot[2], issuedAtBoottimeNs=str(self.issued),
            startupDeadlineBoottimeNs=str(self.launch._startup), lifetimeDeadlineBoottimeNs=str(self.launch._lifetime),
            invocationId=self.launch._invocation, services=services)
        self._names(); self._origin()
        return value

    def capture(self):
        p.require(self.raw is None)
        self._origin()
        self._pin_name(self.launch._originals[0])
        for role in g.ROLES:
            configuration, _, executable = self.launch._configurations[role]
            self._pin_name(configuration); self._pin_name(executable)
        self.value = self._observe()
        self.raw = p.canonical(self.value)
        p.require(len(self.raw) <= MAX_BYTES)
        return self.raw

    def original(self):
        p.require(self.raw is not None and self._observe() == self.value)
        return self.raw

    def close(self):
        p.require(threading.current_thread() is threading.main_thread() and os.getpid() == self.launch._pid
            and all(item["reaped"] for item in self.launch._children.values()))
        while self.fds:
            os.close(self.fds[-1]); self.fds.pop()
        self.closed = True


def preparation_original(launch):
    """Only the actual retained launcher can capture or revisit this original."""
    from catchplate.custody_generation_launch import FiveServiceLaunch

    p.require(type(launch) is FiveServiceLaunch)
    launch.check()
    try:
        if not launch._preparation_attempted:
            launch._preparation_attempted = True
            owner = _Preparation(_TOKEN, launch)
            launch._preparation = owner  # Retain before first measurement/FD.
            return owner.capture()
        p.require(launch._preparation is not None)
        return launch._preparation.original()
    except BaseException:
        if launch._preparation is not None:
            launch._preparation.failed = True
        launch._failed = True
        launch._stop.set()
        raise
