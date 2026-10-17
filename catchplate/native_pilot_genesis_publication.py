"""Retained exclusive publication of cold parent/ordinary public originals.

Only the fixed job planner can derive records from authenticated predecessors.
No private seed, journal, arbitrary path, replacement or rollback is accepted.
The independent operator must provision protected ancestor directories first.
"""
from __future__ import annotations

import copy
import fcntl
import os
import stat
import threading
import time

from catchplate import custody_generation_grants as g
from catchplate import custody_generation_originals as o
from catchplate import native_pilot_genesis_parent_control_io as io

p = g.p
ROOTS = ("/", "/etc", "/etc/catchplate")
ROLES = ("durable-recovery-store", "current-signature-authority")
SUFFIXES = ("runtime", "initial-history", "peer-inspection", "delivery", "guest")
PARENT_PATH = "/etc/catchplate/native-publication-genesis-precreation.json"
MAX_BYTES = 32 * 1024 * 1024
LIMITS = {"runtime": g.MAX_BYTES, "initial-history": g.MAX_BYTES,
    "peer-inspection": 4096, "delivery": 65536, "guest": 32768}
_TOKEN, _CLAIMED = object(), set()


def _paths(job):
    if job == "install-precreation":
        return (PARENT_PATH,)
    for role in ROLES:
        if job == "install-ordinary-" + role:
            return tuple("/etc/catchplate/custody-" + role + "-" + suffix + ".json" for suffix in SUFFIXES)
    raise ValueError("cold public installation purpose refused")


def _plan(job, value):
    """Shape/safety check only, after the actual job planner authenticates it."""
    p.fields(value, ("files", "launchPin", "deadline", "epochLimit"))
    p.require(type(value["files"]) is tuple and tuple(row["path"] for row in value["files"]) == _paths(job))
    p.integer(value["deadline"], maximum=p.MAX_U64)
    if value["epochLimit"] is not None:
        p.integer(value["epochLimit"], maximum=p.MAX_U64)
    total = 0
    for index, row in enumerate(value["files"]):
        p.fields(row, ("path", "uid", "gid", "mode", "raw", "sha256"))
        maximum = 32768 if job == "install-precreation" else LIMITS[SUFFIXES[index]]
        for name in ("uid", "gid"):
            p.integer(row[name], minimum=0, maximum=(1 << 32) - 2)
        p.require(type(row["mode"]) is int and row["mode"] == 0o400
            and type(row["raw"]) is bytes and 0 < len(row["raw"]) <= maximum
            and p.sha(row["raw"]) == p.digest(row["sha256"]))
        # Native C9 opens the public runtime as root; its credential entries
        # (history and inspection policy here) use the final-role identity.
        credential = row["path"].endswith(("-initial-history.json", "-peer-inspection.json"))
        p.require((row["uid"] > 0 and row["gid"] > 0) if credential else row["uid"] == row["gid"] == 0)
        # The native-u64 codec is deliberately capped at 4 MiB. Passing a
        # larger maximum refuses even a tiny original; do not widen that codec.
        g.document(row["raw"], maximum)
        total += len(row["raw"])
    p.require(total <= MAX_BYTES)
    expected = None if job == "install-precreation" else {
        "path": value["files"][-1]["path"], "sha256": value["files"][-1]["sha256"]}
    p.require(value["launchPin"] == expected)
    return copy.deepcopy(value)


def prepare_plan(job_name, prior, observations, *, boot, now_boottime_ns, now_unix_ns):
    """Authenticated predecessor plan plus fixed publication safety checks.

    This pure result cannot establish filesystem installation or ownership.
    """
    from catchplate import native_pilot_genesis_jobs as jobs
    _paths(job_name)
    return _plan(job_name, jobs.publication_plan(job_name, prior, observations,
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns))


class PublicInstallationError(ValueError):
    def __init__(self, owner):
        super().__init__("cold public installation refused; partial files and actual owner retained")
        self.owner = owner


class GenesisPublicInstallation:
    def __init__(self, token, check):
        p.require(token is _TOKEN and callable(check))
        self._outer = check
        self._pid, self._start, self._boot = os.getpid(), o.native._start(), o.native._boot()
        self._last, self._wall = o.clock(), time.time_ns()
        self._roots, self._pending, self._files, self._pins = {}, [], [], {}
        self._plan = None
        self._closed = self._failed = self._installed = False

    @classmethod
    def install(cls, *, job_name, prior, observations, check):
        p.require(cls is GenesisPublicInstallation and job_name not in _CLAIMED)
        _paths(job_name)
        _CLAIMED.add(job_name)  # Failed admission/creation cannot be retried.
        owner = cls(_TOKEN, check)
        try:
            owner._clock()
            owner._plan = prepare_plan(job_name, prior, observations,
                boot=owner._boot, now_boottime_ns=owner._last, now_unix_ns=owner._wall)
            owner._clock()
            for path in ROOTS:
                with io.owning():
                    if path == "/":
                        fd = os.open(path, o.FLAGS | os.O_DIRECTORY)
                    else:
                        parent, leaf = path.rsplit("/", 1)
                        fd = os.open(leaf, o.FLAGS | os.O_DIRECTORY, dir_fd=owner._roots[parent or "/"][0])
                    owner._pending.append(fd)
                    info = os.fstat(fd)
                    owner._roots[path] = fd, o.structural(info)
                    owner._pending.pop()
                owner._protected(info)
            owner.check()
            root = owner._roots[ROOTS[-1]][0]
            # Preflight every name before writing any. O_EXCL still arbitrates
            # races; a partial bundle is retained, never adopted or repaired.
            for row in owner._plan["files"]:
                try:
                    os.stat(row["path"].rsplit("/", 1)[1], dir_fd=root, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError("cold public installation destination exists")
            for row in owner._plan["files"]:
                owner._write(row)
            owner.check()
            owner._installed = True
            return owner
        except BaseException as error:
            owner._failed = True
            raise PublicInstallationError(owner) from error

    @staticmethod
    def _protected(info):
        p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)

    def _origin(self):
        p.require(not self._closed and os.getpid() == self._pid and o.native._start() == self._start
            and o.native._boot() == self._boot and threading.current_thread() is threading.main_thread()
            and len(os.listdir("/proc/self/task")) == 1
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _clock(self):
        self._origin()
        self._outer()
        now, wall = o.clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall)
        if self._plan is not None:
            p.require(now < self._plan["deadline"]
                and (self._plan["epochLimit"] is None or wall < self._plan["epochLimit"]))
        self._last, self._wall = now, wall

    def check(self):
        p.require(not self._failed)
        self._clock()
        self._retained()
        self._clock()

    def _retained(self):
        for path, (fd, expected) in self._roots.items():
            self._protected(os.fstat(fd))
            if path == "/":
                named = os.stat(path, follow_symlinks=False)
            else:
                parent, leaf = path.rsplit("/", 1)
                named = os.stat(leaf, dir_fd=self._roots[parent or "/"][0], follow_symlinks=False)
            p.require(o.structural(os.fstat(fd)) == expected == o.structural(named) and not os.get_inheritable(fd))
        for item in self._files:
            item.check()
            name = item.path.rsplit("/", 1)[1]
            flags = fcntl.fcntl(item.fd, fcntl.F_GETFL)
            p.require(flags & (os.O_ACCMODE | os.O_APPEND | os.O_PATH) == os.O_RDONLY
                and o.identity(os.stat(name, dir_fd=self._roots[ROOTS[-1]][0], follow_symlinks=False)) == item.expected)
            expected = next(row["raw"] for row in self._plan["files"] if row["path"] == item.path)
            p.require(item.read() == expected)
            p.require(o.identity(os.stat(name, dir_fd=self._roots[ROOTS[-1]][0], follow_symlinks=False)) == item.expected)

    def check_retained(self):
        """Successful installation's immutable source custody, not admission.

        No original publication clock is renewed and no output may be written.
        The actual executor must enforce its separate original lifecycle bound.
        """
        p.require(self._installed and not self._failed)
        self._origin(); self._retained(); self._origin()

    def _write(self, row):
        self.check()
        root, name = self._roots[ROOTS[-1]][0], row["path"].rsplit("/", 1)[1]
        with io.owning():
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=root)
            self._pending.append(fd)
        info = os.fstat(fd)
        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0 and info.st_uid == info.st_gid == 0)
        offset = 0
        while offset < len(row["raw"]):
            self.check()
            part = row["raw"][offset:offset + 65536]
            count = os.pwrite(fd, part, offset)
            p.require(0 < count <= len(part))
            offset += count
            self.check()
        os.fsync(fd); self.check()
        p.require(os.pread(fd, len(row["raw"]) + 1, 0) == row["raw"])
        self.check(); os.fchown(fd, row["uid"], row["gid"])
        self.check(); os.fchmod(fd, row["mode"])
        os.fsync(fd); self.check()
        written = o.identity(os.fstat(fd))
        p.require(stat.S_IMODE(written[2]) == row["mode"]
            and written[3:7] == (row["uid"], row["gid"], 1, len(row["raw"]))
            and o.identity(os.stat(name, dir_fd=root, follow_symlinks=False)) == written)
        with io.owning():
            original = o.Original(row["path"], len(row["raw"]), uid=row["uid"], gid=row["gid"], sha=row["sha256"])
            self._files.append(original)
        p.require(original.expected == written and original.read() == row["raw"])
        with io.owning():
            self._pending.remove(fd)
            os.close(fd)  # The numeric slot is retired before a fallible close.
        os.fsync(root)
        self._pins[row["path"]] = {"path": row["path"], "sha256": row["sha256"]}
        self.check()

    def result(self):
        p.require(self._installed)
        self.check()
        result = {"pins": copy.deepcopy(self._pins), "launchPin": copy.deepcopy(self._plan["launchPin"])}
        self._clock()
        return result

    def close(self):
        if self._closed:
            return
        self._origin()
        with io.owning():
            while self._pending:
                os.close(self._pending.pop())
            while self._files:
                item = self._files.pop()
                fd, item.fd = item.fd, -1
                if fd >= 0: os.close(fd)
            while self._roots:
                path = next(reversed(self._roots))
                os.close(self._roots.pop(path)[0])
            self._closed = True
        # Created names are retained durable evidence, even after failure.
