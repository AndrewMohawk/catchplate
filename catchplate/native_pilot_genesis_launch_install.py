"""Retained, exclusive installation of authenticated cold native launch outputs.

The complete protected input is independently approved. Configuration and trust
are preexisting root originals; images, mount targets, journals and private keys
are never opened or created here. Host launch originals are distinct from the
native parent's preexisting /etc/catchplate/native-shadow-guest-launch.json
mount target: the actual parent passes the selected original through FD4.

Creation is one-shot and components precede launch. Failed/partial files remain
with their owner; close releases descriptors only. An external original-window
watchdog must bound filesystem stalls. Installation is not native admission.
"""
from __future__ import annotations

import copy
import fcntl
import os
import stat
import threading
import time

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_launch_profile as launch
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_shadow_proof_cohort_control import _Original

p = g.p
API = "catchplate.nativePilotGenesisLaunchInstallationInput/v1"
RESULT_API = "catchplate.nativePilotGenesisLaunchInstallation/v1"
MAX_INPUT = 32 * 1024 * 1024
ROLES = launch.ROLES
PREREQUISITES = ("deliveryConfiguration", "trust")
COMPONENTS = tuple(name for name in launch.COMPONENTS if name not in PREREQUISITES)
ROOT = "/etc/catchplate/native-pilot-inputs"
DESTINATIONS = {role: {name: ROOT + "/native-" + role + "-"
    + ("verifier" if name == "verifierTransport" else name) + ".json"
    for name in (*COMPONENTS, "serviceGrant", "launch")} for role in ROLES}
FIELDS = ("apiVersion", "role", "launchInputOriginal", "bundleOriginal")
RESULT_FIELDS = ("apiVersion", "role", "inputSha256", "bundleSha256", "launchPin", "pins")
_ROOTS = ("/", "/etc", "/etc/catchplate", ROOT)
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_TOKEN = object()
_ATTEMPTED = set()


def input_document(raw):
    value = p.fields(p.document(raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == API and value["role"] in ROLES)
    return value


def prepare_input(role, raw, *, boot, now_boottime_ns, now_unix_ns):
    """Authenticate the entire plan. No filesystem or process authority."""
    value = input_document(raw)
    p.require(role in ROLES and value["role"] == role)
    input_raw = launch._original(value["launchInputOriginal"], launch.MAX_INPUT)
    bundle_raw = launch._original(value["bundleOriginal"], launch.MAX_OUTPUT)
    prepared = launch.prepare_input(role, input_raw, boot=boot, now_boottime_ns=now_boottime_ns,
        now_unix_ns=now_unix_ns)
    p.require(prepared["bundleOriginal"] == bundle_raw)
    bundle = p.document(bundle_raw, launch.MAX_OUTPUT)
    public = bundle["originals"]
    window = g.document(bundle["windowOriginal"].encode("ascii"), 65536)
    delivery = g.document(public["delivery"]["original"].encode("ascii"), 65536)["payload"]
    expected = (*COMPONENTS, *(("serviceGrant",) if role != ROLES[-1] else ()))
    p.fields(public, (*PREREQUISITES, *expected))
    rows = []
    for name in expected:
        row = public[name]
        pin = row["pin"]
        p.require(pin["path"] == DESTINATIONS[role][name])
        original = row["original"].encode("ascii")
        p.require(pin["sha256"] == p.sha(original))
        # Native guest.rs::admit_files opens runtime as root. Only the C9
        # encrypted credential is final-role-owned; no plaintext key is read.
        uid, gid = (delivery["uid"], delivery["gid"]) if name == "encryptedInventory" else (0, 0)
        rows.append(dict(name=name, pin=copy.deepcopy(pin), raw=original, uid=uid, gid=gid))
    p.require(bundle["launchPin"]["path"] == DESTINATIONS[role]["launch"])
    rows.append(dict(name="launch", pin=copy.deepcopy(bundle["launchPin"]), raw=prepared["launchOriginal"], uid=0, gid=0))
    prerequisites = [dict(name=name, pin=copy.deepcopy(public[name]["pin"]),
        raw=public[name]["original"].encode("ascii"), uid=0, gid=0) for name in PREREQUISITES]
    paths = [row["pin"]["path"] for row in (*prerequisites, *rows)]
    p.require(len(paths) == len(set(paths)) and sum(len(row["raw"]) for row in rows) <= launch.MAX_OUTPUT)
    result = dict(apiVersion=RESULT_API, role=role, inputSha256=p.sha(raw), bundleSha256=p.sha(bundle_raw),
        launchPin=copy.deepcopy(bundle["launchPin"]), pins={row["name"]: copy.deepcopy(row["pin"]) for row in rows})
    return dict(result=result, rows=rows, prerequisites=prerequisites, window=window,
        bundleOriginal=bundle_raw, deadline=prepared["deadline"], epochLimit=prepared["epochLimit"],
        issuedAtUnixNanos=bundle["issuedAtUnixNanos"])


def checked_result(role, raw, result, **clocks):
    expected = prepare_input(role, raw, **clocks)["result"]
    p.fields(result, RESULT_FIELDS)
    p.require(g.canonical(result) == g.canonical(expected))
    return copy.deepcopy(expected)


def _structural(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _identity(info):
    return (*_structural(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(info):
    p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)


class _ProtectedOutputs:
    """Internal writer mechanics; callers must supply their own closed plan.

    This is not an approval/intake API and has no standalone public CLI. Root's
    separate fixed ordinary installer may reuse it only after its own admission.
    """
    def __init__(self):
        self.roots, self.pending, self.files = {}, [], []
        self.attempted, self.closed = set(), False

    def open(self):
        for path in _ROOTS:
            with io.owning():
                if path == "/":
                    fd = os.open(path, _READ | os.O_DIRECTORY)
                else:
                    parent, name = path.rsplit("/", 1)
                    fd = os.open(name, _READ | os.O_DIRECTORY, dir_fd=self.roots[parent or "/"][0])
                self.pending.append(fd)
                info = os.fstat(fd); _directory(info)
                self.roots[path] = (fd, _structural(info))
                self.pending.remove(fd)
        self.check()

    def check(self):
        p.require(not self.closed)
        for path, (fd, expected) in self.roots.items():
            info = os.fstat(fd); _directory(info)
            if path == "/": named = os.stat(path, follow_symlinks=False)
            else:
                parent, name = path.rsplit("/", 1)
                named = os.stat(name, dir_fd=self.roots[parent or "/"][0], follow_symlinks=False)
            p.require(_structural(info) == expected == _structural(named) and not os.get_inheritable(fd))
        for fd, name, expected, raw in self.files:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            p.require(flags & (os.O_ACCMODE | os.O_APPEND | os.O_PATH) == os.O_RDONLY
                and not os.get_inheritable(fd) and _identity(os.fstat(fd)) == expected
                == _identity(os.stat(name, dir_fd=self.roots[ROOT][0], follow_symlinks=False)))
            p.require(os.pread(fd, len(raw) + 1, 0) == raw and _identity(os.fstat(fd)) == expected)

    def require_absent(self, rows):
        self.check()
        for row in rows:
            path = row["pin"]["path"]
            parent, name = path.rsplit("/", 1)
            p.require(parent == ROOT and name and name not in (".", ".."))
            try: os.stat(name, dir_fd=self.roots[ROOT][0], follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError("approved public destination already exists")

    def publish(self, row, check):
        check()
        path, raw = row["pin"]["path"], row["raw"]
        parent, name = path.rsplit("/", 1)
        p.require(parent == ROOT and name and name not in self.attempted)
        self.attempted.add(name)
        p.require(type(raw) is bytes and 0 < len(raw) <= launch.MAX_OUTPUT
            and p.sha(raw) == row["pin"]["sha256"])
        parent_fd = self.roots[ROOT][0]
        with io.owning():
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600, dir_fd=parent_fd)
            self.pending.append(fd)
        info = os.fstat(fd)
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1 and info.st_size == 0)
        offset = 0
        while offset < len(raw):
            check()
            written = os.pwrite(fd, raw[offset:], offset)
            p.require(0 < written <= len(raw) - offset)
            offset += written
            check()
        os.fsync(fd); check()
        p.require(os.pread(fd, len(raw) + 1, 0) == raw)
        os.fchown(fd, row["uid"], row["gid"])
        os.fchmod(fd, 0o400)
        os.fsync(fd); check()
        expected = _identity(os.fstat(fd))
        p.require(stat.S_IMODE(expected[2]) == 0o400 and expected[3:7] == (row["uid"], row["gid"], 1, len(raw))
            and _identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == expected)
        with io.owning():
            held = os.open(name, _READ, dir_fd=parent_fd)
            self.pending.append(held)
            p.require(_identity(os.fstat(held)) == expected and os.pread(held, len(raw) + 1, 0) == raw)
            self.files.append((held, name, expected, raw))
            self.pending.remove(held)
            self.pending.remove(fd)
            # Retire the numeric slot before close: an interrupted close must
            # never leave a stale entry that could later name a reused FD.
            os.close(fd)
        os.fsync(parent_fd)
        check()

    def close(self):
        if self.closed: return
        with io.owning():
            while self.files:
                fd, _, _, _ = self.files.pop()
                os.close(fd)
            while self.pending:
                os.close(self.pending.pop())
            while self.roots:
                path = next(reversed(self.roots))
                fd = self.roots.pop(path)[0]
                os.close(fd)
            self.closed = True


class GenesisLaunchInstallError(ValueError):
    def __init__(self, owner):
        super().__init__("cold native launch installation refused; actual owner and partial files retained")
        self.owner = owner


class GenesisLaunchInstaller:
    def __init__(self, token, role):
        p.require(token is _TOKEN)
        self.role = role
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._namespace = _structural(os.stat("/proc/self/ns/time"))
        self._input, self._plan = None, None
        self._held, self._outputs = [], _ProtectedOutputs()
        self._attempted = self._installed = self._failed = self._closed = False

    def _origin(self):
        p.require(not self._closed and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and os.getpid() == self._pid and originals._start() == self._start and originals._boot() == self._boot
            and _structural(os.stat("/proc/self/ns/time")) == self._namespace)

    def _clock(self):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall)
        if self._plan is not None:
            p.require(p.ns(self._plan["window"]["issuedAtBoottimeNs"]) <= now < self._plan["deadline"]
                and self._plan["issuedAtUnixNanos"] <= wall < self._plan["epochLimit"])
        self._last, self._wall = now, wall
        return now, wall

    def _sources(self):
        if self._input is not None: self._input.check()
        for original in self._held: original.check()
        self._outputs.check()

    def check(self):
        p.require(not self._failed)
        self._clock(); self._sources(); self._clock()

    def check_retained(self):
        """Post-install immutable file custody only; no renewed admission."""
        p.require(self._installed and not self._failed)
        self._origin(); self._sources(); self._origin()

    def install(self):
        try:
            self.check()
            p.require(not self._attempted and not self._installed)
            self._attempted = True
            self._outputs.require_absent(self._plan["rows"])
            for row in self._plan["rows"]: self._outputs.publish(row, self.check)
            result = copy.deepcopy(self._plan["result"])
            self.check()
            self._installed = True
            return result
        except BaseException as error:
            self._failed = True
            raise GenesisLaunchInstallError(self) from error

    def close(self):
        """Caller must first finish actual child cleanup; never removes files."""
        if self._closed: return
        self._origin()
        with io.owning():
            self._outputs.close()
            while self._held:
                self._held[-1].close(); self._held.pop()
            if self._input is not None:
                self._input.close(); self._input = None
            self._closed = True


def prepare(role, input_fd, input_sha256):
    p.require(role in ROLES and role not in _ATTEMPTED
        and threading.current_thread() is threading.main_thread()
        and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
        and len(os.listdir("/proc/self/task")) == 1)
    _ATTEMPTED.add(role)
    owner = GenesisLaunchInstaller(_TOKEN, role)
    try:
        with io.owning(): owner._input = io.PublicInput(input_fd, MAX_INPUT, input_sha256)
        now, wall = owner._clock()
        owner._plan = prepare_input(role, owner._input.raw, boot=owner._boot,
            now_boottime_ns=now, now_unix_ns=wall)
        owner._clock()
        for row in owner._plan["prerequisites"]:
            with io.owning():
                original = _Original(row["pin"]["path"], len(row["raw"]), row["pin"]["sha256"])
                owner._held.append(original)
            p.require(original.raw == row["raw"])
            owner._clock()
        owner._outputs.open()
        owner.check()
        return owner
    except BaseException as error:
        owner._failed = True
        raise GenesisLaunchInstallError(owner) from error
