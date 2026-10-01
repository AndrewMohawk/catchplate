"""One actual local authority child; observation delivery is not readiness.

The independently supplied plan selects installed public resources, not commands
or signing authority.  Signed late originals are supplied in the pinned exchange
directory.  Existing child admission remains the sole signature/role verifier.
No files are removed on failure, and no failed attempt is automatically retried.
"""
from __future__ import annotations

import array
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import select
import signal
import socket
import stat
import struct
import threading
import time

from serverware import authority_fd_entrypoint as entrypoint
from serverware import authority_launcher as launcher
from serverware import authority_stage_zero_contract as contract

PLAN_SCHEMA = "serverware.authorityTrustedHostLocalStartup/v1"
ADMITTED_SCHEMA = "serverware.authorityTrustedHostLocalAdmitted/v1"
INTERPRETER = "/runtime/python/bin/python3"
ENTRYPOINT = "/runtime/authority-bootstrap/authority_fd_entrypoint.py"
BOOTSTRAP = "/runtime/authority-bootstrap/authority_launcher.py"
OBSERVATION_NAME = "observation.json"
LATE_NAMES = {"manifest": "manifest.json", "certificate": "certificate.json", "evidence": "evidence.json"}
LIMITS = {"manifest": launcher.MAX_MANIFEST_BYTES,
          "certificate": launcher.MAX_LAUNCH_IDENTITY_CERTIFICATE_BYTES,
          "evidence": launcher.MAX_RUNTIME_EVIDENCE_BYTES}
MAX_PLAN = 1024 * 1024
MAX_STARTUP_NS = 300_000_000_000
ENVIRONMENT = ("SERVERWARE_ARTIFACT_BUNDLE_DIGEST", "SERVERWARE_AUTHORITY_GENERATION_DIGEST",
               "SERVERWARE_OPERATION_MANIFEST_DIGEST")
_CANCEL = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
_UCRED = struct.Struct("=iII")
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_TOKEN = object()
_LIVE = None


class LocalStartupError(RuntimeError):
    def __init__(self, owner=None):
        super().__init__("local authority startup failed; retained files and child ownership may require recovery")
        self.owner = owner


def _require(value):
    if not value:
        raise LocalStartupError()


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _document(raw, maximum):
    def pairs(rows):
        value = {}
        for name, item in rows:
            _require(name not in value)
            value[name] = item
        return value
    _require(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = json.loads(raw, object_pairs_hook=pairs)
    _require(type(value) is dict and encode(value) == raw)
    return value


def _digest(value):
    _require(type(value) is str and len(value) == 71 and value.startswith("sha256:")
             and all(c in "0123456789abcdef" for c in value[7:]))
    return value


def _integer(value, minimum=0):
    _require(type(value) is int and minimum <= value <= (1 << 63) - 1)
    return value


def _path(value):
    _require(type(value) is str and value.isascii() and 1 < len(value) <= 4096
             and value.startswith("/") and "\0" not in value
             and all(part not in ("", ".", "..") for part in value[1:].split("/")))
    return value


def plan(raw):
    value = _document(raw, MAX_PLAN)
    _require(set(value) == {"schema", "role", "bootIdDigest", "issuedAtBoottimeNs",
        "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos", "credentialDirectory",
        "exchangeDirectory", "retainedFiles", "retainedDirectories", "mutableStateDescriptors", "environment"}
        and value["schema"] == PLAN_SCHEMA and value["role"] in launcher.PROCESS_MODES)
    _digest(value["bootIdDigest"])
    for key in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        _integer(value[key], 1)
    for start, end in (("issuedAtBoottimeNs", "deadlineBoottimeNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        _require(0 < value[end] - value[start] <= MAX_STARTUP_NS)
    _require(type(value["environment"]) is dict and set(value["environment"]) == set(ENVIRONMENT))
    for item in value["environment"].values():
        _digest(item)
    for key in ("credentialDirectory", "exchangeDirectory"):
        item = value[key]
        _require(type(item) is dict and set(item) == {"path", "device", "inode"})
        _path(item["path"]); _integer(item["device"]); _integer(item["inode"], 1)
    _require(value["credentialDirectory"]["path"] != value["exchangeDirectory"]["path"])
    for key, fields, maximum in (("retainedFiles", {"path", "sha256"}, 128),
                                  ("retainedDirectories", {"path", "device", "inode"}, 64)):
        rows = value[key]
        _require(type(rows) is list and 1 <= len(rows) <= maximum)
        paths = []
        for item in rows:
            _require(type(item) is dict and set(item) == fields)
            paths.append(_path(item["path"]))
            if key == "retainedFiles":
                _digest(item["sha256"])
            else:
                _integer(item["device"]); _integer(item["inode"], 1)
        _require(paths == sorted(set(paths)))
    _require({INTERPRETER, ENTRYPOINT, BOOTSTRAP}.issubset({row["path"] for row in value["retainedFiles"]}))
    _require({"/runtime", "/runtime/python/bin", "/usr/bin"}.issubset({row["path"] for row in value["retainedDirectories"]}))
    states = value["mutableStateDescriptors"]
    _require(type(states) is list and len(states) == (1 if value["role"] == "witness" else 0))
    if states:
        contract._validate_mutable_state_descriptor(states[0])
        _require(states[0]["name"] == states[0]["ownerRole"] == "witness"
            and states[0]["runtimePath"] == entrypoint.TRUSTED_HOST_LOCAL_WITNESS_STATE_PATH
            and states[0]["fd"] == 259 and states[0]["singletonLeaseRequired"] is True
            and states[0]["leaseHeld"] is True)
    return value


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _start(pid):
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as source:
        raw = source.read(8193)
    _require(len(raw) <= 8192)
    fields = raw[raw.rfind(")") + 2:].split()
    return int(fields[19]), int(fields[1])


def _boot():
    return launcher._boot_identity_digest()


@contextlib.contextmanager
def _owning():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, _CANCEL)
    try:
        yield previous
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _read(fd, maximum):
    before = _identity(os.fstat(fd))
    _require(stat.S_ISREG(before[2]) and 0 < before[6] <= maximum)
    raw = bytearray()
    while len(raw) < before[6]:
        chunk = os.pread(fd, min(65536, before[6] - len(raw)), len(raw))
        _require(chunk)
        raw.extend(chunk)
    _require(not os.pread(fd, 1, len(raw)) and _identity(os.fstat(fd)) == before)
    return bytes(raw)


def _publish_effect(directory, raw, *, hold, refresh, check):
    """One fixed atomic public-file effect; callbacks retain real FD custody.

    This primitive supplies no authority or child evidence.  Failure retains
    its acquired descriptor and any published name with its caller.
    """
    _require(type(raw) is bytes and 0 < len(raw) <= launcher.MAX_LOCAL_OBSERVATION)
    with _owning():
        fd = hold(os.open(".", os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=directory))
        offset = 0
        while offset < len(raw):
            check()
            count = os.write(fd, raw[offset:offset + 65536]); _require(count > 0); offset += count
        os.fchmod(fd, 0o400); os.fsync(fd)
        _require(_read(fd, launcher.MAX_LOCAL_OBSERVATION) == raw)
        refresh(fd)
        check()
        libc = ctypes.CDLL(None, use_errno=True)
        # Use only our held FD's validated kernel proc magic link. Unlike
        # AT_EMPTY_PATH this does not require CAP_DAC_READ_SEARCH. This is one
        # fixed mechanism, not a fallback accepting caller-selected symlinks.
        proc = hold(os.open("/proc", _READ | os.O_DIRECTORY))
        buffer = ctypes.create_string_buffer(256)
        _require(libc.fstatfs(proc, ctypes.byref(buffer)) == 0
            and ctypes.c_long.from_buffer(buffer).value & 0xffffffff == 0x9fa0
            and os.readlink("self", dir_fd=proc) == str(os.getpid()))
        process = hold(os.open(str(os.getpid()), _READ | os.O_DIRECTORY, dir_fd=proc))
        descriptors = hold(os.open("fd", _READ | os.O_DIRECTORY, dir_fd=process))
        source = str(fd).encode("ascii")
        _require(_identity(os.stat(source, dir_fd=descriptors, follow_symlinks=True)) == _identity(os.fstat(fd)))
        check()
        _require(libc.linkat(descriptors, ctypes.c_char_p(source), directory,
            ctypes.c_char_p(OBSERVATION_NAME.encode("ascii")), 0x400) == 0)
        refresh(fd)
        os.fsync(directory)
        _require(_identity(os.stat(OBSERVATION_NAME, dir_fd=directory, follow_symlinks=False))
            == _identity(os.fstat(fd)) and _read(fd, launcher.MAX_LOCAL_OBSERVATION) == raw)
        check()
        return fd


class LocalAuthorityStartup:
    """Real fork/PIDFD custody. Failed cleanup is sticky; never reconstruct it."""
    def __init__(self, token):
        _require(token is _TOKEN)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.handles, self.names, self.sockets = [], [], []
        self.child_pid = self.child_pidfd = self.child_start = None
        self.child_status = None
        self.closed = self.uncertain = self.failed = self.admitted = False
        self.value = self.raw = self.setup_raw = self.observation_raw = None
        self.last_boot = self.last_epoch = None

    def _hold(self, fd):
        row = [fd, None]
        self.handles.append(row)
        row[1] = _identity(os.fstat(fd))
        return fd

    def _refresh(self, fd):
        next(row for row in self.handles if row[0] == fd)[1] = _identity(os.fstat(fd))

    def _close_fd(self, fd):
        row = next(row for row in self.handles if row[0] == fd)
        _require(_identity(os.fstat(fd))[:2] == row[1][:2])
        row[0] = None
        try:
            os.close(fd)
        except BaseException:
            self.uncertain = True
            raise
        self.handles.remove(row)

    def _close_socket(self, channel):
        _require(not self.uncertain and channel in self.sockets)
        self.uncertain = True
        channel.close()
        self.sockets.remove(channel)
        self.uncertain = False

    def _open(self, path, *, directory=False, owner=0):
        parts = _path(path)[1:].split("/")
        parent = self._hold(os.open("/", _READ | os.O_DIRECTORY))
        for index, name in enumerate(parts):
            info = os.fstat(parent)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
            final = index == len(parts) - 1
            child = self._hold(os.open(name, _READ | (os.O_DIRECTORY if directory or not final else 0), dir_fd=parent))
            info = os.fstat(child)
            _require(info.st_uid == (owner if final else 0) and not info.st_mode & 0o022)
            self.names.append((parent, name, child, _identity(info), directory or not final))
            parent = child
        return parent

    def _sealed(self, raw, name, target=None):
        fd = self._hold(os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING))
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:offset + 65536]); _require(count > 0); offset += count
        os.fchmod(fd, 0o400)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, launcher.REQUIRED_MEMFD_SEALS)
        if target is not None and fd != target:
            try:
                os.fstat(target)
            except OSError as error:
                _require(error.errno == errno.EBADF)
            else:
                raise LocalStartupError(self)
            self._hold(os.dup2(fd, target, inheritable=False)); self._close_fd(fd); fd = target
        # The sealed identity supersedes only this owner's pre-write metadata.
        next(row for row in self.handles if row[0] == fd)[1] = _identity(os.fstat(fd))
        return fd

    @classmethod
    def open(cls, *, plan_fd, plan_sha256, listener_fd):
        global _LIVE
        _require(cls is LocalAuthorityStartup and _LIVE is None and os.geteuid() == os.getegid() == 0
                 and threading.active_count() == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
                 and listener_fd == 3 and type(plan_fd) is int and plan_fd >= 4)
        owner = cls(_TOKEN); _LIVE = owner
        try:
            with _owning():
                info = os.fstat(plan_fd)
                _require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                    and stat.S_IMODE(info.st_mode) == 0o400 and info.st_nlink in (0, 1)
                    and fcntl.fcntl(plan_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
                if info.st_nlink == 0:
                    _require(fcntl.fcntl(plan_fd, fcntl.F_GET_SEALS) == launcher.REQUIRED_MEMFD_SEALS)
                owner.plan_fd = owner._hold(fcntl.fcntl(plan_fd, fcntl.F_DUPFD_CLOEXEC, 4))
                owner.raw = _read(owner.plan_fd, MAX_PLAN)
                _require(sha(owner.raw) == _digest(plan_sha256) and _read(plan_fd, MAX_PLAN) == owner.raw)
                owner.value = plan(owner.raw); owner.check()
                _require(entrypoint._consume_socket_activation(owner.value["role"]) == listener_fd)
                os.set_inheritable(listener_fd, False)
                owner.listener = owner._hold(fcntl.fcntl(listener_fd, fcntl.F_DUPFD_CLOEXEC, 4))
                owner.purposes = ("manifest", "certificate", "evidence") if owner.value["role"] in launcher.RUNTIME_EVIDENCE_ROLES else ("manifest", "certificate")
                owner.reservations = {}
                for purpose in owner.purposes:
                    target = launcher.LOCAL_SLOTS[purpose]
                    fd = owner._sealed(b"", "local-reserved-" + purpose, target)
                    info = os.fstat(fd)
                    owner.reservations[purpose] = dict(fd=fd, device=info.st_dev, inode=info.st_ino)
                if owner.value["mutableStateDescriptors"]:
                    owner._sealed(b"", "local-reserved-witness", 259)
                owner.resource_files, owner.resource_directories = [], []
                for item in owner.value["retainedFiles"]:
                    fd = owner._open(item["path"])
                    _require(4 <= fd <= 1023 and sha(_read(fd, launcher.MAX_CLOSURE_FILE_BYTES)) == item["sha256"])
                    owner.resource_files.append(fd)
                for item in owner.value["retainedDirectories"]:
                    fd = owner._open(item["path"], directory=True)
                    _require(4 <= fd <= 1023 and (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (item["device"], item["inode"]))
                    owner.resource_directories.append(fd)
                owner.directory_fds = {}
                for key in ("credentialDirectory", "exchangeDirectory"):
                    item = owner.value[key]; fd = owner._open(item["path"], directory=True)
                    info = os.fstat(fd)
                    _require((info.st_dev, info.st_ino) == (item["device"], item["inode"]))
                    if key == "exchangeDirectory":
                        _require(info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
                        with os.scandir(fd) as entries:
                            _require(next(entries, None) is None)
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    owner.directory_fds[key] = fd
                if owner.value["mutableStateDescriptors"]:
                    item = owner.value["mutableStateDescriptors"][0]
                    fd = owner._open(item["runtimePath"], directory=True, owner=65523)
                    info = os.fstat(fd)
                    _require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                        == (item["device"], item["inode"], item["uid"], item["gid"], item["mode"]))
                    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as source:
                        mount = [line.split(":", 1)[1].strip() for line in source if line.startswith("mnt_id:")]
                    _require(mount == [str(item["mountId"])])
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    owner._close_fd(259)
                    held = owner._hold(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 259))
                    _require(held == 259)
                owner.check(full=True)
            return owner
        except BaseException as error:
            owner.failed = True
            raise LocalStartupError(owner) from error

    def check(self, *, full=False, startup=True, child_live=False):
        _require(_LIVE is self and (os.getpid(), threading.get_ident()) == (self.pid, self.thread)
            and os.geteuid() == os.getegid() == 0 and not (self.closed or self.uncertain))
        if self.value is not None and startup:
            current_boot, current_epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
            _require(_boot() == self.value["bootIdDigest"]
                and self.value["issuedAtBoottimeNs"] <= current_boot < self.value["deadlineBoottimeNs"]
                and self.value["issuedAtUnixNanos"] <= current_epoch < self.value["expiresAtUnixNanos"]
                and (self.last_boot is None or self.last_boot <= current_boot)
                and (self.last_epoch is None or self.last_epoch <= current_epoch))
        for fd, identity in self.handles:
            _require(fd is not None and _identity(os.fstat(fd))[:6] == identity[:6])
        for parent, name, child, identity, directory in self.names:
            observed = _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
            held = _identity(os.fstat(child))
            _require(observed[:6] == held[:6] == identity[:6] if directory else observed == held == identity)
        if self.raw is not None:
            _require(_read(self.plan_fd, MAX_PLAN) == self.raw)
        if full and hasattr(self, "resource_files"):
            for row, fd in zip(self.value["retainedFiles"], self.resource_files):
                _require(sha(_read(fd, launcher.MAX_CLOSURE_FILE_BYTES)) == row["sha256"])
        if self.child_pid is not None and self.child_status is None:
            _require(_start(self.child_pid) == (self.child_start, self.pid))
            if child_live:
                _require(not select.select([self.child_pidfd], [], [], 0)[0])
        if startup and self.value is not None:
            after_boot, after_epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
            _require(current_boot <= after_boot < self.value["deadlineBoottimeNs"]
                     and current_epoch <= after_epoch < self.value["expiresAtUnixNanos"])
            self.last_boot, self.last_epoch = after_boot, after_epoch

    def _wait(self, *, write=False):
        self.check(child_live=True)
        remaining = min(self.value["deadlineBoottimeNs"] - time.clock_gettime_ns(time.CLOCK_BOOTTIME),
                        self.value["expiresAtUnixNanos"] - time.time_ns()) / 1e9
        readable, writable, _ = select.select([self.child_pidfd] + ([] if write else [self.channel]),
            [self.channel] if write else [], [], max(0, min(0.05, remaining)))
        self.check(child_live=True)
        return bool(writable if write else self.channel in readable)

    def _receive(self, *, admitted=False):
        while not self._wait():
            pass
        with _owning():
            data, ancillary, flags, _ = self.channel.recvmsg(65536, socket.CMSG_SPACE(4 * 4) + socket.CMSG_SPACE(_UCRED.size), socket.MSG_CMSG_CLOEXEC)
            descriptors, credentials, invalid = [], [], False
            for level, kind, raw in ancillary:
                if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, 4):
                    values = array.array("i"); values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
                    for fd in values:
                        descriptors.append(self._hold(fd))
                    invalid |= kind != socket.SCM_RIGHTS or len(raw) % values.itemsize != 0
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                    if len(raw) == _UCRED.size:
                        credentials.append(_UCRED.unpack(raw))
                    else:
                        invalid = True
                else:
                    invalid = True
            uid, gid = launcher.ROLE_IDENTITIES[self.value["role"]] if admitted else (0, 0)
            _require(not invalid and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and credentials == [(self.child_pid, uid, gid)]
                and len(descriptors) == (0 if admitted else 1))
            value = _document(data, 65536)
        self.check(child_live=True)
        return value, descriptors

    def _spawn(self):
        with _owning() as mask:
            pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            self.sockets.extend(pair); self.channel, child_channel = pair
            for channel in pair:
                channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                channel.setblocking(False)
            setup = {name: self.value[name] for name in ("role", "bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos", "mutableStateDescriptors")}
            setup.update(schema=launcher.LOCAL_SETUP_SCHEMA,
                producer=dict(pid=self.pid, uid=0, gid=0, startTimeTicks=_start(self.pid)[0]),
                retainedFiles=self.resource_files, retainedDirectories=self.resource_directories, reservations=self.reservations)
            self.setup_raw = encode(setup)
            self.setup_fd = self._sealed(self.setup_raw, "local-admission")
            _require(4 <= self.setup_fd <= 1023 and 4 <= child_channel.fileno() <= 1023)
            null = self._hold(os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC))
            environment = dict(self.value["environment"], LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC",
                PATH="/runtime/python/bin:/usr/bin", PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0",
                SERVERWARE_AUTHORITY_TRUST_MODE="trusted-host-local", CREDENTIALS_DIRECTORY=self.value["credentialDirectory"]["path"],
                LISTEN_FDS="1", LISTEN_FDNAMES=launcher.ROLE_LISTENER_NAMES[self.value["role"]])
            keep = {3, self.setup_fd, child_channel.fileno(), *self.resource_files, *self.resource_directories,
                    *(row["fd"] for row in self.reservations.values()), *(row["fd"] for row in self.value["mutableStateDescriptors"])}
            argv = [INTERPRETER, "-I", "-B", ENTRYPOINT, self.value["role"], "--local-admission-fd", str(self.setup_fd),
                    "--local-admission-sha256", sha(self.setup_raw), "--local-admission-channel-fd", str(child_channel.fileno())]
            libc = ctypes.CDLL(None, use_errno=True)
            child = os.fork()
            if child == 0:
                try:
                    _require(libc.prctl(1, signal.SIGTERM, 0, 0, 0) == 0 and os.getppid() == self.pid)
                    _require(libc.prctl(38, 1, 0, 0, 0) == 0)
                    for signo in _CANCEL:
                        signal.signal(signo, signal.SIG_DFL)
                    os.dup2(self.listener, 3, inheritable=True)
                    for fd in (0, 1, 2):
                        os.dup2(null, fd, inheritable=True)
                    for fd in keep:
                        os.set_inheritable(fd, True)
                    for name in os.listdir("/proc/self/fd"):
                        fd = int(name)
                        if fd >= 3 and fd not in keep:
                            try:
                                os.close(fd)
                            except OSError as error:
                                if error.errno != errno.EBADF:
                                    raise
                    environment["LISTEN_PID"] = str(os.getpid())
                    os.chdir("/runtime")
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                    os.execve(INTERPRETER, argv, environment)
                except BaseException:
                    os._exit(127)
            self.child_pid = child
            self.child_pidfd = self._hold(os.pidfd_open(child, 0))
            self.child_start, parent = _start(child); _require(parent == self.pid)
            self._close_socket(child_channel)
            self._close_fd(null)

    def _publish(self, raw):
        directory = self.directory_fds["exchangeDirectory"]
        with _owning():
            fd = _publish_effect(directory, raw, hold=self._hold, refresh=self._refresh,
                check=lambda: self.check(child_live=True))
            # After publication this exact named inode remains held through response.
            self.names.append((directory, OBSERVATION_NAME, fd, _identity(os.fstat(fd)), False))
            next(row for row in self.handles if row[0] == fd)[1] = _identity(os.fstat(fd))

    def _late(self):
        directory = self.directory_fds["exchangeDirectory"]
        sources = {}
        while len(sources) != len(self.purposes):
            self.check(child_live=True)
            with os.scandir(directory) as entries:
                names = []
                for item in entries:
                    names.append(item.name); _require(len(names) <= 1 + len(self.purposes))
            _require(set(names) <= {OBSERVATION_NAME, *(LATE_NAMES[p] for p in self.purposes)})
            for purpose in self.purposes:
                if purpose in sources or LATE_NAMES[purpose] not in names:
                    continue
                with _owning():
                    fd = self._hold(os.open(LATE_NAMES[purpose], _READ, dir_fd=directory))
                    info = os.fstat(fd)
                    _require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                        and stat.S_IMODE(info.st_mode) == 0o400 and info.st_nlink == 1)
                    raw = _read(fd, LIMITS[purpose]); _document(raw, LIMITS[purpose])
                    self.names.append((directory, LATE_NAMES[purpose], fd, _identity(info), False))
                    # The original remains named/held; only a literal sealed
                    # copy crosses the existing protected-descriptor protocol.
                    sources[purpose] = (self._sealed(raw, "local-late-" + purpose), raw)
            if len(sources) != len(self.purposes):
                select.select([self.child_pidfd], [], [], 0.05)
        self.check(full=True, child_live=True)
        return sources

    def run(self):
        try:
            self.check(full=True); _require(self.child_pid is None)
            self._spawn()
            header, fds = self._receive()
            _require(set(header) == {"schema", "role", "setupSha256", "observationSha256", "observationBytes"}
                and header["schema"] == launcher.LOCAL_DELIVERY_SCHEMA and header["role"] == self.value["role"]
                and header["setupSha256"] == sha(self.setup_raw))
            observed_fd = fds[0]; info = os.fstat(observed_fd)
            _require(stat.S_IMODE(info.st_mode) == 0o400 and info.st_uid == info.st_gid == 0 and info.st_nlink == 0
                and fcntl.fcntl(observed_fd, fcntl.F_GET_SEALS) == launcher.REQUIRED_MEMFD_SEALS)
            self.observation_raw = _read(observed_fd, launcher.MAX_LOCAL_OBSERVATION)
            _require(header["observationBytes"] == len(self.observation_raw) and type(header["observationBytes"]) is int
                and header["observationSha256"] == sha(self.observation_raw))
            observed = _document(self.observation_raw, launcher.MAX_LOCAL_OBSERVATION)
            _require(observed["schema"] == launcher.LOCAL_OBSERVATION_SCHEMA and observed["role"] == self.value["role"]
                and observed["setupSha256"] == sha(self.setup_raw)
                and (observed["process"]["pid"], observed["process"]["startTimeTicks"], observed["process"]["parentPid"])
                    == (self.child_pid, self.child_start, self.pid)
                and observed["deadlineBoottimeNs"] == self.value["deadlineBoottimeNs"]
                and observed["expiresAtUnixNanos"] == self.value["expiresAtUnixNanos"])
            self._publish(self.observation_raw)
            sources = self._late()
            reply = encode(dict(schema=launcher.LOCAL_REPLY_SCHEMA, role=self.value["role"], setupSha256=sha(self.setup_raw),
                observationSha256=sha(self.observation_raw), originals=[dict(purpose=p, sha256=sha(sources[p][1]), size=len(sources[p][1])) for p in self.purposes]))
            while not self._wait(write=True):
                pass
            _require(self.channel.sendmsg([reply], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                array.array("i", [sources[p][0] for p in self.purposes]))], socket.MSG_NOSIGNAL) == len(reply))
            notice, _ = self._receive(admitted=True)
            uid, gid = launcher.ROLE_IDENTITIES[self.value["role"]]
            _require(notice == dict(schema=ADMITTED_SCHEMA, role=self.value["role"], setupSha256=sha(self.setup_raw),
                                    observationSha256=sha(self.observation_raw), pid=self.child_pid,
                                    uid=uid, gid=gid, startTimeTicks=self.child_start))
            self.check(full=True, child_live=True)
            self.admitted = True
            # Admission is not service readiness. The signed service lifetime is
            # now enforced by the actual admitted child, not a renewed timer here.
            while not select.select([self.child_pidfd], [], [], 0.5)[0]:
                self.check(startup=False)
            self._reap()
            _require(self.child_status == 0)
            self.close()
            return {"status": "child-exited", "admitted": True, "exitCode": 0, "readinessAsserted": False}
        except BaseException as error:
            self.failed = True
            raise LocalStartupError(self) from error

    def _reap(self):
        value = os.waitid(os.P_PIDFD, self.child_pidfd, os.WEXITED)
        _require(value is not None and value.si_pid == self.child_pid)
        self.child_status = value.si_status if value.si_code == os.CLD_EXITED else -value.si_status

    def close(self, *, cancel=False):
        if self.closed:
            return
        _require(not self.uncertain and (os.getpid(), threading.get_ident()) == (self.pid, self.thread))
        try:
            with _owning():
                if self.child_pid is not None and self.child_status is None:
                    _require(cancel)
                    if self.child_pidfd is None:
                        # Only the actual direct child created above is allowed
                        # here. With SIGCHLD default and no other threads/reaper,
                        # its PID cannot recycle before this consuming wait.
                        _require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
                        try:
                            os.kill(self.child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        limit = time.monotonic() + 5
                        while True:
                            pid, status = os.waitpid(self.child_pid, os.WNOHANG)
                            if pid == self.child_pid:
                                self.child_status = os.waitstatus_to_exitcode(status); break
                            _require(time.monotonic() < limit)
                            select.select([], [], [], 0.02)
                    else:
                        if not select.select([self.child_pidfd], [], [], 0)[0]:
                            signal.pidfd_send_signal(self.child_pidfd, signal.SIGTERM)
                        if not select.select([self.child_pidfd], [], [], 5)[0]:
                            signal.pidfd_send_signal(self.child_pidfd, signal.SIGKILL)
                        _require(select.select([self.child_pidfd], [], [], 5)[0])
                        self._reap()
                while self.sockets:
                    self._close_socket(self.sockets[-1])
                for row in tuple(reversed(self.handles)):
                    self._close_fd(row[0])
                self.closed = True
        except BaseException as error:
            self.uncertain = True
            raise LocalStartupError(self) from error
