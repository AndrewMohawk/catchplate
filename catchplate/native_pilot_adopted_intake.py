"""Actual cold-core receiving custody for the fixed adopted conductor.

The independently pinned public configuration is not a core or adoption
approval. The conductor creates its own connection: an inherited socketpair
cannot substitute its parent's kernel credentials for this process. Only the
existing authenticated recvmsg/ACK path constructs ReceivedGenesisCore.
"""
from __future__ import annotations

import copy
import errno
import fcntl
import os
import select
import socket
import stat
import threading
import time

from scripts.authority import native_pilot_authority_io as public_io
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_pilot_genesis_core_channel import GenesisCoreReceiver, GenesisCoreChannelError

p = io.p
API = "catchplate.nativePilotAdoptedIntakeConfiguration/v1"
PURPOSE = "receive-cold-core-for-adopted-native-pilot"
DIRECTORY = "/run/catchplate/native-pilot-core-handoff"
ENDPOINT = DIRECTORY + "/core.sock"
MAX_CONFIGURATION = 8192
FIELDS = ("apiVersion", "purpose", "sender", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs",
    "issuedAtUnixNanos", "expiresAtUnixNanos")
_TOKEN = object()
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def conductor_arguments(*, configuration_fd, configuration_sha256):
    """Source-fixed arguments only; a descriptor number is not authority."""
    p.integer(configuration_fd, minimum=3, maximum=(1 << 31) - 1)
    p.digest(configuration_sha256)
    return ["--run-adopted-native-pilot", "--intake-configuration-fd", str(configuration_fd),
        "--intake-configuration-sha256", configuration_sha256]


def invocation(arguments):
    p.require(type(arguments) is list and all(type(value) is str for value in arguments))
    if arguments == ["--run-native-pilot"]:
        return None
    p.require(len(arguments) == 5 and arguments[0] == "--run-adopted-native-pilot"
        and arguments[1] == "--intake-configuration-fd" and arguments[3] == "--intake-configuration-sha256"
        and arguments[2].isascii() and arguments[2].isdigit() and len(arguments[2]) <= 10)
    result = dict(configuration_fd=int(arguments[2]), configuration_sha256=arguments[4])
    p.require(conductor_arguments(**result) == arguments)
    return result


def validate_configuration(raw, *, boot, now_boottime_ns, now_unix_ns):
    """Pure approved-input validation, not sender ownership or core admission."""
    value = p.fields(p.document(raw, MAX_CONFIGURATION), FIELDS)
    p.require(p.canonical(value) == raw and value["apiVersion"] == API and value["purpose"] == PURPOSE)
    sender = p.fields(value["sender"], ("pid", "uid", "gid", "startTimeTicks"))
    p.integer(sender["pid"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(sender["startTimeTicks"], maximum=p.MAX_I64)
    p.require(type(sender["uid"]) is int and type(sender["gid"]) is int and sender["uid"] == sender["gid"] == 0)
    p.decoded(value["bootIdBase64url"], size=16)
    p.integer(value["timeNamespaceDevice"], maximum=p.MAX_I64)
    p.integer(value["timeNamespaceInode"], maximum=p.MAX_I64)
    p.require((value["bootIdBase64url"], value["timeNamespaceDevice"], value["timeNamespaceInode"]) == boot)
    issued, startup, lifetime = (p.ns(value[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    epoch, expiry = (p.integer(value[name], maximum=p.MAX_I64) for name in ("issuedAtUnixNanos", "expiresAtUnixNanos"))
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns, maximum=p.MAX_I64)
    p.require(issued < startup < lifetime and issued <= now_boottime_ns < lifetime
        and epoch <= now_unix_ns < expiry)
    return copy.deepcopy(value)


class IntakeError(ValueError):
    def __init__(self, owner):
        super().__init__("adopted intake refused; actual owner retained")
        self.owner = owner


class IntakeConfiguration:
    """Process-local protected public original, independently reopened by child."""
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._fd = self._identity = self._raw = self._value = None
        self._closed = self._close_attempted = False

    @classmethod
    def open(cls, fd, sha256):
        owner = cls(_TOKEN)
        try:
            owner._origin()
            p.require(len(os.listdir("/proc/self/task")) == 1)
            p.integer(fd, minimum=3, maximum=(1 << 31) - 1); p.digest(sha256)
            with io.owning():
                expected = public_io._input(fd, MAX_CONFIGURATION)
                owner._fd = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128)
                owner._identity = public_io._input(owner._fd, MAX_CONFIGURATION)
                owner._raw = public_io.read_public(owner._fd, MAX_CONFIGURATION)
                p.require(owner._identity == expected and p.sha(owner._raw) == sha256
                    and public_io.read_public(fd, MAX_CONFIGURATION) == owner._raw)
            owner._value = validate_configuration(owner._raw, boot=owner._boot,
                now_boottime_ns=owner._last, now_unix_ns=owner._wall)
            owner.check(startup=True)
            return owner
        except BaseException as error:
            raise IntakeError(owner) from error

    @property
    def raw(self):
        return self._raw

    @property
    def value(self):
        return copy.deepcopy(self._value)

    @property
    def startup_deadline_boottime_ns(self):
        return p.ns(self._value["startupDeadlineBoottimeNs"])

    @property
    def deadline_boottime_ns(self):
        return p.ns(self._value["lifetimeDeadlineBoottimeNs"])

    @property
    def expires_at_unix_ns(self):
        return self._value["expiresAtUnixNanos"]

    def _origin(self):
        p.require(not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def check(self, *, startup=False):
        self._origin()
        p.require(type(startup) is bool and self._fd is not None and not self._close_attempted
            and not os.get_inheritable(self._fd) and public_io._input(self._fd, MAX_CONFIGURATION) == self._identity)
        p.require(public_io.read_public(self._fd, MAX_CONFIGURATION) == self._raw)
        p.require(public_io._input(self._fd, MAX_CONFIGURATION) == self._identity)
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        validate_configuration(self._raw, boot=self._boot, now_boottime_ns=now, now_unix_ns=wall)
        p.require(self._last <= now and self._wall <= wall
            and (not startup or now < self.startup_deadline_boottime_ns))
        self._last, self._wall = now, wall

    def borrowed_fd(self):
        self.check()
        return self._fd

    def close(self):
        if self._closed:
            return
        self._origin()
        p.require(not self._close_attempted)
        self._close_attempted = True
        with io.owning():
            if self._fd is not None:
                if self._identity is not None:
                    p.require(public_io._identity(os.fstat(self._fd)) == self._identity)
                fd, self._fd = self._fd, None
                os.close(fd)
            self._closed = True


def _structural(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _sender_start(pid):
    # This lookup only checks an already kernel-authenticated held PIDFD. It
    # never creates process authority or authorizes signalling by numeric PID.
    fd = os.open("/proc/" + str(pid) + "/stat", _READ)
    try:
        raw = os.read(fd, 8193)
        p.require(0 < len(raw) <= 8192 and not os.read(fd, 1))
    finally:
        os.close(fd)
    end = raw.rfind(b")")
    p.require(end > 0 and raw[:raw.index(b" ")] == str(pid).encode("ascii"))
    fields = raw[end + 2:].split()
    p.require(len(fields) > 19 and fields[19].isdigit())
    return int(fields[19])


class AdoptedIntake:
    """Retains actual receiver/partial acquisition until known pilot cleanup."""
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start = os.getpid(), originals._start()
        self._configuration = self._receiver = self._socket = self._core = None
        self._input_fd = None
        self._socket_identity = None
        self._directories, self._identities, self._links = [], [], []
        self._leaf = None
        self._attempted = self._closed = self._close_attempted = False

    @classmethod
    def prepare(cls, *, configuration_fd, configuration_sha256):
        """Consume the child's inherited public FD, retaining every failure."""
        owner = cls(_TOKEN)
        try:
            with io.owning():
                p.integer(configuration_fd, minimum=3, maximum=(1 << 31) - 1)
                owner._input_fd = configuration_fd
                try:
                    owner._configuration = IntakeConfiguration.open(configuration_fd, configuration_sha256)
                except IntakeError as error:
                    owner._configuration = error.owner
                    raise
            return owner
        except BaseException as error:
            raise IntakeError(owner) from error

    def _guard(self):
        p.require(not self._closed and not self._close_attempted and os.getpid() == self._pid
            and originals._start() == self._start)
        self._configuration.check(startup=True)
        for fd, identity in zip(self._directories, self._identities, strict=True):
            p.require(_structural(os.fstat(fd)) == identity and not os.get_inheritable(fd))
        for parent, name, identity in self._links:
            p.require(_structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
        if self._leaf is not None and (self._receiver is None or not self._receiver._acked):
            p.require(_structural(os.stat("core.sock", dir_fd=self._directories[-1], follow_symlinks=False)) == self._leaf)
        receiver = self._receiver
        if self._socket is not None:
            p.require(_structural(os.fstat(self._socket.fileno())) == self._socket_identity
                and not self._socket.get_inheritable())
        if receiver is not None and not receiver._acked:
            sender = self._configuration.value["sender"]
            p.require(io.pidfd_pid(receiver._peer_fd) == sender["pid"]
                and _sender_start(sender["pid"]) == sender["startTimeTicks"]
                and io.pidfd_pid(receiver._peer_fd) == sender["pid"])
        self._configuration.check(startup=True)

    def receive(self):
        try:
            p.require(not self._attempted)
            self._attempted = True
            self._guard()
            with io.owning():
                parent = os.open("/", _READ | os.O_DIRECTORY)
                self._directories.append(parent)
                self._identities.append(_structural(os.fstat(parent)))
                for name in ("run", "catchplate", "native-pilot-core-handoff"):
                    info = os.fstat(parent)
                    p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
                    child = os.open(name, _READ | os.O_DIRECTORY, dir_fd=parent)
                    self._directories.append(child)
                    identity = _structural(os.fstat(child))
                    self._identities.append(identity); self._links.append((parent, name, identity))
                    parent = child
                info = os.fstat(parent)
                p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
                leaf = os.stat("core.sock", dir_fd=parent, follow_symlinks=False)
                p.require(stat.S_ISSOCK(leaf.st_mode) and leaf.st_uid == leaf.st_gid == 0
                    and stat.S_IMODE(leaf.st_mode) == 0o600 and leaf.st_nlink == 1)
                self._leaf = _structural(leaf)
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
                self._socket_identity = _structural(os.fstat(self._socket.fileno()))
            self._guard()
            outcome = self._socket.connect_ex("/proc/self/fd/" + str(parent) + "/core.sock")
            p.require(outcome in (0, errno.EINPROGRESS))
            if outcome == errno.EINPROGRESS:
                while True:
                    self._guard()
                    remaining = min(self._configuration.startup_deadline_boottime_ns - self._configuration._last,
                        self._configuration.expires_at_unix_ns - self._configuration._wall) / 1_000_000_000
                    _, writable, _ = select.select([], [self._socket], [], min(0.01, remaining))
                    self._guard()
                    if writable:
                        p.require(self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0)
                        break
            self._guard()
            sender = self._configuration.value["sender"]
            with io.owning():
                try:
                    self._receiver = GenesisCoreReceiver.open(self._socket.fileno(), sender["pid"], sender["uid"], sender["gid"],
                        self._configuration.deadline_boottime_ns, self._configuration.expires_at_unix_ns)
                except GenesisCoreChannelError as error:
                    self._receiver = error.owner
                    raise
            self._guard()
            # The receiver retains its actual _received owner before ACK, so
            # cancellation cannot lose the core even before this assignment.
            self._core = self._receiver.receive(check=self._guard)
            self._guard()
            return self._core
        except BaseException as error:
            raise IntakeError(self) from error

    def close(self):
        if self._closed:
            return
        try:
            p.require(not self._close_attempted and os.getpid() == self._pid and originals._start() == self._start)
            self._close_attempted = True
            # Existing Receiver.close enforces genuine cohort retirement if
            # the core was claimed. No DTO, ACK or exception proves that reap.
            if self._receiver is not None:
                self._receiver.close()
            with io.owning():
                if self._socket is not None:
                    p.require(self._socket_identity is None or _structural(os.fstat(self._socket.fileno())) == self._socket_identity)
                    channel, self._socket = self._socket, None
                    channel.close()
                while self._directories:
                    os.close(self._directories.pop())
                if self._configuration is not None:
                    self._configuration.close()
                if self._input_fd is not None:
                    if self._configuration is not None and self._configuration._identity is not None:
                        p.require(public_io._identity(os.fstat(self._input_fd)) == self._configuration._identity)
                    fd, self._input_fd = self._input_fd, None
                    os.close(fd)
                self._closed = True
        except BaseException as error:
            raise IntakeError(self) from error
