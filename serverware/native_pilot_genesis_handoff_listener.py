"""One real cold-sender listener, before approval of the observed receiver.

An independently approved original window permits this fixed listener only.
Its actual process observation lets a separate authority start the recipient,
then approve the exact existing v2 execution configuration with that real PID.
No future PID, peer approval, core, or operational adoption is manufactured.
"""
from __future__ import annotations

import copy
import os
import select
import socket
import stat
import threading
import time

from serverware import native_pilot_adopted_intake as intake
from serverware import native_pilot_genesis_execution_protocol as wire
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_genesis_core_channel import GenesisCoreChannel, GenesisCoreChannelError

p = wire.p
API = "serverware.nativePilotGenesisListenerConfiguration/v1"
OBSERVATION_API = "serverware.nativePilotGenesisListenerObservation/v1"
REQUEST_API = "serverware.nativePilotGenesisListenerRequest/v1"
REPLY_API = "serverware.nativePilotGenesisListenerReply/v1"
APPROVAL_API = "serverware.nativePilotGenesisListenerApproval/v1"
INPUT_PATH = "/etc/serverware/native-genesis-authority/listener-execution.input.json"
APPROVAL_PATH = "/etc/serverware/native-genesis-authority/listener-execution.approval.json"
DIRECTORY, ENDPOINT = intake.DIRECTORY, intake.ENDPOINT
_TOKEN = object()
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def configuration(raw, *, boot, now_boottime_ns, now_unix_ns):
    value = p.fields(p.document(raw, 4096), ("apiVersion", "window", "expiresAtUnixNanos"))
    p.require(value["apiVersion"] == API and p.canonical(value) == raw)
    window = p.fields(value["window"], wire.endpoints.WINDOW)
    p.require(p.decoded(window["bootIdBase64url"], size=16) != bytes(16))
    p.integer(window["timeNamespaceDevice"], minimum=0, maximum=p.MAX_I64)
    p.integer(window["timeNamespaceInode"], maximum=p.MAX_I64)
    p.require(tuple(window[name] for name in wire.endpoints.WINDOW[:3]) == boot)
    wire.endpoints.parent._invocation(window["invocationId"])
    issued, startup, lifetime = (p.ns(window[name]) for name in wire.endpoints.WINDOW[3:6])
    p.require(issued <= now_boottime_ns < min(startup, lifetime - wire.RESERVE)
        and startup <= lifetime and startup - issued <= 30_000_000_000)
    p.require(now_unix_ns < p.integer(value["expiresAtUnixNanos"]))
    return copy.deepcopy(value)


def require_execution(raw, listener, *, boot, now_boottime_ns, now_unix_ns):
    """Exact approved window join; peer identity remains actual channel work."""
    selected = wire.configuration(raw, boot=boot, now_boottime_ns=now_boottime_ns,
        now_unix_ns=now_unix_ns, handoff=True)
    p.require(p.canonical(selected["window"]) == p.canonical(listener["window"])
        and selected["expiresAtUnixNanos"] == listener["expiresAtUnixNanos"])
    return selected


def reply(raw, request_raw):
    value = p.fields(p.document(raw, 4096), ("apiVersion", "requestSha256", "inputSha256", "approvalSha256"))
    request = p.fields(p.document(request_raw, 8192),
        ("apiVersion", "sequence", "listenerOriginal", "listenerSha256", "configurationSha256", "deadlineBoottimeNs", "expiresAtUnixNanos"))
    p.require(request["apiVersion"] == REQUEST_API and type(request["sequence"]) is int and request["sequence"] == 0)
    p.require(value["apiVersion"] == REPLY_API and value["requestSha256"] == p.sha(request_raw))
    p.digest(value["inputSha256"]); p.digest(value["approvalSha256"])
    return value


def approval(raw, *, request_raw, input_sha256):
    value = p.fields(p.document(raw, 4096), ("apiVersion", "requestSha256", "inputSha256",
        "listenerConfigurationSha256", "deadlineBoottimeNs", "expiresAtUnixNanos"))
    request = p.document(request_raw, 8192)
    p.require(value["apiVersion"] == APPROVAL_API and value["requestSha256"] == p.sha(request_raw)
        and value["inputSha256"] == p.digest(input_sha256)
        and value["listenerConfigurationSha256"] == request["configurationSha256"]
        and value["deadlineBoottimeNs"] == request["deadlineBoottimeNs"]
        and value["expiresAtUnixNanos"] == request["expiresAtUnixNanos"])
    return value


class ListenerError(ValueError):
    def __init__(self, owner):
        super().__init__("cold handoff listener refused; actual owner retained")
        self.owner = owner


class CoreHandoffListener:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._source = self._value = self._socket = self._accepted = self._channel = None
        self._socket_identity = self._accepted_identity = None
        self._directories, self._identities, self._links = [], [], []
        self._leaf = None
        self._bound = self._closed = self._close_attempted = self._accept_attempted = False

    @classmethod
    def open(cls, configuration_fd, configuration_sha256):
        owner = cls(_TOKEN)
        try:
            owner._origin()
            with io.owning():
                owner._source = io.PublicInput(configuration_fd, 4096, configuration_sha256)
            owner._value = configuration(owner._source.raw, boot=owner._boot,
                now_boottime_ns=owner._last, now_unix_ns=owner._wall)
            owner.check(startup=True)
            with io.owning():
                parent = os.open("/", _READ | os.O_DIRECTORY)
                owner._directories.append(parent); owner._identities.append(intake._structural(os.fstat(parent)))
                for name in ("run", "serverware", "native-pilot-core-handoff"):
                    info = os.fstat(parent)
                    p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
                    child = os.open(name, _READ | os.O_DIRECTORY, dir_fd=parent)
                    owner._directories.append(child)
                    identity = intake._structural(os.fstat(child))
                    owner._identities.append(identity); owner._links.append((parent, name, identity))
                    parent = child
                info = os.fstat(parent)
                p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
                owner._socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
                owner._socket_identity = intake._structural(os.fstat(owner._socket.fileno()))
                old_mask = os.umask(0o177)
                try:
                    # bind refuses every preexisting leaf, including symlinks;
                    # no unlink, adoption or replacement precedes this call.
                    owner._socket.bind("/proc/self/fd/" + str(parent) + "/core.sock")
                    owner._bound = True
                finally:
                    os.umask(old_mask)
                leaf = os.stat("core.sock", dir_fd=parent, follow_symlinks=False)
                owner._leaf = intake._structural(leaf)
                p.require(stat.S_ISSOCK(leaf.st_mode) and leaf.st_uid == leaf.st_gid == 0
                    and stat.S_IMODE(leaf.st_mode) == 0o600 and leaf.st_nlink == 1)
                owner._socket.listen(1)
            owner.check(startup=True)
            return owner
        except BaseException as error:
            raise ListenerError(owner) from error

    @property
    def startup_deadline_boottime_ns(self):
        return p.ns(self._value["window"]["startupDeadlineBoottimeNs"])

    @property
    def expires_at_unix_ns(self):
        return self._value["expiresAtUnixNanos"]

    def _origin(self):
        p.require(not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and threading.current_thread() is threading.main_thread()
            and len(os.listdir("/proc/self/task")) == 1 and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def check(self, *, startup=False):
        self._origin()
        p.require(not self._close_attempted and type(startup) is bool)
        self._source.check()
        for fd, identity in zip(self._directories, self._identities, strict=True):
            p.require(intake._structural(os.fstat(fd)) == identity and not os.get_inheritable(fd))
        for parent, name, identity in self._links:
            p.require(intake._structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
        if self._bound:
            p.require(self._leaf is not None and intake._structural(os.stat("core.sock",
                dir_fd=self._directories[-1], follow_symlinks=False)) == self._leaf)
            p.require(self._socket is not None and not os.get_inheritable(self._socket.fileno())
                and intake._structural(os.fstat(self._socket.fileno())) == self._socket_identity
                and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1)
        if self._accepted is not None:
            p.require(intake._structural(os.fstat(self._accepted.fileno())) == self._accepted_identity
                and not self._accepted.get_inheritable())
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        window = self._value["window"]
        p.require(p.ns(window["issuedAtBoottimeNs"]) <= self._last <= now
            < p.ns(window["startupDeadlineBoottimeNs"] if startup else window["lifetimeDeadlineBoottimeNs"])
            and self._wall <= wall < self.expires_at_unix_ns)
        self._last, self._wall = now, wall

    def request_original(self):
        self.check(startup=True)
        p.require(self._bound and self._leaf is not None)
        observed = p.canonical(dict(apiVersion=OBSERVATION_API, configurationSha256=p.sha(self._source.raw),
            processId=self._pid, processStartTimeTicks=self._start, endpoint=ENDPOINT,
            bootIdBase64url=self._boot[0], timeNamespaceDevice=self._boot[1], timeNamespaceInode=self._boot[2],
            socket=dict(zip(("device", "inode", "mode", "uid", "gid"), self._leaf, strict=True))))
        result = p.canonical(dict(apiVersion=REQUEST_API, sequence=0, listenerOriginal=observed.decode("ascii"),
            listenerSha256=p.sha(observed), configurationSha256=p.sha(self._source.raw),
            deadlineBoottimeNs=str(self.startup_deadline_boottime_ns), expiresAtUnixNanos=self.expires_at_unix_ns))
        self.check(startup=True)
        return result

    def require_execution(self, raw):
        self.check(startup=True)
        selected = require_execution(raw, self._value, boot=self._boot,
            now_boottime_ns=self._last, now_unix_ns=self._wall)
        p.require(selected["coreHandoff"]["peerPid"] != self._pid)
        self.check(startup=True)
        return selected

    def accept(self, raw, check):
        try:
            p.require(not self._accept_attempted and callable(check))
            self._accept_attempted = True
            selected = self.require_execution(raw)
            while True:
                self.check(startup=True); check(); self.check(startup=True)
                remaining = min(self.startup_deadline_boottime_ns - self._last, self.expires_at_unix_ns - self._wall) / 1_000_000_000
                ready, _, _ = select.select([self._socket], [], [], min(0.01, remaining))
                self.check(startup=True); check(); self.check(startup=True)
                if ready:
                    with io.owning():
                        self._accepted, _ = self._socket.accept()
                        self._accepted_identity = intake._structural(os.fstat(self._accepted.fileno()))
                        self._accepted.set_inheritable(False)
                        self._accepted.setblocking(False)
                    break
            peer = selected["coreHandoff"]
            with io.owning():
                try:
                    self._channel = GenesisCoreChannel.open(self._accepted.fileno(), peer["peerPid"], peer["peerUid"], peer["peerGid"],
                        p.ns(selected["window"]["lifetimeDeadlineBoottimeNs"]), selected["expiresAtUnixNanos"])
                except GenesisCoreChannelError as error:
                    self._channel = error.owner
                    raise
            self.check(startup=True); check(); self.check(startup=True)
            return self._channel
        except BaseException as error:
            raise ListenerError(self) from error

    def close(self):
        if self._closed:
            return
        try:
            self._origin()
            p.require(not self._close_attempted)
            self._close_attempted = True
            if self._channel is not None:
                self._channel.close()  # Unknown recipient custody retains everything below.
            with io.owning():
                if self._accepted is not None:
                    p.require(self._accepted_identity is None or intake._structural(os.fstat(self._accepted.fileno())) == self._accepted_identity)
                    channel, self._accepted = self._accepted, None
                    channel.close()
                if self._socket is not None:
                    p.require(self._socket_identity is None or intake._structural(os.fstat(self._socket.fileno())) == self._socket_identity)
                    channel, self._socket = self._socket, None
                    channel.close()
                if self._bound:
                    p.require(self._leaf is not None and intake._structural(os.stat("core.sock",
                        dir_fd=self._directories[-1], follow_symlinks=False)) == self._leaf)
                    os.unlink("core.sock", dir_fd=self._directories[-1])
                    self._bound = False
                    os.fsync(self._directories[-1])
                while self._directories:
                    os.close(self._directories.pop())
                if self._source is not None:
                    self._source.close()
                self._closed = True
        except BaseException as error:
            raise ListenerError(self) from error
