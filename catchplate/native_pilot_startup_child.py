"""Actual child-created commissioning sockets and protected late admission.

The control connection carries only the fixed startup protocol. Each final
role creates its own operational sockets in this PID; no inherited socketpair
is accepted as evidence of child identity. Transport custody never substitutes
for the existing role's protected policy, key or runtime admission.
"""
from __future__ import annotations

import array
import errno
import os
import select
import socket
import stat
import struct
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifacts
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_pilot_genesis_receiver_observation as kernel
from catchplate import native_pilot_startup_profile as profile
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_nitro_profile as p
from catchplate import native_shadow_proof_cohort_control as mechanics
from catchplate.native_pilot_genesis_authority import _SelfRuntime
from catchplate.native_pilot_lifecycle import _Protected

MAX_FRAME = 64 * 1024
MAX_RIGHTS = 192
_CREDENTIALS = struct.Struct("=iII")
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_TOKEN = object()
_USED, _LIVE = False, None


def _identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _process():
    parent, start = mechanics._process(os.getpid())
    p.require(os.getresuid() == os.getresgid() == (0, 0, 0))
    return dict(pid=os.getpid(), uid=0, gid=0, startTimeTicks=start, parentPid=parent)


def _socket_identity(channel):
    info = os.fstat(channel.fileno())
    p.require(stat.S_ISSOCK(info.st_mode) and not channel.get_inheritable())
    return dict(device=info.st_dev, inode=info.st_ino)


def _role_context(role, source_originals, inventory_original, peers, *, boot, now_boottime_ns, now_unix_ns):
    """Rejoin the original limits that the unchanged role CLI will enforce."""
    p.require(role in profile.ROLES)
    p.fields(source_originals, profile.ROLE_SOURCES[role])
    profile._peers(peers)
    peer = lambda selected: {name: peers[selected][name] for name in profile.policy.PEER_FIELDS}
    if role == "lifecycle":
        from catchplate import native_pilot_genesis_handoff_listener as listener
        value = listener.configuration(source_originals["listener-configuration"], boot=boot,
            now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns, rendezvous=True)
        return dict(deadline=p.ns(value["window"]["lifetimeDeadlineBoottimeNs"]),
            epochLimit=value["expiresAtUnixNanos"])
    if role == "provider":
        value = profile.policy.prepare(source_originals["provider-policy"],
            recipe_original=source_originals["recipe"], supervisor_inventory_original=inventory_original,
            conductor_inventory_original=source_originals["conductor-inventory"],
            authority_inventory_original=source_originals["authority-inventory"], boot=boot,
            now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
        p.require(value["peer"] == peer("lifecycle") and value["currentHeadPeer"] == peer("decisions"))
        return value
    value = profile.decisions.configuration(source_originals["decision-configuration"],
        inventory_sha256=p.sha(inventory_original), boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.require(value["value"]["providerPeer"] == peer("provider"))
    return value


class _ControlError(ValueError):
    def __init__(self, owner):
        super().__init__("startup control refused; actual descriptors retained")
        self.owner = owner


class _Control:
    """Shared actual socket/PIDFD transport; caller supplies original clock checks.

    open takes ownership of the already connected socket immediately, including
    on failure. Every received descriptor stays here until close; send merely
    borrows outgoing descriptors. Parent process ownership is separate.
    """
    @classmethod
    def open(cls, channel, *, peer, boot, check):
        p.require(cls is _Control and type(channel) is socket.socket and callable(check))
        owner = cls()
        owner._socket, owner._pidfd = channel, None
        owner._socket_id = owner._pidfd_id = None
        owner._incoming = []
        owner._self, owner._boot, owner._callback = None, boot, check
        owner._peer = None
        owner._failed = owner._closing = owner._closed = False
        try:
            owner._self = _process()
            owner._peer = dict(profile.process(peer))
            p.require(owner._peer["uid"] == owner._peer["gid"] == 0
                and owner._peer["pid"] != owner._self["pid"] and originals._boot() == boot)
            channel.set_inheritable(False)
            channel.setblocking(False)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            owner._socket_id = _identity(channel.fileno())
            with io.owning():
                owner._pidfd = kernel.acquire_pidfd(channel)
                os.set_inheritable(owner._pidfd, False)
            owner._pidfd_id = _identity(owner._pidfd)
            owner.check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise _ControlError(owner) from error

    @property
    def peer(self):
        return dict(self._peer)

    def _origin(self):
        current = _process()
        p.require(not self._closed and self._self is not None
            and all(current[name] == self._self[name] for name in ("pid", "uid", "gid", "startTimeTicks"))
            and originals._boot() == self._boot
            and threading.current_thread() is threading.main_thread())

    def _identities(self):
        if self._socket is not None:
            p.require(self._socket_id is None or _identity(self._socket.fileno()) == self._socket_id)
        if self._pidfd is not None:
            p.require(self._pidfd_id is None or _identity(self._pidfd) == self._pidfd_id)
        for fd, identity in self._incoming:
            p.require(fd is not None and (identity is None or _identity(fd) == identity)
                and not os.get_inheritable(fd))

    def check(self):
        try:
            self._origin(); p.require(not self._failed and not self._closing)
            self._callback()
            self._identities()
            observed = kernel.peer_identity(self._socket, self._pidfd, boot=self._boot)
            p.require(observed == {key: self._peer[key] for key in observed}
                and mechanics._process(observed["pid"]) == (self._peer["parentPid"], self._peer["startTimeTicks"])
                and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1)
            self._callback()
        except BaseException as error:
            self._failed = True
            raise _ControlError(self) from error


    def _wait(self, *, writing=False):
        self.check()
        select.select([self._pidfd] + ([] if writing else [self._socket]),
            [self._socket] if writing else [], [], 0.01)
        self.check()

    def send(self, raw, fds=()):
        try:
            p.require(type(raw) is bytes and 0 < len(raw) <= MAX_FRAME
                and type(fds) in (tuple, list) and len(fds) <= MAX_RIGHTS
                and all(type(fd) is int and fd >= 3 for fd in fds))
            rights = [] if not fds else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))]
            while True:
                self.check()
                try:
                    count = self._socket.sendmsg([raw], rights, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
                except (BlockingIOError, InterruptedError):
                    self._wait(writing=True)
                    continue
                p.require(count == len(raw))
                self.check()
                return
        except BaseException as error:
            self._failed = True
            raise _ControlError(self) from error

    def receive(self, expected_rights):
        try:
            p.require(type(expected_rights) is int and 0 <= expected_rights <= MAX_RIGHTS)
            while True:
                self.check()
                with io.owning():
                    try:
                        raw, ancillary, flags, _ = self._socket.recvmsg(MAX_FRAME,
                            socket.CMSG_SPACE(4 * 253) + socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4),
                            socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
                    except (BlockingIOError, InterruptedError):
                        raw = None
                    if raw is not None:
                        rows, received, credentials = [], [], []
                        for level, kind, data in ancillary:
                            if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, 4):
                                numbers = array.array("i")
                                numbers.frombytes(data[:len(data) - len(data) % numbers.itemsize])
                                for fd in numbers:
                                    row = [fd, None]
                                    self._incoming.append(row); rows.append(row); received.append(fd)
                            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                                credentials.append(data)
                        # All delivered FDs are retained before inspecting any
                        # untrusted bytes or ancillary grammar, even on failure.
                        for row in rows:
                            row[1] = _identity(row[0])
                if raw is None:
                    self._wait()
                    continue
                p.require(raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                    and len(received) == expected_rights and len(set(received)) == len(received)
                    and credentials == [_CREDENTIALS.pack(self._peer["pid"], self._peer["uid"], self._peer["gid"])]
                    and all(level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, socket.SCM_CREDENTIALS)
                        and (kind != socket.SCM_RIGHTS or len(data) % 4 == 0)
                        for level, kind, data in ancillary))
                self.check()
                return raw, tuple(received)
        except BaseException as error:
            self._failed = True
            raise _ControlError(self) from error

    def close(self):
        if self._closed: return
        try:
            self._origin(); p.require(not self._closing)
            self._closing = True
            self._identities()
            with io.owning():
                while self._incoming:
                    row = self._incoming[-1]
                    fd, row[0] = row[0], None
                    os.close(fd)
                    self._incoming.pop()
                if self._pidfd is not None:
                    fd, self._pidfd = self._pidfd, None
                    os.close(fd)
                if self._socket is not None:
                    channel, self._socket = self._socket, None
                    channel.close()
                self._closed = True
        except BaseException as error:
            self._failed = True
            raise _ControlError(self) from error


class StartupChildError(ValueError):
    def __init__(self, owner):
        super().__init__("startup child refused; actual owner retained")
        self.owner = owner


class StartupChild:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._sources, self._handles, self._sockets, self._directories = [], [], [], []
        self._listeners, self._edges = {}, {}
        self._runtime = self._configuration = self._inventory = self._prepared = self._control = None
        self._role = self._parent = self._peers = self._hello = self._ready = None
        self._failed = self._closing = self._closed = self._prepare_attempted = self._admit_attempted = False
        self._admitted = False

    def _handle(self, fd):
        row = [fd, None]
        self._handles.append(row)
        row[1] = _identity(fd)
        return row

    def _socket(self):
        with io.owning():
            channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            row = [channel, None]
            self._sockets.append(row)
            row[1] = _identity(channel.fileno())
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        return row

    @classmethod
    def open(cls, *, role, configuration_fd, configuration_sha256,
             supervisor_inventory_fd, supervisor_inventory_sha256, parent_pid, parent_start_time_ticks):
        global _USED, _LIVE
        p.require(cls is StartupChild and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner._origin()
            p.require(role in profile.ROLES and type(parent_pid) is int and parent_pid == os.getppid()
                and parent_pid > 1 and type(parent_start_time_ticks) is int and parent_start_time_ticks > 0
                and type(configuration_fd) is int and type(supervisor_inventory_fd) is int
                and configuration_fd >= 3 and supervisor_inventory_fd >= 3
                and configuration_fd != supervisor_inventory_fd)
            owner._role = role
            ancestor, observed_start = mechanics._process(parent_pid)
            p.require(observed_start == parent_start_time_ticks)
            owner._parent = dict(pid=parent_pid, uid=0, gid=0,
                startTimeTicks=parent_start_time_ticks, parentPid=ancestor)
            owner._configuration = _Protected(owner._sources, configuration_fd,
                profile.MAX_CONFIGURATION, configuration_sha256)
            owner._inventory = _Protected(owner._sources, supervisor_inventory_fd,
                artifacts.MAX_MANIFEST_BYTES, supervisor_inventory_sha256)
            p.require(owner._configuration.identity[:2] != owner._inventory.identity[:2])
            owner._prepared = profile.configuration(owner._configuration.raw,
                inventory_sha256=owner._inventory.digest, boot=owner._boot,
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            owner._runtime = _SelfRuntime()
            owner._runtime.admit(owner._inventory.fd, owner._inventory.digest)
            owner._open_directory()
            owner._source_check()
            for edge in profile.ROLE_LISTENERS[role]:
                row = owner._socket()
                row[0].bind(owner._prepared["addresses"][edge])
                row[0].listen(1)
                owner._listeners[edge] = row
                owner._source_check()
            row = owner._connect(owner._prepared["addresses"]["control"])
            with io.owning():
                try:
                    owner._control = _Control.open(row[0], peer=owner._parent,
                        boot=owner._boot, check=owner._source_check)
                except _ControlError as error:
                    owner._control = error.owner
                    owner._sockets.remove(row)
                    raise
                owner._sockets.remove(row)
            owner._hello = profile.encode("hello", role, owner._configuration.digest,
                process=_process(), control=_socket_identity(owner._control._socket),
                listeners={edge: _socket_identity(item[0]) for edge, item in owner._listeners.items()})
            owner._control.send(owner._hello)
            owner.check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise StartupChildError(owner) from error

    def _origin(self):
        p.require(type(self) is StartupChild and _LIVE is self and not self._closed
            and (os.getpid(), originals._start(), originals._boot()) == (self._pid, self._start, self._boot)
            and os.getresuid() == os.getresgid() == (0, 0, 0)
            and threading.current_thread() is threading.main_thread())

    def _open_directory(self):
        parent = None
        for name in ("/", *profile.DIRECTORY.strip("/").split("/")):
            with io.owning():
                fd = os.open(name, _READ | os.O_DIRECTORY) if parent is None else os.open(name,
                    _READ | os.O_DIRECTORY, dir_fd=parent)
                row = self._handle(fd)
                self._directories.append((row, parent, name))
            info = os.fstat(fd)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
            parent = fd
        leaf = os.fstat(parent)
        p.require(stat.S_IMODE(leaf.st_mode) == 0o700 and dict(device=leaf.st_dev, inode=leaf.st_ino)
            == self._prepared["value"]["directory"])

    def _local_identities(self):
        for fd, identity in self._handles:
            p.require(fd is not None and not os.get_inheritable(fd)
                and (identity is None or _identity(fd) == identity))
        for channel, identity in self._sockets:
            p.require(channel is not None and not channel.get_inheritable()
                and (identity is None or _identity(channel.fileno()) == identity))

    def _source_check(self):
        self._origin()
        p.require(not self._failed and not self._closing and self._prepared is not None)
        for source in self._sources: source.check_identity()
        if self._runtime is not None: self._runtime.check()
        self._local_identities()
        for row, parent, name in self._directories:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            p.require((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) == row[1])
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now < self._prepared["deadline"]
            and self._wall <= wall < self._prepared["epochLimit"])
        self._last, self._wall = now, wall

    def _check_edges(self):
        for edge in self._edges.values():
            observed = kernel.peer_identity(edge["socket"][0], edge["pidfd"][0], boot=self._boot)
            expected = edge["peer"]
            p.require(observed == {name: expected[name] for name in observed}
                and mechanics._process(observed["pid"]) == (expected["parentPid"], expected["startTimeTicks"]))

    def check(self):
        try:
            self._source_check()
            if self._control is not None: self._control.check()
            self._check_edges()
            self._source_check()
        except BaseException as error:
            self._failed = True
            raise StartupChildError(self) from error

    def _connect(self, address):
        self._source_check()
        row = self._socket()
        status = row[0].connect_ex(address)
        p.require(status in (0, errno.EINPROGRESS, errno.EALREADY))
        while status:
            self._source_check()
            if select.select([], [row[0]], [], 0.01)[1]:
                status = row[0].getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                p.require(status in (0, errno.EINPROGRESS, errno.EALREADY))
        self._source_check()
        return row

    def _accept(self, edge):
        channel = self._listeners[edge][0]
        while True:
            self.check()
            with io.owning():
                try:
                    accepted, _ = channel.accept()
                except (BlockingIOError, InterruptedError):
                    accepted = None
                if accepted is not None:
                    row = [accepted, None]
                    self._sockets.append(row)
                    accepted.set_inheritable(False); accepted.setblocking(False)
                    accepted.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                    row[1] = _identity(accepted.fileno())
            if accepted is not None: return row
            select.select([channel], [], [], 0.01)

    def _edge(self, name, row):
        expected = self._peers[profile.PEER_ROLES[self._role][name]]
        with io.owning():
            pidfd = self._handle(kernel.acquire_pidfd(row[0]))
            os.set_inheritable(pidfd[0], False)
        self._edges[name] = dict(socket=row, pidfd=pidfd, peer=expected)
        self._check_edges(); self.check()

    def prepare(self):
        try:
            self.check(); p.require(not self._prepare_attempted)
            self._prepare_attempted = True
            raw, _ = self._control.receive(0)
            message = profile.message(raw, "connect", role=self._role, configuration_sha256=self._configuration.digest)
            self._peers = message["peers"]
            p.require(self._peers[self._role] == _process()
                and all(row["parentPid"] == self._parent["pid"] for row in self._peers.values()))
            if self._role == "lifecycle":
                self._edge("lifecycle", self._connect(self._prepared["addresses"]["lifecycle"]))
            elif self._role == "provider":
                self._edge("lifecycle", self._accept("lifecycle"))
                self._edge("heads", self._connect(self._prepared["addresses"]["heads"]))
            else:
                self._edge("heads", self._accept("heads"))
            self._ready = profile.encode("ready", self._role, self._configuration.digest,
                peersSha256=p.sha(p.canonical(self._peers)), sockets={name: dict(
                    socket=_socket_identity(row["socket"][0]), peer=dict(row["peer"]))
                    for name, row in self._edges.items()})
            self._control.send(self._ready)
            self.check()
            return self._ready
        except BaseException as error:
            self._failed = True
            raise StartupChildError(self) from error

    def admit(self):
        try:
            self.check(); p.require(self._ready is not None and not self._admit_attempted)
            self._admit_attempted = True
            names = profile.ROLE_SOURCES[self._role]
            count = len(names) + (len(profile.KEY_NAMES) if self._role == "lifecycle" else 0)
            raw, descriptors = self._control.receive(count)
            value = profile.message(raw, "admit", role=self._role, configuration_sha256=self._configuration.digest)
            p.require(value["readySha256"] == p.sha(self._ready)
                and self._last < p.ns(value["deadlineBoottimeNs"]) <= self._prepared["deadline"]
                and self._wall < value["expiresAtUnixNanos"] <= self._prepared["epochLimit"])
            held = {}
            identities = {source.identity[:2] for source in self._sources}
            for row, fd in zip(value["sources"], descriptors[:len(names)], strict=True):
                self.check()
                name = row["purpose"]
                source = _Protected(self._sources, fd, profile.SOURCE_LIMITS[name], row["sha256"])
                p.require(source.identity[:2] not in identities)
                identities.add(source.identity[:2]); held[name] = source
                self.check()
            caps = _role_context(self._role, {name: source.raw for name, source in held.items()},
                self._inventory.raw, self._peers, boot=self._boot,
                now_boottime_ns=self._last, now_unix_ns=self._wall)
            p.require(caps["deadline"] <= p.ns(value["deadlineBoottimeNs"])
                and caps["epochLimit"] <= value["expiresAtUnixNanos"])
            self._prepared["deadline"] = p.ns(value["deadlineBoottimeNs"])
            self._prepared["epochLimit"] = value["expiresAtUnixNanos"]
            # Keys remain opaque retained SCM_RIGHTS. Do not read seeds or
            # admit purpose/key authority here; the fixed lifecycle does that.
            keys = {"cold": {}, "adopted": {}} if self._role == "lifecycle" else None
            for row in value["keys"]:
                fd = descriptors[row["index"]]
                p.require(_identity(fd)[:2] not in identities)
                keys[row["family"]][row["purpose"]] = fd
            arguments = profile.role_arguments(self._role,
                supervisor_inventory_fd=self._inventory.fd, supervisor_inventory_sha256=self._inventory.digest,
                source_fds={name: source.fd for name, source in held.items()},
                source_pins={name: source.digest for name, source in held.items()},
                socket_fds={name: row["socket"][0].fileno() for name, row in self._edges.items()},
                peers=self._peers, key_fds=keys)
            for source in self._sources: source.check()
            self.check()
            self._admitted = True
            return arguments
        except BaseException as error:
            self._failed = True
            raise StartupChildError(self) from error

    def close(self):
        if self._closed: return
        try:
            self._origin(); p.require(not self._closing)
            self._closing = True
            self._local_identities()
            with io.owning():
                if self._control is not None: self._control.close()
                while self._sockets:
                    row = self._sockets[-1]
                    channel, row[0] = row[0], None
                    channel.close(); self._sockets.pop()
                while self._handles:
                    row = self._handles[-1]
                    fd, row[0] = row[0], None
                    os.close(fd); self._handles.pop()
                for source in reversed(self._sources): source.close()
                if self._runtime is not None: self._runtime.close()
                self._closed = True
        except BaseException as error:
            self._failed = True
            raise StartupChildError(self) from error
