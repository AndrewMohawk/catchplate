"""Fixed independent generation issuer: protected config3, sealed seed4, TCP5.

The purpose-owned role reuses only the verifier's file/process guards.
No request controls the file name, signing key, socket tuple, boot or lifetime.
"""
from __future__ import annotations

import fcntl
import ipaddress
import os
import select
import socket
import stat
import time

from catchplate import native_shadow_nitro_profile as p
from catchplate import native_generation_origin_profile as t
from catchplate.native_shadow_nitro_originals import _File, _boot, _clock, _hardening, _identity, _security, _start

_TOKEN = object()


class Originals:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._closed, self._key_taken, self.phase = [], False, False, 0
        self.socket = None

    @classmethod
    def open(cls):
        p.require(cls is Originals)
        owner = cls(_TOKEN)
        try:
            for fd in (3, 4, 5):
                os.fstat(fd)
                owner._fds.append(fd)
            owner.libc = _hardening()
            _security(owner.libc)
            owner.pid, owner.start = os.getpid(), _start()
            owner.uid, owner.gid = os.getuid(), os.getgid()
            p.require(owner.uid not in {64988, 64989, 64990, 65534} and owner.gid not in {64988, 64989, 64990, 65534})
            owner.pidfd = os.pidfd_open(owner.pid, 0)
            owner._fds.append(owner.pidfd)
            os.set_inheritable(owner.pidfd, False)
            owner.pidfd_identity = _identity(os.fstat(owner.pidfd))
            owner.pidfd_flags = fcntl.fcntl(owner.pidfd, fcntl.F_GETFL)
            owner.boot = _boot()
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            owner._fds.append(parent)
            owner.directories = []
            for component in ("etc", "catchplate"):
                before = os.fstat(parent)
                p.require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0 and before.st_mode & 0o022 == 0)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                owner._fds.append(child)
                owner.directories.append((parent, component, child, _identity(os.fstat(child))))
                parent = child
            directory = os.fstat(parent)
            p.require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and directory.st_mode & 0o022 == 0)
            owner.directory = parent
            owner.config_original = _File(3, p.MAX_CONFIG, uid=0, gid=0, sealed=False)
            owner.seed_original = _File(4, 32, uid=owner.uid, gid=owner.gid, sealed=True)
            p.require(owner.seed_original.identity[6] == 32
                and owner.seed_original.identity[:2] != owner.config_original.identity[:2])
            owner.config_raw = owner.config_original.read()
            owner.configuration = p.document(owner.config_raw, p.MAX_CONFIG)
            p.fields(owner.configuration, t.CONFIG_FIELDS)
            p.require(p.integer(owner.configuration["uid"], maximum=(1 << 32) - 2) == owner.uid
                and p.integer(owner.configuration["gid"], maximum=(1 << 32) - 2) == owner.gid)
            operation = p.fields(owner.configuration["operation"], ("bootIdBase64url", "timeNamespaceDevice",
                "timeNamespaceInode", "issuedAtBoottimeNs", "deadlineBoottimeNs"))
            p.integer(operation["timeNamespaceDevice"]); p.integer(operation["timeNamespaceInode"])
            p.require(owner.boot == (operation["bootIdBase64url"], operation["timeNamespaceDevice"], operation["timeNamespaceInode"]))
            owner.issued, owner.deadline = p.ns(operation["issuedAtBoottimeNs"]), p.ns(operation["deadlineBoottimeNs"])
            p.require(0 < owner.deadline - owner.issued <= 30_000_000_000)
            observed = os.fstat(5)
            p.require(stat.S_ISSOCK(observed.st_mode) and observed.st_uid == 0 and observed.st_gid == 0)
            owner.socket = socket.socket(fileno=5)
            owner._fds.remove(5)
            p.require(owner.socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
                and owner.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
                and owner.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL) == socket.IPPROTO_TCP
                and owner.socket.family in (socket.AF_INET, socket.AF_INET6))
            flags = fcntl.fcntl(5, fcntl.F_GETFL)
            p.require(flags & os.O_ACCMODE == os.O_RDWR and not flags & (os.O_ASYNC | os.O_PATH | os.O_APPEND))
            owner.socket.setblocking(False)
            os.set_inheritable(5, False)
            owner.socket_identity = _identity(os.fstat(5))
            owner.socket_cookie = owner.socket.getsockopt(socket.SOL_SOCKET, 57, 8)
            p.require(owner.socket_cookie != bytes(8))
            owner.socket_flags = fcntl.fcntl(5, fcntl.F_GETFL)
            owner.local, owner.peer = owner.socket.getsockname(), owner.socket.getpeername()
            transport = p.fields(owner.configuration["transport"], ("localIp", "localPort", "peerIp"))
            for name in ("localIp", "peerIp"):
                address = ipaddress.ip_address(transport[name])
                p.require(str(address) == transport[name] and not address.is_unspecified and not address.is_multicast)
            p.integer(transport["localPort"], minimum=1024, maximum=65535)
            p.require(owner.local[:2] == (transport["localIp"], transport["localPort"])
                and owner.peer[0] == transport["peerIp"] and owner.peer[1] > 0)
            owner.wall = 0
            owner.check()
            return owner
        except BaseException:
            owner.close()
            raise

    def check(self):
        p.require(not self._closed and os.getpid() == self.pid and _start() == self.start
            and os.getresuid() == (self.uid,) * 3 and os.getresgid() == (self.gid,) * 3 and os.getgroups() == []
            and _boot() == self.boot and self.issued <= _clock() < self.deadline)
        _security(self.libc)
        p.require(_identity(os.fstat(self.pidfd)) == self.pidfd_identity
            and fcntl.fcntl(self.pidfd, fcntl.F_GETFL) == self.pidfd_flags and not os.get_inheritable(self.pidfd))
        poll = select.poll(); poll.register(self.pidfd, select.POLLIN)
        p.require(poll.poll(0) == [])
        with open("/proc/self/fdinfo/" + str(self.pidfd), "rt", encoding="ascii") as stream:
            lines = stream.read(4097)
        p.require(len(lines) <= 4096 and [line for line in lines.splitlines() if line.startswith("Pid:")]
            == ["Pid:\t" + str(self.pid)])
        for parent, name, child, identity in self.directories:
            p.require(_identity(os.fstat(child)) == identity
                and _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
        p.require(_identity(os.stat(t.CONFIG_NAME, dir_fd=self.directory, follow_symlinks=False)) == self.config_original.identity
            and self.config_original.read() == self.config_raw and p.canonical(self.configuration) == self.config_raw)
        self.seed_original.check()
        fd = self.socket.fileno()
        p.require(_identity(os.fstat(fd)) == self.socket_identity and not os.get_inheritable(fd)
            and fcntl.fcntl(fd, fcntl.F_GETFL) == self.socket_flags
            and self.socket.getsockopt(socket.SOL_SOCKET, 57, 8) == self.socket_cookie
            and self.socket.getsockname() == self.local and self.socket.getpeername() == self.peer)
        wall = time.time_ns()
        p.integer(wall); p.require(wall >= self.wall)
        self.wall = wall
        return wall

    def remaining(self):
        self.check()
        value = self.deadline - _clock()
        p.require(value > 0)
        return value

    def take_seed(self):
        self.check(); p.require(not self._key_taken and self.phase == 0)
        self._key_taken = True
        seed = bytearray(self.seed_original.read())
        try:
            self.check()
            return seed
        except BaseException:
            seed[:] = b"\0" * len(seed)
            raise

    def _wait(self, event):
        self.check()
        poll = select.poll(); poll.register(self.socket.fileno(), event)
        for _, observed in poll.poll(25):
            p.require(not observed & (select.POLLERR | select.POLLNVAL))
        self.check()

    def _read(self, length):
        result = bytearray()
        while len(result) < length:
            self.check()
            try:
                data = self.socket.recv(length - len(result))
                p.require(bool(data)); result.extend(data)
            except (BlockingIOError, InterruptedError):
                self._wait(select.POLLIN)
        self.check()
        return bytes(result)

    def send(self, tag, raw):
        self.check()
        wire = p.document(raw, t.MAX_FRAME)
        p.require((self.phase, tag) in ((0, t.CHALLENGE_TAG), (2, t.ANCHOR_TAG))
            and 1 <= len(raw) <= t.MAX_FRAME and p.canonical(wire) == raw)
        expires = p.integer(wire["payload"]["expiresAtUnixNanos"])
        self.phase += 1  # Lost/partial output never permits a second handoff.
        frame, offset = tag + len(raw).to_bytes(4, "big") + raw, 0
        while offset < len(frame):
            now = self.check()
            t.authorization(self.configuration, now)
            p.require(now < expires)
            try:
                sent = self.socket.send(frame[offset:], socket.MSG_NOSIGNAL)
                p.require(sent > 0); offset += sent
            except (BlockingIOError, InterruptedError):
                self._wait(select.POLLOUT)
        now = self.check()
        t.authorization(self.configuration, now)
        p.require(now < expires)

    def receive(self):
        self.check(); p.require(self.phase == 1)
        self.phase = 2
        header = self._read(12)
        p.require(header[:8] == t.EVIDENCE_TAG)
        length = int.from_bytes(header[8:], "big")
        p.require(1 <= length <= t.MAX_FRAME)
        result = self._read(length)
        p.document(result, t.MAX_FRAME)
        self.quiet()
        return result

    def quiet(self):
        self.check()
        try:
            self.socket.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        except BlockingIOError:
            return
        # Only queued-data absence, not future silence or EOF proof.
        raise ValueError("generation-origin exchange has extra data or premature EOF")

    def close(self):
        if not self._closed:
            self._closed = True
            if self.socket is not None:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.socket.close()
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
