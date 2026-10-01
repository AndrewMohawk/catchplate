"""One-shot custody transport for an actual cold fs-verity core.

This channel does not approve a Bundle or native adoption. A real completed
cold owner supplies the core; the recipient retains that same inode for later
independently signed C9/adoption admission. Both processes and every packet
are authenticated. No connect, fallback PID lookup, retry, or renewed window.
"""
from __future__ import annotations

import array
import fcntl
import os
import select
import socket
import stat
import struct
import threading
import time

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_core_profile as profile
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_retrieval_store as verity

p = g.p
REQUEST_API = "serverware.nativePilotGenesisCoreTransfer/v1"
ACK_API = "serverware.nativePilotGenesisCoreTransferAck/v1"
MAGIC = b"serverware.nativePilotGenesisCoreOriginals/v1\0"
MAX_OBSERVATION = profile.MAX_OBSERVATION
MAX_BUNDLE = profile.MAX_BUNDLE
MAX_ORIGINALS = len(MAGIC) + 16 + MAX_OBSERVATION + MAX_BUNDLE
MAX_PACKET = 8192
SO_PEERPIDFD, SO_PASSPIDFD, SCM_PIDFD = 77, 76, 4
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
CREDENTIALS = struct.Struct("=iII")
REQUEST_FIELDS = ("apiVersion", "sequence", "observation", "bundle", "originals",
    "deadlineBoottimeNs", "expiresAtUnixNanos")
ACK_FIELDS = ("apiVersion", "sequence", "requestSha256", "observationSha256", "bundleSha256")
_TOKEN, _CLAIMED = object(), set()


class GenesisCoreChannelError(ValueError):
    def __init__(self, owner):
        super().__init__("cold core channel refused; actual descriptors retained; no retry")
        self.owner = owner


def _identity(fd):
    value = os.fstat(fd)
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def _require_peer_credentials(channel, peer):
    p.require(CREDENTIALS.unpack(channel.getsockopt(socket.SOL_SOCKET,
        socket.SO_PEERCRED, CREDENTIALS.size)) == peer)


def file_metadata(fd):
    value = os.fstat(fd)
    return dict(device=value.st_dev, inode=value.st_ino, mode=value.st_mode,
        uid=value.st_uid, gid=value.st_gid, nlink=value.st_nlink, length=value.st_size,
        mtimeNanos=value.st_mtime_ns, ctimeNanos=value.st_ctime_ns)


def _canonical(raw, maximum):
    value = g.document(raw, maximum)
    p.require(g.canonical(value) == raw)
    return value


def pack_originals(observation_raw, bundle_raw):
    """Exact public bytes, no JSON-string expansion or rebuilt Bundle."""
    p.require(type(observation_raw) is bytes and 0 < len(observation_raw) <= MAX_OBSERVATION
        and type(bundle_raw) is bytes and 0 < len(bundle_raw) <= MAX_BUNDLE)
    profile.observation(observation_raw, bundle_raw)
    return MAGIC + struct.pack(">QQ", len(observation_raw), len(bundle_raw)) + observation_raw + bundle_raw


def unpack_originals(raw):
    p.require(type(raw) is bytes and len(MAGIC) + 16 < len(raw) <= MAX_ORIGINALS
        and raw.startswith(MAGIC))
    first, second = struct.unpack(">QQ", raw[len(MAGIC):len(MAGIC) + 16])
    p.require(0 < first <= MAX_OBSERVATION and 0 < second <= MAX_BUNDLE
        and len(raw) == len(MAGIC) + 16 + first + second)
    start = len(MAGIC) + 16
    observation_raw, bundle_raw = raw[start:start + first], raw[start + first:]
    profile.observation(observation_raw, bundle_raw)
    return observation_raw, bundle_raw


def _pin(raw):
    return {"length": len(raw), "sha256": p.sha(raw)}


def request_original(observation_raw, bundle_raw, public_raw, *, deadline, expiry):
    observed = profile.observation(observation_raw, bundle_raw)
    p.require(public_raw == pack_originals(observation_raw, bundle_raw))
    p.require(type(deadline) is int and 0 < deadline <= p.ns(observed["deadlineBoottimeNs"])
        and type(expiry) is int and 0 < expiry <= observed["expiresAtUnixNanos"])
    return g.canonical(dict(apiVersion=REQUEST_API, sequence=1,
        observation=_pin(observation_raw), bundle=_pin(bundle_raw), originals=_pin(public_raw),
        deadlineBoottimeNs=str(deadline), expiresAtUnixNanos=expiry))


def request(raw):
    value = p.fields(_canonical(raw, MAX_PACKET), REQUEST_FIELDS)
    p.require(value["apiVersion"] == REQUEST_API and type(value["sequence"]) is int and value["sequence"] == 1)
    for name, maximum in (("observation", MAX_OBSERVATION), ("bundle", MAX_BUNDLE), ("originals", MAX_ORIGINALS)):
        pin = p.fields(value[name], ("length", "sha256"))
        p.integer(pin["length"], maximum=maximum); p.digest(pin["sha256"])
    p.ns(value["deadlineBoottimeNs"]); p.integer(value["expiresAtUnixNanos"], maximum=p.MAX_I64)
    return value


def acknowledgment(request_raw):
    value = request(request_raw)
    return g.canonical(dict(apiVersion=ACK_API, sequence=1, requestSha256=p.sha(request_raw),
        observationSha256=value["observation"]["sha256"], bundleSha256=value["bundle"]["sha256"]))


def require_ack(raw, request_raw):
    p.fields(_canonical(raw, MAX_PACKET), ACK_FIELDS)
    p.require(raw == acknowledgment(request_raw))


def _read_public(fd, expected):
    """Only the exact fully sealed root public-originals container."""
    before = file_metadata(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    p.require(before["mode"] == stat.S_IFREG | 0o400 and before["uid"] == before["gid"] == 0
        and before["nlink"] == 0 and before["length"] == expected["length"] <= MAX_ORIGINALS
        and flags & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY
        and not os.get_inheritable(fd) and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == SEALS)
    chunks, offset = [], 0
    while offset < before["length"]:
        part = os.pread(fd, min(65536, before["length"] - offset), offset)
        p.require(bool(part)); chunks.append(part); offset += len(part)
    raw = b"".join(chunks)
    p.require(file_metadata(fd) == before and not os.pread(fd, 1, len(raw)) and p.sha(raw) == expected["sha256"])
    return raw


def _core(fd, observed, bundle_raw):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    p.require(flags & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY and not os.get_inheritable(fd))
    profile.verify_file_metadata(file_metadata(fd), observed["file"])
    core = g.canonical(_canonical(bundle_raw, MAX_BUNDLE)["completion"]["prepared"]["core"])
    p.require(len(core) == observed["file"]["length"] and p.sha(core) == observed["objectSha256"]
        and verity._measure(fd) == observed["fsveritySha256"])
    p.require(os.pread(fd, len(core) + 1, 0) == core)
    profile.verify_file_metadata(file_metadata(fd), observed["file"])
    p.require(verity._measure(fd) == observed["fsveritySha256"])


class _Connection:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._socket = self._peer_fd = self._peer_identity = self._socket_identity = None
        self._fds, self._received = [], None
        self._failed = self._closed = self._attempted = self._rights_may_have_sent = self._acked = False
        self._close_attempted = False
        self._deadline = self._expiry = self._peer = None
        self._issued = self._epoch_floor = 0

    @classmethod
    def open(cls, fd, peer_pid, peer_uid, peer_gid, deadline_boottime_ns, expires_at_unix_ns):
        p.require(cls in (GenesisCoreChannel, GenesisCoreReceiver))
        owner = cls(_TOKEN)
        try:
            owner._origin()
            p.integer(peer_pid, minimum=2, maximum=(1 << 31) - 1)
            p.require(type(peer_uid) is int and type(peer_gid) is int and peer_uid == peer_gid == 0
                and peer_pid != owner._pid and type(fd) is int and fd >= 3)
            p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
            p.integer(expires_at_unix_ns, maximum=p.MAX_I64)
            owner._deadline, owner._expiry = deadline_boottime_ns, expires_at_unix_ns
            owner._peer = peer_pid, peer_uid, peer_gid
            identity = _identity(fd)
            p.require(stat.S_ISSOCK(identity[2]) and (owner._pid, identity) not in _CLAIMED)
            _CLAIMED.add((owner._pid, identity))
            with io.owning():
                os.set_inheritable(fd, False)
                held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128)
                owner._fds.append(held)
                channel = socket.socket(fileno=held)
                owner._socket = channel; owner._fds.remove(held)
                p.require(channel.family == socket.AF_UNIX
                    and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                    and channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0)
                channel.getpeername()
                _require_peer_credentials(channel, owner._peer)
                # The kernel's creator peer must itself be the approved peer.
                # Inherited socketpair creator credentials cannot name a child.
                peer_fd = struct.unpack("=i", channel.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4))[0]
                owner._peer_fd = peer_fd
                p.require(peer_fd >= 3)
                os.set_inheritable(peer_fd, False)
                p.require(io.pidfd_pid(peer_fd) == peer_pid)
                channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                channel.setsockopt(socket.SOL_SOCKET, SO_PASSPIDFD, 0)
                channel.setblocking(False)
                owner._socket_identity, owner._peer_identity = _identity(channel.fileno()), _identity(peer_fd)
            owner.check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise GenesisCoreChannelError(owner) from error

    def _origin(self):
        p.require(not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and threading.current_thread() is threading.main_thread()
            and len(os.listdir("/proc/self/task")) == 1
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _clock(self):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._issued <= now and self._last <= now < self._deadline
            and self._epoch_floor <= wall and self._wall <= wall < self._expiry)
        self._last, self._wall = now, wall
        return now

    def _source(self):
        self._origin()
        channel = self._socket
        p.require(channel is not None and _identity(channel.fileno()) == self._socket_identity
            and not os.get_inheritable(channel.fileno())
            and _identity(self._peer_fd) == self._peer_identity and not os.get_inheritable(self._peer_fd)
            and channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
            and channel.getsockopt(socket.SOL_SOCKET, SO_PASSPIDFD) == 0
            and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
            and fcntl.fcntl(channel, fcntl.F_GETFL) & os.O_NONBLOCK)
        _require_peer_credentials(channel, self._peer)

    def peer_terminal(self):
        self._source()
        terminal = bool(select.select([self._peer_fd], [], [], 0)[0])
        p.require(io.pidfd_pid(self._peer_fd) in ((self._peer[0], -1) if terminal else (self._peer[0],)))
        return terminal

    @property
    def custody_known(self):
        self._origin()
        return not self._rights_may_have_sent or self._acked or self.peer_terminal()

    def _check(self, *, terminal=False):
        try:
            p.require(not self._failed)
            self._source(); self._clock()
            if not self._acked and not terminal:
                p.require(not self.peer_terminal())
            self._clock()
        except BaseException as error:
            self._failed = True
            raise GenesisCoreChannelError(self) from error

    def check(self):
        self._check()

    def _guard(self, check, *, terminal=False):
        self._check(terminal=terminal); check(); self._check(terminal=terminal)

    def _wait(self, reading, check, *, terminal=False):
        while True:
            self._guard(check, terminal=terminal)
            now = self._clock()
            ready, writable, _ = select.select([self._socket, self._peer_fd] if reading else [self._peer_fd],
                [] if reading else [self._socket], [], min(0.01, (self._deadline - now) / 1_000_000_000))
            self._guard(check, terminal=terminal)
            if (reading and self._socket in ready) or (not reading and writable):
                return
            # A dead peer with no readable packet cannot supply an ACK.
            p.require(not self.peer_terminal())

    def _send(self, raw, rights, check):
        p.require(type(raw) is bytes and 0 < len(raw) <= MAX_PACKET)
        self._wait(False, check)
        with io.owning():
            # Consume before entering sendmsg: even an exception cannot
            # authorize another send or release a possibly received core.
            if rights:
                self._rights_may_have_sent = True
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights))] if rights else []
            count = self._socket.sendmsg([raw], ancillary, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            p.require(count == len(raw))
            if not rights:
                # This connection only sends a rights-free packet for its
                # exact ACK, after retaining the real receiving owner.
                self._acked = True
        self._guard(check, terminal=bool(rights))

    def _receive(self, count, check, *, terminal=False):
        self._wait(True, check, terminal=terminal)
        with io.owning():
            raw, ancillary, flags, _ = self._socket.recvmsg(MAX_PACKET,
                socket.CMSG_SPACE(16 * array.array("i").itemsize) + socket.CMSG_SPACE(CREDENTIALS.size),
                socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
            rights, credentials, valid = [], None, True
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, SCM_PIDFD):
                    values = array.array("i")
                    valid &= len(data) % values.itemsize == 0 and kind == socket.SCM_RIGHTS
                    values.frombytes(data[:len(data) - len(data) % values.itemsize])
                    for fd in values:
                        if fd < 0:
                            valid = False
                        else:
                            self._fds.append(fd); rights.append(fd)
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                    valid &= credentials is None and len(data) == CREDENTIALS.size
                    if len(data) == CREDENTIALS.size:
                        credentials = CREDENTIALS.unpack(data)
                else:
                    valid = False
            p.require(valid and raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                and credentials == self._peer and len(rights) == count
                and all(not os.get_inheritable(fd) for fd in rights))
        self._guard(check, terminal=terminal)
        return raw, rights

    def close(self):
        if self._closed:
            return {"status": "closed", "acknowledged": self._acked}
        try:
            self._origin()
            p.require(not self._close_attempted)
            self._close_attempted = True
            p.require(self.custody_known)
            with io.owning():
                if self._received is not None:
                    self._received.close()
                while self._fds:
                    os.close(self._fds.pop())
                if self._peer_fd is not None:
                    fd, self._peer_fd = self._peer_fd, None; os.close(fd)
                if self._socket is not None:
                    channel, self._socket = self._socket, None; channel.close()
                self._closed = True
            return {"status": "closed", "acknowledged": self._acked}
        except BaseException as error:
            self._failed = True
            raise GenesisCoreChannelError(self) from error


class GenesisCoreChannel(_Connection):
    """Sender retained through actual ACK or observed peer process death."""
    def constrain(self, *, deadline_boottime_ns, expires_at_unix_ns):
        """Intersect retained graph bounds before the sole transfer attempt."""
        try:
            self.check()
            p.require(not self._attempted)
            p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
            p.integer(expires_at_unix_ns, maximum=p.MAX_I64)
            self._deadline = min(self._deadline, deadline_boottime_ns)
            self._expiry = min(self._expiry, expires_at_unix_ns)
            self.check()
        except BaseException as error:
            self._failed = True
            raise GenesisCoreChannelError(self) from error

    def _send_core(self, fd, observation_raw, bundle_raw, check):
        try:
            p.require(not self._attempted and callable(check))
            self._attempted = True
            self._guard(check)
            observed = profile.observation(observation_raw, bundle_raw)
            self._issued, self._epoch_floor = p.ns(observed["issuedAtBoottimeNs"]), observed["issuedAtUnixNanos"]
            self._deadline = min(self._deadline, p.ns(observed["deadlineBoottimeNs"]))
            self._expiry = min(self._expiry, observed["expiresAtUnixNanos"])
            self._guard(check)
            with io.owning():
                core_fd = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128)
                self._fds.append(core_fd)
            _core(core_fd, observed, bundle_raw)
            public = pack_originals(observation_raw, bundle_raw)
            with io.owning():
                writing = os.memfd_create("serverware-genesis-core-public", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                self._fds.append(writing)
            offset = 0
            while offset < len(public):
                self._guard(check)
                written = os.pwrite(writing, public[offset:offset + 65536], offset)
                p.require(written > 0); offset += written
            os.fchmod(writing, 0o400)
            fcntl.fcntl(writing, fcntl.F_ADD_SEALS, SEALS)
            with io.owning():
                # Reopen only our own held sealed memfd for a readonly OFD.
                public_fd = os.open("/proc/self/fd/" + str(writing), os.O_RDONLY | os.O_CLOEXEC)
                self._fds.append(public_fd)
                p.require(_identity(public_fd) == _identity(writing))
                self._fds.remove(writing); os.close(writing)
            p.require(_read_public(public_fd, _pin(public)) == public)
            raw = request_original(observation_raw, bundle_raw, public, deadline=self._deadline, expiry=self._expiry)
            _core(core_fd, observed, bundle_raw)
            self._send(raw, (core_fd, public_fd), check)
            ack, _ = self._receive(0, check, terminal=True)
            require_ack(ack, raw)
            # Retain definite custody before a final clock/source refusal.
            # The authenticated peer may exit immediately after this ACK.
            self._acked = True
            self._guard(check)
        except BaseException as error:
            self._failed = True
            raise GenesisCoreChannelError(self) from error


class ReceivedGenesisCore:
    """Only a real recvmsg constructs this custody owner; never an approval."""
    def __init__(self, token, channel, fd, public_fd, observation_raw, bundle_raw):
        p.require(token is _TOKEN)
        self._channel, self._fd, self._public_fd = channel, fd, public_fd
        self._observation, self._bundle = observation_raw, bundle_raw
        self._core_identity, self._public_identity = file_metadata(fd), file_metadata(public_fd)
        self._closed = self._close_attempted = False

    def check(self):
        try:
            p.require(not self._closed)
            self._channel.check()
            observed = profile.observation(self._observation, self._bundle)
            _core(self._fd, observed, self._bundle)
            public = pack_originals(self._observation, self._bundle)
            p.require(_read_public(self._public_fd, _pin(public)) == public)
            self._channel.check()
        except BaseException as error:
            self._channel._failed = True
            raise GenesisCoreChannelError(self._channel) from error

    def borrowed_core_fd(self):
        self.check()
        p.require(self._channel._acked)
        return self._fd

    def originals(self):
        self.check()
        return bytes(self._observation), bytes(self._bundle)

    def close(self):
        if self._closed:
            return
        self._channel._origin()
        p.require(not self._close_attempted)
        self._close_attempted = True
        with io.owning():
            for name, expected in (("_fd", self._core_identity), ("_public_fd", self._public_identity)):
                fd = getattr(self, name)
                if fd is not None:
                    p.require(file_metadata(fd) == expected)
            for name in ("_fd", "_public_fd"):
                fd = getattr(self, name)
                if fd is not None:
                    setattr(self, name, None); os.close(fd)
            self._closed = True


class GenesisCoreReceiver(_Connection):
    """Actual descriptor intake; ACK is custody, not native adoption authority."""
    def receive(self, check=lambda: None):
        try:
            p.require(not self._attempted and callable(check))
            self._attempted = True
            self._guard(check)
            raw, descriptors = self._receive(2, check)
            selected = request(raw)
            self._deadline = min(self._deadline, p.ns(selected["deadlineBoottimeNs"]))
            self._expiry = min(self._expiry, selected["expiresAtUnixNanos"])
            self._guard(check)
            core_fd, public_fd = descriptors
            p.require(_identity(core_fd)[:2] != _identity(public_fd)[:2])
            public = _read_public(public_fd, selected["originals"])
            observation_raw, bundle_raw = unpack_originals(public)
            observed = profile.observation(observation_raw, bundle_raw)
            # Numeric BOOTTIME bounds only have meaning in this actual boot
            # and time namespace. Structural custody metadata cannot select
            # another clock namespace for the independently operated receiver.
            scope = _canonical(bundle_raw, MAX_BUNDLE)["completion"]["prepared"]["core"]["genesis"]["scope"]
            p.require(scope["bootIdBase64url"] == self._boot[0]
                and type(scope["timeNamespaceDevice"]) is int and scope["timeNamespaceDevice"] == self._boot[1]
                and type(scope["timeNamespaceInode"]) is int and scope["timeNamespaceInode"] == self._boot[2])
            self._issued, self._epoch_floor = p.ns(observed["issuedAtBoottimeNs"]), observed["issuedAtUnixNanos"]
            p.require(selected["observation"] == _pin(observation_raw) and selected["bundle"] == _pin(bundle_raw)
                and p.ns(selected["deadlineBoottimeNs"]) <= p.ns(observed["deadlineBoottimeNs"])
                and selected["expiresAtUnixNanos"] <= observed["expiresAtUnixNanos"])
            self._guard(check)
            _core(core_fd, observed, bundle_raw)
            with io.owning():
                owner = ReceivedGenesisCore(_TOKEN, self, core_fd, public_fd, observation_raw, bundle_raw)
                self._received = owner
                self._fds.remove(core_fd); self._fds.remove(public_fd)
            owner.check()
            self._send(acknowledgment(raw), (), check)
            self._guard(check)
            self._acked = True
            return owner
        except BaseException as error:
            self._failed = True
            raise GenesisCoreChannelError(self) from error
