"""One fixed machine phase exchange over the conductor's actual stdio pipes.

Only public request data and externally supplied originals cross this channel.
Successful framing is not authority: the existing retained owners still admit
each supplied original. There is no signer, network broker, subprocess, retry,
heartbeat or replacement clock. The caller owns actual workload cleanup.
"""
from __future__ import annotations

import array
import fcntl
import os
import select
import stat
import termios
import threading
import time

from serverware import native_shadow_nitro_profile as p

STAGES = (
    "bootstrap-admission", "endpoint-precreation", "endpoint-inputs", "endpoint-deliveries", "service-originals",
    "bridge-runtime", "bridge-delivery", "release", "constructed-admission", "generation-origin", "shutdown",
)
MAX_FRAME = 32 * 1024 * 1024  # Complete canonical original plus its single LF.
MAX_TOTAL = 128 * 1024 * 1024  # Actual bytes sent and received across all phases.
_TOKEN = object()
_OPENED = False
_CODES = frozenset(("channel-open", "channel-owner", "channel-closed", "channel-poisoned",
    "channel-phase", "channel-deadline", "channel-budget", "channel-io", "channel-eof",
    "channel-future-frame", "request-invalid", "reply-invalid", "channel-interrupted", "channel-close"))


def wire_versions(*, adopted=False):
    """Explicit protocol separation; not permission to acquire any resource."""
    p.require(type(adopted) is bool)
    suffix = "2" if adopted else "1"
    return "serverware.nativePilotOperatorRequest/v" + suffix, "serverware.nativePilotOperatorReply/v" + suffix


class OperatorChannelError(ValueError):
    """A fixed local code, never a supplied original or an exception dump."""

    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else "channel-io"
        super().__init__(self.code)


def _require(value, code):
    if not value:
        raise OperatorChannelError(code)


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _identity(fd):
    info = os.fstat(fd)
    _require(stat.S_ISFIFO(info.st_mode) and info.st_uid == info.st_gid == 0, "channel-owner")
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink


class Channel:
    def __init__(self, token):
        _require(token is _TOKEN, "channel-open")
        self._fds, self._identities = [], []
        self._pid = os.getpid()
        self._sequence = self._total = 0
        self._closed = self._poisoned = self._active = False
        self._adopted = False
        self._last_clock = _clock()
        self._expiry = None
        self._last_wall = time.time_ns()

    @classmethod
    def open(cls):
        return cls._open(adopted=False)

    @classmethod
    def open_adopted(cls):
        return cls._open(adopted=True)

    @classmethod
    def _open(cls, *, adopted):
        """Claim exclusive pipe ownership once in this real root process.

        Duplication shares the operator's open-file descriptions: NONBLOCK is
        intentionally visible on original stdio. Both originals and duplicates
        become CLOEXEC so later launcher children cannot inherit this channel.
        Even an unsuccessful open does not authorize another attempt.
        """
        global _OPENED
        _require(cls is Channel and not _OPENED, "channel-open")
        _OPENED = True
        owner = cls(_TOKEN)
        wire_versions(adopted=adopted)
        owner._adopted = adopted
        try:
            owner._process()
            for original, access in ((0, os.O_RDONLY), (1, os.O_WRONLY)):
                identity = _identity(original)
                flags = fcntl.fcntl(original, fcntl.F_GETFL)
                _require(flags & os.O_ACCMODE == access and not flags & os.O_PATH, "channel-owner")
                fcntl.fcntl(original, fcntl.F_SETFD,
                    fcntl.fcntl(original, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
                held = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 3)
                owner._fds.append(held)
                owner._identities.append(identity)
                fcntl.fcntl(held, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                _require(_identity(held) == identity, "channel-owner")
            _require(owner._identities[0][:2] != owner._identities[1][:2], "channel-owner")
            owner._check()
            _require(owner._pending() == 0, "channel-future-frame")
            return owner
        except BaseException:
            owner._poisoned = True
            for fd in owner._fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
            owner._fds.clear()
            owner._closed = True
            raise OperatorChannelError("channel-open") from None

    def _process(self):
        _require(os.getpid() == self._pid and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), "channel-owner")

    def _check(self, deadline=None):
        _require(not self._closed, "channel-closed")
        _require(not self._poisoned, "channel-poisoned")
        self._process()
        _require(len(self._fds) == len(self._identities) == 2, "channel-owner")
        for original, held, identity, access in zip((0, 1), self._fds, self._identities,
                (os.O_RDONLY, os.O_WRONLY), strict=True):
            for fd in (original, held):
                flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                _require(_identity(fd) == identity and flags & os.O_ACCMODE == access
                    and flags & os.O_NONBLOCK and not flags & os.O_PATH
                    and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, "channel-owner")
        now = _clock()
        _require(now >= self._last_clock, "channel-deadline")
        self._last_clock = now
        if deadline is not None:
            _require(now < deadline, "channel-deadline")
        if self._expiry is not None:
            wall = time.time_ns()
            _require(self._last_wall <= wall < self._expiry, "channel-deadline")
            self._last_wall = wall
        return now

    def _pending(self):
        # Nonconsuming pipe byte count: never read a future frame to reject it.
        pending = array.array("i", [0])
        fcntl.ioctl(self._fds[0], termios.FIONREAD, pending, True)
        _require(pending[0] >= 0, "channel-io")
        return pending[0]

    def _wait(self, reading, deadline):
        while True:
            now = self._check(deadline)
            duration = min(0.05, (deadline - now) / 1_000_000_000)
            if self._expiry is not None:
                duration = min(duration, (self._expiry - self._last_wall) / 1_000_000_000)
            try:
                ready, writable, _ = select.select([self._fds[0]] if reading else [],
                    [] if reading else [self._fds[1]], [], duration)
            except InterruptedError:
                continue
            self._check(deadline)
            if ready or writable:
                return

    def _count(self, amount):
        _require(0 < amount <= MAX_TOTAL - self._total, "channel-budget")
        self._total += amount

    def _write(self, wire, deadline):
        _require(len(wire) <= MAX_TOTAL - self._total, "channel-budget")
        offset = 0
        while offset < len(wire):
            self._wait(False, deadline)
            try:
                count = os.write(self._fds[1], memoryview(wire)[offset:offset + 65536])
            except (InterruptedError, BlockingIOError):
                continue
            _require(count > 0, "channel-io")
            self._count(count)
            offset += count
            self._check(deadline)

    def _read(self, deadline):
        raw = bytearray()
        while True:
            self._wait(True, deadline)
            # Pipes have no MSG_PEEK. Read exactly through LF, never consuming
            # a following frame. Bounded batches avoid per-byte metadata scans.
            for index in range(4096):
                if index % 128 == 0:
                    self._check(deadline)
                _require(len(raw) + 1 <= MAX_FRAME and self._total < MAX_TOTAL, "channel-budget")
                try:
                    part = os.read(self._fds[0], 1)
                except InterruptedError:
                    self._check(deadline)
                    continue
                except BlockingIOError:
                    break
                _require(bool(part), "channel-eof")
                self._count(1)
                if part == b"\n":
                    self._check(deadline)
                    _require(bool(raw) and self._pending() == 0, "channel-future-frame")
                    return bytes(raw)
                _require(part[0] < 128 and len(raw) + 1 < MAX_FRAME, "reply-invalid")
                raw.extend(part)

    def exchange(self, phase, payload, *, deadline_boottime_ns, expires_at_unix_ns=None):
        """One ordered request/reply under the supplied original deadline.

        Positive short I/O completes the same frame; interruption/failure after
        partial progress never resends a request or grants another phase attempt.
        Inputs remain untrusted data until their existing owner admits them.
        """
        try:
            self._check()
            _require(not self._active and self._sequence < len(STAGES)
                and type(phase) is str and phase == STAGES[self._sequence], "channel-phase")
            _require(type(deadline_boottime_ns) is int and 0 < deadline_boottime_ns <= p.MAX_U64,
                "channel-deadline")
            if self._adopted:
                _require(type(expires_at_unix_ns) is int and 0 < expires_at_unix_ns < 2**63,
                    "channel-deadline")
                _require(self._expiry is None or self._expiry == expires_at_unix_ns,
                    "channel-deadline")
                self._expiry = expires_at_unix_ns
            else:
                _require(expires_at_unix_ns is None, "channel-deadline")
            self._check(deadline_boottime_ns)
            self._active = True
            _require(type(payload) is dict, "request-invalid")
            _require(self._pending() == 0, "channel-future-frame")
            sequence = self._sequence + 1
            try:
                request = {"apiVersion": wire_versions(adopted=self._adopted)[0],
                    "sequence": sequence, "phase": phase, "payload": payload,
                    "deadlineBoottimeNs": str(deadline_boottime_ns)}
                if self._adopted:
                    request["expiresAtUnixNanos"] = str(self._expiry)
                original = p.canonical(request)
            except Exception:
                raise OperatorChannelError("request-invalid") from None
            _require(len(original) + 1 <= MAX_FRAME, "channel-budget")
            self._check(deadline_boottime_ns)
            request_sha = p.sha(original)
            self._write(original + b"\n", deadline_boottime_ns)
            raw = self._read(deadline_boottime_ns)
            try:
                reply = p.fields(p.document(raw, MAX_FRAME - 1),
                    ("apiVersion", "sequence", "phase", "requestSha256", "inputs"))
                p.require(reply["apiVersion"] == wire_versions(adopted=self._adopted)[1]
                    and type(reply["sequence"]) is int and reply["sequence"] == sequence
                    and reply["phase"] == phase and reply["requestSha256"] == request_sha
                    and type(reply["inputs"]) is dict)
                if phase == "shutdown":
                    p.fields(reply["inputs"], ("action",))
                    p.require(reply["inputs"]["action"] == "stop")
            except Exception:
                raise OperatorChannelError("reply-invalid") from None
            self._check(deadline_boottime_ns)
            _require(self._pending() == 0, "channel-future-frame")
            self._sequence = sequence
            self._active = False
            return reply["inputs"]
        except OperatorChannelError as error:
            self._poisoned = True
            raise OperatorChannelError(error.code) from None
        except (KeyboardInterrupt, SystemExit):
            self._poisoned = True
            raise OperatorChannelError("channel-interrupted") from None
        except BaseException:
            self._poisoned = True
            raise OperatorChannelError("channel-io") from None

    def close(self):
        """Close held duplicates only; this settles no pilot/process owner."""
        if self._closed:
            return
        self._process()
        self._closed = self._poisoned = True
        failed = False
        for fd in self._fds:
            try:
                os.close(fd)
            except OSError:
                failed = True
        self._fds.clear()
        _require(not failed, "channel-close")
