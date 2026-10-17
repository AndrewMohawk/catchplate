"""Parent-side fixed pilot pipe protocol; framing never grants authority."""
from __future__ import annotations

import array
import copy
import fcntl
import os
import select
import signal
import stat
import termios
import time

from catchplate.native_pilot_operator_channel import STAGES, MAX_FRAME, MAX_TOTAL, wire_versions
from catchplate import native_shadow_nitro_profile as p

_TOKEN = object()


def _require(value):
    if not value:
        raise ValueError("native pilot coordinator channel refused")


def _identity(fd):
    info = os.fstat(fd)
    _require(stat.S_ISFIFO(info.st_mode) and info.st_uid == info.st_gid == 0)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink


def request_value(raw, *, sequence, phase, upper_deadline, adopted=False, expires_at_unix_ns=None):
    """Closed framing only; independently retained owners supply every bound."""
    _require(type(adopted) is bool and type(sequence) is int and 1 <= sequence <= len(STAGES)
        and STAGES[sequence - 1] == phase and type(upper_deadline) is int and 0 < upper_deadline <= p.MAX_U64)
    fields = ("apiVersion", "sequence", "phase", "payload", "deadlineBoottimeNs")
    value = p.fields(p.document(raw, MAX_FRAME - 1), fields + (("expiresAtUnixNanos",) if adopted else ()))
    _require(value["apiVersion"] == wire_versions(adopted=adopted)[0]
        and type(value["sequence"]) is int and value["sequence"] == sequence
        and value["phase"] == phase and phase in STAGES and type(value["payload"]) is dict
        and p.ns(value["deadlineBoottimeNs"]) <= upper_deadline)
    if adopted:
        expiry = p.ns(value["expiresAtUnixNanos"])
        _require(type(expires_at_unix_ns) is int and 0 < expiry <= expires_at_unix_ns <= p.MAX_I64)
    else:
        _require(expires_at_unix_ns is None)
    return value


class Request:
    """Only the actual retained pipe reader constructs this pending request."""
    def __init__(self, token, raw, value):
        _require(token is _TOKEN)
        self._raw, self._value = raw, value

    @property
    def sequence(self):
        return self._value["sequence"]

    @property
    def phase(self):
        return self._value["phase"]

    @property
    def payload(self):
        return copy.deepcopy(self._value["payload"])

    @property
    def raw(self):
        return self._raw

    @property
    def deadline_boottime_ns(self):
        return p.ns(self._value["deadlineBoottimeNs"])

    @property
    def expires_at_unix_ns(self):
        return p.ns(self._value["expiresAtUnixNanos"]) if "expiresAtUnixNanos" in self._value else None


class PipeChannel:
    """Borrow only the actual subprocess's pipes; the process owns cleanup."""
    def __init__(self, owner, reader, writer):
        from catchplate.native_pilot_coordinator_process import ConductorProcess
        _require(type(owner) is ConductorProcess and owner._child is not None
            and reader == owner._child.stdout.fileno() and writer == owner._child.stdin.fileno())
        self._owner, self._reader, self._writer = owner, reader, writer
        self._ids = (_identity(reader), _identity(writer))
        _require(self._ids[0][:2] != self._ids[1][:2])
        for fd, access in ((reader, os.O_RDONLY), (writer, os.O_WRONLY)):
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            _require(flags & os.O_ACCMODE == access and not flags & os.O_PATH)
            os.set_inheritable(fd, False)
            os.set_blocking(fd, False)
        self._index = self._total = 0
        self._pending = None
        self._poisoned = False
        self._interactive_action = self._interactive_origin = None

    def _check(self, deadline, *, allow_terminal=False):
        _require(not self._poisoned)
        self._owner._io_check(deadline, allow_terminal=allow_terminal)
        for fd, identity, access in ((self._reader, self._ids[0], os.O_RDONLY),
                                     (self._writer, self._ids[1], os.O_WRONLY)):
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            _require(_identity(fd) == identity and flags & os.O_ACCMODE == access
                and flags & os.O_NONBLOCK and not os.get_inheritable(fd))

    def _wait(self, reading, deadline):
        while True:
            self._check(deadline)
            duration = min(0.05, (deadline - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1_000_000_000)
            if self._owner._adopted:
                duration = min(duration, (self._owner._epoch_limit - time.time_ns()) / 1_000_000_000)
            _require(duration > 0)
            try:
                ready, writable, _ = select.select([self._reader] if reading else [],
                    [] if reading else [self._writer], [], duration)
            except InterruptedError:
                continue
            self._check(deadline)
            if ready or writable:
                return

    def _count(self, count):
        _require(0 < count <= MAX_TOTAL - self._total)
        self._total += count

    def receive(self, upper_deadline):
        try:
            _require(self._pending is None and self._index < len(STAGES))
            raw = bytearray()
            while True:
                self._wait(True, upper_deadline)
                for index in range(4096):
                    if index % 128 == 0:
                        self._check(upper_deadline)
                    _require(len(raw) + 1 <= MAX_FRAME and self._total < MAX_TOTAL)
                    try:
                        byte = os.read(self._reader, 1)
                    except InterruptedError:
                        continue
                    except BlockingIOError:
                        break
                    _require(bool(byte)); self._count(1)
                    if byte == b"\n":
                        pending = array.array("i", [0])
                        fcntl.ioctl(self._reader, termios.FIONREAD, pending, True)
                        _require(bool(raw) and pending[0] == 0)
                        value = request_value(bytes(raw), sequence=self._index + 1, phase=STAGES[self._index],
                            upper_deadline=upper_deadline, adopted=self._owner._adopted,
                            expires_at_unix_ns=self._owner._epoch_limit if self._owner._adopted else None)
                        if self._owner._adopted:
                            self._owner._retain_core_expiry(p.ns(value["expiresAtUnixNanos"]))
                        deadline = p.ns(value["deadlineBoottimeNs"])
                        _require(deadline <= upper_deadline)
                        self._check(deadline)
                        self._pending = Request(_TOKEN, bytes(raw), value)
                        return self._pending
                    _require(byte[0] < 128 and len(raw) + 1 < MAX_FRAME)
                    raw.extend(byte)
        except BaseException:
            self._poisoned = True
            raise

    def reply(self, request, inputs):
        try:
            _require(type(request) is Request and self._pending is request and type(inputs) is dict)
            deadline = request.deadline_boottime_ns
            self._check(deadline)
            action = handoff = None
            if request.phase == "shutdown":
                if inputs.get("action") == "run-interactive":
                    from catchplate import native_pilot_interactive as interactive
                    handoff = request.payload["originHandoff"]
                    action = interactive.validate_action(inputs, origin_handoff=handoff)
                    now, epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
                    _require(now < action["stopAtBoottimeNanos"] < deadline
                        <= self._owner._lifetime - self._owner._reserve
                        and epoch < action["expiresAtUnixNanos"]
                        and action["stopAtBoottimeNanos"] - now < action["expiresAtUnixNanos"] - epoch)
                else:
                    p.fields(inputs, ("action",)); _require(inputs["action"] == "stop")
            wire = p.canonical({"apiVersion": wire_versions(adopted=self._owner._adopted)[1], "sequence": request.sequence,
                "phase": request.phase, "requestSha256": p.sha(request.raw), "inputs": inputs}) + b"\n"
            _require(len(wire) <= MAX_FRAME and len(wire) <= MAX_TOTAL - self._total)
            offset = 0
            while offset < len(wire):
                self._wait(False, deadline)
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
                try:
                    try:
                        count = os.write(self._writer, memoryview(wire)[offset:offset + 65536])
                    except (InterruptedError, BlockingIOError):
                        continue
                    self._count(count); offset += count
                    self._check(deadline, allow_terminal=(offset == len(wire) and request.phase == STAGES[-1]))
                    if offset == len(wire):
                        # Retain the selected interval atomically with its
                        # positive final write; blocking waits stay cancellable.
                        self._interactive_action, self._interactive_origin = action, copy.deepcopy(handoff)
                        self._pending = None
                        self._index += 1
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        except BaseException:
            self._poisoned = True
            raise
