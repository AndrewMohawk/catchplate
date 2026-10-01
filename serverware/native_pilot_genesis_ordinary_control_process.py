"""Private process mechanisms for the fixed two-service cold owner only."""
from __future__ import annotations

import array
import ctypes
import fcntl
import os
import resource
import select
import signal
import socket
import struct

from serverware import custody_generation_originals as o
from serverware import native_pilot_genesis_parent_control_io as io
from serverware.native_pilot_genesis_ordinary_resources import ACTIVATION

p = o.p
PARKED = b"serverware.custodyGenesisTwoServiceParked/v1"
RELEASE = b"serverware.custodyGenesisTwoServiceRelease/v1"
UCRED = struct.Struct("=iII")


def packet(channel, count, retained):
    with io.owning():
        try:
            raw, ancillary, flags, _ = channel.recvmsg(4096,
                socket.CMSG_SPACE(4 * max(1, count)) + socket.CMSG_SPACE(UCRED.size),
                socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
        except (BlockingIOError, InterruptedError):
            return None
        rights, credentials, valid = [], None, True
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array("i")
                valid &= len(data) % values.itemsize == 0
                values.frombytes(data[:len(data) - len(data) % values.itemsize])
                for fd in values:
                    if fd < 0:
                        valid = False
                    else:
                        retained.append(fd)
                        rights.append(fd)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if credentials is not None or len(data) != UCRED.size:
                    valid = False
                else:
                    credentials = UCRED.unpack(data)
            else:
                valid = False
        p.require(valid and raw and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0
            and credentials is not None and len(rights) == count)
        return bytes(raw), rights, credentials


def _timer(deadline):
    # A real absolute CLOCK_BOOTTIME/SIGKILL timer bounds the parked child even
    # if its Python parent stops calling lifecycle methods. exec deletes this
    # timer; the selected Rust wrapper then arms its original C9 timers.
    class Event(ctypes.Structure):
        _fields_ = (("value", ctypes.c_void_p), ("signo", ctypes.c_int),
            ("notify", ctypes.c_int), ("padding", ctypes.c_int * 12))
    class Timespec(ctypes.Structure):
        _fields_ = (("seconds", ctypes.c_long), ("nanos", ctypes.c_long))
    class Interval(ctypes.Structure):
        _fields_ = (("interval", Timespec), ("value", Timespec))
    p.require(ctypes.sizeof(Event) == 64 and ctypes.sizeof(Timespec) == 16 and o.clock() < deadline)
    libc = ctypes.CDLL(None, use_errno=True)
    handle = ctypes.c_void_p()
    event = Event(None, signal.SIGKILL, 0)
    p.require(libc.timer_create(7, ctypes.byref(event), ctypes.byref(handle)) == 0)
    value = Interval(Timespec(0, 0), Timespec(deadline // 1_000_000_000, deadline % 1_000_000_000))
    p.require(libc.timer_settime(handle, 1, ctypes.byref(value), None) == 0)


def park(channel, executable_fd, parent, role, startup):
    """Only the actual fork child; the same PID later performs the fixed exec."""
    try:
        p.require(role in ACTIVATION and os.uname().machine == "x86_64")
        for selected in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGPIPE, signal.SIGCHLD):
            signal.signal(selected, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        libc = ctypes.CDLL(None, use_errno=True)
        p.require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent
            and libc.prctl(4, 0, 0, 0, 0) == 0)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _timer(startup)
        wire = fcntl.fcntl(channel.fileno(), fcntl.F_DUPFD_CLOEXEC, 256)
        executable = fcntl.fcntl(executable_fd, fcntl.F_DUPFD_CLOEXEC, 256)
        os.dup2(wire, 3, inheritable=True)
        os.dup2(executable, 5, inheritable=False)
        limit = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        p.require(type(limit) is int and 256 < limit <= 1_048_576)
        os.closerange(0, 3)
        os.closerange(4, 5)
        os.closerange(6, limit)
        null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
        for target in (0, 1, 2):
            os.dup2(null, target, inheritable=True)
        if null > 2:
            os.close(null)
        channel = socket.socket(fileno=3)
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        p.require(channel.send(PARKED) == len(PARKED))
        retained = []
        while True:
            p.require(os.getppid() == parent and o.clock() < startup)
            received = packet(channel, 1 + len(ACTIVATION[role]), retained)
            if received is not None:
                raw, rights, credentials = received
                p.require(raw == RELEASE and credentials == (parent, 0, 0))
                break
            select.select([channel], [], [], min(0.01, (startup - o.clock()) / 1_000_000_000))
        copies = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 256) for fd in rights]
        for fd in rights:
            os.close(fd)
        os.dup2(copies[0], 4, inheritable=True)
        for target, fd in enumerate(copies[1:], 6):
            os.dup2(fd, target, inheritable=True)
        for fd in copies:
            os.close(fd)
        p.require(os.getppid() == parent and o.clock() < startup)
        path = "/usr/local/bin/serverware-policy-custody-" + role
        os.execve(5, [path, "--guest-c9-genesis-inspected"], {})
    except BaseException:
        os._exit(1)
