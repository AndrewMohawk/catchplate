"""Private actual process/SCM transport for the fixed cold endpoint parent.

No PID or wire object constructs an owner. Cancellation leaves the actual
spawn, PIDFD, peer socket and sealed executable retained for bounded cleanup.
"""
from __future__ import annotations

import array
import fcntl
import os
import select
import signal
import socket
import stat

from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_shadow_nitro_originals as originals
from serverware.native_shadow_proof_cohort_control import _process, _structural, _terminal

p = io.p
EXECUTABLE = "/opt/serverware/serverware-native-publication-genesis-controller"


class Process:
    def __init__(self, executable):
        self.executable = executable
        self.exec = self.pid = self.pidfd = self.stdout = self.socket = None
        self.received, self.mask, self.reaped = [], None, False
        self.child_rights = []
        self.eof = False

    def seal(self):
        io.require_static_elf(self.executable.raw)
        with io.owning():
            low = os.memfd_create("serverware-genesis-endpoints", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                self.exec = fcntl.fcntl(low, fcntl.F_DUPFD_CLOEXEC, 128)
            finally:
                os.close(low)
        offset = 0
        while offset < len(self.executable.raw):
            count = os.pwrite(self.exec, self.executable.raw[offset:offset + 65536], offset)
            p.require(count > 0); offset += count
        os.fchmod(self.exec, 0o500)
        fcntl.fcntl(self.exec, fcntl.F_ADD_SEALS, io.public_io.SEALS)
        self.identity = originals._identity(os.fstat(self.exec))
        p.require(os.pread(self.exec, len(self.executable.raw) + 1, 0) == self.executable.raw)

    def spawn(self):
        p.require(self.pid is None and self.exec is not None)
        self.mask = signal.pthread_sigmask(signal.SIG_BLOCK, io.CANCELLATION)
        temporary, child = [], None
        try:
            self.socket, child = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, 76, 1)
            self.socket_identity = _structural(os.fstat(self.socket.fileno()))
            self.channel_check()
            source = fcntl.fcntl(child, fcntl.F_DUPFD_CLOEXEC, 128); temporary.append(source)
            self.stdout, output = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK); temporary.append(output)
            self.stdout_identity = _structural(os.fstat(self.stdout))
            output = fcntl.fcntl(output, fcntl.F_DUPFD_CLOEXEC, 128); temporary.append(output)
            null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW); temporary.append(null)
            info = os.fstat(null)
            p.require(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (1, 3))
            null = fcntl.fcntl(null, fcntl.F_DUPFD_CLOEXEC, 128); temporary.append(null)
            actions = [(os.POSIX_SPAWN_DUP2, null, 0), (os.POSIX_SPAWN_DUP2, output, 1),
                (os.POSIX_SPAWN_DUP2, null, 2), (os.POSIX_SPAWN_DUP2, source, 3)]
            for name in os.listdir("/proc/self/fd"):
                fd = int(name)
                if fd > 3 and fd != self.exec:
                    try:
                        os.fstat(fd)
                    except OSError:
                        continue
                    actions.append((os.POSIX_SPAWN_CLOSE, fd))
            self.pid = os.posix_spawn("/proc/self/fd/" + str(self.exec),
                [EXECUTABLE, "--parked-genesis-endpoints"], {}, file_actions=actions,
                setsigmask=(), setsigdef=(signal.SIGPIPE, signal.SIGCHLD))
            self.pidfd = os.pidfd_open(self.pid, 0)
            parent, self.start = _process(self.pid)
            p.require(parent == os.getpid())
            self.check()
        finally:
            for fd in reversed(temporary):
                os.close(fd)
            if child is not None:
                child.close()
            if self.pid is None or self.pidfd is not None:
                mask, self.mask = self.mask, None
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def check(self, *, terminal=False):
        self.channel_check()
        p.require(not self.reaped and self.pidfd is not None and io.pidfd_pid(self.pidfd) == self.pid
            and _process(self.pid) == (os.getpid(), self.start)
            and originals._identity(os.fstat(self.exec)) == self.identity
            and fcntl.fcntl(self.exec, fcntl.F_GET_SEALS) == io.public_io.SEALS)
        if not terminal:
            p.require(not _terminal(self.pidfd))
            info = os.stat(f"/proc/{self.pid}/exe")
            p.require((info.st_dev, info.st_ino, info.st_size) == (self.identity[0], self.identity[1], self.identity[6]))
        p.require(_structural(os.fstat(self.stdout)) == self.stdout_identity
            and fcntl.fcntl(self.stdout, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_NONBLOCK) == os.O_RDONLY | os.O_NONBLOCK)
        if not self.eof:
            try:
                raw = os.read(self.stdout, 1)
                p.require(not raw)  # This controller never emits a business result.
                self.eof = True
            except (BlockingIOError, InterruptedError):
                pass

    def channel_check(self):
        p.require(self.socket is not None and _structural(os.fstat(self.socket.fileno())) == self.socket_identity
            and self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
            and self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX
            and self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
            and self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
            and self.socket.getsockopt(socket.SOL_SOCKET, 76) == 1
            and fcntl.fcntl(self.socket, fcntl.F_GETFL) & os.O_NONBLOCK
            and not os.get_inheritable(self.socket.fileno()))

    def send(self, raw, rights, check):
        p.require(type(raw) is bytes and 0 < len(raw) <= 32768 and len(rights) in (0, 5))
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights))] if rights else []
        while True:
            check(); self.check(); self.channel_check()
            with io.owning():
                try:
                    count = self.socket.sendmsg([raw], ancillary, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
                except (BlockingIOError, InterruptedError):
                    count = None
                if count is not None:
                    p.require(count == len(raw))
                    # The caller marks the attempt before entering send; an
                    # expired post-write bound cannot authorize a retry.
                    self.channel_check(); check(); return
            select.select([], [self.socket], [], 0.001)

    def receive(self, count, *, terminal=False):
        p.require(count in (0, 2))
        self.channel_check()
        with io.owning():
            try:
                raw, ancillary, flags, _ = self.socket.recvmsg(32768, socket.CMSG_SPACE(12)
                    + socket.CMSG_SPACE(4) + socket.CMSG_SPACE(8), socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
            except (BlockingIOError, InterruptedError):
                return None
            rights, senders, credentials, valid = [], [], None, True
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, 4):
                    values = array.array("i")
                    valid &= len(data) % values.itemsize == 0
                    values.frombytes(data[:len(data) - len(data) % values.itemsize])
                    for fd in values:
                        if fd < 0:
                            valid = False
                        else:
                            self.received.append(fd)
                            (rights if kind == socket.SCM_RIGHTS else senders).append(fd)
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                    if credentials is not None or len(data) != io._UCRED.size:
                        valid = False
                    else:
                        credentials = io._UCRED.unpack(data)
                else:
                    valid = False
            if count == 2:
                # Retain even malformed observation candidates. Terminal
                # cleanup may not silently forget an acquired descendant
                # merely because wire validation or peer capture failed.
                self.child_rights.extend(rights)
            p.require(valid and raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                and len(rights) == count and len(senders) == 1 and credentials == (self.pid, 0, 0)
                and io.pidfd_pid(senders[0]) == self.pid
                and _structural(os.fstat(senders[0])) == _structural(os.fstat(self.pidfd)))
            if not terminal:
                p.require(not _terminal(senders[0]))
            self.channel_check()
            return bytes(raw), rights

    def retire(self, check, descendants, *, successful):
        if self.pid is None:
            return
        if self.pidfd is None:
            parent, self.start = _process(self.pid)
            p.require(parent == os.getpid())
            with io.owning():
                self.pidfd = os.pidfd_open(self.pid, 0)
        self.check(terminal=True)
        if not successful and not _terminal(self.pidfd):
            signal.pidfd_send_signal(self.pidfd, signal.SIGTERM, None, 0)
        while True:
            check(); self.check(terminal=True)
            result = os.waitid(os.P_PIDFD, self.pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            if result is not None:
                p.require(result.si_pid == self.pid and result.si_code == os.CLD_EXITED
                    and result.si_status in ((0,) if successful else (0, 1)))
                for fd in descendants:
                    p.require(_terminal(fd) and io.pidfd_pid(fd) == -1)
                if not self.eof:
                    continue
                with io.owning():
                    actual = os.waitid(os.P_PIDFD, self.pidfd, os.WEXITED | os.WNOHANG)
                    p.require(actual is not None and (actual.si_pid, actual.si_code, actual.si_status)
                        == (result.si_pid, result.si_code, result.si_status))
                    self.reaped = True
                return
            select.select([self.pidfd, self.stdout], [], [], 0.001)

    def close_after_reap(self):
        p.require(self.pid is None or self.reaped)
        if self.socket is not None:
            self.socket.close(); self.socket = None
        for fd in set(self.received + [fd for fd in (self.exec, self.pidfd, self.stdout) if fd is not None]):
            os.close(fd)
        self.received.clear()
        self.exec = self.pidfd = self.stdout = None
        if self.mask is not None:
            mask, self.mask = self.mask, None
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
