"""One retained native validation, then one fixed adoption signature.

The independently pinned static executable validates all cold/current original
semantics. Python retains its exact source, sealed executable, child PIDFD and
anonymous stdout pipe. Neither a supplied result nor exit alone authorizes a
key read. Failures retain partial capabilities; there is no retry or new grace.
"""
from __future__ import annotations

import fcntl
import os
import select
import signal
import stat
import threading
import time

from cryptography.hazmat.primitives import serialization

from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_pilot_publication_adoption_profile as profile
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_shadow_proof_cohort_control import _Original, _process, _structural, _terminal

p = profile.p
EXECUTABLE = "/opt/catchplate/catchplate-native-publication-adoption-validator"
_TOKEN, _LIVE, _USED = object(), None, False


def _ownership_identity(info):
    """Same acquired object for close, independent of sealing/writes/chmod."""
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, info.st_gid


class AdoptionAuthorityError(ValueError):
    def __init__(self, owner, *, cleanup_unknown=False):
        super().__init__("publication adoption refused; " + ("cleanup unknown; owner retained"
            if cleanup_unknown else "actual owner retained; no retry"))
        self.owner, self.cleanup_unknown = owner, cleanup_unknown


class AdoptionAuthority:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._inputs, self._fds, self._identities = [], {}, {}
        self._close_identities, self._named_identities = {}, {}
        self._executable = self._control = self._input = self._context = None
        self._child = self._child_start = self._wait_result = self._validation = None
        self._source_fds = ()
        self._output = bytearray()
        self._validate_attempted = self._validated = self._sign_attempted = self._signed = False
        self._reaped = self._eof = self._failed = self._close_attempted = self._closed = False
        self._terminate_attempted = False
        self._close_uncertain = False

    @classmethod
    def prepare(cls, *, control_fd, control_sha256, input_fd, input_sha256):
        global _LIVE, _USED
        p.require(cls is AdoptionAuthority and _LIVE is None and not _USED and control_fd != input_fd)
        io.public_io._process()
        p.require(len(os.listdir("/proc/self/task")) == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
        for fd in (0, 1, 2): os.fstat(fd)
        owner = cls(_TOKEN)
        _LIVE, _USED = owner, True
        try:
            owner._source_fds = (control_fd, input_fd)
            owner._control = owner._retain(control_fd, 4096, control_sha256)
            selected = profile.control(owner._control.raw, input_sha256)
            owner._input = owner._retain(input_fd, profile.MAX_INPUT, input_sha256)
            owner._origin()
            now, wall = originals._clock(), time.time_ns()
            owner._context = profile.prepare_input(owner._input.raw, expected_input_sha256=input_sha256,
                boot=owner._boot, now_boottime_ns=now, now_unix_ns=wall)
            owner._clock()
            with io.owning():
                owner._executable = _Original(EXECUTABLE, io.MAX_EXECUTABLE,
                    selected["validatorExecutableSha256"], 0o555)
                for fd in owner._executable.fds:
                    owner._named_identities[fd] = _ownership_identity(os.fstat(fd))
            io.require_static_elf(owner._executable.raw)
            owner._seal()
            owner.check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise AdoptionAuthorityError(owner, cleanup_unknown=owner._close_uncertain) from error

    @property
    def deadline(self):
        p.require(self._context is not None)
        return self._context["deadline"]

    @property
    def epoch_limit(self):
        p.require(self._context is not None)
        return self._context["epochLimit"]

    def _retain(self, fd, maximum, digest):
        with io.owning():
            value = io.PublicInput(fd, maximum, digest)
            self._inputs.append(value)
            return value

    def _origin(self):
        p.require(_LIVE is self and not self._closed and os.getpid() == self._pid
            and originals._start() == self._start and originals._boot() == self._boot
            and threading.current_thread() is threading.main_thread() and len(os.listdir("/proc/self/task")) == 1
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _clock(self):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall)
        if self._context is not None:
            p.require(self._context["issued"] <= now < self.deadline
                and self._context["epochIssued"] <= wall < self.epoch_limit)
        self._last, self._wall = now, wall
        return now

    def _remember(self, name, fd):
        p.require(name not in self._fds)
        self._fds[name] = fd
        info = os.fstat(fd)
        self._identities[name] = _structural(info)
        self._close_identities[name] = _ownership_identity(info)
        return fd

    def _fd(self, name):
        fd = self._fds[name]
        p.require(_structural(os.fstat(fd)) == self._identities[name] and not os.get_inheritable(fd))
        return fd

    def _drop_fd(self, name):
        with io.owning():
            fd = self._fds[name]
            p.require(_ownership_identity(os.fstat(fd)) == self._close_identities[name])
            # Linux close may have consumed the number even when reporting an
            # error. Retire the slot before the syscall; never retry stale FDs.
            del self._fds[name]; del self._identities[name]; del self._close_identities[name]
            self._close_retired(fd)

    def _close_retired(self, fd):
        previous = self._close_uncertain
        self._close_uncertain = True
        os.close(fd)
        self._close_uncertain = previous

    def _seal(self):
        with io.owning():
            low = self._remember("exec-low", os.memfd_create("catchplate-adoption-validator", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING))
            fd = self._remember("exec", fcntl.fcntl(low, fcntl.F_DUPFD_CLOEXEC, 128))
            self._drop_fd("exec-low")
        offset = 0
        while offset < len(self._executable.raw):
            self._clock()
            count = os.pwrite(fd, self._executable.raw[offset:offset + 65536], offset)
            p.require(count > 0); offset += count
        os.fchmod(fd, 0o500)
        self._identities["exec"] = _structural(os.fstat(fd))
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, io.public_io.SEALS)
        self._exec_identity = originals._identity(os.fstat(fd))
        p.require(os.pread(fd, len(self._executable.raw) + 1, 0) == self._executable.raw)
        self._clock()

    def _sources(self, *, full):
        for source in self._inputs:
            source.check() if full else source.check_identity()
        if self._executable is not None:
            self._executable.check() if full else io.original_identity(self._executable)
        if "exec" in self._fds:
            fd = self._fd("exec")
            p.require(originals._identity(os.fstat(fd)) == self._exec_identity
                and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == io.public_io.SEALS)
        if "private-key" in self._fds:
            p.require(io.public_io._input(self._fd("private-key"), 32, private=True) == self._key_identity)

    def check(self):
        p.require(not self._failed)
        self._clock(); self._sources(full=True)
        if self._child is not None and not self._reaped: self._child_check()
        self._clock()

    def check_identity(self):
        """Cheap output-chunk guard; full check brackets complete publication."""
        p.require(not self._failed)
        self._sources(full=False)
        if self._child is not None and not self._reaped: self._child_check()
        self._clock()

    def _spawn(self):
        p.require(self._child is None and "exec" in self._fds)
        # Retain every returned resource before cancellation can be delivered.
        with io.owning():
            read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            self._fds.update(stdout=read, **{"writer-low": write})
            for name in ("stdout", "writer-low"):
                info = os.fstat(self._fds[name])
                self._identities[name] = _structural(info)
                self._close_identities[name] = _ownership_identity(info)
            writer = self._remember("writer", fcntl.fcntl(write, fcntl.F_DUPFD_CLOEXEC, 128))
            self._drop_fd("writer-low")
            null = self._remember("null-low", os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW))
            info = os.fstat(null)
            p.require(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (1, 3))
            null = self._remember("null", fcntl.fcntl(null, fcntl.F_DUPFD_CLOEXEC, 128))
            self._drop_fd("null-low")
            executable = self._fd("exec")
            actions = [(os.POSIX_SPAWN_DUP2, null, 0), (os.POSIX_SPAWN_DUP2, writer, 1),
                (os.POSIX_SPAWN_DUP2, null, 2), (os.POSIX_SPAWN_DUP2, self._input.fd, 3)]
            for name in os.listdir("/proc/self/fd"):
                fd = int(name)
                if fd > 3 and fd != executable:
                    try: os.fstat(fd)
                    except OSError: continue
                    actions.append((os.POSIX_SPAWN_CLOSE, fd))
            self._sources(full=False); self._clock()
            self._child = os.posix_spawn("/proc/self/fd/" + str(executable),
                [EXECUTABLE, "--input-fd", "3", "--input-sha256", self._context["inputSha256"]], {},
                file_actions=actions, setsigmask=(), setsigdef=(signal.SIGPIPE, signal.SIGCHLD,
                    signal.SIGINT, signal.SIGTERM, signal.SIGHUP))
            # The unreaped direct child cannot be replaced/reused. If either
            # acquisition fails, its PID and all earlier handles stay owned.
            parent, self._child_start = _process(self._child)
            p.require(parent == self._pid)
            self._remember("pidfd", os.pidfd_open(self._child, 0))
            self._drop_fd("writer"); self._drop_fd("null")
        self._child_check(); self._clock()

    def _child_check(self):
        p.require(self._child is not None and not self._reaped)
        fd = self._fd("pidfd")
        p.require(io.pidfd_pid(fd) == self._child and _process(self._child) == (self._pid, self._child_start))
        if not _terminal(fd):
            try:
                info = os.stat("/proc/" + str(self._child) + "/exe")
            except OSError:
                p.require(_terminal(fd))  # A same-child exit may race this read.
            else:
                p.require((info.st_dev, info.st_ino, info.st_size)
                    == (self._exec_identity[0], self._exec_identity[1], self._exec_identity[6]))
        self._pipe_check()

    def _pipe_check(self):
        fd = self._fd("stdout"); info = os.fstat(fd)
        p.require(stat.S_ISFIFO(info.st_mode) and os.readlink("/proc/self/fd/" + str(fd)) == "pipe:[" + str(info.st_ino) + "]"
            and fcntl.fcntl(fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_NONBLOCK | os.O_PATH) == os.O_RDONLY | os.O_NONBLOCK)

    def _drain(self):
        self._pipe_check()
        if self._eof: return
        self._clock()
        try: raw = os.read(self._fd("stdout"), min(65536, profile.MAX_RESULT + 1 - len(self._output)))
        except (BlockingIOError, InterruptedError): return
        if raw: self._output.extend(raw)
        else: self._eof = True
        p.require(len(self._output) <= profile.MAX_RESULT)
        self._pipe_check(); self._clock()

    def _consume(self, expected):
        with io.owning():
            actual = os.waitid(os.P_PIDFD, self._fd("pidfd"), os.WEXITED | os.WNOHANG)
            # Save even an unexpected consuming disposition before checking it.
            self._wait_result, self._reaped = actual, actual is not None
            p.require(actual is not None and (actual.si_pid, actual.si_code, actual.si_status)
                == (expected.si_pid, expected.si_code, expected.si_status))
        return actual

    def validate(self):
        try:
            p.require(not self._failed and not self._validate_attempted and not self._close_attempted)
            self._validate_attempted = True
            self.check(); self._spawn()
            while True:
                self._clock(); self._sources(full=False); self._child_check(); self._drain()
                observed = os.waitid(os.P_PIDFD, self._fd("pidfd"), os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if observed is not None:
                    profile.successful_reap(observed, self._child)
                    # Exit does not imply EOF; drain the actual retained pipe.
                    self._drain()
                    if self._eof:
                        raw = bytes(self._output)
                        profile.result(raw, self._context)
                        self._sources(full=True); self._child_check(); self._clock()
                        actual = self._consume(observed)
                        profile.successful_reap(actual, self._child)
                        self._sources(full=True); self._clock()
                        self._validation, self._validated = raw, True
                        return raw
                now = self._clock()
                select.select([self._fd("pidfd"), self._fd("stdout")], [], [], min(0.01, (self.deadline - now) / 1e9))
        except BaseException as error:
            self._failed = True
            raise AdoptionAuthorityError(self, cleanup_unknown=self._close_uncertain
                or (self._child is not None and not self._reaped)) from error

    def sign(self, *, key_fd):
        try:
            p.require(self._validated and self._reaped and self._eof and not self._failed
                and not self._sign_attempted and not self._close_attempted and type(key_fd) is int
                and key_fd not in (*self._source_fds, *self._fds.values(), *(source.fd for source in self._inputs)))
            self._sign_attempted = True
            self.check(); profile.result(self._validation, self._context)
            self._key_identity = io.public_io._input(key_fd, 32, private=True)
            p.require(self._key_identity[6] == 32)
            with io.owning():
                held = self._remember("private-key", fcntl.fcntl(key_fd, fcntl.F_DUPFD_CLOEXEC, 128))
                p.require(io.public_io._input(held, 32, private=True) == self._key_identity)
            # First private read: unreachable before genuine native EOF/exit0
            # and successful consuming waitid on the same retained PIDFD.
            self._clock()
            key = io.public_io.signing_key(held)
            self._clock()
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            expected = self._context["payload"]["authority"]
            p.require(p.encoded(public) == expected["publicKeyBase64url"])
            message = profile.message(self._context)
            self._clock()
            signature = key.sign(message)
            profile.authority(expected).verify(signature, message)
            result = profile.g.canonical({"payload": self._context["payload"], "signature": p.encoded(signature)})
            p.require(len(result) <= profile.MAX_AUTHORIZATION)
            self.check()
            self._signed = True
            return result
        except BaseException as error:
            self._failed = True
            raise AdoptionAuthorityError(self, cleanup_unknown=self._close_uncertain
                or (self._child is not None and not self._reaped)) from error

    def close(self):
        """Retire known capabilities, not authority or output freshness.

        With no live/unreaped child, expiry does not forbid safe descriptor
        closure. The caller must still deny expired output after close; this
        method neither validates, signs nor renews its original window.
        """
        if self._closed: return
        try:
            p.require(not self._close_attempted)
            self._close_attempted = True
            self._origin()
            if self._child is not None and not self._reaped:
                if "pidfd" not in self._fds:
                    parent, start = _process(self._child)
                    p.require(parent == self._pid and (self._child_start is None or self._child_start == start))
                    self._child_start = start
                    with io.owning(): self._remember("pidfd", os.pidfd_open(self._child, 0))
                self._clock(); self._child_check()
                if not _terminal(self._fd("pidfd")):
                    p.require(not self._terminate_attempted)
                    self._terminate_attempted = True
                    signal.pidfd_send_signal(self._fd("pidfd"), signal.SIGTERM, None, 0)
                while True:
                    self._clock(); self._child_check()
                    observed = os.waitid(os.P_PIDFD, self._fd("pidfd"), os.WEXITED | os.WNOWAIT | os.WNOHANG)
                    if observed is not None:
                        p.require(observed.si_pid == self._child)
                        self._consume(observed); break
                    select.select([self._fd("pidfd")], [], [], 0.001)
            # No authority result survives cancellation/abnormal child exit.
            # Reaping that validator only settles this actual local process.
            # Cleanup needs stable ownership, not fresh authority, unchanged
            # pathname bytes, or completed sealing of a never-executed memfd.
            # A live/unreaped child took the original-window path above.
            for name in tuple(self._fds): self._drop_fd(name)
            with io.owning():
                while self._inputs:
                    source = self._inputs[-1]
                    fd = source.fd
                    expected = source.identity
                    p.require(_ownership_identity(os.fstat(fd)) == (expected[0], expected[1],
                        stat.S_IFMT(expected[2]), expected[3], expected[4]))
                    source.fd = None
                    self._inputs.pop()
                    self._close_retired(fd)
                if self._executable is not None:
                    while self._executable.fds:
                        fd = self._executable.fds[-1]
                        p.require(_ownership_identity(os.fstat(fd)) == self._named_identities[fd])
                        self._executable.fds.pop(); del self._named_identities[fd]
                        self._close_retired(fd)
                    self._executable = None
            self._origin()
            p.require(not self._close_uncertain)
            self._closed = True
        except BaseException as error:
            self._failed = True
            raise AdoptionAuthorityError(self, cleanup_unknown=self._close_uncertain
                or (self._child is not None and not self._reaped)) from error
