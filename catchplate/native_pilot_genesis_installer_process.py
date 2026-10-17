"""Own one fixed approved-pair installer; never forward output before reap.

Only the source-selected rendezvous/job installers may run. Public observations
can be sealed for transport, but approval originals remain independently
provided. Unknown acquisition, exit or cleanup retains this actual owner.
"""
from __future__ import annotations

import fcntl
import os
import select
import signal
import stat
import subprocess
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifact
from scripts.authority import native_pilot_authority_io as public
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_shadow_driver_bootstrap as bootstrap
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_nitro_profile as p
from catchplate.native_pilot_coordinator_process import _Runtime, _structural

ENTRYPOINT = "/supervisor/app/scripts/native_pilot_genesis_install_runtime_entrypoint.py"
MAX_REPLY = 4096
MAX_REQUEST = 32 * 1024 * 1024 - 1
_TOKEN = object()
_LIVE = None
_CLAIMED = set()


class SealedRequestError(ValueError):
    def __init__(self, owner):
        super().__init__("request sealing failed; actual descriptor owner retained")
        self.owner = owner


class SealedRequest:
    """Retain literal public request bytes, without granting them authority."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        self.fd, self.raw, self.digest = None, None, None
        self._pid, self._closed, self._closing = os.getpid(), False, False

    @classmethod
    def open(cls, raw):
        p.require(cls is SealedRequest)
        owner = cls(_TOKEN)
        try:
            public._process()
            p.require(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST)
            with io.owning():
                owner.fd = os.memfd_create("catchplate-cold-request", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            offset = 0
            while offset < len(raw):
                count = os.pwrite(owner.fd, raw[offset:offset + 65536], offset)
                p.require(0 < count <= min(65536, len(raw) - offset))
                offset += count
            os.fchmod(owner.fd, 0o400)
            fcntl.fcntl(owner.fd, fcntl.F_ADD_SEALS, public.SEALS)
            owner.raw, owner.digest = raw, p.sha(raw)
            owner._identity = public._input(owner.fd, MAX_REQUEST)
            owner.check()
            return owner
        except BaseException as error:
            raise SealedRequestError(owner) from error

    def check(self):
        p.require(os.getpid() == self._pid and not self._closed and not self._closing
            and public._input(self.fd, MAX_REQUEST) == self._identity
            and public.read_public(self.fd, MAX_REQUEST) == self.raw)

    def close(self):
        if self._closed:
            return
        p.require(os.getpid() == self._pid and not self._closing)
        self._closing = True
        try:
            with io.owning():
                if self.fd is not None:
                    fd, self.fd = self.fd, None
                    os.close(fd)
                self._closed = True
        except BaseException as error:
            raise SealedRequestError(self) from error


class InstallerProcessError(ValueError):
    def __init__(self, owner):
        super().__init__("fixed cold installer refused; actual process and originals retained")
        self.owner = owner


def command(kind, pairs):
    """Closed argument assembly, not an installation or authority decision."""
    names = ("supervisor_inventory",) + (("configuration",) if kind == "job" else ()) + (
        "request", "input", "approval")
    p.require(kind in ("rendezvous", "job") and type(pairs) is dict and set(pairs) == set(names))
    result = ["/" + artifact.INTERPRETER, "-I", "-B", ENTRYPOINT, "--install-" + kind]
    descriptors = []
    for name in names:
        fd, digest = pairs[name]
        p.integer(fd, minimum=3, maximum=(1 << 31) - 1)
        p.digest(digest)
        descriptors.append(fd)
        flag = name.replace("_", "-")
        result.extend(("--" + flag + "-fd", str(fd), "--" + flag + "-sha256", digest))
    p.require(len(descriptors) == len(set(descriptors)))
    return result, tuple(descriptors)


class GenesisInstallerProcess:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._runtime, self._sources = _Runtime(), {}
        self._child = self._pidfd = self._command = self._deadline = self._expiry = None
        self._last, self._wall = originals._clock(), time.time_ns()
        self._started = self._failed = self._closed = self._closing = self._reaped = False
        self._acquisition_uncertain = False
        self._stdout, self._stderr = bytearray(), bytearray()
        self._eof, self._pipe_ids = set(), {}
        self._expected = self._reply = None

    @classmethod
    def prepare(cls, *, kind, supervisor_inventory_fd, supervisor_inventory_sha256,
                request_fd, request_sha256, input_fd, input_sha256, approval_fd, approval_sha256,
                configuration_fd=None, configuration_sha256=None):
        global _LIVE
        p.require(cls is GenesisInstallerProcess and _LIVE is None and kind in ("rendezvous", "job"))
        p.digest(request_sha256)
        key = (kind, request_sha256)
        p.require(key not in _CLAIMED)
        _CLAIMED.add(key)
        owner = cls(_TOKEN)
        _LIVE = owner
        try:
            owner._origin()
            from catchplate import native_pilot_genesis_rendezvous_install as rendezvous
            if kind == "job":
                from catchplate import native_pilot_genesis_job_install as installer
            else:
                installer = rendezvous
                p.require(configuration_fd is None and configuration_sha256 is None)
            pairs = {"supervisor_inventory": (supervisor_inventory_fd, supervisor_inventory_sha256),
                "request": (request_fd, request_sha256), "input": (input_fd, input_sha256),
                "approval": (approval_fd, approval_sha256)}
            if kind == "job":
                pairs["configuration"] = (configuration_fd, configuration_sha256)
            command(kind, pairs)  # Reject duplicate/or otherwise invalid FDs before acquisition.
            maxima = {"supervisor_inventory": artifact.MAX_MANIFEST_BYTES,
                "configuration": 4096, "request": MAX_REQUEST if kind == "job" else rendezvous.MAX_REQUEST,
                "input": public.MAX_PUBLIC if kind == "job" else rendezvous.MAX_INPUT,
                "approval": 8192 if kind == "job" else rendezvous.MAX_APPROVAL}
            for name in (("configuration",) if kind == "job" else ()) + ("request", "input", "approval", "supervisor_inventory"):
                fd, digest = pairs[name]
                with io.owning():
                    # Retain the actual allocation before its fallible
                    # constructor, including a failed duplicate close.
                    source = io.PublicInput.__new__(io.PublicInput)
                    source.fd = None
                    owner._sources[name] = source
                    try:
                        io.PublicInput.__init__(source, fd, maxima[name], digest)
                    except BaseException:
                        owner._acquisition_uncertain = source.fd is not None
                        raise
                if name == "configuration":
                    selected_configuration = installer.context(owner._sources[name].raw, boot=owner._boot,
                        now_boottime_ns=owner._last, now_unix_ns=owner._wall)
                    owner._deadline = p.ns(selected_configuration["window"]["lifetimeDeadlineBoottimeNs"])
                    owner._expiry = selected_configuration["expiresAtUnixNanos"]
                elif name == "request":
                    if kind == "job":
                        _, selected_job, owner._deadline = installer.request(owner._sources[name].raw,
                            selected_configuration, now_boottime_ns=owner._last)
                        maxima["input"] = selected_job.maximum
                    else:
                        ticket = rendezvous.profile.verify_request(owner._sources[name].raw)
                        owner._deadline = p.ns(ticket["deadlineBoottimeNs"])
                        owner._expiry = ticket["expiresAtUnixNanos"]
                owner._clock()
            p.require(len({item.identity[:2] for item in owner._sources.values()}) == len(owner._sources))
            kwargs = dict(request_sha256=request_sha256, input_sha256=input_sha256,
                approval_sha256=approval_sha256, boot=owner._boot,
                now_boottime_ns=owner._last, now_unix_ns=owner._wall)
            values = [owner._sources[name].raw for name in ("request", "input", "approval")]
            if kind == "job":
                values.append(owner._sources["configuration"].raw)
                kwargs["configuration_sha256"] = configuration_sha256
            prepared = installer.prepare_input(*values, **kwargs)
            owner._deadline, owner._expiry = prepared["deadline"], prepared["epochLimit"]
            owner._expected = p.canonical(prepared["reply"]) + b"\n"
            p.require(0 < len(owner._expected) <= MAX_REPLY + 1)
            owner._clock()
            owner._runtime.admit(owner._sources["supervisor_inventory"].raw, supervisor=True)
            p.require(ENTRYPOINT[1:] in owner._runtime.records)
            owner._command, owner._inherited = command(kind, {name: (item.fd, pairs[name][1])
                for name, item in owner._sources.items()})
            owner._clock()
            return owner
        except BaseException as error:
            owner._failed = True
            raise InstallerProcessError(owner) from error

    def _origin(self):
        public._process()
        p.require(not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and threading.current_thread() is threading.main_thread()
            and len(os.listdir("/proc/self/task")) == 1)

    def _clock(self):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall
            and (self._deadline is None or now < self._deadline)
            and (self._expiry is None or wall < self._expiry))
        self._last, self._wall = now, wall

    def _check(self, check):
        self._clock()
        for item in self._sources.values():
            item.check_identity()
        if check is not None:
            check()
        self._clock()

    def _drain(self):
        for name, target in (("stdout", self._stdout), ("stderr", self._stderr)):
            stream = getattr(self._child, name)
            p.require(_structural(os.fstat(stream.fileno())) == self._pipe_ids[name])
            flags = fcntl.fcntl(stream.fileno(), fcntl.F_GETFL)
            p.require(flags & os.O_ACCMODE == os.O_RDONLY and flags & os.O_NONBLOCK
                and not flags & os.O_PATH and not os.get_inheritable(stream.fileno()))
            if name in self._eof:
                continue
            for _ in range(4):
                try:
                    raw = os.read(stream.fileno(), MAX_REPLY + 2 - len(target))
                except (InterruptedError, BlockingIOError):
                    break
                if not raw:
                    self._eof.add(name)
                    break
                target.extend(raw)
                p.require(len(target) <= MAX_REPLY + 1)

    def _wait(self, check, *, success):
        p.require(self._child is not None and self._pidfd is not None and not self._reaped)
        while True:
            self._check(check)
            self._drain()
            if select.select([self._pidfd], [], [], 0)[0]:
                observed = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                p.require(observed is not None and observed.si_pid == self._child.pid
                    and observed.si_code == os.CLD_EXITED and observed.si_status in (0, 1))
                self._drain()
                p.require(self._eof == {"stdout", "stderr"})
                if success:
                    p.require(observed.si_status == 0 and not self._stderr and bytes(self._stdout) == self._expected)
                self._check(check)
                with io.owning():
                    reaped = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED)
                    p.require(reaped is not None and (reaped.si_pid, reaped.si_code, reaped.si_status)
                        == (observed.si_pid, observed.si_code, observed.si_status))
                    self._child.returncode = reaped.si_status
                    self._reaped = True
                self._check(check)
                return
            readers = [self._pidfd] + [getattr(self._child, name).fileno()
                for name in ("stdout", "stderr") if name not in self._eof]
            remaining = (self._deadline - self._last) / 1_000_000_000
            try:
                select.select(readers, [], [], min(0.05, remaining))
            except InterruptedError:
                continue

    def run(self, *, check=None):
        p.require(not self._started and not self._failed and not self._closing and self._command is not None
            and (check is None or callable(check)))
        self._started = True
        try:
            self._check(check)
            self._runtime.check()
            self._check(check)
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, io.CANCELLATION)
            retained = False
            try:
                self._child = subprocess.Popen(self._command, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, close_fds=True,
                    pass_fds=self._inherited, env={}, cwd="/", restore_signals=True)
                self._pidfd = os.pidfd_open(self._child.pid, 0)
                os.set_inheritable(self._pidfd, False)
                p.require(io.pidfd_pid(self._pidfd) == self._child.pid)
                parent, self._child_start = bootstrap.mechanics._process(self._child.pid)
                p.require(parent == self._pid)
                for name in ("stdout", "stderr"):
                    fd = getattr(self._child, name).fileno()
                    os.set_blocking(fd, False)
                    os.set_inheritable(fd, False)
                    info = os.fstat(fd)
                    p.require(stat.S_ISFIFO(info.st_mode) and info.st_uid == info.st_gid == 0)
                    self._pipe_ids[name] = _structural(info)
                retained = True
            finally:
                if retained or self._child is None:
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            self._wait(check, success=True)
            self._runtime.check()
            self._check(check)
            result = bytes(self._stdout[:-1])
            self.close()
            # Closing does not earn a new clock baseline or deadline.
            now, wall = originals._clock(), time.time_ns()
            p.require(self._last <= now < self._deadline and self._wall <= wall < self._expiry)
            if check is not None:
                check()
            after, after_wall = originals._clock(), time.time_ns()
            p.require(now <= after < self._deadline and wall <= after_wall < self._expiry)
            self._reply = result
            return result
        except BaseException as error:
            self._failed = True
            raise InstallerProcessError(self) from error

    def close(self, *, cancel=False):
        global _LIVE
        if self._closed:
            return
        try:
            self._origin()
            p.require(not self._closing and not self._acquisition_uncertain and type(cancel) is bool)
            self._closing = True
            if self._child is not None and not self._reaped:
                p.require(self._pidfd is not None and cancel)
                if not select.select([self._pidfd], [], [], 0)[0]:
                    try:
                        signal.pidfd_send_signal(self._pidfd, signal.SIGTERM, None, 0)
                    except ProcessLookupError:
                        pass
                self._wait(None, success=False)
            with io.owning():
                if self._child is not None:
                    for name in ("stdout", "stderr"):
                        stream = getattr(self._child, name)
                        if stream is not None:
                            setattr(self._child, name, None)
                            stream.close()
                if self._pidfd is not None:
                    fd, self._pidfd = self._pidfd, None
                    os.close(fd)
                while self._runtime.directories:
                    _, fd = self._runtime.directories.popitem()
                    os.close(fd)
                while self._sources:
                    _, item = self._sources.popitem()
                    item.close()
                self._closed = True
                if _LIVE is self:
                    _LIVE = None
        except BaseException as error:
            self._failed = True
            raise InstallerProcessError(self) from error
