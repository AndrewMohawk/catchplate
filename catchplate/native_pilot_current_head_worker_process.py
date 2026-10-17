"""Retain the fixed, installed decision worker across adopted conductor phases.

Only public inventory/policy descriptors cross exec. Installed runtime admission
precedes spawn, and the worker independently admits that same runtime. Starting
is not completion: success requires its exact eight-decision result, pipe EOF
and consuming PIDFD reap. Ambiguous spawn, reap or cleanup retains this owner.
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

from scripts import native_pilot_runtime_artifacts as artifacts
from scripts.authority import native_pilot_authority_io as public_io
from catchplate import native_pilot_current_head_worker_profile as profile
from catchplate import native_pilot_genesis_parent_control_io as ownership
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_proof_cohort_control as mechanics
from catchplate.native_pilot_coordinator_process import _Runtime
from catchplate.native_pilot_lifecycle import _Protected

p = profile.p
_TOKEN, _USED = object(), False
_RESULT_MAX, _CLEANUP_WAIT_NS = 4096, 5_000_000_000


def child_command(*, supervisor_inventory_fd, supervisor_inventory_sha256, policy_fd, policy_sha256):
    """Fixed existing CLI, with two public descriptor/digest pairs only."""
    from scripts.run_native_pilot_current_head_worker import MODE, _arguments
    arguments = [MODE, "--supervisor-inventory-fd", str(supervisor_inventory_fd),
        "--supervisor-inventory-sha256", supervisor_inventory_sha256,
        "--policy-fd", str(policy_fd), "--policy-sha256", policy_sha256]
    _arguments(arguments)
    return artifacts.SUPERVISOR_COMMAND[:-1] + arguments


def terminal_result(raw, *, exit_code):
    """Pure result grammar; not evidence of actual execution, EOF or reap."""
    p.require(type(exit_code) is int and exit_code in (0, 1) and type(raw) is bytes
        and raw.endswith(b"\n") and raw.count(b"\n") == 1 and len(raw) <= _RESULT_MAX)
    value = p.fields(p.document(raw[:-1], _RESULT_MAX), ("apiVersion", "mode", "status", "stage",
        "decisionsPublished", "stateUpdateOutcome", "pilotAcceptanceVerified", "productionReleaseEligible"))
    p.require(p.canonical(value) + b"\n" == raw
        and value["apiVersion"] == "catchplate.nativePilotCurrentHeadWorkerResult/v1"
        and value["mode"] == "current-head-worker" and value["stateUpdateOutcome"] == "not-selected"
        and value["pilotAcceptanceVerified"] is False and value["productionReleaseEligible"] is False
        and type(value["stage"]) is str and value["stage"].isascii() and 0 < len(value["stage"]) <= 256)
    p.integer(value["decisionsPublished"], minimum=0, maximum=8)
    if exit_code == 0:
        p.require(value["status"] == "complete-eight-decisions" and value["decisionsPublished"] == 8
            and value["stage"] == "eight-authoritative-state-decisions-published")
    else:
        p.require(value["status"] == "failed-cleanup-complete")
    return value


class CurrentHeadWorkerProcessError(ValueError):
    def __init__(self, owner):
        super().__init__("current-head worker process refused; actual owner retained; no retry")
        self.owner = owner


class CurrentHeadWorkerProcess:
    def __init__(self, token, check):
        p.require(token is _TOKEN and callable(check))
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._outer, self._runtime = check, _Runtime()
        self._sources, self._pipes = [], {}
        self._inventory = self._policy = self._prepared = None
        self._child = self._pidfd = self._pidfd_identity = self._identity = self._result = None
        self._stdout, self._stderr = bytearray(), bytearray()
        self._stdout_eof = self._stderr_eof = False
        self._spawn_attempted = self._spawn_uncertain = self._reap_attempted = self._reaped = False
        self._cancelled = self._completed = self._failed = self._closing = self._closed = False

    @classmethod
    def prepare(cls, *, supervisor_inventory_fd, supervisor_inventory_sha256, policy_fd, policy_sha256, check):
        global _USED
        p.require(cls is CurrentHeadWorkerProcess and not _USED)
        _USED = True
        owner = cls(_TOKEN, check)
        try:
            owner._origin(); owner._outer()
            p.require(type(supervisor_inventory_fd) is int and type(policy_fd) is int
                and 3 <= supervisor_inventory_fd < (1 << 31) and 3 <= policy_fd < (1 << 31)
                and supervisor_inventory_fd != policy_fd)
            owner._inventory = _Protected(owner._sources, supervisor_inventory_fd,
                artifacts.MAX_MANIFEST_BYTES, supervisor_inventory_sha256)
            owner._policy = _Protected(owner._sources, policy_fd, profile.MAX_POLICY, policy_sha256)
            p.require(owner._inventory.identity[:2] != owner._policy.identity[:2])
            owner._prepared = profile.prepare(owner._policy.raw, inventory_sha256=owner._inventory.digest,
                boot=owner._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            with ownership.owning(): owner._runtime.admit(owner._inventory.raw, supervisor=True)
            owner._retained(full=True); owner._clock(live=True)
            return owner
        except BaseException as error:
            owner._failed = True
            raise CurrentHeadWorkerProcessError(owner) from error

    def _origin(self):
        public_io._process()
        p.require(type(self) is CurrentHeadWorkerProcess and not self._closed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot())
            and threading.current_thread() is threading.main_thread())

    def _clock(self, *, live=False, cleanup_deadline=None):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall)
        if live:
            p.require(self._prepared is not None and now < self._prepared["deadline"]
                and wall < self._prepared["epochLimit"])
        if cleanup_deadline is not None: p.require(now < cleanup_deadline)
        self._last, self._wall = now, wall

    def _retained(self, *, full=False):
        self._origin(); self._outer()
        for held in self._sources: (held.check if full else held.check_identity)()
        # Both parent and child perform full installed admission. Re-scan the
        # installed namespace at launch/completion, not on every I/O poll.
        if full: self._runtime.check()

    @staticmethod
    def _pipe_identity(fd):
        info = os.fstat(fd)
        p.require(stat.S_ISFIFO(info.st_mode) and info.st_uid == info.st_gid == 0)
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink

    def _child_check(self):
        p.require(self._child is not None and self._pidfd is not None and not self._spawn_uncertain
            and originals._identity(os.fstat(self._pidfd)) == self._pidfd_identity
            and not os.get_inheritable(self._pidfd))
        if not self._reaped:
            p.require(mechanics._pidfd_pid(self._pidfd) == self._child.pid
                and mechanics._process(self._child.pid) == (self._pid, self._identity["startTimeTicks"]))
        for name, identity in self._pipes.items():
            fd = getattr(self._child, name).fileno()
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            p.require(self._pipe_identity(fd) == identity and not os.get_inheritable(fd)
                and flags & os.O_NONBLOCK and flags & os.O_ACCMODE == os.O_RDONLY and not flags & os.O_PATH)

    def start(self):
        try:
            p.require(not self._failed and not self._spawn_attempted and not self._closing and not self._cancelled)
            self._retained(full=True); self._clock(live=True)
            command = child_command(supervisor_inventory_fd=self._inventory.fd,
                supervisor_inventory_sha256=self._inventory.digest,
                policy_fd=self._policy.fd, policy_sha256=self._policy.digest)
            with ownership.owning():
                self._spawn_attempted = self._spawn_uncertain = True
                self._child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, bufsize=0, close_fds=True,
                    pass_fds=(self._inventory.fd, self._policy.fd), env={}, cwd="/", restore_signals=True)
                self._pidfd = os.pidfd_open(self._child.pid, 0)
                os.set_inheritable(self._pidfd, False)
                self._pidfd_identity = originals._identity(os.fstat(self._pidfd))
                parent, start = mechanics._process(self._child.pid)
                p.require(parent == self._pid and mechanics._pidfd_pid(self._pidfd) == self._child.pid)
                self._identity = dict(pid=self._child.pid, uid=0, gid=0, startTimeTicks=start, parentPid=self._pid)
                for name in ("stdout", "stderr"):
                    fd = getattr(self._child, name).fileno()
                    os.set_inheritable(fd, False); os.set_blocking(fd, False)
                    self._pipes[name] = self._pipe_identity(fd)
                self._spawn_uncertain = False
            self.check()
            return dict(self._identity)
        except BaseException as error:
            self._failed = True
            raise CurrentHeadWorkerProcessError(self) from error

    def _drain(self):
        for name in ("stdout", "stderr"):
            if getattr(self, "_" + name + "_eof"): continue
            data = getattr(self, "_" + name)
            while True:
                try: raw = os.read(getattr(self._child, name).fileno(), min(4096, _RESULT_MAX + 1 - len(data)))
                except InterruptedError: continue
                except BlockingIOError: break
                if not raw:
                    setattr(self, "_" + name + "_eof", True)
                    break
                data.extend(raw)
                p.require(len(data) <= _RESULT_MAX and (name != "stdout" or not data))

    def _observe(self):
        self._child_check()
        if self._reaped: return
        self._drain()
        if not select.select([self._pidfd], [], [], 0)[0]: return
        observed = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        p.require(observed is not None and observed.si_pid == self._child.pid)
        self._drain()
        if not self._stdout_eof or not self._stderr_eof: return
        p.require(not self._stdout and not self._reap_attempted and observed.si_code == os.CLD_EXITED)
        result = terminal_result(bytes(self._stderr), exit_code=observed.si_status)
        with ownership.owning():
            self._reap_attempted = True
            actual = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED)
            p.require(actual is not None and (actual.si_pid, actual.si_code, actual.si_status)
                == (observed.si_pid, observed.si_code, observed.si_status))
            self._child.returncode = actual.si_status
            self._reaped, self._result = True, result

    def check(self):
        try:
            p.require(not self._failed and not self._closing and not self._cancelled)
            self._retained(); self._observe()
            self._clock(live=not self._reaped)
            if self._reaped:
                p.require(self._child.returncode == 0)
                self._completed = True
        except BaseException as error:
            self._failed = True
            raise CurrentHeadWorkerProcessError(self) from error

    def _collect(self):
        """Bounded terminal observation, never an extension of worker policy."""
        deadline = originals._clock() + _CLEANUP_WAIT_NS
        while not self._reaped:
            self._clock(cleanup_deadline=deadline); self._observe()
            if self._reaped: break
            watched = [self._pidfd] + [getattr(self._child, name).fileno()
                for name in ("stdout", "stderr") if not getattr(self, "_" + name + "_eof")]
            self._clock(cleanup_deadline=deadline)
            select.select(watched, [], [], min(0.01, (deadline - self._last) / 1e9))

    def require_complete(self):
        try:
            p.require(not self._failed and not self._closing and not self._cancelled)
            self._retained(full=True); self._collect(); self._child_check()
            p.require(self._reaped and self._child.returncode == 0
                and self._result["decisionsPublished"] == 8)
            self._completed = True
        except BaseException as error:
            self._failed = True
            raise CurrentHeadWorkerProcessError(self) from error

    def cancel(self):
        """Signal the actual held child only; successful signalling is not cleanup."""
        try:
            self._origin(); p.require(not self._closing)
            if self._cancelled: return
            self._cancelled = True
            p.require(not self._spawn_uncertain)
            if self._child is not None:
                self._observe()
                if not self._reaped and not select.select([self._pidfd], [], [], 0)[0]:
                    try: signal.pidfd_send_signal(self._pidfd, signal.SIGTERM, None, 0)
                    except ProcessLookupError: pass
        except BaseException as error:
            self._failed = True
            raise CurrentHeadWorkerProcessError(self) from error

    def close(self, *, cancel=False):
        if self._closed: return
        try:
            self._origin(); p.require(type(cancel) is bool and not self._closing and not self._spawn_uncertain)
            if cancel or self._failed: self.cancel()
            self._closing = True
            if self._child is not None:
                self._collect(); self._child_check()
                p.require(self._reaped and (self._cancelled or self._child.returncode == 0))
            with ownership.owning():
                if self._child is not None:
                    for name in ("stdout", "stderr"): getattr(self._child, name).close()
                if self._pidfd is not None:
                    fd, self._pidfd = self._pidfd, None
                    os.close(fd)
                for held in self._sources: held.close()
                self._runtime.close()
                self._closed = True
        except BaseException as error:
            self._failed = True
            raise CurrentHeadWorkerProcessError(self) from error
