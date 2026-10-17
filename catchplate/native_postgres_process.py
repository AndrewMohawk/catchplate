"""Internal Linux direct-child supervision for the source-fixed PG fixture job.

This is not a command-line interface, process-group/descendant supervisor, or
container cleanup proof. Its caller owns every command, environment and
deadline and must provide outer enforced resource limits and teardown. Use one
thread, with no other child reaper; cancellation handlers only set ``cancelled``.
No package installation, shell expansion, PID-file lookup or restart occurs.
"""
from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field


# One initdb, one foreground postmaster, and fifteen sequential fixture children.
MAX_CHILDREN = 17
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_COMMAND_BYTES = 65536
MAX_DEADLINE_SECONDS = 7200.0
PUMP_SECONDS = 0.05
MAX_PUMP_SECONDS = 0.25
POST_EXIT_DRAIN_SECONDS = 1.0
KILL_REAP_RESERVE_SECONDS = 2.0
CLOSE_SECONDS = 5.0
SETUP_CLEANUP_SECONDS = 2.0
READ_CHUNK_BYTES = 65536


class NativePostgresProcessError(RuntimeError):
    pass


def _number(value: float, name: str) -> float:
    if type(value) not in (int, float):
        raise NativePostgresProcessError(f"{name} must be a finite number")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise NativePostgresProcessError(f"{name} must be a finite number") from exc
    if not math.isfinite(result) or result < 0:
        raise NativePostgresProcessError(f"{name} must be a finite nonnegative number")
    return result


def _deadline(value: float) -> float:
    result = _number(value, "deadline")
    if result - time.monotonic() > MAX_DEADLINE_SECONDS:
        raise NativePostgresProcessError("deadline exceeds the source supervisor ceiling")
    return result


def _text(value: str, name: str) -> int:
    if type(value) is not str or "\0" in value:
        raise NativePostgresProcessError(f"{name} must be exact NUL-free text")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise NativePostgresProcessError(f"{name} must be UTF-8 text") from exc
    if size > MAX_COMMAND_BYTES:
        raise NativePostgresProcessError(f"{name} exceeds its byte bound")
    return size


def _command(argv: tuple[str, ...], env: dict[str, str], cwd: str) -> dict[str, str]:
    if type(argv) is not tuple or not 1 <= len(argv) <= 256:
        raise NativePostgresProcessError("child argv must be a bounded exact tuple")
    total = sum(_text(value, "argument") + 1 for value in argv)
    if not os.path.isabs(argv[0]) or total > MAX_COMMAND_BYTES:
        raise NativePostgresProcessError("child executable must be absolute and argv bounded")
    if type(env) is not dict or len(env) > 128:
        raise NativePostgresProcessError("child environment must be a bounded exact dictionary")
    captured = {}
    for key, value in env.items():
        total += _text(key, "environment key") + _text(value, "environment value") + 2
        if not key or "=" in key:
            raise NativePostgresProcessError("child environment key is invalid")
        captured[key] = value
    if total > MAX_COMMAND_BYTES:
        raise NativePostgresProcessError("child command and environment exceed their byte bound")
    if _text(cwd, "working directory") > 4096 or not os.path.isabs(cwd):
        raise NativePostgresProcessError("child working directory must be bounded and absolute")
    return captured


@dataclass(slots=True, eq=False)
class Child:
    """Retained local observation, not an authenticated execution capability."""

    process: subprocess.Popen[bytes]
    pidfd: int | None = None
    log: bytearray = field(default_factory=bytearray)
    eof: bool = False
    overflow: bool = False
    forced_kill: bool = False
    _lost: bool = False
    _timed_out: bool = False
    _pipe_fd: int | None = None
    _exit_drain_deadline: float | None = None

    @property
    def returncode(self) -> int | None:
        return self.process.returncode

    @property
    def lost(self) -> bool:
        return self._lost

    @property
    def complete_log(self) -> bool:
        return (self.returncode is not None and self.eof and not self.overflow
                and not self._lost and not self._timed_out and not self.forced_kill)


class ProcessSet:
    """At most seventeen total direct children and 136 MiB of retained log prefixes.

    ``stop`` reports only direct-child reaping, not clean database shutdown or
    descendants. ``forced_kill`` and every incompleteness flag are sticky.
    Failed setup is retained and poisons further starts. ``close`` raises if a
    retained child cannot be reaped within its finite cleanup window; it does
    not discard the remaining pidfd or manufacture successful teardown.
    """

    def __init__(self) -> None:
        if (sys.platform != "linux" or not callable(getattr(os, "pidfd_open", None))
                or not callable(getattr(signal, "pidfd_send_signal", None))):
            raise NativePostgresProcessError("native supervisor requires Linux pidfds")
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise NativePostgresProcessError("native supervisor requires default SIGCHLD handling")
        # Establish kernel pidfd support before any child exists. This descriptor
        # is never used for signaling; all signals below target retained children.
        probe = os.pidfd_open(os.getpid(), 0)
        os.close(probe)
        self._selector = selectors.DefaultSelector()
        self._children: list[Child] = []
        self._closed = False
        self._broken = False
        self._selector_closed = False
        self._selector_failed = False
        self.cancelled = False

    @property
    def children(self) -> tuple[Child, ...]:
        return tuple(self._children)

    def _owned(self, child: Child) -> None:
        if type(child) is not Child or not any(child is item for item in self._children):
            raise NativePostgresProcessError("child is not retained by this supervisor")

    def start(self, argv: tuple[str, ...], *, env: dict[str, str], cwd: str) -> Child:
        captured_env = _command(argv, env, cwd)
        if self._closed or self._broken or self.cancelled is not False:
            raise NativePostgresProcessError("native supervisor cannot start another child")
        if len(self._children) >= MAX_CHILDREN:
            raise NativePostgresProcessError("native supervisor direct-child inventory is full")
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise NativePostgresProcessError("native supervisor requires default SIGCHLD handling")
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=captured_env, cwd=cwd,
            start_new_session=True, close_fds=True, shell=False, bufsize=0,
        )
        child = Child(process)
        self._children.append(child)
        try:
            # Never poll/reap before acquiring identity or the setup-failure
            # fallback signal: an unreaped retained PID cannot be reused.
            child.pidfd = os.pidfd_open(process.pid, 0)
            if process.stdout is None:
                raise NativePostgresProcessError("child stdout pipe is absent")
            child._pipe_fd = process.stdout.fileno()
            os.set_blocking(child._pipe_fd, False)
            self._selector.register(child._pipe_fd, selectors.EVENT_READ, child)
            if self.cancelled is not False:
                raise NativePostgresProcessError("native supervisor cancelled during child setup")
        except BaseException:
            self._broken = True
            child._lost = True
            child.forced_kill = True
            try:
                if child.pidfd is None:
                    # The only non-pidfd signal fallback: acquisition failed
                    # after Popen returned this exact still-unreaped child.
                    process.kill()
                else:
                    signal.pidfd_send_signal(child.pidfd, signal.SIGKILL, None, 0)
            except (OSError, ProcessLookupError):
                pass
            self._close_pipe(child)
            end = time.monotonic() + SETUP_CLEANUP_SECONDS
            while child.returncode is None and time.monotonic() < end:
                self.pump(min(PUMP_SECONDS, max(0.0, end - time.monotonic())))
            if child.returncode is None:
                raise NativePostgresProcessError("child setup failed and direct reap is incomplete")
            raise
        return child

    def _close_pipe(self, child: Child) -> None:
        descriptor = child._pipe_fd
        child._pipe_fd = None
        if descriptor is not None and not self._selector_closed:
            try:
                self._selector.unregister(descriptor)
            except (KeyError, OSError, ValueError):
                pass
        if child.process.stdout is not None and not child.process.stdout.closed:
            try:
                child.process.stdout.close()
            except OSError:
                child._lost = True
                self._broken = True

    def _poll(self, now: float) -> None:
        for child in self._children:
            try:
                code = child.process.poll()
            except (OSError, ChildProcessError):
                child._lost = True
                self._broken = True
                continue
            if code is not None and child._exit_drain_deadline is None:
                child._exit_drain_deadline = now + POST_EXIT_DRAIN_SECONDS
            if (child._exit_drain_deadline is not None and not child.eof
                    and now >= child._exit_drain_deadline):
                child._lost = True
                self._close_pipe(child)

    def pump(self, timeout: float = PUMP_SECONDS) -> None:
        interval = _number(timeout, "pump timeout")
        if interval > MAX_PUMP_SECONDS:
            raise NativePostgresProcessError("pump timeout exceeds its source bound")
        if self._selector_closed:
            return
        self._poll(time.monotonic())
        if self._selector_failed:
            # Continue deadline-limited reaping even when no log reader remains
            # usable; no subsequent observation can regain completeness.
            time.sleep(interval)
            self._poll(time.monotonic())
            return
        try:
            ready = self._selector.select(interval)
        except (OSError, ValueError):
            self._broken = True
            self._selector_failed = True
            for child in self._children:
                if child.returncode is None or not child.eof:
                    child._lost = True
                    self._close_pipe(child)
            return
        for key, _ in ready:
            child = key.data
            self._owned(child)
            if child._pipe_fd is None:
                continue
            try:
                chunk = os.read(child._pipe_fd, READ_CHUNK_BYTES)
            except BlockingIOError:
                continue
            except OSError:
                child._lost = True
                self._close_pipe(child)
                continue
            if not chunk:
                child.eof = True
                self._close_pipe(child)
                continue
            remaining = MAX_LOG_BYTES - len(child.log)
            child.log.extend(chunk[:remaining])
            if len(chunk) > remaining:
                child.overflow = True
                child._lost = True
            # Even after overflow, drain/discard bounded chunks so background
            # PostgreSQL cannot wedge another child's pipe or cleanup path.
        self._poll(time.monotonic())

    def wait(self, child: Child, deadline: float, *, must_remain_alive: Child | None = None) -> str:
        self._owned(child)
        end = _deadline(deadline)
        if must_remain_alive is not None:
            self._owned(must_remain_alive)
            if must_remain_alive is child:
                raise NativePostgresProcessError("child cannot be its own liveness prerequisite")
        while True:
            self.pump(0.0)
            if self.cancelled is not False:
                child._lost = True
            if (must_remain_alive is not None
                    and (must_remain_alive.returncode is not None or must_remain_alive._lost
                         or must_remain_alive.overflow or must_remain_alive._timed_out
                         or must_remain_alive.eof)):
                child._lost = True
            if child._lost or child.overflow or child.forced_kill:
                return "lost"
            if child._timed_out or time.monotonic() >= end:
                child._timed_out = True
                return "timeout"
            if child.returncode is not None and child.eof:
                return "exited"
            self.pump(min(PUMP_SECONDS, max(0.0, end - time.monotonic())))

    def _signal(self, child: Child, number: int) -> bool:
        if child.returncode is not None:
            return True
        if child.pidfd is None:
            child._lost = True
            return False
        if number == signal.SIGKILL:
            child.forced_kill = True
            child._lost = True
        try:
            signal.pidfd_send_signal(child.pidfd, number, None, 0)
            return True
        except ProcessLookupError:
            # Exited but not yet polled: only the retained Popen can reap it.
            return True
        except OSError:
            child._lost = True
            return False

    def stop(self, child: Child, *, initial_signal: int, deadline: float) -> bool:
        self._owned(child)
        end = _deadline(deadline)
        if type(initial_signal) not in (int, signal.Signals) or initial_signal not in (signal.SIGINT, signal.SIGTERM):
            raise NativePostgresProcessError("initial stop signal must be SIGINT or SIGTERM")
        # Cancellation never disables teardown or draining other children's logs.
        self._signal(child, initial_signal)
        self.pump(0.0)
        now = time.monotonic()
        # PostgreSQL may need most of its caller-owned stop budget to perform a
        # real fast-shutdown checkpoint. Keep the final two seconds for forced
        # termination/reap rather than imposing a one-second database grace.
        grace = max(now, end - KILL_REAP_RESERVE_SECONDS)
        while child.returncode is None and time.monotonic() < grace:
            self.pump(min(PUMP_SECONDS, max(0.0, grace - time.monotonic())))
        if child.returncode is None:
            self._signal(child, signal.SIGKILL)
        while time.monotonic() < end:
            self.pump(0.0)
            if child.returncode is not None and (child.eof or child._pipe_fd is None):
                break
            self.pump(min(PUMP_SECONDS, max(0.0, end - time.monotonic())))
        self._poll(time.monotonic())
        if not child.eof:
            child._lost = True
            self._close_pipe(child)
        return child.returncode is not None

    def close(self) -> None:
        self._closed = True
        if self._selector_closed:
            return
        end = time.monotonic() + CLOSE_SECONDS
        for child in self._children:
            if child.returncode is None:
                self._signal(child, signal.SIGTERM)
        for child in self._children:
            self.stop(child, initial_signal=signal.SIGTERM, deadline=end)
        incomplete = False
        close_error = False
        for child in self._children:
            self._close_pipe(child)
            if child.returncode is None:
                child._lost = True
                incomplete = True
            elif child.pidfd is not None:
                descriptor = child.pidfd
                child.pidfd = None
                try:
                    os.close(descriptor)
                except OSError:
                    # A failed close must not be retried on a potentially
                    # reused descriptor; the execution remains incomplete.
                    child._lost = True
                    close_error = True
        if incomplete:
            raise NativePostgresProcessError("native direct-child cleanup remains incomplete")
        self._selector_closed = True
        try:
            self._selector.close()
        except OSError:
            close_error = True
        if close_error:
            raise NativePostgresProcessError("native supervisor descriptor cleanup is uncertain")
