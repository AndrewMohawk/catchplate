"""One retained, inventory-admitted cold authority child and its fixed dialogue.

Only --run-native-genesis-rendezvous is launched. Requests remain observations,
not approvals or reconstructed owners. The caller supplies independently
approved originals; terminal bytes become available only after actual cleanup,
successful exit and consuming waitid on the same retained PIDFD.
"""
from __future__ import annotations

import array
import copy
import fcntl
import os
import select
import signal
import stat
import subprocess
import termios
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifact
from scripts.authority import native_pilot_authority_io as public_io
from serverware import native_pilot_genesis_authority_channel as replies
from serverware import native_pilot_genesis_core_profile as core
from serverware import native_pilot_genesis_execution_protocol as wire
from serverware import native_pilot_genesis_handoff_listener as listener
from serverware import native_pilot_genesis_jobs as jobs
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_pilot_genesis_rendezvous_profile as rendezvous
from serverware import native_shadow_driver_bootstrap as bootstrap
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_coordinator_process import _Runtime
from serverware.native_pilot_operator_channel import MAX_TOTAL
from serverware.native_shadow_proof_cohort_control import _Original

p = wire.p
_TOKEN, _USED, _LIVE = object(), False, None
_JOBS = jobs.catalogue(handoff=True)
_RESULT_MAX = 4096
_REQUEST_FIELDS = ("apiVersion", "sequence", "job", "deadlineBoottimeNs", "observation", "previousResult")


def sender_value(raw, *, configuration_raw, identity, boot):
    """Pure literal association; the actual child owner supplies identity."""
    value = rendezvous._document(raw, rendezvous.MAX_SENDER, rendezvous.SENDER_REQUEST_FIELDS)
    config = rendezvous._configuration(configuration_raw)
    p.require(value["apiVersion"] == rendezvous.SENDER_REQUEST_API
        and type(value["sequence"]) is int and value["sequence"] == 0
        and value["configurationSha256"] == p.sha(configuration_raw)
        and value["deadlineBoottimeNs"] == config["window"]["startupDeadlineBoottimeNs"]
        and type(value["expiresAtUnixNanos"]) is int
        and value["expiresAtUnixNanos"] == config["expiresAtUnixNanos"])
    observed_raw = rendezvous._original(value["listenerOriginal"], rendezvous.MAX_SENDER)
    observed = rendezvous._document(observed_raw, rendezvous.MAX_SENDER, rendezvous.SENDER_FIELDS)
    p.require(observed["apiVersion"] == rendezvous.SENDER_API and observed["endpoint"] == rendezvous.ENDPOINT
        and observed["configurationSha256"] == value["configurationSha256"]
        and value["listenerSha256"] == p.sha(observed_raw)
        and type(observed["processId"]) is int and observed["processId"] == identity["pid"]
        and type(observed["processStartTimeTicks"]) is int
        and observed["processStartTimeTicks"] == identity["startTimeTicks"]
        and tuple(observed[name] for name in wire.endpoints.WINDOW[:3]) == boot)
    rendezvous._socket(observed["socket"], named=True)
    return value


def job_value(raw, *, index, upper_deadline):
    p.require(type(index) is int and 0 <= index < len(_JOBS))
    value = p.fields(p.document(raw, wire.MAX_REQUEST - 1), _REQUEST_FIELDS)
    p.require(p.canonical(value) == raw and value["apiVersion"] == wire.HANDOFF_REQUEST_API
        and type(value["sequence"]) is int and value["sequence"] == index + 1
        and value["job"] == _JOBS[index].name and p.ns(value["deadlineBoottimeNs"]) <= upper_deadline)
    observation = value["observation"]
    p.require(type(observation) is dict and set(observation) <= set(jobs.OBSERVATIONS) | {"core.observation"})
    for text in observation.values():
        p.require(type(text) is str and text.isascii() and 0 < len(text) <= wire.MAX_REQUEST)
    if index == 0:
        p.require(value["previousResult"] is None)
    else:
        previous = p.fields(value["previousResult"], ("job", "resultOriginal", "resultSha256"))
        text = previous["resultOriginal"]
        p.require(previous["job"] == _JOBS[index - 1].name and type(text) is str
            and text.isascii() and 0 < len(text) <= wire.MAX_REQUEST
            and p.sha(text.encode("ascii")) == p.digest(previous["resultSha256"]))
    return value


def terminal_value(raw, *, observation_raw):
    value = p.fields(p.document(raw, wire.MAX_REQUEST - 1), ("apiVersion", "status", "jobsCompleted",
        "bundleOriginal", "bundleSha256", "pilotAcceptanceVerified", "productionReleaseEligible",
        "operationalAdoptionVerified"))
    p.require(p.canonical(value) == raw and value["apiVersion"] == replies.HANDOFF_TERMINAL_API
        and value["status"] == "cold-core-custody-acknowledged"
        and type(value["jobsCompleted"]) is int and value["jobsCompleted"] == len(_JOBS)
        and value["pilotAcceptanceVerified"] is False and value["productionReleaseEligible"] is False
        and value["operationalAdoptionVerified"] is False)
    text = value["bundleOriginal"]
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= core.MAX_BUNDLE)
    bundle = text.encode("ascii")
    p.require(p.sha(bundle) == p.digest(value["bundleSha256"]))
    core.observation(observation_raw, bundle)
    return value, bundle


class GenesisProcessError(ValueError):
    def __init__(self, owner):
        super().__init__("cold authority process refused; actual owner retained; no retry")
        self.owner = owner


class GenesisRequest:
    """Only this process owner's actual pipe read mints a request token."""
    def __init__(self, token, kind, raw, value):
        p.require(token is _TOKEN)
        self._kind, self._raw, self._value = kind, raw, copy.deepcopy(value)

    @property
    def raw(self): return self._raw

    @property
    def value(self): return copy.deepcopy(self._value)

    @property
    def job(self): return self._value.get("job")

    @property
    def sequence(self): return self._value["sequence"]

    @property
    def deadline_boottime_ns(self): return p.ns(self._value["deadlineBoottimeNs"])


class GenesisAuthorityProcess:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._runtime, self._sources, self._keys, self._named = _Runtime(), [], {}, []
        self._configuration = self._execution = self._value = None
        self._child = self._pidfd = self._child_start = self._pidfd_identity = None
        self._pipes = {}
        self._sender = self._rendezvous = self._pending = None
        self._observations, self._index, self._total = {}, 0, 0
        self._stderr, self._stdout_extra = bytearray(), bytearray()
        self._stderr_eof = self._stdout_eof = False
        self._bundle = self._terminal = self._result = None
        self._core_deadline = self._core_expiry = None
        self._prepared = self._started = self._rendezvous_replied = self._failed = False
        self._finished = self._finish_attempted = self._reaped = self._reap_attempted = False
        self._closed = self._close_attempted = self._signaled = False
        self._acquisition_uncertain = False

    @classmethod
    def prepare(cls, *, supervisor_inventory_fd, supervisor_inventory_sha256,
                listener_configuration_fd, listener_configuration_sha256, authority_key_fds):
        global _USED, _LIVE
        p.require(cls is GenesisAuthorityProcess and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner._origin()
            p.require(supervisor_inventory_fd != listener_configuration_fd)
            for fd, maximum, digest in ((listener_configuration_fd, rendezvous.MAX_CONFIGURATION,
                    listener_configuration_sha256), (supervisor_inventory_fd, artifact.MAX_MANIFEST_BYTES,
                    supervisor_inventory_sha256)):
                with io.owning():
                    source = io.PublicInput.__new__(io.PublicInput)
                    source.fd = None
                    owner._sources.append(source)
                    try:
                        io.PublicInput.__init__(source, fd, maximum, digest)
                    except BaseException:
                        # The constructor closes on refusal. If that close
                        # failed, the retained number has unknown ownership;
                        # another close must never be treated as recovery.
                        owner._acquisition_uncertain = source.fd is not None
                        raise
                if len(owner._sources) == 1:
                    owner._configuration = source
                    owner._clock()
                    owner._value = listener.configuration(source.raw, boot=owner._boot,
                        now_boottime_ns=owner._last, now_unix_ns=owner._wall, rendezvous=True)
                owner._clock()
            p.require(owner._sources[0].identity[:2] != owner._sources[1].identity[:2])
            with io.owning():
                owner._runtime.admit(owner._sources[1].raw, supervisor=True)
            owner._clock()
            p.fields(authority_key_fds, jobs.KEY_PURPOSES)
            for purpose in jobs.KEY_PURPOSES:
                fd = authority_key_fds[purpose]
                p.require(type(fd) is int and fd not in (supervisor_inventory_fd, listener_configuration_fd))
                expected = public_io._input(fd, 32, private=True)
                p.require(expected[6] == 32)
                with io.owning():
                    held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128)
                    owner._keys[purpose] = (held, expected)
                p.require(public_io._input(held, 32, private=True) == expected)
                owner._clock()  # No private key bytes are read by this parent.
            owner._prepared = True
            owner.check_waiting()
            return owner
        except BaseException as error:
            owner._failed = True
            raise GenesisProcessError(owner) from error

    def _origin(self):
        public_io._process()
        p.require(_LIVE is self and not self._closed and os.getpid() == self._pid
            and originals._start() == self._start and originals._boot() == self._boot
            and threading.current_thread() is threading.main_thread() and len(os.listdir("/proc/self/task")) == 1)

    def _upper(self):
        if self._value is None: return None
        lifetime = self.deadline_boottime_ns
        if not self._rendezvous_replied:
            result = min(self.startup_deadline_boottime_ns, lifetime - wire.RESERVE)
        elif self._index < len(_JOBS):
            name = _JOBS[self._index].name
            result = (lifetime if name in ("cleanup", "handoff-cold-core") else lifetime - wire.RESERVE
                if name in ("coordinator-finish", "acquire-cold-core") else min(self.startup_deadline_boottime_ns,
                    lifetime - wire.RESERVE))
        else:
            result = lifetime
        if self._pending is not None:
            result = min(result, self._pending.deadline_boottime_ns)
        return min(result, self._core_deadline) if self._core_deadline is not None else result

    def _clock(self, deadline=None):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall)
        if self._value is not None:
            upper = self._upper() if deadline is None else min(deadline, self.deadline_boottime_ns)
            if self._core_deadline is not None: upper = min(upper, self._core_deadline)
            if self._pending is not None: upper = min(upper, self._pending.deadline_boottime_ns)
            expiry = self.expires_at_unix_ns
            if self._core_expiry is not None: expiry = min(expiry, self._core_expiry)
            p.require(p.ns(self._value["window"]["issuedAtBoottimeNs"]) <= now < upper and wall < expiry)
        self._last, self._wall = now, wall
        return now

    def _capabilities(self, *, full=False):
        self._origin()
        for source in self._sources:
            source.check() if full else source.check_identity()
        for fd, identity in self._keys.values():
            p.require(public_io._input(fd, 32, private=True) == identity)
        for source in self._named:
            source.check() if full else io.original_identity(source)

    @staticmethod
    def _pipe_identity(fd):
        info = os.fstat(fd)
        p.require(stat.S_ISFIFO(info.st_mode) and info.st_uid == info.st_gid == 0)
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink

    def _child_check(self, *, terminal=False):
        p.require(self._child is not None and self._pidfd is not None and self._child_start is not None)
        p.require(originals._identity(os.fstat(self._pidfd)) == self._pidfd_identity
            and not os.get_inheritable(self._pidfd))
        if not self._reaped:
            p.require(bootstrap.mechanics._pidfd_pid(self._pidfd) == self._child.pid
                and bootstrap.mechanics._process(self._child.pid) == (self._pid, self._child_start))
            p.require(terminal or not select.select([self._pidfd], [], [], 0)[0])
        for name, (fd, identity, access) in self._pipes.items():
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            p.require(getattr(self._child, name).fileno() == fd and self._pipe_identity(fd) == identity
                and flags & os.O_ACCMODE == access and flags & os.O_NONBLOCK
                and not flags & os.O_PATH and not os.get_inheritable(fd))

    def check_waiting(self):
        p.require(self._prepared and not self._failed and not self._close_attempted)
        self._clock(); self._capabilities()
        if self._child is not None:
            # After the last positive reply the fixed child can finish before
            # the parent next runs. Terminal is observable, not yet accepted:
            # finish still requires exact output, exit and consuming reap.
            self._child_check(terminal=self._finished or self._index == len(_JOBS))
        self._clock()

    def check_retained(self):
        """Source custody after actual finish/reap, not another admission window."""
        p.require(self._finished and self._reaped and not self._close_attempted)
        self._capabilities(full=True); self._child_check(terminal=True); self._origin()

    def listener_configuration_original(self):
        self.check_waiting()
        return bytes(self._configuration.raw)

    def configuration_original(self):
        self.check_waiting(); p.require(self._rendezvous_replied and self._execution is not None)
        return bytes(self._execution.raw)

    @property
    def window(self): return copy.deepcopy(self._value["window"])

    @property
    def startup_deadline_boottime_ns(self): return p.ns(self._value["window"]["startupDeadlineBoottimeNs"])

    @property
    def deadline_boottime_ns(self): return p.ns(self._value["window"]["lifetimeDeadlineBoottimeNs"])

    @property
    def expires_at_unix_ns(self): return self._value["expiresAtUnixNanos"]

    @property
    def finished(self): return self._finished

    def identity(self):
        self.check_waiting(); p.require(self._child is not None)
        return dict(pid=self._child.pid, uid=0, gid=0, startTimeTicks=self._child_start, parentPid=self._pid)

    def start(self):
        try:
            self.check_waiting(); p.require(not self._started)
            self._started = True
            self._runtime.check(); self.check_waiting()
            inventory = self._sources[1]
            command = artifact.AUTHORITY_COMMAND[:-1] + ["--run-native-genesis-rendezvous",
                "--supervisor-inventory-fd", str(inventory.fd), "--supervisor-inventory-sha256", p.sha(inventory.raw),
                "--genesis-listener-configuration-fd", str(self._configuration.fd),
                "--genesis-listener-configuration-sha256", p.sha(self._configuration.raw)]
            for purpose in jobs.KEY_PURPOSES:
                command += ["--authority-key", purpose + "=" + str(self._keys[purpose][0])]
            inherited = (inventory.fd, self._configuration.fd) + tuple(row[0] for row in self._keys.values())
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, io.CANCELLATION)
            retained = False
            try:
                self._child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, bufsize=0, close_fds=True, pass_fds=inherited,
                    env={}, cwd="/", restore_signals=True)
                self._pidfd = os.pidfd_open(self._child.pid, 0)
                self._pidfd_identity = originals._identity(os.fstat(self._pidfd))
                os.set_inheritable(self._pidfd, False)
                parent, self._child_start = bootstrap.mechanics._process(self._child.pid)
                p.require(parent == self._pid and bootstrap.mechanics._pidfd_pid(self._pidfd) == self._child.pid)
                for name, access in (("stdin", os.O_WRONLY), ("stdout", os.O_RDONLY), ("stderr", os.O_RDONLY)):
                    fd = getattr(self._child, name).fileno()
                    os.set_inheritable(fd, False); os.set_blocking(fd, False)
                    self._pipes[name] = (fd, self._pipe_identity(fd), access)
                retained = True
                self.check_waiting()
            finally:
                if retained or self._child is None:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            raw = self._read_frame(rendezvous.MAX_SENDER, self._upper())
            value = sender_value(raw, configuration_raw=self._configuration.raw, identity=self.identity(), boot=self._boot)
            self._sender = GenesisRequest(_TOKEN, "sender", raw, value)
            self.check_waiting()
            return self._sender
        except BaseException as error:
            self._failed = True
            raise GenesisProcessError(self) from error

    def _drain_stderr(self):
        if self._stderr_eof: return
        fd = self._pipes["stderr"][0]
        while True:
            try: raw = os.read(fd, min(4096, _RESULT_MAX + 1 - len(self._stderr)))
            except InterruptedError: continue
            except BlockingIOError: return
            if not raw:
                self._stderr_eof = True
                return
            self._stderr.extend(raw); p.require(len(self._stderr) <= _RESULT_MAX)

    def _io_check(self, deadline, *, terminal=False):
        self._clock(deadline); self._capabilities(); self._child_check(terminal=terminal)
        self._drain_stderr(); self._clock(deadline)

    def _wait(self, reading, deadline, *, terminal=False):
        while True:
            self._io_check(deadline, terminal=terminal)
            expiry = self.expires_at_unix_ns if self._core_expiry is None else min(self.expires_at_unix_ns, self._core_expiry)
            duration = min(0.05, (deadline - self._last) / 1_000_000_000, (expiry - self._wall) / 1_000_000_000)
            p.require(duration > 0)
            watched = [self._pidfd, self._pipes["stderr"][0]]
            if reading: watched.append(self._pipes["stdout"][0])
            try:
                ready, writable, _ = select.select(watched, [] if reading else [self._pipes["stdin"][0]], [], duration)
            except InterruptedError: continue
            self._io_check(deadline, terminal=terminal)
            if (reading and self._pipes["stdout"][0] in ready) or (not reading and writable): return

    def _read_frame(self, maximum, deadline, *, terminal=False):
        raw = bytearray()
        while True:
            self._wait(True, deadline, terminal=terminal)
            try: part = os.read(self._pipes["stdout"][0], min(4096, maximum + 1 - len(raw)))
            except (InterruptedError, BlockingIOError): continue
            if not part:
                self._stdout_eof = True
                raise ValueError("cold authority frame missing")
            self._total += len(part)
            p.require(self._total <= MAX_TOTAL and all(byte < 128 for byte in part))
            raw.extend(part)
            if b"\n" in raw:
                p.require(raw.endswith(b"\n") and raw.count(b"\n") == 1 and 1 < len(raw) <= maximum + 1)
                pending = array.array("i", [0])
                fcntl.ioctl(self._pipes["stdout"][0], termios.FIONREAD, pending, True)
                p.require(pending[0] == 0)
                self._io_check(deadline, terminal=terminal)
                return bytes(raw[:-1])
            p.require(len(raw) <= maximum)

    def receive_rendezvous(self):
        try:
            self.check_waiting()
            p.require(self._sender is not None and self._rendezvous is None and self._pending is None)
            raw = self._read_frame(rendezvous.MAX_REQUEST, self._upper())
            value = rendezvous.verify_request(raw)
            p.require(value["senderRequestOriginal"].encode("ascii") == self._sender.raw
                and value["configurationOriginal"].encode("ascii") == self._configuration.raw)
            self._rendezvous = self._pending = GenesisRequest(_TOKEN, "rendezvous", raw, value)
            self.check_waiting()
            return self._rendezvous
        except BaseException as error:
            self._failed = True
            raise GenesisProcessError(self) from error

    def _named_original(self, path, maximum, digest):
        with io.owning():
            source = _Original.__new__(_Original)
            source.fds, source.parents = [], []
            self._named.append(source)
            try:
                _Original.__init__(source, path, maximum, digest, mode=0o400)
            except BaseException:
                # _Original.close clears only after every close succeeds.
                # Any remaining list after constructor failure may contain a
                # consumed descriptor; retain it without retrying cleanup.
                self._acquisition_uncertain = bool(source.fds)
                raise
        return source

    def _send(self, raw, deadline, commit):
        wire_raw = raw + b"\n"
        p.require(type(raw) is bytes and len(wire_raw) <= 4096 and self._total + len(wire_raw) <= MAX_TOTAL)
        offset = 0
        while offset < len(wire_raw):
            self._wait(False, deadline)
            with io.owning():
                try: count = os.write(self._pipes["stdin"][0], wire_raw[offset:])
                except (InterruptedError, BlockingIOError): continue
                p.require(0 < count <= len(wire_raw) - offset)
                offset += count; self._total += count
                if offset == len(wire_raw): commit()
                self._io_check(deadline, terminal=(self._index == len(_JOBS)))

    def reply_rendezvous(self, raw):
        try:
            self.check_waiting()
            p.require(self._pending is self._rendezvous and self._rendezvous is not None and not self._rendezvous_replied)
            accepted = rendezvous.reply(raw, self._rendezvous.raw)
            source = self._named_original(rendezvous.INPUT_PATH, rendezvous.MAX_INPUT, accepted["inputSha256"])
            approval = self._named_original(rendezvous.APPROVAL_PATH, rendezvous.MAX_APPROVAL, accepted["approvalSha256"])
            rendezvous.approval(approval.raw, request_raw=self._rendezvous.raw, input_sha256=accepted["inputSha256"])
            self.check_waiting()
            rendezvous.execution(source.raw, self._rendezvous.raw, boot=self._boot,
                now_boottime_ns=self._last, now_unix_ns=self._wall)
            source.check(); approval.check(); self.check_waiting()
            deadline = self._pending.deadline_boottime_ns

            def committed():
                self._execution = source
                self._rendezvous_replied, self._pending = True, None

            self._send(raw, min(deadline, self._upper()), committed)
        except BaseException as error:
            self._failed = True
            raise GenesisProcessError(self) from error

    def receive_job(self):
        try:
            self.check_waiting()
            p.require(self._rendezvous_replied and self._pending is None and self._index < len(_JOBS))
            value_raw = self._read_frame(wire.MAX_REQUEST - 1, self._upper())
            value = job_value(value_raw, index=self._index, upper_deadline=self._upper())
            for name, text in value["observation"].items():
                p.require(name not in self._observations or self._observations[name] == text.encode("ascii"))
                self._observations[name] = text.encode("ascii")
            if "core.observation" in self._observations:
                observed = core.observation(self._observations["core.observation"])
                self._core_deadline, self._core_expiry = p.ns(observed["deadlineBoottimeNs"]), observed["expiresAtUnixNanos"]
            self._pending = GenesisRequest(_TOKEN, "job", value_raw, value)
            self.check_waiting()
            return self._pending
        except BaseException as error:
            self._failed = True
            raise GenesisProcessError(self) from error

    def reply_job(self, raw):
        try:
            self.check_waiting(); p.require(self._pending is not None and self._pending._kind == "job")
            value = replies.reply(raw, self._pending.raw)
            p.require(p.canonical(value) == raw)
            selected = _JOBS[self._index]
            input_path, approval_path = replies.paths(selected.name, handoff=True)
            source = self._named_original(input_path, selected.maximum, value["inputSha256"])
            approval = self._named_original(approval_path, 8192, value["approvalSha256"])
            wire.approval(approval.raw, request_raw=self._pending.raw, input_sha256=value["inputSha256"])
            source.check(); approval.check(); self.check_waiting()
            deadline = self._pending.deadline_boottime_ns

            def committed():
                self._index += 1
                self._pending = None

            self._send(raw, min(deadline, self._upper()), committed)
        except BaseException as error:
            self._failed = True
            raise GenesisProcessError(self) from error

    def _wait_exit(self, deadline):
        while True:
            self._io_check(deadline, terminal=True)
            try: raw = os.read(self._pipes["stdout"][0], 4096)
            except (InterruptedError, BlockingIOError): raw = None
            if raw is not None:
                if not raw: self._stdout_eof = True
                else:
                    self._stdout_extra.extend(raw)
                    p.require(len(self._stdout_extra) <= wire.MAX_REQUEST)
            if select.select([self._pidfd], [], [], 0)[0]:
                observed = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                p.require(observed is not None and observed.si_pid == self._child.pid and observed.si_code == os.CLD_EXITED)
                self._drain_stderr()
                if self._stdout_eof and self._stderr_eof: return observed
            self._clock(deadline)
            expiry = self.expires_at_unix_ns if self._core_expiry is None else min(self.expires_at_unix_ns, self._core_expiry)
            ceiling = deadline if self._core_deadline is None else min(deadline, self._core_deadline)
            if self._pending is not None: ceiling = min(ceiling, self._pending.deadline_boottime_ns)
            remaining = min(ceiling - self._last, expiry - self._wall)
            p.require(remaining > 0)
            try: select.select([self._pidfd, self._pipes["stdout"][0], self._pipes["stderr"][0]], [], [], min(0.01, remaining / 1_000_000_000))
            except InterruptedError: continue

    def _status(self, observed, *, successful):
        p.require(self._stderr_eof and self._stderr.endswith(b"\n") and self._stderr.count(b"\n") == 1)
        result = p.fields(p.document(bytes(self._stderr[:-1]), _RESULT_MAX), ("apiVersion", "status", "phase",
            "jobsCompleted", "bundleSha256", "pilotAcceptanceVerified", "productionReleaseEligible"))
        p.require(result["apiVersion"] == "serverware.nativePilotGenesisAuthorityResult/v1"
            and result["pilotAcceptanceVerified"] is False and result["productionReleaseEligible"] is False
            and type(result["jobsCompleted"]) is int and 0 <= result["jobsCompleted"] <= self._index
            and result["phase"] in ("open", "listener-approval", *(job.name for job in _JOBS)))
        if successful:
            p.require(observed.si_status == 0 and result["status"] == "cold-core-custody-acknowledged"
                and result["jobsCompleted"] == len(_JOBS) == self._index
                and result["phase"] == _JOBS[-1].name and result["bundleSha256"] == p.sha(self._bundle)
                and not self._stdout_extra)
        else:
            p.require(observed.si_status == 1 and result["status"] in ("failed-cleanup-complete", "not-started"))
            if result["status"] == "not-started": p.require(result["jobsCompleted"] == 0)
            if result["bundleSha256"] is not None: p.digest(result["bundleSha256"])
        return result

    def _reap(self, observed, deadline):
        p.require(not self._reap_attempted)
        self._clock(deadline)
        with io.owning():
            self._reap_attempted = True
            actual = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED)
            p.require(actual is not None and (actual.si_pid, actual.si_code, actual.si_status)
                == (observed.si_pid, observed.si_code, observed.si_status))
            self._child.returncode = actual.si_status
            self._reaped = True
        self._clock(deadline)

    def finish(self):
        if self._finished:
            self.check_waiting()
            return bytes(self._bundle)
        try:
            self.check_waiting()
            p.require(not self._finish_attempted and self._pending is None and self._index == len(_JOBS))
            self._finish_attempted = True
            deadline = self._upper()
            raw = self._read_frame(wire.MAX_REQUEST - 1, deadline, terminal=True)
            self._terminal, self._bundle = terminal_value(raw, observation_raw=self._observations["core.observation"])
            observed = self._wait_exit(deadline)
            self._result = self._status(observed, successful=True)
            self._runtime.check(); self._io_check(deadline, terminal=True)
            self._reap(observed, deadline)
            self._finished = True
            return bytes(self._bundle)
        except BaseException as error:
            self._failed = True
            raise GenesisProcessError(self) from error

    def close(self, *, cancel=False):
        global _LIVE
        if self._closed: return dict(status="closed", completed=self._finished)
        try:
            self._origin(); p.require(type(cancel) is bool and not self._close_attempted
                and not self._acquisition_uncertain)
            self._close_attempted = True
            if self._child is not None and not self._reaped:
                p.require(self._pidfd is not None and not self._reap_attempted)
                self._child_check(terminal=True)
                deadline = min(self.deadline_boottime_ns, originals._clock() + wire.RESERVE)
                self._clock(deadline)
                p.require(cancel or self._failed)
                if not select.select([self._pidfd], [], [], 0)[0]:
                    self._signaled = True
                    try: signal.pidfd_send_signal(self._pidfd, signal.SIGTERM, None, 0)
                    except ProcessLookupError: pass
                observed = self._wait_exit(deadline)
                self._result = self._status(observed, successful=False)
                self._reap(observed, deadline)
            with io.owning():
                if self._child is not None:
                    for name in ("stdin", "stdout", "stderr"):
                        stream = getattr(self._child, name)
                        if stream is not None: stream.close()
                if self._pidfd is not None:
                    fd, self._pidfd = self._pidfd, None
                    os.close(fd)
                for original in self._named:
                    while original.fds: os.close(original.fds.pop())
                self._named.clear()
                while self._keys: os.close(self._keys.popitem()[1][0])
                while self._runtime.directories: os.close(self._runtime.directories.popitem()[1])
                while self._sources: self._sources.pop().close()
                self._closed = True
                _LIVE = None
            return dict(status="closed", completed=self._finished)
        except BaseException as error:
            self._failed = True
            raise GenesisProcessError(self) from error
