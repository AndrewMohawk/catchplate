"""Own the fixed authority coordinator; never supply an approval decision.

Both installed runtimes and all purpose-key capabilities are independently
provided. Public key bindings describe those capabilities, not permission to
use them. Child results are observations until purpose composers verify their
signatures. Unknown cleanup retains this actual child and all owned handles.
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

from cryptography.hazmat.primitives import serialization

from scripts import native_pilot_runtime_artifacts as artifact
from scripts.authority import native_pilot_authority_io as io
from serverware import native_pilot_coordinator_channel as pipe
from serverware import native_pilot_window_authority as window_authority
from serverware import native_pilot_interactive as interactive
from serverware import native_shadow_driver_bootstrap as bootstrap
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_coordinator_process import _Runtime, _clock, _structural, ProcessPreparationError
from serverware.native_pilot_operator_channel import MAX_FRAME, MAX_TOTAL, STAGES
from serverware.native_pilot_phase_execution import APPROVAL_ROOT, JOBS, KEY_PURPOSES, MAX_RETAINED_BYTES
from serverware.native_pilot_scope_authority import PRODUCTION_FIELDS
from serverware.native_shadow_proof_cohort_control import _Original

p = bootstrap.p
_TOKEN = object()
_LIVE = None
_USED = False
_ORDER = tuple((phase, index + 1, job) for phase in STAGES for index, job in enumerate(JOBS[phase]))
_REQUEST_FIELDS = ("apiVersion", "sequence", "conductorSequence", "conductorRequestSha256", "phase",
    "jobIndex", "job", "deadlineBoottimeNs", "conductorRequest", "previousResult")
_REPLY_FIELDS = ("apiVersion", "sequence", "conductorSequence", "conductorRequestSha256", "phase",
    "jobIndex", "job", "requestSha256", "approvalSha256", "inputSha256")
_RESULT_MAX = 4096


def _require(value):
    if not value:
        raise ValueError("native pilot supervisor process refused")


def _same(first, second):
    _require(p.canonical(first) == p.canonical(second))


class JobRequest:
    """Only this owner's real pipe receive constructs a pending job token."""

    def __init__(self, token, raw, value):
        _require(token is _TOKEN)
        self._raw, self._value = raw, value

    @property
    def raw(self):
        return self._raw

    @property
    def value(self):
        return copy.deepcopy(self._value)

    @property
    def phase(self):
        return self._value["phase"]

    @property
    def sequence(self):
        return self._value["sequence"]

    @property
    def job_index(self):
        return self._value["jobIndex"]

    @property
    def job(self):
        return self._value["job"]

    @property
    def deadline_boottime_ns(self):
        return p.ns(self._value["deadlineBoottimeNs"])

    @property
    def expires_at_unix_ns(self):
        return p.ns(self._value["expiresAtUnixNanos"]) if "expiresAtUnixNanos" in self._value else None


class _JobChannel(pipe.PipeChannel):
    """Reuse bounded pipe mechanics, not the distinct conductor protocol."""

    def __init__(self, owner):
        _require(type(owner) is AuthorityCoordinatorProcess and owner._child is not None)
        self._owner = owner
        self._reader, self._writer = owner._child.stdout.fileno(), owner._child.stdin.fileno()
        self._ids = (pipe._identity(self._reader), pipe._identity(self._writer))
        _require(self._ids[0][:2] != self._ids[1][:2])
        for fd, access in ((self._reader, os.O_RDONLY), (self._writer, os.O_WRONLY)):
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            _require(flags & os.O_ACCMODE == access and not flags & os.O_PATH)
            os.set_inheritable(fd, False)
            os.set_blocking(fd, False)
        self._index = self._total = 0
        self._pending = None
        self._poisoned = False

    def receive(self, upper_deadline):
        try:
            _require(self._pending is None and self._index < len(self._owner._order))
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
                        value = p.fields(p.document(bytes(raw), MAX_FRAME - 1), _REQUEST_FIELDS +
                            (("expiresAtUnixNanos",) if self._owner._adopted else ()))
                        self._owner._admit_request(value, self._index, upper_deadline)
                        self._check(p.ns(value["deadlineBoottimeNs"]))
                        self._pending = JobRequest(_TOKEN, bytes(raw), value)
                        return self._pending
                    _require(byte[0] < 128 and len(raw) + 1 < MAX_FRAME)
                    raw.extend(byte)
        except BaseException:
            self._poisoned = True
            raise

    def _reply_value(self, request, reply):
        _require(type(request) is JobRequest and self._pending is request)
        value = p.fields(reply, _REPLY_FIELDS)
        _require(value["apiVersion"] == ("serverware.nativePilotAuthorityJobReply/v2" if self._owner._adopted else
            "serverware.nativePilotAuthorityJobReply/v1")
            and value["requestSha256"] == p.sha(request.raw))
        for name in ("sequence", "conductorSequence", "conductorRequestSha256", "phase", "jobIndex", "job"):
            _same(value[name], request._value[name])
        p.digest(value["approvalSha256"]); p.digest(value["inputSha256"])
        return value

    def reply(self, request, reply):
        try:
            value = self._reply_value(request, reply)
            deadline = request.deadline_boottime_ns
            self._check(deadline)
            wire = p.canonical(value) + b"\n"
            _require(len(wire) <= 4096 and len(wire) <= MAX_TOTAL - self._total)
            offset = 0
            while offset < len(wire):
                self._wait(False, deadline)
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
                try:
                    try:
                        count = os.write(self._writer, memoryview(wire)[offset:offset + 65536])
                    except (InterruptedError, BlockingIOError):
                        continue
                    self._count(count); offset += count
                    self._check(deadline, allow_terminal=(offset == len(wire) and self._index == len(self._owner._order) - 1))
                    if offset == len(wire):
                        self._owner._replies[(request.phase, request.job)] = copy.deepcopy(value)
                        if self._owner._interactive_pending is not None:
                            _require((request.phase, request.job) == ("shutdown", "stop"))
                            action, handoff, selected_deadline = self._owner._interactive_pending
                            self._owner._interactive_action = action
                            self._owner._interactive_origin = handoff
                            self._owner._interactive_deadline = selected_deadline
                            self._owner._interactive_pending = None
                        self._pending = None
                        self._index += 1
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        except BaseException:
            self._poisoned = True
            raise


class AuthorityCoordinatorProcess:
    def __init__(self, token):
        _require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._runtimes = (_Runtime(), _Runtime())
        self._inventories, self._keys, self._originals = [], {}, []
        self._bootstrap, self._conductors, self._results, self._replies = {}, {}, {}, {}
        self._approved_inputs, self._approved_bytes = {}, 0
        self._child = self._pidfd = self._channel = None
        self._started = self._closed = self._close_attempted = self._signaled = False
        self._bootstrap_attempted = self._bootstrap_prepared = False
        self._last_clock = _clock()
        self._stderr, self._stderr_eof = bytearray(), False
        self._result = self._bindings = None
        self._interactive_action = self._interactive_origin = self._interactive_deadline = None
        self._interactive_pending = None
        self._interval_wait_attempted = self._interval_wait_done = False
        self._adopted = False
        self._intake = self._epoch_limit = self._core_expiry = None
        self._last_wall = time.time_ns()
        self._jobs, self._order, self._key_purposes, self._approval_root = JOBS, _ORDER, KEY_PURPOSES, APPROVAL_ROOT

    @classmethod
    def prepare(cls, *, conductor_inventory_fd, conductor_inventory_sha256,
                authority_inventory_fd, authority_inventory_sha256, authority_key_fds):
        return cls._prepare(conductor_inventory_fd=conductor_inventory_fd,
            conductor_inventory_sha256=conductor_inventory_sha256, authority_inventory_fd=authority_inventory_fd,
            authority_inventory_sha256=authority_inventory_sha256, authority_key_fds=authority_key_fds, adopted=False)

    @classmethod
    def prepare_adopted(cls, *, conductor_inventory_fd, conductor_inventory_sha256,
                        authority_inventory_fd, authority_inventory_sha256, authority_key_fds,
                        intake_configuration_fd, intake_configuration_sha256):
        return cls._prepare(conductor_inventory_fd=conductor_inventory_fd,
            conductor_inventory_sha256=conductor_inventory_sha256, authority_inventory_fd=authority_inventory_fd,
            authority_inventory_sha256=authority_inventory_sha256, authority_key_fds=authority_key_fds, adopted=True,
            intake_configuration_fd=intake_configuration_fd, intake_configuration_sha256=intake_configuration_sha256)

    @classmethod
    def _prepare(cls, *, conductor_inventory_fd, conductor_inventory_sha256,
                 authority_inventory_fd, authority_inventory_sha256, authority_key_fds, adopted,
                 intake_configuration_fd=None, intake_configuration_sha256=None):
        """Admit installed originals before startup; borrow, then retain FD copies.

        Source FDs stay caller-owned and become CLOEXEC. Only retained copies of
        the conductor inventory and the exact keys are later passed to the
        authority child; that child never passes keys to its conductor.
        """
        global _USED, _LIVE
        _require(cls is AuthorityCoordinatorProcess and not _USED and _LIVE is None and tuple(JOBS) == STAGES)
        _USED = True
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner._adopted = adopted
            if adopted:
                from serverware import native_pilot_adopted_phase_profile as selected
                from serverware.native_pilot_adopted_intake import IntakeConfiguration, IntakeError
                owner._jobs, owner._key_purposes, owner._approval_root = selected.JOBS, selected.KEY_PURPOSES, selected.APPROVAL_ROOT
                owner._order = tuple((phase, index + 1, job) for phase in STAGES
                    for index, job in enumerate(owner._jobs[phase]))
                _require(intake_configuration_fd not in (conductor_inventory_fd, authority_inventory_fd))
                try:
                    owner._intake = IntakeConfiguration.open(intake_configuration_fd, intake_configuration_sha256)
                except IntakeError as error:
                    _require(type(error.owner) is IntakeConfiguration)
                    owner._intake = error.owner
                    raise
                owner._epoch_limit = owner._intake.expires_at_unix_ns
                owner._intake_sha256 = intake_configuration_sha256
            owner._origin()
            _require(conductor_inventory_fd != authority_inventory_fd)
            inventories = []
            for index, (fd, digest) in enumerate(((conductor_inventory_fd, conductor_inventory_sha256),
                                                  (authority_inventory_fd, authority_inventory_sha256))):
                raw = io.read_public(fd, artifact.MAX_MANIFEST_BYTES)
                _require(p.sha(raw) == p.digest(digest))
                identity = io._input(fd, artifact.MAX_MANIFEST_BYTES)
                held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
                owner._inventories.append((held, identity, raw))
                _require(io.read_public(held, artifact.MAX_MANIFEST_BYTES) == raw)
                owner._runtimes[index].admit(raw, authority=(index == 1))
                _require(io.read_public(fd, artifact.MAX_MANIFEST_BYTES) == raw)
                inventories.append(p.document(raw, artifact.MAX_MANIFEST_BYTES))
            _same(inventories[0]["source"], inventories[1]["source"])
            common = owner._runtimes[0].records
            authority_records = owner._runtimes[1].records
            _require({path: row for path, row in authority_records.items()
                if path != "authority" and not path.startswith("authority/")} == common)
            if owner._intake is not None:
                owner._intake.check(startup=True)
            p.fields(authority_key_fds, owner._key_purposes)
            bindings = {}
            for purpose in owner._key_purposes:
                fd = authority_key_fds[purpose]
                _require(type(fd) is int and fd not in (conductor_inventory_fd, authority_inventory_fd, intake_configuration_fd))
                identity = io._input(fd, 32, private=True)
                _require(identity[6] == 32)
                held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
                owner._keys[purpose] = (held, identity)
                _require(io._input(held, 32, private=True) == identity)
                if owner._intake is not None:
                    owner._intake.check(startup=True)
                key = io.signing_key(held)
                try:
                    bindings[purpose] = p.sha(key.public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
                finally:
                    del key  # Software key copies are not guaranteed erased.
                if owner._intake is not None:
                    owner._intake.check(startup=True)
            owner._bindings = {"apiVersion": ("serverware.nativePilotSupervisorBindings/v2" if adopted else
                "serverware.nativePilotSupervisorBindings/v1"),
                "conductorInventorySha256": conductor_inventory_sha256,
                "authorityInventorySha256": authority_inventory_sha256,
                "source": copy.deepcopy(inventories[0]["source"]), "keyBindings": bindings}
            if adopted:
                owner._bindings["intakeConfigurationSha256"] = intake_configuration_sha256
            owner._capabilities()
            return owner
        except BaseException:
            try:
                owner._release_handles()
            except BaseException as error:
                owner._close_attempted = True
                raise ProcessPreparationError(owner) from error
            owner._closed = True; _LIVE = None
            raise

    def _origin(self):
        _require(_LIVE is self and not self._closed and os.getpid() == self._pid
            and originals._start() == self._start and originals._boot() == self._boot
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _capabilities(self):
        self._origin()
        if self._intake is not None:
            self._intake.check()
        for fd, identity, _ in self._inventories:
            _require(io._input(fd, artifact.MAX_MANIFEST_BYTES) == identity)
        for fd, identity in self._keys.values():
            _require(io._input(fd, 32, private=True) == identity)
        for original in self._originals:
            original.check()
        if self._intake is not None:
            self._intake.check()

    def policy_bindings(self):
        self._capabilities()
        _require(self._bindings is not None)
        return copy.deepcopy(self._bindings)

    def adoption_selected(self):
        self._origin()
        return self._adopted

    def intake_configuration_original(self):
        self._capabilities()
        _require(self._adopted and self._intake is not None)
        return bytes(self._intake.raw)

    def runtime_originals(self):
        self._capabilities()
        return tuple(item[2] for item in self._inventories)

    def bootstrap_originals(self):
        self._capabilities()
        _require(self._bootstrap_prepared and len(self._bootstrap) == 4)
        return self._bootstrap.copy()

    def conductor_request(self, phase):
        self._capabilities()
        _require(phase in self._conductors)
        return copy.deepcopy(self._conductors[phase])

    def prior_result(self, phase, job):
        """Return child-reported public data, not a signature/approval verdict."""
        self._capabilities()
        _require((phase, job) in self._results)
        return copy.deepcopy(self._results[(phase, job)])

    def approved_input_sha256(self, phase, job):
        self._capabilities()
        _require((phase, job) in self._replies)
        return self._replies[(phase, job)]["inputSha256"]

    def approved_input_original(self, phase, job):
        """Actual installed input for a fully sent reply, not reconstructed history."""
        self._capabilities()
        slot = (phase, job)
        _require(slot in self._replies and slot in self._approved_inputs)
        raw = self._approved_inputs[slot]
        _require(p.sha(raw) == self._replies[slot]["inputSha256"])
        return raw

    def _open(self, path, maximum, digest=None):
        original = _Original(path, maximum, digest, mode=0o400)
        self._originals.append(original)
        return original.raw

    def prepare_bootstrap(self):
        """Retain installed originals for policy comparison before any spawn."""
        self._capabilities()
        _require(not self._bootstrap_attempted and not self._started and not self._close_attempted)
        self._bootstrap_attempted = True
        control_raw = self._open(bootstrap.CONTROL, 4096)
        control = p.fields(p.document(control_raw, 4096),
            ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
        _require(control["apiVersion"] == "serverware.nativeShadowDriverBootstrapControl/v1")
        p.digest(control["supervisorExecutableSha256"])
        config_raw = self._open(bootstrap.CONFIGURATION, 65536, p.digest(control["configurationSha256"]))
        config = window_authority.validate_configuration(config_raw)
        window_raw = self._open(bootstrap.WINDOW, 32768, p.digest(control["windowSha256"]))
        signed = p.fields(p.document(window_raw, 32768), ("apiVersion", "payload", "signatureBase64url"))
        _require(signed["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1")
        window = signed["payload"]
        bootstrap._key(config["bootstrapAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
            bootstrap.WINDOW_DOMAIN + p.canonical(window))
        window_authority.validate_window(window, config_raw, config, boot=self._boot, now=_clock())
        cold_pin = config["deliveryConfiguration"]
        cold_raw = self._open(cold_pin["path"], 65536, cold_pin["sha256"])
        window_authority.validate_delivery(config, cold_raw)
        self._bootstrap = dict(control=control_raw, configuration=config_raw, window=window_raw,
            deliveryConfiguration=cold_raw)
        self._startup, self._lifetime = p.ns(window["startupDeadlineBoottimeNs"]), p.ns(window["lifetimeDeadlineBoottimeNs"])
        self._reserve = config["lifecycle"]["cleanupReserveNanos"]
        if self._intake is not None:
            self._intake.check(startup=True)
            self._startup = min(self._startup, self._intake.startup_deadline_boottime_ns)
            self._lifetime = min(self._lifetime, self._intake.deadline_boottime_ns)
            _require(_clock() < self._startup < self._lifetime - self._reserve)
        self._capabilities()
        window_authority.validate_window(window, config_raw, config, boot=self._boot, now=_clock())
        self._bootstrap_prepared = True

    def start(self):
        self._capabilities()
        _require(self._bootstrap_prepared and not self._started and not self._close_attempted)
        self._started = True
        for runtime in self._runtimes:
            runtime.check()  # Named identities only; never inside pipe polling.
        config_raw = self._bootstrap["configuration"]
        config = p.document(config_raw, 65536)
        window = p.document(self._bootstrap["window"], 32768)["payload"]
        self._capabilities()
        window_authority.validate_window(window, config_raw, config, boot=self._boot, now=_clock())
        inventory_fd = self._inventories[0][0]
        command = artifact.AUTHORITY_COMMAND + ["--runtime-inventory-fd", str(inventory_fd),
            "--runtime-inventory-sha256", self._bindings["conductorInventorySha256"]]
        if self._adopted:
            self._intake.check()
            self._startup = min(self._startup, self._intake.startup_deadline_boottime_ns)
            self._lifetime = min(self._lifetime, self._intake.deadline_boottime_ns)
            _require(_clock() < self._startup < self._lifetime - self._reserve)
            command = artifact.AUTHORITY_COMMAND[:-1] + ["--run-adopted-native-pilot",
                "--runtime-inventory-fd", str(inventory_fd),
                "--runtime-inventory-sha256", self._bindings["conductorInventorySha256"],
                "--intake-configuration-fd", str(self._intake.borrowed_fd()),
                "--intake-configuration-sha256", self._intake_sha256]
        for purpose in self._key_purposes:
            command += ["--authority-key", purpose + "=" + str(self._keys[purpose][0])]
        inherited = (inventory_fd,) + tuple(self._keys[purpose][0] for purpose in self._key_purposes)
        if self._adopted:
            inherited += (self._intake.borrowed_fd(),)
        self._spawn_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        retained = False
        try:
            self._child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0, close_fds=True, pass_fds=inherited, env={}, cwd="/", restore_signals=True)
            self._pidfd = os.pidfd_open(self._child.pid, 0)
            os.set_inheritable(self._pidfd, False)
            parent, self._child_start = bootstrap.mechanics._process(self._child.pid)
            _require(parent == self._pid and bootstrap.mechanics._pidfd_pid(self._pidfd) == self._child.pid)
            os.set_blocking(self._child.stderr.fileno(), False)
            info = os.fstat(self._child.stderr.fileno())
            _require(stat.S_ISFIFO(info.st_mode) and info.st_uid == info.st_gid == 0)
            self._stderr_identity = _structural(info)
            self._channel = _JobChannel(self)
            retained = True
            self._io_check(self._startup)
        finally:
            # Unknown acquisition keeps both the real owner and blocked parent
            # signals; there is no numeric-PID cleanup or second spawn attempt.
            if retained or self._child is None:
                signal.pthread_sigmask(signal.SIG_SETMASK, self._spawn_mask)

    def _io_check(self, deadline, *, allow_terminal=False):
        self._origin()
        _require(self._child is not None and self._pidfd is not None and not self._close_attempted
            and type(deadline) is int and 0 < deadline <= self._lifetime)
        now = _clock(); _require(self._last_clock <= now < deadline); self._last_clock = now
        if self._adopted:
            wall = time.time_ns()
            _require(self._last_wall <= wall < self._epoch_limit)
            self._last_wall = wall
        _require(allow_terminal or not select.select([self._pidfd], [], [], 0)[0])

    def check_request(self, request):
        self._capabilities()
        _require(self._channel is not None and not self._channel._poisoned
            and type(request) is JobRequest and self._channel._pending is request)
        self._channel._check(request.deadline_boottime_ns)

    def check_waiting(self):
        """Keep the actual adopted authority while its conductor waits for core.

        No pipe is read and no request or phase is advanced by this check.
        Only the original pre-request startup interval remains admissible.
        """
        self._capabilities()
        _require(self._adopted and self._started and self._bootstrap_prepared
            and not self._close_attempted and self._channel is not None
            and not self._channel._poisoned and self._channel._index == 0
            and self._channel._pending is None and self._pidfd is not None)
        self._channel._check(self._startup)
        _require(bootstrap.mechanics._pidfd_pid(self._pidfd) == self._child.pid
            and bootstrap.mechanics._process(self._child.pid) == (self._pid, self._child_start))
        fd = self._child.stderr.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        _require(_structural(os.fstat(fd)) == self._stderr_identity
            and flags & os.O_ACCMODE == os.O_RDONLY and flags & os.O_NONBLOCK
            and not flags & os.O_PATH and not os.get_inheritable(fd))
        self._channel._check(self._startup)

    def _admit_request(self, value, index, upper_deadline):
        phase, job_index, job = self._order[index]
        _require(value["apiVersion"] == ("serverware.nativePilotAuthorityJobRequest/v2" if self._adopted else
            "serverware.nativePilotAuthorityJobRequest/v1")
            and p.integer(value["sequence"], maximum=len(self._order)) == index + 1
            and p.integer(value["conductorSequence"], maximum=len(STAGES)) == STAGES.index(phase) + 1
            and value["phase"] == phase and value["job"] == job.name
            and p.integer(value["jobIndex"], maximum=len(self._jobs[phase])) == job_index
            and p.ns(value["deadlineBoottimeNs"]) <= upper_deadline)
        p.digest(value["conductorRequestSha256"])
        if self._adopted:
            expiry = p.ns(value["expiresAtUnixNanos"])
            _require(0 < expiry <= self._epoch_limit and (self._core_expiry is None or self._core_expiry == expiry))
            self._core_expiry = self._epoch_limit = expiry
        if job_index == 1:
            conductor = pipe.request_value(p.canonical(value["conductorRequest"]), sequence=STAGES.index(phase) + 1,
                phase=phase, upper_deadline=upper_deadline, adopted=self._adopted,
                expires_at_unix_ns=self._epoch_limit if self._adopted else None)
            _require(conductor["apiVersion"] == ("serverware.nativePilotOperatorRequest/v2" if self._adopted else
                "serverware.nativePilotOperatorRequest/v1")
                and type(conductor["payload"]) is dict
                and p.sha(p.canonical(conductor)) == value["conductorRequestSha256"])
            for first, second in (("sequence", "conductorSequence"), ("phase", "phase"),
                                   ("deadlineBoottimeNs", "deadlineBoottimeNs")):
                _same(conductor[first], value[second])
            if self._adopted:
                _same(conductor["expiresAtUnixNanos"], value["expiresAtUnixNanos"])
            _require(phase not in self._conductors)
            self._conductors[phase] = copy.deepcopy(conductor)
        else:
            _require(value["conductorRequest"] is None)
            conductor = self._conductors[phase]
            _require(p.sha(p.canonical(conductor)) == value["conductorRequestSha256"])
            _same(conductor["deadlineBoottimeNs"], value["deadlineBoottimeNs"])
        if index == 0:
            _require(value["previousResult"] is None)
        else:
            prior_phase, _, prior_job = self._order[index - 1]
            previous = p.fields(value["previousResult"], ("phase", "job", "result"))
            _require(previous["phase"] == prior_phase and previous["job"] == prior_job.name
                and type(previous["result"]) is dict and (prior_phase, prior_job.name) in self._replies)
            self._results[(prior_phase, prior_job.name)] = copy.deepcopy(previous["result"])

    def receive(self):
        self._capabilities()
        _require(self._channel is not None and self._channel._index < len(self._order))
        phase, job_index, _ = self._order[self._channel._index]
        if job_index == 1:
            for runtime in self._runtimes:
                runtime.check()
        upper = self._lifetime - self._reserve if phase in ("generation-origin", "shutdown") else self._startup
        return self._channel.receive(upper)

    def reply(self, request, reply):
        self.check_request(request)
        try:
            self._channel._reply_value(request, reply)
            phase, _, job = self._order[self._channel._index]
            slot = (phase, job.name)
            _require(slot not in self._approved_inputs and self._approved_bytes < MAX_RETAINED_BYTES)
            raw = self._open(self._approval_root + "/" + phase + "/" + job.name + ".input.json",
                min(job.maximum, MAX_RETAINED_BYTES - self._approved_bytes), p.digest(reply["inputSha256"]))
            self._approved_bytes += len(raw)
            self._approved_inputs[slot] = raw
            if slot == ("endpoint-inputs", "endpoint-inputs"):
                # This approved fixed input supplies the actual production
                # cleanup reserve. It cannot extend any original deadline.
                production = p.fields(p.document(raw, 65536)["production"], PRODUCTION_FIELDS)
                self._reserve = max(self._reserve,
                    p.integer(production["cleanupReserveNanos"], maximum=5_000_000_000))
            if slot == ("shutdown", "stop"):
                action = p.document(raw, job.maximum)
                if action.get("action") == "run-interactive":
                    handoff = self._conductors["shutdown"]["payload"]["originHandoff"]
                    self._interactive_pending = (interactive.validate_action(action, origin_handoff=handoff),
                        copy.deepcopy(handoff), request.deadline_boottime_ns)
            self._channel.reply(request, reply)
        except BaseException:
            self._channel._poisoned = True
            raise

    def _read_stderr(self):
        fd = self._child.stderr.fileno()
        _require(_structural(os.fstat(fd)) == self._stderr_identity)
        while not self._stderr_eof:
            try:
                raw = os.read(fd, min(4096, _RESULT_MAX + 1 - len(self._stderr)))
            except InterruptedError:
                continue
            except BlockingIOError:
                return
            if not raw:
                self._stderr_eof = True
                return
            self._stderr.extend(raw)
            _require(len(self._stderr) <= _RESULT_MAX)

    def wait_interactive(self):
        """Retain the actual authority child while its approved pilot runs."""
        self._capabilities()
        _require(self._channel is not None and self._channel._index == len(self._order)
            and not self._channel._poisoned)
        if self._interactive_action is not None:
            interactive.wait_for_child(self, action=self._interactive_action,
                origin_handoff=self._interactive_origin, deadline_boottime_ns=self._interactive_deadline)

    def _release_handles(self):
        for original in reversed(self._originals):
            original.close()
        for fd, _ in self._keys.values():
            os.close(fd)
        for fd, _, _ in self._inventories:
            os.close(fd)
        for runtime in self._runtimes:
            runtime.close()
        if self._intake is not None:
            self._intake.close()

    def close(self, *, cancel=False):
        """One SIGTERM at most; require real terminal cleanup, exit and reap."""
        global _LIVE
        if self._closed:
            return copy.deepcopy(self._result)
        self._origin(); _require(not self._close_attempted and type(cancel) is bool)
        _require(self._interactive_action is None or cancel or self._interval_wait_done)
        self._close_attempted = True
        if self._child is None:
            self._result = {"apiVersion": "serverware.nativePilotSupervisorNotStarted/v1", "status": "not-started",
                "pilotAcceptanceVerified": False, "productionReleaseEligible": False}
        else:
            _require(self._pidfd is not None)
            complete = self._channel is not None and self._channel._index == len(self._order) and not self._channel._poisoned
            now = _clock(); deadline = min(self._lifetime, now + self._reserve)
            _require(now < deadline)
            if (cancel or not complete) and not select.select([self._pidfd], [], [], 0)[0]:
                self._signaled = True
                try:
                    signal.pidfd_send_signal(self._pidfd, signal.SIGTERM, None, 0)
                except ProcessLookupError:
                    pass  # Actual terminal/result/reap checks below decide.
            while True:
                self._origin(); self._read_stderr()
                if select.select([self._pidfd], [], [], 0)[0]:
                    observed = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                    _require(observed is not None and observed.si_pid == self._child.pid and observed.si_code == os.CLD_EXITED)
                    self._read_stderr()
                    _require(self._stderr_eof and self._stderr.endswith(b"\n") and self._stderr.count(b"\n") == 1)
                    result = interactive.check_terminal(p.document(bytes(self._stderr[:-1]), _RESULT_MAX),
                        action=self._interactive_action, origin_handoff=self._interactive_origin,
                        deadline_boottime_ns=self._interactive_deadline, now_boottime_ns=_clock(),
                        now_unix_ns=time.time_ns())
                    _require(result["apiVersion"] == "serverware.nativePilotAuthorityCoordinatorResult/v1"
                        and result["pilotAcceptanceVerified"] is False and result["productionReleaseEligible"] is False
                        and result["phase"] in ("open", "starting", *STAGES))
                    _require((result["status"] == "stopped-cleanup-complete" and complete
                        and result["phase"] == STAGES[-1] and observed.si_status == 0)
                        or (result["status"] == "failed-cleanup-complete" and observed.si_status == 1)
                        or (result["status"] == "not-started" and not complete and observed.si_status == 1
                            and result["phase"] in ("open", "starting")))
                    _require(_clock() < deadline)
                    reaped = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED)
                    _require(reaped is not None and (reaped.si_pid, reaped.si_code, reaped.si_status)
                        == (observed.si_pid, observed.si_code, observed.si_status))
                    self._child.returncode = reaped.si_status
                    self._result = result
                    break
                now = _clock(); _require(now < deadline)
                try:
                    select.select([self._pidfd, self._child.stderr.fileno()], [], [],
                        min(0.05, (deadline - now) / 1_000_000_000))
                except InterruptedError:
                    continue
            self._child.stdin.close(); self._child.stdout.close(); self._child.stderr.close()
            os.close(self._pidfd)
        # Unknown cleanup never reaches here; _LIVE retains the actual owner,
        # originals and capabilities, without a destructor or retry path.
        self._release_handles()
        self._closed = True; _LIVE = None
        return copy.deepcopy(self._result)
