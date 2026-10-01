"""Retained fixed three-child commissioning startup, not pilot acceptance.

Only inventory-admitted startup-child commands run. The children create their
own operational connections before independently supplied late files may
authorize their existing roles. No key bytes are read here, no future PID is
predicted, and an exit line without EOF and consuming PIDFD reap is not cleanup.
"""
from __future__ import annotations

import fcntl
import os
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifacts
from scripts.authority import native_pilot_authority_io as public_io
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_pilot_publication as publication
from serverware import native_pilot_startup_profile as profile
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_control as mechanics
from serverware.native_pilot_coordinator_process import _Runtime
from serverware.native_pilot_current_head_state import StartupAtomicPublisher, StateStoreError
from serverware.native_pilot_lifecycle import _Protected
from serverware.native_pilot_startup_child import _Control, _ControlError

p = profile.p
_TOKEN, _USED, _LIVE = object(), False, None
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_ROOTS = ("/", "/etc", "/etc/serverware", profile.DIRECTORY)
_CREDENTIALS = struct.Struct("=iII")
_RESULT_MAX = 4096
_CLEANUP_WAIT_NS = 5_000_000_000
_ADMIT_ORDER = ("decisions", "provider", "lifecycle")


def child_command(role, *, configuration_fd, configuration_sha256, supervisor_inventory_fd,
                  supervisor_inventory_sha256, parent_pid, parent_start_time_ticks):
    """One source-fixed command and public capabilities only, never a key argv."""
    from scripts.run_native_pilot_startup_child import _arguments, MODE
    arguments = [MODE, role, "--configuration-fd", str(configuration_fd),
        "--configuration-sha256", configuration_sha256, "--supervisor-inventory-fd", str(supervisor_inventory_fd),
        "--supervisor-inventory-sha256", supervisor_inventory_sha256, "--parent-pid", str(parent_pid),
        "--parent-start-time-ticks", str(parent_start_time_ticks)]
    _arguments(arguments)
    return artifacts.SUPERVISOR_COMMAND[:-1] + arguments


def role_result(raw, role, *, exit_code, admitted):
    """Pure exact terminal grammar; the parent separately establishes EOF/reap."""
    p.require(role in profile.ROLES and type(exit_code) is int and exit_code in (0, 1)
        and type(admitted) is bool and type(raw) is bytes and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    value = p.document(raw[:-1], _RESULT_MAX)
    p.require(value.get("pilotAcceptanceVerified") is False and value.get("productionReleaseEligible") is False)
    if value.get("apiVersion") == "serverware.nativePilotStartupChildResult/v1":
        p.fields(value, ("apiVersion", "role", "status", "pilotAcceptanceVerified", "productionReleaseEligible"))
        # The fixed wrapper emits this only before entering a role, including
        # a rejected admission frame whose send was ambiguous to the parent.
        p.require(exit_code == 1 and value["role"] == role
            and value["status"] == "failed-cleanup-complete")
        return value
    p.require(admitted)
    fields = ("apiVersion", "status", "stage", "pilotAcceptanceVerified", "productionReleaseEligible")
    if role == "lifecycle":
        p.fields(value, fields + ("coldJobsCompleted", "adoptedJobsCompleted", "coldBundleSha256"))
        p.require(value["apiVersion"] == "serverware.nativePilotLifecycleResult/v1")
        p.integer(value["coldJobsCompleted"], minimum=0, maximum=66)
        p.integer(value["adoptedJobsCompleted"], minimum=0, maximum=176)
        if value["coldBundleSha256"] is not None: p.digest(value["coldBundleSha256"])
        if exit_code == 0:
            p.require(value["status"] == "stopped-cleanup-complete" and value["stage"] == "adopted-finish"
                and value["coldJobsCompleted"] == 66 and value["adoptedJobsCompleted"] == 176
                and value["coldBundleSha256"] is not None)
    elif role == "provider":
        p.fields(value, fields + ("approvalsDelivered", "completionReceipts"))
        p.require(value["apiVersion"] == "serverware.nativePilotApprovalProviderResult/v1")
        p.integer(value["approvalsDelivered"], minimum=0, maximum=244)
        p.integer(value["completionReceipts"], minimum=0, maximum=2)
        if exit_code == 0:
            p.require(value["status"] == value["stage"] == "complete-public-transcript"
                and value["approvalsDelivered"] == 244 and value["completionReceipts"] == 2)
    else:
        p.fields(value, fields + ("decisionsDelivered",))
        p.require(value["apiVersion"] == "serverware.nativePilotCurrentHeadDecisionServiceResult/v1")
        p.integer(value["decisionsDelivered"], minimum=0, maximum=8)
        if exit_code == 0:
            p.require(value["status"] == "complete-eight-decisions" and value["decisionsDelivered"] == 8
                and value["stage"] == "eight-independent-pairs-delivered")
    p.require(type(value["stage"]) is str and value["stage"].isascii() and 0 < len(value["stage"]) <= 256)
    if exit_code == 1: p.require(value["status"] == "failed-cleanup-complete")
    return value


class StartupError(ValueError):
    def __init__(self, owner):
        super().__init__("commissioning startup refused; actual children and originals retained")
        self.owner = owner


class Startup:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._runtime = _Runtime()
        self._sources, self._handles, self._loose_sockets, self._keys = [], [], [], {}
        self._roots, self._files, self._children = {}, {}, {}
        self._configuration = self._inventory = self._prepared = self._accepted = None
        self._listener = self._listener_identity = self._observation = None
        self._atomic = None
        self._hello, self._ready, self._results = {}, {}, {}
        self._allowed, self._input_fds = set(), set()
        self._started = self._admission_attempted = self._admitted = self._completed = False
        self._failed = self._closed = self._closing = self._finish_attempted = False

    @classmethod
    def prepare(cls, *, configuration_fd, configuration_sha256, supervisor_inventory_fd, supervisor_inventory_sha256):
        global _USED, _LIVE
        p.require(cls is Startup and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner._origin()
            p.require(configuration_fd != supervisor_inventory_fd)
            owner._input_fds = {configuration_fd, supervisor_inventory_fd}
            owner._configuration = _Protected(owner._sources, configuration_fd, profile.MAX_CONFIGURATION, configuration_sha256)
            owner._inventory = _Protected(owner._sources, supervisor_inventory_fd, artifacts.MAX_MANIFEST_BYTES,
                supervisor_inventory_sha256)
            p.require(owner._configuration.identity[:2] != owner._inventory.identity[:2])
            owner._prepared = profile.configuration(owner._configuration.raw, inventory_sha256=owner._inventory.digest,
                boot=owner._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            with io.owning(): owner._runtime.admit(owner._inventory.raw, supervisor=True)
            for path in _ROOTS:
                with io.owning():
                    parent, name = path.rsplit("/", 1)
                    fd = os.open(path, _READ | os.O_DIRECTORY) if path == "/" else os.open(name,
                        _READ | os.O_DIRECTORY, dir_fd=owner._roots[parent or "/"][0][0])
                    row = owner._handle(fd)
                    owner._roots[path] = row, publication._structural(os.fstat(fd))
                publication._protected(os.fstat(fd))
            info = os.fstat(owner._roots[profile.DIRECTORY][0][0])
            pin = owner._prepared["value"]["directory"]
            p.require(stat.S_IMODE(info.st_mode) == 0o700 and (info.st_dev, info.st_ino) == (pin["device"], pin["inode"]))
            p.require(not owner._scan())
            with io.owning():
                owner._listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                owner._listener.set_inheritable(False); owner._listener.setblocking(False)
                owner._listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                owner._listener.bind(owner._prepared["addresses"]["control"])
                owner._listener.listen(len(profile.ROLES))
                owner._listener_identity = originals._identity(os.fstat(owner._listener.fileno()))
            owner.check(full=True)
            return owner
        except BaseException as error:
            owner._failed = True
            raise StartupError(owner) from error

    def _origin(self):
        public_io._process()
        p.require(_LIVE is self and not self._closed and os.getpid() == self._pid
            and originals._start() == self._start and originals._boot() == self._boot
            and threading.current_thread() is threading.main_thread() and len(os.listdir("/proc/self/task")) == 1)

    def _handle(self, fd):
        row = [fd, None]
        self._handles.append(row)
        row[1] = originals._identity(os.fstat(fd))[:2]
        return row

    def _drop(self, row):
        p.require(row[0] is not None and originals._identity(os.fstat(row[0]))[:2] == row[1])
        with io.owning():
            fd, row[0] = row[0], None
            os.close(fd); self._handles.remove(row)

    def _clock(self):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall)
        if self._prepared is not None:
            caps = self._accepted if self._accepted is not None else self._prepared
            p.require(now < caps["deadline"] and wall < caps["epochLimit"])
        self._last, self._wall = now, wall

    def _cleanup_clock(self, deadline):
        """Observation/cancellation only; cannot admit, resume or extend a role."""
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now < deadline and self._wall <= wall)
        self._last, self._wall = now, wall

    def _scan(self):
        names = set()
        with os.scandir(self._roots[profile.DIRECTORY][0][0]) as entries:
            for entry in entries:
                p.require(len(names) < 8 and entry.name in self._allowed)
                names.add(entry.name)
        return names

    def _capabilities(self, *, full=False):
        self._origin()
        for source in self._sources: (source.check if full else source.check_identity)()
        self._runtime.check()
        # Publication checks cannot prevent terminal observation of children
        # during cleanup; its actual partial owner is closed only afterwards.
        if self._atomic is not None and not self._closing: self._atomic._retained()
        for path, (row, identity) in self._roots.items():
            parent, name = path.rsplit("/", 1)
            info = os.fstat(row[0]); publication._protected(info)
            named = os.stat(path, follow_symlinks=False) if path == "/" else os.stat(name,
                dir_fd=self._roots[parent or "/"][0][0], follow_symlinks=False)
            p.require(publication._structural(info) == identity == publication._structural(named)
                and not os.get_inheritable(row[0]))
        for name, (row, maximum, identity, raw) in self._files.items():
            p.require(public_io._input(row[0], maximum) == identity == originals._identity(os.stat(name,
                dir_fd=self._roots[profile.DIRECTORY][0][0], follow_symlinks=False)))
            if full: p.require(public_io.read_public(row[0], maximum) == raw)
        for row, identity in self._keys.values():
            p.require(public_io._input(row[0], 32, private=True) == identity)
        if self._listener_identity is not None:
            p.require(originals._identity(os.fstat(self._listener.fileno())) == self._listener_identity
                and self._listener.getsockname() == self._prepared["addresses"]["control"]
                and not self._listener.get_inheritable())

    def _child_check(self, row, *, terminal=False):
        child, pidfd = row["child"], row["pidfd"]
        p.require(child is not None and pidfd is not None and not row["spawn_uncertain"]
            and originals._identity(os.fstat(pidfd)) == row["pidfd_identity"] and not os.get_inheritable(pidfd))
        if not row["reaped"]:
            p.require(mechanics._pidfd_pid(pidfd) == child.pid
                and mechanics._process(child.pid) == (self._pid, row["identity"]["startTimeTicks"])
                and (terminal or not select.select([pidfd], [], [], 0)[0]))
        for name, identity in row["pipes"].items():
            fd = getattr(child, name).fileno()
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            p.require(self._pipe_identity(fd) == identity and not os.get_inheritable(fd)
                and flags & os.O_NONBLOCK and flags & os.O_ACCMODE == os.O_RDONLY and not flags & os.O_PATH)

    @staticmethod
    def _pipe_identity(fd):
        info = os.fstat(fd)
        p.require(stat.S_ISFIFO(info.st_mode) and info.st_uid == info.st_gid == 0)
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink

    def _drain(self, row):
        for name in ("stdout", "stderr"):
            if row[name + "_eof"]: continue
            while True:
                try: raw = os.read(getattr(row["child"], name).fileno(), min(4096, _RESULT_MAX + 1 - len(row[name])))
                except InterruptedError: continue
                except BlockingIOError: break
                if not raw:
                    row[name + "_eof"] = True
                    break
                row[name].extend(raw)
                p.require(len(row[name]) <= _RESULT_MAX and (name != "stdout" or not row[name]))

    def check(self, *, full=False, terminal=False):
        p.require(not self._failed and not self._closing)
        self._clock(); self._capabilities(full=full)
        for row in self._children.values():
            self._child_check(row, terminal=terminal)
            self._drain(row)
        self._clock()

    def _spawn(self, role):
        p.require(role not in self._children)
        row = dict(child=None, pidfd=None, pidfd_identity=None, identity=None, control=None,
            pipes={}, stdout=bytearray(), stderr=bytearray(), stdout_eof=False, stderr_eof=False,
            spawn_uncertain=False, admitted=False, reaped=False, reap_attempted=False, signaled=False)
        self._children[role] = row
        command = child_command(role, configuration_fd=self._configuration.fd,
            configuration_sha256=self._configuration.digest, supervisor_inventory_fd=self._inventory.fd,
            supervisor_inventory_sha256=self._inventory.digest, parent_pid=self._pid, parent_start_time_ticks=self._start)
        with io.owning():
            row["spawn_uncertain"] = True
            row["child"] = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0, close_fds=True, pass_fds=(self._configuration.fd, self._inventory.fd),
                env={}, cwd="/", restore_signals=True)
            row["pidfd"] = os.pidfd_open(row["child"].pid, 0)
            os.set_inheritable(row["pidfd"], False)
            row["pidfd_identity"] = originals._identity(os.fstat(row["pidfd"]))
            parent, start = mechanics._process(row["child"].pid)
            p.require(parent == self._pid and mechanics._pidfd_pid(row["pidfd"]) == row["child"].pid)
            row["identity"] = dict(pid=row["child"].pid, uid=0, gid=0, startTimeTicks=start, parentPid=self._pid)
            for name in ("stdout", "stderr"):
                fd = getattr(row["child"], name).fileno()
                os.set_inheritable(fd, False); os.set_blocking(fd, False)
                row["pipes"][name] = self._pipe_identity(fd)
            row["spawn_uncertain"] = False

    def _pause(self, watched=()):
        self.check()
        caps = self._accepted if self._accepted is not None else self._prepared
        delay = min(0.01, (caps["deadline"] - self._last) / 1e9, (caps["epochLimit"] - self._wall) / 1e9)
        p.require(delay > 0)
        select.select(list(watched), [], [], delay)
        self.check()

    def start(self):
        try:
            self.check(full=True); p.require(not self._started)
            self._started = True
            for role in profile.ROLES:
                self._spawn(role); self.check()
            while len(self._hello) < len(profile.ROLES):
                self.check()
                with io.owning():
                    try: accepted, _ = self._listener.accept()
                    except (BlockingIOError, InterruptedError): accepted = None
                    if accepted is not None: self._loose_sockets.append(accepted)
                if accepted is None:
                    self._pause((self._listener,)); continue
                credentials = _CREDENTIALS.unpack(accepted.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                matches = [role for role, row in self._children.items() if credentials == (row["identity"]["pid"], 0, 0)]
                p.require(len(matches) == 1 and matches[0] not in self._hello)
                role, row = matches[0], self._children[matches[0]]
                with io.owning():
                    try: row["control"] = _Control.open(accepted, peer=row["identity"], boot=self._boot, check=self.check)
                    except _ControlError as error:
                        row["control"] = error.owner
                        raise
                    finally:
                        if row["control"] is not None: self._loose_sockets.remove(accepted)
                raw, _ = row["control"].receive(0)
                hello = profile.message(raw, "hello", role=role, configuration_sha256=self._configuration.digest)
                p.require(hello["process"] == row["identity"])
                self._hello[role] = raw
            peers = {role: row["identity"] for role, row in self._children.items()}
            for role, row in self._children.items():
                row["control"].send(profile.encode("connect", role, self._configuration.digest, peers=peers))
            for role, row in self._children.items():
                raw, _ = row["control"].receive(0)
                profile.message(raw, "ready", role=role, configuration_sha256=self._configuration.digest)
                self._ready[role] = raw
            raw = profile.observation(self._configuration.raw, self._hello, self._ready)
            actual = profile.observation_value(raw, configuration_raw=self._configuration.raw)
            p.require(actual["processes"] == peers and actual["parentPid"] == self._pid)
            self._publish(profile.OBSERVATION_NAME, raw)
            self._observation = raw
            self._allowed.update((profile.ADMISSION_NAME, *profile.SOURCE_FILENAMES.values()))
            self.check(full=True)
            return bytes(raw)
        except BaseException as error:
            self._failed = True
            raise StartupError(self) from error

    def _read(self, name, maximum):
        p.require(name in self._allowed and name not in self._files)
        self.check()
        with io.owning():
            fd = os.open(name, _READ, dir_fd=self._roots[profile.DIRECTORY][0][0])
            row = self._handle(fd)
        identity = public_io._input(fd, maximum)
        raw = public_io.read_public(fd, maximum)
        self._files[name] = row, maximum, identity, raw
        self.check(full=True)
        return self._files[name]

    def _publish(self, name, raw):
        self.check(); p.require(name not in self._allowed and type(raw) is bytes and len(raw) <= profile.MAX_OBSERVATION)
        p.require(name == profile.OBSERVATION_NAME and self._atomic is None)
        with io.owning():
            try:
                self._atomic = StartupAtomicPublisher.open(directory=self._prepared["value"]["directory"], check=self.check)
            except StateStoreError as error:
                p.require(type(error.owner) is StartupAtomicPublisher)
                self._atomic = error.owner
                raise
        self._allowed.add(name)
        self._atomic.publish(name, raw)
        opened = self._read(name, len(raw))
        p.require(opened[3] == raw)
        self.check()

    def wait_admission(self, *, cold_authority_key_fds, adopted_authority_key_fds):
        try:
            self.check(full=True)
            p.require(self._observation is not None and not self._admission_attempted)
            self._admission_attempted = True
            groups = dict(cold=cold_authority_key_fds, adopted=adopted_authority_key_fds)
            for family, supplied in groups.items():
                p.fields(supplied, tuple(name for group, name in profile.KEY_NAMES if group == family))
            for family, purpose in profile.KEY_NAMES:
                fd = groups[family][purpose]
                p.require(type(fd) is int and fd not in self._input_fds)
                identity = public_io._input(fd, 32, private=True)
                p.require(identity[6] == 32)
                with io.owning():
                    held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128)
                    row = self._handle(held)
                    self._keys[family, purpose] = row, identity
                p.require(public_io._input(held, 32, private=True) == identity)
            required = {profile.ADMISSION_NAME, *profile.SOURCE_FILENAMES.values()}
            while not required <= self._scan(): self._pause()
            admission = self._read(profile.ADMISSION_NAME, profile.MAX_ADMISSION)
            sources = {name: self._read(profile.SOURCE_FILENAMES[name], profile.SOURCE_LIMITS[name])
                for name in profile.SOURCE_NAMES}
            p.require(len({row[2][:2] for row in (admission, *sources.values())}) == len(sources) + 1)
            self._accepted = profile.admission(admission[3], configuration_raw=self._configuration.raw,
                observation_raw=self._observation, source_originals={name: row[3] for name, row in sources.items()},
                supervisor_inventory_original=self._inventory.raw, boot=self._boot,
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            p.require(self._accepted["peers"] == {role: row["identity"] for role, row in self._children.items()})
            self.check(full=True)
            for role in _ADMIT_ORDER:
                self.check(full=True)
                p.require(self._last < self._accepted["startupDeadline"])
                names = profile.ROLE_SOURCES[role]
                descriptors = [sources[name][0][0] for name in names]
                keys = []
                if role == "lifecycle":
                    for family, purpose in profile.KEY_NAMES:
                        keys.append(dict(family=family, purpose=purpose, index=len(descriptors)))
                        descriptors.append(self._keys[family, purpose][0][0])
                raw = profile.encode("admit", role, self._configuration.digest,
                    readySha256=p.sha(self._ready[role]), observationSha256=p.sha(self._observation),
                    admissionSha256=p.sha(admission[3]), sources=[dict(purpose=name, sha256=p.sha(sources[name][3])) for name in names],
                    keys=keys, deadlineBoottimeNs=str(self._accepted["deadline"]), expiresAtUnixNanos=self._accepted["epochLimit"])
                # An ambiguous positive send may already have resumed this
                # role. From this point death alone can never prove cleanup.
                self._children[role]["admitted"] = self._admitted = True
                self._children[role]["control"].send(raw, descriptors)
            self.check(full=True, terminal=True)
        except BaseException as error:
            self._failed = True
            raise StartupError(self) from error

    def _collect(self, *, cancel, cleanup_deadline=None):
        p.require(type(cancel) is bool and (cleanup_deadline is None or cancel))
        def clock():
            self._clock() if cleanup_deadline is None else self._cleanup_clock(cleanup_deadline)
        while any(not row["reaped"] for row in self._children.values()):
            clock(); self._capabilities()
            watched = []
            for role, row in self._children.items():
                if row["reaped"]: continue
                self._child_check(row, terminal=True); self._drain(row)
                watched.extend((row["pidfd"], *(getattr(row["child"], name).fileno() for name in ("stdout", "stderr"))))
                if not select.select([row["pidfd"]], [], [], 0)[0]: continue
                observed = os.waitid(os.P_PIDFD, row["pidfd"], os.WEXITED | os.WNOWAIT | os.WNOHANG)
                p.require(observed is not None and observed.si_pid == row["child"].pid)
                self._drain(row)
                if not row["stdout_eof"] or not row["stderr_eof"]: continue
                p.require(not row["stdout"] and not row["reap_attempted"])
                if cancel and not row["admitted"] and row["signaled"] and observed.si_code == os.CLD_KILLED:
                    p.require(observed.si_status == signal.SIGTERM)
                    result = None  # Pre-admission cancellation, never workflow success.
                else:
                    p.require(observed.si_code == os.CLD_EXITED)
                    result = role_result(bytes(row["stderr"]), role,
                        exit_code=observed.si_status, admitted=row["admitted"])
                clock()
                with io.owning():
                    row["reap_attempted"] = True
                    actual = os.waitid(os.P_PIDFD, row["pidfd"], os.WEXITED)
                    p.require(actual is not None and (actual.si_pid, actual.si_code, actual.si_status)
                        == (observed.si_pid, observed.si_code, observed.si_status))
                    row["child"].returncode = actual.si_status if actual.si_code == os.CLD_EXITED else -actual.si_status
                    row["reaped"] = True
                self._results[role] = dict(exitCode=row["child"].returncode,
                    resultOriginal=bytes(row["stderr"]), result=result)
                clock()
            if all(row["reaped"] for row in self._children.values()): break
            clock()
            if cleanup_deadline is None:
                caps = self._accepted if self._accepted is not None else self._prepared
                delay = min(0.01, (caps["deadline"] - self._last) / 1e9, (caps["epochLimit"] - self._wall) / 1e9)
            else:
                delay = min(0.01, (cleanup_deadline - self._last) / 1e9)
            p.require(delay > 0); select.select(watched, [], [], delay)

    def finish(self):
        try:
            self.check(full=True, terminal=True)
            p.require(self._admitted and all(row["admitted"] for row in self._children.values()) and not self._finish_attempted)
            self._finish_attempted = True
            self._collect(cancel=False)
            p.require(set(self._results) == set(profile.ROLES) and all(row["exitCode"] == 0 for row in self._results.values()))
            self._runtime.check(); self._clock()
            self._completed = True
            return {role: bytes(row["resultOriginal"]) for role, row in self._results.items()}
        except BaseException as error:
            self._failed = True
            raise StartupError(self) from error

    def close(self, *, cancel=False):
        global _LIVE
        if self._closed: return dict(status="closed", completed=self._completed)
        try:
            self._origin(); p.require(type(cancel) is bool and not self._closing)
            self._closing = True
            pending = [row for row in self._children.values() if not row["reaped"]]
            if pending:
                p.require(cancel or self._failed)
                cleanup_deadline = originals._clock() + _CLEANUP_WAIT_NS
                for row in pending:
                    self._child_check(row, terminal=True)
                    if not select.select([row["pidfd"]], [], [], 0)[0]:
                        row["signaled"] = True
                        try: signal.pidfd_send_signal(row["pidfd"], signal.SIGTERM, None, 0)
                        except ProcessLookupError: pass
                # Post-admission forced death never becomes known cleanup.
                # Only each existing CLI's exact cleanup result can pass.
                self._collect(cancel=True, cleanup_deadline=cleanup_deadline)
            with io.owning():
                if self._atomic is not None: self._atomic.close()
                for row in self._children.values():
                    if row["control"] is not None: row["control"].close()
                    if row["child"] is not None:
                        for name in ("stdout", "stderr"): getattr(row["child"], name).close()
                    if row["pidfd"] is not None:
                        fd, row["pidfd"] = row["pidfd"], None
                        os.close(fd)
                while self._loose_sockets: self._loose_sockets.pop().close()
                if self._listener is not None:
                    channel, self._listener = self._listener, None
                    channel.close()
                while self._handles:
                    row = self._handles[-1]
                    p.require(row[0] is not None and originals._identity(os.fstat(row[0]))[:2] == row[1])
                    fd, row[0] = row[0], None
                    os.close(fd); self._handles.pop()
                for source in self._sources: source.close()
                self._runtime.close()
                self._closed = True; _LIVE = None
            return dict(status="closed", completed=self._completed)
        except BaseException as error:
            self._failed = True
            raise StartupError(self) from error
