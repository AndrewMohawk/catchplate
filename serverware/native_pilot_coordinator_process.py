"""One real fixed conductor child, retained through uncertain cleanup.

An approved runtime inventory is a pin, not a process owner. Preparation reads
the actual installed files and retains protected directory/file identities.
No authority key is inherited, no runtime/approval is generated, and no child
PID can be supplied. Loader resolution and production acceptance are not proved.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import select
import signal
import stat
import subprocess
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifact
from scripts.authority import native_pilot_authority_io as public_io
from serverware import native_shadow_driver_bootstrap as bootstrap
from serverware import native_pilot_scope_authority as scope
from serverware import native_shadow_nitro_originals as originals
from serverware.native_shadow_proof_cohort_control import _Original
from serverware.native_pilot_coordinator_channel import PipeChannel
from serverware.native_pilot_operator_channel import STAGES

p = bootstrap.p
_TOKEN = object()
_LIVE = None
_USED = False
_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_RESULT_MAX = 4096
_INVENTORY_FIELDS = ("apiVersion", "source", "target", "command", "records", "recordsSha256", "counts", "limits",
    "intendedInstalledOwnership", "exportOwnership", "releaseAuthority", "liveReady", "launchPrepared",
    "dynamicLoaderClosureVerified", "boundary")


def _require(value):
    if not value:
        raise ValueError("native pilot coordinator process refused")


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _structural(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


class _Runtime:
    def __init__(self):
        self.directories, self.identities, self.records, self.children = {}, {}, {}, {}
        self.protected_directories = set()
        self.manifest = self.interpreter_head = None

    def admit(self, raw):
        _require(0 < len(raw) <= artifact.MAX_MANIFEST_BYTES)
        value = json.loads(raw.decode("ascii"), object_pairs_hook=p._pairs, parse_float=p._reject, parse_constant=p._reject)
        p.fields(value, _INVENTORY_FIELDS)
        _require(artifact._canonical(value) == raw and value["apiVersion"] == artifact.API_VERSION
            and value["target"] == "native-pilot-conductor-artifact" and value["command"] == artifact.COMMAND
            and artifact._canonical(value["intendedInstalledOwnership"]) == artifact._canonical({"uid": 0, "gid": 0})
            and value["exportOwnership"] == "Host-export UID/GID are checked for stability, not interpreted as installed ownership."
            and value["boundary"] == "Offline package/source observations only. No execution, DSO-resolution proof, independent approval, installation, authority coordinator, or native service readiness is produced."
            and all(value[name] is False for name in ("releaseAuthority", "liveReady", "launchPrepared", "dynamicLoaderClosureVerified")))
        p.fields(value["source"], artifact.SOURCE_FIELDS)
        source = artifact._source(value["source"])
        expected_limits = dict(entries=artifact.MAX_ENTRIES, depth=artifact.MAX_DEPTH, fileBytes=artifact.MAX_FILE_BYTES,
            regularBytes=artifact.MAX_TOTAL_BYTES, pathBytes=artifact.MAX_PATH_BYTES, symlinkHops=artifact.MAX_SYMLINK_HOPS)
        _require(artifact._canonical(value["limits"]) == artifact._canonical(expected_limits))
        records = value["records"]
        _require(type(records) is list and 0 < len(records) <= artifact.MAX_ENTRIES
            and artifact._sha(artifact._canonical(records)) == value["recordsSha256"])
        total = 0
        for record in records:
            _require(type(record) is dict)
            kind = record.get("type")
            p.fields(record, ("path", "mode", "type") + (("bytes", "sha256") if kind == "file" else
                ("target", "resolvedPath") if kind == "symlink" else ()))
            _require(kind in ("file", "directory", "symlink"))
            path = record["path"]; artifact._path(path)
            _require(path not in self.records and type(record["mode"]) is str
                and re.fullmatch(r"[0-7]{4}", record["mode"]) is not None and int(record["mode"], 8) & 0o6000 == 0)
            if kind == "file":
                total += p.integer(record["bytes"], minimum=0, maximum=artifact.MAX_FILE_BYTES)
                p.digest(record["sha256"])
            self.records[path] = record
            parent, _, name = path.rpartition("/")
            self.children.setdefault(parent, set()).add(name)
            if kind in ("file", "symlink"):
                # Every actual source/library ancestor is protected, not just
                # the application directories. An unrelated directory-only
                # scratch entry may keep its approved mode (for example /tmp).
                while parent:
                    self.protected_directories.add(parent)
                    parent = parent.rpartition("/")[0]
        _require(list(self.records) == sorted(self.records) and total <= artifact.MAX_TOTAL_BYTES)
        counts = dict(entries=len(records), files=sum(r["type"] == "file" for r in records),
            directories=sum(r["type"] == "directory" for r in records),
            symlinks=sum(r["type"] == "symlink" for r in records), regularBytes=total)
        _require(artifact._canonical(counts) == artifact._canonical(value["counts"]))
        resolver = artifact._Inventory(); resolver.records = self.records
        for record in records:
            if record["type"] == "symlink":
                _require(artifact._text(record["target"]) and resolver.resolve(record["path"]) == record["resolvedPath"])
        root = os.open("/", _FLAGS | os.O_DIRECTORY)
        self.directories[""] = root
        root_info = os.fstat(root)
        _require(root_info.st_uid == root_info.st_gid == 0 and not root_info.st_mode & 0o022)
        self.identities[""] = _structural(root_info)
        inodes = set()
        for path, record in self.records.items():
            parent, _, name = path.rpartition("/")
            _require(parent in self.directories)
            fd = self.directories[parent]
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            _require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == int(record["mode"], 8))
            if record["type"] == "directory":
                _require(stat.S_ISDIR(info.st_mode))
                if path in self.protected_directories or path.split("/", 1)[0] in ("app", "vendor", "runtime"):
                    _require(not info.st_mode & 0o022)
                child = os.open(name, _FLAGS | os.O_DIRECTORY, dir_fd=fd)
                self.directories[path] = child
                _require(_structural(os.fstat(child)) == _structural(info))
                self.identities[path] = _structural(info)
            elif record["type"] == "symlink":
                _require(stat.S_ISLNK(info.st_mode) and info.st_nlink == 1
                    and os.readlink(name, dir_fd=fd) == record["target"])
                self.identities[path] = artifact._identity(info)
            else:
                _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022
                    and info.st_size == record["bytes"] and (info.st_dev, info.st_ino) not in inodes)
                inodes.add((info.st_dev, info.st_ino))
                opened = os.open(name, _FLAGS, dir_fd=fd)
                try:
                    _require(artifact._identity(os.fstat(opened)) == artifact._identity(info))
                    digest, offset, captured = hashlib.sha256(), 0, bytearray()
                    while offset < info.st_size:
                        chunk = os.pread(opened, min(65536, info.st_size - offset), offset)
                        _require(bool(chunk)); digest.update(chunk)
                        if path == artifact.SOURCE_MANIFEST:
                            _require(info.st_size <= artifact.MAX_MANIFEST_BYTES); captured.extend(chunk)
                        if path == artifact.INTERPRETER and offset == 0:
                            self.interpreter_head = chunk[:64]
                        offset += len(chunk)
                    _require(not os.pread(opened, 1, offset) and "sha256:" + digest.hexdigest() == record["sha256"]
                        and artifact._identity(os.fstat(opened)) == artifact._identity(info))
                    if path == artifact.SOURCE_MANIFEST:
                        self.manifest = bytes(captured)
                finally:
                    os.close(opened)
                self.identities[path] = artifact._identity(info)
        for path in ("app", "app/serverware", "app/scripts", "runtime", "runtime/python", "vendor"):
            _require(self.records.get(path, {}).get("type") == "directory")
        _require(self.children["app"] == {"serverware", "scripts"}
            and self.children["app/scripts"] == {"run_native_pilot.py", "native_pilot_runtime_entrypoint.py"})
        for path, mode in ((artifact.INTERPRETER, "0555"), (artifact.ENTRYPOINT, "0444"),
                           (artifact.CONDUCTOR, "0444"), (artifact.SOURCE_MANIFEST, "0444")):
            record = self.records.get(path, {})
            _require(record.get("type") == "file" and record.get("mode") == mode and record.get("bytes", 0) > 0)
        head = self.interpreter_head
        _require(head is not None and len(head) == 64 and head[:7] == b"\x7fELF\x02\x01\x01"
            and int.from_bytes(head[16:18], "little") in (2, 3) and int.from_bytes(head[18:20], "little") == 62)
        artifact._bind_source(self, source)
        self.check()

    def check(self):
        _require(_structural(os.fstat(self.directories[""])) == self.identities[""])
        for path, record in self.records.items():
            parent, _, name = path.rpartition("/")
            info = os.stat(name, dir_fd=self.directories[parent], follow_symlinks=False)
            identity = _structural(info) if record["type"] == "directory" else artifact._identity(info)
            _require(identity == self.identities[path])
            if record["type"] == "directory":
                _require(_structural(os.fstat(self.directories[path])) == identity)
                if path.split("/", 1)[0] in ("app", "vendor", "runtime"):
                    _require(not info.st_mode & 0o022)
                    scan = os.open(".", _FLAGS | os.O_DIRECTORY, dir_fd=self.directories[path])
                    try:
                        names = set()
                        with os.scandir(scan) as entries:
                            for entry in entries:
                                _require(len(names) < artifact.MAX_ENTRIES); names.add(entry.name)
                        _require(names == self.children.get(path, set()))
                    finally:
                        os.close(scan)
            elif record["type"] == "symlink":
                _require(os.readlink(name, dir_fd=self.directories[parent]) == record["target"])

    def close(self):
        for fd in self.directories.values():
            os.close(fd)
        self.directories.clear()


class ConductorProcess:
    def __init__(self, token):
        _require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._runtime, self._originals = _Runtime(), []
        self._child = self._pidfd = self._channel = None
        self._started = self._closed = self._close_attempted = self._signaled = False
        self._result = None
        self._last_clock = _clock()
        self._stderr = bytearray(); self._stderr_eof = False
        self._phase = "open"

    @classmethod
    def prepare(cls, *, runtime_inventory_fd, runtime_inventory_sha256):
        global _LIVE, _USED
        _require(cls is ConductorProcess and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner._origin()
            raw = public_io.read_public(runtime_inventory_fd, artifact.MAX_MANIFEST_BYTES)
            _require(p.sha(raw) == p.digest(runtime_inventory_sha256))
            owner._runtime.admit(raw)
            _require(public_io.read_public(runtime_inventory_fd, artifact.MAX_MANIFEST_BYTES) == raw)
            return owner
        except BaseException:
            owner._runtime.close(); owner._closed = True; _LIVE = None
            raise

    def _origin(self):
        _require(_LIVE is self and not self._closed and os.getpid() == self._pid
            and originals._start() == self._start and originals._boot() == self._boot
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _open(self, path, maximum, digest=None):
        original = _Original(path, maximum, digest)
        self._originals.append(original)
        return original.raw

    def start(self):
        self._origin(); _require(not self._started and not self._close_attempted)
        self._started = True
        self._runtime.check()  # No content rehash, and never called inside pipe polling.
        control = p.fields(p.document(self._open(bootstrap.CONTROL, 4096), 4096),
            ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
        _require(control["apiVersion"] == "serverware.nativeShadowDriverBootstrapControl/v1")
        config_raw = self._open(bootstrap.CONFIGURATION, 65536, control["configurationSha256"])
        config = p.fields(p.document(config_raw, 65536), ("apiVersion", "bootstrapAuthority", "phaseTwoAuthority",
            "deliveryConfiguration", "uid", "gid", "image", "continuation", "lifecycle"))
        _require(config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4")
        lifecycle = p.fields(config["lifecycle"], ("apiVersion", "gate", "cleanupReserveNanos", "constructedAdmissionAuthority"))
        _require(lifecycle["apiVersion"] == "serverware.nativeShadowDriverLifecyclePolicy/v3")
        self._reserve = p.integer(lifecycle["cleanupReserveNanos"], minimum=1_000_000, maximum=5_000_000_000)
        signed = p.fields(p.document(self._open(bootstrap.WINDOW, 32768, control["windowSha256"]), 32768),
            ("apiVersion", "payload", "signatureBase64url"))
        window = p.fields(signed["payload"], scope.WINDOW_FIELDS)
        _require(signed["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1"
            and window["configurationSha256"] == p.sha(config_raw)
            and window["signingKeyId"] == config["bootstrapAuthority"]["keyId"])
        bootstrap._key(config["bootstrapAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
            bootstrap.WINDOW_DOMAIN + p.canonical(window))
        _require(p.canonical(list(self._boot)) == p.canonical([window[name] for name in
            ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")]))
        self._startup, self._lifetime = p.ns(window["startupDeadlineBoottimeNs"]), p.ns(window["lifetimeDeadlineBoottimeNs"])
        issued = p.ns(window["issuedAtBoottimeNs"])
        _require(issued <= _clock() < self._startup < self._lifetime - self._reserve
            and self._startup - issued <= 30_000_000_000)
        self._spawn_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        retained = False
        try:
            self._child = subprocess.Popen(artifact.COMMAND, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0, close_fds=True, env={}, cwd="/", restore_signals=True)
            # Both parent signals remain blocked until the real child, PIDFD
            # and pipes are retained. The fixed child unblocks them only after
            # installing its own handlers, before claiming live resources.
            self._pidfd = os.pidfd_open(self._child.pid, 0)
            os.set_inheritable(self._pidfd, False)
            parent, self._child_start = bootstrap.mechanics._process(self._child.pid)
            _require(parent == self._pid and bootstrap.mechanics._pidfd_pid(self._pidfd) == self._child.pid)
            os.set_blocking(self._child.stderr.fileno(), False)
            info = os.fstat(self._child.stderr.fileno())
            _require(stat.S_ISFIFO(info.st_mode) and info.st_uid == info.st_gid == 0)
            self._stderr_identity = _structural(info)
            self._channel = PipeChannel(self, self._child.stdout.fileno(), self._child.stdin.fileno())
            retained = True
            self._io_check(self._startup)
        finally:
            # A partial acquisition remains fenced with its actual owner. No
            # numeric PID signal, retry or dropped Popen can stand in for it.
            if retained or self._child is None:
                signal.pthread_sigmask(signal.SIG_SETMASK, self._spawn_mask)

    def _io_check(self, deadline, *, allow_terminal=False):
        self._origin()
        _require(self._child is not None and self._pidfd is not None and not self._close_attempted
            and type(deadline) is int and 0 < deadline <= self._lifetime)
        now = _clock(); _require(self._last_clock <= now < deadline); self._last_clock = now
        _require(allow_terminal or not select.select([self._pidfd], [], [], 0)[0])

    def _boundary(self):
        self._origin(); self._runtime.check()
        for original in self._originals:
            original.check()

    def receive(self):
        self._boundary(); _require(self._channel is not None)
        index = self._channel._index
        _require(index < len(STAGES))
        phase = STAGES[index]
        upper = self._lifetime - self._reserve if phase in ("generation-origin", "shutdown") else self._startup
        request = self._channel.receive(upper)
        self._phase = phase
        return request

    def reply(self, request, inputs):
        self._boundary(); _require(self._channel is not None)
        if request is self._channel._pending and request.phase == "endpoint-inputs":
            production = p.fields(inputs["production"], scope.PRODUCTION_FIELDS)
            reserve = p.integer(production["cleanupReserveNanos"], maximum=5_000_000_000)
            self._reserve = max(self._reserve, reserve)
        self._channel.reply(request, inputs)

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

    def close(self):
        """One bounded cleanup attempt; unknown retains this actual owner."""
        global _LIVE
        if self._closed:
            return copy.deepcopy(self._result)
        self._origin(); _require(not self._close_attempted)
        self._close_attempted = True
        if self._child is None:
            self._result = {"apiVersion": "serverware.nativePilotCoordinatorNotStarted/v1", "status": "not-started",
                "pilotAcceptanceVerified": False, "productionReleaseEligible": False}
        else:
            _require(self._pidfd is not None)
            complete = self._channel is not None and self._channel._index == len(STAGES) and not self._channel._poisoned
            now = _clock(); deadline = min(self._lifetime, now + self._reserve)
            _require(now < deadline)
            if not complete and not select.select([self._pidfd], [], [], 0)[0]:
                self._signaled = True
                try:
                    signal.pidfd_send_signal(self._pidfd, signal.SIGTERM, None, 0)
                except ProcessLookupError:
                    pass  # A race to exit is proved below, never assumed clean.
            while True:
                self._origin(); self._read_stderr()
                terminal = bool(select.select([self._pidfd], [], [], 0)[0])
                if terminal:
                    observed = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                    _require(observed is not None and observed.si_pid == self._child.pid)
                    self._read_stderr()
                    _require(self._stderr_eof and self._stderr.endswith(b"\n") and self._stderr.count(b"\n") == 1)
                    result = p.fields(p.document(bytes(self._stderr[:-1]), _RESULT_MAX),
                        ("apiVersion", "status", "phase", "pilotAcceptanceVerified", "productionReleaseEligible"))
                    _require(result["apiVersion"] == "serverware.nativePilotOperatorResult/v1"
                        and result["pilotAcceptanceVerified"] is False and result["productionReleaseEligible"] is False
                        and result["phase"] in ("open", "starting", *STAGES) and observed.si_code == os.CLD_EXITED)
                    _require((result["status"] == "stopped-cleanup-complete" and complete
                        and result["phase"] == STAGES[-1] and observed.si_status == 0)
                        or (result["status"] == "failed-cleanup-complete" and observed.si_status == 1))
                    _require(_clock() < deadline)
                    reaped = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED)
                    _require(reaped is not None and (reaped.si_pid, reaped.si_code, reaped.si_status)
                        == (observed.si_pid, observed.si_code, observed.si_status))
                    self._child.returncode = reaped.si_status
                    self._result = result
                    break
                now = _clock(); _require(now < deadline)
                try:
                    select.select([self._pidfd, self._child.stderr.fileno()], [], [], min(0.05, (deadline - now) / 1_000_000_000))
                except InterruptedError:
                    continue
        # Nothing closes before a real terminal cleanup result and reap (or
        # proof no child was ever created). Unknown paths leave all FDs held.
        if self._child is not None:
            self._child.stdin.close(); self._child.stdout.close(); self._child.stderr.close()
            os.close(self._pidfd)
        for original in self._originals:
            original.close()
        self._runtime.close()
        self._closed = True; _LIVE = None
        return copy.deepcopy(self._result)
