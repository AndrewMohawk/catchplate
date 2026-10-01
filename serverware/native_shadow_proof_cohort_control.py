"""Actual fixed cohort process/channel ownership and one-shot public release.

No key, service grant, peer identity, image or listener is generated here. The
Rust parent alone admits the complete service assignments and opens child
gates. A sent packet is neither an acceptance receipt nor a readiness result.
"""
from __future__ import annotations

import array
import copy
import fcntl
import os
import select
import signal
import socket
import stat
import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_assignment as profile
from serverware import native_shadow_proof_cohort_cleanup as cleanup_profile

p = delivery.p
_TOKEN = object()
_LIVE = None
_USED = set()
CONTROL = "/etc/serverware/native-shadow-proof-cohort-control.json"
CONFIGURATION = "/etc/serverware/native-shadow-proof-cohort.json"
PRECREATION = "/etc/serverware/native-shadow-proof-cohort-precreation.json"
EXECUTABLE = "/opt/serverware/serverware-native-shadow-proof-cohort"
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_APIS = {"retrieval": ("serverware.nativeShadowRetrievalGuestLaunch/v1", "retrieval"),
    "persistence": ("serverware.nativeShadowPersistenceGuestLaunch/v2", "persistence"),
    "trustedTime": ("serverware.nativeShadowTrustedTimeGuestLaunch/v1", "trustedTime"),
    "generationInstall": ("serverware.nativeShadowGenerationGuestLaunch/v1", "generation"),
    "bridge": ("serverware.nativeProofBridgeLaunch/v1", "trustedTime"),
    "commitRequest": ("serverware.nativeShadowCommitRequestGuestLaunch/v1", "commitRequest"),
    "ingressAdmission": ("serverware.nativeShadowIngressGuestLaunch/v1", "ingress"),
    "terminalAppend": ("serverware.nativeShadowTerminalSpoolGuestLaunch/v1", "terminalSpool"),
    "dispatchBarrier": ("serverware.nativeShadowDispatchBarrierGuestLaunch/v1", "dispatchBarrier"),
    "activeEffectBarrier": ("serverware.nativeShadowActiveEffectBarrierGuestLaunch/v1", "activeEffectBarrier"),
    "activeEffectCommit": ("serverware.nativeShadowActiveEffectCommitGuestLaunch/v1", "activeEffectCommit")}


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _process(pid):
    with open("/proc/" + str(pid) + "/stat", "rb") as stream:
        raw = stream.read(4097)
    p.require(len(raw) <= 4096 and raw.startswith(str(pid).encode("ascii") + b" ("))
    fields = raw.rsplit(b") ", 1)[1].split()
    p.require(len(fields) >= 20)
    return int(fields[1]), int(fields[19])  # actual parent and start ticks


def _pidfd_pid(fd):
    with open("/proc/self/fdinfo/" + str(fd), "rt", encoding="ascii") as stream:
        raw = stream.read(4097)
    p.require(len(raw) <= 4096)
    lines = [line[4:].strip() for line in raw.splitlines() if line.startswith("Pid:")]
    p.require(len(lines) == 1 and lines[0].isdigit())
    return int(lines[0])


def _terminal(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    events = poll.poll(0)
    p.require(all(bits & ~(select.POLLIN | select.POLLHUP) == 0 for _, bits in events))
    return bool(events)


def _structural(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


class _Original:
    """Protected named input and every real ancestor, not a path-only pin."""
    def __init__(self, path, maximum, digest=None, mode=0o400):
        p.require(type(path) is str and path.isascii() and path.startswith("/") and 1 < len(path) <= 4096
            and "\0" not in path and all(part not in {"", ".", ".."} for part in path.split("/")[1:]))
        if digest is not None:
            p.digest(digest)
        self.fds, self.parents = [], []
        try:
            parent = os.open("/", _READ | os.O_DIRECTORY)
            self.fds.append(parent)
            parts = path[1:].split("/")
            for name in parts[:-1]:
                info = os.fstat(parent)
                p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
                child = os.open(name, _READ | os.O_DIRECTORY, dir_fd=parent)
                self.fds.append(child)
                self.parents.append((parent, name, child, _structural(os.fstat(child))))
                parent = child
            info = os.fstat(parent)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
            self.parent, self.name = parent, parts[-1]
            self.fd = os.open(self.name, _READ, dir_fd=parent)
            self.fds.append(self.fd)
            info = os.fstat(self.fd)
            p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1 and 0 < info.st_size <= maximum)
            self.identity = originals._identity(info)
            self.raw = os.pread(self.fd, maximum + 1, 0)
            p.require(len(self.raw) == info.st_size and (digest is None or p.sha(self.raw) == p.digest(digest)))
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for parent, name, child, expected in self.parents:
            p.require(_structural(os.fstat(child)) == expected
                and _structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        p.require(originals._identity(os.fstat(self.fd)) == self.identity
            and originals._identity(os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)) == self.identity
            and os.pread(self.fd, len(self.raw) + 1, 0) == self.raw)
        p.require(all(not os.get_inheritable(fd) for fd in self.fds))

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


class RetainedActivationFds:
    """Owned duplicates matching actual signed C9 metadata; no service verdict.

    Resources must already have their real purpose-specific producers. This
    adapter does not create them or replace those producers' retained owners.
    Persistence instead requires its dedicated held-lock transfer type.
    """
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._originals = [], []
        self._begun = self._closed = False
        self._retrieval_owner = None
        self._trusted_time_owner = None
        self._commit_request_owner = self._generation_install_owner = None

    def check(self):
        p.require(not self._closed and not self._begun)
        self._cohort.check()
        if self._retrieval_owner is not None:
            self._retrieval_owner.check()
        if self._trusted_time_owner is not None:
            self._trusted_time_owner.check()
        if self._commit_request_owner is not None:
            self._commit_request_owner.check()
        if self._generation_install_owner is not None:
            self._generation_install_owner.check()
        for original in self._originals:
            original.check()
        for fd, entry in zip(self._fds, self._entries, strict=True):
            p.require(_structural(os.fstat(fd)) == tuple(entry[name] for name in
                ("device", "inode", "mode", "uid", "gid")) and not os.get_inheritable(fd))

    def descriptors(self):
        self.check()
        return tuple((entry["fd"], fd) for entry, fd in zip(self._entries, self._fds, strict=True))

    def begin_release(self):
        value = self.descriptors()
        self._begun = True
        return value

    def close(self):
        if self._closed:
            return
        self._closed = True
        for fd in self._fds:
            os.close(fd)
        self._fds.clear()
        for original in self._originals:
            original.close()


class EndpointStartError(ValueError):
    """A failed start retains its real owner until separate driver cleanup."""
    def __init__(self, cohort):
        super().__init__("endpoint cohort start failed; retained owner requires cleanup")
        self.cohort = cohort


class ParkedProofCohort:
    """Private live process owner. There is no JSON/ready/PID constructor."""
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._originals, self._parked, self._transfers = [], [], []
        self._retained = []
        self._spool_resources = None
        self._commit_request_resources = self._generation_install_resources = None
        self._socket = self._pidfd = self._exec = self._child_pid = None
        self._observed = None
        self._attempted = self._closed = False
        self._release_sent = self._cleanup_attempted = self._cleanup_sent = self._parent_reaped = False
        self._release_original = self._cleanup_authorization = self._cleanup_result = None
        self._cleanup_deadline = None
        self._external_driver = self._endpoint_inputs = self._endpoint_five = None
        self._driver_attempted = self._stop_attempted = False
        self._peer_preparation_attempted = False
        self._peer_preparation = None

    def _open(self, path, bound, digest=None, mode=0o400):
        p.require(len(self._originals) < 96)
        original = _Original(path, bound, digest, mode)
        self._originals.append(original)
        return original

    @classmethod
    def start(cls):
        """One actual fixed, no-argument, empty-environment child invocation."""
        return cls._start(None)

    @classmethod
    def start_for_driver(cls, driver):
        """Ten endpoints bound to this actual measured, separately owned driver."""
        from serverware.native_shadow_driver_bootstrap import DriverBootstrap
        p.require(cls is ParkedProofCohort and type(driver) is DriverBootstrap)
        driver.check()
        return cls._start(driver)

    @classmethod
    def _start(cls, driver):
        global _LIVE
        p.require(_LIVE is None and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and len(os.listdir("/proc/self/task")) == 1)
        owner = cls(_TOKEN)
        _LIVE = owner  # also retain uncertain cleanup failures; no next attempt
        try:
            owner._pid, owner._start, owner._boot = os.getpid(), originals._start(), originals._boot()
            control = p.fields(p.document(owner._open(CONTROL, 4096).raw, 4096),
                ("apiVersion", "cohortExecutableSha256", "configurationSha256", "precreationSha256"))
            p.require(control["apiVersion"] == "serverware.nativeShadowProofCohortControl/v1")
            owner._config_original = owner._open(CONFIGURATION, profile.MAX_BYTES, control["configurationSha256"])
            owner._precreate_original = owner._open(PRECREATION, profile.MAX_BYTES, control["precreationSha256"])
            owner._config = profile.configuration(owner._config_original.raw)
            p.require(profile.endpoint_driver_selected(owner._config) == (driver is not None))
            owner._roles = profile.roles(owner._config)
            authority = p.fields(owner._config["authority"], ("publicKeyBase64url", "keyId"))
            public = p.decoded(authority["publicKeyBase64url"], size=32)
            p.require(public != bytes(32) and authority["keyId"] == p.sha(public))
            owner._key = Ed25519PublicKey.from_public_bytes(public)
            owner._cold = {}
            for role in owner._roles:
                pin = owner._config[role + "Configuration"]
                delivery._pin(pin)
                value = delivery.configuration(owner._open(pin["path"], 65536, pin["sha256"]).raw, pin["sha256"])
                p.require(value["authority"] == authority)
                owner._cold[role] = value
            p.require(len({value["uid"] for value in owner._cold.values()}) == len(owner._roles)
                and len({value["gid"] for value in owner._cold.values()}) == len(owner._roles))
            signed = p.fields(p.document(owner._precreate_original.raw, profile.MAX_BYTES),
                ("apiVersion", "payload", "signatureBase64url"))
            p.require(signed["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1")
            owner._window = signed["payload"]
            profile._window(owner._window, owner._config, p.sha(owner._config_original.raw), owner._boot, _clock())
            owner._key.verify(p.decoded(signed["signatureBase64url"], size=64),
                profile.PRECREATE_DOMAIN + p.canonical(owner._window))
            owner._startup = p.ns(owner._window["startupDeadlineBoottimeNs"])
            owner._lifetime = p.ns(owner._window["lifetimeDeadlineBoottimeNs"])
            if driver is not None:
                from serverware.native_shadow_endpoint_driver import EndpointDriver
                owner._external_driver = EndpointDriver.retain(driver, owner._config["externalDriver"], owner._window)
                # Real driver C9, used only as the peer/resource owner. It is
                # not inserted into the owned child inventory or release map.
                pin = driver._config["deliveryConfiguration"]
                delivery._pin(pin)
                cold = delivery.configuration(owner._open(pin["path"], 65536, pin["sha256"]).raw, pin["sha256"])
                p.require(cold["serviceRole"] == "production-bridge"
                    and (cold["uid"], cold["gid"]) == (driver._config["uid"], driver._config["gid"])
                    and cold["uid"] not in {value["uid"] for value in owner._cold.values()}
                    and cold["gid"] not in {value["gid"] for value in owner._cold.values()})
                owner._cold["bridge"] = cold
            used = p.sha(owner._precreate_original.raw)
            p.require(used not in _USED and len(_USED) < 1024)
            _USED.add(used)
            executable = owner._open(EXECUTABLE, 64 * 1024 * 1024, control["cohortExecutableSha256"], 0o555)
            raw = executable.raw
            p.require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
                and int.from_bytes(raw[18:20], "little") == 62
                and int.from_bytes(raw[16:18], "little") in (2, 3))
            table, stride, count = (int.from_bytes(raw[start:end], "little") for start, end in
                ((32, 40), (54, 56), (56, 58)))
            p.require(stride == 56 and 1 <= count <= 128 and 64 <= table <= len(raw)
                and table + stride * count <= len(raw))
            p.require(all(int.from_bytes(raw[table + index * stride:table + index * stride + 4], "little")
                not in (2, 3) for index in range(count)))  # no PT_DYNAMIC or PT_INTERP
            low_exec = os.memfd_create("serverware-proof-cohort", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                owner._exec = fcntl.fcntl(low_exec, fcntl.F_DUPFD_CLOEXEC, 128)
            finally:
                os.close(low_exec)
            offset = 0
            while offset < len(raw):
                count = os.pwrite(owner._exec, raw[offset:], offset)
                p.require(count > 0)
                offset += count
            os.fchmod(owner._exec, 0o500)
            fcntl.fcntl(owner._exec, fcntl.F_ADD_SEALS, 15)
            owner._exec_identity = originals._identity(os.fstat(owner._exec))
            p.require(os.pread(owner._exec, len(raw) + 1, 0) == raw)
            owner._spawn()
            if owner._external_driver is not None:
                owner._external_driver.send(owner._socket)
            owner._receive_originals()
            owner.check()
            return owner
        except BaseException as error:
            if driver is not None:
                # Give the actual caller the retained cleanup capability even
                # on partial start. Do not drop rights while its driver lives.
                raise EndpointStartError(owner) from error
            owner.close()
            raise

    def _spawn(self):
        self._origin()
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        self._socket = parent
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        parent.setsockopt(socket.SOL_SOCKET, 76, 1)  # mandatory SO_PASSPIDFD
        source = fcntl.fcntl(child.fileno(), fcntl.F_DUPFD_CLOEXEC, 128)
        null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(null)
            p.require(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (1, 3))
            null_high = fcntl.fcntl(null, fcntl.F_DUPFD_CLOEXEC, 128)
            try:
                actions = [(os.POSIX_SPAWN_DUP2, null_high, fd) for fd in (0, 1, 2)]
                actions.append((os.POSIX_SPAWN_DUP2, source, 3))
                # No preexec Python, inherited environment, shell or generic
                # argv. Only the pinned CLOEXEC memfd remains until initial exec.
                for text in os.listdir("/proc/self/fd"):
                    fd = int(text)
                    if fd > 3 and fd != self._exec:
                        try:
                            os.fstat(fd)
                        except OSError:
                            continue
                        actions.append((os.POSIX_SPAWN_CLOSE, fd))
                self._child_pid = os.posix_spawn("/proc/self/fd/" + str(self._exec), [EXECUTABLE], {},
                    file_actions=actions, setsigmask=(), setsigdef=(signal.SIGPIPE,))
                self._pidfd = os.pidfd_open(self._child_pid, 0)
                p.require(_pidfd_pid(self._pidfd) == self._child_pid)
                parent_pid, self._child_start = _process(self._child_pid)
                p.require(parent_pid == self._pid)
                self._child_live()
            finally:
                os.close(null_high)
        finally:
            os.close(null)
            os.close(source)
            child.close()

    def _origin(self):
        p.require(not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and p.ns(self._window["issuedAtBoottimeNs"]) <= _clock() < self._lifetime)
        for original in self._originals:
            original.check()

    def _child_live(self):
        p.require(self._pidfd is not None and not _terminal(self._pidfd)
            and _pidfd_pid(self._pidfd) == self._child_pid
            and _process(self._child_pid) == (self._pid, self._child_start))
        p.require(os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None)
        p.require(originals._identity(os.fstat(self._exec)) == self._exec_identity
            and fcntl.fcntl(self._exec, fcntl.F_GET_SEALS) & 15 == 15)
        current = os.stat("/proc/" + str(self._child_pid) + "/exe")
        p.require((current.st_dev, current.st_ino, current.st_size) ==
            (self._exec_identity[0], self._exec_identity[1], self._exec_identity[6]))

    def check(self):
        self._origin()
        p.require(not self._attempted and _clock() < self._startup)
        self._child_live()
        if self._external_driver is not None:
            self._external_driver.check(live=True)
        for fd, pid, start in self._parked:
            p.require(not _terminal(fd) and _pidfd_pid(fd) == pid and _process(pid) == (self._child_pid, start))
        if self._peer_preparation is not None:
            self._peer_preparation.check_resources()
        # Do NOT call transfer.check here: persistence owns this same cohort
        # and checks it before release. No recursive ownership approximation.

    def _receive_originals(self):
        while True:
            self.check()
            try:
                raw, ancillary, flags, _ = self._socket.recvmsg(profile.MAX_BYTES,
                    socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
            except BlockingIOError:
                select.select([self._socket], [], [], 0.01)
                continue
            received = []
            try:
                credentials = None
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, 4):
                        p.require(len(data) % 4 == 0)
                        values = array.array("i")
                        values.frombytes(data)
                        received.extend(values)
                        p.require(kind == 4 and len(values) == 1)
                    elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                        p.require(credentials is None and len(data) == 12)
                        credentials = struct.unpack("=iii", data)
                    else:
                        raise ValueError("unexpected cohort ancillary message")
                p.require(raw and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0
                    and credentials == (self._child_pid, 0, 0) and len(received) == 1
                    and _pidfd_pid(received[0]) == self._child_pid and not _terminal(received[0]))
                observed = p.fields(p.document(raw, profile.MAX_BYTES), profile.originals_fields(self._config))
                p.require(observed["apiVersion"] == profile.originals_api(self._config)
                    and observed["configurationSha256"] == p.sha(self._config_original.raw)
                    and observed["precreationSha256"] == p.sha(self._precreate_original.raw)
                    and observed["invocationId"] == self._window["invocationId"])
                if self._external_driver is not None:
                    p.require(observed["externalDriver"] == self._external_driver.value)
                    profile.external_driver_sha256(self._config, observed)
                identities = set()
                for role in self._roles:
                    value = p.fields(observed[role], ("processId", "startTimeTicks", "executable"))
                    pid = p.integer(value["processId"], minimum=2, maximum=(1 << 31) - 1)
                    start = p.integer(value["startTimeTicks"], maximum=(1 << 64) - 1)
                    exe = p.fields(value["executable"], ("device", "inode", "length", "sha256"))
                    p.integer(exe["device"], maximum=(1 << 64) - 1)
                    p.integer(exe["inode"], maximum=(1 << 64) - 1)
                    p.integer(exe["length"], maximum=64 * 1024 * 1024)
                    p.require(exe["sha256"] == self._config["executableSha256"]
                        and (exe["device"], exe["inode"]) not in identities)
                    identities.add((exe["device"], exe["inode"]))
                    fd = os.pidfd_open(pid, 0)
                    self._parked.append((fd, pid, start))
                p.require(len({pid for _, pid, _ in self._parked}) == len(self._roles))
                self._observed, self._observation_bytes = observed, bytes(raw)
                self.check()
                return
            finally:
                for fd in received:
                    os.close(fd)

    def original_bytes(self):
        self.check()
        p.require(self._observed is not None)
        return self._observation_bytes

    def peer_preparation_original(self, *, profile="retain-observed-cgroup"):
        """Actual parked target FD and cgroup retention, not post-exec proof."""
        from serverware.native_pilot_peer_owners import original
        return original(self, profile=profile)

    def bridge_original(self):
        self.check()
        p.require(self._observed is not None and self._external_driver is None)
        return copy.deepcopy(self._observed["bridge"])

    def endpoint_driver_selected(self):
        self.check()
        return profile.endpoint_driver_selected(self._config)

    def startup_deadline_boottime_ns(self):
        self.check()
        return self._startup

    def commitment_selected(self):
        """Source selection only; never proof that any service is ready."""
        self.check()
        return self._config["apiVersion"] in ("serverware.nativeShadowProofCohortConfiguration/v3", "serverware.nativeShadowProofCohortConfiguration/v4",
            "serverware.nativeShadowProofCohortConfiguration/v5", "serverware.nativeShadowProofCohortConfiguration/v6",
            "serverware.nativeShadowProofCohortConfiguration/v7")

    def spool_selected(self):
        """Explicit native-spool selection, not service or generation readiness."""
        self.check()
        return self._config["apiVersion"] in ("serverware.nativeShadowProofCohortConfiguration/v4", "serverware.nativeShadowProofCohortConfiguration/v5",
            "serverware.nativeShadowProofCohortConfiguration/v6", "serverware.nativeShadowProofCohortConfiguration/v7")

    def terminal_selected(self):
        """A separately authorized terminal owner, not terminal success."""
        self.check()
        return self._config["apiVersion"] in ("serverware.nativeShadowProofCohortConfiguration/v5", "serverware.nativeShadowProofCohortConfiguration/v6",
            "serverware.nativeShadowProofCohortConfiguration/v7")

    def effects_selected(self):
        """Fixed effects inventory, not an effect or dispatch permit."""
        self.check()
        return self._config["apiVersion"] in ("serverware.nativeShadowProofCohortConfiguration/v6", "serverware.nativeShadowProofCohortConfiguration/v7")

    def prepare_spool_inputs(self):
        """New physical resources under this exact parked cohort owner."""
        self.check()
        p.require(self.spool_selected() and self._spool_resources is None)
        from serverware.native_shadow_spool_inputs import SpoolInputs
        return SpoolInputs.prepare(self)

    def deliver_generation_origin(self, *, deadline_boottime_ns=None):
        """One explicit post-install observation handoff, never a retry loop."""
        self._origin(); self._child_live()
        from serverware.native_shadow_spool_inputs import SpoolInputs
        p.require(type(self._spool_resources) is SpoolInputs)
        return self._spool_resources.deliver_origin(deadline_boottime_ns=deadline_boottime_ns)

    def lifetime_deadline_boottime_ns(self):
        self.check()
        return self._lifetime

    def _role_files(self, role, pin):
        self.check()
        p.require(role in self._roles)
        delivery._pin(pin)
        launch_original = self._open(pin["path"], profile.MAX_BYTES, pin["sha256"])
        api, field = _APIS[role]
        if role == "bridge" and self.commitment_selected():
            api = "serverware.nativeProofBridgeLaunch/v2"
        if self.spool_selected():
            api = {"bridge": "serverware.nativeProofBridgeLaunch/v3", "commitRequest": "serverware.nativeShadowCommitRequestGuestLaunch/v2",
                   "retrieval": "serverware.nativeShadowRetrievalGuestLaunch/v2"}.get(role, api)
        if self.terminal_selected():
            api = {"bridge": "serverware.nativeProofBridgeLaunch/v4", "commitRequest": "serverware.nativeShadowCommitRequestGuestLaunch/v3",
                   "retrieval": "serverware.nativeShadowRetrievalGuestLaunch/v3"}.get(role, api)
        if self.effects_selected():
            api = {"bridge": "serverware.nativeProofBridgeLaunch/v5", "retrieval": "serverware.nativeShadowRetrievalGuestLaunch/v4"}.get(role, api)
        launch = p.fields(p.document(launch_original.raw, profile.MAX_BYTES), ("apiVersion", "keyAdmission", field))
        p.require(launch["apiVersion"] == api)
        nested = launch["keyAdmission"]
        p.fields(nested, ("apiVersion", "deliveryConfiguration", "delivery", "trust", "timeBootstrap", "assignment",
            "closure", "keys", "encryptedKeys", "admission", "verifierTransport"))
        p.require(nested["apiVersion"] == "serverware.nativeShadowGuestLaunch/v1")
        p.require(nested["deliveryConfiguration"] == self._config[role + "Configuration"])
        delivery._pin(nested["delivery"])
        delivery_original = self._open(nested["delivery"]["path"], 65536, nested["delivery"]["sha256"])
        signed = p.fields(p.document(delivery_original.raw, 65536), ("apiVersion", "payload", "signatureBase64url"))
        p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
        payload = p.fields(signed["payload"], delivery.FIELDS)
        self._key.verify(p.decoded(signed["signatureBase64url"], size=64), delivery.DOMAIN + p.canonical(payload))
        p.require(all(payload[name] == self._window[name] for name in profile.WINDOW_FIELDS
            if name != "configurationSha256") and payload["configurationSha256"] == nested["deliveryConfiguration"]["sha256"]
            and all(payload[name] == self._cold[role][name] for name in ("serviceRole", "uid", "gid")))
        delivery._pin(launch[field])
        history_operations = {"commitRequest": "ledger" if self.spool_selected() else "commitRequest",
            "ingressAdmission": "ingress", "terminalAppend": "terminal", "dispatchBarrier": "dispatchBarrier",
            "activeEffectBarrier": "activeEffectBarrier", "activeEffectCommit": "activeEffectCommit"}
        maximum = 4 * 1024 * 1024 if role in history_operations or role == "generationInstall" else 65536
        grant = self._open(launch[field]["path"], maximum, launch[field]["sha256"])
        if len(grant.raw) > 65536:
            # Earlier cohort profiles retain their existing small-original
            # grammar. Only closed successor grants may use the larger bound;
            # parsing here is still not native signature/history admission.
            if role == "generationInstall":
                from serverware import native_pilot_generation_install_authority as grant_profile
                grant_profile.grant_original(grant.raw)
            else:
                from serverware import native_pilot_native_service_authority as grant_profile
                grant_profile.grant_original(history_operations[role], grant.raw)
        entries = payload["activation"]
        p.require(type(entries) is list and 1 <= len(entries) <= 64)
        for index, entry in enumerate(entries, 6):
            p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
            p.require(entry["fd"] == index)
        return launch_original, delivery_original, grant, copy.deepcopy(entries)

    def prepare_commit_request_inputs(self):
        """Retain the actual fixed server socket before independent C9 signing."""
        from serverware.native_shadow_commit_request_inputs import CommitRequestInputs
        self.check()
        p.require(self._commit_request_resources is None and self.commitment_selected())
        return CommitRequestInputs.prepare(self)

    def prepare_generation_install_inputs(self):
        """Allocate actual listener/journal resources, never their authority."""
        from serverware.native_shadow_generation_install_inputs import GenerationInstallInputs
        self.check()
        p.require(self._generation_install_resources is None and "generationInstall" in self._roles)
        return GenerationInstallInputs.prepare(self)

    def activation_originals(self, *, role, launch_pin):
        """Retained exact launch/C9/grant originals, never a service verdict.

        The existing role selection and C9 signature/pins are checked here.
        Grant authority admission remains with the actual native Rust owner.
        """
        launch, signed, grant, _ = self._role_files(role, launch_pin)
        return bytes(launch.raw), bytes(signed.raw), bytes(grant.raw)

    def retain_retrieval_activation(self, *, activation, launch_pin):
        """Fixed full4 adapter; retain its real purpose owner through release.

        This is not a caller-selected callback or resource registry. Other
        roles retain their existing exact transfer paths unchanged.
        """
        from serverware.native_shadow_retrieval_activation import RetrievalActivation
        from serverware.native_shadow_spool_inputs import SpoolInputs
        self.check()
        p.require(self.effects_selected() and type(activation) is RetrievalActivation
            and type(self._spool_resources) is SpoolInputs)
        self._spool_resources.retrieval_additions(activation)
        descriptors = activation.cohort_descriptors(self._spool_resources)
        owner = self.retain_activation_fds(role="retrieval", launch_pin=launch_pin, descriptors=descriptors)
        owner._retrieval_owner = activation
        p.require(owner._delivery_bytes == activation.signed_original()
            and tuple(entry["name"] for entry in owner._entries) == delivery.SPOOL_RETRIEVAL_NAMES)
        owner.check()
        return owner

    def retain_activation_fds(self, *, role, launch_pin, descriptors,
                              commit_request_owner=None, generation_install_owner=None,
                              trusted_time_owner=None):
        """Retain real already-created non-Persistence FDs; never create service authority."""
        self.check()
        p.require(role in self._roles and role != "persistence")
        p.require(all(value._role != role for value in self._retained))
        if trusted_time_owner is not None:
            from serverware.native_shadow_trusted_time_inputs import TrustedTimeActivation
            p.require(role == "trustedTime" and type(trusted_time_owner) is TrustedTimeActivation
                and trusted_time_owner._cohort is self and trusted_time_owner._taken
                and trusted_time_owner._pilot_inputs is not None
                and trusted_time_owner._pilot_inputs._trusted_time is trusted_time_owner
                and descriptors == trusted_time_owner._cohort_descriptors)
            trusted_time_owner.check()
        if commit_request_owner is not None:
            from serverware.native_shadow_commit_request_inputs import CommitRequestInputs
            p.require(role == "commitRequest" and type(commit_request_owner) is CommitRequestInputs
                and commit_request_owner is self._commit_request_resources
                and commit_request_owner._cohort is self
                and commit_request_owner._transfer_attempted
                and descriptors == ((6, commit_request_owner._socket.fileno()),))
            commit_request_owner.check()
        if generation_install_owner is not None:
            from serverware.native_shadow_generation_install_inputs import GenerationInstallInputs
            p.require(role == "generationInstall" and type(generation_install_owner) is GenerationInstallInputs
                and generation_install_owner is self._generation_install_resources
                and generation_install_owner._cohort is self
                and generation_install_owner._ready and generation_install_owner._retain_attempted
                and launch_pin == generation_install_owner._launch_pin)
            generation_install_owner.check()
            p.require(descriptors == tuple((target, fd) for target, (_, fd)
                in enumerate(generation_install_owner.additions(), 6)))
        launch, signed, grant, entries = self._role_files(role, launch_pin)
        if trusted_time_owner is not None:
            p.require(signed.raw == trusted_time_owner._signed)
        if generation_install_owner is not None:
            p.require((launch.raw, signed.raw, grant.raw) == generation_install_owner._originals)
        p.require(type(descriptors) is tuple and len(descriptors) == len(entries))
        owner = RetainedActivationFds(_TOKEN)
        owner._cohort, owner._role, owner._entries = self, role, entries
        owner._commit_request_owner, owner._generation_install_owner = commit_request_owner, generation_install_owner
        owner._trusted_time_owner = trusted_time_owner
        owner._launch_sha, owner._delivery_bytes, owner._grant_bytes = p.sha(launch.raw), signed.raw, grant.raw
        try:
            for pair, entry in zip(descriptors, entries, strict=True):
                p.require(type(pair) is tuple and len(pair) == 2 and pair[0] == entry["fd"]
                    and type(pair[1]) is int and pair[1] >= 0)
                owner._fds.append(fcntl.fcntl(pair[1], fcntl.F_DUPFD_CLOEXEC, 128))
            owner.check()
            self._retained.append(owner)
            return owner
        except BaseException:
            owner.close()
            raise

    def release(self, *, release_original, transfers):
        """One SCM_RIGHTS attempt; no automatic retry, acknowledgement or ready return."""
        from serverware.native_shadow_persistence_inputs import PersistenceTransfer
        self.check()
        if self._external_driver is not None:
            # Set only by the actual all-five listening owner below.
            p.require(self._endpoint_five is not None and self._endpoint_inputs is not None)
            self._endpoint_five.check(); self._endpoint_inputs.check()
        if self.spool_selected():
            from serverware.native_shadow_spool_inputs import SpoolInputs
            p.require(type(self._spool_resources) is SpoolInputs and self._spool_resources._head is not None)
            self._spool_resources.check()
        p.require(type(transfers) is dict and set(transfers) == set(self._roles))
        signed = p.fields(p.document(release_original, profile.MAX_BYTES), ("payload", "signatureBase64url"))
        payload = p.fields(signed["payload"], profile.release_fields(self._config))
        p.require(payload["apiVersion"] == profile.release_api(self._config)
            and payload["configurationSha256"] == p.sha(self._config_original.raw)
            and payload["precreationSha256"] == p.sha(self._precreate_original.raw)
            and payload["observationSha256"] == p.sha(self.original_bytes())
            and payload["invocationId"] == self._window["invocationId"]
            and payload["signingKeyId"] == self._config["authority"]["keyId"])
        if self._external_driver is not None:
            p.require(payload["externalDriverSha256"] == profile.external_driver_sha256(self._config, self._observed))
        self._key.verify(p.decoded(signed["signatureBase64url"], size=64),
            profile.release_domain(self._config) + p.canonical(payload))
        expected, identities = {}, set()
        for role in self._roles:
            pins = p.fields(payload[role], ("launch", "image"))
            delivery._pin(pins["image"])
            launch, c9, grant, entries = self._role_files(role, pins["launch"])
            transfer = transfers[role]
            if role == "persistence":
                p.require(type(transfer) is PersistenceTransfer and transfer.signed_originals() == (c9.raw, grant.raw))
            else:
                p.require(type(transfer) is RetainedActivationFds and transfer._cohort is self
                    and transfer._role == role and transfer._launch_sha == p.sha(launch.raw)
                    and transfer._delivery_bytes == c9.raw and transfer._grant_bytes == grant.raw)
            descriptors = transfer.descriptors()
            p.require(len(descriptors) == len(entries))
            for (target, fd), entry in zip(descriptors, entries, strict=True):
                info = os.fstat(fd)
                p.require(target == entry["fd"] and _structural(info) == tuple(entry[name] for name in
                    ("device", "inode", "mode", "uid", "gid")) and (info.st_dev, info.st_ino) not in identities)
                identities.add((info.st_dev, info.st_ino))
            expected[role] = descriptors
        p.require(len(self._roles) <= sum(len(value) for value in expected.values()) <= 128)
        self.check()
        self._transfers = [transfers[role] for role in self._roles]
        rights = []
        # Freeze every source capability before contact. A failure in this
        # sequence is also nonretryable and retains all resources for cleanup.
        try:
            for role in self._roles:
                actual = transfers[role].begin_release()
                p.require(actual == expected[role])
                rights.extend(fd for _, fd in actual)
        finally:
            self._attempted = True
        encoded = array.array("i", rights)
        count = self._socket.sendmsg([release_original], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, encoded)],
            socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        p.require(count == len(release_original))
        self._release_original = bytes(release_original)
        self._release_sent = True
        # No subsequent preparation check, resend or claim about child gates.

    def _authorize_endpoint_release(self, five, driver, inputs):
        from serverware.custody_generation_launch import FiveServiceLaunch
        from serverware.native_shadow_driver_inputs import OperationalInputs
        self.check()
        p.require(type(five) is FiveServiceLaunch and type(inputs) is OperationalInputs
            and self._external_driver is not None and self._external_driver.driver is driver
            and inputs._driver is driver and driver._prepared_inputs is inputs
            and five._effects and five._attempted and five._bridge_attempted
            and five._listening.is_set() and self._endpoint_inputs is None)
        five.check(); inputs.check()
        self._endpoint_five, self._endpoint_inputs = five, inputs

    def continue_driver(self, *, inputs, signed_scope_original, public_originals):
        """Continue exactly the bound driver once, after actual endpoint release."""
        p.require(self._external_driver is not None and self._release_sent and not self._driver_attempted
            and not self._cleanup_attempted and inputs is self._endpoint_inputs)
        self._origin(); self._child_live(); self._external_driver.check(live=True)
        self._endpoint_five.check(); inputs.check()
        p.require(_clock() < self._startup)
        self._driver_attempted = True
        return self._external_driver.driver.continue_scope(inputs=inputs,
            signed_scope_original=signed_scope_original, public_originals=public_originals)

    def request_termination(self, *, authorization_original):
        """One separately authorized whole-cohort cancellation, never Settle/v4.

        The returned value is no acknowledgement. A send failure is unknown;
        neither this method nor settle/recover resends the effect command.
        """
        self._origin(); self._child_live()
        p.require(self._release_sent and not self._cleanup_attempted
                  and self._config["apiVersion"] in ("serverware.nativeShadowProofCohortConfiguration/v2",
                "serverware.nativeShadowProofCohortConfiguration/v3", "serverware.nativeShadowProofCohortConfiguration/v4", "serverware.nativeShadowProofCohortConfiguration/v5", "serverware.nativeShadowProofCohortConfiguration/v6",
                "serverware.nativeShadowProofCohortConfiguration/v7"))
        command = cleanup_profile.authorization(authorization_original, self._config_original.raw,
            self._precreate_original.raw, self._observation_bytes, self._release_original, self._boot, _clock())
        for fd, pid, start in self._parked:
            p.require(not _terminal(fd) and _pidfd_pid(fd) == pid and _process(pid) == (self._child_pid, start))
        self._cleanup_authorization = bytes(authorization_original)
        self._cleanup_deadline = p.ns(command["deadlineBoottimeNs"])
        self._cleanup_attempted = True
        self._cleanup_check()
        count = self._socket.sendmsg([self._cleanup_authorization], [], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        p.require(count == len(self._cleanup_authorization))
        self._cleanup_sent = True

    def _cleanup_check(self):
        self._origin()
        if self._external_driver is not None:
            self._external_driver.check(live=False)
        p.require(self._cleanup_attempted and self._cleanup_authorization is not None
                  and self._cleanup_deadline is not None and _clock() < self._cleanup_deadline)
        p.require(originals._identity(os.fstat(self._exec)) == self._exec_identity
                  and fcntl.fcntl(self._exec, fcntl.F_GET_SEALS) & 15 == 15)

    def _admit_cleanup(self, raw):
        self._cleanup_check()
        value, terminal = cleanup_profile.result(raw, self._cleanup_authorization,
            cleanup_profile.configuration(self._config), self._observed, cohort_configuration=self._config)
        for role, (fd, pid, start) in zip(self._roles, self._parked, strict=True):
            child = terminal["children"][role]
            info = os.fstat(fd)
            p.require(_terminal(fd) and (pid, start) == (child["processId"], child["startTimeTicks"])
                      and (info.st_dev, info.st_ino) == (child["pidfdDevice"], child["pidfdInode"]))
        # A valid packet/journal is still insufficient. The same retained
        # parent must itself finish with status zero and actually be reaped.
        while not _terminal(self._pidfd):
            self._cleanup_check()
            select.select([self._pidfd], [], [], 0.01)
        self._cleanup_check()
        observed = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        p.require(observed is not None and observed.si_pid == self._child_pid
                  and observed.si_code == os.CLD_EXITED and observed.si_status == 0)
        reaped = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOHANG)
        p.require(reaped is not None and (reaped.si_pid, reaped.si_code, reaped.si_status)
                  == (observed.si_pid, observed.si_code, observed.si_status))
        self._parent_reaped = True
        self._cleanup_check()
        # Retain the exact original; this is local lifecycle observation, not
        # an operation result, native attestation, retry permit or readiness.
        self._cleanup_result = bytes(raw)
        if self._external_driver is None:
            self.close()
        else:
            # This receipt covers only local endpoints. Their successful reap
            # must not close resources still held by the separate live driver.
            self.stop_endpoints()
        p.require(_clock() < self._cleanup_deadline)
        return self._cleanup_result

    def settle_cohort(self):
        """Receive once from the retained parent, then verify real terminal/reap."""
        self._cleanup_check()
        p.require(self._cleanup_sent and not self._parent_reaped)
        while True:
            self._cleanup_check()
            try:
                raw, ancillary, flags, _ = self._socket.recvmsg(profile.MAX_BYTES,
                    socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
            except BlockingIOError:
                select.select([self._socket], [], [], 0.01)
                continue
            received = []
            try:
                credentials = None
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, 4):
                        p.require(len(data) % 4 == 0)
                        values = array.array("i"); values.frombytes(data); received.extend(values)
                        p.require(kind == 4 and len(values) == 1)
                    elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                        p.require(credentials is None and len(data) == 12)
                        credentials = struct.unpack("=iii", data)
                    else:
                        raise ValueError("unexpected cleanup ancillary message")
                p.require(raw and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0
                    and credentials == (self._child_pid, 0, 0) and len(received) == 1)
                actual, retained = os.fstat(received[0]), os.fstat(self._pidfd)
                p.require((actual.st_dev, actual.st_ino) == (retained.st_dev, retained.st_ino))
                return self._admit_cleanup(raw)
            finally:
                for fd in received:
                    os.close(fd)

    def recover_cohort_cleanup(self):
        """Explicit observation-only recovery; no command, signal or new window.

        Requires this same live caller's original handles and the actual
        successful parent exit. Missing/partial journal or unknown reap fails.
        """
        self._cleanup_check()
        p.require(not self._parent_reaped and _terminal(self._pidfd))
        raw = cleanup_profile.recover(self._config, self._cleanup_authorization)
        return self._admit_cleanup(raw)

    def cleanup_original(self):
        """Read the already observed original. This grants no action authority."""
        p.require(self._parent_reaped and self._cleanup_result is not None
            and (self._closed or self._external_driver is not None))
        return self._cleanup_result

    def stop_endpoints(self):
        """Terminate/reap only owned children; keep every shared resource held."""
        if self._closed:
            return
        if self._parent_reaped:
            if self._socket is not None:
                self._socket.close(); self._socket = None
            return
        # A partially failed termination is unknown, not a fresh cancellation
        # opportunity. The original retained owner remains available to report.
        p.require(not self._stop_attempted)
        self._stop_attempted = True
        if self._socket is not None:
            self._socket.close()  # Rust observes EOF and signals/reaps its children.
            self._socket = None
        if self._child_pid is not None and not self._parent_reaped:
            p.require(os.getpid() == self._pid and originals._start() == self._start)
            if self._pidfd is None:
                # Still our unreaped child, not an adopted numeric process.
                p.require(_process(self._child_pid)[0] == self._pid)
                self._pidfd = os.pidfd_open(self._child_pid, 0)
            cleanup_end = _clock() + 250_000_000
            if self._config["apiVersion"] in ("serverware.nativeShadowProofCohortConfiguration/v2",
                "serverware.nativeShadowProofCohortConfiguration/v3", "serverware.nativeShadowProofCohortConfiguration/v4", "serverware.nativeShadowProofCohortConfiguration/v5", "serverware.nativeShadowProofCohortConfiguration/v6",
                "serverware.nativeShadowProofCohortConfiguration/v7"):
                cleanup_end = min(cleanup_end, self._cleanup_deadline or self._lifetime, self._lifetime)
            while not _terminal(self._pidfd) and _clock() < cleanup_end:
                select.select([self._pidfd], [], [], 0.01)
            if not _terminal(self._pidfd):
                for fd, _, _ in self._parked:
                    if not _terminal(fd):
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                signal.pidfd_send_signal(self._pidfd, signal.SIGKILL)
            cleanup_end = _clock() + 250_000_000
            if self._config["apiVersion"] in ("serverware.nativeShadowProofCohortConfiguration/v2",
                "serverware.nativeShadowProofCohortConfiguration/v3", "serverware.nativeShadowProofCohortConfiguration/v4", "serverware.nativeShadowProofCohortConfiguration/v5", "serverware.nativeShadowProofCohortConfiguration/v6",
                "serverware.nativeShadowProofCohortConfiguration/v7"):
                cleanup_end = min(cleanup_end, self._cleanup_deadline or self._lifetime, self._lifetime)
            while (not _terminal(self._pidfd) or any(not _terminal(fd) for fd, _, _ in self._parked)) and _clock() < cleanup_end:
                select.select([], [], [], 0.01)
            p.require(_terminal(self._pidfd) and all(_terminal(fd) for fd, _, _ in self._parked))
            terminal = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            p.require(terminal is not None and terminal.si_pid == self._child_pid)
            reaped = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED)
            p.require(reaped.si_pid == terminal.si_pid and reaped.si_code == terminal.si_code
                and reaped.si_status == terminal.si_status)
        self._parent_reaped = True

    def close(self):
        """Release resources only after separate endpoint and driver reaps."""
        global _LIVE
        if self._closed:
            return
        self.stop_endpoints()
        if self._external_driver is not None:
            self._external_driver.terminal()
        for transfer in self._transfers:
            transfer.close()
        for transfer in self._retained:
            transfer.close()
        if self._spool_resources is not None:
            self._spool_resources.close()
        if self._commit_request_resources is not None:
            self._commit_request_resources.close()
        if self._generation_install_resources is not None:
            self._generation_install_resources.close()
        if self._peer_preparation is not None:
            self._peer_preparation.close()
        for fd, _, _ in self._parked:
            os.close(fd)
        for fd in (self._pidfd, self._exec):
            if fd is not None:
                os.close(fd)
        for original in reversed(self._originals):
            original.close()
        if self._external_driver is not None:
            self._external_driver.close()
        self._closed = True
        if _LIVE is self:
            _LIVE = None
        # No unlink, mount-retirement claim, successful service or retry permit.

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_):
        self.close()
