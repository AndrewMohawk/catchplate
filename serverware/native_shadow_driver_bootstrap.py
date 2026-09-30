"""Fixed live two-phase caller; no signer, service admission or readiness API.

Public signatures are supplied by the independently provisioned authorities.
Only the Rust child constructs a driver identity from final kernel originals.
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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_control as mechanics

p = mechanics.p
_TOKEN = object()
_LIVE = None
_USED = set()
CONTROL = "/etc/serverware/native-shadow-driver-bootstrap-control.json"
CONFIGURATION = "/etc/serverware/native-shadow-driver-bootstrap.json"
WINDOW = "/etc/serverware/native-shadow-driver-bootstrap-window.json"
EXECUTABLE = "/opt/serverware/serverware-native-shadow-guest-supervisor"
WINDOW_DOMAIN = b"serverware.nativeShadowDriverBootstrapWindow.signature/v1\0"
SCOPE_DOMAIN = b"serverware.nativeShadowDriverScope.signature/v1\0"
ROLES = ("bounded-cleanup-helper", "cleanup-authorization-consumer", "current-signature-authority",
    "durable-recovery-store", "recovery-target-provider")
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def _key(value):
    fields = p.fields(value, ("publicKeyBase64url", "keyId"))
    raw = p.decoded(fields["publicKeyBase64url"], size=32)
    p.require(raw != bytes(32) and p.sha(raw) == fields["keyId"])
    return Ed25519PublicKey.from_public_bytes(raw)


def _sealed(name, raw, mode):
    fd = os.memfd_create(name, os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:]); p.require(count > 0); offset += count
        os.fchown(fd, 0, 0); os.fchmod(fd, mode); fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        p.require(os.pread(fd, len(raw) + 1, 0) == raw and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == SEALS)
        return fd
    except BaseException:
        os.close(fd)
        raise


class DriverBootstrap:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._originals = []
        self._socket = self._pidfd = self._driver_pidfd = self._exec = self._bundle = self._gate_pidfd = None
        self._child_pid = None
        self._closed = self._attempted = False
        self._constructed = False
        self._operational_inputs = None
        self._gate_binding = None
        self._gate_attempted = False
        self._cleanup_attempted = False
        self._subtree_terminal_original = None

    def _open(self, path, maximum, digest=None, mode=0o400):
        original = mechanics._Original(path, maximum, digest, mode)
        self._originals.append(original)
        return original

    @classmethod
    def start(cls):
        global _LIVE
        p.require(_LIVE is None and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and len(os.listdir("/proc/self/task")) == 1)
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner._pid, owner._start, owner._boot = os.getpid(), originals._start(), originals._boot()
            control = p.fields(p.document(owner._open(CONTROL, 4096).raw, 4096),
                ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
            p.require(control["apiVersion"] == "serverware.nativeShadowDriverBootstrapControl/v1")
            config_raw = owner._open(CONFIGURATION, 65536, control["configurationSha256"]).raw
            config = p.document(config_raw, 65536)
            fields = ("apiVersion", "bootstrapAuthority", "phaseTwoAuthority", "deliveryConfiguration", "uid", "gid", "image")
            if config.get("apiVersion") in ("serverware.nativeShadowDriverBootstrapConfiguration/v2", "serverware.nativeShadowDriverBootstrapConfiguration/v3", "serverware.nativeShadowDriverBootstrapConfiguration/v4"):
                fields += ("continuation",)
                continuation = p.fields(config["continuation"], ("apiVersion", "keyTransport"))
                expected = {"serverware.nativeShadowDriverBootstrapConfiguration/v2": "serverware.nativeShadowDriverContinuationPreparation/v1",
                    "serverware.nativeShadowDriverBootstrapConfiguration/v3": "serverware.nativeShadowDriverContinuationPreparation/v2",
                    "serverware.nativeShadowDriverBootstrapConfiguration/v4": "serverware.nativeShadowDriverContinuationPreparation/v3"}[config["apiVersion"]]
                p.require(continuation["apiVersion"] == expected)
                if config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4":
                    fields += ("lifecycle",)
                    policy = p.fields(config["lifecycle"], ("apiVersion", "gate", "cleanupReserveNanos"))
                    gate = p.fields(policy["gate"], ("uid", "gid", "executableSha256"))
                    p.require(policy["apiVersion"] == "serverware.nativeShadowDriverLifecyclePolicy/v1"
                        and p.integer(gate["uid"]) == 65534 and p.integer(gate["gid"]) == 65534
                        and 1_000_000 <= p.integer(policy["cleanupReserveNanos"]) <= 5_000_000_000)
                    p.digest(gate["executableSha256"])
            else:
                p.require(config.get("apiVersion") == "serverware.nativeShadowDriverBootstrapConfiguration/v1")
            owner._config = p.fields(config, fields)
            p.require(owner._config["bootstrapAuthority"] != owner._config["phaseTwoAuthority"])
            window_raw = owner._open(WINDOW, 32768, control["windowSha256"]).raw
            signed = p.fields(p.document(window_raw, 32768), ("apiVersion", "payload", "signatureBase64url"))
            p.require(signed["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1")
            window = p.fields(signed["payload"], ("configurationSha256", "signingKeyId", "bootIdBase64url",
                "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs",
                "lifetimeDeadlineBoottimeNs", "invocationId"))
            _key(owner._config["bootstrapAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
                WINDOW_DOMAIN + p.canonical(window))
            owner._phase_key = _key(owner._config["phaseTwoAuthority"])
            p.require(window["configurationSha256"] == p.sha(config_raw)
                and window["signingKeyId"] == owner._config["bootstrapAuthority"]["keyId"]
                and (window["bootIdBase64url"], window["timeNamespaceDevice"], window["timeNamespaceInode"]) == owner._boot)
            owner._window = window
            owner._startup, owner._lifetime = p.ns(window["startupDeadlineBoottimeNs"]), p.ns(window["lifetimeDeadlineBoottimeNs"])
            if "lifecycle" in owner._config:
                p.require(owner._startup < owner._lifetime - owner._config["lifecycle"]["cleanupReserveNanos"])
            issued = p.ns(window["issuedAtBoottimeNs"])
            p.require(issued <= mechanics._clock() < owner._startup <= owner._lifetime
                and owner._startup - issued <= 30_000_000_000 and p.sha(window_raw) not in _USED and len(_USED) < 1024)
            _USED.add(p.sha(window_raw))
            owner._config_sha, owner._window_sha = p.sha(config_raw), p.sha(window_raw)
            source = owner._open(EXECUTABLE, 64 * 1024 * 1024, control["supervisorExecutableSha256"], 0o555)
            raw = source.raw
            p.require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
                and int.from_bytes(raw[18:20], "little") == 62 and int.from_bytes(raw[16:18], "little") in (2, 3))
            table, stride, count = (int.from_bytes(raw[start:end], "little") for start, end in ((32, 40), (54, 56), (56, 58)))
            p.require(stride == 56 and 1 <= count <= 128 and 64 <= table <= len(raw) and table + stride * count <= len(raw)
                and all(int.from_bytes(raw[table + index * stride:table + index * stride + 4], "little") not in (2, 3)
                    for index in range(count)))
            owner._exec = _sealed("native-shadow-driver-supervisor", source.raw, 0o500)
            owner._exec_identity = originals._identity(os.fstat(owner._exec))
            owner._spawn()
            owner._observation_raw = owner._receive(65536)
            observation = p.fields(p.document(owner._observation_raw, 65536), ("apiVersion", "configurationSha256",
                "windowSha256", "invocationId", "processId", "uid", "gid", "cgroupOriginalSha256", "root",
                "seccompFilterCount", "descriptors", "driver"))
            p.require(observation["apiVersion"] == "serverware.nativeShadowDriverObservation/v1"
                and observation["configurationSha256"] == owner._config_sha and observation["windowSha256"] == owner._window_sha
                and observation["invocationId"] == window["invocationId"]
                and observation["uid"] == owner._config["uid"] and observation["gid"] == owner._config["gid"])
            owner._observation = observation
            # This PID is first authenticated by the actual retained supervisor;
            # the independently opened PIDFD/start must identify its real child.
            owner._driver_pid = p.integer(observation["processId"])
            owner._driver_pidfd = os.pidfd_open(owner._driver_pid, 0)
            parent, owner._driver_start = mechanics._process(owner._driver_pid)
            p.require(parent == owner._child_pid and mechanics._pidfd_pid(owner._driver_pidfd) == owner._driver_pid
                and owner._driver_start == observation["driver"]["processStartTimeTicks"])
            owner.check()
            return owner
        except BaseException:
            owner.close()
            raise

    def _spawn(self):
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        self._socket = parent
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1); parent.setsockopt(socket.SOL_SOCKET, 76, 1)
        source = fcntl.fcntl(child.fileno(), fcntl.F_DUPFD_CLOEXEC, 128)
        null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(null)
            p.require(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (1, 3))
            safe_null = fcntl.fcntl(null, fcntl.F_DUPFD_CLOEXEC, 128)
            try:
                actions = [(os.POSIX_SPAWN_DUP2, safe_null, fd) for fd in (0, 1, 2)]
                actions.append((os.POSIX_SPAWN_DUP2, source, 3))
                for text in os.listdir("/proc/self/fd"):
                    fd = int(text)
                    if fd > 3 and fd != self._exec:
                        try:
                            os.fstat(fd)
                        except OSError:
                            continue
                        actions.append((os.POSIX_SPAWN_CLOSE, fd))
                self._child_pid = os.posix_spawn("/proc/self/fd/" + str(self._exec), [EXECUTABLE, "--driver-bootstrap"], {},
                    file_actions=actions, setsigmask=(), setsigdef=(signal.SIGPIPE,))
                self._pidfd = os.pidfd_open(self._child_pid, 0)
                parent_pid, self._child_start = mechanics._process(self._child_pid)
                p.require(parent_pid == self._pid and mechanics._pidfd_pid(self._pidfd) == self._child_pid)
            finally:
                os.close(safe_null)
        finally:
            os.close(source); os.close(null); child.close()

    def _origin(self):
        p.require(not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        for value in self._originals:
            value.check()

    def check(self):
        self._origin()
        p.require(mechanics._clock() < (self._lifetime if self._constructed else self._startup) and not mechanics._terminal(self._pidfd)
            and mechanics._pidfd_pid(self._pidfd) == self._child_pid
            and mechanics._process(self._child_pid) == (self._pid, self._child_start)
            and originals._identity(os.fstat(self._exec)) == self._exec_identity
            and fcntl.fcntl(self._exec, fcntl.F_GET_SEALS) == SEALS)
        actual = os.stat("/proc/" + str(self._child_pid) + "/exe")
        p.require((actual.st_dev, actual.st_ino, actual.st_size) == (self._exec_identity[0], self._exec_identity[1], self._exec_identity[6]))
        if self._driver_pidfd is not None:
            p.require(not mechanics._terminal(self._driver_pidfd) and mechanics._pidfd_pid(self._driver_pidfd) == self._driver_pid
                and mechanics._process(self._driver_pid) == (self._child_pid, self._driver_start))
        if self._operational_inputs is not None:
            self._operational_inputs.check()
        if self._gate_binding is not None:
            gate = self._gate_binding["binding"]
            p.require(not mechanics._terminal(self._gate_pidfd)
                and mechanics._pidfd_pid(self._gate_pidfd) == gate["gateProcessId"]
                and mechanics._process(gate["gateProcessId"])[1] == gate["gateStartTimeTicks"])

    def _receive(self, maximum):
        while True:
            self.check()
            remaining = self._startup - mechanics._clock(); p.require(remaining > 0)
            if select.select([self._socket], [], [], min(remaining / 1_000_000_000, 0.05))[0]:
                break
        raw, ancillary, flags, _ = self._socket.recvmsg(maximum, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
        credentials, pidfds = [], []
        try:
            for level, kind, value in ancillary:
                p.require(level == socket.SOL_SOCKET)
                if kind == socket.SCM_CREDENTIALS:
                    p.require(len(value) == 12); credentials.append(struct.unpack("3i", value))
                elif kind == 4:  # SCM_PIDFD, not SCM_RIGHTS
                    p.require(len(value) == 4); pidfds.append(struct.unpack("i", value)[0])
                elif kind == socket.SCM_RIGHTS:
                    received = array.array("i"); received.frombytes(value)
                    for fd in received:
                        os.close(fd)
                    raise ValueError("driver bootstrap reply must not carry descriptors")
                else:
                    raise ValueError("unknown driver bootstrap ancillary data")
            p.require(raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                and credentials == [(self._child_pid, 0, 0)] and len(pidfds) == 1
                and mechanics._pidfd_pid(pidfds[0]) == self._child_pid and not mechanics._terminal(pidfds[0]))
            self.check()
            return raw
        finally:
            for fd in pidfds:
                os.close(fd)

    def observation_original(self):
        self.check()
        return bytes(self._observation_raw)

    def await_gate_binding(self):
        """One actual post-drop gate observation for independent phase-two signing.

        This does not supply cgroup, label, IMA, readiness, or a generation grant.
        The gate waits on its original startup deadline until phase two arrives.
        """
        self.check()
        p.require(self._config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4"
            and not self._gate_attempted and not self._attempted)
        self._gate_attempted = True
        raw = self._receive(8192)
        notice = p.fields(p.document(raw, 8192), ("apiVersion", "configurationSha256", "windowSha256",
            "bootstrapObservationSha256", "gateExecutableSha256", "binding"))
        binding = p.fields(notice["binding"], ("apiVersion", "preparedSha256", "gateProcessId", "gateStartTimeTicks",
            "uid", "gid", "observedAtBoottimeNs"))
        gate = self._config["lifecycle"]["gate"]
        p.require(notice["apiVersion"] == "serverware.nativeShadowDriverGateBound/v1"
            and notice["configurationSha256"] == self._config_sha and notice["windowSha256"] == self._window_sha
            and notice["bootstrapObservationSha256"] == p.sha(self._observation_raw)
            and notice["gateExecutableSha256"] == gate["executableSha256"]
            and binding["apiVersion"] == "serverware.nativeShadowDriverLifecycleBound/v1"
            and (binding["uid"], binding["gid"]) == (gate["uid"], gate["gid"])
            and p.ns(binding["observedAtBoottimeNs"]) <= mechanics._clock() < self._startup)
        p.digest(binding["preparedSha256"])
        pid = p.integer(binding["gateProcessId"]); start = p.integer(binding["gateStartTimeTicks"])
        p.require(pid > 1 and start > 0)
        self._gate_pidfd = os.pidfd_open(pid, 0)
        p.require(mechanics._pidfd_pid(self._gate_pidfd) == pid and not mechanics._terminal(self._gate_pidfd)
            and mechanics._process(pid)[1] == start)
        self._gate_binding = notice
        self.check()
        return bytes(raw)

    def retain_scope(self, *, signed_scope_original, public_originals):
        """One signed-public-original handoff, not permission to operate/retry."""
        self.check(); p.require(self._config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v1"
            and not self._attempted and type(signed_scope_original) is bytes and type(public_originals) is bytes)
        signed = p.fields(p.document(signed_scope_original, 32768), ("payload", "signatureBase64url"))
        scope = p.fields(signed["payload"], ("apiVersion", "configurationSha256", "windowSha256", "observationSha256",
            "kernelDriverIdentitySha256", "invocationId", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs",
            "originals", "publicBundleSha256", "signingKeyId"))
        self._phase_key.verify(p.decoded(signed["signatureBase64url"], size=64), SCOPE_DOMAIN + p.canonical(scope))
        p.require(scope["apiVersion"] == "serverware.nativeShadowDriverScope/v1"
            and scope["configurationSha256"] == self._config_sha and scope["windowSha256"] == self._window_sha
            and scope["observationSha256"] == p.sha(self._observation_raw)
            and scope["kernelDriverIdentitySha256"] == self._observation["driver"]["identitySha256"]
            and scope["invocationId"] == self._window["invocationId"]
            and scope["startupDeadlineBoottimeNs"] == self._window["startupDeadlineBoottimeNs"]
            and scope["lifetimeDeadlineBoottimeNs"] == self._window["lifetimeDeadlineBoottimeNs"]
            and scope["signingKeyId"] == self._config["phaseTwoAuthority"]["keyId"]
            and scope["publicBundleSha256"] == p.sha(public_originals))
        bundle = p.fields(p.document(public_originals, 1024 * 1024), ("runtimeOriginal", "deliveryOriginal", "generationOriginals"))
        pins = p.fields(scope["originals"], ("runtimeSha256", "deliverySha256", "generationGrants"))
        p.fields(bundle["generationOriginals"], ROLES); p.fields(pins["generationGrants"], ROLES)
        for text, digest in [(bundle["runtimeOriginal"], pins["runtimeSha256"]), (bundle["deliveryOriginal"], pins["deliverySha256"]),
            *((bundle["generationOriginals"][role], pins["generationGrants"][role]) for role in ROLES)]:
            p.require(type(text) is str and text.isascii()); raw = text.encode("ascii")
            p.document(raw, 65536); p.require(p.sha(raw) == p.digest(digest))
        self._bundle = _sealed("native-shadow-driver-public-originals", public_originals, 0o400)
        self.check(); self._attempted = True
        count = self._socket.sendmsg([signed_scope_original], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array("i", [self._bundle]))], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        p.require(count == len(signed_scope_original))
        reply = p.fields(p.document(self._receive(4096), 4096), ("apiVersion", "observationSha256", "scopeSha256"))
        p.require(reply == {"apiVersion": "serverware.nativeShadowDriverPhaseTwoRetained/v1",
            "observationSha256": p.sha(self._observation_raw), "scopeSha256": p.sha(signed_scope_original)})
        return copy.deepcopy(reply)  # observation only; no constructed or ready

    def continue_scope(self, *, inputs, signed_scope_original, public_originals):
        """One actual retained-input handoff through native admission/bridge construction.

        A returned construction observation is not full-configuration TEE
        activation, READY, generation installation, or a retry capability.
        """
        from serverware.native_shadow_driver_inputs import OperationalInputs
        self.check()
        p.require(type(inputs) is OperationalInputs and inputs._driver is self
            and self._config["apiVersion"] in ("serverware.nativeShadowDriverBootstrapConfiguration/v2", "serverware.nativeShadowDriverBootstrapConfiguration/v3", "serverware.nativeShadowDriverBootstrapConfiguration/v4")
            and not self._attempted and type(signed_scope_original) is bytes and type(public_originals) is bytes)
        inputs.check()
        signed = p.fields(p.document(signed_scope_original, 32768), ("payload", "signatureBase64url"))
        scope = p.fields(signed["payload"], ("apiVersion", "configurationSha256", "windowSha256", "observationSha256",
            "kernelDriverIdentitySha256", "invocationId", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs",
            "originals", "publicBundleSha256", "signingKeyId", "operation"))
        suffix = self._config["apiVersion"].rsplit("/", 1)[1]
        if suffix == "v4":
            p.require(self._gate_binding is not None)
        domain = ("serverware.nativeShadowDriverScope.signature/" + suffix).encode("ascii") + b"\0"
        version = "serverware.nativeShadowDriverScope/" + suffix
        self._phase_key.verify(p.decoded(signed["signatureBase64url"], size=64), domain + p.canonical(scope))
        p.require(scope["apiVersion"] == version
            and scope["configurationSha256"] == self._config_sha and scope["windowSha256"] == self._window_sha
            and scope["observationSha256"] == p.sha(self._observation_raw)
            and scope["kernelDriverIdentitySha256"] == self._observation["driver"]["identitySha256"]
            and scope["invocationId"] == self._window["invocationId"]
            and scope["startupDeadlineBoottimeNs"] == self._window["startupDeadlineBoottimeNs"]
            and scope["lifetimeDeadlineBoottimeNs"] == self._window["lifetimeDeadlineBoottimeNs"]
            and scope["signingKeyId"] == self._config["phaseTwoAuthority"]["keyId"]
            and scope["publicBundleSha256"] == p.sha(public_originals)
            and p.canonical(scope["operation"]) == inputs._operation)
        bundle = p.fields(p.document(public_originals, 1024 * 1024), ("runtimeOriginal", "deliveryOriginal", "generationOriginals"))
        pins = p.fields(scope["originals"], ("runtimeSha256", "deliverySha256", "generationGrants"))
        p.fields(bundle["generationOriginals"], ROLES); p.fields(pins["generationGrants"], ROLES)
        p.require(bundle["runtimeOriginal"].encode("ascii") == inputs._runtime_raw
            and bundle["deliveryOriginal"].encode("ascii") == inputs._delivery_raw)
        for text, digest in [(bundle["runtimeOriginal"], pins["runtimeSha256"]), (bundle["deliveryOriginal"], pins["deliverySha256"]),
                *((bundle["generationOriginals"][role], pins["generationGrants"][role]) for role in ROLES)]:
            p.require(type(text) is str and text.isascii()); raw = text.encode("ascii")
            p.document(raw, 65536); p.require(p.sha(raw) == p.digest(digest))
        self._bundle = _sealed("native-shadow-driver-public-originals", public_originals, 0o400)
        self._operational_inputs = inputs  # retained through unknown and actual child cleanup
        self.check(); fds = inputs._begin(self)
        self._attempted = True
        count = self._socket.sendmsg([signed_scope_original], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array("i", [self._bundle, *fds]))], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        p.require(count == len(signed_scope_original))
        expected = {"apiVersion": "serverware.nativeShadowDriverPhaseTwoRetained/v1",
            "observationSha256": p.sha(self._observation_raw), "scopeSha256": p.sha(signed_scope_original)}
        p.require(p.document(self._receive(4096), 4096) == expected)
        expected["apiVersion"] = "serverware.nativeShadowDriverBridgeConstructed/v1"
        p.require(p.document(self._receive(4096), 4096) == expected)
        self._constructed = True
        self.check()
        return copy.deepcopy(expected)

    def _receive_subtree_terminal(self):
        """One parent-authenticated waitid observation, never a settlement grant."""
        while True:
            self._origin()
            remaining = self._lifetime - mechanics._clock(); p.require(remaining > 0)
            if select.select([self._socket], [], [], min(remaining / 1_000_000_000, 0.05))[0]:
                break
        raw, ancillary, flags, _ = self._socket.recvmsg(65536,
            socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
        credentials, pidfds = [], []
        try:
            for level, kind, value in ancillary:
                p.require(level == socket.SOL_SOCKET)
                if kind == socket.SCM_CREDENTIALS:
                    p.require(len(value) == 12); credentials.append(struct.unpack("3i", value))
                elif kind == 4:
                    p.require(len(value) == 4); pidfds.append(struct.unpack("i", value)[0])
                elif kind == socket.SCM_RIGHTS:
                    received = array.array("i"); received.frombytes(value)
                    for fd in received:
                        os.close(fd)
                    raise ValueError("lifecycle terminal original cannot carry descriptors")
                else:
                    raise ValueError("unknown lifecycle terminal ancillary data")
            p.require(raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                and credentials == [(self._child_pid, 0, 0)] and len(pidfds) == 1)
            # The parent can exit after sending. Match the retained kernel
            # PIDFD object rather than inventing a live proc identity then.
            actual, retained = os.fstat(pidfds[0]), os.fstat(self._pidfd)
            p.require((actual.st_dev, actual.st_ino) == (retained.st_dev, retained.st_ino))
            value = p.fields(p.document(raw, 65536), ("apiVersion", "configurationSha256", "windowSha256",
                "parent", "driver", "adopted", "completedAtBoottimeNs", "lifetimeDeadlineBoottimeNs"))
            p.require(value["apiVersion"] == "serverware.nativeShadowDriverSubtreeReaped/v1"
                and value["configurationSha256"] == self._config_sha and value["windowSha256"] == self._window_sha
                and value["lifetimeDeadlineBoottimeNs"] == self._window["lifetimeDeadlineBoottimeNs"]
                and p.ns(value["completedAtBoottimeNs"]) <= mechanics._clock() < self._lifetime)
            parent = p.fields(value["parent"], ("processId", "startTimeTicks", "parentId", "pidfdDevice", "pidfdInode"))
            p.require((parent["processId"], parent["startTimeTicks"], parent["parentId"])
                == (self._child_pid, self._child_start, self._pid)
                and (parent["pidfdDevice"], parent["pidfdInode"]) == (retained.st_dev, retained.st_ino))
            driver = p.fields(value["driver"], ("processId", "startTimeTicks", "pidfdDevice", "pidfdInode",
                "terminalCode", "terminalStatus", "observedAtBoottimeNs", "reapedAtBoottimeNs"))
            p.require((driver["processId"], driver["startTimeTicks"]) == (self._driver_pid, self._driver_start)
                and p.integer(driver["terminalCode"]) in (1, 2, 3)
                and type(driver["terminalStatus"]) is int and 0 <= driver["terminalStatus"] <= 255
                and p.ns(driver["observedAtBoottimeNs"]) <= p.ns(driver["reapedAtBoottimeNs"])
                <= p.ns(value["completedAtBoottimeNs"]))
            held_driver = os.fstat(self._driver_pidfd)
            p.require((driver["pidfdDevice"], driver["pidfdInode"]) == (held_driver.st_dev, held_driver.st_ino)
                and type(value["adopted"]) is list and len(value["adopted"]) <= 15)
            seen = {(self._driver_pid, self._driver_start)}
            for item in value["adopted"]:
                item = p.fields(item, ("process", "terminalCode", "terminalStatus", "reapedAtBoottimeNs"))
                process = p.fields(item["process"], ("processId", "startTimeTicks", "parentId", "pidfdDevice", "pidfdInode"))
                identity = (p.integer(process["processId"]), p.integer(process["startTimeTicks"]))
                p.require(identity not in seen and identity[0] > 1 and identity[1] > 0
                    and process["parentId"] == self._child_pid and p.integer(item["terminalCode"]) in (1, 2, 3)
                    and type(item["terminalStatus"]) is int and 0 <= item["terminalStatus"] <= 255
                    and type(process["pidfdDevice"]) is int and process["pidfdDevice"] >= 0
                    and p.integer(process["pidfdInode"]) > 0
                    and p.ns(item["reapedAtBoottimeNs"]) <= p.ns(value["completedAtBoottimeNs"]))
                seen.add(identity)
            return bytes(raw)
        finally:
            for fd in pidfds:
                os.close(fd)

    def close(self):
        global _LIVE
        if self._closed:
            return
        lifecycle = getattr(self, "_config", {}).get("apiVersion") == "serverware.nativeShadowDriverBootstrapConfiguration/v4"
        cleanup_error = None
        if lifecycle and self._socket is not None and self._driver_pidfd is not None:
            p.require(not self._cleanup_attempted)
            self._cleanup_attempted = True
            try:
                # A half-close requests actual subreaper cleanup while keeping
                # the sole authenticated terminal-original receive path alive.
                self._socket.shutdown(socket.SHUT_WR)
                self._subtree_terminal_original = self._receive_subtree_terminal()
            except BaseException as error:
                cleanup_error = error
        if self._socket is not None:
            self._socket.close(); self._socket = None
        if self._child_pid is not None:
            self._origin()
            if self._pidfd is None:
                p.require(mechanics._process(self._child_pid)[0] == self._pid)
                self._pidfd = os.pidfd_open(self._child_pid, 0)
            # Use only original lifetime. No cleanup interval renews admission.
            for fd in (self._driver_pidfd, self._pidfd):
                if fd is not None and not mechanics._terminal(fd):
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
            while any(fd is not None and not mechanics._terminal(fd) for fd in (self._driver_pidfd, self._pidfd)):
                p.require(mechanics._clock() < self._lifetime)
                select.select([], [], [], 0.001)
            terminal = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            p.require(terminal is not None and terminal.si_pid == self._child_pid)
            reaped = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED)
            p.require((reaped.si_pid, reaped.si_code, reaped.si_status) == (terminal.si_pid, terminal.si_code, terminal.si_status))
        if cleanup_error is not None:
            # No second cleanup/contact attempt and no release of business
            # originals on an unknown subtree result. The retained live owner
            # is deliberately not reset into a new bootstrap invocation.
            raise cleanup_error
        prepared_inputs = getattr(self, "_prepared_inputs", None)
        if prepared_inputs is not None:
            prepared_inputs._close_after_exit(self)
        outgoing = getattr(self, "_outgoing_resources", None)
        if outgoing is not None:
            outgoing._close_after_driver_exit(self)
        for fd in (self._driver_pidfd, self._pidfd, self._exec, self._bundle, self._gate_pidfd):
            if fd is not None:
                os.close(fd)
        for original in reversed(self._originals):
            original.close()
        self._closed = True
        if _LIVE is self:
            _LIVE = None

    def subtree_terminal_original(self):
        """Completed local observation only; not a grant or retry permission."""
        p.require(self._closed and self._subtree_terminal_original is not None)
        return bytes(self._subtree_terminal_original)

    def __enter__(self):
        self.check(); return self

    def __exit__(self, *_):
        self.close()
