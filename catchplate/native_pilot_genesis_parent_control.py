"""One retained, independently pinned native parked-genesis controller.

No signatures, expected owners, runtime, activation resources or receipt are
manufactured here. The pinned native controller authenticates the complete
cold protocol and exports the literal Bundle. Python returns that original
only after bounded EOF, native exit zero and actual same-PIDFD reap. Failure
retains this owner; it never retries release or substitutes a numeric PID kill.
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
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import custody_generation_grants as codec
from catchplate import native_pilot_genesis_parent_authority as authority
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_pilot_genesis_coordinator_peer as peer_wire
from catchplate import native_pilot_peer_resources as peer_resources
from catchplate import native_shadow_guest_delivery as c9
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_shadow_proof_cohort_control import _Original, _process, _structural, _terminal

p = codec.p
EXECUTABLE = "/opt/catchplate/catchplate-native-publication-genesis-controller"
CONFIGURATION = "/etc/catchplate/native-publication-genesis-parent.json"
PRECREATION = "/etc/catchplate/native-publication-genesis-precreation.json"
CONTROL_API = "catchplate.nativePublicationGenesisControllerControl/v1"
MAX_WIRE, MAX_BUNDLE = 32768, 4 * 1024 * 1024
RESERVE = 250_000_000
_TOKEN, _LIVE, _USED = object(), None, False
_RUNTIME_FIELDS = ("apiVersion", "scope", "durableGrantOriginal", "currentGrantOriginal",
    "histories", "serviceSessions", "nativeEndpoints", "resultPeer")


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _control(raw):
    value = p.fields(codec.document(raw, 4096), ("apiVersion", "controllerExecutableSha256",
        "configurationSha256", "precreationSha256"))
    p.require(value["apiVersion"] == CONTROL_API)
    for name in ("controllerExecutableSha256", "configurationSha256", "precreationSha256"):
        p.digest(value[name])
    return value


def _bundle(raw, scope):
    # Full signatures/history/Stored validation belongs to the retained native
    # controller, whose successful terminal result is required by finish().
    value = p.fields(codec.document(raw, MAX_BUNDLE), ("completion", "durable", "current"))
    completion = p.fields(value["completion"], ("apiVersion", "prepared", "stored", "receiptOriginal",
        "completedAtBoottimeNanos", "signature"))
    p.require(completion["apiVersion"] == "catchplate.nativePublicationGenesisCompletion/v1"
        and codec.canonical(completion["prepared"]["core"]["genesis"]["scope"]) == codec.canonical(scope))
    p.require(type(completion["receiptOriginal"]) is str and completion["receiptOriginal"].isascii()
        and 0 < len(completion["receiptOriginal"]) <= MAX_BUNDLE)
    completed = p.integer(completion["completedAtBoottimeNanos"], maximum=p.MAX_U64)
    durable = p.integer(value["durable"]["completedAtBoottimeNanos"], maximum=p.MAX_U64)
    current = p.integer(value["current"]["completedAtBoottimeNanos"], maximum=p.MAX_U64)
    p.require(scope["issuedAtBoottimeNanos"] <= completed <= durable <= current < scope["expiresAtBoottimeNanos"])
    return value


class GenesisControllerError(ValueError):
    """The actual owner is available for one bounded terminal cleanup attempt."""
    def __init__(self, owner, *, cleanup_unknown=False):
        super().__init__("cold genesis controller refused; " +
            ("cleanup unknown, owner retained" if cleanup_unknown else "actual owner retained for cleanup"))
        self.owner = owner
        self.cleanup_unknown = cleanup_unknown


class ParkedGenesisController:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start_ticks, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last_clock = _clock()
        self._named, self._inputs, self._received, self._activation = [], [], [], []
        self._controller_pid = self._pidfd = self._exec = self._stdout = self._socket = None
        self._parked_fd = self._observed = self._observation_raw = self._runtime = None
        self._result = self._window = self._context = self._scope = None
        self._started = self._release_attempted = self._released = self._finish_attempted = False
        self._closed = self._close_attempted = self._reaped = self._failed = False
        self._stdout_eof = False
        self._output = bytearray()
        self._spawn_mask = self._terminal_result = None
        self._peer = self._peer_raw = None
        self._peer_attempted = False

    @classmethod
    def prepare(cls, *, control_fd, control_sha256):
        global _LIVE, _USED
        p.require(cls is ParkedGenesisController and _LIVE is None and not _USED)
        io.public_io._process()
        p.require(len(os.listdir("/proc/self/task")) == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
        owner = cls(_TOKEN)
        _LIVE, _USED = owner, True  # Partial acquisition cannot create a second attempt.
        try:
            control = _control(owner._input(control_fd, 4096, control_sha256).raw)
            owner._configuration = owner._open(CONFIGURATION, MAX_WIRE, control["configurationSha256"])
            owner._precreation = owner._open(PRECREATION, MAX_WIRE, control["precreationSha256"])
            raw_config = codec.document(owner._configuration.raw, MAX_WIRE)
            pin = raw_config["deliveryConfiguration"]
            c9._pin(pin)
            owner._cold = owner._open(pin["path"], 65536, pin["sha256"])
            owner._context = authority.validate_precreation(owner._precreation.raw,
                configuration_raw=owner._configuration.raw, delivery_configuration_raw=owner._cold.raw,
                boot=owner._boot, now_boottime_ns=owner._sample())
            owner._window = owner._context["window"]
            owner._startup = p.ns(owner._window["startupDeadlineBoottimeNs"])
            owner._lifetime = p.ns(owner._window["lifetimeDeadlineBoottimeNs"])
            owner._deadline = owner._lifetime
            owner._executable = owner._open(EXECUTABLE, io.MAX_EXECUTABLE,
                control["controllerExecutableSha256"], 0o555)
            io.require_static_elf(owner._executable.raw)
            with io.owning():
                low = os.memfd_create("catchplate-genesis-controller", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                try:
                    owner._exec = fcntl.fcntl(low, fcntl.F_DUPFD_CLOEXEC, 128)
                finally:
                    os.close(low)
            offset = 0
            while offset < len(owner._executable.raw):
                count = os.pwrite(owner._exec, owner._executable.raw[offset:offset + 65536], offset)
                p.require(count > 0)
                offset += count
            os.fchmod(owner._exec, 0o500)
            fcntl.fcntl(owner._exec, fcntl.F_ADD_SEALS, io.public_io.SEALS)
            owner._exec_identity = originals._identity(os.fstat(owner._exec))
            p.require(os.pread(owner._exec, len(owner._executable.raw) + 1, 0) == owner._executable.raw)
            owner._check_sources(full=True)
            owner._before_release()
            return owner
        except BaseException as error:
            owner._failed = True
            raise GenesisControllerError(owner) from error

    def _input(self, fd, maximum, digest):
        with io.owning():
            value = io.PublicInput(fd, maximum, digest)
            self._inputs.append(value)
        return value

    def _open(self, path, maximum, digest, mode=0o400):
        p.require(len(self._named) < 16)
        with io.owning():
            value = _Original(path, maximum, digest, mode)
            self._named.append(value)
        return value

    def _origin(self):
        p.require(_LIVE is self and not self._closed and os.getpid() == self._pid
            and originals._start() == self._start_ticks and originals._boot() == self._boot
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _sample(self, deadline=None):
        self._origin()
        now = _clock()
        p.require(self._last_clock <= now and (deadline is None or now < deadline))
        self._last_clock = now
        return now

    def _before_release(self):
        now = self._sample(self._context["deadline"])
        p.require(not self._close_attempted and not self._failed
            and p.ns(self._window["issuedAtBoottimeNs"]) <= now < self._startup
            and now + RESERVE < self._lifetime)

    def _check_sources(self, *, full=False):
        self._origin()
        if self._peer is not None:
            if _terminal(self._peer.pidfd):
                p.require(self._released or self._close_attempted)
            else:
                self._peer.check()
        for value in self._inputs:
            value.check() if full else value.check_identity()
        for value in self._named:
            value.check() if full else io.original_identity(value)
        if hasattr(self, "_image"):
            self._image.check() if full else self._image.check_identity()
        if self._exec is not None and hasattr(self, "_exec_identity"):
            p.require(originals._identity(os.fstat(self._exec)) == self._exec_identity
                and not os.get_inheritable(self._exec)
                and fcntl.fcntl(self._exec, fcntl.F_GET_SEALS) == io.public_io.SEALS)
        for fd, entry in self._activation:
            p.require(_structural(os.fstat(fd)) == tuple(entry[k] for k in ("device", "inode", "mode", "uid", "gid"))
                and not os.get_inheritable(fd))

    def _controller(self, *, terminal=False):
        self._origin()
        p.require(self._pidfd is not None and not self._reaped
            and io.pidfd_pid(self._pidfd) == self._controller_pid
            and _process(self._controller_pid) == (self._pid, self._controller_start))
        if not terminal:
            p.require(not _terminal(self._pidfd)
                and os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None)
            current = os.stat("/proc/" + str(self._controller_pid) + "/exe")
            p.require((current.st_dev, current.st_ino, current.st_size)
                == (self._exec_identity[0], self._exec_identity[1], self._exec_identity[6]))

    def _parked(self):
        p.require(self._parked_fd is not None and not _terminal(self._parked_fd)
            and io.pidfd_pid(self._parked_fd) == self._observed["processId"]
            and _process(self._observed["processId"]) == (self._controller_pid, self._observed["startTimeTicks"]))
        value = os.fstat(self._parked_fd)
        p.require((value.st_dev, value.st_ino) == (self._observed["pidfdDevice"], self._observed["pidfdInode"]))

    def _spawn(self):
        # Block only cancellation while actual process/FD ownership is in
        # flight. A failure to acquire the PIDFD leaves the true spawn PID and
        # mask retained, never a generic numeric-PID signalling fallback.
        self._spawn_mask = signal.pthread_sigmask(signal.SIG_BLOCK, io.CANCELLATION)
        temporary = []
        child_socket = None
        try:
            parent, child_socket = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            self._socket = parent
            parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            parent.setsockopt(socket.SOL_SOCKET, 76, 1)
            source = fcntl.fcntl(child_socket.fileno(), fcntl.F_DUPFD_CLOEXEC, 128)
            temporary.append(source)
            read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            self._stdout = read
            temporary.append(write)
            self._stdout_identity = _structural(os.fstat(read))
            output = fcntl.fcntl(write, fcntl.F_DUPFD_CLOEXEC, 128)
            temporary.append(output)
            null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            temporary.append(null)
            info = os.fstat(null)
            p.require(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (1, 3))
            null_high = fcntl.fcntl(null, fcntl.F_DUPFD_CLOEXEC, 128)
            temporary.append(null_high)
            actions = [(os.POSIX_SPAWN_DUP2, null_high, 0), (os.POSIX_SPAWN_DUP2, output, 1),
                (os.POSIX_SPAWN_DUP2, null_high, 2), (os.POSIX_SPAWN_DUP2, source, 3)]
            for text in os.listdir("/proc/self/fd"):
                fd = int(text)
                if fd > 3 and fd != self._exec:
                    try:
                        os.fstat(fd)
                    except OSError:
                        continue
                    actions.append((os.POSIX_SPAWN_CLOSE, fd))
            self._controller_pid = os.posix_spawn("/proc/self/fd/" + str(self._exec),
                [EXECUTABLE, "--parked-genesis"], {}, file_actions=actions,
                setsigmask=(), setsigdef=(signal.SIGPIPE, signal.SIGCHLD))
            self._pidfd = os.pidfd_open(self._controller_pid, 0)
            os.set_inheritable(self._pidfd, False)
            parent_pid, self._controller_start = _process(self._controller_pid)
            p.require(parent_pid == self._pid and io.pidfd_pid(self._pidfd) == self._controller_pid)
            self._controller()
        finally:
            for fd in reversed(temporary):
                os.close(fd)
            if child_socket is not None:
                child_socket.close()
            if self._controller_pid is None or self._pidfd is not None:
                mask, self._spawn_mask = self._spawn_mask, None
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def _drain(self):
        p.require(self._stdout is not None and _structural(os.fstat(self._stdout)) == self._stdout_identity
            and fcntl.fcntl(self._stdout, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_NONBLOCK)
                == (os.O_RDONLY | os.O_NONBLOCK))
        if self._stdout_eof:
            return
        # Bound each turn as well as the complete native output.
        for _ in range(16):
            try:
                raw = os.read(self._stdout, min(65536, MAX_BUNDLE + 1 - len(self._output)))
            except (BlockingIOError, InterruptedError):
                return
            if not raw:
                self._stdout_eof = True
                return
            self._output.extend(raw)
            p.require(self._released and len(self._output) <= MAX_BUNDLE)

    def _result_pair(self):
        p.require(len(self._observed["resultActivation"]) == 2)
        if not hasattr(self, "_pair_slots"):
            names = os.listdir("/proc/" + str(self._controller_pid) + "/fd")
            p.require(len(names) <= 512)
            self._pair_slots = []
            for entry in self._observed["resultActivation"]:
                matches = []
                for text in names:
                    if not text.isdigit():
                        continue
                    path = "/proc/" + str(self._controller_pid) + "/fd/" + text
                    try:
                        info = os.stat(path)
                    except FileNotFoundError:
                        continue
                    if _structural(info) == tuple(entry[k] for k in ("device", "inode", "mode", "uid", "gid")):
                        matches.append(path)
                p.require(len(matches) == 1)
                self._pair_slots.append(matches[0])
        for path, entry in zip(self._pair_slots, self._observed["resultActivation"], strict=True):
            info = os.stat(path)
            p.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == info.st_gid == 0
                and _structural(info) == tuple(entry[k] for k in ("device", "inode", "mode", "uid", "gid")))

    def start(self):
        try:
            self._before_release()
            p.require(not self._started)
            self._started = True
            self._check_sources(full=True)
            self._spawn()
            while True:
                self._before_release()
                self._check_sources()
                self._controller()
                self._drain()
                p.require(not self._stdout_eof)
                packet = io.receive_observation(self._socket, self._received)
                if packet is None:
                    select.select([self._socket, self._stdout, self._pidfd], [], [], 0.01)
                    continue
                raw, credentials, sender, child = packet
                p.require(credentials == (self._controller_pid, 0, 0)
                    and io.pidfd_pid(sender) == self._controller_pid and not _terminal(sender)
                    and _structural(os.fstat(sender)) == _structural(os.fstat(self._pidfd)))
                observed = authority.validate_observation(raw, configuration_raw=self._configuration.raw,
                    precreation_raw=self._precreation.raw, context=self._context)
                self._observation_raw, self._observed, self._parked_fd = raw, observed, child
                self._parked()
                self._result_pair()
                self._controller()
                self._before_release()
                return bytes(raw)
        except BaseException as error:
            self._failed = True
            raise GenesisControllerError(self) from error

    def observation_original(self):
        self._before_release()
        self._controller()
        self._parked()
        p.require(not self._release_attempted)
        return bytes(self._observation_raw)

    def controller_observation(self):
        self.observation_original()
        info = os.fstat(self._pidfd)
        return {"processId": self._controller_pid, "startTimeTicks": self._controller_start,
            "uid": 0, "gid": 0, "pidfdDevice": info.st_dev, "pidfdInode": info.st_ino,
            "executable": {"device": self._exec_identity[0], "inode": self._exec_identity[1],
                "length": self._exec_identity[6], "sha256": p.sha(self._executable.raw)}}

    def peer_preparation_original(self):
        """Capture once from this actual parked child; retain until real reap."""
        try:
            self.observation_original()
            if not self._peer_attempted:
                self._peer_attempted = True
                observed = self._sample(self._context["deadline"])
                with io.owning():
                    self._peer = peer_resources._Peer(peer_resources._TOKEN,
                        pidfd=self._parked_fd, pid=self._observed["processId"],
                        start=self._observed["startTimeTicks"], parent=self._controller_pid,
                        executable_fd=None, expected=self._observed["executable"],
                        kind="genesis-coordinator", check=self._before_release)
                value = {"apiVersion": peer_wire.API, "profile": peer_wire.wire.PROFILE,
                    "ownerKind": peer_wire.ROLE, "phase": "parked-pre-exec",
                    "configurationSha256": p.sha(self._configuration.raw),
                    "sourceOriginalSha256": p.sha(self._observation_raw),
                    **{field: self._window[field] for field in ("bootIdBase64url", "timeNamespaceDevice",
                        "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs",
                        "lifetimeDeadlineBoottimeNs", "invocationId")},
                    "observedAtBoottimeNs": str(observed), "peers": {peer_wire.ROLE: self._peer.value}}
                self._peer_raw = codec.canonical(value)
            p.require(self._peer is not None and self._peer_raw is not None)
            self._peer.check()
            peer_wire.validate(self._peer_raw, observation_raw=self._observation_raw,
                configuration_raw=self._configuration.raw, precreation_raw=self._precreation.raw,
                delivery_configuration_raw=self._cold.raw, boot=self._boot,
                now_boottime_ns=self._sample(self._context["deadline"]))
            self.observation_original()
            return bytes(self._peer_raw)
        except BaseException as error:
            self._failed = True
            raise GenesisControllerError(self) from error

    def _release_sources(self, signed):
        # Authenticate this one release before following any of its paths.
        # The complete profile is then checked again with the literal files.
        p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
        payload = p.fields(signed["payload"], authority.RELEASE_FIELDS)
        selected_key = self._context["configuration"]["releaseAuthority"]
        p.require(signed["apiVersion"] == authority.RELEASE_API
            and payload["configurationSha256"] == p.sha(self._configuration.raw)
            and payload["precreationSha256"] == p.sha(self._precreation.raw)
            and payload["observationSha256"] == p.sha(self._observation_raw)
            and payload["invocationId"] == self._window["invocationId"]
            and payload["signingKeyId"] == selected_key["keyId"])
        Ed25519PublicKey.from_public_bytes(p.decoded(selected_key["publicKeyBase64url"], size=32)).verify(
            p.decoded(signed["signatureBase64url"], size=64),
            authority.signature_preimage(authority.RELEASE_DOMAIN, payload))
        pin = signed["payload"]["launch"]
        c9._pin(pin)
        launch = self._open(pin["path"], MAX_WIRE, pin["sha256"])
        value = codec.document(launch.raw, MAX_WIRE)
        selected = value["keyAdmission"]
        pin = selected["closure"]
        c9._pin(pin)
        closure = self._open(pin["path"], 1024 * 1024, pin["sha256"])
        authority.validate_release(self._release.raw, configuration_raw=self._configuration.raw,
            delivery_configuration_raw=self._cold.raw, precreation_raw=self._precreation.raw,
            observation_raw=self._observation_raw, launch_raw=launch.raw, closure_raw=closure.raw,
            boot=self._boot, now_boottime_ns=self._sample())
        pin = selected["delivery"]
        c9._pin(pin)
        delivery = self._open(pin["path"], 65536, pin["sha256"])
        envelope = p.fields(codec.document(delivery.raw, 65536), ("apiVersion", "payload", "signatureBase64url"))
        payload = p.fields(envelope["payload"], c9.FIELDS)
        cold = self._context["cold"]
        p.require(envelope["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1"
            and payload["configurationSha256"] == p.sha(self._cold.raw)
            and payload["authorityKeyId"] == cold["authority"]["keyId"]
            and all(payload[k] == cold[k] for k in ("uid", "gid", "serviceRole"))
            and all(payload[k] == self._window[k] for k in ("bootIdBase64url", "timeNamespaceDevice",
                "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")))
        Ed25519PublicKey.from_public_bytes(p.decoded(cold["authority"]["publicKeyBase64url"], size=32)).verify(
            p.decoded(envelope["signatureBase64url"], size=64), c9.DOMAIN + codec.canonical(payload))
        pin = payload["runtimeConfig"]
        c9._pin(pin)
        self._runtime = self._open(pin["path"], MAX_BUNDLE, pin["sha256"])
        runtime = p.fields(codec.document(self._runtime.raw, MAX_BUNDLE), _RUNTIME_FIELDS)
        p.require(runtime["apiVersion"] == "catchplate.nativePublicationGenesisCoordinatorRuntime/v2")
        self._scope = copy.deepcopy(runtime["scope"])
        p.require(tuple(self._scope[k] for k in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")) == self._boot
            and p.ns(self._window["issuedAtBoottimeNs"]) <= p.integer(self._scope["issuedAtBoottimeNanos"], maximum=p.MAX_U64)
            and self._scope["issuedAtBoottimeNanos"] < p.integer(self._scope["expiresAtBoottimeNanos"], maximum=p.MAX_U64) <= self._lifetime)
        self._deadline = self._scope["expiresAtBoottimeNanos"]
        rows = payload["activation"]
        p.require(type(rows) is list and len(rows) == 10
            and rows[8:] == self._observed["resultActivation"])
        for index, row in enumerate(rows, 6):
            p.fields(row, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
            p.require(row["fd"] == index and type(row["name"]) is str)
        p.require(len({row["name"] for row in rows}) == 10
            and len({(row["device"], row["inode"]) for row in rows}) == 10)
        pin = signed["payload"]["image"]
        c9._pin(pin)
        with io.owning():
            self._image = io.ImageOriginal(pin["path"], pin["sha256"])
        return rows[:8]

    def release(self, *, release_fd, release_sha256, activation_fds):
        return self._release_with_runtime(release_fd=release_fd, release_sha256=release_sha256,
            activation_fds=activation_fds, expected_runtime=None, check=lambda: None)

    def _release_with_runtime(self, *, release_fd, release_sha256, activation_fds, expected_runtime, check):
        try:
            self.observation_original()
            self._release_attempted = True  # Validation failure consumes this attempt too.
            p.require(type(activation_fds) is tuple and len(activation_fds) == 8
                and len(set(activation_fds)) == 8)
            self._release = self._input(release_fd, MAX_WIRE, release_sha256)
            signed = codec.document(self._release.raw, MAX_WIRE)
            rows = self._release_sources(signed)
            if expected_runtime is not None:
                p.require(type(expected_runtime) is bytes and self._runtime.raw == expected_runtime)
            with io.owning():
                for fd, row in zip(activation_fds, rows, strict=True):
                    p.require(type(fd) is int and fd >= 3 and not os.get_inheritable(fd))
                    info = os.fstat(fd)
                    p.require((stat.S_ISDIR(info.st_mode) or stat.S_ISSOCK(info.st_mode))
                        and _structural(info) == tuple(row[k] for k in ("device", "inode", "mode", "uid", "gid")))
                    duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128)
                    self._activation.append((duplicate, copy.deepcopy(row)))
            self._check_sources(full=True)
            self._before_release()
            check()
            self._sample(min(self._startup, self._deadline - RESERVE))
            self._controller()
            self._parked()
            self._result_pair()
            self._drain()
            p.require(not self._stdout_eof)
            rights = array.array("i", [fd for fd, _ in self._activation])
            with io.owning():
                self._sample(min(self._startup, self._deadline - RESERVE))
                count = self._socket.sendmsg([self._release.raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                    socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
                p.require(count == len(self._release.raw))
                self._released = True
            check()
            self._sample(min(self._startup, self._deadline - RESERVE))
            return None  # A sent packet is not admission, readiness or a result.
        except BaseException as error:
            self._failed = True
            raise GenesisControllerError(self) from error

    def _reap(self, terminal):
        with io.owning():
            actual = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOHANG)
            p.require(actual is not None and (actual.si_pid, actual.si_code, actual.si_status)
                == (terminal.si_pid, terminal.si_code, terminal.si_status))
            self._reaped = True
            self._terminal_result = (actual.si_code, actual.si_status)

    def finish(self):
        return self._finish_checked(lambda: None)

    def _finish_checked(self, check):
        try:
            self._origin()
            p.require(self._released and not self._failed and not self._finish_attempted and not self._close_attempted)
            self._finish_attempted = True
            self._check_sources(full=True)
            while True:
                check()
                self._sample(self._deadline)
                self._controller(terminal=True)
                self._check_sources()
                self._drain()
                terminal = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if terminal is not None:
                    p.require(terminal.si_pid == self._controller_pid and terminal.si_code == os.CLD_EXITED
                        and terminal.si_status == 0)
                    # Exit may occur just after the preceding nonblocking
                    # read returned EAGAIN. Observe real EOF separately; exit
                    # is never used to invent it or extend the original cap.
                    if not self._stdout_eof:
                        self._drain()
                        if not self._stdout_eof:
                            continue
                    p.require(_terminal(self._parked_fd) and io.pidfd_pid(self._parked_fd) == -1)
                    raw = bytes(self._output)
                    _bundle(raw, self._scope)
                    self._check_sources(full=True)
                    check()
                    self._sample(self._deadline)
                    self._reap(terminal)
                    self._sample(self._deadline)
                    self._result = raw
                    return bytes(raw)
                select.select([self._stdout, self._pidfd], [], [], 0.01)
        except BaseException as error:
            self._failed = True
            raise GenesisControllerError(self) from error

    def close(self):
        if self._closed:
            return {"status": "closed", "bundleAccepted": self._result is not None}
        self._origin()
        p.require(not self._close_attempted)
        self._close_attempted = True
        try:
            if self._controller_pid is not None and not self._reaped:
                if not hasattr(self, "_controller_start"):
                    parent, self._controller_start = _process(self._controller_pid)
                    p.require(parent == self._pid)
                if self._pidfd is None:
                    # Only the actual unreaped posix_spawn child is eligible.
                    parent, self._controller_start = _process(self._controller_pid)
                    p.require(parent == self._pid)
                    with io.owning():
                        self._pidfd = os.pidfd_open(self._controller_pid, 0)
                self._controller(terminal=True)
                if not _terminal(self._pidfd):
                    signal.pidfd_send_signal(self._pidfd, signal.SIGTERM, None, 0)
                while True:
                    self._sample(self._lifetime)
                    terminal = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                    if terminal is not None:
                        # Normal native return occurs only after its own actual
                        # child close/reap. Watchdog/signal death is NOT cleanup.
                        p.require(terminal.si_pid == self._controller_pid and terminal.si_code == os.CLD_EXITED
                            and terminal.si_status in (0, 1))
                        if self._parked_fd is not None:
                            p.require(_terminal(self._parked_fd) and io.pidfd_pid(self._parked_fd) == -1)
                        self._reap(terminal)
                        break
                    select.select([self._pidfd], [], [], 0.01)
            with io.owning():
                if self._peer is not None:
                    p.require(_terminal(self._peer.pidfd) and io.pidfd_pid(self._peer.pidfd) == -1)
                    self._peer.close()
                    self._peer = None
                if self._socket is not None:
                    self._socket.close()
                    self._socket = None
                for fd in set(self._received + [fd for fd, _ in self._activation]
                        + [fd for fd in (self._stdout, self._pidfd, self._exec) if fd is not None]):
                    os.close(fd)
                self._received.clear()
                self._activation.clear()
                self._stdout = self._pidfd = self._exec = None
                for value in self._inputs:
                    value.close()
                for value in self._named:
                    value.close()
                if hasattr(self, "_image"):
                    self._image.close()
                self._closed = True
            if self._spawn_mask is not None:
                mask, self._spawn_mask = self._spawn_mask, None
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            return {"status": "closed" if self._started else "not-started", "bundleAccepted": self._result is not None}
        except BaseException as error:
            # _LIVE keeps originals, actual controller/descendant PIDFDs and
            # activation FDs reachable. No second cancellation or release.
            raise GenesisControllerError(self, cleanup_unknown=True) from error
