"""Actual fixed retrieval listener/object activation preparation for a launcher.

No process is launched, no socket listens, and no key is created here. The
operator must retain this same-process owner through one explicit handoff.
Closing or failing preserves the socket pathname for explicit reconciliation.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat
import time

from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_retrieval_artifacts as artifacts
from catchplate.native_shadow_retrieval_store import READ_FLAGS, _identity

p = delivery.p
SOCKET_PATH = "/run/catchplate-shadow-retrieval/listener.sock"
_TOKEN = object()


def _structural(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class RetrievalActivation:
    """Retains actual originals; serialized projections cannot construct one."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._parents = [], []
        self._socket = None
        self._closed = self._sign_attempted = self._taken = False
        self._signed = None
        self._spool, self._spool_fds = None, ()
        self._cohort_handoff = False
        self._received_core = self._core_fd = self._core_identity = None

    @classmethod
    def prepare(cls, *, configuration_raw, configuration_sha256, peer_raw, peer_sha256,
                object_directory_fd, startup_deadline_boottime_ns):
        p.require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        cold = delivery.configuration(configuration_raw, configuration_sha256)
        peer = artifacts._peer(peer_raw)
        p.require(p.sha(peer_raw) == p.digest(peer_sha256) and peer["uid"] != cold["uid"])
        deadline = p.ns(startup_deadline_boottime_ns)
        p.require(_clock() < deadline <= _clock() + 30_000_000_000)
        owner = cls(_TOKEN)
        try:
            owner._pid, owner._start, owner._boot = os.getpid(), originals._start(), originals._boot()
            owner._deadline, owner._configuration_raw = deadline, configuration_raw
            owner._configuration_sha256, owner._uid, owner._peer_gid = configuration_sha256, cold["uid"], peer["gid"]
            directory = fcntl.fcntl(object_directory_fd, fcntl.F_DUPFD_CLOEXEC, 128)
            owner._fds.append(directory)
            info = os.fstat(directory)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o555
                and fcntl.fcntl(directory, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
            owner._objects, owner._objects_identity = directory, _identity(info)
            parent = os.open("/", READ_FLAGS | os.O_DIRECTORY)
            owner._fds.append(parent)
            for component in ("run", "catchplate-shadow-retrieval"):
                info = os.fstat(parent)
                p.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
                child = os.open(component, READ_FLAGS | os.O_DIRECTORY, dir_fd=parent)
                owner._fds.append(child)
                owner._parents.append((parent, component, child, _structural(os.fstat(child))))
                parent = child
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o711)
            owner._path_directory = parent
            # This advisory lock serializes cooperating preparations only; the
            # protected directory and exclusive kernel bind remain mandatory.
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                os.stat("listener.sock", dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("retrieval listener already exists; reconciliation required")
            owner._socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            owner._socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            owner._socket.setsockopt(socket.SOL_SOCKET, 76, 1)  # mandatory Linux SO_PASSPIDFD
            owner._socket.bind(SOCKET_PATH)
            os.chown("listener.sock", owner._uid, owner._peer_gid, dir_fd=parent, follow_symlinks=False)
            os.chmod("listener.sock", 0o660, dir_fd=parent, follow_symlinks=False)
            owner._path_identity = _identity(os.stat("listener.sock", dir_fd=parent, follow_symlinks=False))
            p.require(stat.S_ISSOCK(owner._path_identity[2]) and stat.S_IMODE(owner._path_identity[2]) == 0o660
                and owner._path_identity[3:5] == (owner._uid, owner._peer_gid))
            owner._socket_identity = _identity(os.fstat(owner._socket.fileno()))
            owner.check()
            return owner
        except BaseException:
            owner.close()
            raise

    def check(self):
        p.require(not self._closed and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and _clock() < self._deadline)
        for parent, component, child, expected in self._parents:
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0
                and _structural(os.fstat(child)) == expected
                and _structural(os.stat(component, dir_fd=parent, follow_symlinks=False)) == expected)
        p.require(_identity(os.fstat(self._objects)) == self._objects_identity
            and _identity(os.stat("listener.sock", dir_fd=self._path_directory, follow_symlinks=False)) == self._path_identity
            and _identity(os.fstat(self._socket.fileno())) == self._socket_identity
            and self._socket.getsockname() == SOCKET_PATH
            and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
            and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
            and self._socket.getsockopt(socket.SOL_SOCKET, 76) == 1
            and fcntl.fcntl(self._socket.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK)
        for fd in (self._objects, self._socket.fileno()):
            p.require(not os.get_inheritable(fd))
        if self._spool is not None:
            actual = self._spool.retrieval_additions(self)
            p.require(len(self._spool_fds) == len(actual) == 2)
            for (name, fd), (source_name, source_fd) in zip(self._spool_fds, actual, strict=True):
                p.require(name == source_name and _structural(os.fstat(fd)) == _structural(os.fstat(source_fd))
                    and not os.get_inheritable(fd)
                    and fcntl.fcntl(fd, fcntl.F_GETFL) == fcntl.fcntl(source_fd, fcntl.F_GETFL))
        if self._received_core is not None:
            self._received_core.check()
            source = self._received_core.borrowed_core_fd()
            p.require(_identity(os.fstat(self._core_fd)) == self._core_identity == _identity(os.fstat(source))
                and not os.get_inheritable(self._core_fd)
                and fcntl.fcntl(self._core_fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)

    def bind_spool(self, spool_inputs):
        """Only SpoolInputs.prepare_retrieval may select the real full4 owner.

        The actual SpoolInputs must already retain this exact pristine object.
        Duplicate its store/lock descriptors, preserving the held lock OFD.
        """
        from catchplate.native_shadow_spool_inputs import SpoolInputs
        p.require(type(self) is RetrievalActivation and type(spool_inputs) is SpoolInputs)
        self.check()
        p.require(self._spool is None and not self._sign_attempted and not self._taken)
        additions = spool_inputs.retrieval_additions(self)
        p.require(tuple(name for name, _ in additions) == delivery.SPOOL_RETRIEVAL_NAMES[2:])
        self._spool = spool_inputs  # Retained through any partial failure.
        held = []
        for name, source in additions:
            fd = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 128)
            self._fds.append(fd)
            held.append((name, fd))
        self._spool_fds = tuple(held)
        self.check()

    def bind_received_core(self, spool_inputs, received_core):
        """The exact ACK-gated inode, never a caller FD number or path."""
        from catchplate.native_pilot_genesis_core_channel import ReceivedGenesisCore
        from catchplate import native_pilot_genesis_parent_control_io as io
        self.check()
        p.require(self._spool is spool_inputs and spool_inputs._cohort.adoption_selected()
            and type(received_core) is ReceivedGenesisCore and received_core._adopted_cohort is spool_inputs._cohort
            and self._received_core is None and not self._taken and not self._sign_attempted)
        received_core.check()
        self._received_core = received_core  # Retain before any descriptor acquisition.
        source = received_core.borrowed_core_fd()
        with io.owning():
            self._core_fd = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 128)
            self._fds.append(self._core_fd)
        self._core_identity = _identity(os.fstat(source))
        p.require(self._deadline <= received_core.deadline_boottime_ns)
        self.check()

    def _descriptors(self):
        core = () if self._received_core is None else (("publication-genesis-core", self._core_fd),)
        return (("retrieval-listener", self._socket.fileno()), ("retrieval-objects", self._objects)) + self._spool_fds + core

    def activation(self):
        self.check()
        entries = []
        for target, (name, fd) in enumerate(self._descriptors(), 6):
            info = os.fstat(fd)
            entries.append({"name": name, "fd": target, "device": info.st_dev, "inode": info.st_ino,
                "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid})
        self.check()
        return entries

    def sign_delivery(self, *, payload_raw, signing_key):
        self.check()
        p.require(self._spool is None and not self._sign_attempted and not self._taken)
        self._sign_attempted = True
        signed = delivery.sign_retrieval_delivery(configuration_raw=self._configuration_raw,
            configuration_sha256=self._configuration_sha256, payload_raw=payload_raw, signing_key=signing_key,
            activation=self.activation(), boot=self._boot, startup_deadline=self._deadline, now=_clock())
        self.check()
        self._signed = signed
        return signed

    def admit_delivery(self, *, signed_delivery_original):
        """One full4 signature intake; failed intake cannot be retried/signed."""
        self.check()
        p.require(self._spool is not None and not self._sign_attempted and not self._taken)
        self._sign_attempted = True
        verify = delivery.verify_spool_retrieval_delivery
        extra = {}
        if self._received_core is not None:
            p.require(self._spool._cohort.adoption_selected())
            observed, bundle = self._received_core.originals()
            extra = dict(core_observation_raw=observed, core_bundle_raw=bundle)
            verify = delivery.verify_adopted_retrieval_delivery
        signed = verify(configuration_raw=self._configuration_raw,
            configuration_sha256=self._configuration_sha256, signed_delivery_original=signed_delivery_original,
            activation=self.activation(), boot=self._boot, startup_deadline=self._deadline, now=_clock(), **extra)
        self._spool.require_retrieval_delivery(self, signed)
        self.check()
        self._signed = signed
        return signed

    def signed_original(self):
        self.check()
        p.require(self._spool is not None and self._signed is not None)
        return self._signed

    def cohort_descriptors(self, spool_inputs):
        """Borrowed real FDs only for the exact retained cohort adapter."""
        self.check()
        p.require(self._spool is spool_inputs and self._spool is not None
            and self._taken and self._signed is not None and self._cohort_handoff)
        self._cohort_handoff = False
        return tuple((target, fd) for target, (_, fd) in enumerate(self._descriptors(), 6))

    def take_for_cohort(self, *, launch_pin):
        """One full4 retained transfer; no send, listen or launch result.

        Spool genesis must already retain this same admitted C9. The existing
        cohort adapter checks this owner immediately before its one release,
        then retains resources without reapplying preparation checks.
        """
        self.check()
        p.require(self._spool is not None and not self._taken and self._signed is not None)
        self._taken = True
        self._cohort_handoff = True
        try:
            return self._spool.retain_retrieval_transfer(self, launch_pin=launch_pin)
        finally:
            self._cohort_handoff = False

    def take_for_launch(self, *, signed_delivery_sha256):
        """One ownership transfer of actual dup FDs; caller owns successful FDs.

        Targets6/7 must be installed by the separately supervised launcher. No
        descriptor number, tuple or returned signature proves that launch ran.
        """
        self.check()
        p.require(self._spool is None and not self._taken and self._signed is not None
            and p.sha(self._signed) == p.digest(signed_delivery_sha256))
        self._taken = True
        owned = []
        try:
            for fd in (self._socket.fileno(), self._objects):
                owned.append(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128))
            self.check()
            return ((6, owned[0]), (7, owned[1]))
        except BaseException:
            for fd in owned:
                os.close(fd)
            raise

    def close(self):
        if self._closed:
            return
        if self._spool is not None:
            self._spool.require_retrieval_retired(self)
        self._closed = True
        if self._socket is not None:
            self._socket.close()
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()
        # The actual received owner remains with the pilot until the cohort
        # itself is closed; closing these duplicate OFDs is not that custody.
        # Intentionally no unlink/rmdir, including failed preparation.

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_):
        self.close()
