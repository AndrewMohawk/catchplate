"""Purpose-fixed native publication launch inputs, not launch or permission.

Creates an actual socket pair and a fresh retained journal from independently
supplied/pinned initial state. Existing separately provisioned signers approve
exact C9/operational originals explicitly. No key, trust, ready state or initial
publication is generated. Failure leaves journal artifacts for reconciliation.
"""
from __future__ import annotations

import fcntl
import ctypes
import os
import socket
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_key_admission_profile as admission
from catchplate import native_shadow_nitro_originals as originals

p = delivery.p
ROOT = "/var/lib/catchplate/native-policy-activation"
DOMAIN = "catchplate.nativeShadowActivationServiceAssignment.signature/v1"
_TOKEN = object()


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _file_identity(value):
    return _identity(value) + (value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _durable_fs(fd):
    # Fixed Linux x86_64 ABI only. Filesystem type is a refusal filter, not a
    # claim that deployment has proved underlying power-loss persistence.
    p.require(os.uname().machine == "x86_64" and ctypes.sizeof(ctypes.c_long) == 8)
    class Statfs(ctypes.Structure):
        _fields_ = [("kind", ctypes.c_long), ("block_size", ctypes.c_long),
            ("blocks", ctypes.c_ulong), ("free", ctypes.c_ulong), ("available", ctypes.c_ulong),
            ("files", ctypes.c_ulong), ("free_files", ctypes.c_ulong), ("fsid", ctypes.c_int * 2),
            ("name_length", ctypes.c_long), ("fragment_size", ctypes.c_long), ("flags", ctypes.c_long),
            ("spare", ctypes.c_long * 4)]
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes, libc.fstatfs.restype = (ctypes.c_int, ctypes.POINTER(Statfs)), ctypes.c_int
    value = Statfs()
    p.require(ctypes.sizeof(value) == 120 and libc.fstatfs(fd, ctypes.byref(value)) == 0
        and value.kind in {0xEF53, 0x58465342, 0x9123683E} and value.flags & 1 == 0)


def _read(fd, bound):
    info = os.fstat(fd)
    p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= bound)
    raw = os.pread(fd, info.st_size + 1, 0)
    p.require(len(raw) == info.st_size and _file_identity(os.fstat(fd)) == _file_identity(info))
    return raw


def initial_state(raw, expected):
    value = p.fields(p.document(raw, 1024 * 1024 + 16384), ("apiVersion", "assignmentPayloadSha256", "generationId",
        "generationPublicationEnvelopeSha256", "publication", "previousStateSha256", "preparedOriginal"))
    p.require(p.sha(raw) == p.digest(expected) and value["apiVersion"] == "catchplate.nativePolicyActivationState/v1"
        and value["previousStateSha256"] is None and value["preparedOriginal"] is None)
    for name in ("assignmentPayloadSha256", "generationId", "generationPublicationEnvelopeSha256"):
        p.digest(value[name])
    publication = p.fields(value["publication"], ("revision", "policySha256", "policySequence", "rollbackEpoch"))
    p.digest(publication["policySha256"])
    for name in ("revision", "policySequence"):
        p.integer(publication[name], maximum=2**63 - 1)
    p.integer(publication["rollbackEpoch"], minimum=0, maximum=2**63 - 1)
    return value


class ActivationInputs:
    """Same process/start/boot originals; a projection cannot construct one."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._parents, self._sockets = [], [], []
        self._closed = self._delivery_attempted = self._grant_attempted = self._taken = False
        self._signed = self._grant = None

    @classmethod
    def prepare(cls, *, configuration_raw, configuration_sha256, initial_state_raw, initial_state_sha256,
                startup_deadline_boottime_ns):
        p.require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        cold = delivery.configuration(configuration_raw, configuration_sha256)
        state = initial_state(initial_state_raw, initial_state_sha256)
        deadline = p.ns(startup_deadline_boottime_ns)
        p.require(_clock() < deadline <= _clock() + 30_000_000_000)
        owner = cls(_TOKEN)
        try:
            owner._pid, owner._start, owner._boot = os.getpid(), originals._start(), originals._boot()
            owner._deadline, owner._configuration, owner._configuration_sha = deadline, configuration_raw, configuration_sha256
            owner._uid, owner._gid = cold["uid"], cold["gid"]
            owner._state_raw, owner._state, owner._state_sha = initial_state_raw, state, initial_state_sha256
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            parent = os.open("/", flags)
            owner._fds.append(parent)
            for component in ("var", "lib", "catchplate", "native-policy-activation"):
                info = os.fstat(parent)
                p.require(info.st_uid == info.st_gid == 0 and stat.S_ISDIR(info.st_mode) and info.st_mode & 0o022 == 0)
                child = os.open(component, flags, dir_fd=parent)
                owner._fds.append(child)
                owner._parents.append((parent, component, child, _identity(os.fstat(child))))
                parent = child
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o711)
            _durable_fs(parent)
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owner._parent = parent
            os.mkdir("journal", 0o700, dir_fd=parent)  # existing path always refuses
            directory = os.open("journal", flags, dir_fd=parent)
            owner._fds.append(directory)
            owner._journal = directory
            for name, raw, mode in (("publication.json", initial_state_raw, 0o400), ("activation.lock", b"", 0o600)):
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                owner._fds.append(fd)
                position = 0
                while position < len(raw):
                    amount = os.write(fd, raw[position:])
                    p.require(amount > 0)
                    position += amount
                os.fchown(fd, owner._uid, owner._gid)
                os.fchmod(fd, mode)
                os.fsync(fd)
                info = os.fstat(fd)
                p.require(info.st_dev == os.fstat(directory).st_dev and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == len(raw)
                    and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (owner._uid, owner._gid, mode))
                p.require(os.pread(fd, len(raw) + 1, 0) == raw)
                if name == "publication.json":
                    owner._publication, owner._publication_identity = fd, _file_identity(info)
                else:
                    owner._lock, owner._lock_identity = fd, _file_identity(info)
            os.fchown(directory, owner._uid, owner._gid)
            os.fchmod(directory, 0o700)
            os.fsync(directory)
            os.fsync(parent)
            owner._journal_identity = _identity(os.fstat(directory))
            gate, service = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            owner._sockets.extend((gate, service))
            owner._gate, owner._service = gate, service
            owner._socket_identities = tuple(_identity(os.fstat(sock.fileno())) for sock in owner._sockets)
            owner.check()
            return owner
        except BaseException:
            owner.close()
            raise

    def check(self):
        p.require(not self._closed and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and os.getpid() == self._pid and originals._start() == self._start and originals._boot() == self._boot
            and _clock() < self._deadline)
        _durable_fs(self._journal)
        for parent, name, child, identity in self._parents:
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0
                and _identity(os.fstat(child)) == identity and _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
        p.require(_identity(os.fstat(self._journal)) == self._journal_identity
            and _identity(os.stat("journal", dir_fd=self._parent, follow_symlinks=False)) == self._journal_identity
            and _file_identity(os.fstat(self._publication)) == self._publication_identity
            and _file_identity(os.stat("publication.json", dir_fd=self._journal, follow_symlinks=False)) == self._publication_identity
            and _read(self._publication, 1024 * 1024 + 16384) == self._state_raw
            and _file_identity(os.fstat(self._lock)) == self._lock_identity
            and _file_identity(os.stat("activation.lock", dir_fd=self._journal, follow_symlinks=False)) == self._lock_identity)
        for sock, expected in zip(self._sockets, self._socket_identities):
            p.require(_identity(os.fstat(sock.fileno())) == expected and sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                and sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0 and not os.get_inheritable(sock.fileno()))
            sock.getpeername()
        for name in ("publication.next", "activation-request.json", "activation-receipt.json"):
            try:
                os.stat(name, dir_fd=self._journal, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("publication has already attempted an effect; preparation cannot be reused")

    def activation(self):
        self.check()
        result = []
        for target, (name, fd) in enumerate((("activation-channel", self._service.fileno()), ("activation-journal", self._journal)), 6):
            info = os.fstat(fd)
            result.append({"name": name, "fd": target, "device": info.st_dev, "inode": info.st_ino,
                "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid})
        self.check()
        return result

    def gate_channel(self):
        self.check()
        info = os.fstat(self._gate.fileno())
        return {"apiVersion": "catchplate.nativePolicyActivationChannel/v1", "channel": {
            "device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid}}

    def sign_delivery(self, *, payload_raw, signing_key):
        self.check()
        p.require(not self._delivery_attempted and not self._taken)
        self._delivery_attempted = True
        self._signed = delivery.sign_activation_delivery(configuration_raw=self._configuration,
            configuration_sha256=self._configuration_sha, payload_raw=payload_raw, signing_key=signing_key,
            activation=self.activation(), boot=self._boot, startup_deadline=self._deadline, now=_clock())
        self.check()
        return self._signed

    def sign_service_grant(self, *, configuration_original, configuration_sha256, authority_pin,
                           issued_at, expires_at, now, signing_key):
        self.check()
        p.require(not self._grant_attempted and not self._taken and self._signed is not None)
        self._grant_attempted = True
        p.require(p.sha(configuration_original) == p.digest(configuration_sha256))
        configuration = p.document(configuration_original, p.MAX_CONFIG)
        admitted, keys = admission.authorization(configuration, now)
        guest = admitted["guest"]
        delivery._pin(authority_pin)
        p.require(guest["serviceRole"] == "production-bridge" and guest["deliverySha256"] == p.sha(self._signed)
            and (guest["uid"], guest["gid"]) == (self._uid, self._gid)
            and self._state["assignmentPayloadSha256"] == admitted["assignmentPayloadSha256"]
            and "custody-activation-publication" in configuration["authorization"]["payload"]["localRoles"])
        p.freshness(issued_at, expires_at, now)
        p.require(expires_at <= min(configuration[name]["payload"]["expiresAtUnixNanos"] for name in ("authorization", "admissionAuthorization")))
        supervisor = keys[p.ROLES.index("custody-supervisor-capability")]
        p.require(isinstance(signing_key, Ed25519PrivateKey))
        public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p.require(p.encoded(public) == supervisor["publicKeyBase64url"])
        checkpoint = configuration["trustCheckpoint"]
        payload = {"apiVersion": "catchplate.nativeShadowActivationServiceAssignment/v1", "purpose": "native-policy-activation-publication",
            "guest": guest, "assignmentPayloadSha256": admitted["assignmentPayloadSha256"], "keyAuthorizationSha256": admitted["keyAuthorizationSha256"],
            "authority": authority_pin, "initialStateSha256": self._state_sha, "generationId": self._state["generationId"],
            "generationPublicationEnvelopeSha256": self._state["generationPublicationEnvelopeSha256"],
            "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"], "revocationRootSha256": checkpoint["revocationRootSha256"],
            "issuedAtUnixNanos": issued_at, "expiresAtUnixNanos": expires_at, "signingKeyId": supervisor["keyId"], "signingKeySpkiSha256": supervisor["keySpkiSha256"]}
        message = p.preimage(DOMAIN, payload)
        signature = signing_key.sign(message)
        p.public_key(supervisor).verify(signature, message)
        self._grant = p.canonical({"payload": payload, "signature": p.encoded(signature)})
        p.require(len(self._grant) <= 65536)
        self.check()
        return self._grant

    def take_for_launch(self, *, signed_delivery_sha256, service_grant_sha256):
        """One transfer; caller installs gate70 and service6/7 in distinct children.

        Every returned fd is CLOEXEC until the actual supervised handoff. No
        execution, parent identity, policy admission or readiness is asserted.
        """
        self.check()
        p.require(not self._taken and self._signed is not None and self._grant is not None
            and p.sha(self._signed) == p.digest(signed_delivery_sha256) and p.sha(self._grant) == p.digest(service_grant_sha256))
        self._taken = True
        owned = []
        try:
            for fd in (self._gate.fileno(), self._service.fileno(), self._journal):
                owned.append(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128))
            self.check()
            return {"gate": ((70, owned[0]),), "service": ((6, owned[1]), (7, owned[2]))}
        except BaseException:
            for fd in owned:
                os.close(fd)
            raise

    def close(self):
        if self._closed:
            return
        self._closed = True
        for sock in self._sockets:
            sock.close()
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()
        # No unlink/rmdir or inference that a partial journal is safe to retry.

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_):
        self.close()
