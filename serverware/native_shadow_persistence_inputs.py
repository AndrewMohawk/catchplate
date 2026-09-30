"""Actual fresh Persistence/v2 launch inputs, retained until cohort release.

Only fixed resource names; no launch, listening, key creation or repair here.
The separately owned parked proof cohort supplies genuine child originals.
All signatures and genesis/head inputs require independently supplied authority.
"""
from __future__ import annotations

import copy
import errno
import fcntl
import os
import socket
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_persistence_artifacts as artifacts
from serverware import native_shadow_retrieval_artifacts as data
from serverware.native_policy_activation_inputs import _durable_fs, _read
from serverware.native_shadow_retrieval_store import READ_FLAGS, _identity

p = delivery.p
SOCKET_PATH = "/run/serverware-shadow-persistence/listener.sock"
JOURNAL_ROOT = "/var/lib/serverware/native-shadow-persistence"
_TOKEN = object()


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _structural(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _names(fd):
    # scandir(fd) duplicates the same open-file-description and can advance
    # its shared directory offset. Every population check needs a fresh OFD,
    # while the held directory and lock remain continuously owned.
    scan = os.open(".", READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
    try:
        p.require(_structural(os.fstat(scan)) == _structural(os.fstat(fd)))
        names = []
        with os.scandir(scan) as entries:
            for entry in entries:
                names.append(entry.name)
                p.require(len(names) <= 2)
        p.require(_structural(os.fstat(scan)) == _structural(os.fstat(fd)))
        return sorted(names)
    finally:
        os.close(scan)


class PersistenceInputs:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._parents = [], []
        self._socket = None
        self._closed = self._delivery_attempted = self._genesis_attempted = False
        self._grant_attempted = self._taken = self._poisoned = False
        self._signed = self._grant = self._genesis = None

    @classmethod
    def prepare(cls, *, cohort, configuration_raw, configuration_sha256, peer_original, peer_sha256,
                scope_original, scope_sha256, startup_deadline_boottime_ns):
        # Imported lazily to keep the resource producer distinct from the real
        # launcher and prevent a raw observation/duck-typed DTO from substituting.
        from serverware.native_shadow_proof_cohort_control import ParkedProofCohort
        p.require(type(cohort) is ParkedProofCohort)
        cohort.check()
        p.require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        cold = delivery.configuration(configuration_raw, configuration_sha256)
        peer, scope = data._peer(peer_original), data.scope_original(scope_original)
        p.require(p.sha(peer_original) == p.digest(peer_sha256)
            and p.sha(scope_original) == p.digest(scope_sha256) and peer["uid"] != cold["uid"])
        deadline = p.ns(startup_deadline_boottime_ns)
        p.require(_clock() < deadline <= _clock() + 30_000_000_000
            and deadline == cohort.startup_deadline_boottime_ns())
        endpoint = cohort.endpoint_driver_selected()
        child = copy.deepcopy(cohort._external_driver.value) if endpoint else cohort.bridge_original()
        process = child["driver"] if endpoint else child
        p.require(peer["pid"] == process["processId"] and peer["startTimeTicks"] == process["startTimeTicks"])
        if endpoint:
            p.require((peer["uid"], peer["gid"]) == (cohort._cold["bridge"]["uid"], cohort._cold["bridge"]["gid"]))
        for expected, actual in (("executableDevice", "device"), ("executableInode", "inode"),
                                 ("executableLength", "length"), ("executableSha256", "sha256")):
            p.require(peer[expected] == child["executable"][actual])
        owner = cls(_TOKEN)
        try:
            owner._cohort, owner._child, owner._endpoint = cohort, child, endpoint
            owner._pid, owner._start, owner._boot = os.getpid(), originals._start(), originals._boot()
            owner._deadline, owner._configuration_raw, owner._configuration_sha = deadline, configuration_raw, configuration_sha256
            owner._uid, owner._gid, owner._peer_gid = cold["uid"], cold["gid"], peer["gid"]
            owner._peer_raw, owner._peer_sha = peer_original, peer_sha256
            owner._scope_raw, owner._scope_sha, owner._scope = scope_original, scope_sha256, scope
            listener_parent = owner._parent(("run", "serverware-shadow-persistence"))
            owner._listener_parent = listener_parent
            try:
                os.stat("listener.sock", dir_fd=listener_parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("persistence listener exists; reconciliation required")
            journal_parent = owner._parent(("var", "lib", "serverware", "native-shadow-persistence"))
            owner._journal_parent = journal_parent
            _durable_fs(journal_parent)
            # Never open/adopt an old journal or unlink a failed one.
            os.mkdir("journal", 0o700, dir_fd=journal_parent)
            journal = os.open("journal", READ_FLAGS | os.O_DIRECTORY, dir_fd=journal_parent)
            owner._fds.append(journal)
            owner._journal = journal
            os.fchown(journal, owner._uid, owner._gid)
            os.fchmod(journal, 0o700)
            owner._journal_id = _structural(os.fstat(journal))
            p.require(owner._journal_id[0] == os.fstat(journal_parent).st_dev and _names(journal) == [])
            lock = os.open("persistence.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                0o600, dir_fd=journal)
            owner._fds.append(lock)
            owner._lock = lock
            os.fchown(lock, owner._uid, owner._gid)
            os.fchmod(lock, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(lock); os.fsync(journal); os.fsync(journal_parent)
            owner._lock_id = _identity(os.fstat(lock))
            p.require(stat.S_ISREG(owner._lock_id[2]) and owner._lock_id[5:7] == (1, 0)
                and owner._lock_id[0] == owner._journal_id[0])
            owner._socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            owner._socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            owner._socket.setsockopt(socket.SOL_SOCKET, 76, 1)
            owner._socket.bind(SOCKET_PATH)
            os.chown("listener.sock", owner._uid, owner._peer_gid, dir_fd=listener_parent, follow_symlinks=False)
            os.chmod("listener.sock", 0o660, dir_fd=listener_parent, follow_symlinks=False)
            owner._socket_id = _identity(os.fstat(owner._socket.fileno()))
            owner._socket_path_id = _identity(os.stat("listener.sock", dir_fd=listener_parent, follow_symlinks=False))
            owner.check()
            return owner
        except BaseException:
            owner.close()
            raise

    def _parent(self, components):
        fd = os.open("/", READ_FLAGS | os.O_DIRECTORY)
        self._fds.append(fd)
        for component in components:
            info = os.fstat(fd)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
            child = os.open(component, READ_FLAGS | os.O_DIRECTORY, dir_fd=fd)
            self._fds.append(child)
            self._parents.append((fd, component, child, _structural(os.fstat(child))))
            fd = child
        info = os.fstat(fd)
        p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o711)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd

    def check(self):
        p.require(not self._closed and not self._poisoned and os.getresuid() == (0, 0, 0)
            and os.getresgid() == (0, 0, 0) and os.getpid() == self._pid
            and originals._start() == self._start and originals._boot() == self._boot and _clock() < self._deadline)
        self._cohort.check()
        p.require(self._cohort.endpoint_driver_selected() == self._endpoint)
        if self._endpoint:
            p.require(self._cohort._external_driver.value == self._child)
        else:
            p.require(self._cohort.bridge_original() == self._child)
        for parent, name, child, expected in self._parents:
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0
                and _structural(os.fstat(child)) == expected
                and _structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        p.require(_structural(os.fstat(self._journal)) == self._journal_id
            and _structural(os.stat("journal", dir_fd=self._journal_parent, follow_symlinks=False)) == self._journal_id
            and _identity(os.fstat(self._lock)) == self._lock_id
            and _identity(os.stat("persistence.lock", dir_fd=self._journal, follow_symlinks=False)) == self._lock_id)
        _durable_fs(self._journal)
        # Same OFD stays locked from preparation through SCM_RIGHTS and native
        # admission. A separately opened description must conflict already.
        other = os.open("persistence.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self._journal)
        try:
            p.require(_identity(os.fstat(other)) == self._lock_id)
            try:
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                p.require(error.errno == errno.EWOULDBLOCK)
            else:
                raise ValueError("persistence lock continuity lost")
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)
        expected = ["persistence.lock"]
        if self._genesis is not None:
            expected.insert(0, "genesis.json")
            p.require(_identity(os.fstat(self._genesis_fd)) == self._genesis_id
                and _identity(os.stat("genesis.json", dir_fd=self._journal, follow_symlinks=False)) == self._genesis_id
                and _read(self._genesis_fd, 16384) == self._genesis)
        p.require(_names(self._journal) == expected
            and _identity(os.fstat(self._socket.fileno())) == self._socket_id
            and _identity(os.stat("listener.sock", dir_fd=self._listener_parent, follow_symlinks=False)) == self._socket_path_id
            and self._socket.getsockname() == SOCKET_PATH and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
            and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
            and self._socket.getsockopt(socket.SOL_SOCKET, 76) == 1
            and fcntl.fcntl(self._socket.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK)
        for fd in (self._journal, self._lock, self._socket.fileno()):
            p.require(not os.get_inheritable(fd))

    def activation(self):
        self.check()
        entries = []
        for target, (name, fd) in enumerate((("persistence-listener", self._socket.fileno()),
                ("persistence-journal", self._journal), ("persistence-lock", self._lock)), 6):
            info = os.fstat(fd)
            entries.append({"name": name, "fd": target, "device": info.st_dev, "inode": info.st_ino,
                "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid})
        self.check()
        return entries

    def sign_delivery(self, *, payload_raw, signing_key):
        self.check()
        p.require(not self._delivery_attempted and not self._taken)
        self._delivery_attempted = True
        payload = p.fields(p.document(payload_raw, delivery.MAX_DELIVERY), delivery.FIELDS)
        p.require(p.ns(payload["lifetimeDeadlineBoottimeNs"]) == self._cohort.lifetime_deadline_boottime_ns())
        signed = delivery.sign_persistence_delivery(configuration_raw=self._configuration_raw,
            configuration_sha256=self._configuration_sha, payload_raw=payload_raw, signing_key=signing_key,
            activation=self.activation(), boot=self._boot, startup_deadline=self._deadline, now=_clock())
        self._guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in
            {"deliverySha256", "runtimeConfigurationSha256"}}
        self._guest.update(deliverySha256=p.sha(signed), runtimeConfigurationSha256=payload["runtimeConfig"]["sha256"])
        p.guest(self._guest)
        self.check()
        self._signed = signed
        return signed

    def guest_original(self):
        self.check()
        p.require(self._signed is not None)
        return p.canonical(self._guest)  # Public facts for independent genesis/admission approval, not permission.

    def admit_delivery(self, *, signed_delivery_original):
        """Retain independently signed C9 bytes against this actual FD owner.

        Shares the signing path's one-attempt fence. Failure never resets it or
        replaces the already created listener, journal, lock or startup window.
        """
        self.check()
        p.require(not self._delivery_attempted and not self._taken)
        self._delivery_attempted = True
        signed = delivery.verify_persistence_delivery(configuration_raw=self._configuration_raw,
            configuration_sha256=self._configuration_sha, signed_delivery_original=signed_delivery_original,
            activation=self.activation(), boot=self._boot, startup_deadline=self._deadline, now=_clock())
        payload = p.document(signed, delivery.MAX_DELIVERY)["payload"]
        p.require(p.ns(payload["lifetimeDeadlineBoottimeNs"]) == self._cohort.lifetime_deadline_boottime_ns())
        self._guest = delivery._delivery_guest(payload, signed)
        self.check()
        self._signed = signed
        return signed

    def install_genesis(self, *, genesis_original, genesis_sha256, journal_original, journal_sha256):
        self.check()
        p.require(self._signed is not None and not self._genesis_attempted and not self._taken)
        self._genesis_attempted = True
        artifacts.fresh_originals(genesis_original=genesis_original, genesis_sha256=genesis_sha256,
            journal_original=journal_original, journal_sha256=journal_sha256, scope_original=self._scope_raw, guest=self._guest)
        # Mark uncertainty before the first durable effect, including O_EXCL.
        self._poisoned = True
        fd = os.open("genesis.json", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            0o600, dir_fd=self._journal)
        self._fds.append(fd)
        offset = 0
        while offset < len(genesis_original):
            p.require(_clock() < self._deadline)
            written = os.write(fd, genesis_original[offset:])
            p.require(written > 0)
            offset += written
        os.fsync(fd)
        os.fchown(fd, self._uid, self._gid)
        os.fchmod(fd, 0o400)
        os.fsync(fd); os.fsync(self._journal); os.fsync(self._journal_parent)
        info = os.fstat(fd)
        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o400
            and info.st_dev == self._journal_id[0] and (info.st_uid, info.st_gid) == (self._uid, self._gid)
            and _read(fd, 16384) == genesis_original)
        self._genesis, self._genesis_fd, self._genesis_id = genesis_original, fd, _identity(info)
        self._journal_raw, self._journal_sha = journal_original, journal_sha256
        self._poisoned = False
        try:
            self.check()
        except BaseException:
            self._poisoned = True
            raise

    def sign_service_grant(self, *, configuration_original, configuration_sha256, permissions,
                           issued_at, expires_at, now, signing_key):
        self.check()
        p.require(self._genesis is not None and not self._grant_attempted and not self._taken)
        self._grant_attempted = True
        cold = delivery.configuration(self._configuration_raw, self._configuration_sha)
        p.require(isinstance(signing_key, Ed25519PrivateKey))
        public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p.require(p.encoded(public) != cold["authority"]["publicKeyBase64url"])
        grant = artifacts.sign_service_grant(configuration_original=configuration_original,
            configuration_sha256=configuration_sha256, scope_original=self._scope_raw, scope_sha256=self._scope_sha,
            peer_original=self._peer_raw, peer_sha256=self._peer_sha, guest=self._guest,
            journal_original=self._journal_raw, journal_sha256=self._journal_sha, permissions=permissions,
            issued_at=issued_at, expires_at=expires_at, now=now, signing_key=signing_key)
        signed = p.document(grant, 65536)
        p.require(signed["payload"]["signingKeyId"] != cold["authority"]["keyId"])
        self.check()
        self._grant = grant
        return grant

    def take_for_launch(self, *, signed_delivery_sha256, service_grant_sha256):
        self.check()
        p.require(not self._taken and self._signed is not None and self._grant is not None
            and p.sha(self._signed) == p.digest(signed_delivery_sha256)
            and p.sha(self._grant) == p.digest(service_grant_sha256))
        self._taken = True
        owned = []
        try:
            for fd in (self._socket.fileno(), self._journal, self._lock):
                owned.append(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128))
            self.check()
            return PersistenceTransfer(_TOKEN, self, tuple(zip((6, 7, 8), owned)))
        except BaseException:
            for fd in owned:
                os.close(fd)
            raise

    def admit_service_grant(self, *, signed_grant_original, configuration_original, configuration_sha256):
        """Verify independent operational authority against retained genesis.

        No private authority key or supplied current time is accepted. The
        existing transfer path still requires both exact original digests.
        """
        self.check()
        p.require(self._genesis is not None and not self._grant_attempted and not self._taken)
        self._grant_attempted = True
        cold = delivery.configuration(self._configuration_raw, self._configuration_sha)
        observed = time.time_ns()
        raw, supervisor = artifacts.verify_service_grant(signed_grant_original=signed_grant_original,
            configuration_original=configuration_original, configuration_sha256=configuration_sha256,
            scope_original=self._scope_raw, scope_sha256=self._scope_sha,
            peer_original=self._peer_raw, peer_sha256=self._peer_sha, guest=self._guest,
            journal_original=self._journal_raw, journal_sha256=self._journal_sha, now=observed)
        p.require(supervisor["publicKeyBase64url"] != cold["authority"]["publicKeyBase64url"]
            and supervisor["keyId"] != cold["authority"]["keyId"])
        self.check()
        now = time.time_ns()
        p.require(now >= observed)
        payload = p.document(raw, 65536)["payload"]
        p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now)
        self._grant = raw
        return raw

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._socket is not None:
            self._socket.close()
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()
        # Preserve listener, journal, lock and any partial genesis for explicit reconciliation.

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_):
        self.close()


class PersistenceTransfer:
    """One real descriptor handoff, not a launch-success or persistence DTO."""
    def __init__(self, token, owner, descriptors):
        p.require(token is _TOKEN and type(owner) is PersistenceInputs)
        self._owner, self._descriptors = owner, descriptors
        self._closed = self._attempted = False

    def check(self):
        p.require(not self._closed and not self._attempted)
        self._owner.check()
        p.require(tuple(target for target, _ in self._descriptors) == (6, 7, 8))
        originals_fds = (self._owner._socket.fileno(), self._owner._journal, self._owner._lock)
        for (target, fd), original_fd in zip(self._descriptors, originals_fds):
            p.require(target in (6, 7, 8) and not os.get_inheritable(fd)
                and _identity(os.fstat(fd)) == _identity(os.fstat(original_fd)))

    def descriptors(self):
        self.check()
        return self._descriptors

    def signed_originals(self):
        self.check()
        return self._owner._signed, self._owner._grant

    def begin_release(self):
        self.check()
        self._attempted = True  # Before send; an unknown result cannot retry.
        return self._descriptors

    def close(self):
        if self._closed:
            return
        self._closed = True
        for _, fd in self._descriptors:
            os.close(fd)
        # The cohort retains this owner through actual child termination/reap.
        self._owner.close()
