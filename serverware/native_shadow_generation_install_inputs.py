"""Fresh GenerationInstall resources for one retained proof cohort.

Allocate first, then independently authorize the actual C9 descriptor identities.
initialize_journal copies supplied canonical genesis/records against the pinned
coordinator assignment; it neither signs nor certifies those originals. Rust's
generation_install::Configuration and generation_store::Journal remain the
authority, history and live-key admission owners.

The independently provisioned root:root 0711 parents are fixed below. No old
socket, journal, partial record or lock is adopted, removed or repaired. The
socket is bound but NOT listening: the actual guest listens after final drop.
generation.lock is never flocked here; Rust acquires its own exclusive OFD lock.
All resources, including preparation failures, remain with the cohort until
actual endpoint reaps and (when selected) separate external-driver termination.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat

from serverware import custody_generation_originals as o
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_persistence_inputs as existing
from serverware import native_shadow_retrieval_artifacts as artifacts
from serverware.native_policy_activation_inputs import _durable_fs

p = delivery.p
SOCKET_PATH = "/run/serverware-shadow-generation-install/listener.sock"
JOURNAL_ROOT = "/var/lib/serverware/native-shadow-generation-install"
MAX_RECORD = 512 * 1024
MAX_RECORDS = 8
MAX_TOTAL = 4 * 1024 * 1024
_TOKEN = object()
_SERVICES = frozenset(("durable-recovery-store", "recovery-target-provider",
    "current-signature-authority", "cleanup-authorization-consumer", "bounded-cleanup-helper"))
_PAYLOAD_FIELDS = ("apiVersion", "purpose", "guest", "assignmentPayloadSha256",
    "keyAuthorizationSha256", "services", "keyHistory", "journal", "expectedPeer",
    "trustCheckpointId", "revocationGeneration", "revocationRootSha256",
    "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256")


def _names(fd):
    # A fresh directory OFD avoids advancing the retained descriptor's offset.
    scan = os.open(".", o.FLAGS | os.O_DIRECTORY, dir_fd=fd)
    try:
        expected = o.structural(os.fstat(fd))
        p.require(o.structural(os.fstat(scan)) == expected)
        names = []
        with os.scandir(scan) as entries:
            for entry in entries:
                names.append(entry.name)
                p.require(len(names) <= MAX_RECORDS + 2)
        p.require(o.structural(os.fstat(scan)) == o.structural(os.fstat(fd)) == expected)
        return sorted(names)
    finally:
        os.close(scan)


class GenerationInstallInputs:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._parents, self._files = [], [], []
        self._socket = None
        self._closed = self._poisoned = self._journal_attempted = self._retain_attempted = False
        self._ready = False
        self._originals = self._launch_pin = self._transfer = None

    _parent = existing.PersistenceInputs._parent

    @classmethod
    def prepare(cls, cohort):
        from serverware.native_shadow_proof_cohort_control import ParkedProofCohort
        p.require(cls is GenerationInstallInputs and type(cohort) is ParkedProofCohort)
        cohort.check()
        p.require(cohort._generation_install_resources is None and "generationInstall" in cohort._roles)
        value = cls(_TOKEN)
        value._cohort = cohort
        value._pid, value._start, value._boot = os.getpid(), originals._start(), originals._boot()
        value._deadline = cohort.startup_deadline_boottime_ns()
        value._uid, value._gid = (cohort._cold["generationInstall"][name] for name in ("uid", "gid"))
        value._peer_uid, value._peer_gid = (cohort._cold["bridge"][name] for name in ("uid", "gid"))
        p.require(value._uid != value._peer_uid and value._gid != value._peer_gid)
        # Claim before any allocation. A failed attempt still owns its partial
        # resources; only the real cohort cleanup may subsequently close them.
        cohort._generation_install_resources = value
        try:
            value._origin()
            value._listener_parent = value._parent(("run", "serverware-shadow-generation-install"))
            value._journal_parent = value._parent(("var", "lib", "serverware", "native-shadow-generation-install"))
            _durable_fs(value._journal_parent)
            os.mkdir("journal", 0o700, dir_fd=value._journal_parent)
            value._journal = os.open("journal", o.FLAGS | os.O_DIRECTORY, dir_fd=value._journal_parent)
            value._fds.append(value._journal)
            os.fchown(value._journal, value._uid, value._gid)
            os.fchmod(value._journal, 0o700)
            value._journal_id = o.structural(os.fstat(value._journal))
            p.require(value._journal_id[0] == os.fstat(value._journal_parent).st_dev
                and _names(value._journal) == [])
            value._lock = os.open("generation.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL
                | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=value._journal)
            value._fds.append(value._lock)
            os.fchown(value._lock, value._uid, value._gid)
            os.fchmod(value._lock, 0o600)
            # NO flock on this file, including through a duplicate description.
            # The native Journal opens and locks this exact name after drop.
            os.fsync(value._lock)
            os.fsync(value._journal)
            os.fsync(value._journal_parent)
            value._lock_id = o.identity(os.fstat(value._lock))
            p.require(stat.S_ISREG(value._lock_id[2]) and value._lock_id[5:7] == (1, 0)
                and value._lock_id[0] == value._journal_id[0])
            value._socket = socket.socket(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            value._socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            value._socket.setsockopt(socket.SOL_SOCKET, 76, 1)  # Linux SO_PASSPIDFD.
            value._socket.bind(SOCKET_PATH)  # An existing leaf refuses; never unlink.
            os.chown("listener.sock", value._uid, value._peer_gid,
                dir_fd=value._listener_parent, follow_symlinks=False)
            os.chmod("listener.sock", 0o660, dir_fd=value._listener_parent, follow_symlinks=False)
            value._socket_id = o.identity(os.fstat(value._socket.fileno()))
            value._path_id = o.identity(os.stat("listener.sock", dir_fd=value._listener_parent,
                follow_symlinks=False))
            p.require(stat.S_ISSOCK(value._path_id[2]) and stat.S_IMODE(value._path_id[2]) == 0o660
                and value._path_id[3:5] == (value._uid, value._peer_gid))
            value.check()
            return value
        except BaseException:
            value._poisoned = True
            raise

    def _origin(self):
        p.require(not self._closed and not self._poisoned and os.getpid() == self._pid
            and originals._start() == self._start and originals._boot() == self._boot
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and o.clock() < self._deadline and self._cohort._generation_install_resources is self)
        self._cohort.check()

    def check(self):
        """Pre-release currentness, never a post-release journal/readiness claim."""
        self._origin()
        for parent, name, child, identity in self._parents:
            info = os.fstat(parent)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_mode & 0o022 == 0 and o.structural(os.fstat(child)) == identity
                and o.structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
        p.require(o.structural(os.fstat(self._journal)) == self._journal_id
            and o.structural(os.stat("journal", dir_fd=self._journal_parent,
                follow_symlinks=False)) == self._journal_id
            and stat.S_ISDIR(self._journal_id[2]) and stat.S_IMODE(self._journal_id[2]) == 0o700
            and self._journal_id[3:5] == (self._uid, self._gid)
            and o.identity(os.fstat(self._lock)) == self._lock_id
            and o.identity(os.stat("generation.lock", dir_fd=self._journal,
                follow_symlinks=False)) == self._lock_id
            and stat.S_IMODE(self._lock_id[2]) == 0o600
            and self._lock_id[3:5] == (self._uid, self._gid))
        _durable_fs(self._journal)
        for name, fd, identity, raw in self._files:
            p.require(o.identity(os.fstat(fd)) == identity
                and o.identity(os.stat(name, dir_fd=self._journal, follow_symlinks=False)) == identity
                and o.read(fd, MAX_RECORD) == raw)
        p.require(_names(self._journal) == sorted(["generation.lock"] + [item[0] for item in self._files])
            and o.identity(os.fstat(self._socket.fileno())) == self._socket_id
            and o.identity(os.stat("listener.sock", dir_fd=self._listener_parent,
                follow_symlinks=False)) == self._path_id
            and self._socket.getsockname() == SOCKET_PATH
            and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
            and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
            and self._socket.getsockopt(socket.SOL_SOCKET, 76) == 1
            and fcntl.fcntl(self._socket.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK)
        p.require(all(not os.get_inheritable(fd) for fd in self._fds + [self._socket.fileno()]))
        self._origin()

    def additions(self):
        """Borrowed real resources for independent C9 authorship, not a transfer."""
        self.check()
        return (("shadow-generation-install-listener", self._socket.fileno()),
            ("generation-install-journal", self._journal))

    def activation(self):
        entries = []
        for target, (name, fd) in enumerate(self.additions(), 6):
            info = os.fstat(fd)
            entries.append(dict(name=name, fd=target, device=info.st_dev, inode=info.st_ino,
                mode=info.st_mode, uid=info.st_uid, gid=info.st_gid))
        self.check()
        return entries

    def _admission(self, launch_pin):
        # The cohort authenticates C9 and retains the exact protected launch,
        # delivery and pinned operational grant originals. It does not verify
        # the separate native coordinator assignment signature/history.
        raw = self._cohort.activation_originals(role="generationInstall", launch_pin=launch_pin)
        launch_raw, signed_raw, grant_raw = raw
        p.document(launch_raw, 32768)
        signed = p.fields(p.document(signed_raw, 65536), ("apiVersion", "payload", "signatureBase64url"))
        p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
        payload = p.fields(signed["payload"], delivery.FIELDS)
        p.require(p.canonical(payload["activation"]) == p.canonical(self.activation()))
        guest = delivery._delivery_guest(payload, signed_raw)
        p.require((guest["uid"], guest["gid"]) == (self._uid, self._gid))
        envelope = p.fields(p.document(grant_raw, 65536), ("payload", "signature"))
        grant = p.fields(envelope["payload"], _PAYLOAD_FIELDS)
        p.require(grant["apiVersion"] == "serverware.nativeGenerationCoordinatorAssignment/v1"
            and grant["purpose"] == "native-generation-installation"
            and p.canonical(grant["guest"]) == p.canonical(guest) and guest["serviceRole"] == "production-bridge")
        p.digest(grant["assignmentPayloadSha256"])
        services = p.fields(grant["services"], _SERVICES)
        for member in services.values():
            p.fields(member, ("grantOriginal", "historyOriginal", "rootKeyId", "rootKeySpkiSha256"))
            for name, maximum in (("grantOriginal", 65536), ("historyOriginal", 1024 * 1024)):
                p.require(type(member[name]) is str and member[name].isascii() and 0 < len(member[name]) <= maximum)
            p.digest(member["rootKeyId"])
            p.digest(member["rootKeySpkiSha256"])
        peer = artifacts._peer(p.canonical(grant["expectedPeer"]))
        p.require((peer["uid"], peer["gid"]) == (self._peer_uid, self._peer_gid))
        external = self._cohort._external_driver
        original = external.value if external is not None else self._cohort.bridge_original()
        process = original["driver"] if external is not None else original
        p.require((peer["pid"], peer["startTimeTicks"]) == (process["processId"], process["startTimeTicks"]))
        for expected, actual in (("executableDevice", "device"), ("executableInode", "inode"),
                ("executableLength", "length"), ("executableSha256", "sha256")):
            p.require(peer[expected] == original["executable"][actual])
        # Parked observations do not establish final cgroup/label/IMA values.
        # Those supplied signed expectations remain for the actual inspector.
        journal = p.fields(grant["journal"], ("genesisSha256", "sequence", "headSha256"))
        p.integer(journal["sequence"], minimum=0, maximum=MAX_RECORDS)
        p.digest(journal["genesisSha256"])
        p.digest(journal["headSha256"])
        self.check()
        return raw, guest, grant, journal

    def initialize_journal(self, *, launch_pin, genesis_original, record_originals=()):
        """Copy exact supplied originals once; the pinned head is NOT generated.

        There is no head.json. The existing grant's journal field supplies
        sequence/headSha256; zero records require head == SHA256(genesis).
        Record payload authority/recovery is still admitted by native Rust.
        """
        self.check()
        p.require(not self._journal_attempted and not self._retain_attempted)
        self._journal_attempted = True
        try:
            raw, guest, grant, journal = self._admission(launch_pin)
            genesis = p.fields(p.document(genesis_original, MAX_RECORD),
                ("apiVersion", "guest", "assignmentPayloadSha256", "servicesSha256"))
            p.require(genesis["apiVersion"] == "serverware.nativeGenerationCoordinatorGenesis/v1"
                and p.canonical(genesis["guest"]) == p.canonical(guest)
                and genesis["assignmentPayloadSha256"] == grant["assignmentPayloadSha256"]
                and genesis["servicesSha256"] == p.sha(p.canonical(grant["services"]))
                and p.sha(genesis_original) == journal["genesisSha256"])
            p.require(type(record_originals) is tuple and len(record_originals) == journal["sequence"])
            pending = [("genesis.json", genesis_original)]
            head, total = p.sha(genesis_original), len(genesis_original)
            for sequence, record_raw in enumerate(record_originals, 1):
                record = p.fields(p.document(record_raw, MAX_RECORD),
                    ("apiVersion", "sequence", "previousHeadSha256", "original"))
                p.integer(record["sequence"], minimum=1, maximum=MAX_RECORDS)
                p.require(record["apiVersion"] == "serverware.nativeGenerationCoordinatorRecord/v1"
                    and record["sequence"] == sequence and record["previousHeadSha256"] == head
                    and type(record["original"]) is str and record["original"] and record["original"].isascii())
                total += len(record_raw)
                p.require(total <= MAX_TOTAL)
                head = p.sha(record_raw)
                pending.append((f"record-{sequence:02}.json", record_raw))
            p.require(head == journal["headSha256"] and total <= MAX_TOTAL)
            self.check()
            for name, original in pending:
                self._write_original(name, original)
            os.fsync(self._journal)
            os.fsync(self._journal_parent)
            self._originals = raw
            self._launch_pin = dict(launch_pin)
            self._ready = True
            self.check()
        except BaseException:
            self._poisoned = True
            raise

    def _write_original(self, name, raw):
        self.check()
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=self._journal)
        self._fds.append(fd)
        os.fchown(fd, self._uid, self._gid)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            self._origin()
            count = os.write(fd, raw[offset:offset + 65536])
            p.require(count > 0)
            offset += count
        os.fsync(fd)
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        identity = o.identity(os.fstat(fd))
        p.require(stat.S_ISREG(identity[2]) and identity[0] == self._journal_id[0]
            and identity[3:6] == (self._uid, self._gid, 1)
            and stat.S_IMODE(identity[2]) == 0o400 and o.read(fd, MAX_RECORD) == raw)
        # Retain only a read-only descriptor to the completed immutable file.
        readonly = os.open(name, o.FLAGS, dir_fd=self._journal)
        self._fds.append(readonly)
        p.require(o.identity(os.fstat(readonly)) == identity and o.read(readonly, MAX_RECORD) == raw)
        os.close(fd)
        self._fds.remove(fd)
        self._files.append((name, readonly, identity, raw))
        os.fsync(self._journal)
        self.check()

    def retain(self, *, launch_pin):
        """One retained real-FD transfer, consumed by the existing cohort release."""
        self.check()
        p.require(self._ready and not self._retain_attempted and launch_pin == self._launch_pin)
        self._retain_attempted = True
        try:
            raw, _, _, _ = self._admission(launch_pin)
            p.require(raw == self._originals)
            descriptors = tuple((target, fd) for target, (_, fd) in enumerate(self.additions(), 6))
            self._transfer = self._cohort.retain_activation_fds(role="generationInstall", launch_pin=launch_pin,
                descriptors=descriptors, generation_install_owner=self)
            self.check()
            return self._transfer
        except BaseException:
            self._poisoned = True
            raise

    def close(self):
        """Close only after actual owned-child cleanup; leave every name intact."""
        if self._closed:
            return
        from serverware.native_shadow_proof_cohort_control import _terminal
        p.require(os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and self._cohort._generation_install_resources is self
            and self._cohort._parent_reaped
            and all(_terminal(fd) for fd, _, _ in self._cohort._parked))
        if self._cohort._external_driver is not None:
            self._cohort._external_driver.terminal()
        self._closed = True
        if self._socket is not None:
            self._socket.close()
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()
