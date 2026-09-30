"""Fixed-seven retained resources, not an installed generation or authority.

Creates only the new Ingress listener, an empty durable retrieval-core store,
and the one signed-origin channel. Old retrieval objects/listeners and every
other role still have their own producers. Partial state is never adopted,
removed, repaired, or credited as a successful effect.
"""
import ctypes
import errno
import fcntl
import os
import socket
import stat

from serverware import custody_generation_originals as o
from serverware import native_shadow_persistence_inputs as existing
from serverware import native_shadow_nitro_profile as p

_TOKEN = object()
ROOT = "/var/lib/serverware/native-ledger-spool"
SOCKET = "/run/serverware-shadow-ingress-admission/listener.sock"


def _verity_fs(fd):
    # Same fixed Linux x86_64 refusal filter as the actual fs-verity writer.
    # Filesystem type alone is not a power-loss durability attestation.
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
        and value.kind in {0xEF53, 0x9123683E} and value.flags & 1 == 0)


class SpoolInputs:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._parents, self._sockets = [], [], []
        self._closed = self._seal_attempted = self._delivery_attempted = False
        self._genesis = self._scope = self._head = None

    _parent = existing.PersistenceInputs._parent

    @classmethod
    def prepare(cls, cohort):
        from serverware.native_shadow_proof_cohort_control import ParkedProofCohort
        p.require(cls is SpoolInputs and type(cohort) is ParkedProofCohort and cohort.spool_selected())
        value = cls(_TOKEN); value._cohort = cohort
        # Retained even if preparation fails: no new owner may adopt partial
        # resources, and parent cleanup is responsible for the real children.
        cohort._spool_resources = value
        value._uid, value._gid = (cohort._cold["retrieval"][name] for name in ("uid", "gid"))
        value._store_parent = value._parent(("var", "lib", "serverware", "native-ledger-spool"))
        _verity_fs(value._store_parent)
        value._name = cohort._window["invocationId"]
        os.mkdir(value._name, 0o700, dir_fd=value._store_parent)
        value._store = os.open(value._name, o.FLAGS | os.O_DIRECTORY, dir_fd=value._store_parent)
        value._fds.append(value._store)
        os.fchown(value._store, value._uid, value._gid); os.fchmod(value._store, 0o700)
        value._store_id = o.structural(os.fstat(value._store))
        p.require(existing._names(value._store) == [])
        value._lock = os.open("ledger.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=value._store); value._fds.append(value._lock)
        os.fchown(value._lock, value._uid, value._gid); os.fchmod(value._lock, 0o600)
        fcntl.flock(value._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(value._lock); os.fsync(value._store); os.fsync(value._store_parent)
        value._lock_id = o.identity(os.fstat(value._lock))
        value._listener_parent = value._parent(("run", "serverware-shadow-ingress-admission"))
        value._listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        value._sockets.append(value._listener)
        value._listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        value._listener.setsockopt(socket.SOL_SOCKET, 76, 1)
        value._listener.bind(SOCKET)  # Existing path refuses; never unlink.
        os.chown("listener.sock", cohort._cold["ingressAdmission"]["uid"], cohort._cold["bridge"]["gid"],
            dir_fd=value._listener_parent, follow_symlinks=False)
        os.chmod("listener.sock", 0o660, dir_fd=value._listener_parent, follow_symlinks=False)
        value._listener_id = o.identity(os.fstat(value._listener.fileno()))
        value._path_id = o.identity(os.stat("listener.sock", dir_fd=value._listener_parent, follow_symlinks=False))
        value._local, value._remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        value._sockets += [value._local, value._remote]
        for channel in (value._local, value._remote):
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            p.require(channel.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF) >= 4 * 1024 * 1024)
        value._channels = tuple((channel.fileno(), o.identity(os.fstat(channel.fileno()))) for channel in (value._local, value._remote))
        from serverware.native_generation_origin_relay import Configuration
        value._relay = Configuration.open()
        value.check(); return value

    def check(self, *, preparation=True):
        p.require(not self._closed)
        if preparation:
            self._cohort.check()
        else:
            self._cohort._origin(); self._cohort._child_live()
            p.require(self._cohort._release_sent and not self._cohort._cleanup_attempted)
        for parent, name, child, expected in self._parents:
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0
                and o.structural(os.fstat(child)) == expected
                and o.structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        p.require(o.structural(os.fstat(self._store)) == self._store_id
            == o.structural(os.stat(self._name, dir_fd=self._store_parent, follow_symlinks=False))
            and o.identity(os.fstat(self._lock)) == self._lock_id
            == o.identity(os.stat("ledger.lock", dir_fd=self._store, follow_symlinks=False)))
        _verity_fs(self._store)
        other = os.open("ledger.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._store)
        try:
            try:
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                p.require(error.errno == errno.EWOULDBLOCK)
            else:
                raise ValueError("spool lock continuity lost")
        finally:
            os.close(other)
        if preparation:
            p.require(existing._names(self._store) == (["ledger.lock"] if self._genesis is None else ["genesis.json", "ledger.lock"]))
        if self._genesis is not None:
            p.require(o.identity(os.fstat(self._genesis_fd)) == self._genesis_id
                == o.identity(os.stat("genesis.json", dir_fd=self._store, follow_symlinks=False))
                and o.read(self._genesis_fd, 16384) == self._genesis)
        p.require(o.identity(os.fstat(self._listener.fileno())) == self._listener_id
            and o.identity(os.stat("listener.sock", dir_fd=self._listener_parent, follow_symlinks=False)) == self._path_id)
        for fd, expected in self._channels:
            p.require(o.identity(os.fstat(fd)) == expected and not os.get_inheritable(fd))
        self._relay.check()

    def additions(self, role):
        """Actual named FDs for the separately signed C9 activation producer."""
        self.check()
        selected = {"retrieval": (("ledger-spool-store", self._store), ("ledger-spool-lock", self._lock)),
            "ingressAdmission": (("ingress-admission-listener", self._listener.fileno()),),
            "bridge": (("ingress-admission-peer-directory", self._listener_parent), ("generation-origin", self._remote.fileno()))}
        p.require(role in selected); return selected[role]

    def initialize_store(self, *, retrieval_delivery_original, proof_scope_original):
        """Empty storage identity only; never a fabricated shadow ledger head."""
        self.check(); p.require(not self._seal_attempted); self._seal_attempted = True
        signed = p.fields(p.document(retrieval_delivery_original, 65536), ("apiVersion", "payload", "signatureBase64url"))
        from serverware import native_shadow_guest_delivery as d
        p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
        payload = p.fields(signed["payload"], d.FIELDS)
        cold = self._cohort._config["retrievalConfiguration"]
        p.require(payload["configurationSha256"] == cold["sha256"]
            and payload["uid"] == self._uid and payload["gid"] == self._gid
            and all(payload[name] == self._cohort._window[name] for name in
                ("authorityKeyId", "invocationId", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
                 "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")))
        # The cohort's independently pinned C9 root authenticates these
        # originals; final release/native C9 admission additionally binds all
        # executable, boot, credentials, activation and lifetime originals.
        self._cohort._key.verify(p.decoded(signed["signatureBase64url"], size=64), d.DOMAIN + p.canonical(payload))
        guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in {"deliverySha256", "runtimeConfigurationSha256"}}
        guest.update(deliverySha256=p.sha(retrieval_delivery_original), runtimeConfigurationSha256=payload["runtimeConfig"]["sha256"])
        p.guest(guest); p.document(proof_scope_original, 16384)
        raw = p.canonical({"apiVersion": "serverware.nativeLedgerSpoolStoreGenesis/v1", "guest": guest,
            "proofScopeSha256": p.sha(proof_scope_original)})
        fd = os.open("genesis.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400, dir_fd=self._store)
        try:
            os.fchown(fd, self._uid, self._gid); os.fchmod(fd, 0o400)
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:]); p.require(count > 0); offset += count
            os.fsync(fd); os.fsync(self._store)
        finally:
            os.close(fd)
        self._genesis_fd = os.open("genesis.json", o.FLAGS, dir_fd=self._store); self._fds.append(self._genesis_fd)
        self._genesis_id = o.identity(os.fstat(self._genesis_fd)); self._genesis = raw
        self._retrieval_delivery = bytes(retrieval_delivery_original)
        p.require(o.read(self._genesis_fd, 16384) == raw); self.check()
        return {"genesisSha256": p.sha(raw), "sequence": 0, "headSha256": p.sha(raw)}

    def require_release(self, transfers, head_original):
        self.check(); p.require(self._genesis is not None and self._head is None)
        head = p.document(head_original, 65536)["payload"]
        self._scope, self._head = head["scope"], bytes(head_original)
        retrieval = p.document(transfers["retrieval"]._grant_bytes, 65536)["payload"]
        p.require(transfers["retrieval"]._delivery_bytes == self._retrieval_delivery
            and retrieval["store"] == {"genesisSha256": p.sha(self._genesis), "sequence": 0, "headSha256": p.sha(self._genesis)}
            and retrieval["spoolScope"] == self._scope)
        for role in ("retrieval", "ingressAdmission", "bridge"):
            transfer = transfers[role]; transfer.check()
            held = {entry["name"]: fd for entry, fd in zip(transfer._entries, transfer._fds, strict=True)}
            for name, fd in self.additions(role):
                p.require(name in held and o.structural(os.fstat(held[name])) == o.structural(os.fstat(fd)))

    def deliver_origin(self):
        """Explicit post-install attempt, not a poll, retry or ready assertion."""
        self.check(preparation=False)
        p.require(self._head is not None and not self._delivery_attempted)
        self._delivery_attempted = True
        from serverware.native_generation_origin_relay import deliver
        return deliver(self)

    def close(self):
        # Called only after the actual cohort close has observed/reaped all
        # children. Files survive for operator reconciliation; no unlink.
        if self._closed:
            return
        self._closed = True
        if hasattr(self, "_relay"):
            self._relay.close()
        for channel in self._sockets:
            channel.close()
        for fd in reversed(self._fds):
            os.close(fd)
