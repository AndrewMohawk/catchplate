"""Fixed-seven/eight/eleven retained resources, not installed authority.

Creates the Ingress listener, the explicitly selected Terminal listener, an empty
durable retrieval-core store, and the one signed-origin channel. Old retrieval objects/listeners and every
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
EFFECT_LISTENERS = {
    "dispatchBarrier": "dispatch-barrier",
    "activeEffectBarrier": "active-effect-barrier",
    "activeEffectCommit": "active-effect-commit",
}


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
        self._effect_listeners = {}
        self._retrieval_attempted = False
        self._retrieval_activation = None

    _parent = existing.PersistenceInputs._parent

    @classmethod
    def prepare(cls, cohort):
        from serverware.native_shadow_proof_cohort_control import ParkedProofCohort
        p.require(cls is SpoolInputs and type(cohort) is ParkedProofCohort and cohort.spool_selected())
        value = cls(_TOKEN); value._cohort = cohort
        value._terminal_selected = cohort.terminal_selected()
        value._effects_selected = cohort.effects_selected()
        p.require(not value._effects_selected or value._terminal_selected)
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
        if value._terminal_selected:
            value._terminal_parent = value._parent(("run", "serverware-shadow-terminal-append"))
            value._terminal_listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            value._sockets.append(value._terminal_listener)
            value._terminal_listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            value._terminal_listener.setsockopt(socket.SOL_SOCKET, 76, 1)
            value._terminal_listener.bind("/run/serverware-shadow-terminal-append/listener.sock")
            os.chown("listener.sock", cohort._cold["terminalAppend"]["uid"], cohort._cold["bridge"]["gid"],
                dir_fd=value._terminal_parent, follow_symlinks=False)
            os.chmod("listener.sock", 0o660, dir_fd=value._terminal_parent, follow_symlinks=False)
            value._terminal_id = o.identity(os.fstat(value._terminal_listener.fileno()))
            value._terminal_path_id = o.identity(os.stat("listener.sock", dir_fd=value._terminal_parent, follow_symlinks=False))
        if value._effects_selected:
            for role, slug in EFFECT_LISTENERS.items():
                parent = value._parent(("run", "serverware-shadow-" + slug))
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
                value._sockets.append(listener)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                listener.setsockopt(socket.SOL_SOCKET, 76, 1)
                listener.bind("/run/serverware-shadow-" + slug + "/listener.sock")
                os.chown("listener.sock", cohort._cold[role]["uid"], cohort._cold["bridge"]["gid"],
                    dir_fd=parent, follow_symlinks=False)
                os.chmod("listener.sock", 0o660, dir_fd=parent, follow_symlinks=False)
                value._effect_listeners[role] = (parent, listener,
                    o.identity(os.fstat(listener.fileno())),
                    o.identity(os.stat("listener.sock", dir_fd=parent, follow_symlinks=False)))
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
            if self._cohort._external_driver is not None:
                self._cohort._external_driver.check(live=True)
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
        p.require(self._terminal_selected == ("terminalAppend" in self._cohort._roles))
        if self._terminal_selected:
            p.require(o.identity(os.fstat(self._terminal_listener.fileno())) == self._terminal_id
                and o.identity(os.stat("listener.sock", dir_fd=self._terminal_parent, follow_symlinks=False)) == self._terminal_path_id)
        expected_effects = set(EFFECT_LISTENERS) if self._effects_selected else set()
        p.require(set(self._effect_listeners) == expected_effects
            == set(self._cohort._roles).intersection(EFFECT_LISTENERS))
        for parent, listener, listener_id, path_id in self._effect_listeners.values():
            p.require(o.identity(os.fstat(listener.fileno())) == listener_id
                and o.identity(os.stat("listener.sock", dir_fd=parent, follow_symlinks=False)) == path_id)
        for fd, expected in self._channels:
            p.require(o.identity(os.fstat(fd)) == expected and not os.get_inheritable(fd))
        self._relay.check()

    def additions(self, role):
        """Actual named FDs for the separately signed C9 activation producer."""
        self.check()
        selected = {"retrieval": (("ledger-spool-store", self._store), ("ledger-spool-lock", self._lock)),
            "ingressAdmission": (("ingress-admission-listener", self._listener.fileno()),),
            "bridge": (("ingress-admission-peer-directory", self._listener_parent), ("generation-origin", self._remote.fileno()))}
        if self._terminal_selected:
            selected["terminalAppend"] = (("terminal-append-listener", self._terminal_listener.fileno()),)
            selected["bridge"] += (("terminal-append-peer-directory", self._terminal_parent),)
        for effect_role, (parent, listener, _, _) in self._effect_listeners.items():
            slug = EFFECT_LISTENERS[effect_role]
            selected[effect_role] = ((slug + "-listener", listener.fileno()),)
            selected["bridge"] += ((slug + "-peer-directory", parent),)
        p.require(role in selected); return selected[role]

    def prepare_retrieval(self, *, configuration_raw, configuration_sha256, peer_raw, peer_sha256,
                          object_directory_fd, startup_deadline_boottime_ns):
        """Actual full4 effects Retrieval owner, not another signing authority.

        Keep the old RetrievalActivation.prepare path exact2. Here the real
        cohort selects the cold identity/window and retains the resource owner
        before binding its already held store/lock OFDs. Partial preparation
        remains fenced until the cohort's actual cleanup; no old path adoption.
        """
        from serverware.native_shadow_retrieval_activation import RetrievalActivation
        from serverware import native_shadow_guest_delivery as d
        from serverware import native_shadow_retrieval_artifacts as a
        self.check()
        p.require(self._effects_selected and not self._retrieval_attempted)
        self._retrieval_attempted = True
        cold = d.configuration(configuration_raw, configuration_sha256)
        p.require(configuration_sha256 == self._cohort._config["retrievalConfiguration"]["sha256"]
            and p.canonical(cold) == p.canonical(self._cohort._cold["retrieval"])
            and p.ns(startup_deadline_boottime_ns) == self._cohort.startup_deadline_boottime_ns())
        peer = a._peer(peer_raw)
        p.require(p.sha(peer_raw) == p.digest(peer_sha256)
            and (peer["uid"], peer["gid"]) == (self._cohort._cold["bridge"]["uid"], self._cohort._cold["bridge"]["gid"]))
        if self._cohort._external_driver is None:
            original = self._cohort.bridge_original()
            process = original
        else:
            original = self._cohort._external_driver.value
            process = original["driver"]
        p.require(peer["pid"] == process["processId"] and peer["startTimeTicks"] == process["startTimeTicks"])
        for field, source in (("executableDevice", "device"), ("executableInode", "inode"),
                              ("executableLength", "length"), ("executableSha256", "sha256")):
            p.require(peer[field] == original["executable"][source])
        owner = RetrievalActivation.prepare(configuration_raw=configuration_raw,
            configuration_sha256=configuration_sha256, peer_raw=peer_raw, peer_sha256=peer_sha256,
            object_directory_fd=object_directory_fd, startup_deadline_boottime_ns=startup_deadline_boottime_ns)
        self._retrieval_activation = owner
        owner.bind_spool(self)
        self.check()
        return owner

    def retrieval_additions(self, owner):
        """Actual retained store/lock, only for this source-created Retrieval."""
        from serverware.native_shadow_retrieval_activation import RetrievalActivation
        self.check()
        p.require(self._effects_selected and type(owner) is RetrievalActivation
            and owner is self._retrieval_activation)
        return self.additions("retrieval")

    def require_retrieval_delivery(self, owner, original):
        """Bind the verified full4 original to the exact original cohort window."""
        from serverware import native_shadow_guest_delivery as d
        self.retrieval_additions(owner)
        payload = p.fields(p.document(original, d.MAX_DELIVERY)["payload"], d.FIELDS)
        p.require(payload["configurationSha256"] == self._cohort._config["retrievalConfiguration"]["sha256"])
        for name in ("authorityKeyId", "invocationId", "bootIdBase64url", "timeNamespaceDevice",
                     "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"):
            p.require(p.canonical(payload[name]) == p.canonical(self._cohort._window[name]))
        self.check()

    def retain_retrieval_transfer(self, owner, *, launch_pin):
        self.retrieval_additions(owner)
        p.require(self._genesis is not None and self._retrieval_delivery == owner.signed_original())
        return self._cohort.retain_retrieval_activation(activation=owner, launch_pin=launch_pin)

    def require_retrieval_retired(self, owner):
        # Deliberately no preparation/live check after release. Only the same
        # spool's terminal cleanup may discard this shared resource owner.
        p.require(owner is self._retrieval_activation and self._closed)

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
        p.require(self._cohort._external_driver is None)
        return self._require_release(transfers, head_original, inputs=None)

    def require_endpoint_release(self, transfers, head_original, inputs):
        from serverware.native_shadow_driver_inputs import OperationalInputs
        p.require(type(inputs) is OperationalInputs and self._cohort._external_driver is not None
            and inputs._driver is self._cohort._external_driver.driver and not inputs._begun)
        inputs.check()
        return self._require_release(transfers, head_original, inputs=inputs)

    def _require_release(self, transfers, head_original, *, inputs):
        self.check(); p.require(self._genesis is not None and self._head is None)
        head = p.document(head_original, 65536)["payload"]
        head_version = 3 if self._effects_selected else 2 if self._terminal_selected else 1
        p.require(head["apiVersion"] == f"serverware.nativeSpoolHeadGrant/v{head_version}")
        self._scope, self._head = head["scope"], bytes(head_original)
        retrieval = p.document(transfers["retrieval"]._grant_bytes, 65536)["payload"]
        p.require(transfers["retrieval"]._delivery_bytes == self._retrieval_delivery
            and retrieval["store"] == {"genesisSha256": p.sha(self._genesis), "sequence": 0, "headSha256": p.sha(self._genesis)}
            and retrieval["spoolScope"] == self._scope)
        roles = ("retrieval", "ingressAdmission", "bridge")
        if self._terminal_selected:
            terminal = head["completion"]["terminal"]
            p.require(terminal["grantSha256"] == p.sha(transfers["terminalAppend"]._grant_bytes)
                and retrieval["terminal"] == terminal)
            roles += ("terminalAppend",)
        if self._effects_selected:
            p.fields(retrieval["effects"], EFFECT_LISTENERS)
            for role in EFFECT_LISTENERS:
                key = head["effects"][role]
                p.require(key["grantSha256"] == p.sha(transfers[role]._grant_bytes)
                    and retrieval["effects"][role] == key)
            roles += tuple(EFFECT_LISTENERS)
        for role in roles:
            if role == "bridge" and inputs is not None:
                inputs.check()
                held = {name.removeprefix("activation:"): fd for name, fd in inputs._descriptors.items()
                    if name.startswith("activation:")}
            else:
                transfer = transfers[role]; transfer.check()
                held = {entry["name"]: fd for entry, fd in zip(transfer._entries, transfer._fds, strict=True)}
            for name, fd in self.additions(role):
                p.require(name in held and o.structural(os.fstat(held[name])) == o.structural(os.fstat(fd)))

    def deliver_origin(self, *, deadline_boottime_ns=None):
        """Explicit post-install attempt, not a poll, retry or ready assertion."""
        self.check(preparation=False)
        p.require(self._head is not None and not self._delivery_attempted)
        self._delivery_attempted = True
        from serverware.native_generation_origin_relay import deliver
        return deliver(self, deadline_boottime_ns=deadline_boottime_ns)

    def close(self):
        # Called only after the actual cohort close has observed/reaped all
        # children. Files survive for operator reconciliation; no unlink.
        if self._closed:
            return
        if self._retrieval_activation is not None:
            p.require(self._cohort._parent_reaped)
        if self._cohort._external_driver is not None:
            p.require(self._cohort._parent_reaped)
            self._cohort._external_driver.terminal()
        self._closed = True
        if self._retrieval_activation is not None:
            self._retrieval_activation.close()
        if hasattr(self, "_relay"):
            self._relay.close()
        for channel in self._sockets:
            channel.close()
        for fd in reversed(self._fds):
            os.close(fd)
