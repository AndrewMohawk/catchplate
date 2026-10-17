"""Retained cold endpoint sockets and genuine sequence-zero ledger files.

Exclusive creation is not publication genesis evidence. The ledger's actual
genesis.json original is written, synchronized and reread only after C9
authentication. No empty-directory inference produces an admitted store.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat

from catchplate import custody_generation_grants as g
from catchplate import custody_generation_originals as o
from catchplate import native_pilot_genesis_endpoint_profile as wire
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate.native_shadow_spool_inputs import _verity_fs

p = g.p
STORE = "/var/lib/catchplate/publication-genesis-endpoints"
_TOKEN = object()


class Resources:
    def __init__(self, token, owner):
        p.require(token is _TOKEN)
        self.owner, self.fds, self.sockets, self.roots, self.roles = owner, [], [], [], {}
        self.raw = self.genesis = self.store_raw = None
        self.closed = self.released = self.store_attempted = False

    def _directory(self, path):
        with io.owning():
            fd = o.directory(path)
            self.fds.append(fd)
        info = os.fstat(fd)
        p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o711)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        p.require(o.names(fd) == ())
        self.roots.append((path, fd, o.structural(info)))
        return fd

    @classmethod
    def prepare(cls, owner):
        from catchplate.native_pilot_genesis_endpoint_control import GenesisEndpointControl
        p.require(type(owner) is GenesisEndpointControl and owner._resources is None)
        value = cls(_TOKEN, owner)
        owner._resources = value  # Partial descriptors survive an exception.
        value.store = value._directory(STORE)
        _verity_fs(value.store)
        for role in wire.ROLES:
            owner._check(startup=True, resources=False)
            cold = owner._cold[role]
            row = {"directories": {}, "descriptors": []}
            value.roles[role] = row
            path = wire.LISTENERS[role]
            row["run"] = value._directory(path.rsplit("/", 1)[0])
            with io.owning():
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
                value.sockets.append(listener); row["listener"] = listener
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            listener.bind(path)
            os.chown("listener.sock", cold["uid"], owner._parent_cold["gid"], dir_fd=row["run"], follow_symlinks=False)
            os.chmod("listener.sock", 0o660, dir_fd=row["run"])
            listener.listen(1)
            row["path_identity"] = o.identity(os.stat("listener.sock", dir_fd=row["run"], follow_symlinks=False))
            row["descriptors"].append((wire.ACTIVATION[role][0], listener.fileno()))
            for name in wire.DIRECTORIES[role]:
                os.mkdir(name, 0o700, dir_fd=value.store)
                with io.owning():
                    fd = os.open(name, o.FLAGS | os.O_DIRECTORY, dir_fd=value.store)
                    value.fds.append(fd); row["directories"][name] = fd
                os.fchown(fd, cold["uid"], cold["gid"]); os.fchmod(fd, 0o700)
                _verity_fs(fd)
                p.require(o.names(fd) == ())
                row["descriptors"].append((name, fd))
                os.fsync(fd)
            if role == wire.ROLES[0]:
                directory = row["directories"]["ledger-spool-store"]
                with io.owning():
                    lock = os.open("ledger.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600, dir_fd=directory)
                    value.fds.append(lock); row["lock"] = lock
                os.fchown(lock, cold["uid"], cold["gid"]); os.fchmod(lock, 0o600)
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                row["lock_identity"] = o.identity(os.fstat(lock))
                row["descriptors"].append(("ledger-spool-lock", lock))
                os.fsync(lock); os.fsync(directory)
            row["activation"] = [o.activation(name, target, fd) for target, (name, fd) in enumerate(row["descriptors"], 6)]
            row["identities"] = {name: o.directory_identity(fd) for name, fd in row["directories"].items()}
            os.fsync(row["run"])
        os.fsync(value.store)
        value.check()
        value.raw = g.canonical({"apiVersion": wire.RESOURCES_API, "preparationSha256": p.sha(owner._preparation),
            "issuedAtBoottimeNs": owner._window["issuedAtBoottimeNs"], "services": {role: {
                "activation": row["activation"], "listenerSocketPath": wire.LISTENERS[role],
                "directories": {name: {"identity": o.directory_identity(fd), "entryCount": len(o.names(fd))}
                    for name, fd in row["directories"].items()}} for role, row in value.roles.items()}})
        wire.resources(value.raw)
        owner._clock(startup=True)
        return value

    def check(self):
        p.require(not self.closed and tuple(self.roles) == wire.ROLES)
        for path, fd, identity in self.roots:
            p.require(o.structural(os.fstat(fd)) == identity == o.structural(os.stat(path, follow_symlinks=False)))
        p.require(o.names(self.store) == tuple(sorted(wire.DIRECTORIES[wire.ROLES[0]])))
        for role, row in self.roles.items():
            p.require(o.names(row["run"]) == ("listener.sock",)
                and o.identity(os.stat("listener.sock", dir_fd=row["run"], follow_symlinks=False)) == row["path_identity"])
            listener = row["listener"]
            p.require(listener.getsockname() == wire.LISTENERS[role]
                and listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
                and listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                and fcntl.fcntl(listener, fcntl.F_GETFL) & os.O_NONBLOCK)
            for entry, (name, fd) in zip(row["activation"], row["descriptors"], strict=True):
                p.require(entry == o.activation(name, entry["fd"], fd) and not os.get_inheritable(fd))
                if name in row["directories"]:
                    p.require(o.directory_identity(fd) == row["identities"][name]
                        and o.structural(os.stat(name, dir_fd=self.store, follow_symlinks=False)) == o.structural(os.fstat(fd)))
                    if not self.released:
                        expected = () if name == "retrieval-objects" else (("genesis.json", "ledger.lock") if self.genesis else ("ledger.lock",))
                        p.require(o.names(fd) == expected)
            if role == wire.ROLES[0]:
                directory = row["directories"]["ledger-spool-store"]
                p.require(o.identity(os.fstat(row["lock"])) == row["lock_identity"]
                    == o.identity(os.stat("ledger.lock", dir_fd=directory, follow_symlinks=False)))
        if self.genesis is not None:
            fd, identity, raw = self.genesis
            directory = self.roles[wire.ROLES[0]]["directories"]["ledger-spool-store"]
            p.require(o.identity(os.fstat(fd)) == identity == o.identity(os.stat("genesis.json", dir_fd=directory, follow_symlinks=False))
                and o.read(fd, 65536) == raw)

    def original(self):
        self.owner._check(startup=True)
        p.require(self.raw is not None and not self.released)
        return bytes(self.raw)

    def initialize_store(self, *, proof_scope_fd, proof_scope_sha256):
        self.owner._check(startup=True)
        p.require(not self.store_attempted and not self.released and wire.ROLES[0] in self.owner._deliveries)
        self.store_attempted = True
        original = self.owner._input(proof_scope_fd, 65536, proof_scope_sha256)
        g.document(original.raw, 65536)
        delivery = self.owner._deliveries[wire.ROLES[0]]
        raw = g.canonical({"apiVersion": "catchplate.nativeLedgerSpoolStoreGenesis/v1",
            "guest": delivery["context"]["guest"], "proofScopeSha256": p.sha(original.raw)})
        row = self.roles[wire.ROLES[0]]; directory = row["directories"]["ledger-spool-store"]
        cold = self.owner._cold[wire.ROLES[0]]
        with io.owning():
            fd = os.open("genesis.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=directory)
            self.fds.append(fd)
        os.fchown(fd, cold["uid"], cold["gid"]); os.fchmod(fd, 0o400)
        offset = 0
        while offset < len(raw):
            self.owner._clock(startup=True)
            count = os.pwrite(fd, raw[offset:], offset)
            p.require(count > 0); offset += count
        os.fsync(fd); os.fsync(directory)
        written = o.identity(os.fstat(fd))
        with io.owning():
            held = os.open("genesis.json", o.FLAGS, dir_fd=directory); self.fds.append(held)
        p.require(o.identity(os.fstat(held)) == written and written[5] == 1 and o.read(held, 65536) == raw)
        # Retire the writable handle only after durable exact readback.
        with io.owning():
            os.close(fd); self.fds.remove(fd)
        self.genesis = held, written, raw
        info = os.fstat(held)
        self.store_raw = g.canonical({"apiVersion": wire.STORE_API, "resourcesSha256": p.sha(self.raw),
            "deliverySha256": p.sha(delivery["raw"]), "proofScopeSha256": p.sha(original.raw), "genesisOriginal": raw.decode("ascii"),
            "genesisFile": {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
                "uid": info.st_uid, "gid": info.st_gid, "length": info.st_size, "sha256": p.sha(raw)},
            "store": {"genesisSha256": p.sha(raw), "sequence": 0, "headSha256": p.sha(raw)}})
        wire.store_observation(self.store_raw, resources_raw=self.raw, delivery_raw=delivery["raw"], proof_scope_raw=original.raw)
        self.owner._check(startup=True)
        return bytes(self.store_raw)

    def close_after_reap(self):
        p.require(self.owner._process.pid is None or self.owner._process.reaped)
        for listener in self.sockets:
            listener.close()
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear(); self.closed = True
        # Names and durable originals remain evidence. Nothing is deleted.
