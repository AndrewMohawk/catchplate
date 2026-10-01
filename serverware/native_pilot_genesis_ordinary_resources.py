"""Actual fixed cold DRS/CSA listeners, journals and one-use grant memfds.

Empty-directory observations are not genesis, history, admission or readiness.
Only the retained two-service owner may create or release these resources. No
old directory is adopted and no partial original is removed or repaired.
"""
from __future__ import annotations

import ctypes
import fcntl
import os
import socket
import stat

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o
from serverware import native_pilot_genesis_parent_control_io as io

p = g.p
ROLES = (g.ROLES[0], g.ROLES[3])
DIRECTORIES = {ROLES[0]: ("journal", "publication-genesis-journal"),
    ROLES[1]: ("publication-genesis-journal",)}
ACTIVATION = {role: ("listener", *DIRECTORIES[role], "publication-genesis-grant") for role in ROLES}
API = "serverware.custodyGenesisTwoServiceResources/v1"
FIELDS = ("apiVersion", "preparationSha256", "issuedAtBoottimeNs", "services")
RUN = "/run/serverware-custody-genesis"
STORE = "/var/lib/serverware/custody-genesis"
MAX_GRANT = 256 * 1024
_TOKEN = object()


def _persistent(fd):
    buffer = ctypes.create_string_buffer(256)
    p.require(ctypes.CDLL(None, use_errno=True).fstatfs(fd, ctypes.byref(buffer)) == 0)
    p.require(ctypes.c_long.from_buffer(buffer).value & 0xffffffff in {0xef53, 0x58465342, 0x9123683e})


def _protected(fd):
    info = os.fstat(fd)
    p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
        and stat.S_IMODE(info.st_mode) == 0o711 and not os.get_inheritable(fd))


class GenesisOrdinaryResources:
    def __init__(self, token, owner):
        p.require(token is _TOKEN)
        self.owner = owner
        self.fds, self.sockets, self.roles = [], [], {}
        self.closed = self.released = self.grant_attempted = False
        self.raw = None

    @classmethod
    def _prepare(cls, owner):
        from serverware.native_pilot_genesis_ordinary_control import GenesisOrdinaryControl
        p.require(cls is GenesisOrdinaryResources and type(owner) is GenesisOrdinaryControl
            and owner._resources is None and not owner._release_attempted)
        value = cls(_TOKEN, owner)
        owner._resources = value  # Retain partial acquisition before cancellation.
        value.roots = []
        for path in (RUN, STORE):
            with io.owning():
                fd = o.directory(path)
                value.fds.append(fd)
                value.roots.append((path, fd, o.structural(os.fstat(fd))))
            _protected(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            p.require(o.names(fd) == ())
        value.run, value.store = (row[1] for row in value.roots)
        _persistent(value.store)
        identities = {row[2][:2] for row in value.roots}
        p.require(len(identities) == 2)
        for role in ROLES:
            owner._check(startup=True, resources=False)
            cold = owner._roles[role]["cold"]
            row = {"directories": {}, "descriptors": [], "grant_raw": None}
            value.roles[role] = row
            for name, parent in (("run", value.run), ("store", value.store)):
                os.mkdir(role, 0o711, dir_fd=parent)
                with io.owning():
                    fd = os.open(role, o.FLAGS | os.O_DIRECTORY, dir_fd=parent)
                    value.fds.append(fd)
                    row[name] = fd
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o711)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                row[name + "_identity"] = o.structural(os.fstat(fd))
            _persistent(row["store"])
            for name in DIRECTORIES[role]:
                os.mkdir(name, 0o700, dir_fd=row["store"])
                with io.owning():
                    fd = os.open(name, o.FLAGS | os.O_DIRECTORY, dir_fd=row["store"])
                    value.fds.append(fd)
                    row["directories"][name] = fd
                os.fchown(fd, cold["uid"], cold["gid"])
                os.fchmod(fd, 0o700)
                _persistent(fd)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                p.require(o.names(fd) == ())
                os.fsync(fd)
            path = RUN + "/" + role + "/listener.sock"
            p.require(len(path.encode("ascii")) < 108)
            with io.owning():
                listener = socket.socket(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
                value.sockets.append(listener)
                row["listener"] = listener
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            listener.bind(path)
            os.chown("listener.sock", cold["uid"], owner._coordinator_cold_value["gid"],
                dir_fd=row["run"], follow_symlinks=False)
            os.chmod("listener.sock", 0o660, dir_fd=row["run"])
            listener.listen(1)
            row["path"] = path
            row["path_identity"] = o.identity(os.stat("listener.sock", dir_fd=row["run"], follow_symlinks=False))
            with io.owning():
                grant = os.memfd_create("custody-genesis-" + role, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                value.fds.append(grant)
                row["grant"] = grant
            os.fchown(grant, cold["uid"], cold["gid"])
            # The explicit cold Gate requires a fully sealed 0600 memfd;
            # this is distinct from a root0400 public signing-input file.
            os.fchmod(grant, 0o600)
            # C9 pins this actual inode before its later signed contents exist.
            row["descriptors"] = [("listener", listener.fileno()), *row["directories"].items(),
                ("publication-genesis-grant", grant)]
            row["activation"] = [o.activation(name, target, fd)
                for target, (name, fd) in enumerate(row["descriptors"], 6)]
            row["directory_identities"] = {name: o.directory_identity(fd) for name, fd in row["directories"].items()}
            for _, fd in row["descriptors"]:
                identity = o.structural(os.fstat(fd))[:2]
                p.require(identity not in identities)
                identities.add(identity)
            for fd in (row["run"], row["store"], value.run, value.store):
                os.fsync(fd)
        value.check()
        return value

    def check(self):
        p.require(not self.closed and tuple(self.roles) == ROLES)
        for path, fd, identity in self.roots:
            _protected(fd)
            p.require(o.structural(os.fstat(fd)) == identity
                and o.structural(os.stat(path, follow_symlinks=False)) == identity
                and o.names(fd) == tuple(sorted(ROLES)))
        for role, row in self.roles.items():
            for name, root in (("run", self.run), ("store", self.store)):
                fd = row[name]
                _protected(fd)
                p.require(o.structural(os.fstat(fd)) == row[name + "_identity"]
                    == o.structural(os.stat(role, dir_fd=root, follow_symlinks=False)))
            p.require(o.names(row["run"]) == ("listener.sock",)
                and o.names(row["store"]) == tuple(sorted(DIRECTORIES[role]))
                and o.identity(os.stat("listener.sock", dir_fd=row["run"], follow_symlinks=False)) == row["path_identity"])
            listener = row["listener"]
            p.require(listener.getsockname() == row["path"]
                and listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
                and listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                and listener.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
                and fcntl.fcntl(listener, fcntl.F_GETFL) & os.O_NONBLOCK)
            for entry, (name, fd) in zip(row["activation"], row["descriptors"], strict=True):
                p.require(entry == o.activation(name, entry["fd"], fd) and not os.get_inheritable(fd))
                if name in row["directories"]:
                    p.require(o.directory_identity(fd) == row["directory_identities"][name]
                        and o.structural(os.stat(name, dir_fd=row["store"], follow_symlinks=False)) == o.structural(os.fstat(fd)))
                    if not self.released:
                        p.require(o.names(fd) == ())
            if row["grant_raw"] is None:
                p.require(os.fstat(row["grant"]).st_size == 0 and fcntl.fcntl(row["grant"], fcntl.F_GET_SEALS) == 0)
            else:
                p.require(fcntl.fcntl(row["grant"], fcntl.F_GET_SEALS) == o.SEALS
                    and o.read(row["grant"], MAX_GRANT) == row["grant_raw"])

    def original(self, preparation):
        self.check()
        p.require(not self.released)
        value = {"apiVersion": API, "preparationSha256": p.sha(preparation),
            "issuedAtBoottimeNs": str(self.owner._issued), "services": {role: {"directories": {
                name: {"identity": o.directory_identity(fd), "entryCount": len(o.names(fd))}
                for name, fd in self.roles[role]["directories"].items()}} for role in ROLES}}
        raw = g.canonical(value)
        p.require(len(raw) <= 65536 and all(entry["entryCount"] == 0
            for row in value["services"].values() for entry in row["directories"].values()))
        if self.raw is None:
            self.raw = raw
        p.require(self.raw == raw)
        self.check()
        return raw

    def seal(self, grants):
        self.check()
        p.fields(grants, ROLES)
        p.require(not self.grant_attempted and not self.released)
        self.grant_attempted = True
        for role in ROLES:
            raw = grants[role]
            g.document(raw, MAX_GRANT)
            row = self.roles[role]
            offset = 0
            while offset < len(raw):
                self.owner._check(startup=True, resources=False)
                self.owner._release_clock()
                count = os.pwrite(row["grant"], raw[offset:], offset)
                p.require(count > 0)
                offset += count
            fcntl.fcntl(row["grant"], fcntl.F_ADD_SEALS, o.SEALS)
            row["grant_raw"] = raw
            p.require(o.read(row["grant"], MAX_GRANT) == raw)
        self.check()

    def close_after_reap(self):
        p.require(not self.closed and not self.owner._native_may_run
            and all(item["pid"] is None or item["reaped"] for item in self.owner._children.values()))
        # Keep the remaining capabilities accurate if cancellation or a close
        # error interrupts retirement after the actual process reaps.
        with io.owning():
            while self.sockets:
                self.sockets[-1].close()
                self.sockets.pop()
            while self.fds:
                os.close(self.fds[-1])
                self.fds.pop()
            self.closed = True
        # Created directory/socket names remain evidence; never unlink state.
