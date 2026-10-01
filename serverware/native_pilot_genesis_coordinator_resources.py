"""Actual unconnected cold coordinator sockets and held listener directories.

The admitted coordinator itself connects under its final identity. Root never
preconnects a socket or fabricates the two native-parent-owned result FDs.
"""
from __future__ import annotations

import errno
import fcntl
import os
import socket
import stat

from serverware import custody_generation_originals as o
from serverware import native_pilot_genesis_coordinator_runtime as runtime
from serverware import native_pilot_genesis_endpoint_profile as endpoints
from serverware import native_pilot_genesis_parent_control_io as io

p = o.p
_TOKEN = object()


class Resources:
    def __init__(self, token, owner):
        p.require(token is _TOKEN)
        self.owner, self.sockets, self.directories, self.activation = owner, [], [], []
        self.released = self.closed = False

    @classmethod
    def prepare(cls, owner):
        from serverware.native_pilot_genesis_coordinator_control import GenesisCoordinatorAssembly
        p.require(type(owner) is GenesisCoordinatorAssembly and owner._resources is None)
        value = cls(_TOKEN, owner)
        owner._resources = value
        selected = [(owner._ordinary._resources.roles[role]["run"], runtime.ordinary.listener(role),
            owner._ordinary._roles[role]["cold"]["uid"]) for role in runtime.ROLES]
        selected += [(owner._endpoints._resources.roles[role]["run"], endpoints.LISTENERS[role],
            owner._endpoints._cold[role]["uid"]) for role in (endpoints.ROLES[1], endpoints.ROLES[0])]
        for index, (source, path, uid) in enumerate(selected):
            owner._check(startup=True, resources=False)
            with io.owning():
                channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
                value.sockets.append(channel)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            channel.setsockopt(socket.SOL_SOCKET, 76, int(index >= 2))
            with io.owning():
                fd = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 128)
                row = {"fd": fd, "source": source, "path": path, "uid": uid}
                value.directories.append(row)
                row.update(identity=o.structural(os.fstat(fd)),
                    listener=o.structural(os.stat("listener.sock", dir_fd=fd, follow_symlinks=False)))
            value.activation.append(o.activation(runtime.ACTIVATION[index * 2][0], 6 + index * 2, channel.fileno()))
            value.activation.append(o.activation(runtime.ACTIVATION[index * 2 + 1][0], 7 + index * 2, fd))
        value.check()
        return value

    def check(self):
        p.require(not self.closed and len(self.sockets) == len(self.directories) == 4 and len(self.activation) == 8)
        for index, (channel, row) in enumerate(zip(self.sockets, self.directories, strict=True)):
            p.require(o.activation(runtime.ACTIVATION[index * 2][0], 6 + index * 2, channel.fileno()) == self.activation[index * 2]
                and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                and channel.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX
                and channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
                and channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
                and channel.getsockopt(socket.SOL_SOCKET, 76) == int(index >= 2)
                and fcntl.fcntl(channel, fcntl.F_GETFL) & os.O_NONBLOCK and not os.get_inheritable(channel.fileno()))
            if not self.released:
                p.require(channel.getsockname() in ("", b""))
                try:
                    channel.getpeername()
                except OSError as error:
                    p.require(error.errno == errno.ENOTCONN)
                else:
                    p.require(False)
            identity = row["identity"]
            p.require(o.structural(os.fstat(row["fd"])) == identity == o.structural(os.fstat(row["source"]))
                == o.structural(os.stat(row["path"].rsplit("/", 1)[0], follow_symlinks=False))
                and identity[2] == stat.S_IFDIR | 0o711 and identity[3] == identity[4] == 0
                and fcntl.fcntl(row["fd"], fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY
                and not os.get_inheritable(row["fd"]))
            listener = o.structural(os.stat("listener.sock", dir_fd=row["fd"], follow_symlinks=False))
            p.require(listener == row["listener"] and listener[2:] == (stat.S_IFSOCK | 0o660,
                row["uid"], self.owner._coordinator._context["cold"]["gid"]))
            p.require(o.activation(runtime.ACTIVATION[index * 2 + 1][0], 7 + index * 2, row["fd"]) == self.activation[index * 2 + 1])

    def borrowed_fds(self):
        self.check()
        return tuple(fd for channel, row in zip(self.sockets, self.directories, strict=True) for fd in (channel.fileno(), row["fd"]))

    def close_after_coordinator(self):
        # This only retires our duplicates, not any service or listener owner.
        p.require(self.owner._coordinator._closed)
        with io.owning():
            while self.sockets:
                self.sockets[-1].close(); self.sockets.pop()
            while self.directories:
                os.close(self.directories[-1]["fd"]); self.directories.pop()
            self.closed = True
