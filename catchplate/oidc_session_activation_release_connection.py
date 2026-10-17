"""One real accepted release socket, not a caller-selected descriptor grant."""
from __future__ import annotations

from dataclasses import dataclass
import errno
import fcntl
import os
import socket
import stat
import struct

from catchplate import oidc_session_activation_release_resources as resources


class ReleaseConnectionError(RuntimeError):
    pass


def _fail(message):
    raise ReleaseConnectionError(message)


def _identity(descriptor):
    value = os.fstat(descriptor)
    if not stat.S_ISSOCK(value.st_mode):
        _fail("release accepted descriptor is not a socket")
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def _require_inventory(expected):
    # At most seven retained FDs, three standard FDs and this proc scan.
    # A small fixed cap keeps every repeated metadata pass within its charged
    # 4096-byte bound rather than walking a generic 4096-descriptor inventory.
    names = []
    with os.scandir("/proc/self/fd") as entries:
        for entry in entries:
            if len(names) >= 16 or not entry.name.isascii() or not entry.name.isdecimal():
                _fail("release descriptor inventory exceeds its closed bound")
            names.append(int(entry.name))
    observed = set()
    for descriptor in names:
        if descriptor < 3:
            continue
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        observed.add(descriptor)
    if observed != set(expected):
        _fail("release descriptor inventory differs from its actual owned resources")


def _dispose(connection, descriptor, identity):
    """Never let Python's destructor close a replacement occupying an old FD."""
    try:
        if (identity is None or connection.fileno() != descriptor
                or _identity(descriptor) != identity):
            connection.detach()
            return False
        connection.close()
        return True
    except BaseException:
        try:
            connection.detach()
        except BaseException:
            pass
        return False


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    connection: socket.socket
    descriptor: int
    identity: tuple
    peer: tuple


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class _AcceptedConnection:
    _configured: _Configuration
    _seal: _Configuration
    _pid: int
    _closed: bool
    _cleanup_failed: bool

    def __init__(self):
        _fail("release connections require an actual native accept")

    def _check(self):
        configured = self._configured
        if (type(self) is not _AcceptedConnection or self._closed
                or self._pid != os.getpid() or type(configured) is not _Configuration
                or configured is not self._seal):
            _fail("release accepted connection is closed, changed or belongs to another process")
        connection, descriptor = configured.connection, configured.descriptor
        if (type(connection) is not socket.socket or descriptor < 3
                or connection.fileno() != descriptor
                or _identity(descriptor) != configured.identity
                or not fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                or os.get_blocking(descriptor) or connection.gettimeout() != 0.0
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0
                or connection.getsockname() != resources.LISTENER_PATH):
            _fail("release accepted socket differs from its actual sealed identity")
        peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if (peer != configured.peer or peer[0] <= 0
                or peer[1:] != (resources.PEER_UID, resources.PEER_GID)):
            _fail("release accepted peer differs from the fixed private identity")
        return configured

    def close(self):
        if type(self) is not _AcceptedConnection or self._pid != os.getpid():
            _fail("release connection close belongs to another process")
        if self._closed:
            if self._cleanup_failed:
                _fail("release connection cleanup remained uncertain; no retry is permitted")
            return
        object.__setattr__(self, "_closed", True)
        configured = self._configured
        complete = (type(configured) is _Configuration and configured is self._seal
            and _dispose(configured.connection, configured.descriptor, configured.identity))
        object.__setattr__(self, "_cleanup_failed", not complete)
        if not complete:
            _fail("release accepted connection cleanup is not established")


def _accept(listener_fd):
    """Native callback only; startup holds current authority and the work ledger."""
    if type(listener_fd) is not int or listener_fd != resources.LISTENER_FD:
        _fail("release accept requires the fixed inherited listener")
    listener = socket.socket(fileno=listener_fd)
    connection = None
    descriptor = -1
    identity = None
    try:
        connection, _address = listener.accept()
        descriptor = connection.fileno()
        identity = _identity(descriptor)
        connection.setblocking(False)
        connection.set_inheritable(False)
        peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        configured = _Configuration(connection, descriptor, identity, peer)
        owned = object.__new__(_AcceptedConnection)
        for name, value in (("_configured", configured), ("_seal", configured),
                ("_pid", os.getpid()), ("_closed", False), ("_cleanup_failed", False)):
            object.__setattr__(owned, name, value)
        owned._check()
        return owned
    except BaseException:
        if connection is not None:
            _dispose(connection, descriptor, identity)
        raise
    finally:
        # The inherited listener remains owned by the real resource handle.
        listener.detach()
