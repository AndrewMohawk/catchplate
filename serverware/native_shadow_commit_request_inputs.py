"""Actual fixed CommitRequest listener, retained through cohort cleanup.

This creates a bound, non-listening server socket, never an outgoing client or
an admitted signer. Cold C9 inputs and the existing cohort still authenticate
the independently signed launch/grant originals. Partial paths are neither
adopted nor removed; the actual final-role Rust owner performs listen.
"""
from __future__ import annotations

import errno
import fcntl
import os
import socket
import stat

from serverware import custody_generation_originals as originals
from serverware import native_shadow_nitro_profile as p
from serverware.native_shadow_persistence_inputs import PersistenceInputs

_TOKEN = object()
SOCKET_PATH = "/run/serverware-shadow-commit-request/listener.sock"
LISTENER = "commit-request-listener"
PEER_DIRECTORY = "commit-request-peer-directory"


class CommitRequestInputs:
    """One source-created server resource owner; no supplied PID/FD constructor."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._parents = [], []
        self._socket = self._transfer = None
        self._closed = self._ready = self._poisoned = self._transfer_attempted = False

    _parent = PersistenceInputs._parent

    @classmethod
    def prepare(cls, cohort):
        from serverware.native_shadow_proof_cohort_control import ParkedProofCohort
        p.require(cls is CommitRequestInputs and type(cohort) is ParkedProofCohort)
        cohort.check()
        p.require(cohort.commitment_selected() and "commitRequest" in cohort._roles
            and cohort._commit_request_resources is None
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        owner = cls(_TOKEN)
        owner._cohort = cohort
        # Retain before any filesystem effect. A failed preparation still
        # belongs to this same cleanup owner; no implicit close/retry/adoption.
        cohort._commit_request_resources = owner
        owner._uid = cohort._cold["commitRequest"]["uid"]
        owner._peer_gid = cohort._cold["bridge"]["gid"]
        p.require(owner._uid > 0 and owner._peer_gid > 0
            and owner._uid != cohort._cold["bridge"]["uid"])
        owner._directory = owner._parent(("run", "serverware-shadow-commit-request"))
        try:
            os.stat("listener.sock", dir_fd=owner._directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("CommitRequest listener exists; reconciliation required")
        owner._socket = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        owner._socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        owner._socket.setsockopt(socket.SOL_SOCKET, 76, 1)  # SO_PASSPIDFD; no fallback.
        owner._socket.bind(SOCKET_PATH)
        os.chown("listener.sock", owner._uid, owner._peer_gid,
            dir_fd=owner._directory, follow_symlinks=False)
        os.chmod("listener.sock", 0o660, dir_fd=owner._directory, follow_symlinks=False)
        owner._socket_identity = originals.identity(os.fstat(owner._socket.fileno()))
        owner._path_identity = originals.identity(os.stat("listener.sock",
            dir_fd=owner._directory, follow_symlinks=False))
        owner._ready = True
        owner.check()
        return owner

    def check(self):
        """Recheck the actual preparation resources, including before release."""
        p.require(not self._closed and self._ready and not self._poisoned)
        self._poisoned = True
        self._cohort.check()
        p.require(self._cohort._commit_request_resources is self
            and self._uid == self._cohort._cold["commitRequest"]["uid"]
            and self._peer_gid == self._cohort._cold["bridge"]["gid"])
        for parent, name, child, expected in self._parents:
            info = os.fstat(parent)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_mode & 0o022 == 0
                and originals.structural(os.fstat(child)) == expected
                and originals.structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        directory = os.fstat(self._directory)
        p.require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == directory.st_gid == 0
            and stat.S_IMODE(directory.st_mode) == 0o711)
        # A fresh OFD must still conflict with the continuously retained lock.
        other = os.open(".", originals.FLAGS | os.O_DIRECTORY, dir_fd=self._directory)
        try:
            p.require(originals.structural(os.fstat(other)) == originals.structural(directory))
            try:
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                p.require(error.errno in (errno.EWOULDBLOCK, errno.EAGAIN))
            else:
                raise ValueError("CommitRequest directory lock continuity lost")
        finally:
            os.close(other)
        info = os.stat("listener.sock", dir_fd=self._directory, follow_symlinks=False)
        p.require(originals.identity(info) == self._path_identity
            and stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o660
            and (info.st_uid, info.st_gid) == (self._uid, self._peer_gid)
            and originals.identity(os.fstat(self._socket.fileno())) == self._socket_identity
            and self._socket.getsockname() == SOCKET_PATH)
        for option, expected in ((socket.SO_TYPE, socket.SOCK_SEQPACKET), (socket.SO_DOMAIN, socket.AF_UNIX),
                (socket.SO_ACCEPTCONN, 0), (socket.SO_PASSCRED, 1), (76, 1)):
            p.require(self._socket.getsockopt(socket.SOL_SOCKET, option) == expected)
        try:
            self._socket.getpeername()
        except OSError as error:
            p.require(error.errno == errno.ENOTCONN)
        else:
            raise ValueError("CommitRequest resource is not an unconnected server listener")
        p.require(fcntl.fcntl(self._socket.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK
            and all(not os.get_inheritable(fd) for fd in (*self._fds, self._socket.fileno())))
        self._cohort.check()
        self._poisoned = False

    def activation(self):
        """Actual C9 FD6 metadata, not a signed delivery or readiness claim."""
        self.check()
        info = os.fstat(self._socket.fileno())
        result = [{"name": LISTENER, "fd": 6, "device": info.st_dev, "inode": info.st_ino,
            "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid}]
        self.check()
        return result

    def additions(self, role):
        """Fixed actual resources for server and separately owned bridge C9."""
        self.check()
        p.require(role in ("commitRequest", "bridge"))
        return ((LISTENER, self._socket.fileno()),) if role == "commitRequest" else ((PEER_DIRECTORY, self._directory),)

    def transfer(self, *, launch_pin):
        """One signed-original join through the cohort's existing transfer owner.

        The retained purpose owner is checked again by begin_release; no grant
        authority is inferred from these metadata or from the socket's presence.
        """
        self.check()
        p.require(not self._transfer_attempted)
        self._transfer_attempted = True
        self._transfer = self._cohort.retain_activation_fds(role="commitRequest", launch_pin=launch_pin,
            descriptors=((6, self._socket.fileno()),), commit_request_owner=self)
        self.check()
        return self._transfer

    def close(self):
        """Release only after actual endpoint and any separate driver reaps."""
        if self._closed:
            return
        p.require(self._cohort._parent_reaped)
        if self._cohort._external_driver is not None:
            self._cohort._external_driver.terminal()
        if self._transfer is not None:
            self._transfer.close()
        if self._socket is not None:
            self._socket.close()
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()
        self._closed = True
        # Deliberately retain the filesystem socket path for explicit operator
        # reconciliation. No unlink, implicit replacement or lifecycle receipt.
