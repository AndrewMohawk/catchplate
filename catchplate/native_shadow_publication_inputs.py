"""Actual singleton PublicationReconciliation activation for adopted v8 only.

No listener pathname is reused, no service is launched, and no C9/grant or
business result is created. The actual composite retains every partial FD.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat

from catchplate import custody_generation_grants as g
from catchplate import custody_generation_originals as o
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_shadow_guest_delivery as delivery

p = g.p
ROLE = "publicationReconciliation"
NAME = "publication-reconciliation-listener"
PATH = "/run/catchplate-shadow-publication-reconciliation/listener.sock"
_TOKEN = object()


class PublicationActivation:
    def __init__(self, token, inputs):
        p.require(token is _TOKEN)
        self._inputs, self._fds, self._parents = inputs, [], []
        self._socket = self._path_identity = self._socket_identity = None
        self._closed = self._close_attempted = self._poisoned = self._admit_attempted = self._taken = False
        self._signed = None
        self._descriptors = ()

    def _parent(self, components):
        with io.owning():
            fd = os.open("/", o.FLAGS | os.O_DIRECTORY)
            self._fds.append(fd)
        for component in components:
            info = os.fstat(fd)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
            with io.owning():
                child = os.open(component, o.FLAGS | os.O_DIRECTORY, dir_fd=fd)
                self._fds.append(child)
            self._parents.append((fd, component, child, o.structural(os.fstat(child))))
            fd = child
        info = os.fstat(fd)
        p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o711)
        return fd

    @classmethod
    def prepare(cls, inputs):
        from catchplate.native_pilot_endpoint_inputs import PilotEndpointInputs
        p.require(cls is PublicationActivation and type(inputs) is PilotEndpointInputs
            and inputs._adopted and inputs._cohort.adoption_selected() and inputs._publication is None)
        inputs._origin()
        owner = cls(_TOKEN, inputs)
        inputs._publication = owner
        try:
            owner._directory = owner._parent(("run", "catchplate-shadow-publication-reconciliation"))
            p.require(stat.S_IMODE(os.fstat(owner._directory).st_mode) == 0o711)
            fcntl.flock(owner._directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
            p.require(o.names(owner._directory) == ())
            with io.owning():
                owner._socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            owner._socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            owner._socket.setsockopt(socket.SOL_SOCKET, 76, 1)
            owner._socket.bind(PATH)
            cold = inputs._cohort._cold[ROLE]
            os.chown("listener.sock", cold["uid"], inputs._cohort._cold["bridge"]["gid"], dir_fd=owner._directory, follow_symlinks=False)
            os.chmod("listener.sock", 0o660, dir_fd=owner._directory, follow_symlinks=False)
            owner._path_identity = o.identity(os.stat("listener.sock", dir_fd=owner._directory, follow_symlinks=False))
            owner._socket_identity = o.identity(os.fstat(owner._socket.fileno()))
            owner.check()
            return owner
        except BaseException:
            owner._poisoned = True
            raise

    def check(self):
        p.require(not self._closed and not self._poisoned)
        self._inputs._origin()
        for parent, name, child, expected in self._parents:
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0
                and o.structural(os.fstat(child)) == expected
                and o.structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        p.require(o.identity(os.fstat(self._socket.fileno())) == self._socket_identity
            and o.identity(os.stat("listener.sock", dir_fd=self._directory, follow_symlinks=False)) == self._path_identity
            and self._socket.getsockname() == PATH and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
            and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
            and self._socket.getsockopt(socket.SOL_SOCKET, 76) == 1
            and fcntl.fcntl(self._socket.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK
            and not os.get_inheritable(self._socket.fileno()))
        for target, fd in self._descriptors:
            p.require(target == 6 and o.identity(os.fstat(fd)) == self._socket_identity and not os.get_inheritable(fd))
        self._inputs._origin()

    def activation(self):
        self.check()
        value = o.activation(NAME, 6, self._socket.fileno())
        self.check()
        return [value]

    def admit_delivery(self, *, signed_delivery_original):
        from catchplate import native_shadow_driver_bootstrap as driver
        self.check()
        p.require(not self._admit_attempted and not self._taken)
        self._admit_attempted = True
        signed = p.fields(g.document(signed_delivery_original, delivery.MAX_DELIVERY), ("apiVersion", "payload", "signatureBase64url"))
        p.require(signed["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1")
        self._inputs._delivery(ROLE, signed_delivery_original)
        p.require(g.canonical(signed["payload"]["activation"]) == g.canonical(self.activation()))
        cold = self._inputs._cohort._cold[ROLE]
        driver._key(cold["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
            delivery.DOMAIN + g.canonical(signed["payload"]))
        self._signed = bytes(signed_delivery_original)
        self.check()
        return self._signed

    def take_for_cohort(self, *, launch_pin):
        self.check()
        p.require(not self._taken and self._signed is not None)
        self._taken = True
        with io.owning():
            held = fcntl.fcntl(self._socket.fileno(), fcntl.F_DUPFD_CLOEXEC, 128)
            self._fds.append(held); self._descriptors = ((6, held),)
        result = self._inputs._cohort.retain_activation_fds(role=ROLE, launch_pin=launch_pin,
            descriptors=self._descriptors, publication_owner=self)
        self.check()
        return result

    def close(self):
        if self._closed:
            return
        self._inputs.require_retired()
        p.require(not self._close_attempted)
        self._close_attempted = True
        with io.owning():
            if self._socket is not None:
                channel, self._socket = self._socket, None; channel.close()
            while self._fds:
                os.close(self._fds.pop())
            self._closed = True
        # Retain names as evidence. Nothing is unlinked or repaired.
