"""One actual root-owned request issuance and staged cold planner, no retries.

The parent must deliver its original runtime root signer as sealed FD4; this
service never generates, copies to disk or delegates it to a planner/app.
Fixed public policy/cohort admission precedes private access. Every invocation
is terminal after one accepted request, allowing an external original socket
owner to launch a fresh process for a later independent request.
"""
from __future__ import annotations

import os
import select
import socket
import stat
import threading
import time
from types import MethodType

from serverware import authority_oidc_session_activation_request_issuance as issuance
from serverware import authority_oidc_session_activation_request_issuance_transport as transport
from serverware import authority_oidc_session_activation_request_staging_transport as staging
from serverware import oidc_session_activation_request_dynamic_entrypoint as resources


LISTENER_NAME = "serverware-oidc-session-activation-request-issuer"
PROCESS_MODE = "oidc-session-activation-request-issuer"
ROOT_KEY_ENV, ROOT_KEY_FD, LISTENER_FD = "SERVERWARE_ACTIVATION_RUNTIME_ROOT_KEY_FD", 4, 3
MAX_KEY_BYTES = 4096
_PID, _THREAD = os.getpid(), threading.get_ident()
_used, _owner = False, None


def _fail(message):
    raise RuntimeError(message)


def _listener_parent():
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in (None, *transport.LISTENER_PATH.split("/")[1:-1]):
            if component is not None:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            value = os.fstat(descriptor)
            if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
                _fail("activation issuer listener ancestor is not protected root custody")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode) or os.get_blocking(descriptor)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != transport.LISTENER_PATH):
            _fail("activation issuer inherited listener differs")
    finally:
        observed.close()
    parent = _listener_parent()
    try:
        named = os.stat(os.path.basename(transport.LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (0, 65532, 0o660)):
            _fail("activation issuer listener path protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _public_identity(path):
    parent = resources._parent(path)
    try:
        value = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 1
                or stat.S_IMODE(value.st_mode) != 0o444
                or not 2 <= value.st_size <= resources._PUBLIC[path]):
            _fail("activation issuer public-original identity differs")
        return resources.native._material_identity(value)
    finally:
        os.close(parent)


def _namespace():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    expected = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
        "SERVERWARE_PROCESS_MODE": PROCESS_MODE, "LISTEN_PID": str(_PID),
        "LISTEN_FDS": "1", "LISTEN_FDNAMES": LISTENER_NAME, ROOT_KEY_ENV: str(ROOT_KEY_FD)}
    if (os.getpid() != _PID or threading.get_ident() != _THREAD
            or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
            or namespace != tuple(sorted(expected.items())) or _namespace() != namespace):
        _fail("activation issuer original root process/environment changed")


class _StagingChannel:
    __slots__ = ("owner", "opened", "closed")

    def __init__(self):
        _fail("activation staging channel requires actual issuer ownership")

    def _owner(self):
        if (type(self) is not _StagingChannel or self.owner is not _owner
                or type(self.owner) is not _IssuerOwner or self.owner.channel is not self
                or not self.owner.spent or self.closed):
            _fail("activation staging channel lost its actual one-use issuer")
        return self.owner

    def check(self, *, work, deadline_ns, current):
        owner = self._owner()
        if (work is not owner.work or type(deadline_ns) is not int
                or not 0 < deadline_ns <= owner.lifetime.bound
                or type(current) is not MethodType or current.__self__ is not owner
                or current.__func__ is not _IssuerOwner.current):
            _fail("activation staging changed the actual issuer work/window")
        owner.current()

    def open(self):
        owner = self._owner()
        if self.opened or owner.staging is not None:
            _fail("activation staging connection cannot reopen")
        self.opened = True
        owner.current()
        owner.work.charge(input_bytes=4096)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        owner.staging = connection
        resources.ownership._claim(connection.fileno(), owner.owned)
        connection.setblocking(False)
        connection.set_inheritable(False)
        owner.current()
        return connection

    def close(self):
        owner = self._owner()
        self.closed = True
        connection, owner.staging = owner.staging, None
        if connection is not None and not resources._close_socket(connection, owner.owned):
            _fail("activation staging connection cleanup is uncertain")
        owner.current()


class _IssuerOwner:
    __slots__ = ("work", "lifetime", "namespace", "owned", "public", "root", "private",
        "policy", "key_identity", "listener", "listener_pins", "tls", "pins",
        "connection", "staging", "channel", "spent", "closed")

    def __init__(self):
        _fail("activation issuer requires actual original cold admission")

    def current(self):
        if (type(self) is not _IssuerOwner or self is not _owner or self.closed
                or any(a is not b for a, b in zip((self.work, self.lifetime, self.namespace,
                    self.owned, self.public, self.root, self.private, self.policy,
                    self.key_identity, self.listener, self.listener_pins, self.tls), self.pins, strict=True))):
            _fail("activation issuer original singleton custody changed")
        _process(self.namespace)
        self.work.charge(input_bytes=8192)
        if resources.fixed._sealed_identity(ROOT_KEY_FD, MAX_KEY_BYTES, private=True) != self.key_identity:
            _fail("activation issuer original sealed root changed")
        if _listener(LISTENER_FD) != self.listener_pins or self.listener.fileno() != LISTENER_FD:
            _fail("activation issuer actual listener changed")
        for path, identity in self.public:
            if _public_identity(path) != identity:
                _fail("activation issuer public source/configuration changed")
        resources.fixed._tls_unchanged(self.tls)
        for descriptor, identity in self.owned.items():
            if resources.native._material_identity(os.fstat(descriptor)) != identity:
                _fail("activation issuer owned descriptor changed")
        resources.inventory._require_inventory(tuple(self.owned))
        return self.lifetime.current()

    def continuity(self, epoch, monotonic):
        self.current()
        self.lifetime.continuity(epoch, monotonic)
        self.current()
        return self.lifetime.epoch, self.lifetime.monotonic

    def serve(self):
        if self.spent or self.connection is not None:
            _fail("activation issuer request cannot repeat")
        while self.connection is None:
            self.current()
            remaining = (self.lifetime.bound - self.lifetime.monotonic) / 1_000_000_000
            ready, _, exceptional = select.select((self.listener,), (), (self.listener,), min(1.0, remaining))
            self.current()
            if exceptional:
                _fail("activation issuer accept readiness failed")
            if ready:
                self.connection, _ = self.listener.accept()
                resources.ownership._claim(self.connection.fileno(), self.owned)
                self.connection.setblocking(False)
                self.connection.set_inheritable(False)
        self.spent = True
        self.current()
        (request,) = transport._recv_request(self.connection, deadline_ns=self.lifetime.bound,
            work=self.work, current=self.current)
        admitted = issuance.policy._verify_on_work(policy_bytes=self.policy, root_public_key=self.root,
            live_window=self.lifetime.window, transport_deadline_ns=self.lifetime.bound,
            work=self.work, _continuity=self.continuity)
        requested = issuance._verify_request(request, admitted, self.work, self.current)
        self.lifetime.narrow(requested["issuedAtEpochNs"], requested["expiresAtEpochNs"])
        self.current()
        originals = issuance._issue_planning_on_work(policy_bytes=self.policy, request_bytes=request,
            root_private_key=self.private, root_public_key=self.root, live_window=self.lifetime.window,
            transport_deadline_ns=self.lifetime.bound, work=self.work, _continuity=self.continuity)
        self.current()
        channel = object.__new__(_StagingChannel)
        channel.owner, channel.opened, channel.closed = self, False, False
        self.channel = channel
        staging._stage_on_work(channel, originals=originals, deadline_ns=self.lifetime.bound,
            work=self.work, current=self.current)
        self.current()
        # The original raw7, not the unauthenticated staging ACK, is returned.
        transport._send_response(self.connection, originals, deadline_ns=self.lifetime.bound,
            work=self.work, current=self.current)
        self.current()
        closing, self.connection = self.connection, None
        if not resources._close_socket(closing, self.owned):
            _fail("activation issuer response close is uncertain")
        self.current()
        return 0


def main():
    global _used, _owner
    if _used:
        _fail("activation issuer cannot repeat cold initialization")
    _used = True
    namespace = _namespace()
    _process(namespace)
    resources.inventory._require_inventory((LISTENER_FD, ROOT_KEY_FD))
    owned, listener = {}, None
    try:
        resources.ownership._claim(LISTENER_FD, owned)
        resources.ownership._claim(ROOT_KEY_FD, owned)
        os.set_blocking(LISTENER_FD, False)
        resources.ownership._claim(LISTENER_FD, owned)
        listener_pins = _listener(LISTENER_FD)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        lifetime = resources._Lifetime(work)
        public = tuple((path, _public_identity(path)) for path in resources._PUBLIC)
        root_raw, policy_raw = tuple(resources._read_public(path, owned=owned,
            work=work, current=lifetime.current) for path in resources._PUBLIC)
        if any(_public_identity(path) != identity for path, identity in public):
            _fail("activation issuer public originals changed before admission")
        work.charge(input_bytes=len(root_raw))
        root = issuance.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            _fail("activation issuer runtime root must be actual Ed25519")
        admitted = issuance.policy._verify_on_work(policy_bytes=policy_raw, root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            work=work, _continuity=lifetime.continuity)
        lifetime.narrow(admitted.payload["issuedAtEpochNs"], admitted.payload["expiresAtEpochNs"])
        # Only now read the actual parent-held sealed root private original.
        key_identity = resources.fixed._sealed_identity(ROOT_KEY_FD, MAX_KEY_BYTES, private=True)
        work.charge(input_bytes=2 * key_identity[0][6])
        key_raw, observed = resources.fixed._read_original(ROOT_KEY_FD, MAX_KEY_BYTES, private=True)
        if observed != key_identity:
            _fail("activation issuer sealed signer changed during read")
        lifetime.current()
        private = issuance.production._callback(work,
            lambda: serialization.load_pem_private_key(key_raw, password=None))
        if not isinstance(private, Ed25519PrivateKey):
            _fail("activation issuer runtime root signer must be Ed25519")
        issuance.policy.keys._pair_on_work(private, root, work)
        lifetime.current()
        tls_files = admitted.payload["plannerResources"]["tlsFiles"]
        work.charge(hashes=len(tls_files), input_bytes=sum(value["byteCount"] for value in tls_files.values()))
        tls = resources.fixed._tls_identity(tls_files)
        lifetime.current()
        listener = socket.socket(fileno=LISTENER_FD)
        selected = object.__new__(_IssuerOwner)
        selected.work, selected.lifetime, selected.namespace, selected.owned = work, lifetime, namespace, owned
        selected.public, selected.root, selected.private, selected.policy = public, root, private, policy_raw
        selected.key_identity, selected.listener, selected.listener_pins, selected.tls = key_identity, listener, listener_pins, tls
        selected.pins = (work, lifetime, namespace, owned, public, root, private, policy_raw,
            key_identity, listener, listener_pins, tls)
        selected.connection = selected.staging = selected.channel = None
        selected.spent = selected.closed = False
        _owner = selected
        selected.current()
        return selected.serve()
    finally:
        complete = True
        if _owner is not None:
            _owner.closed = True
            for connection in (_owner.staging, _owner.connection):
                if connection is not None:
                    try:
                        complete = resources._close_socket(connection, owned) and complete
                    except BaseException:
                        complete = False
            _owner.private = None
        if listener is not None:
            try:
                complete = resources._close_socket(listener, owned) and complete
            except BaseException:
                complete = False
        if not resources.ownership._close_all_owned(owned) or not complete:
            _fail("activation issuer cleanup uncertain; replaced descriptors were not closed")
