"""Five inherited release resources, admitted before key read and permanent drop.

This source-only intake preserves a listener but never accepts a connection.
Its actual owned handle carries originals/resources, not a successful admission
carrier that a caller may substitute for root-original startup verification.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import os
import socket
import stat
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_fd_entrypoint as native
from serverware import current_root_state_entrypoint as inventory
from serverware import registration_execution_authorizer_entrypoint as sealed
from serverware import authority_oidc_session_activation_release_custody as custody
from serverware import oidc_session_activation_release_bootstrap as bootstrap


ROOT_FD, BOOTSTRAP_FD, DELIVERY_KEY_FD, OUTCOME_DIR_FD, LISTENER_FD = range(198, 203)
INHERITED_DESCRIPTORS = tuple(range(198, 203))
SERVICE_UID = SERVICE_GID = 65502
PEER_UID = PEER_GID = 65532
PROCESS_MODE = "oidc-session-activation-token-release"
LISTENER_PATH = "/run/serverware/oidc-session-activation-token-release/release.sock"
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_KEY_BYTES = 16 * 1024, 16 * 1024 * 1024, 32
ROOT_ENV = "SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_BOOTSTRAP_FD"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "SERVERWARE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
_ENVIRONMENT_SEAL = tuple(sorted(ENVIRONMENT.items()))
_LOCK_TYPE = type(threading.Lock())
_METADATA_BYTES = 4096


class ReleaseResourceError(RuntimeError):
    pass


def _fail(message):
    raise ReleaseResourceError(message)


def _environment():
    if (len(os.environ) != len(_ENVIRONMENT_SEAL)
            or tuple(sorted(os.environ.items())) != _ENVIRONMENT_SEAL
            or tuple(sorted(ENVIRONMENT.items())) != _ENVIRONMENT_SEAL):
        _fail("release resource environment differs from its closed source namespace")


def _process(*, root=False):
    _environment()
    uid, gid = (0, 0) if root else (SERVICE_UID, SERVICE_GID)
    if (os.getresuid() != (uid,) * 3 or os.getresgid() != (gid,) * 3
            or not root and os.getgroups()):
        _fail("release resource process identity differs from its fixed phase")


def _listener_parent():
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in (None, *LISTENER_PATH.split("/")[1:-1]):
            if component is not None:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            value = os.fstat(descriptor)
            if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
                    or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                _fail("release listener ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _stable_metadata(value):
    # Directory size/timestamps may legitimately change during the actual
    # store's publication. Its own journal owns record/inventory continuity.
    return (value.st_dev, value.st_ino, value.st_mode,
        value.st_uid, value.st_gid, value.st_nlink)


def _directory_identity():
    value = os.fstat(OUTCOME_DIR_FD)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode))
                != (SERVICE_UID, SERVICE_GID, 0o700)):
        _fail("release outcome descriptor is not a private delivery-slot directory")
    return _stable_metadata(value)


def _listener_identity():
    value = os.fstat(LISTENER_FD)
    observed = socket.fromfd(LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(LISTENER_FD)):
            _fail("release listener differs from its fixed nonblocking Unix stream")
    finally:
        observed.close()
    parent = _listener_parent()
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode))
                    != (SERVICE_UID, PEER_GID, 0o660)):
            _fail("release listener pathname protection differs")
        return _stable_metadata(value), _stable_metadata(named)
    finally:
        os.close(parent)


def _descriptor_identity(descriptor):
    if descriptor in (ROOT_FD, BOOTSTRAP_FD, DELIVERY_KEY_FD):
        maximum = {ROOT_FD: MAX_ROOT_BYTES, BOOTSTRAP_FD: MAX_BOOTSTRAP_BYTES,
            DELIVERY_KEY_FD: MAX_KEY_BYTES}[descriptor]
        value = sealed._sealed_identity(descriptor, maximum, private=descriptor == DELIVERY_KEY_FD)
        if descriptor == DELIVERY_KEY_FD and value[0][6] != MAX_KEY_BYTES:
            _fail("release delivery key descriptor is not exactly raw32")
    elif descriptor == OUTCOME_DIR_FD:
        value = _directory_identity()
    elif descriptor == LISTENER_FD:
        value = _listener_identity()
    else:
        _fail("release resource descriptor is outside its fixed inventory")
    return value, fcntl.fcntl(descriptor, fcntl.F_GETFD), fcntl.fcntl(descriptor, fcntl.F_GETFL)


def _metadata(work, callback):
    work.charge(input_bytes=_METADATA_BYTES)
    return bootstrap.production._callback(work, callback)


def _require_inventory_on_work(work):
    work.charge(input_bytes=inventory.MAX_FD_ENTRIES * (32 + 9 * 8))
    bootstrap.production._callback(work, lambda: inventory._require_inventory(INHERITED_DESCRIPTORS))


def _read_on_work(descriptor, maximum, work, *, expected, private=False):
    before = _metadata(work, lambda: _descriptor_identity(descriptor))
    if before != expected:
        _fail("release original differs from its initially owned descriptor")
    identity = before[0]
    work.charge(input_bytes=identity[0][6])
    raw, observed = bootstrap.production._callback(work,
        lambda: sealed._read_original(descriptor, maximum, private=private))
    if observed != identity or _metadata(work, lambda: _descriptor_identity(descriptor)) != expected:
        _fail("release sealed original changed across its metered read")
    return raw


def _close_owned(identities):
    # No retries and no replacement-FD close when an inherited slot changed.
    complete = True
    for descriptor, expected in reversed(identities):
        try:
            if _descriptor_identity(descriptor) == expected:
                os.close(descriptor)
            else:
                complete = False
        except BaseException:
            complete = False
    return complete


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    root_public_key: object
    bootstrap_bytes: bytes
    delivery_key: bytes
    directory_fd: int
    listener_fd: int
    live_window: tuple
    deadline_ns: int
    work: object


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class _Resources:
    _configuration: _Configuration
    _seal: _Configuration
    _descriptors: tuple
    _descriptor_seal: tuple
    _admitted_live: object
    _live_seal: object
    _processing: object
    _processing_seal: object
    _pid: int
    _lock: object
    _closed: bool
    _cleanup_failed: bool
    _last_epoch: int
    _last_monotonic: int

    def _identity(self):
        configured = self._configuration
        if (type(self) is not _Resources or self._closed or self._pid != os.getpid()
                or type(configured) is not _Configuration or configured is not self._seal
                or self._descriptors is not self._descriptor_seal
                or self._admitted_live is not self._live_seal
                or self._processing is not self._processing_seal
                or type(self._lock) is not _LOCK_TYPE):
            _fail("release resources are closed, changed or belong to another process")
        _process()
        return configured

    def _snapshot_configuration(self):
        return self._identity()

    @property
    def root_public_key(self):
        return self._snapshot_configuration().root_public_key

    @property
    def bootstrap_bytes(self):
        return self._snapshot_configuration().bootstrap_bytes

    @property
    def delivery_key(self):
        return self._snapshot_configuration().delivery_key

    @property
    def directory_fd(self):
        return self._snapshot_configuration().directory_fd

    @property
    def listener_fd(self):
        return self._snapshot_configuration().listener_fd

    @property
    def live_window(self):
        return self._snapshot_configuration().live_window

    @property
    def deadline_ns(self):
        return self._snapshot_configuration().deadline_ns

    @property
    def work(self):
        return self._snapshot_configuration().work

    def _check_on_work(self, *, work):
        configured = self._identity()
        if work is not configured.work:
            _fail("release resources cannot replace their original cumulative work")
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("release resources are already in use")
        try:
            def current():
                self._identity()
                first = self._processing()
                admitted = self._admitted_live()
                finished = self._processing()
                monotonic = bootstrap.production._callback(work, time.monotonic_ns)
                if (first < self._last_epoch or admitted < first or finished < admitted
                        or monotonic < self._last_monotonic or monotonic >= configured.deadline_ns):
                    _fail("release resource clocks reversed or original authority expired")
                object.__setattr__(self, "_last_epoch", finished)
                object.__setattr__(self, "_last_monotonic", monotonic)
                return finished

            current()
            for descriptor, expected in self._descriptors:
                observed = _metadata(work, lambda descriptor=descriptor: _descriptor_identity(descriptor))
                if observed != expected or not observed[1] & fcntl.FD_CLOEXEC:
                    _fail("release inherited resource identity changed")
                current()
            # The startup owns any genuine journal duplicate and enforces its
            # expanded inventory. This handle checks only its fixed five inputs.
            return current()
        except BaseException:
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_cleanup_failed", not _close_owned(self._descriptors))
            raise
        finally:
            lock.release()

    def close(self):
        if type(self) is not _Resources or self._pid != os.getpid():
            _fail("release resources close requires their actual process owner")
        if self._closed:
            if self._cleanup_failed:
                _fail("release resource cleanup previously remained uncertain; no retry is permitted")
            return
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("release resources cannot close during another operation")
        try:
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_cleanup_failed", not _close_owned(self._descriptors))
            if self._cleanup_failed:
                _fail("release resource descriptor cleanup was not established")
        finally:
            lock.release()


def _intake_on_work(*, work, live_window, transport_deadline_ns):
    """Take fixed inherited resources; admit first, then permanently drop."""
    return _intake_originals_on_work(work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, delivery_current=None)


def _intake_from_delivery_on_work(*, work, live_window, transport_deadline_ns,
        delivery_current):
    """Retain the actual root delivery guard; it can only further restrict use."""
    if not callable(delivery_current):
        _fail("release delivery continuation requires its original current guard")
    return _intake_originals_on_work(work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, delivery_current=delivery_current)


def _intake_originals_on_work(*, work, live_window, transport_deadline_ns,
        delivery_current):
    bootstrap.capture._SharedLedger(work)
    window = bootstrap.clock._validate(live_window)
    bootstrap.shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    _process(root=True)
    _window, intake_current = bootstrap.delivery._window(window, bound, work)
    last_epoch = window[0]

    def original_current():
        nonlocal last_epoch
        first = last_epoch if delivery_current is None else delivery_current()
        bootstrap.shape._integer(first, minimum=1)
        if first < last_epoch:
            _fail("release clock reversed across root delivery and resource intake")
        observed = intake_current()
        if observed < first:
            _fail("release resource clock precedes its original root delivery observation")
        last_epoch = observed
        return observed

    owned, result = {}, None
    try:
        original_current()
        _require_inventory_on_work(work)
        for descriptor in INHERITED_DESCRIPTORS:
            def claim(descriptor=descriptor):
                owned[descriptor] = _descriptor_identity(descriptor)

            _metadata(work, claim)
            original_current()
        root_raw = _read_on_work(ROOT_FD, MAX_ROOT_BYTES, work, expected=owned[ROOT_FD])
        original_current()
        bootstrap_raw = _read_on_work(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES, work,
            expected=owned[BOOTSTRAP_FD])
        original_current()
        work.charge(input_bytes=len(root_raw))
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            _fail("release inherited root must be Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work)
        material.live()
        narrowed = bootstrap.clock._validate(material.live_window)
        if (narrowed[:3] != window[:3] or material.deadline_ns > bound
                or any(actual > prior for actual, prior in zip(narrowed[3:], window[3:]))):
            _fail("release bootstrap renewed its inherited processing allowance")
        window, bound = narrowed, material.deadline_ns
        launch = material.launch
        expected_launch = {"processMode": PROCESS_MODE, "serviceUid": SERVICE_UID,
            "serviceGid": SERVICE_GID, "rootPublicKeyFd": ROOT_FD, "bootstrapFd": BOOTSTRAP_FD,
            "deliveryKeyFd": DELIVERY_KEY_FD, "outcomeDirectoryFd": OUTCOME_DIR_FD,
            "listenerFd": LISTENER_FD, "listenerPath": LISTENER_PATH,
            "peerUid": PEER_UID, "peerGid": PEER_GID}
        for field, expected in expected_launch.items():
            bootstrap.plan._same(launch[field], expected, work, "release launch resource " + field)
        bootstrap.plan._same(tuple(launch["inheritedFileDescriptors"]), INHERITED_DESCRIPTORS,
            work, "release exact inherited resource inventory")
        directory = material.storage_scope["directory"]
        observed = _metadata(work, _directory_identity)
        bootstrap.plan._same((observed[0], observed[1], observed[3], observed[4]),
            tuple(directory[name] for name in ("device", "inode", "uid", "gid")), work,
            "release actual per-delivery slot directory")
        socket_identity, path_identity = _metadata(work, _listener_identity)
        bootstrap.plan._same((socket_identity[0], socket_identity[1], path_identity[0], path_identity[1]),
            tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode")), work, "release root-pinned listener identities")
        material.live()
        _process(root=True)
        # No private key bytes are read until actual fresh root admission and
        # directory/listener joins have succeeded under the original allowance.
        key = _read_on_work(DELIVERY_KEY_FD, MAX_KEY_BYTES, work,
            expected=owned[DELIVERY_KEY_FD], private=True)
        if len(key) != MAX_KEY_BYTES:
            _fail("release private delivery key must be raw32")
        custody._key_binding(material.custody_material, key, work)
        material.live()
        for descriptor in INHERITED_DESCRIPTORS:
            def protect(descriptor=descriptor):
                if _descriptor_identity(descriptor) != owned[descriptor]:
                    _fail("release inherited descriptor changed before permanent drop")
                os.set_inheritable(descriptor, False)
                owned[descriptor] = _descriptor_identity(descriptor)

            _metadata(work, protect)
            material.live()
        _require_inventory_on_work(work)
        _process(root=True)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        _process()
        work.charge(input_bytes=64 * 1024)
        bootstrap.production._callback(work, native._require_unprivileged_process)
        material.live()
        _require_inventory_on_work(work)
        configured = _Configuration(root, bootstrap_raw, key, OUTCOME_DIR_FD, LISTENER_FD,
            window, bound, work)
        descriptors = tuple(owned.items())
        _window, narrowed_processing = bootstrap.delivery._window(window, bound, work)

        def processing():
            # Retain intake's actual pre-root-I/O observations, not merely a
            # later guard with the same numeric opening bracket.
            first = original_current()
            finished = narrowed_processing()
            if finished < first:
                _fail("release resource clock reversed across its narrowed processing guard")
            return finished

        result = object.__new__(_Resources)
        for name, value in (("_configuration", configured), ("_seal", configured),
                ("_descriptors", descriptors), ("_descriptor_seal", descriptors),
                ("_admitted_live", material.live), ("_live_seal", material.live),
                ("_processing", processing), ("_processing_seal", processing),
                ("_pid", os.getpid()), ("_lock", threading.Lock()), ("_closed", False),
                ("_cleanup_failed", False),
                ("_last_epoch", window[0]), ("_last_monotonic", window[2])):
            object.__setattr__(result, name, value)
        _Resources._check_on_work(result, work=work)
        return result
    except BaseException:
        if result is None or not getattr(result, "_closed", False):
            if result is not None:
                object.__setattr__(result, "_closed", True)
            complete = _close_owned(tuple(owned.items()))
            if result is not None:
                object.__setattr__(result, "_cleanup_failed", not complete)
        raise
