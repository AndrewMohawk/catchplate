"""Five original resources, public admission first, same-PID issuer drop.

This is the explicitly software-key profile. The root launcher opens only
source-fixed provisioned paths; it creates no key, journal, socket or trust.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import fcntl
import os
import socket
import stat
import time

from serverware import authority_fd_entrypoint as delivery
from serverware import current_root_state_entrypoint as inventory
from serverware import registration_execution_authorizer_entrypoint as sealed


PROCESS_MODE = "workload-identity-issuer"
SERVICE_UID = SERVICE_GID = 65492
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD = range(198, 203)
INHERITED_DESCRIPTORS = tuple(range(198, 203))
TRUST_PATH = "/run/serverware/workload-identity-issuer-trust"
ROOT_PATH, BOOTSTRAP_PATH = TRUST_PATH + "/root-public-key.pem", TRUST_PATH + "/bootstrap.json"
KEY_PATH = "/run/secrets/serverware-workload-identity-issuer-ca-key"
LISTENER_PATH = "/run/serverware/workload-identity-issuer/issuer.sock"
JOURNAL_PATH = "/var/lib/serverware/workload-identity-issuer"
LISTENER_NAME = "serverware-workload-identity-issuer"
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_KEY_BYTES = 16 * 1024, 128 * 1024, 64 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "SERVERWARE_PROCESS_MODE": PROCESS_MODE}
_MATERIAL = {ROOT_PATH: (MAX_ROOT_BYTES, False), BOOTSTRAP_PATH: (MAX_BOOTSTRAP_BYTES, False),
    KEY_PATH: (MAX_KEY_BYTES, True)}
_CONSTRUCTION = object()
_active_launch = None


class _ServiceLifetime:
    """One signed local lifetime anchored before the first cold original read.

    Cold acquisition must still finish within its original processing window.
    This separate v3 clock never extends that window or a request deadline.
    """

    def __init__(self, construction, *, material, opening, work, cold_current):
        from serverware import workload_identity_issuer_bootstrap as bootstrap

        if (construction is not _CONSTRUCTION
                or type(material) is not bootstrap._IssuerMaterial
                or material.profile != bootstrap.NATIVE_SERVICE_PROFILE):
            raise RuntimeError("workload service lifetime requires its original v3 admission")
        cold_current()
        opening = bootstrap.clock._validate(opening)
        certificate = material.issuer_certificate.certificate
        self.interval = (max(material.attestation_interval[0],
            int(certificate.not_valid_before_utc.timestamp()) * 1_000_000_000),
            min(material.attestation_interval[1],
                int(certificate.not_valid_after_utc.timestamp()) * 1_000_000_000,
                opening[0] + bootstrap._MAX_SERVICE_NS))
        if not self.interval[0] <= opening[0] < self.interval[1]:
            raise RuntimeError("workload service lacks an original currently live interval")
        self.deadline_ns = opening[1] + self.interval[1] - opening[0]
        self._opening, self._work, self._cold = opening, work, cold_current
        self._epoch, self._monotonic = opening[0], opening[2]
        self._active = False
        self._pin = (self.interval, self.deadline_ns, opening, work, cold_current)
        self.current()

    def current(self):
        from serverware import workload_identity_issuer_bootstrap as bootstrap

        if (type(self) is not _ServiceLifetime or type(self._active) is not bool
                or type(self._pin) is not tuple or len(self._pin) != 5
                or any(actual is not original for actual, original in zip(
                    (self.interval, self.deadline_ns, self._opening, self._work, self._cold), self._pin))):
            raise RuntimeError("workload service original lifetime changed")
        if not self._active:
            self._epoch = self._cold()
            return self._epoch
        before, epoch, after = bootstrap.clock._sample_on_work(self._work)
        origin_epoch, origin_before, origin_after = self._opening[:3]
        if (before < self._monotonic or epoch < self._epoch
                or after >= self.deadline_ns or not self.interval[0] <= epoch < self.interval[1]
                or not origin_epoch + before - origin_after <= epoch <= origin_epoch + after - origin_before):
            raise RuntimeError("workload service original local lifetime expired or reversed")
        self._epoch, self._monotonic = epoch, after
        return epoch

    def activate(self):
        if self._active:
            raise RuntimeError("workload service lifetime cannot be reopened")
        self.current()
        self._active = True
        self.current()


def _fd_identity(descriptor):
    value = os.fstat(descriptor)
    # Directory contents legitimately change during durable publication.
    # Never pin mutable size/timestamps as the descriptor's close authority.
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_rdev


def _claim(descriptor, owned):
    owned[descriptor] = None
    owned[descriptor] = _fd_identity(descriptor)


def _close(descriptor, owned):
    expected = owned.pop(descriptor)
    if expected is None:
        return False
    try:
        if _fd_identity(descriptor) != expected:
            return False
    except OSError as exc:
        return exc.errno == errno.EBADF
    try:
        os.close(descriptor)
    except OSError:
        return False
    return True


def _retain(source, target, reservations, owned):
    if (owned.get(source) is None or _fd_identity(source) != owned[source]
            or owned.get(target) != reservations[target] or _fd_identity(target) != reservations[target]):
        raise RuntimeError("workload issuer original descriptor changed before retention")
    if not _close(target, owned):
        raise RuntimeError("workload issuer reserved descriptor closure is uncertain")
    replacement = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, target)
    _claim(replacement, owned)
    if replacement != target or owned[replacement] != owned[source]:
        raise RuntimeError("workload issuer original descriptor handoff differs")
    del reservations[target]


def _parent(path):
    if path not in (*_MATERIAL, LISTENER_PATH, JOURNAL_PATH):
        raise RuntimeError("workload issuer path is not source fixed")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in (None, *path.split("/")[1:-1]):
            if component is not None:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            value = os.fstat(descriptor)
            if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
                    or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("workload issuer ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, *, work, current, expected_size=None):
    maximum, private = _MATERIAL[path]
    if (private and (type(expected_size) is not int or not 2 <= expected_size <= maximum)
            or not private and expected_size is not None):
        raise RuntimeError("workload issuer private size lacks its signed original pin")
    parent, source = _parent(path), None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != (0o400 if private else 0o444)
                or not 2 <= before.st_size <= maximum
                or private and before.st_size != expected_size):
            raise RuntimeError("workload issuer original protection or size differs")
        identity = delivery._material_identity(before)
        if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                follow_symlinks=False)) != identity:
            raise RuntimeError("workload issuer original pathname changed")
        work.charge(input_bytes=2 * before.st_size)
        current()
        raw = delivery._read_exact_source(source, before.st_size)
        current()
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("workload issuer original changed during charged read")
        result = delivery._seal_bytes(source, name="serverware-workload-identity-issuer",
            value=raw, mode=stat.S_IMODE(before.st_mode))
        os.set_inheritable(result, False)
        source = None
        return result
    finally:
        if source is not None:
            os.close(source)
        os.close(parent)


def _read_on_work(descriptor, maximum, work, current, *, private=False):
    current()
    identity = sealed._sealed_identity(descriptor, maximum, private=private)
    work.charge(input_bytes=identity[0][6])
    raw, observed = sealed._read_original(descriptor, maximum, private=private)
    current()
    if observed != identity:
        raise RuntimeError("workload issuer sealed original changed during charged read")
    return raw


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode) or os.get_blocking(descriptor)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH):
            raise RuntimeError("workload issuer requires its exact nonblocking activated listener")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("workload issuer listener pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _journal_identity(descriptor, material):
    value = os.fstat(descriptor)
    wanted = material.journal_device, material.journal_inode, SERVICE_UID, SERVICE_GID, 0o700
    if (not stat.S_ISDIR(value.st_mode)
            or (value.st_dev, value.st_ino, value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != wanted):
        raise RuntimeError("workload issuer journal differs from its signed resource identity")
    parent = _parent(JOURNAL_PATH)
    try:
        named = os.stat(os.path.basename(JOURNAL_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode)
                or (named.st_dev, named.st_ino, named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != wanted):
            raise RuntimeError("workload issuer journal pathname changed")
    finally:
        os.close(parent)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _LaunchContext:
    construction: object
    material: object
    root_public_key: object
    work: object
    window: tuple
    deadline_ns: int
    current: object
    original_reservation_bytes: int
    identities: tuple
    pid: int
    service_lifetime: object = None


def _require_launch(value):
    if (type(value) is not _LaunchContext or value.construction is not _CONSTRUCTION
            or _active_launch is not value or os.getpid() != value.pid
            or tuple(_fd_identity(fd) for fd in INHERITED_DESCRIPTORS) != value.identities):
        raise RuntimeError("workload issuer launch is not the original same-PID handoff")
    value.current()
    return value


def main(*, service_profile=False):
    global _active_launch
    if (type(service_profile) is not bool
            or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
            or os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME or _active_launch is not None):
        raise RuntimeError("workload issuer requires its one original root socket activation")
    inventory._require_inventory({3})
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from serverware import workload_identity_issuer_bootstrap as bootstrap
    from serverware import workload_identity_issuer_startup as startup
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    owned, reservations, status = {3: None}, {}, 1
    try:
        _claim(3, owned)
        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = bootstrap._construction_on_work(work)
        window = bootstrap.clock._validate(window)
        last_epoch, last_monotonic = window[0], window[2]

        def construction_current():
            nonlocal last_epoch, last_monotonic
            epoch = bootstrap.clock._check_on_work(window, work=work)
            monotonic = time.monotonic_ns()
            if epoch < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                raise RuntimeError("workload issuer original construction clock expired or reversed")
            last_epoch, last_monotonic = epoch, monotonic
            return epoch

        construction_current()
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            _claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("workload issuer fixed descriptor slot is occupied")
            reservations[target] = owned[descriptor]
        for path, target in ((ROOT_PATH, ROOT_FD), (BOOTSTRAP_PATH, BOOTSTRAP_FD)):
            descriptor = _open_material(path, work=work, current=construction_current)
            _claim(descriptor, owned)
            _retain(descriptor, target, reservations, owned)
            if not _close(descriptor, owned):
                raise RuntimeError("workload issuer public source cleanup is uncertain")
        root_raw = _read_on_work(ROOT_FD, MAX_ROOT_BYTES, work, construction_current)
        original = _read_on_work(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES, work, construction_current)
        work.charge(input_bytes=len(root_raw))
        root = serialization.load_pem_public_key(root_raw)
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("workload issuer root is not Ed25519")
        material = bootstrap._verify_launch_on_work(bootstrap_bytes=original, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work, _current=construction_current)
        if (material.profile == bootstrap.NATIVE_SERVICE_PROFILE) is not service_profile:
            raise RuntimeError("workload issuer signed profile differs from its fixed launcher mode")
        current_epoch = construction_current()

        def current():
            nonlocal current_epoch
            for guard in (construction_current, material.live, construction_current):
                observed = guard()
                if type(observed) is not int or observed < current_epoch:
                    raise RuntimeError("workload issuer original launch continuity reversed")
                current_epoch = observed
            return current_epoch

        current()
        listener_pin = (material.listener_device, material.listener_inode,
            material.listener_path_device, material.listener_path_inode)
        if (bootstrap.INHERITED_DESCRIPTORS != INHERITED_DESCRIPTORS
                or bootstrap.SERVICE_UID != SERVICE_UID or bootstrap.SERVICE_GID != SERVICE_GID
                or bootstrap.LISTENER_PATH != LISTENER_PATH or _listener(3) != listener_pin):
            raise RuntimeError("workload issuer fixed launch differs from signed public originals")
        reserved = 8 * (len(root_raw) + len(original) + material.ca_private_key_byte_count
            + len(material.issuer_certificate_bytes) + bootstrap._enrollment_original_byte_count(material)
            + len(material.authorization_key_bytes)) + 128 * 1024
        if reserved >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("workload issuer cold captures exhaust the original aggregate bound")
        # Only genuine public admission authorizes these private resource reads.
        descriptor = _open_material(KEY_PATH, work=work, current=current,
            expected_size=material.ca_private_key_byte_count)
        _claim(descriptor, owned)
        _retain(descriptor, KEY_FD, reservations, owned)
        if not _close(descriptor, owned):
            raise RuntimeError("workload issuer private source cleanup is uncertain")
        parent = _parent(JOURNAL_PATH)
        try:
            descriptor = os.open(os.path.basename(JOURNAL_PATH), os.O_RDONLY | os.O_DIRECTORY
                | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            _claim(descriptor, owned)
        finally:
            os.close(parent)
        current()
        _journal_identity(descriptor, material)
        fcntl.fcntl(descriptor, fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _retain(descriptor, JOURNAL_FD, reservations, owned)
        if not _close(descriptor, owned):
            raise RuntimeError("workload issuer journal handoff cleanup is uncertain")
        _retain(3, LISTENER_FD, reservations, owned)
        if not _close(3, owned) or reservations:
            raise RuntimeError("workload issuer listener handoff cleanup is uncertain")
        identities = tuple(_fd_identity(fd) for fd in INHERITED_DESCRIPTORS)
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, False)
        inventory._require_inventory(INHERITED_DESCRIPTORS)
        lifetime = (_ServiceLifetime(_CONSTRUCTION, material=material, opening=window,
            work=work, cold_current=current) if service_profile else None)
        _active_launch = _LaunchContext(_CONSTRUCTION, material, root, work, material.window,
            material.deadline_ns, lifetime.current if lifetime is not None else current,
            reserved, identities, os.getpid(), lifetime)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        delivery._require_unprivileged_process()
        if (os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups()
                or _listener(LISTENER_FD) != listener_pin):
            raise RuntimeError("workload issuer permanent identity drop differs")
        inventory._require_inventory(INHERITED_DESCRIPTORS)
        os.environ.clear()
        os.environ.update(ENVIRONMENT)
        startup._run_on_launch(_active_launch)
        status = 0
    finally:
        _active_launch = None
        for descriptor in sorted(tuple(owned), reverse=True):
            if not _close(descriptor, owned):
                status = 1
    return status
