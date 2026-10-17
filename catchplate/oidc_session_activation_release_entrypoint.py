"""Fixed root delivery of one pre-provisioned release slot, without post-drop exec."""
from __future__ import annotations

import errno
import fcntl
import os
import socket
import stat

from catchplate import authority_fd_entrypoint as native
from catchplate import current_root_state_entrypoint as inventory
from catchplate import registration_execution_authorizer_entrypoint as sealed


ROOT_PATH = "/run/catchplate/oidc-session-activation-token-release-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/catchplate/oidc-session-activation-token-release-trust/bootstrap.json"
DELIVERY_KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-token-release-delivery-key"
OUTCOME_BASE_PATH = "/var/lib/catchplate/oidc-session-activation-release-outcomes"
LISTENER_PATH = "/run/catchplate/oidc-session-activation-token-release/release.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-token-release"
PROCESS_MODE = "oidc-session-activation-token-release"
SERVICE_UID = SERVICE_GID = 65502
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, DELIVERY_KEY_FD, OUTCOME_DIR_FD, LISTENER_FD = range(198, 203)
INHERITED_DESCRIPTORS = tuple(range(198, 203))
ROOT_ENV = "CATCHPLATE_OIDC_SESSION_ACTIVATION_RELEASE_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "CATCHPLATE_OIDC_SESSION_ACTIVATION_RELEASE_BOOTSTRAP_FD"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "CATCHPLATE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_release_launcher.py"
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_KEY_BYTES = 16 * 1024, 16 * 1024 * 1024, 32
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES), (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES))
_MATERIAL = {ROOT_PATH: (MAX_ROOT_BYTES, False), BOOTSTRAP_PATH: (MAX_BOOTSTRAP_BYTES, False),
    DELIVERY_KEY_PATH: (MAX_KEY_BYTES, True)}


def _parent(path):
    if path not in (*_MATERIAL, OUTCOME_BASE_PATH, LISTENER_PATH):
        raise RuntimeError("release delivery path is not source fixed")
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
                raise RuntimeError("release delivery ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, work, current, private=False):
    if type(private) is not bool or _MATERIAL.get(path) != (maximum, private):
        raise RuntimeError("release delivery original inventory changed")
    parent, source = _parent(path), None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 2 <= before.st_size <= maximum
                or private and (stat.S_IMODE(before.st_mode) != 0o400 or before.st_size != MAX_KEY_BYTES)):
            raise RuntimeError("release delivery original is not protected bounded material")
        identity = native._material_identity(before)
        if native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                follow_symlinks=False)) != identity:
            raise RuntimeError("release delivery original pathname differs")
        # Charge the actual admitted size before reading and sealing, not a
        # maximum after allocation or inside a stable-work native callback.
        work.charge(input_bytes=2 * before.st_size)
        current()
        raw = native._read_exact_source(source, before.st_size)
        current()
        if (native._material_identity(os.fstat(source)) != identity
                or native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("release delivery original changed during read")
        current()
        result = native._seal_bytes(source, name="catchplate-oidc-release",
            value=raw, mode=stat.S_IMODE(before.st_mode))
        current()
        os.set_inheritable(result, False)
        return result
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _read_on_work(descriptor, maximum, work):
    from catchplate import authority_revocation_capability_production as production

    identity = sealed._sealed_identity(descriptor, maximum)
    work.charge(input_bytes=identity[0][6])
    raw, observed = production._callback(work, lambda: sealed._read_original(descriptor, maximum))
    if observed != identity:
        raise RuntimeError("release public original changed before its charged read")
    return raw


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("release listener differs from its fixed activated socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("release socket pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _slot_on_work(material, work):
    from catchplate import oidc_session_activation_release_outcome as outcomes

    scope = material.storage_scope
    digest = outcomes._slot_digest_on_work(database_id=scope["databaseId"],
        generation_digest=scope["generationDigest"], delivery_id=scope["deliveryId"], work=work)
    outcomes.shape._digest(digest)
    name = "slot-" + digest[len("sha256:"):]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent, base, slot = _parent(OUTCOME_BASE_PATH), None, None
    try:
        base = os.open(os.path.basename(OUTCOME_BASE_PATH), flags, dir_fd=parent)
        metadata = os.fstat(base)
        base_identity = native._material_identity(metadata)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink < 1
                or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (0, 0, 0o700)
                or native._material_identity(os.stat(os.path.basename(OUTCOME_BASE_PATH),
                    dir_fd=parent, follow_symlinks=False)) != base_identity):
            raise RuntimeError("release outcome base is not the protected provisioned directory")
        slot = os.open(name, flags, dir_fd=base)
        value = os.fstat(slot)
        identity = native._material_identity(value)
        expected = scope["directory"]
        if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1 or stat.S_IMODE(value.st_mode) != 0o700
                or (value.st_dev, value.st_ino, value.st_uid, value.st_gid)
                    != tuple(expected[field] for field in ("device", "inode", "uid", "gid"))
                or (value.st_uid, value.st_gid) != (SERVICE_UID, SERVICE_GID)
                or native._material_identity(os.stat(name, dir_fd=base, follow_symlinks=False)) != identity
                or native._material_identity(os.fstat(base)) != base_identity
                or native._material_identity(os.stat(os.path.basename(OUTCOME_BASE_PATH),
                    dir_fd=parent, follow_symlinks=False)) != base_identity):
            raise RuntimeError("release outcome slot differs from independently signed directory pins")
        return slot
    except BaseException:
        if slot is not None:
            os.close(slot)
        raise
    finally:
        if base is not None:
            os.close(base)
        os.close(parent)


def _claim(descriptor, owned):
    # None records an acquired but indeterminate descriptor: cleanup must not
    # close an identity it could not establish.
    owned[descriptor] = None
    owned[descriptor] = native._material_identity(os.fstat(descriptor))


def _close_owned_descriptor(descriptor, owned):
    expected = owned.pop(descriptor)
    if expected is None:
        return False
    try:
        if native._material_identity(os.fstat(descriptor)) != expected:
            return False
    except OSError as exc:
        # Intake may already have closed the exact descriptor. Do not retry it,
        # and never close a new descriptor subsequently occupying that number.
        return exc.errno == errno.EBADF
    try:
        os.close(descriptor)
    except OSError:
        # A failed close has uncertain ownership. It was removed before the
        # attempt and is never retried, including an interrupted close.
        return False
    return True


def _retain(source, target, reservations, owned):
    if (owned.get(source) is None
            or native._material_identity(os.fstat(source)) != owned[source]
            or owned.get(target) != reservations[target]
            or native._material_identity(os.fstat(target)) != reservations[target]):
        raise RuntimeError("release descriptor identity changed before retention")
    if not _close_owned_descriptor(target, owned):
        raise RuntimeError("release descriptor reservation cleanup is uncertain")
    replacement = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, target)
    _claim(replacement, owned)
    if replacement != target or owned[replacement] != owned[source]:
        raise RuntimeError("release reserved descriptor replacement differs")
    del reservations[target]


def _close_all_owned(owned):
    complete = True
    for descriptor in sorted(tuple(owned), reverse=True):
        if not _close_owned_descriptor(descriptor, owned):
            complete = False
    return complete


def main():
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("release delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("release delivery requires one exact activated listener")
    inventory._require_inventory({3})
    owned, reservations = {3: None}, {}
    resource_owner = None
    transferred = False
    try:
        _claim(3, owned)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from catchplate import oidc_session_activation_release_bootstrap as bootstrap
        from catchplate import oidc_session_activation_release_resources as resources
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = bootstrap._construction_on_work(work)
        _window, construction_current = bootstrap.delivery._window(window, bound, work)
        construction_current()
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            _claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("release descriptor slot is occupied")
            reservations[target] = owned[descriptor]
        for path, target, maximum in _TRUST_FILES:
            construction_current()
            source = _open_material(path, maximum, work=work, current=construction_current)
            _claim(source, owned)
            construction_current()
            _retain(source, target, reservations, owned)
            if not _close_owned_descriptor(source, owned):
                raise RuntimeError("release public original cleanup is uncertain")
        root_raw = _read_on_work(ROOT_FD, MAX_ROOT_BYTES, work)
        construction_current()
        bootstrap_raw = _read_on_work(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES, work)
        construction_current()
        work.charge(input_bytes=len(root_raw))
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("release trust root must be Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work)
        observed_epoch = construction_current()

        def current():
            nonlocal observed_epoch
            before = construction_current()
            if before < observed_epoch:
                raise RuntimeError("release construction clock reversed across root admission")
            after = material.live()
            if after < before:
                raise RuntimeError("release admitted clock precedes root delivery observation")
            observed_epoch = after
            return after

        current()
        narrowed = bootstrap.clock._validate(material.live_window)
        if (narrowed[:3] != window[:3] or material.deadline_ns > bound
                or any(actual > prior for actual, prior in zip(narrowed[3:], window[3:]))):
            raise RuntimeError("release bootstrap renewed its original construction allowance")
        window, bound = narrowed, material.deadline_ns
        launch = material.launch
        expected = {"processMode": PROCESS_MODE, "serviceUid": SERVICE_UID, "serviceGid": SERVICE_GID,
            "peerUid": PEER_UID, "peerGid": PEER_GID, "rootPublicKeyFd": ROOT_FD,
            "bootstrapFd": BOOTSTRAP_FD, "deliveryKeyFd": DELIVERY_KEY_FD,
            "outcomeDirectoryFd": OUTCOME_DIR_FD, "listenerFd": LISTENER_FD, "listenerPath": LISTENER_PATH}
        for field, value in expected.items():
            bootstrap.plan._same(launch[field], value, work, "release delivery launch " + field)
        bootstrap.plan._same(tuple(launch["inheritedFileDescriptors"]), INHERITED_DESCRIPTORS,
            work, "release delivery descriptor inventory")
        listener_pins = tuple(launch[field] for field in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        if _listener(3) != listener_pins:
            raise RuntimeError("release activated listener differs from signed launch")
        current()
        source = _slot_on_work(material, work)
        _claim(source, owned)
        current()
        _retain(source, OUTCOME_DIR_FD, reservations, owned)
        if not _close_owned_descriptor(source, owned):
            raise RuntimeError("release slot duplicate cleanup is uncertain")
        # The public root, complete nested authorization, slot and listener have
        # now actually joined. This is the first private read or sealing call.
        current()
        source = _open_material(DELIVERY_KEY_PATH, MAX_KEY_BYTES, work=work, current=current, private=True)
        _claim(source, owned)
        current()
        _retain(source, DELIVERY_KEY_FD, reservations, owned)
        if not _close_owned_descriptor(source, owned):
            raise RuntimeError("release key duplicate cleanup is uncertain")
        _retain(3, LISTENER_FD, reservations, owned)
        if not _close_owned_descriptor(3, owned):
            raise RuntimeError("release listener duplicate cleanup is uncertain")
        if reservations or _listener(LISTENER_FD) != listener_pins:
            raise RuntimeError("release fixed resource delivery changed")
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, False)
        inventory._require_inventory(INHERITED_DESCRIPTORS)
        if ENVIRONMENT != resources.ENVIRONMENT:
            raise RuntimeError("release delivery and resource environments differ")
        os.environ.clear()
        os.environ.update(ENVIRONMENT)
        current()
        resource_owner = resources._intake_from_delivery_on_work(work=work, live_window=window,
            transport_deadline_ns=bound, delivery_current=current)
        # The actual owner now holds every descriptor and the original live
        # closures after its sole permanent drop. Never exec or intake again.
        owned.clear()
        from catchplate import oidc_session_activation_release_runner as runner

        resources._Resources._check_on_work(resource_owner, work=work)
        transferred = True
        return runner._run_with_resources(resource_owner)
    finally:
        try:
            if resource_owner is not None and not transferred:
                resources._Resources.close(resource_owner)
        finally:
            if not _close_all_owned(owned):
                raise RuntimeError("release delivery cleanup identity is uncertain; changed slots were not closed")
