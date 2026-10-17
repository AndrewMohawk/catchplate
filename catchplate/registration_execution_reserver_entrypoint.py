"""Fixed root delivery for the dedicated registration execution reserver.

Only independently provisioned originals, an activated listener and the exact
signed journal directory are opened. Root admission precedes computation-key
and journal delivery. Five exact descriptors survive the permanent identity
drop. This creates no keys, journal, checkpoint, account or deployment authority.
Protected host delivery is not native measurement or anti-rollback evidence.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat

from catchplate import authority_fd_entrypoint as delivery
from catchplate import current_root_state_entrypoint as fd_inventory
from catchplate import registration_execution_authorizer_entrypoint as sealed_originals


ROOT_PATH = "/run/catchplate/registration-reserver-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/catchplate/registration-reserver-trust/bootstrap.json"
KEY_PATH = "/run/secrets/catchplate-registration-computation-key"
JOURNAL_PATH = "/var/lib/catchplate/registration-reservations"
LISTENER_PATH = "/run/catchplate/registration-execution/reserver.sock"
LISTENER_NAME = "catchplate-registration-execution-reserver"
PROCESS_MODE = "registration-execution-reserver"
SERVICE_UID = SERVICE_GID = 65514
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD = 198, 199, 200, 201, 202
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD)
ROOT_ENV = "CATCHPLATE_REGISTRATION_RESERVER_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "CATCHPLATE_REGISTRATION_RESERVER_BOOTSTRAP_FD"
PREFIX = "CATCHPLATE_REGISTRATION_RESERVER_"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/registration_execution_reserver_launcher.py"
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_KEY_BYTES = 16 * 1024, 4 * 1024 * 1024, 4096
# These helpers inspect only their explicit descriptors/arguments. They do not
# select another role's paths, environment, launch material or main function.
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain
_sealed_identity = sealed_originals._sealed_identity
_read_original = sealed_originals._read_original


def _parent(path):
    if path not in (ROOT_PATH, BOOTSTRAP_PATH, KEY_PATH, JOURNAL_PATH, LISTENER_PATH):
        raise RuntimeError("registration reserver delivery path is not source fixed")
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
                raise RuntimeError("registration reserver ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, private=False):
    if path not in (ROOT_PATH, BOOTSTRAP_PATH, KEY_PATH):
        raise RuntimeError("registration reserver original path is not source fixed")
    parent = _parent(path)
    source = None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 2 <= before.st_size <= maximum
                or private and stat.S_IMODE(before.st_mode) != 0o400):
            raise RuntimeError("registration reserver source is not protected bounded material")
        original = delivery._read_exact_source(source, before.st_size)
        if delivery._material_identity(before) != delivery._material_identity(os.fstat(source)):
            raise RuntimeError("registration reserver source changed while reading")
        return delivery._seal_bytes(source, name="catchplate-registration-reserver",
            value=original, mode=stat.S_IMODE(before.st_mode))
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("registration reserver listener differs from the fixed activated socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        path = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(path.st_mode) or path.st_nlink != 1
                or (path.st_uid, path.st_gid, stat.S_IMODE(path.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("registration reserver socket path ownership differs")
        return value.st_dev, value.st_ino, path.st_dev, path.st_ino
    finally:
        os.close(parent)


def _journal(descriptor):
    """Join the fixed journal pathname and actual descriptor, without mutation."""
    value = os.fstat(descriptor)
    if (not stat.S_ISDIR(value.st_mode)
            or (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (SERVICE_UID, SERVICE_GID, 0o700)):
        raise RuntimeError("registration reserver journal ownership or mode differs")
    parent = _parent(JOURNAL_PATH)
    try:
        path = os.stat(os.path.basename(JOURNAL_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(path.st_mode)
                or (path.st_dev, path.st_ino, path.st_uid, path.st_gid, stat.S_IMODE(path.st_mode))
                    != (value.st_dev, value.st_ino, SERVICE_UID, SERVICE_GID, 0o700)):
            raise RuntimeError("registration reserver journal pathname differs from its descriptor")
        return value.st_dev, value.st_ino
    finally:
        os.close(parent)


def _journal_directory(device, inode):
    parent = _parent(JOURNAL_PATH)
    descriptor = None
    try:
        descriptor = os.open(os.path.basename(JOURNAL_PATH), os.O_RDONLY | os.O_DIRECTORY
            | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        if _journal(descriptor) != (device, inode):
            raise RuntimeError("registration reserver journal differs from its signed identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def main(*, _sealed_originals=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("registration reserver delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("registration reserver requires one exact socket activation")
    from catchplate import registration_dynamic_entrypoint as original_delivery
    incoming = original_delivery._incoming("registration_execution_reserver_entrypoint", _sealed_originals)
    inherited = {3} if incoming is None else {3, original_delivery.BOOTSTRAP_INPUT_FD}
    _require_inventory(inherited)
    owned, reservations, retained = inherited, {}, {}
    try:
        os.set_blocking(3, False)  # Root delivery only; cold admission does not alter borrowed OFDs.
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("registration reserver fixed FD slot is occupied")
            reservations[target] = delivery._material_identity(os.fstat(reserved))
        for path, target, maximum in ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
                (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)):
            source = (original_delivery._source("registration_execution_reserver_entrypoint", incoming)
                if _sealed_originals and target == BOOTSTRAP_FD else _open_material(path, maximum))
            owned.add(source)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            owned.remove(source)
            os.close(source)
        root_raw, _ = _read_original(ROOT_FD, MAX_ROOT_BYTES)
        bootstrap_raw, _ = _read_original(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from catchplate import registration_execution_reserver_bootstrap as bootstrap
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        root = serialization.load_pem_public_key(root_raw)
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("registration reserver root key must be Ed25519")
        work = _ValidationWork(QueryReadValidationLimits())
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
        if _listener(3) != listener_pins:
            raise RuntimeError("registration reserver listener differs from its original root assertion")
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("registration reserver trust original changed during root admission")
        source = _open_material(KEY_PATH, MAX_KEY_BYTES, private=True)
        owned.add(source)
        _retain(source, KEY_FD, reservations, owned)
        retained[KEY_FD] = delivery._material_identity(os.fstat(KEY_FD))
        owned.remove(source)
        os.close(source)
        source = _journal_directory(*journal_pins)
        owned.add(source)
        _retain(source, JOURNAL_FD, reservations, owned)
        retained[JOURNAL_FD] = delivery._material_identity(os.fstat(JOURNAL_FD))
        owned.remove(source)
        os.close(source)
        _retain(3, LISTENER_FD, reservations, owned)
        retained[LISTENER_FD] = delivery._material_identity(os.fstat(LISTENER_FD))
        owned.remove(3)
        os.close(3)
        if reservations or _listener(LISTENER_FD) != listener_pins or _journal(JOURNAL_FD) != journal_pins:
            raise RuntimeError("registration reserver delivery inventory or bound path changed")
        for descriptor, maximum, private in ((ROOT_FD, MAX_ROOT_BYTES, False),
                (BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES, False), (KEY_FD, MAX_KEY_BYTES, True)):
            _read_original(descriptor, maximum, private=private)
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, True)
        _require_inventory(INHERITED_DESCRIPTORS)
        environment = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
            "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
            "CATCHPLATE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if (os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups()):
            raise RuntimeError("registration reserver identity drop retained privilege")
        delivery._require_unprivileged_process()
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("registration reserver descriptor changed before exec")
        _require_inventory(INHERITED_DESCRIPTORS)
        launcher = ("/runtime/authority-bootstrap/registration_execution_reserver_dynamic_launcher.py"
            if _sealed_originals else LAUNCHER)
        os.execve(PYTHON, [PYTHON, "-I", launcher, "--run"], environment)
        raise RuntimeError("registration reserver runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
