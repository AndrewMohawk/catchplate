"""Fixed root delivery for the separate registration grant authorizer.

Only independently provisioned originals and one activated socket are opened.
The root signature and both socket identities precede private-key delivery.
Four sealed/inherited descriptors survive the permanent identity drop. This
does not provision keys, establish native measurement or create replay state.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat

from serverware import authority_fd_entrypoint as delivery
from serverware import current_root_state_entrypoint as fd_inventory


ROOT_PATH = "/run/serverware/registration-execution-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/serverware/registration-execution-trust/bootstrap.json"
KEY_PATH = "/run/secrets/serverware-registration-execution-authorizer-key"
LISTENER_PATH = "/run/serverware/registration-execution/authorizer.sock"
LISTENER_NAME = "serverware-registration-execution-authorizer"
PROCESS_MODE = "registration-execution-authorizer"
SERVICE_UID = SERVICE_GID = 65513
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD = 198, 199, 200, 201
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD)
ROOT_ENV = "SERVERWARE_REGISTRATION_EXECUTION_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "SERVERWARE_REGISTRATION_EXECUTION_BOOTSTRAP_FD"
PREFIX = "SERVERWARE_REGISTRATION_EXECUTION_"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/registration_execution_authorizer_launcher.py"
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_KEY_BYTES = 16 * 1024, 4 * 1024 * 1024, 4096
# These two existing helpers inspect only their explicit FD arguments. They
# neither select current-root material nor invoke that role's delivery main.
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain


def _parent(path):
    if path not in (ROOT_PATH, BOOTSTRAP_PATH, KEY_PATH, LISTENER_PATH):
        raise RuntimeError("registration execution delivery path is not source fixed")
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
                raise RuntimeError("registration execution ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, private=False):
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
            raise RuntimeError("registration execution source is not protected bounded material")
        original = delivery._read_exact_source(source, before.st_size)
        if delivery._material_identity(before) != delivery._material_identity(os.fstat(source)):
            raise RuntimeError("registration execution source changed while reading")
        sealed = delivery._seal_bytes(source, name="serverware-registration-execution",
            value=original, mode=stat.S_IMODE(before.st_mode))
        return sealed
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _sealed_identity(descriptor, maximum, *, private=False):
    value = os.fstat(descriptor)
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    target = os.readlink("/proc/self/fd/" + str(descriptor))
    required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 0
            or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or private and stat.S_IMODE(value.st_mode) != 0o400
            or not 2 <= value.st_size <= maximum or seals & required != required
            or not target.startswith("/memfd:") or not target.endswith(" (deleted)")):
        raise RuntimeError("registration execution inherited original is not a sealed root memfd")
    return delivery._material_identity(value), seals, target


def _read_original(descriptor, maximum, *, private=False):
    identity = _sealed_identity(descriptor, maximum, private=private)
    raw = delivery._read_exact_source(descriptor, identity[0][6])
    if _sealed_identity(descriptor, maximum, private=private) != identity:
        raise RuntimeError("registration execution sealed original changed")
    return raw, identity


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("registration execution listener differs from the fixed activated socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        path = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(path.st_mode) or path.st_nlink != 1
                or (path.st_uid, path.st_gid, stat.S_IMODE(path.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("registration execution socket path ownership differs")
        return value.st_dev, value.st_ino, path.st_dev, path.st_ino
    finally:
        os.close(parent)


def main(*, _sealed_originals=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("registration execution delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("registration execution requires one exact socket activation")
    from serverware import registration_dynamic_entrypoint as original_delivery
    incoming = original_delivery._incoming("registration_execution_authorizer_entrypoint", _sealed_originals)
    inherited = {3} if incoming is None else {3, original_delivery.BOOTSTRAP_INPUT_FD}
    _require_inventory(inherited)
    owned, reservations, retained = inherited, {}, {}
    try:
        os.set_blocking(3, False)  # Delivery only; cold admission never changes borrowed OFDs.
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("registration execution fixed FD slot is occupied")
            reservations[target] = delivery._material_identity(os.fstat(reserved))
        for path, target, maximum in ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
                (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)):
            source = (original_delivery._source("registration_execution_authorizer_entrypoint", incoming)
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
        from serverware import registration_execution_authorizer_bootstrap as bootstrap
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        root = serialization.load_pem_public_key(root_raw)
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("registration execution root key must be Ed25519")
        work = _ValidationWork(QueryReadValidationLimits())
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        if _listener(3) != listener_pins:
            raise RuntimeError("registration execution listener differs from its original root assertion")
        source = _open_material(KEY_PATH, MAX_KEY_BYTES, private=True)
        owned.add(source)
        _retain(source, KEY_FD, reservations, owned)
        retained[KEY_FD] = delivery._material_identity(os.fstat(KEY_FD))
        owned.remove(source)
        os.close(source)
        _retain(3, LISTENER_FD, reservations, owned)
        retained[LISTENER_FD] = delivery._material_identity(os.fstat(LISTENER_FD))
        owned.remove(3)
        os.close(3)
        if reservations or _listener(LISTENER_FD) != listener_pins:
            raise RuntimeError("registration execution delivery inventory or listener changed")
        for descriptor, maximum, private in ((ROOT_FD, MAX_ROOT_BYTES, False),
                (BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES, False), (KEY_FD, MAX_KEY_BYTES, True)):
            _read_original(descriptor, maximum, private=private)
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, True)
        _require_inventory(INHERITED_DESCRIPTORS)
        environment = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
            "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
            "SERVERWARE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if (os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups()):
            raise RuntimeError("registration execution identity drop retained privilege")
        delivery._require_unprivileged_process()
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("registration execution descriptor changed before exec")
        _require_inventory(INHERITED_DESCRIPTORS)
        launcher = ("/runtime/authority-bootstrap/registration_execution_authorizer_dynamic_launcher.py"
            if _sealed_originals else LAUNCHER)
        os.execve(PYTHON, [PYTHON, "-I", launcher, "--run"], environment)
        raise RuntimeError("registration execution runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
