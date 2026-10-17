"""Fixed root delivery for the independently enrolled current-root state owner.

This opens only provisioned originals and an activated listener. It creates no
key, enrollment, journal, checkpoint or authority. The original root signature
must admit the distinct journal, socket-FD and socket-path identities before
delivery; the nonroot cold owner independently repeats admission. Protected
host paths are not native measurement, hardware attestation or anti-rollback.
"""
from __future__ import annotations

import errno
import fcntl
import os
import socket
import stat

from catchplate import authority_fd_entrypoint as delivery


ROOT_PATH = "/run/catchplate/current-root-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/catchplate/current-root-trust/bootstrap.json"
KEY_PATH = "/run/secrets/catchplate-current-root-state-signing-key"
JOURNAL_PATH = "/var/lib/catchplate/current-root-state"
LISTENER_PATH = "/run/catchplate/current-root/state.sock"
LISTENER_NAME = "catchplate-current-root-state"
PROCESS_MODE = "policy-authority-current-root-state"
SERVICE_UID = SERVICE_GID = 65516
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD = (198, 199, 200, 201, 202)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD)
ROOT_ENV = "CATCHPLATE_CURRENT_ROOT_STATE_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "CATCHPLATE_CURRENT_ROOT_STATE_BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/current_root_state_launcher.py"
MAX_ROOT_BYTES = 16 * 1024
MAX_BOOTSTRAP_BYTES = 256 * 1024
MAX_KEY_BYTES = 4096
MAX_FD_ENTRIES = 4096


def _inventory() -> set[int]:
    """Observe open descriptors after closing the bounded proc scan itself."""
    names = []
    with os.scandir("/proc/self/fd") as entries:
        for entry in entries:
            if len(names) >= MAX_FD_ENTRIES:
                raise RuntimeError("current-root descriptor inventory exceeds its bound")
            if not entry.name.isascii() or not entry.name.isdecimal():
                raise RuntimeError("current-root descriptor inventory contains an unexpected name")
            names.append(int(entry.name))
    result = set()
    for descriptor in names:
        if descriptor < 3:
            continue
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise
        result.add(descriptor)
    return result


def _require_inventory(expected) -> None:
    if _inventory() != set(expected):
        raise RuntimeError("current-root inherited descriptors differ from the fixed inventory")


def _parent(path: str) -> int:
    if path not in {ROOT_PATH, BOOTSTRAP_PATH, KEY_PATH, JOURNAL_PATH, LISTENER_PATH}:
        raise RuntimeError("current-root delivery path is not fixed by source")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in (None, *path.split("/")[1:-1]):
            if component is not None:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            metadata = os.fstat(descriptor)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("current-root delivery ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path: str, maximum: int, *, private: bool = False) -> int:
    parent = _parent(path)
    descriptor = None
    try:
        descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_nlink != 1 or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 1 <= before.st_size <= maximum
                or private and stat.S_IMODE(before.st_mode) != 0o400):
            raise RuntimeError("current-root source is not bounded protected root material")
        original = delivery._read_exact_source(descriptor, before.st_size)
        if delivery._material_identity(before) != delivery._material_identity(os.fstat(descriptor)):
            raise RuntimeError("current-root source changed during original-byte delivery")
        return delivery._seal_bytes(descriptor, name="catchplate-current-root-state",
            value=original, mode=stat.S_IMODE(before.st_mode))
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _sealed_original(descriptor: int, maximum: int) -> bytes:
    before = os.fstat(descriptor)
    seals = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 0
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= before.st_size <= maximum
            or fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals):
        raise RuntimeError("current-root retained source is not original sealed root material")
    original = delivery._read_exact_source(descriptor, before.st_size)
    if delivery._material_identity(before) != delivery._material_identity(os.fstat(descriptor)):
        raise RuntimeError("current-root sealed source changed while read")
    return original


def _listener(descriptor: int):
    """Keep sockfs and filesystem socket identities separate, never equate them."""
    metadata = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(metadata.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("current-root listener is not the fixed nonblocking Unix stream")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        path_stat = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(path_stat.st_mode) or path_stat.st_nlink != 1
                or (path_stat.st_uid, path_stat.st_gid) != (SERVICE_UID, SERVICE_GID)
                or stat.S_IMODE(path_stat.st_mode) != 0o660):
            raise RuntimeError("current-root listener pathname identity is not exact")
        return (metadata.st_dev, metadata.st_ino, path_stat.st_dev, path_stat.st_ino)
    finally:
        os.close(parent)


def _retain(source: int, target: int, reservations: dict, owned: set[int]) -> None:
    if delivery._material_identity(os.fstat(target)) != reservations[target]:
        owned.discard(target)
        raise RuntimeError("current-root descriptor reservation changed")
    owned.remove(target)
    os.close(target)
    replacement = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, target)
    owned.add(replacement)
    if replacement != target:
        raise RuntimeError("current-root reserved descriptor became occupied")
    del reservations[target]


def _journal_directory(device: int, inode: int) -> int:
    parent = _parent(JOURNAL_PATH)
    descriptor = None
    try:
        descriptor = os.open(os.path.basename(JOURNAL_PATH), os.O_RDONLY | os.O_DIRECTORY
            | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)
                != (device, inode, SERVICE_UID, SERVICE_GID)):
            raise RuntimeError("current-root journal directory differs from its signed provisioned identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _drop_identity() -> None:
    os.setgroups([])
    os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
    os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
    if (os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3
            or os.getgroups()):
        raise RuntimeError("current-root identity drop retained a root identity or supplementary group")
    delivery._require_unprivileged_process()


def main() -> int:
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("current-root state delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("current-root state requires its one exact systemd activation")
    _require_inventory({3})
    owned, reservations, retained = {3}, {}, {}
    try:
        # Delivery alone sets this shared OFD flag. Cold admission must only
        # validate it and must not set flags on borrowed descriptors.
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("current-root fixed delivery slot was already occupied")
            reservations[target] = delivery._material_identity(os.fstat(reserved))
        for path, target, maximum in ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
                (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)):
            source = _open_material(path, maximum)
            owned.add(source)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            owned.remove(source)
            os.close(source)
        root_original = _sealed_original(ROOT_FD, MAX_ROOT_BYTES)
        bootstrap_original = _sealed_original(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from catchplate import current_root_state_bootstrap as bootstrap
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        root = serialization.load_pem_public_key(root_original)
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("current-root protected root must be an Ed25519 public key")
        material = bootstrap._admit_on_work(bootstrap_bytes=bootstrap_original,
            root_public_key=root, work=_ValidationWork(QueryReadValidationLimits()))
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("current-root trust material changed during root admission")
        launch = material.launch
        expected_listener = (launch["listenerSocketDevice"], launch["listenerSocketInode"],
            launch["listenerPathDevice"], launch["listenerPathInode"])
        journal_device, journal_inode = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
        if _listener(3) != expected_listener:
            raise RuntimeError("current-root activated listener differs from its signed identities")
        source = _open_material(KEY_PATH, MAX_KEY_BYTES, private=True)
        owned.add(source)
        _retain(source, KEY_FD, reservations, owned)
        retained[KEY_FD] = delivery._material_identity(os.fstat(KEY_FD))
        owned.remove(source)
        os.close(source)
        source = _journal_directory(journal_device, journal_inode)
        owned.add(source)
        _retain(source, JOURNAL_FD, reservations, owned)
        retained[JOURNAL_FD] = delivery._material_identity(os.fstat(JOURNAL_FD))
        owned.remove(source)
        os.close(source)
        _retain(3, LISTENER_FD, reservations, owned)
        retained[LISTENER_FD] = delivery._material_identity(os.fstat(LISTENER_FD))
        owned.remove(3)
        os.close(3)
        if reservations:
            raise RuntimeError("current-root delivery left an unfulfilled reservation")
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, True)
        if _listener(LISTENER_FD) != expected_listener:
            raise RuntimeError("current-root listener changed before fixed runner handoff")
        _sealed_original(ROOT_FD, MAX_ROOT_BYTES)
        _sealed_original(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)
        _sealed_original(KEY_FD, MAX_KEY_BYTES)
        _require_inventory(INHERITED_DESCRIPTORS)
        # Drop every ambient authority/DSN/Python/loader/manager setting. No
        # environment path, root key, checkpoint or operation override survives.
        environment = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
            "TZ": "UTC", "LD_LIBRARY_PATH": "/runtime/python/lib",
            "PYTHONDONTWRITEBYTECODE": "1", "CATCHPLATE_PROCESS_MODE": PROCESS_MODE,
            ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
        _drop_identity()
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("current-root retained descriptor changed before fixed runner exec")
        _require_inventory(INHERITED_DESCRIPTORS)
        os.execve(PYTHON, [PYTHON, "-I", LAUNCHER, "--run"], environment)
        raise RuntimeError("current-root fixed runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
