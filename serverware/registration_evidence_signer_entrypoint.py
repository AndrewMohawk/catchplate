"""Root delivery for the separate trusted-host registration evidence signer.

No listener, key, journal directory or authority role is created here. Root
owns the fixed trust files and private ancestors; the independently provisioned
root key authenticates the original bootstrap before signed directory identity
is used. The unprivileged cold runner independently admits the retained bytes.
This is protected host delivery, not native measurement or TEE assurance.
"""
from __future__ import annotations

import errno
import fcntl
import os
import socket
import stat

from serverware import authority_fd_entrypoint as delivery


ROOT_PATH = "/run/serverware/registration-evidence-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/serverware/registration-evidence-trust/bootstrap.json"
KEY_PATH = "/run/secrets/serverware-registration-evidence-signing-key"
REPLAY_PATH = "/var/lib/serverware/registration-evidence-replay"
LISTENER_PATH = "/run/serverware/registration-evidence/signer.sock"
LISTENER_NAME = "serverware-registration-evidence"
PROCESS_MODE = "webauthn-registration-evidence-signer"
SIGNER_UID = SIGNER_GID = 65517
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, REPLAY_FD = (198, 199, 200, 201, 202)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, REPLAY_FD)
ROOT_ENV = "SERVERWARE_REGISTRATION_SIGNER_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "SERVERWARE_REGISTRATION_SIGNER_BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/registration_evidence_signer_launcher.py"
MAX_ROOT_BYTES = 16 * 1024
MAX_BOOTSTRAP_BYTES = 4 * 1024 * 1024
MAX_KEY_BYTES = 4096
MAX_FD_ENTRIES = 4096


def _inventory() -> set[int]:
    """Observe actual open FDs, excluding stdio and the finished proc scan."""
    names = []
    with os.scandir("/proc/self/fd") as entries:
        for entry in entries:
            if len(names) >= MAX_FD_ENTRIES:
                raise RuntimeError("signer inherited descriptor inventory exceeds its bound")
            if not entry.name.isascii() or not entry.name.isdecimal():
                raise RuntimeError("signer descriptor inventory contains an unexpected name")
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
        raise RuntimeError("signer inherited descriptors differ from the exact fixed inventory")


def _parent(path: str) -> int:
    """Only fixed private paths are accepted, with no ancestor symlinks."""
    if path not in {ROOT_PATH, BOOTSTRAP_PATH, KEY_PATH, REPLAY_PATH, LISTENER_PATH}:
        raise RuntimeError("signer delivery path is not fixed by source")
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
                raise RuntimeError("signer delivery ancestor is not root-owned nonwritable material")
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
            raise RuntimeError("signer source is not exact bounded root-owned material")
        original = delivery._read_exact_source(descriptor, before.st_size)
        if delivery._material_identity(before) != delivery._material_identity(os.fstat(descriptor)):
            raise RuntimeError("signer source changed while retaining its original bytes")
        return delivery._seal_bytes(descriptor, name="serverware-registration-evidence",
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
        raise RuntimeError("signer retained material is not original sealed root-owned bytes")
    original = delivery._read_exact_source(descriptor, before.st_size)
    if delivery._material_identity(before) != delivery._material_identity(os.fstat(descriptor)):
        raise RuntimeError("signer sealed source identity changed")
    return original


def _listener(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(metadata.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH
                or os.get_blocking(descriptor)):
            raise RuntimeError("signer listener is not the fixed nonblocking activated Unix stream socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        path_stat = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(path_stat.st_mode) or path_stat.st_nlink != 1
                or (path_stat.st_uid, path_stat.st_gid) != (SIGNER_UID, PEER_GID)
                or stat.S_IMODE(path_stat.st_mode) != 0o660):
            raise RuntimeError("signer activated socket path identity is not exact")
    finally:
        os.close(parent)


def _retain(source: int, target: int, reservations: dict, owned: set[int]) -> None:
    expected = reservations[target]
    if delivery._material_identity(os.fstat(target)) != expected:
        # A changed slot is not ours to close or overwrite.
        owned.discard(target)
        raise RuntimeError("signer fixed descriptor reservation changed")
    owned.remove(target)
    os.close(target)
    replacement = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, target)
    owned.add(replacement)
    if replacement != target:
        raise RuntimeError("signer reserved descriptor became occupied")
    del reservations[target]


def _replay_directory(device: int, inode: int) -> int:
    parent = _parent(REPLAY_PATH)
    descriptor = None
    try:
        descriptor = os.open(os.path.basename(REPLAY_PATH), os.O_RDONLY | os.O_DIRECTORY
            | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)
                != (device, inode, SIGNER_UID, SIGNER_GID)):
            raise RuntimeError("signer replay directory differs from its authenticated provisioned identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _drop_identity() -> None:
    os.setgroups([])
    os.setresgid(SIGNER_GID, SIGNER_GID, SIGNER_GID)
    os.setresuid(SIGNER_UID, SIGNER_UID, SIGNER_UID)
    if (os.getresuid() != (SIGNER_UID,) * 3 or os.getresgid() != (SIGNER_GID,) * 3
            or os.getgroups()):
        raise RuntimeError("signer identity drop did not remove every root identity and supplementary group")
    delivery._require_unprivileged_process()


def main() -> int:
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("registration evidence signer delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("registration evidence signer requires its one exact systemd activation")
    _require_inventory({3})
    owned, reservations, retained = {3}, {}, {}
    try:
        # Root delivery alone may set the shared listener OFD nonblocking. The
        # unprivileged owner must subsequently treat those borrowed flags as fixed.
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("signer fixed delivery slot was already occupied")
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
        from serverware import registration_evidence_signer_bootstrap as bootstrap
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        root = serialization.load_pem_public_key(root_original)
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("signer protected root must be an Ed25519 public key")
        material = bootstrap._admit_on_work(bootstrap_bytes=bootstrap_original,
            root_public_key=root, work=_ValidationWork(QueryReadValidationLimits()))
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("signer retained trust material changed during signature admission")
        # No claimed directory values are used until the actual root signature
        # and the complete signed launch/configuration admission have succeeded.
        device, inode = (material.launch["replayDirectoryDevice"],
            material.launch["replayDirectoryInode"])
        source = _open_material(KEY_PATH, MAX_KEY_BYTES, private=True)
        owned.add(source)
        _retain(source, KEY_FD, reservations, owned)
        retained[KEY_FD] = delivery._material_identity(os.fstat(KEY_FD))
        owned.remove(source)
        os.close(source)
        source = _replay_directory(device, inode)
        owned.add(source)
        _retain(source, REPLAY_FD, reservations, owned)
        retained[REPLAY_FD] = delivery._material_identity(os.fstat(REPLAY_FD))
        owned.remove(source)
        os.close(source)
        _retain(3, LISTENER_FD, reservations, owned)
        retained[LISTENER_FD] = delivery._material_identity(os.fstat(LISTENER_FD))
        owned.remove(3)
        os.close(3)
        if reservations:
            raise RuntimeError("signer delivery left an unfulfilled reservation")
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, True)
        _listener(LISTENER_FD)
        _sealed_original(ROOT_FD, MAX_ROOT_BYTES)
        _sealed_original(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)
        _sealed_original(KEY_FD, MAX_KEY_BYTES)
        _require_inventory(INHERITED_DESCRIPTORS)
        # Rebuilding, rather than inheriting, discards every incoming signer,
        # generic authority, DSN, PYTHON*, LD_* and service-manager variable.
        environment = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
            "TZ": "UTC", "LD_LIBRARY_PATH": "/runtime/python/lib",
            "PYTHONDONTWRITEBYTECODE": "1", "SERVERWARE_PROCESS_MODE": PROCESS_MODE,
            ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
        _drop_identity()
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("signer retained descriptor identity changed before runner exec")
        _require_inventory(INHERITED_DESCRIPTORS)
        os.execve(PYTHON, [PYTHON, "-I", LAUNCHER, "--run"], environment)
        raise RuntimeError("signer fixed runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
