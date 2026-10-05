"""Fixed protected delivery for the registration completion role.

An actual root-signed bootstrap precedes completion-key, journal and PostgreSQL
TLS material access. Five exact descriptors survive the permanent identity
drop. libpq later opens only independently pinned fixed TLS paths. This creates
no key, journal, checkpoint, account or deployment authority; protected host
delivery is not native measurement or anti-rollback evidence.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import socket
import stat

from serverware import authority_fd_entrypoint as delivery
from serverware import current_root_state_entrypoint as fd_inventory
from serverware import registration_execution_authorizer_entrypoint as sealed_originals


ROOT_PATH = "/run/serverware/registration-completion-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/serverware/registration-completion-trust/bootstrap.json"
KEY_PATH = "/run/serverware/registration-completion-keys/completion-ed25519.pem"
JOURNAL_PATH = "/var/lib/serverware/registration-completion-delivery"
LISTENER_PATH = "/run/serverware/registration-execution/completion.sock"
LISTENER_NAME = "serverware-registration-execution-completion"
PROCESS_MODE = "registration-execution-completion"
SERVICE_UID = SERVICE_GID = 65515
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD = 198, 199, 200, 201, 202
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD)
PREFIX = "SERVERWARE_REGISTRATION_COMPLETION_"
ROOT_ENV = PREFIX + "ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = PREFIX + "BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/registration_execution_completion_launcher.py"
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_KEY_BYTES = 16 * 1024, 4 * 1024 * 1024, 4096
_TLS_FILES = (
    ("ca", "/run/serverware/registration-completion-tls/ca.pem", 64 * 1024, False),
    ("custodyCertificate", "/run/serverware/registration-completion-tls/custody.crt", 64 * 1024, False),
    ("custodyKey", "/run/serverware/registration-completion-tls/custody.key", 16 * 1024, True),
    ("commitCertificate", "/run/serverware/registration-completion-tls/commit.crt", 64 * 1024, False),
    ("commitKey", "/run/serverware/registration-completion-tls/commit.key", 16 * 1024, True),
)
_HEX = frozenset("0123456789abcdef")
# Parameter-only helpers: no other role's environment, paths or entrypoint.
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain
_sealed_identity = sealed_originals._sealed_identity
_read_original = sealed_originals._read_original


def _parent(path):
    allowed = (ROOT_PATH, BOOTSTRAP_PATH, KEY_PATH, JOURNAL_PATH, LISTENER_PATH,
        *(item[1] for item in _TLS_FILES))
    if path not in allowed:
        raise RuntimeError("registration completion delivery path is not source fixed")
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
                raise RuntimeError("registration completion ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, private=False):
    if path not in (ROOT_PATH, BOOTSTRAP_PATH, KEY_PATH) or private != (path == KEY_PATH):
        raise RuntimeError("registration completion original path or privacy differs")
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
            raise RuntimeError("registration completion original is not protected bounded material")
        original = delivery._read_exact_source(source, before.st_size)
        if delivery._material_identity(before) != delivery._material_identity(os.fstat(source)):
            raise RuntimeError("registration completion original changed while reading")
        return delivery._seal_bytes(source, name="serverware-registration-completion",
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
            raise RuntimeError("registration completion listener differs from the fixed activated socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        path = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(path.st_mode) or path.st_nlink != 1
                or (path.st_uid, path.st_gid, stat.S_IMODE(path.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("registration completion socket path ownership differs")
        return value.st_dev, value.st_ino, path.st_dev, path.st_ino
    finally:
        os.close(parent)


def _journal(descriptor):
    value = os.fstat(descriptor)
    if (not stat.S_ISDIR(value.st_mode)
            or (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (SERVICE_UID, SERVICE_GID, 0o700)):
        raise RuntimeError("registration completion journal ownership or mode differs")
    parent = _parent(JOURNAL_PATH)
    try:
        path = os.stat(os.path.basename(JOURNAL_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(path.st_mode)
                or (path.st_dev, path.st_ino, path.st_uid, path.st_gid, stat.S_IMODE(path.st_mode))
                    != (value.st_dev, value.st_ino, SERVICE_UID, SERVICE_GID, 0o700)):
            raise RuntimeError("registration completion journal pathname differs from its descriptor")
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
            raise RuntimeError("registration completion journal differs from its signed identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _tls_identity(tls_files):
    """Hash source-fixed TLS originals, returning metadata/pins but no contents.

    Root-owned keys are exactly 0440 with group 65515 so libpq can reopen them
    after the permanent drop. Public files are exactly 0444. This local check
    supplies neither TLS identity validation nor authority against a root writer.
    """
    if type(tls_files) is not dict or set(tls_files) != {item[0] for item in _TLS_FILES}:
        raise RuntimeError("registration completion TLS inventory is not source fixed")
    pins = []
    for name, path, maximum, private in _TLS_FILES:
        record = tls_files[name]
        if type(record) is not dict or set(record) != {"byteCount", "bytesDigest"}:
            raise RuntimeError("registration completion TLS original pin fields differ")
        size, digest = record["byteCount"], record["bytesDigest"]
        if (type(size) is not int or not 2 <= size <= maximum
                or type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in _HEX for character in digest[7:])):
            raise RuntimeError("registration completion TLS original pin is invalid")
        pins.append((name, path, size, digest, private))
    # Every caller scalar is immutable and held before the first file access.
    held = tuple(pins)
    identities = []
    for name, path, size, expected_digest, private in held:
        parent = _parent(path)
        descriptor = None
        try:
            descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
                | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                    or before.st_size != size
                    or stat.S_IMODE(before.st_mode) != (0o440 if private else 0o444)
                    or private and before.st_gid != SERVICE_GID):
                raise RuntimeError("registration completion TLS file protection or size differs")
            identity = delivery._material_identity(before)
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if delivery._material_identity(named) != identity:
                raise RuntimeError("registration completion TLS pathname differs from its descriptor")
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = os.read(descriptor, min(4096, remaining))
                if not chunk:
                    raise RuntimeError("registration completion TLS original was truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise RuntimeError("registration completion TLS original grew while reading")
            after = os.fstat(descriptor)
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if (delivery._material_identity(after) != identity
                    or delivery._material_identity(named) != identity
                    or "sha256:" + digest.hexdigest() != expected_digest):
                raise RuntimeError("registration completion TLS original identity or digest changed")
            identities.append((name, identity, expected_digest))
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
    observed = tuple(identities)
    _tls_unchanged(observed)
    return observed


def _tls_unchanged(expected_identity):
    """Require held fixed-path metadata continuity without reading TLS bytes.

    This is a trusted-host-local continuity check, not protection against a
    malicious root or a replacement occurring after the final observation.
    """
    if type(expected_identity) is not tuple or len(expected_identity) != len(_TLS_FILES):
        raise RuntimeError("registration completion TLS identity inventory differs")
    held = []
    for (name, path, maximum, private), observed in zip(_TLS_FILES, expected_identity):
        if type(observed) is not tuple or len(observed) != 3:
            raise RuntimeError("registration completion TLS identity record differs")
        actual_name, identity, digest = observed
        if (type(actual_name) is not str or actual_name != name
                or type(identity) is not tuple or len(identity) != 9
                or any(type(value) is not int for value in identity)
                or not stat.S_ISREG(identity[2]) or identity[3] != 0 or identity[5] != 1
                or not 2 <= identity[6] <= maximum
                or stat.S_IMODE(identity[2]) != (0o440 if private else 0o444)
                or private and identity[4] != SERVICE_GID
                or type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in _HEX for character in digest[7:])):
            raise RuntimeError("registration completion held TLS identity is invalid")
        held.append((path, identity))
    # No private-key byte reads or hashes are performed on this path.
    for path, identity in held:
        parent = _parent(path)
        try:
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if delivery._material_identity(named) != identity:
                raise RuntimeError("registration completion TLS inventory changed while checking")
        finally:
            os.close(parent)


def main(*, _sealed_originals=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("registration completion delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("registration completion requires one exact socket activation")
    from serverware import registration_dynamic_entrypoint as original_delivery
    incoming = original_delivery._incoming("registration_execution_completion_entrypoint", _sealed_originals)
    inherited = {3} if incoming is None else {3, original_delivery.BOOTSTRAP_INPUT_FD}
    _require_inventory(inherited)
    owned, reservations, retained = inherited, {}, {}
    try:
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("registration completion fixed FD slot is occupied")
            reservations[target] = delivery._material_identity(os.fstat(reserved))
        for path, target, maximum in ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
                (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)):
            source = (original_delivery._source("registration_execution_completion_entrypoint", incoming)
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
        from serverware import registration_execution_completion_bootstrap as bootstrap
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        root = serialization.load_pem_public_key(root_raw)
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("registration completion root key must be Ed25519")
        work = _ValidationWork(QueryReadValidationLimits())
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
        if _listener(3) != listener_pins:
            raise RuntimeError("registration completion listener differs from its original root assertion")
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("registration completion trust original changed during root admission")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        source = _open_material(KEY_PATH, MAX_KEY_BYTES, private=True)
        owned.add(source)
        _retain(source, KEY_FD, reservations, owned)
        retained[KEY_FD] = delivery._material_identity(os.fstat(KEY_FD))
        owned.remove(source)
        os.close(source)
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        tls_identity = _tls_identity(material.tls_files)
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
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
            raise RuntimeError("registration completion delivery inventory or bound path changed")
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
            raise RuntimeError("registration completion identity drop retained privilege")
        delivery._require_unprivileged_process()
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("registration completion descriptor changed before exec")
        _tls_unchanged(tls_identity)
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        _require_inventory(INHERITED_DESCRIPTORS)
        launcher = ("/runtime/authority-bootstrap/registration_execution_completion_dynamic_launcher.py"
            if _sealed_originals else LAUNCHER)
        os.execve(PYTHON, [PYTHON, "-I", launcher, "--run"], environment)
        raise RuntimeError("registration completion runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
