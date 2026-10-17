"""Fixed root delivery for the dedicated activation SQL receiving owner.

Original role/receiving admission precedes AES, database TLS and journal access.
Seven exact descriptors survive a permanent UID/GID drop. libpq reopens only
root-pinned fixed TLS files. No signing key, password, provisioning or state
socket authority is delivered. Local protection is not hostile-root custody.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import socket
import stat

from catchplate import authority_fd_entrypoint as delivery
from catchplate import current_root_state_entrypoint as fd_inventory
from catchplate import registration_execution_authorizer_entrypoint as sealed_originals


ROOT_PATH = "/run/catchplate/oidc-session-activation-execution-sql-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/catchplate/oidc-session-activation-execution-sql-trust/bootstrap.json"
CUSTODY_PATH = "/run/catchplate/oidc-session-activation-execution-sql-trust/custody.json"
BUNDLE_KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-bundle-key"
DELIVERY_KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-delivery-key"
JOURNAL_PATH = "/var/lib/catchplate/oidc-session-activation-execution-sql-attempts"
LISTENER_PATH = "/run/catchplate/oidc-session-activation-execution/sql.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-execution-sql"
PROCESS_MODE = "oidc-session-activation-execution-sql"
SERVICE_UID = SERVICE_GID = 65504
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD = 198, 199, 200, 201
BUNDLE_KEY_FD, DELIVERY_KEY_FD, JOURNAL_FD = 202, 203, 204
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD,
    BUNDLE_KEY_FD, DELIVERY_KEY_FD, JOURNAL_FD)
PREFIX = "CATCHPLATE_OIDC_SESSION_ACTIVATION_EXECUTION_SQL_"
ROOT_ENV, BOOTSTRAP_ENV = PREFIX + "ROOT_PUBLIC_KEY_FD", PREFIX + "BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_execution_sql_launcher.py"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "CATCHPLATE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_CUSTODY_BYTES = 16 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024
MAX_RAW_KEY_BYTES = 32
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
    (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES),
    (CUSTODY_PATH, CUSTODY_FD, MAX_CUSTODY_BYTES))
_KEY_FILES = ((BUNDLE_KEY_PATH, BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (DELIVERY_KEY_PATH, DELIVERY_KEY_FD, MAX_RAW_KEY_BYTES))
_MATERIAL = {path: (maximum, private) for private, inventory in
    ((False, _TRUST_FILES), (True, _KEY_FILES)) for path, _descriptor, maximum in inventory}
_TLS_FILES = (
    ("ca", "/run/catchplate/oidc-session-activation-execution-sql-tls/ca.pem", 64 * 1024, False),
    ("issuerCertificate", "/run/catchplate/oidc-session-activation-execution-sql-tls/issuer.crt", 64 * 1024, False),
    ("issuerKey", "/run/catchplate/oidc-session-activation-execution-sql-tls/issuer.key", 16 * 1024, True),
    ("executorCertificate", "/run/catchplate/oidc-session-activation-execution-sql-tls/executor.crt", 64 * 1024, False),
    ("executorKey", "/run/catchplate/oidc-session-activation-execution-sql-tls/executor.key", 16 * 1024, True),
)
_HEX = frozenset("0123456789abcdef")
# These purpose-neutral helpers use explicit descriptors, not another role's
# paths, environment, bootstrap, process identity or main function.
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain
_sealed_identity = sealed_originals._sealed_identity
_read_original = sealed_originals._read_original


def _parent(path):
    if path not in (*_MATERIAL, JOURNAL_PATH, LISTENER_PATH, *(item[1] for item in _TLS_FILES)):
        raise RuntimeError("activation sql path is not source fixed")
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
                raise RuntimeError("activation sql ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, private=False):
    if path not in _MATERIAL or _MATERIAL[path] != (maximum, private) or type(private) is not bool:
        raise RuntimeError("activation sql original inventory changed")
    parent, source = _parent(path), None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 2 <= before.st_size <= maximum
                or private and stat.S_IMODE(before.st_mode) != 0o400
                or path in (BUNDLE_KEY_PATH, DELIVERY_KEY_PATH) and before.st_size != MAX_RAW_KEY_BYTES):
            raise RuntimeError("activation sql original is not protected bounded material")
        identity = delivery._material_identity(before)
        named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if delivery._material_identity(named) != identity:
            raise RuntimeError("activation sql original pathname differs")
        raw = delivery._read_exact_source(source, before.st_size)
        named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(named) != identity):
            raise RuntimeError("activation sql original changed during read")
        return delivery._seal_bytes(source, name="catchplate-oidc-activation-sql",
            value=raw, mode=stat.S_IMODE(before.st_mode))
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _keys_on_work(material, work):
    """Bind the actual two sealed AES originals after signed scope admission."""
    from catchplate import authority_oidc_session_activation_execution_custody as custody

    evidence = custody.evidence
    evidence.capture._SharedLedger(work)
    work.charge(input_bytes=2 * MAX_RAW_KEY_BYTES)
    originals, identities = [], []
    for _path, descriptor, maximum in _KEY_FILES:
        raw, identity = evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum:
                _read_original(descriptor, maximum, private=True))
        originals.append(raw)
        identities.append((descriptor, maximum, identity))
    bundle_key, delivery_key = originals
    if any(type(raw) is not bytes or len(raw) != MAX_RAW_KEY_BYTES for raw in originals):
        raise RuntimeError("activation SQL encryption originals must be raw32")
    custody._key_bindings(material.custody_material, bundle_key, delivery_key, work)
    for descriptor, maximum, identity in identities:
        observed = evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum: _sealed_identity(descriptor, maximum, private=True))
        if observed != identity:
            raise RuntimeError("activation SQL key descriptor changed during admission")
    return bundle_key, delivery_key


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("activation sql listener differs from fixed socket activation")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("activation sql socket path protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _journal(descriptor):
    """Join the fixed journal path to its actual directory without mutation."""
    value = os.fstat(descriptor)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (SERVICE_UID, SERVICE_GID, 0o700)):
        raise RuntimeError("activation sql journal ownership or mode differs")
    parent = _parent(JOURNAL_PATH)
    try:
        named = os.stat(os.path.basename(JOURNAL_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode) or named.st_nlink < 1
                or (named.st_dev, named.st_ino, named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode))
                    != (value.st_dev, value.st_ino, SERVICE_UID, SERVICE_GID, 0o700)):
            raise RuntimeError("activation sql journal pathname differs from its descriptor")
        return value.st_dev, value.st_ino
    finally:
        os.close(parent)


def _journal_directory(device, inode):
    parent, descriptor = _parent(JOURNAL_PATH), None
    try:
        descriptor = os.open(os.path.basename(JOURNAL_PATH), os.O_RDONLY | os.O_DIRECTORY
            | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        if _journal(descriptor) != (device, inode):
            raise RuntimeError("activation sql journal differs from its signed identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _tls_identity(tls_files):
    """Hash source-fixed TLS originals, retaining identity/pins, never contents.

    Keys are root-owned 0440 with group 65504 for libpq reopening after the
    permanent drop. Public files are root-owned 0444. These local checks do not
    authenticate a TLS identity or protect against a malicious root writer.
    """
    if type(tls_files) is not dict or set(tls_files) != {item[0] for item in _TLS_FILES}:
        raise RuntimeError("activation SQL TLS inventory is not source fixed")
    pins = []
    for name, path, maximum, private in _TLS_FILES:
        record = tls_files[name]
        if type(record) is not dict or set(record) != {"byteCount", "bytesDigest"}:
            raise RuntimeError("activation SQL TLS original pin fields differ")
        size, digest = record["byteCount"], record["bytesDigest"]
        if (type(size) is not int or not 2 <= size <= maximum
                or type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in _HEX for character in digest[7:])):
            raise RuntimeError("activation SQL TLS original pin is invalid")
        pins.append((name, path, size, digest, private))
    # Hold all caller scalars before the first file access.
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
                raise RuntimeError("activation SQL TLS file protection or size differs")
            identity = delivery._material_identity(before)
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if delivery._material_identity(named) != identity:
                raise RuntimeError("activation SQL TLS pathname differs from its descriptor")
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = os.read(descriptor, min(4096, remaining))
                if not chunk:
                    raise RuntimeError("activation SQL TLS original was truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise RuntimeError("activation SQL TLS original grew while reading")
            after = os.fstat(descriptor)
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if (delivery._material_identity(after) != identity
                    or delivery._material_identity(named) != identity
                    or "sha256:" + digest.hexdigest() != expected_digest):
                raise RuntimeError("activation SQL TLS original identity or digest changed")
            identities.append((name, identity, expected_digest))
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
    observed = tuple(identities)
    _tls_unchanged(observed)
    return observed


def _tls_unchanged(expected_identity):
    """Check held fixed-path metadata without reading any TLS original bytes.

    This trusted-host-local check cannot protect against malicious root or a
    path replacement occurring after the final observation.
    """
    if type(expected_identity) is not tuple or len(expected_identity) != len(_TLS_FILES):
        raise RuntimeError("activation SQL TLS identity inventory differs")
    held = []
    for (name, path, maximum, private), observed in zip(_TLS_FILES, expected_identity):
        if type(observed) is not tuple or len(observed) != 3:
            raise RuntimeError("activation SQL TLS identity record differs")
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
            raise RuntimeError("activation SQL held TLS identity is invalid")
        held.append((path, identity))
    # Recheck earlier paths after later originals were hashed. No re-reading
    # private key bytes on this metadata-only continuity path.
    for path, identity in held:
        parent = _parent(path)
        try:
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if delivery._material_identity(named) != identity:
                raise RuntimeError("activation SQL TLS inventory changed while checking")
        finally:
            os.close(parent)


def main(*, _sealed_originals=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("activation sql delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("activation sql requires one exact activated listener")
    from catchplate import oidc_session_activation_execution_dynamic_entrypoint as original_delivery
    incoming = original_delivery._incoming("oidc_session_activation_execution_sql_entrypoint", _sealed_originals)
    inherited = {3, *(item[0] for item in incoming.values())}
    _require_inventory(inherited)
    owned, reservations, retained = inherited, {}, {}
    try:
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("activation sql fixed descriptor slot is occupied")
            reservations[target] = delivery._material_identity(os.fstat(reserved))
        for path, target, maximum in _TRUST_FILES:
            source = (original_delivery._source(path, maximum, incoming)
                if _sealed_originals else _open_material(path, maximum))
            owned.add(source)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            owned.remove(source)
            os.close(source)
        root_raw, _ = _read_original(ROOT_FD, MAX_ROOT_BYTES)
        bootstrap_raw, _ = _read_original(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)
        custody_raw, _ = _read_original(CUSTODY_FD, MAX_CUSTODY_BYTES)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from catchplate import oidc_session_activation_execution_sql_bootstrap as bootstrap
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        work.charge(input_bytes=len(root_raw))
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("activation sql root original must be Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, custody_bytes=custody_raw,
            root_public_key=root, work=work)
        listener_pins = tuple(material.launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = material.launch["journalDirectoryDevice"], material.launch["journalDirectoryInode"]
        if _listener(3) != listener_pins:
            raise RuntimeError("activation sql listener differs from the signed launch")
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("activation sql trust descriptor changed during root admission")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        for path, target, maximum in _KEY_FILES:
            source = _open_material(path, maximum, private=True)
            owned.add(source)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            owned.remove(source)
            os.close(source)
        _keys_on_work(material, work)
        work.charge(hashes=len(material.tls_files),
            input_bytes=sum(record["byteCount"] for record in material.tls_files.values()))
        tls_identity = bootstrap.production._callback(work, lambda: _tls_identity(material.tls_files))
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
        if (reservations or _listener(LISTENER_FD) != listener_pins
                or _journal(JOURNAL_FD) != journal_pins):
            raise RuntimeError("activation sql delivery resource inventory changed")
        for _path, descriptor, maximum in _TRUST_FILES:
            _read_original(descriptor, maximum)
        for _path, descriptor, maximum in _KEY_FILES:
            _sealed_identity(descriptor, maximum, private=True)
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, True)
        _require_inventory(INHERITED_DESCRIPTORS)
        _tls_unchanged(tls_identity)
        environment = dict(ENVIRONMENT)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if (os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups()):
            raise RuntimeError("activation sql identity drop retained privilege")
        delivery._require_unprivileged_process()
        _tls_unchanged(tls_identity)
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("activation sql descriptor changed before exec")
        if _listener(LISTENER_FD) != listener_pins or _journal(JOURNAL_FD) != journal_pins:
            raise RuntimeError("activation sql bound resource changed before exec")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        _require_inventory(INHERITED_DESCRIPTORS)
        os.execve(PYTHON, [PYTHON, "-I", LAUNCHER, "--run"], environment)
        raise RuntimeError("activation sql runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass
