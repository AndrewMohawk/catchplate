"""Fixed cold delivery for activation planning, not provisioning or execution.

Actual root-signed bootstrap admission precedes key, TLS, journal and store access.
Nine exact descriptors survive the permanent identity drop. The dedicated
planner signing key and separate delivery/journal/bundle encryption keys are sealed
originals; libpq uses only independently pinned fixed TLS paths. No password,
new key, directory, listener or deployment authority is synthesized. Protected
host custody is not hardware measurement or independent anti-rollback proof.
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


ROOT_PATH = "/run/catchplate/oidc-session-activation-planner-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/catchplate/oidc-session-activation-planner-trust/bootstrap.json"
JOURNAL_PATH = "/var/lib/catchplate/oidc-session-activation-planner"
EXECUTION_STORE_PATH = "/var/lib/catchplate/oidc-session-activation-execution-bundles"
KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-planner-key"
DELIVERY_KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-delivery-key"
JOURNAL_KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-journal-key"
BUNDLE_KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-bundle-key"
LISTENER_PATH = "/run/catchplate/oidc-session-activation/planner.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-planner"
PROCESS_MODE = "oidc-session-activation-planner"
SERVICE_UID = SERVICE_GID = 65507
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD = 198, 199, 200
KEY_FD, DELIVERY_KEY_FD, JOURNAL_KEY_FD, JOURNAL_FD = 201, 202, 203, 204
BUNDLE_KEY_FD, EXECUTION_STORE_FD = 205, 206
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD,
    DELIVERY_KEY_FD, JOURNAL_KEY_FD, JOURNAL_FD, BUNDLE_KEY_FD, EXECUTION_STORE_FD)
PREFIX = "CATCHPLATE_OIDC_SESSION_ACTIVATION_PLANNER_"
ROOT_ENV = PREFIX + "ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = PREFIX + "BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_planner_launcher.py"
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES = 16 * 1024, 4 * 1024 * 1024
MAX_KEY_BYTES, MAX_RAW_KEY_BYTES = 4096, 32
_KEY_FILES = ((KEY_PATH, KEY_FD, MAX_KEY_BYTES),
    (DELIVERY_KEY_PATH, DELIVERY_KEY_FD, MAX_RAW_KEY_BYTES),
    (JOURNAL_KEY_PATH, JOURNAL_KEY_FD, MAX_RAW_KEY_BYTES),
    (BUNDLE_KEY_PATH, BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES))
_TLS_FILES = (
    ("ca", "/run/catchplate/oidc-session-activation-planner-tls/ca.pem", 64 * 1024, False),
    ("clientCertificate", "/run/catchplate/oidc-session-activation-planner-tls/client.crt", 64 * 1024, False),
    ("clientKey", "/run/catchplate/oidc-session-activation-planner-tls/client.key", 16 * 1024, True),
)
_HEX = frozenset("0123456789abcdef")
# Parameter-only helpers; none selects another role's paths or environment.
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain
_sealed_identity = sealed_originals._sealed_identity
_read_original = sealed_originals._read_original


def _parent(path):
    allowed = (ROOT_PATH, BOOTSTRAP_PATH, JOURNAL_PATH, EXECUTION_STORE_PATH, LISTENER_PATH,
        KEY_PATH, DELIVERY_KEY_PATH, JOURNAL_KEY_PATH, BUNDLE_KEY_PATH, *(item[1] for item in _TLS_FILES))
    if path not in allowed:
        raise RuntimeError("activation planner delivery path is not source fixed")
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
                raise RuntimeError("activation planner ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, private=False):
    if (path not in (ROOT_PATH, BOOTSTRAP_PATH, KEY_PATH, DELIVERY_KEY_PATH, JOURNAL_KEY_PATH, BUNDLE_KEY_PATH)
            or private != (path in (KEY_PATH, DELIVERY_KEY_PATH, JOURNAL_KEY_PATH, BUNDLE_KEY_PATH))):
        raise RuntimeError("activation planner original path is not source fixed")
    parent = _parent(path)
    source = None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 2 <= before.st_size <= maximum
                or private and stat.S_IMODE(before.st_mode) != 0o400
                or path in (DELIVERY_KEY_PATH, JOURNAL_KEY_PATH, BUNDLE_KEY_PATH)
                    and before.st_size != MAX_RAW_KEY_BYTES):
            raise RuntimeError("activation planner original is not protected bounded material")
        original = delivery._read_exact_source(source, before.st_size)
        if delivery._material_identity(before) != delivery._material_identity(os.fstat(source)):
            raise RuntimeError("activation planner original changed while reading")
        return delivery._seal_bytes(source, name="catchplate-oidc-session-activation-planner",
            value=original, mode=stat.S_IMODE(before.st_mode))
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _keys_on_work(material, work):
    """Load actual sealed keys and join pins after genuine bootstrap admission.

    This parameter-only composition authenticates no bootstrap or caller. Its
    root and unprivileged callers retain the original launch/window checks.
    Plaintext is never logged or returned over the service protocol.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from catchplate import authority_webauthn_evidence as evidence

    evidence.capture._SharedLedger(work)
    public, spki = material.planner_public_key, material.planner_spki_digest
    expected_delivery, expected_journal, expected_bundle = (
        material.delivery_key_digest, material.journal_key_digest, material.bundle_key_digest)
    # Reserve the complete fixed read inventory before reading any key. There
    # is no caller-selected path or size and no second work allowance.
    work.charge(input_bytes=MAX_KEY_BYTES + 3 * MAX_RAW_KEY_BYTES)
    originals = []
    for _path, descriptor, maximum in _KEY_FILES:
        raw, _identity = evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum:
                _read_original(descriptor, maximum, private=True))
        originals.append(raw)
    signing_bytes, delivery_key, journal_key, bundle_key = originals
    if any(type(key) is not bytes or len(key) != MAX_RAW_KEY_BYTES
            for key in (delivery_key, journal_key, bundle_key)):
        raise RuntimeError("activation planner encryption keys must be exact raw32 originals")
    work.charge(input_bytes=3 * (len(delivery_key) + len(journal_key) + len(bundle_key)))
    if delivery_key == journal_key or delivery_key == bundle_key or journal_key == bundle_key:
        raise RuntimeError("activation planner delivery, journal and bundle keys must differ")
    for raw, expected in ((delivery_key, expected_delivery), (journal_key, expected_journal),
            (bundle_key, expected_bundle)):
        work.charge(hashes=1)
        digest = evidence.production._callback(work, lambda raw=raw: "sha256:" + hashlib.sha256(raw).hexdigest())
        if digest != expected:
            raise RuntimeError("activation planner encryption key differs from its signed pin")
    private = evidence.production._callback(work,
        lambda: serialization.load_pem_private_key(signing_bytes, password=None))
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("activation planner signing original must be Ed25519")
    evidence.keys._public_binding(public, spki, work)
    evidence.keys._pair_on_work(private, public, work)
    for _path, descriptor, maximum in _KEY_FILES:
        evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum: _sealed_identity(descriptor, maximum, private=True))
    return private, delivery_key, journal_key, bundle_key


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("activation planner listener differs from the fixed activated socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        path = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(path.st_mode) or path.st_nlink != 1
                or (path.st_uid, path.st_gid, stat.S_IMODE(path.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("activation planner socket path ownership differs")
        return value.st_dev, value.st_ino, path.st_dev, path.st_ino
    finally:
        os.close(parent)


def _directory(descriptor, fixed_path):
    if fixed_path not in (JOURNAL_PATH, EXECUTION_STORE_PATH):
        raise RuntimeError("activation planner directory path is not source fixed")
    value = os.fstat(descriptor)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (SERVICE_UID, SERVICE_GID, 0o700)):
        raise RuntimeError("activation planner private directory ownership or mode differs")
    parent = _parent(fixed_path)
    try:
        path = os.stat(os.path.basename(fixed_path), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(path.st_mode)
                or (path.st_dev, path.st_ino, path.st_uid, path.st_gid, stat.S_IMODE(path.st_mode))
                    != (value.st_dev, value.st_ino, SERVICE_UID, SERVICE_GID, 0o700)):
            raise RuntimeError("activation planner private directory pathname differs from its descriptor")
        return value.st_dev, value.st_ino
    finally:
        os.close(parent)


def _journal(descriptor):
    return _directory(descriptor, JOURNAL_PATH)


def _execution_store(descriptor):
    return _directory(descriptor, EXECUTION_STORE_PATH)


def _open_directory(fixed_path, device, inode):
    if fixed_path not in (JOURNAL_PATH, EXECUTION_STORE_PATH):
        raise RuntimeError("activation planner directory open is not source fixed")
    parent = _parent(fixed_path)
    descriptor = None
    try:
        descriptor = os.open(os.path.basename(fixed_path), os.O_RDONLY | os.O_DIRECTORY
            | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        if _directory(descriptor, fixed_path) != (device, inode):
            raise RuntimeError("activation planner private directory differs from its signed identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _journal_directory(device, inode):
    return _open_directory(JOURNAL_PATH, device, inode)


def _execution_store_directory(device, inode):
    return _open_directory(EXECUTION_STORE_PATH, device, inode)


def _tls_identity(tls_files):
    """Hash source-fixed TLS originals, retaining identity/pins, never contents.

    Keys are root-owned 0440 with group 65507 for libpq reopening after the
    permanent drop. Public files are root-owned 0444. These local checks do not
    authenticate a TLS identity or protect against a malicious root writer.
    """
    if type(tls_files) is not dict or set(tls_files) != {item[0] for item in _TLS_FILES}:
        raise RuntimeError("activation planner TLS inventory is not source fixed")
    pins = []
    for name, path, maximum, private in _TLS_FILES:
        record = tls_files[name]
        if type(record) is not dict or set(record) != {"byteCount", "bytesDigest"}:
            raise RuntimeError("activation planner TLS original pin fields differ")
        size, digest = record["byteCount"], record["bytesDigest"]
        if (type(size) is not int or not 2 <= size <= maximum
                or type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in _HEX for character in digest[7:])):
            raise RuntimeError("activation planner TLS original pin is invalid")
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
                raise RuntimeError("activation planner TLS file protection or size differs")
            identity = delivery._material_identity(before)
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if delivery._material_identity(named) != identity:
                raise RuntimeError("activation planner TLS pathname differs from its descriptor")
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = os.read(descriptor, min(4096, remaining))
                if not chunk:
                    raise RuntimeError("activation planner TLS original was truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise RuntimeError("activation planner TLS original grew while reading")
            after = os.fstat(descriptor)
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if (delivery._material_identity(after) != identity
                    or delivery._material_identity(named) != identity
                    or "sha256:" + digest.hexdigest() != expected_digest):
                raise RuntimeError("activation planner TLS original identity or digest changed")
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
        raise RuntimeError("activation planner TLS identity inventory differs")
    held = []
    for (name, path, maximum, private), observed in zip(_TLS_FILES, expected_identity):
        if type(observed) is not tuple or len(observed) != 3:
            raise RuntimeError("activation planner TLS identity record differs")
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
            raise RuntimeError("activation planner held TLS identity is invalid")
        held.append((path, identity))
    # Recheck earlier paths after later originals were hashed. No re-reading
    # private key bytes on this metadata-only continuity path.
    for path, identity in held:
        parent = _parent(path)
        try:
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if delivery._material_identity(named) != identity:
                raise RuntimeError("activation planner TLS inventory changed while checking")
        finally:
            os.close(parent)


def main():
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("activation planner delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("activation planner requires one exact socket activation")
    _require_inventory({3})
    owned, reservations, retained = {3}, {}, {}
    try:
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("activation planner fixed FD slot is occupied")
            reservations[target] = delivery._material_identity(os.fstat(reserved))
        for path, target, maximum in ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
                (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)):
            source = _open_material(path, maximum)
            owned.add(source)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            owned.remove(source)
            os.close(source)
        root_raw, _ = _read_original(ROOT_FD, MAX_ROOT_BYTES)
        bootstrap_raw, _ = _read_original(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from catchplate import oidc_session_activation_planner_bootstrap as bootstrap
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        root = serialization.load_pem_public_key(root_raw)
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("activation planner root key must be Ed25519")
        work = _ValidationWork(QueryReadValidationLimits())
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
        store_pins = launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"]
        if (journal_pins == store_pins or launch["journalDirectoryPath"] != JOURNAL_PATH
                or launch["executionStoreDirectoryPath"] != EXECUTION_STORE_PATH
                or launch["bundleKeyFd"] != BUNDLE_KEY_FD
                or launch["executionStoreDirectoryFd"] != EXECUTION_STORE_FD):
            raise RuntimeError("activation planner store or key scope differs from fixed distinct custody")
        if _listener(3) != listener_pins:
            raise RuntimeError("activation planner listener differs from its original root assertion")
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("activation planner trust original changed during root admission")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        for path, target, maximum in _KEY_FILES:
            source = _open_material(path, maximum, private=True)
            owned.add(source)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            owned.remove(source)
            os.close(source)
        _keys_on_work(material, work)
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        tls_identity = _tls_identity(material.tls_files)
        for opener, target, pins in ((_journal_directory, JOURNAL_FD, journal_pins),
                (_execution_store_directory, EXECUTION_STORE_FD, store_pins)):
            source = opener(*pins)
            owned.add(source)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            owned.remove(source)
            os.close(source)
        _retain(3, LISTENER_FD, reservations, owned)
        retained[LISTENER_FD] = delivery._material_identity(os.fstat(LISTENER_FD))
        owned.remove(3)
        os.close(3)
        if (reservations or _listener(LISTENER_FD) != listener_pins
                or _journal(JOURNAL_FD) != journal_pins or _execution_store(EXECUTION_STORE_FD) != store_pins):
            raise RuntimeError("activation planner delivery inventory or bound path changed")
        for descriptor, maximum in ((ROOT_FD, MAX_ROOT_BYTES), (BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES)):
            _read_original(descriptor, maximum)
        for _path, descriptor, maximum in _KEY_FILES:
            _sealed_identity(descriptor, maximum, private=True)
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
            raise RuntimeError("activation planner identity drop retained privilege")
        delivery._require_unprivileged_process()
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("activation planner descriptor changed before exec")
        if _journal(JOURNAL_FD) != journal_pins or _execution_store(EXECUTION_STORE_FD) != store_pins:
            raise RuntimeError("activation planner private directory binding changed before exec")
        _tls_unchanged(tls_identity)
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        _require_inventory(INHERITED_DESCRIPTORS)
        os.execve(PYTHON, [PYTHON, "-I", LAUNCHER, "--run"], environment)
        raise RuntimeError("activation planner runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass
