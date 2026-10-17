"""Fixed protected delivery for the dedicated activation completion process.

Genuine role/history admission precedes signing/AES keys, TLS and journal.
Seven exact descriptors survive an irreversible identity drop. This code does
not provision files, accounts, permissions, checkpoints or completion authority.
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


ROOT_PATH = "/run/catchplate/oidc-session-activation-completion-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/catchplate/oidc-session-activation-completion-trust/bootstrap.json"
KEY_PATH = "/run/catchplate/oidc-session-activation-completion-key/completion.pem"
BUNDLE_KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-bundle-key"
DELIVERY_KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-delivery-key"
JOURNAL_PATH = "/var/lib/catchplate/oidc-session-activation-completions"
LISTENER_PATH = "/run/catchplate/oidc-session-activation/completion.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-completion"
PROCESS_MODE = "oidc-session-activation-completion"
SERVICE_UID = SERVICE_GID = 65503
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD = range(198, 205)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD)
PREFIX = "CATCHPLATE_OIDC_SESSION_ACTIVATION_COMPLETION_"
ROOT_ENV, BOOTSTRAP_ENV = PREFIX + "ROOT_PUBLIC_KEY_FD", PREFIX + "BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_completion_launcher.py"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "CATCHPLATE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_KEY_BYTES, MAX_RAW_KEY_BYTES = 16 * 1024, 16 * 1024 * 1024, 4096, 32
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES), (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES))
_KEY_FILES = ((KEY_PATH, KEY_FD, MAX_KEY_BYTES), (BUNDLE_KEY_PATH, BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (DELIVERY_KEY_PATH, DELIVERY_KEY_FD, MAX_RAW_KEY_BYTES))
_MATERIAL = {path: (maximum, private) for private, inventory in
    ((False, _TRUST_FILES), (True, _KEY_FILES)) for path, _descriptor, maximum in inventory}
_TLS_FILES = (
    ("ca", "/run/catchplate/oidc-session-activation-completion-tls/ca.pem", 64 * 1024, False),
    ("custodyCertificate", "/run/catchplate/oidc-session-activation-completion-tls/custody.crt", 64 * 1024, False),
    ("custodyKey", "/run/catchplate/oidc-session-activation-completion-tls/custody.key", 16 * 1024, True),
    ("commitCertificate", "/run/catchplate/oidc-session-activation-completion-tls/commit.crt", 64 * 1024, False),
    ("commitKey", "/run/catchplate/oidc-session-activation-completion-tls/commit.key", 16 * 1024, True),
)
_HEX = frozenset("0123456789abcdef")
# Explicit-descriptor neutral helpers only: no other role's paths or verifier.
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain
_sealed_identity = sealed_originals._sealed_identity
_read_original = sealed_originals._read_original


def _parent(path):
    if path not in (*_MATERIAL, JOURNAL_PATH, LISTENER_PATH, *(item[1] for item in _TLS_FILES)):
        raise RuntimeError("activation completion path is not source fixed")
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
                raise RuntimeError("activation completion ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, private=False):
    if path not in _MATERIAL or _MATERIAL[path] != (maximum, private) or type(private) is not bool:
        raise RuntimeError("activation completion material inventory differs")
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
            raise RuntimeError("activation completion original protection or bounds differ")
        identity = delivery._material_identity(before)
        if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)) != identity:
            raise RuntimeError("activation completion original pathname differs")
        raw = delivery._read_exact_source(source, before.st_size)
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("activation completion original changed during read")
        return delivery._seal_bytes(source, name="catchplate-oidc-activation-completion",
            value=raw, mode=stat.S_IMODE(before.st_mode))
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _keys_on_work(material, work):
    """Actual completion signer and separately pinned historical AES originals."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from catchplate import authority_oidc_session_activation_history_custody as custody

    evidence = custody.evidence
    evidence.capture._SharedLedger(work)
    work.charge(input_bytes=MAX_KEY_BYTES + 2 * MAX_RAW_KEY_BYTES)
    originals, identities = [], []
    for _path, descriptor, maximum in _KEY_FILES:
        raw, identity = evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum: _read_original(descriptor, maximum, private=True))
        originals.append(raw)
        identities.append((descriptor, maximum, identity))
    signing_raw, bundle_key, delivery_key = originals
    if any(type(raw) is not bytes or len(raw) != MAX_RAW_KEY_BYTES for raw in (bundle_key, delivery_key)):
        raise RuntimeError("activation completion AES originals must be raw32")
    custody._key_bindings(material.custody_material, bundle_key, delivery_key, work)
    private = evidence.production._callback(work, lambda: serialization.load_pem_private_key(signing_raw, password=None))
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("activation completion signing original must be Ed25519")
    evidence.keys._public_binding(material.completion_public_key, material.completion_spki_digest, work)
    evidence.keys._pair_on_work(private, material.completion_public_key, work)
    for descriptor, maximum, identity in identities:
        actual = evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum: _sealed_identity(descriptor, maximum, private=True))
        if actual != identity:
            raise RuntimeError("activation completion private descriptor changed")
    return private, bundle_key, delivery_key


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("activation completion listener differs from fixed socket activation")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("activation completion socket path protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _journal(descriptor):
    value = os.fstat(descriptor)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (SERVICE_UID, SERVICE_GID, 0o700)):
        raise RuntimeError("activation completion journal protection differs")
    parent = _parent(JOURNAL_PATH)
    try:
        named = os.stat(os.path.basename(JOURNAL_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode) or named.st_nlink < 1
                or (named.st_dev, named.st_ino, named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode))
                    != (value.st_dev, value.st_ino, SERVICE_UID, SERVICE_GID, 0o700)):
            raise RuntimeError("activation completion journal pathname differs")
        return value.st_dev, value.st_ino
    finally:
        os.close(parent)


def _journal_directory(device, inode):
    parent, descriptor = _parent(JOURNAL_PATH), None
    try:
        descriptor = os.open(os.path.basename(JOURNAL_PATH), os.O_RDONLY | os.O_DIRECTORY
            | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        if _journal(descriptor) != (device, inode):
            raise RuntimeError("activation completion journal differs from signed identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _tls_identity(tls_files):
    """Bounded fixed TLS reads; root0444 publics, root:65503 0440 keys."""
    if type(tls_files) is not dict or set(tls_files) != {item[0] for item in _TLS_FILES}:
        raise RuntimeError("activation completion TLS inventory differs")
    pins = []
    for name, path, maximum, private in _TLS_FILES:
        record = tls_files[name]
        if type(record) is not dict or set(record) != {"byteCount", "bytesDigest"}:
            raise RuntimeError("activation completion TLS pin fields differ")
        size, digest = record["byteCount"], record["bytesDigest"]
        if (type(size) is not int or not 2 <= size <= maximum
                or type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in _HEX for character in digest[7:])):
            raise RuntimeError("activation completion TLS pin is invalid")
        pins.append((name, path, size, digest, private))
    held, identities = tuple(pins), []
    for name, path, size, expected, private in held:
        parent, descriptor = _parent(path), None
        try:
            descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
                | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                    or before.st_size != size or stat.S_IMODE(before.st_mode) != (0o440 if private else 0o444)
                    or private and before.st_gid != SERVICE_GID):
                raise RuntimeError("activation completion TLS original protection differs")
            identity = delivery._material_identity(before)
            if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)) != identity:
                raise RuntimeError("activation completion TLS pathname differs")
            digest, remaining = hashlib.sha256(), size
            while remaining:
                chunk = os.read(descriptor, min(4096, remaining))
                if not chunk:
                    raise RuntimeError("activation completion TLS original truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            if (os.read(descriptor, 1) or "sha256:" + digest.hexdigest() != expected
                    or delivery._material_identity(os.fstat(descriptor)) != identity
                    or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                        follow_symlinks=False)) != identity):
                raise RuntimeError("activation completion TLS original changed")
            identities.append((name, identity, expected))
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
    result = tuple(identities)
    _tls_unchanged(result)
    return result


def _tls_unchanged(expected_identity):
    """Fixed-path metadata continuity, not hostile-root protection."""
    if type(expected_identity) is not tuple or len(expected_identity) != len(_TLS_FILES):
        raise RuntimeError("activation completion held TLS inventory differs")
    held = []
    for (name, path, maximum, private), observed in zip(_TLS_FILES, expected_identity):
        if type(observed) is not tuple or len(observed) != 3:
            raise RuntimeError("activation completion held TLS record differs")
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
            raise RuntimeError("activation completion held TLS identity is invalid")
        held.append((path, identity))
    for path, identity in held:
        parent = _parent(path)
        try:
            if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)) != identity:
                raise RuntimeError("activation completion TLS identity changed")
        finally:
            os.close(parent)


def main(*, _sealed_originals=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("activation completion delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("activation completion requires one exact activated listener")
    from catchplate import oidc_session_activation_execution_dynamic_entrypoint as original_delivery
    incoming = original_delivery._incoming("oidc_session_activation_completion_entrypoint", _sealed_originals)
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
                raise RuntimeError("activation completion fixed descriptor slot is occupied")
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
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from catchplate import oidc_session_activation_completion_bootstrap as bootstrap
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        work.charge(input_bytes=len(root_raw))
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("activation completion root original must be Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
        listener_pins = tuple(material.launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = material.launch["journalDirectoryDevice"], material.launch["journalDirectoryInode"]
        if _listener(3) != listener_pins:
            raise RuntimeError("activation completion listener differs from signed launch")
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("activation completion trust descriptor changed")
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
        work.charge(hashes=len(material.tls_files), input_bytes=sum(item["byteCount"] for item in material.tls_files.values()))
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
        if reservations or _listener(LISTENER_FD) != listener_pins or _journal(JOURNAL_FD) != journal_pins:
            raise RuntimeError("activation completion resource inventory changed")
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
            raise RuntimeError("activation completion identity drop retained privilege")
        delivery._require_unprivileged_process()
        _tls_unchanged(tls_identity)
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("activation completion descriptor changed before exec")
        if _listener(LISTENER_FD) != listener_pins or _journal(JOURNAL_FD) != journal_pins:
            raise RuntimeError("activation completion bound resource changed before exec")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        _require_inventory(INHERITED_DESCRIPTORS)
        os.execve(PYTHON, [PYTHON, "-I", LAUNCHER, "--run"], environment)
        raise RuntimeError("activation completion runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass
