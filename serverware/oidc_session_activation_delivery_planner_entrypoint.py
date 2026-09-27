"""Fixed root delivery for request-bound consume planning, not provisioning.

Original role/history admission precedes private keys and resources. Eleven exact
descriptors survive the permanent identity drop; neither an old role's material
nor an environment-selected path can select this purpose. Trusted-host-local
checks do not establish hardware custody or independent rollback protection.
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


ROOT_PATH = "/run/serverware/oidc-session-activation-delivery-planner-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/serverware/oidc-session-activation-delivery-planner-trust/bootstrap.json"
HISTORY_PATH = "/run/serverware/oidc-session-activation-delivery-planner-trust/history.json"
BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-bundle-key"
DELIVERY_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-key"
KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-planner-key"
JOURNAL_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-journal-key"
JOURNAL_PATH = "/var/lib/serverware/oidc-session-activation-delivery-planner"
EXECUTION_BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-execution-bundle-key"
EXECUTION_STORE_PATH = "/var/lib/serverware/oidc-session-activation-delivery-execution"
LISTENER_PATH = "/run/serverware/oidc-session-activation/delivery-planner.sock"
LISTENER_NAME = "serverware-oidc-session-activation-delivery-planner"
PROCESS_MODE = "oidc-session-activation-delivery-planner"
SERVICE_UID = SERVICE_GID = 65501
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, HISTORY_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD, JOURNAL_KEY_FD, JOURNAL_FD = range(198, 207)
EXECUTION_BUNDLE_KEY_FD, EXECUTION_STORE_FD = 207, 208
INHERITED_DESCRIPTORS = tuple(range(198, 209))
PREFIX = "SERVERWARE_OIDC_SESSION_ACTIVATION_DELIVERY_PLANNER_"
ROOT_ENV, BOOTSTRAP_ENV = PREFIX + "ROOT_PUBLIC_KEY_FD", PREFIX + "BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_delivery_planner_launcher.py"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "SERVERWARE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_HISTORY_BYTES = 16 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024
MAX_KEY_BYTES, MAX_RAW_KEY_BYTES = 4096, 32
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
    (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES), (HISTORY_PATH, HISTORY_FD, MAX_HISTORY_BYTES))
_KEY_FILES = ((KEY_PATH, KEY_FD, MAX_KEY_BYTES), (BUNDLE_KEY_PATH, BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (DELIVERY_KEY_PATH, DELIVERY_KEY_FD, MAX_RAW_KEY_BYTES),
    (JOURNAL_KEY_PATH, JOURNAL_KEY_FD, MAX_RAW_KEY_BYTES),
    (EXECUTION_BUNDLE_KEY_PATH, EXECUTION_BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES))
_MATERIAL = {path: (maximum, private) for private, inventory in
    ((False, _TRUST_FILES), (True, _KEY_FILES)) for path, _descriptor, maximum in inventory}
_TLS_FILES = (
    ("ca", "/run/serverware/oidc-session-activation-delivery-planner-tls/ca.pem", 64 * 1024, False),
    ("clientCertificate", "/run/serverware/oidc-session-activation-delivery-planner-tls/client.crt", 64 * 1024, False),
    ("clientKey", "/run/serverware/oidc-session-activation-delivery-planner-tls/client.key", 16 * 1024, True),
)
_HEX = frozenset("0123456789abcdef")
# Parameter-only primitives: no other role's paths, keys, or verifier are used.
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain
_sealed_identity = sealed_originals._sealed_identity
_read_original = sealed_originals._read_original


def _construction_on_work(work):
    """One real source-max bracket, before root/bootstrap/history I/O."""
    from serverware import oidc_session_activation_delivery_planner_bootstrap as bootstrap

    bootstrap.capture._SharedLedger(work)
    before, epoch, after = bootstrap.clock._sample_on_work(work)
    age, skew = (bootstrap.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
        bootstrap.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    window = bootstrap.clock._validate((epoch, before, after, epoch + age,
        before + age, age, skew))
    return window, window[4]


def _parent(path):
    if path not in (*_MATERIAL, JOURNAL_PATH, EXECUTION_STORE_PATH, LISTENER_PATH, *(item[1] for item in _TLS_FILES)):
        raise RuntimeError("consume planner delivery path is not source fixed")
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
                raise RuntimeError("consume planner ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, private=False):
    if _MATERIAL.get(path) != (maximum, private):
        raise RuntimeError("consume planner original inventory is not source fixed")
    parent, source = _parent(path), None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 2 <= before.st_size <= maximum
                or private and stat.S_IMODE(before.st_mode) != 0o400
                or path in (BUNDLE_KEY_PATH, DELIVERY_KEY_PATH, JOURNAL_KEY_PATH, EXECUTION_BUNDLE_KEY_PATH)
                    and before.st_size != MAX_RAW_KEY_BYTES):
            raise RuntimeError("consume planner original is not protected bounded material")
        original = delivery._read_exact_source(source, before.st_size)
        identity = delivery._material_identity(before)
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("consume planner original changed while reading")
        return delivery._seal_bytes(source, name="serverware-oidc-session-activation-delivery-planner",
            value=original, mode=stat.S_IMODE(before.st_mode))
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _keys_on_work(material, work):
    """Read fixed sealed originals after genuine admission; never serialize keys."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import authority_webauthn_evidence as evidence

    evidence.capture._SharedLedger(work)
    public = material.planner_public_key
    spki = material.payload["planner"]["spkiDigest"]
    expected = (material.history_material.bundle_key_digest,
        material.history_material.delivery_key_digest, material.payload["journalKeyDigest"],
        material.execution_bundle_key_digest)
    work.charge(input_bytes=MAX_KEY_BYTES + 4 * MAX_RAW_KEY_BYTES)
    originals = []
    for _path, descriptor, maximum in _KEY_FILES:
        raw, _identity = evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum:
                _read_original(descriptor, maximum, private=True))
        originals.append(raw)
    signing_bytes, bundle, delivery_key, journal, execution_bundle = originals
    raw_keys = bundle, delivery_key, journal, execution_bundle
    if any(type(key) is not bytes or len(key) != MAX_RAW_KEY_BYTES for key in raw_keys):
        raise RuntimeError("consume planner requires exact raw32 custody keys")
    work.charge(input_bytes=len(raw_keys) * sum(map(len, raw_keys)))
    for index, raw in enumerate(raw_keys):
        if any(raw == other for other in raw_keys[index + 1:]):
            raise RuntimeError("consume planner encryption key purposes coincide")
    for raw, pin in zip(raw_keys, expected):
        work.charge(hashes=1)
        digest = evidence.production._callback(work,
            lambda raw=raw: "sha256:" + hashlib.sha256(raw).hexdigest())
        work.prepare_comparison(digest, pin)
        if digest != pin:
            raise RuntimeError("consume planner encryption key differs from root admission")
    private = evidence.production._callback(work,
        lambda: serialization.load_pem_private_key(signing_bytes, password=None))
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("consume planner signing original must be Ed25519")
    evidence.keys._public_binding(public, spki, work)
    evidence.keys._pair_on_work(private, public, work)
    for _path, descriptor, maximum in _KEY_FILES:
        evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum: _sealed_identity(descriptor, maximum, private=True))
    return private, bundle, delivery_key, journal, execution_bundle


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("consume planner listener differs from fixed activation")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("consume planner listener path protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _directory(descriptor, path):
    if path not in (JOURNAL_PATH, EXECUTION_STORE_PATH):
        raise RuntimeError("consume planner directory purpose is not source fixed")
    value = os.fstat(descriptor)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (SERVICE_UID, SERVICE_GID, 0o700)):
        raise RuntimeError("consume planner private directory protection differs")
    parent = _parent(path)
    try:
        named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode)
                or (named.st_dev, named.st_ino, named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode))
                    != (value.st_dev, value.st_ino, SERVICE_UID, SERVICE_GID, 0o700)):
            raise RuntimeError("consume planner private directory pathname differs from descriptor")
        return value.st_dev, value.st_ino
    finally:
        os.close(parent)


def _journal(descriptor):
    return _directory(descriptor, JOURNAL_PATH)


def _execution_store(descriptor):
    return _directory(descriptor, EXECUTION_STORE_PATH)


def _directory_open(path, device, inode):
    if path not in (JOURNAL_PATH, EXECUTION_STORE_PATH):
        raise RuntimeError("consume planner directory purpose is not source fixed")
    parent, descriptor = _parent(path), None
    try:
        descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_DIRECTORY
            | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        if _directory(descriptor, path) != (device, inode):
            raise RuntimeError("consume planner private directory differs from signed identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _journal_directory(device, inode):
    return _directory_open(JOURNAL_PATH, device, inode)


def _execution_store_directory(device, inode):
    return _directory_open(EXECUTION_STORE_PATH, device, inode)


def _tls_identity(tls_files):
    """Fixed TLS hashes/metadata only; libpq never receives an ambient key path."""
    if type(tls_files) is not dict or set(tls_files) != {item[0] for item in _TLS_FILES}:
        raise RuntimeError("consume planner TLS inventory differs")
    held = []
    for name, path, maximum, private in _TLS_FILES:
        record = tls_files[name]
        if type(record) is not dict or set(record) != {"byteCount", "bytesDigest"}:
            raise RuntimeError("consume planner TLS original fields differ")
        size, digest = record["byteCount"], record["bytesDigest"]
        if (type(size) is not int or not 2 <= size <= maximum
                or type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in _HEX for character in digest[7:])):
            raise RuntimeError("consume planner TLS original pin differs")
        held.append((name, path, size, digest, private))
    identities = []
    for name, path, size, expected, private in tuple(held):
        parent, descriptor = _parent(path), None
        try:
            descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
                | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                    or before.st_size != size or stat.S_IMODE(before.st_mode) != (0o440 if private else 0o444)
                    or private and before.st_gid != SERVICE_GID):
                raise RuntimeError("consume planner TLS original protection differs")
            identity = delivery._material_identity(before)
            if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity:
                raise RuntimeError("consume planner TLS pathname differs")
            digest, remaining = hashlib.sha256(), size
            while remaining:
                chunk = os.read(descriptor, min(4096, remaining))
                if not chunk:
                    raise RuntimeError("consume planner TLS original was truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            if (os.read(descriptor, 1) or "sha256:" + digest.hexdigest() != expected
                    or delivery._material_identity(os.fstat(descriptor)) != identity
                    or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                        follow_symlinks=False)) != identity):
                raise RuntimeError("consume planner TLS original changed")
            identities.append((name, identity, expected))
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
    result = tuple(identities)
    _tls_unchanged(result)
    return result


def _tls_unchanged(expected_identity):
    """Protected fixed-path continuity, not protection against a malicious root."""
    if type(expected_identity) is not tuple or len(expected_identity) != len(_TLS_FILES):
        raise RuntimeError("consume planner held TLS inventory differs")
    held = []
    for (name, path, maximum, private), observed in zip(_TLS_FILES, expected_identity):
        if type(observed) is not tuple or len(observed) != 3:
            raise RuntimeError("consume planner held TLS record differs")
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
            raise RuntimeError("consume planner held TLS identity is invalid")
        held.append((path, identity))
    for path, identity in held:
        parent = _parent(path)
        try:
            if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity:
                raise RuntimeError("consume planner TLS identity changed")
        finally:
            os.close(parent)


def main():
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("consume planner delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("consume planner requires one exact activated listener")
    _require_inventory({3})
    owned, reservations, retained = {3}, {}, {}
    try:
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("consume planner fixed descriptor slot is occupied")
            reservations[target] = delivery._material_identity(os.fstat(reserved))
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import authority_successor_execution_window as windows
        from serverware import oidc_session_activation_delivery_planner_bootstrap as bootstrap
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = _construction_on_work(work)
        current = bootstrap.shared._processing(window, bound, work)
        original_values = []
        for path, target, maximum in _TRUST_FILES:
            current()
            work.charge(input_bytes=2 * maximum)
            source = bootstrap.configuration.production._callback(work,
                lambda path=path, maximum=maximum: _open_material(path, maximum))
            owned.add(source)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            owned.remove(source)
            os.close(source)
            original, _identity = bootstrap.configuration.production._callback(work,
                lambda target=target, maximum=maximum: _read_original(target, maximum))
            original_values.append(original)
            current()
        root_raw, bootstrap_raw, history_raw = original_values
        work.charge(input_bytes=len(root_raw))
        root = bootstrap.configuration.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("consume planner root original must be Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, history_custody_bytes=history_raw,
            root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
        current()
        payload, launch = material.payload, material.payload["launch"]
        window = windows._narrow(window,
            deadline_epoch_ns=min(material.attestation_interval[1], material.history_material.attestation_interval[1]),
            maximum_lifetime_ns=payload["maximumPlanAgeNs"], maximum_clock_skew_ns=payload["maximumClockSkewNs"])
        bound = min(bound, window[4])
        inherited = bootstrap.shared._processing(window, bound, work)
        current = bootstrap.shared._launch_guard(material.attestation_interval,
            material.opening_sample, inherited, work)
        current = bootstrap.shared._launch_guard(material.history_material.attestation_interval,
            material.history_material.opening_sample, current, work)
        current()
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
        execution_store_pins = launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"]
        if _listener(3) != listener_pins:
            raise RuntimeError("consume planner listener differs from signed launch")
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("consume planner trust descriptor changed")
        for path, target, maximum in _KEY_FILES:
            current()
            work.charge(input_bytes=maximum)
            source = bootstrap.configuration.production._callback(work,
                lambda path=path, maximum=maximum: _open_material(path, maximum, private=True))
            owned.add(source)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            owned.remove(source)
            os.close(source)
            current()
        _keys_on_work(material, work)
        current()
        tls_files = payload["tlsFiles"]
        work.charge(hashes=len(tls_files), input_bytes=sum(item["byteCount"] for item in tls_files.values()))
        tls_identity = bootstrap.configuration.production._callback(work, lambda: _tls_identity(tls_files))
        current()
        source = bootstrap.configuration.production._callback(work, lambda: _journal_directory(*journal_pins))
        owned.add(source)
        _retain(source, JOURNAL_FD, reservations, owned)
        retained[JOURNAL_FD] = delivery._material_identity(os.fstat(JOURNAL_FD))
        owned.remove(source)
        os.close(source)
        current()
        source = bootstrap.configuration.production._callback(work,
            lambda: _execution_store_directory(*execution_store_pins))
        owned.add(source)
        _retain(source, EXECUTION_STORE_FD, reservations, owned)
        retained[EXECUTION_STORE_FD] = delivery._material_identity(os.fstat(EXECUTION_STORE_FD))
        owned.remove(source)
        os.close(source)
        current()
        _retain(3, LISTENER_FD, reservations, owned)
        retained[LISTENER_FD] = delivery._material_identity(os.fstat(LISTENER_FD))
        owned.remove(3)
        os.close(3)
        if (reservations or _listener(LISTENER_FD) != listener_pins
                or _journal(JOURNAL_FD) != journal_pins
                or _execution_store(EXECUTION_STORE_FD) != execution_store_pins):
            raise RuntimeError("consume planner delivery inventory changed")
        for _path, descriptor, maximum in (*_TRUST_FILES, *_KEY_FILES):
            private = descriptor in (KEY_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD, JOURNAL_KEY_FD, EXECUTION_BUNDLE_KEY_FD)
            _sealed_identity(descriptor, maximum, private=private)
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, True)
        _require_inventory(INHERITED_DESCRIPTORS)
        _tls_unchanged(tls_identity)
        current()
        environment = dict(ENVIRONMENT)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if (os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups()):
            raise RuntimeError("consume planner identity drop retained privilege")
        delivery._require_unprivileged_process()
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("consume planner descriptor changed before exec")
        if (_listener(LISTENER_FD) != listener_pins or _journal(JOURNAL_FD) != journal_pins
                or _execution_store(EXECUTION_STORE_FD) != execution_store_pins):
            raise RuntimeError("consume planner resource binding changed before exec")
        _tls_unchanged(tls_identity)
        _require_inventory(INHERITED_DESCRIPTORS)
        current()
        os.execve(PYTHON, [PYTHON, "-I", LAUNCHER, "--run"], environment)
        raise RuntimeError("consume planner runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass
