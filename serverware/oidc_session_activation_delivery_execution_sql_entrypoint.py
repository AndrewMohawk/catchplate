"""Fixed eleven-FD consume SQL delivery with one original construction bound.

Only actual root originals admit resources. The same isolated process drops
permanently before continuing startup; no key, journal or database is created.
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


ROOT_PATH = "/run/serverware/oidc-session-activation-delivery-execution-sql-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/serverware/oidc-session-activation-delivery-execution-sql-trust/bootstrap.json"
CUSTODY_PATH = "/run/serverware/oidc-session-activation-delivery-execution-sql-trust/custody.json"
PLANNER_BOOTSTRAP_PATH = "/run/serverware/oidc-session-activation-delivery-execution-sql-trust/planner-bootstrap.json"
PLANNER_HISTORY_CUSTODY_PATH = "/run/serverware/oidc-session-activation-delivery-execution-sql-trust/planner-history-custody.json"
RECEIVING_HISTORY_CUSTODY_PATH = "/run/serverware/oidc-session-activation-delivery-execution-sql-trust/receiving-history-custody.json"
EXECUTION_BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-execution-sql-execution-bundle-key"
HISTORICAL_BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-execution-sql-historical-bundle-key"
DELIVERY_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-execution-sql-delivery-key"
LISTENER_PATH = "/run/serverware/oidc-session-activation-delivery-execution/sql.sock"
LISTENER_NAME = "serverware-oidc-session-activation-delivery-execution-sql"
JOURNAL_PATH = "/var/lib/serverware/oidc-session-activation-delivery-execution-sql-attempts"
PROCESS_MODE = "oidc-session-activation-delivery-execution-sql"
SERVICE_UID = SERVICE_GID = 65498
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD = 198, 199, 200, 201
PLANNER_BOOTSTRAP_FD, PLANNER_HISTORY_CUSTODY_FD, RECEIVING_HISTORY_CUSTODY_FD = 202, 203, 204
EXECUTION_BUNDLE_KEY_FD, HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD, JOURNAL_FD = 205, 206, 207, 208
INHERITED_DESCRIPTORS = tuple(range(198, 209))
PREFIX = "SERVERWARE_OIDC_SESSION_ACTIVATION_DELIVERY_EXECUTION_SQL_"
ROOT_ENV, BOOTSTRAP_ENV = PREFIX + "ROOT_PUBLIC_KEY_FD", PREFIX + "BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_delivery_execution_sql_launcher.py"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "SERVERWARE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_CUSTODY_BYTES = 16 * 1024, 4 * 1024 * 1024, 16 * 1024
MAX_PLANNER_BOOTSTRAP_BYTES = 4 * 1024 * 1024
MAX_PLANNER_HISTORY_CUSTODY_BYTES = MAX_RECEIVING_HISTORY_CUSTODY_BYTES = 8 * 1024 * 1024
MAX_RAW_KEY_BYTES = 32
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
    (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES),
    (CUSTODY_PATH, CUSTODY_FD, MAX_CUSTODY_BYTES),
    (PLANNER_BOOTSTRAP_PATH, PLANNER_BOOTSTRAP_FD, MAX_PLANNER_BOOTSTRAP_BYTES),
    (PLANNER_HISTORY_CUSTODY_PATH, PLANNER_HISTORY_CUSTODY_FD, MAX_PLANNER_HISTORY_CUSTODY_BYTES),
    (RECEIVING_HISTORY_CUSTODY_PATH, RECEIVING_HISTORY_CUSTODY_FD, MAX_RECEIVING_HISTORY_CUSTODY_BYTES))
_KEY_FILES = ((EXECUTION_BUNDLE_KEY_PATH, EXECUTION_BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (HISTORICAL_BUNDLE_KEY_PATH, HISTORICAL_BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (DELIVERY_KEY_PATH, DELIVERY_KEY_FD, MAX_RAW_KEY_BYTES))
_MATERIAL = {path: (maximum, private) for private, inventory in
    ((False, _TRUST_FILES), (True, _KEY_FILES)) for path, _descriptor, maximum in inventory}
_TLS_FILES = (
    ("ca", "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/ca.pem", 64 * 1024, False),
    ("issuerCertificate", "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/issuer.crt", 64 * 1024, False),
    ("issuerKey", "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/issuer.key", 16 * 1024, True),
    ("executorCertificate", "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/executor.crt", 64 * 1024, False),
    ("executorKey", "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/executor.key", 16 * 1024, True),
)
_HEX = frozenset("0123456789abcdef")
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain
_sealed_identity = sealed_originals._sealed_identity
_read_original = sealed_originals._read_original


def _construction_on_work(work):
    from serverware import oidc_session_activation_delivery_execution_sql_bootstrap as bootstrap

    return bootstrap._construction_on_work(work)


def _parent(path):
    if path not in (*_MATERIAL, LISTENER_PATH, JOURNAL_PATH, *(item[1] for item in _TLS_FILES)):
        raise RuntimeError("consume SQL path is not source fixed")
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
                raise RuntimeError("consume SQL ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, work, private=False, maximum_capture_bytes=None):
    if path not in _MATERIAL or _MATERIAL[path] != (maximum, private) or type(private) is not bool:
        raise RuntimeError("consume SQL original inventory changed")
    parent, source = _parent(path), None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 2 <= before.st_size <= maximum
                or private and (stat.S_IMODE(before.st_mode) != 0o400 or before.st_size != MAX_RAW_KEY_BYTES)):
            raise RuntimeError("consume SQL original is not protected bounded material")
        identity = delivery._material_identity(before)
        if maximum_capture_bytes is not None and (
                type(maximum_capture_bytes) is not int or maximum_capture_bytes <= 0
                or 16 * before.st_size > maximum_capture_bytes):
            raise RuntimeError("consume execution original exceeds remaining cold capture capacity")
        named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if delivery._material_identity(named) != identity:
            raise RuntimeError("consume SQL original pathname differs")
        work.charge(input_bytes=2 * before.st_size)
        raw = delivery._read_exact_source(source, before.st_size)
        named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(named) != identity):
            raise RuntimeError("consume SQL original changed during read")
        return delivery._seal_bytes(source, name="serverware-oidc-consume-sql",
            value=raw, mode=stat.S_IMODE(before.st_mode))
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _read_on_work(descriptor, maximum, work, *, private=False):
    from serverware import authority_revocation_capability_production as production

    identity = _sealed_identity(descriptor, maximum, private=private)
    work.charge(input_bytes=identity[0][6])
    raw, observed = production._callback(work,
        lambda: _read_original(descriptor, maximum, private=private))
    if observed != identity:
        raise RuntimeError("consume SQL sealed original changed before its charged read")
    return raw, identity


def _keys_on_work(material, work):
    """No signing key: admit only the three exact sealed root-pinned AES keys."""
    from serverware import authority_oidc_session_activation_delivery_execution_custody as custody

    custody.evidence.capture._SharedLedger(work)
    originals, identities = [], []
    for _path, descriptor, maximum in _KEY_FILES:
        raw, identity = _read_on_work(descriptor, maximum, work, private=True)
        originals.append(raw)
        identities.append((descriptor, maximum, identity))
    execution, historical, delivery_key = originals
    if any(type(raw) is not bytes or len(raw) != MAX_RAW_KEY_BYTES for raw in originals):
        raise RuntimeError("consume SQL encryption originals must be raw32")
    custody._key_bindings(material.custody_material, execution, historical, delivery_key, work)
    for descriptor, maximum, identity in identities:
        observed = custody.evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum: _sealed_identity(descriptor, maximum, private=True))
        if observed != identity:
            raise RuntimeError("consume SQL key descriptor changed during admission")
    return execution, historical, delivery_key


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("consume SQL listener differs from fixed socket activation")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("consume SQL socket path protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _journal(descriptor):
    """Check the existing attempt directory and its signed path, without writes."""
    value = os.fstat(descriptor)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (SERVICE_UID, SERVICE_GID, 0o700)):
        raise RuntimeError("consume SQL attempt journal ownership or mode differs")
    parent = _parent(JOURNAL_PATH)
    try:
        named = os.stat(os.path.basename(JOURNAL_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode) or named.st_nlink < 1
                or (named.st_dev, named.st_ino, named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode))
                    != (value.st_dev, value.st_ino, SERVICE_UID, SERVICE_GID, 0o700)):
            raise RuntimeError("consume SQL journal pathname differs from its descriptor")
        return value.st_dev, value.st_ino
    finally:
        os.close(parent)


def _journal_directory(device, inode):
    parent, descriptor = _parent(JOURNAL_PATH), None
    try:
        descriptor = os.open(os.path.basename(JOURNAL_PATH), os.O_RDONLY | os.O_DIRECTORY
            | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        if _journal(descriptor) != (device, inode):
            raise RuntimeError("consume SQL journal differs from its signed identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def _tls_identity(tls_files, *, work):
    """Charge actual lengths before native hashing; retain no TLS file contents."""
    from serverware import authority_revocation_capability_production as production

    if type(tls_files) is not dict or set(tls_files) != {item[0] for item in _TLS_FILES}:
        raise RuntimeError("consume SQL TLS inventory is not source fixed")
    pins = []
    for name, path, maximum, private in _TLS_FILES:
        record = tls_files[name]
        if type(record) is not dict or set(record) != {"byteCount", "bytesDigest"}:
            raise RuntimeError("consume SQL TLS original pin fields differ")
        size, digest = record["byteCount"], record["bytesDigest"]
        if (type(size) is not int or not 2 <= size <= maximum
                or type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in _HEX for character in digest[7:])):
            raise RuntimeError("consume SQL TLS original pin is invalid")
        pins.append((name, path, size, digest, private))
    held, identities = tuple(pins), []
    for name, path, size, expected_digest, private in held:
        parent, descriptor = _parent(path), None
        try:
            descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
                | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                    or before.st_size != size
                    or stat.S_IMODE(before.st_mode) != (0o440 if private else 0o444)
                    or private and before.st_gid != SERVICE_GID):
                raise RuntimeError("consume SQL TLS file protection or size differs")
            identity = delivery._material_identity(before)
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if delivery._material_identity(named) != identity:
                raise RuntimeError("consume SQL TLS pathname differs from its descriptor")
            work.charge(hashes=1, input_bytes=before.st_size)

            def read_digest():
                digest, remaining = hashlib.sha256(), size
                while remaining:
                    chunk = os.read(descriptor, min(4096, remaining))
                    if not chunk:
                        raise RuntimeError("consume SQL TLS original was truncated")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if os.read(descriptor, 1):
                    raise RuntimeError("consume SQL TLS original grew while reading")
                return "sha256:" + digest.hexdigest()

            actual_digest = production._callback(work, read_digest)
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if (delivery._material_identity(os.fstat(descriptor)) != identity
                    or delivery._material_identity(named) != identity or actual_digest != expected_digest):
                raise RuntimeError("consume SQL TLS original identity or digest changed")
            identities.append((name, identity, expected_digest))
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
    observed = tuple(identities)
    _tls_unchanged(observed)
    return observed


def _tls_unchanged(expected_identity):
    """Fixed-path metadata continuity only, not hostile-root race protection."""
    if type(expected_identity) is not tuple or len(expected_identity) != len(_TLS_FILES):
        raise RuntimeError("consume SQL TLS identity inventory differs")
    held = []
    for (name, path, maximum, private), observed in zip(_TLS_FILES, expected_identity):
        if type(observed) is not tuple or len(observed) != 3:
            raise RuntimeError("consume SQL TLS identity record differs")
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
            raise RuntimeError("consume SQL held TLS identity is invalid")
        held.append((path, identity))
    for path, identity in held:
        parent = _parent(path)
        try:
            named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            if delivery._material_identity(named) != identity:
                raise RuntimeError("consume SQL TLS inventory changed while checking")
        finally:
            os.close(parent)


def main(*, _sealed_originals=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("consume SQL delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("consume SQL requires one exact activated listener")
    from serverware import oidc_session_activation_execution_dynamic_entrypoint as original_delivery
    incoming = original_delivery._incoming("oidc_session_activation_delivery_execution_sql_entrypoint", _sealed_originals)
    inherited = {3, *(item[0] for item in incoming.values())}
    _require_inventory(inherited)
    owned, reservations, retained = inherited, {}, {}
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import oidc_session_activation_delivery as lifetime
        from serverware import oidc_session_activation_delivery_execution_sql_bootstrap as bootstrap
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = _construction_on_work(work)
        _window, current = lifetime._window(window, bound, work)
        current()
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("consume SQL fixed descriptor slot is occupied")
            reservations[target] = delivery._material_identity(os.fstat(reserved))
        capture_remaining = bootstrap.receiving.MAX_ORIGINALS_BYTES - bootstrap.receiving.INTAKE_METADATA_BYTES
        for path, target, maximum in _TRUST_FILES:
            current()
            source = (original_delivery._source(path, maximum, incoming, work=work, maximum_capture_bytes=capture_remaining)
                if _sealed_originals else _open_material(path, maximum, work=work, maximum_capture_bytes=capture_remaining))
            owned.add(source)
            current()
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            capture_remaining -= 16 * retained[target][6]
            os.close(source)
            owned.remove(source)
        originals = []
        for _path, descriptor, maximum in _TRUST_FILES:
            current()
            raw, _identity = _read_on_work(descriptor, maximum, work)
            originals.append(raw)
            current()
        root_raw, bootstrap_raw, custody_raw, planner_raw, planning_raw, receiving_raw = originals
        bootstrap.receiving._intake_reservation(tuple(map(len, originals)))
        root = bootstrap.primitives.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("consume SQL root original must be Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, custody_bytes=custody_raw,
            planner_bootstrap_bytes=planner_raw, planner_history_custody_bytes=planning_raw,
            receiving_history_custody_bytes=receiving_raw, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work)
        current()
        launch = material.launch
        fields = ("processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
            "rootPublicKeyFd", "bootstrapFd", "listenerFd", "custodyFd", "plannerBootstrapFd",
            "plannerHistoryCustodyFd", "receivingHistoryCustodyFd", "executionBundleKeyFd",
            "historicalBundleKeyFd", "deliveryKeyFd", "journalDirectoryFd", "listenerPath", "journalDirectoryPath")
        expected = (PROCESS_MODE, SERVICE_UID, SERVICE_GID, PEER_UID, PEER_GID,
            *INHERITED_DESCRIPTORS, LISTENER_PATH, JOURNAL_PATH)
        if (tuple(launch[name] for name in fields) != expected
                or tuple(launch["inheritedFileDescriptors"]) != INHERITED_DESCRIPTORS
                or {name: path for name, path, _maximum, _private in _TLS_FILES} != bootstrap.TLS_PATHS
                or {name: maximum for name, _path, maximum, _private in _TLS_FILES} != bootstrap.TLS_LIMITS):
            raise RuntimeError("consume SQL launch differs from fixed resource delivery")
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
        if _listener(3) != listener_pins:
            raise RuntimeError("consume SQL listener differs from the signed launch")
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("consume SQL trust descriptor changed during root admission")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        current()
        for path, target, maximum in _KEY_FILES:
            current()
            source = _open_material(path, maximum, work=work, private=True)
            owned.add(source)
            current()
            bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            os.close(source)
            owned.remove(source)
        _keys_on_work(material, work)
        current()
        tls_identity = _tls_identity(material.tls_files, work=work)
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        current()
        source = _journal_directory(*journal_pins)
        owned.add(source)
        current()
        _retain(source, JOURNAL_FD, reservations, owned)
        retained[JOURNAL_FD] = delivery._material_identity(os.fstat(JOURNAL_FD))
        os.close(source)
        owned.remove(source)
        _retain(3, LISTENER_FD, reservations, owned)
        retained[LISTENER_FD] = delivery._material_identity(os.fstat(LISTENER_FD))
        os.close(3)
        owned.remove(3)
        if (reservations or _listener(LISTENER_FD) != listener_pins
                or _journal(JOURNAL_FD) != journal_pins):
            raise RuntimeError("consume SQL delivery resource inventory changed")
        for _path, descriptor, maximum in _TRUST_FILES:
            current()
            _read_on_work(descriptor, maximum, work)
        for _path, descriptor, maximum in _KEY_FILES:
            _sealed_identity(descriptor, maximum, private=True)
        _tls_unchanged(tls_identity)
        current()
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, False)
        _require_inventory(INHERITED_DESCRIPTORS)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if (os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups()):
            raise RuntimeError("consume SQL identity drop retained privilege")
        delivery._require_unprivileged_process()
        _tls_unchanged(tls_identity)
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("consume SQL descriptor changed before continuation")
        if _listener(LISTENER_FD) != listener_pins or _journal(JOURNAL_FD) != journal_pins:
            raise RuntimeError("consume SQL bound resource changed before continuation")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        current()
        _require_inventory(INHERITED_DESCRIPTORS)
        os.environ.clear()
        os.environ.update(ENVIRONMENT)
        from serverware import oidc_session_activation_delivery_execution_sql_runner as runner

        current()
        return runner._run_on_work(work=work, live_window=window, transport_deadline_ns=bound)
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass
