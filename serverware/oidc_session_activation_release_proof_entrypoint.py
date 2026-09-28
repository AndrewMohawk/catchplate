"""Seven-FD one-shot proof delivery with original-bound same-process drop."""
from __future__ import annotations

import fcntl
import hashlib
import os
import socket
import stat

from serverware import authority_fd_entrypoint as delivery
from serverware import current_root_state_entrypoint as inventory
from serverware import oidc_session_activation_delivery_completion_entrypoint as completion_delivery
from serverware import oidc_session_activation_release_entrypoint as ownership
from serverware import registration_execution_authorizer_entrypoint as sealed


ROOT_PATH = "/run/serverware/oidc-session-activation-release-proof-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/serverware/oidc-session-activation-release-proof-trust/bootstrap.json"
KEY_PATH = "/run/secrets/serverware-oidc-session-activation-release-proof-signing-key"
EXECUTION_BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-release-proof-execution-bundle-key"
HISTORICAL_BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-release-proof-historical-bundle-key"
DELIVERY_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-release-proof-delivery-key"
LISTENER_PATH = "/run/serverware/oidc-session-activation-token-release/proof.sock"
LISTENER_NAME = "serverware-oidc-session-activation-release-proof"
PROCESS_MODE = "oidc-session-activation-delivery-completion"
SERVICE_UID = SERVICE_GID = 65497
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, EXECUTION_BUNDLE_KEY_FD, HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD = range(198, 205)
INHERITED_DESCRIPTORS = tuple(range(198, 205))
ROOT_ENV = "SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_PROOF_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_PROOF_BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_release_proof_launcher.py"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "SERVERWARE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_KEY_BYTES, MAX_RAW_KEY_BYTES = 16 * 1024, 48 * 1024 * 1024, 16 * 1024, 32
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES), (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES))
_KEY_FILES = ((KEY_PATH, KEY_FD, MAX_KEY_BYTES),
    (EXECUTION_BUNDLE_KEY_PATH, EXECUTION_BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (HISTORICAL_BUNDLE_KEY_PATH, HISTORICAL_BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (DELIVERY_KEY_PATH, DELIVERY_KEY_FD, MAX_RAW_KEY_BYTES))
_MATERIAL = {path: (maximum, private) for private, values in
    ((False, _TRUST_FILES), (True, _KEY_FILES)) for path, _fd, maximum in values}
_TLS_FILES = completion_delivery._TLS_FILES
_require_inventory = inventory._require_inventory
_sealed_identity, _read_original = sealed._sealed_identity, sealed._read_original
_claim, _retain = ownership._claim, ownership._retain
_close_owned_descriptor, _close_all_owned = ownership._close_owned_descriptor, ownership._close_all_owned
_tls_unchanged = completion_delivery._tls_unchanged
_require_unprivileged_process = delivery._require_unprivileged_process


def _construction_on_work(work):
    from serverware import oidc_session_activation_release_proof_bootstrap as bootstrap

    return bootstrap._construction_on_work(work)


def _parent(path):
    if path not in (*_MATERIAL, LISTENER_PATH, *(item[1] for item in _TLS_FILES)):
        raise RuntimeError("proof delivery path is not source fixed")
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
                raise RuntimeError("proof delivery ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, work, current, private=False):
    if type(private) is not bool or _MATERIAL.get(path) != (maximum, private):
        raise RuntimeError("proof delivery original inventory differs")
    parent, source, result = _parent(path), None, None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or not 2 <= before.st_size <= maximum
                or private and stat.S_IMODE(before.st_mode) != 0o400
                or private and path != KEY_PATH and before.st_size != MAX_RAW_KEY_BYTES):
            raise RuntimeError("proof original is not protected bounded material")
        identity = delivery._material_identity(before)
        if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                follow_symlinks=False)) != identity:
            raise RuntimeError("proof original pathname differs")
        work.charge(input_bytes=2 * before.st_size)
        current()
        raw = delivery._read_exact_source(source, before.st_size)
        current()
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("proof original changed during charged read")
        current()
        result = delivery._seal_bytes(source, name="serverware-oidc-release-proof",
            value=raw, mode=stat.S_IMODE(before.st_mode))
        # _seal_bytes transfers/reuses its source descriptor; track only the
        # returned live descriptor after successful sealing.
        source = None
        current()
        os.set_inheritable(result, False)
        return result
    except BaseException:
        if result is not None:
            os.close(result)
        elif source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _read_on_work(descriptor, maximum, work, *, private=False):
    from serverware import authority_revocation_capability_production as production

    identity = _sealed_identity(descriptor, maximum, private=private)
    work.charge(input_bytes=identity[0][6])
    raw, observed = production._callback(work, lambda: _read_original(descriptor, maximum, private=private))
    if observed != identity:
        raise RuntimeError("proof sealed original changed before charged read")
    return raw, identity


def _keys_on_work(material, work, *, current=None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import authority_oidc_session_activation_delivery_completion_custody as custody

    evidence = custody.evidence
    evidence.capture._SharedLedger(work)

    def live():
        if current is not None:
            current()
        material.live()
        if current is not None:
            current()

    originals, identities = [], []
    for _path, descriptor, maximum in _KEY_FILES:
        live()
        raw, identity = _read_on_work(descriptor, maximum, work, private=True)
        live()
        originals.append(raw)
        identities.append((descriptor, maximum, identity))
    signing, execution, historical, delivery_key = originals
    if any(type(raw) is not bytes or len(raw) != MAX_RAW_KEY_BYTES for raw in (execution, historical, delivery_key)):
        raise RuntimeError("proof historical custody requires three raw32 originals")
    custody.neutral._key_bindings(material.completion_material.custody_material,
        execution, historical, delivery_key, work)
    live()
    private = evidence.production._callback(work, lambda: serialization.load_pem_private_key(signing, password=None))
    live()
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("proof signer is not Ed25519")
    evidence.keys._public_binding(material.proof_public_key, material.proof_spki_digest, work)
    evidence.keys._pair_on_work(private, material.proof_public_key, work)
    live()
    for descriptor, maximum, identity in identities:
        if _sealed_identity(descriptor, maximum, private=True) != identity:
            raise RuntimeError("proof private descriptor changed during key admission")
    return private, execution, historical, delivery_key


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("proof listener differs from fixed activated socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("proof socket pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _tls_identity(tls_files, *, work, current=None):
    from serverware import oidc_session_activation_release_proof_bootstrap as bootstrap

    if type(tls_files) is not dict or set(tls_files) != set(bootstrap.TLS_PATHS):
        raise RuntimeError("proof TLS inventory differs")
    pins = []
    for name, path, maximum, private in _TLS_FILES:
        record = tls_files[name]
        bootstrap.shape._object(record, frozenset({"byteCount", "bytesDigest"}), "proof TLS pin")
        bootstrap.shape._integer(record["byteCount"], maximum, minimum=2)
        bootstrap.shape._digest(record["bytesDigest"])
        pins.append((name, path, record["byteCount"], record["bytesDigest"], private))
    identities = []
    for name, path, size, expected, private in pins:
        parent, descriptor = _parent(path), None
        try:
            descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
                | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            value = os.fstat(descriptor)
            if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 1
                    or value.st_size != size or stat.S_IMODE(value.st_mode) != (0o440 if private else 0o444)
                    or private and value.st_gid != SERVICE_GID):
                raise RuntimeError("proof TLS protection or admitted size differs")
            identity = delivery._material_identity(value)
            if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity:
                raise RuntimeError("proof TLS pathname differs")
            work.charge(hashes=1, input_bytes=size)
            digest, remaining = hashlib.sha256(), size
            while remaining:
                if current is not None:
                    current()
                chunk = bootstrap.production._callback(work, lambda: os.read(descriptor, min(4096, remaining)))
                if current is not None:
                    current()
                if not chunk:
                    raise RuntimeError("proof TLS original truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            if current is not None:
                current()
            if os.read(descriptor, 1):
                raise RuntimeError("proof TLS original grew")
            if current is not None:
                current()
            if ("sha256:" + digest.hexdigest() != expected
                    or delivery._material_identity(os.fstat(descriptor)) != identity
                    or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                        follow_symlinks=False)) != identity):
                raise RuntimeError("proof TLS original changed")
            identities.append((name, identity, expected))
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
    result = tuple(identities)
    _tls_unchanged(result)
    return result


def main():
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("proof delivery must start as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("proof delivery requires one exact activated listener")
    _require_inventory({3})
    owned, reservations, status = {3: None}, {}, 1
    try:
        _claim(3, owned)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import oidc_session_activation_release_proof_bootstrap as bootstrap
        from serverware import oidc_session_activation_release_proof_runner as runner
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = _construction_on_work(work)
        _window, construction_current = bootstrap.delivery._window(window, bound, work)
        construction_current()
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            _claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("proof descriptor slot is already occupied")
            reservations[target] = owned[descriptor]
        for path, target, maximum in _TRUST_FILES:
            source = _open_material(path, maximum, work=work, current=construction_current)
            _claim(source, owned)
            _retain(source, target, reservations, owned)
            if not _close_owned_descriptor(source, owned):
                raise RuntimeError("proof public source cleanup is uncertain")
        construction_current()
        root_raw, _identity = _read_on_work(ROOT_FD, MAX_ROOT_BYTES, work)
        construction_current()
        original, _identity = _read_on_work(BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES, work)
        construction_current()
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("proof runtime root is not Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=original, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work)
        last_epoch = construction_current()

        def current():
            nonlocal last_epoch
            for guard in (construction_current, material.live, construction_current):
                epoch = guard()
                if type(epoch) is not int or epoch < last_epoch:
                    raise RuntimeError("proof delivery current guards reversed")
                last_epoch = epoch
            return last_epoch

        current()
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        fields = ("rootPublicKeyFd", "bootstrapFd", "listenerFd", "signingKeyFd",
            "executionBundleKeyFd", "historicalBundleKeyFd", "deliveryKeyFd")
        if (tuple(launch[name] for name in fields) != INHERITED_DESCRIPTORS
                or bootstrap.INHERITED_DESCRIPTORS != INHERITED_DESCRIPTORS
                or bootstrap.MAX_BYTES != MAX_BOOTSTRAP_BYTES
                or _listener(3) != listener_pins
                or {name: path for name, path, _maximum, _private in _TLS_FILES} != bootstrap.TLS_PATHS):
            raise RuntimeError("proof launch and actual resource delivery disagree")
        # Genuine public root/original admission precedes every private read.
        for path, target, maximum in _KEY_FILES:
            current()
            source = _open_material(path, maximum, work=work, current=current, private=True)
            _claim(source, owned)
            _retain(source, target, reservations, owned)
            if not _close_owned_descriptor(source, owned):
                raise RuntimeError("proof private source cleanup is uncertain")
            current()
        _keys_on_work(material, work, current=current)
        current()
        tls_identity = _tls_identity(material.completion_material.tls_files, work=work, current=current)
        _retain(3, LISTENER_FD, reservations, owned)
        if not _close_owned_descriptor(3, owned) or reservations:
            raise RuntimeError("proof listener handoff cleanup is uncertain")
        for descriptor in INHERITED_DESCRIPTORS:
            if delivery._material_identity(os.fstat(descriptor)) != owned[descriptor]:
                raise RuntimeError("proof delivered descriptor identity changed")
            os.set_inheritable(descriptor, False)
        current()
        _require_inventory(INHERITED_DESCRIPTORS)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups():
            raise RuntimeError("proof delivery retained privilege")
        _require_unprivileged_process()
        _tls_unchanged(tls_identity)
        if _listener(LISTENER_FD) != listener_pins:
            raise RuntimeError("proof listener changed during permanent drop")
        current()
        _require_inventory(INHERITED_DESCRIPTORS)
        os.environ.clear()
        os.environ.update(ENVIRONMENT)
        status = runner._run_on_work(work=work, live_window=material.live_window,
            transport_deadline_ns=material.deadline_ns, delivery_current=current)
    finally:
        if not _close_all_owned(owned):
            status = 1
    return status
