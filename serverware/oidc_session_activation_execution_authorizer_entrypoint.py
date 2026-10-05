"""Fixed cold key delivery for the dedicated activation grant authorizer.

Both independent launch and receiving-custody originals are authenticated
before any private key is opened. Seven sealed/listener descriptors survive
the permanent identity drop. No key, account, socket or authority is created.
Host-local file protection does not establish measured or hostile-host custody.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat

from serverware import authority_fd_entrypoint as delivery
from serverware import current_root_state_entrypoint as fd_inventory
from serverware import registration_execution_authorizer_entrypoint as sealed_originals


ROOT_PATH = "/run/serverware/oidc-session-activation-execution-authorizer-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/serverware/oidc-session-activation-execution-authorizer-trust/bootstrap.json"
CUSTODY_PATH = "/run/serverware/oidc-session-activation-execution-authorizer-trust/custody.json"
BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-bundle-key"
DELIVERY_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-key"
KEY_PATH = "/run/secrets/serverware-oidc-session-activation-execution-authorizer-key"
LISTENER_PATH = "/run/serverware/oidc-session-activation-execution/authorizer.sock"
LISTENER_NAME = "serverware-oidc-session-activation-execution-authorizer"
PROCESS_MODE = "oidc-session-activation-execution-authorizer"
SERVICE_UID = SERVICE_GID = 65506
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD = 198, 199, 200, 201
BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD = 202, 203, 204
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD,
    BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD)
PREFIX = "SERVERWARE_OIDC_SESSION_ACTIVATION_EXECUTION_AUTHORIZER_"
ROOT_ENV, BOOTSTRAP_ENV = PREFIX + "ROOT_PUBLIC_KEY_FD", PREFIX + "BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_execution_authorizer_launcher.py"
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_CUSTODY_BYTES = 16 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024
MAX_KEY_BYTES, MAX_RAW_KEY_BYTES = 4096, 32
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
    (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES),
    (CUSTODY_PATH, CUSTODY_FD, MAX_CUSTODY_BYTES))
_KEY_FILES = ((BUNDLE_KEY_PATH, BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (DELIVERY_KEY_PATH, DELIVERY_KEY_FD, MAX_RAW_KEY_BYTES),
    (KEY_PATH, KEY_FD, MAX_KEY_BYTES))
_MATERIAL = {path: (maximum, private) for private, inventory in
    ((False, _TRUST_FILES), (True, _KEY_FILES)) for path, _descriptor, maximum in inventory}
# These helpers act only on explicit descriptors, not the other role's paths.
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain
_sealed_identity = sealed_originals._sealed_identity
_read_original = sealed_originals._read_original


def _parent(path):
    if path not in (*_MATERIAL, LISTENER_PATH):
        raise RuntimeError("activation authorizer path is not source fixed")
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
                raise RuntimeError("activation authorizer ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, private=False):
    if path not in _MATERIAL or _MATERIAL[path] != (maximum, private) or type(private) is not bool:
        raise RuntimeError("activation authorizer original inventory changed")
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
            raise RuntimeError("activation authorizer original is not protected bounded material")
        identity = delivery._material_identity(before)
        named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if delivery._material_identity(named) != identity:
            raise RuntimeError("activation authorizer original pathname differs")
        raw = delivery._read_exact_source(source, before.st_size)
        named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(named) != identity):
            raise RuntimeError("activation authorizer original changed during read")
        return delivery._seal_bytes(source, name="serverware-oidc-activation-authorizer",
            value=raw, mode=stat.S_IMODE(before.st_mode))
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _keys_on_work(material, work):
    """Load actual fixed sealed originals after genuine admission, never admit a DTO."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import authority_oidc_session_activation_execution_custody as custody

    evidence = custody.evidence
    evidence.capture._SharedLedger(work)
    work.charge(input_bytes=2 * MAX_RAW_KEY_BYTES + MAX_KEY_BYTES)
    originals, identities = [], []
    for _path, descriptor, maximum in _KEY_FILES:
        raw, identity = evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum:
                _read_original(descriptor, maximum, private=True))
        originals.append(raw)
        identities.append((descriptor, maximum, identity))
    bundle_key, delivery_key, signing_raw = originals
    if any(type(raw) is not bytes or len(raw) != MAX_RAW_KEY_BYTES for raw in (bundle_key, delivery_key)):
        raise RuntimeError("activation authorizer encryption originals must be raw32")
    custody._key_bindings(material.custody_material, bundle_key, delivery_key, work)
    private = evidence.production._callback(work,
        lambda: serialization.load_pem_private_key(signing_raw, password=None))
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("activation authorizer signing original must be Ed25519")
    evidence.keys._public_binding(material.authorizer_public_key, material.authorizer_spki_digest, work)
    evidence.keys._pair_on_work(private, material.authorizer_public_key, work)
    for descriptor, maximum, identity in identities:
        observed = evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum: _sealed_identity(descriptor, maximum, private=True))
        if observed != identity:
            raise RuntimeError("activation authorizer key descriptor changed during admission")
    return bundle_key, delivery_key, private


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("activation authorizer listener differs from fixed socket activation")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("activation authorizer socket path protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def main(*, _sealed_originals=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("activation authorizer delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("activation authorizer requires one exact activated listener")
    from serverware import oidc_session_activation_execution_dynamic_entrypoint as original_delivery
    incoming = original_delivery._incoming("oidc_session_activation_execution_authorizer_entrypoint", _sealed_originals)
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
                raise RuntimeError("activation authorizer fixed descriptor slot is occupied")
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
        from serverware import oidc_session_activation_execution_authorizer_bootstrap as bootstrap
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        work.charge(input_bytes=len(root_raw))
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("activation authorizer root original must be Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, custody_bytes=custody_raw,
            root_public_key=root, work=work)
        listener_pins = tuple(material.launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        if _listener(3) != listener_pins:
            raise RuntimeError("activation authorizer listener differs from the signed launch")
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("activation authorizer trust descriptor changed during root admission")
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
        _retain(3, LISTENER_FD, reservations, owned)
        retained[LISTENER_FD] = delivery._material_identity(os.fstat(LISTENER_FD))
        owned.remove(3)
        os.close(3)
        if reservations or _listener(LISTENER_FD) != listener_pins:
            raise RuntimeError("activation authorizer delivery resource inventory changed")
        for _path, descriptor, maximum in _TRUST_FILES:
            _read_original(descriptor, maximum)
        for _path, descriptor, maximum in _KEY_FILES:
            _sealed_identity(descriptor, maximum, private=True)
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
            raise RuntimeError("activation authorizer identity drop retained privilege")
        delivery._require_unprivileged_process()
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("activation authorizer descriptor changed before exec")
        if _listener(LISTENER_FD) != listener_pins:
            raise RuntimeError("activation authorizer listener changed before exec")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        _require_inventory(INHERITED_DESCRIPTORS)
        os.execve(PYTHON, [PYTHON, "-I", LAUNCHER, "--run"], environment)
        raise RuntimeError("activation authorizer runner exec unexpectedly returned")
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass
