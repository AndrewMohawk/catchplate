"""Six-FD root delivery, public admission first, original-bound same-PID drop."""
from __future__ import annotations

import fcntl
import hashlib
import os
import socket
import stat

from serverware import authority_fd_entrypoint as delivery
from serverware import current_root_state_entrypoint as inventory
from serverware import oidc_session_activation_release_entrypoint as ownership
from serverware import registration_execution_authorizer_entrypoint as sealed


TRUST_PATH = "/run/serverware/oidc-session-activation-release-grant-issuer-trust"
ROOT_PATH = TRUST_PATH + "/root-public-key.pem"
BOOTSTRAP_PATH = TRUST_PATH + "/bootstrap.json"
POLICY_PATH = TRUST_PATH + "/issuer-policy.json"
PROOF_BOOTSTRAP_PATH = TRUST_PATH + "/proof-bootstrap.json"
KEY_PATH = "/run/secrets/serverware-oidc-session-activation-release-grant-issuer-root-signing-key"
LISTENER_PATH = "/run/serverware/oidc-session-activation-token-release/grants.sock"
LISTENER_NAME = "serverware-oidc-session-activation-release-grant-issuer"
PROCESS_MODE = "oidc-session-activation-release-grant-issuer"
SERVICE_UID = SERVICE_GID = 65496
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, POLICY_FD, PROOF_BOOTSTRAP_FD, KEY_FD = range(198, 204)
INHERITED_DESCRIPTORS = tuple(range(198, 204))
ROOT_ENV = "SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_GRANT_ISSUER_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_GRANT_ISSUER_BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_release_grant_issuer_launcher.py"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "SERVERWARE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
MAX_ROOT_BYTES = MAX_BOOTSTRAP_BYTES = MAX_POLICY_BYTES = MAX_KEY_BYTES = 16 * 1024
MAX_PROOF_BOOTSTRAP_BYTES = 48 * 1024 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
    (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES),
    (POLICY_PATH, POLICY_FD, MAX_POLICY_BYTES),
    (PROOF_BOOTSTRAP_PATH, PROOF_BOOTSTRAP_FD, MAX_PROOF_BOOTSTRAP_BYTES))
_MATERIAL = {path: (maximum, False) for path, _descriptor, maximum in _TRUST_FILES}
_MATERIAL[KEY_PATH] = (MAX_KEY_BYTES, True)
_require_inventory = inventory._require_inventory
_sealed_identity, _read_original = sealed._sealed_identity, sealed._read_original
_claim, _retain = ownership._claim, ownership._retain
_close_owned_descriptor, _close_all_owned = ownership._close_owned_descriptor, ownership._close_all_owned
_require_unprivileged_process = delivery._require_unprivileged_process


def _construction_on_work(work):
    from serverware import oidc_session_activation_release_grant_issuer_bootstrap as bootstrap

    return bootstrap._construction_on_work(work)


def _parent(path):
    if path not in (*_MATERIAL, LISTENER_PATH):
        raise RuntimeError("release issuer path is not source fixed")
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
                raise RuntimeError("release issuer ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, work, current, private=False, expected_size=None):
    if type(private) is not bool or _MATERIAL.get(path) != (maximum, private):
        raise RuntimeError("release issuer original inventory differs")
    if (private and (type(expected_size) is not int or not 2 <= expected_size <= maximum)
            or not private and expected_size is not None):
        raise RuntimeError("release issuer private size requires its actual root pin")
    parent, source, result = _parent(path), None, None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or not 2 <= before.st_size <= maximum
                or stat.S_IMODE(before.st_mode) != (0o400 if private else 0o444)
                or private and before.st_size != expected_size):
            raise RuntimeError("release issuer original protection or root-pinned size differs")
        identity = delivery._material_identity(before)
        if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                follow_symlinks=False)) != identity:
            raise RuntimeError("release issuer original pathname differs")
        # Actual file size is reserved before either read or sealed copy. The
        # real guard runs outside stable callbacks immediately around both.
        work.charge(input_bytes=2 * before.st_size)
        current()
        raw = delivery._read_exact_source(source, before.st_size)
        current()
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("release issuer original changed during charged read")
        current()
        result = delivery._seal_bytes(source, name="serverware-oidc-release-grant-issuer",
            value=raw, mode=stat.S_IMODE(before.st_mode))
        source = None  # Successful sealing transfers the source descriptor.
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
        raise RuntimeError("release issuer sealed original changed before charged read")
    return raw, identity


def _key_on_work(material, root_public_key, work, *, current):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import oidc_session_activation_release_grant_issuer_bootstrap as bootstrap

    root = root_public_key
    if type(material) is not bootstrap._IssuerMaterial or not callable(current):
        raise RuntimeError("release issuer key requires actual original admission and current guard")
    bootstrap.capture._SharedLedger(work)
    bootstrap.authorization._public(root)
    last_epoch = 0

    def live():
        nonlocal last_epoch
        for guarded in (current, material.live, current):
            epoch = guarded()
            if type(epoch) is not int or epoch <= 0 or epoch < last_epoch:
                raise RuntimeError("release issuer key admission clocks reversed")
            last_epoch = epoch
        return last_epoch

    live()
    raw, identity = _read_on_work(KEY_FD, MAX_KEY_BYTES, work, private=True)
    live()
    if len(raw) != material.root_signing_key_byte_count:
        raise RuntimeError("release issuer root key size differs from the signed pin")
    work.charge(hashes=1, input_bytes=len(raw))
    digest = bootstrap.production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    live()
    bootstrap.plan._same(digest, material.root_signing_key_digest, work,
        "release issuer exact root signer original")
    live()
    work.charge(input_bytes=len(raw))
    private = bootstrap.production._callback(work, lambda: serialization.load_pem_private_key(raw, password=None))
    live()
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("release issuer root signer is not Ed25519")
    bootstrap.keys._pair_on_work(private, root, work)
    live()
    if _sealed_identity(KEY_FD, MAX_KEY_BYTES, private=True) != identity:
        raise RuntimeError("release issuer private descriptor changed during key admission")
    live()
    return private


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("release issuer listener differs from the fixed activated socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("release issuer socket pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def main(*, _sealed_sources=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("release issuer delivery must start as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("release issuer requires one exact activated listener")
    from serverware import oidc_session_activation_follow_on_originals as originals
    if type(_sealed_sources) is not bool:
        raise RuntimeError('grant issuer source profile differs')
    sources = originals.roster('grant-issuer') if _sealed_sources else ()
    _require_inventory({3, *(row[0] for row in sources)})
    owned, reservations, status = {3: None, **{row[0]: None for row in sources}}, {}, 1
    try:
        _claim(3, owned)
        supplied = originals._Originals('grant-issuer', owned) if _sealed_sources else None
        opening = supplied.open if supplied is not None else _open_material
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import oidc_session_activation_release_grant_issuer_bootstrap as bootstrap
        from serverware import oidc_session_activation_release_grant_issuer_runner as runner
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = _construction_on_work(work)
        construction_current, _bind = bootstrap.issuer.server.storage._processing(window, bound, work)
        construction_current()
        if sum(maximum for _path, _descriptor, maximum in _TRUST_FILES) + MAX_KEY_BYTES > MAX_ORIGINAL_BYTES:
            raise RuntimeError("release issuer fixed source inventory exceeds its aggregate bound")
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            _claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("release issuer descriptor slot is already occupied")
            reservations[target] = owned[descriptor]
        for path, target, maximum in _TRUST_FILES:
            source = opening(path, maximum, work=work, current=construction_current)
            _claim(source, owned)
            _retain(source, target, reservations, owned)
            if not _close_owned_descriptor(source, owned):
                raise RuntimeError("release issuer public source cleanup is uncertain")
        public = []
        for _path, descriptor, maximum in _TRUST_FILES:
            construction_current()
            raw, _identity = _read_on_work(descriptor, maximum, work)
            construction_current()
            public.append(raw)
        root_raw, original, policy_raw, proof_raw = public
        work.charge(input_bytes=len(root_raw))
        construction_current()
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        construction_current()
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("release issuer runtime root is not Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=original, issuer_policy_bytes=policy_raw,
            proof_bootstrap_bytes=proof_raw, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work)
        last_epoch = construction_current()

        def current():
            nonlocal last_epoch
            for guarded in (construction_current, material.live, construction_current):
                epoch = guarded()
                if type(epoch) is not int or epoch < last_epoch:
                    raise RuntimeError("release issuer root delivery guards reversed")
                last_epoch = epoch
            return last_epoch

        current()
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        if (tuple(launch[name] for name, _descriptor in bootstrap._FD_FIELDS) != INHERITED_DESCRIPTORS
                or bootstrap.INHERITED_DESCRIPTORS != INHERITED_DESCRIPTORS
                or (bootstrap.MAX_BYTES, bootstrap.MAX_POLICY_BYTES, bootstrap.MAX_PROOF_BOOTSTRAP_BYTES,
                    bootstrap.MAX_KEY_BYTES, bootstrap.MAX_ORIGINAL_BYTES)
                    != (MAX_BOOTSTRAP_BYTES, MAX_POLICY_BYTES, MAX_PROOF_BOOTSTRAP_BYTES, MAX_KEY_BYTES, MAX_ORIGINAL_BYTES)
                or _listener(3) != listener_pins
                or sum(map(len, public)) + material.root_signing_key_byte_count > MAX_ORIGINAL_BYTES):
            raise RuntimeError("release issuer launch and actual resource delivery disagree")
        # This is the first private file access: all public root originals and
        # actual policy/proof guards have already been genuinely admitted.
        current()
        source = opening(KEY_PATH, MAX_KEY_BYTES, work=work, current=current,
            private=True, expected_size=material.root_signing_key_byte_count)
        _claim(source, owned)
        _retain(source, KEY_FD, reservations, owned)
        if not _close_owned_descriptor(source, owned):
            raise RuntimeError("release issuer private source cleanup is uncertain")
        _key_on_work(material, root, work, current=current)
        current()
        _retain(3, LISTENER_FD, reservations, owned)
        if not _close_owned_descriptor(3, owned) or reservations:
            raise RuntimeError("release issuer listener handoff cleanup is uncertain")
        for descriptor in INHERITED_DESCRIPTORS:
            if delivery._material_identity(os.fstat(descriptor)) != owned[descriptor]:
                raise RuntimeError("release issuer delivered descriptor identity changed")
            os.set_inheritable(descriptor, False)
        current()
        _require_inventory(INHERITED_DESCRIPTORS)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups():
            raise RuntimeError("release issuer delivery retained privilege")
        _require_unprivileged_process()
        if _listener(LISTENER_FD) != listener_pins:
            raise RuntimeError("release issuer listener changed during permanent drop")
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
