"""Six-FD root delivery with genuine public admission before signer access."""
from __future__ import annotations

import fcntl
import hashlib
import os
import socket
import stat

from catchplate import authority_fd_entrypoint as delivery
from catchplate import current_root_state_entrypoint as inventory
from catchplate import oidc_session_activation_release_entrypoint as ownership
from catchplate import registration_execution_authorizer_entrypoint as sealed


TRUST_PATH = "/run/catchplate/oidc-session-activation-consume-input-issuer-trust"
ROOT_PATH = TRUST_PATH + "/root-public-key.pem"
BOOTSTRAP_PATH = TRUST_PATH + "/bootstrap.json"
POLICY_PATH = TRUST_PATH + "/issuer-policy.json"
ACTIVATION_PLANNER_BOOTSTRAP_PATH = TRUST_PATH + "/activation-planner-bootstrap.json"
KEY_PATH = "/run/secrets/catchplate-oidc-session-activation-consume-input-issuer-root-signing-key"
LISTENER_PATH = "/run/catchplate/oidc-session-activation-consume-inputs/grants.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-consume-input-issuer"
PROCESS_MODE = "oidc-session-activation-consume-input-issuer"
SERVICE_UID = SERVICE_GID = 65495
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, POLICY_FD, ACTIVATION_PLANNER_BOOTSTRAP_FD, KEY_FD = range(198, 204)
INHERITED_DESCRIPTORS = tuple(range(198, 204))
ROOT_ENV = "CATCHPLATE_OIDC_SESSION_ACTIVATION_CONSUME_INPUT_ISSUER_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "CATCHPLATE_OIDC_SESSION_ACTIVATION_CONSUME_INPUT_ISSUER_BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_consume_input_issuer_launcher.py"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "CATCHPLATE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
MAX_ROOT_BYTES = MAX_BOOTSTRAP_BYTES = MAX_KEY_BYTES = 16 * 1024
MAX_POLICY_BYTES = 6 * 1024 * 1024
MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES = 4 * 1024 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
    (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES),
    (POLICY_PATH, POLICY_FD, MAX_POLICY_BYTES),
    (ACTIVATION_PLANNER_BOOTSTRAP_PATH, ACTIVATION_PLANNER_BOOTSTRAP_FD, MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES))
_MATERIAL = {path: (maximum, False) for path, _descriptor, maximum in _TRUST_FILES}
_MATERIAL[KEY_PATH] = (MAX_KEY_BYTES, True)
_require_inventory = inventory._require_inventory
_sealed_identity, _read_original = sealed._sealed_identity, sealed._read_original
_claim, _retain = ownership._claim, ownership._retain
_close_owned_descriptor, _close_all_owned = ownership._close_owned_descriptor, ownership._close_all_owned
_require_unprivileged_process = delivery._require_unprivileged_process


def _construction_on_work(work):
    from catchplate import oidc_session_activation_consume_input_issuer_bootstrap as bootstrap

    return bootstrap._construction_on_work(work)


def _parent(path):
    if path not in (*_MATERIAL, LISTENER_PATH):
        raise RuntimeError("consume issuer path is not source fixed")
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
                raise RuntimeError("consume issuer ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, work, current, private=False, expected_size=None):
    if type(private) is not bool or _MATERIAL.get(path) != (maximum, private):
        raise RuntimeError("consume issuer original inventory differs")
    if (private and (type(expected_size) is not int or not 2 <= expected_size <= maximum)
            or not private and expected_size is not None):
        raise RuntimeError("consume issuer private size requires its actual root pin")
    parent, source, result = _parent(path), None, None
    local = {}
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        _claim(source, local)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or not 2 <= before.st_size <= maximum
                or stat.S_IMODE(before.st_mode) != (0o400 if private else 0o444)
                or private and before.st_size != expected_size):
            raise RuntimeError("consume issuer original protection or root-pinned size differs")
        identity = delivery._material_identity(before)
        if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                follow_symlinks=False)) != identity:
            raise RuntimeError("consume issuer original pathname differs")
        work.charge(input_bytes=2 * before.st_size)
        current()
        raw = delivery._read_exact_source(source, before.st_size)
        current()
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("consume issuer original changed during charged read")
        current()
        # This fixed primitive replaces only our just-opened source descriptor
        # with its sealed copy; it never chooses an inherited destination.
        result = delivery._seal_bytes(source, name="catchplate-oidc-consume-input-issuer",
            value=raw, mode=stat.S_IMODE(before.st_mode))
        _claim(result, local)
        current()
        os.set_inheritable(result, False)
        _sealed_identity(result, maximum, private=private)
        local.pop(result)
        return result
    finally:
        try:
            if not _close_all_owned(local):
                raise RuntimeError("consume issuer source cleanup is uncertain")
        finally:
            os.close(parent)


def _read_on_work(descriptor, maximum, work, *, private=False):
    from catchplate import authority_revocation_capability_production as production

    identity = _sealed_identity(descriptor, maximum, private=private)
    work.charge(input_bytes=identity[0][6])
    raw, observed = production._callback(work, lambda: _read_original(descriptor, maximum, private=private))
    if observed != identity:
        raise RuntimeError("consume issuer sealed original changed before charged read")
    return raw, identity


def _key_on_work(material, root_public_key, work, *, current):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from catchplate import oidc_session_activation_consume_input_issuer_bootstrap as bootstrap

    root = root_public_key
    if type(material) is not bootstrap._IssuerMaterial or not callable(current):
        raise RuntimeError("consume issuer key requires actual original admission and current guard")
    bootstrap.capture._SharedLedger(work)
    bootstrap.authorization._public(root)
    last_epoch = 0

    def live():
        nonlocal last_epoch
        for guarded in (current, material.live, current):
            epoch = guarded()
            if type(epoch) is not int or epoch <= 0 or epoch < last_epoch:
                raise RuntimeError("consume issuer key admission clocks reversed")
            last_epoch = epoch
        return last_epoch

    live()
    raw, identity = _read_on_work(KEY_FD, MAX_KEY_BYTES, work, private=True)
    live()
    if len(raw) != material.root_signing_key_byte_count:
        raise RuntimeError("consume issuer root key size differs from the signed pin")
    work.charge(hashes=1, input_bytes=len(raw))
    digest = bootstrap.production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    live()
    bootstrap.plan._same(digest, material.root_signing_key_digest, work,
        "consume issuer exact root signer original")
    live()
    work.charge(input_bytes=len(raw))
    private = bootstrap.production._callback(work, lambda: serialization.load_pem_private_key(raw, password=None))
    live()
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("consume issuer runtime root signer is not Ed25519")
    bootstrap.keys._pair_on_work(private, root, work)
    live()
    if _sealed_identity(KEY_FD, MAX_KEY_BYTES, private=True) != identity:
        raise RuntimeError("consume issuer private descriptor changed during key admission")
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
            raise RuntimeError("consume issuer listener differs from the fixed activated socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("consume issuer socket pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def main(*, _sealed_sources=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("consume issuer delivery must start as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("consume issuer requires one exact activated listener")
    from catchplate import oidc_session_activation_follow_on_originals as originals
    if type(_sealed_sources) is not bool:
        raise RuntimeError("consume issuer source profile differs")
    sources = originals.roster('consume-issuer') if _sealed_sources else ()
    _require_inventory({3, *(row[0] for row in sources)})
    owned, reservations, status = {3: None, **{row[0]: None for row in sources}}, {}, 1
    try:
        _claim(3, owned)
        supplied = originals._Originals('consume-issuer', owned) if _sealed_sources else None
        opening = supplied.open if supplied is not None else _open_material
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from catchplate import oidc_session_activation_consume_input_issuer_bootstrap as bootstrap
        from catchplate import oidc_session_activation_consume_input_issuer_runner as runner
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = _construction_on_work(work)
        lifetime = bootstrap._Lifetime(window, bound, work, None)
        current = lifetime.current
        current()
        if sum(maximum for _path, _descriptor, maximum in _TRUST_FILES) + MAX_KEY_BYTES > MAX_ORIGINAL_BYTES:
            raise RuntimeError("consume issuer fixed source inventory exceeds its aggregate bound")
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            _claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("consume issuer descriptor slot is already occupied")
            reservations[target] = owned[descriptor]
        for path, target, maximum in _TRUST_FILES:
            source = opening(path, maximum, work=work, current=current)
            _claim(source, owned)
            _retain(source, target, reservations, owned)
            if not _close_owned_descriptor(source, owned):
                raise RuntimeError("consume issuer public source cleanup is uncertain")
        # Public sealing above has its fixed raw bounds. Before decoded
        # admission or private access, reserve both cold captures and this
        # worker's future original-only derivation inside the same 64 MiB.
        current()
        public_sizes = tuple(_sealed_identity(descriptor, maximum)[0][6]
            for _path, descriptor, maximum in _TRUST_FILES)
        bootstrap._intake_reservation((*public_sizes, MAX_KEY_BYTES))
        current()
        public = []
        for _path, descriptor, maximum in _TRUST_FILES:
            current()
            raw, _identity = _read_on_work(descriptor, maximum, work)
            current()
            public.append(raw)
        root_raw, original, policy_raw, activation_raw = public
        work.charge(input_bytes=len(root_raw))
        current()
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        current()
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("consume issuer runtime root is not Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=original, issuer_policy_bytes=policy_raw,
            activation_planner_bootstrap_bytes=activation_raw, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work, _continuity=lifetime.continuity)
        if type(material) is not bootstrap._IssuerMaterial:
            raise RuntimeError("consume issuer requires genuine bootstrap original admission")
        lifetime.attach(material.live)
        lifetime.adopt(material.live_window, material.deadline_ns)
        current()
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        if (tuple(launch[name] for name, _descriptor in bootstrap._FD_FIELDS) != INHERITED_DESCRIPTORS
                or bootstrap.INHERITED_DESCRIPTORS != INHERITED_DESCRIPTORS
                or (bootstrap.MAX_BYTES, bootstrap.MAX_POLICY_BYTES, bootstrap.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES,
                    bootstrap.MAX_KEY_BYTES, bootstrap.MAX_ORIGINAL_BYTES)
                    != (MAX_BOOTSTRAP_BYTES, MAX_POLICY_BYTES, MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES,
                        MAX_KEY_BYTES, MAX_ORIGINAL_BYTES)
                or _listener(3) != listener_pins
                or sum(map(len, public)) + material.root_signing_key_byte_count > MAX_ORIGINAL_BYTES):
            raise RuntimeError("consume issuer launch and actual resource delivery disagree")
        # First private access: exact launch, independent policy and historical
        # activation root originals have all passed genuine admission already.
        current()
        source = opening(KEY_PATH, MAX_KEY_BYTES, work=work, current=current,
            private=True, expected_size=material.root_signing_key_byte_count)
        _claim(source, owned)
        _retain(source, KEY_FD, reservations, owned)
        if not _close_owned_descriptor(source, owned):
            raise RuntimeError("consume issuer private source cleanup is uncertain")
        _key_on_work(material, root, work, current=current)
        current()
        _retain(3, LISTENER_FD, reservations, owned)
        if not _close_owned_descriptor(3, owned) or reservations:
            raise RuntimeError("consume issuer listener handoff cleanup is uncertain")
        for descriptor in INHERITED_DESCRIPTORS:
            if delivery._material_identity(os.fstat(descriptor)) != owned[descriptor]:
                raise RuntimeError("consume issuer delivered descriptor identity changed")
            os.set_inheritable(descriptor, False)
        current()
        _require_inventory(INHERITED_DESCRIPTORS)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups():
            raise RuntimeError("consume issuer delivery retained privilege")
        _require_unprivileged_process()
        if _listener(LISTENER_FD) != listener_pins:
            raise RuntimeError("consume issuer listener changed during permanent drop")
        current()
        _require_inventory(INHERITED_DESCRIPTORS)
        os.environ.clear()
        os.environ.update(ENVIRONMENT)
        # The retained guard is lifetime-only. Startup separately owns its
        # exact six descriptors plus the sole accepted connection suffix.
        status = runner._run_on_work(work=work, live_window=material.live_window,
            transport_deadline_ns=material.deadline_ns, delivery_current=current)
    finally:
        if not _close_all_owned(owned):
            status = 1
    return status
