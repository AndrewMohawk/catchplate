"""Eight-FD root delivery for the source-fixed proof-input issuer."""
from __future__ import annotations

import fcntl
import hashlib
import os
import socket
import stat
from types import MethodType

from serverware import authority_fd_entrypoint as delivery
from serverware import current_root_state_entrypoint as inventory
from serverware import oidc_session_activation_release_entrypoint as ownership
from serverware import registration_execution_authorizer_entrypoint as sealed


TRUST_PATH = "/run/serverware/oidc-session-activation-release-proof-input-issuer-trust"
ROOT_PATH = TRUST_PATH + "/root-public-key.pem"
BOOTSTRAP_PATH = TRUST_PATH + "/bootstrap.json"
POLICY_PATH = TRUST_PATH + "/issuer-policy.json"
COMPLETION_BOOTSTRAP_PATH = TRUST_PATH + "/completion-bootstrap.json"
PROOF_ENROLLMENT_PATH = TRUST_PATH + "/proof-enrollment.json"
INTENT_ENROLLMENT_PATH = TRUST_PATH + "/intent-enrollment.json"
KEY_PATH = "/run/secrets/serverware-oidc-session-activation-release-proof-input-issuer-root-signing-key"
LISTENER_PATH = "/run/serverware/oidc-session-activation-release-proof-inputs/grants.sock"
LISTENER_NAME = "serverware-oidc-session-activation-release-proof-input-issuer"
PROCESS_MODE = "oidc-session-activation-release-proof-input-issuer"
SERVICE_UID = SERVICE_GID = 65494
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, POLICY_FD, COMPLETION_BOOTSTRAP_FD, PROOF_ENROLLMENT_FD, INTENT_ENROLLMENT_FD, KEY_FD = range(198, 206)
INHERITED_DESCRIPTORS = tuple(range(198, 206))
ROOT_ENV = "SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_PROOF_INPUT_ISSUER_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENV = "SERVERWARE_OIDC_SESSION_ACTIVATION_RELEASE_PROOF_INPUT_ISSUER_BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_release_proof_input_issuer_launcher.py"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "SERVERWARE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
MAX_ROOT_BYTES = MAX_BOOTSTRAP_BYTES = MAX_KEY_BYTES = 16 * 1024
MAX_POLICY_BYTES = 64 * 1024
MAX_COMPLETION_BOOTSTRAP_BYTES = 32 * 1024 * 1024
MAX_PROOF_ENROLLMENT_BYTES = MAX_INTENT_ENROLLMENT_BYTES = 16 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
    (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES),
    (POLICY_PATH, POLICY_FD, MAX_POLICY_BYTES),
    (COMPLETION_BOOTSTRAP_PATH, COMPLETION_BOOTSTRAP_FD, MAX_COMPLETION_BOOTSTRAP_BYTES),
    (PROOF_ENROLLMENT_PATH, PROOF_ENROLLMENT_FD, MAX_PROOF_ENROLLMENT_BYTES),
    (INTENT_ENROLLMENT_PATH, INTENT_ENROLLMENT_FD, MAX_INTENT_ENROLLMENT_BYTES))
_MATERIAL = {path: (maximum, False) for path, _descriptor, maximum in _TRUST_FILES}
_MATERIAL[KEY_PATH] = (MAX_KEY_BYTES, True)
# Only the recovery reader's TLS resources enter this issuer. The separate
# completion/proof worker retains its own UID65497 checks and commit TLS pair.
_TLS_FILES = (
    ("ca", "/run/serverware/oidc-session-activation-delivery-completion-tls/ca.pem", 64 * 1024, False),
    ("custodyCertificate", "/run/serverware/oidc-session-activation-delivery-completion-tls/custody.crt", 64 * 1024, False),
    ("custodyKey", "/run/serverware/oidc-session-activation-delivery-completion-tls/custody.key", 16 * 1024, True),
)
_TLS_FIELDS = frozenset({"ca", "custodyCertificate", "custodyKey", "commitCertificate", "commitKey"})
_HEX = frozenset("0123456789abcdef")
_require_inventory = inventory._require_inventory
_sealed_identity, _read_original = sealed._sealed_identity, sealed._read_original
_claim, _retain = ownership._claim, ownership._retain
_close_owned_descriptor, _close_all_owned = ownership._close_owned_descriptor, ownership._close_all_owned
_require_unprivileged_process = delivery._require_unprivileged_process
_PID, _used, _continuation = os.getpid(), False, None


def _construction_on_work(work):
    from serverware import oidc_session_activation_release_proof_input_issuer_bootstrap as bootstrap

    return bootstrap._construction_on_work(work)


def _parent(path):
    if path not in (*_MATERIAL, LISTENER_PATH, *(item[1] for item in _TLS_FILES)):
        raise RuntimeError("proof input issuer path is not source fixed")
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
                raise RuntimeError("proof input issuer ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, work, current, private=False, expected_size=None, retained_bytes=0):
    if type(private) is not bool or _MATERIAL.get(path) != (maximum, private):
        raise RuntimeError("proof input issuer original inventory differs")
    if (private and (type(expected_size) is not int or not 2 <= expected_size <= maximum)
            or not private and expected_size is not None
            or type(retained_bytes) is not int or not 0 <= retained_bytes < MAX_ORIGINAL_BYTES):
        raise RuntimeError("proof input issuer private size or retained capacity differs")
    current()
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
                or private and before.st_size != expected_size
                or retained_bytes + 2 * before.st_size > MAX_ORIGINAL_BYTES):
            raise RuntimeError("proof input issuer original protection, size or aggregate differs")
        identity = delivery._material_identity(before)
        if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                follow_symlinks=False)) != identity:
            raise RuntimeError("proof input issuer original pathname differs")
        work.charge(input_bytes=2 * before.st_size)
        current()
        raw = delivery._read_exact_source(source, before.st_size)
        current()
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("proof input issuer original changed during charged read")
        current()
        result = delivery._seal_bytes(source, name="serverware-oidc-proof-input-issuer",
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
                raise RuntimeError("proof input issuer source cleanup is uncertain")
        finally:
            os.close(parent)


def _read_on_work(descriptor, maximum, work, *, private=False):
    from serverware import authority_revocation_capability_production as production

    identity = _sealed_identity(descriptor, maximum, private=private)
    work.charge(input_bytes=identity[0][6])
    raw, observed = production._callback(work, lambda: _read_original(descriptor, maximum, private=private))
    if observed != identity:
        raise RuntimeError("proof input issuer sealed original changed before charged read")
    return raw, identity


def _key_on_work(material, root_public_key, work, *, current):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import oidc_session_activation_release_proof_input_issuer_bootstrap as bootstrap

    root = root_public_key
    if type(material) is not bootstrap._IssuerMaterial or not callable(current):
        raise RuntimeError("proof input issuer key requires actual original admission and current guard")
    bootstrap.capture._SharedLedger(work)
    bootstrap.authorization._public(root)
    last_epoch = 0

    def live():
        nonlocal last_epoch
        for guarded in (current, material.live, current):
            epoch = guarded()
            if type(epoch) is not int or epoch <= 0 or epoch < last_epoch:
                raise RuntimeError("proof input issuer key admission clocks reversed")
            last_epoch = epoch
        return last_epoch

    live()
    raw, identity = _read_on_work(KEY_FD, MAX_KEY_BYTES, work, private=True)
    live()
    if len(raw) != material.root_signing_key_byte_count:
        raise RuntimeError("proof input issuer root key size differs from the signed pin")
    work.charge(hashes=1, input_bytes=len(raw))
    digest = bootstrap.production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    live()
    bootstrap.plan._same(digest, material.root_signing_key_digest, work, "proof input issuer root signer original")
    live()
    work.charge(input_bytes=len(raw))
    private = bootstrap.production._callback(work, lambda: serialization.load_pem_private_key(raw, password=None))
    live()
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("proof input issuer runtime root signer is not Ed25519")
    bootstrap.keys._pair_on_work(private, root, work)
    live()
    if _sealed_identity(KEY_FD, MAX_KEY_BYTES, private=True) != identity:
        raise RuntimeError("proof input issuer private descriptor changed during key admission")
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
            raise RuntimeError("proof input issuer listener differs from the fixed activated socket")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("proof input issuer socket pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _tls_unchanged(expected_identity):
    if type(expected_identity) is not tuple or len(expected_identity) != len(_TLS_FILES):
        raise RuntimeError("proof input issuer TLS identity inventory differs")
    for (name, path, maximum, private), observed in zip(_TLS_FILES, expected_identity):
        if type(observed) is not tuple or len(observed) != 3:
            raise RuntimeError("proof input issuer TLS identity record differs")
        actual_name, identity, digest = observed
        if (type(actual_name) is not str or actual_name != name
                or type(identity) is not tuple or len(identity) != 9
                or any(type(value) is not int for value in identity) or not stat.S_ISREG(identity[2])
                or identity[3] != 0 or identity[5] != 1 or not 2 <= identity[6] <= maximum
                or stat.S_IMODE(identity[2]) != (0o440 if private else 0o444)
                or private and identity[4] != SERVICE_GID
                or type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in _HEX for character in digest[7:])):
            raise RuntimeError("proof input issuer held TLS protection differs")
        parent = _parent(path)
        try:
            if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity:
                raise RuntimeError("proof input issuer TLS identity changed")
        finally:
            os.close(parent)


def _tls_identity(tls_files, *, work, current=None):
    from serverware import oidc_session_activation_release_proof_input_issuer_bootstrap as bootstrap

    if type(tls_files) is not dict or set(tls_files) != _TLS_FIELDS:
        raise RuntimeError("proof input issuer TLS pins differ from the original completion inventory")
    bootstrap.capture._SharedLedger(work)
    if current is not None and not callable(current):
        raise RuntimeError("proof input issuer TLS guard differs")
    pins = []
    for name, path, maximum, private in _TLS_FILES:
        record = tls_files[name]
        bootstrap.shape._object(record, frozenset({"byteCount", "bytesDigest"}), "proof input issuer TLS pin")
        bootstrap.shape._integer(record["byteCount"], maximum, minimum=2)
        bootstrap.shape._digest(record["bytesDigest"])
        pins.append((name, path, record["byteCount"], record["bytesDigest"], private))
    identities = []
    for name, path, size, expected, private in pins:
        if current is not None:
            current()
        parent, descriptor, local = _parent(path), None, {}
        try:
            descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
                | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            _claim(descriptor, local)
            value = os.fstat(descriptor)
            if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 1
                    or value.st_size != size or stat.S_IMODE(value.st_mode) != (0o440 if private else 0o444)
                    or private and value.st_gid != SERVICE_GID):
                raise RuntimeError("proof input issuer TLS protection or admitted size differs")
            identity = delivery._material_identity(value)
            if delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity:
                raise RuntimeError("proof input issuer TLS pathname differs")
            work.charge(hashes=1, input_bytes=size + 1)
            digest, remaining = hashlib.sha256(), size
            while remaining:
                if current is not None:
                    current()
                chunk = bootstrap.production._callback(work, lambda: os.read(descriptor, min(4096, remaining)))
                if current is not None:
                    current()
                if not chunk:
                    raise RuntimeError("proof input issuer TLS original truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            if current is not None:
                current()
            extra = bootstrap.production._callback(work, lambda: os.read(descriptor, 1))
            if current is not None:
                current()
            if (extra or "sha256:" + digest.hexdigest() != expected
                    or delivery._material_identity(os.fstat(descriptor)) != identity
                    or delivery._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                        follow_symlinks=False)) != identity):
                raise RuntimeError("proof input issuer TLS original changed")
            identities.append((name, identity, expected))
        finally:
            try:
                if not _close_all_owned(local):
                    raise RuntimeError("proof input issuer TLS cleanup is uncertain")
            finally:
                os.close(parent)
        if current is not None:
            current()
    result = tuple(identities)
    _tls_unchanged(result)
    return result


def _material_bytes_on_work(material, work, current):
    """Measure only this actual admission's retained originals and known graphs."""
    from serverware import oidc_session_activation_release_proof_input_issuer_bootstrap as bootstrap

    if type(material) is not bootstrap._IssuerMaterial:
        raise RuntimeError("proof input issuer capacity requires actual original admission")
    policy = material.policy_material
    if type(policy) is not bootstrap.issuer._IssuerPolicyMaterial:
        raise RuntimeError("proof input issuer capacity lost its original policy")
    completed = policy.completion_material
    originals = (material.bootstrap_bytes, material.issuer_policy_bytes, material.completion_bootstrap_bytes,
        material.proof_enrollment_bytes, material.intent_enrollment_bytes,
        policy.policy_bytes, policy.completion_bootstrap_bytes, policy.proof_enrollment_bytes,
        policy.intent_enrollment_bytes, completed.bootstrap_bytes, completed.custody_bytes,
        completed.planner_bootstrap_bytes, completed.planner_history_custody_bytes,
        completed.receiving_history_custody_bytes, completed.authorization_bytes,
        completed.current_root_enrollment_bytes, completed.grant_enrollment_bytes,
        completed.authorization_enrollment_bytes)
    total = 3 * sum(map(len, originals))
    for graph in (material.launch, policy.payload, policy.proof_scope, policy.proof_launch,
            completed.receiver_identity, completed.configuration_payload, completed.generation,
            completed.runtime_role_identities, completed.expectations, completed.tls_files, completed.launch):
        current()
        measured = bootstrap.issuer.completion.configuration._ConfigurationCapture(
            bootstrap.capture._SharedLedger(work), maximum_bytes=MAX_ORIGINAL_BYTES, retain=False)
        measured.visit(graph)
        total += measured.bytes
        if total >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("proof input issuer retained originals and graphs exceed capacity")
    current()
    return total


class _DeliveryContinuation:
    __slots__ = ("_work", "_lifetime", "_sealed", "_tls", "_listener", "_retained_bytes",
        "_production", "_seal", "_closed")

    def __init__(self):
        raise RuntimeError("proof input issuer continuation requires actual root delivery")

    def _identity(self):
        if (type(self) is not _DeliveryContinuation or self is not _continuation
                or os.getpid() != _PID or self._closed
                or any(actual is not held for actual, held in zip(
                    (self._work, self._lifetime, self._sealed, self._tls, self._listener, self._production),
                    (self._seal[0], self._seal[1], self._seal[2], self._seal[3], self._seal[4], self._seal[6])))
                or self._retained_bytes != self._seal[5] or self._lifetime.work is not self._work
                or type(self._retained_bytes) is not int or not 0 < self._retained_bytes < MAX_ORIGINAL_BYTES):
            raise RuntimeError("proof input issuer delivery identity or capacity changed")
        for descriptor, maximum, private, identity in self._sealed:
            if _sealed_identity(descriptor, maximum, private=private) != identity:
                raise RuntimeError("proof input issuer sealed original changed")
        if _listener(LISTENER_FD) != self._listener:
            raise RuntimeError("proof input issuer held listener changed")
        _tls_unchanged(self._tls)
        # Startup owns its exact accepted/staging sockets and transient reader
        # descriptors. This guard never exempts an arbitrary descriptor set.

    def current(self):
        self._work.charge(input_bytes=8192)
        self._production._callback(self._work, self._identity)
        return self._lifetime.current()


def _retained_bytes_on_work(delivery_current, work, *, live_window=None, transport_deadline_ns=None):
    if (type(delivery_current) is not MethodType
            or delivery_current.__func__ is not _DeliveryContinuation.current
            or type(delivery_current.__self__) is not _DeliveryContinuation
            or delivery_current.__self__ is not _continuation
            or delivery_current.__self__._work is not work):
        raise RuntimeError("proof input issuer requires its actual original delivery continuation")
    selected = delivery_current.__self__
    selected.current()
    if (live_window is None) != (transport_deadline_ns is None):
        raise RuntimeError("proof input issuer processing bounds must be supplied together")
    if live_window is not None:
        from serverware import authority_webauthn_evidence_plan_clock as clock

        window, original = clock._validate(live_window), selected._lifetime.window
        if (type(transport_deadline_ns) is not int or transport_deadline_ns <= 0
                or window[:3] != original[:3]
                or any(value > bound for value, bound in zip(window[3:], original[3:]))
                or transport_deadline_ns > min(selected._lifetime.bound, window[4])):
            raise RuntimeError("proof input issuer widened or reopened its original allowance")
    return selected._retained_bytes


def main():
    global _used, _continuation
    if _used or os.getpid() != _PID or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("proof input issuer delivery must start once in its original root PID")
    _used = True
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("proof input issuer requires one exact activated listener")
    _require_inventory({3})
    owned, reservations, status = {3: None}, {}, 1
    try:
        _claim(3, owned)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import oidc_session_activation_release_proof_input_issuer_bootstrap as bootstrap
        from serverware import oidc_session_activation_release_proof_input_issuer_runner as runner
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = _construction_on_work(work)
        lifetime = bootstrap._Lifetime(window, bound, work, None)
        current = lifetime.current
        current()
        resource_reserve = MAX_KEY_BYTES + sum(item[2] for item in _TLS_FILES)
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            _claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("proof input issuer descriptor slot is already occupied")
            reservations[target] = owned[descriptor]
        sealed_bytes = 0
        for path, target, maximum in _TRUST_FILES:
            source = _open_material(path, maximum, work=work, current=current,
                retained_bytes=sealed_bytes + resource_reserve)
            _claim(source, owned)
            sealed_bytes += os.fstat(source).st_size
            _retain(source, target, reservations, owned)
            if not _close_owned_descriptor(source, owned):
                raise RuntimeError("proof input issuer public source cleanup is uncertain")
        public = []
        for _path, descriptor, maximum in _TRUST_FILES:
            current()
            size = _sealed_identity(descriptor, maximum)[0][6]
            if sealed_bytes + sum(map(len, public)) + size + resource_reserve >= MAX_ORIGINAL_BYTES:
                raise RuntimeError("proof input issuer public reread exceeds retained capacity")
            raw, _identity = _read_on_work(descriptor, maximum, work)
            current()
            public.append(raw)
        root_raw, original, policy_raw, completed_raw, proof_raw, intent_raw = public
        # Covers these held sealed/read copies plus root-original decoding and
        # nested canonical captures before any policy or private-key callback.
        if 6 * sum(map(len, public)) + resource_reserve >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("proof input issuer cold originals exhaust decoding capacity")
        work.charge(input_bytes=len(root_raw))
        current()
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        current()
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("proof input issuer runtime root is not Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=original, issuer_policy_bytes=policy_raw,
            completion_bootstrap_bytes=completed_raw, proof_enrollment_bytes=proof_raw,
            intent_enrollment_bytes=intent_raw, root_public_key=root, live_window=window,
            transport_deadline_ns=bound, work=work, _continuity=lifetime.continuity)
        if type(material) is not bootstrap._IssuerMaterial:
            raise RuntimeError("proof input issuer requires genuine original bootstrap admission")
        lifetime.attach(material.live)
        lifetime.adopt(material.live_window, material.deadline_ns)
        current()
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        if (tuple(launch[name] for name, _descriptor in bootstrap._FD_FIELDS) != INHERITED_DESCRIPTORS
                or bootstrap.INHERITED_DESCRIPTORS != INHERITED_DESCRIPTORS
                or (bootstrap.MAX_BYTES, bootstrap.MAX_POLICY_BYTES, bootstrap.MAX_COMPLETION_BOOTSTRAP_BYTES,
                    bootstrap.MAX_PROOF_ENROLLMENT_BYTES, bootstrap.MAX_INTENT_ENROLLMENT_BYTES,
                    bootstrap.MAX_KEY_BYTES, bootstrap.MAX_ORIGINAL_BYTES)
                    != (MAX_BOOTSTRAP_BYTES, MAX_POLICY_BYTES, MAX_COMPLETION_BOOTSTRAP_BYTES,
                        MAX_PROOF_ENROLLMENT_BYTES, MAX_INTENT_ENROLLMENT_BYTES, MAX_KEY_BYTES, MAX_ORIGINAL_BYTES)
                or _listener(3) != listener_pins):
            raise RuntimeError("proof input issuer launch and actual resource delivery disagree")
        retained = sum(map(len, public)) + resource_reserve + _material_bytes_on_work(material, work, current)
        if retained >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("proof input issuer actual retained inventory exceeds capacity")
        # First private access follows genuine root launch, independent policy,
        # completion and both enrollment original admissions.
        source = _open_material(KEY_PATH, MAX_KEY_BYTES, work=work, current=current,
            private=True, expected_size=material.root_signing_key_byte_count, retained_bytes=retained)
        _claim(source, owned)
        _retain(source, KEY_FD, reservations, owned)
        if not _close_owned_descriptor(source, owned):
            raise RuntimeError("proof input issuer private source cleanup is uncertain")
        _key_on_work(material, root, work, current=current)
        tls = _tls_identity(material.policy_material.completion_material.tls_files, work=work, current=current)
        current()
        _retain(3, LISTENER_FD, reservations, owned)
        if not _close_owned_descriptor(3, owned) or reservations:
            raise RuntimeError("proof input issuer listener handoff cleanup is uncertain")
        for descriptor in INHERITED_DESCRIPTORS:
            if delivery._material_identity(os.fstat(descriptor)) != owned[descriptor]:
                raise RuntimeError("proof input issuer delivered descriptor identity changed")
            os.set_inheritable(descriptor, False)
        descriptions = tuple((descriptor, maximum, False) for _path, descriptor, maximum in _TRUST_FILES) + (
            (KEY_FD, MAX_KEY_BYTES, True),)
        sealed_pins = tuple((descriptor, maximum, private, _sealed_identity(descriptor, maximum, private=private))
            for descriptor, maximum, private in descriptions)
        continuation = object.__new__(_DeliveryContinuation)
        continuation._work, continuation._lifetime = work, lifetime
        continuation._sealed, continuation._tls, continuation._listener = sealed_pins, tls, listener_pins
        continuation._retained_bytes, continuation._production = retained, bootstrap.production
        continuation._closed = False
        continuation._seal = (work, lifetime, sealed_pins, tls, listener_pins, retained, bootstrap.production)
        _continuation = continuation
        continuation.current()
        _require_inventory(INHERITED_DESCRIPTORS)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups():
            raise RuntimeError("proof input issuer delivery retained privilege")
        _require_unprivileged_process()
        continuation.current()
        _require_inventory(INHERITED_DESCRIPTORS)
        os.environ.clear()
        os.environ.update(ENVIRONMENT)
        status = runner._run_on_work(work=work, live_window=lifetime.window,
            transport_deadline_ns=lifetime.bound, delivery_current=continuation.current)
    finally:
        if _continuation is not None:
            _continuation._closed = True
        if not _close_all_owned(owned):
            status = 1
    return status
