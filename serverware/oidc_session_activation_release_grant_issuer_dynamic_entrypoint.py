"""Admit a fresh proof and derive the fixed grant-issuer originals.

No private resource is opened before independent public-original admission.
Staging is not readiness, committed proof, token release or retry permission.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import select
import socket
import stat
import time
from types import MethodType

from serverware import authority_fd_entrypoint as native
from serverware import oidc_session_activation_release_grant_issuer_entrypoint as fixed
from serverware import oidc_session_activation_release_entrypoint as ownership


TRUST_PATH = "/run/serverware/oidc-session-activation-release-grant-issuer-dynamic-trust"
ROOT_PATH = TRUST_PATH + "/root-public-key.pem"
AUTHORIZATION_PATH = TRUST_PATH + "/authorization.json"
POLICY_PATH = TRUST_PATH + "/proof-input-policy.json"
COMPLETION_PATH = TRUST_PATH + "/completion-bootstrap.json"
PROOF_ENROLLMENT_PATH = TRUST_PATH + "/proof-enrollment.json"
INTENT_ENROLLMENT_PATH = TRUST_PATH + "/intent-enrollment.json"
STAGING_PATH = "/run/serverware/oidc-session-activation-token-release/grant-issuer-bootstrap.sock"
STAGING_NAME = "serverware-oidc-session-activation-release-grant-issuer-bootstrap"
ISSUER_NAME = fixed.LISTENER_NAME
STAGING_UID, STAGING_GID = 0, 65494
MAX_ROOT_BYTES, MAX_POLICY_BYTES = 16 * 1024, 64 * 1024
MAX_AUTHORIZATION_BYTES = 64 * 1024
MAX_COMPLETION_BYTES, MAX_ENROLLMENT_BYTES = 32 * 1024 * 1024, 16 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_release_grant_issuer_dynamic_launcher.py"
_PUBLIC_FILES = ((ROOT_PATH, MAX_ROOT_BYTES), (AUTHORIZATION_PATH, MAX_AUTHORIZATION_BYTES),
    (POLICY_PATH, MAX_POLICY_BYTES),
    (COMPLETION_PATH, MAX_COMPLETION_BYTES), (PROOF_ENROLLMENT_PATH, MAX_ENROLLMENT_BYTES),
    (INTENT_ENROLLMENT_PATH, MAX_ENROLLMENT_BYTES))
_PUBLIC_LIMITS = dict(_PUBLIC_FILES)
_PID, _continuation = os.getpid(), None
_used = False


def _parent(path):
    if path not in (*_PUBLIC_LIMITS, STAGING_PATH):
        raise RuntimeError("dynamic grant issuer path is not source fixed")
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
                raise RuntimeError("dynamic grant issuer ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_public(path, maximum, *, owned, work, current):
    if _PUBLIC_LIMITS.get(path) != maximum:
        raise RuntimeError("dynamic grant issuer public-original inventory differs")
    parent, descriptor = _parent(path), None
    try:
        descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        ownership._claim(descriptor, owned)
        value = os.fstat(descriptor)
        identity = native._material_identity(value)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 1
                or stat.S_IMODE(value.st_mode) != 0o444 or not 2 <= value.st_size <= maximum
                or native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("dynamic grant issuer public original protection differs")
        work.charge(input_bytes=value.st_size)
        current()
        raw = native._read_exact_source(descriptor, value.st_size)
        current()
        if (native._material_identity(os.fstat(descriptor)) != identity
                or native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("dynamic grant issuer public original changed during read")
        return raw
    finally:
        try:
            if descriptor is not None and not ownership._close_owned_descriptor(descriptor, owned):
                raise RuntimeError("dynamic grant issuer public-original cleanup is uncertain")
        finally:
            os.close(parent)


def _seal_original(raw, maximum, *, owned, work, current):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise RuntimeError("dynamic grant issuer requires bounded immutable originals")
    work.charge(input_bytes=len(raw))
    current()
    descriptor = os.memfd_create("serverware-dynamic-grant-issuer-original",
        flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    ownership._claim(descriptor, owned)
    try:
        offset = 0
        while offset < len(raw):
            current()
            written = os.write(descriptor, raw[offset:offset + 4096])
            ownership._claim(descriptor, owned)
            current()
            if written <= 0:
                raise RuntimeError("dynamic grant issuer original sealing was incomplete")
            offset += written
        os.fchmod(descriptor, 0o444)
        ownership._claim(descriptor, owned)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        ownership._claim(descriptor, owned)
        os.set_inheritable(descriptor, False)
        current()
        fixed._sealed_identity(descriptor, maximum)
        return descriptor
    except BaseException:
        if not ownership._close_owned_descriptor(descriptor, owned):
            raise RuntimeError("dynamic grant issuer sealed-original cleanup is uncertain")
        raise


def _staging_listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != STAGING_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("dynamic grant issuer staging listener differs")
    finally:
        observed.close()
    parent = _parent(STAGING_PATH)
    try:
        named = os.stat(os.path.basename(STAGING_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (STAGING_UID, STAGING_GID, 0o660)):
            raise RuntimeError("dynamic grant issuer staging pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _activated_descriptors():
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "2":
        raise RuntimeError("dynamic grant issuer requires exactly two activated listeners")
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if len(names) != 2 or set(names) != {STAGING_NAME, ISSUER_NAME}:
        raise RuntimeError("dynamic grant issuer listener names are not the exact distinct pair")
    mapping = dict(zip(names, (3, 4)))
    return mapping[STAGING_NAME], mapping[ISSUER_NAME]


def _close_socket(observed, owned):
    descriptor = observed.fileno()
    if descriptor < 0 or observed.detach() != descriptor:
        return False
    return ownership._close_owned_descriptor(descriptor, owned)


def _accept_once(listener, *, owned, work, current, deadline_ns, production):
    while True:
        current()
        now = production._callback(work, time.monotonic_ns)
        if now >= deadline_ns:
            raise RuntimeError("dynamic grant issuer staging exhausted the original deadline")
        work.charge(input_bytes=4096)
        current()
        ready, _writers, exceptional = production._callback(work,
            lambda: select.select((listener,), (), (listener,), min(1.0, (deadline_ns - now) / 1_000_000_000)))
        current()
        if exceptional:
            raise RuntimeError("dynamic grant issuer staging readiness failed")
        if ready:
            connection, _address = listener.accept()
            try:
                ownership._claim(connection.fileno(), owned)
                connection.setblocking(False)
                connection.set_inheritable(False)
                current()
                return connection
            except BaseException:
                if not _close_socket(connection, owned):
                    raise RuntimeError("dynamic grant issuer accepted cleanup is uncertain")
                raise


def _graphs_on_work(graphs, work, current):
    from serverware import oidc_session_activation_delivery_completion_bootstrap as completed

    total = 0
    for graph in graphs:
        current()
        measured = completed.configuration._ConfigurationCapture(
            completed.capture._SharedLedger(work), maximum_bytes=MAX_ORIGINAL_BYTES, retain=False)
        measured.visit(graph)
        total += measured.bytes
        if total >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("dynamic grant issuer known graphs exceed retained capacity")
    current()
    return total


def _completion_inventory(completed):
    return ((completed.bootstrap_bytes, completed.custody_bytes, completed.planner_bootstrap_bytes,
        completed.planner_history_custody_bytes, completed.receiving_history_custody_bytes,
        completed.authorization_bytes, completed.current_root_enrollment_bytes,
        completed.grant_enrollment_bytes, completed.authorization_enrollment_bytes),
        (completed.receiver_identity, completed.configuration_payload, completed.generation,
            completed.runtime_role_identities, completed.expectations, completed.tls_files, completed.launch))


def _authorization_bytes_on_work(material, work, current):
    from serverware import oidc_session_activation_release_grant_issuer_dynamic_authorization as authorization

    if type(material) is not authorization._AuthorizationMaterial:
        raise RuntimeError("dynamic grant issuer capacity requires original cold authorization")
    policy = material.input_policy_material
    nested, graphs = _completion_inventory(policy.completion_material)
    originals = (material.authorization_bytes, material.proof_input_issuer_policy_bytes,
        material.completion_bootstrap_bytes, material.proof_enrollment_bytes, material.intent_enrollment_bytes,
        policy.policy_bytes, policy.completion_bootstrap_bytes, policy.proof_enrollment_bytes,
        policy.intent_enrollment_bytes, *nested)
    total = 3 * sum(map(len, originals)) + _graphs_on_work(
        (material.payload, material.issuer_launch, policy.payload, policy.proof_scope, policy.proof_launch, *graphs),
        work, current)
    if total >= MAX_ORIGINAL_BYTES:
        raise RuntimeError("dynamic grant issuer cold retained originals exceed capacity")
    return total


def _proof_bytes_on_work(material, work, current):
    from serverware import oidc_session_activation_release_proof_bootstrap as proof

    if type(material) is not proof._ProofMaterial:
        raise RuntimeError("dynamic grant issuer capacity requires genuine proof original admission")
    nested, graphs = _completion_inventory(material.completion_material)
    originals = (material.bootstrap_bytes, material.completion_bootstrap_bytes, material.proof_enrollment_bytes,
        material.release_custody_bytes, material.intent_bytes, material.intent_enrollment_bytes,
        material.completion_request_bytes, material.state_receipt_bytes, *nested)
    total = 3 * sum(map(len, originals)) + _graphs_on_work(
        (material.expected_proof_scope, material.expected_release, material.expected_consume_binding,
            material.launch, *graphs), work, current)
    if total >= MAX_ORIGINAL_BYTES:
        raise RuntimeError("dynamic grant issuer proof retained inventory exceeds capacity")
    return total


def _material_bytes_on_work(material, work, current):
    from serverware import oidc_session_activation_release_grant_issuer_bootstrap as bootstrap

    if type(material) is not bootstrap._IssuerMaterial:
        raise RuntimeError("dynamic grant issuer capacity requires the actual derived cold originals")
    policy = material.policy_material
    total = (3 * sum(map(len, (material.bootstrap_bytes, material.issuer_policy_bytes,
        material.proof_bootstrap_bytes, policy.policy_bytes, policy.proof_bootstrap_bytes)))
        + _graphs_on_work((material.launch, policy.payload), work, current)
        + _proof_bytes_on_work(policy.proof_material, work, current))
    if total >= MAX_ORIGINAL_BYTES:
        raise RuntimeError("dynamic grant issuer derived retained inventory exceeds capacity")
    return total


def _admit_signer_on_work(admitted, root, work, current):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import oidc_session_activation_release_grant_issuer_dynamic_authorization as authorization
    from serverware import oidc_session_activation_release_grant_issuer_bootstrap as bootstrap

    if type(admitted) is not authorization._AdmittedMaterial:
        raise RuntimeError("dynamic grant signer requires exact fresh-proof original admission")
    material = admitted.authorization_material
    current()
    raw, identity = fixed._read_on_work(fixed.KEY_FD, fixed.MAX_KEY_BYTES, work, private=True)
    current()
    if len(raw) != material.root_signing_key_byte_count:
        raise RuntimeError("dynamic grant signer size differs from the independently signed pin")
    work.charge(hashes=1, input_bytes=len(raw))
    digest = bootstrap.production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    current()
    bootstrap.plan._same(digest, material.root_signing_key_digest, work, "dynamic grant issuer root signer")
    work.charge(input_bytes=len(raw))
    current()
    key = bootstrap.production._callback(work, lambda: serialization.load_pem_private_key(raw, password=None))
    current()
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("dynamic grant issuer signer must be the actual Ed25519 runtime root")
    bootstrap.keys._pair_on_work(key, root, work)
    current()
    if fixed._sealed_identity(fixed.KEY_FD, fixed.MAX_KEY_BYTES, private=True) != identity:
        raise RuntimeError("dynamic grant issuer signer original changed")
    current()
    return key


class _DeliveryContinuation:
    __slots__ = ("_work", "_lifetime", "_sealed", "_listener", "_retained_bytes", "_production", "_seal", "_closed")

    def __init__(self):
        raise RuntimeError("dynamic grant issuer continuation requires actual root delivery")

    def _identity(self):
        if (type(self) is not _DeliveryContinuation or self is not _continuation
                or os.getpid() != _PID or self._closed
                or any(actual is not held for actual, held in zip(
                    (self._work, self._lifetime, self._sealed, self._listener, self._production),
                    (self._seal[0], self._seal[1], self._seal[2], self._seal[3], self._seal[5])))
                or self._retained_bytes != self._seal[4] or self._lifetime.work is not self._work
                or type(self._retained_bytes) is not int or not 0 < self._retained_bytes < MAX_ORIGINAL_BYTES):
            raise RuntimeError("dynamic grant issuer retained delivery identity changed")
        for descriptor, maximum, private, identity in self._sealed:
            if fixed._sealed_identity(descriptor, maximum, private=private) != identity:
                raise RuntimeError("dynamic grant issuer sealed original changed")
        if fixed._listener(fixed.LISTENER_FD) != self._listener:
            raise RuntimeError("dynamic grant issuer admitted listener changed")
        # The genuine startup separately owns accepted and staging sockets.

    def current(self):
        self._work.charge(input_bytes=4096)
        self._production._callback(self._work, self._identity)
        return self._lifetime.current()


def _retained_bytes_on_work(delivery_current, work, *, live_window=None, transport_deadline_ns=None):
    if (type(delivery_current) is not MethodType
            or delivery_current.__func__ is not _DeliveryContinuation.current
            or type(delivery_current.__self__) is not _DeliveryContinuation
            or delivery_current.__self__ is not _continuation
            or delivery_current.__self__._work is not work):
        raise RuntimeError("dynamic grant issuer requires its actual source-bound continuation")
    selected = delivery_current.__self__
    selected.current()
    if (live_window is None) != (transport_deadline_ns is None):
        raise RuntimeError("dynamic grant issuer processing bounds must be paired")
    if live_window is not None:
        from serverware import authority_webauthn_evidence_plan_clock as clock

        window, original = clock._validate(live_window), selected._lifetime.window
        if (type(transport_deadline_ns) is not int or transport_deadline_ns <= 0
                or window[:3] != original[:3]
                or any(value > bound for value, bound in zip(window[3:], original[3:]))
                or transport_deadline_ns > min(selected._lifetime.bound, window[4])):
            raise RuntimeError("dynamic grant issuer reset or widened its original allowance")
    return selected._retained_bytes


def _continuity_on_work(delivery_current, work, epoch, monotonic):
    """Exchange only restrictive floors with this PID's actual delivery owner."""
    _retained_bytes_on_work(delivery_current, work)
    selected = delivery_current.__self__
    selected._lifetime.continuity(epoch, monotonic)
    selected.current()
    return selected._lifetime.epoch, selected._lifetime.monotonic


def main():
    global _used, _continuation
    if _used or os.getpid() != _PID or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("dynamic grant issuer delivery must start once in its original root PID")
    _used = True
    intake_fd, issuer_fd = _activated_descriptors()
    fixed._require_inventory({intake_fd, issuer_fd})
    owned, reservations = {}, {}
    listener = connection = None
    status = 1
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import oidc_session_activation_release_grant_issuer_dynamic_authorization as authorization
        from serverware import oidc_session_activation_release_grant_issuer_bootstrap as bootstrap
        from serverware import oidc_session_activation_release_grant_issuer_runner as runner
        from serverware import authority_oidc_session_activation_release_grant_input_delivery_transport as transport
        from serverware import authority_oidc_session_activation_release_grant_transport as issuer_transport
        from serverware import authority_oidc_session_activation_release_grant_production as producer
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        ownership._claim(intake_fd, owned)
        ownership._claim(issuer_fd, owned)
        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = fixed._construction_on_work(work)
        lifetime = producer._Lifetime(window, bound, work, None)
        current = lifetime.current
        current()
        os.set_blocking(intake_fd, False)
        os.set_blocking(issuer_fd, False)
        staging_pins, issuer_pins = _staging_listener(intake_fd), fixed._listener(issuer_fd)
        for target in fixed.INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(issuer_fd, fcntl.F_DUPFD_CLOEXEC, target)
            ownership._claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("dynamic grant issuer inherited slot is occupied")
            reservations[target] = owned[descriptor]
        public = tuple(_read_public(path, maximum, owned=owned, work=work, current=current)
            for path, maximum in _PUBLIC_FILES)
        root_raw, authorization_raw, policy_raw, completion_raw, proof_enrollment, intent_enrollment = public
        if 6 * sum(map(len, public)) + fixed.MAX_KEY_BYTES >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("dynamic grant issuer cold public decoding exceeds capacity")
        work.charge(input_bytes=len(root_raw))
        current()
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        current()
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("dynamic grant issuer requires the actual runtime Ed25519 root")
        originals = dict(authorization_bytes=authorization_raw,
            proof_input_issuer_policy_bytes=policy_raw, completion_bootstrap_bytes=completion_raw,
            proof_enrollment_bytes=proof_enrollment, intent_enrollment_bytes=intent_enrollment,
            root_public_key=root, work=work, _continuity=lifetime.continuity)
        static = authorization._verify_on_work(**originals, live_window=lifetime.window,
            transport_deadline_ns=lifetime.bound,
            maximum_original_bytes=MAX_ORIGINAL_BYTES - sum(map(len, public)) - fixed.MAX_KEY_BYTES)
        if type(static) is not authorization._AuthorizationMaterial:
            raise RuntimeError("dynamic grant issuer independent authorization was not admitted")
        lifetime.attach(static.live)
        lifetime.adopt(static.live_window, static.deadline_ns)
        intake = static.payload["intake"]
        named_pins = tuple(intake[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        launch_pins = tuple(static.issuer_launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        if ((intake["path"], intake["peerUid"], intake["peerGid"])
                != (STAGING_PATH, transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID)
                or named_pins != staging_pins or launch_pins != issuer_pins
                or tuple(static.issuer_launch[name] for name, _fd in bootstrap._FD_FIELDS) != fixed.INHERITED_DESCRIPTORS):
            raise RuntimeError("dynamic grant issuer independent listener/resource pins differ")
        timeout = min(intake["requestTimeoutSeconds"], static.issuer_launch["requestTimeoutSeconds"]) * 1_000_000_000
        lifetime.narrow(lifetime.window[0] + timeout, min(lifetime.window[5], timeout), lifetime.window[6])
        held = sum(map(len, public)) + _authorization_bytes_on_work(static, work, current) + fixed.MAX_KEY_BYTES
        reserve = (producer._OUTPUT_RESERVATION + issuer_transport.MAX_REQUEST_BYTES
            + issuer_transport.REQUEST_HEADER_BYTES + issuer_transport.RESPONSE_HEADER_BYTES
            + transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES + transport.MAX_RESPONSE_BYTES
            + len(transport.PURPOSE) + 4 * (fixed.MAX_POLICY_BYTES + fixed.MAX_BOOTSTRAP_BYTES))
        maximum = min(fixed.MAX_PROOF_BOOTSTRAP_BYTES, (MAX_ORIGINAL_BYTES - held - reserve) // 8)
        if maximum < 2:
            raise RuntimeError("dynamic grant issuer cold inventory leaves no bounded staging capacity")
        current()
        if _staging_listener(intake_fd) != staging_pins or fixed._listener(issuer_fd) != issuer_pins:
            raise RuntimeError("dynamic grant issuer listeners changed before intake")
        fixed._require_inventory(tuple(owned))
        listener = socket.socket(fileno=intake_fd)
        connection = _accept_once(listener, owned=owned, work=work, current=current,
            deadline_ns=lifetime.bound, production=bootstrap.production)
        # The actual codec checks the source-fixed issuer peer before bytes.
        request = transport._recv_request(connection, deadline_ns=lifetime.bound, work=work,
            current=current, maximum_original_bytes=maximum)
        current()
        admitted = authorization._admit_on_work(**originals, proof_bootstrap_bytes=request[1],
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            maximum_original_bytes=MAX_ORIGINAL_BYTES - held - reserve)
        if type(admitted) is not authorization._AdmittedMaterial:
            raise RuntimeError("dynamic grant issuer exact fresh proof was not independently admitted")
        lifetime.attach(admitted.live)
        lifetime.adopt(admitted.live_window, admitted.deadline_ns)
        work.charge(input_bytes=len(request[1]) + len(admitted.proof_bootstrap_bytes))
        if admitted.proof_bootstrap_bytes != request[1]:
            raise RuntimeError("dynamic grant issuer admission replaced the exact proof original")
        held += (_authorization_bytes_on_work(admitted.authorization_material, work, current)
            + _proof_bytes_on_work(admitted.proof_material, work, current) + len(request[1]))
        if held + reserve >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("dynamic grant issuer fresh-proof graphs exhaust capacity")
        # Private signer access begins only after both independent static and
        # exact fresh original admissions. Old successful material is not forged.
        source = fixed._open_material(fixed.KEY_PATH, fixed.MAX_KEY_BYTES, work=work, current=current,
            private=True, expected_size=admitted.authorization_material.root_signing_key_byte_count)
        ownership._claim(source, owned)
        ownership._retain(source, fixed.KEY_FD, reservations, owned)
        if not ownership._close_owned_descriptor(source, owned):
            raise RuntimeError("dynamic grant issuer root key handoff is uncertain")
        key = _admit_signer_on_work(admitted, root, work, current)
        produced = authorization._produce_on_work(**originals, proof_bootstrap_bytes=request[1],
            root_private_key=key, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            maximum_original_bytes=MAX_ORIGINAL_BYTES - held - reserve)
        current()
        if (type(produced) is not tuple or len(produced) != 2
                or any(type(raw) is not bytes for raw in produced)
                or not 2 <= len(produced[0]) <= fixed.MAX_POLICY_BYTES
                or not 2 <= len(produced[1]) <= fixed.MAX_BOOTSTRAP_BYTES):
            raise RuntimeError("dynamic grant issuer derived originals differ from the old closed grammars")
        policy, original = produced
        material = bootstrap._verify_on_work(bootstrap_bytes=original, issuer_policy_bytes=policy,
            proof_bootstrap_bytes=request[1], root_public_key=root, live_window=lifetime.window,
            transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
        if type(material) is not bootstrap._IssuerMaterial or material.delivery_endpoint is None:
            raise RuntimeError("dynamic grant issuer requires genuine derived staging-enabled old originals")
        lifetime.attach(material.live)
        lifetime.adopt(material.live_window, material.deadline_ns)
        if tuple(material.launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode")) != issuer_pins:
            raise RuntimeError("dynamic grant issuer derived launch changed its independently pinned listener")
        for raw, maximum, target in ((root_raw, fixed.MAX_ROOT_BYTES, fixed.ROOT_FD),
                (original, fixed.MAX_BOOTSTRAP_BYTES, fixed.BOOTSTRAP_FD),
                (policy, fixed.MAX_POLICY_BYTES, fixed.POLICY_FD),
                (request[1], fixed.MAX_PROOF_BOOTSTRAP_BYTES, fixed.PROOF_BOOTSTRAP_FD)):
            source = _seal_original(raw, maximum, owned=owned, work=work, current=current)
            ownership._retain(source, target, reservations, owned)
            if not ownership._close_owned_descriptor(source, owned):
                raise RuntimeError("dynamic grant issuer original handoff cleanup is uncertain")
        fixed._key_on_work(material, root, work, current=current)
        del key
        ownership._retain(issuer_fd, fixed.LISTENER_FD, reservations, owned)
        if not ownership._close_owned_descriptor(issuer_fd, owned) or reservations:
            raise RuntimeError("dynamic grant issuer listener handoff cleanup is uncertain")
        descriptions = ((fixed.ROOT_FD, fixed.MAX_ROOT_BYTES, False),
            (fixed.BOOTSTRAP_FD, fixed.MAX_BOOTSTRAP_BYTES, False),
            (fixed.POLICY_FD, fixed.MAX_POLICY_BYTES, False),
            (fixed.PROOF_BOOTSTRAP_FD, fixed.MAX_PROOF_BOOTSTRAP_BYTES, False),
            (fixed.KEY_FD, fixed.MAX_KEY_BYTES, True))
        seals = tuple((descriptor, maximum, private, fixed._sealed_identity(descriptor, maximum, private=private))
            for descriptor, maximum, private in descriptions)
        retained = held + sum(map(len, produced)) + _material_bytes_on_work(material, work, current)
        if retained + reserve >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("dynamic grant issuer complete held originals exhaust capacity")
        continuation = object.__new__(_DeliveryContinuation)
        continuation._work, continuation._lifetime = work, lifetime
        continuation._sealed, continuation._listener = seals, issuer_pins
        continuation._retained_bytes, continuation._production = retained, bootstrap.production
        continuation._closed = False
        continuation._seal = (work, lifetime, seals, issuer_pins, retained, bootstrap.production)
        _continuation = continuation
        current = continuation.current
        current()
        if _staging_listener(intake_fd) != staging_pins:
            raise RuntimeError("dynamic grant issuer intake changed before its exact ACK")
        identity = transport._bootstrap_identity_on_work(request[1], deadline_ns=lifetime.bound, work=work, current=current)
        work.charge(input_bytes=len(identity) + len(admitted.bootstrap_identity))
        if identity != admitted.bootstrap_identity:
            raise RuntimeError("dynamic grant issuer staged proof identity differs")
        fixed._require_inventory(tuple(owned))
        transport._send_response(connection, (transport.ACK_STATUS, identity),
            deadline_ns=lifetime.bound, work=work, current=current)
        if not _close_socket(connection, owned):
            raise RuntimeError("dynamic grant issuer staging connection close is uncertain")
        connection = None
        if not _close_socket(listener, owned):
            raise RuntimeError("dynamic grant issuer staging listener close is uncertain")
        listener = None
        current()
        fixed._require_inventory(fixed.INHERITED_DESCRIPTORS)
        os.setgroups([])
        os.setresgid(fixed.SERVICE_GID, fixed.SERVICE_GID, fixed.SERVICE_GID)
        os.setresuid(fixed.SERVICE_UID, fixed.SERVICE_UID, fixed.SERVICE_UID)
        if os.getresuid() != (fixed.SERVICE_UID,) * 3 or os.getresgid() != (fixed.SERVICE_GID,) * 3 or os.getgroups():
            raise RuntimeError("dynamic grant issuer did not permanently drop its root privilege")
        fixed._require_unprivileged_process()
        current()
        fixed._require_inventory(fixed.INHERITED_DESCRIPTORS)
        os.environ.clear()
        os.environ.update(fixed.ENVIRONMENT)
        status = runner._run_from_dynamic_delivery_on_work(work=work, live_window=lifetime.window,
            transport_deadline_ns=lifetime.bound, delivery_current=current)
    finally:
        if _continuation is not None:
            _continuation._closed = True
        for observed in (connection, listener):
            if observed is not None:
                try:
                    if not _close_socket(observed, owned):
                        status = 1
                except BaseException:
                    status = 1
        if not ownership._close_all_owned(owned):
            status = 1
    return status
