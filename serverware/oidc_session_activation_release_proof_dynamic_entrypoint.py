"""Stage a policy-bound proof original and continue the existing private worker.

No private resource is opened before independent public-original admission.
Staging is not readiness, committed proof, token release or retry permission.
"""
from __future__ import annotations

import fcntl
import os
import select
import socket
import stat
import time
from types import MethodType

from serverware import authority_fd_entrypoint as native
from serverware import oidc_session_activation_release_proof_entrypoint as fixed
from serverware import oidc_session_activation_release_entrypoint as ownership


TRUST_PATH = "/run/serverware/oidc-session-activation-release-proof-dynamic-trust"
ROOT_PATH = TRUST_PATH + "/root-public-key.pem"
POLICY_PATH = TRUST_PATH + "/issuer-policy.json"
COMPLETION_PATH = TRUST_PATH + "/completion-bootstrap.json"
PROOF_ENROLLMENT_PATH = TRUST_PATH + "/proof-enrollment.json"
INTENT_ENROLLMENT_PATH = TRUST_PATH + "/intent-enrollment.json"
STAGING_PATH = "/run/serverware/oidc-session-activation-token-release/proof-bootstrap.sock"
STAGING_NAME = "serverware-oidc-session-activation-release-proof-bootstrap"
PROOF_NAME = fixed.LISTENER_NAME
STAGING_UID, STAGING_GID = 0, 65494
MAX_ROOT_BYTES, MAX_POLICY_BYTES = 16 * 1024, 6 * 1024 * 1024
MAX_COMPLETION_BYTES, MAX_ENROLLMENT_BYTES = 32 * 1024 * 1024, 16 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_release_proof_dynamic_launcher.py"
_PUBLIC_FILES = ((ROOT_PATH, MAX_ROOT_BYTES), (POLICY_PATH, MAX_POLICY_BYTES),
    (COMPLETION_PATH, MAX_COMPLETION_BYTES), (PROOF_ENROLLMENT_PATH, MAX_ENROLLMENT_BYTES),
    (INTENT_ENROLLMENT_PATH, MAX_ENROLLMENT_BYTES))
_PUBLIC_LIMITS = dict(_PUBLIC_FILES)
_PID, _continuation = os.getpid(), None
_used = False


def _parent(path):
    if path not in (*_PUBLIC_LIMITS, STAGING_PATH):
        raise RuntimeError("dynamic proof path is not source fixed")
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
                raise RuntimeError("dynamic proof ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_public(path, maximum, *, owned, work, current):
    if _PUBLIC_LIMITS.get(path) != maximum:
        raise RuntimeError("dynamic proof public-original inventory differs")
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
            raise RuntimeError("dynamic proof public original protection differs")
        work.charge(input_bytes=value.st_size)
        current()
        raw = native._read_exact_source(descriptor, value.st_size)
        current()
        if (native._material_identity(os.fstat(descriptor)) != identity
                or native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("dynamic proof public original changed during read")
        return raw
    finally:
        try:
            if descriptor is not None and not ownership._close_owned_descriptor(descriptor, owned):
                raise RuntimeError("dynamic proof public-original cleanup is uncertain")
        finally:
            os.close(parent)


def _seal_original(raw, maximum, *, owned, work, current):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise RuntimeError("dynamic proof requires bounded immutable originals")
    work.charge(input_bytes=len(raw))
    current()
    descriptor = os.memfd_create("serverware-dynamic-proof-original",
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
                raise RuntimeError("dynamic proof original sealing was incomplete")
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
            raise RuntimeError("dynamic proof sealed-original cleanup is uncertain")
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
            raise RuntimeError("dynamic proof staging listener differs")
    finally:
        observed.close()
    parent = _parent(STAGING_PATH)
    try:
        named = os.stat(os.path.basename(STAGING_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (STAGING_UID, STAGING_GID, 0o660)):
            raise RuntimeError("dynamic proof staging pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _activated_descriptors():
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "2":
        raise RuntimeError("dynamic proof requires exactly two activated listeners")
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if len(names) != 2 or set(names) != {STAGING_NAME, PROOF_NAME}:
        raise RuntimeError("dynamic proof listener names are not the exact distinct pair")
    mapping = dict(zip(names, (3, 4)))
    return mapping[STAGING_NAME], mapping[PROOF_NAME]


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
            raise RuntimeError("dynamic proof staging exhausted the original deadline")
        work.charge(input_bytes=4096)
        current()
        ready, _writers, exceptional = production._callback(work,
            lambda: select.select((listener,), (), (listener,), min(1.0, (deadline_ns - now) / 1_000_000_000)))
        current()
        if exceptional:
            raise RuntimeError("dynamic proof staging readiness failed")
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
                    raise RuntimeError("dynamic proof accepted cleanup is uncertain")
                raise


class _DeliveryContinuation:
    """Source-bound sealed-original/resource continuity, never authority data."""

    __slots__ = ("_work", "_lifetime", "_sealed", "_tls", "_listener", "_retained_bytes",
        "_seal", "_closed", "_production")

    def __init__(self):
        raise RuntimeError("dynamic proof continuation requires actual root delivery")

    def _identity(self):
        if (type(self) is not _DeliveryContinuation or self is not _continuation
                or os.getpid() != _PID or self._closed
                or any(actual is not held for actual, held in zip(
                    (self._work, self._lifetime, self._sealed, self._tls, self._listener, self._production),
                    (self._seal[0], self._seal[1], self._seal[2], self._seal[3], self._seal[4], self._seal[6])))
                or self._retained_bytes != self._seal[5]
                or self._lifetime.work is not self._work
                or type(self._retained_bytes) is not int or not 0 < self._retained_bytes < MAX_ORIGINAL_BYTES):
            raise RuntimeError("dynamic proof continuation identity or retained capacity changed")
        for descriptor, maximum, private, identity in self._sealed:
            if fixed._sealed_identity(descriptor, maximum, private=private) != identity:
                raise RuntimeError("dynamic proof sealed original changed")
        if fixed._listener(fixed.LISTENER_FD) != self._listener:
            raise RuntimeError("dynamic proof listener changed")
        fixed._tls_unchanged(self._tls)
        # The genuine worker owns its exact accepted and transient reader FDs.

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
        raise RuntimeError("dynamic proof requires its actual original-bound continuation")
    selected = delivery_current.__self__
    selected.current()
    if (live_window is None) != (transport_deadline_ns is None):
        raise RuntimeError("dynamic proof processing bounds must be supplied together")
    if live_window is not None:
        from serverware import authority_webauthn_evidence_plan_clock as clock

        window, original = clock._validate(live_window), selected._lifetime.window
        if (type(transport_deadline_ns) is not int or transport_deadline_ns <= 0
                or window[:3] != original[:3]
                or any(value > bound for value, bound in zip(window[3:], original[3:]))
                or transport_deadline_ns > min(selected._lifetime.bound, window[4])):
            raise RuntimeError("dynamic proof worker widened or reopened the original allowance")
    return selected._retained_bytes


def _material_bytes_on_work(material, work, current):
    """Measure actual held proof originals and their bounded public projections."""
    from serverware import oidc_session_activation_release_proof_bootstrap as bootstrap

    if type(material) is not bootstrap._ProofMaterial:
        raise RuntimeError("dynamic proof capacity requires its actual original admission")
    completion = material.completion_material
    originals = (material.bootstrap_bytes, material.completion_bootstrap_bytes,
        material.proof_enrollment_bytes, material.release_custody_bytes, material.intent_bytes,
        material.intent_enrollment_bytes, material.completion_request_bytes, material.state_receipt_bytes,
        completion.bootstrap_bytes, completion.custody_bytes, completion.planner_bootstrap_bytes,
        completion.planner_history_custody_bytes, completion.receiving_history_custody_bytes,
        completion.authorization_bytes, completion.current_root_enrollment_bytes,
        completion.grant_enrollment_bytes, completion.authorization_enrollment_bytes)
    graphs = (material.expected_proof_scope, material.expected_release,
        material.expected_consume_binding, material.launch, completion.receiver_identity,
        completion.configuration_payload, completion.generation, completion.runtime_role_identities,
        completion.expectations, completion.tls_files, completion.launch)
    if material.current_activation_planner_bytes is not None:
        planner = material.current_activation_planner
        if type(planner) is not bootstrap.release_bootstrap.planner_bootstrap._PlannerMaterial:
            raise RuntimeError("dynamic proof lost its genuine current planner template")
        originals += (material.current_activation_planner_bytes, planner.bootstrap_bytes,
            planner.state_enrollment_bytes, planner.complete_root_vector_bytes)
        graphs += (planner.configuration_payload, planner.generation, planner.runtime_role_identities,
            planner.planner_identity, planner.authn_policy, planner.trust_policy,
            planner.tls_files, planner.launch)
    # Reserve the actual encoded originals again for their nested verifier
    # snapshots, detached scalar projections and canonical comparison buffers.
    total = 3 * sum(map(len, originals))
    for graph in graphs:
        current()
        measured = bootstrap.completion.configuration._ConfigurationCapture(
            bootstrap.capture._SharedLedger(work), maximum_bytes=MAX_ORIGINAL_BYTES, retain=False)
        measured.visit(graph)
        total += measured.bytes
        if total >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("dynamic proof retained originals and graphs exceed the complete inventory")
    current()
    return total


def _policy_bytes_on_work(policy, work, current):
    from serverware import oidc_session_activation_release_proof_input_issuer_policy as issuer

    if type(policy) is not issuer._IssuerPolicyMaterial:
        raise RuntimeError("dynamic proof capacity requires the independent original policy")
    completion = policy.completion_material
    originals = (policy.policy_bytes, policy.completion_bootstrap_bytes, policy.proof_enrollment_bytes,
        policy.intent_enrollment_bytes, completion.bootstrap_bytes, completion.custody_bytes,
        completion.planner_bootstrap_bytes, completion.planner_history_custody_bytes,
        completion.receiving_history_custody_bytes, completion.authorization_bytes,
        completion.current_root_enrollment_bytes, completion.grant_enrollment_bytes,
        completion.authorization_enrollment_bytes)
    graphs = (policy.payload, policy.proof_scope, policy.proof_launch,
        completion.receiver_identity, completion.configuration_payload, completion.generation,
        completion.runtime_role_identities, completion.expectations, completion.tls_files, completion.launch)
    if policy.current_activation_planner_bytes is not None:
        planner = policy.current_activation_planner
        if type(planner) is not issuer.bootstrap.release_bootstrap.planner_bootstrap._PlannerMaterial:
            raise RuntimeError("dynamic proof policy lost its genuine current planner template")
        originals += (policy.current_activation_planner_bytes, planner.bootstrap_bytes,
            planner.state_enrollment_bytes, planner.complete_root_vector_bytes)
        graphs += (planner.configuration_payload, planner.generation, planner.runtime_role_identities,
            planner.planner_identity, planner.authn_policy, planner.trust_policy,
            planner.tls_files, planner.launch)
    total = 3 * sum(map(len, originals))
    for graph in graphs:
        current()
        measured = issuer.completion.configuration._ConfigurationCapture(
            issuer.capture._SharedLedger(work), maximum_bytes=MAX_ORIGINAL_BYTES, retain=False)
        measured.visit(graph)
        total += measured.bytes
        if total >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("dynamic proof independent policy exhausts the complete retained inventory")
    current()
    return total


def main():
    global _used, _continuation
    if _used or os.getpid() != _PID or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("dynamic proof delivery must start once in its original root PID")
    _used = True
    staging_fd, proof_fd = _activated_descriptors()
    fixed._require_inventory({3, 4})
    owned, reservations = {3: None, 4: None}, {}
    staging = connection = None
    try:
        ownership._claim(3, owned)
        ownership._claim(4, owned)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping
        from serverware import authority_oidc_session_activation_release_proof_input_delivery_transport as transport
        from serverware import authority_oidc_session_activation_release_proof_production as producer
        from serverware import authority_oidc_session_activation_release_proof_transport as proof_transport
        from serverware import oidc_session_activation_release_proof_input_delivery_admission as admission
        from serverware import oidc_session_activation_release_proof_input_issuer_policy as issuer
        from serverware import oidc_session_activation_release_proof_runner as runner
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = fixed._construction_on_work(work)
        # Source-private clock/ledger bookkeeping is not receiving authority.
        lifetime = bookkeeping._Lifetime(window, bound, work, None)
        current, production = lifetime.current, issuer.production
        current()
        os.set_blocking(staging_fd, False)
        os.set_blocking(proof_fd, False)
        staging_pins = _staging_listener(staging_fd)
        fixed._listener(proof_fd)
        for target in fixed.INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(proof_fd, fcntl.F_DUPFD_CLOEXEC, target)
            ownership._claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("dynamic proof inherited descriptor slot is occupied")
            reservations[target] = owned[descriptor]
        public = tuple(_read_public(path, maximum, owned=owned, work=work, current=current)
            for path, maximum in _PUBLIC_FILES)
        root_raw, policy_raw, completion_raw, proof_enrollment, intent_enrollment = public
        if (issuer.MAX_BYTES != MAX_POLICY_BYTES or issuer.MAX_COMPLETION_BOOTSTRAP_BYTES != MAX_COMPLETION_BYTES
                or fixed.MAX_BOOTSTRAP_BYTES != 48 * 1024 * 1024):
            raise RuntimeError("dynamic proof public-original source limits differ")
        work.charge(input_bytes=len(root_raw))
        current()
        root = production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        current()
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("dynamic proof runtime root must be Ed25519")
        if (sum(map(len, public)) + issuer._cold_reservation_bytes(
                len(policy_raw), len(completion_raw), len(proof_enrollment), len(intent_enrollment))
                + transport.MAX_RESPONSE_BYTES >= MAX_ORIGINAL_BYTES):
            raise RuntimeError("dynamic proof policy admission exceeds its original capacity")
        policy = issuer._verify_on_work(policy_bytes=policy_raw, completion_bootstrap_bytes=completion_raw,
            proof_enrollment_bytes=proof_enrollment, intent_enrollment_bytes=intent_enrollment,
            root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            work=work, _continuity=lifetime.continuity)
        if type(policy) is not issuer._IssuerPolicyMaterial:
            raise RuntimeError("dynamic proof requires genuine independent policy admission")
        lifetime.attach(policy.live)
        lifetime.adopt(policy.live_window, policy.deadline_ns)
        timeout = policy.proof_launch["requestTimeoutSeconds"] * 1_000_000_000
        lifetime.narrow(lifetime.window[0] + timeout, min(timeout, lifetime.window[5]), lifetime.window[6])
        held = sum(map(len, public)) + _policy_bytes_on_work(policy, work, current)
        resources = sum(maximum for _path, _descriptor, maximum in fixed._KEY_FILES)
        resources += sum(maximum for _name, _path, maximum, _private in fixed._TLS_FILES)
        reserve = (resources + proof_transport.MAX_RESPONSE_BYTES + proof_transport.REQUEST_HEADER_BYTES
            + proof_transport.RESPONSE_HEADER_BYTES + proof_transport.MAX_REQUEST_BYTES
            + transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES
            + transport.MAX_RESPONSE_BYTES + len(transport.PURPOSE) + 2 * producer.MAX_GRAPH_BYTES)
        # Input, nested originals, decode/capture and canonical comparison
        # allocations share this conservative pre-body reservation.
        maximum_original = min(fixed.MAX_BOOTSTRAP_BYTES, (MAX_ORIGINAL_BYTES - held - reserve) // 8)
        if maximum_original < 2:
            raise RuntimeError("dynamic proof has no complete incoming-original capacity")
        source = _seal_original(root_raw, MAX_ROOT_BYTES, owned=owned, work=work, current=current)
        ownership._retain(source, fixed.ROOT_FD, reservations, owned)
        if not ownership._close_owned_descriptor(source, owned):
            raise RuntimeError("dynamic proof root-original cleanup is uncertain")
        current()
        if _staging_listener(staging_fd) != staging_pins:
            raise RuntimeError("dynamic proof staging listener changed before intake")
        fixed._require_inventory(tuple(owned))
        staging = socket.socket(fileno=staging_fd)
        connection = _accept_once(staging, owned=owned, work=work, current=current,
            deadline_ns=lifetime.bound, production=production)
        request = transport._recv_request(connection, deadline_ns=lifetime.bound,
            work=work, current=current, maximum_original_bytes=maximum_original)
        current()
        delivered = admission._verify_on_work(proof_bootstrap_bytes=request[1], issuer_policy_bytes=policy_raw,
            completion_bootstrap_bytes=completion_raw, proof_enrollment_bytes=proof_enrollment,
            intent_enrollment_bytes=intent_enrollment, root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            work=work, _continuity=lifetime.continuity)
        if type(delivered) is not admission._DeliveryMaterial:
            raise RuntimeError("dynamic proof requires genuine issued-original admission")
        lifetime.attach(delivered.live)
        lifetime.adopt(delivered.live_window, delivered.deadline_ns)
        material = delivered.proof_material
        work.charge(input_bytes=len(request[1]) + len(delivered.bootstrap_bytes) + len(material.bootstrap_bytes))
        if request[1] != delivered.bootstrap_bytes or request[1] != material.bootstrap_bytes:
            raise RuntimeError("dynamic proof admitted another bootstrap original")
        source = _seal_original(request[1], fixed.MAX_BOOTSTRAP_BYTES, owned=owned, work=work, current=current)
        ownership._retain(source, fixed.BOOTSTRAP_FD, reservations, owned)
        if not ownership._close_owned_descriptor(source, owned):
            raise RuntimeError("dynamic proof bootstrap duplicate cleanup is uncertain")
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        current()
        if fixed._listener(proof_fd) != listener_pins:
            raise RuntimeError("dynamic proof listener differs from independently admitted launch")
        # Genuine policy + exact bootstrap admission precedes every private open.
        for path, target, maximum in fixed._KEY_FILES:
            current()
            source = fixed._open_material(path, maximum, work=work, current=current, private=True)
            ownership._claim(source, owned)
            current()
            ownership._retain(source, target, reservations, owned)
            if not ownership._close_owned_descriptor(source, owned):
                raise RuntimeError("dynamic proof key duplicate cleanup is uncertain")
        fixed._keys_on_work(material, work, current=current)
        current()
        tls = fixed._tls_identity(material.completion_material.tls_files, work=work, current=current)
        current()
        ownership._retain(proof_fd, fixed.LISTENER_FD, reservations, owned)
        if not ownership._close_owned_descriptor(proof_fd, owned) or reservations:
            raise RuntimeError("dynamic proof listener handoff cleanup is uncertain")
        sealed = []
        for _path, descriptor, maximum in (*fixed._TRUST_FILES, *fixed._KEY_FILES):
            private = descriptor not in (fixed.ROOT_FD, fixed.BOOTSTRAP_FD)
            sealed.append((descriptor, maximum, private, fixed._sealed_identity(descriptor, maximum, private=private)))
        for descriptor in fixed.INHERITED_DESCRIPTORS:
            if native._material_identity(os.fstat(descriptor)) != owned[descriptor]:
                raise RuntimeError("dynamic proof staged descriptor identity changed")
            os.set_inheritable(descriptor, False)
        retained = (held + resources + sum(map(len, request))
            + _policy_bytes_on_work(delivered.policy_material, work, current)
            + _material_bytes_on_work(material, work, current))
        if retained + reserve >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("dynamic proof staged originals leave no complete worker allowance")
        continuation = object.__new__(_DeliveryContinuation)
        continuation._work, continuation._lifetime = work, lifetime
        continuation._sealed, continuation._tls, continuation._listener = tuple(sealed), tls, listener_pins
        continuation._retained_bytes, continuation._closed, continuation._production = retained, False, production
        continuation._seal = (work, lifetime, continuation._sealed, tls, listener_pins, retained, production)
        _continuation = continuation
        continuation.current()
        if _staging_listener(staging_fd) != staging_pins:
            raise RuntimeError("dynamic proof staging listener changed before ACK")
        identity = transport._bootstrap_identity_on_work(request[1], deadline_ns=lifetime.bound,
            work=work, current=continuation.current)
        work.charge(input_bytes=len(identity) + len(delivered.bootstrap_identity))
        if identity != delivered.bootstrap_identity:
            raise RuntimeError("dynamic proof staged identity differs from genuine admission")
        fixed._require_inventory(tuple(owned))
        transport._send_response(connection, (transport.ACK_STATUS, identity),
            deadline_ns=lifetime.bound, work=work, current=continuation.current)
        continuation.current()
        closing, connection = connection, None
        if not _close_socket(closing, owned):
            raise RuntimeError("dynamic proof staging connection cleanup is uncertain")
        closing, staging = staging, None
        if not _close_socket(closing, owned):
            raise RuntimeError("dynamic proof staging listener cleanup is uncertain")
        fixed._require_inventory(fixed.INHERITED_DESCRIPTORS)
        continuation.current()
        os.setgroups([])
        os.setresgid(fixed.SERVICE_GID, fixed.SERVICE_GID, fixed.SERVICE_GID)
        os.setresuid(fixed.SERVICE_UID, fixed.SERVICE_UID, fixed.SERVICE_UID)
        if (os.getresuid() != (fixed.SERVICE_UID,) * 3
                or os.getresgid() != (fixed.SERVICE_GID,) * 3 or os.getgroups()):
            raise RuntimeError("dynamic proof permanent drop retained privilege")
        fixed._require_unprivileged_process()
        os.environ.clear()
        os.environ.update(fixed.ENVIRONMENT)
        continuation.current()
        fixed._require_inventory(fixed.INHERITED_DESCRIPTORS)
        return runner._run_from_dynamic_delivery_on_work(work=work, live_window=lifetime.window,
            transport_deadline_ns=lifetime.bound, delivery_current=continuation.current)
    finally:
        if _continuation is not None:
            _continuation._closed = True
        complete = True
        for observed in (connection, staging):
            if observed is not None:
                try:
                    if not _close_socket(observed, owned):
                        complete = False
                except BaseException:
                    complete = False
        if not ownership._close_all_owned(owned) or not complete:
            raise RuntimeError("dynamic proof cleanup is uncertain; changed slots were not closed")
