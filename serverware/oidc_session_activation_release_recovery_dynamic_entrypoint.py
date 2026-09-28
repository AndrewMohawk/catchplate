"""Stage one independently authorized RECOVERY bootstrap, then continue in place.

The root-owned originals precede intake; the candidate never supplies its own
policy, checkpoint or resource pins. A staged ACK proves only this exact byte
and resource handoff. The existing outcome record is read by the genuine worker
after permanent privilege drop; this receiver never creates or appends it.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat
import threading

from serverware import authority_fd_entrypoint as native
from serverware import current_root_state_entrypoint as inventory
from serverware import oidc_session_activation_release_entrypoint as fixed
from serverware import oidc_session_activation_release_dynamic_entrypoint as mechanics


TRUST_PATH = "/run/serverware/oidc-session-activation-release-recovery-dynamic-trust"
ROOT_PATH = TRUST_PATH + "/root-public-key.pem"
POLICY_PATH = TRUST_PATH + "/issuer-policy.json"
CUSTODY_PATH = TRUST_PATH + "/release-custody.json"
PROOF_ENROLLMENT_PATH = TRUST_PATH + "/proof-enrollment.json"
INTENT_ENROLLMENT_PATH = TRUST_PATH + "/intent-enrollment.json"
STAGING_PATH = "/run/serverware/oidc-session-activation-token-release/recovery-bootstrap.sock"
STAGING_NAME = "serverware-oidc-session-activation-release-recovery-bootstrap"
RELEASE_NAME = fixed.LISTENER_NAME
STAGING_UID, STAGING_GID = 0, 65532
MAX_ROOT_BYTES = MAX_ENROLLMENT_BYTES = 16 * 1024
MAX_POLICY_BYTES, MAX_CUSTODY_BYTES = 64 * 1024, 8 * 1024 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_release_recovery_dynamic_launcher.py"
_PUBLIC_FILES = ((ROOT_PATH, MAX_ROOT_BYTES), (POLICY_PATH, MAX_POLICY_BYTES),
    (CUSTODY_PATH, MAX_CUSTODY_BYTES), (PROOF_ENROLLMENT_PATH, MAX_ENROLLMENT_BYTES),
    (INTENT_ENROLLMENT_PATH, MAX_ENROLLMENT_BYTES))
_PUBLIC_LIMITS = dict(_PUBLIC_FILES)


def _parent(path):
    if path not in (*_PUBLIC_LIMITS, STAGING_PATH):
        raise RuntimeError("recovery delivery path is not source fixed")
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
                raise RuntimeError("recovery delivery ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_public(path, maximum, *, owned, work, current):
    if _PUBLIC_LIMITS.get(path) != maximum:
        raise RuntimeError("recovery delivery public inventory differs")
    current()
    parent, source = _parent(path), None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        fixed._claim(source, owned)
        before = os.fstat(source)
        identity = native._material_identity(before)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o444 or not 2 <= before.st_size <= maximum
                or native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("recovery delivery original protection or pathname differs")
        # The five fixed maxima fit before semantic admission. Reserve the
        # actual nested/capture representations separately before their use.
        work.charge(input_bytes=2 * before.st_size)
        current()
        raw = native._read_exact_source(source, before.st_size)
        current()
        if (native._material_identity(os.fstat(source)) != identity
                or native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("recovery delivery original changed during read")
        return raw
    finally:
        try:
            if source is not None and not fixed._close_owned_descriptor(source, owned):
                raise RuntimeError("recovery delivery original cleanup is uncertain")
        finally:
            os.close(parent)


def _staging_listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != STAGING_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("recovery staging listener differs from its fixed activated socket")
    finally:
        observed.close()
    parent = _parent(STAGING_PATH)
    try:
        named = os.stat(os.path.basename(STAGING_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode))
                    != (STAGING_UID, STAGING_GID, 0o660)):
            raise RuntimeError("recovery staging socket pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _activated_descriptors():
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "2":
        raise RuntimeError("recovery delivery requires exactly two activated descriptors")
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if len(names) != 2 or set(names) != {STAGING_NAME, RELEASE_NAME}:
        raise RuntimeError("recovery delivery activated descriptor names differ")
    descriptors = dict(zip(names, (3, 4)))
    return descriptors[STAGING_NAME], descriptors[RELEASE_NAME]


def _policy_reservation(originals):
    root, policy, custody, proof, intent = originals
    # Source-known historical custody/planner, vector and enrollment captures.
    # This is conservative representation accounting, not a Python heap bound.
    return 16 * len(custody) + 8 * sum(map(len, (policy, proof, intent))) + 4 * len(root)


def _material_bytes_on_work(policy, material, work, current):
    """Measure only admitted source-known original fields and finite graphs."""
    from serverware import oidc_session_activation_release_recovery_delivery_admission as admission

    issuer = admission.issuer
    if type(policy) is not issuer._IssuerPolicyMaterial:
        raise RuntimeError("recovery delivery capacity requires actual independent policy")
    originals = [policy.policy_bytes, policy.release_custody_bytes,
        policy.proof_enrollment_bytes, policy.intent_enrollment_bytes]
    graphs = [policy.payload, policy.client_identity, policy.release_launch]
    custodies = [policy.custody_material]
    if material is not None:
        if type(material) is not admission.server._ReleaseMaterial:
            raise RuntimeError("recovery delivery capacity requires actual server admission")
        originals.extend((material.bootstrap_bytes, material.custody_bytes,
            material.storage_authorization_bytes, material.recovery_authorization_bytes))
        graphs.extend((material.launch, material.storage_scope, material.recovery_scope,
            material.expected_release, material.producer_identity, material.receiver_identity))
        custodies.append(material.custody_material)
    for custody in custodies:
        if type(custody) is not issuer.custody._ReleaseCustodyMaterial:
            raise RuntimeError("recovery delivery capacity lost admitted historical custody")
        planner = custody.planner
        originals.extend((custody.custody_bytes, planner.bootstrap_bytes,
            planner.state_enrollment_bytes, planner.complete_root_vector_bytes))
        graphs.extend((custody.receiver_identity, custody.delivery_scope,
            planner.configuration_payload, planner.generation, planner.runtime_role_identities,
            planner.planner_identity, planner.authn_policy, planner.trust_policy,
            planner.tls_files, planner.launch))
    # Count repeated fields conservatively, even where immutable originals alias.
    if any(type(raw) is not bytes for raw in originals):
        raise RuntimeError("recovery delivery retained original is not immutable bytes")
    total = 3 * sum(map(len, originals))
    for graph in graphs:
        current()
        measured = issuer.custody.planner_bootstrap.configuration._ConfigurationCapture(
            issuer.capture._SharedLedger(work), maximum_bytes=MAX_ORIGINAL_BYTES, retain=False)
        measured.visit(graph)
        total += 4 * measured.bytes
        if total >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("recovery delivery held original and graph capacity exhausted")
    current()
    return total


def main():
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("recovery dynamic delivery requires its root-only entry")
    staging_fd, release_fd = _activated_descriptors()
    owned, reservations = {3: None, 4: None}, {}
    staging = connection = resource_owner = None
    transferred = False
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import authority_oidc_session_activation_release_recovery_delivery_transport as transport
        from serverware import oidc_session_activation_release_recovery_delivery_admission as admission
        from serverware import oidc_session_activation_release_resources as resources
        from serverware import oidc_session_activation_release_runner as runner
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = admission.server._construction_on_work(work)
        lifetime = admission.issuer._Lifetime(window, bound, work, None)
        original_pid, original_thread = os.getpid(), threading.get_ident()

        def identity():
            if os.getpid() != original_pid or threading.get_ident() != original_thread:
                raise RuntimeError("recovery delivery changed process or thread")

        def continuity(epoch, monotonic):
            identity()
            # Nested ancestors see base only, never the attached admission
            # guards. The outer guard may therefore retain those children.
            return lifetime.continuity(epoch, monotonic)

        def current():
            identity()
            return lifetime.current()

        production = admission.issuer.production
        current()
        inventory._require_inventory({3, 4})
        fixed._claim(3, owned)
        fixed._claim(4, owned)
        current()
        os.set_blocking(staging_fd, False)
        os.set_blocking(release_fd, False)
        staging_pins = _staging_listener(staging_fd)
        fixed._listener(release_fd)
        for target in fixed.INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(release_fd, fcntl.F_DUPFD_CLOEXEC, target)
            fixed._claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("recovery delivery inherited descriptor slot is occupied")
            reservations[target] = owned[descriptor]
        originals = tuple(_read_public(path, maximum, owned=owned, work=work, current=current)
            for path, maximum in _PUBLIC_FILES)
        root_raw, policy_raw, custody_raw, proof_raw, intent_raw = originals
        frame_reserve = (transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES
            + len(transport.PURPOSE) + transport.MAX_RESPONSE_BYTES + 3 * fixed.MAX_KEY_BYTES)
        resource_reserve = 8 * resources._RECOVERY_OPERATION_BYTES + 8 * len(root_raw)
        independent_reserve = _policy_reservation(originals)
        if independent_reserve + frame_reserve + resource_reserve >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("recovery delivery cold originals exceed combined capacity")
        work.charge(input_bytes=len(root_raw))
        current()
        root = production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        current()
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("recovery delivery runtime root must be Ed25519")
        policy = admission.issuer._verify_on_work(policy_bytes=policy_raw,
            release_custody_bytes=custody_raw, proof_enrollment_bytes=proof_raw,
            intent_enrollment_bytes=intent_raw, root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _continuity=continuity)
        if type(policy) is not admission.issuer._IssuerPolicyMaterial:
            raise RuntimeError("recovery delivery requires genuine independent policy admission")
        lifetime.attach(policy.live)
        lifetime.adopt(policy.live_window, policy.deadline_ns)
        # Signed timeout is anchored at the original pre-I/O samples, never at
        # this stage or the later accepted connection.
        seconds = policy.release_launch["requestTimeoutSeconds"]
        lifetime.narrow(window[0] + seconds * 1_000_000_000,
            lifetime.window[5], lifetime.window[6])
        lifetime.adopt(lifetime.window, min(lifetime.bound, window[2] + seconds * 1_000_000_000))
        cold_held = (3 * sum(map(len, originals))
            + _material_bytes_on_work(policy, None, work, current))
        # Forty candidate footprints cover framing/sealing, both nested
        # custody paths/captures and the subsequent sixteen-footprint resource
        # re-admission. Existing held and repeated independent paths stay out
        # of that candidate allowance and are reserved separately.
        remaining = MAX_ORIGINAL_BYTES - cold_held - independent_reserve - frame_reserve - resource_reserve
        maximum_bootstrap = min(transport.MAX_BOOTSTRAP_BYTES, remaining // 40)
        if maximum_bootstrap < 2:
            raise RuntimeError("recovery delivery has no bounded incoming-original capacity")
        source = mechanics._seal_original(root_raw, MAX_ROOT_BYTES,
            owned=owned, work=work, current=current)
        fixed._retain(source, fixed.ROOT_FD, reservations, owned)
        if not fixed._close_owned_descriptor(source, owned):
            raise RuntimeError("recovery delivery root duplicate cleanup is uncertain")
        current()
        if _staging_listener(staging_fd) != staging_pins:
            raise RuntimeError("recovery staging listener changed before intake")
        inventory._require_inventory(tuple(owned))
        staging = socket.socket(fileno=staging_fd)
        # One accepted peer only. The transport checks its kernel65532 peer
        # before any request bytes; wrong peers and uncertainty are terminal.
        connection = mechanics._accept_once(staging, owned=owned, work=work, current=current,
            deadline_ns=lifetime.bound, production=production)
        current()
        request = transport._recv_request(connection, deadline_ns=lifetime.bound,
            work=work, current=current, maximum_bootstrap_bytes=maximum_bootstrap)
        current()
        delivered = admission._verify_on_work(server_bootstrap_bytes=request[1],
            issuer_policy_bytes=policy_raw, release_custody_bytes=custody_raw,
            proof_enrollment_bytes=proof_raw, intent_enrollment_bytes=intent_raw, root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _continuity=continuity)
        if type(delivered) is not admission._DeliveryMaterial:
            raise RuntimeError("recovery delivery requires genuine original-only admission")
        lifetime.attach(delivered.live)
        lifetime.adopt(delivered.live_window, delivered.deadline_ns)
        material = delivered.server_material
        if (material.profile != admission.server.RECOVERY_PROFILE
                or material.storage_scope["checkpoint"]["recordCount"] != 1):
            raise RuntimeError("recovery delivery requires exact checkpoint-one recovery")
        held = (cold_held + 3 * len(request[1]) + frame_reserve
            + _material_bytes_on_work(delivered.issuer_policy_material, material, work, current))
        if held + 16 * len(request[1]) + resource_reserve > MAX_ORIGINAL_BYTES:
            raise RuntimeError("recovery delivery cannot retain its full resource continuation")
        source = mechanics._seal_original(request[1], fixed.MAX_BOOTSTRAP_BYTES,
            owned=owned, work=work, current=current)
        fixed._retain(source, fixed.BOOTSTRAP_FD, reservations, owned)
        if not fixed._close_owned_descriptor(source, owned):
            raise RuntimeError("recovery delivery bootstrap duplicate cleanup is uncertain")
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        current()
        if fixed._listener(release_fd) != listener_pins:
            raise RuntimeError("recovery release listener differs from independent signed pins")
        source = fixed._slot_on_work(material, work)
        fixed._claim(source, owned)
        current()
        fixed._retain(source, fixed.OUTCOME_DIR_FD, reservations, owned)
        if not fixed._close_owned_descriptor(source, owned):
            raise RuntimeError("recovery outcome slot duplicate cleanup is uncertain")
        current()
        source = fixed._open_material(fixed.DELIVERY_KEY_PATH, fixed.MAX_KEY_BYTES,
            work=work, current=current, private=True)
        fixed._claim(source, owned)
        current()
        fixed._retain(source, fixed.DELIVERY_KEY_FD, reservations, owned)
        if not fixed._close_owned_descriptor(source, owned):
            raise RuntimeError("recovery delivery key duplicate cleanup is uncertain")
        key_identity = resources._metadata(work, lambda: resources._descriptor_identity(fixed.DELIVERY_KEY_FD))
        current()
        key = resources._read_on_work(fixed.DELIVERY_KEY_FD, fixed.MAX_KEY_BYTES,
            work, expected=key_identity, private=True)
        current()
        if len(key) != fixed.MAX_KEY_BYTES:
            raise RuntimeError("recovery delivery key must be raw32")
        resources.custody._key_binding(material.custody_material, key, work)
        current()
        fixed._retain(release_fd, fixed.LISTENER_FD, reservations, owned)
        if not fixed._close_owned_descriptor(release_fd, owned) or reservations:
            raise RuntimeError("recovery release listener handoff cleanup is uncertain")
        for descriptor in fixed.INHERITED_DESCRIPTORS:
            if native._material_identity(os.fstat(descriptor)) != owned[descriptor]:
                raise RuntimeError("recovery staged descriptor identity changed")
            os.set_inheritable(descriptor, False)
        current()
        if (fixed._listener(fixed.LISTENER_FD) != listener_pins
                or _staging_listener(staging_fd) != staging_pins):
            raise RuntimeError("recovery staged listener identity changed")
        identity_digest = transport._bootstrap_identity_on_work(request[1],
            deadline_ns=lifetime.bound, work=work, current=current)
        work.charge(input_bytes=len(identity_digest) + len(delivered.bootstrap_identity))
        if identity_digest != delivered.bootstrap_identity:
            raise RuntimeError("recovery staged identity differs from genuine admission")
        inventory._require_inventory(tuple(owned))
        current()
        # ACK is exact bytes plus observed resource staging only. No outcome
        # file has been read and no readiness/token claim is made here.
        transport._send_response(connection, (b"staged", identity_digest),
            deadline_ns=lifetime.bound, work=work, current=current)
        current()
        closing, connection = connection, None
        if not mechanics._close_socket(closing, owned):
            raise RuntimeError("recovery staging connection cleanup is uncertain")
        closing, staging = staging, None
        if not mechanics._close_socket(closing, owned):
            raise RuntimeError("recovery staging listener cleanup is uncertain")
        inventory._require_inventory(fixed.INHERITED_DESCRIPTORS)
        if fixed.ENVIRONMENT != resources.ENVIRONMENT:
            raise RuntimeError("recovery delivery resource environment differs")
        os.environ.clear()
        os.environ.update(fixed.ENVIRONMENT)
        current()
        resource_owner = resources._intake_from_delivery_on_work(work=work,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            delivery_current=current, _additional_original_bytes=held)
        owned.clear()
        resources._Resources._check_on_work(resource_owner, work=work)
        transferred = True
        return runner._run_with_resources(resource_owner)
    finally:
        complete = True
        for observed in (connection, staging):
            if observed is not None:
                try:
                    if not mechanics._close_socket(observed, owned):
                        complete = False
                except BaseException:
                    complete = False
        try:
            if resource_owner is not None and not transferred:
                resources._Resources.close(resource_owner)
        finally:
            if not fixed._close_all_owned(owned) or not complete:
                raise RuntimeError("recovery delivery cleanup is uncertain; changed slots were not closed")
