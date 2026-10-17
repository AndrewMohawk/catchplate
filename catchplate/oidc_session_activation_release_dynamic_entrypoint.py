"""Stage one original release bootstrap, then continue the same-PID worker.

The independent public policy/proof are admitted before waiting for the issuer.
The received bootstrap is never published as a file. A staged ACK attests only
to this bounded delivery step, not worker readiness, storage emptiness or release.
"""
from __future__ import annotations

import fcntl
import os
import select
import socket
import stat
import time

from catchplate import authority_fd_entrypoint as native
from catchplate import current_root_state_entrypoint as inventory
from catchplate import oidc_session_activation_release_entrypoint as fixed


TRUST_PATH = "/run/catchplate/oidc-session-activation-token-release-dynamic-trust"
ROOT_PATH = TRUST_PATH + "/root-public-key.pem"
POLICY_PATH = TRUST_PATH + "/issuer-policy.json"
PROOF_BOOTSTRAP_PATH = TRUST_PATH + "/proof-bootstrap.json"
STAGING_PATH = "/run/catchplate/oidc-session-activation-token-release/bootstrap.sock"
STAGING_NAME = "catchplate-oidc-session-activation-token-release-bootstrap"
RELEASE_NAME = fixed.LISTENER_NAME
STAGING_UID, STAGING_GID = 0, 65496
MAX_ROOT_BYTES = MAX_POLICY_BYTES = 16 * 1024
MAX_PROOF_BOOTSTRAP_BYTES = 48 * 1024 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_release_dynamic_launcher.py"
_PUBLIC_FILES = ((ROOT_PATH, MAX_ROOT_BYTES), (POLICY_PATH, MAX_POLICY_BYTES),
    (PROOF_BOOTSTRAP_PATH, MAX_PROOF_BOOTSTRAP_BYTES))
_PUBLIC_LIMITS = dict(_PUBLIC_FILES)


def _parent(path):
    if path not in (*_PUBLIC_LIMITS, STAGING_PATH):
        raise RuntimeError("dynamic release path is not source fixed")
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
                raise RuntimeError("dynamic release ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_public(path, maximum, *, owned, work, current):
    if _PUBLIC_LIMITS.get(path) != maximum:
        raise RuntimeError("dynamic release public-original inventory differs")
    parent, descriptor = _parent(path), None
    try:
        descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        fixed._claim(descriptor, owned)
        value = os.fstat(descriptor)
        identity = native._material_identity(value)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 1
                or stat.S_IMODE(value.st_mode) != 0o444 or not 2 <= value.st_size <= maximum
                or native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("dynamic release public original protection differs")
        work.charge(input_bytes=value.st_size)
        current()
        raw = native._read_exact_source(descriptor, value.st_size)
        current()
        if (native._material_identity(os.fstat(descriptor)) != identity
                or native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("dynamic release public original changed during read")
        return raw
    finally:
        try:
            if descriptor is not None and not fixed._close_owned_descriptor(descriptor, owned):
                raise RuntimeError("dynamic release public original cleanup is uncertain")
        finally:
            os.close(parent)


def _seal_original(raw, maximum, *, owned, work, current):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise RuntimeError("dynamic release requires bounded immutable bytes to seal")
    work.charge(input_bytes=len(raw))
    current()
    descriptor = os.memfd_create("catchplate-dynamic-release-original",
        flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    fixed._claim(descriptor, owned)
    try:
        offset = 0
        while offset < len(raw):
            current()
            written = os.write(descriptor, raw[offset:offset + 4096])
            fixed._claim(descriptor, owned)
            current()
            if written <= 0:
                raise RuntimeError("dynamic release original sealing was incomplete")
            offset += written
        os.fchmod(descriptor, 0o444)
        fixed._claim(descriptor, owned)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        fixed._claim(descriptor, owned)
        os.set_inheritable(descriptor, False)
        current()
        fixed.sealed._sealed_identity(descriptor, maximum)
        return descriptor
    except BaseException:
        if not fixed._close_owned_descriptor(descriptor, owned):
            raise RuntimeError("dynamic release sealed-original cleanup is uncertain")
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
            raise RuntimeError("dynamic release staging listener differs")
    finally:
        observed.close()
    parent = _parent(STAGING_PATH)
    try:
        named = os.stat(os.path.basename(STAGING_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (STAGING_UID, STAGING_GID, 0o660)):
            raise RuntimeError("dynamic release staging pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _activated_descriptors():
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "2"):
        raise RuntimeError("dynamic release requires exactly two activated listeners")
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if len(names) != 2 or set(names) != {STAGING_NAME, RELEASE_NAME}:
        raise RuntimeError("dynamic release listener names are not the exact distinct pair")
    # Separate systemd socket units do not specify cross-unit FD ordering.
    mapping = dict(zip(names, (3, 4)))
    return mapping[STAGING_NAME], mapping[RELEASE_NAME]


def _close_socket(observed, owned):
    descriptor = observed.fileno()
    if descriptor < 0:
        return False
    detached = observed.detach()
    if detached != descriptor:
        return False
    return fixed._close_owned_descriptor(descriptor, owned)


def _accept_once(listener, *, owned, work, current, deadline_ns, production):
    while True:
        current()
        now = production._callback(work, time.monotonic_ns)
        if now >= deadline_ns:
            raise RuntimeError("dynamic release staging wait exhausted the original deadline")
        work.charge(input_bytes=4096)
        current()
        ready, _writable, _exceptional = production._callback(work,
            lambda: select.select((listener,), (), (), min(1.0, (deadline_ns - now) / 1_000_000_000)))
        current()
        if ready:
            # Exactly one accept attempt. No replacement peer is accepted on
            # a peer, framing, original-admission or resource-delivery failure.
            connection, _address = listener.accept()
            try:
                fixed._claim(connection.fileno(), owned)
                connection.setblocking(False)
                connection.set_inheritable(False)
                current()
                return connection
            except BaseException:
                if not _close_socket(connection, owned):
                    raise RuntimeError("dynamic release accepted-connection cleanup is uncertain")
                raise


def _held_public_bytes(root_raw, policy_raw, proof_raw, policy):
    proof, completion = policy.proof_material, policy.proof_material.completion_material
    embedded = (proof.completion_bootstrap_bytes, proof.proof_enrollment_bytes,
        proof.release_custody_bytes, proof.intent_bytes, proof.intent_enrollment_bytes,
        proof.completion_request_bytes, proof.state_receipt_bytes,
        completion.current_root_enrollment_bytes, completion.authorization_enrollment_bytes,
        completion.grant_enrollment_bytes)
    return sum(map(len, (root_raw, policy_raw, proof_raw, *embedded)))


def main(*, _sealed_sources=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("dynamic release delivery must begin as root")
    staging_fd, release_fd = _activated_descriptors()
    from catchplate import oidc_session_activation_follow_on_originals as originals
    if type(_sealed_sources) is not bool:
        raise RuntimeError('release dynamic source profile differs')
    sources = originals.roster('release-worker') if _sealed_sources else ()
    inventory._require_inventory({3, 4, *(row[0] for row in sources)})
    owned, reservations = {3: None, 4: None, **{row[0]: None for row in sources}}, {}
    staging = connection = resource_owner = None
    transferred = False
    try:
        fixed._claim(3, owned)
        fixed._claim(4, owned)
        supplied = originals._Originals('release-worker', owned) if _sealed_sources else None
        reading = supplied.read if supplied is not None else _read_public
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from catchplate import authority_oidc_session_activation_release_grant_delivery_transport as transport
        from catchplate import oidc_session_activation_release_grant_delivery_admission as admission
        from catchplate import oidc_session_activation_release_resources as resources
        from catchplate import oidc_session_activation_release_runner as runner
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = admission.server._construction_on_work(work)
        # Actual source-private bookkeeping only: it supplies no root authority
        # and keeps the original ledger, bracket and pre-I/O clock floors.
        lifetime = admission.producer._Lifetime(window, bound, work, None)
        current = lifetime.current
        production = admission.issuer.production
        current()
        os.set_blocking(staging_fd, False)
        os.set_blocking(release_fd, False)
        staging_pins = _staging_listener(staging_fd)
        fixed._listener(release_fd)
        for target in fixed.INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(release_fd, fcntl.F_DUPFD_CLOEXEC, target)
            fixed._claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("dynamic release inherited descriptor slot is occupied")
            reservations[target] = owned[descriptor]
        root_raw, policy_raw, proof_raw = tuple(reading(path, maximum,
            owned=owned, work=work, current=current) for path, maximum in _PUBLIC_FILES)
        work.charge(input_bytes=len(root_raw))
        current()
        root = production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        current()
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("dynamic release runtime root must be Ed25519")
        policy = admission.issuer._verify_on_work(policy_bytes=policy_raw,
            proof_bootstrap_bytes=proof_raw, root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
        if type(policy) is not admission.issuer._IssuerPolicyMaterial:
            raise RuntimeError("dynamic release requires genuine independent policy admission")
        lifetime.attach(policy.live)
        lifetime.adopt(policy.live_window, policy.deadline_ns)
        held = _held_public_bytes(root_raw, policy_raw, proof_raw, policy)
        frame_reserve = (transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES
            + len(transport.PURPOSE) + transport.MAX_RESPONSE_BYTES + fixed.MAX_KEY_BYTES)
        maximum_bootstrap = min(transport.MAX_BOOTSTRAP_BYTES, MAX_ORIGINAL_BYTES - held - frame_reserve)
        if maximum_bootstrap < 2:
            raise RuntimeError("dynamic release has no bounded incoming-original capacity")
        source = _seal_original(root_raw, MAX_ROOT_BYTES, owned=owned, work=work, current=current)
        fixed._retain(source, fixed.ROOT_FD, reservations, owned)
        if not fixed._close_owned_descriptor(source, owned):
            raise RuntimeError("dynamic release root original cleanup is uncertain")
        current()
        if _staging_listener(staging_fd) != staging_pins:
            raise RuntimeError("dynamic release staging listener changed before admission")
        inventory._require_inventory(tuple(owned))
        staging = socket.socket(fileno=staging_fd)
        connection = _accept_once(staging, owned=owned, work=work, current=current,
            deadline_ns=lifetime.bound, production=production)
        current()
        request = transport._recv_request(connection, deadline_ns=lifetime.bound,
            work=work, current=current, maximum_bootstrap_bytes=maximum_bootstrap)
        current()
        delivered = admission._verify_on_work(server_bootstrap_bytes=request[1],
            issuer_policy_bytes=policy_raw, proof_bootstrap_bytes=proof_raw, root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _continuity=lifetime.continuity)
        if type(delivered) is not admission._DeliveryMaterial:
            raise RuntimeError("dynamic release requires actual original-only receiving admission")
        lifetime.attach(delivered.live)
        lifetime.adopt(delivered.live_window, delivered.deadline_ns)
        material = delivered.server_material
        source = _seal_original(request[1], fixed.MAX_BOOTSTRAP_BYTES,
            owned=owned, work=work, current=current)
        fixed._retain(source, fixed.BOOTSTRAP_FD, reservations, owned)
        if not fixed._close_owned_descriptor(source, owned):
            raise RuntimeError("dynamic release bootstrap original cleanup is uncertain")
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        current()
        if fixed._listener(release_fd) != listener_pins:
            raise RuntimeError("dynamic release listener differs from actual signed launch")
        source = fixed._slot_on_work(material, work)
        fixed._claim(source, owned)
        current()
        fixed._retain(source, fixed.OUTCOME_DIR_FD, reservations, owned)
        if not fixed._close_owned_descriptor(source, owned):
            raise RuntimeError("dynamic release outcome duplicate cleanup is uncertain")
        current()
        source = fixed._open_material(fixed.DELIVERY_KEY_PATH, fixed.MAX_KEY_BYTES,
            work=work, current=current, private=True)
        fixed._claim(source, owned)
        current()
        fixed._retain(source, fixed.DELIVERY_KEY_FD, reservations, owned)
        if not fixed._close_owned_descriptor(source, owned):
            raise RuntimeError("dynamic release key duplicate cleanup is uncertain")
        key_identity = resources._metadata(work,
            lambda: resources._descriptor_identity(fixed.DELIVERY_KEY_FD))
        current()
        key = resources._read_on_work(fixed.DELIVERY_KEY_FD, fixed.MAX_KEY_BYTES,
            work, expected=key_identity, private=True)
        current()
        if len(key) != fixed.MAX_KEY_BYTES:
            raise RuntimeError("dynamic release delivery key must be raw32")
        resources.custody._key_binding(material.custody_material, key, work)
        current()
        fixed._retain(release_fd, fixed.LISTENER_FD, reservations, owned)
        if not fixed._close_owned_descriptor(release_fd, owned) or reservations:
            raise RuntimeError("dynamic release listener handoff cleanup is uncertain")
        for descriptor in fixed.INHERITED_DESCRIPTORS:
            if native._material_identity(os.fstat(descriptor)) != owned[descriptor]:
                raise RuntimeError("dynamic release staged descriptor identity changed")
            os.set_inheritable(descriptor, False)
        current()
        if (fixed._listener(fixed.LISTENER_FD) != listener_pins
                or _staging_listener(staging_fd) != staging_pins):
            raise RuntimeError("dynamic release staged listener identity changed")
        identity = transport._bootstrap_identity_on_work(request[1], deadline_ns=lifetime.bound,
            work=work, current=current)
        work.charge(input_bytes=len(identity) + len(delivered.bootstrap_identity))
        if identity != delivered.bootstrap_identity:
            raise RuntimeError("dynamic release staged identity differs from actual admission")
        inventory._require_inventory(tuple(owned))
        current()
        # Only bytes/resources are staged. The permanent drop, actual store
        # recovery and finite release worker have not happened at this point.
        transport._send_response(connection, (b"staged", identity),
            deadline_ns=lifetime.bound, work=work, current=current)
        current()
        closing, connection = connection, None
        if not _close_socket(closing, owned):
            raise RuntimeError("dynamic release staging connection cleanup is uncertain")
        closing, staging = staging, None
        if not _close_socket(closing, owned):
            raise RuntimeError("dynamic release staging listener cleanup is uncertain")
        inventory._require_inventory(fixed.INHERITED_DESCRIPTORS)
        if fixed.ENVIRONMENT != resources.ENVIRONMENT:
            raise RuntimeError("dynamic release resource environment differs")
        os.environ.clear()
        os.environ.update(fixed.ENVIRONMENT)
        current()
        resource_owner = resources._intake_from_delivery_on_work(work=work,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, delivery_current=current)
        owned.clear()
        resources._Resources._check_on_work(resource_owner, work=work)
        transferred = True
        return runner._run_with_resources(resource_owner)
    finally:
        complete = True
        for observed in (connection, staging):
            if observed is not None:
                try:
                    if not _close_socket(observed, owned):
                        complete = False
                except BaseException:
                    complete = False
        try:
            if resource_owner is not None and not transferred:
                resources._Resources.close(resource_owner)
        finally:
            if not fixed._close_all_owned(owned) or not complete:
                raise RuntimeError("dynamic release cleanup is uncertain; changed slots were not closed")
