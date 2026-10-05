"""Stage exact consume originals and continue the same-PID finite worker.

Independent policy precedes waiting; genuine pair admission precedes private
resources. The ACK establishes only sealed originals and held resource pins,
not request replay, worker readiness, SQL, token release or empty directories.
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
from serverware import current_root_state_entrypoint as inventory
from serverware import oidc_session_activation_delivery_planner_entrypoint as fixed
from serverware import oidc_session_activation_release_entrypoint as ownership


TRUST_PATH = "/run/serverware/oidc-session-activation-consume-dynamic-trust"
ROOT_PATH = TRUST_PATH + "/root-public-key.pem"
POLICY_PATH = TRUST_PATH + "/issuer-policy.json"
ACTIVATION_PATH = TRUST_PATH + "/activation-planner-bootstrap.json"
STAGING_PATH = "/run/serverware/oidc-session-activation/consume-bootstrap.sock"
STAGING_NAME = "serverware-oidc-session-activation-consume-bootstrap"
PLANNER_NAME = fixed.LISTENER_NAME
STAGING_UID, STAGING_GID = 0, 65495
MAX_ROOT_BYTES, MAX_POLICY_BYTES = 16 * 1024, 6 * 1024 * 1024
LEGACY_MAX_POLICY_BYTES = 64 * 1024
MAX_ACTIVATION_BYTES, MAX_ORIGINAL_BYTES = 4 * 1024 * 1024, 64 * 1024 * 1024
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_consume_dynamic_launcher.py"
_PUBLIC_FILES = ((ROOT_PATH, MAX_ROOT_BYTES), (POLICY_PATH, MAX_POLICY_BYTES),
    (ACTIVATION_PATH, MAX_ACTIVATION_BYTES))
_PUBLIC_LIMITS = dict(_PUBLIC_FILES)
_PID, _continuation = os.getpid(), None
_used = False


def _parent(path):
    if path not in (*_PUBLIC_LIMITS, STAGING_PATH):
        raise RuntimeError("dynamic consume path is not source fixed")
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
                raise RuntimeError("dynamic consume ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_public(path, maximum, *, owned, work, current):
    if _PUBLIC_LIMITS.get(path) != maximum:
        raise RuntimeError("dynamic consume public-original inventory differs")
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
            raise RuntimeError("dynamic consume public original protection differs")
        work.charge(input_bytes=value.st_size)
        current()
        raw = native._read_exact_source(descriptor, value.st_size)
        current()
        if (native._material_identity(os.fstat(descriptor)) != identity
                or native._material_identity(os.stat(os.path.basename(path), dir_fd=parent,
                    follow_symlinks=False)) != identity):
            raise RuntimeError("dynamic consume public original changed during read")
        return raw
    finally:
        try:
            if descriptor is not None and not ownership._close_owned_descriptor(descriptor, owned):
                raise RuntimeError("dynamic consume public-original cleanup is uncertain")
        finally:
            os.close(parent)


def _seal_original(raw, maximum, *, owned, work, current):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise RuntimeError("dynamic consume requires bounded immutable originals")
    work.charge(input_bytes=len(raw))
    current()
    descriptor = os.memfd_create("serverware-dynamic-consume-original",
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
                raise RuntimeError("dynamic consume original sealing was incomplete")
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
            raise RuntimeError("dynamic consume sealed-original cleanup is uncertain")
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
            raise RuntimeError("dynamic consume staging listener differs")
    finally:
        observed.close()
    parent = _parent(STAGING_PATH)
    try:
        named = os.stat(os.path.basename(STAGING_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (STAGING_UID, STAGING_GID, 0o660)):
            raise RuntimeError("dynamic consume staging pathname protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _activated_descriptors():
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "2"):
        raise RuntimeError("dynamic consume requires exactly two activated listeners")
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if len(names) != 2 or set(names) != {STAGING_NAME, PLANNER_NAME}:
        raise RuntimeError("dynamic consume listener names are not the exact distinct pair")
    mapping = dict(zip(names, (3, 4)))
    return mapping[STAGING_NAME], mapping[PLANNER_NAME]


def _close_socket(observed, owned):
    descriptor = observed.fileno()
    if descriptor < 0:
        return False
    detached = observed.detach()
    if detached != descriptor:
        return False
    return ownership._close_owned_descriptor(descriptor, owned)


def _accept_once(listener, *, owned, work, current, deadline_ns, production):
    while True:
        current()
        now = production._callback(work, time.monotonic_ns)
        if now >= deadline_ns:
            raise RuntimeError("dynamic consume staging wait exhausted the original deadline")
        work.charge(input_bytes=4096)
        current()
        ready, _writers, exceptional = production._callback(work,
            lambda: select.select((listener,), (), (listener,), min(1.0, (deadline_ns - now) / 1_000_000_000)))
        current()
        if exceptional:
            raise RuntimeError("dynamic consume staging readiness failed")
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
                    raise RuntimeError("dynamic consume accepted-connection cleanup is uncertain")
                raise


class _DeliveryContinuation:
    """Actual sealed-resource/clock owner, not a successful admission carrier."""

    __slots__ = ("_work", "_lifetime", "_sealed", "_tls", "_resources", "_retained_bytes",
        "_seal", "_closed", "_production")

    def __init__(self):
        raise RuntimeError("dynamic consume continuation requires actual root delivery")

    def _identity(self):
        if (type(self) is not _DeliveryContinuation or self is not _continuation
                or os.getpid() != _PID or self._closed
                or any(actual is not held for actual, held in zip(
                    (self._work, self._lifetime, self._sealed, self._tls, self._resources, self._production),
                    (self._seal[0], self._seal[1], self._seal[2], self._seal[3], self._seal[4], self._seal[6])))
                or self._retained_bytes != self._seal[5]
                or self._lifetime.work is not self._work
                or type(self._retained_bytes) is not int or not 0 < self._retained_bytes < MAX_ORIGINAL_BYTES):
            raise RuntimeError("dynamic consume continuation identity or capacity changed")
        for descriptor, maximum, private, identity in self._sealed:
            if fixed._sealed_identity(descriptor, maximum, private=private) != identity:
                raise RuntimeError("dynamic consume delivered original identity changed")
        listener, journal, execution = self._resources
        if (fixed._listener(fixed.LISTENER_FD) != listener
                or fixed._journal(fixed.JOURNAL_FD) != journal
                or fixed._execution_store(fixed.EXECUTION_STORE_FD) != execution):
            raise RuntimeError("dynamic consume delivered resource identity changed")
        fixed._tls_unchanged(self._tls)
        # No whole-FD inventory here: the genuine service owns its precise
        # duplicate/listener/connection and transient private replay lifecycle.

    def current(self):
        self._work.charge(input_bytes=8192)
        self._production._callback(self._work, self._identity)
        return self._lifetime.current()


def _retained_bytes_on_work(delivery_current, work, *, live_window=None, transport_deadline_ns=None):
    """Read capacity only from this PID's actual original-bound continuation."""
    if (type(delivery_current) is not MethodType
            or delivery_current.__func__ is not _DeliveryContinuation.current
            or type(delivery_current.__self__) is not _DeliveryContinuation
            or delivery_current.__self__ is not _continuation
            or delivery_current.__self__._work is not work):
        raise RuntimeError("dynamic consume service lacks the actual delivery continuation")
    selected = delivery_current.__self__
    selected.current()
    if (live_window is None) != (transport_deadline_ns is None):
        raise RuntimeError("dynamic consume processing bounds must be supplied together")
    if live_window is not None:
        from serverware import authority_webauthn_evidence_plan_clock as clock

        live_window = clock._validate(live_window)
        original = selected._lifetime.window
        if (type(transport_deadline_ns) is not int or transport_deadline_ns <= 0
                or live_window[:3] != original[:3]
                or any(value > bound for value, bound in zip(live_window[3:], original[3:]))
                or transport_deadline_ns > min(selected._lifetime.bound, live_window[4])):
            raise RuntimeError("dynamic consume service widened or reopened the delivery allowance")
    return selected._retained_bytes


def _retained_inventory_on_work(raws, policy, delivered, work, current, admission):
    """Measure actual held originals/graphs, including both admission closures."""
    material, old = delivered.planner_material, policy.activation_planner
    other = delivered.issuer_policy_material.activation_planner
    originals = (*raws, material.bootstrap_bytes, material.history_custody_bytes,
        material.consume_request_bytes, material.complete_root_vector_bytes, material.state_enrollment_bytes,
        old.bootstrap_bytes, old.complete_root_vector_bytes, old.state_enrollment_bytes,
        other.bootstrap_bytes, other.complete_root_vector_bytes, other.state_enrollment_bytes,
        material.history_material.planner.bootstrap_bytes,
        material.history_material.planner.complete_root_vector_bytes,
        material.history_material.planner.state_enrollment_bytes)
    total = sum(map(len, originals))
    historical = old, other, material.history_material.planner
    # The actual signed originals additionally bound detached scalar/reader
    # configuration projections and the private verifier closure's snapshots.
    total += sum(len(selected.bootstrap_bytes) for selected in historical)
    graphs = (policy.payload, delivered.issuer_policy_material.payload, material.payload,
            old.configuration_payload, old.generation, old.runtime_role_identities,
            other.configuration_payload, other.generation, other.runtime_role_identities,
            material.history_material.planner.configuration_payload,
            material.history_material.planner.generation, material.history_material.planner.runtime_role_identities,
            material.history_material.receiver_identity)
    for graph in (*graphs, *(graph for selected in historical for graph in (
            selected.planner_identity, selected.authn_policy, selected.trust_policy,
            selected.tls_files, selected.launch))):
        current()
        measured = admission.issuer.configuration._ConfigurationCapture(
            admission.capture._SharedLedger(work), maximum_bytes=MAX_ORIGINAL_BYTES, retain=False)
        measured.visit(graph)
        total += measured.bytes
        if total >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("dynamic consume retained originals/graphs exhaust the complete inventory")
    # Actual native key objects and the bounded TLS read buffers stay private.
    total += sum(maximum for _path, _descriptor, maximum in fixed._KEY_FILES)
    total += sum(maximum for _name, _path, maximum, _private in fixed._TLS_FILES)
    current()
    if total >= MAX_ORIGINAL_BYTES:
        raise RuntimeError("dynamic consume retained resources exhaust the complete inventory")
    return total


def main(*, _sealed_sources=False):
    global _used, _continuation
    if _used or os.getpid() != _PID or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("dynamic consume delivery must begin once in its original root PID")
    _used = True
    staging_fd, planner_fd = _activated_descriptors()
    from serverware import oidc_session_activation_follow_on_originals as originals
    if type(_sealed_sources) is not bool:
        raise RuntimeError("consume dynamic source profile differs")
    sources = originals.roster('consume-worker') if _sealed_sources else ()
    output = (originals.OUTPUT_FD,) if _sealed_sources else ()
    inventory._require_inventory({3, 4, *output, *(row[0] for row in sources)})
    owned, reservations = {3: None, 4: None, **{fd: None for fd in output},
        **{row[0]: None for row in sources}}, {}
    staging = connection = None
    try:
        ownership._claim(3, owned)
        ownership._claim(4, owned)
        for descriptor in output:
            ownership._claim(descriptor, owned)
        supplied = originals._Originals('consume-worker', owned) if _sealed_sources else None
        reading = supplied.read if supplied is not None else _read_public
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import authority_oidc_session_activation_consume_input_delivery_transport as transport
        from serverware import oidc_session_activation_consume_input_delivery_admission as admission
        from serverware import oidc_session_activation_delivery_planner_runner as runner
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = fixed._construction_on_work(work)
        lifetime = admission.producer._Lifetime(window, bound, work, None)
        current, production = lifetime.current, admission.issuer.production
        current()
        os.set_blocking(staging_fd, False)
        os.set_blocking(planner_fd, False)
        staging_pins = _staging_listener(staging_fd)
        fixed._listener(planner_fd)
        for target in fixed.INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(planner_fd, fcntl.F_DUPFD_CLOEXEC, target)
            ownership._claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("dynamic consume inherited descriptor slot is occupied")
            reservations[target] = owned[descriptor]
        root_raw, policy_raw, activation_raw = tuple(reading(path, maximum,
            owned=owned, work=work, current=current) for path, maximum in _PUBLIC_FILES)
        # Intake can contain the explicit static v3 original. Old launch
        # profiles retain their exact original 64 KiB limit; this is not an
        # admission of arbitrary larger policies or a replacement work cap.
        policy_shape = admission.issuer._read(policy_raw, work)
        version = policy_shape["schema"]
        if (version not in (admission.issuer.SCHEMA, admission.issuer.V2_SCHEMA, admission.issuer.V3_SCHEMA)
                or len(policy_raw) > (MAX_POLICY_BYTES if version == admission.issuer.V3_SCHEMA
                    else LEGACY_MAX_POLICY_BYTES)):
            raise RuntimeError("dynamic consume policy exceeds its explicit versioned source limit")
        work.charge(input_bytes=len(root_raw))
        current()
        root = production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        current()
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("dynamic consume runtime root must be Ed25519")
        policy = admission.issuer._verify_on_work(policy_bytes=policy_raw,
            activation_planner_bootstrap_bytes=activation_raw, root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _continuity=lifetime.continuity)
        if type(policy) is not admission.issuer._IssuerPolicyMaterial:
            raise RuntimeError("dynamic consume requires genuine independent policy admission")
        lifetime.attach(policy.live)
        lifetime.adopt(policy.live_window, policy.deadline_ns)
        timeout = policy.consume_planner["launch"]["requestTimeoutSeconds"] * 1_000_000_000
        lifetime.narrow(lifetime.window[0] + timeout, min(timeout, lifetime.window[5]), lifetime.window[6])
        held = sum(map(len, (root_raw, policy_raw, activation_raw)))
        reserve = (admission.DECODED_RESERVATION_BYTES + transport.REQUEST_HEADER_BYTES
            + transport.RESPONSE_HEADER_BYTES + len(transport.PURPOSE) + transport.MAX_RESPONSE_BYTES
            + sum(maximum for _path, _descriptor, maximum in fixed._KEY_FILES)
            + sum(maximum for _name, _path, maximum, _private in fixed._TLS_FILES))
        maximum_original = min(transport.MAX_ORIGINAL_BYTES, MAX_ORIGINAL_BYTES - held - reserve)
        if maximum_original < 4:
            raise RuntimeError("dynamic consume has no bounded incoming-original capacity")
        source = _seal_original(root_raw, MAX_ROOT_BYTES, owned=owned, work=work, current=current)
        ownership._retain(source, fixed.ROOT_FD, reservations, owned)
        if not ownership._close_owned_descriptor(source, owned):
            raise RuntimeError("dynamic consume root original cleanup is uncertain")
        current()
        if _staging_listener(staging_fd) != staging_pins:
            raise RuntimeError("dynamic consume staging listener changed before admission")
        inventory._require_inventory(tuple(owned))
        staging = socket.socket(fileno=staging_fd)
        connection = _accept_once(staging, owned=owned, work=work, current=current,
            deadline_ns=lifetime.bound, production=production)
        request = transport._recv_request(connection, deadline_ns=lifetime.bound,
            work=work, current=current, maximum_original_bytes=maximum_original)
        current()
        delivered = admission._verify_on_work(planner_bootstrap_bytes=request[1], history_custody_bytes=request[2],
            issuer_policy_bytes=policy_raw, activation_planner_bootstrap_bytes=activation_raw,
            root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            work=work, _continuity=lifetime.continuity)
        if type(delivered) is not admission._DeliveryMaterial:
            raise RuntimeError("dynamic consume requires genuine issued-pair admission")
        lifetime.attach(delivered.live)
        lifetime.adopt(delivered.live_window, delivered.deadline_ns)
        material, launch = delivered.planner_material, delivered.planner_material.payload["launch"]
        for original, target, maximum in ((request[1], fixed.BOOTSTRAP_FD, fixed.MAX_BOOTSTRAP_BYTES),
                (request[2], fixed.HISTORY_FD, fixed.MAX_HISTORY_BYTES)):
            source = _seal_original(original, maximum, owned=owned, work=work, current=current)
            ownership._retain(source, target, reservations, owned)
            if not ownership._close_owned_descriptor(source, owned):
                raise RuntimeError("dynamic consume issued-original cleanup is uncertain")
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
        execution_pins = launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"]
        current()
        if fixed._listener(planner_fd) != listener_pins:
            raise RuntimeError("dynamic consume planner listener differs from the signed launch")
        # Only now may any private key, directory or TLS resource be opened.
        for path, target, maximum in fixed._KEY_FILES:
            current()
            work.charge(input_bytes=maximum)
            source = production._callback(work,
                lambda path=path, maximum=maximum: fixed._open_material(path, maximum, private=True))
            ownership._claim(source, owned)
            current()
            ownership._retain(source, target, reservations, owned)
            if not ownership._close_owned_descriptor(source, owned):
                raise RuntimeError("dynamic consume key duplicate cleanup is uncertain")
        current()
        fixed._keys_on_work(material, work)
        current()
        tls_files = material.payload["tlsFiles"]
        work.charge(hashes=len(tls_files), input_bytes=sum(item["byteCount"] for item in tls_files.values()))
        tls = production._callback(work, lambda: fixed._tls_identity(tls_files))
        current()
        for target, opening, pins in ((fixed.JOURNAL_FD, fixed._journal_directory, journal_pins),
                (fixed.EXECUTION_STORE_FD, fixed._execution_store_directory, execution_pins)):
            work.charge(input_bytes=4096)
            source = production._callback(work, lambda opening=opening, pins=pins: opening(*pins))
            ownership._claim(source, owned)
            current()
            ownership._retain(source, target, reservations, owned)
            if not ownership._close_owned_descriptor(source, owned):
                raise RuntimeError("dynamic consume directory duplicate cleanup is uncertain")
        ownership._retain(planner_fd, fixed.LISTENER_FD, reservations, owned)
        if not ownership._close_owned_descriptor(planner_fd, owned) or reservations:
            raise RuntimeError("dynamic consume listener handoff cleanup is uncertain")
        sealed = []
        for _path, descriptor, maximum in (*fixed._TRUST_FILES, *fixed._KEY_FILES):
            private = descriptor not in (fixed.ROOT_FD, fixed.BOOTSTRAP_FD, fixed.HISTORY_FD)
            sealed.append((descriptor, maximum, private, fixed._sealed_identity(descriptor, maximum, private=private)))
        for descriptor in fixed.INHERITED_DESCRIPTORS:
            if native._material_identity(os.fstat(descriptor)) != owned[descriptor]:
                raise RuntimeError("dynamic consume staged descriptor identity changed")
            os.set_inheritable(descriptor, False)
        retained_bytes = _retained_inventory_on_work((root_raw, policy_raw, activation_raw, *request),
            policy, delivered, work, current, admission)
        continuation = object.__new__(_DeliveryContinuation)
        continuation._work, continuation._lifetime = work, lifetime
        continuation._sealed, continuation._tls = tuple(sealed), tls
        continuation._resources = listener_pins, journal_pins, execution_pins
        continuation._retained_bytes, continuation._closed, continuation._production = retained_bytes, False, production
        continuation._seal = (work, lifetime, continuation._sealed, tls,
            continuation._resources, retained_bytes, production)
        _continuation = continuation
        continuation.current()
        if _staging_listener(staging_fd) != staging_pins:
            raise RuntimeError("dynamic consume staging listener changed before ACK")
        identities = transport._pair_identities_on_work(request[1], request[2],
            deadline_ns=lifetime.bound, work=work, current=continuation.current)
        work.charge(input_bytes=sum(map(len, identities)) * 2)
        if identities != (delivered.planner_identity, delivered.history_identity):
            raise RuntimeError("dynamic consume staged identities differ from genuine admission")
        inventory._require_inventory(tuple(owned))
        # The ACK precedes permanent drop and genuine worker construction.
        if _sealed_sources:
            originals._return_originals('consume-worker', owned=owned, work=work, current=continuation.current)
        transport._send_response(connection, (b"staged", *identities),
            deadline_ns=lifetime.bound, work=work, current=continuation.current)
        continuation.current()
        closing, connection = connection, None
        if not _close_socket(closing, owned):
            raise RuntimeError("dynamic consume staging connection cleanup is uncertain")
        closing, staging = staging, None
        if not _close_socket(closing, owned):
            raise RuntimeError("dynamic consume staging listener cleanup is uncertain")
        inventory._require_inventory(fixed.INHERITED_DESCRIPTORS)
        continuation.current()
        os.setgroups([])
        os.setresgid(fixed.SERVICE_GID, fixed.SERVICE_GID, fixed.SERVICE_GID)
        os.setresuid(fixed.SERVICE_UID, fixed.SERVICE_UID, fixed.SERVICE_UID)
        if (os.getresuid() != (fixed.SERVICE_UID,) * 3
                or os.getresgid() != (fixed.SERVICE_GID,) * 3 or os.getgroups()):
            raise RuntimeError("dynamic consume permanent drop retained privilege")
        native._require_unprivileged_process()
        os.environ.clear()
        os.environ.update(fixed.ENVIRONMENT)
        continuation.current()
        inventory._require_inventory(fixed.INHERITED_DESCRIPTORS)
        return runner._run_on_work(work=work, live_window=lifetime.window,
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
            raise RuntimeError("dynamic consume cleanup is uncertain; changed slots were not closed")
