"""Fixed twelve-FD, root-original delivery for the consume-only reserver.

Admission precedes all private-key and journal access. No key, account,
directory, checkpoint or state authority is provisioned by this module.
"""
from __future__ import annotations

import fcntl
import os
import socket
import stat

from serverware import authority_fd_entrypoint as delivery
from serverware import current_root_state_entrypoint as fd_inventory
from serverware import registration_execution_authorizer_entrypoint as sealed_originals


ROOT_PATH = "/run/serverware/oidc-session-activation-delivery-execution-reserver-trust/root-public-key.pem"
BOOTSTRAP_PATH = "/run/serverware/oidc-session-activation-delivery-execution-reserver-trust/bootstrap.json"
CUSTODY_PATH = "/run/serverware/oidc-session-activation-delivery-execution-reserver-trust/custody.json"
PLANNER_BOOTSTRAP_PATH = "/run/serverware/oidc-session-activation-delivery-execution-reserver-trust/planner-bootstrap.json"
PLANNER_HISTORY_CUSTODY_PATH = "/run/serverware/oidc-session-activation-delivery-execution-reserver-trust/planner-history-custody.json"
RECEIVING_HISTORY_CUSTODY_PATH = "/run/serverware/oidc-session-activation-delivery-execution-reserver-trust/receiving-history-custody.json"
EXECUTION_BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-execution-reserver-execution-bundle-key"
HISTORICAL_BUNDLE_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-execution-reserver-historical-bundle-key"
DELIVERY_KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-execution-reserver-delivery-key"
KEY_PATH = "/run/secrets/serverware-oidc-session-activation-delivery-execution-reserver-computation-key"
LISTENER_PATH = "/run/serverware/oidc-session-activation-delivery-execution/reserver.sock"
LISTENER_NAME = "serverware-oidc-session-activation-delivery-execution-reserver"
JOURNAL_PATH = "/var/lib/serverware/oidc-session-activation-delivery-execution-reservations"
PROCESS_MODE = "oidc-session-activation-delivery-execution-reserver"
SERVICE_UID = SERVICE_GID = 65499
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD = 198, 199, 200, 201
PLANNER_BOOTSTRAP_FD, PLANNER_HISTORY_CUSTODY_FD, RECEIVING_HISTORY_CUSTODY_FD = 202, 203, 204
EXECUTION_BUNDLE_KEY_FD, HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD, JOURNAL_FD = 205, 206, 207, 208, 209
INHERITED_DESCRIPTORS = tuple(range(198, 210))
PREFIX = "SERVERWARE_OIDC_SESSION_ACTIVATION_DELIVERY_EXECUTION_RESERVER_"
ROOT_ENV, BOOTSTRAP_ENV = PREFIX + "ROOT_PUBLIC_KEY_FD", PREFIX + "BOOTSTRAP_FD"
PYTHON = "/runtime/python/bin/python3"
LAUNCHER = "/runtime/authority-bootstrap/oidc_session_activation_delivery_execution_reserver_launcher.py"
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "SERVERWARE_PROCESS_MODE": PROCESS_MODE, ROOT_ENV: str(ROOT_FD), BOOTSTRAP_ENV: str(BOOTSTRAP_FD)}
MAX_ROOT_BYTES, MAX_BOOTSTRAP_BYTES, MAX_CUSTODY_BYTES = 16 * 1024, 4 * 1024 * 1024, 16 * 1024
MAX_PLANNER_BOOTSTRAP_BYTES = 4 * 1024 * 1024
MAX_PLANNER_HISTORY_CUSTODY_BYTES = MAX_RECEIVING_HISTORY_CUSTODY_BYTES = 8 * 1024 * 1024
MAX_KEY_BYTES, MAX_RAW_KEY_BYTES = 4096, 32
_TRUST_FILES = ((ROOT_PATH, ROOT_FD, MAX_ROOT_BYTES),
    (BOOTSTRAP_PATH, BOOTSTRAP_FD, MAX_BOOTSTRAP_BYTES),
    (CUSTODY_PATH, CUSTODY_FD, MAX_CUSTODY_BYTES),
    (PLANNER_BOOTSTRAP_PATH, PLANNER_BOOTSTRAP_FD, MAX_PLANNER_BOOTSTRAP_BYTES),
    (PLANNER_HISTORY_CUSTODY_PATH, PLANNER_HISTORY_CUSTODY_FD, MAX_PLANNER_HISTORY_CUSTODY_BYTES),
    (RECEIVING_HISTORY_CUSTODY_PATH, RECEIVING_HISTORY_CUSTODY_FD, MAX_RECEIVING_HISTORY_CUSTODY_BYTES))
_KEY_FILES = ((EXECUTION_BUNDLE_KEY_PATH, EXECUTION_BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (HISTORICAL_BUNDLE_KEY_PATH, HISTORICAL_BUNDLE_KEY_FD, MAX_RAW_KEY_BYTES),
    (DELIVERY_KEY_PATH, DELIVERY_KEY_FD, MAX_RAW_KEY_BYTES),
    (KEY_PATH, KEY_FD, MAX_KEY_BYTES))
_MATERIAL = {path: (maximum, private) for private, inventory in
    ((False, _TRUST_FILES), (True, _KEY_FILES)) for path, _descriptor, maximum in inventory}
# Descriptor-only neutral helpers do not adopt another role's paths or mode.
_require_inventory = fd_inventory._require_inventory
_retain = fd_inventory._retain
_sealed_identity = sealed_originals._sealed_identity
_read_original = sealed_originals._read_original


def _construction_on_work(work):
    from serverware import oidc_session_activation_delivery_execution_reserver_bootstrap as bootstrap

    return bootstrap._construction_on_work(work)


def _parent(path):
    if path not in (*_MATERIAL, LISTENER_PATH, JOURNAL_PATH):
        raise RuntimeError("consume reserver path is not source fixed")
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
                raise RuntimeError("consume reserver ancestor is not protected root material")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_material(path, maximum, *, work, private=False, maximum_capture_bytes=None):
    if path not in _MATERIAL or _MATERIAL[path] != (maximum, private) or type(private) is not bool:
        raise RuntimeError("consume reserver original inventory changed")
    parent, source = _parent(path), None
    try:
        source = os.open(os.path.basename(path), os.O_RDONLY | os.O_CLOEXEC
            | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 2 <= before.st_size <= maximum
                or private and stat.S_IMODE(before.st_mode) != 0o400
                or path in (EXECUTION_BUNDLE_KEY_PATH, HISTORICAL_BUNDLE_KEY_PATH, DELIVERY_KEY_PATH)
                    and before.st_size != MAX_RAW_KEY_BYTES):
            raise RuntimeError("consume reserver original is not protected bounded material")
        identity = delivery._material_identity(before)
        if maximum_capture_bytes is not None and (
                type(maximum_capture_bytes) is not int or maximum_capture_bytes <= 0
                or 16 * before.st_size > maximum_capture_bytes):
            raise RuntimeError("consume execution original exceeds remaining cold capture capacity")
        named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if delivery._material_identity(named) != identity:
            raise RuntimeError("consume reserver original pathname differs")
        work.charge(input_bytes=2 * before.st_size)
        raw = delivery._read_exact_source(source, before.st_size)
        named = os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
        if (delivery._material_identity(os.fstat(source)) != identity
                or delivery._material_identity(named) != identity):
            raise RuntimeError("consume reserver original changed during read")
        return delivery._seal_bytes(source, name="serverware-oidc-consume-reserver",
            value=raw, mode=stat.S_IMODE(before.st_mode))
    except BaseException:
        if source is not None:
            os.close(source)
        raise
    finally:
        os.close(parent)


def _read_on_work(descriptor, maximum, work, *, private=False):
    from serverware import authority_revocation_capability_production as production

    identity = _sealed_identity(descriptor, maximum, private=private)
    size = identity[0][6]
    work.charge(input_bytes=size)
    raw, observed = production._callback(work,
        lambda: _read_original(descriptor, maximum, private=private))
    if observed != identity:
        raise RuntimeError("consume reserver sealed original changed before its charged read")
    return raw, identity


def _keys_on_work(material, work):
    """Admit only actual sealed raw32 keys and the enrolled computation pair."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from serverware import authority_oidc_session_activation_delivery_execution_custody as custody

    evidence = custody.evidence
    evidence.capture._SharedLedger(work)
    originals, identities = [], []
    for _path, descriptor, maximum in _KEY_FILES:
        raw, identity = _read_on_work(descriptor, maximum, work, private=True)
        originals.append(raw)
        identities.append((descriptor, maximum, identity))
    execution, historical, delivery_key, signing_raw = originals
    if any(type(raw) is not bytes or len(raw) != MAX_RAW_KEY_BYTES
            for raw in (execution, historical, delivery_key)):
        raise RuntimeError("consume reserver encryption originals must be raw32")
    custody._key_bindings(material.custody_material, execution, historical, delivery_key, work)
    private = evidence.production._callback(work,
        lambda: serialization.load_pem_private_key(signing_raw, password=None))
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("consume reserver computation original must be Ed25519")
    evidence.keys._public_binding(material.computation_public_key, material.computation_spki_digest, work)
    evidence.keys._pair_on_work(private, material.computation_public_key, work)
    for descriptor, maximum, identity in identities:
        observed = evidence.production._callback(work,
            lambda descriptor=descriptor, maximum=maximum: _sealed_identity(descriptor, maximum, private=True))
        if observed != identity:
            raise RuntimeError("consume reserver key descriptor changed during admission")
    return execution, historical, delivery_key, private


def _listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != LISTENER_PATH or os.get_blocking(descriptor)):
            raise RuntimeError("consume reserver listener differs from fixed socket activation")
    finally:
        observed.close()
    parent = _parent(LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)):
            raise RuntimeError("consume reserver socket path protection differs")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _journal(descriptor):
    """Validate the actual fixed journal directory without creating or writing it."""
    value = os.fstat(descriptor)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) != (SERVICE_UID, SERVICE_GID, 0o700)):
        raise RuntimeError("consume reserver journal ownership or mode differs")
    parent = _parent(JOURNAL_PATH)
    try:
        named = os.stat(os.path.basename(JOURNAL_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode) or named.st_nlink < 1
                or (named.st_dev, named.st_ino, named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode))
                    != (value.st_dev, value.st_ino, SERVICE_UID, SERVICE_GID, 0o700)):
            raise RuntimeError("consume reserver journal pathname differs from its descriptor")
        return value.st_dev, value.st_ino
    finally:
        os.close(parent)


def _journal_directory(device, inode):
    parent, descriptor = _parent(JOURNAL_PATH), None
    try:
        descriptor = os.open(os.path.basename(JOURNAL_PATH), os.O_RDONLY | os.O_DIRECTORY
            | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        if _journal(descriptor) != (device, inode):
            raise RuntimeError("consume reserver journal differs from its signed identity")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent)


def main(*, _sealed_originals=False):
    if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise RuntimeError("consume reserver delivery must begin as root")
    if (os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") != LISTENER_NAME):
        raise RuntimeError("consume reserver requires one exact activated listener")
    from serverware import oidc_session_activation_execution_dynamic_entrypoint as original_delivery
    incoming = original_delivery._incoming("oidc_session_activation_delivery_execution_reserver_entrypoint", _sealed_originals)
    inherited = {3, *(item[0] for item in incoming.values())}
    _require_inventory(inherited)
    owned, reservations, retained = inherited, {}, {}
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware import oidc_session_activation_delivery as lifetime
        from serverware import oidc_session_activation_delivery_execution_reserver_bootstrap as bootstrap
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = _construction_on_work(work)
        _window, current = lifetime._window(window, bound, work)
        current()
        os.set_blocking(3, False)
        _listener(3)
        for target in INHERITED_DESCRIPTORS:
            reserved = fcntl.fcntl(3, fcntl.F_DUPFD_CLOEXEC, target)
            owned.add(reserved)
            if reserved != target:
                raise RuntimeError("consume reserver fixed descriptor slot is occupied")
            reservations[target] = delivery._material_identity(os.fstat(reserved))
        capture_remaining = bootstrap.receiving.MAX_ORIGINALS_BYTES - bootstrap.receiving.INTAKE_METADATA_BYTES
        for path, target, maximum in _TRUST_FILES:
            current()
            source = (original_delivery._source(path, maximum, incoming, work=work, maximum_capture_bytes=capture_remaining)
                if _sealed_originals else _open_material(path, maximum, work=work, maximum_capture_bytes=capture_remaining))
            owned.add(source)
            current()
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            capture_remaining -= 16 * retained[target][6]
            os.close(source)
            owned.remove(source)
        originals = []
        for _path, descriptor, maximum in _TRUST_FILES:
            current()
            raw, _identity = _read_on_work(descriptor, maximum, work)
            originals.append(raw)
            current()
        root_raw, bootstrap_raw, custody_raw, planner_raw, planning_raw, receiving_raw = originals
        bootstrap.receiving._intake_reservation(tuple(map(len, originals)))
        root = bootstrap.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("consume reserver root original must be Ed25519")
        material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, custody_bytes=custody_raw,
            planner_bootstrap_bytes=planner_raw, planner_history_custody_bytes=planning_raw,
            receiving_history_custody_bytes=receiving_raw, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work)
        current()
        launch = material.launch
        fields = ("processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
            "rootPublicKeyFd", "bootstrapFd", "listenerFd", "custodyFd", "plannerBootstrapFd",
            "plannerHistoryCustodyFd", "receivingHistoryCustodyFd", "executionBundleKeyFd",
            "historicalBundleKeyFd", "deliveryKeyFd", "signingKeyFd", "journalDirectoryFd",
            "listenerPath", "journalDirectoryPath")
        expected = (PROCESS_MODE, SERVICE_UID, SERVICE_GID, PEER_UID, PEER_GID,
            *INHERITED_DESCRIPTORS, LISTENER_PATH, JOURNAL_PATH)
        if (tuple(launch[name] for name in fields) != expected
                or tuple(launch["inheritedFileDescriptors"]) != INHERITED_DESCRIPTORS):
            raise RuntimeError("consume reserver launch differs from fixed resource delivery")
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
        if _listener(3) != listener_pins:
            raise RuntimeError("consume reserver listener differs from the signed launch")
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("consume reserver trust descriptor changed during root admission")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        current()
        for path, target, maximum in _KEY_FILES:
            current()
            source = _open_material(path, maximum, work=work, private=True)
            owned.add(source)
            current()
            bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            _retain(source, target, reservations, owned)
            retained[target] = delivery._material_identity(os.fstat(target))
            os.close(source)
            owned.remove(source)
        _keys_on_work(material, work)
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        current()
        source = _journal_directory(*journal_pins)
        owned.add(source)
        current()
        _retain(source, JOURNAL_FD, reservations, owned)
        retained[JOURNAL_FD] = delivery._material_identity(os.fstat(JOURNAL_FD))
        os.close(source)
        owned.remove(source)
        _retain(3, LISTENER_FD, reservations, owned)
        retained[LISTENER_FD] = delivery._material_identity(os.fstat(LISTENER_FD))
        os.close(3)
        owned.remove(3)
        if (reservations or _listener(LISTENER_FD) != listener_pins
                or _journal(JOURNAL_FD) != journal_pins):
            raise RuntimeError("consume reserver delivery resource inventory changed")
        for _path, descriptor, maximum in _TRUST_FILES:
            current()
            _read_on_work(descriptor, maximum, work)
        for _path, descriptor, maximum in _KEY_FILES:
            _sealed_identity(descriptor, maximum, private=True)
        current()
        for descriptor in INHERITED_DESCRIPTORS:
            os.set_inheritable(descriptor, False)
        _require_inventory(INHERITED_DESCRIPTORS)
        os.setgroups([])
        os.setresgid(SERVICE_GID, SERVICE_GID, SERVICE_GID)
        os.setresuid(SERVICE_UID, SERVICE_UID, SERVICE_UID)
        if (os.getresuid() != (SERVICE_UID,) * 3 or os.getresgid() != (SERVICE_GID,) * 3 or os.getgroups()):
            raise RuntimeError("consume reserver identity drop retained privilege")
        delivery._require_unprivileged_process()
        for descriptor, identity in retained.items():
            if delivery._material_identity(os.fstat(descriptor)) != identity:
                owned.discard(descriptor)
                raise RuntimeError("consume reserver descriptor changed before continuation")
        if _listener(LISTENER_FD) != listener_pins or _journal(JOURNAL_FD) != journal_pins:
            raise RuntimeError("consume reserver bound resource changed before continuation")
        bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
        current()
        _require_inventory(INHERITED_DESCRIPTORS)
        # Preserve the actual first work ledger and clock objects across the
        # permanent drop. A new process/window would renew this allowance.
        os.environ.clear()
        os.environ.update(ENVIRONMENT)
        from serverware import oidc_session_activation_delivery_execution_reserver_runner as runner

        current()
        return runner._run_on_work(work=work, live_window=window, transport_deadline_ns=bound)
    finally:
        for descriptor in sorted(owned, reverse=True):
            try:
                os.close(descriptor)
            except OSError:
                pass
