"""Fixed cold admission and single-PID lifecycle for current-root state.

Root delivery supplies exactly five inherited descriptors and the dedicated
nonroot process. The independent root public key is delivered separately from
the signed bootstrap, which retains the original enrollment and independently
current exact checkpoint. No journal observation chooses that checkpoint.

Actual journal recovery, state-key admission and request handling belong to
CurrentRootJournal, CurrentRootDecisionOwner and CurrentRootDecisionService.
This owner retains the original launch interval through accept and service
deadlines, without renewal. Failed or closed admission cannot restart in this
process. Only the private listener duplicate and real decision/journal owner
are closed here; inherited descriptors remain borrowed.

This is trusted-host-local startup, not hardware measurement, hostile-host
antirollback, deployment, provisioning or fresh independent state authority.
"""
from __future__ import annotations

import fcntl
import os
import select
import socket
import stat
import threading
import time


PROCESS_MODE = ROLE = "policy-authority-current-root-state"
SERVICE_UID = SERVICE_GID = 65516
RESERVE_PEER_UID = RESERVE_PEER_GID = 65514
COMPLETE_PEER_UID = COMPLETE_PEER_GID = 65515
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD = 198, 199, 200, 201, 202
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD)
LISTENER_PATH = "/run/serverware/current-root/state.sock"
ROOT_ENVIRONMENT = "SERVERWARE_CURRENT_ROOT_STATE_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENVIRONMENT = "SERVERWARE_CURRENT_ROOT_STATE_BOOTSTRAP_FD"
_PREFIX = "SERVERWARE_CURRENT_ROOT_STATE_"
_MAX_ROOT_BYTES, _MAX_BOOTSTRAP_BYTES, _MAX_KEY_BYTES = 16384, 256 * 1024, 4096
_PID = os.getpid()
_LOCK = threading.RLock()
_state = "new"
_namespace = None
_owner = None


class CurrentRootStateStartupError(RuntimeError):
    """Terminal cold/lifecycle failure; the runner must stop."""


class CurrentRootStateRequestError(RuntimeError):
    """One request failed; publication or delivery may already have occurred."""


def _require_pid():
    if os.getpid() != _PID:
        raise CurrentRootStateStartupError("forked process cannot use current-root state startup")


def _environment():
    return os.environ.get("SERVERWARE_PROCESS_MODE", ""), tuple(sorted(
        (name, value) for name, value in os.environ.items() if name.startswith(_PREFIX)))


def _process(namespace):
    if (namespace != (PROCESS_MODE, tuple(sorted(((ROOT_ENVIRONMENT, str(ROOT_FD)),
            (BOOTSTRAP_ENVIRONMENT, str(BOOTSTRAP_FD))))))
            or (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
                != (SERVICE_UID, SERVICE_UID, SERVICE_GID, SERVICE_GID)):
        raise CurrentRootStateStartupError("current-root state requires its exact nonroot process and FD namespace")


def _sealed_identity(descriptor, maximum, *, private=False):
    value = os.fstat(descriptor)
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    target = os.readlink("/proc/self/fd/" + str(descriptor))
    required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 0
            or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or private and stat.S_IMODE(value.st_mode) != 0o400
            or not 2 <= value.st_size <= maximum or seals & required != required
            or not target.startswith("/memfd:") or not target.endswith(" (deleted)")):
        raise CurrentRootStateStartupError("current-root credential is not bounded root-owned sealed memfd material")
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns, seals, target)


def _read_original(descriptor, maximum, *, private=False):
    before = _sealed_identity(descriptor, maximum, private=private)
    size = before[6]
    value = bytearray()
    while len(value) < size:
        chunk = os.pread(descriptor, min(4096, size - len(value)), len(value))
        if not chunk:
            raise CurrentRootStateStartupError("current-root credential was truncated")
        value.extend(chunk)
    if os.pread(descriptor, 1, size) or _sealed_identity(descriptor, maximum, private=private) != before:
        raise CurrentRootStateStartupError("current-root credential changed while reading")
    return bytes(value), before


def _inherited_inventory():
    names = os.listdir("/proc/self/fd")
    if len(names) > len(INHERITED_DESCRIPTORS) + 4:
        raise CurrentRootStateStartupError("current-root inherited descriptor inventory is oversized")
    descriptors = []
    for name in names:
        if not name.isascii() or not name.isdecimal():
            raise CurrentRootStateStartupError("current-root descriptor inventory is invalid")
        descriptor = int(name)
        if descriptor < 3:
            continue
        try:
            os.fstat(descriptor)
        except OSError:
            # listdir has already closed its own enumeration descriptor.
            continue
        descriptors.append(descriptor)
    if tuple(sorted(descriptors)) != INHERITED_DESCRIPTORS:
        raise CurrentRootStateStartupError("current-root inherited descriptor inventory is not exact")


def _metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _listener_identity(listener, pins):
    socket_device, socket_inode, path_device, path_inode = pins
    original = os.fstat(LISTENER_FD)
    duplicate = os.fstat(listener.fileno())
    path = os.stat(LISTENER_PATH, follow_symlinks=False)
    bound = listener.getsockname()
    if type(bound) is bytes:
        bound = bound.decode("ascii")
    if (not stat.S_ISSOCK(original.st_mode) or _metadata(original) != _metadata(duplicate)
            or (original.st_dev, original.st_ino) != (socket_device, socket_inode)
            or not stat.S_ISSOCK(path.st_mode) or path.st_nlink != 1
            or (path.st_dev, path.st_ino) != (path_device, path_inode)
            or (path.st_uid, path.st_gid, stat.S_IMODE(path.st_mode)) != (SERVICE_UID, SERVICE_GID, 0o660)
            or bound != LISTENER_PATH
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or os.get_blocking(LISTENER_FD) or os.get_blocking(listener.fileno())):
        raise CurrentRootStateStartupError("current-root listener differs from its signed activated socket")
    return _metadata(original), _metadata(path), bound


def _directory_identity(device, inode):
    value = os.fstat(JOURNAL_FD)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_dev, value.st_ino, value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode))
                != (device, inode, SERVICE_UID, SERVICE_GID, 0o700)):
        raise CurrentRootStateStartupError("current-root journal directory differs from its signed private identity")
    # The actual journal owns changing directory/record stamps across appends.
    return value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode


def _live(owner):
    from serverware import current_root_state_bootstrap as bootstrap

    sample = bootstrap._fresh(owner._interval, owner._work, opening=owner._opening)
    if (sample[0] < owner._last_monotonic or sample[1] < owner._last_epoch
            or sample[2] >= owner._launch_deadline):
        raise CurrentRootStateStartupError("current-root original launch expired or its clock reversed")
    owner._last_monotonic, owner._last_epoch = sample[2], sample[1]


def _require_owner(owner):
    global _state
    _require_pid()
    try:
        if (type(owner) is not _StateOwner or owner._closed or owner._failed
                or _owner is not owner or _state != "started" or _environment() != _namespace):
            raise CurrentRootStateStartupError("current-root singleton or namespace changed")
        _process(_namespace)
        _live(owner)
        for descriptor, maximum, private, expected in owner._sealed:
            if _sealed_identity(descriptor, maximum, private=private) != expected:
                raise CurrentRootStateStartupError("current-root sealed credential custody changed")
        if _listener_identity(owner._listener, owner._listener_pins) != owner._listener_identity:
            raise CurrentRootStateStartupError("current-root socket identity changed")
        if _directory_identity(*owner._directory_pins) != owner._directory_identity:
            raise CurrentRootStateStartupError("current-root journal directory custody changed")
        from serverware import authority_current_root_decisions as decisions
        from serverware import authority_current_root_service as service

        if (service.CurrentRootDecisionService._snapshot_configuration(owner._service) is not owner._service_config
                or owner._decision._journal is not owner._journal
                or owner._decision._state_private_key is not owner._state_key
                or owner._decision._root_public_key is not owner._root_key
                or owner._decision._enrollment_bytes is not owner._enrollment):
            raise CurrentRootStateStartupError("current-root configured owner or key custody changed")
        # Actual readiness includes the genuine journal's poison/inventory
        # checks. This observation never supplies an independent checkpoint.
        decisions.CurrentRootDecisionOwner.inspect(owner._decision)
        _live(owner)
        return owner
    except BaseException as exc:
        _state = "failed"
        if type(owner) is _StateOwner:
            owner._failed = True
        if isinstance(exc, CurrentRootStateStartupError):
            raise
        raise CurrentRootStateStartupError("current-root lifecycle admission failed") from exc


class _StateOwner:
    __slots__ = ("_decision", "_journal", "_service", "_service_config", "_listener", "_sealed",
        "_listener_pins", "_listener_identity", "_directory_pins", "_directory_identity",
        "_root_key", "_state_key", "_enrollment", "_interval", "_opening", "_launch_deadline",
        "_work", "_last_epoch", "_last_monotonic", "_closed", "_failed")

    def __init__(self):
        raise CurrentRootStateStartupError("current-root startup owner requires fixed cold admission")

    def serve_once(self):
        """Return False after bounded idle wait, True after one handled stream."""
        global _state
        _require_pid()
        with _LOCK:
            _require_owner(self)
            listener = self._listener
            remaining = self._launch_deadline - time.monotonic_ns()
            if remaining <= 0:
                _require_owner(self)
                raise CurrentRootStateStartupError("current-root original launch expired")
            try:
                ready, _, _ = select.select((listener,), (), (), min(1.0, remaining / 1_000_000_000))
                _require_owner(self)
                if not ready:
                    return False
                try:
                    connection, _address = listener.accept()
                except BlockingIOError:
                    _require_owner(self)
                    return False
            except CurrentRootStateStartupError:
                raise
            except BaseException as exc:
                self._failed, _state = True, "failed"
                raise CurrentRootStateStartupError("current-root listener acceptance failed") from exc
            try:
                _require_owner(self)
                from serverware import authority_current_root_service as service

                # The genuine service admits purpose-specific SO_PEERCRED
                # before bodies, uses the actual owner's work, and closes the
                # accepted connection. It may only shorten this launch bound.
                service.CurrentRootDecisionService.serve_connection(self._service, connection,
                    transport_deadline_ns=self._launch_deadline)
            except CurrentRootStateStartupError:
                raise
            except Exception as exc:
                # Poison, identity drift or expired launch is terminal; only
                # an independently still-live owner permits the next request.
                _require_owner(self)
                raise CurrentRootStateRequestError("current-root request failed; outcome remains uncertain") from exc
            finally:
                try:
                    connection.close()
                except BaseException:
                    pass
            _require_owner(self)
            return True


def initialize_from_environment():
    """Authenticate one root delivery before opening owned listener/journal FDs."""
    global _state, _namespace, _owner
    _require_pid()
    with _LOCK:
        if _state == "started":
            return require_started()
        if _state != "new":
            raise CurrentRootStateStartupError("current-root state cannot restart after failure or shutdown")
        namespace = _environment()
        _namespace, _state = namespace, "initializing"
        listener = journal = decision = None
        try:
            _process(namespace)
            root_original, root_identity = _read_original(ROOT_FD, _MAX_ROOT_BYTES)
            bootstrap_original, bootstrap_identity = _read_original(BOOTSTRAP_FD, _MAX_BOOTSTRAP_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
            from serverware import current_root_state_bootstrap as bootstrap
            from serverware import authority_current_root_decisions as decisions
            from serverware import authority_current_root_journal as storage
            from serverware import authority_current_root_service as service
            from serverware import authority_webauthn_evidence as evidence
            from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != _MAX_BOOTSTRAP_BYTES:
                raise CurrentRootStateStartupError("current-root bootstrap byte contract changed")
            work = _ValidationWork(QueryReadValidationLimits())
            work.charge(input_bytes=len(root_original))
            root_key = evidence.production._callback(work, lambda: serialization.load_pem_public_key(root_original))
            if not isinstance(root_key, Ed25519PublicKey):
                raise CurrentRootStateStartupError("current-root trust requires an actual Ed25519 PEM public key")
            material = bootstrap._admit_on_work(bootstrap_bytes=bootstrap_original,
                root_public_key=root_key, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["reservePeerUid"], launch["reservePeerGid"],
                    launch["completePeerUid"], launch["completePeerGid"], launch["rootPublicKeyFd"],
                    launch["bootstrapFd"], launch["listenerFd"], launch["signingKeyFd"],
                    launch["journalDirectoryFd"], launch["listenerPath"])
                    != (PROCESS_MODE, SERVICE_UID, SERVICE_GID, RESERVE_PEER_UID, RESERVE_PEER_GID,
                        COMPLETE_PEER_UID, COMPLETE_PEER_GID, ROOT_FD, BOOTSTRAP_FD, LISTENER_FD,
                        KEY_FD, JOURNAL_FD, LISTENER_PATH)
                    or type(launch["inheritedFileDescriptors"]) is not list
                    or tuple(launch["inheritedFileDescriptors"]) != INHERITED_DESCRIPTORS):
                raise CurrentRootStateStartupError("current-root launch differs from its fixed source topology")
            device, inode, maximum_records, timeout = (launch["journalDirectoryDevice"],
                launch["journalDirectoryInode"], launch["journalMaximumRecords"], launch["requestTimeoutSeconds"])
            listener_pins = (launch["listenerSocketDevice"], launch["listenerSocketInode"],
                launch["listenerPathDevice"], launch["listenerPathInode"])
            enrollment, public_key = material.enrollment_bytes, material.state_public_key
            sequence, head = material.checkpoint
            interval = material.attestation_interval
            opening = bootstrap._fresh(interval, work)
            launch_deadline = opening[0] + interval[1] - opening[1]
            _inherited_inventory()
            directory_identity = _directory_identity(device, inode)
            raw_key, key_identity = _read_original(KEY_FD, _MAX_KEY_BYTES, private=True)
            if (not raw_key.startswith(b"-----BEGIN PRIVATE KEY-----\n")
                    or not raw_key.endswith(b"-----END PRIVATE KEY-----\n")):
                raise CurrentRootStateStartupError("current-root state key requires unencrypted PKCS8 PEM")
            work.charge(input_bytes=len(raw_key))
            private_key = evidence.production._callback(work,
                lambda: serialization.load_pem_private_key(raw_key, password=None))
            if not isinstance(private_key, Ed25519PrivateKey):
                raise CurrentRootStateStartupError("current-root state key is not Ed25519")
            evidence.keys._pair_on_work(private_key, public_key, work)
            listener = socket.fromfd(LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            listener_identity = _listener_identity(listener, listener_pins)
            journal = storage.CurrentRootJournal(directory_fd=JOURNAL_FD, expected_device=device,
                expected_inode=inode, expected_uid=SERVICE_UID, expected_gid=SERVICE_GID,
                maximum_records=maximum_records)
            # Constructor owns genuine replay and the exact independently
            # signed checkpoint comparison, including journal failure cleanup.
            decision = decisions.CurrentRootDecisionOwner(journal=journal, enrollment_bytes=enrollment,
                root_public_key=root_key, state_private_key=private_key,
                expected_sequence=sequence, expected_head_digest=head)
            if launch["schema"] == bootstrap.LAUNCH_SCHEMA_V8:
                # V8 adds only the separate consume reserver. The actual
                # owner joins signed reserve/consume before history return
                # or publication; the consume planner remains head-only.
                serving = service.CurrentRootDecisionService._with_delivery_reserver(
                    owner=decision, timeout_seconds=timeout)
            elif launch["schema"] == bootstrap.LAUNCH_SCHEMA_V7:
                # V7 opts only the distinct consume planner into its own head
                # protocol. It gets no activation, lookup or decision purpose.
                serving = service.CurrentRootDecisionService._with_delivery_planner(
                    owner=decision, timeout_seconds=timeout)
            elif launch["schema"] == bootstrap.LAUNCH_SCHEMA_V6:
                # V6 independently admits only activation completion/lookup.
                # Older signed profiles never inherit the new caller identity.
                serving = service.CurrentRootDecisionService._with_activation_completion(
                    owner=decision, timeout_seconds=timeout)
            elif launch["schema"] == bootstrap.LAUNCH_SCHEMA_V5:
                # V5 adds a separate activation reserve identity. The actual
                # owner must join both reserve and activation before history
                # return or publication; planner access remains head-only.
                serving = service.CurrentRootDecisionService._with_activation_reserver(
                    owner=decision, timeout_seconds=timeout)
            elif launch["schema"] == bootstrap.LAUNCH_SCHEMA_V4:
                # V4 adds only head observations for the fixed activation
                # planner. Its identity cannot reserve, complete or lookup.
                serving = service.CurrentRootDecisionService._with_activation_planner(
                    owner=decision, timeout_seconds=timeout)
            elif launch["schema"] == bootstrap.LAUNCH_SCHEMA_V3:
                # V3 independently opts into the fixed finalization completion
                # peer and signed-operation restriction; v1/v2 do not widen.
                serving = service.CurrentRootDecisionService._with_finalization_completion(
                    owner=decision, timeout_seconds=timeout)
            elif launch["schema"] == bootstrap.LAUNCH_SCHEMA_V2:
                # Only genuine root v2 admission selects this source-fixed
                # peer/operation profile. v1 retains its exact older behavior.
                serving = service.CurrentRootDecisionService._with_finalization_reserver(
                    owner=decision, timeout_seconds=timeout)
            else:
                serving = service.CurrentRootDecisionService(owner=decision,
                    reserve_peer_uid=RESERVE_PEER_UID, reserve_peer_gid=RESERVE_PEER_GID,
                    complete_peer_uid=COMPLETE_PEER_UID, complete_peer_gid=COMPLETE_PEER_GID,
                    timeout_seconds=timeout)
            bootstrap._fresh(interval, work, opening=opening)
            if _environment() != namespace:
                raise CurrentRootStateStartupError("current-root namespace changed during admission")
            owner = object.__new__(_StateOwner)
            owner._decision, owner._journal, owner._service = decision, journal, serving
            owner._service_config = service.CurrentRootDecisionService._snapshot_configuration(serving)
            owner._listener, owner._listener_pins, owner._listener_identity = listener, listener_pins, listener_identity
            owner._sealed = ((ROOT_FD, _MAX_ROOT_BYTES, False, root_identity),
                (BOOTSTRAP_FD, _MAX_BOOTSTRAP_BYTES, False, bootstrap_identity),
                (KEY_FD, _MAX_KEY_BYTES, True, key_identity))
            owner._directory_pins, owner._directory_identity = (device, inode), directory_identity
            owner._root_key, owner._state_key, owner._enrollment = root_key, private_key, enrollment
            owner._interval, owner._opening, owner._launch_deadline = interval, opening, launch_deadline
            owner._work, owner._last_epoch, owner._last_monotonic = work, opening[1], opening[2]
            owner._closed, owner._failed = False, False
            _owner, _state = owner, "started"
            _require_owner(owner)
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            if decision is not None:
                try:
                    decision.close()
                except BaseException:
                    pass
            elif journal is not None:
                try:
                    journal.close()
                except BaseException:
                    pass
            if listener is not None:
                try:
                    listener.close()
                except BaseException:
                    pass
            if isinstance(exc, CurrentRootStateStartupError):
                raise
            raise CurrentRootStateStartupError("current-root cold admission failed") from exc


def require_started():
    """Return the live singleton, never perform lazy or replacement admission."""
    _require_pid()
    with _LOCK:
        if _state != "started":
            raise CurrentRootStateStartupError("current-root state requires successful cold startup")
        return _require_owner(_owner)


def close():
    """Release only this PID's listener duplicate and real decision/journal owner."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        if _state == "closed":
            return
        if _state == "initializing":
            raise CurrentRootStateStartupError("current-root state cannot close during admission")
        owner = _owner
        _owner, _state = None, "closed"
        if owner is None:
            return
        owner._closed = True
        first = None
        try:
            owner._decision.close()
        except BaseException as exc:
            first = exc
        owner._state_key = None
        try:
            owner._listener.close()
        except BaseException as exc:
            if first is None:
                first = exc
        if first is not None:
            raise CurrentRootStateStartupError("current-root state shutdown failed") from first
