"""Fixed cold admission and accept owner for the registration evidence signer.

Root delivery supplies exactly five inherited descriptors and drops to the
dedicated nonroot process. The bootstrap and its separate trusted-host-local
receipt are genuinely authenticated before any private listener/replay handle
is opened. This establishes no hardware/enclave assurance or anti-rollback
property for the independently provisioned replay directory.

Only this PID may use the singleton. Failed/closed admission never restarts in
process, borrowed descriptors are never changed or closed, and live receipt,
environment, descriptor and socket-path continuity remain mandatory. Connected
sockets belong to the actual signer service, including its peer admission and
one request allowance. There is no key/path fallback or development opt-out.
"""
from __future__ import annotations

import fcntl
import os
import select
import socket
import stat
import threading
import time


PROCESS_MODE = "webauthn-registration-evidence-signer"
SERVICE_UID = SERVICE_GID = 65517
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, REPLAY_FD = 198, 199, 200, 201, 202
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, REPLAY_FD)
LISTENER_PATH = "/run/catchplate/registration-evidence/signer.sock"
ROOT_ENVIRONMENT = "CATCHPLATE_REGISTRATION_SIGNER_ROOT_PUBLIC_KEY_FD"
BOOTSTRAP_ENVIRONMENT = "CATCHPLATE_REGISTRATION_SIGNER_BOOTSTRAP_FD"
_PREFIX = "CATCHPLATE_REGISTRATION_SIGNER_"
_PID = os.getpid()
_LOCK = threading.RLock()
_state = "new"
_namespace = None
_owner = None


class SignerStartupError(RuntimeError):
    """Terminal cold/lifecycle failure; the runner must stop."""


class SignerRequestError(RuntimeError):
    """One connection failed; its grant may already have been consumed."""


def _require_pid():
    if os.getpid() != _PID:
        raise SignerStartupError("forked process cannot use the registration signer startup owner")


def _environment():
    return os.environ.get("CATCHPLATE_PROCESS_MODE", ""), tuple(sorted(
        (name, value) for name, value in os.environ.items() if name.startswith(_PREFIX)))


def _process(namespace):
    if (namespace != (PROCESS_MODE, tuple(sorted(((ROOT_ENVIRONMENT, str(ROOT_FD)),
            (BOOTSTRAP_ENVIRONMENT, str(BOOTSTRAP_FD))))))
            or (os.geteuid(), os.getegid()) != (SERVICE_UID, SERVICE_GID)):
        raise SignerStartupError("registration signer requires its exact nonroot process and FD namespace")


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
        raise SignerStartupError("registration signer credential is not bounded root-owned sealed memfd material")
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns, seals, target)


def _read_original(descriptor, maximum, *, private=False):
    before = _sealed_identity(descriptor, maximum, private=private)
    size = before[6]
    value = bytearray()
    while len(value) < size:
        chunk = os.pread(descriptor, min(4096, size - len(value)), len(value))
        if not chunk:
            raise SignerStartupError("registration signer credential was truncated")
        value.extend(chunk)
    if os.pread(descriptor, 1, size) or _sealed_identity(descriptor, maximum, private=private) != before:
        raise SignerStartupError("registration signer credential changed while reading")
    return bytes(value), before


def _inherited_inventory():
    # Like the existing authority inventory reader, listdir closes its own
    # enumeration FD before fstat: it is never treated as an inherited FD.
    names = os.listdir("/proc/self/fd")
    if len(names) > len(INHERITED_DESCRIPTORS) + 4:
        raise SignerStartupError("registration signer inherited descriptor inventory is oversized")
    descriptors = []
    for name in names:
        if not name.isascii() or not name.isdecimal():
            raise SignerStartupError("registration signer descriptor inventory is invalid")
        descriptor = int(name)
        if descriptor < 3:
            continue
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        descriptors.append(descriptor)
    if tuple(sorted(descriptors)) != INHERITED_DESCRIPTORS:
        raise SignerStartupError("registration signer inherited descriptor inventory is not exact")


def _metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _listener_identity(listener):
    original = os.fstat(LISTENER_FD)
    duplicate = os.fstat(listener.fileno())
    path = os.stat(LISTENER_PATH, follow_symlinks=False)
    bound = listener.getsockname()
    if type(bound) is bytes:
        bound = bound.decode("ascii")
    if (not stat.S_ISSOCK(original.st_mode) or _metadata(original) != _metadata(duplicate)
            or not stat.S_ISSOCK(path.st_mode) or path.st_nlink != 1
            or (path.st_uid, path.st_gid, stat.S_IMODE(path.st_mode)) != (SERVICE_UID, PEER_GID, 0o660)
            or bound != LISTENER_PATH
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or os.get_blocking(LISTENER_FD) or os.get_blocking(listener.fileno())):
        raise SignerStartupError("registration signer listener differs from its fixed activated socket")
    return _metadata(original), _metadata(path), bound


def _directory_identity(device, inode):
    value = os.fstat(REPLAY_FD)
    if (not stat.S_ISDIR(value.st_mode) or value.st_nlink < 1
            or (value.st_dev, value.st_ino, value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode))
                != (device, inode, SERVICE_UID, SERVICE_GID, 0o700)):
        raise SignerStartupError("registration signer replay directory differs from its signed private identity")
    # Legitimate append-only replay writes change size and timestamps. The
    # actual replay owner independently tracks those changing fields.
    return value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode


def _require_owner(owner):
    global _state
    _require_pid()
    try:
        if (type(owner) is not _SignerOwner or owner._closed or owner._failed
                or _owner is not owner or _state != "started" or _environment() != _namespace):
            raise SignerStartupError("registration signer singleton or namespace changed")
        _process(_namespace)
        for descriptor, maximum, private, expected in owner._sealed:
            if _sealed_identity(descriptor, maximum, private=private) != expected:
                raise SignerStartupError("registration signer sealed credential custody changed")
        if _listener_identity(owner._listener) != owner._listener_identity:
            raise SignerStartupError("registration signer socket path or descriptor changed")
        if _directory_identity(*owner._directory_pin) != owner._directory_identity:
            raise SignerStartupError("registration signer replay directory custody changed")
        owner._signer._live(owner._service_binding)
        return owner
    except BaseException as exc:
        _state = "failed"
        if type(owner) is _SignerOwner:
            owner._failed = True
        if isinstance(exc, SignerStartupError):
            raise
        raise SignerStartupError("registration signer lifecycle admission failed") from exc


class _SignerOwner:
    __slots__ = ("_signer", "_service_binding", "_listener", "_sealed", "_listener_identity",
        "_directory_pin", "_directory_identity", "_closed", "_failed")

    def __init__(self):
        raise SignerStartupError("registration signer owner requires fixed cold admission")

    def serve_once(self):
        """Return False for a bounded idle wait, True after one handled stream."""
        global _state
        _require_pid()
        with _LOCK:
            _require_owner(self)
            binding, listener, signer = self._service_binding, self._listener, self._signer
            receipt_deadline = binding.opening_sample[0] + binding.attestation_interval[1] - binding.opening_sample[1]
            remaining = receipt_deadline - time.monotonic_ns()
            if remaining <= 0:
                _require_owner(self)
                raise SignerStartupError("registration signer original receipt expired")
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
            except SignerStartupError:
                raise
            except BaseException as exc:
                self._failed = True
                _state = "failed"
                raise SignerStartupError("registration signer listener acceptance failed") from exc
            try:
                _require_owner(self)
                from catchplate import authority_webauthn_registration_signer_service as service

                deadline = min(service.transport._deadline_ns(binding.timeout_seconds), receipt_deadline)
                # The actual service performs SO_PEERCRED before reading its
                # prefix and owns/closes this separately accepted connection.
                service.RegistrationEvidenceSigner.serve_connection(signer, connection, deadline_ns=deadline)
            except SignerStartupError:
                raise
            except Exception as exc:
                # A poisoned replay owner, expired receipt or descriptor drift
                # is terminal, not a recoverable request error.
                _require_owner(self)
                raise SignerRequestError("registration signer connection failed; no retry authority is implied") from exc
            finally:
                try:
                    connection.close()
                except BaseException:
                    pass
            _require_owner(self)
            return True


def initialize_from_environment():
    """Root-admit exactly once, before duplicate listener/replay handles open."""
    global _state, _namespace, _owner
    _require_pid()
    with _LOCK:
        if _state == "started":
            return require_started()
        if _state != "new":
            raise SignerStartupError("registration signer cannot restart after failure or shutdown")
        namespace = _environment()
        _namespace, _state = namespace, "initializing"
        listener = signer = None
        try:
            _process(namespace)
            root_original, root_identity = _read_original(ROOT_FD, 16384)
            bootstrap_original, bootstrap_identity = _read_original(BOOTSTRAP_FD, 4 * 1024 * 1024)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
            from catchplate import registration_evidence_signer_bootstrap as bootstrap
            from catchplate import authority_webauthn_registration_signer_service as service
            from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            work = _ValidationWork(QueryReadValidationLimits())
            work.charge(input_bytes=len(root_original))
            root_key = service.evidence.production._callback(work,
                lambda: serialization.load_pem_public_key(root_original))
            if not isinstance(root_key, Ed25519PublicKey):
                raise SignerStartupError("registration signer root must be a real Ed25519 PEM public key")
            material = bootstrap._admit_on_work(bootstrap_bytes=bootstrap_original,
                root_public_key=root_key, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["peerUid"], launch["peerGid"], launch["rootPublicKeyFd"],
                    launch["bootstrapFd"], launch["listenerFd"], launch["signingKeyFd"],
                    launch["replayDirectoryFd"], launch["listenerPath"])
                    != (PROCESS_MODE, SERVICE_UID, SERVICE_GID, PEER_UID, PEER_GID,
                        ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, REPLAY_FD, LISTENER_PATH)
                    or type(launch["inheritedFileDescriptors"]) is not list
                    or tuple(launch["inheritedFileDescriptors"]) != INHERITED_DESCRIPTORS):
                raise SignerStartupError("registration signer launch differs from the fixed source topology")
            device, inode, capacity, timeout = (launch["replayDirectoryDevice"],
                launch["replayDirectoryInode"], launch["replayMaximumRecords"], launch["requestTimeoutSeconds"])
            public_key, signer_identity, interval = (material.evidence_public_key,
                material.evidence_signer_identity, material.attestation_interval)
            # Only genuine root-admitted descriptors may precede the private
            # listener duplicate and ReplayStore's independently owned lease.
            _inherited_inventory()
            directory_identity = _directory_identity(device, inode)
            raw_key, key_identity = _read_original(KEY_FD, 4096, private=True)
            if (not raw_key.startswith(b"-----BEGIN PRIVATE KEY-----\n")
                    or not raw_key.endswith(b"-----END PRIVATE KEY-----\n")):
                raise SignerStartupError("registration evidence key must be fixed unencrypted PKCS8 PEM")
            work.charge(input_bytes=len(raw_key))
            private_key = service.evidence.production._callback(work,
                lambda: serialization.load_pem_private_key(raw_key, password=None))
            if not isinstance(private_key, Ed25519PrivateKey):
                raise SignerStartupError("registration evidence key is not Ed25519")
            service.evidence.keys._pair_on_work(private_key, public_key, work)
            listener = socket.fromfd(LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            listener_identity = _listener_identity(listener)
            signer = service.RegistrationEvidenceSigner.from_admitted_configuration(
                payload=material.configuration_payload, configuration_digest=material.configuration_digest,
                generation=material.generation, runtime_role_identities=material.runtime_role_identities,
                evidence_private_key=private_key, evidence_signer_identity=signer_identity,
                signer_uid=SERVICE_UID, signer_gid=SERVICE_GID, peer_uid=PEER_UID, peer_gid=PEER_GID,
                attestation_interval=interval, request_timeout_seconds=timeout,
                replay_directory_fd=REPLAY_FD, replay_directory_device=device,
                replay_directory_inode=inode, maximum_records=capacity, work=work)
            if _environment() != namespace:
                raise SignerStartupError("registration signer namespace changed during admission")
            owner = object.__new__(_SignerOwner)
            owner._signer, owner._service_binding, owner._listener = signer, signer._binding, listener
            owner._sealed = ((ROOT_FD, 16384, False, root_identity),
                (BOOTSTRAP_FD, 4 * 1024 * 1024, False, bootstrap_identity),
                (KEY_FD, 4096, True, key_identity))
            owner._listener_identity = listener_identity
            owner._directory_pin, owner._directory_identity = (device, inode), directory_identity
            owner._closed, owner._failed = False, False
            _owner, _state = owner, "started"
            _require_owner(owner)
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            if signer is not None:
                try:
                    signer.close()
                except BaseException:
                    pass
            if listener is not None:
                try:
                    listener.close()
                except BaseException:
                    pass
            if isinstance(exc, SignerStartupError):
                raise
            raise SignerStartupError("registration signer cold admission failed") from exc


def require_started():
    """Return the actual live owner, never perform lazy admission."""
    _require_pid()
    with _LOCK:
        if _state != "started":
            raise SignerStartupError("registration signer requires successful cold startup")
        return _require_owner(_owner)


def close():
    """Release only this PID's private listener and real replay/key owner."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        if _state == "closed":
            return
        if _state == "initializing":
            raise SignerStartupError("registration signer cannot close during admission")
        owner = _owner
        _owner, _state = None, "closed"
        if owner is None:
            return
        owner._closed = True
        first = None
        try:
            owner._signer.close()
        except BaseException as exc:
            first = exc
        try:
            owner._listener.close()
        except BaseException as exc:
            if first is None:
                first = exc
        if first is not None:
            raise SignerStartupError("registration signer shutdown failed") from first
