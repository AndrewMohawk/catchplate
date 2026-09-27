"""Cold, finite-lifetime owner for registration execution-grant requests.

An independently pinned root authenticates configuration, enrollment originals,
runtime assertions and both listener identities before the purpose-only key is
loaded. Only root delivery's exact four FDs and nonroot identity are admitted.
Each accepted connection has one bounded original-only exchange and one work
allowance. Failure/expiry never restarts or renews this singleton. A grant is
not a reserve, one-use receipt, credential finalization or SQL authorization.
"""
from __future__ import annotations

import os
import select
import socket
import threading
import time

from serverware import registration_execution_authorizer_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None


class AuthorizerStartupError(RuntimeError):
    pass


class AuthorizerRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise AuthorizerStartupError("forked process cannot use the registration execution owner")


def _environment():
    return os.environ.get("SERVERWARE_PROCESS_MODE", ""), tuple(sorted(
        (name, value) for name, value in os.environ.items() if name.startswith(delivery.PREFIX)))


def _process(namespace):
    expected = (delivery.PROCESS_MODE, tuple(sorted(((delivery.ROOT_ENV, str(delivery.ROOT_FD)),
        (delivery.BOOTSTRAP_ENV, str(delivery.BOOTSTRAP_FD))))))
    if (namespace != expected or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise AuthorizerStartupError("registration execution process or namespace differs")
    delivery.delivery._require_unprivileged_process()


class _AuthorizerOwner:
    __slots__ = ("_material", "_root", "_key", "_listener", "_listener_pins", "_sealed",
        "_opening", "_interval", "_deadline", "_last_epoch", "_last_monotonic",
        "_closed", "_failed", "_connection")

    def __init__(self):
        raise AuthorizerStartupError("registration execution owner requires genuine cold admission")

    def _live(self):
        global _state
        _require_pid()
        try:
            if (self is not _owner or _state != "started" or self._closed or self._failed
                    or _environment() != _namespace):
                raise AuthorizerStartupError("registration execution lifetime or singleton changed")
            _process(_namespace)
            for descriptor, maximum, private, original in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != original:
                    raise AuthorizerStartupError("registration execution sealed custody changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins):
                raise AuthorizerStartupError("registration execution listener or socket path changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno())
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_before, opened_epoch, opened_after = self._opening
            # Same strict original bracket as bootstrap._fresh, plus sticky
            # rollback samples. No work is allocated merely for an idle check.
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < self._interval[1] or after >= self._deadline
                    or not opened_epoch + before - opened_after <= epoch
                        <= opened_epoch + after - opened_before):
                raise AuthorizerStartupError("registration execution original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, AuthorizerStartupError):
                raise
            raise AuthorizerStartupError("registration execution lifecycle admission failed") from exc

    def _serve_connection(self, connection):
        from serverware import authority_registration_execution_transport as transport
        from serverware import authority_registration_execution_exchange as exchange
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        material = self._material
        deadline = min(self._deadline, transport._deadline_ns(material.launch["requestTimeoutSeconds"]))
        self._live()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, deadline,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise AuthorizerRequestError("registration execution caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=deadline)
        # Exact EOF and every frame length precede this sole request ledger.
        work = _ValidationWork(QueryReadValidationLimits())
        self._live()
        grant = exchange._produce_on_configuration(payload=material.configuration_payload,
            configuration_digest=material.configuration_digest, generation=material.generation,
            runtime_role_identities=material.runtime_role_identities,
            authorization_bytes=originals[0], request_originals=originals[1:4],
            response_originals=originals[4:8], before_vector_bytes=originals[8],
            authorization_enrollment_bytes=material.authorization_enrollment_bytes,
            current_root_enrollment_bytes=material.current_root_enrollment_bytes,
            grant_enrollment_bytes=material.grant_enrollment_bytes,
            root_public_key=self._root, authorizer_private_key=self._key,
            deadline_epoch_ns=material.attestation_interval[1], transport_deadline_ns=deadline, work=work)
        self._live()
        transport._check_deadline(deadline)
        transport._send_response(connection, grant, deadline_ns=deadline)
        self._live()
        transport._check_deadline(deadline)

    def serve_once(self):
        """At most one bounded serial connection; idle waits never renew trust."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._connection is not None:
                raise AuthorizerStartupError("registration execution already has an active connection")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                self._live()
                raise AuthorizerStartupError("registration execution original lifetime expired")
            ready, _, _ = select.select((self._listener,), (), (), min(1.0, remaining))
            self._live()
            if not ready:
                return False
            try:
                connection, _address = self._listener.accept()
            except BlockingIOError:
                self._live()
                return False
            self._connection = connection
            try:
                self._serve_connection(connection)
            except BaseException as exc:
                self._live()  # A failed lifetime is terminal, not a request denial.
                raise AuthorizerRequestError("registration execution request denied") from exc
            finally:
                try:
                    connection.close()
                finally:
                    self._connection = None
            self._live()
            return True


def initialize_from_environment():
    global _state, _owner, _namespace
    _require_pid()
    with _LOCK:
        if _state == "started":
            return require_started()
        if _state != "new":
            raise AuthorizerStartupError("registration execution cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            root_raw, root_identity = delivery._read_original(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES)
            bootstrap_raw, bootstrap_identity = delivery._read_original(
                delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
            from serverware import registration_execution_authorizer_bootstrap as bootstrap
            from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES:
                raise AuthorizerStartupError("registration execution bootstrap bounds changed")
            work = _ValidationWork(QueryReadValidationLimits())
            work.charge(input_bytes=len(root_raw))
            root = bootstrap.authorization.production._callback(work,
                lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise AuthorizerStartupError("registration execution root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["peerUid"], launch["peerGid"], launch["rootPublicKeyFd"], launch["bootstrapFd"],
                    launch["listenerFd"], launch["signingKeyFd"], launch["listenerPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS,
                        delivery.LISTENER_PATH)
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise AuthorizerStartupError("registration execution launch differs from fixed delivery")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            if delivery._listener(delivery.LISTENER_FD) != listener_pins:
                raise AuthorizerStartupError("registration execution listener differs from signed identities")
            raw_key, key_identity = delivery._read_original(delivery.KEY_FD, delivery.MAX_KEY_BYTES, private=True)
            if not raw_key.startswith(b"-----BEGIN PRIVATE KEY-----\n") or not raw_key.endswith(b"-----END PRIVATE KEY-----\n"):
                raise AuthorizerStartupError("registration execution key must be unencrypted PKCS8 PEM")
            work.charge(input_bytes=len(raw_key))
            key = bootstrap.authorization.production._callback(work,
                lambda: serialization.load_pem_private_key(raw_key, password=None))
            del raw_key
            if not isinstance(key, Ed25519PrivateKey):
                raise AuthorizerStartupError("registration execution signing key must be Ed25519")
            bootstrap.grants.keys._pair_on_work(key, material.authorizer_public_key, work)
            final_sample = bootstrap._fresh(material.attestation_interval, work,
                opening=material.opening_sample)
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            owner = object.__new__(_AuthorizerOwner)
            owner._material, owner._root, owner._key = material, root, key
            owner._listener, owner._listener_pins = listener, listener_pins
            owner._sealed = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False, root_identity),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False, bootstrap_identity),
                (delivery.KEY_FD, delivery.MAX_KEY_BYTES, True, key_identity))
            owner._opening, owner._interval = material.opening_sample, material.attestation_interval
            owner._deadline = owner._opening[0] + owner._interval[1] - owner._opening[1]
            owner._last_epoch, owner._last_monotonic = final_sample[1], final_sample[2]
            owner._closed, owner._failed, owner._connection = False, False, None
            _owner, _state = owner, "started"
            owner._live()
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            if listener is not None:
                listener.close()
            if isinstance(exc, AuthorizerStartupError):
                raise
            raise AuthorizerStartupError("registration execution cold admission failed") from exc


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _AuthorizerOwner:
            raise AuthorizerStartupError("registration execution owner has not started")
        _owner._live()
        return _owner


def close():
    """Drop key references and close only this PID's privately duplicated listener."""
    global _owner, _state
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise AuthorizerStartupError("cannot close an active registration execution connection")
        _owner, _state = None, "closed"
        if owner is not None:
            owner._closed, owner._failed = True, True
            owner._key = owner._root = owner._material = None
            owner._listener.close()
