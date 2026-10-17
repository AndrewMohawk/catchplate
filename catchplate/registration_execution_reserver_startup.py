"""Cold, finite-lifetime registration reserve owner with original-only recovery.

Independent root delivery fixes the configuration, computation key, listener,
separate reservation journal/checkpoint and one state predecessor/fence. New
originals undergo genuine authorization/grant/plan replay before signing. The
actual journal retains the reserve before the state exchange and its verified
acknowledgment before response. Neither an acknowledgment nor recovered history
advances the admitted predecessor or authorizes SQL or credential finalization.

An exact retained grant-bundle identity can recover its original reservation,
without signing a replacement or renewing any operation. An uncertain exchange
never causes automatic retry. This trusted-host-local owner provisions nothing;
independent custody, path access and a hard syscall watchdog remain external.
"""
from __future__ import annotations

import os
import select
import socket
import threading
import time

from catchplate import registration_execution_reserver_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None


class ReserverStartupError(RuntimeError):
    """Terminal cold/lifecycle failure; this process cannot restart admission."""


class ReserverRequestError(RuntimeError):
    """Request failed; local durability or state acceptance may have occurred."""


def _require_pid():
    if os.getpid() != _PID:
        raise ReserverStartupError("forked process cannot use the registration reserver")


def _environment():
    return os.environ.get("CATCHPLATE_PROCESS_MODE", ""), tuple(sorted(
        (name, value) for name, value in os.environ.items() if name.startswith(delivery.PREFIX)))


def _process(namespace):
    expected = (delivery.PROCESS_MODE, tuple(sorted(((delivery.ROOT_ENV, str(delivery.ROOT_FD)),
        (delivery.BOOTSTRAP_ENV, str(delivery.BOOTSTRAP_FD))))))
    if (namespace != expected or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise ReserverStartupError("registration reserver process or namespace differs")
    delivery.delivery._require_unprivileged_process()


class _ReserverOwner:
    __slots__ = ("_material", "_root", "_key", "_listener", "_listener_pins", "_sealed",
        "_journal", "_journal_fd", "_journal_pins", "_reservation", "_client", "_client_config",
        "_opening", "_interval", "_deadline", "_last_epoch", "_last_monotonic",
        "_closed", "_failed", "_connection")

    def __init__(self):
        raise ReserverStartupError("registration reserver requires genuine cold admission")

    def _live(self):
        global _state
        _require_pid()
        try:
            if (self is not _owner or _state != "started" or self._closed or self._failed
                    or _environment() != _namespace):
                raise ReserverStartupError("registration reserver lifetime or singleton changed")
            _process(_namespace)
            for descriptor, maximum, private, original in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != original:
                    raise ReserverStartupError("registration reserver sealed custody changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins):
                raise ReserverStartupError("registration reserver listener or journal binding changed")
            from catchplate import authority_current_root_journal as storage
            from catchplate import authority_current_root_transport as state_transport
            from catchplate import authority_registration_reservation_delivery as reservations

            if (type(self._journal) is not storage.CurrentRootJournal
                    or self._journal._directory_fd != self._journal_fd
                    or type(self._reservation) is not reservations.RegistrationReservationDelivery
                    or self._reservation._journal is not self._journal
                    or self._reservation._root_public_key is not self._root
                    or self._reservation._enrollment_bytes is not self._material.current_root_enrollment_bytes
                    or state_transport.CurrentRootDecisionClient._snapshot_configuration(self._client)
                        != self._client_config):
                raise ReserverStartupError("registration reserver actual owner configuration changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(), self._journal_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            # Genuine journal continuity includes poison and bounded inventory
            # checks. This observation never supplies an independent checkpoint.
            reservations.RegistrationReservationDelivery.inspect(self._reservation)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_before, opened_epoch, opened_after = self._opening
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < self._interval[1] or after >= self._deadline
                    or not opened_epoch + before - opened_after <= epoch
                        <= opened_epoch + after - opened_before):
                raise ReserverStartupError("registration reserver original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, ReserverStartupError):
                raise
            raise ReserverStartupError("registration reserver lifecycle admission failed") from exc

    def _reserve_on_work(self, originals, *, deadline, work):
        from catchplate import authority_registration_execution_reservation as producer
        from catchplate import authority_registration_reservation_delivery as reservations
        from catchplate import control_plane_registration_execution_records as grant_records

        material = self._material
        # Charge the existing codec's complete bounded content hash before its
        # native callback. This ID is a local association, not grant admission
        # or proof that the caller durably stored anything.
        work.charge(hashes=1, input_bytes=sum(len(raw) for raw in originals)
            + grant_records._MAX_HEADER_BYTES + len(grant_records.IDENTITY_DOMAIN) + 10)
        locator, encoded = producer.evidence.production._callback(work, lambda: grant_records.encode(originals))
        del encoded
        self._live()
        sequence, head, fence = material.state_predecessor
        retained = reservations.RegistrationReservationDelivery._original_for_execution_on_work(
            self._reservation, locator, expected_predecessor_sequence=sequence,
            expected_predecessor_head_digest=head, expected_fence=fence, work=work)
        window = producer.clock._open_on_work(deadline_epoch_ns=material.attestation_interval[1],
            maximum_lifetime_ns=material.launch["requestTimeoutSeconds"] * 1_000_000_000,
            maximum_clock_skew_ns=0, work=work)
        if retained is None:
            produced = producer._produce_on_configuration(payload=material.configuration_payload,
                configuration_digest=material.configuration_digest, generation=material.generation,
                runtime_role_identities=material.runtime_role_identities,
                authorization_bytes=originals[0], request_originals=originals[1:4],
                response_originals=originals[4:8], before_vector_bytes=originals[8], grant_bytes=originals[9],
                authorization_enrollment_bytes=material.authorization_enrollment_bytes,
                current_root_enrollment_bytes=material.current_root_enrollment_bytes,
                grant_enrollment_bytes=material.grant_enrollment_bytes,
                root_public_key=self._root, computation_private_key=self._key,
                predecessor_sequence=sequence, predecessor_head_digest=head, fence=fence,
                deadline_epoch_ns=window[3], transport_deadline_ns=deadline, work=work)
            self._live()
            identity = reservations.RegistrationReservationDelivery.enqueue(self._reservation,
                produced.request_bytes, snapshot_bytes=produced.snapshot_bytes,
                execution_record_digest=locator, expected_predecessor_sequence=sequence,
                expected_predecessor_head_digest=head, expected_fence=fence,
                live_window=window, transport_deadline_ns=deadline, work=work)
        else:
            # Historical retrieval reuses the exact retained reserve. Its
            # original expiration still controls any new state acceptance.
            identity = producer.grants.authorization.plan._frame(
                producer.grants.authorization.REQUEST_IDENTITY_DOMAIN, (retained.request_bytes,), work)
        self._live()
        receipt = reservations.RegistrationReservationDelivery.deliver(self._reservation, identity,
            client=self._client, live_window=window, transport_deadline_ns=deadline, work=work)
        retained = reservations.RegistrationReservationDelivery.originals(self._reservation, identity)
        self._live()
        if type(retained.receipt_bytes) is not bytes or type(receipt) is not bytes:
            raise ReserverStartupError("registration reserve lacks a durable acknowledgment")
        work.charge(input_bytes=len(retained.receipt_bytes) + len(receipt))
        if retained.receipt_bytes != receipt:
            raise ReserverStartupError("registration reserve response differs from durable acknowledgment")
        return retained.request_bytes, retained.snapshot_bytes, retained.receipt_bytes

    def _serve_connection(self, connection):
        from catchplate import authority_registration_reservation_transport as transport
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        deadline = min(self._deadline, transport._deadline_ns(self._material.launch["requestTimeoutSeconds"]))
        self._live()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, deadline,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise ReserverRequestError("registration reserver caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=deadline)
        # Every length and exact EOF precedes this sole per-request allowance.
        work = _ValidationWork(QueryReadValidationLimits())
        self._live()
        response = self._reserve_on_work(originals, deadline=deadline, work=work)
        self._live()
        transport._check_deadline(deadline)
        transport._send_response(connection, response, deadline_ns=deadline)
        self._live()
        transport._check_deadline(deadline)

    def serve_once(self):
        """At most one serial exchange; idle waits cannot renew the launch."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._connection is not None:
                raise ReserverStartupError("registration reserver already has an active connection")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                self._live()
                raise ReserverStartupError("registration reserver original lifetime expired")
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
            except ReserverStartupError:
                self._failed = True
                raise
            except Exception as exc:
                self._live()  # Poison or lifetime failure is terminal, not denial.
                raise ReserverRequestError("registration reserve failed; outcome remains uncertain") from exc
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
            raise ReserverStartupError("registration reserver cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = journal = reservation = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            root_raw, root_identity = delivery._read_original(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES)
            bootstrap_raw, bootstrap_identity = delivery._read_original(
                delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
            from catchplate import registration_execution_reserver_bootstrap as bootstrap
            from catchplate import authority_current_root_journal as storage
            from catchplate import authority_current_root_transport as state_transport
            from catchplate import authority_registration_reservation_delivery as reservations
            from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES:
                raise ReserverStartupError("registration reserver bootstrap bounds changed")
            work = _ValidationWork(QueryReadValidationLimits())
            work.charge(input_bytes=len(root_raw))
            root = bootstrap.authorization.production._callback(work,
                lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise ReserverStartupError("registration reserver root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["peerUid"], launch["peerGid"], launch["rootPublicKeyFd"], launch["bootstrapFd"],
                    launch["listenerFd"], launch["signingKeyFd"], launch["journalDirectoryFd"], launch["listenerPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS, delivery.LISTENER_PATH)
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise ReserverStartupError("registration reserver launch differs from fixed delivery")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins):
                raise ReserverStartupError("registration reserver resources differ from signed identities")
            raw_key, key_identity = delivery._read_original(delivery.KEY_FD, delivery.MAX_KEY_BYTES, private=True)
            if not raw_key.startswith(b"-----BEGIN PRIVATE KEY-----\n") or not raw_key.endswith(b"-----END PRIVATE KEY-----\n"):
                raise ReserverStartupError("registration computation key must be unencrypted PKCS8 PEM")
            work.charge(input_bytes=len(raw_key))
            key = bootstrap.authorization.production._callback(work,
                lambda: serialization.load_pem_private_key(raw_key, password=None))
            del raw_key
            if not isinstance(key, Ed25519PrivateKey):
                raise ReserverStartupError("registration computation key must be Ed25519")
            bootstrap.grants.keys._pair_on_work(key, material.computation_public_key, work)
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            journal = storage.CurrentRootJournal(directory_fd=delivery.JOURNAL_FD,
                expected_device=journal_pins[0], expected_inode=journal_pins[1],
                expected_uid=delivery.SERVICE_UID, expected_gid=delivery.SERVICE_GID,
                maximum_records=launch["journalMaximumRecords"])
            reservation = reservations.RegistrationReservationDelivery(journal=journal,
                enrollment_bytes=material.current_root_enrollment_bytes, root_public_key=root,
                expected_local_sequence=material.reservation_checkpoint[0],
                expected_local_head_digest=material.reservation_checkpoint[1])
            path, timeout, uid, gid = material.state_endpoint
            client = state_transport.CurrentRootDecisionClient(path=path, timeout_seconds=timeout,
                expected_peer_uid=uid, expected_peer_gid=gid)
            final_sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            owner = object.__new__(_ReserverOwner)
            owner._material, owner._root, owner._key = material, root, key
            owner._listener, owner._listener_pins = listener, listener_pins
            owner._journal, owner._journal_fd, owner._journal_pins = journal, journal._directory_fd, journal_pins
            owner._reservation, owner._client = reservation, client
            owner._client_config = state_transport.CurrentRootDecisionClient._snapshot_configuration(client)
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
            for resource in (reservation if reservation is not None else journal, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            if isinstance(exc, ReserverStartupError):
                raise
            raise ReserverStartupError("registration reserver cold admission failed") from exc


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _ReserverOwner:
            raise ReserverStartupError("registration reserver has not started")
        _owner._live()
        return _owner


def close():
    """Close owned journal/listener handles; leave inherited descriptors borrowed."""
    global _owner, _state
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise ReserverStartupError("cannot close an active registration reserve connection")
        _owner, _state = None, "closed"
        if owner is not None:
            owner._closed, owner._failed = True, True
            owner._key = owner._root = owner._material = None
            try:
                owner._reservation.close()
            finally:
                owner._listener.close()
