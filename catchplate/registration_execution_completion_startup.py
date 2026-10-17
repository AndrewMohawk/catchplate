"""Cold, single-connection completion recovery under separate key custody.

The root-signed launch supplies historical expectations, original enrollments,
one packet/authorization/pending scope, protected reader configuration and an
independently current completion-journal checkpoint. No request can choose a
key, database, historical context or different pending decision. Genuine packet
replay and committed-state readback remain inside the actual completion owner.

Existing completions are reused unchanged; no execution, replacement signature,
expiry renewal or credential finalization occurs here. Original completion and
state acknowledgment are durable before a successful response. An uncertain
response grants no retry permission or inference that no effect occurred.
Cold/path/TLS continuity remains trusted-host-local, not native attestation,
independent action-time currentness, hostile-root protection or a hard watchdog.
"""
from __future__ import annotations

import os
import select
import socket
import threading
import time

from catchplate import registration_execution_completion_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None
OPERATION = "webauthn.registration.evidence.admit"


class CompletionStartupError(RuntimeError):
    """Terminal cold/lifecycle failure; this process cannot renew admission."""


class CompletionRequestError(RuntimeError):
    """Terminal exchange failure; completion or acknowledgment may be durable."""


def _require_pid():
    if os.getpid() != _PID:
        raise CompletionStartupError("forked process cannot use registration completion")


def _environment():
    # Every name is part of cold admission, including absence of ambient
    # libpq/HOME/service/password variables and alternate runtime settings.
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    expected = tuple(sorted({"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
        "CATCHPLATE_PROCESS_MODE": delivery.PROCESS_MODE,
        delivery.ROOT_ENV: str(delivery.ROOT_FD), delivery.BOOTSTRAP_ENV: str(delivery.BOOTSTRAP_FD)}.items()))
    if (namespace != expected or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise CompletionStartupError("registration completion process or environment differs")
    delivery.delivery._require_unprivileged_process()


def _reader_arguments(configured):
    dsn, timeout, role, client_dn, client_serial, issuer_dn, query, structure = configured
    return {"dsn": dsn, "connect_timeout_seconds": timeout, "database_role": role,
        "tls_client_dn": client_dn, "tls_client_serial": client_serial,
        "tls_issuer_dn": issuer_dn, "query_manifest_digest": query,
        "expected_structure_manifest_digest": structure}


class _CompletionOwner:
    __slots__ = ("_material", "_root", "_key", "_listener", "_listener_pins", "_sealed", "_tls",
        "_journal", "_journal_fd", "_journal_pins", "_delivery", "_custody_reader", "_commit_reader",
        "_custody_configuration", "_commit_configuration", "_client", "_client_configuration",
        "_opening", "_interval", "_deadline", "_last_epoch", "_last_monotonic",
        "_closed", "_failed", "_spent", "_connection")

    def __init__(self):
        raise CompletionStartupError("registration completion requires genuine cold admission")

    def _live(self):
        global _state
        _require_pid()
        try:
            if (self is not _owner or _state != "started" or self._closed or self._failed
                    or _environment() != _namespace):
                raise CompletionStartupError("registration completion lifetime or singleton changed")
            _process(_namespace)
            for descriptor, maximum, private, original in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != original:
                    raise CompletionStartupError("registration completion sealed custody changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins):
                raise CompletionStartupError("registration completion listener or journal binding changed")
            delivery._tls_unchanged(self._tls)
            from catchplate import authority_current_root_journal as storage
            from catchplate import authority_current_root_delivery as retained
            from catchplate import authority_current_root_commit_reader as committed
            from catchplate import authority_current_root_transport as state_transport
            from catchplate import authority_successor_execution_owner as custody

            if (type(self._journal) is not storage.CurrentRootJournal
                    or self._journal._directory_fd != self._journal_fd
                    or type(self._delivery) is not retained.CurrentRootCompletionDelivery
                    or self._delivery._journal is not self._journal
                    or self._delivery._root_public_key is not self._root
                    or self._delivery._enrollment_bytes is not self._material.current_root_enrollment_bytes
                    or custody.SuccessorExecutionRecoveryReader._snapshot_configuration(self._custody_reader)
                        != self._custody_configuration
                    or committed.CurrentRootCommitReader._snapshot_configuration(self._commit_reader)
                        != self._commit_configuration
                    or state_transport.CurrentRootDecisionClient._snapshot_configuration(self._client)
                        != self._client_configuration):
                raise CompletionStartupError("registration completion actual owner configuration changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(), self._journal_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            retained.CurrentRootCompletionDelivery.inspect(self._delivery)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_before, opened_epoch, opened_after = self._opening
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < self._interval[1] or after >= self._deadline
                    or not opened_epoch + before - opened_after <= epoch
                        <= opened_epoch + after - opened_before):
                raise CompletionStartupError("registration completion original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, CompletionStartupError):
                raise
            raise CompletionStartupError("registration completion lifecycle admission failed") from exc

    def _recover_on_work(self, originals, *, deadline, work):
        from catchplate import authority_successor_completion_recovery as recovery

        material = self._material
        work.charge(input_bytes=len(originals[1]) + len(material.packet_digest))
        if originals[1] != material.packet_digest.encode("ascii"):
            raise CompletionRequestError("registration completion packet differs from its cold pin")
        sequence, head, fence = material.current_pending
        window = recovery.clock._open_on_work(deadline_epoch_ns=material.attestation_interval[1],
            maximum_lifetime_ns=material.launch["requestTimeoutSeconds"] * 1_000_000_000,
            maximum_clock_skew_ns=0, work=work)
        bound = min(deadline, window[4])
        try:
            result = recovery.recover_and_deliver(custody_reader=self._custody_reader,
                commit_reader=self._commit_reader, delivery=self._delivery, client=self._client,
                operation=OPERATION, packet_digest=material.packet_digest,
                expectations=material.expectations, planner_public_key=material.planner_public_key,
                operation_public_key=material.evidence_public_key, root_public_key=self._root,
                completion_private_key=self._key, expected_authorization_digest=material.authorization_digest,
                expected_database_id=material.database_id, expected_generation_digest=material.generation_digest,
                expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
                deadline_epoch_ns=window[3], work=work, transport_deadline_ns=bound)
            if type(result) is not recovery.SuccessorCompletionRecoveryResult:
                raise CompletionRequestError("registration completion returned no actual recovery result")
            # Read only this actual owner's same-pending durable original, not
            # an incoming result carrier or a newly signed replacement.
            original = recovery.delivery_store.CurrentRootCompletionDelivery._original_for_pending_on_work(
                self._delivery, expected_pending_sequence=sequence,
                expected_pending_head_digest=head, work=work)
            if type(original) is not tuple or len(original) != 2:
                raise CompletionRequestError("registration completion lacks its retained original")
            identity, request = original
            recovery.authorization.plan._same(identity, result.request_digest, work,
                "registration completion outcome differs from its retained original")
            return b"acknowledged", identity.encode("ascii"), request, result.receipt_bytes
        except Exception:
            # Signing, retention and state acceptance may already have happened.
            # Never serialize exception text, an invented receipt or a claim
            # that cancellation rolled anything back. BaseException propagates.
            return b"uncertain", b"", b"", b""

    def _serve_connection(self, connection):
        from catchplate import authority_registration_completion_transport as transport
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        deadline = min(self._deadline, transport._deadline_ns(self._material.launch["requestTimeoutSeconds"]))
        self._live()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, deadline,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise CompletionRequestError("registration completion caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=deadline)
        work = _ValidationWork(QueryReadValidationLimits())
        self._live()
        if self._spent:
            raise CompletionStartupError("registration completion cold request was already spent")
        self._spent = True
        response = self._recover_on_work(originals, deadline=deadline, work=work)
        self._live()
        transport._check_deadline(deadline)
        transport._send_response(connection, response, deadline_ns=deadline)
        self._live()
        transport._check_deadline(deadline)

    def serve_once(self):
        """Wait briefly, or handle one accepted connection and never reenter."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._spent or self._connection is not None:
                raise CompletionStartupError("registration completion cold exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                self._live()
                raise CompletionStartupError("registration completion original lifetime expired")
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
            except BaseException:
                self._failed = True
                raise
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
            raise CompletionStartupError("registration completion cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = journal = completion_delivery = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            root_raw, root_identity = delivery._read_original(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES)
            bootstrap_raw, bootstrap_identity = delivery._read_original(
                delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
            from catchplate import registration_execution_completion_bootstrap as bootstrap
            from catchplate import authority_current_root_journal as storage
            from catchplate import authority_current_root_delivery as retained
            from catchplate import authority_current_root_commit_reader as committed
            from catchplate import authority_current_root_transport as state_transport
            from catchplate import authority_successor_execution_owner as custody
            from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES:
                raise CompletionStartupError("registration completion bootstrap bounds changed")
            work = _ValidationWork(QueryReadValidationLimits())
            work.charge(input_bytes=len(root_raw))
            root = bootstrap.authorization.production._callback(work,
                lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise CompletionStartupError("registration completion root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["peerUid"], launch["peerGid"], launch["rootPublicKeyFd"], launch["bootstrapFd"],
                    launch["listenerFd"], launch["signingKeyFd"], launch["journalDirectoryFd"], launch["listenerPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS, delivery.LISTENER_PATH)
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise CompletionStartupError("registration completion launch differs from fixed delivery")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins):
                raise CompletionStartupError("registration completion resources differ from signed identities")
            raw_key, key_identity = delivery._read_original(delivery.KEY_FD, delivery.MAX_KEY_BYTES, private=True)
            if not raw_key.startswith(b"-----BEGIN PRIVATE KEY-----\n") or not raw_key.endswith(b"-----END PRIVATE KEY-----\n"):
                raise CompletionStartupError("registration completion key must be unencrypted PKCS8 PEM")
            work.charge(input_bytes=len(raw_key))
            key = bootstrap.authorization.production._callback(work,
                lambda: serialization.load_pem_private_key(raw_key, password=None))
            del raw_key
            if not isinstance(key, Ed25519PrivateKey):
                raise CompletionStartupError("registration completion key must be Ed25519")
            bootstrap.grants.keys._pair_on_work(key, material.completion_public_key, work)
            tls_identity = delivery._tls_identity(material.tls_files)
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            journal = storage.CurrentRootJournal(directory_fd=delivery.JOURNAL_FD,
                expected_device=journal_pins[0], expected_inode=journal_pins[1],
                expected_uid=delivery.SERVICE_UID, expected_gid=delivery.SERVICE_GID,
                maximum_records=launch["journalMaximumRecords"])
            completion_delivery = retained.CurrentRootCompletionDelivery(journal=journal,
                enrollment_bytes=material.current_root_enrollment_bytes, root_public_key=root,
                expected_local_sequence=material.completion_checkpoint[0],
                expected_local_head_digest=material.completion_checkpoint[1])
            custody_arguments = _reader_arguments(material.custody_configuration)
            del custody_arguments["database_role"]  # Actual custody constructor fixes its role.
            custody_reader = custody.SuccessorExecutionRecoveryReader(**custody_arguments)
            commit_reader = committed.CurrentRootCommitReader(**_reader_arguments(material.commit_configuration))
            path, timeout, uid, gid = material.state_endpoint
            client = state_transport.CurrentRootDecisionClient(path=path, timeout_seconds=timeout,
                expected_peer_uid=uid, expected_peer_gid=gid)
            final_sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            owner = object.__new__(_CompletionOwner)
            owner._material, owner._root, owner._key = material, root, key
            owner._listener, owner._listener_pins = listener, listener_pins
            owner._journal, owner._journal_fd, owner._journal_pins = journal, journal._directory_fd, journal_pins
            owner._delivery, owner._custody_reader, owner._commit_reader = completion_delivery, custody_reader, commit_reader
            owner._custody_configuration, owner._commit_configuration = material.custody_configuration, material.commit_configuration
            owner._client, owner._client_configuration = client, state_transport.CurrentRootDecisionClient._snapshot_configuration(client)
            owner._tls = tls_identity
            owner._sealed = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False, root_identity),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False, bootstrap_identity),
                (delivery.KEY_FD, delivery.MAX_KEY_BYTES, True, key_identity))
            owner._opening, owner._interval = material.opening_sample, material.attestation_interval
            owner._deadline = owner._opening[0] + owner._interval[1] - owner._opening[1]
            owner._last_epoch, owner._last_monotonic = final_sample[1], final_sample[2]
            owner._closed, owner._failed, owner._spent, owner._connection = False, False, False, None
            _owner, _state = owner, "started"
            owner._live()
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            for resource in (completion_delivery if completion_delivery is not None else journal, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            if isinstance(exc, CompletionStartupError):
                raise
            raise CompletionStartupError("registration completion cold admission failed") from exc


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _CompletionOwner:
            raise CompletionStartupError("registration completion has not started")
        _owner._live()
        return _owner


def close():
    """Close owned journal/listener; inherited descriptors remain borrowed."""
    global _owner, _state
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise CompletionStartupError("cannot close an active registration completion connection")
        _owner, _state = None, "closed"
        if owner is not None:
            owner._closed, owner._failed = True, True
            owner._key = owner._root = owner._material = owner._custody_reader = owner._commit_reader = None
            try:
                owner._delivery.close()
            finally:
                owner._listener.close()
