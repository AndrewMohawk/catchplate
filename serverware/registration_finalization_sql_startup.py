"""One cold finalization SQL exchange under independent root-admitted scope.

The fixed worker has no signing key, completion authority or public route. It
retains actual issuer/executor TLS owners and an independently current protected
attempt journal. One accepted connection ends the launch; a valid raw13 spends
the in-process request before actual original-input composition. No uncertain
issuance, execution or response permits automatic retry.

The sole request work/window opens before peer/frame/body reads and is retained
through admission, SQL and response. TLS originals are hashed at cold admission
then checked for protected pathname/metadata continuity. These local checks are
not hostile-root protection, an action-time off-host witness or a hard syscall
watchdog. An unsigned commit observation is not completion or session activation.
"""
from __future__ import annotations

import os
import select
import socket
import threading
import time

from serverware import registration_finalization_sql_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None


class SqlStartupError(RuntimeError):
    """Terminal cold/lifecycle failure; this process cannot restart admission."""


class SqlRequestError(RuntimeError):
    """Terminal exchange failure; a protected SQL effect may already be durable."""


def _require_pid():
    if os.getpid() != _PID:
        raise SqlStartupError("forked process cannot use the finalization SQL owner")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    # No ambient libpq, HOME, service file or password setting may amend the
    # independently admitted source-generated database connections.
    expected = tuple(sorted({"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
        "SERVERWARE_PROCESS_MODE": delivery.PROCESS_MODE,
        delivery.ROOT_ENV: str(delivery.ROOT_FD), delivery.BOOTSTRAP_ENV: str(delivery.BOOTSTRAP_FD)}.items()))
    if (namespace != expected or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise SqlStartupError("finalization SQL process or environment differs")
    delivery.delivery._require_unprivileged_process()


def _owner_arguments(configured):
    dsn, timeout, _role, client_dn, client_serial, issuer_dn, query, structure = configured
    return {"dsn": dsn, "connect_timeout_seconds": timeout, "tls_client_dn": client_dn,
        "tls_client_serial": client_serial, "tls_issuer_dn": issuer_dn,
        "query_manifest_digest": query, "expected_structure_manifest_digest": structure}


class _SqlOwner:
    __slots__ = ("_material", "_root", "_listener", "_listener_pins", "_sealed", "_tls",
        "_journal", "_journal_fd", "_journal_pins", "_attempts", "_issuer", "_executor",
        "_issuer_configuration", "_executor_configuration", "_opening", "_interval", "_deadline",
        "_last_epoch", "_last_monotonic", "_closed", "_failed", "_spent", "_connection")

    def __init__(self):
        raise SqlStartupError("finalization SQL requires genuine cold admission")

    def _live(self):
        global _state
        _require_pid()
        try:
            if (self is not _owner or _state != "started" or self._closed or self._failed
                    or _environment() != _namespace):
                raise SqlStartupError("finalization SQL lifetime or singleton changed")
            _process(_namespace)
            for descriptor, maximum, original in self._sealed:
                if delivery._sealed_identity(descriptor, maximum) != original:
                    raise SqlStartupError("finalization SQL sealed custody changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins):
                raise SqlStartupError("finalization SQL listener or journal binding changed")
            delivery._tls_unchanged(self._tls)
            from serverware import authority_current_root_journal as storage
            from serverware import authority_successor_execution_attempts as attempts
            from serverware import authority_successor_execution_owner as owners

            if (type(self._journal) is not storage.CurrentRootJournal
                    or self._journal._directory_fd != self._journal_fd
                    or type(self._attempts) is not attempts.SuccessorExecutionAttempts
                    or self._attempts._journal is not self._journal
                    or type(self._issuer) is not owners.SuccessorExecutionIssuer
                    or type(self._executor) is not owners.SuccessorExecutionExecutor
                    or self._executor._attempts is not self._attempts
                    or owners.SuccessorExecutionIssuer._snapshot_configuration(self._issuer)
                        != self._issuer_configuration
                    or owners.SuccessorExecutionExecutor._snapshot_configuration(self._executor)
                        != self._executor_configuration):
                raise SqlStartupError("finalization SQL actual owner configuration changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(), self._journal_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            attempts.SuccessorExecutionAttempts.inspect(self._attempts)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_before, opened_epoch, opened_after = self._opening
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < self._interval[1] or after >= self._deadline
                    or not opened_epoch + before - opened_after <= epoch
                        <= opened_epoch + after - opened_before):
                raise SqlStartupError("finalization SQL original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, SqlStartupError):
                raise
            raise SqlStartupError("finalization SQL lifecycle admission failed") from exc

    def _execute_on_work(self, originals, *, live_window, deadline, work):
        from serverware import authority_registration_finalization_sql as execution

        material = self._material
        sequence, head, fence = material.current_pending
        # This is the exact pre-read window and work, never a replacement
        # allowance or clock opening after an expensive frame/body read.
        try:
            observed = execution._execute_on_configuration(payload=material.configuration_payload,
                configuration_digest=material.configuration_digest, generation=material.generation,
                runtime_role_identities=material.runtime_role_identities,
                originals=originals[:10], reservation_originals=originals[10:],
                authorization_enrollment_bytes=material.authorization_enrollment_bytes,
                grant_enrollment_bytes=material.grant_enrollment_bytes,
                current_root_enrollment_bytes=material.current_root_enrollment_bytes,
                root_public_key=self._root, expected_pending_sequence=sequence,
                expected_pending_head_digest=head, expected_fence=fence,
                live_window=live_window, transport_deadline_ns=deadline, work=work,
                issuer=self._issuer, executor=self._executor)
        except execution.RegistrationFinalizationSqlOutcomeError as exc:
            return (b"uncertain", exc.pending_decision_digest.encode("ascii"),
                exc.packet_digest.encode("ascii"), b"")
        except Exception:
            # An ordinary failure may follow durable custody/SQL. No exception
            # text, manufactured IDs, noncommit or retry assertion is returned.
            return b"uncertain", b"", b"", b""
        if type(observed) is not execution.owners.SuccessorExecutionObservation:
            raise SqlRequestError("finalization SQL returned no actual observation")
        return (b"observed-commit", observed.pending_decision_digest.encode("ascii"),
            observed.packet_digest.encode("ascii"), observed.marker_bytes)

    def _serve_connection(self, connection):
        from serverware import authority_registration_finalization_sql as execution
        from serverware import authority_registration_finalization_sql_transport as transport
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        self._live()
        work = _ValidationWork(QueryReadValidationLimits())
        window = execution.clock._open_on_work(deadline_epoch_ns=self._interval[1],
            maximum_lifetime_ns=self._material.launch["requestTimeoutSeconds"] * 1_000_000_000,
            maximum_clock_skew_ns=0, work=work)
        deadline = min(self._deadline, window[4])
        transport._check_deadline(deadline)
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, deadline,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise SqlRequestError("finalization SQL caller peer differs")
        # The actual peer is admitted before any prefix/body; all reads and
        # subsequent admission share this original window and deadline.
        originals = transport._recv_request(connection, deadline_ns=deadline)
        execution.clock._check_on_work(window, work=work)
        self._live()
        if self._spent:
            raise SqlStartupError("finalization SQL cold request was already spent")
        self._spent = True
        response = self._execute_on_work(originals, live_window=window, deadline=deadline, work=work)
        self._live()
        execution.clock._check_on_work(window, work=work)
        transport._check_deadline(deadline)
        transport._send_response(connection, response, deadline_ns=deadline)
        self._live()
        execution.clock._check_on_work(window, work=work)
        transport._check_deadline(deadline)

    def serve_once(self):
        """Wait briefly, or handle one accepted connection and never reenter."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._spent or self._connection is not None:
                raise SqlStartupError("finalization SQL cold exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                self._live()
                raise SqlStartupError("finalization SQL original lifetime expired")
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
                # Malformed and unauthorized accepted connections terminate
                # this cold launch too; cancellation is not an uncertain DTO.
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
            raise SqlStartupError("finalization SQL cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = journal = attempt_owner = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            root_raw, root_identity = delivery._read_original(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES)
            bootstrap_raw, bootstrap_identity = delivery._read_original(
                delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from serverware import registration_finalization_sql_bootstrap as bootstrap
            from serverware import authority_current_root_journal as storage
            from serverware import authority_successor_execution_attempts as attempts
            from serverware import authority_successor_execution_owner as owners
            from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES:
                raise SqlStartupError("finalization SQL bootstrap bounds changed")
            work = _ValidationWork(QueryReadValidationLimits())
            work.charge(input_bytes=len(root_raw))
            root = bootstrap.authorization.production._callback(work,
                lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise SqlStartupError("finalization SQL root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["peerUid"], launch["peerGid"], launch["rootPublicKeyFd"], launch["bootstrapFd"],
                    launch["listenerFd"], launch["journalDirectoryFd"], launch["listenerPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS, delivery.LISTENER_PATH)
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise SqlStartupError("finalization SQL launch differs from fixed delivery")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins):
                raise SqlStartupError("finalization SQL resources differ from signed identities")
            tls_identity = delivery._tls_identity(material.tls_files)
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            journal = storage.CurrentRootJournal(directory_fd=delivery.JOURNAL_FD,
                expected_device=journal_pins[0], expected_inode=journal_pins[1],
                expected_uid=delivery.SERVICE_UID, expected_gid=delivery.SERVICE_GID,
                maximum_records=launch["journalMaximumRecords"])
            attempt_owner = attempts.SuccessorExecutionAttempts(journal=journal,
                expected_structure_manifest_digest=material.issuer_configuration[7],
                expected_local_sequence=material.attempt_checkpoint[0],
                expected_local_head_digest=material.attempt_checkpoint[1])
            issuer = owners.SuccessorExecutionIssuer(**_owner_arguments(material.issuer_configuration))
            executor = owners.SuccessorExecutionExecutor(**_owner_arguments(material.executor_configuration),
                attempt_owner=attempt_owner)
            final_sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            owner = object.__new__(_SqlOwner)
            owner._material, owner._root = material, root
            owner._listener, owner._listener_pins = listener, listener_pins
            owner._journal, owner._journal_fd, owner._journal_pins = journal, journal._directory_fd, journal_pins
            owner._attempts, owner._issuer, owner._executor = attempt_owner, issuer, executor
            owner._issuer_configuration, owner._executor_configuration = material.issuer_configuration, material.executor_configuration
            owner._tls = tls_identity
            owner._sealed = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, root_identity),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, bootstrap_identity))
            owner._opening, owner._interval = material.opening_sample, material.attestation_interval
            owner._deadline = owner._opening[0] + owner._interval[1] - owner._opening[1]
            owner._last_epoch, owner._last_monotonic = final_sample[1], final_sample[2]
            owner._closed, owner._failed, owner._spent, owner._connection = False, False, False, None
            _owner, _state = owner, "started"
            owner._live()
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            for resource in (attempt_owner if attempt_owner is not None else journal, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            if isinstance(exc, SqlStartupError):
                raise
            raise SqlStartupError("finalization SQL cold admission failed") from exc


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _SqlOwner:
            raise SqlStartupError("finalization SQL has not started")
        _owner._live()
        return _owner


def close():
    """Close owned journal/listener handles; inherited descriptors are borrowed."""
    global _owner, _state
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise SqlStartupError("cannot close an active finalization SQL connection")
        _owner, _state = None, "closed"
        if owner is not None:
            owner._closed, owner._failed = True, True
            owner._root = owner._material = owner._issuer = owner._executor = None
            try:
                owner._attempts.close()
            finally:
                owner._listener.close()
