"""One root-admitted activation SQL exchange under independent pending scope.

The original window/work precedes peer and body intake. Real issuer/executor
owners and an irreversible attempt journal are composed only through genuine
original replay. An unsigned commit observation is not completion, token
release or browser activation. Every accepted connection spends this launch.
"""
from __future__ import annotations

import errno
import os
import select
import socket
import threading
import time

from catchplate import oidc_session_activation_execution_sql_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None
_descriptors_owned = False


class ActivationSqlStartupError(RuntimeError):
    pass


class ActivationSqlRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise ActivationSqlStartupError("forked process cannot use the activation SQL owner")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    if (namespace != tuple(sorted(delivery.ENVIRONMENT.items()))
            or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise ActivationSqlStartupError("activation SQL process or literal environment differs")
    delivery.delivery._require_unprivileged_process()


def _policy(material):
    planner = material.custody_material.planner
    return (min(material.maximum_authorization_age_ns, planner.maximum_plan_age_ns),
        min(material.maximum_authorization_clock_skew_ns, planner.maximum_clock_skew_ns))


def _construction_window(material, clock):
    before, epoch, after = material.opening_sample
    age, skew = _policy(material)
    deadline = min(material.attestation_interval[1], epoch + age)
    return clock._validate((epoch, before, after, deadline, before + deadline - epoch, age, skew))


def _owner_arguments(configured):
    dsn, timeout, _role, client_dn, client_serial, issuer_dn, query, structure = configured
    return {"dsn": dsn, "connect_timeout_seconds": timeout, "tls_client_dn": client_dn,
        "tls_client_serial": client_serial, "tls_issuer_dn": issuer_dn,
        "query_manifest_digest": query, "expected_structure_manifest_digest": structure}


def _expectations(original, work):
    from catchplate import authority_oidc_session_activation_execution_expectations as expected
    from catchplate import authority_current_root_vector as vector

    decoded = vector.wire._decode_object(original, work=work, maximum_bytes=expected.MAX_BYTES,
        maximum_nodes=expected.MAX_NODES, maximum_depth=12)
    owned = expected._capture_on_work(decoded, work=work)
    canonical = vector.encoding._bounded_wire(owned, vector.capture._SharedLedger(work),
        maximum_bytes=expected.MAX_BYTES, maximum_nodes=expected.MAX_NODES)
    work.charge(input_bytes=len(original) + len(canonical))
    if original != canonical:
        raise ActivationSqlRequestError("activation SQL expectations are not canonical originals")
    return owned


def _close_inherited():
    global _descriptors_owned
    if not _descriptors_owned:
        return
    _descriptors_owned = False
    failed = False
    for descriptor in delivery.INHERITED_DESCRIPTORS:
        try:
            os.close(descriptor)
        except OSError as exc:
            failed = failed or exc.errno != errno.EBADF
    if failed:
        raise ActivationSqlStartupError("activation SQL inherited descriptor cleanup is not established")


class _SqlOwner:
    __slots__ = ("_material", "_root", "_custody", "_custody_configuration", "_seal",
        "_listener", "_listener_pins", "_sealed", "_tls", "_journal", "_journal_fd", "_journal_pins",
        "_attempts", "_issuer", "_executor", "_issuer_configuration", "_executor_configuration",
        "_opening", "_interval", "_deadline", "_last_epoch", "_last_monotonic",
        "_closed", "_failed", "_accepted", "_connection")

    def __init__(self):
        raise ActivationSqlStartupError("activation SQL requires genuine cold admission")

    def _live(self):
        global _state
        from catchplate import authority_oidc_session_activation_execution_custody as custody
        from catchplate import authority_current_root_journal as storage
        from catchplate import authority_successor_execution_attempts as attempts
        from catchplate import authority_successor_execution_owner as owners

        _require_pid()
        try:
            if (type(self) is not _SqlOwner or self is not _owner or _state != "started"
                    or self._closed or self._failed or _environment() != _namespace
                    or type(self._seal) is not tuple or len(self._seal) != 7
                    or any(actual is not held for actual, held in zip((self._material, self._root,
                        self._custody, self._journal, self._attempts, self._issuer, self._executor), self._seal))):
                raise ActivationSqlStartupError("activation SQL lifetime or held owners changed")
            _process(_namespace)
            for descriptor, maximum, private, identity in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                    raise ActivationSqlStartupError("activation SQL sealed originals changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins
                    or custody.OidcSessionActivationExecutionCustody._snapshot_configuration(self._custody)
                        is not self._custody_configuration):
                raise ActivationSqlStartupError("activation SQL resource or custody binding changed")
            delivery._tls_unchanged(self._tls)
            if (type(self._journal) is not storage.CurrentRootJournal
                    or self._journal._directory_fd != self._journal_fd
                    or type(self._attempts) is not attempts.SuccessorExecutionAttempts
                    or self._attempts._journal is not self._journal
                    or type(self._issuer) is not owners.SuccessorExecutionIssuer
                    or type(self._executor) is not owners.SuccessorExecutionExecutor
                    or self._executor._attempts is not self._attempts
                    or owners.SuccessorExecutionIssuer._snapshot_configuration(self._issuer) != self._issuer_configuration
                    or owners.SuccessorExecutionExecutor._snapshot_configuration(self._executor) != self._executor_configuration):
                raise ActivationSqlStartupError("activation SQL actual database or attempt owners changed")
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
                raise ActivationSqlStartupError("activation SQL original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, ActivationSqlStartupError) or not isinstance(exc, Exception):
                raise
            raise ActivationSqlStartupError("activation SQL lifecycle admission failed") from None

    def _serve_connection(self, connection):
        from catchplate import oidc_session_activation_execution_sql_bootstrap as bootstrap
        from catchplate import authority_oidc_session_activation_sql as execution
        from catchplate import authority_oidc_session_activation_sql_transport as transport
        from catchplate import authority_successor_execution_window as processing
        from catchplate import authority_webauthn_evidence_plan_clock as clock
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        material = self._material
        work = _ValidationWork(QueryReadValidationLimits())
        age, skew = _policy(material)
        window = clock._open_on_work(deadline_epoch_ns=self._interval[1],
            maximum_lifetime_ns=min(age, material.launch["requestTimeoutSeconds"] * 1_000_000_000),
            maximum_clock_skew_ns=skew, work=work)
        bound = min(self._deadline, window[4])
        last_epoch, last_monotonic = window[0], window[2]
        callback = bootstrap.authorization.production._callback
        execution_live = None

        def current():
            nonlocal last_epoch, last_monotonic
            callback(work, self._live)
            if execution_live is not None:
                last_epoch = max(last_epoch, execution_live())
            now = clock._check_on_work(window, work=work)
            monotonic = callback(work, time.monotonic_ns)
            bootstrap.shape._integer(monotonic, minimum=1)
            if now < last_epoch or now < self._last_epoch or monotonic < last_monotonic or monotonic >= bound:
                raise ActivationSqlRequestError("activation SQL original request clocks expired or reversed")
            last_epoch, last_monotonic = now, monotonic
            return now

        current()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, bound,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise ActivationSqlRequestError("activation SQL caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=bound)
        current()
        expected = _expectations(originals[3], work)
        scope = expected["scope"]
        # Unauthenticated incoming scope only narrows the original clock. The
        # real bridge still verifies every original before protected issuance.
        window = processing._narrow(window, deadline_epoch_ns=scope["deadlineEpochNs"],
            maximum_lifetime_ns=scope["maximumPlanAgeNs"], maximum_clock_skew_ns=scope["maximumClockSkewNs"])
        bound = min(bound, window[4])
        current()
        admitted = bootstrap._verify_on_work(bootstrap_bytes=material.bootstrap_bytes,
            custody_bytes=material.custody_bytes, root_public_key=self._root,
            live_window=window, transport_deadline_ns=bound, work=work)
        bootstrap.plan._same(admitted.attestation_interval, self._interval, work,
            "activation SQL original launch interval changed")
        current()
        predecessor_sequence, predecessor_head, predecessor_fence = admitted.state_predecessor
        pending_sequence, pending_head, pending_fence = admitted.current_pending
        bootstrap.plan._same(predecessor_fence, pending_fence, work,
            "activation SQL independent predecessor and pending fences differ")
        executed = None
        try:
            executed = execution._execute_on_configuration(originals=originals[1:3], expectations=expected,
                before_vector_bytes=admitted.custody_material.planner.complete_root_vector_bytes,
                authorization_bytes=originals[0], grant_bytes=originals[4], response_originals=originals[5:],
                authorization_enrollment_bytes=admitted.authorization_enrollment_bytes,
                grant_enrollment_bytes=admitted.grant_enrollment_bytes,
                current_root_enrollment_bytes=admitted.current_root_enrollment_bytes,
                root_public_key=self._root, planner_public_key=admitted.planner_public_key,
                operation_public_key=admitted.operation_public_key, configuration_digest=admitted.configuration_digest,
                expected_predecessor_sequence=predecessor_sequence,
                expected_predecessor_head_digest=predecessor_head, expected_database_id=admitted.database_id,
                expected_generation_digest=admitted.generation_digest, expected_pending_sequence=pending_sequence,
                expected_pending_head_digest=pending_head, expected_fence=pending_fence,
                activation_custody=self._custody, live_window=window, transport_deadline_ns=bound, work=work,
                issuer=self._issuer, executor=self._executor)
        except execution.OidcSessionActivationSqlOutcomeError as exc:
            # Only actual same-call issuer locators may be returned. These
            # unsigned identifiers prove neither noncommit nor retry permission.
            work.prepare_utf8(exc.pending_decision_digest)
            work.prepare_utf8(exc.packet_digest)
            response = (b"uncertain", exc.pending_decision_digest.encode("ascii"),
                exc.packet_digest.encode("ascii"), b"")
        except Exception:
            # Issuance/commit may already be durable. Do not manufacture IDs or
            # expose exception details, even when a protected attempt is spent.
            response = (b"uncertain", b"", b"", b"")
        if executed is not None:
            if type(executed) is not execution._ExecutedSql:
                raise ActivationSqlRequestError("activation SQL returned no actual same-call execution result")
            observed = executed.observation
            if type(observed) is not execution.owners.SuccessorExecutionObservation:
                raise ActivationSqlRequestError("activation SQL returned no actual unsigned commit observation")
            execution_live = executed.live
            # Only this actual invocation's output supplies the shorter bound.
            # No successful carrier is accepted on the network/bridge input.
            result_window = clock._validate(executed.live_window)
            if result_window[:3] != window[:3]:
                raise ActivationSqlRequestError("activation SQL replaced the original request clock bracket")
            window = processing._narrow(window, deadline_epoch_ns=result_window[3],
                maximum_lifetime_ns=result_window[5], maximum_clock_skew_ns=result_window[6])
            bootstrap.shape._integer(executed.deadline_ns, minimum=1)
            bound = min(bound, window[4], executed.deadline_ns)
            current()
            work.prepare_utf8(observed.pending_decision_digest)
            work.prepare_utf8(observed.packet_digest)
            work.charge(input_bytes=len(observed.marker_bytes))
            response = (b"observed-commit", observed.pending_decision_digest.encode("ascii"),
                observed.packet_digest.encode("ascii"), observed.marker_bytes)
        response = transport._originals(response, response=True)
        current()
        transport._send_response(connection, response, deadline_ns=bound)
        current()
        transport._check_deadline(bound)

    def serve_once(self):
        """Idle briefly or spend this launch on exactly one accepted connection."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._accepted or self._connection is not None:
                raise ActivationSqlStartupError("activation SQL accepted exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise ActivationSqlStartupError("activation SQL original lifetime expired")
            ready, _, _ = select.select((self._listener,), (), (), min(1.0, remaining))
            self._live()
            if not ready:
                return False
            try:
                connection, _address = self._listener.accept()
            except BlockingIOError:
                self._live()
                return False
            self._accepted, self._connection = True, connection
            try:
                self._serve_connection(connection)
            except Exception:
                raise ActivationSqlRequestError(
                    "activation SQL outcome is not established; automatic retry is not permitted") from None
            finally:
                try:
                    connection.close()
                finally:
                    self._connection = None
            self._live()
            return True


def initialize_from_environment():
    global _state, _owner, _namespace, _descriptors_owned
    _require_pid()
    with _LOCK:
        if _state == "started":
            return require_started()
        if _state != "new":
            raise ActivationSqlStartupError("activation SQL cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = receiving = journal = attempt_owner = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            _descriptors_owned = True
            root_raw, root_identity = delivery._read_original(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES)
            bootstrap_raw, bootstrap_identity = delivery._read_original(delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES)
            custody_raw, custody_identity = delivery._read_original(delivery.CUSTODY_FD, delivery.MAX_CUSTODY_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from catchplate import oidc_session_activation_execution_sql_bootstrap as bootstrap
            from catchplate import authority_oidc_session_activation_execution_custody as custody
            from catchplate import authority_current_root_journal as storage
            from catchplate import authority_successor_execution_attempts as attempts
            from catchplate import authority_successor_execution_owner as owners
            from catchplate import authority_webauthn_evidence_plan_clock as clock
            from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES:
                raise ActivationSqlStartupError("activation SQL bootstrap bound changed")
            work = _ValidationWork(QueryReadValidationLimits())
            callback = bootstrap.authorization.production._callback
            work.charge(input_bytes=len(root_raw))
            root = callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise ActivationSqlStartupError("activation SQL root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw,
                custody_bytes=custody_raw, root_public_key=root, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"], launch["peerUid"], launch["peerGid"],
                    launch["rootPublicKeyFd"], launch["bootstrapFd"], launch["listenerFd"], launch["custodyFd"],
                    launch["bundleKeyFd"], launch["deliveryKeyFd"], launch["journalDirectoryFd"],
                    launch["listenerPath"], launch["journalDirectoryPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS,
                        delivery.LISTENER_PATH, delivery.JOURNAL_PATH)
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise ActivationSqlStartupError("activation SQL launch differs from fixed delivery")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins):
                raise ActivationSqlStartupError("activation SQL resources differ from signed pins")
            private_pins = tuple((fd, delivery.MAX_RAW_KEY_BYTES, True,
                delivery._sealed_identity(fd, delivery.MAX_RAW_KEY_BYTES, private=True))
                for fd in (delivery.BUNDLE_KEY_FD, delivery.DELIVERY_KEY_FD))
            window = _construction_window(material, clock)
            bound = min(window[4], material.opening_sample[0] + material.attestation_interval[1]
                - material.opening_sample[1])
            clock._check_on_work(window, work=work)
            bundle_key, delivery_key = delivery._keys_on_work(material, work)
            receiving = custody.OidcSessionActivationExecutionCustody(custody_bytes=custody_raw,
                root_public_key=root, consumer_role="sql-issuer", expected_receiver_identity=material.receiver_identity,
                bundle_key=bundle_key, delivery_custody_key=delivery_key, live_window=window,
                transport_deadline_ns=bound, work=work)
            del bundle_key, delivery_key
            configuration = custody.OidcSessionActivationExecutionCustody._snapshot_configuration(receiving)
            work.charge(hashes=len(material.tls_files),
                input_bytes=sum(record["byteCount"] for record in material.tls_files.values()))
            tls_identity = callback(work, lambda: delivery._tls_identity(material.tls_files))
            clock._check_on_work(window, work=work)

            def open_journal():
                nonlocal journal
                journal = storage.CurrentRootJournal(directory_fd=delivery.JOURNAL_FD,
                    expected_device=journal_pins[0], expected_inode=journal_pins[1],
                    expected_uid=delivery.SERVICE_UID, expected_gid=delivery.SERVICE_GID,
                    maximum_records=launch["journalMaximumRecords"])

            callback(work, open_journal)
            # Ownership is assigned inside the callback before its suffix may
            # fail. Recovery keeps the same cumulative cold work/window too.
            def recover_attempts():
                nonlocal attempt_owner
                attempt_owner = attempts.SuccessorExecutionAttempts(journal=journal,
                    expected_structure_manifest_digest=material.issuer_configuration[7],
                    expected_local_sequence=material.attempt_checkpoint[0],
                    expected_local_head_digest=material.attempt_checkpoint[1],
                    live_window=window, work=work, transport_deadline_ns=bound)

            callback(work, recover_attempts)
            issuer = owners.SuccessorExecutionIssuer(**_owner_arguments(material.issuer_configuration))
            executor = owners.SuccessorExecutionExecutor(**_owner_arguments(material.executor_configuration),
                attempt_owner=attempt_owner)
            sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            clock._check_on_work(window, work=work)
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            owner = object.__new__(_SqlOwner)
            owner._material, owner._root, owner._custody = material, root, receiving
            owner._custody_configuration = configuration
            owner._journal, owner._journal_fd, owner._journal_pins = journal, journal._directory_fd, journal_pins
            owner._attempts, owner._issuer, owner._executor = attempt_owner, issuer, executor
            owner._issuer_configuration = material.issuer_configuration
            owner._executor_configuration = material.executor_configuration
            owner._seal = (material, root, receiving, journal, attempt_owner, issuer, executor)
            owner._listener, owner._listener_pins, owner._tls = listener, listener_pins, tls_identity
            owner._sealed = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False, root_identity),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False, bootstrap_identity),
                (delivery.CUSTODY_FD, delivery.MAX_CUSTODY_BYTES, False, custody_identity), *private_pins)
            owner._opening, owner._interval = material.opening_sample, material.attestation_interval
            owner._deadline = owner._opening[0] + owner._interval[1] - owner._opening[1]
            owner._last_epoch, owner._last_monotonic = sample[1], sample[2]
            owner._closed = owner._failed = owner._accepted = False
            owner._connection = None
            _owner, _state = owner, "started"
            owner._live()
            clock._check_on_work(window, work=work)
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            for resource in (attempt_owner if attempt_owner is not None else journal, receiving, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            try:
                _close_inherited()
            except BaseException:
                pass
            if isinstance(exc, ActivationSqlStartupError) or not isinstance(exc, Exception):
                raise
            raise ActivationSqlStartupError("activation SQL cold admission failed") from None


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _SqlOwner:
            raise ActivationSqlStartupError("activation SQL has not started")
        _owner._live()
        return _owner


def close():
    """Drop private owner references and close this PID's adopted resources."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise ActivationSqlStartupError("cannot close an active activation SQL connection")
        _owner, _state = None, "closed"
        failed = False
        if owner is not None:
            owner._closed = owner._failed = True
            resources = (owner._attempts, owner._custody, owner._listener)
            owner._root = owner._material = owner._custody = owner._journal = None
            owner._attempts = owner._issuer = owner._executor = None
            owner._seal = owner._custody_configuration = None
            for resource in resources:
                try:
                    resource.close()
                except BaseException:
                    failed = True
        try:
            _close_inherited()
        except BaseException:
            failed = True
        if failed:
            raise ActivationSqlStartupError("activation SQL cleanup is not established")
