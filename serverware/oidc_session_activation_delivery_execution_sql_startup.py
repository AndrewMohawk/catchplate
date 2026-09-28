"""One consume SQL exchange under independent root-held pending scope.

The fixed root launcher continues in the same permanently dropped PID with its
actual construction allowance. One separate request allowance opens before peer
or body intake and can only narrow that inherited lifetime. Actual receiving,
issuer, executor and attempt owners are required; unsigned outcomes never grant
completion, token release, current authentication or a retry.
"""
from __future__ import annotations

import errno
import os
import select
import socket
import threading
import time

from serverware import oidc_session_activation_delivery_execution_sql_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None
_descriptors_owned = False


class DeliveryExecutionSqlStartupError(RuntimeError):
    pass


class DeliveryExecutionSqlRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise DeliveryExecutionSqlStartupError("forked process cannot use the consume SQL owner")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    expected = tuple(sorted({"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
        "SERVERWARE_PROCESS_MODE": delivery.PROCESS_MODE,
        delivery.ROOT_ENV: str(delivery.ROOT_FD), delivery.BOOTSTRAP_ENV: str(delivery.BOOTSTRAP_FD)}.items()))
    if (namespace != expected or tuple(sorted(delivery.ENVIRONMENT.items())) != expected
            or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise DeliveryExecutionSqlStartupError("consume SQL process or literal environment differs")
    delivery.delivery._require_unprivileged_process()


def _policy(material):
    planner = material.custody_material.planner.payload
    return (min(material.maximum_authorization_age_ns, planner["maximumPlanAgeNs"]),
        min(material.maximum_authorization_clock_skew_ns, planner["maximumClockSkewNs"]))


def _admit(originals, root, window, bound, work):
    from serverware import oidc_session_activation_delivery_execution_sql_bootstrap as bootstrap

    return bootstrap._verify_on_work(bootstrap_bytes=originals[0], custody_bytes=originals[1],
        planner_bootstrap_bytes=originals[2], planner_history_custody_bytes=originals[3],
        receiving_history_custody_bytes=originals[4], root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work)


def _owner_arguments(configured):
    dsn, timeout, _role, client_dn, client_serial, issuer_dn, query, structure = configured
    return {"dsn": dsn, "connect_timeout_seconds": timeout, "tls_client_dn": client_dn,
        "tls_client_serial": client_serial, "tls_issuer_dn": issuer_dn,
        "query_manifest_digest": query, "expected_structure_manifest_digest": structure}


def _expectations(original, work):
    from serverware import authority_oidc_session_activation_delivery_execution_expectations as expected
    from serverware import authority_current_root_vector as vector

    decoded = vector.wire._decode_object(original, work=work, maximum_bytes=expected.MAX_BYTES,
        maximum_nodes=expected.MAX_NODES, maximum_depth=12)
    owned = expected._capture_on_work(decoded, work=work)
    canonical = vector.encoding._bounded_wire(owned, vector.capture._SharedLedger(work),
        maximum_bytes=expected.MAX_BYTES, maximum_nodes=expected.MAX_NODES)
    work.charge(input_bytes=len(original) + len(canonical))
    if original != canonical:
        raise DeliveryExecutionSqlRequestError("consume SQL expectations are not canonical originals")
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
        raise DeliveryExecutionSqlStartupError("consume SQL descriptor cleanup is not established")


class _SqlOwner:
    __slots__ = ("_material", "_root", "_custody", "_custody_configuration", "_originals", "_seal",
        "_listener", "_listener_pins", "_sealed", "_tls", "_journal", "_journal_fd", "_journal_pins",
        "_attempts", "_issuer", "_executor", "_issuer_configuration", "_executor_configuration",
        "_startup_window", "_inherited_deadline", "_opening", "_interval", "_deadline",
        "_last_epoch", "_last_monotonic", "_closed", "_failed", "_accepted", "_connection")

    def __init__(self):
        raise DeliveryExecutionSqlStartupError("consume SQL requires genuine cold admission")

    def _live(self):
        global _state
        from serverware import authority_oidc_session_activation_delivery_execution_custody as custody
        from serverware import authority_current_root_journal as storage
        from serverware import authority_successor_execution_attempts as attempts
        from serverware import authority_successor_execution_owner as owners

        _require_pid()
        try:
            held = (self._material, self._root, self._custody, self._custody_configuration, self._originals,
                self._startup_window, self._inherited_deadline, self._listener, self._listener_pins, self._sealed,
                self._tls, self._journal, self._journal_fd, self._journal_pins, self._attempts,
                self._issuer, self._executor, self._issuer_configuration, self._executor_configuration)
            if (type(self) is not _SqlOwner or self is not _owner or _state != "started"
                    or self._closed or self._failed or _environment() != _namespace
                    or type(self._seal) is not tuple or len(self._seal) != len(held)
                    or any(actual is not original for actual, original in zip(held, self._seal))
                    or self._opening is not self._material.opening_sample
                    or self._interval is not self._material.attestation_interval
                    or self._deadline != min(self._inherited_deadline, self._startup_window[4],
                        self._opening[0] + self._interval[1] - self._opening[1])):
                raise DeliveryExecutionSqlStartupError("consume SQL lifetime or held owners changed")
            _process(_namespace)
            for descriptor, maximum, private, identity in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                    raise DeliveryExecutionSqlStartupError("consume SQL sealed originals changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins
                    or custody.OidcSessionActivationDeliveryExecutionCustody._snapshot_configuration(self._custody)
                        is not self._custody_configuration):
                raise DeliveryExecutionSqlStartupError("consume SQL resources or custody changed")
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
                raise DeliveryExecutionSqlStartupError("consume SQL actual database or attempt owners changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(), self._journal_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            attempts.SuccessorExecutionAttempts.inspect(self._attempts)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_epoch, opened_before, opened_after, expiry, _bound, _age, skew = self._startup_window
            launch_before, launch_epoch, launch_after = self._opening
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < min(self._interval[1], expiry)
                    or after >= self._deadline
                    or not opened_epoch + before - opened_after - skew <= epoch
                        <= opened_epoch + after - opened_before + skew
                    or not launch_epoch + before - launch_after <= epoch
                        <= launch_epoch + after - launch_before):
                raise DeliveryExecutionSqlStartupError("consume SQL original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, DeliveryExecutionSqlStartupError) or not isinstance(exc, Exception):
                raise
            raise DeliveryExecutionSqlStartupError("consume SQL lifecycle admission failed") from None

    def _serve_connection(self, connection):
        from serverware import oidc_session_activation_delivery_execution_sql_bootstrap as bootstrap
        from serverware import authority_oidc_session_activation_delivery_sql as execution
        from serverware import authority_oidc_session_activation_delivery_sql_transport as transport
        from serverware import authority_successor_execution_window as processing
        from serverware import authority_webauthn_evidence_plan_clock as clock
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        material = self._material
        work = _ValidationWork(QueryReadValidationLimits())
        age, skew = _policy(material)
        window = clock._open_on_work(deadline_epoch_ns=min(self._interval[1], self._startup_window[3]),
            maximum_lifetime_ns=min(age, material.launch["requestTimeoutSeconds"] * 1_000_000_000),
            maximum_clock_skew_ns=skew, work=work)
        bound = min(self._deadline, window[4])
        last_epoch, last_monotonic = window[0], window[2]
        callback = bootstrap.primitives.production._callback
        execution_live = None

        def current():
            nonlocal last_epoch, last_monotonic
            callback(work, self._live)
            if execution_live is not None:
                observed_epoch = execution_live()
                bootstrap.shape._integer(observed_epoch, minimum=1)
                last_epoch = max(last_epoch, observed_epoch)
            now = clock._check_on_work(window, work=work)
            monotonic = callback(work, time.monotonic_ns)
            bootstrap.shape._integer(monotonic, minimum=1)
            if now < last_epoch or now < self._last_epoch or monotonic < last_monotonic or monotonic >= bound:
                raise DeliveryExecutionSqlRequestError("consume SQL original request clocks expired or reversed")
            last_epoch, last_monotonic = now, monotonic
            return now

        current()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, bound,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise DeliveryExecutionSqlRequestError("consume SQL caller peer differs")
        cold_bytes = bootstrap.receiving._intake_reservation((16 * 1024, *map(len, self._originals)))
        maximum_request = (transport.MAX_BYTES - cold_bytes - 4 * transport.MAX_RESPONSE_BYTES
            - transport.REQUEST_HEADER_BYTES - transport.RESPONSE_HEADER_BYTES) // 8
        if maximum_request <= 0:
            raise DeliveryExecutionSqlRequestError("consume cold captures leave no bounded request capacity")
        originals = transport._recv_request(connection, deadline_ns=bound,
            maximum_request_bytes=min(transport.MAX_REQUEST_BYTES, maximum_request))
        current()
        expected = _expectations(originals[3], work)
        scope = expected["scope"]
        # Unauthenticated scope can only narrow. The actual bridge still
        # authenticates all originals and independent pins before issuance.
        window = processing._narrow(window, deadline_epoch_ns=scope["deadlineEpochNs"],
            maximum_lifetime_ns=scope["maximumPlanAgeNs"], maximum_clock_skew_ns=scope["maximumClockSkewNs"])
        bound = min(bound, window[4])
        current()
        admitted = _admit(self._originals, self._root, window, bound, work)
        bootstrap.plan._same(admitted.attestation_interval, self._interval, work,
            "consume SQL original launch interval changed")
        current()
        predecessor_sequence, predecessor_head, predecessor_fence = admitted.state_predecessor
        pending_sequence, pending_head, pending_fence = admitted.current_pending
        bootstrap.plan._same(predecessor_fence, pending_fence, work,
            "consume SQL independent predecessor and pending fences differ")
        executed = failure = None
        try:
            executed = execution._execute_on_configuration(originals=originals[1:3], expectations=expected,
                before_vector_bytes=admitted.before_vector_bytes, authorization_bytes=originals[0],
                grant_bytes=originals[4], response_originals=originals[5:],
                authorization_enrollment_bytes=admitted.authorization_enrollment_bytes,
                grant_enrollment_bytes=admitted.grant_enrollment_bytes,
                current_root_enrollment_bytes=admitted.current_root_enrollment_bytes,
                root_public_key=self._root, planner_public_key=admitted.planner_public_key,
                operation_public_key=admitted.operation_public_key, configuration_digest=admitted.configuration_digest,
                expected_predecessor_sequence=predecessor_sequence,
                expected_predecessor_head_digest=predecessor_head, expected_database_id=admitted.database_id,
                expected_generation_digest=admitted.generation_digest, expected_pending_sequence=pending_sequence,
                expected_pending_head_digest=pending_head, expected_fence=pending_fence,
                receiving_custody=self._custody, live_window=window, transport_deadline_ns=bound, work=work,
                issuer=self._issuer, executor=self._executor)
        except execution.DeliverySqlOutcomeError as exc:
            failure = exc
        # No generic exception is converted to a response: only the genuine
        # same-call bridge continuation can keep uncertainty live for sending.
        if failure is not None:
            if type(failure) is not execution.DeliverySqlOutcomeError:
                raise DeliveryExecutionSqlRequestError("consume SQL uncertainty is not an actual outcome")
            continuation = failure
        else:
            if type(executed) is not execution._ExecutedSql:
                raise DeliveryExecutionSqlRequestError("consume SQL lacks its actual same-call result")
            continuation = executed
        if (continuation.live_window is None or continuation.deadline_ns is None
                or not callable(continuation.live)):
            raise DeliveryExecutionSqlRequestError("consume SQL outcome has no live original continuation")
        result_window = clock._validate(continuation.live_window)
        if result_window[:3] != window[:3]:
            raise DeliveryExecutionSqlRequestError("consume SQL replaced the original request opening")
        window = processing._narrow(window, deadline_epoch_ns=result_window[3],
            maximum_lifetime_ns=result_window[5], maximum_clock_skew_ns=result_window[6])
        bootstrap.shape._integer(continuation.deadline_ns, minimum=1)
        bound = min(bound, window[4], continuation.deadline_ns)
        execution_live = continuation.live
        current()
        if failure is not None:
            work.prepare_utf8(failure.pending_decision_digest)
            work.prepare_utf8(failure.packet_digest)
            response = (b"uncertain", failure.pending_decision_digest.encode("ascii"),
                failure.packet_digest.encode("ascii"), b"")
        else:
            observed = executed.observation
            if type(observed) is not execution.owners.SuccessorExecutionObservation:
                raise DeliveryExecutionSqlRequestError("consume SQL lacks its actual commit observation")
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
        return current

    def serve_once(self):
        """Idle briefly or spend this launch before one accepted peer/body."""
        global _state
        _require_pid()
        with _LOCK:
            self._live()
            if self._accepted or self._connection is not None:
                raise DeliveryExecutionSqlStartupError("consume SQL exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise DeliveryExecutionSqlStartupError("consume SQL original lifetime expired")
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
                try:
                    final_current = self._serve_connection(connection)
                finally:
                    try:
                        connection.close()
                    finally:
                        self._connection = None
                final_current()
                return True
            except Exception:
                raise DeliveryExecutionSqlRequestError(
                    "consume SQL outcome is not established; automatic retry is not permitted") from None
            finally:
                if _state == "started":
                    _state = "spent"


def initialize_from_environment(*, work, live_window, transport_deadline_ns):
    """Continue the actual root launch, never renew it after permanent drop."""
    global _state, _owner, _namespace, _descriptors_owned
    _require_pid()
    with _LOCK:
        if _state == "started":
            return require_started()
        if _state != "new":
            raise DeliveryExecutionSqlStartupError("consume SQL cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = receiving = journal = attempt_owner = None
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from serverware import oidc_session_activation_delivery_execution_sql_bootstrap as bootstrap
            from serverware import authority_oidc_session_activation_delivery_execution_custody as custody
            from serverware import authority_current_root_journal as storage
            from serverware import authority_successor_execution_attempts as attempts
            from serverware import authority_successor_execution_owner as owners
            from serverware import authority_successor_execution_window as processing
            from serverware import authority_webauthn_evidence_plan_clock as clock
            from serverware.authority_query_read_work import _ValidationWork

            if type(work) is not _ValidationWork:
                raise DeliveryExecutionSqlStartupError("consume SQL requires the actual inherited startup work")
            window = clock._validate(live_window)
            bootstrap.shape._integer(transport_deadline_ns, minimum=1)
            inherited_deadline = transport_deadline_ns
            bound = min(inherited_deadline, window[4])
            last_epoch, last_monotonic = window[0], window[2]
            callback = bootstrap.primitives.production._callback

            def current():
                nonlocal last_epoch, last_monotonic
                _require_pid()
                if _environment() != _namespace:
                    raise DeliveryExecutionSqlStartupError("consume SQL construction environment changed")
                _process(_namespace)
                now = clock._check_on_work(window, work=work)
                monotonic = callback(work, time.monotonic_ns)
                bootstrap.shape._integer(monotonic, minimum=1)
                if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                    raise DeliveryExecutionSqlStartupError("consume SQL construction clocks expired or reversed")
                last_epoch, last_monotonic = now, monotonic
                return now

            current()
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            _descriptors_owned = True
            maxima = (delivery.MAX_BOOTSTRAP_BYTES, delivery.MAX_CUSTODY_BYTES,
                delivery.MAX_PLANNER_BOOTSTRAP_BYTES, delivery.MAX_PLANNER_HISTORY_CUSTODY_BYTES,
                delivery.MAX_RECEIVING_HISTORY_CUSTODY_BYTES)
            if maxima != (bootstrap.MAX_BYTES, bootstrap.MAX_CUSTODY_BYTES,
                    bootstrap.MAX_PLANNER_BOOTSTRAP_BYTES, bootstrap.MAX_PLANNER_HISTORY_CUSTODY_BYTES,
                    bootstrap.MAX_RECEIVING_HISTORY_CUSTODY_BYTES):
                raise DeliveryExecutionSqlStartupError("consume SQL original bounds changed")
            descriptors = (delivery.BOOTSTRAP_FD, delivery.CUSTODY_FD, delivery.PLANNER_BOOTSTRAP_FD,
                delivery.PLANNER_HISTORY_CUSTODY_FD, delivery.RECEIVING_HISTORY_CUSTODY_FD)
            public_originals, public_pins = [], []
            inventory = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES), *zip(descriptors, maxima))
            identities = []
            for descriptor, maximum in inventory:
                current()
                identities.append(callback(work,
                    lambda descriptor=descriptor, maximum=maximum: delivery._sealed_identity(descriptor, maximum)))
                current()
            bootstrap.receiving._intake_reservation(tuple(value[0][6] for value in identities))
            for (descriptor, maximum), expected_identity in zip(inventory, identities):
                current()
                raw, identity = delivery._read_on_work(descriptor, maximum, work)
                if identity != expected_identity:
                    raise DeliveryExecutionSqlStartupError("consume cold original changed after aggregate preflight")
                public_originals.append(raw)
                public_pins.append((descriptor, maximum, False, identity))
                current()
            root_raw, originals = public_originals[0], tuple(public_originals[1:])
            root = callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise DeliveryExecutionSqlStartupError("consume SQL root must be Ed25519")
            current()
            material = _admit(originals, root, window, bound, work)
            current()
            launch = material.launch
            fd_fields = ("rootPublicKeyFd", "bootstrapFd", "listenerFd", "custodyFd", "plannerBootstrapFd",
                "plannerHistoryCustodyFd", "receivingHistoryCustodyFd", "executionBundleKeyFd",
                "historicalBundleKeyFd", "deliveryKeyFd", "journalDirectoryFd")
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"], launch["peerUid"],
                    launch["peerGid"], launch["listenerPath"], launch["journalDirectoryPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, delivery.LISTENER_PATH, delivery.JOURNAL_PATH)
                    or tuple(launch[name] for name in fd_fields) != delivery.INHERITED_DESCRIPTORS
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise DeliveryExecutionSqlStartupError("consume SQL launch differs from fixed delivery")
            age, skew = _policy(material)
            window = processing._narrow(window, deadline_epoch_ns=material.attestation_interval[1],
                maximum_lifetime_ns=age, maximum_clock_skew_ns=skew)
            bound = min(bound, window[4], material.opening_sample[0]
                + material.attestation_interval[1] - material.opening_sample[1])
            current()
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins):
                raise DeliveryExecutionSqlStartupError("consume SQL resources differ from signed pins")
            private_pins = tuple((fd, delivery.MAX_RAW_KEY_BYTES, True,
                delivery._sealed_identity(fd, delivery.MAX_RAW_KEY_BYTES, private=True))
                for fd in (delivery.EXECUTION_BUNDLE_KEY_FD, delivery.HISTORICAL_BUNDLE_KEY_FD, delivery.DELIVERY_KEY_FD))
            current()
            execution_key, historical_key, delivery_key = delivery._keys_on_work(material, work)
            current()
            receiving = custody.OidcSessionActivationDeliveryExecutionCustody.for_sql_issuer(
                custody_bytes=originals[1], planner_bootstrap_bytes=originals[2],
                planner_history_custody_bytes=originals[3], receiving_history_custody_bytes=originals[4],
                root_public_key=root, expected_receiver_identity=material.receiver_identity,
                execution_bundle_key=execution_key, historical_bundle_key=historical_key,
                delivery_custody_key=delivery_key, live_window=window, transport_deadline_ns=bound, work=work)
            del execution_key, historical_key, delivery_key
            current()
            configuration = custody.OidcSessionActivationDeliveryExecutionCustody._snapshot_configuration(receiving)
            # Charging helpers own their native-only callbacks. An outer stable
            # callback would incorrectly reject the legitimate shared charges.
            tls_identity = delivery._tls_identity(material.tls_files, work=work)
            current()

            def open_journal():
                nonlocal journal
                # Retain ownership before any callback suffix can fail.
                journal = storage.CurrentRootJournal(directory_fd=delivery.JOURNAL_FD,
                    expected_device=journal_pins[0], expected_inode=journal_pins[1],
                    expected_uid=delivery.SERVICE_UID, expected_gid=delivery.SERVICE_GID,
                    maximum_records=launch["journalMaximumRecords"])

            callback(work, open_journal)
            current()
            attempt_owner = attempts.SuccessorExecutionAttempts(journal=journal,
                expected_structure_manifest_digest=material.issuer_configuration[7],
                expected_local_sequence=material.attempt_checkpoint[0],
                expected_local_head_digest=material.attempt_checkpoint[1],
                live_window=window, work=work, transport_deadline_ns=bound)
            current()
            issuer = owners.SuccessorExecutionIssuer(**_owner_arguments(material.issuer_configuration))
            executor = owners.SuccessorExecutionExecutor(**_owner_arguments(material.executor_configuration),
                attempt_owner=attempt_owner)
            sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            current()
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            current()
            owner = object.__new__(_SqlOwner)
            owner._material, owner._root, owner._custody = material, root, receiving
            owner._custody_configuration, owner._originals = configuration, originals
            owner._journal, owner._journal_fd, owner._journal_pins = journal, journal._directory_fd, journal_pins
            owner._attempts, owner._issuer, owner._executor = attempt_owner, issuer, executor
            owner._issuer_configuration, owner._executor_configuration = material.issuer_configuration, material.executor_configuration
            owner._listener, owner._listener_pins, owner._tls = listener, listener_pins, tls_identity
            owner._sealed = (*public_pins, *private_pins)
            owner._startup_window, owner._inherited_deadline = window, inherited_deadline
            owner._opening, owner._interval, owner._deadline = material.opening_sample, material.attestation_interval, bound
            owner._last_epoch, owner._last_monotonic = sample[1], sample[2]
            owner._closed = owner._failed = owner._accepted = False
            owner._connection = None
            owner._seal = (material, root, receiving, configuration, originals, window, inherited_deadline,
                listener, listener_pins, owner._sealed, tls_identity, journal, owner._journal_fd, journal_pins,
                attempt_owner, issuer, executor, owner._issuer_configuration, owner._executor_configuration)
            _owner, _state = owner, "started"
            owner._live()
            final_epoch = current()
            if final_epoch < owner._last_epoch or last_monotonic < owner._last_monotonic:
                raise DeliveryExecutionSqlStartupError("consume SQL clocks reversed at construction return")
            owner._last_epoch, owner._last_monotonic = final_epoch, last_monotonic
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
            if isinstance(exc, DeliveryExecutionSqlStartupError) or not isinstance(exc, Exception):
                raise
            raise DeliveryExecutionSqlStartupError("consume SQL cold admission failed") from None


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _SqlOwner:
            raise DeliveryExecutionSqlStartupError("consume SQL has not started")
        _owner._live()
        return _owner


def close():
    """Close this PID's resources; never clear durable execution attempts."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise DeliveryExecutionSqlStartupError("cannot close an active consume SQL connection")
        _owner, _state = None, "closed"
        failed = False
        if owner is not None:
            owner._closed = owner._failed = True
            resources = (owner._attempts, owner._custody, owner._listener)
            owner._root = owner._material = owner._custody = owner._journal = None
            owner._attempts = owner._issuer = owner._executor = None
            owner._seal = owner._custody_configuration = owner._originals = None
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
            raise DeliveryExecutionSqlStartupError("consume SQL cleanup is not established")
