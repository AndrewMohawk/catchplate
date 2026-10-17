"""One root-selected consume completion exchange under the original cold allowance.

The root delivery continues in this same permanently dropped PID. Startup never
opens a replacement allowance; a single request allowance starts before peer or
body intake and remains bounded by that launch. Even an uncertain response
requires genuine, still-live completion custody and unchanged resources.
"""
from __future__ import annotations

import errno
import os
import select
import socket
import threading
import time

from catchplate import oidc_session_activation_delivery_completion_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None
_descriptors_owned = False


class DeliveryCompletionStartupError(RuntimeError):
    pass


class DeliveryCompletionRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise DeliveryCompletionStartupError("forked process cannot use consume completion")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    expected = tuple(sorted({"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
        "CATCHPLATE_PROCESS_MODE": delivery.PROCESS_MODE,
        delivery.ROOT_ENV: str(delivery.ROOT_FD), delivery.BOOTSTRAP_ENV: str(delivery.BOOTSTRAP_FD)}.items()))
    if (namespace != expected or tuple(sorted(delivery.ENVIRONMENT.items())) != expected
            or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise DeliveryCompletionStartupError("consume completion process or literal environment differs")
    delivery.delivery._require_unprivileged_process()


def _reader_arguments(configured):
    dsn, timeout, role, client_dn, client_serial, issuer_dn, query, structure = configured
    return {"dsn": dsn, "connect_timeout_seconds": timeout, "database_role": role,
        "tls_client_dn": client_dn, "tls_client_serial": client_serial, "tls_issuer_dn": issuer_dn,
        "query_manifest_digest": query, "expected_structure_manifest_digest": structure}


def _policy(material, root, work):
    from catchplate import oidc_session_activation_delivery_completion_bootstrap as bootstrap

    enrollment = bootstrap.authorization._admit_enrollment_on_work(
        enrollment_bytes=material.current_root_enrollment_bytes,
        root_public_key=material.evidence_root_public_key, work=work)
    planner = material.custody_material.planner.payload
    return (min(material.maximum_authorization_age_ns, planner["maximumPlanAgeNs"],
                enrollment.payload["maxControlAgeNs"]),
        min(material.maximum_authorization_clock_skew_ns, planner["maximumClockSkewNs"],
                enrollment.payload["maxClockSkewNs"]))


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
        raise DeliveryCompletionStartupError("consume completion descriptor cleanup is not established")


class _CompletionOwner:
    __slots__ = ("_material", "_root", "_key", "_historical", "_historical_configuration",
        "_listener", "_listener_pins", "_sealed", "_tls", "_journal", "_journal_fd", "_journal_pins",
        "_delivery", "_custody_reader", "_commit_reader", "_custody_configuration", "_commit_configuration",
        "_client", "_client_configuration", "_policy", "_startup_window", "_inherited_deadline",
        "_opening", "_interval", "_deadline", "_launch_schema", "_seal", "_last_epoch", "_last_monotonic",
        "_closed", "_failed", "_accepted", "_connection")

    def __init__(self):
        raise DeliveryCompletionStartupError("consume completion requires genuine cold admission")

    def _identity(self):
        return (self._material, self._root, self._key, self._historical, self._historical_configuration,
            self._listener, self._listener_pins, self._sealed, self._tls, self._journal,
            self._journal_fd, self._journal_pins, self._delivery, self._custody_reader, self._commit_reader,
            self._custody_configuration, self._commit_configuration, self._client, self._client_configuration,
            self._policy, self._startup_window, self._inherited_deadline, self._deadline, self._launch_schema)

    def _live(self):
        global _state
        from catchplate import authority_oidc_session_activation_delivery_completion_custody as historical
        from catchplate import authority_current_root_journal as storage
        from catchplate import authority_current_root_delivery as retained
        from catchplate import authority_current_root_commit_reader as committed
        from catchplate import authority_current_root_transport as state_transport
        from catchplate import authority_successor_execution_owner as custody

        _require_pid()
        try:
            held = _CompletionOwner._identity(self)
            if (type(self) is not _CompletionOwner or self is not _owner or _state != "started"
                    or self._closed or self._failed or _environment() != _namespace
                    or type(self._seal) is not tuple or len(self._seal) != len(held)
                    or any(actual is not original for actual, original in zip(held, self._seal))
                    or self._opening is not self._material.opening_sample
                    or self._interval is not self._material.attestation_interval
                    or self._material.launch["schema"] != self._launch_schema
                    or self._deadline > min(self._inherited_deadline, self._startup_window[4],
                        self._opening[0] + self._interval[1] - self._opening[1])):
                raise DeliveryCompletionStartupError("consume completion held lifetime or owners changed")
            _process(_namespace)
            for descriptor, maximum, private, identity in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                    raise DeliveryCompletionStartupError("consume completion sealed originals changed")
            if (delivery._listener(delivery.LISTENER_FD, launch_schema=self._launch_schema) != self._listener_pins
                    or delivery._listener(self._listener.fileno(), launch_schema=self._launch_schema) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins
                    or historical.OidcSessionActivationDeliveryCompletionCustody._snapshot_configuration(
                        self._historical) is not self._historical_configuration):
                raise DeliveryCompletionStartupError("consume completion resources or custody changed")
            delivery._tls_unchanged(self._tls)
            if (type(self._journal) is not storage.CurrentRootJournal
                    or self._journal._directory_fd != self._journal_fd
                    or type(self._delivery) is not retained.CurrentRootCompletionDelivery
                    or self._delivery._journal is not self._journal
                    or custody.SuccessorExecutionRecoveryReader._snapshot_configuration(self._custody_reader)
                        != self._custody_configuration
                    or committed.CurrentRootCommitReader._snapshot_configuration(self._commit_reader)
                        != self._commit_configuration
                    or state_transport.CurrentRootDecisionClient._snapshot_configuration(self._client)
                        != self._client_configuration):
                raise DeliveryCompletionStartupError("consume completion readers or journal owners changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(), self._journal_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            retained.CurrentRootCompletionDelivery.inspect(self._delivery)
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
                raise DeliveryCompletionStartupError("consume completion original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, DeliveryCompletionStartupError) or not isinstance(exc, Exception):
                raise
            raise DeliveryCompletionStartupError("consume completion lifecycle admission failed") from None

    def _serve_connection(self, connection):
        from catchplate import oidc_session_activation_delivery_completion_bootstrap as bootstrap
        from catchplate import authority_oidc_session_activation_delivery_completion_custody as historical
        from catchplate import authority_oidc_session_activation_delivery_completion_recovery as recovery
        from catchplate import authority_oidc_session_activation_delivery_completion_transport as private_transport
        from catchplate import authority_oidc_session_activation_delivery_completion_dispatch_transport as dispatch_transport
        from catchplate import authority_oidc_session_activation_delivery_completion_release_transport as release_transport
        from catchplate import authority_successor_execution_window as processing
        from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        profile = self._launch_schema
        if profile == bootstrap.LAUNCH_SCHEMA:
            transport = private_transport
        elif profile == bootstrap.DISPATCH_LAUNCH_SCHEMA:
            transport = dispatch_transport
        elif profile == bootstrap.RELEASE_LAUNCH_SCHEMA:
            transport = release_transport
        else:
            raise DeliveryCompletionRequestError("consume completion launch profile differs")
        expected_peer = delivery._launch_peer(profile)
        if (transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID) != expected_peer:
            raise DeliveryCompletionRequestError("consume completion transport peer profile differs")
        work = _ValidationWork(QueryReadValidationLimits())
        age, skew = self._policy
        window = bootstrap.clock._open_on_work(
            deadline_epoch_ns=min(self._interval[1], self._startup_window[3]),
            maximum_lifetime_ns=min(age, self._material.launch["requestTimeoutSeconds"] * 1_000_000_000),
            maximum_clock_skew_ns=skew, work=work)
        bound = min(self._deadline, window[4])
        last_epoch, last_monotonic = window[0], window[2]
        callback, custody_live = bootstrap.production._callback, None

        def current():
            nonlocal last_epoch, last_monotonic
            callback(work, self._live)
            if custody_live is not None:
                epoch = custody_live()
                bootstrap.shape._integer(epoch, minimum=1)
                if epoch < last_epoch or epoch < self._last_epoch:
                    raise DeliveryCompletionRequestError("consume completion custody clocks reversed")
                last_epoch = epoch
            now = bootstrap.clock._check_on_work(window, work=work)
            monotonic = callback(work, time.monotonic_ns)
            bootstrap.shape._integer(monotonic, minimum=1)
            if now < last_epoch or now < self._last_epoch or monotonic < last_monotonic or monotonic >= bound:
                raise DeliveryCompletionRequestError("consume completion request clocks expired or reversed")
            last_epoch, last_monotonic = now, monotonic
            return now

        current()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, bound,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != expected_peer:
            raise DeliveryCompletionRequestError("consume completion root-selected caller peer differs")
        # Charge the selected request's complete ceiling before any
        # prefix/body allocation. The wire helper separately bounds raw4/raw6.
        work.charge(input_bytes=transport.REQUEST_HEADER_BYTES + transport.MAX_REQUEST_BYTES)
        originals = transport._recv_request(connection, deadline_ns=bound)
        current()
        material = bootstrap._verify_on_work(bootstrap_bytes=self._material.bootstrap_bytes,
            root_public_key=self._root, live_window=window, transport_deadline_ns=bound, work=work)
        bootstrap.plan._same(material.attestation_interval, self._interval, work,
            "consume completion launch interval changed")
        bootstrap.plan._same(material.launch["schema"], profile, work,
            "consume completion root-selected profile changed")
        if profile in (bootstrap.DISPATCH_LAUNCH_SCHEMA, bootstrap.RELEASE_LAUNCH_SCHEMA):
            work.charge(input_bytes=len(originals[1]) + len(material.authorization_bytes))
            if originals[1] != material.authorization_bytes:
                raise DeliveryCompletionRequestError(
                    "consume completion dispatch authorization differs from independent root original")
        else:
            work.prepare_utf8(material.packet_digest)
            selector = material.packet_digest.encode("ascii")
            work.charge(input_bytes=len(originals[1]) + len(selector))
            if originals[1] != selector:
                raise DeliveryCompletionRequestError(
                    "consume completion selector differs from independent root scope")
        policy = _policy(material, self._root, work)
        bootstrap.plan._same(policy, self._policy, work, "consume completion enrolled policy changed")
        window = processing._narrow(window, deadline_epoch_ns=material.attestation_interval[1],
            maximum_lifetime_ns=policy[0], maximum_clock_skew_ns=policy[1])
        bound = min(bound, window[4])
        window, bound = historical.OidcSessionActivationDeliveryCompletionCustody.processing_bounds_on_work(
            self._historical, live_window=window, transport_deadline_ns=bound, work=work)
        custody_live = historical.OidcSessionActivationDeliveryCompletionCustody.check_on_work(
            self._historical, live_window=window, transport_deadline_ns=bound, work=work)
        current()
        sequence, head, fence = material.current_pending
        try:
            result = recovery.recover_and_deliver(custody_reader=self._custody_reader,
                commit_reader=self._commit_reader, delivery=self._delivery, client=self._client,
                historical_custody=self._historical, packet_digest=material.packet_digest,
                expectations=material.expectations, planner_public_key=material.planner_public_key,
                operation_public_key=material.operation_public_key,
                root_public_key=material.evidence_root_public_key,
                completion_private_key=self._key, authorization_bytes=material.authorization_bytes,
                authorization_enrollment_bytes=material.authorization_enrollment_bytes,
                grant_enrollment_bytes=material.grant_enrollment_bytes,
                current_root_enrollment_bytes=material.current_root_enrollment_bytes,
                configuration_digest=material.configuration_digest,
                expected_authorization_digest=material.authorization_digest,
                expected_database_id=material.database_id, expected_generation_digest=material.generation_digest,
                expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
                live_window=window, transport_deadline_ns=bound, work=work,
                include_release_hints=profile == bootstrap.RELEASE_LAUNCH_SCHEMA)
            current()
            hints = ()
            if profile == bootstrap.RELEASE_LAUNCH_SCHEMA:
                if type(result) is not tuple or len(result) != 2:
                    raise DeliveryCompletionRequestError("consume completion lacks its same-read release hints")
                result, hints = result
                if type(hints) is not tuple or len(hints) != 2:
                    raise DeliveryCompletionRequestError("consume completion release hint inventory differs")
            if type(result) is not recovery.common.SuccessorCompletionRecoveryResult:
                raise DeliveryCompletionRequestError("consume completion lacks its actual recovery result")
            original = recovery.delivery_store.CurrentRootCompletionDelivery._original_for_pending_on_work(
                self._delivery, expected_pending_sequence=sequence, expected_pending_head_digest=head, work=work)
            if type(original) is not tuple or len(original) != 2:
                raise DeliveryCompletionRequestError("consume completion lacks its retained original")
            identity, request = original
            bootstrap.plan._same(identity, result.request_digest, work,
                "consume completion outcome differs from its durable original")
            work.prepare_utf8(identity)
            response = (b"acknowledged", identity.encode("ascii"), request, result.receipt_bytes) + hints
        except Exception:
            # No exception text or invented receipt, retry or noncommit claim.
            # A poisoned journal, spent allowance or expired actual custody
            # fails this guard and emits nothing, including uncertainty.
            current()
            response = (b"uncertain", b"", b"", b"")
            if profile == bootstrap.RELEASE_LAUNCH_SCHEMA:
                response += (b"", b"")
        current()
        response = transport._originals(response, response=True)
        work.charge(input_bytes=transport.RESPONSE_HEADER_BYTES + sum(map(len, response)))
        current()
        transport._send_response(connection, response, deadline_ns=bound)
        current()
        transport._check_deadline(bound)
        return current

    def serve_once(self):
        """Idle briefly, or spend this launch before one accepted peer/body."""
        global _state
        _require_pid()
        with _LOCK:
            self._live()
            if self._accepted or self._connection is not None:
                raise DeliveryCompletionStartupError("consume completion exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise DeliveryCompletionStartupError("consume completion original lifetime expired")
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
                raise DeliveryCompletionRequestError(
                    "consume completion delivery is not established; automatic retry is not permitted") from None
            finally:
                if _state == "started":
                    _state = "spent"


def initialize_from_environment(*, work, live_window, transport_deadline_ns):
    """Continue the actual root construction work and original clock bracket."""
    global _state, _owner, _namespace, _descriptors_owned
    _require_pid()
    with _LOCK:
        if _state == "started":
            return require_started()
        if _state != "new":
            raise DeliveryCompletionStartupError("consume completion cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = journal = completion_delivery = historical_owner = None
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from catchplate import oidc_session_activation_delivery_completion_bootstrap as bootstrap
            from catchplate import authority_oidc_session_activation_delivery_completion_custody as historical
            from catchplate import authority_current_root_journal as storage
            from catchplate import authority_current_root_delivery as retained
            from catchplate import authority_current_root_commit_reader as committed
            from catchplate import authority_current_root_transport as state_transport
            from catchplate import authority_successor_execution_owner as custody
            from catchplate import authority_successor_execution_window as processing
            from catchplate.authority_query_read_work import _ValidationWork

            if type(work) is not _ValidationWork:
                raise DeliveryCompletionStartupError("consume completion requires actual inherited startup work")
            window = bootstrap.clock._validate(live_window)
            bootstrap.shape._integer(transport_deadline_ns, minimum=1)
            inherited_deadline = transport_deadline_ns
            bound = min(inherited_deadline, window[4])
            last_epoch, last_monotonic = window[0], window[2]
            callback, custody_live = bootstrap.production._callback, None

            def current():
                nonlocal last_epoch, last_monotonic
                _require_pid()
                if _environment() != _namespace:
                    raise DeliveryCompletionStartupError("consume completion construction environment changed")
                _process(_namespace)
                if custody_live is not None:
                    epoch = custody_live()
                    bootstrap.shape._integer(epoch, minimum=1)
                    if epoch < last_epoch:
                        raise DeliveryCompletionStartupError("consume completion custody construction clocks reversed")
                    last_epoch = epoch
                now = bootstrap.clock._check_on_work(window, work=work)
                monotonic = callback(work, time.monotonic_ns)
                bootstrap.shape._integer(monotonic, minimum=1)
                if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                    raise DeliveryCompletionStartupError("consume completion construction clocks expired or reversed")
                last_epoch, last_monotonic = now, monotonic
                return now

            current()
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            _descriptors_owned = True
            if delivery.MAX_BOOTSTRAP_BYTES != bootstrap.MAX_BYTES:
                raise DeliveryCompletionStartupError("consume completion bootstrap bounds changed")
            root_raw, root_identity = delivery._read_on_work(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, work)
            current()
            bootstrap_raw, bootstrap_identity = delivery._read_on_work(
                delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, work)
            current()
            work.charge(input_bytes=len(root_raw))
            root = callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise DeliveryCompletionStartupError("consume completion root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root,
                live_window=window, transport_deadline_ns=bound, work=work)
            current()
            launch = material.launch
            launch_schema = launch["schema"]
            peer_uid, peer_gid = delivery._launch_peer(launch_schema)
            fd_fields = ("rootPublicKeyFd", "bootstrapFd", "listenerFd", "signingKeyFd", "journalDirectoryFd",
                "executionBundleKeyFd", "historicalBundleKeyFd", "deliveryKeyFd")
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["peerUid"], launch["peerGid"], launch["listenerPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        peer_uid, peer_gid, delivery.LISTENER_PATH)
                    or tuple(launch[name] for name in fd_fields) != delivery.INHERITED_DESCRIPTORS
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise DeliveryCompletionStartupError("consume completion fixed delivery inventory differs")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD, launch_schema=launch_schema) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins):
                raise DeliveryCompletionStartupError("consume completion resources differ from signed pins")
            policy = _policy(material, root, work)
            window = processing._narrow(window, deadline_epoch_ns=material.attestation_interval[1],
                maximum_lifetime_ns=policy[0], maximum_clock_skew_ns=policy[1])
            bound = min(bound, window[4], material.opening_sample[0]
                + material.attestation_interval[1] - material.opening_sample[1])
            current()
            private_pins = ((delivery.KEY_FD, delivery.MAX_KEY_BYTES, True,
                delivery._sealed_identity(delivery.KEY_FD, delivery.MAX_KEY_BYTES, private=True)),)
            private_pins += tuple((fd, delivery.MAX_RAW_KEY_BYTES, True,
                delivery._sealed_identity(fd, delivery.MAX_RAW_KEY_BYTES, private=True))
                for fd in (delivery.EXECUTION_BUNDLE_KEY_FD, delivery.HISTORICAL_BUNDLE_KEY_FD, delivery.DELIVERY_KEY_FD))
            key, execution_key, historical_key, delivery_key = delivery._keys_on_work(material, work)
            current()
            historical_owner = historical.OidcSessionActivationDeliveryCompletionCustody(
                custody_bytes=material.custody_bytes, planner_bootstrap_bytes=material.planner_bootstrap_bytes,
                planner_history_custody_bytes=material.planner_history_custody_bytes,
                receiving_history_custody_bytes=material.receiving_history_custody_bytes,
                root_public_key=root, expected_receiver_identity=material.receiver_identity,
                execution_bundle_key=execution_key, historical_bundle_key=historical_key,
                delivery_custody_key=delivery_key, live_window=window, transport_deadline_ns=bound, work=work)
            del execution_key, historical_key, delivery_key
            historical.OidcSessionActivationDeliveryCompletionCustody.bind_context_on_work(historical_owner,
                root_public_key=material.evidence_root_public_key,
                current_root_enrollment_bytes=material.current_root_enrollment_bytes, work=work)
            window, bound = historical.OidcSessionActivationDeliveryCompletionCustody.processing_bounds_on_work(
                historical_owner, live_window=window, transport_deadline_ns=bound, work=work)
            custody_live = historical.OidcSessionActivationDeliveryCompletionCustody.check_on_work(
                historical_owner, live_window=window, transport_deadline_ns=bound, work=work)
            current()
            historical_configuration = historical.OidcSessionActivationDeliveryCompletionCustody._snapshot_configuration(
                historical_owner)
            tls_identity = delivery._tls_identity(material.tls_files, work=work)
            current()

            def open_journal():
                nonlocal journal
                journal = storage.CurrentRootJournal(directory_fd=delivery.JOURNAL_FD,
                    expected_device=journal_pins[0], expected_inode=journal_pins[1],
                    expected_uid=delivery.SERVICE_UID, expected_gid=delivery.SERVICE_GID,
                    maximum_records=launch["journalMaximumRecords"])

            callback(work, open_journal)
            current()
            # Native reads are metered before their stable callbacks; semantic
            # record reducers charge this same allowance outside callbacks.
            completion_delivery = retained.CurrentRootCompletionDelivery(journal=journal,
                enrollment_bytes=material.current_root_enrollment_bytes,
                root_public_key=material.evidence_root_public_key,
                expected_local_sequence=material.completion_checkpoint[0],
                expected_local_head_digest=material.completion_checkpoint[1],
                live_window=window, transport_deadline_ns=bound, work=work)
            current()
            reader_arguments = _reader_arguments(material.custody_configuration)
            del reader_arguments["database_role"]
            custody_reader = custody.SuccessorExecutionRecoveryReader(**reader_arguments)
            commit_reader = committed.CurrentRootCommitReader(**_reader_arguments(material.commit_configuration))
            path, timeout, uid, gid = material.state_endpoint
            client = state_transport.CurrentRootDecisionClient(path=path, timeout_seconds=timeout,
                expected_peer_uid=uid, expected_peer_gid=gid)
            current()
            sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            current()
            owner = object.__new__(_CompletionOwner)
            owner._material, owner._root, owner._key = material, root, key
            owner._historical, owner._historical_configuration = historical_owner, historical_configuration
            owner._listener, owner._listener_pins, owner._tls = listener, listener_pins, tls_identity
            owner._sealed = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False, root_identity),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False, bootstrap_identity), *private_pins)
            owner._journal, owner._journal_fd, owner._journal_pins = journal, journal._directory_fd, journal_pins
            owner._delivery, owner._custody_reader, owner._commit_reader = completion_delivery, custody_reader, commit_reader
            owner._custody_configuration, owner._commit_configuration = material.custody_configuration, material.commit_configuration
            owner._client, owner._client_configuration = client, state_transport.CurrentRootDecisionClient._snapshot_configuration(client)
            owner._policy, owner._startup_window, owner._inherited_deadline = policy, window, inherited_deadline
            owner._opening, owner._interval, owner._deadline = material.opening_sample, material.attestation_interval, bound
            owner._launch_schema = launch_schema
            owner._last_epoch, owner._last_monotonic = sample[1], sample[2]
            owner._closed = owner._failed = owner._accepted = False
            owner._connection = None
            owner._seal = _CompletionOwner._identity(owner)
            _owner, _state = owner, "started"
            owner._live()
            final_epoch = current()
            if final_epoch < owner._last_epoch or last_monotonic < owner._last_monotonic:
                raise DeliveryCompletionStartupError("consume completion clocks reversed at construction return")
            owner._last_epoch, owner._last_monotonic = final_epoch, last_monotonic
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            for resource in (completion_delivery if completion_delivery is not None else journal,
                    historical_owner, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            try:
                _close_inherited()
            except BaseException:
                pass
            if isinstance(exc, DeliveryCompletionStartupError) or not isinstance(exc, Exception):
                raise
            raise DeliveryCompletionStartupError("consume completion cold admission failed") from None


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _CompletionOwner:
            raise DeliveryCompletionStartupError("consume completion has not started")
        _owner._live()
        return _owner


def close():
    """Close owned resources without clearing or replacing durable originals."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise DeliveryCompletionStartupError("cannot close an active consume completion connection")
        _owner, _state = None, "closed"
        failed = False
        if owner is not None:
            owner._closed = owner._failed = True
            resources = (owner._delivery, owner._historical, owner._listener)
            owner._key = owner._root = owner._material = owner._historical = owner._journal = None
            owner._delivery = owner._custody_reader = owner._commit_reader = owner._client = None
            owner._seal = owner._historical_configuration = None
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
            raise DeliveryCompletionStartupError("consume completion cleanup is not established")
