"""One cold consume reservation exchange with durable first-exact originals.

The original construction lifetime survives idle and request processing. One
request allowance opens before peer/body intake, then actual caller/grant and
private replay precede durable reserve delivery. No replacement signature,
automatic retry, ACK-derived currentness, SQL or token release is provided.
"""
from __future__ import annotations

import errno
import os
import select
import socket
import threading
import time

from serverware import oidc_session_activation_delivery_execution_reserver_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None
_descriptors_owned = False
INPUT_IDENTITY_DOMAIN = "serverware.oidcSessionActivationDeliveryReservationInputIdentity/v1"


class DeliveryExecutionReserverStartupError(RuntimeError):
    pass


class DeliveryExecutionReserverRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise DeliveryExecutionReserverStartupError("forked process cannot use the consume reserver")


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
        raise DeliveryExecutionReserverStartupError("consume reserver process or literal environment differs")
    delivery.delivery._require_unprivileged_process()


def _policy(material):
    planner = material.custody_material.planner.payload
    return (min(material.maximum_authorization_age_ns, planner["maximumPlanAgeNs"]),
        min(material.maximum_authorization_clock_skew_ns, planner["maximumClockSkewNs"]))


def _admit(originals, root, window, bound, work):
    from serverware import oidc_session_activation_delivery_execution_reserver_bootstrap as bootstrap

    return bootstrap._verify_on_work(bootstrap_bytes=originals[0], custody_bytes=originals[1],
        planner_bootstrap_bytes=originals[2], planner_history_custody_bytes=originals[3],
        receiving_history_custody_bytes=originals[4], root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work)


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
        raise DeliveryExecutionReserverRequestError("consume reservation expectations are not canonical")
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
        raise DeliveryExecutionReserverStartupError("consume reserver descriptor cleanup is not established")


class _ReserverOwner:
    __slots__ = ("_material", "_root", "_key", "_custody", "_custody_configuration", "_originals", "_seal",
        "_listener", "_listener_pins", "_sealed", "_journal", "_journal_fd", "_journal_pins",
        "_reservation", "_client", "_client_config", "_startup_window", "_inherited_deadline", "_opening", "_interval", "_deadline",
        "_last_epoch", "_last_monotonic", "_closed", "_failed", "_accepted", "_connection")

    def __init__(self):
        raise DeliveryExecutionReserverStartupError("consume reserver requires genuine cold admission")

    def _live(self):
        global _state
        from serverware import authority_oidc_session_activation_delivery_execution_custody as custody
        from serverware import authority_oidc_session_activation_delivery_reservation_delivery as reservations
        from serverware import authority_current_root_journal as storage
        from serverware import authority_current_root_transport as state_transport

        _require_pid()
        try:
            held = (self._material, self._root, self._key, self._custody, self._originals,
                self._startup_window, self._inherited_deadline, self._listener, self._listener_pins, self._sealed,
                self._journal, self._journal_fd, self._journal_pins, self._reservation,
                self._client, self._client_config)
            if (type(self) is not _ReserverOwner or self is not _owner or _state != "started"
                    or self._closed or self._failed or _environment() != _namespace
                    or type(self._seal) is not tuple or len(self._seal) != len(held)
                    or any(actual is not original for actual, original in zip(held, self._seal))
                    or self._opening is not self._material.opening_sample
                    or self._interval is not self._material.attestation_interval
                    or self._deadline != min(self._inherited_deadline, self._startup_window[4],
                        self._opening[0] + self._interval[1] - self._opening[1])):
                raise DeliveryExecutionReserverStartupError("consume reserver lifetime or held configuration changed")
            _process(_namespace)
            for descriptor, maximum, private, identity in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                    raise DeliveryExecutionReserverStartupError("consume reserver sealed originals changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins
                    or custody.OidcSessionActivationDeliveryExecutionCustody._snapshot_configuration(self._custody)
                        is not self._custody_configuration):
                raise DeliveryExecutionReserverStartupError("consume reserver resources or custody changed")
            if (type(self._journal) is not storage.CurrentRootJournal
                    or self._journal._directory_fd != self._journal_fd
                    or type(self._reservation) is not reservations.OidcSessionActivationDeliveryReservationDelivery
                    or self._reservation._journal is not self._journal
                    or self._reservation._root_public_key is not self._root
                    or self._reservation._enrollment_bytes is not self._material.current_root_enrollment_bytes
                    or state_transport.CurrentRootDecisionClient._snapshot_configuration(self._client)
                        != self._client_config):
                raise DeliveryExecutionReserverStartupError("consume reserver actual owner configuration changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(), self._journal_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            reservations.OidcSessionActivationDeliveryReservationDelivery.inspect(self._reservation)
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
                raise DeliveryExecutionReserverStartupError("consume reserver original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, DeliveryExecutionReserverStartupError) or not isinstance(exc, Exception):
                raise
            raise DeliveryExecutionReserverStartupError("consume reserver lifecycle admission failed") from None

    def _serve_connection(self, connection):
        from serverware import authority_oidc_session_activation_delivery_reservation_transport as transport
        from serverware import oidc_session_activation_delivery_execution_reserver_bootstrap as bootstrap
        from serverware import authority_oidc_session_activation_delivery_reservation as producer
        from serverware import authority_oidc_session_activation_delivery_reservation_delivery as reservations
        from serverware import authority_oidc_session_activation_delivery_execution_grant_admission as admission
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
        callback = bootstrap.production._callback
        original_live, reserve_payload, reserve_material = None, None, None

        def current():
            nonlocal last_epoch, last_monotonic
            callback(work, self._live)
            if original_live is not None:
                original_epoch, original_monotonic = original_live()
                last_epoch = max(last_epoch, original_epoch)
                last_monotonic = max(last_monotonic, original_monotonic)
            now = clock._check_on_work(window, work=work)
            monotonic = callback(work, time.monotonic_ns)
            bootstrap.shape._integer(monotonic, minimum=1)
            if (now < last_epoch or now < self._last_epoch or monotonic < last_monotonic or monotonic >= bound):
                raise DeliveryExecutionReserverRequestError("consume reserver request clocks expired or reversed")
            if reserve_payload is not None:
                bootstrap.authorization._fresh(reserve_payload, reserve_material, now)
            last_epoch, last_monotonic = now, monotonic
            return now

        current()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, bound,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise DeliveryExecutionReserverRequestError("consume reserver caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=bound)
        current()
        expected = _expectations(originals[3], work)
        scope = expected["scope"]
        # Untrusted incoming ceilings only narrow the actual pre-peer opening.
        # Original signatures, current role admission and proof replay follow.
        window = processing._narrow(window, deadline_epoch_ns=scope["deadlineEpochNs"],
            maximum_lifetime_ns=scope["maximumPlanAgeNs"],
            maximum_clock_skew_ns=scope["maximumClockSkewNs"])
        bound = min(bound, window[4])
        current()
        admitted = _admit(self._originals, self._root, window, bound, work)
        bootstrap.plan._same(admitted.attestation_interval, self._interval, work,
            "consume reserver original launch interval")
        bootstrap.plan._same(admitted.launch, material.launch, work, "consume reserver original launch scope")
        current()
        # Admit original caller/root scope and the actual grant signature before
        # local lookup. This is not a private proof replay or an input carrier
        # to the producer; the selected fresh/retained path replays exactly once.
        held = admission._hold_on_work(authorization_bytes=originals[0],
            authorization_enrollment_bytes=admitted.authorization_enrollment_bytes,
            current_root_enrollment_bytes=admitted.current_root_enrollment_bytes,
            grant_enrollment_bytes=admitted.grant_enrollment_bytes, root_public_key=self._root,
            configuration_digest=admitted.configuration_digest, planner_public_key=admitted.planner_public_key,
            operation_public_key=admitted.operation_public_key, originals=originals[1:3], expectations=expected,
            before_vector_bytes=admitted.custody_material.planner.complete_root_vector_bytes,
            receiving_custody=self._custody, live_window=window, transport_deadline_ns=bound, work=work,
            required_consumer_role="reserve", extra_originals=(originals[4],))
        authorized = admission._admit_on_work(held, work)
        original_live = authorized.live
        current()
        grant_payload, _grant_digest = admission.wire._verify_signature_on_work(originals[4],
            authorized.enrollment.authorizer_public_key, work)
        admission._check_control_on_work(grant_payload, authorized, work)
        window = processing._narrow(authorized.window, deadline_epoch_ns=grant_payload["expiresAtEpochNs"],
            maximum_lifetime_ns=authorized.window[5], maximum_clock_skew_ns=authorized.window[6])
        bound = min(bound, authorized.deadline_ns, window[4])
        current()
        inputs = held.inputs
        arguments = dict(originals=inputs.originals, expectations=inputs.expectations,
            before_vector_bytes=inputs.before, authorization_bytes=held.authorization_bytes, grant_bytes=originals[4],
            authorization_enrollment_bytes=inputs.caller_enrollment,
            grant_enrollment_bytes=inputs.grant_enrollment, current_root_enrollment_bytes=inputs.current_enrollment,
            root_public_key=inputs.root, planner_public_key=inputs.planner,
            operation_public_key=inputs.operation_key, configuration_digest=inputs.configuration_digest,
            receiving_custody=self._custody, live_window=window, transport_deadline_ns=bound, work=work)
        locator = bootstrap.plan._frame(INPUT_IDENTITY_DOMAIN, originals, work)
        sequence, head, fence = admitted.state_predecessor
        predecessor = dict(expected_predecessor_sequence=sequence,
            expected_predecessor_head_digest=head, expected_fence=fence)
        retained = reservations.OidcSessionActivationDeliveryReservationDelivery._original_for_execution_on_work(
            self._reservation, locator, **predecessor, work=work)
        current()
        if retained is None:
            produced = producer._produce_on_work(**arguments, **predecessor, computation_private_key=self._key)
            request_bytes, snapshot_bytes = produced.request_bytes, produced.snapshot_bytes
        else:
            returned = producer._verify_retained_on_work(**arguments, **predecessor,
                response_originals=(retained.request_bytes, retained.snapshot_bytes, retained.receipt_bytes))
            request_bytes, snapshot_bytes = returned[:2]
        current()
        reserve_material, reserve_payload, request_identity = bootstrap.authorization._verify_request_on_work(
            request_bytes=request_bytes, enrollment_bytes=admitted.current_root_enrollment_bytes,
            root_public_key=self._root, now_epoch_ns=current(), work=work)
        window = processing._narrow(window, deadline_epoch_ns=reserve_payload["expiresAtEpochNs"],
            maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
        bound = min(bound, window[4])
        current()
        if retained is None:
            identity = reservations.OidcSessionActivationDeliveryReservationDelivery.enqueue(self._reservation,
                request_bytes, snapshot_bytes=snapshot_bytes, execution_record_digest=locator,
                **predecessor, live_window=window, transport_deadline_ns=bound, work=work)
            bootstrap.plan._same(identity, request_identity, work, "durable consume reserve identity changed")
        current()
        receipt = reservations.OidcSessionActivationDeliveryReservationDelivery.deliver(self._reservation,
            request_identity, client=self._client, live_window=window, transport_deadline_ns=bound, work=work)
        current()
        saved = reservations.OidcSessionActivationDeliveryReservationDelivery.originals(self._reservation, request_identity)
        response = transport._originals((saved.request_bytes, saved.snapshot_bytes, saved.receipt_bytes), response=True)
        for actual, wanted in zip(response, (request_bytes, snapshot_bytes, receipt)):
            producer._same_bytes(actual, wanted, work, "consume response differs from first durable originals")
        bootstrap.plan._same(saved.execution_record_digest, locator, work, "consume durable input association changed")
        # The delivery owner already genuinely verified and fsynced the ACK.
        # No second private replay is needed merely to send those exact bytes.
        current()
        transport._send_response(connection, response, deadline_ns=bound)
        current()
        transport._check_deadline(bound)
        return current

    def serve_once(self):
        """Idle briefly or spend this launch on one accepted connection."""
        global _state
        _require_pid()
        with _LOCK:
            self._live()
            if self._accepted or self._connection is not None:
                raise DeliveryExecutionReserverStartupError("consume reserver exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise DeliveryExecutionReserverStartupError("consume reserver original lifetime expired")
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
                raise DeliveryExecutionReserverRequestError(
                    "consume reservation outcome is not established; automatic retry is not permitted") from None
            finally:
                if _state == "started":
                    _state = "spent"


def initialize_from_environment(*, work, live_window, transport_deadline_ns):
    """Continue the real root launch in the same permanently dropped PID.

    No default construction allowance exists: the fixed root entrypoint passes
    the actual work/window it opened before root or key I/O, without exec.
    Reauthentication here still uses sealed originals, never a material DTO.
    """
    global _state, _owner, _namespace, _descriptors_owned
    _require_pid()
    with _LOCK:
        if _state == "started":
            return require_started()
        if _state != "new":
            raise DeliveryExecutionReserverStartupError("consume reserver cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = receiving = journal = reservation = None
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from serverware import oidc_session_activation_delivery_execution_reserver_bootstrap as bootstrap
            from serverware import authority_oidc_session_activation_delivery_execution_custody as custody
            from serverware import authority_oidc_session_activation_delivery_reservation_delivery as reservations
            from serverware import authority_current_root_journal as storage
            from serverware import authority_current_root_transport as state_transport
            from serverware import authority_successor_execution_window as processing
            from serverware import authority_webauthn_evidence_plan_clock as clock
            from serverware.authority_query_read_work import _ValidationWork

            if type(work) is not _ValidationWork:
                raise DeliveryExecutionReserverStartupError("consume reserver requires the actual inherited startup work")
            window = clock._validate(live_window)
            bootstrap.shape._integer(transport_deadline_ns, minimum=1)
            inherited_deadline = transport_deadline_ns
            bound = min(inherited_deadline, window[4])
            last_epoch, last_monotonic = window[0], window[2]
            callback = bootstrap.production._callback

            def current():
                nonlocal last_epoch, last_monotonic
                _require_pid()
                if _environment() != _namespace:
                    raise DeliveryExecutionReserverStartupError("consume reserver construction environment changed")
                _process(_namespace)
                now = clock._check_on_work(window, work=work)
                monotonic = callback(work, time.monotonic_ns)
                bootstrap.shape._integer(monotonic, minimum=1)
                if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                    raise DeliveryExecutionReserverStartupError("consume reserver construction clocks expired or reversed")
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
                raise DeliveryExecutionReserverStartupError("consume reserver original bounds changed")
            descriptors = (delivery.BOOTSTRAP_FD, delivery.CUSTODY_FD, delivery.PLANNER_BOOTSTRAP_FD,
                delivery.PLANNER_HISTORY_CUSTODY_FD, delivery.RECEIVING_HISTORY_CUSTODY_FD)
            public_originals, public_pins = [], []
            for descriptor, maximum in ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES), *zip(descriptors, maxima)):
                current()
                # The helper charges first, then wraps only its native read.
                # Nesting it in a callback would reject legitimate metering.
                raw, identity = delivery._read_on_work(descriptor, maximum, work)
                public_originals.append(raw)
                public_pins.append((descriptor, maximum, False, identity))
                current()
            root_raw, originals = public_originals[0], tuple(public_originals[1:])
            root = callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise DeliveryExecutionReserverStartupError("consume reserver root must be Ed25519")
            current()
            material = _admit(originals, root, window, bound, work)
            current()
            launch = material.launch
            fd_fields = ("rootPublicKeyFd", "bootstrapFd", "listenerFd", "custodyFd", "plannerBootstrapFd",
                "plannerHistoryCustodyFd", "receivingHistoryCustodyFd", "executionBundleKeyFd",
                "historicalBundleKeyFd", "deliveryKeyFd", "signingKeyFd", "journalDirectoryFd")
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"], launch["peerUid"],
                    launch["peerGid"], launch["listenerPath"], launch["journalDirectoryPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, delivery.LISTENER_PATH, delivery.JOURNAL_PATH)
                    or tuple(launch[name] for name in fd_fields) != delivery.INHERITED_DESCRIPTORS
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise DeliveryExecutionReserverStartupError("consume reserver launch differs from fixed delivery")
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
                raise DeliveryExecutionReserverStartupError("consume reserver resources differ from signed pins")
            private_pins = tuple((fd, maximum, True, delivery._sealed_identity(fd, maximum, private=True))
                for fd, maximum in ((delivery.EXECUTION_BUNDLE_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.HISTORICAL_BUNDLE_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.DELIVERY_KEY_FD, delivery.MAX_RAW_KEY_BYTES), (delivery.KEY_FD, delivery.MAX_KEY_BYTES)))
            current()
            execution_key, historical_key, delivery_key, key = delivery._keys_on_work(material, work)
            current()
            receiving = custody.OidcSessionActivationDeliveryExecutionCustody.for_reserve(custody_bytes=originals[1],
                planner_bootstrap_bytes=originals[2], planner_history_custody_bytes=originals[3],
                receiving_history_custody_bytes=originals[4], root_public_key=root,
                expected_receiver_identity=material.receiver_identity, execution_bundle_key=execution_key,
                historical_bundle_key=historical_key, delivery_custody_key=delivery_key,
                live_window=window, transport_deadline_ns=bound, work=work)
            del execution_key, historical_key, delivery_key
            current()
            configuration = custody.OidcSessionActivationDeliveryExecutionCustody._snapshot_configuration(receiving)

            def open_journal():
                nonlocal journal
                # Keep ownership before a callback suffix can fail after flock.
                journal = storage.CurrentRootJournal(directory_fd=delivery.JOURNAL_FD,
                    expected_device=journal_pins[0], expected_inode=journal_pins[1],
                    expected_uid=delivery.SERVICE_UID, expected_gid=delivery.SERVICE_GID,
                    maximum_records=launch["journalMaximumRecords"])

            callback(work, open_journal)
            current()
            reservation = reservations.OidcSessionActivationDeliveryReservationDelivery(journal=journal,
                enrollment_bytes=material.current_root_enrollment_bytes, root_public_key=root,
                expected_local_sequence=material.reservation_checkpoint[0],
                expected_local_head_digest=material.reservation_checkpoint[1], live_window=window,
                transport_deadline_ns=bound, work=work)
            current()
            path, timeout, _state_uid, _state_gid, peer_uid, peer_gid = material.state_endpoint
            client = state_transport.CurrentRootDecisionClient(path=path, timeout_seconds=timeout,
                expected_peer_uid=peer_uid, expected_peer_gid=peer_gid)
            sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            current()
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            current()
            owner = object.__new__(_ReserverOwner)
            owner._material, owner._root, owner._key, owner._custody = material, root, key, receiving
            owner._custody_configuration, owner._originals = configuration, originals
            owner._journal, owner._journal_fd, owner._journal_pins = journal, journal._directory_fd, journal_pins
            owner._reservation, owner._client = reservation, client
            owner._client_config = state_transport.CurrentRootDecisionClient._snapshot_configuration(client)
            owner._listener, owner._listener_pins = listener, listener_pins
            owner._sealed = (*public_pins, *private_pins)
            owner._startup_window = window
            owner._inherited_deadline = inherited_deadline
            owner._opening, owner._interval = material.opening_sample, material.attestation_interval
            owner._deadline = bound
            owner._last_epoch, owner._last_monotonic = sample[1], sample[2]
            owner._closed = owner._failed = owner._accepted = False
            owner._connection = None
            owner._seal = (material, root, key, receiving, originals, window, inherited_deadline, listener, listener_pins,
                owner._sealed, journal, owner._journal_fd, journal_pins, reservation, client, owner._client_config)
            _owner, _state = owner, "started"
            owner._live()
            final_epoch = current()
            if final_epoch < owner._last_epoch or last_monotonic < owner._last_monotonic:
                raise DeliveryExecutionReserverStartupError("consume reserver clocks reversed at construction return")
            owner._last_epoch, owner._last_monotonic = final_epoch, last_monotonic
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            for resource in (reservation if reservation is not None else journal, receiving, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            try:
                _close_inherited()
            except BaseException:
                pass
            if isinstance(exc, DeliveryExecutionReserverStartupError) or not isinstance(exc, Exception):
                raise
            raise DeliveryExecutionReserverStartupError("consume reserver cold admission failed") from None


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _ReserverOwner:
            raise DeliveryExecutionReserverStartupError("consume reserver has not started")
        _owner._live()
        return _owner


def close():
    """Close actual owned/adopted resources without erasing durable outcomes."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise DeliveryExecutionReserverStartupError("cannot close an active consume reserver connection")
        _owner, _state = None, "closed"
        failed = False
        if owner is not None:
            owner._closed = owner._failed = True
            resources = (owner._reservation, owner._custody, owner._listener)
            owner._key = owner._root = owner._material = owner._custody = None
            owner._journal = owner._reservation = owner._client = None
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
            raise DeliveryExecutionReserverStartupError("consume reserver cleanup is not established")
