"""One cold activation reservation exchange with first-exact durable originals.

An accepted connection spends this launch even on uncertainty. Root admission
and the original work/window precede peer/body intake. Exact retained reserves
can be explicitly recovered, never regenerated or automatically retried.
"""
from __future__ import annotations

import errno
import os
import select
import socket
import threading
import time

from serverware import oidc_session_activation_execution_reserver_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None
_descriptors_owned = False
INPUT_IDENTITY_DOMAIN = "serverware.oidcSessionActivationReservationInputIdentity/v1"


class ActivationReserverStartupError(RuntimeError):
    pass


class ActivationReserverRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise ActivationReserverStartupError("forked process cannot use the activation reserver")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    if (namespace != tuple(sorted(delivery.ENVIRONMENT.items()))
            or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise ActivationReserverStartupError("activation reserver process or literal environment differs")
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


def _expectations(original, work):
    from serverware import authority_oidc_session_activation_execution_expectations as expected
    from serverware import authority_current_root_vector as vector

    decoded = vector.wire._decode_object(original, work=work, maximum_bytes=expected.MAX_BYTES,
        maximum_nodes=expected.MAX_NODES, maximum_depth=12)
    owned = expected._capture_on_work(decoded, work=work)
    canonical = vector.encoding._bounded_wire(owned, vector.capture._SharedLedger(work),
        maximum_bytes=expected.MAX_BYTES, maximum_nodes=expected.MAX_NODES)
    work.charge(input_bytes=len(original) + len(canonical))
    if original != canonical:
        raise ActivationReserverRequestError("activation expectation originals are not canonical")
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
        raise ActivationReserverStartupError("activation reserver descriptor cleanup is not established")


class _ReserverOwner:
    __slots__ = ("_material", "_root", "_key", "_custody", "_custody_configuration", "_seal",
        "_listener", "_listener_pins", "_sealed", "_journal", "_journal_fd", "_journal_pins",
        "_reservation", "_client", "_client_config", "_opening", "_interval", "_deadline",
        "_last_epoch", "_last_monotonic", "_closed", "_failed", "_accepted", "_connection")

    def __init__(self):
        raise ActivationReserverStartupError("activation reserver requires genuine cold admission")

    def _live(self):
        global _state
        from serverware import authority_oidc_session_activation_execution_custody as custody
        from serverware import authority_oidc_session_activation_reservation_delivery as reservations
        from serverware import authority_current_root_journal as storage
        from serverware import authority_current_root_transport as state_transport

        _require_pid()
        try:
            if (type(self) is not _ReserverOwner or self is not _owner
                    or _state != "started" or self._closed or self._failed or _environment() != _namespace
                    or type(self._seal) is not tuple or len(self._seal) != 7
                    or any(actual is not held for actual, held in zip((self._material, self._root,
                        self._key, self._custody, self._journal, self._reservation, self._client), self._seal))):
                raise ActivationReserverStartupError("activation reserver lifetime or held owner changed")
            _process(_namespace)
            for descriptor, maximum, private, identity in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                    raise ActivationReserverStartupError("activation reserver sealed originals changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins
                    or custody.OidcSessionActivationExecutionCustody._snapshot_configuration(self._custody)
                        is not self._custody_configuration):
                raise ActivationReserverStartupError("activation reserver resource or custody binding changed")
            if (type(self._journal) is not storage.CurrentRootJournal
                    or self._journal._directory_fd != self._journal_fd
                    or type(self._reservation) is not reservations.OidcSessionActivationReservationDelivery
                    or self._reservation._journal is not self._journal
                    or self._reservation._root_public_key is not self._root
                    or self._reservation._enrollment_bytes is not self._material.current_root_enrollment_bytes
                    or state_transport.CurrentRootDecisionClient._snapshot_configuration(self._client)
                        != self._client_config):
                raise ActivationReserverStartupError("activation reserver actual owner configuration changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(), self._journal_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            reservations.OidcSessionActivationReservationDelivery.inspect(self._reservation)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_before, opened_epoch, opened_after = self._opening
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < self._interval[1] or after >= self._deadline
                    or not opened_epoch + before - opened_after <= epoch
                        <= opened_epoch + after - opened_before):
                raise ActivationReserverStartupError("activation reserver original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, ActivationReserverStartupError) or not isinstance(exc, Exception):
                raise
            raise ActivationReserverStartupError("activation reserver lifecycle admission failed") from None

    def _serve_connection(self, connection):
        from serverware import authority_oidc_session_activation_reservation_transport as transport
        from serverware import oidc_session_activation_execution_reserver_bootstrap as bootstrap
        from serverware import authority_oidc_session_activation_reservation as producer
        from serverware import authority_oidc_session_activation_reservation_delivery as reservations
        from serverware import authority_successor_execution_window as processing
        from serverware import authority_webauthn_evidence_plan_clock as clock
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        material = self._material
        work = _ValidationWork(QueryReadValidationLimits())
        age, skew = _policy(material)
        window = clock._open_on_work(deadline_epoch_ns=self._interval[1],
            maximum_lifetime_ns=min(age, material.launch["requestTimeoutSeconds"] * 1_000_000_000),
            maximum_clock_skew_ns=skew, work=work)
        bound = min(self._deadline, window[4])
        last_epoch, last_monotonic = window[0], window[2]
        callback = bootstrap.authorization.production._callback
        original_live, reserve_payload, reserve_material = None, None, None

        def current():
            nonlocal last_epoch, last_monotonic
            callback(work, self._live)
            if original_live is not None:
                original_now, original_monotonic = original_live()
                last_epoch = max(last_epoch, original_now)
                last_monotonic = max(last_monotonic, original_monotonic)
            now = clock._check_on_work(window, work=work)
            monotonic = callback(work, time.monotonic_ns)
            bootstrap.shape._integer(monotonic, minimum=1)
            if (now < last_epoch or now < self._last_epoch or monotonic < last_monotonic or monotonic >= bound):
                raise ActivationReserverRequestError("activation reserver request clocks expired or reversed")
            if reserve_payload is not None:
                bootstrap.authorization._fresh(reserve_payload, reserve_material, now)
            last_epoch, last_monotonic = now, monotonic
            return now

        current()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, bound,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise ActivationReserverRequestError("activation reserver caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=bound)
        current()
        expected = _expectations(originals[3], work)
        scope = expected["scope"]
        # Incoming scope can only narrow the original pre-peer clock bracket;
        # genuine known signatures and private replay still establish its truth.
        window = processing._narrow(window, deadline_epoch_ns=scope["deadlineEpochNs"],
            maximum_lifetime_ns=scope["maximumPlanAgeNs"], maximum_clock_skew_ns=scope["maximumClockSkewNs"])
        bound = min(bound, window[4])
        current()
        admitted = bootstrap._verify_on_work(bootstrap_bytes=material.bootstrap_bytes,
            custody_bytes=material.custody_bytes, root_public_key=self._root,
            live_window=window, transport_deadline_ns=bound, work=work)
        bootstrap.plan._same(admitted.attestation_interval, self._interval, work,
            "activation reserver original launch interval changed")
        arguments = dict(originals=originals[1:3], expectations=expected,
            before_vector_bytes=admitted.custody_material.planner.complete_root_vector_bytes,
            authorization_bytes=originals[0], grant_bytes=originals[4],
            authorization_enrollment_bytes=admitted.authorization_enrollment_bytes,
            grant_enrollment_bytes=admitted.grant_enrollment_bytes,
            current_root_enrollment_bytes=admitted.current_root_enrollment_bytes,
            root_public_key=self._root, planner_public_key=admitted.planner_public_key,
            operation_public_key=admitted.operation_public_key, configuration_digest=admitted.configuration_digest,
            activation_custody=self._custody, live_window=window, transport_deadline_ns=bound, work=work)
        _held, _grant, authorized, _payload, original_live = producer._authorize_on_work(
            **arguments, consumer_role="reserve")
        # Keep this actual original caller/grant guard around storage and IO;
        # never pass its successful return as authority to the producer/verifier.
        window = authorized.window
        bound = min(bound, authorized.deadline_ns, window[4])
        arguments.update(live_window=window, transport_deadline_ns=bound)
        current()
        locator = bootstrap.plan._frame(INPUT_IDENTITY_DOMAIN, originals, work)
        sequence, head, fence = admitted.state_predecessor
        predecessor = dict(expected_predecessor_sequence=sequence,
            expected_predecessor_head_digest=head, expected_fence=fence)
        retained = reservations.OidcSessionActivationReservationDelivery._original_for_execution_on_work(
            self._reservation, locator, **predecessor, work=work)
        current()
        if retained is None:
            produced = producer._produce_on_work(**arguments, **predecessor, computation_private_key=self._key)
            request_bytes, snapshot_bytes = produced.request_bytes, produced.snapshot_bytes
        else:
            # Original recovery is explicit and still live. Full caller/grant/
            # private plan replay precedes any resend of the exact old reserve.
            pair = producer._verify_retained_on_work(**arguments, **predecessor,
                response_originals=(retained.request_bytes, retained.snapshot_bytes, retained.receipt_bytes))
            request_bytes, snapshot_bytes = pair[:2]
        current()
        reserve_material, reserve_payload, request_identity = bootstrap.authorization._verify_request_on_work(
            request_bytes=request_bytes, enrollment_bytes=admitted.current_root_enrollment_bytes,
            root_public_key=self._root, now_epoch_ns=current(), work=work)
        # Actual signed reserve expiry can be shorter than caller/grant/launch.
        # Preserve the same opening and clip both state exchange and response.
        window = processing._narrow(window, deadline_epoch_ns=reserve_payload["expiresAtEpochNs"],
            maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
        bound = min(bound, window[4])
        current()
        if retained is None:
            identity = reservations.OidcSessionActivationReservationDelivery.enqueue(self._reservation,
                request_bytes, snapshot_bytes=snapshot_bytes, execution_record_digest=locator,
                **predecessor, live_window=window, transport_deadline_ns=bound, work=work)
            bootstrap.plan._same(identity, request_identity, work, "durable activation reserve identity changed")
        current()
        receipt = reservations.OidcSessionActivationReservationDelivery.deliver(self._reservation,
            request_identity, client=self._client, live_window=window, transport_deadline_ns=bound, work=work)
        current()
        saved = reservations.OidcSessionActivationReservationDelivery.originals(self._reservation, request_identity)
        response = transport._originals((saved.request_bytes, saved.snapshot_bytes, saved.receipt_bytes), response=True)
        for actual, wanted in zip(response, (request_bytes, snapshot_bytes, receipt)):
            producer._same_bytes(actual, wanted, work, "activation response differs from first durable originals")
        bootstrap.plan._same(saved.execution_record_digest, locator, work, "activation durable input association changed")
        # Delivery has verified and fsynced the ACK before this original-only
        # return. It does not provide an independently current pending head.
        current()
        transport._send_response(connection, response, deadline_ns=bound)
        current()
        transport._check_deadline(bound)

    def serve_once(self):
        """Idle briefly or spend this launch on one accepted connection."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._accepted or self._connection is not None:
                raise ActivationReserverStartupError("activation reserver accepted exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise ActivationReserverStartupError("activation reserver original lifetime expired")
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
                raise ActivationReserverRequestError(
                    "activation reservation outcome is not established; automatic retry is not permitted") from None
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
            raise ActivationReserverStartupError("activation reserver cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = receiving = journal = reservation = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            _descriptors_owned = True
            root_raw, root_identity = delivery._read_original(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES)
            bootstrap_raw, bootstrap_identity = delivery._read_original(delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES)
            custody_raw, custody_identity = delivery._read_original(delivery.CUSTODY_FD, delivery.MAX_CUSTODY_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from serverware import oidc_session_activation_execution_reserver_bootstrap as bootstrap
            from serverware import authority_oidc_session_activation_execution_custody as custody
            from serverware import authority_oidc_session_activation_reservation_delivery as reservations
            from serverware import authority_current_root_journal as storage
            from serverware import authority_current_root_transport as state_transport
            from serverware import authority_webauthn_evidence_plan_clock as clock
            from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES:
                raise ActivationReserverStartupError("activation reserver bootstrap bound changed")
            work = _ValidationWork(QueryReadValidationLimits())
            callback = bootstrap.authorization.production._callback
            work.charge(input_bytes=len(root_raw))
            root = callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise ActivationReserverStartupError("activation reserver root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw,
                custody_bytes=custody_raw, root_public_key=root, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"], launch["peerUid"], launch["peerGid"],
                    launch["rootPublicKeyFd"], launch["bootstrapFd"], launch["listenerFd"], launch["custodyFd"],
                    launch["bundleKeyFd"], launch["deliveryKeyFd"], launch["signingKeyFd"], launch["journalDirectoryFd"],
                    launch["listenerPath"], launch["journalDirectoryPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS,
                        delivery.LISTENER_PATH, delivery.JOURNAL_PATH)
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise ActivationReserverStartupError("activation reserver launch differs from fixed delivery")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins):
                raise ActivationReserverStartupError("activation reserver resources differ from signed pins")
            private_pins = tuple((fd, maximum, True, delivery._sealed_identity(fd, maximum, private=True))
                for fd, maximum in ((delivery.BUNDLE_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.DELIVERY_KEY_FD, delivery.MAX_RAW_KEY_BYTES), (delivery.KEY_FD, delivery.MAX_KEY_BYTES)))
            window = _construction_window(material, clock)
            bound = min(window[4], material.opening_sample[0] + material.attestation_interval[1]
                - material.opening_sample[1])
            clock._check_on_work(window, work=work)
            bundle_key, delivery_key, key = delivery._keys_on_work(material, work)
            receiving = custody.OidcSessionActivationExecutionCustody(custody_bytes=custody_raw,
                root_public_key=root, consumer_role="reserve", expected_receiver_identity=material.receiver_identity,
                bundle_key=bundle_key, delivery_custody_key=delivery_key, live_window=window,
                transport_deadline_ns=bound, work=work)
            del bundle_key, delivery_key
            configuration = custody.OidcSessionActivationExecutionCustody._snapshot_configuration(receiving)
            def open_journal():
                nonlocal journal
                # Retain cleanup ownership before the callback's suffix can
                # fail after successfully acquiring the independent flock FD.
                journal = storage.CurrentRootJournal(directory_fd=delivery.JOURNAL_FD,
                    expected_device=journal_pins[0], expected_inode=journal_pins[1],
                    expected_uid=delivery.SERVICE_UID, expected_gid=delivery.SERVICE_GID,
                    maximum_records=launch["journalMaximumRecords"])

            callback(work, open_journal)
            reservation = reservations.OidcSessionActivationReservationDelivery(journal=journal,
                enrollment_bytes=material.current_root_enrollment_bytes, root_public_key=root,
                expected_local_sequence=material.reservation_checkpoint[0],
                expected_local_head_digest=material.reservation_checkpoint[1], live_window=window,
                transport_deadline_ns=bound, work=work)
            path, timeout, _state_uid, _state_gid, peer_uid, peer_gid = material.state_endpoint
            client = state_transport.CurrentRootDecisionClient(path=path, timeout_seconds=timeout,
                expected_peer_uid=peer_uid, expected_peer_gid=peer_gid)
            sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            clock._check_on_work(window, work=work)
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            owner = object.__new__(_ReserverOwner)
            owner._material, owner._root, owner._key, owner._custody = material, root, key, receiving
            owner._custody_configuration = configuration
            owner._journal, owner._journal_fd, owner._journal_pins = journal, journal._directory_fd, journal_pins
            owner._reservation, owner._client = reservation, client
            owner._client_config = state_transport.CurrentRootDecisionClient._snapshot_configuration(client)
            owner._seal = (material, root, key, receiving, journal, reservation, client)
            owner._listener, owner._listener_pins = listener, listener_pins
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
            if isinstance(exc, ActivationReserverStartupError) or not isinstance(exc, Exception):
                raise
            raise ActivationReserverStartupError("activation reserver cold admission failed") from None


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _ReserverOwner:
            raise ActivationReserverStartupError("activation reserver has not started")
        _owner._live()
        return _owner


def close():
    """Close all adopted/owned descriptors and drop this PID's key references."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise ActivationReserverStartupError("cannot close an active activation reserver connection")
        _owner, _state = None, "closed"
        failed = False
        if owner is not None:
            owner._closed = owner._failed = True
            resources = (owner._reservation, owner._custody, owner._listener)
            owner._key = owner._root = owner._material = owner._custody = None
            owner._journal = owner._reservation = owner._client = None
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
            raise ActivationReserverStartupError("activation reserver cleanup is not established")
