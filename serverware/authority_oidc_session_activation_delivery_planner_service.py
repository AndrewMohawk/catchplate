"""One private consume-planning exchange under genuinely admitted cold custody.

Root/history originals precede private keys and resources. The actual cold owner
acquires/replays/signs/retains, verifies, or exports exact retained originals; the service
never accepts a successful material as authority. Peer admission precedes frames,
one accepted connection is terminal, and uncertainty grants no retry. This is
neither consumption SQL, token release nor independently measured custody.
"""
from __future__ import annotations

import os
import select
import socket
import threading
import time

from serverware import oidc_session_activation_delivery_planner_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None


class DeliveryPlannerStartupError(RuntimeError):
    pass


class DeliveryPlannerRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise DeliveryPlannerStartupError("forked process cannot use consume planning custody")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    if (namespace != tuple(sorted(delivery.ENVIRONMENT.items()))
            or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise DeliveryPlannerStartupError("consume planner process or literal environment differs")
    delivery.delivery._require_unprivileged_process()


def _launch(material):
    launch = material.payload["launch"]
    names = ("processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
        "rootPublicKeyFd", "bootstrapFd", "listenerFd", "historyCustodyFd", "bundleKeyFd",
        "deliveryKeyFd", "signingKeyFd", "journalKeyFd", "journalDirectoryFd",
        "executionBundleKeyFd", "executionStoreDirectoryFd", "listenerPath",
        "journalDirectoryPath", "executionStoreDirectoryPath")
    expected = (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
        delivery.PEER_UID, delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS,
        delivery.LISTENER_PATH, delivery.JOURNAL_PATH, delivery.EXECUTION_STORE_PATH)
    if (tuple(launch[name] for name in names) != expected
            or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
        raise DeliveryPlannerStartupError("consume bootstrap differs from its fixed descriptor delivery")
    return launch


class _PlannerOwner:
    __slots__ = ("_planner", "_configuration", "_listener", "_listener_pins", "_journal_fd",
        "_journal_pins", "_execution_store_fd", "_execution_store_pins", "_sealed", "_tls",
        "_opening", "_interval", "_deadline", "_age", "_skew",
        "_request_timeout", "_last_epoch", "_last_monotonic", "_closed", "_failed", "_accepted",
        "_spent", "_connection")

    def __init__(self):
        raise DeliveryPlannerStartupError("consume planning requires genuine cold original admission")

    def _live(self):
        global _state
        _require_pid()
        try:
            if (self is not _owner or _state != "started" or self._closed or self._failed
                    or _environment() != _namespace):
                raise DeliveryPlannerStartupError("consume planner singleton or original lifetime changed")
            _process(_namespace)
            for descriptor, maximum, private, original in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != original:
                    raise DeliveryPlannerStartupError("consume planner sealed original changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins
                    or delivery._execution_store(delivery.EXECUTION_STORE_FD) != self._execution_store_pins
                    or delivery._execution_store(self._execution_store_fd) != self._execution_store_pins):
                raise DeliveryPlannerStartupError("consume listener or private directory changed")
            delivery._tls_unchanged(self._tls)
            from serverware import authority_oidc_session_activation_delivery_cold_planning as cold
            from serverware import authority_oidc_session_activation_delivery_execution_store as stores

            held = self._configuration
            if (type(self._planner) is not cold._ColdPlanner
                    or cold._ColdPlanner._snapshot(self._planner) is not held
                    or cold.owner_module.OidcSessionActivationDeliveryPlanOwner._snapshot_configuration(
                        held.owner) is not held.owner_configuration
                    or cold.history_module.OidcSessionActivationHistoryCustody._snapshot_configuration(
                        held.historical) is not held.historical_configuration
                    or cold.journal_module.DeliveryOriginalJournal._snapshot_configuration(
                        held.journal) is not held.journal_configuration
                    or type(held.execution_store) is not stores.DeliveryExecutionBundleStore
                    or stores.DeliveryExecutionBundleStore._snapshot_configuration(
                        held.execution_store) is not held.execution_store_configuration
                    or held.journal._directory_fd != self._journal_fd
                    or held.execution_store._directory_fd != self._execution_store_fd
                    or self._execution_store_fd == self._journal_fd
                    or self._execution_store_pins == self._journal_pins):
                raise DeliveryPlannerStartupError("consume actual cold owner configuration changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(),
                self._journal_fd, self._execution_store_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_before, opened_epoch, opened_after = self._opening
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < self._interval[1] or after >= self._deadline
                    or not opened_epoch + before - opened_after - self._skew <= epoch
                        <= opened_epoch + after - opened_before + self._skew):
                raise DeliveryPlannerStartupError("consume original launch clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, DeliveryPlannerStartupError):
                raise
            raise DeliveryPlannerStartupError("consume planner lifecycle admission failed") from exc

    def _dispatch(self, originals, *, live_window, deadline, work):
        from serverware import authority_oidc_session_activation_delivery_cold_planning as cold
        from serverware import authority_oidc_session_activation_delivery_planner_transport as transport

        exporting = originals[0] == transport.EXPORT_PURPOSE
        bounded_prepare = originals[0] == transport.BOUNDED_PREPARE_PURPOSE
        if bounded_prepare:
            ceiling = transport._bounded_prepare_deadline_on_work(originals, work)
            # Retain the actual pre-read opening samples, policy and monotonic
            # bound. The unsigned caller ceiling only tightens this invocation;
            # it neither admits authority nor substitutes a historical clock.
            live_window = cold.processing._narrow(live_window,
                deadline_epoch_ns=ceiling, maximum_lifetime_ns=live_window[5],
                maximum_clock_skew_ns=live_window[6])
            deadline = min(deadline, live_window[4])
            cold.clock._check_on_work(live_window, work=work)
            transport._check_deadline(deadline)
        try:
            if originals[0] in (transport.PREPARE_PURPOSE, transport.BOUNDED_PREPARE_PURPOSE):
                prepared = cold._ColdPlanner.prepare(self._planner, old_token_bytes=originals[1],
                    activation_originals=originals[2:-1] if bounded_prepare else originals[2:],
                    live_window=live_window,
                    transport_deadline_ns=deadline, work=work)
                status = b"prepared"
            elif originals[0] == transport.RETAINED_PURPOSE:
                original_deadline, journal_digest = transport._retained_scope(originals, work)
                prepared = cold._ColdPlanner.verify_retained(self._planner, envelope_bytes=originals[1],
                    expected_deadline_epoch_ns=original_deadline, expected_journal_digest=journal_digest,
                    live_window=live_window, transport_deadline_ns=deadline, work=work)
                status = b"verified"
            elif exporting:
                original_deadline, journal_digest = transport._retained_scope(originals, work)
                prepared = cold._ColdPlanner.export_retained(self._planner, envelope_bytes=originals[1],
                    expected_deadline_epoch_ns=original_deadline, expected_journal_digest=journal_digest,
                    live_window=live_window, transport_deadline_ns=deadline, work=work)
                status = b"exported"
            else:
                raise DeliveryPlannerRequestError("consume planner has no requested private purpose")
            expected_type = cold.ExportedDeliveryPlan if exporting else cold.owner_module.PreparedDeliveryPlan
            if type(prepared) is not expected_type:
                raise DeliveryPlannerRequestError("consume planner returned no actual prepared originals")
            work.charge(input_bytes=len(prepared.plan_digest) + len(prepared.journal_digest))
            response = (status, prepared.request_bytes, prepared.scope_bytes, prepared.envelope_bytes)
            if exporting:
                response += (prepared.bundle_bytes,)
            response += (
                prepared.plan_digest.encode("ascii"), prepared.journal_digest.encode("ascii"))
            transport._originals(response, response=True, export=exporting)
            payload = cold.plan.contract._decode_on_work(prepared.envelope_bytes, envelope=True, work=work)["payload"]
            response_window = cold.processing._narrow(live_window,
                deadline_epoch_ns=payload["expiresAtEpochNs"],
                maximum_lifetime_ns=live_window[5], maximum_clock_skew_ns=live_window[6])
            response_deadline = min(deadline, response_window[4])
            transport._check_deadline(response_deadline)
            return response, response_window, response_deadline
        except Exception:
            # A durable append may already exist. This branch never means
            # absence, noncommit, safe retry or permission to re-sign.
            response = (b"uncertain",) + (b"",) * (6 if exporting else 5)
            return response, live_window, deadline

    def _serve_connection(self, connection):
        from serverware import authority_oidc_session_activation_delivery_planner_transport as transport
        from serverware import authority_webauthn_evidence_plan_clock as clock
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        self._live()
        work = _ValidationWork(QueryReadValidationLimits())
        window = clock._open_on_work(deadline_epoch_ns=self._interval[1],
            maximum_lifetime_ns=self._age, maximum_clock_skew_ns=self._skew, work=work)
        deadline = min(self._deadline, window[4], window[1] + self._request_timeout * 1_000_000_000)
        transport._check_deadline(deadline)
        # The transport checks peer 65532 before prefix/length/body reads.
        # It reserves both headers and maximum response before body allocation.
        originals = transport._recv_request(connection, live_window=window, deadline_ns=deadline, work=work)
        self._live()
        clock._check_on_work(window, work=work)
        if self._spent:
            raise DeliveryPlannerStartupError("consume planner cold exchange was already spent")
        self._spent = True
        response, response_window, response_deadline = self._dispatch(
            originals, live_window=window, deadline=deadline, work=work)
        self._live()
        clock._check_on_work(response_window, work=work)
        transport._send_response(connection, response, live_window=response_window,
            deadline_ns=response_deadline, work=work, export=originals[0] == transport.EXPORT_PURPOSE)
        self._live()
        clock._check_on_work(response_window, work=work)
        transport._check_deadline(response_deadline)

    def serve_once(self):
        """False is an idle poll; one accepted connection always ends the launch."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._accepted or self._spent or self._connection is not None:
                raise DeliveryPlannerStartupError("consume planner cold exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise DeliveryPlannerStartupError("consume planner original launch expired")
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
            raise DeliveryPlannerStartupError("consume planner cannot repeat cold admission")
        _state, _namespace = "initializing", _environment()
        listener = planner = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from serverware import oidc_session_activation_delivery_planner_bootstrap as bootstrap
            from serverware import authority_oidc_session_activation_delivery_cold_planning as cold
            from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if (bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES
                    or bootstrap.history.MAX_BYTES != delivery.MAX_HISTORY_BYTES):
                raise DeliveryPlannerStartupError("consume bootstrap/history byte contract changed")
            work = _ValidationWork(QueryReadValidationLimits())
            initial_window, initial_deadline = delivery._construction_on_work(work)
            # One actual bracket precedes all original reads and verification.
            work.charge(input_bytes=delivery.MAX_ROOT_BYTES + delivery.MAX_BOOTSTRAP_BYTES + delivery.MAX_HISTORY_BYTES)
            originals, sealed = [], []
            for descriptor, maximum in ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES),
                    (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES),
                    (delivery.HISTORY_FD, delivery.MAX_HISTORY_BYTES)):
                raw, identity = cold.production._callback(work,
                    lambda descriptor=descriptor, maximum=maximum: delivery._read_original(descriptor, maximum))
                cold.clock._check_on_work(initial_window, work=work)
                originals.append(raw)
                sealed.append((descriptor, maximum, False, identity))
            root_raw, bootstrap_raw, history_raw = originals
            root = cold.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise DeliveryPlannerStartupError("consume root must be independently admitted Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, history_custody_bytes=history_raw,
                root_public_key=root, live_window=initial_window, transport_deadline_ns=initial_deadline, work=work)
            payload, launch = material.payload, _launch(material)
            interval = (max(material.attestation_interval[0], material.history_material.attestation_interval[0]),
                min(material.attestation_interval[1], material.history_material.attestation_interval[1]))
            window = cold.processing._narrow(initial_window, deadline_epoch_ns=interval[1],
                maximum_lifetime_ns=payload["maximumPlanAgeNs"], maximum_clock_skew_ns=payload["maximumClockSkewNs"])
            bound = min(initial_deadline, window[4])
            current = bootstrap.shared._launch_guard(interval,
                (initial_window[1], initial_window[0], initial_window[2]),
                bootstrap.shared._processing(window, bound, work), work)
            current()
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            execution_store_pins = launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins
                    or delivery._execution_store(delivery.EXECUTION_STORE_FD) != execution_store_pins
                    or execution_store_pins == journal_pins):
                raise DeliveryPlannerStartupError("consume resources differ from original root pins")
            for descriptor, maximum in ((delivery.KEY_FD, delivery.MAX_KEY_BYTES),
                    (delivery.BUNDLE_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.DELIVERY_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.JOURNAL_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.EXECUTION_BUNDLE_KEY_FD, delivery.MAX_RAW_KEY_BYTES)):
                sealed.append((descriptor, maximum, True, delivery._sealed_identity(descriptor, maximum, private=True)))
            current()
            private, bundle_key, delivery_key, journal_key, execution_bundle_key = delivery._keys_on_work(material, work)
            current()
            work.charge(input_bytes=sum(item["byteCount"] for item in payload["tlsFiles"].values()), hashes=3)
            tls = cold.production._callback(work, lambda: delivery._tls_identity(payload["tlsFiles"]))
            current()
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            planner = cold._create_on_work(bootstrap_bytes=bootstrap_raw, history_custody_bytes=history_raw,
                root_public_key=root, planner_private_key=private, bundle_key=bundle_key,
                delivery_custody_key=delivery_key, journal_key=journal_key, journal_directory_fd=delivery.JOURNAL_FD,
                execution_bundle_key=execution_bundle_key, execution_store_directory_fd=delivery.EXECUTION_STORE_FD,
                live_window=window, transport_deadline_ns=bound, work=work)
            current()
            if type(planner) is not cold._ColdPlanner:
                raise DeliveryPlannerStartupError("consume construction returned no actual cold owner")
            configured = cold._ColdPlanner._snapshot(planner)
            for descriptor, maximum, private_flag, identity in sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private_flag) != identity:
                    raise DeliveryPlannerStartupError("consume original descriptor changed during admission")
            delivery._tls_unchanged(tls)
            final_epoch = current()
            final_monotonic = cold.production._callback(work, time.monotonic_ns)
            current()
            owner = object.__new__(_PlannerOwner)
            owner._planner, owner._configuration = planner, configured
            owner._listener, owner._listener_pins = listener, listener_pins
            owner._journal_fd, owner._journal_pins = configured.journal._directory_fd, journal_pins
            owner._execution_store_fd = configured.execution_store._directory_fd
            owner._execution_store_pins = execution_store_pins
            owner._sealed, owner._tls = tuple(sealed), tls
            owner._opening = (initial_window[1], initial_window[0], initial_window[2])
            owner._interval, owner._deadline = interval, bound
            owner._age, owner._skew = window[5], window[6]
            owner._request_timeout = launch["requestTimeoutSeconds"]
            owner._last_epoch, owner._last_monotonic = final_epoch, final_monotonic
            owner._closed, owner._failed, owner._accepted, owner._spent, owner._connection = False, False, False, False, None
            _owner, _state = owner, "started"
            owner._live()
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            for resource in (planner, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            if isinstance(exc, DeliveryPlannerStartupError):
                raise
            raise DeliveryPlannerStartupError("consume planner genuine cold admission failed") from exc


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _PlannerOwner:
            raise DeliveryPlannerStartupError("consume planner has not started")
        _owner._live()
        return _owner


def close():
    """Close actual custody/journal/export store/listener, not a memory erasure claim."""
    global _owner, _state
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise DeliveryPlannerStartupError("cannot close an active consume planner connection")
        _owner, _state = None, "closed"
        if owner is not None:
            owner._closed, owner._failed = True, True
            try:
                owner._planner.close()
            finally:
                owner._planner = owner._configuration = None
                owner._listener.close()
