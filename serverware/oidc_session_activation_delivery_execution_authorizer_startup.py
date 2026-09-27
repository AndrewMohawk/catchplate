"""One cold consume-grant exchange under independently admitted receiving custody.

Construction retains its original clock bracket through idle and request work.
The sole accepted request gets one bounded allowance before peer/body intake;
all original admission, private replay, signing and sending share that allowance.
No successful input carrier, generic grant fallback, retry or SQL is accepted.
"""
from __future__ import annotations

import errno
import os
import select
import socket
import threading
import time

from serverware import oidc_session_activation_delivery_execution_authorizer_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None
_descriptors_owned = False


class DeliveryExecutionAuthorizerStartupError(RuntimeError):
    pass


class DeliveryExecutionAuthorizerRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise DeliveryExecutionAuthorizerStartupError("forked process cannot use the consume authorizer")


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
        raise DeliveryExecutionAuthorizerStartupError("consume authorizer process or literal environment differs")
    delivery.delivery._require_unprivileged_process()


def _policy(material):
    planner = material.custody_material.planner.payload
    return (min(material.maximum_authorization_age_ns, planner["maximumPlanAgeNs"]),
        min(material.maximum_authorization_clock_skew_ns, planner["maximumClockSkewNs"]))


def _admit(originals, root, window, bound, work):
    from serverware import oidc_session_activation_delivery_execution_authorizer_bootstrap as bootstrap

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
        raise DeliveryExecutionAuthorizerRequestError("consume expectation originals are not canonical")
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
        raise DeliveryExecutionAuthorizerStartupError("consume authorizer descriptor cleanup is not established")


class _AuthorizerOwner:
    __slots__ = ("_material", "_root", "_key", "_custody", "_custody_configuration", "_originals", "_seal",
        "_listener", "_listener_pins", "_sealed", "_startup_window", "_inherited_deadline", "_opening", "_interval", "_deadline",
        "_last_epoch", "_last_monotonic", "_closed", "_failed", "_accepted", "_connection")

    def __init__(self):
        raise DeliveryExecutionAuthorizerStartupError("consume authorizer requires genuine cold admission")

    def _live(self):
        global _state
        from serverware import authority_oidc_session_activation_delivery_execution_custody as custody

        _require_pid()
        try:
            held = (self._material, self._root, self._key, self._custody, self._originals,
                self._startup_window, self._inherited_deadline, self._listener, self._listener_pins, self._sealed)
            if (type(self) is not _AuthorizerOwner or self is not _owner or _state != "started"
                    or self._closed or self._failed or _environment() != _namespace
                    or type(self._seal) is not tuple or len(self._seal) != len(held)
                    or any(actual is not original for actual, original in zip(held, self._seal))
                    or self._opening is not self._material.opening_sample
                    or self._interval is not self._material.attestation_interval
                    or self._deadline != min(self._inherited_deadline, self._startup_window[4],
                        self._opening[0] + self._interval[1] - self._opening[1])):
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer lifetime or held configuration changed")
            _process(_namespace)
            for descriptor, maximum, private, identity in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                    raise DeliveryExecutionAuthorizerStartupError("consume authorizer sealed originals changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or custody.OidcSessionActivationDeliveryExecutionCustody._snapshot_configuration(self._custody)
                        is not self._custody_configuration):
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer listener or receiving custody changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno())
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
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
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, DeliveryExecutionAuthorizerStartupError) or not isinstance(exc, Exception):
                raise
            raise DeliveryExecutionAuthorizerStartupError("consume authorizer lifecycle admission failed") from None

    def _serve_connection(self, connection):
        from serverware import authority_oidc_session_activation_delivery_execution_authorizer_transport as transport
        from serverware import oidc_session_activation_delivery_execution_authorizer_bootstrap as bootstrap
        from serverware import authority_oidc_session_activation_delivery_execution_grant_production as production
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

        def current():
            nonlocal last_epoch, last_monotonic
            callback(work, self._live)
            now = clock._check_on_work(window, work=work)
            monotonic = callback(work, time.monotonic_ns)
            bootstrap.shape._integer(monotonic, minimum=1)
            if (now < last_epoch or now < self._last_epoch or monotonic < last_monotonic
                    or monotonic >= bound):
                raise DeliveryExecutionAuthorizerRequestError("consume authorizer request clocks expired or reversed")
            last_epoch, last_monotonic = now, monotonic
            return now

        current()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, bound,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise DeliveryExecutionAuthorizerRequestError("consume authorizer caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=bound)
        current()
        expected = _expectations(originals[3], work)
        # Received scope is still untrusted data. It may only shorten the real
        # opening; original role/caller/custody admission must establish it.
        scope = expected["scope"]
        window = processing._narrow(window, deadline_epoch_ns=scope["deadlineEpochNs"],
            maximum_lifetime_ns=scope["maximumPlanAgeNs"],
            maximum_clock_skew_ns=scope["maximumClockSkewNs"])
        bound = min(bound, window[4])
        current()
        admitted = _admit(self._originals, self._root, window, bound, work)
        bootstrap.authorization.plan._same(admitted.attestation_interval, self._interval, work,
            "consume authorizer original launch interval")
        bootstrap.authorization.plan._same(admitted.launch, material.launch, work,
            "consume authorizer original launch scope")
        current()
        grant = production._produce_on_work(authorization_bytes=originals[0],
            authorization_enrollment_bytes=admitted.authorization_enrollment_bytes,
            current_root_enrollment_bytes=admitted.current_root_enrollment_bytes,
            grant_enrollment_bytes=admitted.grant_enrollment_bytes, root_public_key=self._root,
            configuration_digest=admitted.configuration_digest, planner_public_key=admitted.planner_public_key,
            operation_public_key=admitted.operation_public_key, originals=originals[1:3], expectations=expected,
            before_vector_bytes=admitted.custody_material.planner.complete_root_vector_bytes,
            receiving_custody=self._custody, live_window=window, transport_deadline_ns=bound,
            private_key=self._key, work=work)
        current()
        # Read only the genuine same-call output to narrow transport. This is
        # not another proof replay, nor admission of an incoming grant carrier.
        payload = production.contract._read_on_work(grant, work)["payload"]
        window = processing._narrow(window, deadline_epoch_ns=payload["expiresAtEpochNs"],
            maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
        bound = min(bound, window[4])
        current()
        transport._send_response(connection, grant, deadline_ns=bound)
        current()
        transport._check_deadline(bound)
        return current

    def serve_once(self):
        """Wait briefly, or spend the launch on its one accepted connection."""
        global _state
        _require_pid()
        with _LOCK:
            self._live()
            if self._accepted or self._connection is not None:
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer original lifetime expired")
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
                # The same request guard survives socket cleanup; even a slow
                # native close cannot turn expired delivery into a success.
                final_current()
                return True
            except Exception:
                raise DeliveryExecutionAuthorizerRequestError(
                    "consume grant delivery is not established; automatic retry is not permitted") from None
            finally:
                if _state == "started":
                    _state = "spent"


def initialize_from_environment(*, work, live_window, transport_deadline_ns):
    """Continue root delivery in its original, permanently dropped process.

    The caller supplies the actual ledger/window opened before root/key I/O;
    no default cold allowance or post-exec replacement exists. Admission still
    reauthenticates every sealed original rather than accepting material DTOs.
    """
    global _state, _owner, _namespace, _descriptors_owned
    _require_pid()
    with _LOCK:
        if _state == "started":
            return require_started()
        if _state != "new":
            raise DeliveryExecutionAuthorizerStartupError("consume authorizer cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = receiving = None
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from serverware import oidc_session_activation_delivery_execution_authorizer_bootstrap as bootstrap
            from serverware import authority_oidc_session_activation_delivery_execution_custody as custody
            from serverware import authority_successor_execution_window as processing
            from serverware import authority_webauthn_evidence_plan_clock as clock
            from serverware.authority_query_read_work import _ValidationWork

            if type(work) is not _ValidationWork:
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer requires the actual inherited startup work")
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
                    raise DeliveryExecutionAuthorizerStartupError("consume authorizer construction environment changed")
                _process(_namespace)
                now = clock._check_on_work(window, work=work)
                monotonic = callback(work, time.monotonic_ns)
                bootstrap.shape._integer(monotonic, minimum=1)
                if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                    raise DeliveryExecutionAuthorizerStartupError("consume authorizer construction clocks expired or reversed")
                last_epoch, last_monotonic = now, monotonic
                return now

            current()
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            _descriptors_owned = True
            maxima = (delivery.MAX_BOOTSTRAP_BYTES, delivery.MAX_CUSTODY_BYTES,
                delivery.MAX_PLANNER_BOOTSTRAP_BYTES, delivery.MAX_PLANNER_HISTORY_CUSTODY_BYTES,
                delivery.MAX_RECEIVING_HISTORY_CUSTODY_BYTES)
            if maxima != (bootstrap.MAX_BYTES, bootstrap.MAX_CUSTODY_BYTES,
                    bootstrap.MAX_PLANNER_BOOTSTRAP_BYTES, bootstrap.MAX_PLANNER_HISTORY_CUSTODY_BYTES,
                    bootstrap.MAX_RECEIVING_HISTORY_CUSTODY_BYTES):
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer original bounds changed")
            descriptors = (delivery.BOOTSTRAP_FD, delivery.CUSTODY_FD, delivery.PLANNER_BOOTSTRAP_FD,
                delivery.PLANNER_HISTORY_CUSTODY_FD, delivery.RECEIVING_HISTORY_CUSTODY_FD)
            public_originals, public_pins = [], []
            for descriptor, maximum in ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES), *zip(descriptors, maxima)):
                current()
                raw, identity = delivery._read_on_work(descriptor, maximum, work)
                public_originals.append(raw)
                public_pins.append((descriptor, maximum, False, identity))
                current()
            root_raw, originals = public_originals[0], tuple(public_originals[1:])
            root = callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer root must be Ed25519")
            current()
            material = _admit(originals, root, window, bound, work)
            current()
            launch = material.launch
            fd_fields = ("rootPublicKeyFd", "bootstrapFd", "listenerFd", "custodyFd", "plannerBootstrapFd",
                "plannerHistoryCustodyFd", "receivingHistoryCustodyFd", "executionBundleKeyFd",
                "historicalBundleKeyFd", "deliveryKeyFd", "signingKeyFd")
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["peerUid"], launch["peerGid"], launch["listenerPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, delivery.LISTENER_PATH)
                    or tuple(launch[name] for name in fd_fields) != delivery.INHERITED_DESCRIPTORS
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer launch differs from fixed delivery")
            age, skew = _policy(material)
            window = processing._narrow(window, deadline_epoch_ns=material.attestation_interval[1],
                maximum_lifetime_ns=age, maximum_clock_skew_ns=skew)
            bound = min(bound, window[4], material.opening_sample[0]
                + material.attestation_interval[1] - material.opening_sample[1])
            current()
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            if delivery._listener(delivery.LISTENER_FD) != listener_pins:
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer listener differs from signed pins")
            private_pins = tuple((fd, maximum, True, delivery._sealed_identity(fd, maximum, private=True))
                for fd, maximum in ((delivery.EXECUTION_BUNDLE_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.HISTORICAL_BUNDLE_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.DELIVERY_KEY_FD, delivery.MAX_RAW_KEY_BYTES), (delivery.KEY_FD, delivery.MAX_KEY_BYTES)))
            current()
            execution_key, historical_key, delivery_key, key = delivery._keys_on_work(material, work)
            current()
            receiving = custody.OidcSessionActivationDeliveryExecutionCustody(custody_bytes=originals[1],
                planner_bootstrap_bytes=originals[2], planner_history_custody_bytes=originals[3],
                receiving_history_custody_bytes=originals[4], root_public_key=root,
                expected_receiver_identity=material.receiver_identity, execution_bundle_key=execution_key,
                historical_bundle_key=historical_key, delivery_custody_key=delivery_key,
                live_window=window, transport_deadline_ns=bound, work=work)
            del execution_key, historical_key, delivery_key
            current()
            configuration = custody.OidcSessionActivationDeliveryExecutionCustody._snapshot_configuration(receiving)
            sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            current()
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            current()
            owner = object.__new__(_AuthorizerOwner)
            owner._material, owner._root, owner._key, owner._custody = material, root, key, receiving
            owner._custody_configuration, owner._originals = configuration, originals
            owner._listener, owner._listener_pins = listener, listener_pins
            owner._sealed = (*public_pins, *private_pins)
            owner._startup_window = window
            owner._inherited_deadline = inherited_deadline
            owner._opening, owner._interval = material.opening_sample, material.attestation_interval
            owner._deadline = bound
            owner._last_epoch, owner._last_monotonic = sample[1], sample[2]
            owner._closed = owner._failed = owner._accepted = False
            owner._connection = None
            owner._seal = (material, root, key, receiving, originals, window, inherited_deadline,
                listener, listener_pins, owner._sealed)
            _owner, _state = owner, "started"
            owner._live()
            final_epoch = current()
            if final_epoch < owner._last_epoch or last_monotonic < owner._last_monotonic:
                raise DeliveryExecutionAuthorizerStartupError("consume authorizer clocks reversed at construction return")
            owner._last_epoch, owner._last_monotonic = final_epoch, last_monotonic
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            for resource in (receiving, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            try:
                _close_inherited()
            except BaseException:
                pass
            if isinstance(exc, DeliveryExecutionAuthorizerStartupError) or not isinstance(exc, Exception):
                raise
            raise DeliveryExecutionAuthorizerStartupError("consume authorizer cold admission failed") from None


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _AuthorizerOwner:
            raise DeliveryExecutionAuthorizerStartupError("consume authorizer has not started")
        _owner._live()
        return _owner


def close():
    """Drop key references and close only this PID's adopted descriptors/owners."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise DeliveryExecutionAuthorizerStartupError("cannot close an active consume authorizer connection")
        _owner, _state = None, "closed"
        failed = False
        if owner is not None:
            owner._closed = owner._failed = True
            resources = (owner._custody, owner._listener)
            owner._key = owner._root = owner._material = owner._custody = None
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
            raise DeliveryExecutionAuthorizerStartupError("consume authorizer cleanup is not established")
