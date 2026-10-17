"""One cold activation-grant exchange, with actual receiving custody.

The root-signed role/bootstrap originals precede private-key loading. One work
and clock bracket precede peer/body intake and remain through original replay,
signing and sending. Any accepted connection spends this launch, including
rejection or uncertain delivery. No reservation, SQL, history or retry occurs.
"""
from __future__ import annotations

import errno
import os
import select
import socket
import threading
import time

from catchplate import oidc_session_activation_execution_authorizer_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None
_descriptors_owned = False


class ActivationAuthorizerStartupError(RuntimeError):
    pass


class ActivationAuthorizerRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise ActivationAuthorizerStartupError("forked process cannot use the activation authorizer")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    expected = tuple(sorted({"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
        "CATCHPLATE_PROCESS_MODE": delivery.PROCESS_MODE,
        delivery.ROOT_ENV: str(delivery.ROOT_FD), delivery.BOOTSTRAP_ENV: str(delivery.BOOTSTRAP_FD)}.items()))
    if (namespace != expected or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise ActivationAuthorizerStartupError("activation authorizer process or literal environment differs")
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
    from catchplate import authority_oidc_session_activation_execution_expectations as expected
    from catchplate import authority_current_root_vector as vector

    decoded = vector.wire._decode_object(original, work=work, maximum_bytes=expected.MAX_BYTES,
        maximum_nodes=expected.MAX_NODES, maximum_depth=12)
    owned = expected._capture_on_work(decoded, work=work)
    canonical = vector.encoding._bounded_wire(owned, vector.capture._SharedLedger(work),
        maximum_bytes=expected.MAX_BYTES, maximum_nodes=expected.MAX_NODES)
    work.charge(input_bytes=len(original) + len(canonical))
    if original != canonical:
        raise ActivationAuthorizerRequestError("activation expectation originals are not canonical")
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
        raise ActivationAuthorizerStartupError("activation authorizer descriptor cleanup is not established")


class _AuthorizerOwner:
    __slots__ = ("_material", "_root", "_key", "_custody", "_custody_configuration", "_seal",
        "_listener", "_listener_pins", "_sealed", "_opening", "_interval", "_deadline",
        "_last_epoch", "_last_monotonic", "_closed", "_failed", "_accepted", "_connection")

    def __init__(self):
        raise ActivationAuthorizerStartupError("activation authorizer requires genuine cold admission")

    def _live(self):
        global _state
        from catchplate import authority_oidc_session_activation_execution_custody as custody

        _require_pid()
        try:
            if (type(self) is not _AuthorizerOwner or self is not _owner
                    or _state != "started" or self._closed or self._failed
                    or _environment() != _namespace
                    or type(self._seal) is not tuple or len(self._seal) != 4
                    or any(actual is not held for actual, held in zip(
                        (self._material, self._root, self._key, self._custody), self._seal))):
                raise ActivationAuthorizerStartupError("activation authorizer lifetime or held owner changed")
            _process(_namespace)
            for descriptor, maximum, private, identity in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                    raise ActivationAuthorizerStartupError("activation authorizer sealed originals changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or custody.OidcSessionActivationExecutionCustody._snapshot_configuration(self._custody)
                        is not self._custody_configuration):
                raise ActivationAuthorizerStartupError("activation authorizer listener or receiving custody changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno())
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_before, opened_epoch, opened_after = self._opening
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < self._interval[1] or after >= self._deadline
                    or not opened_epoch + before - opened_after <= epoch
                        <= opened_epoch + after - opened_before):
                raise ActivationAuthorizerStartupError("activation authorizer original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, ActivationAuthorizerStartupError) or not isinstance(exc, Exception):
                raise
            raise ActivationAuthorizerStartupError("activation authorizer lifecycle admission failed") from None

    def _serve_connection(self, connection):
        from catchplate import authority_oidc_session_activation_execution_authorizer_transport as transport
        from catchplate import oidc_session_activation_execution_authorizer_bootstrap as bootstrap
        from catchplate import authority_oidc_session_activation_execution_grant_production as production
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

        def current():
            nonlocal last_epoch, last_monotonic
            callback(work, self._live)
            now = clock._check_on_work(window, work=work)
            monotonic = callback(work, time.monotonic_ns)
            bootstrap.shape._integer(monotonic, minimum=1)
            if (now < last_epoch or now < self._last_epoch or monotonic < last_monotonic
                    or monotonic >= bound):
                raise ActivationAuthorizerRequestError("activation authorizer request clocks expired or reversed")
            last_epoch, last_monotonic = now, monotonic
            return now

        current()
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, bound,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise ActivationAuthorizerRequestError("activation authorizer caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=bound)
        current()
        expected = _expectations(originals[3], work)
        # Unauthenticated incoming scope can only shorten this real bracket.
        # Genuine original authorization and receiving replay must still join
        # every scope field before any grant can be signed.
        scope = expected["scope"]
        window = processing._narrow(window, deadline_epoch_ns=scope["deadlineEpochNs"],
            maximum_lifetime_ns=scope["maximumPlanAgeNs"],
            maximum_clock_skew_ns=scope["maximumClockSkewNs"])
        bound = min(bound, window[4])
        current()
        admitted = bootstrap._verify_on_work(bootstrap_bytes=material.bootstrap_bytes,
            custody_bytes=material.custody_bytes, root_public_key=self._root,
            live_window=window, transport_deadline_ns=bound, work=work)
        bootstrap.authorization.plan._same(admitted.attestation_interval, self._interval, work,
            "activation authorizer original launch interval")
        current()
        grant = production._produce_on_work(originals=originals[1:3], expectations=expected,
            before_vector_bytes=admitted.custody_material.planner.complete_root_vector_bytes,
            authorization_bytes=originals[0], authorization_enrollment_bytes=admitted.authorization_enrollment_bytes,
            grant_enrollment_bytes=admitted.grant_enrollment_bytes,
            current_root_enrollment_bytes=admitted.current_root_enrollment_bytes,
            root_public_key=self._root, planner_public_key=admitted.planner_public_key,
            operation_public_key=admitted.operation_public_key, authorizer_private_key=self._key,
            configuration_digest=admitted.configuration_digest, activation_custody=self._custody,
            live_window=window, transport_deadline_ns=bound, work=work)
        current()
        # This is the actual same-call producer output, not received authority.
        # Its original expiry additionally bounds transmission and final return.
        payload = bootstrap.grants._read(grant, enrollment=False, work=work)["payload"]
        window = processing._narrow(window, deadline_epoch_ns=payload["expiresAtEpochNs"],
            maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
        bound = min(bound, window[4])
        current()
        transport._send_response(connection, grant, deadline_ns=bound)
        current()
        transport._check_deadline(bound)

    def serve_once(self):
        """Wait briefly, or spend this launch on exactly one accepted connection."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._accepted or self._connection is not None:
                raise ActivationAuthorizerStartupError("activation authorizer accepted exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise ActivationAuthorizerStartupError("activation authorizer original lifetime expired")
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
                raise ActivationAuthorizerRequestError(
                    "activation grant delivery is not established; automatic retry is not permitted") from None
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
            raise ActivationAuthorizerStartupError("activation authorizer cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = receiving = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            _descriptors_owned = True
            root_raw, root_identity = delivery._read_original(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES)
            bootstrap_raw, bootstrap_identity = delivery._read_original(delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES)
            custody_raw, custody_identity = delivery._read_original(delivery.CUSTODY_FD, delivery.MAX_CUSTODY_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from catchplate import oidc_session_activation_execution_authorizer_bootstrap as bootstrap
            from catchplate import authority_oidc_session_activation_execution_custody as custody
            from catchplate import authority_webauthn_evidence_plan_clock as clock
            from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES:
                raise ActivationAuthorizerStartupError("activation authorizer bootstrap bound changed")
            work = _ValidationWork(QueryReadValidationLimits())
            callback = bootstrap.authorization.production._callback
            work.charge(input_bytes=len(root_raw))
            root = callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise ActivationAuthorizerStartupError("activation authorizer root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw,
                custody_bytes=custody_raw, root_public_key=root, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["peerUid"], launch["peerGid"], launch["rootPublicKeyFd"], launch["bootstrapFd"],
                    launch["listenerFd"], launch["custodyFd"], launch["bundleKeyFd"], launch["deliveryKeyFd"],
                    launch["signingKeyFd"], launch["listenerPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS, delivery.LISTENER_PATH)
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise ActivationAuthorizerStartupError("activation authorizer launch differs from fixed delivery")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            if delivery._listener(delivery.LISTENER_FD) != listener_pins:
                raise ActivationAuthorizerStartupError("activation authorizer listener differs from signed pins")
            private_pins = tuple((fd, maximum, True, delivery._sealed_identity(fd, maximum, private=True))
                for fd, maximum in ((delivery.BUNDLE_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.DELIVERY_KEY_FD, delivery.MAX_RAW_KEY_BYTES), (delivery.KEY_FD, delivery.MAX_KEY_BYTES)))
            window = _construction_window(material, clock)
            bound = min(window[4], material.opening_sample[0] + material.attestation_interval[1]
                - material.opening_sample[1])
            clock._check_on_work(window, work=work)
            bundle_key, delivery_key, key = delivery._keys_on_work(material, work)
            receiving = custody.OidcSessionActivationExecutionCustody(custody_bytes=custody_raw,
                root_public_key=root, consumer_role="grant", expected_receiver_identity=material.receiver_identity,
                bundle_key=bundle_key, delivery_custody_key=delivery_key, live_window=window,
                transport_deadline_ns=bound, work=work)
            del bundle_key, delivery_key
            configuration = custody.OidcSessionActivationExecutionCustody._snapshot_configuration(receiving)
            sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            clock._check_on_work(window, work=work)
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            owner = object.__new__(_AuthorizerOwner)
            owner._material, owner._root, owner._key, owner._custody = material, root, key, receiving
            owner._custody_configuration = configuration
            owner._seal = (material, root, key, receiving)
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
            if isinstance(exc, ActivationAuthorizerStartupError) or not isinstance(exc, Exception):
                raise
            raise ActivationAuthorizerStartupError("activation authorizer cold admission failed") from None


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _AuthorizerOwner:
            raise ActivationAuthorizerStartupError("activation authorizer has not started")
        _owner._live()
        return _owner


def close():
    """Drop key references and close this PID's adopted descriptors and owners."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise ActivationAuthorizerStartupError("cannot close an active activation authorizer connection")
        _owner, _state = None, "closed"
        failed = False
        if owner is not None:
            owner._closed = owner._failed = True
            resources = (owner._custody, owner._listener)
            owner._key = owner._root = owner._material = owner._custody = None
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
            raise ActivationAuthorizerStartupError("activation authorizer cleanup is not established")
