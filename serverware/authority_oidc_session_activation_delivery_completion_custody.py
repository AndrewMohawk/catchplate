"""Process-bound private history custody for consume completion only.

Genuine fresh root originals admit three distinct AES purposes and historical
planner scope. Every protected use reauthenticates those originals; no live SQL
receiver, key-only object or successful replay carrier can substitute. Returned
guards retain the actual current processing allowance, never old plan expiry.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import os
import threading

from serverware import oidc_session_activation_delivery_completion_custody_bootstrap as bootstrap
from serverware import authority_oidc_session_activation_delivery_execution_custody as neutral
from serverware import authority_oidc_session_activation_delivery_execution_authorization as caller
from serverware import authority_oidc_session_activation_delivery_execution_grant as grants


history, replay, processing = neutral.history, neutral.replay, neutral.processing
registration, evidence, clock = neutral.registration, neutral.evidence, neutral.clock
_LOCK_TYPE = type(threading.Lock())


class DeliveryCompletionCustodyError(ValueError):
    pass


def _fail(message):
    raise DeliveryCompletionCustodyError(message)


def _process():
    if (os.getresuid() != (bootstrap.SERVICE_UID,) * 3
            or os.getresgid() != (bootstrap.SERVICE_GID,) * 3 or os.getgroups()
            or os.environ.get("SERVERWARE_PROCESS_MODE") != bootstrap.PROCESS_MODE):
        _fail("consume completion custody requires its distinct fixed process")


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    source_revision: str
    custody_bytes: bytes
    planner_bootstrap_bytes: bytes
    planner_history_custody_bytes: bytes
    receiving_history_custody_bytes: bytes
    root_public_key: object
    execution_bundle_key: bytes
    historical: object
    historical_configuration: object
    receiver_identity_bytes: bytes
    state_enrollment_bytes: bytes
    before_vector_bytes: bytes
    consume_request_bytes: bytes
    planner_interval: tuple
    planning_history_interval: tuple
    attestation_interval: tuple
    opening_sample: tuple
    maximum_age_ns: int
    maximum_clock_skew_ns: int


def _verify(configured, window, bound, work):
    return bootstrap._verify_on_work(custody_bytes=configured.custody_bytes,
        planner_bootstrap_bytes=configured.planner_bootstrap_bytes,
        planner_history_custody_bytes=configured.planner_history_custody_bytes,
        receiving_history_custody_bytes=configured.receiving_history_custody_bytes,
        root_public_key=configured.root_public_key, live_window=window,
        transport_deadline_ns=bound, work=work)


def _join(configured, material, work):
    actual = history.OidcSessionActivationHistoryCustody._snapshot_configuration(configured.historical)
    if actual is not configured.historical_configuration:
        _fail("consume completion nested history owner changed")
    history.OidcSessionActivationHistoryCustody.require_consume_completion_on_work(configured.historical, work=work)
    for left, right, label in (
            (neutral._identity(material.receiver_identity, work), configured.receiver_identity_bytes, "receiver identity"),
            (actual.receiver_identity_bytes, configured.receiver_identity_bytes, "nested receiver identity"),
            (actual.custody_bytes, configured.receiving_history_custody_bytes, "nested root original"),
            (material.planner.state_enrollment_bytes, configured.state_enrollment_bytes, "state enrollment"),
            (material.planner.complete_root_vector_bytes, configured.before_vector_bytes, "complete vector"),
            (material.planner.consume_request_bytes, configured.consume_request_bytes, "root-bound request")):
        replay._bytes_equal(left, right, work, label)
    registration._same(evidence.keys._spki_on_work(actual.root_public_key, work),
        evidence.keys._spki_on_work(configured.root_public_key, work), work, "consume completion root")
    registration._same((material.attestation_interval, material.planner.attestation_interval,
        material.planner.history_material.attestation_interval),
        (configured.attestation_interval, configured.planner_interval, configured.planning_history_interval),
        work, "consume completion original intervals")
    registration._same((material.planner.payload["maximumPlanAgeNs"],
        material.planner.payload["maximumClockSkewNs"]),
        (configured.maximum_age_ns, configured.maximum_clock_skew_ns), work,
        "consume completion original processing policy")
    history.OidcSessionActivationHistoryCustody.bind_consume_request_on_work(configured.historical,
        expected_consume_request=material.planner.payload["consumeRequest"], work=work)
    neutral._key_bindings(material, configured.execution_bundle_key, actual.bundle_key, actual.delivery_key, work)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationDeliveryCompletionCustody:
    _configured: _Configuration | None
    _seal: _Configuration | None
    _pid: int
    _lock: object
    _closed: bool
    _last_epoch: int
    _last_monotonic: int

    def __init__(self, *, custody_bytes, planner_bootstrap_bytes, planner_history_custody_bytes,
            receiving_history_custody_bytes, root_public_key, expected_receiver_identity,
            execution_bundle_key, historical_bundle_key, delivery_custody_key,
            live_window, transport_deadline_ns, work):
        evidence.capture._SharedLedger(work)
        if type(self) is not OidcSessionActivationDeliveryCompletionCustody:
            _fail("consume completion requires its exact owner class")
        original = caller.authorization._original(custody_bytes, bootstrap.MAX_BYTES,
            "consume completion custody original")
        planner, planning, receiving = bootstrap._originals(planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes, outer_bytes=len(original))
        root, execution, historical_key, delivery = (
            root_public_key, execution_bundle_key, historical_bundle_key, delivery_custody_key)
        caller.authorization._public(root)
        for key in (execution, historical_key, delivery):
            if type(key) is not bytes or len(key) != replay.bundle.KEY_BYTES:
                _fail("consume completion keys require exact immutable originals")
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "consume completion inherited deadline", 1)
        bound = min(window[4], transport_deadline_ns)
        receiver = neutral._identity(expected_receiver_identity, work)
        _process()
        current = bootstrap.shared._processing(window, bound, work)
        current()
        material = bootstrap._verify_on_work(custody_bytes=original,
            planner_bootstrap_bytes=planner, planner_history_custody_bytes=planning,
            receiving_history_custody_bytes=receiving, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work)
        current()
        replay._bytes_equal(neutral._identity(material.receiver_identity, work), receiver,
            work, "independent completion receiver")
        neutral._key_bindings(material, execution, historical_key, delivery, work)
        nested = None
        try:
            nested = history.OidcSessionActivationHistoryCustody.for_consume_completion(
                custody_bytes=receiving, root_public_key=root, expected_receiver_identity=material.receiver_identity,
                expected_consume_request=material.planner.payload["consumeRequest"], bundle_key=historical_key,
                delivery_custody_key=delivery, live_window=window, transport_deadline_ns=bound, work=work)
            configured = _Configuration(replay.contract.authority.SOURCE_REVISION, original, planner, planning,
                receiving, root, execution, nested,
                history.OidcSessionActivationHistoryCustody._snapshot_configuration(nested), receiver,
                material.planner.state_enrollment_bytes, material.planner.complete_root_vector_bytes,
                material.planner.consume_request_bytes, material.planner.attestation_interval,
                material.planner.history_material.attestation_interval, material.attestation_interval,
                material.opening_sample, material.planner.payload["maximumPlanAgeNs"],
                material.planner.payload["maximumClockSkewNs"])
            object.__setattr__(self, "_configured", configured)
            object.__setattr__(self, "_seal", configured)
            object.__setattr__(self, "_pid", os.getpid())
            object.__setattr__(self, "_lock", threading.Lock())
            object.__setattr__(self, "_closed", False)
            object.__setattr__(self, "_last_epoch", material.opening_sample[1])
            object.__setattr__(self, "_last_monotonic", material.opening_sample[2])
            _join(configured, material, work)
            narrowed, deadline = self._bounds(configured, window, bound, work)
            self._guard(configured, narrowed, deadline, work)()
            current()
        except BaseException:
            if nested is not None:
                history.OidcSessionActivationHistoryCustody.close(nested)
            raise

    def _snapshot_configuration(self):
        if (type(self) is not OidcSessionActivationDeliveryCompletionCustody or self._closed
                or self._pid != os.getpid() or type(self._lock) is not _LOCK_TYPE
                or type(self._configured) is not _Configuration or self._configured is not self._seal
                or self._configured.source_revision != replay.contract.authority.SOURCE_REVISION):
            _fail("consume completion custody is closed, changed or belongs to another process")
        _process()
        if history.OidcSessionActivationHistoryCustody._snapshot_configuration(
                self._configured.historical) is not self._configured.historical_configuration:
            _fail("consume completion history custody changed")
        return self._configured

    def require_completion_on_work(self, *, work):
        evidence.capture._SharedLedger(work)
        configured = self._snapshot_configuration()
        history.OidcSessionActivationHistoryCustody.require_consume_completion_on_work(configured.historical, work=work)

    def _bounds(self, configured, window, deadline, work):
        narrowed = processing._narrow(window, deadline_epoch_ns=configured.attestation_interval[1],
            maximum_lifetime_ns=configured.maximum_age_ns,
            maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
        bound = min(deadline, narrowed[4], configured.opening_sample[0]
            + configured.attestation_interval[1] - configured.opening_sample[1])
        return history.OidcSessionActivationHistoryCustody.processing_bounds_on_work(configured.historical,
            live_window=narrowed, transport_deadline_ns=bound, work=work)

    def _guard(self, configured, window, bound, work):
        inherited = bootstrap.shared._processing(window, bound, work)

        def current():
            if self._snapshot_configuration() is not configured:
                _fail("consume completion configuration changed")
            sample = bootstrap._fresh(configured.attestation_interval, work, opening=configured.opening_sample)
            now = inherited()
            if (sample[0] < self._last_monotonic or sample[1] < self._last_epoch
                    or sample[2] >= bound or now < sample[1]):
                _fail("consume completion clocks expired or reversed")
            object.__setattr__(self, "_last_epoch", now)
            object.__setattr__(self, "_last_monotonic", sample[2])
            self._snapshot_configuration()
            return now

        return current

    def _reauthenticate_locked(self, configured, window, bound, work):
        window, bound = self._bounds(configured, window, bound, work)
        current = self._guard(configured, window, bound, work)
        current()
        material = _verify(configured, window, bound, work)
        current()
        _join(configured, material, work)
        nested = history.OidcSessionActivationHistoryCustody.check_on_work(configured.historical,
            live_window=window, transport_deadline_ns=bound, work=work)

        def checked():
            first, middle, last = current(), nested(), current()
            if not first <= middle <= last:
                _fail("consume completion nested clocks reversed")
            return last

        checked()
        return material, window, bound, checked

    def _retained_guard(self, current, continuation=None):
        def checked():
            lock = self._lock
            if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
                _fail("consume completion custody is already in use")
            try:
                first = current()
                if continuation is not None:
                    middle, last = continuation(), current()
                    if not first <= middle <= last:
                        _fail("consume completion exchange clocks reversed")
                    return last
                return first
            finally:
                lock.release()
        return checked

    def bind_context_on_work(self, *, root_public_key, current_root_enrollment_bytes, work):
        root = root_public_key
        original = caller.authorization._original(current_root_enrollment_bytes,
            caller.authorization.MAX_ENROLLMENT_BYTES, "consume completion state enrollment")
        caller.authorization._public(root)
        configured = self._snapshot_configuration()
        if not self._lock.acquire(blocking=False):
            _fail("consume completion custody is already in use")
        try:
            registration._same(evidence.keys._spki_on_work(root, work),
                evidence.keys._spki_on_work(configured.root_public_key, work), work, "consume completion root")
            replay._bytes_equal(original, configured.state_enrollment_bytes, work, "consume completion enrollment")
            if self._snapshot_configuration() is not configured:
                _fail("consume completion changed during static context binding")
        finally:
            self._lock.release()

    def processing_bounds_on_work(self, *, live_window, transport_deadline_ns, work):
        evidence.capture._SharedLedger(work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "consume completion inherited deadline", 1)
        configured = self._snapshot_configuration()
        if not self._lock.acquire(blocking=False):
            _fail("consume completion custody is already in use")
        try:
            _material, narrowed, bound, current = self._reauthenticate_locked(
                configured, window, min(window[4], transport_deadline_ns), work)
            current()
            return narrowed, bound
        finally:
            self._lock.release()

    def check_on_work(self, *, live_window, transport_deadline_ns, work):
        evidence.capture._SharedLedger(work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "consume completion inherited deadline", 1)
        configured = self._snapshot_configuration()
        if not self._lock.acquire(blocking=False):
            _fail("consume completion custody is already in use")
        try:
            _material, _window, _bound, current = self._reauthenticate_locked(
                configured, window, min(window[4], transport_deadline_ns), work)
            result = self._retained_guard(current)
            current()
            return result
        finally:
            self._lock.release()

    def verify_exchange_on_work(self, *, originals, expectations, before_vector_bytes,
            authorization_bytes, grant_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
            current_root_enrollment_bytes, root_public_key, planner_public_key, operation_public_key,
            configuration_digest, live_window, transport_deadline_ns, work):
        from serverware import authority_oidc_session_activation_delivery_history_exchange as exchange

        evidence.capture._SharedLedger(work)
        if type(originals) is not tuple or len(originals) != 2:
            _fail("consume completion requires exact signed-plan/ciphertext originals")
        envelope = caller.authorization._original(originals[0], replay.contract.MAX_BYTES, "historical consume plan")
        ciphertext = replay.bundle._bounded_frame(originals[1])
        before = caller.authorization._original(before_vector_bytes, replay.state.vector.MAX_BYTES,
            "consume completion complete vector")
        caller_raw = caller.authorization._original(authorization_bytes, caller.MAX_AUTHORIZATION_BYTES,
            "historical consume caller")
        grant_raw = caller.authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "historical consume grant")
        caller_enrollment = caller.authorization._original(authorization_enrollment_bytes,
            caller.MAX_ENROLLMENT_BYTES, "historical consume caller enrollment")
        grant_enrollment = caller.authorization._original(grant_enrollment_bytes,
            caller.enrollments.MAX_ENROLLMENT_BYTES, "historical consume grant enrollment")
        state_enrollment = caller.authorization._original(current_root_enrollment_bytes,
            caller.authorization.MAX_ENROLLMENT_BYTES, "consume completion state enrollment")
        root, planner, operation_key, config = root_public_key, planner_public_key, operation_public_key, configuration_digest
        for key in (root, planner, operation_key):
            caller.authorization._public(key)
        registration._digest(config)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "consume completion inherited deadline", 1)
        configured = self._snapshot_configuration()
        if sum(len(raw) for raw in (envelope, ciphertext, before, caller_raw, grant_raw,
                caller_enrollment, grant_enrollment, state_enrollment, configured.custody_bytes,
                configured.planner_bootstrap_bytes, configured.planner_history_custody_bytes,
                configured.receiving_history_custody_bytes)) > replay.MAX_ORIGINAL_BYTES:
            _fail("consume completion originals exceed the existing aggregate bound")
        owned = caller.expectations_wire._capture_on_work(expectations, work=work)
        if not self._lock.acquire(blocking=False):
            _fail("consume completion custody is already in use")
        try:
            material, window, bound, current = self._reauthenticate_locked(
                configured, window, min(window[4], transport_deadline_ns), work)
            registration._same(evidence.keys._spki_on_work(root, work),
                evidence.keys._spki_on_work(configured.root_public_key, work), work, "consume completion root")
            registration._same(evidence.keys._spki_on_work(operation_key, work),
                evidence.keys._spki_on_work(configured.root_public_key, work), work, "consume completion operation key")
            payload = material.planner.payload
            evidence.keys._public_binding(planner, payload["planner"]["spkiDigest"], work)
            registration._same(config, payload["configurationDigest"], work, "consume completion configuration")
            replay._bytes_equal(state_enrollment, configured.state_enrollment_bytes, work, "independent state enrollment")
            neutral._expectations(material, owned, before, work)
            current()
            actual = exchange._verify_on_work(originals=(envelope, ciphertext), expectations=owned,
                before_vector_bytes=before, authorization_bytes=caller_raw, grant_bytes=grant_raw,
                authorization_enrollment_bytes=caller_enrollment, grant_enrollment_bytes=grant_enrollment,
                current_root_enrollment_bytes=state_enrollment, root_public_key=root,
                planner_public_key=planner, operation_public_key=operation_key, configuration_digest=config,
                activation_expectations=payload["activationExpectations"], activation_scope=payload["activationScope"],
                activation_planner_public_key=material.history.planner.planner_public_key,
                historical_custody=configured.historical, bundle_key=configured.execution_bundle_key,
                live_window=window, transport_deadline_ns=bound, work=work)
            if type(actual) is not exchange._HistoricalExchange:
                _fail("consume completion requires actual same-call historical exchange")
            issued, expires = actual.replayed.original_interval
            for interval in (configured.planner_interval, configured.planning_history_interval):
                if not interval[0] <= issued < expires <= interval[1]:
                    _fail("historical consume plan escapes its original planning authority")
            replay._bytes_equal(actual.replayed.before_vector_bytes, configured.before_vector_bytes,
                work, "replayed independent complete vector")
            registration._same(actual.replayed.request, owned["request"], work, "replayed independent consume request")
            first, middle, last = current(), actual.live(), current()
            if not first <= middle <= last:
                _fail("consume completion clocks reversed after historical exchange")
            result = replace(actual, live=self._retained_guard(current, actual.live))
            current()
            return result
        finally:
            self._lock.release()

    def close(self):
        if type(self) is not OidcSessionActivationDeliveryCompletionCustody or self._pid != os.getpid():
            _fail("consume completion custody cannot close in another process")
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("consume completion custody is already in use")
        try:
            configured = self._configured
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_configured", None)
            object.__setattr__(self, "_seal", None)
            if configured is not None:
                history.OidcSessionActivationHistoryCustody.close(configured.historical)
        finally:
            lock.release()
