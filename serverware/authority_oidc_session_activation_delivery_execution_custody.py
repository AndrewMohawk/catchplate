"""Independent consume-grant receiving keys and live original replay.

Only the fixed grant receiver may construct this owner from root-signed
originals and actual private keys. Every replay reauthenticates those originals
and independently bound expectations. No planner owner, received result, key
return, grant issuance, SQL privilege or historical execution renewal is here.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import os
import threading

from serverware import oidc_session_activation_delivery_execution_custody_bootstrap as bootstrap
from serverware import authority_oidc_session_activation_delivery_execution_replay as replay
from serverware import authority_oidc_session_activation_history_custody as history
from serverware import authority_successor_execution_window as processing


registration, evidence, clock = replay.registration, replay.evidence, replay.clock
_LOCK_TYPE = type(threading.Lock())
_SUBJECT = (("delivery_id", "deliveryId"), ("user_id", "userId"), ("session_id", "sessionId"),
    ("credential_id", "credentialId"), ("credential_record_id", "credentialRecordId"),
    ("challenge_id", "challengeId"))


class DeliveryExecutionCustodyError(ValueError):
    pass


def _fail(message):
    raise DeliveryExecutionCustodyError(message)


def _process():
    if (os.getresuid() != (bootstrap.SERVICE_UID,) * 3
            or os.getresgid() != (bootstrap.SERVICE_GID,) * 3 or os.getgroups()
            or os.environ.get("SERVERWARE_PROCESS_MODE") != bootstrap.PROCESS_MODE):
        _fail("consume receiving custody requires its fixed grant process")


def _identity(value, work):
    ledger = evidence.capture._SharedLedger(work)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=1024).visit(value)
    evidence._identity(owned)
    return evidence.capability._wire(owned, ledger, 1024, 7)


def _key_bindings(material, execution, historical, delivery, work):
    for key in (execution, historical, delivery):
        if type(key) is not bytes or len(key) != replay.bundle.KEY_BYTES:
            _fail("consume receiving keys must be exact immutable originals")
    work.charge(input_bytes=6 * replay.bundle.KEY_BYTES)
    if execution in (historical, delivery) or historical == delivery:
        _fail("consume receiving encryption purposes are not separate")
    for key, name in ((execution, "executionBundleKeyDigest"),
            (historical, "historicalBundleKeyDigest"), (delivery, "deliveryKeyDigest")):
        registration._same(bootstrap.planner_bootstrap._sha(key, work), material.payload[name],
            work, "consume receiving actual key differs from independent root pin")


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
        _fail("consume receiving historical owner configuration changed")
    history.OidcSessionActivationHistoryCustody.require_consume_grant_on_work(configured.historical, work=work)
    for left, right, label in (
            (_identity(material.receiver_identity, work), configured.receiver_identity_bytes, "receiver identity"),
            (actual.receiver_identity_bytes, configured.receiver_identity_bytes, "history receiver identity"),
            (actual.custody_bytes, configured.receiving_history_custody_bytes, "history original"),
            (material.planner.state_enrollment_bytes, configured.state_enrollment_bytes, "state enrollment")):
        replay._bytes_equal(left, right, work, label)
    registration._same(evidence.keys._spki_on_work(actual.root_public_key, work),
        evidence.keys._spki_on_work(configured.root_public_key, work), work, "consume receiving historical root")
    registration._same(material.attestation_interval, configured.attestation_interval, work,
        "consume receiving original launch interval")
    registration._same((material.planner.payload["maximumPlanAgeNs"],
        material.planner.payload["maximumClockSkewNs"]),
        (configured.maximum_age_ns, configured.maximum_clock_skew_ns), work,
        "consume receiving original processing policy")
    history.OidcSessionActivationHistoryCustody.bind_consume_request_on_work(configured.historical,
        expected_consume_request=material.planner.payload["consumeRequest"], work=work)
    _key_bindings(material, configured.execution_bundle_key, actual.bundle_key, actual.delivery_key, work)


def _expectations(material, owned, before, work):
    payload, scope = material.planner.payload, owned["scope"]
    registration._same(owned["request"], payload["consumeRequest"], work,
        "consume receiving independent request differs from root scope")
    fixed = {name: payload[name] for name in ("authenticationPolicy", "trustPolicy",
        "configurationDigest", "maximumPlanAgeNs", "maximumClockSkewNs")}
    fixed.update({"plannerIdentity": payload["planner"]["identity"],
        "plannerSpkiDigest": payload["planner"]["spkiDigest"]})
    fixed.update({name: payload["consumeRequest"]["arguments"][argument] for argument, name in _SUBJECT})
    work.prepare_copy(fixed)
    registration._same({name: scope[name] for name in fixed}, fixed, work,
        "consume receiving independently expected policy or subject differs")
    registration._integer(scope["deadlineEpochNs"], "consume original scope deadline", 1)
    replay._bytes_equal(before, material.planner.complete_root_vector_bytes, work,
        "root-admitted complete before vector")


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationDeliveryExecutionCustody:
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
        if type(self) is not OidcSessionActivationDeliveryExecutionCustody:
            _fail("consume receiving custody requires its exact owner class")
        outer = bootstrap.authorization._original(custody_bytes, bootstrap.MAX_BYTES, "consume receiving custody")
        planner, planning_history, receiving_history = bootstrap._originals(planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes, outer_bytes=len(outer))
        root, execution, historical_key, delivery = (
            root_public_key, execution_bundle_key, historical_bundle_key, delivery_custody_key)
        receiver = _identity(expected_receiver_identity, work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "consume receiving construction deadline", 1)
        bound = min(window[4], transport_deadline_ns)
        bootstrap.authorization._public(root)
        for key in (execution, historical_key, delivery):
            if type(key) is not bytes or len(key) != replay.bundle.KEY_BYTES:
                _fail("consume receiving construction requires exact private key originals")
        _process()
        _window, current = replay.lifetime._window(window, bound, work)
        current()
        material = bootstrap._verify_on_work(custody_bytes=outer, planner_bootstrap_bytes=planner,
            planner_history_custody_bytes=planning_history, receiving_history_custody_bytes=receiving_history,
            root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
        current()
        replay._bytes_equal(_identity(material.receiver_identity, work), receiver, work,
            "independent consume receiving identity")
        _key_bindings(material, execution, historical_key, delivery, work)
        current()
        historical = None
        try:
            historical = history.OidcSessionActivationHistoryCustody.for_consume_grant(
                custody_bytes=receiving_history, root_public_key=root, expected_receiver_identity=material.receiver_identity,
                expected_consume_request=material.planner.payload["consumeRequest"], bundle_key=historical_key,
                delivery_custody_key=delivery, live_window=window, transport_deadline_ns=bound, work=work)
            configured = _Configuration(replay.contract.authority.SOURCE_REVISION, outer, planner,
                planning_history, receiving_history, root, execution, historical,
                history.OidcSessionActivationHistoryCustody._snapshot_configuration(historical),
                receiver, material.planner.state_enrollment_bytes, material.attestation_interval,
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
            if historical is not None:
                history.OidcSessionActivationHistoryCustody.close(historical)
            raise

    def _snapshot_configuration(self):
        if (type(self) is not OidcSessionActivationDeliveryExecutionCustody or self._closed
                or self._pid != os.getpid() or type(self._lock) is not _LOCK_TYPE
                or type(self._configured) is not _Configuration or self._configured is not self._seal
                or self._configured.source_revision != replay.contract.authority.SOURCE_REVISION):
            _fail("consume receiving custody is closed, changed or belongs to another process")
        _process()
        if history.OidcSessionActivationHistoryCustody._snapshot_configuration(
                self._configured.historical) is not self._configured.historical_configuration:
            _fail("consume receiving historical owner changed")
        return self._configured

    def _bounds(self, configured, window, deadline, work):
        narrowed = processing._narrow(window, deadline_epoch_ns=configured.attestation_interval[1],
            maximum_lifetime_ns=configured.maximum_age_ns,
            maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
        bound = min(deadline, narrowed[4], configured.opening_sample[0]
            + configured.attestation_interval[1] - configured.opening_sample[1])
        return history.OidcSessionActivationHistoryCustody.processing_bounds_on_work(configured.historical,
            live_window=narrowed, transport_deadline_ns=bound, work=work)

    def _guard(self, configured, window, bound, work):
        _window, inherited = replay.lifetime._window(window, bound, work)

        def current():
            if self._snapshot_configuration() is not configured:
                _fail("consume receiving lifecycle changed")
            sample = bootstrap._fresh(configured.attestation_interval, work, opening=configured.opening_sample)
            now = inherited()
            if (sample[0] < self._last_monotonic or sample[1] < self._last_epoch
                    or sample[2] >= bound or now < sample[1]):
                _fail("consume receiving clocks expired or reversed")
            object.__setattr__(self, "_last_epoch", now)
            object.__setattr__(self, "_last_monotonic", sample[2])
            self._snapshot_configuration()
            return now

        return current

    def bind_context_on_work(self, *, root_public_key, current_root_enrollment_bytes, work):
        """Static exact-original join only; not fresh receiving authorization."""
        root = root_public_key
        original = replay.state._original(current_root_enrollment_bytes,
            replay.state.head.authorization.MAX_ENROLLMENT_BYTES, "consume receiving state enrollment")
        bootstrap.authorization._public(root)
        configured = self._snapshot_configuration()
        registration._same(evidence.keys._spki_on_work(root, work),
            evidence.keys._spki_on_work(configured.root_public_key, work), work, "consume receiving root")
        replay._bytes_equal(original, configured.state_enrollment_bytes, work, "consume receiving enrollment")
        if self._snapshot_configuration() is not configured:
            _fail("consume receiving configuration changed during context join")

    def replay_on_work(self, *, envelope_bytes, encrypted_originals_bytes, expectations,
            before_vector_bytes, live_window, transport_deadline_ns, work):
        evidence.capture._SharedLedger(work)
        envelope = replay.state._original(envelope_bytes, replay.contract.MAX_BYTES, "known consume plan")
        ciphertext = replay.bundle._bounded_frame(encrypted_originals_bytes)
        before = replay.state._original(before_vector_bytes, replay.state.vector.MAX_BYTES, "complete before vector")
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "consume receiving inherited deadline", 1)
        owned = replay.expectations._capture_on_work(expectations, work=work)
        configured = self._snapshot_configuration()
        if sum(len(raw) for raw in (envelope, ciphertext, before, configured.custody_bytes,
                configured.planner_bootstrap_bytes, configured.planner_history_custody_bytes,
                configured.receiving_history_custody_bytes)) > replay.MAX_ORIGINAL_BYTES:
            _fail("consume receiving originals exceed their aggregate bound")
        if not self._lock.acquire(blocking=False):
            _fail("consume receiving custody is already in use")
        try:
            window, bound = self._bounds(configured, window, min(window[4], transport_deadline_ns), work)
            current = self._guard(configured, window, bound, work)
            current()
            material = _verify(configured, window, bound, work)
            current()
            _join(configured, material, work)
            _expectations(material, owned, before, work)
            narrowed = processing._narrow(window, deadline_epoch_ns=owned["scope"]["deadlineEpochNs"],
                maximum_lifetime_ns=configured.maximum_age_ns,
                maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
            bound = min(bound, narrowed[4])
            current = self._guard(configured, narrowed, bound, work)
            current()
            payload = material.planner.payload
            actual = replay._replay_on_work(envelope_bytes=envelope, encrypted_originals_bytes=ciphertext,
                expected_request=owned["request"], expected_scope=owned["scope"],
                expected_journal_digest=owned["journalDigest"],
                state_enrollment_bytes=material.planner.state_enrollment_bytes, before_vector_bytes=before,
                activation_expectations=payload["activationExpectations"], activation_scope=payload["activationScope"],
                planner_public_key=material.planner.planner_public_key,
                activation_planner_public_key=material.history.planner.planner_public_key,
                operation_public_key=configured.root_public_key, state_root_public_key=configured.root_public_key,
                historical_custody=configured.historical, bundle_key=configured.execution_bundle_key,
                live_window=narrowed, transport_deadline_ns=bound, work=work)
            if type(actual) is not replay._ReplayedDelivery:
                _fail("consume receiving replay returned another result type")
            first, middle, last = current(), actual.live(), current()
            if not first <= middle <= last or last >= actual.valid_until_epoch_ns:
                _fail("consume receiving original replay expired or clocks reversed")

            def live():
                lock = self._lock
                if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
                    _fail("consume receiving custody is already in use")
                try:
                    first, middle, last = current(), actual.live(), current()
                    if not first <= middle <= last or last >= actual.valid_until_epoch_ns:
                        _fail("consume receiving replay expired or clocks reversed after return")
                    return last
                finally:
                    lock.release()

            # Same-call projection only. No receiving/issuance input accepts
            # this object in place of original signatures and proof replay.
            return replace(actual, live=live)
        finally:
            self._lock.release()

    def close(self):
        if type(self) is not OidcSessionActivationDeliveryExecutionCustody or self._pid != os.getpid():
            _fail("consume receiving custody cannot close in another process")
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("consume receiving custody is already in use")
        try:
            if self._closed:
                return
            configured = self._configured
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_configured", None)
            object.__setattr__(self, "_seal", None)
            history.OidcSessionActivationHistoryCustody.close(configured.historical)
        finally:
            lock.release()
