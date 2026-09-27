"""Root-original-admitted activation receiving keys; no SQL or token release.

Only dedicated unprivileged receiver identities may hold this private owner.
Every replay reauthenticates both receiving and planner bootstrap originals,
then invokes actual live original replay. No receipt, object, label or result
can replace that work. Keys never enter JSON, packets or return values.
"""
from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass

from serverware import oidc_session_activation_execution_custody_bootstrap as bootstrap
from serverware import authority_oidc_session_activation_execution_expectations as expectations_capture
from serverware import authority_oidc_session_activation_execution_replay as replay
from serverware import authority_successor_execution_window as processing_window


evidence, registration, clock = replay.evidence, replay.registration, replay.clock
_LOCK_TYPE = type(threading.Lock())


class ActivationExecutionCustodyError(ValueError):
    pass


def _fail(message):
    raise ActivationExecutionCustodyError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    source_revision: str
    custody_bytes: bytes
    root_public_key: object
    consumer_role: str
    bundle_key: bytes
    delivery_key: bytes
    state_enrollment_bytes: bytes
    attestation_interval: tuple
    opening_sample: tuple
    receiver_identity_bytes: bytes


def _receiver_identity_on_work(value, work):
    ledger = evidence.capture._SharedLedger(work)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=1024).visit(value)
    evidence._identity(owned)
    return evidence.capability._wire(owned, ledger, 1024, 7)


def _key_bindings(material, bundle_key, delivery_key, work):
    work.charge(input_bytes=64)
    if bundle_key == delivery_key:
        _fail("activation receiving custody keys share a private purpose")
    for raw, expected in ((bundle_key, material.planner.bundle_key_digest),
            (delivery_key, material.planner.delivery_key_digest)):
        work.charge(hashes=1, input_bytes=len(raw))
        actual = evidence.production._callback(work, lambda raw=raw: "sha256:" + hashlib.sha256(raw).hexdigest())
        registration._same(actual, expected, work, "independently admitted receiving key")


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationExecutionCustody:
    _configured: _Configuration | None
    _seal: _Configuration | None
    _pid: int
    _lock: object
    _closed: bool
    _last_epoch: int
    _last_monotonic: int

    def __init__(self, *, custody_bytes, root_public_key, consumer_role, expected_receiver_identity,
            bundle_key, delivery_custody_key, work, live_window=None, transport_deadline_ns=None):
        evidence.capture._SharedLedger(work)
        if (type(custody_bytes) is not bytes or not 2 <= len(custody_bytes) <= bootstrap.MAX_BYTES
                or type(consumer_role) is not str or consumer_role not in bootstrap.CONSUMERS
                or type(bundle_key) is not bytes or len(bundle_key) != replay.bundle.KEY_BYTES
                or type(delivery_custody_key) is not bytes or len(delivery_custody_key) != 32):
            _fail("activation receiving custody requires bounded independent originals")
        original, root, role, bundle, delivery = (
            custody_bytes, root_public_key, consumer_role, bundle_key, delivery_custody_key)
        window = None if live_window is None else clock._validate(live_window)
        deadline = transport_deadline_ns
        receiver_identity_bytes = _receiver_identity_on_work(expected_receiver_identity, work)
        replay.plan.state.head.authorization._public(root)
        _process(role)
        inherited = bootstrap.planner_bootstrap._processing(window, deadline, work)
        inherited()
        material = bootstrap._verify_on_work(custody_bytes=original, root_public_key=root,
            expected_consumer_role=role, live_window=window,
            transport_deadline_ns=deadline, work=work)
        current = bootstrap.planner_bootstrap._launch_guard(material.attestation_interval,
            material.opening_sample, inherited, work)
        current()
        replay._bytes_equal(_receiver_identity_on_work(material.receiver_identity, work),
            receiver_identity_bytes, work, "independent receiving runtime identity")
        _key_bindings(material, bundle, delivery, work)
        current()
        configured = _Configuration(replay.contract.authority.SOURCE_REVISION, original, root, role,
            bundle, delivery, material.planner.state_enrollment_bytes,
            material.attestation_interval, material.opening_sample,
            receiver_identity_bytes=receiver_identity_bytes)
        object.__setattr__(self, "_configured", configured)
        object.__setattr__(self, "_seal", configured)
        object.__setattr__(self, "_pid", os.getpid())
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_last_epoch", material.opening_sample[1])
        object.__setattr__(self, "_last_monotonic", material.opening_sample[2])
        self._snapshot_configuration()
        current()

    def _snapshot_configuration(self):
        if (type(self) is not OidcSessionActivationExecutionCustody or self._closed
                or self._pid != os.getpid() or type(self._lock) is not _LOCK_TYPE
                or type(self._configured) is not _Configuration or self._configured is not self._seal
                or self._configured.source_revision != replay.contract.authority.SOURCE_REVISION):
            _fail("activation receiving custody is closed, changed or belongs to another process")
        _process(self._configured.consumer_role)
        return self._configured

    def bind_context_on_work(self, *, root_public_key, current_root_enrollment_bytes, work):
        """Join static independent originals; this never admits a live replay."""
        configured = self._snapshot_configuration()
        original = replay.plan.state._original(current_root_enrollment_bytes,
            replay.plan.state.head.authorization.MAX_ENROLLMENT_BYTES, "receiving state enrollment")
        replay.plan.state.head.authorization._public(root_public_key)
        registration._same(evidence.keys._spki_on_work(root_public_key, work),
            evidence.keys._spki_on_work(configured.root_public_key, work), work, "receiving authority root")
        replay._bytes_equal(original, configured.state_enrollment_bytes, work, "receiving state enrollment")
        if self._snapshot_configuration() is not configured:
            _fail("activation receiving configuration changed during context binding")

    def replay_on_work(self, *, originals, expectations, planner_public_key, operation_public_key,
            before_vector_bytes, live_window, transport_deadline_ns, work):
        evidence.capture._SharedLedger(work)
        if type(originals) is not tuple or len(originals) != 2:
            _fail("activation receiving custody requires exact signed-plan/ciphertext originals")
        envelope = replay.plan.state._original(originals[0], replay.contract.MAX_BYTES, "signed plan")
        ciphertext = replay.bundle._bounded_frame(originals[1])
        before = replay.plan.state._original(before_vector_bytes, replay.plan.state.vector.MAX_BYTES, "complete vector")
        owned = expectations_capture._capture_on_work(expectations, work=work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "activation receiving inherited deadline", 1)
        planner_key, operation_key = planner_public_key, operation_public_key
        replay.plan.state.head.authorization._public(planner_key)
        replay.plan.state.head.authorization._public(operation_key)
        configured = self._snapshot_configuration()
        if (sum(len(raw) for raw in (envelope, ciphertext, before, configured.custody_bytes,
                configured.state_enrollment_bytes)) > replay.MAX_ORIGINAL_BYTES):
            _fail("activation receiving originals exceed the existing aggregate bound")
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("activation receiving custody is already in use")
        try:
            opening, interval = configured.opening_sample, configured.attestation_interval
            bound = min(window[4], transport_deadline_ns, opening[0] + interval[1] - opening[1])
            _window, live = replay.delivery._window(window, bound, work)

            def current():
                if self._snapshot_configuration() is not configured:
                    _fail("activation receiving configuration changed during replay")
                sample = bootstrap.planner_bootstrap._fresh(interval, work, opening=opening)
                now = live()
                if (sample[0] < self._last_monotonic or sample[1] < self._last_epoch
                        or sample[2] >= bound or now < sample[1]):
                    _fail("activation receiving original clocks expired or reversed")
                object.__setattr__(self, "_last_epoch", now)
                object.__setattr__(self, "_last_monotonic", sample[2])
                self._snapshot_configuration()
                return now

            current()
            material = bootstrap._verify_on_work(custody_bytes=configured.custody_bytes,
                root_public_key=configured.root_public_key, expected_consumer_role=configured.consumer_role,
                live_window=window, transport_deadline_ns=bound, work=work)
            registration._same(material.attestation_interval, interval, work, "original receiving interval")
            replay._bytes_equal(_receiver_identity_on_work(material.receiver_identity, work),
                configured.receiver_identity_bytes, work, "independent receiving runtime identity")
            admitted = material.planner
            _key_bindings(material, configured.bundle_key, configured.delivery_key, work)
            evidence.keys._public_binding(planner_key, admitted.planner_spki_digest, work)
            registration._same(evidence.keys._spki_on_work(operation_key, work),
                evidence.keys._spki_on_work(configured.root_public_key, work), work, "activation state root")
            replay._bytes_equal(before, admitted.complete_root_vector_bytes, work, "root-admitted complete vector")
            replay._bytes_equal(admitted.state_enrollment_bytes, configured.state_enrollment_bytes,
                work, "original receiving state enrollment")
            scope = owned["scope"]
            fixed = {"configurationDigest": admitted.configuration_digest,
                "plannerSpkiDigest": admitted.planner_spki_digest, "plannerIdentity": admitted.planner_identity,
                "rpId": admitted.rp_id, "origin": admitted.origin,
                "authenticationPolicy": admitted.authn_policy, "trustPolicy": admitted.trust_policy,
                "maximumPlanAgeNs": admitted.maximum_plan_age_ns,
                "maximumClockSkewNs": admitted.maximum_clock_skew_ns}
            work.prepare_copy(fixed)
            registration._same({name: scope[name] for name in fixed}, fixed, work, "root-admitted receiving policy")
            narrowed = processing_window._narrow(window,
                deadline_epoch_ns=min(scope["deadlineEpochNs"], interval[1]),
                maximum_lifetime_ns=admitted.maximum_plan_age_ns,
                maximum_clock_skew_ns=admitted.maximum_clock_skew_ns)
            bound = min(bound, narrowed[4])
            # Keep the same opening and sticky owner samples, including through
            # the final owner suffix, under the newly narrowed clock policy.
            _window, live = replay.delivery._window(narrowed, bound, work)
            current()
            actual = replay._replay_on_work(envelope_bytes=envelope, encrypted_originals_bytes=ciphertext,
                expected_request=owned["request"], expected_scope=scope,
                expected_journal_digest=owned["journalDigest"], planner_public_key=planner_key,
                state_enrollment_bytes=admitted.state_enrollment_bytes,
                state_root_public_key=configured.root_public_key, bundle_key=configured.bundle_key,
                delivery_custody_key=configured.delivery_key, before_vector_bytes=before,
                live_window=narrowed, transport_deadline_ns=bound, work=work)
            clock._check_on_work(narrowed, work=work)
            if current() >= actual.original_interval[1]:
                _fail("activation original authority expired after receiving replay")
            return actual
        finally:
            lock.release()

    def close(self):
        if type(self) is not OidcSessionActivationExecutionCustody or self._pid != os.getpid():
            _fail("activation receiving custody cannot close in another process")
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("activation receiving custody is already in use")
        try:
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_configured", None)
            object.__setattr__(self, "_seal", None)
        finally:
            lock.release()


def _process(role):
    process_mode, uid, gid = bootstrap.CONSUMERS[role]
    if (os.getresuid() != (uid,) * 3 or os.getresgid() != (gid,) * 3 or os.getgroups()
            or os.environ.get("SERVERWARE_PROCESS_MODE") != process_mode):
        _fail("activation receiving process differs from its dedicated root-admitted identity")
