"""Distinct root-admitted historical activation custody; no live execution.

Separate fixed completion-history and consume-purpose processes may hold these
AES originals under their own fresh root-signed purposes. Each consume profile
binds an independently expected original request; v6 permits historical consume
completion only, while live consume gates remain restricted to v2-v5.
Every entrypoint requiring current authority reauthenticates the fresh outer
bootstrap; expired planner policy remains original metadata, never a clock or
renewed launch. No material/result carrier is accepted in place of originals.
"""
from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass, replace

from serverware import oidc_session_activation_history_custody_bootstrap as bootstrap
from serverware import authority_oidc_session_activation_history_exchange as exchange
from serverware import authority_successor_execution_window as processing_window


history, caller = exchange.history, exchange.caller
evidence, registration, clock = history.evidence, history.registration, history.clock
_LOCK_TYPE = type(threading.Lock())


class OidcSessionActivationHistoryCustodyError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationHistoryCustodyError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    source_revision: str
    custody_bytes: bytes
    root_public_key: object
    bundle_key: bytes
    delivery_key: bytes
    state_enrollment_bytes: bytes
    complete_vector_bytes: bytes
    policy_bytes: bytes
    maximum_age_ns: int
    maximum_clock_skew_ns: int
    planner_interval: tuple
    attestation_interval: tuple
    opening_sample: tuple
    receiver_identity_bytes: bytes
    consume_planning: bool
    consume_request_bytes: bytes | None
    consumer_role: str


def _identity(value, work):
    ledger = evidence.capture._SharedLedger(work)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=1024).visit(value)
    evidence._identity(owned)
    return evidence.capability._wire(owned, ledger, 1024, 7)


def _policy(material, work):
    value = {"configurationDigest": material.configuration_digest,
        "plannerSpkiDigest": material.planner_spki_digest, "plannerIdentity": material.planner_identity,
        "rpId": material.rp_id, "origin": material.origin,
        "authenticationPolicy": material.authn_policy, "trustPolicy": material.trust_policy,
        "maximumPlanAgeNs": material.maximum_plan_age_ns,
        "maximumClockSkewNs": material.maximum_clock_skew_ns}
    return evidence.capability._wire(value, evidence.capture._SharedLedger(work),
        history.assertion.MAX_CONTEXT_BYTES, history.assertion.MAX_CONTEXT_NODES)


def _key_bindings(material, bundle, delivery, work):
    work.charge(input_bytes=64)
    if bundle == delivery:
        _fail("historical activation private key purposes coincide")
    for raw, expected in ((bundle, material.bundle_key_digest), (delivery, material.delivery_key_digest)):
        work.charge(hashes=1, input_bytes=len(raw))
        actual = evidence.production._callback(work, lambda raw=raw: "sha256:" + hashlib.sha256(raw).hexdigest())
        registration._same(actual, expected, work, "root-admitted historical custody key")


def _process(consume):
    return _process_for_purpose(bootstrap._purpose_from_consume(consume))


def _process_for_purpose(purpose):
    _schema, _payload, _operation, _role, mode, uid, gid = bootstrap._purpose_profile(purpose)
    if (os.getresuid() != (uid,) * 3 or os.getresgid() != (gid,) * 3 or os.getgroups()
            or os.environ.get("SERVERWARE_PROCESS_MODE") != mode):
        _fail("historical activation custody requires its fixed purpose process")


def _verifier(purpose):
    bootstrap._purpose_profile(purpose)
    if purpose == bootstrap.CONSUMER_ROLE:
        return bootstrap._verify_on_work
    if purpose == bootstrap.CONSUME_CONSUMER_ROLE:
        return bootstrap._verify_consume_on_work
    if purpose == bootstrap.CONSUME_GRANT_CONSUMER_ROLE:
        return bootstrap._verify_consume_grant_on_work
    if purpose == bootstrap.CONSUME_RESERVE_CONSUMER_ROLE:
        return bootstrap._verify_consume_reserve_on_work
    if purpose == bootstrap.CONSUME_SQL_ISSUER_CONSUMER_ROLE:
        return bootstrap._verify_consume_sql_issuer_on_work
    if purpose == bootstrap.CONSUME_COMPLETION_CONSUMER_ROLE:
        return bootstrap._verify_consume_completion_on_work
    _fail("historical activation custody has no verifier for this purpose")


def _activation_binding(configured, request, work):
    """Join original activation data to the independently root-bound consume."""
    if not bootstrap._requires_consume_request(configured.consumer_role):
        return
    consume = evidence.wire._decode_object(configured.consume_request_bytes, work=work,
        maximum_bytes=bootstrap.MAX_CONSUME_REQUEST_BYTES,
        maximum_nodes=history.assertion.MAX_CONTEXT_NODES, maximum_depth=12)
    if request["operation"] != history.OPERATION:
        _fail("consume history requires original activation semantics")
    actual, expected = request["arguments"], consume["arguments"]
    for field in ("user_id", "session_id", "credential_id", "credential_record_id", "challenge_id",
            "old_token_digest", "new_token_digest", "assertion_digest"):
        registration._same(actual[field], expected[field], work,
            "consume history root-bound activation " + field)
    delivery_id = history.plan.core._deterministic_uuid(operation=history.OPERATION,
        request_digest=request["requestDigest"], purpose=history.plan.transition.DELIVERY_PURPOSE, work=work)
    registration._same(delivery_id, expected["delivery_id"], work,
        "consume history root-bound original activation delivery")


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationHistoryCustody:
    _configured: _Configuration | None
    _seal: _Configuration | None
    _pid: int
    _lock: object
    _closed: bool
    _last_epoch: int
    _last_monotonic: int

    def __init__(self, *, custody_bytes, root_public_key, expected_receiver_identity,
            bundle_key, delivery_custody_key, live_window, transport_deadline_ns, work):
        self._initialize(custody_bytes=custody_bytes, root_public_key=root_public_key,
            expected_receiver_identity=expected_receiver_identity, bundle_key=bundle_key,
            delivery_custody_key=delivery_custody_key, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work, purpose=bootstrap.CONSUMER_ROLE,
            expected_consume_request=None)

    @classmethod
    def for_consume_planning(cls, *, custody_bytes, root_public_key, expected_receiver_identity,
            expected_consume_request, bundle_key, delivery_custody_key, live_window,
            transport_deadline_ns, work, _current=None):
        """Fixed v2 factory; never reinterpret a completion owner or material."""
        if cls is not OidcSessionActivationHistoryCustody:
            _fail("consume history requires the exact configured owner class")
        owner = object.__new__(cls)
        owner._initialize(custody_bytes=custody_bytes, root_public_key=root_public_key,
            expected_receiver_identity=expected_receiver_identity,
            expected_consume_request=expected_consume_request, bundle_key=bundle_key,
            delivery_custody_key=delivery_custody_key, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work,
            purpose=bootstrap.CONSUME_CONSUMER_ROLE, _current=_current)
        return owner

    @classmethod
    def for_consume_grant(cls, *, custody_bytes, root_public_key, expected_receiver_identity,
            expected_consume_request, bundle_key, delivery_custody_key, live_window,
            transport_deadline_ns, work):
        """Fixed v3 receiving purpose; never relabel a v1/v2 owner or material."""
        if cls is not OidcSessionActivationHistoryCustody:
            _fail("consume-grant history requires the exact configured owner class")
        owner = object.__new__(cls)
        owner._initialize(custody_bytes=custody_bytes, root_public_key=root_public_key,
            expected_receiver_identity=expected_receiver_identity,
            expected_consume_request=expected_consume_request, bundle_key=bundle_key,
            delivery_custody_key=delivery_custody_key, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work,
            purpose=bootstrap.CONSUME_GRANT_CONSUMER_ROLE)
        return owner

    @classmethod
    def for_consume_reserve(cls, *, custody_bytes, root_public_key, expected_receiver_identity,
            expected_consume_request, bundle_key, delivery_custody_key, live_window,
            transport_deadline_ns, work):
        """Fixed v4 reserve history; no grant/planning owner can be relabeled."""
        if cls is not OidcSessionActivationHistoryCustody:
            _fail("consume reserve history requires its exact owner class")
        owner = object.__new__(cls)
        owner._initialize(custody_bytes=custody_bytes, root_public_key=root_public_key,
            expected_receiver_identity=expected_receiver_identity,
            expected_consume_request=expected_consume_request, bundle_key=bundle_key,
            delivery_custody_key=delivery_custody_key, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work,
            purpose=bootstrap.CONSUME_RESERVE_CONSUMER_ROLE)
        return owner

    @classmethod
    def for_consume_sql_issuer(cls, *, custody_bytes, root_public_key, expected_receiver_identity,
            expected_consume_request, bundle_key, delivery_custody_key, live_window,
            transport_deadline_ns, work):
        """Fixed v5 pending receiver history; this factory does not issue SQL."""
        if cls is not OidcSessionActivationHistoryCustody:
            _fail("consume SQL-issuer history requires its exact owner class")
        owner = object.__new__(cls)
        owner._initialize(custody_bytes=custody_bytes, root_public_key=root_public_key,
            expected_receiver_identity=expected_receiver_identity,
            expected_consume_request=expected_consume_request, bundle_key=bundle_key,
            delivery_custody_key=delivery_custody_key, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work,
            purpose=bootstrap.CONSUME_SQL_ISSUER_CONSUMER_ROLE)
        return owner

    @classmethod
    def for_consume_completion(cls, *, custody_bytes, root_public_key, expected_receiver_identity,
            expected_consume_request, bundle_key, delivery_custody_key, live_window,
            transport_deadline_ns, work):
        """Fixed v6 historical consume-completion purpose, never live execution."""
        if cls is not OidcSessionActivationHistoryCustody:
            _fail("consume completion history requires its exact owner class")
        owner = object.__new__(cls)
        owner._initialize(custody_bytes=custody_bytes, root_public_key=root_public_key,
            expected_receiver_identity=expected_receiver_identity,
            expected_consume_request=expected_consume_request, bundle_key=bundle_key,
            delivery_custody_key=delivery_custody_key, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work,
            purpose=bootstrap.CONSUME_COMPLETION_CONSUMER_ROLE)
        return owner

    def _initialize(self, *, custody_bytes, root_public_key, expected_receiver_identity,
            bundle_key, delivery_custody_key, live_window, transport_deadline_ns, work,
            purpose, expected_consume_request, _current=None):
        evidence.capture._SharedLedger(work)
        if type(self) is not OidcSessionActivationHistoryCustody:
            _fail("historical activation custody requires its exact owner class")
        consume = bootstrap._requires_consume_request(purpose)
        original = caller.authorization._original(custody_bytes, bootstrap.MAX_BYTES,
            "historical activation custody bootstrap")
        root, bundle, delivery = root_public_key, bundle_key, delivery_custody_key
        caller.authorization._public(root)
        if (type(bundle) is not bytes or len(bundle) != 32
                or type(delivery) is not bytes or len(delivery) != 32):
            _fail("historical activation custody requires exact independent private keys")
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "historical custody inherited deadline", 1)
        bound = min(window[4], transport_deadline_ns)
        receiver = _identity(expected_receiver_identity, work)
        expected_request = (bootstrap._consume_request_on_work(expected_consume_request, work)
            if consume else None)
        _process_for_purpose(purpose)
        _window, processing = history.delivery._window(window, bound, work)
        processing = history.delivery._join_current(processing, _current, work)
        processing()
        verify = _verifier(purpose)
        material = verify(custody_bytes=original, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work)
        processing()
        registration._same(material.consumer_role, purpose, work, "historical receiving purpose")
        history.replay._bytes_equal(_identity(material.receiver_identity, work), receiver,
            work, "independent historical receiving identity")
        if consume:
            history.replay._bytes_equal(material.consume_request_bytes, expected_request, work,
                "independent consume request differs from root-admitted original")
        _key_bindings(material, bundle, delivery, work)
        policy = _policy(material.planner, work)
        configured = _Configuration(history.contract.authority.SOURCE_REVISION, original, root,
            bundle, delivery, material.planner.state_enrollment_bytes,
            material.planner.complete_root_vector_bytes, policy,
            material.planner.maximum_plan_age_ns, material.planner.maximum_clock_skew_ns,
            material.planner.attestation_interval,
            material.attestation_interval, material.opening_sample, receiver,
            purpose == bootstrap.CONSUME_CONSUMER_ROLE, expected_request, purpose)
        object.__setattr__(self, "_configured", configured)
        object.__setattr__(self, "_seal", configured)
        object.__setattr__(self, "_pid", os.getpid())
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_last_epoch", material.opening_sample[1])
        object.__setattr__(self, "_last_monotonic", material.opening_sample[2])
        self._snapshot_configuration()
        self._guard(configured, window, bound, work, _current)()

    def _snapshot_configuration(self):
        if (type(self) is not OidcSessionActivationHistoryCustody or self._closed
                or self._pid != os.getpid() or type(self._lock) is not _LOCK_TYPE
                or type(self._configured) is not _Configuration or self._configured is not self._seal
                or self._configured.source_revision != history.contract.authority.SOURCE_REVISION):
            _fail("historical activation custody is closed, changed or belongs to another process")
        configured = self._configured
        consume = bootstrap._requires_consume_request(configured.consumer_role)
        if (type(configured.consume_planning) is not bool
                or configured.consume_planning is not (configured.consumer_role == bootstrap.CONSUME_CONSUMER_ROLE)
                or (consume and (type(configured.consume_request_bytes) is not bytes
                    or not 2 <= len(configured.consume_request_bytes) <= bootstrap.MAX_CONSUME_REQUEST_BYTES))
                or (not consume and configured.consume_request_bytes is not None)):
            _fail("historical activation custody purpose and original-request scope differ")
        _process_for_purpose(configured.consumer_role)
        return configured

    def _guard(self, configured, window, bound, work, _current=None):
        opening, interval = configured.opening_sample, configured.attestation_interval
        bound = min(bound, window[4], opening[0] + interval[1] - opening[1])
        _window, processing = history.delivery._window(window, bound, work)

        def current():
            if self._snapshot_configuration() is not configured:
                _fail("historical activation custody configuration changed")
            # Only the fresh outer interval authorizes this process. The old
            # planner launch never enters a freshness call or a current window.
            sample = bootstrap._fresh(interval, work, opening=opening)
            now = processing()
            if (sample[0] < self._last_monotonic or sample[1] < self._last_epoch
                    or sample[2] >= bound or now < sample[1]):
                _fail("historical activation custody clocks expired or reversed")
            object.__setattr__(self, "_last_epoch", now)
            object.__setattr__(self, "_last_monotonic", sample[2])
            self._snapshot_configuration()
            return now

        return history.delivery._join_current(current, _current, work)

    def _bounds(self, configured, window, deadline):
        opening, interval = configured.opening_sample, configured.attestation_interval
        narrowed = processing_window._narrow(window, deadline_epoch_ns=interval[1],
            maximum_lifetime_ns=configured.maximum_age_ns,
            maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
        return narrowed, min(narrowed[4], deadline, opening[0] + interval[1] - opening[1])

    def _reauthenticate_locked(self, configured, window, bound, work, _current=None):
        current = self._guard(configured, window, bound, work, _current)
        current()
        verify = _verifier(configured.consumer_role)
        material = verify(custody_bytes=configured.custody_bytes,
            root_public_key=configured.root_public_key, live_window=window,
            transport_deadline_ns=bound, work=work)
        current()
        registration._same(material.consumer_role, configured.consumer_role, work,
            "original historical receiving purpose")
        registration._same(material.attestation_interval, configured.attestation_interval, work,
            "original historical receiving interval")
        registration._same(material.planner.attestation_interval, configured.planner_interval, work,
            "original historical planner interval")
        registration._same((material.planner.maximum_plan_age_ns, material.planner.maximum_clock_skew_ns),
            (configured.maximum_age_ns, configured.maximum_clock_skew_ns), work,
            "original historical processing policy")
        for actual, expected, label in (
                (_identity(material.receiver_identity, work), configured.receiver_identity_bytes, "runtime identity"),
                (_policy(material.planner, work), configured.policy_bytes, "planner policy"),
                (material.planner.state_enrollment_bytes, configured.state_enrollment_bytes, "state enrollment"),
                (material.planner.complete_root_vector_bytes, configured.complete_vector_bytes, "complete vector")):
            history.replay._bytes_equal(actual, expected, work, "historical receiving " + label)
        if bootstrap._requires_consume_request(configured.consumer_role):
            history.replay._bytes_equal(material.consume_request_bytes, configured.consume_request_bytes,
                work, "original root-bound consume request")
        elif material.consume_request_bytes is not None:
            _fail("completion history acquired a consume purpose")
        _key_bindings(material, configured.bundle_key, configured.delivery_key, work)
        current()
        return material, current

    def _retained_guard(self, current, continuation=None):
        def checked():
            lock = self._lock
            if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
                _fail("historical activation custody is already in use")
            try:
                first = current()
                if continuation is not None:
                    sampled = continuation()
                    last = current()
                    if sampled < first or last < sampled:
                        _fail("historical activation custody clocks reversed across original admission")
                    return last
                return first
            finally:
                lock.release()

        return checked

    def bind_context_on_work(self, *, root_public_key, current_root_enrollment_bytes, work):
        """Static independent-root join only, not present role admission."""
        original = caller.authorization._original(current_root_enrollment_bytes,
            caller.authorization.MAX_ENROLLMENT_BYTES, "historical receiving state enrollment")
        root = root_public_key
        caller.authorization._public(root)
        configured = self._snapshot_configuration()
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("historical activation custody is already in use")
        try:
            registration._same(evidence.keys._spki_on_work(root, work),
                evidence.keys._spki_on_work(configured.root_public_key, work), work, "historical receiving root")
            history.replay._bytes_equal(original, configured.state_enrollment_bytes, work,
                "historical receiving state enrollment")
            if self._snapshot_configuration() is not configured:
                _fail("historical activation custody changed during context binding")
        finally:
            lock.release()

    def require_completion_on_work(self, *, work):
        """Static fixed-purpose guard; current I/O still needs real reauthentication."""
        evidence.capture._SharedLedger(work)
        if self._snapshot_configuration().consumer_role != bootstrap.CONSUMER_ROLE:
            _fail("consume history cannot authorize completion or recovery")

    def _require_consume_planning_on_work(self, *, work):
        evidence.capture._SharedLedger(work)
        if self._snapshot_configuration().consumer_role != bootstrap.CONSUME_CONSUMER_ROLE:
            _fail("consume planning requires its separate root-signed history purpose")

    def require_consume_grant_on_work(self, *, work):
        """Static v3-only receiving gate; original reauthentication is separate."""
        evidence.capture._SharedLedger(work)
        if self._snapshot_configuration().consumer_role != bootstrap.CONSUME_GRANT_CONSUMER_ROLE:
            _fail("consume-grant receiving requires its separate v3 history purpose")

    def _require_consume_receiving_on_work(self, *, work):
        """Semantic replay only; the outer receiver enforces its exact role."""
        evidence.capture._SharedLedger(work)
        if self._snapshot_configuration().consumer_role not in (
                bootstrap.CONSUME_GRANT_CONSUMER_ROLE, bootstrap.CONSUME_RESERVE_CONSUMER_ROLE,
                bootstrap.CONSUME_SQL_ISSUER_CONSUMER_ROLE):
            _fail("consume execution replay requires a separately root-signed receiving purpose")

    def _require_consume_history_on_work(self, *, work):
        """Predecessor activation provenance only, not consume execution authority."""
        evidence.capture._SharedLedger(work)
        if not bootstrap._requires_consume_request(self._snapshot_configuration().consumer_role):
            _fail("consume provenance requires a request-bound history purpose")

    def _require_live_consume_history_on_work(self, *, work):
        """Keep live consume planning/receiving strictly separate from v6 history."""
        evidence.capture._SharedLedger(work)
        if self._snapshot_configuration().consumer_role not in (
                bootstrap.CONSUME_CONSUMER_ROLE, bootstrap.CONSUME_GRANT_CONSUMER_ROLE,
                bootstrap.CONSUME_RESERVE_CONSUMER_ROLE, bootstrap.CONSUME_SQL_ISSUER_CONSUMER_ROLE):
            _fail("historical completion custody cannot authorize live consume planning")

    def require_consume_reserve_on_work(self, *, work):
        evidence.capture._SharedLedger(work)
        if self._snapshot_configuration().consumer_role != bootstrap.CONSUME_RESERVE_CONSUMER_ROLE:
            _fail("consume reserve requires its separate v4 history purpose")

    def require_consume_sql_issuer_on_work(self, *, work):
        evidence.capture._SharedLedger(work)
        if self._snapshot_configuration().consumer_role != bootstrap.CONSUME_SQL_ISSUER_CONSUMER_ROLE:
            _fail("consume pending receiver requires its separate v5 history purpose")

    def require_consume_completion_on_work(self, *, work):
        """Historical consume replay only; v1/v2/v3/v4/v5 are never substitutes."""
        evidence.capture._SharedLedger(work)
        if self._snapshot_configuration().consumer_role != bootstrap.CONSUME_COMPLETION_CONSUMER_ROLE:
            _fail("consume completion requires its separate v6 history purpose")

    def bind_consume_request_on_work(self, *, expected_consume_request, work):
        """Join independent ordinary request data; return no authority carrier."""
        expected = bootstrap._consume_request_on_work(expected_consume_request, work)
        configured = self._snapshot_configuration()
        if not bootstrap._requires_consume_request(configured.consumer_role):
            _fail("completion history cannot be relabeled for a consume purpose")
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("historical activation custody is already in use")
        try:
            history.replay._bytes_equal(expected, configured.consume_request_bytes, work,
                "consume request differs from independent root-authorized original")
            if self._snapshot_configuration() is not configured:
                _fail("historical activation custody changed during consume binding")
        finally:
            lock.release()

    def check_on_work(self, *, live_window, transport_deadline_ns, work, _current=None):
        """Authenticate current custody before protected I/O or retained reuse."""
        evidence.capture._SharedLedger(work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "historical custody inherited deadline", 1)
        bound = min(window[4], transport_deadline_ns)
        configured = self._snapshot_configuration()
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("historical activation custody is already in use")
        try:
            _material, current = self._reauthenticate_locked(configured, window, bound, work, _current)
            window, bound = self._bounds(configured, window, bound)
            current = self._guard(configured, window, bound, work, _current)
            result = self._retained_guard(current)
            current()
            return result
        finally:
            lock.release()

    def processing_bounds_on_work(self, *, live_window, transport_deadline_ns, work, _current=None):
        """Authenticate, then return only narrower current I/O bound data."""
        evidence.capture._SharedLedger(work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "historical custody inherited deadline", 1)
        bound = min(window[4], transport_deadline_ns)
        configured = self._snapshot_configuration()
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("historical activation custody is already in use")
        try:
            _material, current = self._reauthenticate_locked(configured, window, bound, work, _current)
            narrowed, bound = self._bounds(configured, window, bound)
            current()
            self._guard(configured, narrowed, bound, work, _current)()
            return narrowed, bound
        finally:
            lock.release()

    def verify_exchange_on_work(self, *, originals, expectations, before_vector_bytes,
            authorization_bytes, grant_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
            current_root_enrollment_bytes, root_public_key, planner_public_key, operation_public_key,
            configuration_digest, live_window, transport_deadline_ns, work, _current=None):
        evidence.capture._SharedLedger(work)
        raw2, before = caller.grants.replay._originals(history.OPERATION, originals, before_vector_bytes)
        caller_raw = caller.authorization._original(authorization_bytes, caller.MAX_AUTHORIZATION_BYTES,
            "historical receiving caller authorization")
        grant_raw = caller.authorization._original(grant_bytes, caller.grants.MAX_GRANT_BYTES,
            "historical receiving execution grant")
        caller_enrollment = caller.authorization._original(authorization_enrollment_bytes,
            caller.MAX_ENROLLMENT_BYTES, "historical receiving caller enrollment")
        grant_enrollment = caller.authorization._original(grant_enrollment_bytes,
            caller.grants.MAX_ENROLLMENT_BYTES, "historical receiving grant enrollment")
        state_enrollment = caller.authorization._original(current_root_enrollment_bytes,
            caller.authorization.MAX_ENROLLMENT_BYTES, "historical receiving state enrollment")
        root, planner, operation_key, config = root_public_key, planner_public_key, operation_public_key, configuration_digest
        for key in (root, planner, operation_key):
            caller.authorization._public(key)
        registration._digest(config)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "historical custody inherited deadline", 1)
        bound = min(window[4], transport_deadline_ns)
        owned = caller.expectations_wire._capture_on_work(expectations, work=work)
        configured = self._snapshot_configuration()
        if sum(len(raw) for raw in (*raw2, before, caller_raw, grant_raw, caller_enrollment,
                grant_enrollment, state_enrollment, configured.custody_bytes)) > history.MAX_ORIGINAL_BYTES:
            _fail("historical receiving originals exceed the existing aggregate bound")
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("historical activation custody is already in use")
        try:
            material, current = self._reauthenticate_locked(configured, window, bound, work, _current)
            window, bound = self._bounds(configured, window, bound)
            current = self._guard(configured, window, bound, work, _current)
            current()
            admitted = material.planner
            registration._same(evidence.keys._spki_on_work(root, work),
                evidence.keys._spki_on_work(configured.root_public_key, work), work, "historical receiving root")
            registration._same(evidence.keys._spki_on_work(operation_key, work),
                evidence.keys._spki_on_work(configured.root_public_key, work), work, "historical operation root")
            evidence.keys._public_binding(planner, admitted.planner_spki_digest, work)
            registration._same(config, admitted.configuration_digest, work, "historical receiving configuration")
            history.replay._bytes_equal(state_enrollment, configured.state_enrollment_bytes, work,
                "independent historical state enrollment")
            history.replay._bytes_equal(before, configured.complete_vector_bytes, work,
                "independent historical complete vector")
            policy = evidence.wire._decode_object(configured.policy_bytes, work=work,
                maximum_bytes=history.assertion.MAX_CONTEXT_BYTES,
                maximum_nodes=history.assertion.MAX_CONTEXT_NODES, maximum_depth=12)
            scope = owned["scope"]
            work.prepare_copy(policy)
            registration._same({name: scope[name] for name in policy}, policy, work,
                "independent historical receiving policy")
            history._expectations(owned["request"], scope, window, work)
            _activation_binding(configured, owned["request"], work)
            current()
            actual = exchange._verify_on_work(originals=raw2, expectations=owned, before_vector_bytes=before,
                authorization_bytes=caller_raw, grant_bytes=grant_raw,
                authorization_enrollment_bytes=caller_enrollment, grant_enrollment_bytes=grant_enrollment,
                current_root_enrollment_bytes=state_enrollment, root_public_key=root,
                planner_public_key=planner, operation_public_key=operation_key, configuration_digest=config,
                bundle_key=configured.bundle_key, delivery_custody_key=configured.delivery_key,
                live_window=window, transport_deadline_ns=bound, work=work, _current=_current)
            if type(actual) is not exchange._HistoricalExchange:
                _fail("historical custody requires genuine same-call original exchange")
            _activation_binding(configured, actual.replayed.request, work)
            sampled = actual.live()
            if current() < sampled:
                _fail("historical custody clock reversed after original exchange")
            issued, expires = actual.replayed.original_interval
            if not configured.planner_interval[0] <= issued < expires <= configured.planner_interval[1]:
                _fail("historical plan escapes its genuinely admitted original planner launch")
            # Keep the actual same-call facts and add owner liveness, not a new
            # proof input. The retained guard takes the lock only after return.
            result = replace(actual, live=self._retained_guard(current, actual.live))
            sampled = actual.live()
            if current() < sampled:
                _fail("historical custody clock reversed before return")
            return result
        finally:
            lock.release()

    def close(self):
        if type(self) is not OidcSessionActivationHistoryCustody or self._pid != os.getpid():
            _fail("historical activation custody cannot close in another process")
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("historical activation custody is already in use")
        try:
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_configured", None)
            object.__setattr__(self, "_seal", None)
        finally:
            lock.release()
