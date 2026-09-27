"""Process-bound delivery-key custody with NO plaintext release entrypoint.

Original root scope is reauthenticated before every check, original-intent
admission and exact AEAD metadata inspection. Fresh intent admission proves
caller authority and old-token possession, not committed consumption. This
owner still has no token-release method, SQL, journal, transport or public HTTP
result, and no successful admission result can be supplied as release proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import threading

from serverware import oidc_session_activation_release_custody_bootstrap as bootstrap
from serverware import oidc_session_activation_delivery as delivery
from serverware import oidc_session_activation_release_intent as release_intent
from serverware import oidc_session_activation_release_intent_enrollment as intent_enrollment
from serverware import authority_oidc_session_activation_release_intent as intent_admission
from serverware import authority_successor_execution_window as processing_window


registration, clock = delivery.registration, delivery.clock
evidence = registration.evidence
_LOCK_TYPE = type(threading.Lock())


class OidcSessionActivationReleaseCustodyError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseCustodyError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    source_revision: str
    custody_bytes: bytes
    root_public_key: object
    delivery_key: bytes
    receiver_identity_bytes: bytes
    scope_bytes: bytes
    maximum_age_ns: int
    maximum_clock_skew_ns: int
    attestation_interval: tuple
    opening_sample: tuple


def _identity(value, work):
    ledger = evidence.capture._SharedLedger(work)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=1024).visit(value)
    evidence._identity(owned)
    return evidence.capability._wire(owned, ledger, 1024, 7)


def _binding(material, work):
    # All values come from this invocation's actual original verification.
    # A binding is held for change detection, never accepted as an input proof.
    return bootstrap._wire({
        "configurationDigest": material.planner.configuration_digest,
        "generationDigest": material.planner.generation["digest"],
        "runtimeClosureDigest": material.planner.runtime_closure_digest,
        "deliveryKeyDigest": material.delivery_key_digest,
        "activationRequestDigest": material.activation_request_digest,
        "activationOperationId": material.activation_operation_id,
        "deliveryEnvelopeDigest": material.delivery_envelope_digest,
        "deliveryScope": material.delivery_scope,
        "releaseIntentDigest": material.release_intent_digest,
        "consumeRequestDigest": material.consume_request_digest,
        "consumeOperation": material.consume_operation,
    }, work)


def _key_binding(material, key, work):
    work.charge(hashes=1, input_bytes=delivery.KEY_BYTES)
    digest = evidence.production._callback(work, lambda: "sha256:" + hashlib.sha256(key).hexdigest())
    registration._same(digest, material.delivery_key_digest, work, "root-admitted release delivery key")


def _process():
    uid, gid = bootstrap.SERVICE_UID, bootstrap.SERVICE_GID
    if (os.getresuid() != (uid,) * 3 or os.getresgid() != (gid,) * 3 or os.getgroups()
            or os.environ.get("SERVERWARE_PROCESS_MODE") != bootstrap.PROCESS_MODE):
        _fail("release custody requires its dedicated nonroot process")


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationReleaseCustody:
    _configured: _Configuration | None
    _seal: _Configuration | None
    _pid: int
    _lock: object
    _closed: bool
    _last_epoch: int
    _last_monotonic: int

    def __init__(self, *, custody_bytes, root_public_key, expected_receiver_identity,
            delivery_custody_key, live_window, transport_deadline_ns, work):
        evidence.capture._SharedLedger(work)
        original = bootstrap.authorization._original(custody_bytes, bootstrap.MAX_BYTES,
            "activation release custody original")
        root, key = root_public_key, delivery_custody_key
        bootstrap.authorization._public(root)
        if type(key) is not bytes or len(key) != delivery.KEY_BYTES:
            _fail("release custody requires an exact independently admitted delivery key")
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "release custody inherited deadline", 1)
        bound = min(window[4], transport_deadline_ns)
        receiver = _identity(expected_receiver_identity, work)
        _process()
        _window, current = delivery._window(window, bound, work)
        current()
        material = bootstrap._verify_on_work(custody_bytes=original, root_public_key=root,
            live_window=window, transport_deadline_ns=bound, work=work)
        current()
        registration._same(_identity(material.receiver_identity, work), receiver, work,
            "independent activation release receiver identity")
        _key_binding(material, key, work)
        current()
        configured = _Configuration(bootstrap.authority.SOURCE_REVISION, original, root, key,
            receiver, _binding(material, work), material.planner.maximum_plan_age_ns,
            material.planner.maximum_clock_skew_ns, material.attestation_interval, material.opening_sample)
        object.__setattr__(self, "_configured", configured)
        object.__setattr__(self, "_seal", configured)
        object.__setattr__(self, "_pid", os.getpid())
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_last_epoch", material.opening_sample[1])
        object.__setattr__(self, "_last_monotonic", material.opening_sample[2])
        self._snapshot_configuration()
        narrowed, bound = self._bounds(configured, window, bound)
        self._guard(configured, narrowed, bound, work)()

    def _snapshot_configuration(self):
        if (type(self) is not OidcSessionActivationReleaseCustody or self._closed
                or self._pid != os.getpid() or type(self._lock) is not _LOCK_TYPE
                or type(self._configured) is not _Configuration or self._configured is not self._seal
                or self._configured.source_revision != bootstrap.authority.SOURCE_REVISION):
            _fail("release custody is closed, changed or belongs to another process")
        _process()
        return self._configured

    def _bounds(self, configured, window, deadline):
        interval, opening = configured.attestation_interval, configured.opening_sample
        narrowed = processing_window._narrow(window, deadline_epoch_ns=interval[1],
            maximum_lifetime_ns=configured.maximum_age_ns,
            maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
        return narrowed, min(deadline, narrowed[4], opening[0] + interval[1] - opening[1])

    def _guard(self, configured, window, bound, work):
        opening, interval = configured.opening_sample, configured.attestation_interval
        bound = min(bound, window[4], opening[0] + interval[1] - opening[1])
        _window, processing = delivery._window(window, bound, work)

        def current():
            if self._snapshot_configuration() is not configured:
                _fail("activation release custody configuration changed")
            sample = bootstrap._fresh(interval, work, opening=opening)
            now = processing()
            if (sample[0] < self._last_monotonic or sample[1] < self._last_epoch
                    or sample[2] >= bound or now < sample[1]):
                _fail("activation release custody clocks expired or reversed")
            object.__setattr__(self, "_last_epoch", now)
            object.__setattr__(self, "_last_monotonic", sample[2])
            self._snapshot_configuration()
            return now

        return current

    def _reauthenticate_locked(self, configured, window, bound, work):
        current = self._guard(configured, window, bound, work)
        current()
        material = bootstrap._verify_on_work(custody_bytes=configured.custody_bytes,
            root_public_key=configured.root_public_key, live_window=window,
            transport_deadline_ns=bound, work=work)
        current()
        registration._same(material.attestation_interval, configured.attestation_interval, work,
            "original activation release interval")
        registration._same(_identity(material.receiver_identity, work), configured.receiver_identity_bytes,
            work, "original independently pinned release receiver")
        registration._same(_binding(material, work), configured.scope_bytes, work,
            "original activation release identity and delivery scope")
        registration._same((material.planner.maximum_plan_age_ns, material.planner.maximum_clock_skew_ns),
            (configured.maximum_age_ns, configured.maximum_clock_skew_ns), work, "original release processing policy")
        _key_binding(material, configured.delivery_key, work)
        current()
        return material, current

    def check_on_work(self, *, live_window, transport_deadline_ns, work):
        """Reauthenticate current custody; return no reusable success carrier."""
        evidence.capture._SharedLedger(work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "release custody inherited deadline", 1)
        configured = self._snapshot_configuration()
        window, bound = self._bounds(configured, window, transport_deadline_ns)
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("activation release custody is already in use")
        try:
            _material, current = self._reauthenticate_locked(configured, window, bound, work)
            current()
        finally:
            lock.release()

    def inspect_delivery_on_work(self, *, envelope_bytes, live_window, transport_deadline_ns, work):
        """Authenticate exact ciphertext, returning only ordinary owned metadata.

        Neither this result nor expected intent/consume identities authorize a
        token return. The existing live AEAD helper discards plaintext after
        deriving ciphertext-row data; that row is not returned or retained.
        """
        evidence.capture._SharedLedger(work)
        envelope = delivery._envelope(envelope_bytes, work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "release custody inherited deadline", 1)
        configured = self._snapshot_configuration()
        window, bound = self._bounds(configured, window, transport_deadline_ns)
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("activation release custody is already in use")
        try:
            material, current = self._reauthenticate_locked(configured, window, bound, work)
            work.charge(hashes=1, input_bytes=len(envelope))
            digest = evidence.production._callback(work, lambda: "sha256:" + hashlib.sha256(envelope).hexdigest())
            current()
            registration._same(digest, material.delivery_envelope_digest, work,
                "root-pinned activation release envelope original")
            # This API genuinely opens/authenticates on the held key and exact
            # root-owned scope. It does not export the private token result.
            delivery._delivery_row_on_work(envelope_bytes=envelope, custody_key=configured.delivery_key,
                scope=material.delivery_scope, live_window=window, transport_deadline_ns=bound, work=work)
            current()
            result = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
                maximum_bytes=delivery.MAX_SCOPE_BYTES).visit({"deliveryScope": material.delivery_scope,
                    "deliveryEnvelopeDigest": digest})
            current()
            return result
        finally:
            lock.release()

    def verify_intent_on_work(self, *, intent_bytes, intent_enrollment_bytes,
            expected_caller_id, expected_consume_binding, old_token_bytes,
            live_window, transport_deadline_ns, work):
        """Authenticate fresh intent originals, returning no release capability.

        The root-pinned exact intent identity is joined before admitting its
        original signature and enrollment. The consume binding remains a set
        of expected identities: this method reads no commit/packet or outcome,
        opens no ciphertext, and never authorizes a later plaintext call.
        """
        ledger = evidence.capture._SharedLedger(work)
        original = bootstrap.authorization._original(intent_bytes,
            release_intent.MAX_BYTES, "activation release intent original")
        enrollment_original = bootstrap.authorization._original(intent_enrollment_bytes,
            intent_enrollment.MAX_BYTES, "activation release intent enrollment original")
        caller = expected_caller_id
        bootstrap.authorization._token(caller)
        consume_binding = evidence.capture._JSONCapture(ledger,
            maximum_bytes=1024).visit(expected_consume_binding)
        registration._closed(consume_binding, release_intent.CONSUME_BINDING_FIELDS,
            "independent release consume binding")
        for digest in consume_binding.values():
            registration._digest(digest)
        old_token = delivery._token(old_token_bytes, work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "release intent inherited deadline", 1)
        configured = self._snapshot_configuration()
        window, bound = self._bounds(configured, window, transport_deadline_ns)
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("activation release custody is already in use")
        try:
            material, current = self._reauthenticate_locked(configured, window, bound, work)
            digest = release_intent._digest(original, work)
            current()
            registration._same(digest, material.release_intent_digest, work,
                "root-pinned original release intent identity")
            # Use only the original planner's actually admitted current-root
            # enrollment, not keys or a database identity selected by intent.
            state = bootstrap.authorization._admit_enrollment_on_work(
                enrollment_bytes=material.planner.state_enrollment_bytes,
                root_public_key=configured.root_public_key, work=work)
            current()
            registration._same(state.enrollment_digest,
                material.planner.state_enrollment_digest, work,
                "original release planner state enrollment")
            registration._same(state.payload["generationDigest"],
                material.planner.generation["digest"], work,
                "original release planner state generation")
            expected_scope = {
                "configurationDigest": material.planner.configuration_digest,
                "databaseId": state.payload["databaseId"],
                "generationDigest": material.planner.generation["digest"],
                "runtimeClosureDigest": material.planner.runtime_closure_digest,
                "callerId": caller,
                "receiverIdentity": material.receiver_identity,
            }
            expected_release = {
                "activationRequestDigest": material.activation_request_digest,
                "activationOperationId": material.activation_operation_id,
                "consumeRequestDigest": material.consume_request_digest,
                "deliveryEnvelopeDigest": material.delivery_envelope_digest,
                "deliveryScope": material.delivery_scope,
                "consumeBinding": consume_binding,
            }
            admitted = intent_admission._verify_on_work(intent_bytes=original,
                enrollment_bytes=enrollment_original, root_public_key=configured.root_public_key,
                forbidden_public_keys=(material.planner.planner_public_key,
                    state.computation_public_key, state.completion_public_key, state.state_public_key),
                expected_scope=expected_scope, expected_release=expected_release,
                old_token_bytes=old_token, live_window=window,
                transport_deadline_ns=bound, work=work)
            if type(admitted) is not intent_admission._AdmittedIntent:
                _fail("release intent did not return the genuine original admission")
            registration._same(admitted.intent_digest, digest, work,
                "original release intent identity after admission")
            intent_now = admitted.live()
            if intent_now < self._last_epoch:
                _fail("release custody clock reversed after original intent admission")
            # Preserve the nested guard's observed epoch even if the next
            # custody sample fails; a later call cannot forget that sample.
            object.__setattr__(self, "_last_epoch", intent_now)
            current()
            # Deliberately return None. This call cannot mint reusable release
            # authority; full release must join all original proofs itself.
        finally:
            lock.release()

    def close(self):
        if type(self) is not OidcSessionActivationReleaseCustody or self._pid != os.getpid():
            _fail("activation release custody close belongs to another owner/process")
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("activation release custody is already in use")
        try:
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_configured", None)
            object.__setattr__(self, "_seal", None)
        finally:
            lock.release()
