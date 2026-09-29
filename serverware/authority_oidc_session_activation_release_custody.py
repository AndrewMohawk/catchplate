"""Process-bound delivery-key custody with original-only private token opening.

Original root scope is reauthenticated before every check, original-intent
admission, signed committed-proof admission and exact AEAD metadata inspection.
Fresh intent alone proves caller authority and old-token possession, not
committed consumption. The separate proof join alone grants no token egress.
Private opening additionally binds the exact ciphertext and durably retains a
token-free outcome through separately root-authorized storage, with genuine
readback before and after opening. No successful result is accepted as proof;
there is no SQL, recovery authorization, transport or public HTTP result here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import threading

from serverware import oidc_session_activation_release_custody_bootstrap as bootstrap
from serverware import oidc_session_activation_release_retained_authority as retained
from serverware import oidc_session_activation_delivery as delivery
from serverware import oidc_session_activation_release_intent as release_intent
from serverware import oidc_session_activation_release_intent_enrollment as intent_enrollment
from serverware import authority_oidc_session_activation_release_intent as intent_admission
from serverware import oidc_session_activation_release_proof as release_proof
from serverware import oidc_session_activation_release_proof_enrollment as proof_enrollment
from serverware import authority_oidc_session_activation_release_proof as proof_admission
from serverware import oidc_session_activation_release_outcome as outcomes
from serverware import authority_oidc_session_activation_release_outcome_store as outcome_storage
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
            receiver, _binding(material, work), retained.planner_for(material).maximum_plan_age_ns,
            retained.planner_for(material).maximum_clock_skew_ns, material.attestation_interval, material.opening_sample)
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
        planner = retained.planner_for(material)
        registration._same((planner.maximum_plan_age_ns, planner.maximum_clock_skew_ns),
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

    def _intent_locked(self, *, configured, material, current, original,
            enrollment_original, caller, consume_binding, old_token, window, bound, work):
        """Join actual root/intent originals inside this owner's held lock."""
        digest = release_intent._digest(original, work)
        current()
        registration._same(digest, material.release_intent_digest, work,
            "root-pinned original release intent identity")
        historical = material.intent_root_public_key is not None
        root = retained.root_for(material, configured.root_public_key)
        if historical:
            retained._same_bytes(enrollment_original, material.intent_enrollment_bytes, work,
                "current custody independently pinned intent enrollment")
        # Use only the original planner's actually admitted current-root
        # enrollment, not keys or a database identity selected by intent.
        state = bootstrap.authorization._admit_enrollment_on_work(
            enrollment_bytes=material.planner.state_enrollment_bytes,
            root_public_key=root, work=work)
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
        verifier = intent_admission._verify_historical_on_work if historical else intent_admission._verify_on_work
        admitted = verifier(intent_bytes=original,
            enrollment_bytes=enrollment_original, root_public_key=root,
            forbidden_public_keys=(material.planner.planner_public_key,
                state.computation_public_key, state.completion_public_key, state.state_public_key),
            expected_scope=expected_scope, expected_release=expected_release,
            old_token_bytes=old_token, live_window=window,
            transport_deadline_ns=bound, work=work)
        if type(admitted) is not (intent_admission._HistoricalIntentEvidence if historical else intent_admission._AdmittedIntent):
            _fail("release intent did not return the genuine original admission")
        retained.contain(material, admitted.payload)
        registration._same(admitted.intent_digest, digest, work,
            "original release intent identity after admission")
        intent_now = admitted.live()
        if intent_now < self._last_epoch:
            _fail("release custody clock reversed after original intent admission")
        # Preserve the nested guard's observed epoch even if the next
        # custody sample fails; a later call cannot forget that sample.
        object.__setattr__(self, "_last_epoch", intent_now)
        current()
        return admitted, expected_scope, expected_release, (
            material.planner.planner_public_key, state.computation_public_key,
            state.completion_public_key, state.state_public_key)

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
            self._intent_locked(configured=configured, material=material, current=current,
                original=original, enrollment_original=enrollment_original, caller=caller,
                consume_binding=consume_binding, old_token=old_token, window=window,
                bound=bound, work=work)
            # Deliberately return None. This call cannot mint reusable release
            # authority; full release must join all original proofs itself.
        finally:
            lock.release()

    def verify_committed_on_work(self, *, proof_bytes, proof_enrollment_bytes,
            intent_bytes, intent_enrollment_bytes, expected_producer_id,
            expected_producer_identity, expected_caller_id, expected_consume_binding,
            expected_state_receipt_digest, old_token_bytes,
            live_window, transport_deadline_ns, work):
        """Join original committed facts and fresh intent; return no authority."""
        self._committed_on_work(proof_bytes=proof_bytes, proof_enrollment_bytes=proof_enrollment_bytes,
            intent_bytes=intent_bytes, intent_enrollment_bytes=intent_enrollment_bytes,
            expected_producer_id=expected_producer_id, expected_producer_identity=expected_producer_identity,
            expected_caller_id=expected_caller_id, expected_consume_binding=expected_consume_binding,
            expected_state_receipt_digest=expected_state_receipt_digest, old_token_bytes=old_token_bytes,
            outcome_store=None, envelope_bytes=None, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work)

    def retain_outcome_on_work(self, *, proof_bytes, proof_enrollment_bytes,
            intent_bytes, intent_enrollment_bytes, expected_producer_id,
            expected_producer_identity, expected_caller_id, expected_consume_binding,
            expected_state_receipt_digest, old_token_bytes, outcome_store,
            live_window, transport_deadline_ns, work):
        """Authenticate originals and durably bind one exact token-free outcome.

        The returned digest identifies retained bytes, never token delivery or
        permission for another call. No successful proof object is accepted.
        """
        if type(outcome_store) is not outcome_storage.ReleaseOutcomeStore:
            _fail("release outcome requires its actual distinct storage owner")
        return self._committed_on_work(proof_bytes=proof_bytes, proof_enrollment_bytes=proof_enrollment_bytes,
            intent_bytes=intent_bytes, intent_enrollment_bytes=intent_enrollment_bytes,
            expected_producer_id=expected_producer_id, expected_producer_identity=expected_producer_identity,
            expected_caller_id=expected_caller_id, expected_consume_binding=expected_consume_binding,
            expected_state_receipt_digest=expected_state_receipt_digest, old_token_bytes=old_token_bytes,
            outcome_store=outcome_store, envelope_bytes=None, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work)

    def open_committed_on_work(self, *, proof_bytes, proof_enrollment_bytes,
            intent_bytes, intent_enrollment_bytes, expected_producer_id,
            expected_producer_identity, expected_caller_id, expected_consume_binding,
            expected_state_receipt_digest, old_token_bytes, envelope_bytes, outcome_store,
            live_window, transport_deadline_ns, work):
        """Return the exact private token after original admission and readback.

        This is not a transport acknowledgment or recovery permission. The
        same call authenticates every original; no retained digest, inspected
        metadata or successful proof object can authorize a later opening.
        """
        if type(envelope_bytes) is not bytes:
            _fail("committed release opening requires original ciphertext bytes")
        if type(outcome_store) is not outcome_storage.ReleaseOutcomeStore:
            _fail("committed release opening requires its actual storage owner")
        return self._committed_on_work(proof_bytes=proof_bytes, proof_enrollment_bytes=proof_enrollment_bytes,
            intent_bytes=intent_bytes, intent_enrollment_bytes=intent_enrollment_bytes,
            expected_producer_id=expected_producer_id, expected_producer_identity=expected_producer_identity,
            expected_caller_id=expected_caller_id, expected_consume_binding=expected_consume_binding,
            expected_state_receipt_digest=expected_state_receipt_digest, old_token_bytes=old_token_bytes,
            outcome_store=outcome_store, envelope_bytes=envelope_bytes, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work)

    def _committed_on_work(self, *, proof_bytes, proof_enrollment_bytes,
            intent_bytes, intent_enrollment_bytes, expected_producer_id,
            expected_producer_identity, expected_caller_id, expected_consume_binding,
            expected_state_receipt_digest, old_token_bytes, outcome_store, envelope_bytes,
            live_window, transport_deadline_ns, work):
        """One locked original-consuming composition through private return."""
        ledger = evidence.capture._SharedLedger(work)
        store = outcome_store
        if store is not None and type(store) is not outcome_storage.ReleaseOutcomeStore:
            _fail("release outcome requires its exact storage owner")
        envelope = None if envelope_bytes is None else delivery._envelope(envelope_bytes, work)
        if envelope is not None and store is None:
            _fail("private token opening requires durable outcome storage")
        proof_raw = bootstrap.authorization._original(proof_bytes,
            release_proof.MAX_BYTES, "release committed proof original")
        proof_enrolled = bootstrap.authorization._original(proof_enrollment_bytes,
            proof_enrollment.MAX_BYTES, "release proof enrollment original")
        intent_raw = bootstrap.authorization._original(intent_bytes,
            release_intent.MAX_BYTES, "release intent original")
        intent_enrolled = bootstrap.authorization._original(intent_enrollment_bytes,
            intent_enrollment.MAX_BYTES, "release intent enrollment original")
        producer, caller, receipt = (expected_producer_id, expected_caller_id,
            expected_state_receipt_digest)
        bootstrap.authorization._token(producer)
        bootstrap.authorization._token(caller)
        registration._digest(receipt)
        old_token = delivery._token(old_token_bytes, work)
        # Joint structural ownership precedes any root/key/hash/clock callback.
        held = evidence.capture._JSONCapture(ledger, maximum_bytes=2048).visit({
            "producerIdentity": expected_producer_identity,
            "consumeBinding": expected_consume_binding})
        bootstrap.shape.validate_identity_shape(held["producerIdentity"])
        registration._closed(held["consumeBinding"], release_intent.CONSUME_BINDING_FIELDS,
            "independent committed release consumption")
        for digest in held["consumeBinding"].values():
            registration._digest(digest)
        total = sum(map(len, (proof_raw, proof_enrolled, intent_raw, intent_enrolled, old_token)))
        maximum = (release_proof.MAX_BYTES + proof_enrollment.MAX_BYTES
            + release_intent.MAX_BYTES + intent_enrollment.MAX_BYTES + delivery.TOKEN_BYTES)
        if envelope is not None:
            total += len(envelope)
            maximum += delivery.ENVELOPE_BYTES
        if total > maximum:
            _fail("release committed originals exceed their aggregate bound")
        work.charge(input_bytes=total)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "release committed inherited deadline", 1)
        configured = self._snapshot_configuration()
        window, bound = self._bounds(configured, window, transport_deadline_ns)
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("activation release custody is already in use")
        outcome_started = False
        try:
            material, current = self._reauthenticate_locked(configured, window, bound, work)
            historical = material.intent_root_public_key is not None
            root = retained.root_for(material, configured.root_public_key)
            retained.require_originals(material, intent_enrolled, proof_enrolled, work)
            intent, intent_scope, release, forbidden = self._intent_locked(
                configured=configured, material=material, current=current, original=intent_raw,
                enrollment_original=intent_enrolled, caller=caller,
                consume_binding=held["consumeBinding"], old_token=old_token,
                window=window, bound=bound, work=work)
            # Authenticate the actual intent key, not a PEM chosen by the
            # proof, before checking separation from the new proof signer.
            intent_key = intent_enrollment._admit_on_work(enrollment_bytes=intent_enrolled,
                root_public_key=root, expected_scope=intent_scope,
                forbidden_public_keys=forbidden, work=work)
            registration._same(intent_key.enrollment_digest, intent.payload["enrollmentDigest"],
                work, "release proof actual intent enrollment")
            current()
            expected_scope = {name: intent_scope[name] for name in (
                "configurationDigest", "databaseId", "generationDigest",
                "runtimeClosureDigest", "receiverIdentity")}
            expected_scope.update(producerId=producer, producerIdentity=held["producerIdentity"])
            if historical:
                registration._same(expected_scope, material.proof_scope, work,
                    "current custody independently pinned proof scope")
            custody_digest = evidence.plan._frame(release_proof.CUSTODY_IDENTITY_DOMAIN,
                (retained.custody_for(material),), work)
            current()
            verifier = proof_admission._verify_historical_on_work if historical else proof_admission._verify_on_work
            admitted = verifier(proof_bytes=proof_raw,
                enrollment_bytes=proof_enrolled, root_public_key=root,
                forbidden_public_keys=(*forbidden, intent_key.caller_public_key),
                expected_scope=expected_scope, expected_release=release,
                expected_evidence={"releaseCustodyDigest": custody_digest,
                    "releaseIntentDigest": material.release_intent_digest,
                    "stateReceiptDigest": receipt},
                expected_intent_interval=(intent.payload["issuedAtEpochNs"],
                    intent.payload["expiresAtEpochNs"]),
                live_window=window, transport_deadline_ns=bound, work=work)
            if type(admitted) is not (proof_admission._HistoricalProofEvidence if historical else proof_admission._AdmittedProof):
                _fail("release committed proof lacks genuine original admission")
            retained.contain(material, admitted.payload)
            # Current-only release obeys both evidence expiries. Explicit v2
            # historical evidence instead retains the current custody deadline;
            # neither branch opens a new processing allowance.
            final_window = processing_window._narrow(window,
                deadline_epoch_ns=(material.attestation_interval[1] if historical else
                    min(intent.payload["expiresAtEpochNs"], admitted.payload["expiresAtEpochNs"])),
                maximum_lifetime_ns=configured.maximum_age_ns,
                maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
            final_current = self._guard(configured, final_window,
                min(bound, final_window[4]), work)

            def joined_current():
                for guard in (intent.live, admitted.live, intent.live, admitted.live):
                    now = guard()
                    if now < self._last_epoch:
                        _fail("release custody clock reversed across original proof admission")
                    object.__setattr__(self, "_last_epoch", now)
                    current()
                    final_current()

            joined_current()
            if store is None:
                return None
            opening = None
            if envelope is not None:
                work.charge(hashes=1, input_bytes=len(envelope))
                digest = evidence.production._callback(work,
                    lambda: "sha256:" + hashlib.sha256(envelope).hexdigest())
                joined_current()
                registration._same(digest, material.delivery_envelope_digest, work,
                    "committed release exact root/proof ciphertext original")
                # Keep the actual live delivery guard, including preparation's
                # observations. The ordinary opening wrapper would hide it.
                owned, aad, delivery_current = delivery._prepare(configured.delivery_key,
                    material.delivery_scope, final_window, min(bound, final_window[4]), work)

                def opening_current():
                    joined_current()
                    now = delivery_current()
                    if now < self._last_epoch:
                        _fail("release custody clock reversed across private delivery opening")
                    object.__setattr__(self, "_last_epoch", now)
                    joined_current()
                    return self._last_epoch

                opening = opening_current
                opening()
            store_type = outcome_storage.ReleaseOutcomeStore
            store_configuration = store_type._snapshot_configuration(store)
            joined_current()
            record = outcomes._encode_on_work(
                scope={name: admitted.payload[name] for name in release_proof.SCOPE_FIELDS},
                release_binding={name: admitted.payload[name] for name in release_proof.RELEASE_FIELDS},
                evidence_binding={"releaseCustodyDigest": custody_digest,
                    "releaseIntentDigest": intent.intent_digest, "stateReceiptDigest": receipt,
                    "releaseProofDigest": admitted.proof_digest,
                    "proofEnrollmentDigest": admitted.payload["enrollmentDigest"],
                    "intentEnrollmentDigest": intent.payload["enrollmentDigest"]},
                caller_id=intent.payload["callerId"], work=work)
            expected_outcome = outcomes._digest_on_work(record, work)
            binding = {name: intent_scope[name] for name in (
                "configurationDigest", "databaseId", "generationDigest",
                "runtimeClosureDigest", "receiverIdentity")}
            binding.update(deliveryId=material.delivery_scope["deliveryId"],
                releaseCustodyDigest=custody_digest)
            joined_current()
            # The actual store reauthenticates its distinct root grant and
            # exact binding before any first publication. Its current grant
            # identity is not part of this stable retained outcome identity.
            outcome_started = True
            observed = store_type.retain_on_work(store, record_bytes=record,
                root_public_key=configured.root_public_key, expected_binding=binding,
                live_window=final_window, transport_deadline_ns=min(bound, final_window[4]), work=work)
            joined_current()
            if store_type._snapshot_configuration(store) is not store_configuration:
                _fail("release outcome store changed during retention")
            registration._same(observed, expected_outcome, work, "durable exact release outcome identity")
            joined_current()
            if opening is None:
                return observed
            opening()
            token = delivery._open_captured(envelope, configured.delivery_key,
                owned, aad, work, opening)
            opening()
            # Hold plaintext locally until the same actual owner reauthenticates
            # storage and performs a second normal-close read of identical bytes.
            # Neither the first digest nor a cached journal snapshot is enough.
            repeated = store_type.retain_on_work(store, record_bytes=record,
                root_public_key=configured.root_public_key, expected_binding=binding,
                live_window=final_window, transport_deadline_ns=min(bound, final_window[4]), work=work)
            opening()
            if store_type._snapshot_configuration(store) is not store_configuration:
                _fail("release outcome store changed across private token opening")
            registration._same(repeated, expected_outcome, work,
                "durable exact release outcome identity after opening")
            opening()
            return token
        except BaseException:
            if outcome_started:
                # Publication may already be durable. Never delete or retry;
                # close both owners even when a final guard fails afterward.
                object.__setattr__(self, "_closed", True)
                object.__setattr__(self, "_configured", None)
                object.__setattr__(self, "_seal", None)
                try:
                    outcome_storage.ReleaseOutcomeStore.close(store)
                except BaseException:
                    pass
            raise
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
