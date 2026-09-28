"""Recover one unchanged private token under fresh recovery-only authority.

Old custody, intent and proof originals are authenticated as historical facts,
never renewed execution permission. A separately admitted checkpoint-one store
must read the exact retained record before and after live delivery opening.
There is no outcome creation, consumption, SQL, automatic retry or transport.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import threading
import time

from serverware import oidc_session_activation_release_recovery_authorization as grants
from serverware import authority_oidc_session_activation_release_custody as release_custody
from serverware import authority_oidc_session_activation_release_outcome_store as stores


bootstrap, delivery = grants.bootstrap, grants.delivery
authorization, shape, plan = grants.authorization, grants.shape, grants.plan
capture, production, clock = grants.capture, grants.production, grants.clock
outcomes, intents, intent_keys = release_custody.outcomes, release_custody.release_intent, release_custody.intent_enrollment
proofs, proof_keys = release_custody.release_proof, release_custody.proof_enrollment
intent_admission, proof_admission = release_custody.intent_admission, release_custody.proof_admission
processing = release_custody.processing_window
_LOCK_TYPE = type(threading.Lock())
MAX_ORIGINAL_BYTES = (outcomes.MAX_BYTES + intents.MAX_BYTES + intent_keys.MAX_BYTES
    + proofs.MAX_BYTES + proof_keys.MAX_BYTES + delivery.ENVELOPE_BYTES + delivery.TOKEN_BYTES)


class OidcSessionActivationReleaseRecoveryError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseRecoveryError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    source_revision: str
    recovery_bytes: bytes
    custody_bytes: bytes
    root_public_key: object
    delivery_key: bytes
    scope_bytes: bytes
    store: stores.ReleaseOutcomeStore
    store_configuration: object
    ancestor: object = None


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationReleaseRecovery:
    _configured: _Configuration | None
    _seal: _Configuration | None
    _lifetime: tuple
    _lifetime_seal: tuple
    _pid: int
    _lock: object
    _closed: bool
    _ready: bool
    _last_epoch: int
    _last_monotonic: int

    def __init__(self, *, recovery_authorization_bytes, custody_bytes, root_public_key,
            expected_scope, delivery_custody_key, outcome_store, live_window,
            transport_deadline_ns, work, _continuity=None):
        capture._SharedLedger(work)
        recovery = authorization._original(recovery_authorization_bytes, grants.MAX_BYTES,
            "release recovery authorization original")
        custody = authorization._original(custody_bytes, bootstrap.MAX_BYTES,
            "historical release custody original")
        root, key, store = root_public_key, delivery_custody_key, outcome_store
        authorization._public(root)
        if type(key) is not bytes or len(key) != delivery.KEY_BYTES:
            _fail("release recovery requires the exact independently delivered key")
        if type(store) is not stores.ReleaseOutcomeStore:
            _fail("release recovery requires the actual checkpoint-one store")
        scope = grants._scope(expected_scope, work)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(transport_deadline_ns, window[4])
        release_custody._process()
        configured = _Configuration(grants.authority.SOURCE_REVISION, recovery, custody,
            root, key, grants._wire(scope, work), store,
            stores.ReleaseOutcomeStore._snapshot_configuration(store), _continuity)
        lifetime = (work, window, bound)
        for name, value in (("_configured", configured), ("_seal", configured),
                ("_lifetime", lifetime), ("_lifetime_seal", lifetime), ("_pid", os.getpid()),
                ("_lock", threading.Lock()), ("_closed", False), ("_ready", False),
                ("_last_epoch", window[0]), ("_last_monotonic", window[2])):
            object.__setattr__(self, name, value)
        try:
            self._context(configured, window, bound, work)
            object.__setattr__(self, "_ready", True)
        except BaseException:
            self._close_preserving(configured)
            raise

    def _identity(self, configured):
        if (type(self) is not OidcSessionActivationReleaseRecovery or self._closed
                or self._pid != os.getpid() or type(self._lock) is not _LOCK_TYPE
                or type(configured) is not _Configuration or self._configured is not configured
                or self._seal is not configured or configured.source_revision != grants.authority.SOURCE_REVISION
                or type(self._lifetime) is not tuple or self._lifetime is not self._lifetime_seal):
            _fail("release recovery owner is closed, changed or belongs to another process")
        release_custody._process()
        if stores.ReleaseOutcomeStore._snapshot_configuration(configured.store) is not configured.store_configuration:
            _fail("release recovery store configuration changed")

    def _snapshot_configuration(self):
        configured = self._configured
        self._identity(configured)
        if not self._ready:
            _fail("release recovery owner has not completed admission")
        return configured

    def _narrow(self, work, window, bound):
        original_work, prior, prior_bound = self._lifetime
        if work is not original_work or window[:3] != prior[:3]:
            _fail("release recovery cannot restart its original processing allowance")
        # Callers may still supply their original window after construction
        # clips it to signed authority. Intersect, never replace held ceilings.
        window = window[:3] + tuple(min(actual, previous)
            for actual, previous in zip(window[3:], prior[3:]))
        bound = min(bound, prior_bound, window[4])
        lifetime = (work, window, bound)
        object.__setattr__(self, "_lifetime", lifetime)
        object.__setattr__(self, "_lifetime_seal", lifetime)
        return window, bound

    def _guard(self, configured, grant_live, window, bound, work):
        _window, check = delivery._window(window, bound, work)

        def current():
            self._identity(configured)
            first, permitted, last = check(), grant_live(), check()
            monotonic = production._callback(work, time.monotonic_ns)
            shape._integer(monotonic, minimum=1)
            if (first < self._last_epoch or permitted < first or last < permitted
                    or monotonic < self._last_monotonic or monotonic >= bound):
                _fail("release recovery authority expired or clocks reversed")
            object.__setattr__(self, "_last_epoch", last)
            object.__setattr__(self, "_last_monotonic", monotonic)
            self._identity(configured)
            return last

        return current

    def _context(self, configured, window, bound, work):
        scope = grants.capability.wire._decode_object(configured.scope_bytes, work=work,
            maximum_bytes=grants.MAX_BYTES, maximum_nodes=grants.MAX_NODES, maximum_depth=grants.MAX_DEPTH)
        admitted = grants._verify_on_work(authorization_bytes=configured.recovery_bytes,
            root_public_key=configured.root_public_key, expected_scope=scope,
            live_window=window, transport_deadline_ns=bound, work=work,
            _continuity=configured.ancestor)
        original_current = self._guard(configured, admitted.live, window, bound, work)
        original_current()
        material = bootstrap._verify_historical_on_work(custody_bytes=configured.custody_bytes,
            root_public_key=configured.root_public_key, live_window=window,
            transport_deadline_ns=bound, work=work,
            _current=original_current if configured.ancestor is not None else None)
        original_current()
        custody_digest = plan._frame(proofs.CUSTODY_IDENTITY_DOMAIN, (configured.custody_bytes,), work)
        for observed, expected in ((custody_digest, scope["releaseCustodyDigest"]),
                (material.planner.configuration_digest, scope["configurationDigest"]),
                (material.planner.generation["digest"], scope["generationDigest"]),
                (material.planner.runtime_closure_digest, scope["runtimeClosureDigest"]),
                (material.receiver_identity, scope["receiverIdentity"]),
                (material.delivery_key_digest, scope["deliveryKeyDigest"]),
                (material.delivery_scope["deliveryId"], scope["deliveryId"])):
            plan._same(observed, expected, work, "recovery authority and historical custody binding")
        release_custody._key_binding(material, configured.delivery_key, work)
        original_current()
        state = authorization._admit_enrollment_on_work(
            enrollment_bytes=material.planner.state_enrollment_bytes,
            root_public_key=configured.root_public_key, work=work)
        for observed, expected in ((state.enrollment_digest, material.planner.state_enrollment_digest),
                (state.payload["databaseId"], scope["databaseId"]),
                (state.payload["generationDigest"], scope["generationDigest"])):
            plan._same(observed, expected, work, "recovery historical state enrollment")
        original_current()
        _created, delivery_expiry = bootstrap._scope(material.delivery_scope, work)
        window = processing._narrow(window,
            deadline_epoch_ns=min(admitted.payload["expiresAtEpochNs"], delivery_expiry),
            maximum_lifetime_ns=material.planner.maximum_plan_age_ns,
            maximum_clock_skew_ns=material.planner.maximum_clock_skew_ns)
        bound = min(bound, window[4])
        window, bound = self._narrow(work, window, bound)
        narrowed = self._guard(configured, admitted.live, window, bound, work)

        def current():
            original_current()
            return narrowed()

        current()
        store_scope = {name: scope[name] for name in stores.BINDING_FIELDS}
        store_scope.update(directory=scope["directory"],
            checkpoint={"recordCount": 1, "outcomeDigest": scope["outcomeDigest"]})
        storage = configured.store_configuration
        held_scope = grants.capability.wire._decode_object(storage.scope_bytes, work=work,
            maximum_bytes=stores.grants.MAX_BYTES, maximum_nodes=stores.grants.MAX_NODES,
            maximum_depth=stores.grants.MAX_DEPTH)
        plan._same(held_scope, store_scope, work, "recovery requires independently pinned checkpoint one")
        plan._same(storage.root_spki_digest, grants.keys._spki_on_work(configured.root_public_key, work),
            work, "recovery and outcome storage actual root")
        current()
        forbidden = (material.planner.planner_public_key, state.computation_public_key,
            state.completion_public_key, state.state_public_key)
        return material, scope, forbidden, window, bound, current

    def recover_on_work(self, *, record_bytes, proof_bytes, proof_enrollment_bytes,
            intent_bytes, intent_enrollment_bytes, old_token_bytes, envelope_bytes,
            live_window, transport_deadline_ns, work):
        """Return only the unchanged private token; never create or replay an outcome."""
        capture._SharedLedger(work)
        record_raw = authorization._original(record_bytes, outcomes.MAX_BYTES, "retained release outcome")
        proof_raw = authorization._original(proof_bytes, proofs.MAX_BYTES, "historical release proof")
        proof_enrolled = authorization._original(proof_enrollment_bytes, proof_keys.MAX_BYTES,
            "historical release proof enrollment")
        intent_raw = authorization._original(intent_bytes, intents.MAX_BYTES, "historical release intent")
        intent_enrolled = authorization._original(intent_enrollment_bytes, intent_keys.MAX_BYTES,
            "historical release intent enrollment")
        old_token = delivery._token(old_token_bytes, work)
        envelope = delivery._envelope(envelope_bytes, work)
        total = sum(map(len, (record_raw, proof_raw, proof_enrolled, intent_raw,
            intent_enrolled, old_token, envelope)))
        if total > MAX_ORIGINAL_BYTES:
            _fail("release recovery originals exceed their aggregate bound")
        work.charge(input_bytes=total)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(transport_deadline_ns, window[4])
        configured = self._snapshot_configuration()
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("release recovery owner is already in use")
        try:
            window, bound = self._narrow(work, window, bound)
            material, scope, forbidden, window, bound, current = self._context(configured, window, bound, work)
            # Only this already-admitted parent guard enters child evidence
            # admission; joined_current below must never become its own ancestor.
            evidence_continuity = bootstrap._continuity(current, work) if configured.ancestor is not None else None
            record = outcomes._decode_on_work(record_raw, work)
            record_digest = outcomes._digest_on_work(record_raw, work)
            plan._same(record_digest, scope["outcomeDigest"], work, "fresh recovery exact retained outcome")
            plan._same(record["callerId"], scope["callerId"], work, "recovery independently authorized caller")
            for name in ("configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity"):
                plan._same(record["scope"][name], scope[name], work, "recovery retained scope " + name)
            evidence = record["evidenceBinding"]
            plan._same(evidence["releaseCustodyDigest"], scope["releaseCustodyDigest"], work,
                "recovery retained original custody")
            expected_release = {"activationRequestDigest": material.activation_request_digest,
                "activationOperationId": material.activation_operation_id,
                "consumeRequestDigest": material.consume_request_digest,
                "deliveryEnvelopeDigest": material.delivery_envelope_digest,
                "deliveryScope": material.delivery_scope, "consumeBinding": record["releaseBinding"]["consumeBinding"]}
            plan._same(record["releaseBinding"], expected_release, work, "recovery unchanged original release")
            intent_scope = {name: scope[name] for name in intent_keys.SCOPE_FIELDS}
            current()
            intent = intent_admission._verify_historical_on_work(intent_bytes=intent_raw,
                enrollment_bytes=intent_enrolled, root_public_key=configured.root_public_key,
                forbidden_public_keys=forbidden, expected_scope=intent_scope,
                expected_release=expected_release, old_token_bytes=old_token,
                live_window=window, transport_deadline_ns=bound, work=work,
                _continuity=evidence_continuity)
            plan._same(intent.intent_digest, material.release_intent_digest, work, "recovery old custody exact intent")
            plan._same(intent.intent_digest, evidence["releaseIntentDigest"], work, "recovery retained exact intent")
            enrolled = intent_keys._admit_on_work(enrollment_bytes=intent_enrolled,
                root_public_key=configured.root_public_key, expected_scope=intent_scope,
                forbidden_public_keys=forbidden, work=work)
            plan._same(enrolled.enrollment_digest, intent.payload["enrollmentDigest"], work,
                "recovery actual historical intent key")
            current()
            proof = proof_admission._verify_historical_on_work(proof_bytes=proof_raw,
                enrollment_bytes=proof_enrolled, root_public_key=configured.root_public_key,
                forbidden_public_keys=(*forbidden, enrolled.caller_public_key),
                expected_scope=record["scope"], expected_release=expected_release,
                expected_evidence={name: evidence[name] for name in proof_admission.EVIDENCE_FIELDS},
                expected_intent_interval=(intent.payload["issuedAtEpochNs"], intent.payload["expiresAtEpochNs"]),
                live_window=window, transport_deadline_ns=bound, work=work,
                _continuity=evidence_continuity)
            if (type(intent) is not intent_admission._HistoricalIntentEvidence
                    or type(proof) is not proof_admission._HistoricalProofEvidence):
                _fail("recovery requires genuine historical original admission")

            def joined_current():
                for guard in (intent.live, proof.live, intent.live, proof.live):
                    now = guard()
                    if now < self._last_epoch:
                        _fail("release recovery clock reversed across historical evidence")
                    object.__setattr__(self, "_last_epoch", now)
                    current()
                return self._last_epoch

            joined_current()
            derived = outcomes._encode_on_work(scope={name: proof.payload[name] for name in proofs.SCOPE_FIELDS},
                release_binding={name: proof.payload[name] for name in proofs.RELEASE_FIELDS},
                evidence_binding={"releaseCustodyDigest": scope["releaseCustodyDigest"],
                    "releaseIntentDigest": intent.intent_digest, "stateReceiptDigest": evidence["stateReceiptDigest"],
                    "releaseProofDigest": proof.proof_digest, "proofEnrollmentDigest": proof.payload["enrollmentDigest"],
                    "intentEnrollmentDigest": intent.payload["enrollmentDigest"]},
                caller_id=intent.payload["callerId"], work=work)
            stores._same_bytes(derived, record_raw, work, "recovery exact original-derived outcome")
            work.charge(hashes=1, input_bytes=len(envelope))
            digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(envelope).hexdigest())
            joined_current()
            plan._same(digest, material.delivery_envelope_digest, work, "recovery original ciphertext")
            owned, aad, delivery_current = delivery._prepare(configured.delivery_key,
                material.delivery_scope, window, bound, work)

            def opening_current():
                joined_current()
                now = delivery_current()
                if now < self._last_epoch:
                    _fail("release recovery clock reversed across delivery opening")
                object.__setattr__(self, "_last_epoch", now)
                return joined_current()

            binding = {name: scope[name] for name in stores.BINDING_FIELDS}

            def read_exact():
                opening_current()
                observed = stores.ReleaseOutcomeStore.retain_on_work(configured.store,
                    record_bytes=record_raw, root_public_key=configured.root_public_key,
                    expected_binding=binding, live_window=window, transport_deadline_ns=bound, work=work)
                opening_current()
                plan._same(observed, scope["outcomeDigest"], work, "recovery unchanged durable readback")
                opening_current()

            # Configuration checkpoint-one admission makes both operations
            # actual readbacks of an existing record, never an empty-slot append.
            read_exact()
            token = delivery._open_captured(envelope, configured.delivery_key, owned, aad, work, opening_current)
            read_exact()
            opening_current()
            return token
        except BaseException:
            self._close_preserving(configured)
            raise
        finally:
            lock.release()

    def _close_preserving(self, configured):
        object.__setattr__(self, "_closed", True)
        object.__setattr__(self, "_ready", False)
        object.__setattr__(self, "_configured", None)
        object.__setattr__(self, "_seal", None)
        try:
            stores.ReleaseOutcomeStore.close(configured.store)
        except BaseException:
            # Preserve the original failure and retained bytes; never retry I/O.
            pass

    def close(self):
        if type(self) is not OidcSessionActivationReleaseRecovery or self._pid != os.getpid():
            _fail("release recovery close requires its actual process owner")
        if self._closed:
            return
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("release recovery cannot close during another operation")
        try:
            self._close_preserving(self._configured)
        finally:
            lock.release()
