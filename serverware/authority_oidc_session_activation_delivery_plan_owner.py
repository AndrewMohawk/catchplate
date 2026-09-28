"""Configured consume planning with exact encrypted original retention.

This owner composes actual read/write acquisition with genuine original state,
completed-activation provenance and signed-plan production before durable append.
Known-envelope replay binds the exact ciphertext and repeats original admission;
storage integrity is never proof, execution authority or permission to retry.
Independent configuration/policy pins still need actual cold root admission.
No key, plaintext token, SQL mutation or release is returned.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading

from serverware import authority_oidc_session_activation_delivery_plan as plan
from serverware import authority_oidc_session_activation_delivery_planning as planning
from serverware import authority_oidc_session_activation_delivery_journal as custody
from serverware import authority_oidc_session_activation_delivery_retained as retained
from serverware import authority_oidc_session_activation_delivery_writes as writes
from serverware import authority_oidc_session_activation_execution_expectations as expectations
from serverware import authority_oidc_session_activation_history_custody as history


registration, assertion = planning.transition.registration, planning.transition.assertion
evidence, clock = registration.evidence, assertion.clock
contract, state = plan.contract, plan.state
OPERATION = planning.OPERATION
_LOCK_TYPE = type(threading.Lock())
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_ACTIVATION_SCOPE_FIELDS = frozenset({"authorizationDigest", "databaseId", "generationDigest",
    "pendingSequence", "pendingHeadDigest", "fence"})


class OidcSessionActivationDeliveryPlanOwnerError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationDeliveryPlanOwnerError(message)


@dataclass(frozen=True, slots=True, repr=False)
class PreparedDeliveryPlan:
    """Token-free plan and exact journal identity; never execution authority."""

    request_bytes: bytes
    scope_bytes: bytes
    envelope_bytes: bytes
    plan_digest: str
    journal_digest: str


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    source_revision: str
    read_planner: object
    read_configuration: tuple
    planner_private_key: object
    planner_public_key: object
    planner_identity: tuple
    planner_spki_digest: str
    configuration_digest: str
    authentication_policy_bytes: bytes
    trust_policy_bytes: bytes
    maximum_plan_age_ns: int
    maximum_clock_skew_ns: int
    state_enrollment_bytes: bytes
    state_root_public_key: object
    complete_root_vector_bytes: bytes
    historical_custody: object
    historical_configuration: object
    activation_expectations_bytes: bytes
    activation_scope_bytes: bytes
    activation_planner_public_key: object
    operation_public_key: object
    journal: object
    journal_configuration: tuple


def _json(original, work):
    return evidence.wire._decode_object(original, work=work,
        maximum_bytes=contract.authority.MAX_RESULT_BYTES,
        maximum_nodes=assertion.MAX_CONTEXT_NODES, maximum_depth=12)


def _scope_shape(value, work):
    registration._closed(value, _ACTIVATION_SCOPE_FIELDS, "configured activation provenance scope")
    for name in ("authorizationDigest", "generationDigest", "pendingHeadDigest"):
        registration._digest(value[name])
    state.head.authorization._token(value["databaseId"])
    for name in ("pendingSequence", "fence"):
        registration._integer(value[name], "configured activation " + name, 1)


def _bytes_equal(left, right, work, label):
    if type(left) is not bytes or type(right) is not bytes:
        _fail("consume " + label + " requires immutable originals")
    work.charge(input_bytes=len(left) + len(right))
    if left != right:
        _fail("consume " + label + " originals differ")


def _journal_scope(configured, request, envelope, work):
    return {"sourceRevision": configured.source_revision,
        "configurationDigest": configured.configuration_digest,
        "requestDigest": request["requestDigest"],
        "planDigest": evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope,), work)}


def _authenticate_known(envelope_bytes, request, scope, configured, current, work):
    """Authenticate only the lookup prerequisite; full replay still follows."""
    envelope = contract._decode_on_work(envelope_bytes, envelope=True, work=work)
    payload = envelope["payload"]
    for name in ("requestDigest", "operationId"):
        registration._same(payload[name], request[name], work, "known consume " + name)
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        registration._same(payload[name], scope[name], work, "known consume " + name)
    unsigned = contract._encode_on_work(payload, work=work)
    evidence.keys._public_binding(configured.planner_public_key, configured.planner_spki_digest, work)
    evidence.capability._signature(configured.planner_public_key, envelope["signatureBase64Url"],
        contract.SIGNATURE_DOMAIN, unsigned, evidence.capture._SharedLedger(work))
    now = current()
    evidence._fresh(payload, now, configured.maximum_plan_age_ns, configured.maximum_clock_skew_ns)
    if now >= scope["deadlineEpochNs"] or payload["expiresAtEpochNs"] > scope["deadlineEpochNs"]:
        _fail("known consume plan exceeds its independently expected original deadline")
    return payload


def _window(configured, live_window, deadline):
    value = clock._validate(live_window)
    registration._integer(deadline, "consume planner inherited deadline", 1)
    if (value[5] > configured.maximum_plan_age_ns
            or value[6] > configured.maximum_clock_skew_ns):
        _fail("consume owner processing exceeds its independently configured policy")
    return value, min(deadline, value[4])


def _fixed_scope(configured, work):
    return {"authenticationPolicy": _json(configured.authentication_policy_bytes, work),
        "trustPolicy": _json(configured.trust_policy_bytes, work),
        "configurationDigest": configured.configuration_digest,
        "plannerIdentity": dict(zip(_IDENTITY_FIELDS, configured.planner_identity)),
        "plannerSpkiDigest": configured.planner_spki_digest,
        "maximumPlanAgeNs": configured.maximum_plan_age_ns,
        "maximumClockSkewNs": configured.maximum_clock_skew_ns}


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationDeliveryPlanOwner:
    _configured: _Configuration | None
    _seal: _Configuration | None
    _pid: int
    _lock: object
    _closed: bool

    def __init__(self, *, read_planner, planner_private_key, planner_public_key,
            expected_planner_identity, expected_planner_spki_digest, configuration_digest,
            authn_policy, trust_policy, maximum_plan_age_ns, maximum_clock_skew_ns,
            state_enrollment_bytes, state_root_public_key, complete_root_vector_bytes,
            historical_custody, activation_expectations, activation_scope,
            activation_planner_public_key, operation_public_key, journal,
            live_window, transport_deadline_ns, work, _current=None):
        ledger = evidence.capture._SharedLedger(work)
        if (type(read_planner) is not planning.OidcSessionActivationDeliveryReadPlanner
                or type(historical_custody) is not history.OidcSessionActivationHistoryCustody
                or type(journal) is not custody.DeliveryOriginalJournal):
            _fail("consume planning requires actual configured read, history and journal owners")
        root, private, public = state_root_public_key, planner_private_key, planner_public_key
        original_planner, operation_key = activation_planner_public_key, operation_public_key
        if not isinstance(private, evidence.Ed25519PrivateKey):
            _fail("consume planning requires the actual configured Ed25519 private key")
        for key in (root, public, original_planner, operation_key):
            state.head.authorization._public(key)
        enrolled = state._original(state_enrollment_bytes,
            state.head.authorization.MAX_ENROLLMENT_BYTES, "enrollment")
        vector = state._original(complete_root_vector_bytes, state.vector.MAX_BYTES, "complete vector")
        # All caller graphs are owned before key, root or expectation hashing.
        owned = assertion._Capture(ledger, maximum_bytes=contract.authority.MAX_RESULT_BYTES).visit({
            "identity": expected_planner_identity, "spki": expected_planner_spki_digest,
            "configuration": configuration_digest, "policy": authn_policy, "trust": trust_policy,
            "age": maximum_plan_age_ns, "skew": maximum_clock_skew_ns,
            "activationExpectations": activation_expectations, "activationScope": activation_scope})
        evidence._identity(owned["identity"])
        for name in ("spki", "configuration"):
            registration._digest(owned[name])
        registration._integer(owned["age"], "consume plan age", 1, contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
        registration._integer(owned["skew"], "consume plan skew", 0, contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
        registration._closed(owned["policy"], {"userVerification", "allowedAuthenticatorClasses",
            "requireHardwareAttestation"}, "consume authentication policy")
        registration._closed(owned["trust"], {"roots", "currentBundleDigest", "currentBundleSequence"},
            "consume trust policy")
        _scope_shape(owned["activationScope"], work)
        window = clock._validate(live_window)
        registration._integer(transport_deadline_ns, "consume construction deadline", 1)
        bound = min(window[4], transport_deadline_ns)
        if window[5] > owned["age"] or window[6] > owned["skew"]:
            _fail("consume construction window exceeds configured policy")
        _window_value, current = planning.transition.delivery._window(window, bound, work)
        current = planning.transition.delivery._join_current(current, _current, work)
        current()
        observed = expectations._capture_on_work(owned["activationExpectations"], work=work)
        selected = history.OidcSessionActivationHistoryCustody._consume_context_on_work(
            historical_custody, root_public_key=root, current_root_enrollment_bytes=enrolled,
            configuration_digest=owned["configuration"], live_window=window,
            transport_deadline_ns=bound, work=work, _current=_current,
            _additional_original_bytes=len(enrolled) + len(vector) + work.measure(owned)[0])
        if type(selected) is not history._ConsumeContext:
            _fail("consume constructor requires genuine same-call history context")
        registration._same(observed["scope"]["configurationDigest"], selected.configuration_digest, work,
            "consume original activation configuration cohort")
        read_config = planning.OidcSessionActivationDeliveryReadPlanner._snapshot_configuration(read_planner)
        if read_config[3] != owned["skew"]:
            _fail("consume reader and configured clock policy differ")
        evidence.keys._public_binding(public, owned["spki"], work)
        evidence.keys._pair_on_work(private, public, work)
        evidence.keys._public_binding(original_planner, observed["scope"]["plannerSpkiDigest"], work)
        evidence.keys._public_binding(original_planner,
            evidence.keys._spki_on_work(selected.planner_public_key, work), work)
        root_spki = evidence.keys._spki_on_work(root, work)
        original_root_spki = evidence.keys._spki_on_work(selected.operation_public_key, work)
        registration._same(evidence.keys._spki_on_work(operation_key, work), original_root_spki, work,
            "consume original activation operation root")
        admitted = state.head.authorization._admit_enrollment_on_work(
            enrollment_bytes=enrolled, root_public_key=root, work=work)
        for role in ("state", "computation", "completion"):
            if admitted.payload[role]["spkiDigest"] == owned["spki"]:
                _fail("consume planner overlaps an enrolled state-purpose key")
        if owned["spki"] in (root_spki, original_root_spki, observed["scope"]["plannerSpkiDigest"]):
            _fail("consume planner requires a separate root/original-activation signing key")
        state.vector._decode_on_work(vector, work=work)
        history.OidcSessionActivationHistoryCustody._require_consume_planning_on_work(
            historical_custody, work=work)
        selected.live()
        narrowed, clipped = selected.window, selected.deadline_ns
        historical_configuration = history.OidcSessionActivationHistoryCustody._snapshot_configuration(historical_custody)
        journal_configuration = custody.DeliveryOriginalJournal._snapshot_configuration(journal)
        if type(journal_configuration) is not tuple or len(journal_configuration) != 8:
            _fail("consume journal configuration inventory differs")
        registration._same(journal_configuration[:2],
            (contract.authority.SOURCE_REVISION, owned["configuration"]), work, "consume journal source/configuration")
        _bytes_equal(journal_configuration[3], historical_configuration.bundle_key, work, "journal/history bundle key")
        _bytes_equal(journal_configuration[4], historical_configuration.delivery_key, work, "journal/history delivery key")
        current()
        configured = _Configuration(contract.authority.SOURCE_REVISION, read_planner, read_config,
            private, public, tuple(owned["identity"][name] for name in _IDENTITY_FIELDS),
            owned["spki"], owned["configuration"], registration._wire(owned["policy"], work),
            registration._wire(owned["trust"], work), owned["age"], owned["skew"], enrolled, root, vector,
            historical_custody, historical_configuration, registration._wire(observed, work),
            registration._wire(owned["activationScope"], work), original_planner, operation_key,
            journal, journal_configuration)
        object.__setattr__(self, "_configured", configured)
        object.__setattr__(self, "_seal", configured)
        object.__setattr__(self, "_pid", os.getpid())
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_closed", False)
        self._guard(configured, narrowed, clipped, work, _current=_current)()

    def _snapshot_configuration(self):
        if (type(self) is not OidcSessionActivationDeliveryPlanOwner or self._closed
                or self._pid != os.getpid() or type(self._lock) is not _LOCK_TYPE
                or type(self._configured) is not _Configuration or self._configured is not self._seal):
            _fail("consume plan owner is closed, changed or belongs to another process")
        configured = self._configured
        if (configured.source_revision != contract.authority.SOURCE_REVISION
                or planning.OidcSessionActivationDeliveryReadPlanner._snapshot_configuration(
                    configured.read_planner) is not configured.read_configuration
                or history.OidcSessionActivationHistoryCustody._snapshot_configuration(
                    configured.historical_custody) is not configured.historical_configuration
                or custody.DeliveryOriginalJournal._snapshot_configuration(
                    configured.journal) is not configured.journal_configuration):
            _fail("consume configured read, history or journal owner changed")
        return configured

    def _guard(self, configured, window, bound, work, *, _current=None):
        _window_value, current = planning.transition.delivery._window(window, bound, work)
        current = planning.transition.delivery._join_current(current, _current, work)

        def check():
            if self._snapshot_configuration() is not configured:
                _fail("consume owner changed before a current clock check")
            now = current()
            if self._snapshot_configuration() is not configured:
                _fail("consume owner changed during a current clock check")
            return now

        return check

    def prepare(self, *, request, old_token_bytes, expected_delivery_id, expected_user_id,
            expected_session_id, expected_credential_id, expected_credential_record_id,
            expected_challenge_id, business_before_roots, authorization_before_roots,
            expected_counted_heads, head_query_bytes, head_observation_bytes, activation_originals,
            live_window, transport_deadline_ns, work, _current=None):
        configured = self._snapshot_configuration()
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("consume plan owner is already in use")
        try:
            token = assertion._token(old_token_bytes, work)
            query = state._original(head_query_bytes, state.head.MAX_QUERY_BYTES, "query")
            observation = state._original(head_observation_bytes, state.head.MAX_BYTES, "observation")
            raw = plan._activation_originals(activation_originals, work)
            subject = {"deliveryId": expected_delivery_id, "userId": expected_user_id,
                "sessionId": expected_session_id, "credentialId": expected_credential_id,
                "credentialRecordId": expected_credential_record_id, "challengeId": expected_challenge_id}
            # This is original graph capture only, not a previous read result.
            owned = planning._capture(request=request, business_before_roots=business_before_roots,
                authorization_before_roots=authorization_before_roots, expected_counted_heads=expected_counted_heads,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns,
                work=work, transition_inputs=subject)
            window, bound = _window(configured, owned["liveWindow"], owned["transportDeadlineNs"])
            current = self._guard(configured, window, bound, work, _current=_current)
            current()
            window, bound = history.OidcSessionActivationHistoryCustody.processing_bounds_on_work(
                configured.historical_custody, live_window=window, transport_deadline_ns=bound, work=work,
                _current=_current)
            current()
            current = self._guard(configured, window, bound, work, _current=_current)
            subject, request = owned["transitionInputs"], owned["request"]
            history.OidcSessionActivationHistoryCustody.bind_consume_request_on_work(
                configured.historical_custody, expected_consume_request=request, work=work)
            scope = {**subject, **_fixed_scope(configured, work), "deadlineEpochNs": window[3]}
            payload = state._verify_on_work(request=request, scope=scope, old_token_bytes=token,
                complete_root_vector_bytes=configured.complete_root_vector_bytes,
                query_bytes=query, observation_bytes=observation, enrollment_bytes=configured.state_enrollment_bytes,
                root_public_key=configured.state_root_public_key, now_epoch_ns=current(), work=work)
            projected = state._project_on_work(vector_bytes=configured.complete_root_vector_bytes,
                expected_vector_digest=payload["vectorDigest"], work=work)
            planning.semantics._canonical_equal((projected.business_before_roots, projected.authorization_before_roots,
                projected.expected_counted_heads), (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"],
                owned["expectedCountedHeads"]), work=work,
                label="consume owner independent roots and exact head projection differ")
            if current() >= payload["expiresAtEpochNs"]:
                _fail("consume head observation expired before acquisition")
            acquired = planning.OidcSessionActivationDeliveryReadPlanner.acquire_transition(configured.read_planner,
                request=request, business_before_roots=owned["businessBeforeRoots"],
                authorization_before_roots=owned["authorizationBeforeRoots"],
                expected_counted_heads=owned["expectedCountedHeads"], old_token_bytes=token,
                expected_delivery_id=subject["deliveryId"], expected_user_id=subject["userId"],
                expected_session_id=subject["sessionId"], expected_credential_id=subject["credentialId"],
                expected_credential_record_id=subject["credentialRecordId"], expected_challenge_id=subject["challengeId"],
                authn_policy=scope["authenticationPolicy"], trust_policy=scope["trustPolicy"],
                live_window=window, transport_deadline_ns=bound, work=work, _current=_current)
            current()
            proof = writes._encode_on_work(request_digest=request["requestDigest"],
                counted_before_heads=acquired.counted_before_heads, write_inputs=acquired.write_inputs, work=work)
            context = planning.transition.core.KernelContext(OPERATION, request["arguments"], acquired.selected_rows,
                acquired.database_now, request["requestDigest"], query_reads=acquired.query_reads)
            originals = {"request": request, "scope": scope, "old_token_bytes": token,
                "business_before_roots": owned["businessBeforeRoots"],
                "authorization_before_roots": owned["authorizationBeforeRoots"],
                "before_proofs": acquired.before_proofs, "read_heads": acquired.read_heads,
                "query_frontiers": acquired.query_frontiers, "expected_counted_heads": owned["expectedCountedHeads"],
                "write_proof_bytes": proof, "state_enrollment_bytes": configured.state_enrollment_bytes,
                "state_root_public_key": configured.state_root_public_key,
                "complete_root_vector_bytes": configured.complete_root_vector_bytes,
                "head_query_bytes": query, "head_observation_bytes": observation, "activation_originals": raw,
                "activation_expectations": _json(configured.activation_expectations_bytes, work),
                "activation_scope": _json(configured.activation_scope_bytes, work),
                "activation_planner_public_key": configured.activation_planner_public_key,
                "operation_public_key": configured.operation_public_key,
                "historical_custody": configured.historical_custody,
                "live_window": window, "transport_deadline_ns": bound, "work": work}
            envelope = plan._produce_on_work(context, **originals,
                planner_private_key=configured.planner_private_key, planner_public_key=configured.planner_public_key,
                _current=_current)
            signed = contract._decode_on_work(envelope, envelope=True, work=work)["payload"]
            plan_digest = evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope,), work)
            # Recapture ordinary owned originals, not a cached proof result.
            invocation = plan._capture(context, **originals, _current=_current)
            journal_scope, original_bytes = retained._encode_on_work(invocation,
                envelope_bytes=envelope, plan_digest=plan_digest, work=work)
            expiry = min(signed["expiresAtEpochNs"], payload["expiresAtEpochNs"])
            window = plan.windows._narrow(window, deadline_epoch_ns=expiry,
                maximum_lifetime_ns=configured.maximum_plan_age_ns,
                maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
            bound = min(bound, window[4])
            current = self._guard(configured, window, bound, work, _current=_current)
            current()
            journal_digest = custody.DeliveryOriginalJournal.append(configured.journal,
                scope=journal_scope, original_bytes=original_bytes,
                live_window=window, transport_deadline_ns=bound, work=work, _current=_current)
            result = PreparedDeliveryPlan(registration._wire(request, work), registration._wire(scope, work),
                envelope, plan_digest, registration._digest(journal_digest))
            if current() >= expiry:
                _fail("consume plan expired after retention; no replacement or retry is authorized")
            return result
        finally:
            lock.release()

    def verify_retained(self, *, envelope_bytes, expected_request, expected_scope,
            business_before_roots, authorization_before_roots, expected_counted_heads,
            expected_journal_digest, live_window, transport_deadline_ns, work, _current=None):
        """Read only exact retained originals; never reacquire, re-sign or renew."""
        envelope = state._original(envelope_bytes, contract.MAX_BYTES, "known consume plan")
        journal_digest = registration._digest(expected_journal_digest)
        configured = self._snapshot_configuration()
        lock = self._lock
        if not lock.acquire(blocking=False):
            _fail("consume plan owner is already in use")
        try:
            _original, _scope, _window_value, _bound, current, full = (
                OidcSessionActivationDeliveryPlanOwner._verify_retained_locked(self,
                    configured=configured, envelope_bytes=envelope, expected_request=expected_request,
                    expected_scope=expected_scope, business_before_roots=business_before_roots,
                    authorization_before_roots=authorization_before_roots,
                    expected_counted_heads=expected_counted_heads, expected_journal_digest=journal_digest,
                    live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work,
                    _current=_current))
            full.live()
            result = PreparedDeliveryPlan(registration._wire(full.invocation.request, work),
                registration._wire(full.invocation.scope, work),
                envelope, full.plan_digest, journal_digest)
            full.live()
            if current() >= full.valid_until_epoch_ns:
                _fail("retained consume plan expired before token-free return")
            return result
        finally:
            lock.release()

    def _verify_retained_locked(self, *, configured, envelope_bytes, expected_request, expected_scope,
            business_before_roots, authorization_before_roots, expected_counted_heads,
            expected_journal_digest, live_window, transport_deadline_ns, work, _current=None):
        """Actual same-call originals/full replay; the caller holds this owner lock."""
        if (type(self._lock) is not _LOCK_TYPE or not self._lock.locked()
                or self._snapshot_configuration() is not configured):
            _fail("consume retained replay requires the held actual owner lock/configuration")
        envelope = state._original(envelope_bytes, contract.MAX_BYTES, "known consume plan")
        owned = planning._capture(request=expected_request,
            business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads,
            transition_inputs={"scope": expected_scope, "journalDigest": expected_journal_digest},
            live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
        request, expected = owned["request"], owned["transitionInputs"]
        scope, journal_digest = expected["scope"], registration._digest(expected["journalDigest"])
        registration._closed(scope, state.SCOPE_FIELDS, "independently expected retained consume scope")
        fixed = _fixed_scope(configured, work)
        registration._same({name: scope[name] for name in fixed}, fixed, work, "configured retained consume scope")
        for argument, name in (("delivery_id", "deliveryId"), ("user_id", "userId"),
                ("session_id", "sessionId"), ("credential_id", "credentialId"),
                ("credential_record_id", "credentialRecordId"), ("challenge_id", "challengeId")):
            registration._same(scope[name], request["arguments"][argument], work, "retained consume subject")
        window, bound = _window(configured, owned["liveWindow"], owned["transportDeadlineNs"])
        window = plan.windows._narrow(window, deadline_epoch_ns=scope["deadlineEpochNs"],
            maximum_lifetime_ns=configured.maximum_plan_age_ns,
            maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
        bound = min(bound, window[4])
        current = self._guard(configured, window, bound, work, _current=_current)
        current()
        history.OidcSessionActivationHistoryCustody.bind_consume_request_on_work(
            configured.historical_custody, expected_consume_request=request, work=work)
        window, bound = history.OidcSessionActivationHistoryCustody.processing_bounds_on_work(
            configured.historical_custody, live_window=window, transport_deadline_ns=bound, work=work,
            _current=_current)
        current()
        current = self._guard(configured, window, bound, work, _current=_current)
        signed = _authenticate_known(envelope, request, scope, configured, current, work)
        window = plan.windows._narrow(window, deadline_epoch_ns=signed["expiresAtEpochNs"],
            maximum_lifetime_ns=configured.maximum_plan_age_ns,
            maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
        bound = min(bound, window[4])
        current = self._guard(configured, window, bound, work, _current=_current)
        journal_scope = _journal_scope(configured, request, envelope, work)
        current()
        original = custody.DeliveryOriginalJournal.read_bound(configured.journal,
            scope=journal_scope, expected_journal_digest=journal_digest,
            live_window=window, transport_deadline_ns=bound, work=work, _current=_current)
        if original is None:
            _fail("exact retained consume original is absent; no regeneration is authorized")
        current()
        context, originals = retained._restore_on_work(original, scope=journal_scope, work=work)
        for name, value in (("request", request), ("scope", scope),
                ("activation_expectations", _json(configured.activation_expectations_bytes, work)),
                ("activation_scope", _json(configured.activation_scope_bytes, work))):
            registration._same(originals[name], value, work, "independent retained consume " + name)
        planning.semantics._canonical_equal(
            (originals["business_before_roots"], originals["authorization_before_roots"],
                originals["expected_counted_heads"]),
            (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"], owned["expectedCountedHeads"]),
            work=work, label="retained consume independent primary roots and counted heads differ")
        for name, value in (("envelope_bytes", envelope),
                ("state_enrollment_bytes", configured.state_enrollment_bytes),
                ("complete_root_vector_bytes", configured.complete_root_vector_bytes)):
            _bytes_equal(originals[name], value, work, name)
        current()
        # Keys, custody and the original current allowance never come from storage.
        full = plan._verify_full_on_work(context, **originals,
            state_root_public_key=configured.state_root_public_key,
            activation_planner_public_key=configured.activation_planner_public_key,
            operation_public_key=configured.operation_public_key,
            historical_custody=configured.historical_custody,
            planner_public_key=configured.planner_public_key,
            live_window=window, transport_deadline_ns=bound, work=work, _current=_current)
        registration._same(full.plan_digest, journal_scope["planDigest"], work, "retained consume plan identity")
        full.live()
        current()
        window = plan.windows._narrow(full.invocation.window, deadline_epoch_ns=full.valid_until_epoch_ns,
            maximum_lifetime_ns=configured.maximum_plan_age_ns,
            maximum_clock_skew_ns=configured.maximum_clock_skew_ns)
        bound = min(bound, full.invocation.monotonic_deadline, window[4])
        current = self._guard(configured, window, bound, work, _current=_current)
        full.live()
        if current() >= full.valid_until_epoch_ns:
            _fail("retained consume plan expired before its private same-call return")
        return original, journal_scope, window, bound, current, full

    def close(self):
        if type(self) is not OidcSessionActivationDeliveryPlanOwner or self._pid != os.getpid():
            _fail("consume plan close belongs to another owner/process")
        lock = self._lock
        if type(lock) is not _LOCK_TYPE or not lock.acquire(blocking=False):
            _fail("consume plan owner is already in use")
        try:
            if self._closed:
                return
            configured = self._configured
            object.__setattr__(self, "_closed", True)
            object.__setattr__(self, "_configured", None)
            object.__setattr__(self, "_seal", None)
            custody.DeliveryOriginalJournal.close(configured.journal)
        finally:
            lock.release()
