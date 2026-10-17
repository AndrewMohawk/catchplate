"""Live private consume-original replay, not a grant or execution capability.

The known consume-plan signature precedes private decryption. Independent
request, policy, vector, state and activation-provenance originals are never
learned from the stored document. Only the genuine consume-grant history role
can supply historical provenance. The returned same-call facts contain no
plaintext token, key, custody owner or generic replay capability.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_oidc_session_activation_delivery_execution_bundle as bundle
from catchplate import authority_oidc_session_activation_delivery_execution_expectations as expectations
from catchplate import authority_oidc_session_activation_delivery_retained as retained
from catchplate import oidc_session_activation_delivery as lifetime


plan, journal = retained.plan, retained.journal
contract, state, custody = plan.contract, plan.state, plan.custody
assertion, registration, evidence, clock = plan.assertion, plan.registration, plan.evidence, plan.clock
OPERATION = contract.OPERATION
IDENTITY_DOMAIN = bundle.RECORD_IDENTITY_DOMAIN
MAX_ORIGINAL_BYTES = contract.MAX_ORIGINAL_BYTES


class OidcSessionActivationDeliveryExecutionReplayError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReplayedDelivery:
    """Ordinary derived facts; no receiving API accepts this as proof input."""
    operation: str
    request: dict
    originals: tuple
    retained_record_digest: str
    before_vector_bytes: bytes
    after_vector_bytes: bytes
    before_vector_digest: str
    after_vector_digest: str
    result: object
    original_interval: tuple
    plan_digest: str
    mutations: tuple
    work_units: int
    live_window: tuple
    deadline_ns: int
    valid_until_epoch_ns: int
    live: object
    selected_rows: tuple


def _fail(message):
    raise OidcSessionActivationDeliveryExecutionReplayError(message)


def _bytes_equal(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail("consume execution original " + label + " differs")


def _scope(owned, window, work):
    """Validate owned independent policy/subject data, not a stored policy."""
    request, scope = owned["request"], owned["scope"]
    for name in ("configurationDigest", "plannerSpkiDigest"):
        registration._digest(scope[name])
    evidence._identity(scope["plannerIdentity"])
    for name, maximum in (("deliveryId", 128), ("userId", 1024), ("sessionId", 128),
            ("credentialId", 1366), ("credentialRecordId", 1024), ("challengeId", 1024)):
        registration._text(scope[name], name, maximum, work)
    registration._integer(scope["maximumPlanAgeNs"], "consume execution plan age", 1,
        contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._integer(scope["maximumClockSkewNs"], "consume execution plan skew", 0,
        contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    registration._integer(scope["deadlineEpochNs"], "consume execution original deadline", 1)
    if (window[5] > scope["maximumPlanAgeNs"] or window[6] > scope["maximumClockSkewNs"]
            or window[3] > scope["deadlineEpochNs"]):
        _fail("consume execution processing exceeds its independent original scope")
    arguments = plan.transition._arguments(request["arguments"], work)
    for field, name in (("delivery_id", "deliveryId"), ("user_id", "userId"),
            ("session_id", "sessionId"), ("credential_id", "credentialId"),
            ("credential_record_id", "credentialRecordId"), ("challenge_id", "challengeId")):
        registration._same(arguments[field], scope[name], work, "consume execution subject " + name)


def _authenticate(envelope_bytes, request, scope, planner_key, current, work):
    """Authenticate the known original before opening its private ciphertext."""
    current()
    envelope = contract._decode_on_work(envelope_bytes, envelope=True, work=work)
    payload = envelope["payload"]
    for name in ("requestDigest", "operationId"):
        registration._same(payload[name], request[name], work, "known consume plan " + name)
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        registration._same(payload[name], scope[name], work, "known consume plan " + name)
    unsigned = contract._encode_on_work(payload, work=work)
    evidence.keys._public_binding(planner_key, scope["plannerSpkiDigest"], work)
    evidence.capability._signature(planner_key, envelope["signatureBase64Url"],
        contract.SIGNATURE_DOMAIN, unsigned, evidence.capture._SharedLedger(work))
    now = current()
    evidence._fresh(payload, now, scope["maximumPlanAgeNs"], scope["maximumClockSkewNs"])
    if payload["expiresAtEpochNs"] > scope["deadlineEpochNs"] or now >= scope["deadlineEpochNs"]:
        _fail("known consume plan exceeds its independent original interval")
    identity = evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope_bytes,), work)
    if current() >= payload["expiresAtEpochNs"]:
        _fail("known consume plan expired before private opening")
    return payload, identity


def _narrowed(original, narrowed, previous_bound, bound):
    if (narrowed[:3] != original[:3] or any(narrowed[index] > original[index] for index in (3, 4, 5, 6))
            or type(bound) is not int or not 0 < bound <= min(previous_bound, narrowed[4])):
        _fail("consume execution replaced or widened its original processing allowance")


def _replay_on_work(*, envelope_bytes, encrypted_originals_bytes, expected_request,
        expected_scope, expected_journal_digest, state_enrollment_bytes, before_vector_bytes,
        activation_expectations, activation_scope, planner_public_key, activation_planner_public_key,
        operation_public_key, state_root_public_key, historical_custody, bundle_key,
        live_window, transport_deadline_ns, work):
    """Derive token-free live facts from originals under independent receiving pins."""
    ledger = evidence.capture._SharedLedger(work)
    envelope = state._original(envelope_bytes, contract.MAX_BYTES, "known consume plan")
    ciphertext = bundle._bounded_frame(encrypted_originals_bytes)
    enrollment = state._original(state_enrollment_bytes,
        state.head.authorization.MAX_ENROLLMENT_BYTES, "independent state enrollment")
    before_bytes = state._original(before_vector_bytes, state.vector.MAX_BYTES, "independent complete vector")
    total = sum(map(len, (envelope, ciphertext, enrollment, before_bytes)))
    if total > MAX_ORIGINAL_BYTES:
        _fail("consume execution originals exceed the fixed aggregate bound")
    public, old_public, operation_key, root = (planner_public_key, activation_planner_public_key,
        operation_public_key, state_root_public_key)
    for key in (public, old_public, operation_key, root):
        state.head.authorization._public(key)
    owner, key = historical_custody, bundle_key
    if type(owner) is not custody.OidcSessionActivationHistoryCustody:
        _fail("consume execution requires the actual consume-grant history owner")
    if type(key) is not bytes or len(key) != bundle.KEY_BYTES:
        _fail("consume execution requires an independently admitted exact bundle key")
    digest = registration._digest(expected_journal_digest)
    window = clock._validate(live_window)
    registration._integer(transport_deadline_ns, "consume execution inherited deadline", 1)
    bound = min(window[4], transport_deadline_ns)
    work.charge(input_bytes=total + len(key))
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "expectations": {"request": expected_request, "scope": expected_scope, "journalDigest": digest},
        "activationExpectations": activation_expectations, "activationScope": activation_scope})
    # All external graphs, immutable originals, key references and the actual
    # owner are held before the first commitment, clock or native callback.
    expected = expectations._capture_on_work(owned["expectations"], work=work)
    request, scope = expected["request"], expected["scope"]
    _scope(expected, window, work)
    registration._closed(owned["activationScope"], plan._ACTIVATION_SCOPE_FIELDS,
        "independent consume execution activation scope")
    custody.OidcSessionActivationHistoryCustody._require_consume_receiving_on_work(owner, work=work)
    custody.OidcSessionActivationHistoryCustody.bind_consume_request_on_work(owner,
        expected_consume_request=request, work=work)
    custody.OidcSessionActivationHistoryCustody.bind_context_on_work(owner,
        root_public_key=root, current_root_enrollment_bytes=enrollment, work=work)
    configured = custody.OidcSessionActivationHistoryCustody._snapshot_configuration(owner)
    work.charge(input_bytes=3 * bundle.KEY_BYTES)
    if key in (configured.bundle_key, configured.delivery_key):
        _fail("consume execution bundle key reuses a historical private-key purpose")
    narrowed, narrowed_bound = custody.OidcSessionActivationHistoryCustody.processing_bounds_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    _narrowed(window, narrowed, bound, narrowed_bound)
    window, bound = narrowed, narrowed_bound
    owner_live = custody.OidcSessionActivationHistoryCustody.check_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    _window, processing = lifetime._window(window, bound, work)

    def current():
        first = processing()
        admitted = owner_live()
        now = processing()
        if (not first <= admitted <= now
                or custody.OidcSessionActivationHistoryCustody._snapshot_configuration(owner) is not configured):
            _fail("consume execution custody changed or processing clocks reversed")
        return now

    payload, plan_digest = _authenticate(envelope, request, scope, public, current, work)
    original_window, original_bound = window, bound
    window = plan.windows._narrow(window, deadline_epoch_ns=payload["expiresAtEpochNs"],
        maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
    bound = min(bound, window[4])
    _narrowed(original_window, window, original_bound, bound)
    _window, known_live = lifetime._window(window, bound, work)

    def known_current():
        first, now = current(), known_live()
        if now < first or now >= payload["expiresAtEpochNs"]:
            _fail("known consume plan expired during private original replay")
        return now

    context_fields = {"schema": bundle.CONTEXT_SCHEMA, "operation": OPERATION,
        "sourceRevision": contract.authority.SOURCE_REVISION,
        "configurationDigest": scope["configurationDigest"], "requestDigest": request["requestDigest"],
        "planDigest": plan_digest, "journalDigest": digest}
    known_current()
    original = bundle._open_on_work(bundle_bytes=ciphertext, bundle_key=key,
        expected_context=context_fields, live_window=window, transport_deadline_ns=bound, work=work)
    known_current()
    journal_scope = {name: context_fields[name] for name in journal.SCOPE_FIELDS}
    context, restored = retained._restore_on_work(original, scope=journal_scope, work=work)
    for name, expected_value in (("request", request), ("scope", scope),
            ("activation_expectations", owned["activationExpectations"]),
            ("activation_scope", owned["activationScope"])):
        registration._same(restored[name], expected_value, work, "independent consume execution " + name)
    for name, expected_value in (("envelope_bytes", envelope), ("state_enrollment_bytes", enrollment),
            ("complete_root_vector_bytes", before_bytes)):
        _bytes_equal(restored[name], expected_value, work, name)
    before_digest = evidence.plan._frame(state.vector.IDENTITY_DOMAIN, (before_bytes,), work)
    projected = state._project_on_work(vector_bytes=before_bytes,
        expected_vector_digest=before_digest, work=work)
    for name, expected_value in (("business_before_roots", projected.business_before_roots),
            ("authorization_before_roots", projected.authorization_before_roots),
            ("expected_counted_heads", projected.expected_counted_heads)):
        work.prepare_copy(restored[name])
        registration._same(tuple(restored[name]), expected_value, work,
            "independent complete-vector consume " + name)
    # Replace independently compared stored pins with the actual held external
    # originals. Proofs, old token and database time remain untrusted replay input.
    restored.update(envelope_bytes=envelope, request=request, scope=scope,
        state_enrollment_bytes=enrollment, complete_root_vector_bytes=before_bytes,
        activation_expectations=owned["activationExpectations"], activation_scope=owned["activationScope"])
    known_current()
    full = plan._verify_full_on_work(context, **restored, planner_public_key=public,
        activation_planner_public_key=old_public, operation_public_key=operation_key,
        state_root_public_key=root, historical_custody=owner, live_window=window,
        transport_deadline_ns=bound, work=work)
    registration._same(full.plan_digest, plan_digest, work, "same original consume plan identity")
    result_window = plan.windows._narrow(full.invocation.window,
        deadline_epoch_ns=full.valid_until_epoch_ns,
        maximum_lifetime_ns=full.invocation.window[5], maximum_clock_skew_ns=full.invocation.window[6])
    result_bound = min(bound, full.invocation.monotonic_deadline, result_window[4])
    _narrowed(window, result_window, bound, result_bound)
    valid_until = min(full.valid_until_epoch_ns, result_window[3])
    _window, final_live = lifetime._window(result_window, result_bound, work)

    def check():
        first = known_current()
        replayed = full.live()
        now = final_live()
        if not first <= replayed <= now or now >= valid_until:
            _fail("consume original replay expired or clocks reversed before return")
        return now

    check()
    # These helpers merge only genuine same-call roots and validate the full
    # source delta. No generic dispatch, operation admission or result is used.
    from catchplate import authority_current_root_plan_replay as roots

    actual, invocation = full.write_result, full.invocation
    before = state.vector._decode_on_work(before_bytes, work=work)
    reads = invocation.raw_reads
    for value in (reads["business_before_roots"], reads["authorization_before_roots"],
            invocation.expected_counted_heads):
        work.prepare_copy(value)
    after = roots._merge(OPERATION, before, list(reads["business_before_roots"]),
        list(reads["authorization_before_roots"]), roots._primary_documents(actual.business_after_roots, work),
        roots._primary_documents(actual.authorization_after_roots, work), list(invocation.expected_counted_heads),
        roots._head_documents(actual.counted_after_heads, work), work)
    after_bytes = state.vector._encode_on_work(after, work=work)
    roots.delta._validate_on_work(operation=OPERATION, before_vector_bytes=before_bytes,
        after_vector_bytes=after_bytes, work=work)
    after_digest = evidence.plan._frame(state.vector.IDENTITY_DOMAIN, (after_bytes,), work)
    raw_pair = envelope, ciphertext
    record_digest = evidence.plan._frame(IDENTITY_DOMAIN, raw_pair, work)
    transition = actual.transition
    work.prepare_copy(transition.mutations)
    work.prepare_copy(invocation.context.selected_rows)
    output = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_ORIGINAL_BYTES).visit({
        "request": invocation.request, "result": transition.result, "mutations": list(transition.mutations),
        "selectedRows": list(invocation.context.selected_rows)})
    work_units = transition.work_units
    registration._integer(work_units, "consume execution replay work", 1,
        contract.authority.operation_spec(OPERATION)["maximumWorkUnits"])
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if interval[0] >= interval[1] or output["result"].get("tokenReleased") is not False:
        _fail("consume replay output is not its token-free original live derivation")
    work.prepare_copy(output["mutations"])
    work.prepare_copy(output["selectedRows"])
    result = _ReplayedDelivery(OPERATION, output["request"], raw_pair, record_digest,
        before_bytes, after_bytes, before_digest, after_digest, output["result"], interval,
        plan_digest, tuple(output["mutations"]), work_units, result_window, result_bound,
        valid_until, check, tuple(output["selectedRows"]))
    check()
    return result
