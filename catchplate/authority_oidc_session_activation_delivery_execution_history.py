"""Private original-only historical consume replay for dedicated completion.

Known plan authentication precedes private AEAD opening. Independent originals
are compared against restored data, then all state, completed-activation,
old-token possession, read and indexed-write semantics run again. Expired
original authority is never renewed. Returned facts are token-free history,
not execution, completion, retry, release or current-session authority.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_oidc_session_activation_delivery_execution_replay as live_replay
from catchplate import authority_oidc_session_activation_delivery_plan_history as history


bundle, expectations, retained = live_replay.bundle, live_replay.expectations, live_replay.retained
plan, journal = retained.plan, retained.journal
contract, state, custody = plan.contract, plan.state, plan.custody
assertion, registration, evidence, clock = plan.assertion, plan.registration, plan.evidence, plan.clock
lifetime = live_replay.lifetime
OPERATION = contract.OPERATION
IDENTITY_DOMAIN = bundle.RECORD_IDENTITY_DOMAIN
MAX_ORIGINAL_BYTES = contract.MAX_ORIGINAL_BYTES


class OidcSessionActivationDeliveryExecutionHistoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalReplayedDelivery:
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
    activation_request_digest: str
    activation_delivery_id: str
    activation_delivery_scope_digest: str
    activation_delivery_envelope_digest: str


def _fail(message):
    raise OidcSessionActivationDeliveryExecutionHistoryError(message)


def _scope(owned, window, work):
    return history._scope(owned, window, work)


def _authenticate(envelope_bytes, request, scope, planner_key, current, work):
    return history._authenticate(envelope_bytes, request, scope, planner_key, current, work)


def _replay_on_work(*, envelope_bytes, encrypted_originals_bytes, expected_request,
        expected_scope, expected_journal_digest, state_enrollment_bytes, before_vector_bytes,
        activation_expectations, activation_scope, planner_public_key, activation_planner_public_key,
        operation_public_key, state_root_public_key, historical_custody, bundle_key,
        live_window, transport_deadline_ns, work):
    """Derive historical facts from actual raw2 and independent completion pins."""
    ledger = evidence.capture._SharedLedger(work)
    envelope = state._original(envelope_bytes, contract.MAX_BYTES, "historical consume plan")
    ciphertext = bundle._bounded_frame(encrypted_originals_bytes)
    enrollment = state._original(state_enrollment_bytes,
        state.head.authorization.MAX_ENROLLMENT_BYTES, "historical independent enrollment")
    before_bytes = state._original(before_vector_bytes, state.vector.MAX_BYTES, "historical independent vector")
    total = sum(map(len, (envelope, ciphertext, enrollment, before_bytes)))
    if total > MAX_ORIGINAL_BYTES:
        _fail("historical consume originals exceed the fixed aggregate bound")
    public, old_public, operation_key, root = (planner_public_key, activation_planner_public_key,
        operation_public_key, state_root_public_key)
    for public_key in (public, old_public, operation_key, root):
        state.head.authorization._public(public_key)
    owner, key = historical_custody, bundle_key
    if type(owner) is not custody.OidcSessionActivationHistoryCustody:
        _fail("historical consume requires the actual distinct completion-history owner")
    if type(key) is not bytes or len(key) != bundle.KEY_BYTES:
        _fail("historical consume requires its independently admitted exact bundle key")
    digest = registration._digest(expected_journal_digest)
    window = clock._validate(live_window)
    registration._integer(transport_deadline_ns, "historical consume inherited deadline", 1)
    bound = min(window[4], transport_deadline_ns)
    work.charge(input_bytes=total + len(key))
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "expectations": {"request": expected_request, "scope": expected_scope, "journalDigest": digest},
        "activationExpectations": activation_expectations, "activationScope": activation_scope})
    # Every external graph, immutable original and key reference is held before
    # commitment, clock, native key or custody callbacks.
    expected = expectations._capture_on_work(owned["expectations"], work=work)
    request, scope = expected["request"], expected["scope"]
    _scope(expected, window, work)
    registration._closed(owned["activationScope"], plan._ACTIVATION_SCOPE_FIELDS,
        "historical consume independent activation scope")
    custody.OidcSessionActivationHistoryCustody.require_consume_completion_on_work(owner, work=work)
    custody.OidcSessionActivationHistoryCustody.bind_consume_request_on_work(owner,
        expected_consume_request=request, work=work)
    configured = custody.OidcSessionActivationHistoryCustody._snapshot_configuration(owner)
    bridge_live = None
    if configured.consumer_role == custody.bootstrap.BRIDGE_CONSUME_COMPLETION_CONSUMER_ROLE:
        # The caller/grant operation root is consume evidence R1. Only actual
        # fresh v11 custody may derive predecessor activation provenance R0.
        # Reserve held inputs before re-decoding that owner's original bridge;
        # drop the decoded context before opening and replaying the ciphertext.
        held_bytes = 4 * (total + work.measure(owned)[0] + work.measure(expected)[0]) + 64 * 1024
        selected_context = custody.OidcSessionActivationHistoryCustody._completion_context_on_work(owner,
            root_public_key=root, current_root_enrollment_bytes=enrollment,
            configuration_digest=scope["configurationDigest"], live_window=window,
            transport_deadline_ns=bound, work=work, _additional_original_bytes=held_bytes)
        if (type(selected_context) is not custody._ConsumeContext
                or selected_context.custody_bytes is not configured.custody_bytes
                or type(selected_context.bridge_policy_bytes) is not bytes):
            _fail("historical consume requires its genuine completion bridge context")
        registration._same(evidence.keys._spki_on_work(operation_key, work),
            evidence.keys._spki_on_work(root, work), work,
            "historical consume original operation root")
        registration._same(evidence.keys._spki_on_work(old_public, work),
            evidence.keys._spki_on_work(selected_context.planner_public_key, work), work,
            "historical consume predecessor planner")
        live_replay._narrowed(window, selected_context.window, bound, selected_context.deadline_ns)
        operation_key = selected_context.operation_public_key
        window, bound, bridge_live = (selected_context.window, selected_context.deadline_ns,
            selected_context.live)
        bridge_live()
        del selected_context
    else:
        custody.OidcSessionActivationHistoryCustody.bind_context_on_work(owner,
            root_public_key=root, current_root_enrollment_bytes=enrollment, work=work)
    work.charge(input_bytes=3 * bundle.KEY_BYTES)
    if key in (configured.bundle_key, configured.delivery_key):
        _fail("historical consume execution key reuses a predecessor private-key purpose")
    narrowed, narrowed_bound = custody.OidcSessionActivationHistoryCustody.processing_bounds_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    live_replay._narrowed(window, narrowed, bound, narrowed_bound)
    window, bound = narrowed, narrowed_bound
    owner_live = custody.OidcSessionActivationHistoryCustody.check_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    _window, processing = lifetime._window(window, bound, work)

    def current():
        first = processing()
        bridged = first if bridge_live is None else bridge_live()
        admitted = owner_live()
        now = processing()
        if (not first <= bridged <= admitted <= now
                or custody.OidcSessionActivationHistoryCustody._snapshot_configuration(owner) is not configured):
            _fail("historical consume custody changed or processing clocks reversed")
        return now

    payload, plan_digest = _authenticate(envelope, request, scope, public, current, work)
    context_fields = {"schema": bundle.CONTEXT_SCHEMA, "operation": OPERATION,
        "sourceRevision": contract.authority.SOURCE_REVISION,
        "configurationDigest": scope["configurationDigest"], "requestDigest": request["requestDigest"],
        "planDigest": plan_digest, "journalDigest": digest}
    current()
    original = bundle._open_on_work(bundle_bytes=ciphertext, bundle_key=key,
        expected_context=context_fields, live_window=window, transport_deadline_ns=bound, work=work)
    current()
    journal_scope = {name: context_fields[name] for name in journal.SCOPE_FIELDS}
    context, restored = retained._restore_on_work(original, scope=journal_scope, work=work)
    for name, value in (("request", request), ("scope", scope),
            ("activation_expectations", owned["activationExpectations"]),
            ("activation_scope", owned["activationScope"])):
        registration._same(restored[name], value, work, "historical independent consume " + name)
    for name, value in (("envelope_bytes", envelope), ("state_enrollment_bytes", enrollment),
            ("complete_root_vector_bytes", before_bytes)):
        live_replay._bytes_equal(restored[name], value, work, name)
    before_digest = evidence.plan._frame(state.vector.IDENTITY_DOMAIN, (before_bytes,), work)
    projected = state._project_on_work(vector_bytes=before_bytes,
        expected_vector_digest=before_digest, work=work)
    for name, value in (("business_before_roots", projected.business_before_roots),
            ("authorization_before_roots", projected.authorization_before_roots),
            ("expected_counted_heads", projected.expected_counted_heads)):
        work.prepare_copy(restored[name])
        registration._same(tuple(restored[name]), value, work, "historical consume complete-vector " + name)
    restored.update(envelope_bytes=envelope, request=request, scope=scope,
        state_enrollment_bytes=enrollment, complete_root_vector_bytes=before_bytes,
        activation_expectations=owned["activationExpectations"], activation_scope=owned["activationScope"])
    current()
    full = history._verify_full_on_work(context, **restored, planner_public_key=public,
        activation_planner_public_key=old_public, operation_public_key=operation_key,
        state_root_public_key=root, historical_custody=owner, live_window=window,
        transport_deadline_ns=bound, work=work)
    if type(full) is not history._HistoricalVerifiedPlan:
        _fail("historical consume returned another plan result family")
    registration._same(full.plan_digest, plan_digest, work, "historical same consume plan identity")
    result_window = full.invocation.window
    result_bound = min(bound, full.invocation.monotonic_deadline, result_window[4])
    live_replay._narrowed(window, result_window, bound, result_bound)
    _window, final_live = lifetime._window(result_window, result_bound, work)

    def check():
        first = current()
        replayed = full.live()
        now = final_live()
        if not first <= replayed <= now:
            _fail("historical consume processing clocks reversed before return")
        return now

    check()
    # Neutral root merge validates the actual full source delta; no generic
    # replay dispatch or operation-authority allowlist is called or widened.
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
    registration._integer(work_units, "historical consume replay work", 1,
        contract.authority.operation_spec(OPERATION)["maximumWorkUnits"])
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if (interval != full.historical_plan_interval or interval[1] > full.valid_until_epoch_ns
            or output["result"].get("tokenReleased") is not False):
        _fail("historical consume output changed its original interval or token-free effects")
    work.prepare_copy(output["mutations"])
    work.prepare_copy(output["selectedRows"])
    # Preserve the full original activation identity already verified by this
    # invocation. A deterministic delivery UUID alone cannot establish it.
    provenance = full.provenance
    if type(provenance) is not history.plan.provenance._VerifiedProvenance:
        _fail("historical consume lacks genuine same-call activation provenance")
    activation_request = registration._digest(provenance.activation_request_digest)
    activation_delivery_id = registration._text(provenance.delivery_id,
        "historical activation delivery identity", 128, work)
    activation_scope_digest = registration._digest(provenance.delivery_scope_digest)
    activation_envelope_digest = registration._digest(provenance.delivery_envelope_digest)
    result = _HistoricalReplayedDelivery(OPERATION, output["request"], raw_pair, record_digest,
        before_bytes, after_bytes, before_digest, after_digest, output["result"], interval,
        plan_digest, tuple(output["mutations"]), work_units, result_window, result_bound,
        full.valid_until_epoch_ns, check, tuple(output["selectedRows"]), activation_request,
        activation_delivery_id, activation_scope_digest, activation_envelope_digest)
    check()
    return result
