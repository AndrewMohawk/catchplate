"""Historical encrypted activation originals, never permission to execute.

Independently admitted keys, original request/scope, journal identity and full
before-vector remain mandatory. Authenticate the real plan before AES opening,
then genuinely replay every retained assertion, row/proof, delivery and indexed
write under a separate CURRENT processing window. Historical intervals are
data checked against original policy, never substituted clock samples.

This primitive has no receiving bootstrap, key loader, generic dispatch, SQL,
completion signature, token release or cross-version authority. A future cold
historical owner must independently admit its purpose and historical cohort;
the live grant/reserve/sql-issuer owner cannot simply be relabeled.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_execution_replay as replay


plan, bundle, journal, retained, delivery = (replay.plan, replay.bundle,
    replay.journal, replay.retained, replay.delivery)
contract, assertion, registration = replay.contract, replay.assertion, replay.registration
evidence, clock = replay.evidence, replay.clock
OPERATION, IDENTITY_DOMAIN = replay.OPERATION, replay.IDENTITY_DOMAIN
MAX_ORIGINAL_BYTES = replay.MAX_ORIGINAL_BYTES


class OidcSessionActivationExecutionHistoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalReplayedPlan:
    """Same-call historical facts; no live or completion input accepts these."""

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
    signed_snapshot_digest: None
    signed_capability_id: None
    selected_rows: tuple
    mutations: tuple
    work_units: int
    live: object


def _fail(message):
    raise OidcSessionActivationExecutionHistoryError(message)


def _expectations(request, scope, window, work):
    """Check held independent history, not a renewed original deadline."""
    registration._closed(scope, plan._SCOPE_FIELDS, "independent activation historical scope")
    if type(request) is not dict or request.get("operation") != OPERATION:
        _fail("activation historical request has the wrong operation")
    for name in ("configurationDigest", "plannerSpkiDigest"):
        registration._digest(scope[name])
    evidence._identity(scope["plannerIdentity"])
    for name, maximum in (("userId", 1024), ("sessionId", 128), ("credentialId", 1366),
            ("credentialRecordId", 1024), ("challengeId", 1024), ("rpId", 4096), ("origin", 8192)):
        registration._text(scope[name], name, maximum, work)
    registration._integer(scope["maximumPlanAgeNs"], "historical activation plan age", 1,
        contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._integer(scope["maximumClockSkewNs"], "historical activation plan skew", 0,
        contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    registration._integer(scope["deadlineEpochNs"], "historical activation original deadline", 1)
    if window[5] > scope["maximumPlanAgeNs"] or window[6] > scope["maximumClockSkewNs"]:
        _fail("activation historical processing exceeds independently admitted policy")
    # The original deadline constrains the original plan below, not the real
    # current processing deadline. No old instant is a validation clock here.
    digest = plan.commitment._typed_request_digest(request, work=work)
    registration._same(request["requestDigest"], digest, work, "historical activation request")
    operation_id = evidence.plan._frame("serverware.policyAuthorityOperation/v2",
        (evidence.plan._ascii(OPERATION, work), evidence.plan._ascii(digest, work)), work)
    registration._same(request["operationId"], operation_id, work, "historical activation operation")
    plan.transition._arguments(request["arguments"], work)


def _authenticate(envelope_bytes, request, scope, planner_key, current, work):
    """Verify the known signature and interval before any private opening."""
    current()
    envelope = contract._decode_on_work(envelope_bytes, envelope=True, work=work)
    payload = envelope["payload"]
    for name in ("requestDigest", "operationId"):
        registration._same(payload[name], request[name], work, "historical activation plan " + name)
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        registration._same(payload[name], scope[name], work, "historical activation plan " + name)
    unsigned = contract._encode_on_work(payload, work=work)
    evidence.keys._public_binding(planner_key, scope["plannerSpkiDigest"], work)
    evidence.capability._signature(planner_key, envelope["signatureBase64Url"],
        contract.SIGNATURE_DOMAIN, unsigned, evidence.capture._SharedLedger(work))
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if (not 0 < expires - issued <= scope["maximumPlanAgeNs"]
            or expires > scope["deadlineEpochNs"]
            or issued > current() + scope["maximumClockSkewNs"]):
        _fail("activation historical plan exceeds original policy or is future-issued")
    digest = evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope_bytes,), work)
    evidence.capability._canonical(envelope_bytes, envelope,
        evidence.capture._SharedLedger(work), contract.MAX_BYTES, contract.MAX_NODES)
    current()
    return payload, digest


def _replay_on_work(*, envelope_bytes, encrypted_originals_bytes, expected_request,
        expected_scope, expected_journal_digest, planner_public_key, state_enrollment_bytes,
        state_root_public_key, bundle_key, delivery_custody_key, before_vector_bytes,
        live_window, transport_deadline_ns, work):
    """Derive historical raw2/full-vector facts from actual original replay.

    The current work/window is supplied, never opened here or retimed. This
    API neither constructs an executable packet nor accepts a prior result.
    """
    ledger = evidence.capture._SharedLedger(work)
    envelope = plan.state._original(envelope_bytes, contract.MAX_BYTES, "historical signed plan")
    ciphertext = bundle._bounded_frame(encrypted_originals_bytes)
    before_bytes = plan.state._original(before_vector_bytes,
        plan.state.vector.MAX_BYTES, "historical complete vector")
    enrollment = plan.state._original(state_enrollment_bytes,
        plan.state.head.authorization.MAX_ENROLLMENT_BYTES, "historical state enrollment")
    if sum(len(raw) for raw in (envelope, ciphertext, before_bytes, enrollment)) > MAX_ORIGINAL_BYTES:
        _fail("activation historical originals exceed the existing aggregate bound")
    planner_key, root_key = planner_public_key, state_root_public_key
    if not isinstance(planner_key, evidence.keys.Ed25519PublicKey):
        _fail("activation historical planner key is not actual Ed25519")
    plan.state.head.authorization._public(root_key)
    if (type(bundle_key) is not bytes or len(bundle_key) != bundle.KEY_BYTES
            or type(delivery_custody_key) is not bytes or len(delivery_custody_key) != 32):
        _fail("activation history requires independently admitted exact private keys")
    held_bundle_key, held_delivery_key = bundle_key, delivery_custody_key
    work.charge(input_bytes=64)
    if held_bundle_key == held_delivery_key:
        _fail("activation historical bundle and delivery keys must differ")
    journal_digest = registration._digest(expected_journal_digest)
    window = clock._validate(live_window)
    registration._integer(transport_deadline_ns, "activation historical inherited deadline", 1)
    bound = min(window[4], transport_deadline_ns)
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "request": expected_request, "scope": expected_scope})
    request, scope = owned["request"], owned["scope"]
    # Hold every external graph, immutable original and key before callbacks.
    _expectations(request, scope, window, work)
    _window, current = delivery._window(window, bound, work)
    known_payload, plan_digest = _authenticate(envelope, request, scope, planner_key, current, work)
    original_interval = known_payload["issuedAtEpochNs"], known_payload["expiresAtEpochNs"]
    expected_context = {"schema": bundle.CONTEXT_SCHEMA, "operation": OPERATION,
        "sourceRevision": contract.authority.SOURCE_REVISION,
        "configurationDigest": scope["configurationDigest"], "requestDigest": request["requestDigest"],
        "planDigest": plan_digest, "journalDigest": journal_digest}
    original = bundle._open_on_work(bundle_bytes=ciphertext, bundle_key=held_bundle_key,
        expected_context=expected_context, live_window=window, transport_deadline_ns=bound, work=work)
    current()
    journal_scope = {name: expected_context[name] for name in journal.SCOPE_FIELDS}
    stored = journal._decode_original_on_work(original, scope=journal_scope, work=work)
    registration._same(stored["request"], request, work, "independent historical activation request")
    registration._same(stored["scope"], scope, work, "independent historical activation scope")
    stored_envelope = registration._encoded_original(stored["planEnvelopeBase64Url"], contract.MAX_BYTES, work)
    stored_enrollment = registration._encoded_original(stored["stateEnrollmentBase64Url"],
        plan.state.head.authorization.MAX_ENROLLMENT_BYTES, work)
    stored_vector = registration._encoded_original(stored["completeRootVectorBase64Url"],
        plan.state.vector.MAX_BYTES, work)
    for actual, expected, label in ((stored_envelope, envelope, "historical signed plan"),
            (stored_enrollment, enrollment, "historical state enrollment"),
            (stored_vector, before_bytes, "historical complete vector")):
        replay._bytes_equal(actual, expected, work, label)
    raw = stored["readInputs"]
    selected, proofs, heads, frontiers, records = retained._restore_inputs(raw, work)
    database_now = registration._utc(stored["databaseNow"], "retained historical activation database time", work)
    context = plan.core.KernelContext(OPERATION, request["arguments"], selected, database_now,
        request["requestDigest"], query_reads=records)
    original_assertion = registration._encoded_original(stored["assertionBase64Url"], assertion.MAX_ASSERTION_BYTES, work)
    old_token = registration._encoded_original(stored["oldTokenBase64Url"], 64, work, minimum=64)
    new_token = registration._encoded_original(stored["newTokenBase64Url"], 64, work, minimum=64)
    delivery_bytes = registration._encoded_original(stored["deliveryEnvelopeBase64Url"],
        delivery.ENVELOPE_BYTES, work, minimum=delivery.ENVELOPE_BYTES)
    write_bytes = registration._encoded_original(stored["writeProofBase64Url"], plan.writes.MAX_WRITE_PROOF_BYTES, work)
    query_bytes = registration._encoded_original(stored["headQueryBase64Url"], plan.state.head.MAX_QUERY_BYTES, work)
    observation_bytes = registration._encoded_original(stored["headObservationBase64Url"], plan.state.head.MAX_BYTES, work)
    if type(raw["countedBeforeHeads"]) is not list or len(raw["countedBeforeHeads"]) != plan.writes.HEAD_COUNT:
        _fail("activation historical counted-head inventory differs")
    work.prepare_copy(raw["countedBeforeHeads"])
    current()
    full = plan._verify_historical_full_on_work(context, envelope_bytes=envelope, request=request, scope=scope,
        assertion_bytes=original_assertion, old_token_bytes=old_token, new_token_bytes=new_token,
        delivery_envelope_bytes=delivery_bytes, delivery_custody_key=held_delivery_key,
        business_before_roots=raw["businessBeforeRoots"], authorization_before_roots=raw["authorizationBeforeRoots"],
        before_proofs=proofs, read_heads=heads, query_frontiers=frontiers,
        expected_counted_heads=tuple(raw["countedBeforeHeads"]), write_proof_bytes=write_bytes,
        planner_public_key=planner_key, state_enrollment_bytes=enrollment, state_root_public_key=root_key,
        complete_root_vector_bytes=before_bytes, head_query_bytes=query_bytes,
        head_observation_bytes=observation_bytes, live_window=window, work=work, transport_deadline_ns=bound)
    if type(full) is not plan._HistoricalVerifiedPlan:
        _fail("activation history requires its actual same-call historical replay")
    from serverware import authority_current_root_plan_replay as generic

    invocation, actual, payload = full.invocation, full.write_result, full.payload
    processing = plan._historical_live(invocation, work)

    def check():
        opened_sample = current()
        original_sample = actual.live()
        now = processing()
        if original_sample < opened_sample or now < original_sample:
            _fail("activation historical processing reversed after original replay")
        return now

    check()
    registration._same(full.plan_digest, plan_digest, work, "same historical activation plan identity")
    registration._same((payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]), original_interval,
        work, "same original historical activation interval")
    before = generic.vector._decode_on_work(before_bytes, work=work)
    read = invocation.raw_reads
    work.prepare_copy(read["business_before_roots"])
    work.prepare_copy(read["authorization_before_roots"])
    work.prepare_copy(invocation.expected_counted_heads)
    after = generic._merge(OPERATION, before, list(read["business_before_roots"]),
        list(read["authorization_before_roots"]), generic._primary_documents(actual.business_after_roots, work),
        generic._primary_documents(actual.authorization_after_roots, work), list(invocation.expected_counted_heads),
        generic._head_documents(actual.counted_after_heads, work), work)
    after_bytes = generic.vector._encode_on_work(after, work=work)
    generic.delta._validate_on_work(operation=OPERATION, before_vector_bytes=before_bytes,
        after_vector_bytes=after_bytes, work=work)
    check()
    before_digest = evidence.plan._frame(generic.vector.IDENTITY_DOMAIN, (before_bytes,), work)
    after_digest = evidence.plan._frame(generic.vector.IDENTITY_DOMAIN, (after_bytes,), work)
    raw_pair = envelope, ciphertext
    record_digest = evidence.plan._frame(IDENTITY_DOMAIN, raw_pair, work)
    transition = actual.transition
    output = plan._ReadInputsCapture(ledger, maximum_bytes=MAX_ORIGINAL_BYTES).visit({
        "request": invocation.request, "result": transition.result,
        "selectedRows": invocation.context.selected_rows, "mutations": transition.mutations})
    work_units = transition.work_units
    registration._integer(work_units, "activation historical replay work", 1,
        contract.authority.operation_spec(OPERATION)["maximumWorkUnits"])
    work.prepare_copy(output["selectedRows"])
    work.prepare_copy(output["mutations"])
    result = _HistoricalReplayedPlan(OPERATION, output["request"], raw_pair, record_digest,
        before_bytes, after_bytes, before_digest, after_digest, output["result"], original_interval,
        plan_digest, None, None, tuple(output["selectedRows"]), tuple(output["mutations"]), work_units, check)
    check()
    return result
