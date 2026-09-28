"""Historical consume-plan originals, never renewed execution authority.

The known plan is genuinely authenticated and its state, predecessor activation,
possession, complete reads and indexed effects are replayed. Current processing
uses only the supplied real window; original expiries are algebraic evidence.
No API accepts the returned facts in place of the original inputs.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_delivery_plan as plan


contract, state, writes = plan.contract, plan.state, plan.writes
registration, evidence, custody = plan.registration, plan.evidence, plan.custody


class OidcSessionActivationDeliveryPlanHistoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalVerifiedPlan:
    invocation: plan._Invocation
    write_result: writes._HistoricalReplayedWrites
    payload: dict
    plan_digest: str
    provenance: object
    live: object
    valid_until_epoch_ns: int
    historical_plan_interval: tuple


def _fail(message):
    raise OidcSessionActivationDeliveryPlanHistoryError(message)


def _scope(owned, window, work):
    """Original independent policy is data; its old deadline is not a clock."""
    request, scope = owned["request"], owned["scope"]
    registration._closed(scope, state.SCOPE_FIELDS, "historical consume independent scope")
    for name in ("configurationDigest", "plannerSpkiDigest"):
        registration._digest(scope[name])
    evidence._identity(scope["plannerIdentity"])
    for name, maximum in (("deliveryId", 128), ("userId", 1024), ("sessionId", 128),
            ("credentialId", 1366), ("credentialRecordId", 1024), ("challengeId", 1024)):
        registration._text(scope[name], name, maximum, work)
    registration._integer(scope["maximumPlanAgeNs"], "historical consume plan age", 1,
        contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._integer(scope["maximumClockSkewNs"], "historical consume plan skew", 0,
        contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    registration._integer(scope["deadlineEpochNs"], "historical consume original deadline", 1)
    if window[5] > scope["maximumPlanAgeNs"] or window[6] > scope["maximumClockSkewNs"]:
        _fail("historical consume processing exceeds independently admitted policy")
    if type(request) is not dict or request.get("operation") != contract.OPERATION:
        _fail("historical consume requires its exact typed operation")
    digest = plan.commitment._typed_request_digest(request, work=work)
    registration._same(request["requestDigest"], digest, work, "historical consume request identity")
    operation_id = evidence.plan._frame("serverware.policyAuthorityOperation/v2",
        (evidence.plan._ascii(contract.OPERATION, work), evidence.plan._ascii(digest, work)), work)
    registration._same(request["operationId"], operation_id, work, "historical consume operation identity")
    arguments = plan.transition._arguments(request["arguments"], work)
    for field, name in (("delivery_id", "deliveryId"), ("user_id", "userId"),
            ("session_id", "sessionId"), ("credential_id", "credentialId"),
            ("credential_record_id", "credentialRecordId"), ("challenge_id", "challengeId")):
        registration._same(arguments[field], scope[name], work, "historical consume subject " + name)


def _authenticate(envelope_bytes, request, scope, planner_key, current, work):
    """Actual known signature before private opening, with no old-clock call."""
    current()
    envelope = contract._decode_on_work(envelope_bytes, envelope=True, work=work)
    payload = envelope["payload"]
    for name in ("requestDigest", "operationId"):
        registration._same(payload[name], request[name], work, "historical known consume " + name)
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        registration._same(payload[name], scope[name], work, "historical known consume " + name)
    unsigned = contract._encode_on_work(payload, work=work)
    evidence.keys._public_binding(planner_key, scope["plannerSpkiDigest"], work)
    evidence.capability._signature(planner_key, envelope["signatureBase64Url"],
        contract.SIGNATURE_DOMAIN, unsigned, evidence.capture._SharedLedger(work))
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if (not 0 < expires - issued <= scope["maximumPlanAgeNs"]
            or expires > scope["deadlineEpochNs"] or issued > current() + scope["maximumClockSkewNs"]):
        _fail("historical consume plan exceeds its independent original interval")
    identity = evidence.plan._frame(contract.IDENTITY_DOMAIN, (envelope_bytes,), work)
    if issued > current() + scope["maximumClockSkewNs"]:
        _fail("historical consume issue changed relative to the current clock")
    return payload, identity


def _verify_full_on_work(context, *, envelope_bytes, request, scope, old_token_bytes,
        business_before_roots, authorization_before_roots, before_proofs, read_heads, query_frontiers,
        expected_counted_heads, write_proof_bytes, state_enrollment_bytes,
        state_root_public_key, complete_root_vector_bytes, head_query_bytes,
        head_observation_bytes, activation_originals, activation_expectations, activation_scope,
        activation_planner_public_key, operation_public_key, historical_custody,
        planner_public_key, live_window, transport_deadline_ns, work):
    """Authenticate and semantically replay originals under actual fresh custody."""
    original = state._original(envelope_bytes, contract.MAX_BYTES, "historical consume plan")
    public = planner_public_key
    state.head.authorization._public(public)
    # This private fixed entry owns all external graphs before crypto/clock
    # work, keeps the supplied window, and requires genuine v6 or separately
    # signed v11 completion ownership. The latter re-admits its own bridge
    # before deriving old activation provenance; no supplied root selects it.
    invocation = plan._capture_originals(context, request=request, scope=scope,
        old_token_bytes=old_token_bytes, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, expected_counted_heads=expected_counted_heads,
        write_proof_bytes=write_proof_bytes, state_enrollment_bytes=state_enrollment_bytes,
        state_root_public_key=state_root_public_key, complete_root_vector_bytes=complete_root_vector_bytes,
        head_query_bytes=head_query_bytes, head_observation_bytes=head_observation_bytes,
        activation_originals=activation_originals, activation_expectations=activation_expectations,
        activation_scope=activation_scope, activation_planner_public_key=activation_planner_public_key,
        operation_public_key=operation_public_key, historical_custody=historical_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work, historical=True)
    current = plan._live(invocation, work)
    _scope({"request": invocation.request, "scope": invocation.scope}, invocation.window, work)
    payload, identity = _authenticate(original, invocation.request, invocation.scope, public, current, work)
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    database_now = registration._now(invocation.context.database_now)
    if not interval[0] - invocation.scope["maximumClockSkewNs"] <= database_now < interval[1]:
        _fail("historical consume database cutoff is outside its original signed plan")
    originals = invocation.state_originals
    observed = state._verify_historical_on_work(request=invocation.request, scope=invocation.scope,
        old_token_bytes=invocation.old_token_bytes, complete_root_vector_bytes=originals[1],
        query_bytes=originals[2], observation_bytes=originals[3], enrollment_bytes=originals[0],
        root_public_key=invocation.state_root_public_key, historical_plan_interval=interval,
        live_window=invocation.window, transport_deadline_ns=invocation.monotonic_deadline, work=work)
    projected = state._project_on_work(vector_bytes=originals[1],
        expected_vector_digest=observed["vectorDigest"], work=work)
    for actual, expected, label in (
            (invocation.raw_reads["business_before_roots"], projected.business_before_roots, "business roots"),
            (invocation.raw_reads["authorization_before_roots"], projected.authorization_before_roots, "authorization roots"),
            (invocation.expected_counted_heads, projected.expected_counted_heads, "seven counted heads")):
        work.prepare_copy(actual)
        registration._same(tuple(actual), expected, work, "historical consume " + label)
    current()
    actual_provenance = plan._provenance(invocation, work)
    provenance_now = actual_provenance.live()
    if current() < provenance_now:
        _fail("historical consume processing reversed across activation provenance")
    expected, raw = invocation.scope, invocation.raw_reads
    actual_writes = writes._replay_historical_on_work(invocation.context,
        old_token_bytes=invocation.old_token_bytes, expected_delivery_id=expected["deliveryId"],
        expected_user_id=expected["userId"], expected_session_id=expected["sessionId"],
        expected_credential_id=expected["credentialId"], expected_credential_record_id=expected["credentialRecordId"],
        expected_challenge_id=expected["challengeId"], authn_policy=expected["authenticationPolicy"],
        trust_policy=expected["trustPolicy"], business_before_roots=raw["business_before_roots"],
        authorization_before_roots=raw["authorization_before_roots"], before_proofs=raw["before_proofs"],
        read_heads=invocation.read_heads, query_frontiers=invocation.query_frontiers,
        expected_counted_heads=invocation.expected_counted_heads, write_proof_bytes=invocation.write_proof_bytes,
        historical_plan_interval=interval, live_window=invocation.window,
        transport_deadline_ns=invocation.monotonic_deadline, work=work)
    if (type(actual_writes) is not writes._HistoricalReplayedWrites
            or actual_writes.historical_plan_interval != interval):
        _fail("historical consume writes returned another original family")
    fields = plan._bodies(invocation, actual_provenance, actual_writes, work)
    for name, value in fields.items():
        registration._same(payload[name], value, work, "historical consume original " + name)
    original_until = min(observed["expiresAtEpochNs"], actual_writes.valid_until_epoch_ns,
        expected["deadlineEpochNs"], interval[0] + expected["maximumPlanAgeNs"])
    if interval[1] > original_until:
        _fail("historical consume plan exceeded its actually derived original lifetime")

    def checked():
        first = current()
        provenance_now = actual_provenance.live()
        writes_now = actual_writes.live()
        now = current()
        if not first <= provenance_now <= writes_now <= now or interval[0] > now + expected["maximumClockSkewNs"]:
            _fail("historical consume processing clocks reversed or issue is in the future")
        return now

    checked()
    result = _HistoricalVerifiedPlan(invocation, actual_writes, payload, identity,
        actual_provenance, checked, min(interval[1], original_until), interval)
    checked()
    return result
