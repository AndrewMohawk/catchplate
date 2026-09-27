"""Current, token-free consume plans with original state/provenance/write replay.

Only a signed commitment leaves production. Receiving repeats the actual
current proof, possession, completed-activation and indexed-write algorithms.
Neither a previous success nor a supplied transition is accepted. This private
primitive does not issue execution authority, consume SQL, retain a plan or
release a token. It has no historical/expired consume-plan admission path.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import time

from serverware import authority_oidc_session_activation_delivery_plan_contract as contract
from serverware import authority_oidc_session_activation_delivery_provenance as provenance
from serverware import authority_oidc_session_activation_delivery_reads as reads
from serverware import authority_oidc_session_activation_delivery_state as state
from serverware import authority_oidc_session_activation_delivery_writes as writes
from serverware import authority_oidc_session_activation_execution_bundle as bundle
from serverware import authority_oidc_session_activation_history_custody as custody
from serverware import authority_oidc_session_activation_plan as activation_plan
from serverware import authority_request_commitment as commitment
from serverware import authority_successor_execution_window as windows


transition = writes.consumption
assertion, registration, core = transition.assertion, transition.registration, transition.core
evidence, clock = registration.evidence, assertion.clock
_ACTIVATION_SCOPE_FIELDS = frozenset({"authorizationDigest", "databaseId", "generationDigest",
    "pendingSequence", "pendingHeadDigest", "fence"})


class OidcSessionActivationDeliveryPlanError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Invocation:
    request: dict
    scope: dict
    context: core.KernelContext
    old_token_bytes: bytes
    raw_reads: dict
    read_heads: tuple
    query_frontiers: tuple
    expected_counted_heads: tuple
    write_proof_bytes: bytes
    state_originals: tuple
    state_root_public_key: object
    activation_originals: tuple
    activation_expectations: dict
    activation_scope: dict
    activation_planner_public_key: object
    operation_public_key: object
    historical_custody: object
    window: tuple
    monotonic_deadline: int


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedPlan:
    """Actual same-call facts/guard; never accepted in place of originals."""
    invocation: _Invocation
    write_result: writes._ReplayedWrites
    payload: dict
    plan_digest: str
    provenance: object
    live: object
    valid_until_epoch_ns: int


def _fail(message):
    raise OidcSessionActivationDeliveryPlanError(message)


def _activation_originals(values, work):
    """Hold exact raw13 and real frame bounds before any callback or DB work."""
    evidence.capture._SharedLedger(work)
    response = provenance.response
    maxima = (*response.transport.RESPONSE_LIMITS, activation_plan.contract.MAX_BYTES,
        bundle.MAX_BYTES, response.authorization.MAX_BYTES, response.pending.MAX_RECEIPT_BYTES,
        response.pending.computation.MAX_SNAPSHOT_BYTES, response.admission.caller.MAX_AUTHORIZATION_BYTES,
        response.grants.MAX_GRANT_BYTES, response.admission.caller.MAX_ENROLLMENT_BYTES,
        response.grants.MAX_ENROLLMENT_BYTES)
    if (len(maxima) != 13 or type(values) is not tuple or len(values) != 13
            or any(type(raw) is not bytes or len(raw) > cap for raw, cap in zip(values, maxima))
            or any(len(raw) < 2 for raw in values[4:])
            or sum(map(len, values)) > contract.MAX_ORIGINAL_BYTES):
        _fail("consume plan requires the exact bounded activation original tuple13")
    # This is only closed transport shape, never completion admission.
    response.transport._originals(values[:4], response=True)
    work.charge(input_bytes=sum(map(len, values)))
    return values


def _capture(context, *, request, scope, old_token_bytes, business_before_roots,
        authorization_before_roots, before_proofs, read_heads, query_frontiers,
        expected_counted_heads, write_proof_bytes, state_enrollment_bytes,
        state_root_public_key, complete_root_vector_bytes, head_query_bytes,
        head_observation_bytes, activation_originals, activation_expectations, activation_scope,
        activation_planner_public_key, operation_public_key, historical_custody,
        live_window, transport_deadline_ns, work):
    return _capture_originals(context, request=request, scope=scope, old_token_bytes=old_token_bytes,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers,
        expected_counted_heads=expected_counted_heads, write_proof_bytes=write_proof_bytes,
        state_enrollment_bytes=state_enrollment_bytes, state_root_public_key=state_root_public_key,
        complete_root_vector_bytes=complete_root_vector_bytes, head_query_bytes=head_query_bytes,
        head_observation_bytes=head_observation_bytes, activation_originals=activation_originals,
        activation_expectations=activation_expectations, activation_scope=activation_scope,
        activation_planner_public_key=activation_planner_public_key, operation_public_key=operation_public_key,
        historical_custody=historical_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, historical=False)


def _capture_originals(context, *, request, scope, old_token_bytes, business_before_roots,
        authorization_before_roots, before_proofs, read_heads, query_frontiers,
        expected_counted_heads, write_proof_bytes, state_enrollment_bytes,
        state_root_public_key, complete_root_vector_bytes, head_query_bytes,
        head_observation_bytes, activation_originals, activation_expectations, activation_scope,
        activation_planner_public_key, operation_public_key, historical_custody,
        live_window, transport_deadline_ns, work, historical):
    """Detach all graphs and hold originals/keys before native/hash/clock work."""
    ledger = evidence.capture._SharedLedger(work)
    if type(historical) is not bool:
        _fail("consume capture must use a fixed live or historical entrypoint")
    if (type(context) is not core.KernelContext or context.operation != contract.OPERATION
            or context.verified_webauthn_evidence is not None
            or type(context.database_now) is not datetime or context.database_now.tzinfo is not timezone.utc):
        _fail("consume plan requires its actual original UTC context")
    database_now = context.database_now
    owner, root, old_planner, operation_key = (historical_custody, state_root_public_key,
        activation_planner_public_key, operation_public_key)
    if type(owner) is not custody.OidcSessionActivationHistoryCustody:
        _fail("consume plan requires the actual distinct historical custody owner")
    for key in (root, old_planner, operation_key):
        state.head.authorization._public(key)
    old = assertion._token(old_token_bytes, work)
    original_activation = _activation_originals(activation_originals, work)
    original_state = (
        state._original(state_enrollment_bytes, state.head.authorization.MAX_ENROLLMENT_BYTES, "enrollment"),
        state._original(complete_root_vector_bytes, state.vector.MAX_BYTES, "vector"),
        state._original(head_query_bytes, state.head.MAX_QUERY_BYTES, "query"),
        state._original(head_observation_bytes, state.head.MAX_BYTES, "observation"))
    write_original = state._original(write_proof_bytes, writes.MAX_WRITE_PROOF_BYTES, "write proof")
    if (type(expected_counted_heads) is not tuple or len(expected_counted_heads) != writes.HEAD_COUNT
            or sum(map(len, (*original_activation, *original_state, old, write_original)))
                > contract.MAX_ORIGINAL_BYTES):
        _fail("consume plan exceeds its fixed head or aggregate original bound")
    window = clock._validate(live_window)
    registration._integer(transport_deadline_ns, "consume plan inherited deadline", 1)
    bound = min(window[4], transport_deadline_ns)
    work.prepare_copy(expected_counted_heads)
    owned = assertion._Capture(ledger, maximum_bytes=assertion.MAX_CONTEXT_BYTES).visit({
        "request": request, "scope": scope, "countedBeforeHeads": list(expected_counted_heads),
        "activationExpectations": activation_expectations, "activationScope": activation_scope})
    raw, records, heads, frontiers = reads._capture(arguments=context.arguments,
        request_digest=context.request_digest, selected_rows=context.selected_rows,
        query_reads=context.query_reads, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, work=work)
    # No external mutable graph remains when genuine commitment/custody work starts.
    expected, actual, old_scope = owned["scope"], owned["request"], owned["activationScope"]
    registration._closed(expected, state.SCOPE_FIELDS, "independent consume plan scope")
    registration._closed(old_scope, _ACTIVATION_SCOPE_FIELDS, "independent activation provenance scope")
    for name in ("configurationDigest", "plannerSpkiDigest"):
        registration._digest(expected[name])
    for name in ("authorizationDigest", "generationDigest", "pendingHeadDigest"):
        registration._digest(old_scope[name])
    registration._text(old_scope["databaseId"], "activation database", 1024, work)
    for name in ("pendingSequence", "fence"):
        registration._integer(old_scope[name], name, 1)
    evidence._identity(expected["plannerIdentity"])
    writes._heads(owned["countedBeforeHeads"])
    for name, maximum in (("deliveryId", 128), ("userId", 1024), ("sessionId", 128),
            ("credentialId", 1366), ("credentialRecordId", 1024), ("challengeId", 1024)):
        registration._text(expected[name], name, maximum, work)
    if historical:
        registration._integer(expected["deadlineEpochNs"], "original consume deadline", 1)
        registration._integer(expected["maximumPlanAgeNs"], "original consume age", 1,
            contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
        registration._integer(expected["maximumClockSkewNs"], "original consume skew", 0,
            contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
        if window[5] > expected["maximumPlanAgeNs"] or window[6] > expected["maximumClockSkewNs"]:
            _fail("historical consume processing exceeds independent policy")
        custody.OidcSessionActivationHistoryCustody.require_consume_completion_on_work(owner, work=work)
    else:
        custody.OidcSessionActivationHistoryCustody._require_live_consume_history_on_work(owner, work=work)
        window = windows._narrow(window, deadline_epoch_ns=expected["deadlineEpochNs"],
            maximum_lifetime_ns=expected["maximumPlanAgeNs"],
            maximum_clock_skew_ns=expected["maximumClockSkewNs"])
    bound = min(bound, window[4])
    if type(actual) is not dict or actual.get("operation") != contract.OPERATION:
        _fail("consume plan requires the distinct typed consume operation")
    digest = commitment._typed_request_digest(actual, work=work)
    registration._same((digest, actual["arguments"]), (raw["request_digest"], raw["arguments"]),
        work, "consume request/context")
    registration._same(actual["requestDigest"], digest, work, "consume request identity")
    operation_id = evidence.plan._frame("serverware.policyAuthorityOperation/v2",
        (evidence.plan._ascii(contract.OPERATION, work), evidence.plan._ascii(digest, work)), work)
    registration._same(actual["operationId"], operation_id, work, "consume operation identity")
    transition._arguments(raw["arguments"], work)
    custody.OidcSessionActivationHistoryCustody.bind_consume_request_on_work(owner,
        expected_consume_request=actual, work=work)
    custody.OidcSessionActivationHistoryCustody.bind_context_on_work(owner,
        root_public_key=root, current_root_enrollment_bytes=original_state[0], work=work)
    narrowed, narrowed_bound = custody.OidcSessionActivationHistoryCustody.processing_bounds_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    if (narrowed[:3] != window[:3] or narrowed[3] > window[3] or narrowed[4] > window[4]
            or narrowed[5] > window[5] or narrowed[6] > window[6] or narrowed_bound > bound):
        _fail("consume provenance custody renewed the original processing allowance")
    held = core.KernelContext(contract.OPERATION, raw["arguments"], raw["selected_rows"],
        database_now, digest, query_reads=records)
    return _Invocation(actual, expected, held, old, raw, heads, frontiers,
        tuple(owned["countedBeforeHeads"]), write_original, original_state, root,
        original_activation, owned["activationExpectations"], old_scope, old_planner,
        operation_key, owner, narrowed, min(narrowed_bound, narrowed[4]))


def _live(invocation, work):
    epoch, monotonic = invocation.window[0], invocation.window[2]

    def check():
        nonlocal epoch, monotonic
        now = clock._check_on_work(invocation.window, work=work)
        observed = evidence.production._callback(work, time.monotonic_ns)
        registration._integer(observed, "consume plan monotonic sample", 1)
        if now < epoch or observed < monotonic or observed >= invocation.monotonic_deadline:
            _fail("consume plan processing expired or clocks reversed")
        epoch, monotonic = now, observed
        return now

    return check


def _provenance(invocation, work):
    raw, old, scope = invocation.activation_originals, invocation.activation_scope, invocation.scope
    selected = invocation.context._exact("oidc_session_activation_deliveries",
        {"id": scope["deliveryId"]}, work=work)
    if selected["present"] is not True or type(selected["row"]) is not dict:
        _fail("consume provenance requires the supplied delivery row, independently proved by writes")
    return provenance._verify_on_work(consume_request=invocation.request,
        current_delivery_row=selected["row"], response_originals=raw[:4], plan_originals=raw[4:6],
        reserve_request_bytes=raw[6], reserve_receipt_bytes=raw[7], snapshot_bytes=raw[8],
        enrollment_bytes=invocation.state_originals[0], authorization_bytes=raw[9],
        authorization_enrollment_bytes=raw[11], grant_bytes=raw[10], grant_enrollment_bytes=raw[12],
        expectations=invocation.activation_expectations, planner_public_key=invocation.activation_planner_public_key,
        operation_public_key=invocation.operation_public_key, root_public_key=invocation.state_root_public_key,
        configuration_digest=scope["configurationDigest"], expected_authorization_digest=old["authorizationDigest"],
        expected_database_id=old["databaseId"], expected_generation_digest=old["generationDigest"],
        expected_pending_sequence=old["pendingSequence"], expected_pending_head_digest=old["pendingHeadDigest"],
        expected_fence=old["fence"], historical_custody=invocation.historical_custody,
        live_window=invocation.window, transport_deadline_ns=invocation.monotonic_deadline, work=work)


def _replay(invocation, work):
    expected, raw = invocation.scope, invocation.raw_reads
    return writes._replay_on_work(invocation.context, old_token_bytes=invocation.old_token_bytes,
        expected_delivery_id=expected["deliveryId"], expected_user_id=expected["userId"],
        expected_session_id=expected["sessionId"], expected_credential_id=expected["credentialId"],
        expected_credential_record_id=expected["credentialRecordId"], expected_challenge_id=expected["challengeId"],
        authn_policy=expected["authenticationPolicy"], trust_policy=expected["trustPolicy"],
        business_before_roots=raw["business_before_roots"], authorization_before_roots=raw["authorization_before_roots"],
        before_proofs=raw["before_proofs"], read_heads=invocation.read_heads,
        query_frontiers=invocation.query_frontiers, expected_counted_heads=invocation.expected_counted_heads,
        write_proof_bytes=invocation.write_proof_bytes, live_window=invocation.window,
        transport_deadline_ns=invocation.monotonic_deadline, work=work)


def _authorities(invocation, live, work):
    originals = invocation.state_originals
    observed = state._verify_on_work(request=invocation.request, scope=invocation.scope,
        old_token_bytes=invocation.old_token_bytes, complete_root_vector_bytes=originals[1],
        query_bytes=originals[2], observation_bytes=originals[3], enrollment_bytes=originals[0],
        root_public_key=invocation.state_root_public_key, now_epoch_ns=live(), work=work)
    projected = state._project_on_work(vector_bytes=originals[1],
        expected_vector_digest=observed["vectorDigest"], work=work)
    for actual, expected, label in (
            (invocation.raw_reads["business_before_roots"], projected.business_before_roots, "business roots"),
            (invocation.raw_reads["authorization_before_roots"], projected.authorization_before_roots, "authorization roots"),
            (invocation.expected_counted_heads, projected.expected_counted_heads, "seven counted heads")):
        work.prepare_copy(actual)
        registration._same(tuple(actual), expected, work, "observed consume " + label)
    actual_provenance = _provenance(invocation, work)
    first = actual_provenance.live()
    if live() < first:
        _fail("consume processing reversed after completed-activation admission")
    actual_writes = _replay(invocation, work)
    return observed, actual_provenance, actual_writes


def _wire(value, work):
    return evidence.capability._wire(value, evidence.capture._SharedLedger(work),
        contract.MAX_ORIGINAL_BYTES, reads.reads.MAX_JSON_NODES)


def _read_inputs(invocation, work):
    """Owned exact9 original projection; no successful acquisition is accepted."""
    if type(invocation) is not _Invocation:
        _fail("consume read projection requires this call's actual invocation")
    records = []
    for record in invocation.context.query_reads:
        work.charge(input_bytes=len(record.declared_query_json) + len(record.resolved_query_json)
            + sum(len(address.key_json) for address in record.addresses))
        records.append({"queryId": record.query_id,
            "declaredQueryJson": record.declared_query_json.decode("ascii"),
            "resolvedQueryJson": record.resolved_query_json.decode("ascii"),
            "returnedRowCount": record.returned_row_count,
            "addresses": [{"table": address.table, "keyJson": address.key_json.decode("ascii"),
                "keyDigest": address.key_digest, "present": address.present} for address in record.addresses]})
    raw = invocation.raw_reads
    # Reuse only the operation-neutral, charged tuple-to-JSON normalization.
    return activation_plan._ReadInputsCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=contract.MAX_ORIGINAL_BYTES).visit({"schema": contract.PROOF_DOMAIN,
        "selectedRows": raw["selected_rows"], "beforeProofs": raw["before_proofs"],
        "readHeads": raw["read_heads"], "queryFrontiers": raw["query_frontiers"], "queryReads": records,
        "businessBeforeRoots": raw["business_before_roots"],
        "authorizationBeforeRoots": raw["authorization_before_roots"],
        "countedBeforeHeads": invocation.expected_counted_heads})


def _bodies(invocation, actual_provenance, actual_writes, work):
    read_inputs = _read_inputs(invocation, work)
    proof = {name: read_inputs[name] for name in ("schema", "selectedRows", "beforeProofs",
        "readHeads", "queryFrontiers", "queryReads")}
    original = invocation.write_proof_bytes
    encoded_size = (4 * len(original) + 2) // 3
    if encoded_size > contract.MAX_ORIGINAL_BYTES:
        _fail("consume encoded write proof exceeds its original bound")
    work.charge(input_bytes=len(original) + 3 * (encoded_size + 2))
    proof["writeProofBase64Url"] = base64.urlsafe_b64encode(original).decode("ascii").rstrip("=")
    evaluation = {"schema": contract.CONTEXT_DOMAIN, "request": invocation.request, "scope": invocation.scope,
        "databaseNow": invocation.context.database_now.isoformat(),
        "businessBeforeRoots": read_inputs["businessBeforeRoots"],
        "authorizationBeforeRoots": read_inputs["authorizationBeforeRoots"],
        "countedBeforeHeads": read_inputs["countedBeforeHeads"],
        "activationExpectations": invocation.activation_expectations, "activationScope": invocation.activation_scope,
        "activationProvenanceDigest": actual_provenance.provenance_digest}
    inputs = {"schema": contract.INPUTS_DOMAIN}
    names = ("oldToken", "stateEnrollment", "completeRootVector", "headQuery", "headObservation",
        "completionStatus", "completionId", "completionRequest", "completionReceipt", "activationPlan",
        "activationBundle", "reserveRequest", "reserveReceipt", "snapshot", "callerAuthorization",
        "executionGrant", "callerEnrollment", "grantEnrollment")
    originals = (invocation.old_token_bytes, *invocation.state_originals, *invocation.activation_originals)
    if len(names) != len(originals):
        _fail("consume source original commitment inventory changed")
    for name, raw in zip(names, originals):
        inputs[name] = {"digest": evidence.plan._frame(contract.INPUTS_DOMAIN + "/" + name, (raw,), work),
            "byteCount": len(raw)}
    return contract._body_commitments_on_work(proof_bytes=_wire(proof, work),
        context_bytes=_wire(evaluation, work), inputs_bytes=_wire(inputs, work),
        transition_bytes=actual_writes.transition_bytes, work=work)


def _expiry(invocation, observed, actual_writes, issued):
    return min(invocation.scope["deadlineEpochNs"], issued + invocation.scope["maximumPlanAgeNs"],
        observed["expiresAtEpochNs"], actual_writes.valid_until_epoch_ns)


def _fresh(payload, invocation, observed, actual_provenance, actual_writes, live, work):
    first = live()
    original_now = actual_provenance.live()
    replay_now = actual_writes.live()
    now = live()
    if not first <= original_now <= replay_now <= now:
        _fail("consume clocks reversed across original provenance/write guards")
    evidence._fresh(payload, now, invocation.scope["maximumPlanAgeNs"], invocation.scope["maximumClockSkewNs"])
    expiry = _expiry(invocation, observed, actual_writes, payload["issuedAtEpochNs"])
    if now >= expiry or payload["expiresAtEpochNs"] > expiry:
        _fail("consume plan exceeds actual observation, delivery or original scope lifetime")
    return now


def _produce_on_work(context, *, request, scope, old_token_bytes, business_before_roots,
        authorization_before_roots, before_proofs, read_heads, query_frontiers,
        expected_counted_heads, write_proof_bytes, state_enrollment_bytes,
        state_root_public_key, complete_root_vector_bytes, head_query_bytes,
        head_observation_bytes, activation_originals, activation_expectations, activation_scope,
        activation_planner_public_key, operation_public_key, historical_custody,
        planner_private_key, planner_public_key, live_window, transport_deadline_ns, work):
    """Replay actual originals, then sign only bounded token-free commitments."""
    private, public = planner_private_key, planner_public_key
    if (not isinstance(private, evidence.Ed25519PrivateKey)
            or not isinstance(public, evidence.keys.Ed25519PublicKey)):
        _fail("consume plan needs actual independently admitted Ed25519 keys")
    invocation = _capture(context, request=request, scope=scope, old_token_bytes=old_token_bytes,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers,
        expected_counted_heads=expected_counted_heads, write_proof_bytes=write_proof_bytes,
        state_enrollment_bytes=state_enrollment_bytes, state_root_public_key=state_root_public_key,
        complete_root_vector_bytes=complete_root_vector_bytes, head_query_bytes=head_query_bytes,
        head_observation_bytes=head_observation_bytes, activation_originals=activation_originals,
        activation_expectations=activation_expectations, activation_scope=activation_scope,
        activation_planner_public_key=activation_planner_public_key, operation_public_key=operation_public_key,
        historical_custody=historical_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    live = _live(invocation, work)
    observed, actual_provenance, actual_writes = _authorities(invocation, live, work)
    fields = _bodies(invocation, actual_provenance, actual_writes, work)
    expected, issued = invocation.scope, invocation.window[0]
    payload = {**contract._source_fields(), **fields,
        "requestDigest": invocation.request["requestDigest"], "operationId": invocation.request["operationId"],
        "configurationDigest": expected["configurationDigest"], "plannerIdentity": expected["plannerIdentity"],
        "plannerSpkiDigest": expected["plannerSpkiDigest"], "issuedAtEpochNs": issued,
        "expiresAtEpochNs": min(_expiry(invocation, observed, actual_writes, issued), invocation.window[3],
            issued + invocation.monotonic_deadline - invocation.window[1])}
    unsigned = contract._encode_on_work(payload, work=work)
    _fresh(payload, invocation, observed, actual_provenance, actual_writes, live, work)
    evidence.keys._public_binding(public, expected["plannerSpkiDigest"], work)
    evidence.keys._pair_on_work(private, public, work)
    message = evidence.plan._ascii(evidence.plan._frame(contract.SIGNATURE_DOMAIN, (unsigned,), work), work)
    placeholder = {"schema": contract.ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    envelope_size, envelope_nodes = work.measure(placeholder)
    payload_size, payload_nodes = work.measure(payload)
    if envelope_size > contract.MAX_BYTES or envelope_nodes > contract.MAX_NODES:
        _fail("consume signed output exceeds its fixed wire bound")
    work.charge(input_bytes=envelope_size + 2 * payload_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=envelope_nodes + payload_nodes)
    _fresh(payload, invocation, observed, actual_provenance, actual_writes, live, work)
    signature = evidence.production._sign_and_verify(private, public, message, work)
    _fresh(payload, invocation, observed, actual_provenance, actual_writes, live, work)
    if commitment.canonical_bytes(payload) != unsigned:
        _fail("consume payload changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    contract.shape._base64url(encoded, signature=True)
    result = commitment.canonical_bytes({"schema": contract.ENVELOPE_SCHEMA,
        "payload": payload, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        _fail("consume signed output changed after sizing")
    _fresh(payload, invocation, observed, actual_provenance, actual_writes, live, work)
    return result


def _verify_full_on_work(context, *, envelope_bytes, request, scope, old_token_bytes,
        business_before_roots, authorization_before_roots, before_proofs, read_heads, query_frontiers,
        expected_counted_heads, write_proof_bytes, state_enrollment_bytes,
        state_root_public_key, complete_root_vector_bytes, head_query_bytes,
        head_observation_bytes, activation_originals, activation_expectations, activation_scope,
        activation_planner_public_key, operation_public_key, historical_custody,
        planner_public_key, live_window, transport_deadline_ns, work):
    """Authenticate the known signer, then genuinely replay every original again."""
    original, public = envelope_bytes, planner_public_key
    if (type(original) is not bytes or not 2 <= len(original) <= contract.MAX_BYTES
            or not isinstance(public, evidence.keys.Ed25519PublicKey)):
        _fail("consume receiver requires its original envelope and independent public key")
    invocation = _capture(context, request=request, scope=scope, old_token_bytes=old_token_bytes,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers,
        expected_counted_heads=expected_counted_heads, write_proof_bytes=write_proof_bytes,
        state_enrollment_bytes=state_enrollment_bytes, state_root_public_key=state_root_public_key,
        complete_root_vector_bytes=complete_root_vector_bytes, head_query_bytes=head_query_bytes,
        head_observation_bytes=head_observation_bytes, activation_originals=activation_originals,
        activation_expectations=activation_expectations, activation_scope=activation_scope,
        activation_planner_public_key=activation_planner_public_key, operation_public_key=operation_public_key,
        historical_custody=historical_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    live = _live(invocation, work)
    live()
    envelope = contract._decode_on_work(original, envelope=True, work=work)
    payload, expected = envelope["payload"], invocation.scope
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        registration._same(payload[name], expected[name], work, "independent consume " + name)
    for name in ("requestDigest", "operationId"):
        registration._same(payload[name], invocation.request[name], work, "consume " + name)
    unsigned = contract._encode_on_work(payload, work=work)
    evidence.keys._public_binding(public, expected["plannerSpkiDigest"], work)
    evidence.capability._signature(public, envelope["signatureBase64Url"], contract.SIGNATURE_DOMAIN,
        unsigned, evidence.capture._SharedLedger(work))
    evidence._fresh(payload, live(), expected["maximumPlanAgeNs"], expected["maximumClockSkewNs"])
    observed, actual_provenance, actual_writes = _authorities(invocation, live, work)
    fields = _bodies(invocation, actual_provenance, actual_writes, work)
    for name, value in fields.items():
        registration._same(payload[name], value, work, "consume original " + name)

    def checked():
        return _fresh(payload, invocation, observed, actual_provenance, actual_writes, live, work)

    checked()
    identity = evidence.plan._frame(contract.IDENTITY_DOMAIN, (original,), work)
    result = _VerifiedPlan(invocation, actual_writes, payload, identity, actual_provenance, checked,
        min(payload["expiresAtEpochNs"], _expiry(invocation, observed, actual_writes, payload["issuedAtEpochNs"])))
    checked()
    return result


def _verify_on_work(context, *, envelope_bytes, request, scope, old_token_bytes,
        business_before_roots, authorization_before_roots, before_proofs, read_heads, query_frontiers,
        expected_counted_heads, write_proof_bytes, state_enrollment_bytes,
        state_root_public_key, complete_root_vector_bytes, head_query_bytes,
        head_observation_bytes, activation_originals, activation_expectations, activation_scope,
        activation_planner_public_key, operation_public_key, historical_custody,
        planner_public_key, live_window, transport_deadline_ns, work):
    return _verify_full_on_work(context, envelope_bytes=envelope_bytes, request=request, scope=scope,
        old_token_bytes=old_token_bytes, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, expected_counted_heads=expected_counted_heads,
        write_proof_bytes=write_proof_bytes, state_enrollment_bytes=state_enrollment_bytes,
        state_root_public_key=state_root_public_key, complete_root_vector_bytes=complete_root_vector_bytes,
        head_query_bytes=head_query_bytes, head_observation_bytes=head_observation_bytes,
        activation_originals=activation_originals, activation_expectations=activation_expectations,
        activation_scope=activation_scope, activation_planner_public_key=activation_planner_public_key,
        operation_public_key=operation_public_key, historical_custody=historical_custody,
        planner_public_key=planner_public_key, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work).write_result.transition
