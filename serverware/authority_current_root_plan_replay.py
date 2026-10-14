"""Genuine successor plan replay lifted into complete source root vectors.

Only original raw2 revocation, raw3 evidence-admission, raw4 transition or
ciphertext-only raw2 activation plans are accepted. Activation additionally
requires the actual independently configured private custody owner and original
live window; it has no historical-expiry fallback.
The replay inventory is the union of these implemented disjoint families, not
the larger planning-program inventory. A registered consume planner supplies
no generic execution replay family and is rejected here.
The actual family verifier authenticates originals and recomputes semantics,
memberships, complete queries, mutations and every required index projection.
Operation-local before roots must match the supplied complete vector exactly;
only genuine replay outputs replace descriptors, with all others unchanged.

The full vector is data, not current-root authority. Neither a returned record
nor a signed planner assertion substitutes for root enrollment/latest-head
admission. The existing families preserve their original interval without a
clock sample or renewal; activation retains its supplied original live bound.
Revocation's signed capability ID and Snapshot/v4 remain distinct from
an original capability digest or any new computation-snapshot commitment.
No execution-capability admission, SQL, key enrollment, new work or successful
proof-token input is provided here.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_contract as authority
from serverware import authority_current_root_delta as delta
from serverware import authority_current_root_vector as vector
from serverware import authority_oidc_session_activation_plan_contract as activation_contract
from serverware import authority_primary_contract as primary
from serverware import authority_revocation_retention as revocation
from serverware import authority_webauthn_evidence_plan_retention as evidence
from serverware import authority_webauthn_transition_retention as transition


capture, framing, wire = vector.capture, vector.framing, vector.wire
shape = revocation.plan.contract
REVOCATION_OPERATION = revocation.plan.contract.OPERATION
EVIDENCE_OPERATIONS = evidence.plan.contract.OPERATIONS
TRANSITION_OPERATIONS = transition.plan.contract.OPERATIONS
ACTIVATION_OPERATION = activation_contract.OPERATION
NATIVE_REVIEW_OPERATION = "jit.review-open.receipt.issue"
# Planning registration alone never grants an original execution-frame grammar.
OPERATIONS = (frozenset({REVOCATION_OPERATION, ACTIVATION_OPERATION, NATIVE_REVIEW_OPERATION})
    | EVIDENCE_OPERATIONS | TRANSITION_OPERATIONS)
MAX_ORIGINAL_BYTES = authority.MAX_RESULT_BYTES
_REVOCATION_EXPECTATIONS = revocation.wire._EXPECTATIONS - {
    "planner_public_key", "verifier_public_key"}
_ROOT_FIELDS = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})
_HEAD_FIELDS = frozenset({"indexId", "indexRevision", "rootDigest", "leafCount"})


class CurrentRootPlanReplayError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReplayedPlan:
    """Ordinary same-call derived observations, never accepted as proof input."""

    operation: str
    request: dict
    originals: tuple[bytes, ...]
    retained_record_digest: str
    before_vector_bytes: bytes
    after_vector_bytes: bytes
    before_vector_digest: str
    after_vector_digest: str
    result: object
    original_interval: tuple[int, int]
    plan_digest: str
    signed_snapshot_digest: str | None
    signed_capability_id: str | None
    selected_rows: tuple
    mutations: tuple
    work_units: int


def _frame_maxima(operation):
    """Return original-frame caps only for implemented disjoint replay families."""
    if (OPERATIONS != frozenset({REVOCATION_OPERATION, ACTIVATION_OPERATION, NATIVE_REVIEW_OPERATION})
            | EVIDENCE_OPERATIONS | TRANSITION_OPERATIONS
            or not OPERATIONS <= delta.OPERATIONS
            or not OPERATIONS <= frozenset(delta.programs.PROGRAMS)
            or EVIDENCE_OPERATIONS & TRANSITION_OPERATIONS
            or REVOCATION_OPERATION == ACTIVATION_OPERATION
            or REVOCATION_OPERATION in EVIDENCE_OPERATIONS | TRANSITION_OPERATIONS
            or ACTIVATION_OPERATION in EVIDENCE_OPERATIONS | TRANSITION_OPERATIONS):
        raise CurrentRootPlanReplayError("successor replay families are not a disjoint source-program subset")
    if type(operation) is not str or operation not in OPERATIONS:
        raise CurrentRootPlanReplayError("successor operation has no implemented original replay family")
    delta._source(operation)
    if operation == NATIVE_REVIEW_OPERATION:
        from serverware import authority_native_jit_review_open_contract as native
        from serverware import authority_native_jit_review_plan_stream as stream

        return (64 * 1024, native.MAX_NATIVE_ORIGINAL, native.MAX_AUTHORITY_ORIGINAL,
            native.MAX_NATIVE_ORIGINAL, stream.MAX_MANIFEST_BYTES)
    if operation == REVOCATION_OPERATION:
        return (revocation.plan.contract.MAX_PAYLOAD_BYTES, revocation.MAX_CONTEXT_BYTES)
    if operation in EVIDENCE_OPERATIONS:
        return (evidence.plan.contract.MAX_BYTES, evidence.plan.inputs_wire.MAX_BYTES,
            evidence.context_wire.MAX_BYTES)
    if operation in TRANSITION_OPERATIONS:
        return (transition.plan.contract.MAX_BYTES, transition.plan.proof.contract.MAX_BYTES,
            transition.plan.proof.wire.MAX_BYTES, transition.plan.context.MAX_BYTES)
    if operation == ACTIVATION_OPERATION:
        from serverware import authority_oidc_session_activation_execution_bundle as activation_bundle

        return (activation_contract.MAX_BYTES, activation_bundle.MAX_BYTES)
    raise CurrentRootPlanReplayError("successor replay operation has no explicit original family")


def _originals(operation, originals, before_vector_bytes):
    maxima = _frame_maxima(operation)
    if (type(originals) is not tuple or len(originals) != len(maxima)
            or any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
                for raw, maximum in zip(originals, maxima))
            or type(before_vector_bytes) is not bytes
            or not 2 <= len(before_vector_bytes) <= vector.MAX_BYTES):
        raise CurrentRootPlanReplayError("successor replay requires its fixed bounded original tuple and vector")
    if sum(len(raw) for raw in originals) + len(before_vector_bytes) > MAX_ORIGINAL_BYTES:
        raise CurrentRootPlanReplayError("successor replay originals exceed the existing aggregate byte bound")
    if operation == ACTIVATION_OPERATION:
        from serverware import authority_oidc_session_activation_execution_bundle as activation_bundle

        try:
            activation_bundle._bounded_frame(originals[1])
        except activation_bundle.ActivationExecutionBundleError as exc:
            raise CurrentRootPlanReplayError("activation replay requires its original ciphertext frame") from exc
    return originals, before_vector_bytes


def _expectations(operation, expectations, planner_key, operation_key, work):
    ledger = capture._SharedLedger(work)
    if not isinstance(planner_key, Ed25519PublicKey) or not isinstance(operation_key, Ed25519PublicKey):
        raise CurrentRootPlanReplayError("successor replay needs independently admitted actual Ed25519 keys")
    if operation == ACTIVATION_OPERATION:
        from serverware import authority_oidc_session_activation_execution_expectations as activation_expectations

        return activation_expectations._capture_on_work(expectations, work=work)
    if operation == REVOCATION_OPERATION:
        shape._object(expectations, _REVOCATION_EXPECTATIONS, "independent revocation replay expectations")
        database_now = expectations["database_now"]
        revocation.plan._verification_types(planner_key, operation_key, database_now)
        # UTC datetime is an exact immutable original, not JSON and never
        # reconstructed from the returned plan. Every remaining graph is
        # detached before complete-vector hashing or a key callback.
        work.charge(json_nodes=len(_REVOCATION_EXPECTATIONS))
        owned = capture._JSONCapture(ledger).visit({name: expectations[name]
            for name in sorted(_REVOCATION_EXPECTATIONS - {"database_now"})})
        owned["database_now"] = database_now
        return owned
    owned = capture._JSONCapture(ledger).visit(expectations)
    if operation == NATIVE_REVIEW_OPERATION:
        shape._object(owned, frozenset({"request"}), "native receipt independent request")
        from serverware import authority_transition_native_jit_review_open as native

        native._arguments(owned["request"], operation, work)
    elif operation in EVIDENCE_OPERATIONS:
        evidence.plan._validate_expectations(owned, operation)
    elif operation in TRANSITION_OPERATIONS:
        actual = transition.plan.contract._validate_expectations(owned)
        framing._same(actual, operation, work, "successor replay independent operation")
    else:
        raise CurrentRootPlanReplayError("successor replay expectations have no explicit source family")
    return owned


def _activation_context_on_work(operation, activation_custody, *, root_public_key,
        current_root_enrollment_bytes, work):
    """Join the actual generic caller's root/enrollment, never a context DTO."""
    if operation == ACTIVATION_OPERATION:
        from serverware import authority_oidc_session_activation_execution_custody as activation_owner

        if type(activation_custody) is not activation_owner.OidcSessionActivationExecutionCustody:
            raise CurrentRootPlanReplayError("activation context requires the actual private custody owner")
        return activation_owner.OidcSessionActivationExecutionCustody.bind_context_on_work(activation_custody,
            root_public_key=root_public_key, current_root_enrollment_bytes=current_root_enrollment_bytes,
            work=work)
    if activation_custody is not None:
        raise CurrentRootPlanReplayError("activation custody cannot bind another replay family")


def _native_context_on_work(operation, native_review_owner, *, root_public_key,
        current_root_enrollment_bytes, work):
    """Join genuine native reader root originals, not a caller-created verdict."""
    if operation == NATIVE_REVIEW_OPERATION:
        from serverware import authority_native_jit_review_plan_owner as native

        if type(native_review_owner) is not native.NativeJitReviewPlanOwner:
            raise CurrentRootPlanReplayError("native receipt requires its actual original replay owner")
        native.NativeJitReviewPlanOwner._bind_execution_context_on_work(native_review_owner,
            root_public_key=root_public_key, current_root_enrollment_bytes=current_root_enrollment_bytes,
            work=work)
    elif native_review_owner is not None:
        raise CurrentRootPlanReplayError("native receipt owner cannot bind another replay family")


def _primary_documents(values, work):
    # These are actual source-bounded engine roots from this invocation only.
    work.charge(input_bytes=2 + 512 * len(values), json_nodes=1 + 9 * len(values))
    return [root.json_projection() for root in values]


def _head_documents(values, work):
    work.charge(input_bytes=2 + 512 * len(values), json_nodes=1 + 9 * len(values))
    return [{"indexId": head.index_id, "indexRevision": head.index_revision,
        "rootDigest": head.index_root.digest, "leafCount": head.index_root.count} for head in values]


def _primary_inventory(values, tables):
    if type(values) is not list or len(values) != len(tables):
        raise CurrentRootPlanReplayError("replayed primary inventory is not source complete")
    for value, table in zip(values, tables):
        shape._object(value, _ROOT_FIELDS, "replayed primary root")
        shape._literal(value["table"], table)
        shape._integer(value["rootRevision"])
        shape._integer(value["leafCount"])
        shape._digest(value["rootDigest"])


def _head_inventory(values):
    if type(values) is not list or len(values) > len(vector.INDEX_IDS):
        raise CurrentRootPlanReplayError("replayed counted inventory is not source bounded")
    previous = None
    for value in values:
        shape._object(value, _HEAD_FIELDS, "replayed counted root")
        identity = value["indexId"]
        if (type(identity) is not str or identity not in vector.INDEX_IDS
                or previous is not None and identity <= previous):
            raise CurrentRootPlanReplayError("replayed counted identities are not unique source order")
        previous = identity
        shape._integer(value["indexRevision"])
        shape._integer(value["leafCount"])
        shape._digest(value["rootDigest"])


def _merge(operation, before, business_before, authorization_before,
        business_after, authorization_after, heads_before, heads_after, work):
    """Join every observed predecessor and change only actual replay outputs."""
    contracts = primary.primary_table_contracts(operation)
    business_tables = tuple(contract.table for contract in contracts if contract.root_class == "business")
    authorization_tables = tuple(contract.table for contract in contracts if contract.root_class == "authorization")
    for values, tables in ((business_before, business_tables), (business_after, business_tables),
            (authorization_before, authorization_tables), (authorization_after, authorization_tables)):
        _primary_inventory(values, tables)
    _head_inventory(heads_before)
    _head_inventory(heads_after)
    work.charge(input_bytes=4 + 130 * (len(heads_before) + len(heads_after)),
        json_nodes=2 + len(heads_before) + len(heads_after))
    framing._same([head["indexId"] for head in heads_before],
        [head["indexId"] for head in heads_after], work, "replayed counted before/after inventory")
    work.prepare_scan(before)
    primary_map = {root["table"]: root for root in before["primaryRoots"]}
    counted_map = {root["indexId"]: root for root in before["countedRoots"]}
    work.prepare_copy(business_before)
    work.prepare_copy(authorization_before)
    for root in business_before + authorization_before:
        framing._same(root, primary_map[root["table"]], work,
            "replayed primary predecessor differs from complete vector")
    for head in heads_before:
        full = counted_map[head["indexId"]]
        work.charge(input_bytes=512, json_nodes=9)
        observed = {name: full[name] for name in _HEAD_FIELDS}
        framing._same(head, observed, work,
            "replayed counted predecessor differs from complete vector")
    # Copy the complete source graph once. Nonselected primary and counted
    # descriptors keep every original field, not merely their root digests.
    after = vector._Capture(capture._SharedLedger(work), maximum_bytes=vector.MAX_BYTES).visit(before)
    work.prepare_copy(business_after)
    work.prepare_copy(authorization_after)
    primary_after = {root["table"]: root for root in business_after + authorization_after}
    work.prepare_copy(heads_after)
    counted_after = {head["indexId"]: head for head in heads_after}
    for root in after["primaryRoots"]:
        replacement = primary_after.get(root["table"])
        if replacement is not None:
            work.prepare_copy(replacement)
            root.update(replacement)
    for head in after["countedRoots"]:
        replacement = counted_after.get(head["indexId"])
        if replacement is not None:
            work.prepare_copy(replacement)
            head.update(replacement)
    return after


def _revocation(originals, expected, planner_key, operation_key, work):
    retained = revocation._verify_record_on_work(envelope_bytes=originals[0],
        evaluation_context_bytes=originals[1], planner_public_key=planner_key,
        verifier_public_key=operation_key, work=work, **expected)
    actual = retained.verification.semantics
    # The bytes below were derived by the genuine same-call mixed engine and
    # already compared with the original signed compact transition. Decoding
    # them only projects its actual heads; it does not accept a proof token.
    compact_contract = revocation.plan.retained.contract
    compact = wire._decode_object(actual.proof.transition_bytes, work=work,
        maximum_bytes=compact_contract.MAX_COMPACT_BYTES,
        maximum_nodes=compact_contract.MAX_COMPACT_NODES, maximum_depth=16)
    compact_contract.validate_transition_shape(compact)
    encoded = revocation.plan.retained._bounded_wire(compact, capture._SharedLedger(work),
        maximum_bytes=compact_contract.MAX_COMPACT_BYTES, maximum_nodes=compact_contract.MAX_COMPACT_NODES)
    work.charge(input_bytes=len(encoded) + len(actual.proof.transition_bytes))
    if encoded != actual.proof.transition_bytes:
        raise CurrentRootPlanReplayError("genuine revocation compact output is not canonical")
    observed = compact["primaryTransition"]
    independently_expected = expected["expected_before"]
    for name in ("businessBeforeRoots", "authorizationBeforeRoots"):
        framing._same(observed[name], independently_expected[name], work,
            "revocation replay changed independent predecessor roots")
    framing._same(compact["indexBeforeHeads"], independently_expected["indexBeforeHeads"], work,
        "revocation replay changed independent counted predecessors")
    written = actual.proof.primary
    business_after = _primary_documents(written.business_after_roots, work)
    authorization_after = _primary_documents(written.authorization_after_roots, work)
    for name, roots in (("businessAfterRoots", business_after), ("authorizationAfterRoots", authorization_after)):
        framing._same(observed[name], roots, work, "revocation compact roots differ from actual primary outputs")
    payload = retained.payload
    projection, measured = payload["authorizationProjection"], payload["measuredPlan"]
    return (payload["typedRequest"], retained.record_digest, retained.envelope_digest,
        actual.kernel.result, (projection["createdAtEpochNs"], projection["expiresAtEpochNs"]),
        measured["authoritySnapshotDigest"], measured["capabilityId"],
        observed["businessBeforeRoots"], observed["authorizationBeforeRoots"],
        business_after, authorization_after, compact["indexBeforeHeads"], compact["indexAfterHeads"],
        payload["selectedBusinessRows"], actual.mutations, actual.work_units)


def _evidence(originals, expected, planner_key, operation_key, work):
    retained = evidence._verify_record_on_work(envelope_bytes=originals[0], inputs_bytes=originals[1],
        evaluation_context_bytes=originals[2], expectations=expected,
        planner_public_key=planner_key, evidence_public_key=operation_key, work=work)
    verification = retained.verification
    payload = wire._decode_object(verification.payload_bytes, work=work,
        maximum_bytes=evidence.plan.contract.MAX_BYTES, maximum_nodes=evidence.plan.contract.MAX_NODES,
        maximum_depth=evidence.plan.contract.MAX_DEPTH)
    evidence.plan.contract.validate_payload_shape(payload)
    evidence.plan._fresh(payload, expected, expected["nowEpochNs"])
    written = verification.write_result
    if written.before_heads != () or written.after_heads != ():
        raise CurrentRootPlanReplayError("evidence-admission replay acquired a counted write inventory")
    return (expected["request"], retained.record_digest, verification.plan_digest,
        verification.semantics.kernel.result, (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]),
        None, None, expected["businessBeforeRoots"], expected["authorizationBeforeRoots"],
        _primary_documents(written.primary.business_after_roots, work),
        _primary_documents(written.primary.authorization_after_roots, work), [], [],
        payload["selectedRows"], verification.semantics.kernel.mutations, verification.semantics.work_units)


def _transition(originals, expected, planner_key, operation_key, work):
    retained = transition._verify_record_on_work(envelope_bytes=originals[0], proof_bytes=originals[1],
        inputs_bytes=originals[2], context_bytes=originals[3], expectations=expected,
        planner_public_key=planner_key, operation_public_key=operation_key, work=work)
    verification = retained.verification
    envelope = wire._decode_object(originals[0], work=work,
        maximum_bytes=transition.plan.contract.MAX_BYTES, maximum_nodes=transition.plan.contract.MAX_NODES,
        maximum_depth=transition.plan.contract.MAX_DEPTH)
    transition.plan.contract.validate_envelope_shape(envelope)
    # This immutable original proof has just undergone genuine authentication,
    # membership/query and semantic replay. Project its verified selected rows,
    # not caller-supplied parallel metadata or a successful observation token.
    proof = wire._decode_object(originals[1], work=work,
        maximum_bytes=transition.plan.proof.contract.MAX_BYTES,
        maximum_nodes=transition.plan.proof.contract.MAX_NODES,
        maximum_depth=transition.plan.proof.contract.MAX_DEPTH)
    transition.plan.proof.contract.validate_payload_shape(proof)
    payload, proof_expected = envelope["payload"], expected["proofExpectations"]
    # Authenticate/replay first, then retain exactly the signed plan interval
    # and require its original historical-policy/cutoff joins. No clock is read.
    transition.plan._fresh(payload, expected, proof_expected["policy"]["nowEpochNs"])
    written = verification.replay.written
    before_heads = _head_documents(written.before_heads, work)
    framing._same(before_heads, proof_expected["countedBeforeHeads"], work,
        "transition replay changed independent counted predecessors")
    return (proof_expected["request"], retained.record_digest, verification.plan_digest,
        verification.replay.semantics.kernel.result, (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]),
        None, None, proof_expected["businessBeforeRoots"], proof_expected["authorizationBeforeRoots"],
        _primary_documents(written.primary.business_after_roots, work),
        _primary_documents(written.primary.authorization_after_roots, work),
        before_heads, _head_documents(written.after_heads, work),
        proof["selectedRows"], verification.replay.semantics.mutations, verification.replay.semantics.work_units)


def _replay_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, before_vector_bytes, work, activation_custody=None,
        live_window=None, transport_deadline_ns=None, native_review_owner=None,
        native_review_frames=None, session_token_original=None):
    """Reconstruct complete effects from original plans on one existing work.

    Revocation expectations are the existing closed verifier expectations minus
    the two explicit keys; their exact UTC database_now is retained unchanged.
    Evidence and transition use their unchanged independent18/independent5.
    Activation uses its closed data-only expectations and the actual private
    custody owner, which reauthenticates original cold authority and performs
    genuine live original replay. No incoming successful result is accepted.
    The returned interval is revocation's signed authorization creation/expiry,
    or the other families' signed plan issue/expiry. None is renewed. The three
    existing families retain historical semantics; activation requires its
    actual original live guard. Revocation plan_digest is the retained original-envelope
    raw SHA identity; the other families retain their dedicated plan identity.
    """
    capture._SharedLedger(work)
    held_operation = operation
    held_originals, held_before = _originals(held_operation, originals, before_vector_bytes)
    planner_key, operation_key = planner_public_key, operation_public_key
    if held_operation == NATIVE_REVIEW_OPERATION:
        from serverware import authority_native_jit_review_plan_owner as native

        if type(native_review_owner) is not native.NativeJitReviewPlanOwner or activation_custody is not None:
            raise CurrentRootPlanReplayError("native receipt requires its actual original replay owner")
        owned = _expectations(held_operation, expectations, planner_key, operation_key, work)
        return native.NativeJitReviewPlanOwner._replay_for_execution_on_work(native_review_owner,
            originals=held_originals, expectations=owned, before_vector_bytes=held_before,
            session_token_original=session_token_original, read_frames=native_review_frames,
            live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    if native_review_owner is not None or native_review_frames is not None or session_token_original is not None:
        raise CurrentRootPlanReplayError("native receipt material cannot replay another family")
    if held_operation == ACTIVATION_OPERATION:
        from serverware import authority_oidc_session_activation_execution_custody as activation_owner
        from serverware import authority_webauthn_evidence_plan_clock as activation_clock

        if type(activation_custody) is not activation_owner.OidcSessionActivationExecutionCustody:
            raise CurrentRootPlanReplayError("activation replay requires the actual private custody owner")
        window = activation_clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        owned = _expectations(held_operation, expectations, planner_key, operation_key, work)
        return activation_owner.OidcSessionActivationExecutionCustody.replay_on_work(activation_custody,
            originals=held_originals, expectations=owned, planner_public_key=planner_key,
            operation_public_key=operation_key, before_vector_bytes=held_before,
            live_window=window, transport_deadline_ns=transport_deadline_ns, work=work)
    if activation_custody is not None:
        raise CurrentRootPlanReplayError("activation custody cannot be supplied to another replay family")
    owned = _expectations(held_operation, expectations, planner_key, operation_key, work)
    before = vector._decode_on_work(held_before, work=work)
    if held_operation == REVOCATION_OPERATION:
        values = _revocation(held_originals, owned, planner_key, operation_key, work)
    elif held_operation in EVIDENCE_OPERATIONS:
        values = _evidence(held_originals, owned, planner_key, operation_key, work)
    elif held_operation in TRANSITION_OPERATIONS:
        values = _transition(held_originals, owned, planner_key, operation_key, work)
    else:
        raise CurrentRootPlanReplayError("successor replay has no explicit source algorithm")
    (request, record_digest, plan_digest, result, interval, snapshot, capability_id,
        business_before, authorization_before, business_after, authorization_after,
        heads_before, heads_after, selected_rows, mutations, work_units) = values
    framing._same(request["operation"], held_operation, work, "replayed operation differs from source selection")
    after = _merge(held_operation, before, business_before, authorization_before,
        business_after, authorization_after, heads_before, heads_after, work)
    after_bytes = vector._encode_on_work(after, work=work)
    # The source delta checker independently closes the complete vectors and
    # checks all nonwritable descriptors plus actual per-event revision bounds.
    # This supplements, and never substitutes for, the genuine proof replay.
    delta._validate_on_work(operation=held_operation, before_vector_bytes=held_before,
        after_vector_bytes=after_bytes, work=work)
    before_digest = framing._frame(vector.IDENTITY_DOMAIN, (held_before,), work)
    after_digest = framing._frame(vector.IDENTITY_DOMAIN, (after_bytes,), work)
    work.prepare_copy(mutations)
    output = capture._JSONCapture(capture._SharedLedger(work)).visit({"request": request,
        "result": result, "selectedRows": selected_rows, "mutations": list(mutations)})
    shape._integer(interval[0], minimum=1)
    shape._integer(interval[1], minimum=1)
    shape._integer(work_units, authority.operation_spec(held_operation)["maximumWorkUnits"], minimum=1)
    if interval[0] >= interval[1]:
        raise CurrentRootPlanReplayError("replayed original interval is empty")
    work.prepare_copy(output["selectedRows"])
    work.prepare_copy(output["mutations"])
    return _ReplayedPlan(held_operation, output["request"], held_originals, record_digest,
        held_before, after_bytes, before_digest, after_digest, output["result"], interval,
        plan_digest, snapshot, capability_id, tuple(output["selectedRows"]), tuple(output["mutations"]), work_units)
