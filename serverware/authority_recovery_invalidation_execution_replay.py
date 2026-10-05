"""Live original-only invalidation replay into complete source root vectors.

The genuine retained-plan verifier authenticates the four immutable originals
and repeats exact-primary, terminal/audit and counted-write proof evaluation.
Its independent five primary roots and nine counted heads must then equal the
corresponding descriptors in the complete before vector. Only the actual
same-call proof outputs replace those descriptors; every other field survives
unchanged. The complete resulting vector undergoes real source validation.

This purpose-bound component is deliberately outside generic successor frame
admission: recovery invalidation remains disabled. No registry, delta gate or
execution family is widened. The returned data establishes neither recovery
witness custody nor current-root enrollment/currentness, reservation, durable
retention, execution permission or SQL completion. The original interval and
work remain live through final vector/output framing; no window is renewed.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_current_root_plan_replay as complete
from serverware import authority_recovery_invalidation_retention as retention
from serverware.authority_query_read_work import QueryReadValidationMetrics


plan, vector = retention.plan, complete.vector
proof = plan.proof
OPERATION = "webauthn.recovery.invalidate"
MAX_ORIGINAL_BYTES = proof.contract.MAX_RESULT_BYTES
_MUTATIONS = frozenset({
    ("webauthn_recovery_ceremonies", "UPDATE"),
    ("webauthn_recovery_revocations", "UPDATE"),
    ("webauthn_challenges", "UPDATE"),
    ("metadata_audit_outbox", "INSERT"),
    ("policy_authority_bounded_aggregate_states", "UPDATE"),
})


class RecoveryInvalidationExecutionReplayError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReplayedInvalidation:
    """Locally derived observations only; no API accepts this as authority."""

    request: dict
    originals: tuple[bytes, bytes, bytes, bytes]
    retained_record_digest: str
    plan_digest: str
    before_vector_bytes: bytes
    after_vector_bytes: bytes
    before_vector_digest: str
    after_vector_digest: str
    original_interval: tuple[int, int]
    original_deadline_ns: int
    affected: bool
    selected_rows: tuple
    mutations: tuple
    metrics: QueryReadValidationMetrics


def _require(value):
    if not value:
        raise RecoveryInvalidationExecutionReplayError(
            "invalidation replay differs from original proofs or complete source roots")


def _originals(originals, before_vector_bytes):
    maxima = (plan.MAX_PARENT_BYTES, proof.contract.MAX_REQUEST_BYTES,
        proof.MAX_INPUT_BYTES, plan.MAX_CONTEXT_BYTES)
    _require(type(originals) is tuple and len(originals) == 4
        and all(type(raw) is bytes and 2 <= len(raw) <= maximum
            for raw, maximum in zip(originals, maxima))
        and type(before_vector_bytes) is bytes
        and 2 <= len(before_vector_bytes) <= vector.MAX_BYTES)
    _require(sum(len(raw) for raw in originals) + len(before_vector_bytes)
        <= MAX_ORIGINAL_BYTES)
    return originals, before_vector_bytes


def _replay_on_work(*, originals, expectations, planner_public_key,
        before_vector_bytes, live_window, check, work):
    """Authenticate raw4 and derive complete vectors on original caller work.

    ``expectations`` is the unchanged independent plan.EXPECTATION_FIELDS
    contract, including the admitted request context and actual DB cutoff.
    The complete before vector is independently supplied original data, not a
    claim that it is enrolled or current. No after vector, prior verifier
    result, witness flag or caller-created successful record is accepted.
    """
    proof.batch._SharedLedger(work)
    held, held_before = _originals(originals, before_vector_bytes)
    _require(plan.OPERATION == OPERATION and proof.OPERATION == OPERATION)
    # Fixed local source semantics, not generic PROGRAMS/_frame_maxima
    # admission. Those gates intentionally continue to reject this operation.
    work.charge(input_bytes=8192, json_nodes=512)
    spec = proof.contract.operation_spec(OPERATION)
    tables = frozenset(table for table, _kind in _MUTATIONS)
    _require(spec["handler"] == "serverware_policy_authority_webauthn_recovery_invalidate"
        and frozenset(spec["businessWrites"]) == tables
        and frozenset(spec["businessReads"]) <= tables
        and spec["authorizationReads"] == ()
        and len(spec["mutationTemplates"]) == len(_MUTATIONS)
        and frozenset((item["table"], item["mutation"])
            for item in spec["mutationTemplates"]) == _MUTATIONS)
    owned, _request, expected_context = plan._originals(
        held[1], held[2], expectations, work)
    work.charge(input_bytes=len(held[3]) + len(expected_context))
    _require(held[3] == expected_context)
    window = plan.clock._validate(live_window)
    envelope = plan._decode(held[0], plan.MAX_PARENT_BYTES, work, nodes=2048, depth=8)
    plan._object(envelope, {"schema", "payload", "signatureBase64Url"})
    _require(envelope["schema"] == plan.ENVELOPE_SCHEMA)
    plan._bind(envelope["payload"], owned, _request, held[1], held[2], held[3], work)
    # Before authentication this interval may only refuse. The outer guard
    # already exists when genuine verification starts, and keeps its own
    # nondecreasing monotonic observations through all later vector framing.
    live = plan._Live(owned, envelope["payload"], window, check, work)
    try:
        live.checked()
        retained = retention._verify_record_on_work(envelope_bytes=held[0],
            request_bytes=held[1], proof_bytes=held[2], context_bytes=held[3],
            expectations=owned, planner_public_key=planner_public_key,
            live_window=window, check=live.checked, work=work)
        live.checked()
        context, actual = retained.context, retained.verification.replay
        _require(type(retained.verification) is plan.VerifiedRecoveryInvalidationPlan
            and type(actual) is proof._Computation and type(actual.affected) is bool
            and len(context["businessBeforeRoots"]) == 5
            and context["authorizationBeforeRoots"] == []
            and len(context["countedBeforeHeads"]) == 9
            and len(actual.counted_after_heads) == 9
            and type(actual.mutations) is tuple
            and len(actual.mutations) <= spec["maximumMutations"])
        before = vector._decode_on_work(held_before, work=work)
        live.checked()
        written = actual.write.primary
        business_after = complete._primary_documents(written.business_after_roots, work)
        authorization_after = complete._primary_documents(written.authorization_after_roots, work)
        work.prepare_copy(actual.counted_after_heads)
        heads_after = list(actual.counted_after_heads)
        # _merge validates exact source table/head rosters, compares every
        # independent predecessor and copies the complete source graph. It
        # invokes neither the generic replay entry nor its registry gate.
        after = complete._merge(OPERATION, before,
            context["businessBeforeRoots"], context["authorizationBeforeRoots"],
            business_after, authorization_after, context["countedBeforeHeads"],
            heads_after, work)
        live.checked()
        after_bytes = vector._encode_on_work(after, work=work)
        live.checked()
        before_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (held_before,), work)
        after_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (after_bytes,), work)
        # This is the literal authenticated proof just replayed above, not an
        # alternate selected-row input or a supplied verification DTO.
        document = plan._decode(held[2], proof.MAX_INPUT_BYTES, work)
        selected = proof._own(document["selectedRows"], work)
        mutations = proof._own(actual.mutations, work)
        request = proof._own(retained.request, work)
        proof._same(request["operation"], OPERATION, work)
        _require(retained.original_interval == (
            retained.payload["issuedAtEpochNs"], retained.payload["expiresAtEpochNs"])
            and retained.original_deadline_ns == owned["originalDeadlineNs"])
        work.prepare_copy(selected)
        work.prepare_copy(mutations)
        # All hashes, encoding and bounded result scaffolding precede the
        # final guard. The plain local constructor below has no callback or
        # encoding, and its cumulative metrics are sampled after that guard.
        work.charge(input_bytes=4096, json_nodes=128)
        live.checked()
        return _ReplayedInvalidation(request, held, retained.record_digest,
            retained.verification.plan_digest, held_before, after_bytes,
            before_digest, after_digest, retained.original_interval,
            retained.original_deadline_ns, actual.affected, tuple(selected),
            tuple(mutations), work.metrics)
    except BaseException:
        live.failed = True
        raise
