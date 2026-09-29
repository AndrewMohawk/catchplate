"""Inactive revocation semantics recomputed from raw retained proof inputs.

The actual request digest, pinned verifier receipt, complete read/write proofs,
business kernel and audit-capacity finalizer share one bounded ledger. The
existing retained compact remains a proof-only observation: no semantic fields
or metrics are added to its v1 wire, and no planner operation is registered.

Verifier pins, capability identity, fresh receipt time/deadline and the UTC
database instant and before-root vectors must come from independent admission.
This component neither establishes that provenance nor executes SQL or writes.
Its outputs are freely constructible observations, never successful input tokens.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_audit_capacity as capacity
from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as query_batch
from serverware import authority_contract
from serverware import authority_request_commitment as request_commitment
from serverware import authority_revocation_bundle_contract as contract
from serverware import authority_revocation_proof_bundle as retained
from serverware import authority_revocation_read_write as mixed
from serverware import authority_transition_core as core
from serverware import authority_transition_webauthn as candidate
from serverware import authority_webauthn_assertion as assertion
from serverware.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES, QueryReadValidationLimits,
    QueryReadValidationMetrics, _ValidationWork,
)


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_BEFORE_FIELDS = frozenset({"businessBeforeRoots", "authorizationBeforeRoots", "indexBeforeHeads"})
_MUTATION_FIELDS = frozenset({"templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row"})
_OWNED_FIELDS = frozenset({"bundle", "transition", "request", "evidence", "verifierIdentity",
    "capabilityId", "databaseCutoffUs", "nowEpochNs", "deadlineEpochNs", "maximumAgeNs", "expectedBefore"})


class RevocationSemanticsError(ValueError):
    pass


def _verify_evidence(evidence, *, operation_id, request_digest, capability_id,
        verifier_identity, verifier_public_key, now_epoch_ns, deadline_epoch_ns,
        maximum_age_ns, work):
    from serverware import authority_public_webauthn_revocation as public
    if public.is_public(evidence):
        return public.verify(evidence, operation_id=operation_id, request_digest=request_digest,
            capability_id=capability_id, verifier_identity=verifier_identity,
            verifier_public_key=verifier_public_key, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, maximum_age_ns=maximum_age_ns, work=work)
    receipt_work = assertion._ReceiptWork(work)
    verified = assertion._verify_revoke_assertion_evidence(evidence,
        operation_id=operation_id, request_digest=request_digest, capability_id=capability_id,
        verifier_identity=verifier_identity, verifier_public_key=verifier_public_key,
        now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns,
        maximum_age_ns=maximum_age_ns, work=receipt_work)
    return verified, receipt_work.signature_attempts


def _evidence_binding(evidence):
    from serverware import authority_public_webauthn_revocation as public
    if public.is_public(evidence):
        return public.binding(evidence)
    return {name: evidence[name] for name in ("credentialRecordId", "challengeId")}


@dataclass(frozen=True, slots=True)
class RevocationSemanticMetrics:
    capture: QueryReadValidationMetrics
    request_binding: QueryReadValidationMetrics
    receipt: QueryReadValidationMetrics
    context_binding: QueryReadValidationMetrics
    proof: QueryReadValidationMetrics
    kernel: QueryReadValidationMetrics
    capacity: QueryReadValidationMetrics
    mutation_binding: QueryReadValidationMetrics
    signature_attempts: int
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class RevocationSemanticObservation:
    """Owned observations, not a capability, current checkpoint or commit.

    Nested dictionaries are detached from caller inputs, not deeply frozen.
    ``proof.packaging`` snapshots cumulative work when proof packaging finished;
    ``metrics`` reports the final whole-ledger totals and exclusive phase work.
    """

    proof: retained.RetainedRevocationProof
    kernel: core.KernelTransition
    mutations: tuple[dict[str, Any], ...]
    work_units: int
    metrics: RevocationSemanticMetrics


def _equal(left, right, *, work, label):
    work.prepare_comparison(left, right)
    if left != right:
        raise RevocationSemanticsError(label)


def _canonical_equal(left, right, *, work, label):
    # JSON-byte equality distinguishes booleans from integers, unlike Python's
    # recursive ==. Each real encoder and both byte scans are prepared anew.
    work.prepare_encoding(left)
    left_wire = core.canonical_bytes(left)
    work.prepare_encoding(right)
    right_wire = core.canonical_bytes(right)
    work.charge(input_bytes=len(left_wire) + len(right_wire))
    if left_wire != right_wire:
        raise RevocationSemanticsError(label)


def _expected_before(value):
    # Called only after the complete bounded ownership capture. These existing
    # closed transport-shape helpers perform no constructors, encodings or SHA.
    if (type(value) is not dict or len(value) != len(_BEFORE_FIELDS)
            or any(type(key) is not str for key in value) or set(value) != _BEFORE_FIELDS):
        raise RevocationSemanticsError("independent before-root vector is not closed")
    contract._root_pair(value["businessBeforeRoots"], value["authorizationBeforeRoots"])
    contract._heads(value["indexBeforeHeads"])


def _capture(*, ledger, bundle, transition, request, evidence, verifier_identity,
             capability_id, database_now, now_epoch_ns, deadline_epoch_ns,
             maximum_age_ns, expected_before):
    # The real planner's database clock already returns exact UTC. Reject
    # caller-defined tzinfo callbacks instead of invoking them before ownership.
    if type(database_now) is not datetime or database_now.tzinfo is not timezone.utc:
        raise RevocationSemanticsError("semantic database time is not an exact UTC datetime")
    database_cutoff = complete.cutoff_microseconds(database_now)
    before = ledger.work.metrics
    owned = query_batch._JSONCapture(ledger).visit({
        "bundle": bundle, "transition": transition, "request": request, "evidence": evidence,
        "verifierIdentity": verifier_identity, "capabilityId": capability_id,
        "databaseCutoffUs": database_cutoff, "nowEpochNs": now_epoch_ns,
        "deadlineEpochNs": deadline_epoch_ns, "maximumAgeNs": maximum_age_ns,
        "expectedBefore": expected_before,
    }, depth=-1)
    return owned, mixed._delta(before, ledger.work.metrics)


def _require_owned_handoff(owned, ledger, capture) -> None:
    """Check the private carrier, not ownership or independent authority.

    The caller must already have captured every referenced graph together and
    must discard the invocation on any failure. The one existing comparing
    compact hold must remain unchanged until the genuine proof worker releases
    it; lowering its work limits after construction is not another safe hold.
    """
    if (type(owned) is not dict or len(owned) != len(_OWNED_FIELDS)
            or any(type(key) is not str for key in owned) or set(owned) != _OWNED_FIELDS):
        raise RevocationSemanticsError("owned semantic input fields are not closed")
    if (type(ledger) is not retained._PackagingLedger
            or type(getattr(ledger, "work", None)) is not _ValidationWork
            or getattr(ledger, "_held", None) is not True):
        raise RevocationSemanticsError("semantic handoff requires the existing held packaging ledger")
    work = ledger.work
    original = getattr(ledger, "original_limits", None)
    effective_limits = getattr(work, "limits", None)
    reserved = getattr(ledger, "reserved", None)
    if (type(original) is not QueryReadValidationLimits
            or type(effective_limits) is not QueryReadValidationLimits
            or type(reserved) is not QueryReadValidationMetrics
            or type(capture) is not QueryReadValidationMetrics):
        raise RevocationSemanticsError("semantic handoff work metadata has an unexpected exact type")
    for limit_name, metric_name, counter_name, maximum, hold in (
            ("max_hashes", "hash_work", "hash_work", MAX_HASHES, 1),
            ("max_input_bytes", "input_bytes", "input_bytes", MAX_INPUT_BYTES, 4 * contract.MAX_COMPACT_BYTES),
            ("max_json_nodes", "json_nodes", "json_nodes", MAX_JSON_NODES, 2 * contract.MAX_COMPACT_NODES)):
        ceiling = getattr(original, limit_name, None)
        effective = getattr(effective_limits, limit_name, None)
        retained_hold = getattr(reserved, metric_name, None)
        spent = getattr(work, counter_name, None)
        captured = getattr(capture, metric_name, None)
        if (type(ceiling) is not int or not 1 <= ceiling <= maximum
                or type(effective) is not int or effective != ceiling - hold or effective < 1
                or type(retained_hold) is not int or retained_hold != hold
                or type(spent) is not int or not 0 <= spent <= effective
                or type(captured) is not int or not 0 <= captured <= spent):
            raise RevocationSemanticsError("semantic handoff work or compact reservation changed")


def _derive_revocation_effects(
    *, arguments, selected_rows, query_program, query_reads, database_now,
    request_digest, verified_webauthn_evidence, work: _ValidationWork,
):
    """Run the genuine kernel and capacity body on already-owned raw inputs.

    The private caller must first derive/bind the request, verify the pinned
    receipt, and authenticate these exact rows and complete observations at
    the original database cutoff. Neither these shape checks nor a freely
    constructible receipt mapping establishes those prerequisites. This helper
    does no capture, clock read, signature, query generation, SQL or proof pass.
    Failure aborts the caller's invocation; no new work allowance is created.

    Return the actual kernel, UNSORTED finalized mutations, signed work units,
    and exclusive kernel/capacity deltas. These are ordinary observations, not
    a successful-result input token for any proof or authorization consumer.
    """
    spec = authority_contract.operation_spec(candidate.OPERATION)
    if (type(work) is not _ValidationWork or type(arguments) is not dict
            or type(selected_rows) is not tuple or len(selected_rows) > spec["maximumQueryRows"]
            or any(type(item) is not dict for item in selected_rows)
            or type(query_program) is not tuple or not 1 <= len(query_program) <= mixed.MAX_QUERY_READS
            or any(type(query) not in (core.BoundedQuery, complete.CompleteIndexQuery)
                   for query in query_program)
            or type(query_reads) is not tuple or len(query_reads) != len(query_program)
            or any(type(record) is not mixed.reads.QueryRead for record in query_reads)
            or type(database_now) is not datetime or database_now.tzinfo is not timezone.utc
            or type(verified_webauthn_evidence) not in (dict, MappingProxyType)):
        raise RevocationSemanticsError("revocation effect inputs or shared work have unexpected exact types")
    core.require_digest(request_digest, "revocation effect request digest")
    before = work.metrics
    context = core.KernelContext(
        operation=candidate.OPERATION, arguments=arguments,
        selected_rows=selected_rows, database_now=database_now,
        request_digest=request_digest, verified_webauthn_evidence=verified_webauthn_evidence,
        query_reads=query_reads,
    )
    kernel = candidate.WebAuthnCredentialRevokeKernel()._transition(context, work=work)
    kernel_work = mixed._delta(before, work.metrics)

    before = work.metrics
    finalized = capacity._finalize_capacity(context, kernel.mutations, work=work)
    # At most 45 declarations and 137 mutations: fixed metadata scaffolding,
    # not row-payload traversal. Signed units are not hash/byte/node work.
    total_work_units = capacity.transition_work_units(
        operation=candidate.OPERATION,
        query_work_units=sum(query.work_units for query in query_program),
        kernel_work_units=kernel.work_units, mutations=finalized,
    )
    capacity.validate_transition_work_units(candidate.OPERATION, total_work_units, finalized)
    if (not finalized or len(finalized) > spec["maximumMutations"]
            or not 1 <= total_work_units <= spec["maximumWorkUnits"]
            or any(type(item) is not dict or len(item) != len(_MUTATION_FIELDS)
                   or set(item) != _MUTATION_FIELDS for item in finalized)):
        raise RevocationSemanticsError("semantic finalized transition exceeds its source contract")
    capacity_work = mixed._delta(before, work.metrics)
    return kernel, finalized, total_work_units, kernel_work, capacity_work


def _ordered_mutations(mutations, *, work: _ValidationWork):
    """Meter the actual planner ordering of an already-owned closed inventory."""
    if (type(work) is not _ValidationWork or type(mutations) is not tuple
            or len(mutations) > authority_contract.operation_spec(candidate.OPERATION)["maximumMutations"]):
        raise RevocationSemanticsError("revocation ordering requires owned mutations and exact shared work")
    work.prepare_copy(mutations)
    ordered = sorted(mutations, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    work.prepare_copy(ordered)
    return tuple(ordered)


def _verify(owned, ledger, capture, verifier_public_key):
    """Recompute on the caller's already-owned graph and sole live ledger.

    Outer transport code may pass this exact eleven-field mapping of references
    into a larger joint capture. ``capture`` then describes that actual larger
    capture, not a reconstructed semantic-only copy. Earlier transport work
    remains in cumulative totals and the proof packaging snapshot; each named
    semantic phase is still its own delta. This entry makes no fresh capture,
    work object, successful-result admission or independent trust assertion.
    Encode any outer output before entry: the compact hold is the only hold.
    On failure the caller must abort, not retry this partially spent invocation.
    """
    _require_owned_handoff(owned, ledger, capture)
    work = ledger.work
    contract.validate_bundle_shape(owned["bundle"])
    contract.validate_transition_shape(owned["transition"])
    _expected_before(owned["expectedBefore"])
    inputs = owned["bundle"]["inputs"]
    request = owned["request"]
    if type(request) is not dict or request.get("operation") != candidate.OPERATION:
        raise RevocationSemanticsError("semantic request is outside explicit revocation")

    before = work.metrics
    request_digest = request_commitment._typed_request_digest(request, work=work)
    core.require_digest(request["requestDigest"], "semantic request digest")
    core.require_digest(request["operationId"], "semantic operation identifier")
    _equal(request_digest, request["requestDigest"], work=work,
           label="semantic request digest differs from actual request derivation")
    _equal(request_digest, inputs["requestDigest"], work=work,
           label="semantic request digest differs from retained proof input")
    work.prepare_utf8(candidate.OPERATION)
    work.prepare_utf8(request_digest)
    work.charge(hashes=1)
    operation_id = request_commitment.operation_id(candidate.OPERATION, request_digest)
    _equal(operation_id, request["operationId"], work=work,
           label="semantic operation identifier differs from actual derivation")
    _canonical_equal(request["arguments"], inputs["arguments"], work=work,
                     label="semantic request arguments differ from retained proof input")
    request_binding = mixed._delta(before, work.metrics)

    before = work.metrics
    verified_evidence, signature_attempts = _verify_evidence(
        owned["evidence"], operation_id=operation_id, request_digest=request_digest,
        capability_id=owned["capabilityId"], verifier_identity=owned["verifierIdentity"],
        verifier_public_key=verifier_public_key, now_epoch_ns=owned["nowEpochNs"],
        deadline_epoch_ns=owned["deadlineEpochNs"], maximum_age_ns=owned["maximumAgeNs"],
        work=work,
    )
    receipt = mixed._delta(before, work.metrics)

    before = work.metrics
    _equal(owned["databaseCutoffUs"], inputs["cutoffUs"], work=work,
           label="semantic database time differs from the complete-query cutoff")
    _canonical_equal(_evidence_binding(verified_evidence), inputs["assertionBinding"], work=work,
        label="verified authorization differs from retained query binding")
    for expected, supplied in (("businessBeforeRoots", "businessBeforeRoots"),
                               ("authorizationBeforeRoots", "authorizationBeforeRoots"),
                               ("indexBeforeHeads", "countedBeforeHeads")):
        _canonical_equal(owned["expectedBefore"][expected], inputs[supplied], work=work,
                         label="retained before roots differ from independent expectations")
    database_now = _EPOCH + timedelta(microseconds=owned["databaseCutoffUs"])
    context_binding = mixed._delta(before, work.metrics)

    before = work.metrics
    claim_wire = retained._bounded_wire(owned["transition"], ledger,
        maximum_bytes=contract.MAX_COMPACT_BYTES, maximum_nodes=contract.MAX_COMPACT_NODES)
    claim_encoding = mixed._delta(before, work.metrics)
    proof, actual = retained._compute_and_package(
        ledger=ledger, bundle=owned["bundle"], raw_decode_bytes=0, capture=capture,
        claim_encoding=claim_encoding, claim_wire=claim_wire,
    )
    proof_work = mixed._delta(before, work.metrics)

    # The private proof worker returned its actual owned rows and declarations.
    # KernelContext stores these references without another graph copy or proof
    # pass. The receipt's fresh scalar MappingProxy is passed without recopying.
    kernel, finalized, total_work_units, kernel_work, capacity_work = _derive_revocation_effects(
        arguments=actual.arguments,
        selected_rows=actual.selected_rows, database_now=database_now,
        request_digest=request_digest, verified_webauthn_evidence=verified_evidence,
        query_program=actual.query_program, query_reads=actual.query_reads, work=work,
    )

    before = work.metrics
    # The framework appends its counter. Restore the actual planner ordering
    # before comparing every seven-field mutation, including full OLD/NEW rows.
    mutations = _ordered_mutations(finalized, work=work)
    # Proof evaluation admits a duplicate-free inventory without imposing its
    # transport order. Compare effects in the same source order on both sides.
    claimed_mutations = _ordered_mutations(actual.mutations, work=work)
    _canonical_equal(mutations, claimed_mutations, work=work,
                     label="proved mutations differ from genuine kernel and capacity semantics")
    mutation_binding = mixed._delta(before, work.metrics)
    return RevocationSemanticObservation(proof, kernel, mutations, total_work_units,
        RevocationSemanticMetrics(capture, request_binding, receipt, context_binding, proof_work,
            kernel_work, capacity_work, mutation_binding, signature_attempts,
            ledger.hashes, ledger.input_bytes, ledger.json_nodes))


def verify_revocation_semantics(
    *, bundle: Any, transition: Any, request: Any, evidence: Any,
    verifier_identity: Any, verifier_public_key: Ed25519PublicKey, capability_id: str,
    database_now: datetime, now_epoch_ns: int, deadline_epoch_ns: int, maximum_age_ns: int,
    expected_before: Any, limits: QueryReadValidationLimits | None = None,
) -> RevocationSemanticObservation:
    """Recompute genuine semantics from raw graphs and independent expectations.

    The typed request body is genuinely hashed; its public registry gate remains
    closed. All raw evidence and expectation graphs are captured before any SHA.
    One receipt wrapper permits one actual signature attempt. Every phase shares
    the same whole-operation 8M-hash/64MiB/1M-node ceilings; failure aborts the
    invocation without retry or refund. No SQL, authorization or currentness is
    inferred from caller-supplied pins, clocks, capability or before-root vectors.
    """
    try:
        ledger = retained._PackagingLedger(
            QueryReadValidationLimits() if limits is None else limits, comparing=True)
        owned, capture = _capture(ledger=ledger, bundle=bundle, transition=transition,
            request=request, evidence=evidence, verifier_identity=verifier_identity,
            capability_id=capability_id, database_now=database_now, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, maximum_age_ns=maximum_age_ns,
            expected_before=expected_before)
        return _verify(owned, ledger, capture, verifier_public_key)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError,
            core.TransitionKernelError, request_commitment.AuthorityPlannerError) as exc:
        if isinstance(exc, RevocationSemanticsError):
            raise
        raise RevocationSemanticsError("revocation semantic recomputation failed") from exc
