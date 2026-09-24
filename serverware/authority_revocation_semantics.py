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
from serverware.authority_query_read_work import QueryReadValidationLimits, QueryReadValidationMetrics


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_BEFORE_FIELDS = frozenset({"businessBeforeRoots", "authorizationBeforeRoots", "indexBeforeHeads"})
_MUTATION_FIELDS = frozenset({"templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row"})


class RevocationSemanticsError(ValueError):
    pass


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


def _verify(owned, ledger, capture, verifier_public_key):
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
    receipt_work = assertion._ReceiptWork(work)
    verified_evidence = assertion._verify_revoke_assertion_evidence(
        owned["evidence"], operation_id=operation_id, request_digest=request_digest,
        capability_id=owned["capabilityId"], verifier_identity=owned["verifierIdentity"],
        verifier_public_key=verifier_public_key, now_epoch_ns=owned["nowEpochNs"],
        deadline_epoch_ns=owned["deadlineEpochNs"], maximum_age_ns=owned["maximumAgeNs"],
        work=receipt_work,
    )
    receipt = mixed._delta(before, work.metrics)

    before = work.metrics
    _equal(owned["databaseCutoffUs"], inputs["cutoffUs"], work=work,
           label="semantic database time differs from the complete-query cutoff")
    for field in ("credentialRecordId", "challengeId"):
        _equal(verified_evidence[field], inputs["assertionBinding"][field], work=work,
               label="verified assertion identity differs from retained query binding")
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
    before = work.metrics
    context = core.KernelContext(
        operation=candidate.OPERATION, arguments=actual.arguments,
        selected_rows=actual.selected_rows, database_now=database_now,
        request_digest=request_digest, verified_webauthn_evidence=verified_evidence,
        query_reads=actual.query_reads,
    )
    kernel = candidate.WebAuthnCredentialRevokeKernel()._transition(context, work=work)
    kernel_work = mixed._delta(before, work.metrics)

    before = work.metrics
    finalized = capacity._finalize_capacity(context, kernel.mutations, work=work)
    # These source-bounded metadata-only inventories (<=42 declarations and
    # <=137 mutations) are fixed scaffolding, not traversal of row payloads.
    # Signed operation work is distinct from cumulative hash/byte/node work.
    total_work_units = capacity.transition_work_units(
        operation=candidate.OPERATION,
        query_work_units=sum(query.work_units for query in actual.query_program),
        kernel_work_units=kernel.work_units, mutations=finalized,
    )
    capacity.validate_transition_work_units(candidate.OPERATION, total_work_units, finalized)
    spec = authority_contract.operation_spec(candidate.OPERATION)
    if (not finalized or len(finalized) > spec["maximumMutations"]
            or not 1 <= total_work_units <= spec["maximumWorkUnits"]
            or any(type(item) is not dict or len(item) != len(_MUTATION_FIELDS)
                   or set(item) != _MUTATION_FIELDS for item in finalized)):
        raise RevocationSemanticsError("semantic finalized transition exceeds its source contract")
    capacity_work = mixed._delta(before, work.metrics)

    before = work.metrics
    # The framework appends its counter. Restore the actual planner ordering
    # before comparing every seven-field mutation, including full OLD/NEW rows.
    work.prepare_copy(finalized)
    ordered = sorted(finalized, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    work.prepare_copy(ordered)
    mutations = tuple(ordered)
    # Proof evaluation admits a duplicate-free inventory without imposing its
    # transport order. Compare effects in the same source order on both sides.
    work.prepare_copy(actual.mutations)
    ordered_claim = sorted(actual.mutations,
        key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    work.prepare_copy(ordered_claim)
    claimed_mutations = tuple(ordered_claim)
    _canonical_equal(mutations, claimed_mutations, work=work,
                     label="proved mutations differ from genuine kernel and capacity semantics")
    mutation_binding = mixed._delta(before, work.metrics)
    return RevocationSemanticObservation(proof, kernel, mutations, total_work_units,
        RevocationSemanticMetrics(capture, request_binding, receipt, context_binding, proof_work,
            kernel_work, capacity_work, mutation_binding, receipt_work.signature_attempts,
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
