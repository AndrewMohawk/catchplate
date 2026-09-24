"""Retain and genuinely recompute raw mixed revocation proof evidence.

The raw bundle can contain sensitive selected rows. It belongs inside the
semantic execution/storage boundary, not in an external witness request.
Digests authenticate neither origin, signatures, time, current roots nor
operation intent. This component does not activate a planner or SQL protocol.

Replay accepts already-decoded lossless JSON graphs: bounded transport parsing
is the caller's separate responsibility. Retained query JSON is never parsed
into declarations. No public API accepts a successful proof result as input.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from serverware import authority_contract
from serverware import authority_complete_query_batch as query_batch
from serverware import authority_index_contract as counted
from serverware import authority_radix_mutation as primary
from serverware import authority_revocation_bundle_contract as contract
from serverware import authority_revocation_read_write as mixed
from serverware import authority_root_transition as legacy
from serverware import authority_transition_core as core
from serverware.authority_query_read_work import QueryReadValidationLimits, QueryReadValidationMetrics


_PHASES = (
    ("generation", "generation"), ("declarationBinding", "declaration_binding"),
    ("observationValidation", "observation_validation"), ("pointBinding", "point_binding"),
    ("proofWork", "proof_work"), ("completeBinding", "complete_binding"),
)
_INPUT_KEYWORDS = frozenset({
    "operation", "arguments", "cutoff_us", "request_digest", "assertion_binding", "query_reads",
    "queries", "business_before_roots", "authorization_before_roots", "selected_rows",
    "before_proofs", "mutations", "counted_before_heads", "query_frontiers", "write_frontiers",
})


class RevocationProofBundleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RevocationProofPackagingMetrics:
    raw_decode_bytes: int
    capture: QueryReadValidationMetrics
    claim_encoding: QueryReadValidationMetrics
    bundle_encoding: QueryReadValidationMetrics
    verification: tuple[tuple[str, QueryReadValidationMetrics], ...]
    finalization: QueryReadValidationMetrics
    reserved_compact_work: QueryReadValidationMetrics
    peak_reserved_work: QueryReadValidationMetrics
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class RetainedRevocationProof:
    """Immutable wire observations and the actual writer's primary result.

    Freely constructible data, never a reusable authorization capability.
    Packaging totals are outside both hashed documents to avoid self-reference.
    """

    primary: primary.PrimaryRadixBatchResult
    bundle_bytes: bytes
    bundle_digest: str
    transition_bytes: bytes
    transition_digest: str
    packaging: RevocationProofPackagingMetrics


class _PackagingLedger(mixed._Ledger):
    """A held output allowance constrains the actual work object's limits.

    Only private code controls the hold. Reducing the effective ceilings keeps
    direct work calls, including the mixed worker's final comparison, within
    the unheld pool. Release restores capacity exactly once; spent counters
    never decrease and no fresh source-sized ledger is created.
    """

    def __init__(self, limits, *, comparing: bool):
        super().__init__(limits)
        self.original_limits = self.work.limits
        self.reserved = QueryReadValidationMetrics(1,
            (4 if comparing else 2) * contract.MAX_COMPACT_BYTES,
            2 * contract.MAX_COMPACT_NODES)
        reduced = (self.original_limits.max_hashes - self.reserved.hash_work,
                   self.original_limits.max_input_bytes - self.reserved.input_bytes,
                   self.original_limits.max_json_nodes - self.reserved.json_nodes)
        if min(reduced) < 1:
            raise RevocationProofBundleError("retained proof budget cannot reserve bounded compact output")
        self.work.limits = QueryReadValidationLimits(*reduced)
        self._held = True

    def release_compact_hold(self) -> QueryReadValidationMetrics:
        if not self._held:
            raise RevocationProofBundleError("retained proof compact allowance was already released")
        peak = QueryReadValidationMetrics(self.hashes + self.reserved.hash_work,
            self.input_bytes + self.reserved.input_bytes, self.json_nodes + self.reserved.json_nodes)
        self.work.limits = self.original_limits
        self._held = False
        return peak


def _zero() -> QueryReadValidationMetrics:
    return QueryReadValidationMetrics(0, 0, 0)


def _bounded_wire(value, ledger, *, maximum_bytes: int, maximum_nodes: int) -> bytes:
    """Charge actual measurement and reserve the real canonical encoder.

    Size checks occur after bounded measurement but before creating the encoded
    buffer. A rejected measurement is still spent work, never a free probe.
    """
    size, nodes = ledger.work.measure(value)
    if size > maximum_bytes or nodes > maximum_nodes:
        raise RevocationProofBundleError("retained proof document exceeds its wire or node ceiling")
    ledger.charge(input_bytes=size, json_nodes=nodes)
    encoded = core.canonical_bytes(value)
    if len(encoded) != size:
        raise RevocationProofBundleError("retained proof canonical measurement changed")
    return encoded


def _bundle(owned) -> dict[str, Any]:
    return {"schema": contract.BUNDLE_SCHEMA, "profile": contract.BUNDLE_PROFILE,
            "sourceRevision": authority_contract.SOURCE_REVISION, "inputs": owned}


def _metric(value) -> dict[str, int]:
    return {"hashWork": value.hash_work, "inputBytes": value.input_bytes, "jsonNodes": value.json_nodes}


def _compact_document(result, bundle_digest) -> dict[str, Any]:
    # Fixed bounded projections of the ACTUAL result. No legacy derive or
    # structural validator is called to repeat primary/profile constructors.
    metrics = {name: _metric(getattr(result.metrics, attribute)) for name, attribute in _PHASES}
    totals = {key: sum(value[key] for value in metrics.values())
              for key in ("hashWork", "inputBytes", "jsonNodes")}
    metrics.update(totals)

    def heads(values):
        # The actual projection-manifest commitment binds source identity and
        # table/profile mapping; no extra profile_for call is hidden here.
        return [{"indexId": value.index_id, "indexRevision": value.index_revision,
                 "rootDigest": value.index_root.digest, "leafCount": value.index_root.count}
                for value in values]

    return {"schema": contract.TRANSITION_SCHEMA, "profile": contract.TRANSITION_PROFILE,
        "sourceRevision": authority_contract.SOURCE_REVISION, "operation": result.operation,
        "requestDigest": result.request_digest, "cutoffUs": result.cutoff_us,
        "assertionBinding": result.assertion_binding, "countedProfile": counted.PROFILE,
        "projectionManifestDigest": result.projection_manifest_digest, "proofBundleDigest": bundle_digest,
        "primaryTransition": {"schema": legacy.TRANSITION_SCHEMA, "profile": legacy.TRANSITION_PROFILE,
            "businessBeforeRoots": [root.json_projection() for root in result.business_before_roots],
            "authorizationBeforeRoots": [root.json_projection() for root in result.authorization_before_roots],
            **result.write.primary.json_projection()},
        "indexBeforeHeads": heads(result.before_heads), "indexAfterHeads": heads(result.after_heads),
        "metrics": metrics}


def _compute_and_package(*, ledger, bundle, raw_decode_bytes, capture, claim_encoding, claim_wire):
    before = ledger.work.metrics
    bundle_wire = _bounded_wire(bundle, ledger,
        maximum_bytes=query_batch.MAX_TOTAL_INPUT_BYTES, maximum_nodes=query_batch.MAX_TOTAL_JSON_NODES)
    ledger.charge(hashes=1)
    bundle_digest = core.framed_digest(contract.BUNDLE_SCHEMA, bundle_wire)
    bundle_encoding = mixed._delta(before, ledger.work.metrics)
    # One genuine private evaluation of the owned normalized graph. A decoded
    # bundle supplies no DTO constructors, callbacks or successful result tokens.
    result = mixed._verify(bundle["inputs"], ledger, raw_decode_bytes, capture)
    compact = _compact_document(result, bundle_digest)
    contract.validate_transition_shape(compact)
    verification = tuple((name, getattr(result.metrics, attribute)) for name, attribute in _PHASES)
    peak = ledger.release_compact_hold()
    before = ledger.work.metrics
    transition_wire = _bounded_wire(compact, ledger,
        maximum_bytes=contract.MAX_COMPACT_BYTES, maximum_nodes=contract.MAX_COMPACT_NODES)
    if claim_wire is not None:
        ledger.charge(input_bytes=len(claim_wire) + len(transition_wire))
        if transition_wire != claim_wire:
            raise RevocationProofBundleError("retained transition differs from genuine raw proof recomputation")
    ledger.charge(hashes=1)
    transition_digest = core.framed_digest(contract.TRANSITION_SCHEMA, transition_wire)
    finalization = mixed._delta(before, ledger.work.metrics)
    # These checks protect the reservation argument even if a future helper
    # changes its work schedule without updating the source-sized hold.
    if (finalization.hash_work > ledger.reserved.hash_work
            or finalization.input_bytes > ledger.reserved.input_bytes
            or finalization.json_nodes > ledger.reserved.json_nodes):
        raise RevocationProofBundleError("retained proof finalization exceeded its reserved source work")
    retained = RetainedRevocationProof(result.write.primary, bundle_wire, bundle_digest,
        transition_wire, transition_digest, RevocationProofPackagingMetrics(
            raw_decode_bytes, capture, claim_encoding, bundle_encoding, verification, finalization,
            ledger.reserved, peak, ledger.hashes, ledger.input_bytes, ledger.json_nodes))
    # Private composition retains this actual result without evaluating the
    # proofs again. Neither public facade accepts a successful result as input.
    return retained, result


def derive_revocation_proof_bundle(*, limits: QueryReadValidationLimits | None = None,
                                  **inputs) -> RetainedRevocationProof:
    """Retain original typed inputs and compute one bounded mixed transition.

    Limits include capture, raw-bundle encoding, genuine proof work and compact
    output. The conservative output hold can make admission's peak higher than
    final actual work; unused held capacity is not reported as spent work.
    """
    try:
        if len(inputs) != len(_INPUT_KEYWORDS) or set(inputs) != _INPUT_KEYWORDS:
            raise RevocationProofBundleError("retained proof input keyword inventory is not closed")
        ledger = _PackagingLedger(QueryReadValidationLimits() if limits is None else limits, comparing=False)
        owned, raw_decode_bytes, capture = mixed._capture(ledger=ledger, **inputs)
        contract.validate_inputs_shape(owned)
        return _compute_and_package(ledger=ledger, bundle=_bundle(owned), raw_decode_bytes=raw_decode_bytes,
            capture=capture, claim_encoding=_zero(), claim_wire=None)[0]
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError,
            core.TransitionKernelError) as exc:
        if isinstance(exc, RevocationProofBundleError):
            raise
        raise RevocationProofBundleError("retained revocation proof derivation failed") from exc


def verify_revocation_proof_bundle(*, bundle: Any, transition: Any,
                                  limits: QueryReadValidationLimits | None = None) -> RetainedRevocationProof:
    """Own both decoded wire graphs, genuinely recompute once and compare all.

    This does not parse transport bytes or retained query JSON. Shape admission
    is deliberately not a public successful-result token. Caller-supplied
    context and before roots still need separate independent authorization.
    """
    try:
        ledger = _PackagingLedger(QueryReadValidationLimits() if limits is None else limits, comparing=True)
        before = ledger.work.metrics
        # The pair is our synthetic ownership frame, not either wire document.
        # Both actual document roots start at depth zero, matching derivation's
        # encoder. The pair's bytes/nodes and all cycle checks are still paid.
        owned = query_batch._JSONCapture(ledger).visit(
            {"bundle": bundle, "transition": transition}, depth=-1)
        capture = mixed._delta(before, ledger.work.metrics)
        contract.validate_bundle_shape(owned["bundle"])
        contract.validate_transition_shape(owned["transition"])
        before = ledger.work.metrics
        claim_wire = _bounded_wire(owned["transition"], ledger,
            maximum_bytes=contract.MAX_COMPACT_BYTES, maximum_nodes=contract.MAX_COMPACT_NODES)
        claim_encoding = mixed._delta(before, ledger.work.metrics)
        return _compute_and_package(ledger=ledger, bundle=owned["bundle"], raw_decode_bytes=0,
            capture=capture, claim_encoding=claim_encoding, claim_wire=claim_wire)[0]
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError,
            core.TransitionKernelError) as exc:
        if isinstance(exc, RevocationProofBundleError):
            raise
        raise RevocationProofBundleError("retained revocation proof recomputation failed") from exc
