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

from catchplate import authority_contract
from catchplate import authority_complete_query_batch as query_batch
from catchplate import authority_index_contract as counted
from catchplate import authority_radix_mutation as primary
from catchplate import authority_revocation_bundle_contract as contract
from catchplate import authority_revocation_read_write as mixed
from catchplate import authority_root_transition as legacy
from catchplate import authority_transition_core as core
from catchplate.authority_query_read_work import (
    QueryReadValidationLimits, QueryReadValidationMetrics, _ValidationWork,
)


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


@dataclass(frozen=True, slots=True)
class _DerivedRevocationProof:
    """Actual private outputs, including owned mutable graphs; never authority.

    No graph is reconstructed by parsing the immutable retained bytes. Callers
    must keep these ordinary values inside their own invocation and must not
    accept a freely constructed instance as proof or authorization.
    """

    retained: RetainedRevocationProof
    result: mixed.RevocationReadWriteInputs
    bundle: dict[str, Any]
    transition: dict[str, Any]


class _PackagingLedger(mixed._Ledger):
    """A held output allowance constrains the actual work object's limits.

    Only private code controls the hold. Reducing the effective ceilings keeps
    direct work calls, including the mixed worker's final comparison, within
    the unheld pool. Release restores capacity exactly once; spent counters
    never decrease and no fresh source-sized ledger is created.
    """

    def __init__(self, limits, *, comparing: bool):
        super().__init__(limits)
        self._reserve_compact(comparing=comparing)

    @classmethod
    def _attach(cls, work: _ValidationWork, *, comparing: bool):
        """Attach exact live work, without constructing a replacement meter."""
        if type(work) is not _ValidationWork or type(work.limits) is not QueryReadValidationLimits:
            raise RevocationProofBundleError("retained proof attachment requires exact shared work")
        owner = getattr(work, "_revocation_packaging_owner", None)
        if owner is not None:
            if type(owner) is cls:
                owner._attachment_failed = True
            raise RevocationProofBundleError("retained proof shared attachment is already active")
        try:
            limits = work.limits
            QueryReadValidationLimits(limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
            for value, maximum in ((work.hash_work, limits.max_hashes),
                                   (work.input_bytes, limits.max_input_bytes),
                                   (work.json_nodes, limits.max_json_nodes)):
                if type(value) is not int or not 0 <= value <= maximum:
                    raise RevocationProofBundleError("retained proof shared counters are not within entering limits")
        except AttributeError as exc:
            raise RevocationProofBundleError("retained proof shared work is incomplete") from exc
        ledger = object.__new__(cls)
        ledger.work = work
        ledger._reserve_compact(comparing=comparing)
        ledger._attachment_failed = False
        work._revocation_packaging_owner = ledger
        return ledger

    def _reserve_compact(self, *, comparing: bool):
        self.original_limits = self.work.limits
        self._original_limit_values = (self.original_limits.max_hashes,
            self.original_limits.max_input_bytes, self.original_limits.max_json_nodes)
        self._original_work = self.work
        self._entering_metrics = self.work.metrics
        self.reserved = QueryReadValidationMetrics(1,
            (4 if comparing else 2) * contract.MAX_COMPACT_BYTES,
            2 * contract.MAX_COMPACT_NODES)
        reduced = (self.original_limits.max_hashes - self.reserved.hash_work,
                   self.original_limits.max_input_bytes - self.reserved.input_bytes,
                   self.original_limits.max_json_nodes - self.reserved.json_nodes)
        if (min(reduced) < 1 or self.work.hash_work > reduced[0]
                or self.work.input_bytes > reduced[1] or self.work.json_nodes > reduced[2]):
            raise RevocationProofBundleError("retained proof budget cannot reserve bounded compact output")
        self.work.limits = self._held_limits = QueryReadValidationLimits(*reduced)
        self._held = True

    def _require_original_limits(self) -> None:
        # An external callback can retain this object while the live work uses
        # held limits. Identity checks on the live object alone cannot detect
        # an in-place change to the ceiling that will later be restored.
        if type(self.original_limits) is not QueryReadValidationLimits:
            raise RevocationProofBundleError("retained proof entering limits were changed")
        values = (self.original_limits.max_hashes, self.original_limits.max_input_bytes,
                  self.original_limits.max_json_nodes)
        if any(type(value) is not int for value in values) or values != self._original_limit_values:
            raise RevocationProofBundleError("retained proof entering limits were changed")

    def release_compact_hold(self) -> QueryReadValidationMetrics:
        self._require_original_limits()
        if (not self._held or getattr(self, "_attachment_failed", False)
                or self.work is not self._original_work
                or self.work.limits is not self._held_limits
                or self.work.hash_work < self._entering_metrics.hash_work
                or self.work.input_bytes < self._entering_metrics.input_bytes
                or self.work.json_nodes < self._entering_metrics.json_nodes):
            raise RevocationProofBundleError("retained proof compact allowance was already released")
        peak = QueryReadValidationMetrics(self.hashes + self.reserved.hash_work,
            self.input_bytes + self.reserved.input_bytes, self.json_nodes + self.reserved.json_nodes)
        self.work.limits = self.original_limits
        self._held = False
        return peak

    def _restore_entering_limits(self) -> None:
        """Restore the entering reference, never counters or corrupted scalars.

        External mutation of that object denies publication; unwind does not
        repair caller state or make a failed invocation safe to reuse.
        """
        self._original_work.limits = self.original_limits
        self._held = False
        if getattr(self._original_work, "_revocation_packaging_owner", None) is self:
            del self._original_work._revocation_packaging_owner

    def _require_attachment_complete(self) -> None:
        self._require_original_limits()
        if (self._attachment_failed or self._held or self.work is not self._original_work
                or self.work.limits is not self.original_limits
                or getattr(self.work, "_revocation_packaging_owner", None) is not self
                or self.work.hash_work < self._entering_metrics.hash_work
                or self.work.input_bytes < self._entering_metrics.input_bytes
                or self.work.json_nodes < self._entering_metrics.json_nodes):
            raise RevocationProofBundleError("retained proof shared attachment was poisoned or replaced")


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
    schema, profile = contract.profile(owned["assertionBinding"])
    return {"schema": schema, "profile": profile,
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

    schema, profile = contract.profile(result.assertion_binding, transition=True)
    return {"schema": schema, "profile": profile,
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


def _compute_with_graphs(*, ledger, bundle, raw_decode_bytes, capture, claim_encoding, claim_wire):
    before = ledger.work.metrics
    bundle_wire = _bounded_wire(bundle, ledger,
        maximum_bytes=query_batch.MAX_TOTAL_INPUT_BYTES, maximum_nodes=query_batch.MAX_TOTAL_JSON_NODES)
    ledger.charge(hashes=1)
    bundle_digest = core.framed_digest(contract.profile(bundle["inputs"]["assertionBinding"])[0], bundle_wire)
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
    transition_digest = core.framed_digest(contract.profile(result.assertion_binding, transition=True)[0], transition_wire)
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
    return _DerivedRevocationProof(retained, result, bundle, compact)


def _compute_and_package(*, ledger, bundle, raw_decode_bytes, capture, claim_encoding, claim_wire):
    # Preserve the established private two-tuple seam used by semantic replay.
    # Both routes execute the same actual body, with no repeated proof pass.
    derived = _compute_with_graphs(ledger=ledger, bundle=bundle, raw_decode_bytes=raw_decode_bytes,
        capture=capture, claim_encoding=claim_encoding, claim_wire=claim_wire)
    return derived.retained, derived.result


def _derive_on_work(*, work: _ValidationWork, **inputs) -> _DerivedRevocationProof:
    """Own raw evidence and genuinely recompute on the caller's remaining work.

    Earlier acquisition is not accepted as proof: the actual mixed verifier
    runs and is charged again. Packaging phase deltas retain their existing
    meaning; cumulative totals and reservation peaks include prior spending.
    A failure aborts the owning invocation. This restores its entering limit
    object (including any outer hold), but never repairs externally corrupted
    scalars, refunds spent work or creates an independent allowance. Returned
    graphs are not authority tokens.
    """
    ledger = None
    try:
        if len(inputs) != len(_INPUT_KEYWORDS) or set(inputs) != _INPUT_KEYWORDS:
            raise RevocationProofBundleError("retained proof input keyword inventory is not closed")
        ledger = _PackagingLedger._attach(work, comparing=False)
        owned, raw_decode_bytes, capture = mixed._capture(ledger=ledger, **inputs)
        contract.validate_inputs_shape(owned)
        derived = _compute_with_graphs(ledger=ledger, bundle=_bundle(owned), raw_decode_bytes=raw_decode_bytes,
            capture=capture, claim_encoding=_zero(), claim_wire=None)
        ledger._require_attachment_complete()
        return derived
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError,
            core.TransitionKernelError) as exc:
        if isinstance(exc, RevocationProofBundleError):
            raise
        raise RevocationProofBundleError("shared retained revocation proof derivation failed") from exc
    finally:
        if ledger is not None:
            ledger._restore_entering_limits()


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
