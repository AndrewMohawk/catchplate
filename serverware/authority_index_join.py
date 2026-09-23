"""Join complete index intervals to actual owned primary-proof snapshots.

The supplied anchor is a declared root pair, not a signed checkpoint. This
component rederives fixed selectors and projections, but does not establish
index population, writer maintenance, root currentness or transition authority.
No caller-provided verified object, predicate callback or projection is accepted.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
from typing import Any

from serverware import authority_contract
from serverware import authority_index_projection as projection
from serverware import authority_radix_mutation as primary
from serverware.authority_index_contract import (
    CountedNode, IndexLeaf, IndexRangeError, KeyInterval, OpaqueSubtree,
    validate_counted_node,
)
from serverware.authority_index_range import (
    IndexRangeLimits, IndexRangeMetrics, reconstruct_complete_index_range,
)
from serverware.authority_primary_contract import PRIMARY_KEY_COLUMNS
from serverware.authority_transition_core import canonical_bytes, framed_digest


CONTEXT_SCHEMA = "serverware.policyAuthorityIndexPrimaryContext/v1"
# Cold root-constructor ladder + two source profile lookups + context digest.
# The primary engine independently retains its conservative empty-hash charge;
# no warmed cache is used to discount this combined source-owned allowance.
CONTEXT_HASH_WORK = 66 + 2 * projection.PROFILE_HASH_WORK + 1
MAX_CONTEXT_BYTES = 262144
MAX_TOTAL_INPUT_BYTES = authority_contract.MAX_RESULT_BYTES + 4194304 + MAX_CONTEXT_BYTES
MAX_TOTAL_HASHES = 1100000


class IndexJoinError(IndexRangeError):
    pass


def _copy_context(value: Any, expected: type) -> Any:
    if type(value) is not expected:
        raise IndexJoinError("indexed query context has an unexpected exact type")
    try:
        return expected(**{field.name: getattr(value, field.name) for field in fields(expected)})
    except (AttributeError, primary.PrimaryRadixMutationError) as exc:
        raise IndexJoinError("indexed query context is incomplete or invalid") from exc


@dataclass(frozen=True, slots=True)
class IndexPrimaryAnchor:
    """Caller-supplied root pair; constructing it authenticates no checkpoint."""

    index_id: str
    index_revision: int
    index_root: CountedNode
    primary_root: primary.PrimaryRoot

    def __post_init__(self) -> None:
        profile = projection.profile_for(self.index_id)
        index_root = validate_counted_node(self.index_root)
        primary_root = _copy_context(self.primary_root, primary.PrimaryRoot)
        if (type(self.index_revision) is not int or not 0 <= self.index_revision <= 2**63 - 1
                or (self.index_revision == 0 and index_root.count != 0)
                or primary_root.table != profile.table):
            raise IndexJoinError("indexed query root pair identity or revision is invalid")
        object.__setattr__(self, "index_root", index_root)
        object.__setattr__(self, "primary_root", primary_root)


@dataclass(frozen=True, slots=True)
class IndexJoinLimits:
    primary: primary.PrimaryRadixLimits
    index: IndexRangeLimits
    max_total_hashes: int = MAX_TOTAL_HASHES
    max_total_input_bytes: int = MAX_TOTAL_INPUT_BYTES

    def __post_init__(self) -> None:
        for value, maximum in ((self.max_total_hashes, MAX_TOTAL_HASHES),
                               (self.max_total_input_bytes, MAX_TOTAL_INPUT_BYTES)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise IndexJoinError("indexed query total budget is not an exact bounded value")
        object.__setattr__(self, "primary", _copy_context(self.primary, primary.PrimaryRadixLimits))
        object.__setattr__(self, "index", _copy_context(self.index, IndexRangeLimits))


@dataclass(frozen=True, slots=True)
class IndexJoinMetrics:
    primary: primary.PrimaryRadixMetrics
    index: IndexRangeMetrics
    context_hashes: int
    projection_hashes: int
    context_bytes: int
    total_hashes: int
    total_input_bytes: int


@dataclass(frozen=True, slots=True)
class JoinedIndexObservation:
    anchor: IndexPrimaryAnchor
    interval: KeyInterval
    leaves: tuple[IndexLeaf, ...]
    context_digest: str
    metrics: IndexJoinMetrics


class _Budget:
    def __init__(self, limits: IndexJoinLimits) -> None:
        self.limits = limits
        self.hashes = 0
        self.input_bytes = 0

    @property
    def remaining_hashes(self) -> int:
        return self.limits.max_total_hashes - self.hashes

    @property
    def remaining_bytes(self) -> int:
        return self.limits.max_total_input_bytes - self.input_bytes

    def charge(self, *, hashes: int = 0, input_bytes: int = 0) -> None:
        if hashes > self.remaining_hashes or input_bytes > self.remaining_bytes:
            raise IndexJoinError("indexed query combined work or input budget exceeded")
        self.hashes += hashes
        self.input_bytes += input_bytes

    def require_phase(self) -> None:
        if self.remaining_hashes < 1 or self.remaining_bytes < 1:
            raise IndexJoinError("indexed query has no remaining phase budget")


def join_index_range(
    *, anchor: IndexPrimaryAnchor, selector: dict[str, Any],
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...],
    selected_rows: tuple[dict[str, Any], ...], before_proofs: tuple[dict[str, Any], ...],
    limits: IndexJoinLimits,
) -> JoinedIndexObservation:
    """Reverify both proof families and join exactly their returned members.

    Each phase's effective budget is clamped to the combined remaining budget
    before execution. Primary rows/proofs are copied only by the actual primary
    engine and projection uses exactly those verified owned copies. This is not
    a transport parser: primary wire bytes retain the engine's post-snapshot
    encoding check, and range bytes retain their separate scalar framing.
    """
    limits = _copy_context(limits, IndexJoinLimits)
    budget = _Budget(limits)
    budget.charge(hashes=CONTEXT_HASH_WORK)
    anchor = _copy_context(anchor, IndexPrimaryAnchor)
    profile = projection.profile_for(anchor.index_id)
    owned_selector = projection.snapshot_selector(anchor.index_id, selector)
    context = {
        "schema": CONTEXT_SCHEMA,
        "profile": {"indexId": profile.index_id, "table": profile.table,
                    "projectionDigest": profile.projection_digest},
        "indexRevision": anchor.index_revision,
        "indexRoot": {"digest": anchor.index_root.digest, "count": anchor.index_root.count},
        "primaryRoot": anchor.primary_root.json_projection(),
        "selector": owned_selector,
    }
    # Only source-bounded identities and a closed shallow <=4096-byte-per-text
    # selector enter this encoding, never selected rows or arbitrary JSON.
    context_wire = canonical_bytes(context)
    if len(context_wire) > MAX_CONTEXT_BYTES:
        raise IndexJoinError("indexed query context exceeds its wire byte ceiling")
    budget.charge(input_bytes=len(context_wire), hashes=projection.QUERY_HASH_WORK)
    context_digest = framed_digest(CONTEXT_SCHEMA, context_wire)
    interval = projection.query_interval(anchor.index_id, owned_selector)

    budget.require_phase()
    range_limits = replace(
        limits.index, max_hashes=min(limits.index.max_hashes, budget.remaining_hashes),
        max_input_bytes=min(limits.index.max_input_bytes, budget.remaining_bytes),
        max_leaves=min(limits.index.max_leaves, limits.primary.max_selected_rows,
                       authority_contract.MAX_QUERY_PROOFS),
    )
    indexed = reconstruct_complete_index_range(
        profile=profile, expected_root=anchor.index_root, interval=interval,
        frontier=frontier, limits=range_limits,
    )
    budget.charge(hashes=indexed.metrics.hashes, input_bytes=indexed.metrics.input_bytes)
    count = len(indexed.leaves)
    if (type(selected_rows) is not tuple or type(before_proofs) is not tuple
            or len(selected_rows) != count or len(before_proofs) != count):
        raise IndexJoinError("indexed query primary inventory does not match its complete range")
    # Reserve every row projection before starting primary work. A failed or
    # nonmember projection cannot use a partial result to refund this allowance.
    row_hashes = projection.ROW_HASH_WORK * count
    budget.charge(hashes=row_hashes)
    budget.require_phase()
    primary_limits = replace(
        limits.primary, max_hashes=min(limits.primary.max_hashes, budget.remaining_hashes),
        max_input_bytes=min(limits.primary.max_input_bytes, budget.remaining_bytes),
        max_selected_rows=min(limits.primary.max_selected_rows, authority_contract.MAX_QUERY_PROOFS),
    )
    try:
        memberships = primary.evaluate_primary_radix_memberships(
            table_contracts=(primary.PrimaryTableContract(
                profile.table, PRIMARY_KEY_COLUMNS[profile.table], False, "business"),),
            business_before_roots=(anchor.primary_root,), authorization_before_roots=(),
            selected_rows=selected_rows, before_proofs=before_proofs, limits=primary_limits,
        )
    except primary.PrimaryRadixMutationError as exc:
        raise IndexJoinError("indexed query primary membership reconstruction failed") from exc
    budget.charge(hashes=memberships.result.metrics.hash_work,
                  input_bytes=memberships.result.metrics.input_bytes)
    if (memberships.result.business_after_roots != (anchor.primary_root,)
            or memberships.result.authorization_after_roots):
        raise IndexJoinError("indexed query read-only evaluation changed its root pair")

    indexed_by_key = {leaf.primary_key_digest: leaf for leaf in indexed.leaves}
    proofs_by_key = {proof["keyDigest"]: proof for proof in memberships.before_proofs}
    seen: set[str] = set()
    for selected in memberships.selected_rows:
        key_digest = selected["keyDigest"]
        if (selected["present"] is not True or selected["contractSelector"] is not None
                or key_digest not in indexed_by_key or key_digest in seen):
            raise IndexJoinError("indexed query returned row is absent, extra or not an exact member")
        derived = projection.project_row(
            anchor.index_id, selected["row"], primary_key_digest=key_digest,
            primary_row_digest=proofs_by_key[key_digest]["rowDigest"],
        )
        if derived is None or derived != indexed_by_key[key_digest]:
            raise IndexJoinError("indexed query row projection differs from its committed leaf")
        seen.add(key_digest)
    if seen != set(indexed_by_key):
        raise IndexJoinError("indexed query leaves and primary members are not bijective")
    return JoinedIndexObservation(
        anchor=anchor, interval=indexed.interval, leaves=indexed.leaves,
        context_digest=context_digest,
        metrics=IndexJoinMetrics(
            primary=memberships.result.metrics, index=indexed.metrics,
            context_hashes=CONTEXT_HASH_WORK,
            projection_hashes=projection.QUERY_HASH_WORK + row_hashes,
            context_bytes=len(context_wire), total_hashes=budget.hashes,
            total_input_bytes=budget.input_bytes,
        ),
    )
