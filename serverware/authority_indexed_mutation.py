"""Calculate all affected counted roots from genuinely verified primary changes.

The actual primary engine owns and validates OLD/NEW images before projection.
Every fixed index of every changed source table is required, including profiles
whose two images are nonmembers. Genuine sparse before/after folds follow.
Supplied contracts and heads are not independent authority or operation intent.
This installs no stores/triggers, accepts no successful-verifier token and does
not activate planner/executor, witness, bootstrap or Snapshot/v4 integration.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
from typing import Any

from serverware import authority_contract
from serverware import authority_index_projection as projection
from serverware import authority_index_mutation as counted
from serverware import authority_radix_mutation as primary
from serverware import authority_radix_proof as radix
from serverware.authority_index_contract import (
    I64_MAX, CountedNode, IndexLeaf, IndexRangeError, OpaqueSubtree,
    validate_counted_node, validate_leaf, validate_opaque_subtree,
)


MAX_TOTAL_HASHES = 8_000_000
MAX_TOTAL_INPUT_BYTES = authority_contract.MAX_RESULT_BYTES
_INPUT_DOMAIN = "serverware.policyAuthorityIndexedMutationInput/v1"


class IndexedMutationError(IndexRangeError):
    pass


@dataclass(frozen=True, slots=True)
class IndexedMutationInput:
    index_id: str
    index_revision: int
    index_root: CountedNode
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...]


@dataclass(frozen=True, slots=True)
class IndexedMutationHead:
    index_id: str
    index_revision: int
    index_root: CountedNode


def _copy(value: Any, expected: type) -> Any:
    if type(value) is not expected:
        raise IndexedMutationError("indexed mutation context has an unexpected exact type")
    try:
        return expected(**{item.name: getattr(value, item.name) for item in fields(expected)})
    except AttributeError as exc:
        raise IndexedMutationError("indexed mutation context is incomplete") from exc


@dataclass(frozen=True, slots=True)
class IndexedMutationLimits:
    primary: primary.PrimaryRadixLimits
    index: counted.IndexMutationLimits
    max_total_hashes: int = MAX_TOTAL_HASHES
    max_total_input_bytes: int = MAX_TOTAL_INPUT_BYTES

    def __post_init__(self) -> None:
        for value, maximum in ((self.max_total_hashes, MAX_TOTAL_HASHES),
                               (self.max_total_input_bytes, MAX_TOTAL_INPUT_BYTES)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise IndexedMutationError("indexed mutation aggregate budget is not an exact bounded value")
        object.__setattr__(self, "primary", _copy(self.primary, primary.PrimaryRadixLimits))
        object.__setattr__(self, "index", _copy(self.index, counted.IndexMutationLimits))


@dataclass(frozen=True, slots=True)
class IndexedMutationMetrics:
    primary: primary.PrimaryRadixMetrics
    indexes: tuple[tuple[str, counted.IndexMutationMetrics], ...]
    context_hashes: int
    projection_hash_allowance: int
    new_row_hashes: int
    input_bytes: int

    @property
    def hashes(self) -> int:
        return (self.primary.hash_work + sum(value.hashes for _, value in self.indexes)
                + self.context_hashes + self.projection_hash_allowance + self.new_row_hashes)


@dataclass(frozen=True, slots=True)
class IndexedMutationResult:
    primary: primary.PrimaryRadixBatchResult
    before_heads: tuple[IndexedMutationHead, ...]
    after_heads: tuple[IndexedMutationHead, ...]
    metrics: IndexedMutationMetrics


class _Budget:
    def __init__(self, limits: IndexedMutationLimits) -> None:
        self.limits = limits
        self.hashes = self.input_bytes = 0

    def hash_work(self, amount: int) -> None:
        if amount > self.limits.max_total_hashes - self.hashes:
            raise IndexedMutationError("indexed mutation exceeds its aggregate hash budget")
        self.hashes += amount

    def input_work(self, amount: int) -> None:
        if amount < 0 or amount > self.limits.max_total_input_bytes - self.input_bytes:
            raise IndexedMutationError("indexed mutation exceeds its aggregate input budget")
        self.input_bytes += amount

    def fields(self, *values: str) -> int:
        amount = sum(8 + len(value) for value in values)
        self.input_work(amount)
        return amount


def _inputs_snapshot(inputs: Any, budget: _Budget):
    if type(inputs) is not tuple or len(inputs) > len(projection.INDEX_IDS):
        raise IndexedMutationError("indexed mutation index inventory is not a bounded exact tuple")
    budget.fields(_INPUT_DOMAIN, str(len(inputs)))
    owned, reservations = [], {}
    previous = ""
    for raw in inputs:
        item = _copy(raw, IndexedMutationInput)
        if (type(item.index_id) is not str or len(item.index_id) > 128
                or item.index_id not in projection.INDEX_IDS or item.index_id <= previous):
            raise IndexedMutationError("indexed mutation index inventory is not source sorted and unique")
        root = validate_counted_node(item.index_root)
        if (type(item.index_revision) is not int or not 0 <= item.index_revision <= I64_MAX
                or (item.index_revision == 0 and root.count != 0)):
            raise IndexedMutationError("indexed mutation index revision or genesis count is invalid")
        if (type(item.frontier) is not tuple
                or len(item.frontier) > budget.limits.index.max_frontier_entries):
            raise IndexedMutationError("indexed mutation frontier exceeds its exact tuple bound")
        budget.fields(item.index_id, str(item.index_revision), root.digest, str(root.count), str(len(item.frontier)))
        records, reserved = [], 0
        for raw_record in item.frontier:
            if type(raw_record) is IndexLeaf:
                record = validate_leaf(raw_record)
                reserved += budget.fields("leaf", record.key, record.primary_key_digest, record.primary_row_digest)
            elif type(raw_record) is OpaqueSubtree:
                record = validate_opaque_subtree(raw_record)
                reserved += budget.fields("opaque", record.prefix, record.digest, str(record.count))
            else:
                raise IndexedMutationError("indexed mutation frontier has an unexpected record type")
            records.append(record)
        owned.append(IndexedMutationInput(item.index_id, item.index_revision, root, tuple(records)))
        reservations[item.index_id] = reserved
        previous = item.index_id
    return tuple(owned), reservations


def _positive_remaining(value: int, label: str) -> int:
    if value < 1:
        raise IndexedMutationError(f"indexed mutation has no remaining aggregate {label} budget")
    return value


def _changes_for_index(index_id, mutations, old_digests, new_digests, budget):
    changes: dict[str, tuple[IndexLeaf | None, IndexLeaf | None]] = {}
    revision_delta = projection_allowance = 0
    for mutation in mutations:
        address = (mutation["table"], mutation["keyDigest"])
        images = []
        for name, digests in (("expectedRow", old_digests), ("row", new_digests)):
            row = mutation[name]
            if row is None:
                images.append(None)
                continue
            # Conservative even for nonmembers, which currently return before
            # hashing. Reserve before calling the actual fixed projection.
            budget.hash_work(projection.ROW_HASH_WORK)
            projection_allowance += projection.ROW_HASH_WORK
            images.append(projection.project_row(index_id, row,
                primary_key_digest=address[1], primary_row_digest=digests[address]))
        old, new = images
        revision_delta += int(old is not None or new is not None)
        if old is not None:
            if old.key in changes:
                raise IndexedMutationError("indexed mutation repeats a projected path across primary addresses")
            changes[old.key] = (old, None)
        if new is not None:
            if new.key in changes and (old is None or old.key != new.key):
                raise IndexedMutationError("indexed mutation collides with another projected path")
            changes[new.key] = (old if old is not None and old.key == new.key else None, new)
    return (tuple(counted.IndexLeafChange(key, *changes[key]) for key in sorted(changes)),
            revision_delta, projection_allowance)


def _verify_primary(*, table_contracts, business_before_roots, authorization_before_roots,
                    selected_rows, before_proofs, mutations, budget):
    """Run the genuine primary body once on this computation's remaining budget.

    Private composition only: public entrypoints always supply raw inputs and
    never accept a successful primary result as authorization or a shortcut.
    """
    limits = budget.limits
    primary_limits = replace(limits.primary,
        max_hashes=min(limits.primary.max_hashes, _positive_remaining(
            limits.max_total_hashes - budget.hashes, "hash")),
        max_input_bytes=min(limits.primary.max_input_bytes, _positive_remaining(
            limits.max_total_input_bytes - budget.input_bytes, "input")))
    verified = primary.evaluate_primary_radix_inputs(
        table_contracts=table_contracts, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, selected_rows=selected_rows,
        before_proofs=before_proofs, mutations=mutations, limits=primary_limits)
    budget.hash_work(verified.result.metrics.hash_work)
    budget.input_work(verified.result.metrics.input_bytes)
    return verified


@dataclass(frozen=True, slots=True)
class _PreparedPrimaryChanges:
    """Private references to this invocation's genuine owned primary inputs."""

    verified: primary.PrimaryRadixMutationInputs
    by_table: dict[str, list[dict[str, Any]]]
    primary_after_counts: dict[str, int]
    primary_before_counts: dict[str, int]
    old_digests: dict[tuple[str, str], str]
    new_digests: dict[tuple[str, str], str]
    new_row_hashes: int


def _prepare_primary_changes(verified, index_ids, budget):
    # All fixed profiles are required before NEW-row hashing, including those
    # for which both source images will be nonmembers. Preserve row order and
    # hash each real NEW row once, not once per affected profile.
    by_table: dict[str, list[dict[str, Any]]] = {}
    for mutation in verified.mutations:
        table = mutation["table"]
        if projection.index_ids_for_table(table):
            if len(mutation["key"]) != 1 or "id" not in mutation["key"]:
                raise IndexedMutationError("indexed mutation primary key does not match its source id codec")
            by_table.setdefault(table, []).append(mutation)
    expected_ids = tuple(sorted(index_id for table in by_table for index_id in projection.index_ids_for_table(table)))
    if index_ids != expected_ids:
        raise IndexedMutationError("indexed mutation does not include exactly every affected source profile")
    primary_after_counts = {root.table: root.leaf_count for root in verified.result.business_after_roots}
    primary_before_counts = {table: primary_after_counts[table] - sum(
        int(change["operation"] == "INSERT") - int(change["operation"] == "DELETE")
        for change in changes) for table, changes in by_table.items()}
    old_digests = {(proof["table"], proof["keyDigest"]): proof["rowDigest"] for proof in verified.before_proofs}
    new_digests = {}
    new_row_hashes = 0
    for table, changes in by_table.items():
        for mutation in changes:
            if mutation["row"] is not None:
                budget.hash_work(1)
                new_row_hashes += 1
                new_digests[(table, mutation["keyDigest"])] = radix._tree_digest(
                    "serverware.policyAuthorityAuthenticatedRow/v1", table.encode("ascii"),
                    radix.tree_json_bytes(mutation["row"]))
    return _PreparedPrimaryChanges(verified, by_table, primary_after_counts,
        primary_before_counts, old_digests, new_digests, new_row_hashes)


def _prepare_index_changes(item, prepared, budget):
    """Genuine source profile and OLD/NEW projections, charged exactly once."""
    budget.hash_work(projection.PROFILE_HASH_WORK)
    profile = projection.profile_for(item.index_id)
    # Each fixed profile emits at most one leaf per base row. This necessary
    # descriptor-consistency check is not authenticated population proof.
    if item.index_root.count > prepared.primary_before_counts[profile.table]:
        raise IndexedMutationError("indexed mutation before count exceeds its primary population descriptor")
    changes, delta, allowance = _changes_for_index(
        item.index_id, prepared.by_table[profile.table], prepared.old_digests, prepared.new_digests, budget)
    if delta > I64_MAX - item.index_revision:
        raise IndexedMutationError("indexed mutation head revision overflows int64")
    return profile, changes, delta, allowance


def _evaluate_one_index(item, prepared, profile, changes, budget, reserved):
    """Fold an owned frontier with the genuine sparse evaluator and same ledger.

    Only this frontier's already charged scalar framing receives ``reserved``
    credit. SQL parameters, returned row material and acquisition work cannot
    be subtracted as though they were that proof-input reservation.
    """
    limits = budget.limits
    index_limits = replace(limits.index,
        max_hashes=min(limits.index.max_hashes, _positive_remaining(
            limits.max_total_hashes - budget.hashes, "hash")),
        max_input_bytes=min(limits.index.max_input_bytes, _positive_remaining(
            limits.max_total_input_bytes - budget.input_bytes + reserved, "input")))
    calculated = counted.evaluate_index_mutations(profile=profile, before_root=item.index_root,
        changes=changes, frontier=item.frontier, limits=index_limits)
    budget.hash_work(calculated.metrics.hashes)
    budget.input_work(calculated.metrics.input_bytes - reserved)
    if calculated.after_root.count > prepared.primary_after_counts[profile.table]:
        raise IndexedMutationError("indexed mutation after count exceeds its primary population descriptor")
    return calculated


def evaluate_indexed_primary_batch(
    *, table_contracts: tuple[primary.PrimaryTableContract, ...],
    business_before_roots: tuple[primary.PrimaryRoot, ...],
    authorization_before_roots: tuple[primary.PrimaryRoot, ...],
    selected_rows: tuple[dict[str, Any], ...], before_proofs: tuple[dict[str, Any], ...],
    mutations: tuple[dict[str, Any], ...], index_inputs: tuple[IndexedMutationInput, ...],
    limits: IndexedMutationLimits,
) -> IndexedMutationResult:
    """Reverify actual primary inputs and every affected fixed counted index.

    Primary-key-changing UPDATE stays forbidden by the primary engine. Explicit
    DELETE/INSERT pairs are two primary mutation events. Each profile advances
    once per such event whose old or new image is a member (even equal leaves);
    a partition move touches two paths but advances once, and two nonmembers
    advance zero. This is a proposed maintenance revision contract, not SQL
    trigger execution or an independently authenticated head vector.
    """
    limits = _copy(limits, IndexedMutationLimits)
    budget = _Budget(limits)
    # Detach every counted record before primary verification. Later caller
    # changes cannot substitute another head/frontier between the two engines.
    inputs, reservations = _inputs_snapshot(index_inputs, budget)
    verified = _verify_primary(table_contracts=table_contracts, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, selected_rows=selected_rows,
        before_proofs=before_proofs, mutations=mutations, budget=budget)
    prepared = _prepare_primary_changes(verified, tuple(item.index_id for item in inputs), budget)

    before_heads, after_heads, index_metrics = [], [], []
    projection_allowance = context_hashes = 0
    for item in inputs:
        profile, changes, delta, allowance = _prepare_index_changes(item, prepared, budget)
        context_hashes += projection.PROFILE_HASH_WORK
        projection_allowance += allowance
        # The initial frontier reservation uses exactly the low evaluator's
        # record framing. Credit it for this call only; all other frontiers
        # remain reserved while real input/work accumulate across profiles.
        reserved = reservations[item.index_id]
        calculated = _evaluate_one_index(item, prepared, profile, changes, budget, reserved)
        before_heads.append(IndexedMutationHead(item.index_id, item.index_revision, calculated.before_root))
        after_heads.append(IndexedMutationHead(item.index_id, item.index_revision + delta, calculated.after_root))
        index_metrics.append((item.index_id, calculated.metrics))
    return IndexedMutationResult(verified.result, tuple(before_heads), tuple(after_heads),
        IndexedMutationMetrics(verified.result.metrics, tuple(index_metrics), context_hashes,
                               projection_allowance, prepared.new_row_hashes, budget.input_bytes))
