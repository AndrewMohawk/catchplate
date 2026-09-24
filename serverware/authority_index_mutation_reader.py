"""Acquire real sparse write evidence relative to supplied counted heads.

The genuine primary evaluator owns OLD/NEW, and the fixed projector determines
every target and affected profile. SQL reads only those target leaves and the
immediate untouched siblings of their proper ancestors. The real sparse engine
then folds BEFORE and AFTER; missing records alone never prove absence.

This installs nothing, performs no writes and does not enroll or authenticate
current heads. The new trace profile is deliberately NOT admitted by the
production planner. Component preflight is not whole-plan trace admission.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from serverware import authority_index_mutation as counted
from serverware import authority_index_projection as projection
from serverware import authority_index_reader as transport
from serverware import authority_indexed_mutation as indexed
from serverware import authority_radix_mutation as primary
from serverware.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, PROFILE, IndexLeaf, IndexProfile, IndexRangeError,
    OpaqueSubtree, validate_counted_node,
)


READ_PROFILE = "serverware.policyAuthorityCountedIndexMutationRead/v1"
MAX_IDENTITIES = 256
MAX_SQL_READS = 4096
MAX_PARAMETER_BYTES = 4 * 1024 * 1024
MAX_TRANSPORT_BYTES = 4 * 1024 * 1024
_HEAD_DOMAIN = "serverware.policyAuthorityCountedMutationReadHeads/v1"
_NIBBLES = "0123456789abcdef"


class IndexMutationReadError(IndexRangeError):
    pass


@dataclass(frozen=True, slots=True)
class IndexMutationReadMetrics:
    # Invocation deltas, not a fresh allowance for each profile.
    sql_reads: int
    leaf_reads: int
    node_reads: int
    requested_targets: int
    requested_siblings: int
    returned_rows: int
    parameter_bytes: int
    transport_bytes: int
    head_bytes: int
    acquisition_hashes: int
    hash_work: int
    input_bytes: int
    # The private composition budget retains both acquisition and engine work.
    cumulative_sql_reads: int
    cumulative_parameter_bytes: int
    cumulative_transport_bytes: int
    cumulative_hash_work: int
    cumulative_input_bytes: int


@dataclass(frozen=True, slots=True)
class AcquiredIndexedMutation:
    result: indexed.IndexedMutationResult
    index_inputs: tuple[indexed.IndexedMutationInput, ...]
    metrics: IndexMutationReadMetrics


@dataclass(frozen=True, slots=True)
class _AcquisitionLimits:
    max_sql_reads: int = MAX_SQL_READS
    max_parameter_bytes: int = MAX_PARAMETER_BYTES
    max_transport_bytes: int = MAX_TRANSPORT_BYTES

    def __post_init__(self) -> None:
        for value, maximum in (
            (self.max_sql_reads, MAX_SQL_READS),
            (self.max_parameter_bytes, MAX_PARAMETER_BYTES),
            (self.max_transport_bytes, MAX_TRANSPORT_BYTES),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise IndexMutationReadError("mutation acquisition limit is not an exact source bound")


def _frames(*values: str | int) -> int:
    # All callers first admit exact scalars. SQL parameters and heads here are
    # ASCII; returned primary_id is UTF-8. This is scalar framing, not a driver
    # wire, SQL plan, JSON allocation or network-memory metric.
    return sum(8 + len((str(value) if type(value) is int else value).encode("utf-8"))
               for value in values)


class _AcquisitionBudget:
    """Private persistent work, never a public authority or success token."""

    def __init__(self, limits: _AcquisitionLimits = _AcquisitionLimits()) -> None:
        if type(limits) is not _AcquisitionLimits:
            raise IndexMutationReadError("mutation acquisition limits have an unexpected exact type")
        try:
            self.limits = _AcquisitionLimits(limits.max_sql_reads, limits.max_parameter_bytes,
                                             limits.max_transport_bytes)
        except AttributeError as exc:
            raise IndexMutationReadError("mutation acquisition limits are incomplete") from exc
        self.engine: indexed._Budget | None = None
        self.sql_reads = self.leaf_reads = self.node_reads = self.returned_rows = 0
        self.parameter_bytes = self.transport_bytes = 0
        self.failed = self.active = False
        self._pending_parameters = self._proof_bytes = 0

    def begin(self, limits: indexed.IndexedMutationLimits) -> indexed._Budget:
        if self.failed or self.active:
            raise IndexMutationReadError("mutation acquisition budget is failed or already active")
        owned = indexed._copy(limits, indexed.IndexedMutationLimits)
        if self.engine is None:
            self.engine = indexed._Budget(owned)
        elif self.engine.limits != owned:
            raise IndexMutationReadError("mutation acquisition cannot replace its shared engine limits")
        self.active = True
        return self.engine

    def require_active(self) -> None:
        if self.failed or not self.active:
            raise IndexMutationReadError("mutation acquisition was poisoned or left its active invocation")

    def preflight(self, reads: int, parameters: int, proof_bytes: int, proof_hashes: int) -> None:
        self.require_active()
        assert self.engine is not None
        if reads > self.limits.max_sql_reads - self.sql_reads:
            raise IndexMutationReadError("mutation acquisition exceeds its cumulative physical read bound")
        if parameters > self.limits.max_parameter_bytes - self.parameter_bytes:
            raise IndexMutationReadError("mutation acquisition exceeds its cumulative parameter byte bound")
        if parameters + proof_bytes > self.engine.limits.max_total_input_bytes - self.engine.input_bytes:
            raise IndexMutationReadError("mutation acquisition has no room for parameters and retained proof work")
        if proof_hashes > self.engine.limits.max_total_hashes - self.engine.hashes:
            raise IndexMutationReadError("mutation acquisition has no room for both genuine sparse folds")
        self._pending_parameters, self._proof_bytes = parameters, proof_bytes

    def read(self, cursor: Any, trace: Any, table: str, key: dict[str, Any],
             sql: str, parameters: tuple[Any, ...], maximum: int) -> list[dict[str, Any]]:
        self.require_active()
        assert self.engine is not None
        amount = _frames(*parameters)
        if (amount > self._pending_parameters
                or self.sql_reads >= self.limits.max_sql_reads):
            raise IndexMutationReadError("mutation SQL escaped its preflighted acquisition plan")
        self._pending_parameters -= amount
        self.engine.input_work(amount)
        self.parameter_bytes += amount
        # One trace record per physical SELECT. Current PlannerTrace rejects
        # this table/profile; this standalone producer does not bypass it.
        trace.read(table, key)
        self.require_active()
        self.sql_reads += 1
        self.leaf_reads += int(table == transport.LEAF_TABLE)
        self.node_reads += int(table == transport.NODE_TABLE)
        rows = cursor.execute(sql, parameters).fetchmany(maximum + 1)
        self.require_active()
        if type(rows) is not list or len(rows) > maximum:
            raise IndexMutationReadError("mutation SQL result exceeds its exact row sentinel bound")
        self.returned_rows += len(rows)
        return rows

    def charge_row(self, kind: str, row: dict[str, Any], fields: tuple[str, ...]) -> None:
        self.require_active()
        assert self.engine is not None
        amount = _frames(kind, *(row[name] for name in fields))
        if amount > self.limits.max_transport_bytes - self.transport_bytes:
            raise IndexMutationReadError("mutation returned scalar bytes exceed their cumulative bound")
        # Future parameters and the conservative retained-proof allowance stay
        # held while SQL returns arrive. Releasing this hold never refunds any
        # spent input work, including this distinct transport framing.
        remaining = (self.engine.limits.max_total_input_bytes - self.engine.input_bytes
                     - self._pending_parameters - self._proof_bytes)
        if amount > remaining:
            raise IndexMutationReadError("mutation returned scalars would consume reserved proof work")
        self.engine.input_work(amount)
        self.transport_bytes += amount

    def release_proof_hold(self) -> None:
        self.require_active()
        if self._pending_parameters:
            raise IndexMutationReadError("mutation acquisition did not execute its whole preflighted plan")
        self._proof_bytes = 0


@dataclass(frozen=True, slots=True)
class _Plan:
    item: indexed.IndexedMutationInput
    profile: IndexProfile
    changes: tuple[counted.IndexLeafChange, ...]
    revision_delta: int
    projection_allowance: int
    targets: tuple[str, ...]
    siblings: tuple[str, ...]
    old_ids: dict[str, str]
    opened_nodes: int
    sql_reads: int
    parameter_bytes: int
    proof_bytes: int
    proof_hashes: int


def _heads_snapshot(raw: Any, budget: indexed._Budget) -> tuple[indexed.IndexedMutationInput, ...]:
    if type(raw) is not tuple or len(raw) > len(projection.INDEX_IDS):
        raise IndexMutationReadError("mutation head inventory is not an exact bounded tuple")
    budget.fields(_HEAD_DOMAIN, str(len(raw)))
    heads = []
    previous = ""
    for value in raw:
        head = indexed._copy(value, indexed.IndexedMutationHead)
        if (type(head.index_id) is not str or len(head.index_id) > 128
                or head.index_id not in projection.INDEX_IDS or head.index_id <= previous):
            raise IndexMutationReadError("mutation heads are not fixed source identities in sorted unique order")
        root = validate_counted_node(head.index_root)
        revision = transport._integer(head.index_revision, 0, I64_MAX)
        if revision == 0 and root.count:
            raise IndexMutationReadError("revision zero cannot describe a populated mutation head")
        budget.fields(head.index_id, str(revision), root.digest, str(root.count))
        heads.append(indexed.IndexedMutationInput(head.index_id, revision, root, ()))
        previous = head.index_id
    return tuple(heads)


def _batches(values):
    for offset in range(0, len(values), MAX_IDENTITIES):
        yield values[offset:offset + MAX_IDENTITIES]


def _parameters(index_id: str, batch: tuple[str, ...], *, nodes: bool) -> tuple[Any, ...]:
    identities = (tuple(value for prefix in batch for value in (len(prefix), prefix))
                  if nodes else batch)
    return (*identities, index_id, len(batch) + 1)


def _plan(item, profile, changes, delta, allowance, prepared, acquisition,
          *, earlier_reads: int, earlier_parameters: int) -> _Plan:
    assert acquisition.engine is not None
    limits = acquisition.engine.limits.index
    if len(changes) > limits.max_changes:
        raise IndexMutationReadError("mutation targets exceed the source sparse change bound")
    targets = tuple(change.key for change in changes)
    target_set = set(targets)
    opened = {""}
    for key in targets:
        for depth in range(KEY_NIBBLES):
            prefix = key[:depth]
            if prefix not in opened:
                if len(opened) >= limits.max_opened_nodes:
                    raise IndexMutationReadError("mutation acquisition exceeds the source opened-path bound")
                opened.add(prefix)
    sibling_count = 15 * len(opened) + 1 - len(targets)
    calls = ((len(targets) + MAX_IDENTITIES - 1) // MAX_IDENTITIES
             + (sibling_count + MAX_IDENTITIES - 1) // MAX_IDENTITIES)
    if calls + earlier_reads > acquisition.limits.max_sql_reads - acquisition.sql_reads:
        raise IndexMutationReadError("mutation shape exceeds remaining physical reads before sibling allocation")
    # At least a one-digit depth and one-byte prefix, each scalar framed.
    # Reject oversized shape before building its sibling tuple or SQL values.
    minimum_parameters = 168 * len(targets) + 18 * sibling_count
    if minimum_parameters + earlier_parameters > acquisition.limits.max_parameter_bytes - acquisition.parameter_bytes:
        raise IndexMutationReadError("mutation shape exceeds parameter bytes before sibling allocation")
    siblings = []
    identity_bytes = 168 * len(targets)
    for prefix in sorted(opened):
        for digit in _NIBBLES:
            child = prefix + digit
            if child in opened or child in target_set:
                continue
            identity_bytes += _frames(len(child), child)
            if identity_bytes + earlier_parameters > acquisition.limits.max_parameter_bytes - acquisition.parameter_bytes:
                raise IndexMutationReadError("mutation sibling identities exceed remaining parameter bytes")
            siblings.append(child)
    siblings = tuple(sorted(siblings))
    if len(siblings) != sibling_count:
        raise IndexMutationReadError("mutation sibling shape is not closed")
    parameter_bytes = sum(_frames(*_parameters(item.index_id, batch, nodes=nodes))
                          for nodes, identities in ((False, targets), (True, siblings))
                          for batch in _batches(identities))
    if parameter_bytes + earlier_parameters > acquisition.limits.max_parameter_bytes - acquisition.parameter_bytes:
        raise IndexMutationReadError("mutation batch parameters exceed remaining bytes")
    before = tuple(change.before for change in changes if change.before is not None)
    frontier_count = len(before) + len(siblings)
    if frontier_count > limits.max_frontier_entries:
        raise IndexMutationReadError("mutation possible frontier exceeds retained sparse record capacity")
    # Every possible positive sibling is reserved with a signed64 count. This
    # conservative headroom is not charged as actual work or a claim that all
    # independent maxima can simultaneously be reached.
    frontier_bytes = sum(_frames("leaf", leaf.key, leaf.primary_key_digest, leaf.primary_row_digest)
                         for leaf in before)
    frontier_bytes += sum(_frames("opaque", prefix, "sha256:" + "0" * 64, I64_MAX)
                          for prefix in siblings)
    sparse_bytes = _frames(counted._INPUT_DOMAIN, PROFILE, profile.index_id, profile.table,
                           profile.projection_digest, KEY_NIBBLES, item.index_root.digest,
                           item.index_root.count, len(changes), frontier_count)
    for change in changes:
        sparse_bytes += _frames("change", change.key)
        for name, leaf in (("before", change.before), ("after", change.after)):
            sparse_bytes += (_frames(name + "-absent") if leaf is None else
                             _frames(name + "-leaf", leaf.key, leaf.primary_key_digest, leaf.primary_row_digest))
    sparse_bytes += frontier_bytes
    proof_hashes = 2 * (16 * len(opened) + len(targets))
    if sparse_bytes > limits.max_input_bytes or proof_hashes > limits.max_hashes:
        raise IndexMutationReadError("mutation conservative sparse work exceeds its component budget")
    # _inputs_snapshot's descriptors plus the actual sparse frame budget;
    # frontier bytes occur once after the ordinary exact reservation credit.
    proof_bytes = sparse_bytes + _frames(item.index_id, item.index_revision,
        item.index_root.digest, item.index_root.count, frontier_count)
    old_ids = {mutation["keyDigest"]: mutation["expectedRow"]["id"]
               for mutation in prepared.by_table[profile.table]
               if mutation["expectedRow"] is not None}
    return _Plan(item, profile, changes, delta, allowance, targets, siblings,
                 old_ids, len(opened), calls, parameter_bytes, proof_bytes, proof_hashes)


def _acquire_frontier(cursor: Any, trace: Any, plan: _Plan,
                      acquisition: _AcquisitionBudget) -> indexed.IndexedMutationInput:
    item, profile = plan.item, plan.profile
    context = {
        "profile": READ_PROFILE, "indexId": item.index_id,
        "projectionDigest": profile.projection_digest,
        "indexRevision": item.index_revision, "rootDigest": item.index_root.digest,
        "rootCount": item.index_root.count,
    }
    changes = {change.key: change for change in plan.changes}
    frontier: list[IndexLeaf | OpaqueSubtree] = []
    for batch in _batches(plan.targets):
        requested = set(batch)
        values_sql = ", ".join("(%s::pg_catalog.text)" for _ in batch)
        rows = acquisition.read(cursor, trace, transport.LEAF_TABLE,
            {**context, "targets": list(batch), "limit": len(batch) + 1},
            f'SELECT {transport._LEAF_SELECT} FROM "serverware_metadata"."{transport.LEAF_TABLE}" AS leaf '
            f'JOIN (VALUES {values_sql}) AS requested(index_key) '
            'ON leaf.index_key COLLATE "C" = requested.index_key COLLATE "C" '
            'WHERE leaf.index_id COLLATE "C" = %s LIMIT %s',
            _parameters(item.index_id, batch, nodes=False), len(batch))
        seen: set[str] = set()
        for raw in rows:
            row = transport._record(raw, transport._LEAF_FIELDS)
            transport._context(row, item.index_id, profile.projection_digest, item.index_revision)
            leaf = IndexLeaf(row["index_key"], row["primary_key_digest"], row["primary_row_digest"])
            primary_id = transport._text(row["primary_id"], projection.MAX_TEXT_BYTES, minimum=0)
            if leaf.key not in requested or leaf.key in seen:
                raise IndexMutationReadError("mutation leaf identity is unrequested or duplicated")
            acquisition.charge_row("leaf", row, transport._LEAF_FIELDS)
            expected = changes[leaf.key].before
            # Actual verified OLD already binds this BusinessKey and full row.
            # Equality to its real projection and exact raw id requires no
            # additional BusinessKey hash. A new target must actually be empty.
            if (expected is None or leaf != expected
                    or primary_id != plan.old_ids[expected.primary_key_digest]):
                raise IndexMutationReadError("mutation leaf is not the genuine OLD image or target absence")
            seen.add(leaf.key)
            frontier.append(leaf)
        if seen != {key for key in batch if changes[key].before is not None}:
            raise IndexMutationReadError("mutation acquisition omitted an actual OLD leaf")

    for batch in _batches(plan.siblings):
        requested = {(len(prefix), prefix) for prefix in batch}
        values_sql = ", ".join("(%s::pg_catalog.int4,%s::pg_catalog.text)" for _ in batch)
        rows = acquisition.read(cursor, trace, transport.NODE_TABLE,
            {**context, "prefixes": [{"depth": len(prefix), "pathPrefix": prefix}
                                      for prefix in batch], "limit": len(batch) + 1},
            f'SELECT {transport._NODE_SELECT} FROM "serverware_metadata"."{transport.NODE_TABLE}" AS node '
            f'JOIN (VALUES {values_sql}) AS requested(depth, path_prefix) '
            'ON node.depth = requested.depth AND node.path_prefix COLLATE "C" = '
            'requested.path_prefix COLLATE "C" WHERE node.index_id COLLATE "C" = %s LIMIT %s',
            _parameters(item.index_id, batch, nodes=True), len(batch))
        seen: set[tuple[int, str]] = set()
        for raw in rows:
            row = transport._record(raw, transport._NODE_FIELDS)
            transport._context(row, item.index_id, profile.projection_digest, item.index_revision)
            depth = transport._integer(row["depth"], 1, KEY_NIBBLES)
            prefix = transport._text(row["path_prefix"], KEY_NIBBLES)
            identity = (depth, prefix)
            if len(prefix) != depth or identity not in requested or identity in seen:
                raise IndexMutationReadError("mutation sibling identity is unrequested or duplicated")
            record = OpaqueSubtree(prefix, row["node_digest"], row["subtree_count"])
            acquisition.charge_row("node", row, transport._NODE_FIELDS)
            seen.add(identity)
            frontier.append(record)
    return indexed.IndexedMutationInput(item.index_id, item.index_revision, item.index_root,
        tuple(sorted(frontier, key=lambda record: record.key if type(record) is IndexLeaf else record.prefix)))


def _acquire_indexed_primary_batch(
    cursor: Any, *, table_contracts: tuple[primary.PrimaryTableContract, ...],
    business_before_roots: tuple[primary.PrimaryRoot, ...],
    authorization_before_roots: tuple[primary.PrimaryRoot, ...],
    selected_rows: tuple[dict[str, Any], ...], before_proofs: tuple[dict[str, Any], ...],
    mutations: tuple[dict[str, Any], ...],
    index_before_heads: tuple[indexed.IndexedMutationHead, ...],
    limits: indexed.IndexedMutationLimits, trace: Any,
    acquisition_budget: _AcquisitionBudget,
) -> AcquiredIndexedMutation:
    """Private raw-input composition on one persistent, fail-closed ledger."""
    if type(acquisition_budget) is not _AcquisitionBudget:
        raise IndexMutationReadError("mutation acquisition budget has an unexpected exact type")
    acquisition = acquisition_budget
    try:
        budget = acquisition.begin(limits)
        start = (acquisition.sql_reads, acquisition.leaf_reads, acquisition.node_reads,
                 acquisition.returned_rows, acquisition.parameter_bytes, acquisition.transport_bytes,
                 budget.hashes, budget.input_bytes)
        # No source profile/hash callback precedes this complete head capture.
        # Primary ownership itself remains the genuine primary engine's job.
        heads = _heads_snapshot(index_before_heads, budget)
        head_bytes = budget.input_bytes - start[7]
        verified = indexed._verify_primary(table_contracts=table_contracts,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            selected_rows=selected_rows, before_proofs=before_proofs, mutations=mutations, budget=budget)
        prepared = indexed._prepare_primary_changes(verified, tuple(item.index_id for item in heads), budget)
        # Prepare every actual source projection once before any SQL. The
        # standalone public pure evaluator retains its original interleaving.
        projected = tuple((item, *indexed._prepare_index_changes(item, prepared, budget)) for item in heads)
        plans = []
        reads = parameters = hashes = 0
        proof_bytes = _frames(indexed._INPUT_DOMAIN, len(heads))
        for item, profile, changes, delta, allowance in projected:
            plan = _plan(item, profile, changes, delta, allowance, prepared, acquisition,
                         earlier_reads=reads, earlier_parameters=parameters)
            plans.append(plan)
            reads += plan.sql_reads
            parameters += plan.parameter_bytes
            proof_bytes += plan.proof_bytes
            hashes += plan.proof_hashes
        acquisition.preflight(reads, parameters, proof_bytes, hashes)
        acquired = tuple(_acquire_frontier(cursor, trace, plan, acquisition) for plan in plans)
        if acquisition.sql_reads - start[0] != reads:
            raise IndexMutationReadError("mutation acquisition physical reads differ from preflight")
        acquisition.release_proof_hold()
        # This second, actual engine snapshot retains every acquired frontier.
        # Its exact reservation is the only byte credit used by the sparse
        # evaluator; head capture, parameters and returned records remain spent.
        inputs, reservations = indexed._inputs_snapshot(acquired, budget)
        before_heads, after_heads, index_metrics = [], [], []
        for item, plan in zip(inputs, plans):
            calculated = indexed._evaluate_one_index(item, prepared, plan.profile, plan.changes,
                                                      budget, reservations[item.index_id])
            before_heads.append(indexed.IndexedMutationHead(item.index_id, item.index_revision,
                                                           calculated.before_root))
            after_heads.append(indexed.IndexedMutationHead(item.index_id,
                item.index_revision + plan.revision_delta, calculated.after_root))
            index_metrics.append((item.index_id, calculated.metrics))
        # A nested private call may have failed inside an observer even when
        # that observer swallowed the exception. Such poisoning also aborts
        # this original invocation; it must never yield a successful result.
        acquisition.require_active()
        invocation_hashes, invocation_bytes = budget.hashes - start[6], budget.input_bytes - start[7]
        result = indexed.IndexedMutationResult(verified.result, tuple(before_heads), tuple(after_heads),
            indexed.IndexedMutationMetrics(verified.result.metrics, tuple(index_metrics),
                len(plans) * projection.PROFILE_HASH_WORK,
                sum(plan.projection_allowance for plan in plans), prepared.new_row_hashes,
                invocation_bytes))
        observation = AcquiredIndexedMutation(result, inputs, IndexMutationReadMetrics(
            acquisition.sql_reads - start[0], acquisition.leaf_reads - start[1], acquisition.node_reads - start[2],
            sum(len(plan.targets) for plan in plans), sum(len(plan.siblings) for plan in plans),
            acquisition.returned_rows - start[3], acquisition.parameter_bytes - start[4],
            acquisition.transport_bytes - start[5], head_bytes, 0, invocation_hashes, invocation_bytes,
            acquisition.sql_reads, acquisition.parameter_bytes, acquisition.transport_bytes,
            budget.hashes, budget.input_bytes))
        acquisition.active = False
        return observation
    except BaseException as exc:
        acquisition.failed = True
        acquisition.active = False
        if isinstance(exc, (IndexRangeError, primary.PrimaryRadixMutationError)):
            if type(exc) is IndexMutationReadError:
                raise
            raise IndexMutationReadError(str(exc)) from exc
        # SQL/trace/driver failures abort the same collector, never a partial
        # result. Their original exception type is intentionally preserved.
        raise


def acquire_indexed_primary_batch(
    cursor: Any, *, table_contracts: tuple[primary.PrimaryTableContract, ...],
    business_before_roots: tuple[primary.PrimaryRoot, ...],
    authorization_before_roots: tuple[primary.PrimaryRoot, ...],
    selected_rows: tuple[dict[str, Any], ...], before_proofs: tuple[dict[str, Any], ...],
    mutations: tuple[dict[str, Any], ...],
    index_before_heads: tuple[indexed.IndexedMutationHead, ...],
    limits: indexed.IndexedMutationLimits, trace: Any,
) -> AcquiredIndexedMutation:
    """Acquire every affected profile and genuinely recompute both root states.

    The raw API accepts neither targets nor a successful verification result.
    Source-fixed 256-identity batches share one 4096-read/4-MiB-parameter/
    4-MiB-returned-scalar allowance across all profiles. All actual parameter
    and returned framing also consumes the same 64-MiB indexed ledger. This
    conservative preflight may reject a sparse population that would fit with
    foreknowledge of which siblings are empty; no such knowledge is assumed.

    Result input bytes include this invocation's additional acquisition work;
    pure hash metrics still describe genuine primary/projection/sparse work.
    These are observations relative to supplied heads, not operation admission,
    whole-plan trace permission, SQL execution-cost bounds or currentness.
    """
    return _acquire_indexed_primary_batch(cursor, table_contracts=table_contracts,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        selected_rows=selected_rows, before_proofs=before_proofs, mutations=mutations,
        index_before_heads=index_before_heads, limits=limits, trace=trace,
        acquisition_budget=_AcquisitionBudget())
