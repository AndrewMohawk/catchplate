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

from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from catchplate import authority_index_mutation as counted
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as transport
from catchplate import authority_indexed_mutation as indexed
from catchplate import authority_radix_mutation as primary
from catchplate.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from catchplate.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, PROFILE, IndexLeaf, IndexProfile, IndexRangeError,
    OpaqueSubtree, validate_counted_node,
)


READ_PROFILE = "catchplate.policyAuthorityCountedIndexMutationRead/v1"
MAX_IDENTITIES = 256
MAX_SQL_READS = 4096
MAX_PARAMETER_BYTES = 4 * 1024 * 1024
MAX_TRANSPORT_BYTES = 4 * 1024 * 1024
_HEAD_DOMAIN = "catchplate.policyAuthorityCountedMutationReadHeads/v1"
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
    # Shared mode exposes the real whole-invocation physical/work counters
    # here; invocation input_bytes above keeps historical writer frame units.
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


def _parameter_units(parameters: tuple[Any, ...]) -> tuple[int, int, int]:
    """Exact sizing of source-generated ASCII parameters, without encoding.

    The later real physical reader performs and charges both UTF-8 passes.
    This bounded plan arithmetic is metadata scaffolding, not another codec.
    """
    size = 0
    for value in parameters:
        if type(value) is int and 0 <= value <= I64_MAX:
            value = str(value)
        elif type(value) is not str or not value.isascii() or len(value) > KEY_NIBBLES:
            raise IndexMutationReadError("mutation parameter is not source-generated bounded ASCII")
        size += len(value)
    return 8 * len(parameters) + size, 8 * len(parameters) + 2 * size, 2 * len(parameters)


class _AcquisitionBudget:
    """Private persistent work, never a public authority or success token.

    Shared mode reuses the exact counted-read physical ledger and work object.
    Its work includes existing indexed framing/hash units, actual primary JSON
    ownership nodes, and the real transport copy/UTF-8 preparations. SQL/driver,
    projection/NEW-row canonical allocation, low hash-material encodings and
    fixed plan/DTO scaffolding are not whole-plan/process accounting.
    """

    def __init__(self, limits: _AcquisitionLimits = _AcquisitionLimits(), *,
                 shared_acquisition: transport._ReadAcquisitionBudget | None = None,
                 work: _ValidationWork | None = None) -> None:
        if type(limits) is not _AcquisitionLimits:
            raise IndexMutationReadError("mutation acquisition limits have an unexpected exact type")
        try:
            self.limits = _AcquisitionLimits(limits.max_sql_reads, limits.max_parameter_bytes,
                                             limits.max_transport_bytes)
        except AttributeError as exc:
            raise IndexMutationReadError("mutation acquisition limits are incomplete") from exc
        if ((shared_acquisition is None) != (work is None)
                or shared_acquisition is not None and (
                    type(shared_acquisition) is not transport._ReadAcquisitionBudget
                    or type(work) is not _ValidationWork or shared_acquisition.work is not work)):
            raise IndexMutationReadError("mutation shared acquisition and work must be the exact paired objects")
        self.shared_acquisition, self.work = shared_acquisition, work
        self._shared_identity = shared_acquisition, work
        self.engine: indexed._Budget | None = None
        self._sql_reads = self.leaf_reads = self.node_reads = self.returned_rows = 0
        self._parameter_bytes = self._transport_bytes = 0
        self.failed = self.active = False
        self._pending_parameters = self._proof_bytes = 0
        self._pending_work_bytes = self._pending_nodes = self._proof_hashes = 0
        self._entering_limits = self._installed_limits = None

    @property
    def sql_reads(self):
        return self._sql_reads if self.shared_acquisition is None else self.shared_acquisition.sql_reads

    @property
    def parameter_bytes(self):
        return self._parameter_bytes if self.shared_acquisition is None else self.shared_acquisition.parameter_bytes

    @property
    def transport_bytes(self):
        return self._transport_bytes if self.shared_acquisition is None else self.shared_acquisition.transport_bytes

    def remaining_reads(self):
        maximum = self.limits.max_sql_reads
        if self.shared_acquisition is not None:
            maximum = min(maximum, self.shared_acquisition.limits.max_sql_reads)
        return maximum - self.sql_reads

    def remaining_parameters(self):
        maximum = self.limits.max_parameter_bytes
        if self.shared_acquisition is not None:
            maximum = min(maximum, self.shared_acquisition.limits.max_parameter_bytes)
        return maximum - self.parameter_bytes

    def begin(self, limits: indexed.IndexedMutationLimits) -> indexed._Budget:
        if self.failed or self.active:
            raise IndexMutationReadError("mutation acquisition budget is failed or already active")
        if (self.shared_acquisition is not self._shared_identity[0]
                or self.work is not self._shared_identity[1]):
            raise IndexMutationReadError("mutation acquisition shared identity was replaced")
        if self.shared_acquisition is not None:
            self.shared_acquisition.require_active()
            self._entering_limits = self.work.limits
            self._installed_limits = self._entering_limits
        owned = indexed._copy(limits, indexed.IndexedMutationLimits)
        if self.engine is None:
            self.engine = indexed._Budget(owned, self.work)
        elif self.engine.limits != owned:
            raise IndexMutationReadError("mutation acquisition cannot replace its shared engine limits")
        if self.engine.work is not self.work:
            raise IndexMutationReadError("mutation engine work identity was replaced")
        self.active = True
        return self.engine

    def require_active(self) -> None:
        if (self.failed or not self.active
                or self.shared_acquisition is not self._shared_identity[0]
                or self.work is not self._shared_identity[1]
                or self.engine is None or self.engine.work is not self.work):
            raise IndexMutationReadError("mutation acquisition was poisoned or left its active invocation")
        if self.shared_acquisition is not None:
            self.shared_acquisition.require_active()
            if self.work.limits is not self._installed_limits:
                raise IndexMutationReadError("mutation shared reservation limits were replaced")

    def _install_hold(self) -> None:
        if self.work is None:
            return
        self.require_active()
        original = self._entering_limits
        if type(original) is not QueryReadValidationLimits:
            raise IndexMutationReadError("mutation shared reservation is incomplete")
        held = QueryReadValidationLimits(
            original.max_hashes - self._proof_hashes,
            original.max_input_bytes - self._pending_work_bytes - self._proof_bytes,
            original.max_json_nodes - self._pending_nodes)
        if (held.max_hashes < self.work.hash_work or held.max_input_bytes < self.work.input_bytes
                or held.max_json_nodes < self.work.json_nodes):
            raise IndexMutationReadError("mutation reservation exceeds actual remaining shared work")
        self.work.limits = self._installed_limits = held

    def restore_limits(self) -> None:
        # Restore only the exact entering ceiling, which may itself have an
        # outer compact-proof hold. Actual work counters are never refunded.
        original_work = self._shared_identity[1]
        if original_work is not None and self._entering_limits is not None:
            original_work.limits = self._entering_limits
            self._entering_limits = self._installed_limits = None

    def preflight(self, reads: int, parameters: int, proof_bytes: int, proof_hashes: int,
                  *, parameter_work_bytes: int = 0, parameter_nodes: int = 0) -> None:
        self.require_active()
        assert self.engine is not None
        if reads > self.remaining_reads():
            raise IndexMutationReadError("mutation acquisition exceeds its cumulative physical read bound")
        if parameters > self.remaining_parameters():
            raise IndexMutationReadError("mutation acquisition exceeds its cumulative parameter byte bound")
        if parameters + proof_bytes > self.engine.limits.max_total_input_bytes - self.engine.input_bytes:
            raise IndexMutationReadError("mutation acquisition has no room for parameters and retained proof work")
        if proof_hashes > self.engine.remaining_hashes():
            raise IndexMutationReadError("mutation acquisition has no room for both genuine sparse folds")
        self._pending_parameters, self._proof_bytes = parameters, proof_bytes
        if self.work is not None:
            if (parameter_work_bytes + proof_bytes > self.engine.remaining_input_bytes()
                    or parameter_nodes > self.engine.remaining_json_nodes()):
                raise IndexMutationReadError("mutation parameters and proof exceed shared work before SQL")
            self._pending_work_bytes, self._pending_nodes = parameter_work_bytes, parameter_nodes
            self._proof_hashes = proof_hashes
            self._install_hold()

    def read(self, cursor: Any, trace: Any, table: str, key: dict[str, Any],
             sql: str, parameters: tuple[Any, ...], maximum: int) -> list[dict[str, Any]]:
        self.require_active()
        assert self.engine is not None
        amount, work_bytes, work_nodes = _parameter_units(parameters)
        if (amount > self._pending_parameters
                or self.sql_reads >= self.limits.max_sql_reads):
            raise IndexMutationReadError("mutation SQL escaped its preflighted acquisition plan")
        self._pending_parameters -= amount
        if self.shared_acquisition is not None:
            if work_bytes > self._pending_work_bytes or work_nodes > self._pending_nodes:
                raise IndexMutationReadError("mutation SQL escaped its pending shared work reservation")
            self._pending_work_bytes -= work_bytes
            self._pending_nodes -= work_nodes
            self._install_hold()
            self.engine.input_work(amount, shared_already_charged=True)
            rows = self.shared_acquisition.read(table, key, sql, parameters, maximum)
            self.require_active()
            self.leaf_reads += int(table == transport.LEAF_TABLE)
            self.node_reads += int(table == transport.NODE_TABLE)
            self.returned_rows += len(rows)
            return rows
        self.engine.input_work(amount)
        self._parameter_bytes += amount
        # One trace record per physical SELECT. Public PlannerTrace rejects
        # this profile; only the private complete trace admits its source shape.
        trace.read(table, key)
        self.require_active()
        self._sql_reads += 1
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
        if self.shared_acquisition is not None:
            maximum = self.limits.max_transport_bytes - self.transport_bytes
            amount = self.shared_acquisition.charge(kind, row, fields, maximum=maximum)
            self.require_active()
            remaining = (self.engine.limits.max_total_input_bytes - self.engine.input_bytes
                         - self._pending_parameters - self._proof_bytes)
            if amount > remaining:
                raise IndexMutationReadError("mutation returned scalars would consume reserved local proof work")
            self.engine.input_work(amount, shared_already_charged=True)
            return
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
        self._transport_bytes += amount

    def release_proof_hold(self) -> None:
        self.require_active()
        if self._pending_parameters or self._pending_work_bytes or self._pending_nodes:
            raise IndexMutationReadError("mutation acquisition did not execute its whole preflighted plan")
        self._proof_bytes = 0
        self._proof_hashes = 0
        self._install_hold()


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
    parameter_work_bytes: int
    parameter_nodes: int
    proof_bytes: int
    proof_hashes: int


@dataclass(frozen=True, slots=True)
class _TargetGeometry:
    targets: tuple[str, ...]
    siblings: tuple[str, ...]
    opened_nodes: int
    sql_reads: int
    parameter_bytes: int
    parameter_work_bytes: int
    parameter_nodes: int


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


def _target_geometry(index_id, changes, *, limits, remaining_reads: int,
                     remaining_parameter_bytes: int, earlier_reads: int = 0,
                     earlier_parameters: int = 0) -> _TargetGeometry:
    """The actual bounded target/opened/immediate-sibling recipe.

    Internal callers first own and derive changes from genuine source images.
    This ordinary geometry is not proof authority or a caller target override.
    """
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
    if calls + earlier_reads > remaining_reads:
        raise IndexMutationReadError("mutation shape exceeds remaining physical reads before sibling allocation")
    # At least a one-digit depth and one-byte prefix, each scalar framed.
    # Reject oversized shape before building its sibling tuple or SQL values.
    minimum_parameters = 168 * len(targets) + 18 * sibling_count
    if minimum_parameters + earlier_parameters > remaining_parameter_bytes:
        raise IndexMutationReadError("mutation shape exceeds parameter bytes before sibling allocation")
    siblings = []
    identity_bytes = 168 * len(targets)
    for prefix in sorted(opened):
        for digit in _NIBBLES:
            child = prefix + digit
            if child in opened or child in target_set:
                continue
            identity_bytes += _parameter_units((len(child), child))[0]
            if identity_bytes + earlier_parameters > remaining_parameter_bytes:
                raise IndexMutationReadError("mutation sibling identities exceed remaining parameter bytes")
            siblings.append(child)
    siblings = tuple(sorted(siblings))
    if len(siblings) != sibling_count:
        raise IndexMutationReadError("mutation sibling shape is not closed")
    parameter_bytes = parameter_work_bytes = parameter_nodes = 0
    for nodes, identities in ((False, targets), (True, siblings)):
        for batch in _batches(identities):
            size, work_bytes, work_nodes = _parameter_units(_parameters(index_id, batch, nodes=nodes))
            parameter_bytes += size
            parameter_work_bytes += work_bytes
            parameter_nodes += work_nodes
    if parameter_bytes + earlier_parameters > remaining_parameter_bytes:
        raise IndexMutationReadError("mutation batch parameters exceed remaining bytes")
    return _TargetGeometry(targets, siblings, len(opened), calls, parameter_bytes,
                           parameter_work_bytes, parameter_nodes)


def _plan(item, profile, changes, delta, allowance, prepared, acquisition,
          *, earlier_reads: int, earlier_parameters: int) -> _Plan:
    assert acquisition.engine is not None
    limits = acquisition.engine.limits.index
    geometry = _target_geometry(item.index_id, changes, limits=limits,
        remaining_reads=acquisition.remaining_reads(),
        remaining_parameter_bytes=acquisition.remaining_parameters(),
        earlier_reads=earlier_reads, earlier_parameters=earlier_parameters)
    targets, siblings = geometry.targets, geometry.siblings
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
    proof_hashes = 2 * (16 * geometry.opened_nodes + len(targets))
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
                 old_ids, geometry.opened_nodes, geometry.sql_reads, geometry.parameter_bytes,
                 geometry.parameter_work_bytes, geometry.parameter_nodes, proof_bytes, proof_hashes)


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
            f'SELECT {transport._LEAF_SELECT} FROM "catchplate_metadata"."{transport.LEAF_TABLE}" AS leaf '
            f'JOIN (VALUES {values_sql}) AS requested(index_key) '
            'ON leaf.index_key COLLATE "C" = requested.index_key COLLATE "C" '
            'WHERE leaf.index_id COLLATE "C" = %s LIMIT %s',
            _parameters(item.index_id, batch, nodes=False), len(batch))
        seen: set[str] = set()
        for raw in rows:
            row = transport._record(raw, transport._LEAF_FIELDS, acquisition.work)
            transport._context(row, item.index_id, profile.projection_digest, item.index_revision, acquisition.work)
            leaf = IndexLeaf(row["index_key"], row["primary_key_digest"], row["primary_row_digest"])
            primary_id = transport._text(row["primary_id"], projection.MAX_TEXT_BYTES, minimum=0,
                                         work=acquisition.work)
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
            f'SELECT {transport._NODE_SELECT} FROM "catchplate_metadata"."{transport.NODE_TABLE}" AS node '
            f'JOIN (VALUES {values_sql}) AS requested(depth, path_prefix) '
            'ON node.depth = requested.depth AND node.path_prefix COLLATE "C" = '
            'requested.path_prefix COLLATE "C" WHERE node.index_id COLLATE "C" = %s LIMIT %s',
            _parameters(item.index_id, batch, nodes=True), len(batch))
        seen: set[tuple[int, str]] = set()
        for raw in rows:
            row = transport._record(raw, transport._NODE_FIELDS, acquisition.work)
            transport._context(row, item.index_id, profile.projection_digest, item.index_revision, acquisition.work)
            depth = transport._integer(row["depth"], 1, KEY_NIBBLES)
            prefix = transport._text(row["path_prefix"], KEY_NIBBLES, work=acquisition.work)
            identity = (depth, prefix)
            if len(prefix) != depth or identity not in requested or identity in seen:
                raise IndexMutationReadError("mutation sibling identity is unrequested or duplicated")
            record = OpaqueSubtree(prefix, row["node_digest"], row["subtree_count"])
            acquisition.charge_row("node", row, transport._NODE_FIELDS)
            seen.add(identity)
            frontier.append(record)
    return indexed.IndexedMutationInput(item.index_id, item.index_revision, item.index_root,
        tuple(sorted(frontier, key=lambda record: record.key if type(record) is IndexLeaf else record.prefix)))


def _acquire_indexed_primary_batch_body(
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
        reads = parameters = hashes = parameter_work_bytes = parameter_nodes = 0
        proof_bytes = _frames(indexed._INPUT_DOMAIN, len(heads))
        for item, profile, changes, delta, allowance in projected:
            plan = _plan(item, profile, changes, delta, allowance, prepared, acquisition,
                         earlier_reads=reads, earlier_parameters=parameters)
            plans.append(plan)
            reads += plan.sql_reads
            parameters += plan.parameter_bytes
            parameter_work_bytes += plan.parameter_work_bytes
            parameter_nodes += plan.parameter_nodes
            proof_bytes += plan.proof_bytes
            hashes += plan.proof_hashes
        acquisition.preflight(reads, parameters, proof_bytes, hashes,
            parameter_work_bytes=parameter_work_bytes, parameter_nodes=parameter_nodes)
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
            budget.hashes if acquisition.work is None else acquisition.work.hash_work,
            budget.input_bytes if acquisition.work is None else acquisition.work.input_bytes))
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
    """Run the genuine body within the optional existing physical scope."""
    if type(acquisition_budget) is not _AcquisitionBudget:
        raise IndexMutationReadError("mutation acquisition budget has an unexpected exact type")
    acquisition = acquisition_budget
    shared = acquisition._shared_identity[0]
    if acquisition.failed or acquisition.active:
        acquisition.failed = True
        if shared is not None:
            shared.failed = True
        raise IndexMutationReadError("mutation acquisition budget is failed or already active")
    try:
        scope = (nullcontext() if shared is None else
                 shared.scope(cursor, trace, acquisition._shared_identity[1]))
        with scope:
            return _acquire_indexed_primary_batch_body(cursor,
                table_contracts=table_contracts, business_before_roots=business_before_roots,
                authorization_before_roots=authorization_before_roots, selected_rows=selected_rows,
                before_proofs=before_proofs, mutations=mutations, index_before_heads=index_before_heads,
                limits=limits, trace=trace, acquisition_budget=acquisition)
    except BaseException as exc:
        acquisition.failed = True
        acquisition.active = False
        if shared is not None:
            shared.failed = True
        if isinstance(exc, IndexRangeError) and type(exc) is not IndexMutationReadError:
            raise IndexMutationReadError(str(exc)) from exc
        raise
    finally:
        acquisition.restore_limits()


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
