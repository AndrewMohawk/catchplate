"""One genuine relative challenge transition, not phase or write authority.

The streaming owner invokes this computation on each original row/proof and
independently closes candidate uniqueness/order, count/range/rank and all nine
index roots. No caller-supplied mutation, successful proof result or projected
change can replace the genuine primary engine below. This module performs no
SQL, connection management, clock sampling or commit.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from serverware import authority_challenge_counts as counts
from serverware import authority_challenge_frontier_reader as frontier
from serverware import authority_challenge_maintenance as maintenance
from serverware import authority_challenge_retention as retention
from serverware import authority_complete_query_batch as batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_contract as contract
from serverware import authority_index_projection as projection
from serverware import authority_index_reader as reader
from serverware import authority_indexed_mutation as indexed
from serverware import authority_radix_mutation as primary
from serverware import authority_transition_core as core
from serverware.authority_index_contract import IndexLeaf
from serverware.authority_index_mutation import IndexLeafChange
from serverware.authority_query_read_work import _ValidationWork


_TABLE = retention.CHALLENGE_TABLE
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class ChallengeRowTransitionError(core.TransitionKernelError):
    pass


@dataclass(frozen=True, slots=True)
class _IndexChanges:
    index_id: str
    changes: tuple[IndexLeafChange, ...]
    revision_delta: int


@dataclass(frozen=True, slots=True)
class _RowComputation:
    """Private same-invocation outputs; never accepted as proof input."""

    mutation: dict
    primary_before: primary.PrimaryRoot
    primary_after: primary.PrimaryRoot
    primary_nodes: dict
    candidate_leaf: IndexLeaf
    index_changes: tuple[_IndexChanges, ...]


def _require(value):
    if not value:
        raise ChallengeRowTransitionError("challenge row transition differs from its source predicate")


def _projection_work(index_id, row, work):
    """Meter the real projector's declared scalars, never the whole payload.

    The primary evaluator has already owned and authenticated every full-row
    field. project_row itself snapshots only these source-declared primitives.
    Profile/partition work is conservatively reserved even for nonmembers;
    _changes_for_index retains the existing projection hash allowance.
    """
    definition = projection._definition(index_id)
    referenced = {name: row[name] for name, _kind in definition.row_fields}
    work.prepare_copy(referenced)
    for value in referenced.values():
        if type(value) is str:
            work.prepare_utf8(value)
    work.prepare_encoding(definition.document(), ensure_ascii=False)
    partition = {name: referenced[name] for name in definition.partition_fields if name in referenced}
    work.prepare_encoding(partition, ensure_ascii=False)


def evaluate_row(*, phase, cutoff_us, retention_us, primary_root, selected_row, before_proof, work):
    """Compute one source-derived UPDATE/DELETE on the original shared meter."""
    role = maintenance.phase_role(phase)
    maintenance._integer(cutoff_us)
    maintenance._integer(retention_us, 1)
    _require(type(work) is _ValidationWork and type(primary_root) is primary.PrimaryRoot
             and type(selected_row) is dict and type(before_proof) is dict)
    # Only one ownership traversal of the supplied graph. The genuine engine
    # later performs its own unchanged, independently metered raw admission.
    raw = maintenance._owned({"root": primary_root.json_projection(),
        "selected": selected_row, "proof": before_proof}, work)
    selected, proof = raw["selected"], raw["proof"]
    _require(set(selected) == retention._SELECTED_FIELDS and selected["table"] == _TABLE
             and selected["present"] is True and selected["contractSelector"] is None
             and type(selected["row"]) is dict
             and selected["key"] == {"id": selected["row"].get("id")})
    size, _ = work.measure(selected["row"])
    _require(size <= reader.MAX_PRIMARY_ROW_BYTES)
    retention._validate_inline(selected["row"])
    work.charge(hashes=contract.TREE_DEPTH + 1)
    before = maintenance._root(raw["root"])
    if phase == "expire":
        try:
            timestamp = (_EPOCH + timedelta(microseconds=cutoff_us)).isoformat()
        except OverflowError as exc:
            raise ChallengeRowTransitionError("challenge cutoff exceeds its source timestamp domain") from exc
        work.prepare_copy(selected["row"])
        after_row = dict(selected["row"], used_at=timestamp)
        # core.mutation makes these exact shallow key/OLD/NEW copies.
        work.prepare_copy(selected["key"])
        work.prepare_copy(selected["row"])
        work.prepare_copy(after_row)
        mutation = core.mutation(operation=maintenance.OPERATION, selected=selected, row=after_row)
    else:
        _require(selected["row"]["retention_reference_mask"] == 0)
        work.prepare_copy(selected["key"])
        work.prepare_copy(selected["row"])
        mutation = core.delete_mutation(operation=maintenance.OPERATION, selected=selected)
    retention.validate_inline_delta(operation=maintenance.OPERATION, selected_rows=(selected,),
        mutations=(mutation,), work=work)
    limits = read_write._write_limits(contract.operation_spec(maintenance.OPERATION), batch._SharedLedger(work))
    # These are restrictions of the unchanged source engine ceilings, not a
    # new allowance. _verify_primary additionally takes current remaining work.
    limits = replace(limits, primary=replace(limits.primary,
        max_selected_rows=1, max_mutations=1, max_proof_vectors=contract.TREE_DEPTH,
        max_proof_child_slots=contract.TREE_DEPTH * contract.TREE_RADIX,
        max_hashes=min(limits.primary.max_hashes, 66 + 136)))
    budget = indexed._Budget(limits, work)
    nodes = {}
    verified = indexed._verify_primary(
        table_contracts=(primary.PrimaryTableContract(_TABLE, ("id",), True, "business"),),
        business_before_roots=(before,), authorization_before_roots=(),
        selected_rows=(selected,), before_proofs=(proof,), mutations=(mutation,),
        budget=budget, captured_nodes=nodes)
    _require(len(verified.mutations) == 1 and len(verified.result.business_after_roots) == 1
             and not verified.result.authorization_after_roots)
    actual = verified.mutations[0]
    identities = projection.index_ids_for_table(_TABLE)
    _require(identities == tuple(sorted(frontier.INDEX_IDS)))
    # The existing helper hashes NEW exactly once for every affected profile.
    # Reserve its real normalized JSON graph/encoding before that helper runs.
    if actual["row"] is not None:
        wire_size, wire_nodes = work.prepare_encoding(actual["row"], ensure_ascii=False)
        work.charge(input_bytes=wire_size, json_nodes=wire_nodes)
        work.charge(input_bytes=24 + len("serverware.policyAuthorityAuthenticatedRow/v1")
                    + len(_TABLE) + wire_size)
    prepared = indexed._prepare_owned_primary_changes(mutations=verified.mutations,
        before_proofs=verified.before_proofs, business_after_roots=verified.result.business_after_roots,
        index_ids=identities, budget=budget)
    changes = []
    for identity in identities:
        for image in (actual["expectedRow"], actual["row"]):
            if image is not None:
                _projection_work(identity, image, work)
        leaves, delta, _allowance = indexed._changes_for_index(identity, prepared.by_table[_TABLE],
            prepared.old_digests, prepared.new_digests, budget)
        changes.append(_IndexChanges(identity, leaves, delta))
    profile, interval = counts.source_interval(role, user_id="", cutoff_us=cutoff_us,
        rate_window_us=1, retention_us=retention_us, work=work)
    candidates = tuple(change.before for item in changes if item.index_id == profile.index_id
        for change in item.changes if change.before is not None)
    _require(len(candidates) == 1)
    candidate = candidates[0]
    _require(interval.lower <= candidate.key and (interval.upper is None or candidate.key < interval.upper))
    return _RowComputation(actual, before, verified.result.business_after_roots[0], nodes,
                           candidate, tuple(changes))
