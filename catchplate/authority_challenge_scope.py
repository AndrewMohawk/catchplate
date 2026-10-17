"""Exact read-only replacement inventory inside challenge maintenance.

The direct maintenance caller first prunes, then measures replacement slots,
then prunes again. It does NOT replace these rows in that transaction. An
inventory of 256 or more causes a later admission refusal but the second
pruning pass still runs with zero replacement slots. A source count proof
preserves that behavior without enumerating or truncating a larger partition.
Actual replacements remain the separate challenge creation transaction's work.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_challenge_counts as counts
from catchplate import authority_challenge_maintenance as maintenance
from catchplate import authority_challenge_retention as retention
from catchplate import authority_complete_query_batch as batch
from catchplate import authority_contract as contract
from catchplate import authority_index_range as ranges
from catchplate import authority_index_reader as reader
from catchplate import authority_radix_mutation as primary
from catchplate.authority_index_contract import KEY_NIBBLES
from catchplate.authority_query_read_work import _ValidationWork


MAX_REPLACEMENTS = contract.MAX_QUERY_PROOFS - 1


@dataclass(frozen=True, slots=True)
class ScopeObservation:
    """Fresh relative computation only; never accepted instead of originals."""

    count: int
    terminal_slots: int
    overflow: bool
    selected_rows: tuple[dict, ...]
    before_proofs: tuple[dict, ...]


def derive_scope(*, challenge_type, user_id, scope_key, replace_scope,
        primary_root, index_head, selected_rows, before_proofs,
        count_evidence, range_evidence, work):
    if type(work) is not _ValidationWork or type(replace_scope) is not bool:
        raise maintenance.ChallengeMaintenanceError("challenge scope lacks original typed request/work")
    if (type(selected_rows) is not tuple or type(before_proofs) is not tuple
            or len(selected_rows) > MAX_REPLACEMENTS or len(before_proofs) != len(selected_rows)):
        raise maintenance.ChallengeMaintenanceError("challenge scope inventory exceeds the original replacement bound")
    raw = maintenance._owned({"challengeType": challenge_type, "userId": user_id,
        "scopeKey": scope_key, "primary": primary_root, "head": maintenance.head_wire(index_head),
        "selected": list(selected_rows), "proofs": list(before_proofs),
        "count": count_evidence, "range": range_evidence}, work)
    if not replace_scope or raw["scopeKey"] is None:
        if raw["selected"] or raw["proofs"] or raw["count"] is not None or raw["range"] is not None:
            raise maintenance.ChallengeMaintenanceError("disabled scope replacement cannot carry query evidence")
        return ScopeObservation(0, 0, False, (), ())
    work.charge(hashes=contract.TREE_DEPTH + 1)
    root = maintenance._root(raw["primary"])
    profile, interval = counts.scope_interval(challenge_type=raw["challengeType"],
        user_id=raw["userId"], scope_key=raw["scopeKey"], work=work)
    head = maintenance._head(raw["head"], profile, root, work)
    count = counts._verify_interval_evidence(raw["count"], role=counts.SCOPE_ROLE,
        expected_head=head, profile=profile, interval=interval, work=work)
    if count > MAX_REPLACEMENTS:
        if raw["selected"] or raw["proofs"] or raw["range"] is not None:
            raise maintenance.ChallengeMaintenanceError("overflow scope cannot substitute a truncated replacement set")
        return ScopeObservation(count, 0, True, (), ())
    if len(raw["selected"]) != count:
        raise maintenance.ChallengeMaintenanceError("challenge scope rows differ from authenticated population")
    ledger = batch._SharedLedger(work)
    observed = primary.evaluate_primary_radix_memberships(
        table_contracts=(primary.PrimaryTableContract(retention.CHALLENGE_TABLE, ("id",), False, "business"),),
        business_before_roots=(root,), authorization_before_roots=(),
        selected_rows=tuple(raw["selected"]), before_proofs=tuple(raw["proofs"]),
        limits=batch._primary_limits(contract.operation_spec(maintenance.OPERATION), MAX_REPLACEMENTS, ledger))
    metrics = observed.result.metrics
    work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
    if observed.result.business_after_roots != (root,) or observed.result.authorization_after_roots:
        raise maintenance.ChallengeMaintenanceError("scope read-only primary proof changed roots")
    proofs = {item["keyDigest"]: item for item in observed.before_proofs}
    projected = [maintenance._project(profile, item, proofs[item["keyDigest"]], work)
                 for item in observed.selected_rows]
    projected.sort(key=lambda leaf: leaf.key)
    opened = 1 + KEY_NIBBLES * MAX_REPLACEMENTS + 2 * KEY_NIBBLES
    complete = ranges._reconstruct_complete_index_range(profile=profile, expected_root=head.index_root,
        interval=interval, frontier=maintenance._frontier(raw["range"]), limits=ranges.IndexRangeLimits(
            max_entries=reader.MAX_OUTSIDE_PREFIXES + MAX_REPLACEMENTS, max_leaves=MAX_REPLACEMENTS,
            max_opened_nodes=opened, max_hashes=16 * opened + MAX_REPLACEMENTS), work=work)
    work.prepare_comparison(
        [[leaf.key, leaf.primary_key_digest, leaf.primary_row_digest] for leaf in complete.leaves],
        [[leaf.key, leaf.primary_key_digest, leaf.primary_row_digest] for leaf in projected])
    if complete.leaves != tuple(projected):
        raise maintenance.ChallengeMaintenanceError("scope range does not exactly join its primary originals")
    slots = sum(item["row"]["retention_reference_mask"] == 0 for item in observed.selected_rows)
    return ScopeObservation(count, slots, False, observed.selected_rows, observed.before_proofs)
