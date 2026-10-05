"""Exact bounded challenge-maintenance phase over genuine raw proofs.

Each phase retains the direct path's 256 candidates and timestamp/id order.
The count frontier proves cardinality without enumerating a 100000-row store;
the range frontier and independent primary proofs prove the exact candidates.
For overflow, a second authenticated count proves precisely the retained rows
skipped above the selected descending batch. No SQL COUNT, challenge-type
shortcut, or caller-produced verification result is used.

This is one relative phase, not a commit protocol or an authority capability.
The successor owner must bind the original cutoff/configuration and replay all
phases in the original order under one transaction/root chain. A phase error
rolls that transaction back; admission refusal after successful maintenance
must retain the direct caller's separate maintenance-commit semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from serverware import authority_challenge_counts as counts
from serverware import authority_challenge_retention as retention
from serverware import authority_complete_query_batch as batch
from serverware import authority_contract as contract
from serverware import authority_index_projection as projection
from serverware import authority_index_reader as reader
from serverware import authority_index_range as ranges
from serverware import authority_radix_mutation as primary
from serverware import authority_transition_core as core
from serverware.authority_index_contract import (
    KEY_NIBBLES, CountedNode, IndexLeaf, KeyInterval, OpaqueSubtree,
)
from serverware.authority_index_heads import CapturedIndexHead
from serverware.authority_query_read_work import _ValidationWork


OPERATION = "webauthn.challenge.maintain"
PHASES = ("expire", "old", "overflow")
BATCH_SIZE = 256
RANGE_SCHEMA = "serverware.policyAuthorityChallengeMaintenanceRange/v1"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ROOT_FIELDS = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})
_HEAD_FIELDS = frozenset({"indexId", "table", "countedProfile", "projectionDigest",
    "projectionManifestDigest", "indexRevision", "rootDigest", "rootCount"})


class ChallengeMaintenanceError(core.TransitionKernelError):
    pass


@dataclass(frozen=True, slots=True)
class MaintenancePhase:
    """Owned relative outputs only; callers must reverify the original proofs."""

    phase: str
    cutoff_us: int
    available: int
    selected_rows: tuple[dict[str, Any], ...]
    before_proofs: tuple[dict[str, Any], ...]
    mutations: tuple[dict[str, Any], ...]


def phase_role(phase):
    if type(phase) is not str or phase not in PHASES:
        raise ChallengeMaintenanceError("challenge maintenance phase is not source declared")
    return {"expire": "expired_remaining", "old": "old_remaining",
            "overflow": "admission_terminal_count"}[phase]


def _integer(value, lower=0, upper=2**63 - 1):
    if type(value) is not int or not lower <= value <= upper:
        raise ChallengeMaintenanceError("challenge maintenance parameter is not an exact integer")
    return value


def _owned(value, work):
    # A full original 256-row phase already carries 16384 sixteen-child
    # primary vectors.  Encoding/decoding that graph merely to detach it
    # would consume four copies before any proof was checked.  Reuse the
    # existing exact JSON ownership traversal instead; it charges every
    # retained node/byte on the same meter without a hidden JSON round trip.
    return batch._JSONCapture(batch._SharedLedger(work)).visit(value)


def _next_key(key):
    successor = int(key, 16) + 1
    return None if successor == 1 << (4 * KEY_NIBBLES) else f"{successor:0{KEY_NIBBLES}x}"


def _root(value):
    if type(value) is not dict or set(value) != _ROOT_FIELDS:
        raise ChallengeMaintenanceError("challenge maintenance primary root is not closed")
    if value["table"] != retention.CHALLENGE_TABLE:
        raise ChallengeMaintenanceError("challenge maintenance primary root names a different source")
    return primary.PrimaryRoot(value["table"], value["rootRevision"], value["rootDigest"], value["leafCount"])


def head_wire(head):
    if type(head) is not CapturedIndexHead or type(head.index_root) is not CountedNode:
        raise ChallengeMaintenanceError("challenge maintenance head is not the exact observation")
    return {"indexId": head.index_id, "table": head.table,
        "countedProfile": head.counted_profile, "projectionDigest": head.projection_digest,
        "projectionManifestDigest": head.projection_manifest_digest,
        "indexRevision": head.index_revision, "rootDigest": head.index_root.digest,
        "rootCount": head.index_root.count}


def _head(value, profile, primary_root, work):
    if type(value) is not dict or set(value) != _HEAD_FIELDS:
        raise ChallengeMaintenanceError("challenge maintenance head is not source closed")
    # An independent owner supplies currentness. Here even freely constructed
    # exact dataclasses must match the source profile and original root pair.
    manifest = [definition.document() for definition in projection._DEFINITIONS]
    work.prepare_encoding(manifest, ensure_ascii=False)
    work.charge(hashes=1)
    if (value["indexId"] != profile.index_id or value["table"] != retention.CHALLENGE_TABLE
            or value["countedProfile"] != projection.COUNTED_PROFILE
            or value["projectionDigest"] != profile.projection_digest
            or value["projectionManifestDigest"] != projection.projection_manifest_digest()):
        raise ChallengeMaintenanceError("challenge maintenance head differs from its source profile")
    revision = _integer(value["indexRevision"])
    root = CountedNode(value["rootDigest"], value["rootCount"])
    if root.count > primary_root.leaf_count or (revision == 0 and root.count != 0):
        raise ChallengeMaintenanceError("challenge maintenance index exceeds its primary population")
    return CapturedIndexHead(profile.index_id, profile.table, projection.COUNTED_PROFILE,
        profile.projection_digest, value["projectionManifestDigest"], revision, root)


def _frontier(raw):
    if type(raw) is not dict or set(raw) != {"schema", "frontier"} or raw["schema"] != RANGE_SCHEMA:
        raise ChallengeMaintenanceError("challenge maintenance range evidence is not source closed")
    entries = raw["frontier"]
    if type(entries) is not list or len(entries) > reader.MAX_OUTSIDE_PREFIXES + BATCH_SIZE:
        raise ChallengeMaintenanceError("challenge maintenance range exceeds its original phase bound")
    result, leaves, opaque = [], 0, 0
    for entry in entries:
        if type(entry) is not dict:
            raise ChallengeMaintenanceError("challenge maintenance frontier record is not closed")
        if set(entry) == {"kind", "key", "primaryKeyDigest", "primaryRowDigest"} and entry["kind"] == "leaf":
            leaves += 1
            result.append(IndexLeaf(entry["key"], entry["primaryKeyDigest"], entry["primaryRowDigest"]))
        elif set(entry) == {"kind", "prefix", "digest", "count"} and entry["kind"] == "opaque":
            opaque += 1
            result.append(OpaqueSubtree(entry["prefix"], entry["digest"], entry["count"]))
        else:
            raise ChallengeMaintenanceError("challenge maintenance frontier record is not source declared")
    if leaves > BATCH_SIZE or opaque > reader.MAX_OUTSIDE_PREFIXES:
        raise ChallengeMaintenanceError("challenge maintenance frontier exceeds its phase inventory")
    return tuple(result)


def _project(profile, selected, proof, work):
    row = selected["row"]
    if (selected["table"] != retention.CHALLENGE_TABLE or selected["present"] is not True
            or selected["contractSelector"] is not None or type(row) is not dict
            or selected["key"] != {"id": row.get("id")}):
        raise ChallengeMaintenanceError("challenge maintenance candidate is not a full present primary row")
    work.prepare_scan(row)
    retention._validate_inline(row)
    # The source projector copies only its declared scalar subset; charging
    # the full engine-owned row is conservative, not a replacement projection.
    work.prepare_copy(row)
    work.charge(hashes=projection.ROW_HASH_WORK)
    leaf = projection.project_row(profile.index_id, row,
        primary_key_digest=selected["keyDigest"], primary_row_digest=proof["rowDigest"])
    if leaf is None:
        raise ChallengeMaintenanceError("challenge maintenance candidate is outside the actual index")
    return leaf


def _close_selection(*, phase, retained_limit, available, profile, whole, head,
                     projected, range_evidence, rank_evidence, work):
    """Private complete-selection closure over this owner's actual row folds.

    The aggregate path derives these leaves from one genuine primary batch.
    The compound path derives them from its source-fixed raw one-row folds,
    retaining only immutable leaf commitments rather than256 full1MiB rows.
    Neither public verifier accepts caller-produced membership observations.
    The unchanged whole-range engine and authenticated descending rank below
    still determine the exact original batch, including timestamp/ID ties.
    """
    expected = min(BATCH_SIZE, max(0, available - retained_limit) if phase == "overflow" else available)
    if (type(projected) is not tuple or len(projected) != expected
            or any(type(leaf) is not IndexLeaf for leaf in projected)
            or tuple(sorted(projected, key=lambda leaf: leaf.key)) != projected
            or len({leaf.key for leaf in projected}) != len(projected)
            or (phase != "overflow" or not expected) and rank_evidence is not None):
        raise ChallengeMaintenanceError("challenge candidate leaves do not close the original phase inventory")
    if expected:
        first, last = projected[0].key, projected[-1].key
        end = _next_key(last)
        interval = KeyInterval(first if phase == "overflow" else whole.lower, end)
        if (first < whole.lower or (whole.upper is not None and
                (end is None or end > whole.upper))):
            raise ChallengeMaintenanceError("challenge maintenance candidates escaped the source predicate")
        if phase == "overflow":
            skipped = counts._verify_interval_evidence(rank_evidence, role="overflow_skip_count",
                expected_head=head, profile=profile, interval=KeyInterval(end, whole.upper), work=work)
            if skipped != retained_limit:
                raise ChallengeMaintenanceError("challenge overflow skipped rank differs from configured retention")
    else:
        interval = KeyInterval(whole.lower, whole.lower)
    frontier = _frontier(range_evidence)
    opened = 1 + KEY_NIBBLES * BATCH_SIZE + 2 * KEY_NIBBLES
    observed = ranges._reconstruct_complete_index_range(profile=profile, expected_root=head.index_root,
        interval=interval, frontier=frontier, limits=ranges.IndexRangeLimits(
            max_entries=reader.MAX_OUTSIDE_PREFIXES + BATCH_SIZE, max_leaves=BATCH_SIZE,
            max_opened_nodes=opened, max_hashes=16 * opened + BATCH_SIZE), work=work)
    work.prepare_comparison(
        [[item.key, item.primary_key_digest, item.primary_row_digest] for item in observed.leaves],
        [[item.key, item.primary_key_digest, item.primary_row_digest] for item in projected])
    if observed.leaves != projected:
        raise ChallengeMaintenanceError("challenge maintenance range does not bijectively join primary originals")


def derive_phase(*, phase: str, cutoff_us: int, retention_us: int, retained_limit: int,
                 primary_root: dict[str, Any], index_head: CapturedIndexHead,
                 selected_rows: tuple[dict[str, Any], ...], before_proofs: tuple[dict[str, Any], ...],
                 count_evidence: dict[str, Any], range_evidence: dict[str, Any],
                 rank_evidence: dict[str, Any] | None, work: _ValidationWork) -> MaintenancePhase:
    """Recompute one exact legacy batch from primary/range/cardinality inputs.

    The supplied original cutoff and configured retained bound are not trusted
    merely because this routine accepts them. The enclosing successor binds
    them to its signed request/configuration, holds the transaction lock, and
    independently invokes this routine from the raw plan during execution.
    """
    role = phase_role(phase)
    if type(work) is not _ValidationWork:
        raise ChallengeMaintenanceError("challenge maintenance requires its original shared meter")
    _integer(cutoff_us)
    _integer(retention_us, 1)
    _integer(retained_limit, 0, 1000000)
    if (type(selected_rows) is not tuple or len(selected_rows) > BATCH_SIZE
            or type(before_proofs) is not tuple or len(before_proofs) != len(selected_rows)
            or (phase != "overflow" and rank_evidence is not None)):
        raise ChallengeMaintenanceError("challenge maintenance primary/rank inventory changed")
    # Detach every caller graph before the first profile/root/hash operation.
    raw = _owned({"primary": primary_root, "head": head_wire(index_head),
        "selected": list(selected_rows), "proofs": list(before_proofs),
        "count": count_evidence, "range": range_evidence, "rank": rank_evidence}, work)
    return _derive_owned(phase=phase, cutoff_us=cutoff_us, retention_us=retention_us,
        retained_limit=retained_limit, raw=raw, work=work)


def _derive_owned(*, phase, cutoff_us, retention_us, retained_limit, raw, work):
    """Private composition over the enclosing verifier's already owned graph.

    The plan composer uses this function after its one complete ownership
    traversal, so the original proof vectors are not copied a second time.
    No public successful-membership result is accepted: the genuine primary
    and counted proof engines still run below on the retained raw evidence.
    """
    role = phase_role(phase)
    if type(work) is not _ValidationWork:
        raise ChallengeMaintenanceError("challenge maintenance requires its original shared meter")
    _integer(cutoff_us)
    _integer(retention_us, 1)
    _integer(retained_limit, 0, 1000000)
    if (type(raw) is not dict or set(raw) != {
            "primary", "head", "selected", "proofs", "count", "range", "rank"}
            or type(raw["selected"]) is not list or len(raw["selected"]) > BATCH_SIZE
            or type(raw["proofs"]) is not list or len(raw["proofs"]) != len(raw["selected"])
            or phase != "overflow" and raw["rank"] is not None):
        raise ChallengeMaintenanceError("challenge maintenance owned inventory changed")
    # PrimaryRoot reconstructs the actual cold empty-hash ladder.
    work.charge(hashes=contract.TREE_DEPTH + 1)
    root = _root(raw["primary"])
    profile, whole = counts.source_interval(role, user_id="", cutoff_us=cutoff_us,
        rate_window_us=1, retention_us=retention_us, work=work)
    head = _head(raw["head"], profile, root, work)
    available = counts._verify_interval_evidence(raw["count"], role=role, expected_head=head,
        profile=profile, interval=whole, work=work)
    expected = min(BATCH_SIZE, max(0, available - retained_limit) if phase == "overflow" else available)
    if len(raw["selected"]) != expected:
        raise ChallengeMaintenanceError("challenge maintenance candidate count differs from authenticated population")
    if expected == 0 and raw["rank"] is not None:
        raise ChallengeMaintenanceError("empty challenge maintenance cannot carry a rank boundary")
    ledger = batch._SharedLedger(work)
    memberships = primary.evaluate_primary_radix_memberships(
        table_contracts=(primary.PrimaryTableContract(retention.CHALLENGE_TABLE, ("id",), False, "business"),),
        business_before_roots=(root,), authorization_before_roots=(),
        selected_rows=tuple(raw["selected"]), before_proofs=tuple(raw["proofs"]),
        limits=batch._primary_limits(contract.operation_spec(OPERATION), BATCH_SIZE, ledger))
    metrics = memberships.result.metrics
    work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
    if memberships.result.business_after_roots != (root,) or memberships.result.authorization_after_roots:
        raise ChallengeMaintenanceError("challenge maintenance read-only primary evaluation changed roots")
    proofs = {entry["keyDigest"]: entry for entry in memberships.before_proofs}
    projected = [_project(profile, item, proofs[item["keyDigest"]], work)
                 for item in memberships.selected_rows]
    projected.sort(key=lambda leaf: leaf.key)
    _close_selection(phase=phase, retained_limit=retained_limit, available=available,
        profile=profile, whole=whole, head=head, projected=tuple(projected),
        range_evidence=raw["range"], rank_evidence=raw["rank"], work=work)
    try:
        now = (_EPOCH + timedelta(microseconds=cutoff_us)).isoformat()
    except OverflowError as exc:
        raise ChallengeMaintenanceError("challenge maintenance cutoff exceeds the source timestamp domain") from exc
    mutations = []
    for item in memberships.selected_rows:
        if phase == "expire":
            work.prepare_copy(item["row"])
            row = dict(item["row"])
            row["used_at"] = now
            mutations.append(core.mutation(operation=OPERATION, selected=item, row=row))
        else:
            if item["row"]["retention_reference_mask"] != 0:
                raise ChallengeMaintenanceError("challenge maintenance attempted to delete a referenced challenge")
            mutations.append(core.delete_mutation(operation=OPERATION, selected=item))
    result = tuple(sorted(mutations, key=lambda item: (item["table"], item["keyDigest"], item["operation"])))
    retention.validate_inline_delta(operation=OPERATION, selected_rows=memberships.selected_rows,
        mutations=result, work=work)
    return MaintenancePhase(phase, cutoff_us, available, memberships.selected_rows,
                            memberships.before_proofs, result)
