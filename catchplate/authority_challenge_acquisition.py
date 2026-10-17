"""Actual held-cursor inputs for one challenge-maintenance successor phase.

SQL supplies bounded candidates, never pruning authority. Cardinality and
rank come from actual counted-node frontiers; the phase kernel independently
joins candidate primary proofs and reconstructs the selected interval. This
reader owns no transaction, clock, key, request or current-root capability.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from catchplate import authority_challenge_counts as counts
from catchplate import authority_challenge_id as challenge_ids
from catchplate import authority_challenge_maintenance as maintenance
from catchplate import authority_index_count_reader as count_reader
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate import authority_index_range as ranges
from catchplate import authority_query_reads as reads
from catchplate import authority_transition_core as core
from catchplate.authority_index_contract import (
    KEY_NIBBLES, CountedNode, IndexLeaf, KeyInterval, OpaqueSubtree,
)
from catchplate.authority_index_heads import CapturedIndexHead
from catchplate.authority_query_read_work import _ValidationWork


CANDIDATE_READ_PROFILE = "catchplate.policyAuthorityChallengeCandidateRead/v1"
PRIMARY_READ_PROFILE = "catchplate.policyAuthorityChallengePrimaryRead/v1"


@dataclass(frozen=True, slots=True)
class MaintenanceRead:
    """Actual owned raw observations, not successful admission evidence."""

    phase: str
    cutoff_us: int
    head: CapturedIndexHead
    selected_rows: tuple[dict[str, Any], ...]
    count_evidence: dict[str, Any]
    range_evidence: dict[str, Any]
    rank_evidence: dict[str, Any] | None


def _wire_frontier(frontier, work):
    raw = []
    for entry in frontier:
        if type(entry) is IndexLeaf:
            raw.append({"kind": "leaf", "key": entry.key,
                "primaryKeyDigest": entry.primary_key_digest, "primaryRowDigest": entry.primary_row_digest})
        elif type(entry) is OpaqueSubtree:
            raw.append({"kind": "opaque", "prefix": entry.prefix,
                "digest": entry.digest, "count": entry.count})
        else:
            raise reader.IndexReadError("challenge frontier has an unexpected exact record")
    return maintenance._owned({"schema": maintenance.RANGE_SCHEMA, "frontier": raw}, work)


def _head(original, work):
    value = maintenance._owned(maintenance.head_wire(original), work)
    return CapturedIndexHead(value["indexId"], value["table"], value["countedProfile"],
        value["projectionDigest"], value["projectionManifestDigest"], value["indexRevision"],
        CountedNode(value["rootDigest"], value["rootCount"]))


def _candidate_leaves(cursor, *, phase, profile, head, interval, retained_limit, trace, work, acquisition):
    descending = phase == "overflow"
    offset = retained_limit if descending else 0
    direction = "DESC" if descending else "ASC"
    context = {"profile": CANDIDATE_READ_PROFILE, "phase": phase,
        "indexId": profile.index_id, "projectionDigest": profile.projection_digest,
        "indexRevision": head.index_revision, "rootDigest": head.index_root.digest,
        "rootCount": head.index_root.count, "lower": interval.lower, "upper": interval.upper,
        "descending": descending, "offset": offset, "limit": maintenance.BATCH_SIZE}
    upper_sql = '' if interval.upper is None else ' AND leaf.index_key COLLATE "C" < %s'
    parameters = (profile.index_id, interval.lower)
    if interval.upper is not None:
        parameters += (interval.upper,)
    with acquisition.scope(cursor, trace, work):
        budget = reader._ReadBudget(cursor, trace, acquisition)
        rows = budget.read(reader.LEAF_TABLE, context,
            f'SELECT {reader._LEAF_SELECT} FROM "catchplate_metadata"."{reader.LEAF_TABLE}" AS leaf '
            'WHERE leaf.index_id COLLATE "C" = %s AND leaf.index_key COLLATE "C" >= %s'
            f'{upper_sql} ORDER BY leaf.index_key COLLATE "C" {direction} LIMIT %s OFFSET %s',
            (*parameters, maintenance.BATCH_SIZE, offset), maintenance.BATCH_SIZE)
        leaves, primary_ids, previous, seen = [], [], None, set()
        for raw in rows:
            row = reader._record(raw, reader._LEAF_FIELDS, work)
            reader._context(row, profile.index_id, profile.projection_digest, head.index_revision, work)
            leaf = IndexLeaf(row["index_key"], row["primary_key_digest"], row["primary_row_digest"])
            identity = reader._text(row["primary_id"], 71, minimum=36, work=work)
            challenge_ids.require_generated(identity)
            if (leaf.key < interval.lower or interval.upper is not None and leaf.key >= interval.upper
                    or previous is not None and (leaf.key >= previous if descending else leaf.key <= previous)
                    or leaf.primary_key_digest in seen):
                raise reader.IndexReadError("challenge candidates changed their exact source order or range")
            budget.charge("leaf", row, reader._LEAF_FIELDS)
            work.prepare_utf8(profile.table)
            work.prepare_encoding({"id": identity})
            work.charge(hashes=1, input_bytes=16)
            digest = core.framed_digest("catchplate.policyAuthorityBusinessKey/v1",
                profile.table.encode("ascii"), core.canonical_bytes({"id": identity}))
            if digest != leaf.primary_key_digest or leaf.key[-80:] != challenge_ids.order_suffix(identity):
                raise reader.IndexReadError("challenge candidate ID differs from its source key commitments")
            previous = leaf.key
            seen.add(digest)
            leaves.append(leaf)
            primary_ids.append((digest, identity))
        acquisition.require_active()
    return tuple(leaves), tuple(primary_ids)


def _primary_rows(cursor, *, phase, profile, primary_ids, trace, work, acquisition):
    selected = []
    with acquisition.scope(cursor, trace, work):
        for digest, identity in primary_ids:
            key = {"profile": PRIMARY_READ_PROFILE, "phase": phase,
                "indexId": profile.index_id, "primaryId": identity,
                "primaryKeyDigest": digest, "limit": 2}
            fetched = acquisition.read(profile.table, key,
                "SELECT CASE WHEN pg_catalog.octet_length(pg_catalog.to_jsonb(target)::pg_catalog.text) "
                f"<= {reader.MAX_PRIMARY_ROW_BYTES} THEN pg_catalog.to_jsonb(target) "
                "ELSE NULL END AS row_value FROM catchplate_metadata.webauthn_challenges AS target "
                "WHERE target.id = %s LIMIT %s", (identity, 2), 1)
            if (len(fetched) != 1 or type(fetched[0]) is not dict or set(fetched[0]) != {"row_value"}
                    or type(fetched[0]["row_value"]) is not dict
                    or fetched[0]["row_value"].get("id") != identity):
                raise reader.IndexReadError("challenge candidate lacks its exact full primary source row")
            raw = fetched[0]["row_value"]
            size, _ = work.prepare_encoding(raw)
            if size > reader.MAX_PRIMARY_ROW_BYTES:
                raise reader.IndexReadError("challenge primary source row exceeds its retained byte bound")
            wire = reads._wire(raw)
            if len(wire) != size:
                raise reader.IndexReadError("challenge primary source row changed during encoding")
            acquisition.charge_primary_row(wire)
            row = reads._CopyBudget(work).copy(raw)
            selected.append({"table": profile.table, "key": {"id": identity}, "keyDigest": digest,
                "present": True, "row": row, "contractSelector": None})
        acquisition.require_active()
    return tuple(sorted(selected, key=lambda item: (item["table"], item["keyDigest"])))


def capture_phase(cursor: Any, *, phase: str, cutoff_us: int, retention_us: int,
                  retained_limit: int, head: CapturedIndexHead, trace: Any,
                  work: _ValidationWork, acquisition: reader._ReadAcquisitionBudget) -> MaintenanceRead:
    """Read once on the original held transaction and common physical ledger.

    This does not obtain primary multiproofs: the existing real planner proof
    reader consumes the returned exact selections under that same transaction.
    Nothing may apply the rows until independent phase and root-delta replay.
    """
    if type(work) is not _ValidationWork or type(acquisition) is not reader._ReadAcquisitionBudget:
        raise reader.IndexReadError("challenge acquisition requires the original physical ledger")
    try:
        with acquisition.read_phase(cursor, trace, work):
            role = maintenance.phase_role(phase)
            maintenance._integer(retained_limit, 0, 1000000)
            head = _head(head, work)
            profile, whole = counts.source_interval(role, user_id="", cutoff_us=cutoff_us,
                rate_window_us=1, retention_us=retention_us, work=work)
            if (head.index_id != profile.index_id or head.table != profile.table
                    or head.counted_profile != projection.COUNTED_PROFILE
                    or head.projection_digest != profile.projection_digest):
                raise reader.IndexReadError("challenge acquisition head differs from its source phase")
            population = count_reader.acquire_count_frontier(cursor, profile=profile,
                index_revision=head.index_revision, expected_root=head.index_root, interval=whole,
                trace=trace, work=work, acquisition=acquisition)
            leaves, primary_ids = _candidate_leaves(cursor, phase=phase, profile=profile, head=head,
                interval=whole, retained_limit=retained_limit, trace=trace, work=work, acquisition=acquisition)
            expected = min(maintenance.BATCH_SIZE,
                max(0, population.count - retained_limit) if phase == "overflow" else population.count)
            if len(leaves) != expected:
                raise reader.IndexReadError("challenge SQL candidates differ from the actual authenticated count")
            ordered = tuple(sorted(leaves, key=lambda item: item.key))
            end = maintenance._next_key(ordered[-1].key) if ordered else whole.lower
            interval = KeyInterval(ordered[0].key if ordered and phase == "overflow" else whole.lower, end)
            # Reuse the genuine count reader for the exact candidate interval.
            # Its opaque inside records are replaced with actual candidate
            # leaves; range reconstruction must then recover the same root.
            covering = count_reader.acquire_count_frontier(cursor, profile=profile,
                index_revision=head.index_revision, expected_root=head.index_root, interval=interval,
                trace=trace, work=work, acquisition=acquisition)
            if covering.count != len(leaves):
                raise reader.IndexReadError("challenge candidates omit an actual inside member")
            outside = set(reader.outside_prefixes(interval))
            frontier = tuple(sorted((*ordered,
                *(entry for entry in covering.frontier if entry.prefix in outside)),
                key=lambda item: item.key if type(item) is IndexLeaf else item.prefix))
            opened = 1 + KEY_NIBBLES * maintenance.BATCH_SIZE + 2 * KEY_NIBBLES
            ranges._reconstruct_complete_index_range(profile=profile, expected_root=head.index_root,
                interval=interval, frontier=frontier, limits=ranges.IndexRangeLimits(
                    max_entries=reader.MAX_OUTSIDE_PREFIXES + maintenance.BATCH_SIZE,
                    max_leaves=maintenance.BATCH_SIZE, max_opened_nodes=opened,
                    max_hashes=16 * opened + maintenance.BATCH_SIZE), work=work)
            rank = None
            if phase == "overflow" and leaves:
                rank_read = count_reader.acquire_count_frontier(cursor, profile=profile,
                    index_revision=head.index_revision, expected_root=head.index_root,
                    interval=KeyInterval(end, whole.upper), trace=trace, work=work, acquisition=acquisition)
                if rank_read.count != retained_limit:
                    raise reader.IndexReadError("challenge SQL offset differs from the authenticated rank")
                rank = counts.evidence("overflow_skip_count", rank_read, work=work)
            selected = _primary_rows(cursor, phase=phase, profile=profile, primary_ids=primary_ids,
                trace=trace, work=work, acquisition=acquisition)
            return MaintenanceRead(phase, cutoff_us, head, selected,
                counts.evidence(role, population, work=work), _wire_frontier(frontier, work), rank)
    except BaseException:
        acquisition.failed = True
        raise
