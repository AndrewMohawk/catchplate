"""Acquire bounded cardinality evidence from actual counted-node records.

The caller supplies a source-derived interval and separately authenticated
index head. This reader rechecks the source profile, obtains a fixed prefix
cover using guarded SQL, and reconstructs that head on the existing shared
work/acquisition ledger. No COUNT(*) result, leaf enumeration, replacement
allowance, primary-row claim or cross-table eligibility claim is accepted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from serverware import authority_index_reader as reader
from serverware import authority_index_range_count as counts
from serverware.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, CountedNode, IndexProfile, KeyInterval, OpaqueSubtree,
    validate_counted_node, validate_interval, validate_profile,
)
from serverware.authority_query_read_work import _ValidationWork


READ_PROFILE = "serverware.policyAuthorityCountedIndexCountRead/v1"
MAX_PREFIXES = 16 + 2 * 15 * (KEY_NIBBLES - 1)
MAX_OPENED_NODES = 2 * KEY_NIBBLES - 1
MAX_VISITED_SLOTS = 16 * MAX_OPENED_NODES
MAX_SQL_READS = (MAX_PREFIXES + reader.MAX_NODE_IDENTITIES - 1) // reader.MAX_NODE_IDENTITIES
_NIBBLES = "0123456789abcdef"
_TOP = 1 << (4 * KEY_NIBBLES)


@dataclass(frozen=True, slots=True)
class AcquiredIndexCount:
    """Detached relative observations; consumers must replay the raw frontier."""

    profile: IndexProfile
    index_revision: int
    root: CountedNode
    interval: KeyInterval
    frontier: tuple[OpaqueSubtree, ...]
    count: int
    metrics: reader.IndexReadMetrics


def count_prefixes(interval: KeyInterval) -> tuple[str, ...]:
    """Cover the whole keyspace with inside or outside non-root prefixes.

    Only two boundary paths can split at each depth. Unlike enumeration's
    outside cover, fully inside subtrees remain opaque count-bearing entries.
    Empty and full intervals still open the root and request all16 children.
    """
    owned = validate_interval(interval)
    lower = int(owned.lower, 16)
    upper = _TOP if owned.upper is None else int(owned.upper, 16)
    width = _TOP // 16
    pending = [(digit, ordinal * width, width)
        for ordinal, digit in reversed(tuple(enumerate(_NIBBLES)))]
    result = []
    visited = 0
    while pending:
        if visited >= MAX_VISITED_SLOTS:
            raise reader.IndexReadError("count prefix traversal exceeds its fixed source bound")
        prefix, start, size = pending.pop()
        visited += 1
        end = start + size
        covered = lower <= start and end <= upper
        intersects = lower != upper and start < upper and lower < end
        if covered or not intersects:
            if len(result) >= MAX_PREFIXES:
                raise reader.IndexReadError("count prefix cover exceeds its fixed source bound")
            result.append(prefix)
        else:
            if len(prefix) >= KEY_NIBBLES or size < 16:
                raise reader.IndexReadError("count prefix boundary cannot be subdivided")
            child_size = size // 16
            pending.extend((prefix + _NIBBLES[ordinal], start + ordinal * child_size, child_size)
                for ordinal in range(15, -1, -1))
    return tuple(result)


def acquire_count_frontier(
    cursor: Any, *, profile: IndexProfile, index_revision: int,
    expected_root: CountedNode, interval: KeyInterval, trace: Any,
    work: _ValidationWork, acquisition: reader._ReadAcquisitionBudget,
) -> AcquiredIndexCount:
    """Acquire/reconstruct once on the original cursor, trace and shared meter.

    No operation may use this result as authority. Its separately source-bound
    selector/head and the raw frontier must reach independent signed-plan
    replay. Existing public-v3 complete-query admission is not changed here.
    """
    if type(work) is not _ValidationWork or type(acquisition) is not reader._ReadAcquisitionBudget:
        if type(acquisition) is reader._ReadAcquisitionBudget:
            acquisition.failed = True
        raise reader.IndexReadError("count reader requires the original shared acquisition/work pair")
    with acquisition.scope(cursor, trace, work):
        # Detach all supplied context before source hashing or physical callbacks.
        profile = validate_profile(profile)
        root = validate_counted_node(expected_root)
        interval = validate_interval(interval)
        revision = reader._integer(index_revision, 0, I64_MAX)
        if revision == 0 and root.count != 0:
            raise reader.IndexReadError("revision zero cannot describe a populated counted index")
        reader._profile_work(profile.index_id, work)
        selected = reader.projection.profile_for(profile.index_id)
        acquisition.require_active()
        if selected != profile:
            raise reader.IndexReadError("count reader profile differs from its source definition")
        prefixes = count_prefixes(interval)
        budget = reader._ReadBudget(cursor, trace, acquisition)
        context = dict(profile=READ_PROFILE, indexId=profile.index_id,
            projectionDigest=profile.projection_digest, indexRevision=revision,
            rootDigest=root.digest, rootCount=root.count,
            lower=interval.lower, upper=interval.upper)
        frontier = []
        for offset in range(0, len(prefixes), reader.MAX_NODE_IDENTITIES):
            batch = prefixes[offset:offset + reader.MAX_NODE_IDENTITIES]
            requested = {(len(prefix), prefix) for prefix in batch}
            values_sql = ", ".join("(%s::pg_catalog.int4,%s::pg_catalog.text)" for _ in batch)
            parameters = tuple(value for prefix in batch for value in (len(prefix), prefix))
            rows = budget.read(reader.NODE_TABLE,
                {**context, "prefixes": [{"depth": len(prefix), "pathPrefix": prefix}
                    for prefix in batch], "limit": len(batch) + 1},
                f'SELECT {reader._NODE_SELECT} FROM "serverware_metadata"."{reader.NODE_TABLE}" AS node '
                f'JOIN (VALUES {values_sql}) AS requested(depth, path_prefix) '
                'ON node.depth = requested.depth AND node.path_prefix COLLATE "C" = '
                'requested.path_prefix COLLATE "C" WHERE node.index_id COLLATE "C" = %s LIMIT %s',
                (*parameters, profile.index_id, len(batch) + 1), len(batch))
            seen = set()
            for raw in rows:
                row = reader._record(raw, reader._NODE_FIELDS, work)
                reader._context(row, profile.index_id, profile.projection_digest, revision, work)
                depth = reader._integer(row["depth"], 1, KEY_NIBBLES)
                prefix = reader._text(row["path_prefix"], KEY_NIBBLES, work=work)
                identity = (depth, prefix)
                if len(prefix) != depth or identity not in requested or identity in seen:
                    raise reader.IndexReadError("count node identity is unexpected or duplicated")
                node = OpaqueSubtree(prefix, row["node_digest"], row["subtree_count"])
                budget.charge("node", row, reader._NODE_FIELDS)
                seen.add(identity)
                frontier.append(node)
        original_frontier = tuple(sorted(frontier, key=lambda node: node.prefix))
        observed = counts._reconstruct_index_range_count(profile=profile, expected_root=root,
            interval=interval, frontier=original_frontier,
            limits=reader.IndexRangeLimits(max_entries=MAX_PREFIXES, max_leaves=1,
                max_opened_nodes=MAX_OPENED_NODES, max_hashes=16 * MAX_OPENED_NODES,
                max_input_bytes=reader.MAX_TRANSPORT_BYTES), work=work)
        acquisition.require_active()
        return AcquiredIndexCount(profile=profile, index_revision=revision,
            root=observed.root, interval=observed.interval, frontier=original_frontier,
            count=observed.count, metrics=reader.IndexReadMetrics(sql_reads=budget.sql_reads,
                node_reads=budget.node_reads, requested_prefixes=len(prefixes),
                returned_rows=budget.returned_rows, transport_bytes=budget.transport_bytes,
                context_hashes=1, business_key_hashes=0, range_metrics=observed.metrics))
