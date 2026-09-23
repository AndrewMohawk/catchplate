"""Bounded counted-index SQL acquisition, relative to a supplied root.

Only source-owned complete queries select a profile and interval. Every result
passes actual counted-range reconstruction; missing records are never accepted
as absence on their own. The supplied root/revision are NOT authenticated here.
This component installs no storage, selects no head, proves no primary rows,
maintains no index and grants no planner or operation authority. Its output is
immutable observation data, not a reusable verification capability.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from serverware import authority_complete_query as complete
from serverware import authority_index_projection as projection
from serverware.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, CountedNode, IndexLeaf, IndexRangeError, KeyInterval,
    OpaqueSubtree, validate_counted_node,
)
from serverware.authority_index_frontier import MAX_OUTSIDE_PREFIXES, outside_prefixes
from serverware.authority_index_range import (
    IndexRangeLimits, IndexRangeMetrics, reconstruct_complete_index_range,
)
from serverware.authority_transition_core import canonical_bytes, framed_digest


READ_PROFILE = "serverware.policyAuthorityCountedIndexRead/v1"
LEAF_TABLE = "policy_authority_counted_index_leaves"
NODE_TABLE = "policy_authority_counted_index_nodes"
MAX_NODE_IDENTITIES = 256
MAX_SQL_READS = 1 + (MAX_OUTSIDE_PREFIXES + MAX_NODE_IDENTITIES - 1) // MAX_NODE_IDENTITIES
MAX_TRANSPORT_BYTES = 4 * 1024 * 1024
_LEAF_FIELDS = ("index_id", "projection_digest", "index_key", "primary_id",
                "primary_key_digest", "primary_row_digest", "index_revision")
_NODE_FIELDS = ("index_id", "projection_digest", "depth", "path_prefix",
                "node_digest", "subtree_count", "index_revision")


class IndexReadError(IndexRangeError):
    pass


@dataclass(frozen=True, slots=True)
class IndexReadMetrics:
    sql_reads: int
    node_reads: int
    requested_prefixes: int
    returned_rows: int
    transport_bytes: int
    context_hashes: int
    business_key_hashes: int
    range_metrics: IndexRangeMetrics

    @property
    def hashes(self) -> int:
        return self.context_hashes + self.business_key_hashes + self.range_metrics.hashes


@dataclass(frozen=True, slots=True)
class AcquiredIndexFrontier:
    query: complete.CompleteIndexQuery
    index_revision: int
    root: CountedNode
    interval: KeyInterval
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...]
    # BusinessKey/v1 digest and original primary id, in inside-leaf order.
    # Lookup material only: genuine primary membership and row join remain due.
    primary_ids: tuple[tuple[str, str], ...]
    metrics: IndexReadMetrics


def _text(value: Any, maximum: int, *, minimum: int = 1) -> str:
    if (type(value) is not str or not minimum <= len(value) <= maximum
            or "\x00" in value):
        raise IndexReadError("counted-index text is not an exact bounded string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise IndexReadError("counted-index text is not valid UTF-8") from exc
    if not minimum <= size <= maximum:
        raise IndexReadError("counted-index text exceeds its UTF-8 byte bound")
    return value


def _integer(value: Any, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise IndexReadError("counted-index integer or revision is outside its exact bound")
    return value


def _record(raw: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    # The fixed PostgreSQL dict_row driver returns exact dictionaries. Bound
    # field count before inspecting keys; do not coerce arbitrary row adapters.
    if (type(raw) is not dict or len(raw) != len(fields)
            or any(type(name) is not str or len(name) > 32 for name in raw)
            or set(raw) != set(fields)):
        raise IndexReadError("counted-index row is not a closed database record")
    return raw.copy()


def _text_sql(alias: str, name: str, lower: int, upper: int) -> str:
    # All identifiers and bounds come from literals below, never query input.
    field = f"{alias}.{name}"
    return (f"CASE WHEN pg_catalog.pg_typeof({field}) = 'pg_catalog.text'::pg_catalog.regtype "
            f"AND pg_catalog.octet_length({field}) BETWEEN {lower} AND {upper} "
            f"THEN {field} ELSE NULL END AS {name}")


def _integer_sql(alias: str, name: str, lower: int, upper: int, *, depth: bool = False) -> str:
    field = f"{alias}.{name}"
    kind = "int4" if depth else "int8"
    # Wrong catalog types become NULL, not rounded/coerced valid integers.
    # An incompatible schema may fail SQL outright; neither route is success.
    return (f"CASE WHEN pg_catalog.pg_typeof({field}) = 'pg_catalog.{kind}'::pg_catalog.regtype "
            f"AND {field} BETWEEN {lower} AND {upper} "
            f"THEN {field}::pg_catalog.int8 ELSE NULL END AS {name}")


_LEAF_SELECT = ", ".join((
    _text_sql("leaf", "index_id", 1, 128),
    _text_sql("leaf", "projection_digest", 71, 71),
    _text_sql("leaf", "index_key", KEY_NIBBLES, KEY_NIBBLES),
    _text_sql("leaf", "primary_id", 0, projection.MAX_TEXT_BYTES),
    _text_sql("leaf", "primary_key_digest", 71, 71),
    _text_sql("leaf", "primary_row_digest", 71, 71),
    _integer_sql("leaf", "index_revision", 1, I64_MAX),
))
_NODE_SELECT = ", ".join((
    _text_sql("node", "index_id", 1, 128),
    _text_sql("node", "projection_digest", 71, 71),
    _integer_sql("node", "depth", 1, KEY_NIBBLES, depth=True),
    _text_sql("node", "path_prefix", 1, KEY_NIBBLES),
    _text_sql("node", "node_digest", 71, 71),
    _integer_sql("node", "subtree_count", 1, I64_MAX),
    _integer_sql("node", "index_revision", 1, I64_MAX),
))


class _ReadBudget:
    def __init__(self, cursor: Any, trace: Any) -> None:
        self.cursor, self.trace = cursor, trace
        self.sql_reads = self.node_reads = self.returned_rows = self.transport_bytes = 0

    def read(self, table: str, key: dict[str, Any], sql: str,
             parameters: tuple[Any, ...], maximum: int) -> list[dict[str, Any]]:
        if self.sql_reads >= MAX_SQL_READS:
            raise IndexReadError("counted-index acquisition exceeds its physical read bound")
        # One trace entry for every physical SELECT, never one entry for a loop.
        # This new profile is not yet admitted by the production planner trace.
        self.trace.read(table, key)
        self.sql_reads += 1
        self.node_reads += int(table == NODE_TABLE)
        rows = self.cursor.execute(sql, parameters).fetchmany(maximum + 1)
        if type(rows) is not list or len(rows) > maximum:
            raise IndexReadError("counted-index SQL result exceeds its row bound")
        self.returned_rows += len(rows)
        return rows

    def charge(self, kind: str, row: dict[str, Any], fields: tuple[str, ...]) -> None:
        # Exact metric: UTF-8 scalar values (integers as decimal), in the fixed
        # column order, prefixed by the kind; each has an eight-byte length.
        # Call only after scalar admission. This is NOT network-wire size,
        # driver/parser memory, outbound parameters or database execution cost.
        for value in (kind, *(row[name] for name in fields)):
            encoded = (str(value) if type(value) is int else value).encode("utf-8")
            size = 8 + len(encoded)
            if size > MAX_TRANSPORT_BYTES - self.transport_bytes:
                raise IndexReadError("counted-index returned scalar bytes exceed their budget")
            self.transport_bytes += size


def _context(row: dict[str, Any], index_id: str, projection_digest: str, revision: int) -> None:
    if (_text(row["index_id"], 128) != index_id
            or _text(row["projection_digest"], 71, minimum=71) != projection_digest):
        raise IndexReadError("counted-index row crosses its source profile")
    _integer(row["index_revision"], 1, revision)


def read_complete_frontier(
    cursor: Any, *, query: complete.CompleteIndexQuery, expected_root: CountedNode,
    index_revision: int, trace: Any,
) -> AcquiredIndexFrontier:
    """Read and reconstruct one source-derived range with fixed component caps.

    No caller selects SQL identifiers, projection, interval or budgets. The
    complete-query binding to actual operation arguments/time, admitted root
    pair, whole-operation budgets and genuine primary join belong to the future
    consumer. This function deliberately does not read or invent an index head.
    Database/trace errors propagate without a result or a partial-success token.
    """
    query = complete.snapshot_query(query)
    root = validate_counted_node(expected_root)
    revision = _integer(index_revision, 0, I64_MAX)
    if revision == 0 and root.count != 0:
        raise IndexReadError("revision zero cannot describe a populated counted index")
    profile = projection.profile_for(query.index_id)
    interval = projection.query_interval(query.index_id, query.selector())
    prefixes = outside_prefixes(interval)
    maximum = query.maximum_rows
    budget = _ReadBudget(cursor, trace)
    trace_context = {
        "profile": READ_PROFILE, "queryId": query.query_id,
        "indexId": profile.index_id, "projectionDigest": profile.projection_digest,
        "indexRevision": revision, "rootDigest": root.digest, "rootCount": root.count,
    }

    # No profile/revision/syntax predicates may hide matching corrupt records.
    # A malformed matching row must become a rejecting sentinel or Python error.
    upper_sql = "" if interval.upper is None else ' AND leaf.index_key COLLATE "C" < %s'
    leaf_parameters = (profile.index_id, interval.lower)
    if interval.upper is not None:
        leaf_parameters += (interval.upper,)
    raw_leaves = budget.read(
        LEAF_TABLE, {**trace_context, "lower": interval.lower, "upper": interval.upper,
                     "limit": maximum + 1},
        f'SELECT {_LEAF_SELECT} FROM "serverware_metadata"."{LEAF_TABLE}" AS leaf '
        'WHERE leaf.index_id COLLATE "C" = %s AND leaf.index_key COLLATE "C" >= %s'
        f'{upper_sql} ORDER BY leaf.index_key COLLATE "C" LIMIT %s',
        (*leaf_parameters, maximum + 1), maximum,
    )
    leaves: list[IndexLeaf] = []
    primary_ids: list[tuple[str, str]] = []
    primary_digests: set[str] = set()
    previous = None
    for raw in raw_leaves:
        row = _record(raw, _LEAF_FIELDS)
        _context(row, profile.index_id, profile.projection_digest, revision)
        leaf = IndexLeaf(row["index_key"], row["primary_key_digest"], row["primary_row_digest"])
        primary_id = _text(row["primary_id"], projection.MAX_TEXT_BYTES, minimum=0)
        if (leaf.key < interval.lower or (interval.upper is not None and leaf.key >= interval.upper)
                or (previous is not None and leaf.key <= previous)
                or leaf.primary_key_digest in primary_digests):
            raise IndexReadError("counted-index leaves are not an ordered unique inside range")
        budget.charge("leaf", row, _LEAF_FIELDS)
        key_digest = framed_digest("serverware.policyAuthorityBusinessKey/v1",
                                   profile.table.encode("ascii"), canonical_bytes({"id": primary_id}))
        if key_digest != leaf.primary_key_digest or leaf.key[-64:] != key_digest[7:]:
            raise IndexReadError("counted-index primary lookup differs from its BusinessKey commitment")
        previous = leaf.key
        primary_digests.add(key_digest)
        leaves.append(leaf)
        primary_ids.append((key_digest, primary_id))

    opaque: list[OpaqueSubtree] = []
    for offset in range(0, len(prefixes), MAX_NODE_IDENTITIES):
        batch = prefixes[offset:offset + MAX_NODE_IDENTITIES]
        requested = {(len(prefix), prefix) for prefix in batch}
        values_sql = ", ".join("(%s::pg_catalog.int4,%s::pg_catalog.text)" for _ in batch)
        parameters = tuple(value for prefix in batch for value in (len(prefix), prefix))
        rows = budget.read(
            NODE_TABLE, {**trace_context, "prefixes": [
                {"depth": len(prefix), "pathPrefix": prefix} for prefix in batch],
                "limit": len(batch) + 1},
            f'SELECT {_NODE_SELECT} FROM "serverware_metadata"."{NODE_TABLE}" AS node '
            f'JOIN (VALUES {values_sql}) AS requested(depth, path_prefix) '
            'ON node.depth = requested.depth AND node.path_prefix COLLATE "C" = '
            'requested.path_prefix COLLATE "C" WHERE node.index_id COLLATE "C" = %s LIMIT %s',
            (*parameters, profile.index_id, len(batch) + 1), len(batch),
        )
        seen: set[tuple[int, str]] = set()
        for raw in rows:
            row = _record(raw, _NODE_FIELDS)
            _context(row, profile.index_id, profile.projection_digest, revision)
            depth = _integer(row["depth"], 1, KEY_NIBBLES)
            prefix = _text(row["path_prefix"], KEY_NIBBLES)
            identity = (depth, prefix)
            if len(prefix) != depth or identity not in requested or identity in seen:
                raise IndexReadError("counted-index node identity is unexpected or duplicated")
            node = OpaqueSubtree(prefix, row["node_digest"], row["subtree_count"])
            budget.charge("node", row, _NODE_FIELDS)
            seen.add(identity)
            opaque.append(node)

    frontier = tuple(sorted((*leaves, *opaque), key=lambda item:
                            item.key if type(item) is IndexLeaf else item.prefix))
    opened_limit = 1 + KEY_NIBBLES * maximum + 2 * KEY_NIBBLES
    observation = reconstruct_complete_index_range(
        profile=profile, expected_root=root, interval=interval, frontier=frontier,
        limits=IndexRangeLimits(max_entries=MAX_OUTSIDE_PREFIXES + maximum,
            max_leaves=maximum, max_opened_nodes=opened_limit,
            max_hashes=16 * opened_limit + maximum, max_input_bytes=MAX_TRANSPORT_BYTES),
    )
    return AcquiredIndexFrontier(
        query=query, index_revision=revision, root=observation.root, interval=observation.interval,
        frontier=frontier, primary_ids=tuple(primary_ids), metrics=IndexReadMetrics(
            sql_reads=budget.sql_reads, node_reads=budget.node_reads,
            requested_prefixes=len(prefixes), returned_rows=budget.returned_rows,
            transport_bytes=budget.transport_bytes,
            # Query snapshot:1 profile; profile_for:1; query_interval:1 profile
            # plus1 partition. No query.projection_digest property is rehashed.
            context_hashes=4, business_key_hashes=len(leaves), range_metrics=observation.metrics,
        ),
    )
