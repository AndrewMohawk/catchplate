"""Bounded counted-index SQL acquisition, relative to a supplied root.

Only source-owned complete queries select a profile and interval. Every result
passes actual counted-range reconstruction; missing records are never accepted
as absence on their own. The supplied root/revision are NOT authenticated here.
This component installs no storage, selects no head, proves no primary rows,
maintains no index and grants no planner or operation authority. Its output is
immutable observation data, not a reusable verification capability.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from typing import Any

from serverware import authority_complete_query as complete
from serverware import authority_index_projection as projection
from serverware import authority_challenge_id as challenge_ids
from serverware import authority_index_range as ranges
from serverware.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, CountedNode, IndexLeaf, IndexRangeError, KeyInterval,
    OpaqueSubtree, validate_counted_node,
)
from serverware.authority_index_frontier import MAX_OUTSIDE_PREFIXES, outside_prefixes
from serverware.authority_index_range import (
    IndexRangeLimits, IndexRangeMetrics, reconstruct_complete_index_range,
)
from serverware.authority_transition_core import canonical_bytes, framed_digest
from serverware.authority_query_read_work import _ValidationWork


READ_PROFILE = "serverware.policyAuthorityCountedIndexRead/v1"
LEAF_TABLE = "policy_authority_counted_index_leaves"
NODE_TABLE = "policy_authority_counted_index_nodes"
MAX_NODE_IDENTITIES = 256
MAX_SQL_READS = 1 + (MAX_OUTSIDE_PREFIXES + MAX_NODE_IDENTITIES - 1) // MAX_NODE_IDENTITIES
MAX_TRANSPORT_BYTES = 4 * 1024 * 1024
MAX_CUMULATIVE_SQL_READS = 4096
MAX_PARAMETER_BYTES = 4 * 1024 * 1024
MAX_PRIMARY_ROW_BYTES = 1024 * 1024
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


def _text(value: Any, maximum: int, *, minimum: int = 1,
          work: _ValidationWork | None = None) -> str:
    if (type(value) is not str or not minimum <= len(value) <= maximum
            or "\x00" in value):
        raise IndexReadError("counted-index text is not an exact bounded string")
    try:
        if work is not None:
            work.prepare_utf8(value)
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


def _record(raw: Any, fields: tuple[str, ...],
            work: _ValidationWork | None = None) -> dict[str, Any]:
    # The fixed PostgreSQL dict_row driver returns exact dictionaries. Bound
    # field count before inspecting keys; do not coerce arbitrary row adapters.
    if (type(raw) is not dict or len(raw) != len(fields)
            or any(type(name) is not str or len(name) > 32 for name in raw)
            or set(raw) != set(fields)):
        raise IndexReadError("counted-index row is not a closed database record")
    if work is not None:
        # Driver values must be bounded before the preparatory traversal/copy.
        # Semantic per-column admission below remains unchanged and stricter.
        if any(not ((type(value) is str and len(value) <= projection.MAX_TEXT_BYTES)
                    or (type(value) is int and 0 <= value <= I64_MAX)
                    or value is None) for value in raw.values()):
            raise IndexReadError("counted-index row scalar exceeds its source bound")
        work.prepare_copy(raw)
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


@dataclass(frozen=True, slots=True)
class _ReadAcquisitionLimits:
    max_sql_reads: int = MAX_CUMULATIVE_SQL_READS
    max_parameter_bytes: int = MAX_PARAMETER_BYTES
    max_transport_bytes: int = MAX_TRANSPORT_BYTES

    def __post_init__(self) -> None:
        for value, maximum in ((self.max_sql_reads, MAX_CUMULATIVE_SQL_READS),
                               (self.max_parameter_bytes, MAX_PARAMETER_BYTES),
                               (self.max_transport_bytes, MAX_TRANSPORT_BYTES)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise IndexReadError("index acquisition limit is not an exact source bound")


class _ReadAcquisitionBudget:
    """One cursor/trace/work-bound cumulative acquisition, never authority.

    Parameters and returned scalars use kind/field-order UTF-8 length frames,
    not PostgreSQL wire size. Shared work charges each actual preparatory UTF-8
    scan and encoding (2U/2 scalar nodes), plus eight bytes per length frame.
    SQL execution/driver allocation and trace's own serialization are excluded.
    An error or caught nested use permanently poisons this private instance.
    """

    def __init__(self, cursor: Any, trace: Any, *, work: _ValidationWork,
                 limits: _ReadAcquisitionLimits = _ReadAcquisitionLimits()) -> None:
        if type(work) is not _ValidationWork or type(limits) is not _ReadAcquisitionLimits:
            raise IndexReadError("index acquisition context has an unexpected exact type")
        try:
            self.limits = _ReadAcquisitionLimits(limits.max_sql_reads,
                limits.max_parameter_bytes, limits.max_transport_bytes)
        except AttributeError as exc:
            raise IndexReadError("index acquisition limits are incomplete") from exc
        self.cursor, self.trace, self.work = cursor, trace, work
        self._identity = cursor, trace, work
        self.sql_reads = self.returned_rows = self.parameter_bytes = self.transport_bytes = 0
        self.active = self.failed = False
        self._reading = False
        self._read_phase_active = False

    def require_idle(self, cursor: Any, trace: Any, work: _ValidationWork) -> None:
        """Bind an existing ledger between phases without exporting counters."""
        if (self.failed or self.active
                or any(actual is not expected for actual, expected in
                       zip((cursor, trace, work), self._identity))
                or any(actual is not expected for actual, expected in
                       zip((self.cursor, self.trace, self.work), self._identity))):
            self.failed = True
            raise IndexReadError("index acquisition context is failed, active or replaced")

    @contextmanager
    def read_phase(self, cursor: Any, trace: Any, work: _ValidationWork):
        """Own the read phase across clock and between physical callbacks.

        Physical child scopes still enter normally. A second phase entry on
        this same ledger, even while no SQL scope is active, poisons the first
        invocation and cannot be hidden by a callback catching the exception.
        """
        self.require_idle(cursor, trace, work)
        if self._read_phase_active:
            self.failed = True
            raise IndexReadError("index acquisition read phase is already active")
        self._read_phase_active = True
        try:
            yield self
            self.require_idle(cursor, trace, work)
        except BaseException:
            self.failed = True
            raise
        finally:
            self._read_phase_active = False

    @contextmanager
    def scope(self, cursor: Any, trace: Any, work: _ValidationWork):
        self.require_idle(cursor, trace, work)
        self.active = True
        try:
            yield self
            self.require_active()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.active = False

    def require_active(self) -> None:
        if (self.failed or not self.active
                or any(actual is not expected for actual, expected in
                       zip((self.cursor, self.trace, self.work), self._identity))):
            self.failed = True
            raise IndexReadError("index acquisition was poisoned or is not active")

    def _frames(self, values: tuple[Any, ...], maximum: int) -> int:
        self.require_active()
        amount = 0
        for value in values:
            if type(value) is int and 0 <= value <= I64_MAX:
                value = str(value)
            elif type(value) is not str or len(value) > projection.MAX_TEXT_BYTES:
                raise IndexReadError("index acquisition frame is not a bounded exact scalar")
            size = self.work.prepare_utf8(value)
            if 8 + size > maximum - amount:
                raise IndexReadError("index acquisition framed bytes exceed their cumulative bound")
            self.work.charge(input_bytes=8)
            encoded = value.encode("utf-8")
            self.require_active()
            if len(encoded) != size:
                raise IndexReadError("index acquisition scalar encoding changed")
            amount += 8 + size
        return amount

    def read(self, table: str, key: dict[str, Any], sql: str,
             parameters: tuple[Any, ...], maximum: int) -> list[dict[str, Any]]:
        if self._reading:
            self.failed = True
            raise IndexReadError("index acquisition physical read is already active")
        self._reading = True
        try:
            return self._read(table, key, sql, parameters, maximum)
        except BaseException:
            self.failed = True
            raise
        finally:
            self._reading = False

    def _read(self, table: str, key: dict[str, Any], sql: str,
              parameters: tuple[Any, ...], maximum: int) -> list[dict[str, Any]]:
        self.require_active()
        if self.sql_reads >= self.limits.max_sql_reads:
            raise IndexReadError("index acquisition exceeds its cumulative physical read bound")
        if (type(parameters) is not tuple or len(parameters) > 2 * MAX_NODE_IDENTITIES + 2
                or type(maximum) is not int or not 1 <= maximum <= MAX_NODE_IDENTITIES):
            raise IndexReadError("index acquisition SQL bounds are not source bounded")
        amount = self._frames(parameters, self.limits.max_parameter_bytes - self.parameter_bytes)
        self.parameter_bytes += amount
        self.trace.read(table, key)
        self.require_active()
        self.sql_reads += 1
        result = self.cursor.execute(sql, parameters)
        self.require_active()
        rows = result.fetchmany(maximum + 1)
        self.require_active()
        if type(rows) is not list or len(rows) > maximum:
            raise IndexReadError("counted-index SQL result exceeds its row bound")
        self.returned_rows += len(rows)
        return rows

    def charge(self, kind: str, row: dict[str, Any], fields: tuple[str, ...],
               *, maximum: int | None = None) -> int:
        try:
            return self._charge(kind, row, fields, maximum=maximum)
        except BaseException:
            self.failed = True
            raise

    def _charge(self, kind: str, row: dict[str, Any], fields: tuple[str, ...],
                *, maximum: int | None = None) -> int:
        self.require_active()
        remaining = self.limits.max_transport_bytes - self.transport_bytes
        if maximum is not None:
            remaining = min(remaining, maximum)
        amount = self._frames((kind, *(row[name] for name in fields)), remaining)
        self.transport_bytes += amount
        return amount

    def charge_primary_row(self, wire: bytes) -> None:
        """Charge a caller-prepared canonical full-row retention frame.

        The caller first reserves encoding on this exact work object, performs
        the canonical encoding, and then owns the row. These 8+L bytes are
        distinct from its already spent canonical
        measurement/encoding and are not a PostgreSQL network-size claim.
        No parser, decoder, re-encoder or replacement JSON graph is used here.
        """
        try:
            self._charge_primary_row(wire)
        except BaseException:
            self.failed = True
            raise

    def _charge_primary_row(self, wire: bytes) -> None:
        self.require_active()
        if type(wire) is not bytes or len(wire) > MAX_PRIMARY_ROW_BYTES:
            raise IndexReadError("primary row canonical wire exceeds its exact source bound")
        amount = 8 + len(wire)
        if amount > self.limits.max_transport_bytes - self.transport_bytes:
            raise IndexReadError("primary row frame exceeds cumulative returned transport")
        self.work.charge(input_bytes=amount)
        self.transport_bytes += amount
        self.require_active()


class _ReadBudget:
    def __init__(self, cursor: Any, trace: Any,
                 acquisition: _ReadAcquisitionBudget | None = None) -> None:
        self.cursor, self.trace = cursor, trace
        self.acquisition = acquisition
        self.sql_reads = self.node_reads = self.returned_rows = self.transport_bytes = 0

    def read(self, table: str, key: dict[str, Any], sql: str,
             parameters: tuple[Any, ...], maximum: int) -> list[dict[str, Any]]:
        if self.sql_reads >= MAX_SQL_READS:
            raise IndexReadError("counted-index acquisition exceeds its physical read bound")
        if self.acquisition is not None:
            rows = self.acquisition.read(table, key, sql, parameters, maximum)
            self.sql_reads += 1
            self.node_reads += int(table == NODE_TABLE)
            self.returned_rows += len(rows)
            return rows
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
        if self.acquisition is not None:
            self.transport_bytes += self.acquisition.charge(
                kind, row, fields, maximum=MAX_TRANSPORT_BYTES - self.transport_bytes)
            return
        for value in (kind, *(row[name] for name in fields)):
            encoded = (str(value) if type(value) is int else value).encode("utf-8")
            size = 8 + len(encoded)
            if size > MAX_TRANSPORT_BYTES - self.transport_bytes:
                raise IndexReadError("counted-index returned scalar bytes exceed their budget")
            self.transport_bytes += size


def _context(row: dict[str, Any], index_id: str, projection_digest: str, revision: int,
             work: _ValidationWork | None = None) -> None:
    if (_text(row["index_id"], 128, work=work) != index_id
            or _text(row["projection_digest"], 71, minimum=71, work=work) != projection_digest):
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
    return _read_complete_frontier(
        cursor, query=query, expected_root=expected_root, index_revision=index_revision,
        trace=trace, work=None, acquisition=None,
    )


def _profile_work(index_id: str, work: _ValidationWork) -> None:
    work.prepare_encoding(projection._definition(index_id).document(), ensure_ascii=False)
    work.charge(hashes=1)


def _query_work(query: complete.CompleteIndexQuery, work: _ValidationWork) -> None:
    if type(query) is not complete.CompleteIndexQuery:
        raise IndexReadError("counted query has an unexpected exact type")
    try:
        declared = complete._role(query.operation, query.role)
        items = query.selector_items
        if (type(items) is not tuple or len(items) != len(declared.selector_names)
                or type(query.maximum_rows) is not int
                or not 1 <= query.maximum_rows <= declared.maximum_rows):
            raise IndexReadError("counted query selector shape is invalid")
        for item, name in zip(items, declared.selector_names):
            if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                    or item[0] != name
                    or not ((type(item[1]) is str and len(item[1]) <= projection.MAX_TEXT_BYTES)
                            or (type(item[1]) is int and -(2**63) <= item[1] <= I64_MAX))):
                raise IndexReadError("counted query selector scalar is invalid")
        complete._prepare_constructor_work(declared.index_id, items, work)
    except AttributeError as exc:
        raise IndexReadError("counted query is incomplete") from exc


def _interval_work(query, profile, selector, work: _ValidationWork) -> None:
    # Actual query_interval: one selector snapshot, one source profile and one
    # source-selected partition copy/UTF-8 encoder/hash. This preparer neither
    # returns an interval nor substitutes an independently generated recipe.
    work.prepare_copy(selector)
    for value in selector.values():
        if type(value) is str:
            work.prepare_utf8(value)
    _profile_work(query.index_id, work)
    fields = {name: selector[name]
              for name in projection._definition(query.index_id).partition_fields}
    work.prepare_copy(fields)
    work.prepare_encoding(fields, ensure_ascii=False)
    for value in (projection.PARTITION_DOMAIN, projection.COUNTED_PROFILE,
                  profile.index_id, profile.table, profile.projection_digest):
        work.prepare_utf8(value)
    work.charge(hashes=1, input_bytes=8 * 6)


def _read_complete_frontier(
    cursor: Any, *, query: complete.CompleteIndexQuery, expected_root: CountedNode,
    index_revision: int, trace: Any, work: _ValidationWork | None = None,
    acquisition: _ReadAcquisitionBudget | None = None,
) -> AcquiredIndexFrontier:
    """Actual reader with optional exact shared work and acquisition identity.

    Caller must retain one acquisition/work object through all head/range
    phases. None preserves the isolated public reader. Per-range observations
    retain their old metrics; cumulative encoding work lives only on work.
    """
    if work is None and acquisition is None:
        scope = nullcontext()
    elif type(work) is _ValidationWork and type(acquisition) is _ReadAcquisitionBudget:
        scope = acquisition.scope(cursor, trace, work)
    else:
        if type(acquisition) is _ReadAcquisitionBudget:
            acquisition.failed = True
        raise IndexReadError("counted reader requires one exact shared acquisition/work pair")
    with scope:
        result = _read_complete_frontier_body(
            cursor, query=query, expected_root=expected_root, index_revision=index_revision,
            trace=trace, work=work, acquisition=acquisition,
        )
        if acquisition is not None:
            acquisition.require_active()
        return result


def _read_complete_frontier_body(
    cursor, *, query, expected_root, index_revision, trace, work, acquisition,
) -> AcquiredIndexFrontier:
    if work is not None:
        # Own the supplied root before the first constructor/profile hash.
        # Frozen caller DTOs may still be deliberately changed by a callback.
        expected_root = validate_counted_node(expected_root)
        _query_work(query, work)
    query = complete.snapshot_query(query)
    root = validate_counted_node(expected_root)
    revision = _integer(index_revision, 0, I64_MAX)
    if revision == 0 and root.count != 0:
        raise IndexReadError("revision zero cannot describe a populated counted index")
    if work is not None:
        _profile_work(query.index_id, work)
    profile = projection.profile_for(query.index_id)
    if work is not None:
        work.prepare_copy(query.selector_items)
    selector = query.selector()
    if work is not None:
        _interval_work(query, profile, selector, work)
    interval = projection.query_interval(query.index_id, selector)
    prefixes = outside_prefixes(interval)
    maximum = query.maximum_rows
    budget = _ReadBudget(cursor, trace, acquisition)
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
        row = _record(raw, _LEAF_FIELDS, work)
        _context(row, profile.index_id, profile.projection_digest, revision, work)
        leaf = IndexLeaf(row["index_key"], row["primary_key_digest"], row["primary_row_digest"])
        primary_id = _text(row["primary_id"], projection.MAX_TEXT_BYTES, minimum=0, work=work)
        if (leaf.key < interval.lower or (interval.upper is not None and leaf.key >= interval.upper)
                or (previous is not None and leaf.key <= previous)
                or leaf.primary_key_digest in primary_digests):
            raise IndexReadError("counted-index leaves are not an ordered unique inside range")
        budget.charge("leaf", row, _LEAF_FIELDS)
        if work is not None:
            work.prepare_utf8(profile.table)
            work.prepare_encoding({"id": primary_id})
            work.charge(hashes=1, input_bytes=16)
        key_digest = framed_digest("serverware.policyAuthorityBusinessKey/v1",
                                   profile.table.encode("ascii"), canonical_bytes({"id": primary_id}))
        if projection._definition(profile.index_id).order_codec.endswith(
                "/generated-challenge-id-text-order"):
            # Fresh source profiles retain the independent BusinessKey payload
            # but use the real generated ID's text order, never a hash tie.
            try:
                suffix_matches = leaf.key[-80:] == challenge_ids.order_suffix(primary_id)
            except ValueError as exc:
                raise IndexReadError("counted challenge lookup violates its fresh ID contract") from exc
        else:
            suffix_matches = leaf.key[-64:] == key_digest[7:]
        if key_digest != leaf.primary_key_digest or not suffix_matches:
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
            row = _record(raw, _NODE_FIELDS, work)
            _context(row, profile.index_id, profile.projection_digest, revision, work)
            depth = _integer(row["depth"], 1, KEY_NIBBLES)
            prefix = _text(row["path_prefix"], KEY_NIBBLES, work=work)
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
    reconstruct = (reconstruct_complete_index_range if work is None
                   else ranges._reconstruct_complete_index_range)
    observation = reconstruct(
        profile=profile, expected_root=root, interval=interval, frontier=frontier,
        limits=IndexRangeLimits(max_entries=MAX_OUTSIDE_PREFIXES + maximum,
            max_leaves=maximum, max_opened_nodes=opened_limit,
            max_hashes=16 * opened_limit + maximum, max_input_bytes=MAX_TRANSPORT_BYTES),
        **({} if work is None else {"work": work}),
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
