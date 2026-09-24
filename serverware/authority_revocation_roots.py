"""Independent private revocation root observations on one read snapshot.

The caller owns genuine verifier role/TLS/schema and read-only transaction
admission. This worker observes source-selected rows; neither its arguments nor
its freely constructible result enroll roots, prove populations/currentness,
admit a plan, or authorize a write. No clock or planner trace is used.

Exactly two physical SELECTs share one fresh local acquisition ledger and the
caller's existing work: primary roots, then genuine counted heads. Its byte
limits are ordered scalar length frames, not PostgreSQL network allocation.
Fixed source global-manifest reconstruction/admission, fixed DTO/tuple/trace
scaffolding, driver allocation and SQL execution are explicitly outside H/B/N.
Actual scalar frames, owned row copies, counted source work and conservative
cold primary-empty hash/encoding work are charged; counters are never reset.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as batch
from serverware import authority_contract as authority
from serverware import authority_index_contract as counted
from serverware import authority_index_heads as heads
from serverware import authority_index_projection as projection
from serverware import authority_index_reader as reader
from serverware import authority_primary_contract as primary
from serverware import authority_radix_proof as radix


OPERATION = complete.OPERATION
PRIMARY_TABLE = "policy_authority_authenticated_table_roots"
PRIMARY_READ_PROFILE = "serverware.policyAuthorityRevocationPrimaryRootRead/v1"
_PRIMARY_FIELDS = ("table_name", "root_revision", "root_digest", "leaf_count",
    "tree_depth", "tree_radix", "manifest_digest", "updated_at_epoch_ns")
_PRIMARY_COUNTERS = ("root_revision", "leaf_count", "updated_at_epoch_ns")
_CONTRACTS = primary.primary_table_contracts(OPERATION)
_PRIMARY_TABLES = tuple(item.table for item in _CONTRACTS)
_BUSINESS_TABLES = tuple(item.table for item in _CONTRACTS if item.root_class == "business")
_AUTHORIZATION_TABLES = tuple(item.table for item in _CONTRACTS if item.root_class == "authorization")
_HEAD_IDS = heads.required_index_ids(OPERATION)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EMPTY_LEAF_DOMAIN = "serverware.policyAuthorityAuthenticatedEmptyLeaf/v1"
_EMPTY_NODE_DOMAIN = "serverware.policyAuthorityAuthenticatedNode/v1"

# Each SELECT sends nine exact source names and the decimal row limit 10.
_MAX_PARAMETER_BYTES = sum(8 + len(name) for name in (*_PRIMARY_TABLES, *_HEAD_IDS)) + 2 * (8 + 2)
# Each returned row has nine frames: its kind plus eight ordered scalars.
# Primary depth/radix have two digits; the other three counters permit int64.
_MAX_PRIMARY_BYTES = sum(9 * 8 + len("primary-root") + len(name) + 2 * 71 + 3 * 19 + 2 * 2
    for name in _PRIMARY_TABLES)
_MAX_HEAD_BYTES = sum(9 * 8 + len("head") + len(name) + len(projection._definition(name).table)
    + len(counted.PROFILE) + 3 * 71 + 2 * 19 for name in _HEAD_IDS)
_ROOT_LIMITS = reader._ReadAcquisitionLimits(max_sql_reads=2,
    max_parameter_bytes=_MAX_PARAMETER_BYTES,
    max_transport_bytes=_MAX_PRIMARY_BYTES + _MAX_HEAD_BYTES)
_PRIMARY_SELECT = ", ".join(
    reader._integer_sql("root", name,
        authority.TREE_DEPTH if name == "tree_depth" else authority.TREE_RADIX if name == "tree_radix" else 0,
        authority.TREE_DEPTH if name == "tree_depth" else authority.TREE_RADIX if name == "tree_radix" else counted.I64_MAX)
    if name in (*_PRIMARY_COUNTERS, "tree_depth", "tree_radix") else
    reader._text_sql("root", name, 71 if name.endswith("digest") else 1,
        71 if name.endswith("digest") else 128)
    for name in _PRIMARY_FIELDS)
_PRIMARY_SQL = (f"SELECT {_PRIMARY_SELECT} FROM serverware_metadata.{PRIMARY_TABLE} AS root "
    f"WHERE root.table_name IN ({', '.join('%s' for _ in _PRIMARY_TABLES)}) "
    'ORDER BY root.table_name COLLATE "C" LIMIT %s')


class RevocationRootReadError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _PrimaryObservation:
    table_name: str
    root_revision: int
    root_digest: str
    leaf_count: int
    tree_depth: int
    tree_radix: int
    manifest_digest: str
    updated_at_epoch_ns: int


@dataclass(frozen=True, slots=True)
class _RootInventory:
    """Owned observations only; constructing this class confers no authority."""

    business_roots: tuple[_PrimaryObservation, ...]
    authorization_roots: tuple[_PrimaryObservation, ...]
    counted_heads: tuple[heads.CapturedIndexHead, ...]


def _callback(work, function, *args, **kwargs):
    """Guard actual driver/source callbacks without any database-global binding."""
    batch._SharedLedger(work)
    limits, metrics = work.limits, work.metrics
    values = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    result = function(*args, **kwargs)
    batch._SharedLedger(work)
    if (work.limits is not limits or work.metrics != metrics
            or (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) != values):
        raise RevocationRootReadError("revocation root callback changed its shared work")
    return result


def _physical_stamp(acquisition):
    """Pin physical counters/limits across callbacks, never accept consumed metrics."""
    if type(acquisition) is not reader._ReadAcquisitionBudget:
        raise RevocationRootReadError("revocation roots require the actual acquisition ledger")
    acquisition.require_active()
    limits = acquisition.limits
    if (type(limits) is not reader._ReadAcquisitionLimits
            or any(type(value) is not int or value != expected for value, expected in zip(
                (limits.max_sql_reads, limits.max_parameter_bytes, limits.max_transport_bytes),
                (2, _MAX_PARAMETER_BYTES, _MAX_PRIMARY_BYTES + _MAX_HEAD_BYTES)))
            or any(type(value) is not int or not 0 <= value <= maximum for value, maximum in (
                (acquisition.sql_reads, 2), (acquisition.returned_rows, 18),
                (acquisition.parameter_bytes, _MAX_PARAMETER_BYTES),
                (acquisition.transport_bytes, _MAX_PRIMARY_BYTES + _MAX_HEAD_BYTES)))
            or any(type(value) is not bool for value in (acquisition.active,
                acquisition.failed, acquisition._reading, acquisition._read_phase_active))):
        raise RevocationRootReadError("revocation root physical limits or counters changed")
    return (limits, acquisition.sql_reads, acquisition.returned_rows,
        acquisition.parameter_bytes, acquisition.transport_bytes,
        acquisition.active, acquisition.failed, acquisition._reading, acquisition._read_phase_active)


def _same_physical_stamp(before, after):
    # Hold the actual original object across the callback. Neither a recycled
    # id nor equal dataclass values can conceal replacement of its limits.
    return before[0] is after[0] and before[1:] == after[1:]


class _RootResult:
    __slots__ = ("_result", "_cursor")

    def __init__(self, result, cursor):
        self._result, self._cursor = result, cursor

    def fetchone(self):
        return self._cursor._call(lambda: self._result.fetchone())

    def fetchall(self):
        return self._cursor._call(lambda: self._result.fetchall())

    def fetchmany(self, size):
        return self._cursor._call(lambda: self._result.fetchmany(size))


class _RootCursor:
    """Guard real callbacks; usable for owner admission before ledger binding."""

    __slots__ = ("_cursor", "_work", "_identity", "_acquisition")

    def __init__(self, cursor, work):
        batch._SharedLedger(work)
        self._cursor, self._work = cursor, work
        self._identity = cursor, work
        self._acquisition = None

    def _require(self):
        if (type(self._identity) is not tuple or len(self._identity) != 2
                or self._cursor is not self._identity[0] or self._work is not self._identity[1]):
            raise RevocationRootReadError("revocation root cursor identity changed")

    def _call(self, function, *args):
        acquisition = self._acquisition
        try:
            self._require()
            raw, work, identity = self._cursor, self._work, self._identity
            before = _physical_stamp(acquisition) if acquisition is not None else None
            result = _callback(work, function, *args)
            self._require()
            if (self._cursor is not raw or self._work is not work or self._identity is not identity
                    or self._acquisition is not acquisition
                    or acquisition is not None and not _same_physical_stamp(before, _physical_stamp(acquisition))):
                raise RevocationRootReadError("revocation root driver changed its physical ledger")
            return result
        except BaseException:
            if acquisition is not None:
                acquisition.failed = True
            raise

    def execute(self, sql, parameters=None):
        arguments = (sql,) if parameters is None else (sql, parameters)
        return _RootResult(self._call(lambda: self._cursor.execute(*arguments)), self)


class _RootTrace:
    """Exact two-step local acquisition trace, not a planner proof trace."""

    __slots__ = ("operation", "_work", "_phase", "_active", "_failed", "_acquisition")

    def __init__(self, work):
        batch._SharedLedger(work)
        self.operation, self._work = OPERATION, work
        self._phase, self._active, self._failed, self._acquisition = 0, False, False, None

    def _advance(self, table, key):
        if self._phase == 0:
            fields = ("profile", "tableNames", "rowLimit")
            if (type(table) is not str or table != PRIMARY_TABLE
                    or type(key) is not dict or len(key) != 3
                    or any(type(name) is not str or len(name) > 32 for name in key)
                    or set(key) != set(fields)
                    or type(key["profile"]) is not str or key["profile"] != PRIMARY_READ_PROFILE
                    or type(key["tableNames"]) is not list or len(key["tableNames"]) != 9
                    or any(type(name) is not str or not 1 <= len(name) <= 128 for name in key["tableNames"])
                    or tuple(key["tableNames"]) != _PRIMARY_TABLES
                    or type(key["rowLimit"]) is not int or key["rowLimit"] != 10):
                raise RevocationRootReadError("revocation primary root marker is not source exact")
        elif self._phase == 1:
            if type(table) is not str or table != heads.HEAD_TABLE:
                raise RevocationRootReadError("revocation counted head marker changed")
            heads.validate_head_trace_key(OPERATION, key)
        else:
            raise RevocationRootReadError("revocation root trace contains an extra read")
        self._phase += 1

    def read(self, table, key):
        acquisition = self._acquisition
        try:
            if (type(self.operation) is not str or self.operation != OPERATION
                    or self._active is not True or self._failed is not False
                    or acquisition is None or acquisition.work is not self._work):
                raise RevocationRootReadError("revocation root trace is not active and original")
            before, phase, work = _physical_stamp(acquisition), self._phase, self._work
            _callback(work, self._advance, table, key)
            if (self._acquisition is not acquisition or self._work is not work
                    or type(self.operation) is not str or self.operation != OPERATION
                    or self._active is not True or self._failed is not False
                    or type(self._phase) is not int or self._phase != phase + 1
                    or not _same_physical_stamp(before, _physical_stamp(acquisition))):
                raise RevocationRootReadError("revocation root trace changed its physical ledger")
        except BaseException:
            self._failed = True
            if acquisition is not None:
                acquisition.failed = True
            raise


def _primary_empty_root(work):
    """Prepay the real SQL-compatible cold65 ladder before its cached helper.

    Domains and decimal depths have actual UTF-8 preparation. Each branch's
    sixteen-digest list prepays measurement, the real tree JSON normalization
    copy and encoding (3L/3N), then the complete length-domain hash frame. A
    source-sized placeholder measures size only; it is never used as a root.
    Warm cache hits conservatively retain exactly the same cold reservation.
    """
    leaf_depth = str(authority.TREE_DEPTH)
    for value in (_EMPTY_LEAF_DOMAIN, leaf_depth):
        work.prepare_utf8(value)
    work.charge(hashes=1, input_bytes=16 + len(_EMPTY_LEAF_DOMAIN) + len(leaf_depth))
    children = ["sha256:" + "0" * 64] * authority.TREE_RADIX
    for depth in range(authority.TREE_DEPTH - 1, -1, -1):
        text = str(depth)
        for value in (_EMPTY_NODE_DOMAIN, text):
            work.prepare_utf8(value)
        size, _ = work.prepare_encoding(children, ensure_ascii=False, shallow_copies=1)
        work.charge(hashes=1, input_bytes=24 + len(_EMPTY_NODE_DOMAIN) + len(text) + size)
    result = _callback(work, radix.empty_digest, 0)
    if type(result) is not str or len(result) != 71 or _DIGEST.fullmatch(result) is None:
        raise RevocationRootReadError("revocation primary empty helper did not return an exact digest")
    return result


def _owned_primary_row(raw, table, manifest, empty, acquisition, work):
    if (type(raw) is not dict or len(raw) != 8
            or any(type(name) is not str or len(name) > 32 for name in raw)
            or set(raw) != set(_PRIMARY_FIELDS)):
        raise RevocationRootReadError("revocation primary root row is not closed")
    if (type(raw["table_name"]) is not str or not 1 <= len(raw["table_name"]) <= 128 or raw["table_name"] != table
            or any(type(raw[name]) is not int or not 0 <= raw[name] <= counted.I64_MAX for name in _PRIMARY_COUNTERS)
            or type(raw["tree_depth"]) is not int or raw["tree_depth"] != authority.TREE_DEPTH
            or type(raw["tree_radix"]) is not int or raw["tree_radix"] != authority.TREE_RADIX
            or any(type(raw[name]) is not str or len(raw[name]) != 71 or _DIGEST.fullmatch(raw[name]) is None
                   for name in ("root_digest", "manifest_digest"))
            or raw["manifest_digest"] != manifest
            or (raw["leaf_count"] == 0) != (raw["root_digest"] == empty)
            or raw["root_revision"] == 0 and raw["leaf_count"] != 0):
        raise RevocationRootReadError("revocation primary root scalar or source binding changed")
    acquisition.charge("primary-root", raw, _PRIMARY_FIELDS)
    work.prepare_copy(raw)
    owned = raw.copy()
    return _PrimaryObservation(*(owned[name] for name in _PRIMARY_FIELDS))


def _read_revocation_root_inventory_on_work(cursor, *, expected_query_manifest_digest, work, acquisition):
    """Read source7+2 primary roots and genuine full9 heads on existing work.

    The owner creates `_RootCursor`, `_RootTrace` and the actual acquisition
    ledger with `_ROOT_LIMITS` after its independent transaction/role admission.
    The physical ledger is fresh and single-use; prior spending on `work` is
    retained. Both primary root classes bind the GLOBAL business-query manifest,
    not the separate authorization-manifest digest. No supplied observation is
    admitted, and no full9-to-actual-write-subset projection occurs here.
    """
    trace = acquisition.trace if type(acquisition) is reader._ReadAcquisitionBudget else None
    try:
        batch._SharedLedger(work)
        if (type(cursor) is not _RootCursor or type(trace) is not _RootTrace
                or cursor._work is not work or trace._work is not work
                or cursor._acquisition is not None or trace._acquisition is not None
                or type(trace._phase) is not int or trace._phase != 0 or trace._active is not False or trace._failed is not False
                or type(expected_query_manifest_digest) is not str
                or len(expected_query_manifest_digest) != 71 or _DIGEST.fullmatch(expected_query_manifest_digest) is None
                or (len(_BUSINESS_TABLES), len(_AUTHORIZATION_TABLES), len(_HEAD_IDS)) != (7, 2, 9)
                or (authority.TREE_DEPTH, authority.TREE_RADIX) != (64, 16)):
            raise RevocationRootReadError("revocation root invocation is not source exact and unused")
        cursor._require()
        acquisition.require_idle(cursor, trace, work)
        limits = acquisition.limits
        if (type(limits) is not reader._ReadAcquisitionLimits
                or any(type(value) is not int or value != expected for value, expected in zip(
                    (limits.max_sql_reads, limits.max_parameter_bytes, limits.max_transport_bytes),
                    (2, _MAX_PARAMETER_BYTES, _MAX_PRIMARY_BYTES + _MAX_HEAD_BYTES)))):
            raise RevocationRootReadError("revocation root physical limits are not source exact")
        if any(type(value) is not int or value != 0 for value in
                (acquisition.sql_reads, acquisition.returned_rows, acquisition.parameter_bytes, acquisition.transport_bytes)):
            raise RevocationRootReadError("revocation roots cannot accept caller-consumed physical metrics")
        cursor._acquisition = trace._acquisition = acquisition
        trace._active = True
        with acquisition.read_phase(cursor, trace, work):
            # This is actual fixed source reconstruction, not an opaque expected
            # label or final-hash-only H/B/N claim. No database callback precedes it.
            manifest = _callback(work, primary.source_query_manifest_digest)
            if manifest != expected_query_manifest_digest:
                raise RevocationRootReadError("revocation global query manifest differs from its independent pin")
            empty = _primary_empty_root(work)
            with acquisition.scope(cursor, trace, work):
                _physical_stamp(acquisition)
                rows = acquisition.read(PRIMARY_TABLE,
                    {"profile": PRIMARY_READ_PROFILE, "tableNames": list(_PRIMARY_TABLES), "rowLimit": 10},
                    _PRIMARY_SQL, (*_PRIMARY_TABLES, 10), 9)
                if len(rows) != 9:
                    raise RevocationRootReadError("revocation primary root inventory is incomplete")
                owned = tuple(_owned_primary_row(raw, table, manifest, empty, acquisition, work)
                    for table, raw in zip(_PRIMARY_TABLES, rows))
            observed_heads = heads.read_operation_index_heads(cursor, operation=OPERATION,
                trace=trace, work=work, acquisition=acquisition)
            acquisition.require_idle(cursor, trace, work)
            if (type(trace.operation) is not str or trace.operation != OPERATION
                    or type(trace._phase) is not int or trace._phase != 2
                    or trace._active is not True or trace._failed is not False
                    or cursor._acquisition is not acquisition or trace._acquisition is not acquisition
                    or cursor._work is not work or trace._work is not work or acquisition.limits is not limits
                    or acquisition.sql_reads != 2 or acquisition.returned_rows != 18):
                raise RevocationRootReadError("revocation root acquisition did not complete both physical reads")
            result = _RootInventory(tuple(row for row in owned if row.table_name in _BUSINESS_TABLES),
                tuple(row for row in owned if row.table_name in _AUTHORIZATION_TABLES), observed_heads)
        batch._SharedLedger(work)
        return result
    except BaseException:
        if type(acquisition) is reader._ReadAcquisitionBudget:
            acquisition.failed = True
        if type(trace) is _RootTrace:
            trace._failed = True
        raise
    finally:
        if type(trace) is _RootTrace:
            trace._active = False
