"""Complete root observations inside an independently admitted transaction.

The caller supplies an already open PostgreSQL 16 SERIALIZABLE transaction,
its actual raw connection and original work. This module creates one cursor,
not a connection, transaction, clock, timeout or replacement allowance. TLS,
database identity, role/ACL, statement deadlines and outer lifecycle admission
remain the configured caller's responsibility.

Two complete inventory SELECTs are bracketed by three fixed transaction-state
SELECTs. The actual backend virtual transaction identity works for read-only
transactions without allocating a permanent XID. Its continuity and inherited
settings are checked; this is not protection against a hostile database/driver.
Unknown, missing or duplicate root rows fail rather than becoming defaults.

Every variable returned scalar/copy and real vector computation spends the
same work. Physical limits describe ordered scalar frames, not native driver
allocation or PostgreSQL execution cost. Returned canonical vector bytes are
unsigned observations, never population, enrollment, currentness, independent
provenance, a reservation, or permission to execute.
"""
from __future__ import annotations

import re

from serverware import authority_current_root_vector as vector
from serverware import authority_revocation_root_reader as connection_reader


roots = vector.roots
heads, reader = roots.heads, roots.reader
PRIMARY_TABLES, INDEX_IDS = vector.PRIMARY_TABLES, vector.INDEX_IDS
_PRIMARY_PROFILE = "serverware.policyAuthorityCompletePrimaryRootRead/v1"
_TRANSACTION_PROFILE = "serverware.policyAuthorityCompleteRootTransactionRead/v1"
_TRANSACTION_TABLE = "pg_catalog.pg_locks"
_TRANSACTION_FIELDS = ("server_version_num", "backend_pid", "virtual_transaction",
    "transaction_isolation", "transaction_read_only", "transaction_deferrable",
    "statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout")
_VIRTUAL_TRANSACTION = re.compile(r"[1-9][0-9]{0,9}/[1-9][0-9]{0,19}\Z")
_TRANSACTION_SQL = (
    "SELECT pg_catalog.current_setting('server_version_num')::integer AS server_version_num, "
    "pg_catalog.pg_backend_pid() AS backend_pid, held.virtualtransaction AS virtual_transaction, "
    "pg_catalog.current_setting('transaction_isolation') AS transaction_isolation, "
    "pg_catalog.current_setting('transaction_read_only') AS transaction_read_only, "
    "pg_catalog.current_setting('transaction_deferrable') AS transaction_deferrable, "
    "pg_catalog.current_setting('statement_timeout') AS statement_timeout, "
    "pg_catalog.current_setting('lock_timeout') AS lock_timeout, "
    "pg_catalog.current_setting('idle_in_transaction_session_timeout') "
    "AS idle_in_transaction_session_timeout "
    "FROM pg_catalog.pg_locks AS held "
    "WHERE held.pid = pg_catalog.pg_backend_pid() AND held.locktype = 'virtualxid' "
    "AND held.mode = 'ExclusiveLock' AND held.granted "
    "AND held.virtualxid = held.virtualtransaction LIMIT 2"
)
_PRIMARY_SQL = (f"SELECT {roots._PRIMARY_SELECT} "
    f"FROM serverware_metadata.{roots.PRIMARY_TABLE} AS root "
    'ORDER BY root.table_name COLLATE "C" LIMIT %s')
_HEAD_SQL = (f"SELECT {heads._HEAD_SELECT} "
    f"FROM serverware_metadata.{heads.HEAD_TABLE} AS head "
    'ORDER BY head.index_id COLLATE "C" LIMIT %s')
_PARAMETER_BYTES = sum(8 + len(str(len(names) + 1)) for names in (PRIMARY_TABLES, INDEX_IDS))
_PRIMARY_BYTES = sum(9 * 8 + len("primary-root") + len(name) + 2 * 71 + 3 * 19 + 4
    for name in PRIMARY_TABLES)
_HEAD_BYTES = sum(9 * 8 + len("head") + len(identity)
    + len(vector.projection._definition(identity).table) + len(vector.counted.PROFILE)
    + 3 * 71 + 2 * 19 for identity in INDEX_IDS)
_TRANSACTION_BYTES = 10 * 8 + len("transaction") + 6 + 10 + 31 + 12 + 2 * 3 + 3 * 64
_LIMITS = reader._ReadAcquisitionLimits(max_sql_reads=5,
    max_parameter_bytes=_PARAMETER_BYTES,
    max_transport_bytes=_PRIMARY_BYTES + _HEAD_BYTES + 3 * _TRANSACTION_BYTES)


class CurrentRootObservationError(ValueError):
    pass


class _Trace:
    """One fixed admission/primary/continuity/head/continuity sequence."""

    __slots__ = ("phase",)

    def __init__(self):
        self.phase = 0

    def read(self, table, key):
        phase = self.phase
        if type(phase) is not int or not 0 <= phase < 5:
            raise CurrentRootObservationError("complete root trace exceeded its fixed reads")
        if phase in (0, 2, 4):
            expected_table, expected = _TRANSACTION_TABLE, {"profile": _TRANSACTION_PROFILE, "rowLimit": 2}
        else:
            names, field, expected_table, profile = ((PRIMARY_TABLES, "tableNames", roots.PRIMARY_TABLE,
                _PRIMARY_PROFILE) if phase == 1 else (INDEX_IDS, "indexIds", heads.HEAD_TABLE, heads.READ_PROFILE))
            expected = {"profile": profile, field: list(names), "rowLimit": len(names) + 1}
        if type(table) is not str or table != expected_table or type(key) is not dict or key != expected:
            raise CurrentRootObservationError("complete root physical marker changed")
        self.phase = phase + 1


class _Cursor:
    """Hold physical connection and acquisition state across every callback."""

    __slots__ = ("binding", "acquisition")

    def __init__(self, cursor, connection, physical, work):
        self.binding = cursor, connection, physical, work
        self.acquisition = None

    def _stamp(self):
        acquisition = self.acquisition
        if type(acquisition) is not reader._ReadAcquisitionBudget:
            raise CurrentRootObservationError("complete root acquisition is not actual")
        acquisition.require_active()
        limits, trace = acquisition.limits, acquisition.trace
        if (acquisition.cursor is not self or acquisition.work is not self.binding[3]
                or type(trace) is not _Trace or type(trace.phase) is not int or not 1 <= trace.phase <= 5
                or type(limits) is not reader._ReadAcquisitionLimits
                or (limits.max_sql_reads, limits.max_parameter_bytes, limits.max_transport_bytes)
                    != (_LIMITS.max_sql_reads, _LIMITS.max_parameter_bytes, _LIMITS.max_transport_bytes)
                or acquisition._read_phase_active is not True):
            raise CurrentRootObservationError("complete root acquisition binding changed")
        counters = (acquisition.sql_reads, acquisition.returned_rows,
            acquisition.parameter_bytes, acquisition.transport_bytes)
        maxima = (5, len(PRIMARY_TABLES) + len(INDEX_IDS) + 3,
            _PARAMETER_BYTES, _LIMITS.max_transport_bytes)
        if any(type(value) is not int or not 0 <= value <= maximum for value, maximum in zip(counters, maxima)):
            raise CurrentRootObservationError("complete root acquisition counters changed")
        flags = acquisition.active, acquisition.failed, acquisition._reading, acquisition._read_phase_active
        if any(type(value) is not bool for value in flags):
            raise CurrentRootObservationError("complete root acquisition flags changed")
        return (limits, acquisition._identity, trace, counters, flags, trace.phase)

    def _call(self, callback):
        binding, acquisition = self.binding, self.acquisition
        if type(binding) is not tuple or len(binding) != 4:
            raise CurrentRootObservationError("complete root cursor binding is invalid")
        _, connection, physical, work = binding
        before = self._stamp()

        def invoke():
            connection_reader._require_connection(connection, physical, 2)
            try:
                return callback()
            finally:
                connection_reader._require_connection(connection, physical, 2)

        try:
            return roots._callback(work, invoke)
        finally:
            if self.binding is not binding or self.acquisition is not acquisition:
                raise CurrentRootObservationError("complete root callback replaced its cursor binding")
            after = self._stamp()
            if (any(before[index] is not after[index] for index in range(3)) or before[3:] != after[3:]):
                raise CurrentRootObservationError("complete root callback changed its acquisition")

    def execute(self, sql, parameters):
        return roots._RootResult(self._call(lambda: self.binding[0].execute(sql, parameters)), self)


def _transaction(acquisition, work):
    rows = acquisition.read(_TRANSACTION_TABLE,
        {"profile": _TRANSACTION_PROFILE, "rowLimit": 2}, _TRANSACTION_SQL, (), 1)
    if len(rows) != 1:
        raise CurrentRootObservationError("complete root transaction identity is absent or ambiguous")
    row = rows[0]
    if (type(row) is not dict or len(row) != len(_TRANSACTION_FIELDS)
            or any(type(name) is not str or len(name) > 64 for name in row)
            or set(row) != set(_TRANSACTION_FIELDS)):
        raise CurrentRootObservationError("complete root transaction observation is not closed")
    for field in _TRANSACTION_FIELDS:
        value = row[field]
        if field in ("server_version_num", "backend_pid"):
            if type(value) is not int or not 1 <= value <= 2147483647:
                raise CurrentRootObservationError("complete root transaction integer is invalid")
        elif type(value) is not str or not 1 <= len(value) <= 64 or not value.isascii() or "\x00" in value:
            raise CurrentRootObservationError("complete root transaction scalar is invalid")
    if (not 160000 <= row["server_version_num"] < 170000
            or _VIRTUAL_TRANSACTION.fullmatch(row["virtual_transaction"]) is None
            or row["transaction_isolation"] != "serializable"
            or row["transaction_read_only"] not in ("on", "off")
            or row["transaction_deferrable"] not in ("on", "off")):
        raise CurrentRootObservationError("complete root caller transaction is not admitted PostgreSQL 16 SERIALIZABLE")
    acquisition.charge("transaction", row, _TRANSACTION_FIELDS)
    work.prepare_copy(row)
    return tuple(row[field] for field in _TRANSACTION_FIELDS)


def _observe_on_work(connection, *, work):
    """Return canonical full vector bytes on the caller's existing raw transaction.

    No caller-selected inventory, supplied roots, opener or admission callback is
    accepted. The caller must admit the database/TLS/role/ACL and retain its
    outer transaction. This function never commits, rolls back or closes it.
    """
    vector.capture._SharedLedger(work)
    physical = roots._callback(work, connection_reader._connection_identity, connection, 2)
    bindings = vector._source_bindings_on_work(work=work)
    empty = roots._primary_empty_root(work)
    manager = roots._callback(work, connection.cursor)
    with connection_reader._context(manager, work) as raw_cursor:
        cursor, trace = _Cursor(raw_cursor, connection, physical, work), _Trace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work, limits=_LIMITS)
        cursor.acquisition = acquisition
        with acquisition.read_phase(cursor, trace, work):
            with acquisition.scope(cursor, trace, work):
                original = _transaction(acquisition, work)
                primary_rows = acquisition.read(roots.PRIMARY_TABLE,
                    {"profile": _PRIMARY_PROFILE, "tableNames": list(PRIMARY_TABLES), "rowLimit": len(PRIMARY_TABLES) + 1},
                    _PRIMARY_SQL, (len(PRIMARY_TABLES) + 1,), len(PRIMARY_TABLES))
                if len(primary_rows) != len(PRIMARY_TABLES):
                    raise CurrentRootObservationError("complete primary inventory is missing or contains extra rows")
                primary = tuple(roots._owned_primary_row(row, table, bindings["queryManifestDigest"],
                    empty, acquisition, work) for table, row in zip(PRIMARY_TABLES, primary_rows))
                current = _transaction(acquisition, work)
                work.prepare_comparison(original, current)
                if current != original:
                    raise CurrentRootObservationError("complete root caller transaction changed between inventories")
                head_rows = acquisition.read(heads.HEAD_TABLE,
                    {"profile": heads.READ_PROFILE, "indexIds": list(INDEX_IDS), "rowLimit": len(INDEX_IDS) + 1},
                    _HEAD_SQL, (len(INDEX_IDS) + 1,), len(INDEX_IDS))
                if len(head_rows) != len(INDEX_IDS):
                    raise CurrentRootObservationError("complete counted inventory is missing or contains extra rows")
                counted = tuple(heads._owned_row(row, acquisition, work) for row in head_rows)
                document = {**bindings,
                    "primaryRoots": [{"table": row.table_name, "rootRevision": row.root_revision,
                        "rootDigest": row.root_digest, "leafCount": row.leaf_count} for row in primary],
                    "countedRoots": [{"indexId": row["index_id"], "table": row["table_name"],
                        "countedProfile": row["counted_profile"], "projectionDigest": row["projection_digest"],
                        "projectionManifestDigest": row["projection_manifest_digest"],
                        "indexRevision": row["index_revision"], "rootDigest": row["root_digest"],
                        "leafCount": row["leaf_count"]} for row in counted]}
                encoded = vector._encode_on_work(document, work=work)
                current = _transaction(acquisition, work)
                work.prepare_comparison(original, current)
                if current != original:
                    raise CurrentRootObservationError("complete root caller transaction changed before return")
                if (trace.phase != 5 or acquisition.sql_reads != 5
                        or acquisition.returned_rows != len(PRIMARY_TABLES) + len(INDEX_IDS) + 3
                        or acquisition.parameter_bytes != _PARAMETER_BYTES):
                    raise CurrentRootObservationError("complete root physical sequence did not finish exactly")
        acquisition.require_idle(cursor, trace, work)
    if roots._callback(work, lambda: raw_cursor.closed) is not True:
        raise CurrentRootObservationError("complete root cursor did not close normally")
    roots._callback(work, connection_reader._require_connection, connection, physical, 2)
    return encoded
