"""Native configured setup for the private source-fixed JIT compound pass.

Construction is inert. The caller supplies admitted protected configuration,
request authority, full before anchors and one original live window. Twelve
metadata SELECTs share one setup collector on the original parent work. The
existing independent RBAC witness owner retains its separate real admission
and deadline contract; its two metadata reads are included, not bypassed.

The direct compound pass owns its finite child stages and physical collectors.
Parent work stays suspended during that pass. Output is an observation, never
an authority token, and cannot escape normal native resource closure. These
meters bound retained frames/shared work, not PostgreSQL or process CPU.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_jit_assertion_planning as existing
from catchplate.authority_query_read_work import _ValidationWork


acquisition, native, physical = existing.acquisition, existing.native, existing.physical
roots, heads, reader = physical.roots, acquisition.heads, acquisition.reader
transaction_source = existing.transaction_source
OPERATION = acquisition.OPERATION
_require = acquisition._require
_SETUP_LIMITS = reader._ReadAcquisitionLimits(max_sql_reads=12,
    max_parameter_bytes=4096, max_transport_bytes=1024 * 1024)
_PRIMARY_PROFILE = "catchplate.policyAuthorityJitCompoundPrimaryRoots/v1"
_CLOCK_PROFILE = "catchplate.policyAuthorityJitCompoundCutoff/v1"
_RBAC_PROFILE = "catchplate.policyAuthorityJitCompoundRbacCurrentness/v1"
_CLOCK_SQL = ("SELECT pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) "
    "* 1000000)::bigint AS cutoff_us")
# Literal admission of the existing currentness helper's two queries. The
# helper remains the sole producer; this adapter cannot substitute a witness.
_RBAC_SQL = (
    "SELECT (pg_catalog.pg_control_system()).system_identifier::text AS cluster_id,"
    "pg_catalog.current_database() AS database",
    "SELECT table_name,root_revision,root_digest,leaf_count FROM catchplate_metadata."
    "policy_authority_authenticated_table_roots WHERE table_name IN "
    "('rbac_authority_state','rbac_role_bindings') ORDER BY table_name",
)
_RBAC_TABLES = ("pg_catalog.pg_control_system", roots.PRIMARY_TABLE)
_RBAC_ROWS = (1, 2)


def _same_transaction(actual, original):
    _require(type(actual) is tuple and type(original) is tuple
        and len(actual) == len(original) == len(transaction_source._TRANSACTION_FIELDS)
        and all(type(a) is type(b) and a == b for a, b in zip(actual, original)))


class _SetupTrace:
    """Exact source order; not a complete business/audit trace or verdict."""

    def __init__(self, tables, identities):
        self.operation, self.tables, self.identities = OPERATION, tables, identities
        self.position = self.catalog = 0

    def read(self, table, key):
        position = self.position
        _require(type(position) is int and 0 <= position < 12)
        if position in (0, 10, 11):
            expected_table = transaction_source._TRANSACTION_TABLE
            expected = {"profile": transaction_source._TRANSACTION_PROFILE, "rowLimit": 2}
        elif 1 <= position <= 4:
            ordinal = position - 1
            _require(self.catalog == ordinal)
            expected_table = existing._CATALOG[ordinal]
            expected = {"operation": OPERATION, "setupOrdinal": ordinal,
                "rowLimit": existing._CATALOG_ROWS[ordinal] + 1}
        elif position == 5:
            expected_table = roots.PRIMARY_TABLE
            expected = {"profile": _PRIMARY_PROFILE, "tableNames": list(self.tables), "rowLimit": 9}
        elif position == 6:
            expected_table = heads.HEAD_TABLE
            expected = {"profile": heads.READ_PROFILE, "indexIds": list(self.identities), "rowLimit": 13}
        elif position in (7, 8):
            ordinal = position - 7
            expected_table = _RBAC_TABLES[ordinal]
            expected = {"profile": _RBAC_PROFILE, "ordinal": ordinal, "rowLimit": _RBAC_ROWS[ordinal] + 1}
        else:
            expected_table = "pg_catalog.clock_timestamp"
            expected = {"profile": _CLOCK_PROFILE, "rowLimit": 2}
        # Exact scalar types prevent bool/int aliases in these small markers.
        _require(type(table) is str and table == expected_table and type(key) is dict
            and set(key) == set(expected) and all(type(key[name]) is type(value)
                and key[name] == value for name, value in expected.items()))
        if 1 <= position <= 4:
            self.catalog += 1
        self.position += 1


class _RbacCursor:
    """Meter the unchanged helper's actual metadata reads, not its verdict."""

    def __init__(self, cursor, trace, budget, work):
        self.cursor, self.trace, self.budget, self.work = cursor, trace, budget, work
        self.ordinal, self.pending = 0, None

    def execute(self, sql, parameters=()):
        ordinal = self.ordinal
        _require(type(ordinal) is int and ordinal in (0, 1) and self.pending is None
            and type(sql) is str and sql == _RBAC_SQL[ordinal]
            and type(parameters) is tuple and not parameters)
        self.work.prepare_scan(sql)
        with self.budget.scope(self.cursor, self.trace, self.work):
            rows = self.budget.read(_RBAC_TABLES[ordinal],
                {"profile": _RBAC_PROFILE, "ordinal": ordinal, "rowLimit": _RBAC_ROWS[ordinal] + 1},
                sql, parameters, _RBAC_ROWS[ordinal])
            _require(len(rows) == _RBAC_ROWS[ordinal])
            owned = []
            fields = ({"cluster_id", "database"} if ordinal == 0 else
                {"table_name", "root_revision", "root_digest", "leaf_count"})
            for row in rows:
                _require(type(row) is dict and set(row) == fields)
                if ordinal == 0:
                    physical._bounded_text(row["cluster_id"], 20)
                    physical._bounded_text(row["database"], 63)
                else:
                    physical._bounded_text(row["table_name"], 128)
                    acquisition.shape._digest(row["root_digest"])
                    for name in ("root_revision", "leaf_count"):
                        acquisition.shape._integer(row[name], 2**63 - 1)
                value = acquisition._owned(row, self.work)
                self.budget.charge_primary_row(self.work.wire(value))
                owned.append(value)
            self.pending = owned
        self.ordinal += 1
        return self

    def fetchall(self):
        _require(type(self.pending) is list)
        rows, self.pending = self.pending, None
        return rows

    def fetchone(self):
        rows = self.fetchall()
        _require(len(rows) == 1)
        return rows[0]


def _initial_roots(cursor, trace, budget, manifest_digest, contracts, work):
    # Reserve fixed inventory/SQL/result scaffolding before constructing it.
    work.charge(input_bytes=16384, json_nodes=512)
    _require(tuple(item.table for item in contracts) == trace.tables)
    empty = roots._primary_empty_root(work)
    sql = (f"SELECT {roots._PRIMARY_SELECT} FROM catchplate_metadata.{roots.PRIMARY_TABLE} AS root "
        f"WHERE root.table_name IN ({', '.join('%s' for _ in trace.tables)}) "
        'ORDER BY root.table_name COLLATE "C" LIMIT %s')
    work.prepare_scan(sql)
    with budget.scope(cursor, trace, work):
        rows = budget.read(roots.PRIMARY_TABLE,
            {"profile": _PRIMARY_PROFILE, "tableNames": list(trace.tables), "rowLimit": 9},
            sql, (*trace.tables, 9), 8)
        _require(len(rows) == 8)
        # The actual metadata producer binds every primary root to the global
        # QUERY manifest, including authorization-class roots. The separate
        # authorization manifest is admitted above, not substituted here.
        observed = tuple(roots._owned_primary_row(row, table, manifest_digest, empty, budget, work)
            for table, row in zip(trace.tables, rows, strict=True))
    counted = heads.read_operation_index_heads(cursor, operation=OPERATION, trace=trace,
        work=work, acquisition=budget, include_write_heads=True)
    _require(tuple(head.index_id for head in counted) == trace.identities)
    by_table = {row.table_name: row.leaf_count for row in observed}
    _require(all(head.index_root.count <= by_table[head.table] for head in counted))
    primary = tuple(acquisition.indexed.primary.PrimaryRoot(row.table_name, row.root_revision,
        row.root_digest, row.leaf_count) for row in observed)
    business = tuple(root for item, root in zip(contracts, primary, strict=True)
        if item.root_class == "business")
    authorization = tuple(root for item, root in zip(contracts, primary, strict=True)
        if item.root_class == "authorization")
    write_heads = tuple(acquisition.read_write.CompleteReadWriteHead(head.index_id,
        head.index_revision, head.index_root) for head in counted)
    return business, authorization, write_heads


def _cutoff_value(row, now, deadline, skew):
    _require(type(row) is dict and set(row) == {"cutoff_us"})
    value = row["cutoff_us"]
    acquisition.shape._integer(value, (2**63 - 1) // 1000, minimum=1)
    _require(abs(value * 1000 - now) <= skew and value * 1000 < deadline)
    return value


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class JitCompoundReadPlanner:
    _configured: tuple

    def __init__(self, *, read_dsn, connect_timeout_seconds, database_identity, assertion_policy):
        acquisition._policy(assertion_policy)
        configured = existing._configuration((read_dsn, connect_timeout_seconds, database_identity,
            tuple(assertion_policy[name] for name in acquisition._POLICY_FIELDS)))
        object.__setattr__(self, "_configured", configured)

    def acquire_pass(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, now_epoch_ns, deadline_epoch_ns, live_window,
            check, work, retain_original=None):
        _require(type(self) is JitCompoundReadPlanner and type(work) is _ValidationWork
            and (retain_original is None or callable(retain_original)))
        # Fixed source inventory/trace/native-owner scaffolding, before copies.
        work.charge(input_bytes=65536, json_nodes=2048)
        configured = existing._configuration(self._configured)
        dsn, timeout, identity, policy = configured
        _require(type(request) is dict and type(business_before_roots) is tuple
            and type(authorization_before_roots) is tuple and type(expected_counted_heads) is tuple
            and len(business_before_roots) == 4 and len(authorization_before_roots) == 4
            and len(expected_counted_heads) == 12)
        owned = acquisition.reads._CopyBudget(work).copy({"request": request,
            "business": business_before_roots, "authorization": authorization_before_roots,
            "heads": expected_counted_heads})
        acquisition._request(owned["request"], work)
        work.prepare_copy(policy)
        selected_policy = dict(zip(acquisition._POLICY_FIELDS, policy))
        contracts = acquisition.primary_contract.primary_table_contracts(OPERATION)
        _require(len(contracts) == 8
            and sum(item.root_class == "business" for item in contracts) == 4
            and sum(item.root_class == "authorization" for item in contracts) == 4)
        tables = tuple(item.table for item in contracts)
        identities = heads._jit_receipt_ids()
        _require(len(identities) == 12)
        guard = existing._Guard(self, configured, live_window, now_epoch_ns, deadline_epoch_ns, check, work)
        guard.check()
        from catchplate import authority_planner_read as planner
        from catchplate import authority_jit_compound as compound
        from catchplate import control_plane_rbac_currentness as rbac
        from catchplate.authority_planner_read import _source_admission_work
        import psycopg
        from psycopg.rows import dict_row
        from psycopg.transaction import Transaction

        connection = physical._connect(work, lambda: psycopg.connect(dsn, row_factory=dict_row,
            connect_timeout=timeout, options="-c search_path=pg_catalog"))
        try:
            guard.check()
            _require(type(connection) is psycopg.Connection)
            pgconn = physical._connection_identity(connection, 0)
            with physical._context(connection, work) as active_connection:
                _require(active_connection is connection)
                transaction = roots._callback(work, connection.transaction)
                with physical._context(transaction, work):
                    cursor = roots._callback(work, connection.cursor)
                    with physical._context(cursor, work) as active_cursor:
                        _require(active_cursor is cursor)
                        held = existing._Native(cursor, connection, transaction, pgconn, guard,
                            (psycopg.Cursor, psycopg.Connection, Transaction))
                        wrapped = native._ReadCursor(cursor, connection, pgconn, work, _current=held.check)
                        wrapped.execute(physical._SET_TRANSACTION)
                        trace = _SetupTrace(tables, identities)
                        budget = reader._ReadAcquisitionBudget(wrapped, trace, work=work, limits=_SETUP_LIMITS)
                        with budget.read_phase(wrapped, trace, work):
                            original_transaction = existing._transaction(wrapped, trace, budget, work)
                            _source_admission_work(OPERATION, work)
                            catalog = existing._Catalog(wrapped, trace, budget, work)
                            planner._validate_database_identity(catalog, planner.PlannerIdentity(*identity))
                            proof_trace = planner.PlannerTrace(operation=OPERATION, _jit_successor=True)
                            manifest, digest = planner._load_manifest(catalog, operation=OPERATION, trace=proof_trace)
                            authorization = planner._load_authorization_manifest(catalog,
                                operation=OPERATION, trace=proof_trace)
                            _require(len(manifest) == 4 and len(authorization) == 4 and catalog.pending is None)
                            business, authorization, counted = _initial_roots(
                                wrapped, trace, budget, digest, contracts, work)
                            work.charge(input_bytes=16384, json_nodes=512)
                            business_wire = tuple(root.json_projection() for root in business)
                            authorization_wire = tuple(root.json_projection() for root in authorization)
                            counted_wire = tuple({"indexId": head.index_id, "indexRevision": head.index_revision,
                                "rootDigest": head.index_root.digest, "leafCount": head.index_root.count} for head in counted)
                            acquisition._same(business_wire, owned["business"], work)
                            acquisition._same(authorization_wire, owned["authorization"], work)
                            acquisition._same(counted_wire, owned["heads"], work)
                            rbac_cursor = _RbacCursor(wrapped, trace, budget, work)
                            held.check()
                            rbac.require_roots(business_wire + authorization_wire, cursor=rbac_cursor,
                                deadline_epoch_ns=deadline_epoch_ns, deadline_ns=guard._original[4])
                            _require(rbac_cursor.ordinal == 2 and rbac_cursor.pending is None)
                            held.check()
                            work.prepare_scan(_CLOCK_SQL)
                            with budget.scope(wrapped, trace, work):
                                rows = budget.read("pg_catalog.clock_timestamp",
                                    {"profile": _CLOCK_PROFILE, "rowLimit": 2}, _CLOCK_SQL, (), 1)
                                _require(len(rows) == 1)
                                cutoff = _cutoff_value(rows[0], now_epoch_ns, deadline_epoch_ns, guard._original[2][6])
                                budget.charge("cutoff", rows[0], ("cutoff_us",))
                            _same_transaction(existing._transaction(wrapped, trace, budget, work), original_transaction)

                            def current(_stage):
                                # No query or parent debit inside a child stage.
                                held.check()

                            # The exact source call alone creates/owns child
                            # work; no operation callback or supplied verdict.
                            result = roots._callback(work, compound.run_pass,
                                request=owned["request"], assertion_policy=selected_policy,
                                business_before_roots=business, authorization_before_roots=authorization,
                                counted_before_heads=counted, database_cutoff_us=cutoff,
                                original_deadline_ns=guard._original[4], cursor=wrapped,
                                trace=proof_trace, check=current, retain_original=retain_original,
                                read_original=None)
                            _require(type(result) is compound.JitPassObservation)
                            _same_transaction(existing._transaction(wrapped, trace, budget, work), original_transaction)
                            _require(trace.position == 12 and trace.catalog == 4 and budget.sql_reads == 12)
                            held.check()
                    _require(cursor.closed is True)
                    physical._require_connection(connection, pgconn, 2)
                    guard.check()
                _require(transaction._exited is True and connection._num_transactions == 0)
                physical._require_connection(connection, pgconn, 0)
                guard.check()
            _require(connection.closed is True)
            guard.check()
            return result
        except BaseException:
            physical._close_after_failure(connection)
            raise
