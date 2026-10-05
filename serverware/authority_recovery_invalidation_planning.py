"""Native original-byte recovery invalidation read owner, not authority.

Construction is inert. Independently admitted configuration, current roots and
the claimed recovery witness remain upstream. One real PostgreSQL transaction
owns TLS/role/source admission, five primary roots, the actual cutoff and all
nine counted heads. No raw bytes escape until normal resource closure.

There are exactly two source-fixed physical accounting stages: setup (14 reads,
1 MiB) and the unchanged proof collector (4096 reads, 4 MiB). Both spend the
same original H/B/N work and live window. Their actual physical counters are
aggregated once at closure; these are framing counts, not network/server CPU.
No generic read-scope, signer, witness or registry admission is extended here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
import threading
import time

from serverware import authority_recovery_invalidation_acquisition as acquisition
from serverware import authority_revocation_planning as native
from serverware import authority_revocation_root_reader as physical
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_query_read_work import _ValidationWork
from serverware.authority_store import current_root_observation as transaction_source


proof, roots, reader = acquisition.proof, physical.roots, acquisition.reader
_require = acquisition._require
_SETUP_LIMITS = reader._ReadAcquisitionLimits(max_sql_reads=14,
    max_parameter_bytes=4096, max_transport_bytes=1024 * 1024)
_TABLES = ("metadata_audit_outbox", "policy_authority_bounded_aggregate_states",
    "webauthn_challenges", "webauthn_recovery_ceremonies", "webauthn_recovery_revocations")
_CATALOG = ("pg_catalog.pg_stat_ssl", "pg_catalog.pg_class",
    "policy_authority_query_dependency_manifests", "policy_authority_authorization_dependency_manifests")
_CATALOG_ROWS = (1, 1, 5, 1)
_ROOT_PROFILE = "serverware.policyAuthorityRecoveryInvalidationRootRead/v1"
_CLOCK_PROFILE = "serverware.policyAuthorityRecoveryInvalidationCutoffRead/v1"
_ROOT_SQL = (f"SELECT {roots._PRIMARY_SELECT} FROM serverware_metadata.{roots.PRIMARY_TABLE} AS root "
    'WHERE root.table_name = %s ORDER BY root.table_name COLLATE "C" LIMIT %s')
_CLOCK_SQL = ("SELECT pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) "
    "* 1000000)::bigint AS cutoff_us")
_COUNTERS = ("sql_reads", "returned_rows", "parameter_bytes", "transport_bytes")


def _stamp(budget):
    # The root-reader's similarly named helper is deliberately restricted to
    # its own two-read inventory, so it is not reusable for these two stages.
    _require(type(budget) is reader._ReadAcquisitionBudget
        and type(budget.limits) is reader._ReadAcquisitionLimits)
    limits = budget.limits
    _require(limits in (_SETUP_LIMITS, reader._ReadAcquisitionLimits())
        and all(type(value) is int for value in (limits.max_sql_reads,
            limits.max_parameter_bytes, limits.max_transport_bytes))
        and all(type(value) is int and 0 <= value <= maximum for value, maximum in (
            (budget.sql_reads, limits.max_sql_reads),
            (budget.returned_rows, 256 * limits.max_sql_reads),
            (budget.parameter_bytes, limits.max_parameter_bytes),
            (budget.transport_bytes, limits.max_transport_bytes)))
        and all(type(value) is bool for value in (budget.active, budget.failed,
            budget._reading, budget._read_phase_active)) and not budget.failed)
    return (limits, *(getattr(budget, name) for name in _COUNTERS),
        budget.active, budget.failed, budget._reading, budget._read_phase_active)


def _configuration(value):
    _require(type(value) is tuple and len(value) == 5)
    dsn, timeout, identity, seconds, maximum = value
    native._validate_read_scope_configuration(value[:3])
    physical._bounded_text(dsn, 65536)
    physical._bounded_text(identity[0], 63)
    _require(timeout >= 2 and "\n" not in dsn and "\r" not in dsn
        and type(seconds) is int and 86_400 <= seconds <= 31_536_000
        and type(maximum) is int and 100 <= maximum <= 1_000_000)
    return value


class _Guard:
    def __init__(self, owner, configured, window, now, deadline, check, work):
        _require(type(work) is _ValidationWork and callable(check))
        window = clock._validate(window)
        acquisition.shape._integer(now, minimum=1)
        acquisition.shape._integer(deadline, minimum=1)
        _require(now == window[0] and now < deadline <= window[3])
        mono = min(window[4], window[1] + deadline - window[0])
        self._original = owner, configured, window, deadline, mono, check, work, work.limits
        self._held = self._original
        self._process = os.getpid(), threading.get_ident()
        self._metrics = work.hash_work, work.input_bytes, work.json_nodes
        self._limits = work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes
        self._reservation = acquisition.reservations._MutationReservationGuard(work)
        self._reservation_held = self._reservation
        self._budgets = ()
        self._last = 0
        self._busy = self._failed = False

    def attach(self, budget):
        _require(not self._busy and len(self._budgets) < 2
            and type(budget) is reader._ReadAcquisitionBudget
            and budget.work is self._original[6] and budget.limits ==
                (_SETUP_LIMITS if not self._budgets else reader._ReadAcquisitionLimits()))
        _stamp(budget)
        self._budgets += ((budget, budget.limits, budget._identity),)

    def local(self):
        owner, configured, window, deadline, mono, _check, work, limits = self._original
        _require(self._original is self._held and not self._failed
            and owner._configured is configured and self._reservation is self._reservation_held
            and type(self._reservation) is acquisition.reservations._MutationReservationGuard
            and work.limits is self._reservation.current_limits()
            and self._process == (os.getpid(), threading.get_ident()))
        proof.batch._SharedLedger(work)
        _require((limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) == self._limits)
        values = work.hash_work, work.input_bytes, work.json_nodes
        _require(all(type(value) is int and value >= previous
            for value, previous in zip(values, self._metrics)))
        self._metrics = values
        for budget, original_limits, identity in self._budgets:
            _require(budget.limits is original_limits and budget._identity is identity
                and budget.work is work and budget.failed is False
                and budget.cursor is identity[0] and budget.trace is identity[1])
            _stamp(budget)
        epoch = clock._check_on_work(window, work=work)
        actual = roots._callback(work, time.monotonic_ns)
        _require(type(actual) is int and self._last <= actual < mono and epoch < deadline)
        self._last = actual

    def check(self):
        try:
            _require(not self._busy)
            self._busy = True
            self.local()
            held = self._budgets
            stamps = tuple(_stamp(item[0]) for item in held)
            reservation = self._reservation._snapshot()
            _require(roots._callback(self._original[6], self._original[5]) is None)
            self._reservation._unchanged(reservation, self._reservation._snapshot())
            _require(self._budgets is held and all(roots._same_physical_stamp(before,
                _stamp(item[0])) for before, item in zip(stamps, held)))
            self.local()
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False


class _Native:
    def __init__(self, cursor, connection, transaction, pgconn, guard, types):
        self._original = cursor, connection, transaction, pgconn, guard, types
        self._held = self._original

    def check(self):
        def local():
            cursor, connection, transaction, pgconn, _guard, types = self._original
            _require(self._original is self._held and type(cursor) is types[0]
                and type(connection) is types[1] and type(transaction) is types[2]
                and cursor.connection is connection and cursor.closed is False
                and transaction.connection is connection and transaction.pgconn is pgconn
                and transaction._entered is True and transaction._exited is False
                and transaction._outer_transaction is True and transaction._stack_index == 0
                and connection._num_transactions == 1)
            physical._require_connection(connection, pgconn, 2)
        local()
        self._original[4].check()
        local()


class _SetupTrace:
    """Exactly four transaction probes, four catalog reads, five roots, one clock."""

    def __init__(self):
        self.ordinal = 0

    def read(self, table, key):
        ordinal = self.ordinal
        if ordinal in (0, 11, 12, 13):
            expected_table = transaction_source._TRANSACTION_TABLE
            expected = {"profile": transaction_source._TRANSACTION_PROFILE, "rowLimit": 2}
        elif 1 <= ordinal <= 4:
            index = ordinal - 1
            expected_table = _CATALOG[index]
            expected = {"operation": acquisition.OPERATION, "setupOrdinal": index,
                "rowLimit": _CATALOG_ROWS[index] + 1}
        elif 5 <= ordinal <= 9:
            expected_table = roots.PRIMARY_TABLE
            expected = {"profile": _ROOT_PROFILE, "tableName": _TABLES[ordinal - 5], "rowLimit": 2}
        else:
            _require(ordinal == 10)
            expected_table = "pg_catalog.clock_timestamp"
            expected = {"profile": _CLOCK_PROFILE, "rowLimit": 2}
        _require(type(table) is str and table == expected_table and type(key) is dict
            and set(key) == set(expected) and all(type(key[name]) is type(value)
                and key[name] == value for name, value in expected.items()))
        self.ordinal += 1


class _Catalog:
    def __init__(self, cursor, trace, budget, work):
        self.cursor, self.trace, self.budget, self.work = cursor, trace, budget, work
        self.pending = None

    def execute(self, sql, parameters=()):
        index = self.trace.ordinal - 1
        _require(self.pending is None and 0 <= index < 4 and type(sql) is str
            and len(sql) <= 16384 and sql.startswith("SELECT "))
        self.work.prepare_scan(sql)
        with self.budget.scope(self.cursor, self.trace, self.work):
            rows = self.budget.read(_CATALOG[index], {"operation": acquisition.OPERATION,
                "setupOrdinal": index, "rowLimit": _CATALOG_ROWS[index] + 1},
                sql, parameters, _CATALOG_ROWS[index])
            self.pending = []
            for row in rows:
                _require(type(row) is dict and len(row) <= 32)
                owned = proof._own(row, self.work)
                self.budget.charge_primary_row(self.work.wire(owned))
                self.pending.append(owned)
        return self

    def fetchall(self):
        _require(type(self.pending) is list)
        result, self.pending = self.pending, None
        return result

    def fetchone(self):
        rows = self.fetchall()
        _require(len(rows) <= 1)
        return rows[0] if rows else None


def _transaction(cursor, trace, budget, work, expected=None):
    with budget.scope(cursor, trace, work):
        actual = transaction_source._transaction(budget, work)
    _require(actual[4:6] == ("on", "on"))
    if expected is not None:
        work.prepare_comparison(actual, expected)
        _require(type(expected) is tuple and len(actual) == len(expected)
            and all(type(a) is type(b) and a == b for a, b in zip(actual, expected)))
    return actual


def _anchors(cursor, trace, budget, work, *, manifest_digest, business, authorization):
    contracts = proof.terminal.contracts.primary_table_contracts(acquisition.OPERATION)
    _require(tuple(item.table for item in contracts) == _TABLES
        and all(item.root_class == "business" for item in contracts)
        and type(business) is tuple and len(business) == 5
        and type(authorization) is tuple and not authorization)
    empty = roots._primary_empty_root(work)
    observed = []
    for table in _TABLES:
        with budget.scope(cursor, trace, work):
            rows = budget.read(roots.PRIMARY_TABLE,
                {"profile": _ROOT_PROFILE, "tableName": table, "rowLimit": 2}, _ROOT_SQL, (table, 2), 1)
            _require(len(rows) == 1)
            original = roots._owned_primary_row(rows[0], table, manifest_digest, empty, budget, work)
        work.charge(json_nodes=9)
        observed.append(dict(table=original.table_name, rootRevision=original.root_revision,
            rootDigest=original.root_digest, leafCount=original.leaf_count))
    proof._same((tuple(observed), ()), (business, authorization), work)


def _cutoff(cursor, trace, budget, work, *, now, deadline, skew):
    with budget.scope(cursor, trace, work):
        rows = budget.read("pg_catalog.clock_timestamp",
            {"profile": _CLOCK_PROFILE, "rowLimit": 2}, _CLOCK_SQL, (), 1)
        _require(len(rows) == 1 and type(rows[0]) is dict and set(rows[0]) == {"cutoff_us"})
        value = rows[0]["cutoff_us"]
        acquisition.shape._integer(value, minimum=1)
        _require(abs(value * 1000 - now) <= skew and value * 1000 < deadline)
        budget.charge("cutoff", rows[0], ("cutoff_us",))
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value)
    except OverflowError as exc:
        raise proof.RecoveryInvalidationError("invalidation cutoff is outside UTC datetime") from exc


def _physical_totals(setup, proof_budget, work):
    _require(type(setup) is reader._ReadAcquisitionBudget
        and type(proof_budget) is reader._ReadAcquisitionBudget and setup is not proof_budget
        and setup.work is work and proof_budget.work is work)
    first, second = _stamp(setup), _stamp(proof_budget)
    _require(first[0] == _SETUP_LIMITS and second[0] == reader._ReadAcquisitionLimits()
        and setup.sql_reads == 14 and setup.returned_rows == 16)
    totals = tuple(getattr(setup, name) + getattr(proof_budget, name) for name in _COUNTERS)
    _require(totals[0] <= 14 + reader.MAX_CUMULATIVE_SQL_READS
        and totals[1] <= 16 + 256 * reader.MAX_CUMULATIVE_SQL_READS
        and totals[2] <= 4096 + reader.MAX_PARAMETER_BYTES
        and totals[3] <= 1024 * 1024 + reader.MAX_TRANSPORT_BYTES)
    work.prepare_copy(totals)
    return totals


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class RecoveryInvalidationReadPlanner:
    _configured: tuple

    def __init__(self, *, read_dsn, connect_timeout_seconds, database_identity,
            terminal_retention_seconds, maximum_retained):
        configured = _configuration((read_dsn, connect_timeout_seconds, database_identity,
            terminal_retention_seconds, maximum_retained))
        object.__setattr__(self, "_configured", configured)

    def acquire_originals(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, now_epoch_ns, deadline_epoch_ns, live_window, check, work):
        _require(type(self) is RecoveryInvalidationReadPlanner and type(work) is _ValidationWork)
        configured = _configuration(self._configured)
        dsn, timeout, identity, seconds, maximum = configured
        _require(type(request) is dict and type(business_before_roots) is tuple
            and len(business_before_roots) == 5 and type(authorization_before_roots) is tuple
            and not authorization_before_roots and type(expected_counted_heads) is tuple
            and len(expected_counted_heads) == 9)
        owned = proof._own((request, business_before_roots, authorization_before_roots,
            expected_counted_heads), work)
        acquisition._request(owned[0], work)
        guard = _Guard(self, configured, live_window, now_epoch_ns, deadline_epoch_ns, check, work)
        guard.check()
        from serverware import authority_planner as planner
        from serverware.authority_challenge_planning import _source_admission_work
        import psycopg
        from psycopg.rows import dict_row
        from psycopg.transaction import Transaction

        connection = physical._connect(work, lambda: psycopg.connect(dsn, row_factory=dict_row,
            connect_timeout=timeout, options="-c search_path=pg_catalog"))
        try:
            guard.check()
            _require(type(connection) is psycopg.Connection)
            pgconn = physical._connection_identity(connection, 0)
            with physical._context(connection, work) as entered_connection:
                _require(entered_connection is connection)
                transaction = roots._callback(work, connection.transaction)
                with physical._context(transaction, work):
                    cursor = roots._callback(work, connection.cursor)
                    with physical._context(cursor, work) as entered_cursor:
                        _require(entered_cursor is cursor)
                        held = _Native(cursor, connection, transaction, pgconn, guard,
                            (psycopg.Cursor, psycopg.Connection, Transaction))
                        wrapped = native._ReadCursor(cursor, connection, pgconn, work, _current=held.check)
                        wrapped.execute(physical._SET_TRANSACTION)
                        trace = _SetupTrace()
                        setup = reader._ReadAcquisitionBudget(wrapped, trace, work=work, limits=_SETUP_LIMITS)
                        guard.attach(setup)
                        with setup.read_phase(wrapped, trace, work):
                            original = _transaction(wrapped, trace, setup, work)
                            _source_admission_work(acquisition.OPERATION, work)
                            catalog = _Catalog(wrapped, trace, setup, work)
                            planner._validate_database_identity(catalog, planner.PlannerIdentity(*identity))
                            proof_trace = planner.PlannerTrace(operation=acquisition.OPERATION, _recovery_successor=True)
                            manifest, digest = planner._load_manifest(catalog,
                                operation=acquisition.OPERATION, trace=proof_trace)
                            authorization = planner._load_authorization_manifest(catalog,
                                operation=acquisition.OPERATION, trace=proof_trace)
                            _require(len(manifest) == 5 and not authorization and catalog.pending is None)
                            _anchors(wrapped, trace, setup, work, manifest_digest=digest,
                                business=owned[1], authorization=owned[2])
                            now = _cutoff(wrapped, trace, setup, work, now=now_epoch_ns,
                                deadline=deadline_epoch_ns, skew=live_window[6])
                            _transaction(wrapped, trace, setup, work, original)
                            proof_budget = reader._ReadAcquisitionBudget(wrapped, proof_trace, work=work)
                            guard.attach(proof_budget)
                            raw = acquisition.acquire_originals(wrapped, request=owned[0], manifest=manifest,
                                business_before_roots=owned[1], authorization_before_roots=owned[2],
                                expected_counted_heads=owned[3], database_now=now,
                                terminal_retention_seconds=seconds, maximum_retained=maximum,
                                trace=proof_trace, work=work, acquisition=proof_budget,
                                reservation_guard=guard._reservation)
                            _require(type(raw) is bytes)
                            proof_budget.require_idle(wrapped, proof_trace, work)
                            _transaction(wrapped, trace, setup, work, original)
                            held.check()
                            _transaction(wrapped, trace, setup, work, original)
                            _require(trace.ordinal == 14)
                            _physical_totals(setup, proof_budget, work)
                            held.check()
                    _require(cursor.closed is True)
                    physical._require_connection(connection, pgconn, 2)
                    guard.check()
                _require(transaction._exited is True and connection._num_transactions == 0)
                physical._require_connection(connection, pgconn, 0)
                guard.check()
            _require(connection.closed is True)
            guard.check()
            return raw
        except BaseException:
            physical._close_after_failure(connection)
            raise
