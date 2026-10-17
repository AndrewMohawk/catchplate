"""Configured native JIT read owner, with no signer or authority-result DTO.

The measured caller supplies admitted protected settings, independent roots,
request authority and its original live window. Construction is inert. Actual
PG16 TLS/catalog admission and all proof reads share one SERIALIZABLE READ ONLY
DEFERRABLE transaction. Virtual-transaction continuity is checked between the
two read stages and before return; output cannot escape resource closure.
The physical frames/shared-work meters are not process or server CPU limits.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from catchplate import authority_jit_assertion_acquisition as acquisition
from catchplate import authority_revocation_planning as native
from catchplate import authority_revocation_root_reader as physical
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate.authority_query_read_work import _ValidationWork
from catchplate.authority_store import current_root_observation as transaction_source


_SETUP_LIMITS = acquisition.reader._ReadAcquisitionLimits(max_sql_reads=10,
    max_parameter_bytes=4096, max_transport_bytes=1024 * 1024)
_CATALOG = ("pg_catalog.pg_stat_ssl", "pg_catalog.pg_class",
    "policy_authority_query_dependency_manifests", "policy_authority_authorization_dependency_manifests")
_CATALOG_ROWS = (1, 1, 4, 4)
_require = acquisition._require


def _configuration(value):
    _require(type(value) is tuple and len(value) == 4)
    dsn, timeout, identity, policy = value
    native._validate_read_scope_configuration((dsn, timeout, identity))
    _require(timeout >= 2 and "\x00" not in dsn and "\n" not in dsn and "\r" not in dsn)
    physical._bounded_text(identity[0], 63)
    _require(type(policy) is tuple and len(policy) == len(acquisition._POLICY_FIELDS))
    acquisition._policy(dict(zip(acquisition._POLICY_FIELDS, policy)))
    return value


class _Guard:
    def __init__(self, owner, configured, window, now, deadline, check, work):
        _require(type(work) is _ValidationWork and callable(check))
        window = clock._validate(window)
        acquisition.shape._integer(now, minimum=1)
        acquisition.shape._integer(deadline, minimum=1)
        _require(now == window[0] and now < deadline <= window[3])
        # Narrow only against the earliest ORIGINAL monotonic bracket.
        mono = min(window[4], window[1] + deadline - window[0])
        self._original = (owner, configured, window, deadline, mono, check, work, work.limits)
        self._held = self._original
        self._process = os.getpid(), threading.get_ident()
        self._metrics = work.hash_work, work.input_bytes, work.json_nodes
        self._reservation = acquisition.reservations._MutationReservationGuard(work)
        self._reservation_held = self._reservation
        self._last = 0
        self._busy = self._failed = False

    def local(self):
        owner, configured, window, deadline, mono, _check, work, limits = self._original
        _require(self._original is self._held and not self._failed and owner._configured is configured
            and self._process == (os.getpid(), threading.get_ident())
            and self._reservation is self._reservation_held
            and type(self._reservation) is acquisition.reservations._MutationReservationGuard
            and work.limits is self._reservation.current_limits())
        acquisition.batch._SharedLedger(work)
        values = work.hash_work, work.input_bytes, work.json_nodes
        _require(all(type(value) is int and value >= prior for value, prior in zip(values, self._metrics)))
        self._metrics = values
        epoch = clock._check_on_work(window, work=work)
        actual = physical.roots._callback(work, time.monotonic_ns)
        _require(type(actual) is int and self._last <= actual < mono and epoch < deadline)
        self._last = actual

    def check(self):
        try:
            _require(not self._busy)
            self._busy = True
            self.local()
            reservation = self._reservation._snapshot()
            _require(physical.roots._callback(self._original[6], self._original[5]) is None)
            self._reservation._unchanged(reservation, self._reservation._snapshot())
            self.local()
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False


class _SetupTrace:
    """Fixed catalog/transaction observations, not a business trace verdict."""

    def __init__(self):
        self.catalog = self.transactions = 0

    def read(self, table, key):
        if table == transaction_source._TRANSACTION_TABLE:
            _require(self.transactions < 6 and key == {
                "profile": transaction_source._TRANSACTION_PROFILE, "rowLimit": 2})
            self.transactions += 1
        else:
            ordinal = self.catalog
            _require(ordinal < 4 and table == _CATALOG[ordinal]
                and key == {"operation": acquisition.OPERATION, "setupOrdinal": ordinal,
                    "rowLimit": _CATALOG_ROWS[ordinal] + 1})
            self.catalog += 1


class _Native:
    def __init__(self, cursor, connection, transaction, pgconn, guard, types):
        self._held = cursor, connection, transaction, pgconn, guard, types
        self._original = self._held

    def check(self):
        cursor, connection, transaction, pgconn, guard, types = self._original
        _require(self._original is self._held and type(cursor) is types[0]
            and type(connection) is types[1] and type(transaction) is types[2]
            and cursor.connection is connection and cursor.closed is False
            and transaction.connection is connection and transaction.pgconn is pgconn
            and transaction._entered is True and transaction._exited is False
            and transaction._outer_transaction is True and transaction._stack_index == 0
            and connection._num_transactions == 1)
        physical._require_connection(connection, pgconn, 2)
        guard.check()
        _require(self._original is self._held and cursor.connection is connection
            and cursor.closed is False and transaction.connection is connection
            and transaction.pgconn is pgconn and transaction._entered is True
            and transaction._exited is False and transaction._outer_transaction is True
            and transaction._stack_index == 0 and connection._num_transactions == 1)
        physical._require_connection(connection, pgconn, 2)


class _Catalog:
    """Retain the actual planner's four admission queries with bounded rows."""

    def __init__(self, cursor, trace, budget, work):
        self.cursor, self.trace, self.budget, self.work = cursor, trace, budget, work
        self.pending = None

    def execute(self, sql, parameters=()):
        ordinal = self.trace.catalog
        _require(self.pending is None and 0 <= ordinal < 4 and type(sql) is str
            and len(sql) <= 16384 and sql.startswith("SELECT "))
        self.work.prepare_scan(sql)
        with self.budget.scope(self.cursor, self.trace, self.work):
            rows = self.budget.read(_CATALOG[ordinal],
                {"operation": acquisition.OPERATION, "setupOrdinal": ordinal,
                    "rowLimit": _CATALOG_ROWS[ordinal] + 1}, sql, parameters, _CATALOG_ROWS[ordinal])
            owned = []
            for row in rows:
                _require(type(row) is dict and len(row) <= 32)
                value = acquisition._owned(row, self.work)
                self.budget.charge_primary_row(self.work.wire(value))
                owned.append(value)
            self.pending = owned
        return self

    def fetchall(self):
        _require(type(self.pending) is list)
        result, self.pending = self.pending, None
        return result

    def fetchone(self):
        rows = self.fetchall()
        _require(len(rows) <= 1)
        return rows[0] if rows else None


def _transaction(cursor, trace, budget, work):
    with budget.scope(cursor, trace, work):
        observed = transaction_source._transaction(budget, work)
    _require(observed[4:6] == ("on", "on"))
    return observed


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class JitAssertionReadPlanner:
    _configured: tuple

    def __init__(self, *, read_dsn, connect_timeout_seconds, database_identity, assertion_policy):
        acquisition._policy(assertion_policy)
        configured = _configuration((read_dsn, connect_timeout_seconds, database_identity,
            tuple(assertion_policy[name] for name in acquisition._POLICY_FIELDS)))
        object.__setattr__(self, "_configured", configured)

    def acquire_originals(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, now_epoch_ns, deadline_epoch_ns, live_window, check, work):
        _require(type(self) is JitAssertionReadPlanner and type(work) is _ValidationWork)
        configured = _configuration(self._configured)
        dsn, timeout, identity, policy = configured
        _require(type(request) is dict and type(business_before_roots) is tuple
            and type(authorization_before_roots) is tuple and type(expected_counted_heads) is tuple
            and len(business_before_roots) == len(authorization_before_roots) == 4
            and len(expected_counted_heads) == 12)
        # The caller's mutable request/root graphs are detached BEFORE callbacks.
        owned = acquisition.reads._CopyBudget(work).copy({"request": request,
            "business": business_before_roots, "authorization": authorization_before_roots,
            "heads": expected_counted_heads})
        acquisition._request(owned["request"], work)
        work.prepare_copy(policy)
        selected_policy = dict(zip(acquisition._POLICY_FIELDS, policy))
        guard = _Guard(self, configured, live_window, now_epoch_ns, deadline_epoch_ns, check, work)
        guard.check()
        # No imported replacement registry/driver and no injected opener.
        from catchplate import authority_planner as planner
        from catchplate.authority_challenge_planning import _source_admission_work
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
                transaction = physical.roots._callback(work, connection.transaction)
                with physical._context(transaction, work):
                    cursor = physical.roots._callback(work, connection.cursor)
                    with physical._context(cursor, work) as entered_cursor:
                        _require(entered_cursor is cursor)
                        held = _Native(cursor, connection, transaction, pgconn, guard,
                            (psycopg.Cursor, psycopg.Connection, Transaction))
                        wrapped = native._ReadCursor(cursor, connection, pgconn, work, _current=held.check)
                        wrapped.execute(physical._SET_TRANSACTION)
                        trace = _SetupTrace()
                        budget = acquisition.reader._ReadAcquisitionBudget(wrapped, trace,
                            work=work, limits=_SETUP_LIMITS)
                        with budget.read_phase(wrapped, trace, work):
                            original_transaction = _transaction(wrapped, trace, budget, work)
                            _source_admission_work(acquisition.OPERATION, work)
                            catalog = _Catalog(wrapped, trace, budget, work)
                            planner._validate_database_identity(catalog, planner.PlannerIdentity(*identity))
                            proof_trace = planner.PlannerTrace(operation=acquisition.OPERATION, _jit_successor=True)
                            manifest, digest = planner._load_manifest(catalog,
                                operation=acquisition.OPERATION, trace=proof_trace)
                            authorization = planner._load_authorization_manifest(catalog,
                                operation=acquisition.OPERATION, trace=proof_trace)
                            _require(len(manifest) == len(authorization) == 4 and catalog.pending is None)
                            # Both manifests were independently checked by their
                            # genuine source validators. Exact-key acquisition
                            # needs their combined table/key roster, without
                            # relabelling either root class or manifest digest.
                            work.prepare_copy((manifest, authorization))
                            read_manifest = tuple(sorted((*manifest, *authorization), key=lambda item: item["table"]))

                            def current_snapshot():
                                held.check()
                                actual = _transaction(wrapped, trace, budget, work)
                                _require(type(actual) is tuple and len(actual) == len(original_transaction)
                                    and all(type(a) is type(b) and a == b
                                        for a, b in zip(actual, original_transaction)))
                                held.check()

                            raw = acquisition._acquire_on_work(wrapped, request=owned["request"],
                                assertion_policy=selected_policy, manifest=read_manifest,
                                manifest_digest=digest, business_before_roots=owned["business"],
                                authorization_before_roots=owned["authorization"],
                                expected_counted_heads=owned["heads"], now_epoch_ns=now_epoch_ns,
                                deadline_epoch_ns=deadline_epoch_ns,
                                deadline_monotonic_ns=guard._original[4], maximum_clock_skew_ns=live_window[6],
                                trace=proof_trace, check_snapshot=current_snapshot, work=work,
                                reservation_guard=guard._reservation)
                            current_snapshot()
                            _require(trace.catalog == 4 and trace.transactions == 6 and budget.sql_reads == 10)
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
