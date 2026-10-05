"""Configured native read/sign owner for private challenge maintenance.

Construction is inert and does not admit its configuration or observations.
The service must supply genuinely admitted protected read credentials, keys,
current roots and one original live window. No writer connection, root lookup
fallback, public registry change, retry or renewed authority is available here.
Only the genuine two-pass producer runs inside the original PostgreSQL snapshot;
its output escapes after successful native resource closure. Physical frames and
shared work are bounded, not PostgreSQL/network/process resource measurements.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_challenge_maintenance as maintenance
from serverware import authority_challenge_manifest as manifests
from serverware import authority_challenge_plan as plan
from serverware import authority_challenge_plan_request as requests
from serverware import authority_challenge_policy as policy
from serverware import authority_challenge_snapshot as snapshots
from serverware import authority_revocation_root_reader as physical
from serverware.authority_query_read_work import _ValidationWork


roots, reader, heads, authority = physical.roots, physical.roots.reader, physical.roots.heads, requests.authority
transaction_source = snapshots.transaction_source
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_POLICY_FIELDS = tuple(sorted(policy._FIELDS))
_SETUP_LIMITS = reader._ReadAcquisitionLimits(max_sql_reads=10,
    max_parameter_bytes=4096, max_transport_bytes=512 * 1024)
_PRIMARY_PROFILE = "serverware.policyAuthorityChallengePrimaryRootRead/v1"
_CLOCK_PROFILE = "serverware.policyAuthorityChallengeCutoffRead/v1"
_CLOCK_SQL = ("SELECT pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) "
    "* 1000000)::bigint AS cutoff_us")
_PRIMARY_SQL = (f"SELECT {roots._PRIMARY_SELECT} FROM serverware_metadata.{roots.PRIMARY_TABLE} AS root "
    'WHERE root.table_name = %s ORDER BY root.table_name COLLATE "C" LIMIT %s')
_CATALOG = ("pg_catalog.pg_stat_ssl", "pg_catalog.pg_class",
    "policy_authority_query_dependency_manifests", "policy_authority_authorization_dependency_manifests")


class ChallengePlanningError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengePlanningError("challenge planner lost its original configured read scope")


def _same_transaction(actual, expected):
    # Fixed nine source-bounded scalars, never a caller identity/clock DTO.
    _require(type(actual) is tuple and len(actual) == len(transaction_source._TRANSACTION_FIELDS)
        and len(actual) == len(expected)
        and all(type(left) is type(right) and left == right for left, right in zip(actual, expected)))


def _configuration(values):
    _require(type(values) is tuple and len(values) == 12)
    operation, dsn, timeout, database, private, public, identity, spki, configuration, selected, age, skew = values
    _require(type(operation) is str and operation in requests.OPERATIONS)
    physical._bounded_text(dsn, 65536)
    _require("\n" not in dsn and "\r" not in dsn and type(timeout) is int and 2 <= timeout <= 300)
    _require(type(database) is tuple and len(database) == 7)
    physical._bounded_text(database[0], 63)
    for value in database[1:4]:
        physical._bounded_text(value, 4096)
    _require(type(identity) is tuple and len(identity) == 3 and identity == database[4:])
    for value in (*identity, spki, configuration):
        requests.shape._digest(value)
    _require(isinstance(private, Ed25519PrivateKey) and isinstance(public, Ed25519PublicKey))
    _require(type(selected) is tuple and len(selected) == len(_POLICY_FIELDS))
    for name, value in zip(_POLICY_FIELDS, selected):
        if name == "schema":
            _require(type(value) is str and value == policy.SCHEMA)
        else:
            low, high = policy._BOUNDS[name]
            _require(type(value) is int and low <= value <= high)
    requests.shape._integer(age, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    requests.shape._integer(skew, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    return values


class _Guard:
    """Invocation-local original references; no replacement work or deadline."""

    def __init__(self, owner, configured, window, deadline, check, work):
        _require(type(work) is _ValidationWork and callable(check))
        requests.shape._integer(deadline, minimum=1)
        window = plan.clock._validate(window)
        _require(deadline <= window[4] and window[5:] == configured[10:])
        self._original = owner, configured, window, deadline, check, work, work.limits
        self._held = self._original
        self._process = os.getpid(), threading.get_ident()
        self._metrics = (work.hash_work, work.input_bytes, work.json_nodes)
        self._clock = 0
        self._failed = self._busy = False

    def local(self):
        owner, configured, window, deadline, _check, work, limits = self._original
        _require(self._original is self._held and not self._failed and owner._configured is configured
            and self._process == (os.getpid(), threading.get_ident()) and work.limits is limits)
        roots.batch._SharedLedger(work)
        metrics = work.hash_work, work.input_bytes, work.json_nodes
        _require(all(type(value) is int and value >= prior for value, prior in zip(metrics, self._metrics)))
        self._metrics = metrics
        now = roots._callback(work, time.monotonic_ns)
        _require(type(now) is int and self._clock <= now < deadline)
        self._clock = now
        plan.clock._check_on_work(window, work=work)

    def check(self):
        try:
            _require(not self._busy)
            self._busy = True
            self.local()
            _require(roots._callback(self._original[5], self._original[4]) is None)
            self.local()
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False


class _Trace:
    """Ten fixed setup/final SELECTs; not a completed planner audit trace."""

    def __init__(self, operation, work):
        self.operation, self.work, self.position = operation, work, 0

    def read(self, table, key):
        position = self.position
        _require(type(position) is int and 0 <= position < 10)
        if position in (0, 8, 9):
            expected_table = transaction_source._TRANSACTION_TABLE
            expected = {"profile": transaction_source._TRANSACTION_PROFILE, "rowLimit": 2}
        elif 1 <= position <= 4:
            expected_table = _CATALOG[position - 1]
            expected = {"operation": self.operation, "setupOrdinal": position, "rowLimit": 2}
        elif position == 5:
            expected_table = roots.PRIMARY_TABLE
            expected = {"profile": _PRIMARY_PROFILE, "tableNames": ["webauthn_challenges"], "rowLimit": 2}
        elif position == 6:
            expected_table = heads.HEAD_TABLE
            expected = {"profile": heads.READ_PROFILE, "indexIds": list(manifests.WRITE_IDS), "rowLimit": 10}
        else:
            expected_table = "pg_catalog.clock_timestamp"
            expected = {"profile": _CLOCK_PROFILE, "rowLimit": 2}
        plan._same([table, key], [expected_table, expected], self.work)
        self.position += 1


class _Result:
    def __init__(self, owner):
        self.owner = owner

    def fetchmany(self, size):
        _require(type(size) is int and 1 <= size <= 11)
        return self.owner.call(lambda: self.owner.cursor.fetchmany(size))


class _Setup:
    """Native cursor/transaction and physical counters held across each call."""

    def __init__(self, cursor, connection, transaction, pgconn, guard, native_types):
        self.cursor, self.connection, self.transaction = cursor, connection, transaction
        self._original = cursor, connection, transaction, pgconn, guard, native_types
        self.work = guard._original[5]
        self.trace = _Trace(guard._original[1][0], self.work)
        self.acquisition = reader._ReadAcquisitionBudget(self, self.trace, work=self.work, limits=_SETUP_LIMITS)
        self._ledger = self.acquisition, self.acquisition.limits, self.acquisition._identity, self.trace

    def local(self):
        cursor, connection, transaction, pgconn, guard, types = self._original
        _require(self.cursor is cursor and self.connection is connection and self.transaction is transaction
            and type(cursor) is types[0] and type(connection) is types[1] and type(transaction) is types[2]
            and cursor.connection is connection and cursor.closed is False
            and transaction.connection is connection and transaction.pgconn is pgconn
            and transaction._entered is True and transaction._exited is False
            and transaction._outer_transaction is True and transaction._stack_index == 0
            and connection._num_transactions == 1 and self.work is guard._original[5])
        physical._require_connection(connection, pgconn, 2)
        acquisition, limits, identity, trace = self._ledger
        _require(self.acquisition is acquisition and acquisition.limits is limits
            and acquisition._identity is identity and acquisition.cursor is self
            and acquisition.trace is trace and self.trace is trace and acquisition.work is self.work
            and limits == _SETUP_LIMITS and acquisition.failed is False)
        values = (acquisition.sql_reads, acquisition.returned_rows,
            acquisition.parameter_bytes, acquisition.transport_bytes, trace.position)
        _require(all(type(value) is int and 0 <= value <= maximum for value, maximum in
            zip(values, (10, 32, 4096, 512 * 1024, 10))))
        flags = acquisition.active, acquisition._reading, acquisition._read_phase_active
        _require(all(type(value) is bool for value in flags))
        return values, flags

    def check(self):
        self.local()
        self._original[4].check()
        self.local()

    def call(self, callback):
        try:
            self.check()
            stamp = self.local()
            result = roots._callback(self.work, callback)
            self.check()
            _require(self.local() == stamp)
            return result
        except BaseException:
            self.acquisition.failed = True
            raise

    def execute(self, sql, parameters=()):
        _require(type(sql) is str and 1 <= len(sql) <= 16384)
        self.work.prepare_scan(sql)
        result = self.call(lambda: self.cursor.execute(sql, parameters))
        _require(result is self.cursor)
        return _Result(self)

    def transaction_identity(self):
        with self.acquisition.scope(self, self.trace, self.work):
            result = transaction_source._transaction(self.acquisition, self.work)
        _require(result[4:6] == ("on", "on"))
        return result


class _Catalog:
    """Bound real legacy admission helpers to four one-row setup queries."""

    def __init__(self, setup):
        self.setup, self.pending = setup, None

    def execute(self, sql, parameters=()):
        setup = self.setup
        position = setup.trace.position
        _require(self.pending is None and 1 <= position <= 4 and sql.startswith("SELECT "))
        with setup.acquisition.scope(setup, setup.trace, setup.work):
            rows = setup.acquisition.read(_CATALOG[position - 1],
                {"operation": setup.trace.operation, "setupOrdinal": position, "rowLimit": 2},
                sql, parameters, 1)
            owned = []
            for row in rows:
                _require(type(row) is dict and len(row) <= 32)
                copy = roots.batch._JSONCapture(roots.batch._SharedLedger(setup.work),
                    maximum_bytes=64 * 1024).visit(row)
                setup.acquisition.charge_primary_row(setup.work.wire(copy))
                owned.append(copy)
            self.pending = owned
        return self

    def fetchone(self):
        rows = self.fetchall()
        return rows[0] if rows else None

    def fetchall(self):
        _require(type(self.pending) is list)
        result, self.pending = self.pending, None
        return result


def _source_admission_work(operation, work):
    """Conservative reservations for genuine fixed catalog source rebuilds.

    These descriptors come only from measured source, never database/request
    values. Their bounded reconstruction is not a generic CPU/allocation claim.
    Reserve repeated full source documents, hashes, row copies and comparisons
    before the original planner admission functions reconstruct/compare them.
    """
    primary = roots.primary
    operations = roots._callback(work, authority.operation_manifest)
    query = roots._callback(work, primary.source_query_manifest)
    authorization = roots._callback(work, primary.source_authorization_manifest)
    for _ in range(4):
        work.prepare_encoding(operations)
        work.prepare_copy(operations)
        work.charge(hashes=len(operations))
    for document, repeats in ((query, 3), (authorization, 2)):
        for _ in range(repeats):
            work.prepare_encoding(document)
            work.prepare_copy(document)
            work.prepare_scan(document)
            work.charge(hashes=1 + sum(entry["operation"] == operation for entry in document),
                input_bytes=16 + 128)


def _initial_roots(setup, operation, manifest_digest):
    work, acquisition = setup.work, setup.acquisition
    empty = roots._primary_empty_root(work)
    with acquisition.scope(setup, setup.trace, work):
        rows = acquisition.read(roots.PRIMARY_TABLE,
            {"profile": _PRIMARY_PROFILE, "tableNames": ["webauthn_challenges"], "rowLimit": 2},
            _PRIMARY_SQL, ("webauthn_challenges", 2), 1)
        _require(len(rows) == 1)
        observed = roots._owned_primary_row(rows[0], "webauthn_challenges", manifest_digest, empty, acquisition, work)
    primary = {"table": observed.table_name, "rootRevision": observed.root_revision,
        "rootDigest": observed.root_digest, "leafCount": observed.leaf_count}
    counted = heads.read_operation_index_heads(setup, operation=operation, trace=setup.trace,
        work=work, acquisition=acquisition, include_write_heads=True)
    _require(tuple(head.index_id for head in counted) == manifests.WRITE_IDS
        and all(head.index_root.count <= observed.leaf_count for head in counted))
    return primary, [maintenance.head_wire(head) for head in counted]


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class MaintenancePlanner:
    _configured: tuple

    def __init__(self, *, operation, read_dsn, connect_timeout_seconds, database_identity,
            planner_private_key, planner_public_key, planner_identity, planner_spki_digest,
            configuration_digest, maintenance_policy, maximum_plan_age_ns, maximum_clock_skew_ns):
        plan.evidence._identity(planner_identity)
        _require(type(maintenance_policy) is dict and set(maintenance_policy) == policy._FIELDS)
        configured = _configuration((operation, read_dsn, connect_timeout_seconds, database_identity,
            planner_private_key, planner_public_key, tuple(planner_identity[name] for name in _IDENTITY_FIELDS),
            planner_spki_digest, configuration_digest, tuple(maintenance_policy[name] for name in _POLICY_FIELDS),
            maximum_plan_age_ns, maximum_clock_skew_ns))
        object.__setattr__(self, "_configured", configured)

    def produce(self, *, request_bytes, primary_root, index_heads, live_window,
            original_deadline_ns, retain_page, check, work):
        _require(type(self) is MaintenancePlanner and type(work) is _ValidationWork and callable(retain_page))
        configured = _configuration(self._configured)
        operation, dsn, timeout, database, private, public, identity, spki, configuration, selected, age, skew = configured
        request = requests.capture_request(request_bytes, work=work)
        subject = requests.context_subject(request, work=work)
        _require(subject["operation"] == operation and type(primary_root) is maintenance.primary.PrimaryRoot
            and type(index_heads) is tuple and len(index_heads) == len(manifests.WRITE_IDS)
            and all(type(head) is heads.CapturedIndexHead for head in index_heads))
        anchors = maintenance._owned({"primary": primary_root.json_projection(),
            "heads": [maintenance.head_wire(head) for head in index_heads]}, work)
        selected_policy = policy.validate_policy(dict(zip(_POLICY_FIELDS, selected)), work=work)
        guard = _Guard(self, configured, live_window, original_deadline_ns, check, work)
        guard.check()
        plan.evidence.keys._public_binding(public, spki, work)
        plan.evidence.keys._pair_on_work(private, public, work)
        guard.check()
        # Genuine imports and source admission, never a replacement registry.
        from serverware import authority_planner as planner
        import psycopg
        from psycopg.rows import dict_row
        from psycopg.transaction import Transaction

        connection = physical._connect(work, lambda: psycopg.connect(dsn, row_factory=dict_row,
            connect_timeout=timeout, options="-c search_path=pg_catalog"))
        acquisition = None
        try:
            guard.check()
            _require(type(connection) is psycopg.Connection)
            pgconn = physical._connection_identity(connection, 0)
            with physical._context(connection, work) as active_connection:
                _require(active_connection is connection)
                transaction = roots._callback(work, connection.transaction)
                with physical._context(transaction, work):
                    physical._require_connection(connection, pgconn, 2)
                    cursor = roots._callback(work, connection.cursor)
                    with physical._context(cursor, work) as active_cursor:
                        _require(active_cursor is cursor)
                        setup = _Setup(cursor, connection, transaction, pgconn, guard,
                            (psycopg.Cursor, psycopg.Connection, Transaction))
                        setup.execute(physical._SET_TRANSACTION)
                        with setup.acquisition.read_phase(setup, setup.trace, work):
                            original_transaction = setup.transaction_identity()
                            _source_admission_work(operation, work)
                            catalog = _Catalog(setup)
                            planner._validate_database_identity(catalog, planner.PlannerIdentity(*database))
                            trace = planner.PlannerTrace(operation=operation, _challenge_successor=True)
                            manifest, digest = planner._load_manifest(catalog, operation=operation, trace=trace)
                            authorization = planner._load_authorization_manifest(catalog, operation=operation, trace=trace)
                            _require(len(manifest) == 1 and manifest[0]["table"] == "webauthn_challenges"
                                and not authorization and catalog.pending is None)
                            actual_primary, actual_heads = _initial_roots(setup, operation, digest)
                            plan._same(anchors, {"primary": actual_primary, "heads": actual_heads}, work)
                            with setup.acquisition.scope(setup, setup.trace, work):
                                rows = setup.acquisition.read("pg_catalog.clock_timestamp",
                                    {"profile": _CLOCK_PROFILE, "rowLimit": 2}, _CLOCK_SQL, (), 1)
                                _require(len(rows) == 1 and type(rows[0]) is dict and set(rows[0]) == {"cutoff_us"})
                                cutoff = rows[0]["cutoff_us"]
                                requests.shape._integer(cutoff)
                                setup.acquisition.charge("cutoff", rows[0], ("cutoff_us",))
                            _same_transaction(setup.transaction_identity(), original_transaction)
                            context = {"sourceRevision": authority.SOURCE_REVISION, **subject,
                                "configurationDigest": configuration, "cutoffUs": cutoff,
                                **policy.maintenance_context(selected_policy, work=work),
                                "primaryRoot": actual_primary, "indexHeads": actual_heads,
                                "originalDeadlineNs": original_deadline_ns}
                            context = manifests._context(context, work)

                            def current():
                                setup.check()
                                _require(acquisition is not None and acquisition._original_transaction is not None)
                                _same_transaction(acquisition._original_transaction, original_transaction)

                            acquisition = snapshots.MaintenanceAcquisition(cursor=cursor, connection=connection,
                                transaction=transaction, context=context, check=current)
                            expected = {"context": context, "plannerIdentity": dict(zip(_IDENTITY_FIELDS, identity)),
                                "plannerSpkiDigest": spki, "policy": {"nowEpochNs": live_window[0],
                                    "deadlineEpochNs": live_window[3], "maximumPlanAgeNs": age, "maximumClockSkewNs": skew}}
                            result = plan.produce_maintenance_parent(acquisition=acquisition,
                                request_bytes=request_bytes, expectations=expected, planner_private_key=private,
                                planner_public_key=public, live_window=live_window, retain_page=retain_page, work=work)
                            _same_transaction(acquisition._original_transaction, original_transaction)
                            _same_transaction(setup.transaction_identity(), original_transaction)
                            _require(setup.trace.position == 10 and setup.acquisition.sql_reads == 10)
                            setup.check()
                    _require(cursor.closed is True)
                    physical._require_connection(connection, pgconn, 2)
                    guard.check()
                physical._require_connection(connection, pgconn, 0)
                _require(transaction._exited is True and connection._num_transactions == 0)
                guard.check()
            _require(connection.closed is True)
            guard.check()
            return result
        except BaseException:
            if acquisition is not None:
                try:
                    snapshots.MaintenanceAcquisition.close(acquisition)
                except BaseException:
                    pass
            physical._close_after_failure(connection)
            raise
