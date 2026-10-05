"""Private native owner for the fixed streamed maintenance execution calls.

One actual PostgreSQL transaction holds all tentative steps and their seal, or
one identifier-only execution. Actual role/TLS/effective privileges and the
independently selected complete catalog are admitted before and after it.
Nothing here opens a new clock/allowance, enrolls a catalog, retries, or accepts
a proof verdict. A session exposes only the three source-fixed function calls.

Python scalar framing/copy/hash work uses the supplied parent or actual child
allowance. Native driver, PostgreSQL and complete catalog collection costs are
outside H/B/N, as in the existing owner. Continuity probes are real SQL, not
invented acquisition/trace metrics. Fixed waits and checks are not a syscall
watchdog; a late post-commit error cannot undo a committed transaction.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time

from serverware import authority_challenge_execution_contract as contract
from serverware import authority_challenge_execution_packet as packet
from serverware import authority_challenge_execution_stream as stream
from serverware import authority_successor_execution_owner as existing
from serverware.authority_query_read_work import _ValidationWork
from serverware.authority_store import current_root_observation as observation
from serverware.authority_store.challenge_execution_privileges import challenge_execution_privilege_check


evidence, clock = existing.evidence, existing.clock
native = existing.connection_owner
_STEP_SQL = ("SELECT serverware_metadata." + contract.STEP_FUNCTION
    + "(%s, %s, %s, %s, %s) AS step_ordinal")
_SEAL_SQL = "SELECT * FROM serverware_metadata." + contract.SEAL_FUNCTION + "(%s, %s, %s)"
_EXECUTE_SQL = ("SELECT serverware_metadata." + contract.EXECUTE_FUNCTION
    + "(%s, %s) AS marker_json")


class ChallengeExecutionConnectionError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengeExecutionConnectionError("maintenance native execution custody changed")


def _same(left, right, work):
    work.prepare_comparison(left, right)
    _require(type(left) is type(right) and left == right)


def _stamp(work):
    _require(type(work) is _ValidationWork)
    evidence.capture._SharedLedger(work)
    limits = work.limits
    return (limits, (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes),
        (work.hash_work, work.input_bytes, work.json_nodes))


def _progress(work, before, *, neutral=False):
    after = _stamp(work)
    _require(after[0] is before[0] and after[1] == before[1]
        and all(type(value) is int and old <= value <= maximum for old, value, maximum
            in zip(before[2], after[2], after[1], strict=True))
        and (not neutral or after[2] == before[2]))
    return after


class _Guard:
    """One original window and parent allowance; retain at most one child pin."""

    def __init__(self, configured, *, purpose, live_window, original_deadline_ns, work, check):
        _require(type(purpose) is str and purpose in ("issue", "execute") and callable(check))
        role = contract.ISSUER_ROLE if purpose == "issue" else contract.EXECUTOR_ROLE
        self.configured = existing._configuration(configured, role)
        self.purpose, self.window = purpose, clock._validate(live_window)
        existing.authorization.shape._integer(original_deadline_ns, minimum=1)
        self.bound = min(self.window[4], original_deadline_ns)
        self.epoch_bound = min(self.window[3], self.window[0] + original_deadline_ns - self.window[1])
        _require(self.epoch_bound > 0)
        self.parent, self.parent_stamp = work, _stamp(work)
        self.child = self.child_stamp = None
        self.process = os.getpid(), threading.get_ident()
        self.external = check
        self.originals = (self.configured, self.purpose, self.window, self.bound,
            self.epoch_bound, self.parent, self.process, self.external)
        self.last_epoch, self.last_monotonic = self.window[0], self.window[2]
        self.busy = self.failed = self.closed = False

    def local(self, work):
        _require(not self.failed and not self.closed
            and (os.getpid(), threading.get_ident()) == self.process
            and all(actual is original for actual, original in zip(
                (self.configured, self.purpose, self.window, self.bound, self.epoch_bound,
                    self.parent, self.process, self.external), self.originals, strict=True)))
        self.parent_stamp = _progress(self.parent, self.parent_stamp)
        if work is not self.parent:
            if work is not self.child:
                self.child, self.child_stamp = work, _stamp(work)
            self.child_stamp = _progress(work, self.child_stamp)
        epoch = clock._check_on_work(self.window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        _require(type(epoch) is int and type(monotonic) is int
            and self.last_epoch <= epoch < self.epoch_bound
            and self.last_monotonic <= monotonic < self.bound)
        self.last_epoch, self.last_monotonic = epoch, monotonic
        return min(self.epoch_bound - epoch, self.bound - monotonic)

    def callback(self, work, call):
        try:
            self.local(work)
            _require(self.busy is False)
            self.busy = True
            parent = _stamp(self.parent)
            result = evidence.production._callback(work, call)
            _progress(self.parent, parent, neutral=True)
            self.local(work)
            _require(self.failed is False)
            return result
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def check(self, work):
        try:
            _require(self.callback(work, lambda: self.external(work)) is None)
        except BaseException:
            self.failed = True
            raise


def _transaction_row(row, work):
    """Bound and meter the actual nine-scalar pg_locks observation."""
    fields = observation._TRANSACTION_FIELDS
    _require(type(row) is dict and len(row) == len(fields)
        and all(type(name) is str and len(name) <= 64 for name in row) and set(row) == set(fields))
    for field in fields:
        value = row[field]
        if field in ("server_version_num", "backend_pid"):
            _require(type(value) is int and 1 <= value <= 2147483647)
        else:
            _require(type(value) is str and 1 <= len(value) <= 64
                and value.isascii() and "\x00" not in value)
    _require(160000 <= row["server_version_num"] < 170000
        and observation._VIRTUAL_TRANSACTION.fullmatch(row["virtual_transaction"]) is not None
        and row["transaction_isolation"] == "serializable"
        and row["transaction_read_only"] == "off" and row["transaction_deferrable"] == "off")
    for field in fields:
        scalar = row[field]
        if type(scalar) is int:
            work.charge(input_bytes=10, json_nodes=1)
            scalar = str(scalar)
        size = work.prepare_utf8(scalar)
        work.charge(input_bytes=8)
        _require(len(scalar.encode("ascii")) == size)
    work.prepare_copy(row)
    return tuple(row[field] for field in fields)


def _step_arguments(*, pending_decision_digest, ordinal, body_bytes, descriptor, deadline, work):
    existing.authorization.shape._digest(pending_decision_digest)
    _require(type(ordinal) is int and 0 <= ordinal < stream.MAX_STEPS
        and type(body_bytes) is bytes and 2 <= len(body_bytes) <= stream.MAX_BODY_BYTES
        and body_bytes.isascii() and type(descriptor) is dict
        and len(descriptor) == len(stream._DESCRIPTOR_FIELDS)
        and all(type(name) is str for name in descriptor)
        and set(descriptor) == set(stream._DESCRIPTOR_FIELDS))
    kind, phase, row, size, digest = (descriptor[name] for name in stream._DESCRIPTOR_FIELDS)
    _require(type(kind) is str and kind in ("phase-before", "row", "phase-after")
        and type(phase) is int and phase in stream.PHASES and type(row) is int
        and (0 <= row < 256 if kind == "row" else row == 0)
        and type(size) is int and size == len(body_bytes))
    existing.authorization.shape._digest(digest)
    work.charge(hashes=1, input_bytes=len(body_bytes))
    actual = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
    _same(actual, digest, work)
    encoded = work.wire(descriptor)
    _require(len(encoded) <= 512)
    work.charge(input_bytes=len(encoded) + len(body_bytes))
    return (pending_decision_digest, ordinal, encoded.decode("ascii"), body_bytes.decode("ascii"), deadline)


def _seal_readback(row, expected, work):
    existing.authorization.shape._object(row, existing._ISSUE_FIELDS, "maintenance seal readback")
    _require(all(type(row[name]) is type(value)
        and (len(row[name]) == len(value) if type(value) is str else row[name] == value)
        for name, value in expected.items()))
    _same(row, expected, work)


def _marker(value, pending, work):
    # The aggregate successor marker parser deliberately excludes this new
    # operation. Keep its closed scalar guards without widening that registry.
    _require(type(value) is str and 2 <= len(value) <= 4096 and value.isascii())
    work.charge(input_bytes=len(value))
    raw = value.encode("ascii")
    owned = existing.authorization.wire._decode_object(raw, work=work,
        maximum_bytes=4096, maximum_nodes=64, maximum_depth=2)
    fields = existing.markers
    existing.authorization.shape._object(owned, frozenset(fields.FIELDS), "maintenance committed marker")
    for name in fields.FIELDS:
        item = owned[name]
        if name in fields._COUNTERS:
            existing.authorization.shape._integer(item)
        else:
            _require(type(item) is str and 1 <= len(item) <= fields._SCALAR_BYTES[name]
                and item.isascii() and "\x00" not in item)
            if name in fields._DIGEST_FIELDS:
                existing.authorization.shape._digest(item)
    _require(owned["source_revision"] == existing.authority.SOURCE_REVISION
        and owned["operation"] == contract.OPERATION
        and fields._TOKEN.fullmatch(owned["database_id"]) is not None
        and owned["pending_sequence"] == owned["predecessor_sequence"] + 1
        and owned["fence"] >= 1)
    _same(owned["pending_decision_digest"], pending, work)
    existing.authorization.capability._canonical(raw, owned,
        evidence.capture._SharedLedger(work), 4096, 64)
    return raw


class _Session:
    """Held native resources; no public arbitrary query or connection method."""

    def __init__(self, guard, connection, cursor, transaction, physical, psycopg):
        self.binding = guard, connection, cursor, transaction, physical, psycopg
        self.original = self.binding
        self.transaction = None
        self.busy = self.done = False
        self.next_step, self.pending, self.result = 0, None, None

    def _native(self):
        _require(self.binding is self.original)
        guard, connection, cursor, transaction, physical, psycopg = self.binding
        _require(type(connection) is psycopg.Connection and type(cursor) is psycopg.Cursor
            and type(transaction) is psycopg.transaction.Transaction
            and cursor.connection is connection and cursor.closed is False
            and transaction.connection is connection and transaction.pgconn is physical
            and transaction._entered is True and transaction._exited is False
            and transaction._outer_transaction is True and transaction._stack_index == 0
            and type(connection._num_transactions) is int and connection._num_transactions == 1)
        native._require_connection(connection, physical, 2)
        _require(guard.failed is False and guard.closed is False)

    def _driver(self, work, call):
        guard = self.binding[0]
        guard.check(work)
        def invoke():
            self._native()
            value = call()
            self._native()
            return value
        result = guard.callback(work, invoke)
        guard.check(work)
        return result

    def _rows(self, sql, parameters, work):
        # These are actual emitted native query parameters, not claimed SQL
        # rows/acquisition metrics. The fixed result has at most one row.
        work.prepare_utf8(sql)
        work.prepare_copy(parameters)
        cursor = self.binding[2]
        result = self._driver(work, lambda: cursor.execute(sql, parameters))
        _require(result is cursor)
        rows = self._driver(work, lambda: cursor.fetchmany(2))
        _require(type(rows) is list and len(rows) <= 1)
        return rows

    def _probe(self, work):
        rows = self._rows(observation._TRANSACTION_SQL, (), work)
        _require(len(rows) == 1)
        actual = _transaction_row(rows[0], work)
        if self.transaction is None:
            self.transaction = actual
        else:
            _same(actual, self.transaction, work)

    def _enter(self, work, purpose=None):
        guard = self.binding[0]
        try:
            _require(self.busy is False and not self.done and not guard.failed
                and (purpose is None or guard.purpose == purpose))
            self.busy = True
            self._native()
            self._probe(work)
        except BaseException:
            guard.failed = True
            raise

    def _leave(self, work):
        self._probe(work)
        self.busy = False

    def check(self, active_work):
        try:
            self._enter(active_work)
            self.busy = False
        except BaseException:
            self.binding[0].failed = True
            raise

    def retain_step(self, *, pending_decision_digest, ordinal, body_bytes, descriptor, work):
        try:
            self._enter(work, "issue")
            _require(type(ordinal) is int and ordinal == self.next_step)
            if self.pending is not None:
                _same(pending_decision_digest, self.pending, work)
            parameters = _step_arguments(pending_decision_digest=pending_decision_digest,
                ordinal=ordinal, body_bytes=body_bytes, descriptor=descriptor,
                deadline=self.binding[0].epoch_bound, work=work)
            rows = self._rows(_STEP_SQL, parameters, work)
            _require(len(rows) == 1 and type(rows[0]) is dict and set(rows[0]) == {"step_ordinal"}
                and type(rows[0]["step_ordinal"]) is int)
            _same(rows[0]["step_ordinal"], ordinal, work)
            self.pending, self.next_step = pending_decision_digest, ordinal + 1
            self._leave(work)
        except BaseException:
            self.binding[0].failed = True
            raise

    def seal(self, *, packet_bytes, packet_digest, pending_decision_digest,
            issued_at_epoch_ns, expires_at_epoch_ns, work):
        try:
            self._enter(work, "issue")
            _require(12 <= self.next_step <= stream.MAX_STEPS and self.pending is not None
                and type(packet_bytes) is bytes and 2 <= len(packet_bytes) <= packet.MAX_BYTES
                and packet_bytes.isascii())
            _same(pending_decision_digest, self.pending, work)
            existing.authorization.shape._digest(packet_digest)
            for value in (issued_at_epoch_ns, expires_at_epoch_ns):
                existing.authorization.shape._integer(value, minimum=1)
            _require(issued_at_epoch_ns < expires_at_epoch_ns)
            actual = evidence.plan._frame(packet.IDENTITY_DOMAIN, (packet_bytes,), work)
            _same(actual, packet_digest, work)
            work.charge(input_bytes=len(packet_bytes))
            parameters = pending_decision_digest, packet_digest, packet_bytes.decode("ascii")
            rows = self._rows(_SEAL_SQL, parameters, work)
            _require(len(rows) == 1)
            expected = dict(pending_decision_digest=pending_decision_digest, packet_digest=packet_digest,
                issued_at_epoch_ns=issued_at_epoch_ns, expires_at_epoch_ns=expires_at_epoch_ns)
            _seal_readback(rows[0], expected, work)
            self._leave(work)
            self.result = existing.SuccessorCustodyObservation(**expected)
            self.done = True
            return self.result
        except BaseException:
            self.binding[0].failed = True
            raise

    def execute(self, *, pending_decision_digest, packet_digest, work):
        try:
            self._enter(work, "execute")
            for value in (pending_decision_digest, packet_digest):
                existing.authorization.shape._digest(value)
            rows = self._rows(_EXECUTE_SQL, (pending_decision_digest, packet_digest), work)
            _require(len(rows) == 1)
            existing.authorization.shape._object(rows[0], frozenset({"marker_json"}), "maintenance execution")
            raw = _marker(rows[0]["marker_json"], pending_decision_digest, work)
            self._leave(work)
            self.result = existing.SuccessorExecutionObservation(pending_decision_digest, packet_digest, raw)
            self.done = True
            return self.result
        except BaseException:
            self.binding[0].failed = True
            raise


def _run_on_configuration(configured, *, purpose, live_window, original_deadline_ns, work, operation, check):
    """Private genuine transaction owner, not an injectable SQL/opener API."""
    _require(callable(operation))
    guard = _Guard(configured, purpose=purpose, live_window=live_window,
        original_deadline_ns=original_deadline_ns, work=work, check=check)
    guard.check(work)
    bindings = existing.vector._source_bindings_on_work(work=work)
    _same(configured[6], bindings["queryManifestDigest"], work)
    import psycopg
    from psycopg.rows import dict_row
    from serverware import db

    remaining = guard.local(work)
    connect_timeout = min(configured[1], remaining // 1_000_000_000)
    _require(connect_timeout >= 2)
    options = "-c search_path=pg_catalog" + "".join(
        " -c " + name + "=" + str(remaining // 1_000_000) for name in existing._WAIT_TIMEOUTS)
    connection = native._connect(work, lambda: psycopg.connect(configured[0], row_factory=dict_row,
        connect_timeout=connect_timeout, autocommit=False, options=options))
    session = None
    try:
        guard.check(work)
        _require(type(connection) is psycopg.Connection)
        physical = guard.callback(work, lambda: native._connection_identity(connection, 0))
        with native._context(connection, work) as active_connection:
            guard.check(work)
            _require(active_connection is connection)
            cursor = guard.callback(work, connection.cursor)
            with native._context(cursor, work) as active_cursor:
                guard.check(work)
                _require(type(cursor) is psycopg.Cursor and active_cursor is cursor)
                transaction = guard.callback(work, connection.transaction)
                with native._context(transaction, work) as active_transaction:
                    guard.check(work)
                    _require(type(transaction) is psycopg.transaction.Transaction
                        and active_transaction is transaction)
                    # Native Transaction enters BEGIN. This is the first
                    # application SQL, before any identity/catalog reads.
                    work.prepare_utf8(existing._SET_TRANSACTION)
                    guard.callback(work, lambda: cursor.execute(existing._SET_TRANSACTION))
                    session = _Session(guard, connection, cursor, transaction, physical, psycopg)
                    session.check(work)

                    def admit():
                        session._probe(work)
                        rows = session._rows(native._IDENTITY_SQL, (), work)
                        _require(len(rows) == 1)
                        existing._identity(rows[0], configured)
                        work.prepare_scan(rows[0])
                        sql, parameters = challenge_execution_privilege_check(
                            role=configured[2], namespace="serverware_metadata")
                        _require(session._rows(sql, parameters, work) == [])
                        facade = db.PostgresMetadataConnection(connection)
                        manifest = session._driver(work,
                            lambda: db._policy_candidate_authority_structure_manifest(facade))
                        _, digest = session._driver(work,
                            lambda: db._policy_candidate_authority_manifest_digest(manifest))
                        _same(digest, configured[7], work)
                        session._probe(work)

                    work.prepare_utf8(existing._SEARCH_PATH)
                    session._driver(work, lambda: cursor.execute(existing._SEARCH_PATH))
                    admit()
                    parent = _stamp(work)
                    result = operation(session)
                    _progress(work, parent)
                    _require(not guard.failed and session.done and result is session.result)
                    admit()
                    guard.check(work)
                guard.check(work)
                native._require_connection(connection, physical, 0)
                _require(transaction._exited is True and connection._num_transactions == 0)
            guard.check(work)
            _require(cursor.closed is True)
            native._require_connection(connection, physical, 0)
        guard.check(work)
        _require(connection.closed is True)
        guard.closed = True
        return result
    except BaseException:
        guard.failed = True
        native._close_after_failure(connection)
        raise
    finally:
        guard.closed = True
