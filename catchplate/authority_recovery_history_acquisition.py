"""Two bounded raw-history passes on one caller-owned PostgreSQL snapshot.

The caller admits TLS/database/role and statement deadlines before constructing
this owner. Neither callbacks nor returned observations supply that admission.
No connection, transaction, cursor lifetime, commit or authority clock is owned
here. The second pass retains bytes only after matching the first real replay.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import threading
import time

from catchplate import authority_index_reader as reader
from catchplate import authority_planner as planner
from catchplate import authority_recovery_history as history
from catchplate import authority_recovery_history_reader as capture
from catchplate import authority_revocation_root_reader as physical
from catchplate.authority_index_contract import CountedNode
from catchplate.authority_index_heads import CapturedIndexHead
from catchplate.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES,
    QueryReadValidationLimits, QueryReadValidationMetrics, _ValidationWork,
)
from catchplate.authority_store import current_root_observation as transaction_source


class HistoryAcquisitionError(ValueError):
    pass


def _require(value):
    if not value:
        raise HistoryAcquisitionError("recovery history acquisition custody changed")


@dataclass(frozen=True, slots=True)
class PhaseMetrics:
    pass_ordinal: int
    kind: str
    ordinal: int
    work: QueryReadValidationMetrics
    sql_reads: int
    returned_rows: int
    parameter_bytes: int
    transport_bytes: int
    trace_entries: int
    trace_digest: str


@dataclass(frozen=True, slots=True)
class AcquisitionMetrics:
    phases: tuple[PhaseMetrics, ...]
    total_work: QueryReadValidationMetrics
    sql_reads: int
    returned_rows: int
    parameter_bytes: int
    transport_bytes: int


class _Trace(planner.PlannerTrace):
    """A read fragment, deliberately not a completed global-audit trace."""

    def __init__(self, operation):
        super().__init__(operation=operation, _recovery_successor=True)

    def read(self, table, key):
        if table == transaction_source._TRANSACTION_TABLE:
            _require(type(key) is dict and key == {
                "profile": transaction_source._TRANSACTION_PROFILE, "rowLimit": 2})
            self._append("read", table, key)
        else:
            super().read(table, key)


class _Result:
    def __init__(self, phase, original):
        self._phase, self._original = phase, original

    def fetchmany(self, size):
        return self._phase.call(lambda: self._original.fetchmany(size))


class _Phase:
    def __init__(self, owner, pass_ordinal, kind, ordinal):
        self.owner = owner
        self.identity = (pass_ordinal, kind, ordinal)
        self.work = _ValidationWork(QueryReadValidationLimits())
        self.trace = _Trace(owner._operation)
        self.acquisition = reader._ReadAcquisitionBudget(self, self.trace, work=self.work)
        self._held = (self.work, self.work.limits, self.trace, self.acquisition,
            self.acquisition.limits, self.acquisition._identity)
        self._previous = (0,) * 7
        self.closed = False

    def stamp(self):
        work, limits, trace, acquisition, acquisition_limits, identity = self._held
        _require(not self.closed and self.work is work and work.limits is limits
            and limits == QueryReadValidationLimits() and self.trace is trace
            and self.acquisition is acquisition and acquisition.limits is acquisition_limits
            and acquisition_limits == reader._ReadAcquisitionLimits()
            and acquisition._identity is identity
            and acquisition.cursor is self and acquisition.trace is trace and acquisition.work is work
            and acquisition.failed is False
            and all(type(flag) is bool for flag in (
                acquisition.active, acquisition._reading, acquisition._read_phase_active)))
        values = (work.hash_work, work.input_bytes, work.json_nodes, acquisition.sql_reads,
            acquisition.returned_rows, acquisition.parameter_bytes, acquisition.transport_bytes)
        maxima = (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES, reader.MAX_CUMULATIVE_SQL_READS,
            reader.MAX_CUMULATIVE_SQL_READS * reader.MAX_NODE_IDENTITIES,
            reader.MAX_PARAMETER_BYTES, reader.MAX_TRANSPORT_BYTES)
        _require(all(type(value) is int and old <= value <= maximum
            for value, old, maximum in zip(values, self._previous, maxima)))
        self._previous = values
        return values, len(trace._entries), acquisition.active, acquisition._reading, acquisition._read_phase_active

    def call(self, callback):
        before = self.stamp()
        self.owner._local()
        try:
            result = callback()
            self.owner._local()
            _require(self.stamp() == before)
            return result
        except BaseException:
            self.owner._failed = True
            raise

    def execute(self, sql, parameters):
        return _Result(self, self.call(lambda: self.owner._cursor.execute(sql, parameters)))

    def finish(self):
        self.owner._local()
        self.acquisition.require_idle(self, self.trace, self.work)
        _require(not self.acquisition._reading and not self.acquisition._read_phase_active)
        entries = self.trace._entries
        _require(len(entries) == self.acquisition.sql_reads
            and all(entry["access"] == "read" for entry in entries))
        raw = self.work.wire(entries)
        self.work.charge(hashes=1, input_bytes=len(raw))
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        values, *_ = self.stamp()
        self.closed = True
        return PhaseMetrics(*self.identity, self.work.metrics, *values[3:], len(entries), digest)


class HistoryAcquisition:
    """Invocation-local borrowing; exact context check, production, retention."""

    def __init__(self, *, cursor, connection, transaction, operation, user_id,
                 primary_root, index_head, cutoff_us, maximum_count, maximum_bytes,
                 original_deadline_ns, check):
        import psycopg
        from psycopg.transaction import Transaction

        _require(type(connection) is psycopg.Connection and type(cursor) is psycopg.Cursor
            and type(transaction) is Transaction and callable(check)
            and type(original_deadline_ns) is int and 0 < original_deadline_ns < 2**63)
        self._cursor, self._connection, self._transaction = cursor, connection, transaction
        self._physical = physical._connection_identity(connection, 2)
        self._held = cursor, connection, transaction, self._physical, check, original_deadline_ns
        self._check = check
        self._deadline = original_deadline_ns
        self._process = os.getpid(), threading.get_ident()
        self._clock = 0
        self._failed = self._closed = False
        self._busy = True
        self._state = "new"
        self._original_transaction = None
        self._operation = operation
        self._phases = []
        self._first = _Phase(self, 0, "count", 0)
        try:
            self._local(initializing=True)
            context, self._root, self._profile, self._counted, self._whole = history._context(
                operation=operation, user_id=user_id, primary_root=primary_root, index_head=index_head,
                cutoff_us=cutoff_us, maximum_count=maximum_count, maximum_bytes=maximum_bytes,
                work=self._first.work)
            self._context = context
            head = context["indexHead"]
            self._head = CapturedIndexHead(head["indexId"], head["table"], head["countedProfile"],
                head["projectionDigest"], head["projectionManifestDigest"], head["indexRevision"],
                CountedNode(head["rootDigest"], head["rootCount"]))
            self._anchors = (self._operation, self._context, self._root, self._profile,
                self._counted, self._whole, self._head, self._first.work.wire(context))
            self._external(self._first, self._check)
            self._busy = False
        except BaseException:
            self._failed = True
            raise

    def _local(self, *, initializing=False):
        try:
            cursor, connection, transaction, pgconn, check, deadline = self._held
            _require(not self._closed and not self._failed
                and self._process == (os.getpid(), threading.get_ident())
                and self._cursor is cursor and self._connection is connection
                and self._transaction is transaction and self._physical is pgconn and self._check is check
                and type(self._deadline) is int and self._deadline == deadline)
            if not initializing:
                _require(all(actual is original for actual, original in zip(
                    (self._operation, self._context, self._root, self._profile,
                     self._counted, self._whole, self._head), self._anchors[:7])))
            physical._require_connection(connection, pgconn, 2)
            _require(cursor.connection is connection and cursor.closed is False
                and transaction.connection is connection and transaction.pgconn is pgconn
                and transaction._entered is True and transaction._exited is False
                and transaction._outer_transaction is True and transaction._stack_index == 0
                and connection._num_transactions == 1)
            now = time.monotonic_ns()
            _require(type(now) is int and self._clock <= now < self._deadline)
            self._clock = now
        except BaseException:
            self._failed = True
            raise

    def _probe(self, phase):
        self._local()
        with phase.acquisition.scope(phase, phase.trace, phase.work):
            observed = transaction_source._transaction(phase.acquisition, phase.work)
        _require(observed[4:6] == ("on", "on"))
        if self._original_transaction is None:
            self._original_transaction = observed
        else:
            phase.work.prepare_comparison(observed, self._original_transaction)
            _require(observed == self._original_transaction)
        self._local()

    def _external(self, phase, callback):
        self._context_check(phase)
        self._probe(phase)
        result = phase.call(callback)
        self._context_check(phase)
        self._probe(phase)
        return result

    def _context_check(self, phase):
        self._local()
        current = phase.work.wire(self._context)
        original = self._anchors[7]
        phase.work.charge(input_bytes=len(current) + len(original))
        _require(current == original)

    def _enter(self, state):
        self._local()
        if self._busy or self._state != state:
            self._failed = True
            raise HistoryAcquisitionError("recovery history pass is nested, repeated or out of order")
        self._busy = True

    def assert_context(self, *, operation, user_id, primary_root, index_head,
                       cutoff_us, maximum_count, maximum_bytes):
        """Compare independently held kernel anchors once; not admission."""
        self._enter("new")
        try:
            current, *_ = history._context(operation=operation, user_id=user_id,
                primary_root=primary_root, index_head=index_head, cutoff_us=cutoff_us,
                maximum_count=maximum_count, maximum_bytes=maximum_bytes, work=self._first.work)
            observed = self._first.work.wire(current)
            original = self._first.work.wire(self._context)
            self._first.work.charge(input_bytes=len(observed) + len(original))
            _require(observed == original)
            self._external(self._first, self._check)
            self._state = "checked"
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def _acquire(self, phase, *, expected=None):
        self._external(phase, self._check)
        arguments = dict(operation=self._operation, user_id=self._context["userId"],
            head=self._head, trace=phase.trace, work=phase.work, acquisition=phase.acquisition)
        if phase.identity[1] == "count":
            raw = capture.acquire_history_count(phase, **arguments)
        else:
            raw = capture.acquire_history_page(phase, primary_root=self._root,
                ordinal=phase.identity[2], authenticated_count=self._count, lower=self._lower, **arguments)
        self._external(phase, self._check)
        descriptor = history.body_descriptor(raw, work=phase.work)
        if expected is not None:
            phase.work.prepare_comparison(descriptor, expected)
            _require(descriptor == expected)
        value = history._body(raw, descriptor, phase.work)
        if phase.identity[1] == "count":
            history._closed(value, {"schema", "frontier"})
            _require(value["schema"] == history.COUNT_SCHEMA)
            count = history.counts._reconstruct_index_range_count(profile=self._profile,
                expected_root=self._counted, interval=self._whole,
                frontier=history._frontier(value["frontier"], count_only=True),
                limits=history.ranges.IndexRangeLimits(max_entries=history.count_reader.MAX_PREFIXES,
                    max_leaves=1, max_opened_nodes=history.count_reader.MAX_OPENED_NODES,
                    max_hashes=16 * history.count_reader.MAX_OPENED_NODES), work=phase.work).count
            _require(count <= self._context["maximumCount"])
            if phase.identity[0] == 1:
                _require(count == self._count)
            self._count, self._lower = count, self._whole.lower
        else:
            history._closed(value, history._PAGE_FIELDS)
            _require(value["schema"] == history.PAGE_SCHEMA and type(value["ordinal"]) is int
                and value["ordinal"] == phase.identity[2] and value["lower"] == self._lower)
            upper = value["upper"]
            _require(upper is None or capture._key(upper) and upper > self._lower)
            _require(upper is not None or phase.identity[2] == self._count - 1)
            self._lower = upper
        return raw, descriptor

    def produce(self):
        """Actually replay first-pass raw proofs; no observed-result input."""
        self._enter("checked")
        try:
            count_body, _ = self._acquire(self._first)
            self._next = 0
            def read(ordinal):
                _require(type(ordinal) is int and ordinal == self._next and ordinal < self._count)
                phase = _Phase(self, 0, "row", ordinal)
                raw, _ = self._acquire(phase)
                self._phases.append(phase.finish())
                self._next += 1
                return raw
            context = self._context
            manifest, observation = history.produce_history(count_body=count_body, read_page=read,
                operation=self._operation, user_id=context["userId"], cutoff_us=context["cutoffUs"],
                maximum_count=context["maximumCount"], maximum_bytes=context["maximumBytes"],
                primary_root=context["primaryRoot"], index_head=self._head)
            _require(self._next == self._count and (not self._count or self._lower == self._whole.upper))
            self._manifest = history._own(manifest, self._first.work)
            self._phases.insert(0, self._first.finish())
            self._first = None
            self._state = "produced"
            return manifest, observation
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def retain(self, consume):
        """Second pass only: deliver each exact matching body before discard."""
        self._enter("produced")
        try:
            _require(callable(consume))
            descriptors = (self._manifest["countBody"], *self._manifest["pages"])
            for position, descriptor in enumerate(descriptors):
                kind, ordinal = ("count", 0) if position == 0 else ("row", position - 1)
                phase = _Phase(self, 1, kind, ordinal)
                raw, actual = self._acquire(phase, expected=descriptor)
                exported = history._own(actual, phase.work)
                _require(self._external(phase, lambda: consume(kind, ordinal, raw, exported)) is None)
                self._external(phase, self._check)
                self._phases.append(phase.finish())
            _require(not self._count or self._lower == self._whole.upper)
            self._local()
            phases = tuple(self._phases)
            expected = tuple((run, kind, ordinal) for run in (0, 1)
                for kind, ordinal in (("count", 0), *(("row", index) for index in range(self._count))))
            _require(tuple((phase.pass_ordinal, phase.kind, phase.ordinal) for phase in phases) == expected)
            total = QueryReadValidationMetrics(
                sum(item.work.hash_work for item in phases), sum(item.work.input_bytes for item in phases),
                sum(item.work.json_nodes for item in phases))
            result = AcquisitionMetrics(phases, total,
                *(sum(getattr(item, name) for item in phases)
                  for name in ("sql_reads", "returned_rows", "parameter_bytes", "transport_bytes")))
            stage_count = 2 * (self._count + 1)
            maxima = (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES, reader.MAX_CUMULATIVE_SQL_READS,
                reader.MAX_CUMULATIVE_SQL_READS * reader.MAX_NODE_IDENTITIES,
                reader.MAX_PARAMETER_BYTES, reader.MAX_TRANSPORT_BYTES)
            values = (total.hash_work, total.input_bytes, total.json_nodes, result.sql_reads,
                result.returned_rows, result.parameter_bytes, result.transport_bytes)
            _require(all(type(value) is int and 0 <= value <= stage_count * maximum
                for value, maximum in zip(values, maxima)))
            self._state, self._closed = "retained", True
            return result
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def close(self):
        """Retire this borrower only, never the caller's database resources."""
        self._closed = True
