"""Two actual maintenance passes borrowing one native read-only snapshot.

The caller has already admitted the configuration, current root, PostgreSQL
role/TLS, outer transaction and original deadline. This owner supplies none of
that authority. It neither opens nor closes SQL resources, commits, retries,
renews a deadline, nor accepts proof results or a caller-selected schedule.
Every raw page comes from the source readers and reaches the real maintenance
chain. Second-pass retention is provisional until both complete manifests and
computed decisions match; a partial callback is never permission to execute.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import threading
import time

from catchplate import authority_challenge_chain as chains
from catchplate import authority_challenge_compound as compounds
from catchplate import authority_challenge_maintenance as maintenance
from catchplate import authority_challenge_manifest as manifests
from catchplate import authority_challenge_pass as passes
from catchplate import authority_index_reader as reader
from catchplate import authority_index_projection as projection
from catchplate import authority_revocation_root_reader as physical
from catchplate.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES, QueryReadValidationLimits,
    QueryReadValidationMetrics, _ValidationWork,
)
from catchplate.authority_store import current_root_observation as transaction_source


class ChallengeSnapshotError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengeSnapshotError("challenge maintenance snapshot custody changed")


@dataclass(frozen=True, slots=True)
class TraceMetrics:
    pass_ordinal: int
    fragments: int
    sql_reads: int
    chain_digest: str


@dataclass(frozen=True, slots=True)
class PassMetrics:
    pass_ordinal: int
    initial_work: QueryReadValidationMetrics
    stages: compounds.CompoundMetrics
    trace: TraceMetrics


@dataclass(frozen=True, slots=True)
class AcquisitionMetrics:
    passes: tuple[PassMetrics, PassMetrics]
    total_work: QueryReadValidationMetrics
    total_acquisition: compounds.AcquisitionMetrics


class _Result:
    def __init__(self, proxy, original):
        self._proxy, self._original = proxy, original

    def fetchmany(self, size):
        _require(self._original is self._proxy._owner._cursor)
        return self._proxy._owner._native_call(lambda: self._original.fetchmany(size))


class _Cursor:
    def __init__(self, owner):
        self._owner = owner

    def execute(self, sql, parameters):
        result = self._owner._native_call(lambda: self._owner._cursor.execute(sql, parameters))
        _require(result is self._owner._cursor)
        return _Result(self, result)


class MaintenanceAcquisition:
    """Single-use produce then retain; observations are not currentness."""

    def __init__(self, *, cursor, connection, transaction, context, check):
        import psycopg
        from psycopg.transaction import Transaction

        _require(type(connection) is psycopg.Connection and type(cursor) is psycopg.Cursor
            and type(transaction) is Transaction and callable(check))
        self._cursor, self._connection, self._transaction = cursor, connection, transaction
        self._physical = physical._connection_identity(connection, 2)
        self._check_callback = check
        self._held = cursor, connection, transaction, self._physical, check
        self._process = os.getpid(), threading.get_ident()
        self._failed = self._closed = self._busy = False
        self._state, self._clock = "new", 0
        self._original_transaction = None
        self._current = self._compound = self._chain = self._manifest = None
        self._proxy = _Cursor(self)
        self._proxy_original = self._proxy
        self._records = []
        self._initial = _ValidationWork(QueryReadValidationLimits())
        self._initial_limits = self._initial.limits
        try:
            self._context = manifests._context(context, self._initial)
            self._context_bytes = self._initial.wire(self._context)
            self._deadline = self._original_deadline = self._context["originalDeadlineNs"]
            self._local()
        except BaseException:
            self._failed = True
            raise

    def _local(self):
        try:
            cursor, connection, transaction, pgconn, callback = self._held
            _require(not self._closed and not self._failed
                and self._process == (os.getpid(), threading.get_ident())
                and self._cursor is cursor and self._connection is connection
                and self._transaction is transaction and self._physical is pgconn
                and self._check_callback is callback and self._proxy is self._proxy_original
                and self._proxy._owner is self and type(self._deadline) is int
                and self._deadline == self._original_deadline)
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

    def _context_check(self, work):
        self._local()
        raw = work.wire(self._context)
        work.charge(input_bytes=len(raw) + len(self._context_bytes))
        _require(raw == self._context_bytes)

    def _stamp(self):
        """Capture actual counters/identities, including inside a SQL read."""
        binding = self._current
        _require(type(binding) is tuple and len(binding) == 8)
        stage, work, limits, acquisition, acquisition_limits, identity, trace, ordinal = binding
        _require(type(stage) is compounds._Stage and stage._owner is self._compound
            and self._compound._active is stage and self._compound._position == ordinal
            and stage.work is work and stage._work is work and work.limits is limits
            and type(work) is _ValidationWork and limits == QueryReadValidationLimits()
            and stage.acquisition is acquisition and stage._acquisition is acquisition)
        values = work.hash_work, work.input_bytes, work.json_nodes
        maxima = MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES
        flags = ()
        entries = 0
        if acquisition is not None:
            _require(type(acquisition) is reader._ReadAcquisitionBudget
                and stage._cursor is self._proxy and stage._trace is trace
                and acquisition.cursor is self._proxy and acquisition.trace is trace
                and acquisition.work is work and acquisition.limits is acquisition_limits
                and acquisition_limits == reader._ReadAcquisitionLimits()
                and acquisition._identity is identity and acquisition.failed is False)
            flags = acquisition.active, acquisition._reading, acquisition._read_phase_active
            _require(all(type(flag) is bool for flag in flags))
            values += (acquisition.sql_reads, acquisition.returned_rows,
                acquisition.parameter_bytes, acquisition.transport_bytes)
            maxima += (reader.MAX_CUMULATIVE_SQL_READS,
                reader.MAX_CUMULATIVE_SQL_READS * reader.MAX_NODE_IDENTITIES,
                reader.MAX_PARAMETER_BYTES, reader.MAX_TRANSPORT_BYTES)
            entries = len(trace._entries)
        else:
            _require(stage._cursor is None and stage._trace is None and trace is None)
        _require(all(type(value) is int and 0 <= value <= maximum
            for value, maximum in zip(values, maxima, strict=True)))
        return binding, values, flags, entries

    def _native_call(self, callback):
        try:
            before = self._stamp()
            _require(before[0][3] is not None)
            before[0][3].require_active()
            self._local()
            result = callback()
            self._local()
            after = self._stamp()
            _require(after[0] is before[0] and after[1:] == before[1:])
            return result
        except BaseException:
            self._failed = True
            raise

    def _bind(self, stage):
        self._local()
        _require(type(stage) is compounds._Stage and stage._owner is self._compound)
        if self._current is None:
            acquisition = stage.acquisition
            self._current = (stage, stage.work, stage.work.limits, acquisition,
                acquisition.limits if acquisition is not None else None,
                acquisition._identity if acquisition is not None else None,
                stage._trace, self._compound._position)
        _require(self._current[0] is stage)
        stage.check()
        self._stamp()

    def _probe(self, stage):
        self._local()
        if stage.acquisition is None:
            return
        with stage.acquisition.scope(self._proxy, stage._trace, stage.work):
            observed = transaction_source._transaction(stage.acquisition, stage.work)
        _require(observed[4:6] == ("on", "on"))
        if self._original_transaction is None:
            self._original_transaction = observed
        else:
            stage.work.prepare_comparison(observed, self._original_transaction)
            _require(observed == self._original_transaction)
        self._local()

    def _check(self, stage):
        """Brackets source acquisition/callbacks; proof stages never probe."""
        try:
            self._bind(stage)
            self._context_check(stage.work)
            self._probe(stage)
            before = self._stamp()
            result = self._check_callback()
            self._local()
            after = self._stamp()
            _require(result is None and after[0] is before[0] and after[1:] == before[1:])
            self._context_check(stage.work)
            self._probe(stage)
        except BaseException:
            self._failed = True
            raise

    def _seal(self, stage):
        """Final in-stage probe then hash; no SQL after this fragment seal."""
        try:
            self._bind(stage)
            self._context_check(stage.work)
            self._probe(stage)
            acquisition = stage.acquisition
            if acquisition is not None:
                acquisition.require_idle(self._proxy, stage._trace, stage.work)
                entries = stage._trace._entries
                _require(len(entries) == acquisition.sql_reads
                    and all(entry["access"] == "read" for entry in entries))
                raw = stage.work.wire(entries)
                stage.work.charge(hashes=1, input_bytes=len(raw))
                fragment = "sha256:" + hashlib.sha256(raw).hexdigest()
                raw = stage.work.wire({"previous": self._trace_chain,
                    "passOrdinal": self._pass_ordinal, "stageOrdinal": self._compound._position,
                    "entries": len(entries), "fragmentDigest": fragment})
                stage.work.charge(hashes=1, input_bytes=len(raw))
                self._trace_chain = "sha256:" + hashlib.sha256(raw).hexdigest()
                self._trace_count += 1
                self._trace_reads += acquisition.sql_reads
            stage.check()
            self._stamp()
            self._current = None
        except BaseException:
            self._failed = True
            raise

    def _enter(self, state):
        self._local()
        if self._busy or self._state != state:
            self._failed = True
            raise ChallengeSnapshotError("challenge snapshot pass is repeated, nested or out of order")
        self._busy = True

    def _decision_bytes(self, decision, work):
        _require(type(decision) is chains.MaintenanceDecision)
        return work.wire({"replacementOverflow": decision.replacement_overflow,
            "pruningPending": decision.pruning_pending, "retainedLimit": decision.retained_limit,
            "primaryAfter": decision.primary_after.json_projection(),
            "countedAfter": [maintenance.head_wire(head) for head in decision.counted_after]})

    def _run(self, ordinal, initial, consume):
        self._local()
        _require(type(initial) is _ValidationWork and initial.limits == QueryReadValidationLimits()
            and self._current is None)
        self._context_check(initial)
        context = self._context
        initial.charge(hashes=maintenance.contract.TREE_DEPTH + 1)
        root = maintenance._root(context["primaryRoot"])
        captured = []
        for raw in context["indexHeads"]:
            initial.charge(hashes=projection.PROFILE_HASH_WORK)
            captured.append(maintenance._head(raw, projection.profile_for(raw["indexId"]), root, initial))
        self._chain = chains.MaintenanceChain(request_digest=context["requestDigest"],
            cutoff_us=context["cutoffUs"], retention_us=context["retentionUs"],
            maximum_retained=context["maximumRetained"], challenge_type=context["challengeType"],
            user_id=context["userId"], scope_key=context["scopeKey"], replace_scope=context["replaceScope"],
            primary_root=context["primaryRoot"], index_heads=tuple(captured), work=initial)
        self._manifest = manifests.MaintenanceManifest(context=context, work=initial)
        self._compound = compounds.MaintenanceCompound(request_digest=context["requestDigest"],
            original_deadline_ns=self._deadline, chain=self._chain)
        self._pass_ordinal, self._trace_count, self._trace_reads = ordinal, 0, 0
        seed = initial.wire({"schema": "catchplate.policyAuthorityChallengeSnapshotTrace/v1",
            "passOrdinal": ordinal, "context": context})
        initial.charge(hashes=1, input_bytes=len(seed))
        self._trace_chain = "sha256:" + hashlib.sha256(seed).hexdigest()

        def retain_original(phase, kind, index_id, page, raw, descriptor, stage):
            expected = stage.work.wire(descriptor)
            result = consume(phase, kind, index_id, page, raw, descriptor, stage)
            actual = stage.work.wire(descriptor)
            stage.work.charge(input_bytes=len(expected) + len(actual))
            _require(result is None and expected == actual)

        observed = passes.run_pass(operation=context["operation"], chain=self._chain,
            compound=self._compound, manifest=self._manifest, cursor=self._proxy,
            check=self._check, observe_original=retain_original if consume is not None else None,
            seal_stage=self._seal)
        self._local()
        _require(type(observed) is passes.MaintenancePassObservation and self._current is None
            and self._original_transaction is not None
            and self._trace_count == sum(stage.acquisition is not None for stage in observed.metrics.stages)
            and self._trace_reads == observed.metrics.total_acquisition.sql_reads)
        manifest_raw = initial.wire(observed.manifest)
        decision_raw = self._decision_bytes(observed.decision, initial)
        initial.charge(input_bytes=len(manifest_raw) + len(decision_raw))
        if ordinal == 0:
            self._first_manifest, self._first_decision = manifest_raw, decision_raw
        else:
            initial.charge(input_bytes=len(self._first_manifest) + len(self._first_decision))
            _require(manifest_raw == self._first_manifest and decision_raw == self._first_decision)
        self._context_check(initial)
        self._records.append(PassMetrics(ordinal, initial.metrics, observed.metrics,
            TraceMetrics(ordinal, self._trace_count, self._trace_reads, self._trace_chain)))
        return observed

    def produce(self):
        self._enter("new")
        try:
            _require(self._initial.limits is self._initial_limits)
            result = self._run(0, self._initial, None)
            self._state = "produced"
            return result
        except BaseException:
            self._failed = True
            self._retire_workers()
            raise
        finally:
            self._busy = False

    def retain(self, consume):
        self._enter("produced")
        try:
            _require(callable(consume) and self._initial.limits is self._initial_limits
                and self._initial.metrics == self._records[0].initial_work)
            initial = _ValidationWork(QueryReadValidationLimits())
            result = self._run(1, initial, consume)
            records = tuple(self._records)
            _require(len(records) == 2 and tuple(record.pass_ordinal for record in records) == (0, 1)
                and self._initial.limits is self._initial_limits
                and self._initial.metrics == records[0].initial_work)
            work = QueryReadValidationMetrics(*(sum(getattr(record.initial_work, name)
                + getattr(record.stages.total_work, name) for record in records)
                for name in ("hash_work", "input_bytes", "json_nodes")))
            physical_totals = compounds.AcquisitionMetrics(*(sum(getattr(record.stages.total_acquisition, name)
                for record in records) for name in
                ("sql_reads", "returned_rows", "parameter_bytes", "transport_bytes")))
            values = (work.hash_work, work.input_bytes, work.json_nodes,
                physical_totals.sql_reads, physical_totals.returned_rows,
                physical_totals.parameter_bytes, physical_totals.transport_bytes)
            maxima = tuple(2 * (compounds.MAX_STAGES + 1) * maximum
                for maximum in (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES)) + tuple(
                2 * compounds.MAX_ACQUISITION_STAGES * maximum for maximum in (
                    reader.MAX_CUMULATIVE_SQL_READS,
                    reader.MAX_CUMULATIVE_SQL_READS * reader.MAX_NODE_IDENTITIES,
                    reader.MAX_PARAMETER_BYTES, reader.MAX_TRANSPORT_BYTES))
            _require(all(type(value) is int and 0 <= value <= maximum
                for value, maximum in zip(values, maxima, strict=True)))
            self._local()
            self._state, self._closed = "retained", True
            return result, AcquisitionMetrics(records, work, physical_totals)
        except BaseException:
            self._failed = True
            self._retire_workers()
            raise
        finally:
            self._busy = False

    def _retire_workers(self):
        for worker in (self._compound, self._chain, self._manifest):
            if worker is not None:
                worker.close()

    def close(self):
        """Retire only this borrower; caller still owns every SQL resource."""
        self._closed = True
        self._retire_workers()
