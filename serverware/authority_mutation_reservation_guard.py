"""Private recognition of one genuine mutation reader's temporary hold.

This never installs/restores limits, refunds counters or authorizes a read.
The source caller creates the real collector and enters hold immediately around
its actual mutation reader. Only that collector's exact installed identity and
original-minus-pending formula may replace the original work ceiling. Generic
readers, SQL APIs and public proof/operation limits remain unchanged.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
import threading

from serverware import authority_index_mutation_reader as mutation
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits


class MutationReservationError(ValueError):
    pass


def _require(value):
    if not value:
        raise MutationReservationError("native mutation reservation lost its exact original owner")


def _limits(value):
    _require(type(value) is QueryReadValidationLimits)
    fields = value.max_hashes, value.max_input_bytes, value.max_json_nodes
    QueryReadValidationLimits(*fields)
    return fields


def _counters(work):
    values = work.hash_work, work.input_bytes, work.json_nodes
    _require(all(type(value) is int and 0 <= value <= maximum
        for value, maximum in zip(values, _limits(work.limits))))
    return values


class _MutationReservationGuard:
    def __init__(self, work):
        _require(type(work) is _ValidationWork)
        self._original = work, work.limits, _limits(work.limits), os.getpid(), threading.get_ident()
        self._held = self._original
        self._metrics = _counters(work)
        self._active = None
        self._engine = None
        self._progress = None
        self._used = self._failed = False

    def _inspect(self):
        _require(self._original is self._held and not self._failed)
        work, original, maximum, process, thread = self._original
        _require(type(work) is _ValidationWork and (process, thread) == (os.getpid(), threading.get_ident())
            and _limits(original) == maximum)
        metrics = _counters(work)
        _require(all(value >= previous for value, previous in zip(metrics, self._metrics)))
        self._metrics = metrics
        active = self._active
        if active is None:
            _require(work.limits is original)
            return work.limits, None, metrics

        collector, shared, identity, collector_limits, shared_limits = active
        _require(type(collector) is mutation._AcquisitionBudget
            and collector.work is work and collector.shared_acquisition is shared
            and collector._shared_identity is identity and identity[0] is shared and identity[1] is work
            and collector.limits is collector_limits and type(collector_limits) is mutation._AcquisitionLimits
            and type(shared) is mutation.transport._ReadAcquisitionBudget and shared.work is work
            and shared.limits is shared_limits and type(shared_limits) is mutation.transport._ReadAcquisitionLimits
            and shared.cursor is shared._identity[0] and shared.trace is shared._identity[1]
            and shared._identity[2] is work and collector.failed is False and shared.failed is False
            and all(type(value) is bool for value in (collector.active, shared.active,
                shared._reading, shared._read_phase_active)))
        _require((collector_limits.max_sql_reads, collector_limits.max_parameter_bytes,
            collector_limits.max_transport_bytes) == self._collector_maximum
            and (shared_limits.max_sql_reads, shared_limits.max_parameter_bytes,
                shared_limits.max_transport_bytes) == self._shared_maximum)
        mutation._AcquisitionLimits(*self._collector_maximum)
        mutation.transport._ReadAcquisitionLimits(*self._shared_maximum)
        pending = (collector._pending_parameters, collector._pending_work_bytes,
            collector._proof_bytes, collector._pending_nodes, collector._proof_hashes)
        _require(all(type(value) is int and value >= 0 for value in pending))
        engine = collector.engine
        if engine is None:
            _require(self._engine is None and collector.active is False
                and collector._entering_limits is None and collector._installed_limits is None
                and not any(pending) and work.limits is original)
            engine_values = ()
        else:
            _require(type(engine) is mutation.indexed._Budget and engine.work is work)
            if self._engine is None:
                self._engine = engine, engine.limits, mutation.indexed._copy(
                    engine.limits, mutation.indexed.IndexedMutationLimits)
            _require(engine is self._engine[0] and engine.limits is self._engine[1]
                and mutation.indexed._copy(engine.limits, mutation.indexed.IndexedMutationLimits)
                    == self._engine[2])
            engine_values = engine.hashes, engine.input_bytes, engine.json_nodes
            _require(all(type(value) is int and value >= 0 for value in engine_values))
            if collector.active:
                _require(shared.active is True and collector._entering_limits is original
                    and collector._installed_limits is work.limits)
                expected = (maximum[0] - collector._proof_hashes,
                    maximum[1] - collector._pending_work_bytes - collector._proof_bytes,
                    maximum[2] - collector._pending_nodes)
                _require(_limits(work.limits) == expected)
                if work.limits is original:
                    # begin() precedes preflight, or the exact hold is empty;
                    # an original ceiling cannot conceal outstanding holds.
                    _require(not any(pending))
            else:
                _require(collector._entering_limits is None and collector._installed_limits is None
                    and not any(pending) and work.limits is original)
        physical = (shared.sql_reads, shared.returned_rows, shared.parameter_bytes, shared.transport_bytes,
            collector.leaf_reads, collector.node_reads, collector.returned_rows,
            collector._sql_reads, collector._parameter_bytes, collector._transport_bytes)
        _require(all(type(value) is int and value >= 0 for value in physical)
            and shared.sql_reads <= shared_limits.max_sql_reads
            and shared.returned_rows <= 256 * shared_limits.max_sql_reads
            and shared.parameter_bytes <= shared_limits.max_parameter_bytes
            and shared.transport_bytes <= shared_limits.max_transport_bytes)
        progress = (*physical, *engine_values)
        if self._progress is not None:
            _require(len(progress) >= len(self._progress)
                and all(value >= previous for value, previous in zip(progress, self._progress)))
        self._progress = progress
        return (work.limits, active, metrics, engine, collector._entering_limits,
            collector._installed_limits, pending, physical, engine_values,
            collector.active, shared.active, shared._reading, shared._read_phase_active)

    def _snapshot(self):
        try:
            return self._inspect()
        except BaseException:
            self._failed = True
            raise

    @staticmethod
    def _unchanged(before, after):
        _require(len(before) == len(after) and before[0] is after[0] and before[1] is after[1]
            and before[2:] == after[2:])

    def current_limits(self):
        return self._snapshot()[0]

    @contextmanager
    def hold(self, collector):
        try:
            self.current_limits()
            _require(not self._used and self._active is None
                and type(collector) is mutation._AcquisitionBudget)
            work = self._original[0]
            shared = collector.shared_acquisition
            _require(type(shared) is mutation.transport._ReadAcquisitionBudget
                and collector.work is work and shared.work is work
                and collector.engine is None and collector.active is False and collector.failed is False
                and collector._entering_limits is None and collector._installed_limits is None
                and not any((collector._pending_parameters, collector._pending_work_bytes,
                    collector._proof_bytes, collector._pending_nodes, collector._proof_hashes)))
            shared.require_idle(shared.cursor, shared.trace, work)
            self._collector_maximum = (collector.limits.max_sql_reads,
                collector.limits.max_parameter_bytes, collector.limits.max_transport_bytes)
            self._shared_maximum = (shared.limits.max_sql_reads,
                shared.limits.max_parameter_bytes, shared.limits.max_transport_bytes)
            self._active = collector, shared, collector._shared_identity, collector.limits, shared.limits
            self._used = True
            self.current_limits()
            yield
            self.current_limits()
            _require(collector.engine is not None and collector.active is False
                and collector._entering_limits is None and collector._installed_limits is None
                and work.limits is self._original[1])
            shared.require_idle(shared.cursor, shared.trace, work)
            self._active = None
            self.current_limits()
        except BaseException:
            self._failed = True
            # The real reader's own finally restores its entering identity.
            # Do not override it, close resources or replace the first error.
            raise
