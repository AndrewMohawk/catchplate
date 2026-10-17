"""One JIT sparse frontier from the actual pending indexed engine stage.

The original caller owns the cursor, read phase, physical collector, work and
reservation guard. Only the exact indexed owner supplies targets and OLD leaf
images. This reader returns raw evidence, never a computed or admitted root.
The owner's subsequent genuine fold remains mandatory. No clock, connection,
transaction, read phase, replacement allowance or primary replay is created.
"""
from __future__ import annotations

from catchplate import authority_complete_query_batch as batch
from catchplate import authority_complete_read_write as read_write
from catchplate import authority_contract as contract
from catchplate import authority_index_mutation_reader as mutation
from catchplate import authority_index_reader as physical
from catchplate import authority_jit_indexed_phases as phases
from catchplate import authority_mutation_reservation_guard as reservation
from catchplate.authority_index_contract import KEY_NIBBLES
from catchplate.authority_query_read_work import _ValidationWork


def _require(condition):
    if not condition:
        raise physical.IndexReadError("JIT index read lost its source-owned pending phase")


def _construction(work, change_count):
    """Precharge source-bounded geometry, SQL and frontier scaffolding.

    These conservative construction units are distinct from the collector's
    actual parameter/returned-scalar counters and the later real fold. The
    shared helper builds proper ancestors, sixteen children per ancestor,
    sorted immediate siblings, fixed VALUES/marker batches and a sorted raw
    frontier. Each of at most two changes opens at most 159 new ancestors.
    Reserve those structures and bounded key-sort comparisons *before* the
    helper creates them; unused construction headroom is never refunded.
    """
    _require(type(change_count) is int and 0 <= change_count <= 2)
    opened = 1 + (KEY_NIBBLES - 1) * change_count
    siblings = 15 * opened + 1 - change_count
    frontier = siblings + change_count
    calls = ((change_count + mutation.MAX_IDENTITIES - 1) // mutation.MAX_IDENTITIES
        + (siblings + mutation.MAX_IDENTITIES - 1) // mutation.MAX_IDENTITIES)
    comparisons = sum(size * max(1, size.bit_length())
        for size in (opened, siblings, frontier))
    # Sixteen prefix-width structural passes cover temporary prefix strings,
    # containers, parameter/marker copies and fixed frame sizing. Sort units
    # use both 160-character operands, as other source-owned key sorts do.
    structures = opened + siblings + change_count
    work.charge(input_bytes=16384 + 16 * KEY_NIBBLES * structures
        + 2 * KEY_NIBBLES * comparisons + 256 * frontier + 8192 * calls,
        json_nodes=1024 + 32 * structures + comparisons + 512 * calls)


def acquire_index(cursor, *, owner, trace, work, acquisition,
                  reservation_guard) -> mutation.indexed.IndexedMutationInput:
    """Acquire exactly one pending profile on the original active read phase."""
    adapter = None
    try:
        _require(type(owner) is phases._JitIndexedPhases
            and type(work) is _ValidationWork
            and type(acquisition) is physical._ReadAcquisitionBudget
            and type(reservation_guard) is reservation._MutationReservationGuard
            and reservation_guard._original[0] is work)
        acquisition.require_idle(cursor, trace, work)
        _require(acquisition._read_phase_active is True
            and type(getattr(trace, "operation", None)) is str
            and trace.operation == phases.OPERATION
            and getattr(trace, "_jit_successor", None) is True)
        # This adapter shares the original physical/work objects. It is not
        # a fresh collector or an additional allowance.
        adapter = mutation._AcquisitionBudget(shared_acquisition=acquisition, work=work)
        with owner._acquisition_binding(work=work) as binding:
            item, profile, changes, delta, allowance, prepared = binding
            _construction(work, len(changes))
            with reservation_guard.hold(adapter):
                try:
                    with acquisition.scope(cursor, trace, work):
                        limits = read_write._write_limits(contract.operation_spec(phases.OPERATION),
                            batch._SharedLedger(work))
                        adapter.begin(limits)
                        start = acquisition.sql_reads, acquisition.parameter_bytes
                        plan = mutation._plan(item, profile, changes, delta, allowance, prepared,
                            adapter, earlier_reads=0, earlier_parameters=0)
                        adapter.preflight(plan.sql_reads, plan.parameter_bytes,
                            plan.proof_bytes, plan.proof_hashes,
                            parameter_work_bytes=plan.parameter_work_bytes,
                            parameter_nodes=plan.parameter_nodes)
                        owner._local()
                        raw = mutation._acquire_frontier(cursor, trace, plan, adapter)
                        owner._local()
                        _require(acquisition.sql_reads - start[0] == plan.sql_reads
                            and acquisition.parameter_bytes - start[1] == plan.parameter_bytes
                            and type(raw) is mutation.indexed.IndexedMutationInput
                            and raw.index_id == item.index_id
                            and raw.index_revision == item.index_revision
                            and raw.index_root is item.index_root)
                        # This is only the real helper's temporary conservative
                        # proof reservation. No fold has run or been debited.
                        adapter.release_proof_hold()
                        adapter.require_active()
                        adapter.active = False
                finally:
                    # Restore the exact entering ceiling before the guard and
                    # owner binding exit; never refund actual spent counters.
                    adapter.restore_limits()
            acquisition.require_idle(cursor, trace, work)
            _require(acquisition._read_phase_active is True)
        return raw
    except BaseException:
        if adapter is not None:
            adapter.failed = True
            adapter.active = False
        if type(acquisition) is physical._ReadAcquisitionBudget:
            acquisition.failed = True
        if type(owner) is phases._JitIndexedPhases:
            owner._failed = True
        if type(reservation_guard) is reservation._MutationReservationGuard:
            reservation_guard._failed = True
        raise
