"""Native physical steps bound to the genuine seven-row JIT owner.

The caller retains its original native cursor/snapshot, clock, physical stage
collector and work. Source-owned bindings choose the only codec or selected
row/root. A chunk is acknowledged on that same stage work; a genuine raw
primary proof is returned for a distinct subsequent owner-admission stage.
No connection, clock, allowance, read phase, receipt or proof verdict is made.
"""
from __future__ import annotations

from catchplate import authority_index_reader as physical
from catchplate import authority_jit_primary_chunk_reader as chunk_reader
from catchplate import authority_jit_primary_rows as rows
from catchplate import authority_primary_original_reader as primary_reader
from catchplate.authority_query_read_work import _ValidationWork


def _require(condition):
    if not condition:
        raise physical.IndexReadError("JIT primary acquisition lost its original row owner")


def _admit(cursor, owner, trace, work, acquisition):
    _require(type(owner) is rows._JitPrimaryRows and type(work) is _ValidationWork
        and type(acquisition) is physical._ReadAcquisitionBudget)
    acquisition.require_idle(cursor, trace, work)
    _require(acquisition._read_phase_active is True
        and type(getattr(trace, "operation", None)) is str
        and trace.operation == chunk_reader.codec.OPERATION
        and getattr(trace, "_jit_successor", None) is True)


def _poison(owner, acquisition):
    if type(owner) is rows._JitPrimaryRows:
        owner._failed = True
    if type(acquisition) is physical._ReadAcquisitionBudget:
        acquisition.failed = True


def acquire_chunk(cursor, *, owner, trace, work, acquisition) -> None:
    """Consume and acknowledge one actual source chunk, never an external DTO."""
    try:
        _admit(cursor, owner, trace, work, acquisition)
        started = acquisition.sql_reads
        with owner._acquisition_binding(kind="chunk", work=work) as codec:
            _require(type(codec) is chunk_reader.codec.JitPrimaryRowChunks)
            chunk_reader.acquire_chunk(cursor, chunks=codec, trace=trace,
                work=work, acquisition=acquisition)
            _admit(cursor, owner, trace, work, acquisition)
            _require(acquisition.sql_reads - started == 1)
        # The owner releases only its physical binding here. There is no
        # external callback before the source progress join on the same work.
        owner.observe_acquired_chunk(work)
        _admit(cursor, owner, trace, work, acquisition)
    except BaseException:
        _poison(owner, acquisition)
        raise


def acquire_proof(cursor, *, owner, trace, work, acquisition) -> dict:
    """Read 65 real proof originals and replay membership, leaving admit due."""
    try:
        _admit(cursor, owner, trace, work, acquisition)
        started = acquisition.sql_reads
        with owner._acquisition_binding(kind="proof", work=work) as binding:
            _require(type(binding) is tuple and len(binding) == 2)
            selected, root = binding
            _require(type(selected) is dict and type(root) is primary_reader.primary.PrimaryRoot)
            proof = primary_reader.acquire_primary_proof(cursor,
                operation=chunk_reader.codec.OPERATION, selected_row=selected,
                primary_root=root, trace=trace, work=work, acquisition=acquisition)
            _admit(cursor, owner, trace, work, acquisition)
            _require(acquisition.sql_reads - started == primary_reader.SQL_READS_PER_PROOF
                and type(proof) is dict)
        # This is the actual raw evidence, not membership/current-root or
        # receipt authority. The original row-proof owner stage stays pending.
        return proof
    except BaseException:
        _poison(owner, acquisition)
        raise
