"""One physical native-row chunk on an original JIT read phase.

The codec supplies the only query and ordinal. This reader uses the caller's
actual collector, cursor and work, retains the same codec across callbacks,
and charges its complete canonical result frame. It creates no transaction,
clock, allowance, selected row or membership verdict. The source coordinator
still owes all aggregate limits and every reconstructed row's primary proof.
"""
from __future__ import annotations

from catchplate import authority_index_reader as physical
from catchplate import authority_jit_primary_chunks as codec
from catchplate import authority_transition_core as core
from catchplate.authority_query_read_work import _ValidationWork


READ_PROFILE = "catchplate.policyAuthorityJitPrimaryChunkRead/v1"
_MARKER_FIELDS = frozenset({"profile", "queryId", "keyColumn", "keyValue",
    "ordinal", "offset", "chunkBytes", "limit"})
_STATE_FIELDS = ("_query", "_held", "_chunks", "_total", "_native_bytes",
    "_data_chunks", "_complete", "_failed", "_finished")


def _require(condition):
    if not condition:
        raise physical.IndexReadError("JIT chunk read differs from its original source state")


def validate_chunk_read_trace(operation, table, marker):
    """Closed private JIT marker; this is not admission of generic row scans."""
    _require(type(operation) is str and operation == codec.OPERATION
        and type(table) is str and table in codec._QUERIES
        and type(marker) is dict and len(marker) == len(_MARKER_FIELDS)
        and set(marker) == _MARKER_FIELDS)
    name, column, fixed = codec._QUERIES[table]
    value, ordinal = marker["keyValue"], marker["ordinal"]
    _require(type(marker["profile"]) is str and marker["profile"] == READ_PROFILE
        and type(marker["queryId"]) is str and len(marker["queryId"]) <= 256
        and marker["queryId"] == core.query_program_id(codec.OPERATION, name, table)
        and type(marker["keyColumn"]) is str and marker["keyColumn"] == column
        and type(value) is str and 1 <= len(value) <= 1024
        and value == value.strip() and all(32 <= ord(c) != 127 for c in value)
        and len(value.encode("utf-8", "strict")) <= 1024
        and (fixed is None or value == fixed)
        and type(ordinal) is int and 0 <= ordinal < codec.MAX_ROW_DATA_CHUNKS
        and type(marker["offset"]) is int and marker["offset"] == ordinal * codec.CHUNK_BYTES
        and type(marker["chunkBytes"]) is int and marker["chunkBytes"] == codec.CHUNK_BYTES
        and type(marker["limit"]) is int and marker["limit"] == 1)


def _hold(chunks, work):
    _require(type(chunks) is codec.JitPrimaryRowChunks)
    chunks._local()
    _require(chunks._active is False and chunks._complete is False
        and chunks._finished is False and chunks._failed is False
        and type(chunks._held) is tuple and len(chunks._held) == 4
        and type(chunks._chunks) is list and len(chunks._chunks) < codec.MAX_ROW_DATA_CHUNKS
        and type(chunks._native_bytes) is int and type(chunks._data_chunks) is int
        and chunks._data_chunks == len(chunks._chunks)
        and chunks._native_bytes == len(chunks._chunks) * codec.CHUNK_BYTES
        and (chunks._total is None if not chunks._chunks else
            type(chunks._total) is int
            and chunks._native_bytes < chunks._total <= codec.MAX_ROW_NATIVE_BYTES))
    # Only bounded structural identities are copied, never the retained byte
    # contents. Every earlier unfinished chunk must be exactly one full page.
    work.charge(input_bytes=8 * (len(_STATE_FIELDS) + len(chunks._chunks) + 5),
        json_nodes=len(_STATE_FIELDS) + len(chunks._chunks) + 8)
    _require(all(type(item) is bytes and len(item) == codec.CHUNK_BYTES for item in chunks._chunks))
    return (tuple(getattr(chunks, name) for name in _STATE_FIELDS),
        tuple(chunks._chunks), chunks._held)


def _unchanged(chunks, held, work):
    state, parts, query_values = held
    work.charge(input_bytes=8 * (len(_STATE_FIELDS) + len(parts) + 8),
        json_nodes=len(_STATE_FIELDS) + len(parts) + 12)
    _require(chunks._active is True
        and all(getattr(chunks, name) is value for name, value in zip(_STATE_FIELDS, state))
        and len(chunks._chunks) == len(parts)
        and all(actual is original for actual, original in zip(chunks._chunks, parts))
        and all(actual is original for actual, original in zip((chunks._query.query_id,
            chunks._query.table, chunks._query.key_column, chunks._query.key_value), query_values)))
    chunks._local()


def _frame(rows, ordinal, work):
    if not rows:
        work.charge(input_bytes=2, json_nodes=1)
        return b"[]"
    record = rows[0]
    _require(type(record) is dict and len(record) == 4 and set(record) == codec._RECORD_FIELDS)
    total, received, offset, raw = (record["total_bytes"], record["chunk_ordinal"],
        record["chunk_offset"], record["chunk_hex"])
    _require(type(total) is int and 2 <= total <= codec.MAX_ROW_NATIVE_BYTES
        and type(received) is int and received == ordinal
        and type(offset) is int and offset == ordinal * codec.CHUNK_BYTES and offset < total
        and type(raw) is str and len(raw) == 2 * min(codec.CHUNK_BYTES, total - offset))
    size, _ = work.prepare_encoding(record)
    _require(size <= physical.MAX_PRIMARY_ROW_BYTES)
    wire = core.canonical_bytes(record)
    _require(len(wire) == size)
    return wire


def acquire_chunk(cursor, *, chunks, trace, work, acquisition) -> None:
    """Read and consume one original chunk; never start another read phase."""
    try:
        _require(type(work) is _ValidationWork and type(acquisition) is physical._ReadAcquisitionBudget)
        acquisition.require_idle(cursor, trace, work)
        _require(acquisition._read_phase_active is True
            and getattr(trace, "operation", None) == codec.OPERATION
            and getattr(trace, "_jit_successor", None) is True)
        held = _hold(chunks, work)
        sql, parameters, table, query_id, column, value, ordinal = chunks._next_query(work=work)
        work.prepare_copy((READ_PROFILE, query_id, column, value, ordinal,
            ordinal * codec.CHUNK_BYTES, codec.CHUNK_BYTES, 1))
        marker = dict(profile=READ_PROFILE, queryId=query_id, keyColumn=column,
            keyValue=value, ordinal=ordinal, offset=ordinal * codec.CHUNK_BYTES,
            chunkBytes=codec.CHUNK_BYTES, limit=1)
        # Reserve the fixed marker validation and trace copy before either is
        # called. Actual parameter UTF-8 framing is separately charged by read.
        work.prepare_scan(marker)
        work.prepare_copy(marker)
        validate_chunk_read_trace(trace.operation, table, marker)
        chunks._active = True
        _unchanged(chunks, held, work)
        with acquisition.scope(cursor, trace, work):
            rows = acquisition.read(table, marker, sql, parameters, 1)
            _unchanged(chunks, held, work)
            wire = _frame(rows, ordinal, work)
            acquisition.charge_primary_row(wire)
            _unchanged(chunks, held, work)
        acquisition.require_idle(cursor, trace, work)
        _require(acquisition._read_phase_active is True)
        _unchanged(chunks, held, work)
        # There is no external callback between clearing our lock and the
        # source codec's sole accept. The real codec itself locks reentry.
        chunks._active = False
        chunks.accept(rows, work=work)
        work.charge(input_bytes=8 * (len(held[1]) + 16), json_nodes=len(held[1]) + 20)
        _require(chunks._query is held[0][0] and chunks._held is held[0][1]
            and chunks._chunks is held[0][2] and chunks._failed is False
            and chunks._finished is False and chunks._active is False
            and all(actual is original for actual, original in zip(chunks._chunks, held[1])))
        if rows:
            record = rows[0]
            amount = len(record["chunk_hex"]) // 2
            _require(chunks.data_chunks == ordinal + 1 and len(chunks._chunks) == ordinal + 1
                and chunks.native_bytes == held[0][4] + amount
                and chunks._total == record["total_bytes"]
                and chunks.complete is (chunks.native_bytes == chunks._total)
                and chunks.next_ordinal == (None if chunks.complete else ordinal + 1))
        else:
            _require(ordinal == 0 and chunks._total == 0 and chunks.native_bytes == 0
                and chunks.data_chunks == 0 and not chunks._chunks
                and chunks.complete is True and chunks.next_ordinal is None)
    except BaseException:
        if type(acquisition) is physical._ReadAcquisitionBudget:
            acquisition.failed = True
        if type(chunks) is codec.JitPrimaryRowChunks:
            chunks._failed = True
        raise
    finally:
        if type(chunks) is codec.JitPrimaryRowChunks:
            chunks._active = False
