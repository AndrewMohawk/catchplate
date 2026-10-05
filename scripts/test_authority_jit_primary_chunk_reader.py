#!/usr/bin/env python3
"""UNRUN physical-reader/codec controls with explicit cursor/trace doubles.

These execute the real collector, codec and extracted PlannerTrace.read when
authorized. They make no PostgreSQL, TLS, snapshot, primary-proof or complete
JIT capacity claim. No production registry is imported by this component.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping
import copy
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_primary_chunk_reader as source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_jit_primary_chunks import frames, native, query, row


class Trace:
    def __init__(self):
        self.operation, self._jit_successor = source.codec.OPERATION, True
        self.entries = []
        self.callback = lambda: None

    def read(self, table, marker):
        source.validate_chunk_read_trace(self.operation, table, marker)
        self.entries.append((table, dict(marker)))
        self.callback()


class Cursor:
    def __init__(self, records):
        self.records, self.calls, self.requested = records, [], []
        self.pending = None
        self.execute_callback = lambda: None
        self.fetch_callback = lambda: None

    def execute(self, sql, parameters):
        if self.pending is not None:
            raise AssertionError("synthetic result was not consumed")
        self.calls.append((sql, parameters))
        ordinal = int(re.search(r"(\d+)::pg_catalog.int4 AS chunk_ordinal", sql).group(1))
        self.pending = copy.deepcopy(self.records[ordinal])
        self.execute_callback()
        return self

    def fetchmany(self, maximum):
        self.requested.append(maximum)
        rows, self.pending = self.pending, None
        self.fetch_callback()
        return rows


def context(value=None, *, absent=False, limits=None, slot=4):
    value = row(slot) if value is None else value
    records = [[]] if absent else [[record] for record in frames(native(value))]
    cursor, trace = Cursor(records), Trace()
    work = _ValidationWork(QueryReadValidationLimits())
    chunks = source.codec.JitPrimaryRowChunks(query(slot), work=work)
    collector = source.physical._ReadAcquisitionBudget(cursor, trace, work=work,
        limits=limits or source.physical._ReadAcquisitionLimits())
    return cursor, trace, work, chunks, collector


def acquire(parts, *, work=None):
    cursor, trace, original_work, chunks, collector = parts
    source.acquire_chunk(cursor, chunks=chunks, trace=trace,
        work=original_work if work is None else work, acquisition=collector)


def real_trace_read():
    """Compile the complete actual method, not a rewritten gate or stub."""
    path = Path(__file__).resolve().parents[1] / "serverware/authority_planner.py"
    parsed = ast.parse(path.read_text())
    cls = next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == "PlannerTrace")
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "read")
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
        method], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {"Mapping": Mapping, "AuthorityPlannerError": ValueError,
        "authority_index_reader": source.physical}
    exec(compile(module, str(path), "exec"), namespace)
    return namespace["read"]


class JitPrimaryChunkReaderControls(unittest.TestCase):
    def test_multichunk_actual_parameters_records_and_single_original_ledger(self):
        expected = row(4)
        expected["bundle_json"] = "x" * (source.codec.CHUNK_BYTES + 17)
        parts = context(expected)
        cursor, trace, work, chunks, collector = parts
        with collector.read_phase(cursor, trace, work):
            while not chunks.complete:
                acquire(parts)
                self.assertTrue(collector._read_phase_active)
                self.assertFalse(collector.active)
        self.assertEqual(chunks.finish(work=work), expected)
        count = len(frames(native(expected)))
        self.assertEqual(collector.sql_reads, count)
        self.assertEqual(collector.returned_rows, count)
        self.assertEqual(cursor.requested, [2] * count)
        self.assertEqual(collector.parameter_bytes, count * (8 + len("publication-one")))
        expected_transport = sum(8 + len(source.core.canonical_bytes(record))
            for record in frames(native(expected)))
        self.assertEqual(collector.transport_bytes, expected_transport)
        self.assertGreater(expected_transport, 4096)
        self.assertEqual([entry[1]["ordinal"] for entry in trace.entries], list(range(count)))
        for ordinal, (sql, parameters) in enumerate(cursor.calls):
            self.assertEqual(parameters, ("publication-one",))
            self.assertIn("FROM serverware_metadata.webauthn_trust_publications AS target", sql)
            self.assertIn("LIMIT 2", sql)
            self.assertEqual(trace.entries[ordinal][1]["offset"], ordinal * source.codec.CHUNK_BYTES)

    def test_absence_is_one_real_read_and_nonzero_empty_frame(self):
        parts = context(absent=True)
        cursor, trace, work, chunks, collector = parts
        with collector.read_phase(cursor, trace, work):
            acquire(parts)
        self.assertIsNone(chunks.finish(work=work))
        self.assertEqual((collector.sql_reads, collector.returned_rows, collector.transport_bytes), (1, 0, 10))
        self.assertEqual(len(trace.entries), 1)
        self.assertEqual(cursor.requested, [2])
        self.assertEqual(chunks.native_bytes, 0)

    def test_real_trace_method_rejects_public_or_changed_marker(self):
        parts = context()
        cursor, trace, work, _, collector = parts
        with collector.read_phase(cursor, trace, work):
            acquire(parts)
        table, marker = trace.entries[0]
        read = real_trace_read()
        recorded = []
        target = SimpleNamespace(operation=source.codec.OPERATION, _jit_successor=True,
            allowed_reads={table}, _append=lambda *values: recorded.append(values))
        read(target, table, marker)
        self.assertEqual(recorded, [("read", table, marker)])
        target._jit_successor = False
        with self.assertRaises(ValueError):
            read(target, table, marker)
        target._jit_successor = True
        for field, bad in (("ordinal", True), ("offset", 1), ("chunkBytes", 1),
                ("limit", 2), ("queryId", "caller"), ("keyColumn", "scope"),
                ("keyValue", " has-space"), ("extra", "authority")):
            changed = dict(marker, **{field: bad})
            with self.subTest(field=field), self.assertRaises(ValueError):
                read(target, table, changed)
        with self.assertRaises(ValueError):
            source.validate_chunk_read_trace("webauthn.recovery.invalidate", table, marker)

    def test_callbacks_cannot_replace_or_advance_retained_state(self):
        expected = row(4)
        expected["bundle_json"] = "x" * (source.codec.CHUNK_BYTES + 17)
        for stage in ("trace", "execute", "fetch"):
            for fault in ("equal-bytes", "list", "query", "counter", "accept"):
                parts = context(expected)
                cursor, trace, work, chunks, collector = parts
                with self.assertRaises(ValueError):
                    with collector.read_phase(cursor, trace, work):
                        acquire(parts)
                        def corrupt():
                            if fault == "equal-bytes":
                                replacement = bytes(bytearray(chunks._chunks[0]))
                                self.assertIsNot(replacement, chunks._chunks[0])
                                chunks._chunks[0] = replacement
                            elif fault == "list":
                                chunks._chunks = list(chunks._chunks)
                            elif fault == "query":
                                object.__setattr__(chunks._query, "key_value", "other")
                            elif fault == "counter":
                                chunks._native_bytes = 0
                            else:
                                try:
                                    chunks.accept(cursor.records[1], work=work)
                                except ValueError:
                                    pass
                        if stage == "trace":
                            trace.callback = corrupt
                        elif stage == "execute":
                            cursor.execute_callback = corrupt
                        else:
                            cursor.fetch_callback = corrupt
                        acquire(parts)
                self.assertTrue(collector.failed, (stage, fault))
                self.assertTrue(chunks._failed, (stage, fault))

    def test_caught_reentry_cancellation_wrong_work_and_missing_phase_poison(self):
        for fault in ("reentry", "cancel", "work", "phase"):
            parts = context()
            cursor, trace, work, chunks, collector = parts
            def callback():
                if fault == "cancel":
                    raise KeyboardInterrupt("synthetic cancellation")
                try:
                    acquire(parts)
                except ValueError:
                    pass
            if fault in ("reentry", "cancel"):
                cursor.execute_callback = callback
            with self.assertRaises((ValueError, KeyboardInterrupt)):
                if fault == "phase":
                    acquire(parts)
                else:
                    with collector.read_phase(cursor, trace, work):
                        acquire(parts, work=_ValidationWork(QueryReadValidationLimits()) if fault == "work" else None)
            self.assertTrue(collector.failed)
            self.assertTrue(chunks._failed)
            if fault in ("phase", "work"):
                self.assertEqual(cursor.calls, [])

    def test_real_physical_bounds_and_corrupt_frames_fail_without_codec_progress(self):
        for fault in ("transport", "parameters", "duplicate", "offset", "null", "oversized", "sql"):
            limits = source.physical._ReadAcquisitionLimits(
                max_transport_bytes=1 if fault == "transport" else source.physical.MAX_TRANSPORT_BYTES,
                max_parameter_bytes=1 if fault == "parameters" else source.physical.MAX_PARAMETER_BYTES,
                max_sql_reads=1 if fault == "sql" else source.physical.MAX_CUMULATIVE_SQL_READS)
            expected = row(4)
            if fault == "sql":
                expected["bundle_json"] = "x" * (source.codec.CHUNK_BYTES + 17)
            parts = context(expected, limits=limits)
            cursor, trace, work, chunks, collector = parts
            if fault == "duplicate":
                cursor.records[0] *= 2
            elif fault == "offset":
                cursor.records[0][0]["chunk_offset"] = 1
            elif fault == "null":
                cursor.records[0][0]["chunk_hex"] = None
            elif fault == "oversized":
                cursor.records[0][0]["total_bytes"] = source.codec.MAX_ROW_NATIVE_BYTES + 1
            with self.assertRaises(ValueError):
                with collector.read_phase(cursor, trace, work):
                    acquire(parts)
                    if fault == "sql":
                        acquire(parts)
            self.assertTrue(collector.failed)
            self.assertTrue(chunks._failed)
            self.assertEqual(chunks._data_chunks, 1 if fault == "sql" else 0)


if __name__ == "__main__":
    unittest.main()
