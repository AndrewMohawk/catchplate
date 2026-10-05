"""UNRUN component joins: real chunks, physical ledgers and primary proofs.

The cursor below is a deterministic reply double, not PostgreSQL. Source-flat
rows and independent trees come from the existing fixtures; their non-key
scalars are not a valid ES256 assertion. These controls establish no native
TLS/transaction/current-root custody, receipt, signed parent or deployment.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_primary_row_reader as source
from test_authority_jit_primary_rows import fixture, meter
from test_authority_jit_primary_chunks import native
from test_authority_primary_original_reader import Cursor as ProofCursor


class Trace:
    operation = source.chunk_reader.codec.OPERATION
    _jit_successor = True

    def __init__(self):
        self.records = []
        self.callback = lambda: None

    def read(self, table, marker):
        if marker.get("profile") == source.chunk_reader.READ_PROFILE:
            source.chunk_reader.validate_chunk_read_trace(self.operation, table, marker)
        elif table not in ("policy_authority_authenticated_leaves",
                "policy_authority_authenticated_tree_nodes"):
            raise AssertionError("unexpected component read table")
        self.records.append((table, copy.deepcopy(marker)))
        self.callback()


class Cursor(ProofCursor):
    """Actual fixed chunk SQL and original proof SELECTs over one small store."""
    def __init__(self, trees):
        super().__init__(trees)
        self.native_rows = {(table, tuple(sorted(tree.key(row).items()))): native(row)
            for table, tree in trees.items() for row in tree.rows.values()}
        self.callback = lambda: None
        self.chunk_transform = lambda records: records
        self.fetches = []

    def execute(self, sql, parameters):
        marker = re.search(r"(\d+)::pg_catalog.int4 AS chunk_ordinal", sql)
        if marker is None:
            result = super().execute(sql, parameters)
            self.callback()
            return result
        if self.pending is not None:
            raise AssertionError("synthetic chunk result was not consumed")
        table = re.search(r"FROM serverware_metadata\.([a-z_]+) AS target", sql).group(1)
        column = re.search(r"WHERE target\.([a-z_]+) IS NOT DISTINCT FROM %s", sql).group(1)
        if type(parameters) is not tuple or len(parameters) != 1 or "LIMIT 2" not in sql:
            raise AssertionError("chunk query changed its exact PK/sentinel shape")
        ordinal = int(marker.group(1))
        raw = self.native_rows.get((table, ((column, parameters[0]),)))
        offset = ordinal * source.chunk_reader.codec.CHUNK_BYTES
        records = [] if raw is None else [dict(total_bytes=len(raw), chunk_ordinal=ordinal,
            chunk_offset=offset, chunk_hex=raw[offset:offset + source.chunk_reader.codec.CHUNK_BYTES].hex())]
        self.calls.append((sql, parameters))
        self.pending = self.chunk_transform(records)
        self.callback()
        return self

    def fetchmany(self, maximum):
        self.fetches.append(maximum)
        return super().fetchmany(maximum)


def stage(cursor, trace, *, work=None, limits=None):
    work = meter() if work is None else work
    collector = source.physical._ReadAcquisitionBudget(cursor, trace, work=work,
        limits=source.physical._ReadAcquisitionLimits() if limits is None else limits)
    return work, collector


def read_chunk(owner, cursor, trace, *, work=None, limits=None):
    work, collector = stage(cursor, trace, work=work, limits=limits)
    with collector.read_phase(cursor, trace, work):
        result = source.acquire_chunk(cursor, owner=owner, trace=trace, work=work, acquisition=collector)
        if result is not None or not collector._read_phase_active:
            raise AssertionError("physical chunk returned authority or ended the original phase")
    return work, collector


def read_proof(owner, cursor, trace, *, work=None, limits=None):
    work, collector = stage(cursor, trace, work=work, limits=limits)
    with collector.read_phase(cursor, trace, work):
        proof = source.acquire_proof(cursor, owner=owner, trace=trace, work=work, acquisition=collector)
        if not collector._read_phase_active:
            raise AssertionError("physical proof ended the original phase")
    return proof, work, collector


def decode_first(owner, cursor, trace):
    owner.begin_row(meter())
    while owner.next_stage[0] == "row-chunk":
        read_chunk(owner, cursor, trace)
    return owner.decode_row(meter())


class JitPrimaryRowReaderControls(unittest.TestCase):
    def test_seven_rows_and_absence_use_real_physical_steps_then_distinct_admission(self):
        owner, request, roots, trees, queries = fixture(absent=("rbac_role_bindings",))
        cursor, trace = Cursor(trees), Trace()
        physical_reads = returned = 0
        for slot, query in enumerate(queries):
            owner.begin_row(meter())
            while owner.next_stage[0] == "row-chunk":
                work, collector = read_chunk(owner, cursor, trace)
                self.assertEqual(collector.sql_reads, 1)
                self.assertEqual(owner._meters[-1][0], work)
                physical_reads += collector.sql_reads
                returned += collector.returned_rows
                if query.table == "rbac_role_bindings":
                    self.assertEqual((collector.returned_rows, collector.transport_bytes), (0, 10))
            selected = owner.decode_row(meter())
            self.assertEqual(selected, trees[query.table].selected(query.absent_key))
            proof, proof_work, collector = read_proof(owner, cursor, trace)
            self.assertEqual(collector.sql_reads, 65)
            self.assertEqual(proof, trees[query.table].proof(selected))
            self.assertEqual(owner.next_stage, ("row-proof", slot))
            physical_reads += collector.sql_reads
            self.assertGreater(collector.parameter_bytes, 0)
            self.assertGreater(collector.transport_bytes, 0)
            owner.admit_proof(proof, meter())
            self.assertIsNot(owner._meters[-1][0], proof_work)
        result = owner.finish(meter())
        self.assertEqual((physical_reads, returned), (7 * 66, 6))
        self.assertEqual(len(cursor.calls), len(trace.records))
        self.assertEqual(result.request, request)
        self.assertEqual(result.business_before_roots, roots)
        self.assertEqual((len(result.context.selected_rows), len(result.before_proofs)), (7, 7))
        self.assertEqual(result.data_chunks, 6)

    def test_genuine_large_trust_row_uses_chunks_not_the_generic_row_select(self):
        owner, _, _, trees, queries = fixture(large={"webauthn_trust_publications":
            ("bundle_json", 2 * 1024 * 1024)})
        cursor, trace = Cursor(trees), Trace()
        trust_chunks = 0
        for query in queries:
            owner.begin_row(meter())
            while owner.next_stage[0] == "row-chunk":
                _, collector = read_chunk(owner, cursor, trace)
                self.assertLess(collector.transport_bytes, source.physical.MAX_PRIMARY_ROW_BYTES)
                trust_chunks += int(query.table == "webauthn_trust_publications")
            selected = owner.decode_row(meter())
            proof, _, collector = read_proof(owner, cursor, trace)
            self.assertEqual(collector.sql_reads, 65)
            self.assertEqual(proof, trees[query.table].proof(selected))
            owner.admit_proof(proof, meter())
        result = owner.finish(meter())
        self.assertGreater(trust_chunks, 16)
        self.assertGreater(result.native_bytes, 2 * 1024 * 1024)
        self.assertLessEqual(result.data_chunks, source.chunk_reader.codec.MAX_TOTAL_DATA_CHUNKS)
        self.assertFalse(any("END AS row_value" in sql for sql, _ in cursor.calls))

    def test_private_owner_phase_trace_and_existing_collector_are_mandatory(self):
        for defect in ("owner", "phase", "private", "operation", "cursor", "work"):
            owner, _, _, trees, _queries = fixture()
            owner.begin_row(meter())
            cursor, trace = Cursor(trees), Trace()
            work, collector = stage(cursor, trace)
            if defect == "owner": owner = object()
            elif defect == "private": trace._jit_successor = False
            elif defect == "operation": trace.operation = "webauthn.recovery.invalidate"
            other_cursor = Cursor(trees) if defect == "cursor" else cursor
            other_work = meter() if defect == "work" else work
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                if defect == "phase":
                    source.acquire_chunk(other_cursor, owner=owner, trace=trace, work=other_work,
                        acquisition=collector)
                else:
                    with collector.read_phase(cursor, trace, work):
                        source.acquire_chunk(other_cursor, owner=owner, trace=trace, work=other_work,
                            acquisition=collector)
            self.assertFalse(cursor.calls or other_cursor.calls)
            self.assertTrue(collector.failed)

    def test_native_callbacks_cannot_replace_owner_state_or_catch_reentry(self):
        for defect in ("codec", "slot", "phase", "trace", "nested"):
            owner, _, _, trees, _queries = fixture()
            owner.begin_row(meter())
            cursor, trace = Cursor(trees), Trace()
            work, collector = stage(cursor, trace)
            def change():
                if defect == "codec": owner._codec = object()
                elif defect == "slot": owner._slot += 1
                elif defect == "phase": owner._phase = "row-proof"
                elif defect == "trace": trace._jit_successor = False
                else:
                    try:
                        source.acquire_chunk(cursor, owner=owner, trace=trace, work=work,
                            acquisition=collector)
                    except ValueError:
                        pass
            cursor.callback = change
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                with collector.read_phase(cursor, trace, work):
                    source.acquire_chunk(cursor, owner=owner, trace=trace, work=work,
                        acquisition=collector)
            self.assertTrue(collector.failed and owner._failed)

    def test_proof_identity_tampering_false_absence_and_bad_tree_never_advance(self):
        for defect in ("selection", "root", "proof", "false-absence"):
            owner, _, _, trees, queries = fixture()
            cursor, trace = Cursor(trees), Trace()
            if defect == "false-absence":
                cursor.chunk_transform = lambda records: []
            selected = decode_first(owner, cursor, trace)
            if defect == "selection":
                cursor.callback = lambda: selected["row"].update(status="changed after capture")
            elif defect == "root":
                root = next(root for root in owner._roots if root.table == queries[0].table)
                cursor.callback = lambda: object.__setattr__(root, "root_digest", "sha256:" + "f" * 64)
            elif defect == "proof":
                cursor.transform = lambda sql, records: [] if "authenticated_tree_nodes " in sql else records
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                proof, _, _ = read_proof(owner, cursor, trace)
                # The physical reader copied the raw row before callbacks.
                # Its returned proof is not admission: the mandatory owner
                # stage rejects any in-place change to the exposed original.
                owner.admit_proof(proof, meter())
            self.assertEqual(owner._slot, 0)
            self.assertTrue(owner._failed)

    def test_proof_reborrow_and_admission_on_the_acquisition_work_are_refused(self):
        for defect in ("repeat", "same-work"):
            owner, _, _, trees, _queries = fixture()
            cursor, trace = Cursor(trees), Trace()
            decode_first(owner, cursor, trace)
            proof, work, _collector = read_proof(owner, cursor, trace)
            calls = len(cursor.calls)
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                if defect == "repeat": read_proof(owner, cursor, trace)
                else: owner.admit_proof(proof, work)
            self.assertEqual(len(cursor.calls), calls)
            self.assertTrue(owner._failed)

    def test_actual_physical_exhaustion_and_cancellation_poison_without_restart(self):
        for defect in ("chunk-limit", "proof-limit", "cancel"):
            owner, _, _, trees, _queries = fixture()
            cursor, trace = Cursor(trees), Trace()
            if defect == "proof-limit":
                decode_first(owner, cursor, trace)
                work, collector = stage(cursor, trace,
                    limits=source.physical._ReadAcquisitionLimits(max_sql_reads=64))
                reader = source.acquire_proof
            else:
                owner.begin_row(meter())
                work, collector = stage(cursor, trace,
                    limits=source.physical._ReadAcquisitionLimits(max_transport_bytes=1)
                        if defect == "chunk-limit" else None)
                reader = source.acquire_chunk
            class Cancel(BaseException):
                pass
            error = Cancel("synthetic cancellation")
            if defect == "cancel":
                def cancel(): raise error
                cursor.callback = cancel
            with self.subTest(defect=defect), self.assertRaises(Cancel if defect == "cancel" else ValueError) as caught:
                with collector.read_phase(cursor, trace, work):
                    reader(cursor, owner=owner, trace=trace, work=work, acquisition=collector)
            if defect == "cancel": self.assertIs(caught.exception, error)
            self.assertTrue(owner._failed and collector.failed)
            calls = len(cursor.calls)
            with self.assertRaises(ValueError):
                reader(cursor, owner=owner, trace=trace, work=work, acquisition=collector)
            self.assertEqual(len(cursor.calls), calls)
        parsed = ast.parse((Path(__file__).resolve().parents[1]
            / "serverware/authority_jit_primary_row_reader.py").read_text())
        calls = {node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            for node in ast.walk(parsed) if isinstance(node, ast.Call)
            and isinstance(node.func, (ast.Name, ast.Attribute))}
        self.assertFalse(calls & {"_ValidationWork", "QueryReadValidationLimits", "_ReadAcquisitionBudget",
            "read_phase", "connect", "commit", "admit_proof", "_membership"})


if __name__ == "__main__":
    unittest.main()
