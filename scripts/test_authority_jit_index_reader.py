"""UNRUN component controls: genuine JIT engines, synthetic cursor records.

The fixed SELECT responder is not PostgreSQL. Independent small trees commit
the records, while actual source projections, primary verification and sparse
folds run. No SQL installation/currentness/operation or compound admission is
claimed. Each reader uses its original caller-created physical stage budget.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_index_trace as trace_contract
from catchplate import authority_jit_index_reader as source
from test_authority_index_mutation_reader import Cursor, LEAF_FIELDS, NODE_FIELDS, frames
from test_authority_index_range import IndependentIndex
from test_authority_jit_indexed_phases import fixture, meter, primary
from test_authority_radix_proof import sql_digest, sql_json


class Store:
    def __init__(self, anchors, trees):
        self.leaves, self.nodes = {}, {}
        for head in anchors["counted_before_heads"]:
            profile = source.phases.projection.profile_for(head.index_id)
            tree, leaves = trees[profile.table], []
            for row in tree.rows.values():
                key_digest = tree.selected(tree.key(row))["keyDigest"]
                row_digest = sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1",
                    profile.table.encode("ascii"), sql_json(row))
                leaf = source.phases.projection.project_row(head.index_id, row,
                    primary_key_digest=key_digest, primary_row_digest=row_digest)
                if leaf is not None:
                    leaves.append(leaf)
                    self.leaves[head.index_id, leaf.key] = dict(zip(LEAF_FIELDS,
                        (head.index_id, profile.projection_digest, leaf.key, row["id"],
                         leaf.primary_key_digest, leaf.primary_row_digest, head.index_revision)))
            independent = IndependentIndex(leaves, profile=profile)
            if independent.root != head.index_root:
                raise AssertionError("independent stored population differs from the fixture head")
            for prefix, (digest, count) in independent.nodes.items():
                if prefix and count:
                    self.nodes[head.index_id, len(prefix), prefix] = dict(zip(NODE_FIELDS,
                        (head.index_id, profile.projection_digest, len(prefix), prefix,
                         digest, count, head.index_revision)))


class Trace:
    operation = source.phases.OPERATION
    _jit_successor = True

    def __init__(self, guard, callback=None):
        self.guard, self.callback, self.calls = guard, callback, []

    def read(self, table, key):
        self.guard.current_limits()
        trace_contract.validate_mutation_read_trace(self.operation, table, key)
        self.calls.append((table, copy.deepcopy(key)))
        if self.callback is not None:
            self.callback()
        self.guard.current_limits()


def prepared(*, selected=0):
    anchors, rows, proofs, mutations, inputs, trees = fixture()
    works = [meter() for _ in range(source.phases.STAGE_COUNT)]
    owner = source.phases._JitIndexedPhases(**anchors, work=works[0])
    primary(owner, rows, proofs, mutations, works)
    for ordinal in range(selected):
        owner.prepare_index(works[5 + 2 * ordinal])
        owner.fold_index(inputs[ordinal], work=works[6 + 2 * ordinal])
    observed = owner.prepare_index(works[5 + 2 * selected])
    return owner, works, inputs, Store(anchors, trees), observed


def session(store, *, work=None, limits=None, alter=None, callback=None):
    work = meter() if work is None else work
    guard = source.reservation._MutationReservationGuard(work)
    trace = Trace(guard, callback)
    cursor = Cursor(store, alter)
    acquisition = source.physical._ReadAcquisitionBudget(cursor, trace, work=work,
        limits=source.physical._ReadAcquisitionLimits() if limits is None else limits)
    return cursor, trace, work, acquisition, guard


def acquire(owner, values):
    cursor, trace, work, acquisition, guard = values
    with acquisition.read_phase(cursor, trace, work):
        return source.acquire_index(cursor, owner=owner, trace=trace, work=work,
            acquisition=acquisition, reservation_guard=guard)


def actual_frames(cursor, store):
    parameters = transport = rows = 0
    for kind, _sql, values in cursor.calls:
        parameters += frames(*values)
        if kind == "leaf":
            records = [store.leaves[values[-2], key] for key in values[:-2]
                if (values[-2], key) in store.leaves]
            fields = LEAF_FIELDS
        else:
            records = [store.nodes[values[-2], depth, prefix]
                for depth, prefix in zip(values[:-2:2], values[1:-2:2])
                if (values[-2], depth, prefix) in store.nodes]
            fields = NODE_FIELDS
        rows += len(records)
        transport += sum(frames(kind, *(row[name] for name in fields)) for row in records)
    return parameters, transport, rows


class JitIndexReaderControls(unittest.TestCase):
    def test_all_twelve_original_profiles_acquire_then_genuinely_fold(self):
        anchors, rows, proofs, mutations, _inputs, trees = fixture()
        works = [meter() for _ in range(source.phases.STAGE_COUNT)]
        owner = source.phases._JitIndexedPhases(**anchors, work=works[0])
        primary(owner, rows, proofs, mutations, works)
        store, acquired, empty = Store(anchors, trees), [], 0
        for ordinal in range(12):
            observed = owner.prepare_index(works[5 + 2 * ordinal])
            values = session(store)
            cursor, trace, work, physical, guard = values
            limits = work.limits
            raw = acquire(owner, values)
            self.assertEqual(owner._phase, 6 + 2 * ordinal)
            self.assertIsNotNone(owner._pending)
            self.assertIs(type(raw), source.mutation.indexed.IndexedMutationInput)
            self.assertEqual(raw.index_id, observed.index_id)
            self.assertEqual((physical.parameter_bytes, physical.transport_bytes, physical.returned_rows),
                actual_frames(cursor, store))
            self.assertEqual(physical.sql_reads, len(cursor.calls))
            self.assertEqual(len(trace.calls), len(cursor.calls))
            self.assertIs(work.limits, limits)
            self.assertEqual(work.hash_work, 0)  # Reservation is not a fabricated sparse fold.
            self.assertTrue(guard._used)
            self.assertFalse(guard._failed or physical.failed or physical.active)
            if not observed.changes:
                empty += 1
                self.assertEqual([item[0] for item in cursor.calls], ["node"])
                self.assertEqual(len(cursor.calls[0][2][:-2]), 32)  # All sixteen root children.
            owner.fold_index(raw, work=works[6 + 2 * ordinal])
            acquired.append(raw)
        self.assertGreaterEqual(empty, 2)
        actual = owner.finish(works[29])
        self.assertEqual(len(acquired), len(actual.result.after_heads))
        self.assertEqual(len(actual.stage_work), 30)
        self.assertEqual(actual.result.metrics.primary.mutations, 3)
        self.assertEqual(actual.result.metrics.new_row_hashes, 2)

    def test_requires_real_pending_owner_private_trace_and_original_read_phase(self):
        for defect in ("owner", "unprepared", "trace", "phase", "guard", "cursor"):
            owner, _works, _inputs, store, _observed = prepared()
            cursor, trace, work, physical, guard = session(store)
            if defect == "owner":
                owner = object()
            elif defect == "unprepared":
                owner._pending = None
            elif defect == "trace":
                trace._jit_successor = False
            elif defect == "guard":
                guard = source.reservation._MutationReservationGuard(meter())
            elif defect == "cursor":
                cursor = Cursor(store)
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                if defect == "phase":
                    source.acquire_index(cursor, owner=owner, trace=trace, work=work,
                        acquisition=physical, reservation_guard=guard)
                else:
                    with physical.read_phase(physical.cursor, trace, work):
                        source.acquire_index(cursor, owner=owner, trace=trace, work=work,
                            acquisition=physical, reservation_guard=guard)
            self.assertFalse(cursor.calls)
            self.assertTrue(physical.failed)

    def test_actual_old_leaf_must_be_present_with_exact_row_and_primary_identity(self):
        anchors, rows, proofs, mutations, inputs, _trees = fixture()
        probe_works = [meter() for _ in range(30)]
        probe = source.phases._JitIndexedPhases(**anchors, work=probe_works[0])
        primary(probe, rows, proofs, mutations, probe_works)
        selected = None
        for ordinal in range(12):
            observed = probe.prepare_index(probe_works[5 + 2 * ordinal])
            if any(change.before is not None for change in observed.changes):
                selected = ordinal
                break
            probe.fold_index(inputs[ordinal], work=probe_works[6 + 2 * ordinal])
        self.assertIsNotNone(selected)
        for defect in ("missing", "row", "identity", "overflow"):
            owner, _works, _inputs, store, _observed = prepared(selected=selected)
            def alter(kind, _index, _keys, records):
                if kind != "leaf":
                    return records
                self.assertTrue(records)
                if defect == "missing":
                    return []
                if defect == "row":
                    records[0]["primary_row_digest"] = "sha256:" + "a" * 64
                elif defect == "identity":
                    records[0]["primary_id"] = "not-the-held-original"
                else:
                    return records * 257
                return records
            values = session(store, alter=alter)
            original_limits = values[2].limits
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                acquire(owner, values)
            self.assertIs(values[2].limits, original_limits)
            self.assertTrue(owner._failed and values[3].failed and values[4]._failed)

    def test_pending_and_prepared_identity_changes_and_swallowed_reentry_poison(self):
        for defect in ("pending", "head", "count", "phase", "nested"):
            owner, _works, _inputs, store, _observed = prepared()
            values = session(store)
            cursor, trace, work, physical, guard = values
            original_limits = work.limits
            fired = False
            def alter(_kind, _index, _keys, records):
                nonlocal fired
                if fired:
                    return records
                fired = True
                if defect == "pending":
                    owner._pending = tuple(list(owner._pending))
                elif defect == "head":
                    object.__setattr__(owner._pending[0].index_root, "count",
                        owner._pending[0].index_root.count + 1)
                elif defect == "count":
                    counts = owner._prepared.primary_after_counts
                    name = next(iter(counts))
                    counts[name] += 1
                elif defect == "phase":
                    owner._phase += 2
                else:
                    try:
                        source.acquire_index(cursor, owner=owner, trace=trace, work=work,
                            acquisition=physical, reservation_guard=guard)
                    except ValueError:
                        pass
                return records
            cursor.alter = alter
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                acquire(owner, values)
            self.assertTrue(fired)
            self.assertIs(work.limits, original_limits)
            self.assertTrue(owner._failed and physical.failed and guard._failed)

    def test_original_work_and_physical_limits_are_not_replaced_or_reset(self):
        for defect in ("work", "reads", "parameters", "transport"):
            selected = 0
            if defect == "transport":
                anchors, *_rest = fixture()
                selected = next(index for index, head in enumerate(anchors["counted_before_heads"])
                    if head.index_root.count > 0)
            owner, _works, _inputs, store, _observed = prepared(selected=selected)
            # A pre-used original collector cannot gain even one more read.
            used = int(defect == "reads")
            work = meter(max_input_bytes=40000) if defect == "work" else meter()
            limits = source.physical._ReadAcquisitionLimits(**{
                "max_sql_reads" if defect == "reads" else
                "max_parameter_bytes" if defect == "parameters" else "max_transport_bytes": 1
            }) if defect != "work" else None
            values = session(store, work=work, limits=limits)
            values[3].sql_reads = used
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                acquire(owner, values)
            self.assertTrue(values[3].failed and owner._failed)
            if defect in ("work", "reads", "parameters"):
                self.assertFalse(values[0].calls)
            self.assertGreaterEqual(values[3].sql_reads, used)

    def test_construction_is_reserved_before_shared_geometry_and_cancellation_is_preserved(self):
        owner, _works, _inputs, store, _observed = prepared()
        values = session(store, work=meter(max_input_bytes=40000))
        with patch.object(source.mutation, "_plan") as planning:
            with self.assertRaises(ValueError):
                acquire(owner, values)
            planning.assert_not_called()
        class Cancel(BaseException):
            pass
        error = Cancel("synthetic cancellation")
        owner, _works, _inputs, store, _observed = prepared()
        def cancel():
            raise error
        values = session(store, callback=cancel)
        original_limits = values[2].limits
        with self.assertRaises(Cancel) as caught:
            acquire(owner, values)
        self.assertIs(caught.exception, error)
        self.assertIs(values[2].limits, original_limits)
        self.assertTrue(owner._failed and values[3].failed and values[4]._failed)
        parsed = ast.parse((Path(__file__).resolve().parents[1]
            / "catchplate/authority_jit_index_reader.py").read_text())
        forbidden = {"_ValidationWork", "QueryReadValidationLimits", "_ReadAcquisitionBudget",
            "_verify_primary", "_evaluate_one_index", "_acquire_indexed_primary_batch", "read_phase",
            "connect", "commit"}
        names = {node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            for node in ast.walk(parsed) if isinstance(node, ast.Call)
            and isinstance(node.func, (ast.Name, ast.Attribute))}
        self.assertFalse(names & forbidden)


if __name__ == "__main__":
    unittest.main()
