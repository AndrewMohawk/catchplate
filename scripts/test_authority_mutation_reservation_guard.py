#!/usr/bin/env python3
"""UNRUN exact-reservation controls; no native SQL/proof success simulation.

The tests exercise the real collector's begin/preflight/release/restore and
actual work spending. They deliberately do not call a SQL driver or replace a
proof result. Source joins are inspected separately, not claimed executed.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_mutation_reservation_guard as source
from catchplate.authority_query_read_work import _ValidationWork, QueryReadValidationLimits


def fixture():
    work = _ValidationWork(QueryReadValidationLimits())
    shared = source.mutation.transport._ReadAcquisitionBudget(object(), object(), work=work)
    collector = source.mutation._AcquisitionBudget(shared_acquisition=shared, work=work)
    owner = source._MutationReservationGuard(work)
    primary = source.mutation.primary.PrimaryRadixLimits(max_selected_rows=1, max_mutations=1,
        max_proof_vectors=64, max_proof_child_slots=1024, max_hashes=202,
        max_input_bytes=work.limits.max_input_bytes, max_json_depth=128, max_json_nodes=1000000)
    limits = source.mutation.indexed.IndexedMutationLimits(primary,
        source.mutation.counted.IndexMutationLimits())
    return work, shared, collector, owner, limits


@contextmanager
def collector_phase(shared, collector, limits, work):
    """Component scope matching the genuine reader's unchanged cleanup path."""
    try:
        with shared.scope(shared.cursor, shared.trace, work):
            engine = collector.begin(limits)
            try:
                yield engine
            finally:
                collector.active = False
    finally:
        collector.restore_limits()


def hold(collector):
    collector.preflight(0, 0, 4096, 64, parameter_work_bytes=0, parameter_nodes=0)


class MutationReservationControls(unittest.TestCase):
    def test_real_begin_hold_release_restore_spends_original_work(self):
        work, shared, collector, owner, limits = fixture()
        original = work.limits
        self.assertIs(owner.current_limits(), original)
        with owner.hold(collector):
            with collector_phase(shared, collector, limits, work) as engine:
                self.assertIs(owner.current_limits(), original)
                hold(collector)
                narrowed = owner.current_limits()
                self.assertIs(narrowed, collector._installed_limits)
                self.assertIsNot(narrowed, original)
                self.assertEqual(narrowed.max_hashes, original.max_hashes - 64)
                self.assertEqual(narrowed.max_input_bytes, original.max_input_bytes - 4096)
                engine.input_work(17)
                engine.hash_work(1)
                self.assertIs(owner.current_limits(), narrowed)
                collector.release_proof_hold()
                self.assertIs(owner.current_limits(), work.limits)
                self.assertEqual(work.limits, original)
                self.assertIsNot(work.limits, original)
        self.assertIs(owner.current_limits(), original)
        self.assertEqual((work.hash_work, work.input_bytes), (1, 17))
        with self.assertRaises(ValueError):
            with owner.hold(collector):
                self.fail("one collector cannot be resumed")

    def test_only_installed_identity_and_exact_reservation_formula(self):
        for mode in ("equal-copy", "weaker", "wrong-formula", "early-original", "wrong-entering"):
            work, shared, collector, owner, limits = fixture()
            original = work.limits
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                with owner.hold(collector):
                    with collector_phase(shared, collector, limits, work):
                        hold(collector)
                        installed = owner.current_limits()
                        if mode == "equal-copy":
                            work.limits = QueryReadValidationLimits(installed.max_hashes,
                                installed.max_input_bytes, installed.max_json_nodes)
                        elif mode == "weaker":
                            work.limits = collector._installed_limits = QueryReadValidationLimits(
                                installed.max_hashes - 1, installed.max_input_bytes, installed.max_json_nodes)
                        elif mode == "wrong-formula":
                            collector._proof_bytes -= 1
                        elif mode == "early-original":
                            work.limits = collector._installed_limits = original
                        else:
                            collector._entering_limits = QueryReadValidationLimits()
                        owner.current_limits()
            self.assertTrue(owner._failed)

    def test_zero_hold_stale_pair_and_engine_owner_refused(self):
        for mode in ("stale-idle", "wrong-engine-work", "replaced-engine", "boolean-reservation"):
            work, shared, collector, owner, limits = fixture()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                with owner.hold(collector):
                    with collector_phase(shared, collector, limits, work):
                        owner.current_limits()
                        if mode == "stale-idle":
                            collector.active = False
                        elif mode == "wrong-engine-work":
                            collector.engine.work = _ValidationWork(QueryReadValidationLimits())
                        elif mode == "replaced-engine":
                            collector.engine = source.mutation.indexed._Budget(limits, work)
                        else:
                            collector._proof_hashes = False
                        owner.current_limits()

    def test_original_work_physical_counters_and_callback_snapshot(self):
        for mode in ("work-reset", "physical-reset", "limit-change", "callback-spend"):
            work, shared, collector, owner, limits = fixture()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                with owner.hold(collector):
                    with collector_phase(shared, collector, limits, work) as engine:
                        engine.input_work(17)
                        shared.sql_reads = 1
                        before = owner._snapshot()
                        if mode == "work-reset":
                            work.input_bytes = 0
                        elif mode == "physical-reset":
                            shared.sql_reads = 0
                        elif mode == "limit-change":
                            collector.limits = source.mutation._AcquisitionLimits()
                        else:
                            engine.input_work(1)
                        after = owner._snapshot()
                        owner._unchanged(before, after)

    def test_reentrancy_and_first_baseexception_remain_failed(self):
        work, shared, collector, owner, limits = fixture()
        with self.assertRaises(ValueError):
            with owner.hold(collector):
                try:
                    with owner.hold(collector):
                        self.fail("reentry")
                except ValueError:
                    pass
        self.assertTrue(owner._failed)
        work, shared, collector, owner, limits = fixture()
        original_limit = work.limits
        class Cancel(BaseException):
            pass
        original = Cancel()
        with self.assertRaises(Cancel) as caught:
            with owner.hold(collector):
                with collector_phase(shared, collector, limits, work):
                    hold(collector)
                    raise original
        self.assertIs(caught.exception, original)
        self.assertTrue(owner._failed)
        self.assertIs(work.limits, original_limit)
        with self.assertRaises(ValueError):
            owner.current_limits()

    def test_native_and_borrowed_join_is_only_the_real_collector(self):
        directory = Path(source.__file__).parent
        for name in ("authority_jit_assertion_planning.py", "authority_recovery_invalidation_planning.py"):
            text = (directory / name).read_text()
            tree = ast.parse(text)
            self.assertIn("_MutationReservationGuard(work)", text)
            self.assertIn("reservation_guard=guard._reservation", text)
            self.assertIn("self._reservation.current_limits()", text)
            self.assertIn("self._reservation._unchanged(reservation, self._reservation._snapshot())", text)
            self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_ValidationWork" for node in ast.walk(tree)))
        for name in ("authority_jit_assertion_acquisition.py", "authority_recovery_invalidation_acquisition.py"):
            text = (directory / name).read_text()
            tree = ast.parse(text)
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
            create = [node for node in calls if isinstance(node.func, ast.Attribute)
                and node.func.attr == "_AcquisitionBudget"]
            actual = [node for node in calls if isinstance(node.func, ast.Attribute)
                and node.func.attr == "_acquire_indexed_primary_batch"]
            self.assertEqual(len(create), 1)
            self.assertEqual(len(actual), 1)
            self.assertLess(create[0].lineno, actual[0].lineno)
            self.assertIn("reservation_guard.hold(mutation_acquisition)", text)
            self.assertIn("acquisition_budget=mutation_acquisition", text)
        text = Path(source.__file__).read_text()
        self.assertNotIn("work.limits =", text)
        self.assertNotIn("restore_limits()", text)


if __name__ == "__main__":
    unittest.main()
