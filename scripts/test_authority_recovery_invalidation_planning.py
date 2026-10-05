#!/usr/bin/env python3
"""UNRUN native-owner components; no PostgreSQL/TLS acceptance claim.

The root/cutoff cursor is synthetic and uses independent primary-tree fixture
commitments. Clock doubles exercise guard failure only. Source-order controls
do not substitute for an actual entered native transaction or proof run.
"""
from __future__ import annotations

import ast
import copy
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_recovery_invalidation_planning as source
from test_authority_recovery_invalidation import fixture, meter


def digest(value):
    return "sha256:" + value * 64


def configuration():
    return dict(read_dsn="host=synthetic.invalid dbname=synthetic", connect_timeout_seconds=2,
        database_identity=("synthetic_planner", "CN=synthetic", "17", "CN=syntheticCA",
            digest("1"), digest("2"), digest("3")),
        terminal_retention_seconds=86400, maximum_retained=100000)


def guard(owner, check=lambda: None, work=None):
    return source._Guard(owner, owner._configured, (10000, 10, 11, 11000, 1010, 1000, 0),
        10000, 10900, check, work or meter())


class Cursor:
    """Only the fixed five source-root SELECTs and one scalar cutoff SELECT."""

    def __init__(self, call):
        self.values = {row["table"]: row for row in call["context"]["businessBeforeRoots"]}
        self.calls = []
        self.pending = None
        self.cutoff = 10

    def execute(self, sql, parameters):
        if self.pending is not None:
            raise AssertionError("synthetic cursor retained unread results")
        self.calls.append((sql, parameters))
        if sql == source._ROOT_SQL:
            table, limit = parameters
            if limit != 2 or table not in source._TABLES:
                raise AssertionError("root query was not source-fixed")
            row = self.values[table]
            self.pending = [dict(table_name=table, root_revision=row["rootRevision"],
                root_digest=row["rootDigest"], leaf_count=row["leafCount"], tree_depth=64,
                tree_radix=16, manifest_digest=digest("a"), updated_at_epoch_ns=1)]
        elif sql == source._CLOCK_SQL and parameters == ():
            self.pending = [{"cutoff_us": self.cutoff}]
        else:
            raise AssertionError("unexpected physical query")
        return self

    def fetchmany(self, maximum):
        result, self.pending = self.pending, None
        if result is None:
            raise AssertionError("no pending original")
        return copy.deepcopy(result[:maximum])


def root_capture(call, expected=None):
    cursor, trace, work = Cursor(call), source._SetupTrace(), meter()
    trace.ordinal = 5  # This component does not simulate catalog admission.
    budget = source.reader._ReadAcquisitionBudget(cursor, trace, work=work, limits=source._SETUP_LIMITS)
    with budget.read_phase(cursor, trace, work):
        source._anchors(cursor, trace, budget, work, manifest_digest=digest("a"),
            business=tuple(call["context"]["businessBeforeRoots"]) if expected is None else expected,
            authorization=())
    return cursor, trace, work, budget


class RecoveryInvalidationPlanningControls(unittest.TestCase):
    def test_inert_exact_configuration_and_fixed_policy(self):
        with patch.object(source.physical, "_connect", side_effect=AssertionError("no native I/O")):
            owner = source.RecoveryInvalidationReadPlanner(**configuration())
        self.assertEqual(owner._configured[3:], (86400, 100000))
        with self.assertRaises(FrozenInstanceError):
            owner._configured = ()
        for changed in (dict(connect_timeout_seconds=True), dict(connect_timeout_seconds=1),
                dict(connect_timeout_seconds=301), dict(read_dsn="host=x\nunsafe=y"),
                dict(terminal_retention_seconds=True), dict(terminal_retention_seconds=86399),
                dict(maximum_retained=99), dict(maximum_retained=1000001),
                dict(database_identity=(*configuration()["database_identity"][:6], "bad"))):
            with self.subTest(fields=tuple(changed)), self.assertRaises(ValueError):
                source.RecoveryInvalidationReadPlanner(**{**configuration(), **changed})

    def test_original_clock_work_and_cancellation_guard(self):
        owner = source.RecoveryInvalidationReadPlanner(**configuration())
        with patch.object(source.time, "monotonic_ns", return_value=20), \
                patch.object(source.clock, "_check_on_work", return_value=10020):
            held = guard(owner)
            held.check()
            held._original = (*held._original[:3], 11000, 1010, *held._original[5:])
            with self.assertRaises(ValueError):
                held.check()
            work = meter()
            work.charge(hashes=1)
            held = guard(owner, lambda: setattr(work, "hash_work", 0), work)
            with self.assertRaises(ValueError):
                held.check()
            held = guard(owner, lambda: held.check())
            with self.assertRaises(ValueError):
                held.check()
            class Cancel(BaseException):
                pass
            original = Cancel()
            def cancel():
                raise original
            held = guard(owner, cancel)
            with self.assertRaises(Cancel) as caught:
                held.check()
            self.assertIs(caught.exception, original)
            self.assertTrue(held._failed)
        with patch.object(source.time, "monotonic_ns", return_value=910), \
                patch.object(source.clock, "_check_on_work", return_value=10020):
            with self.assertRaises(ValueError):
                guard(owner).check()

    def test_physical_limits_cannot_be_reset_by_external_guard(self):
        work = meter()
        owner = source.RecoveryInvalidationReadPlanner(**configuration())
        budget = source.reader._ReadAcquisitionBudget(object(), object(), work=work,
            limits=source._SETUP_LIMITS)
        budget.sql_reads = 1
        held = guard(owner, lambda: setattr(budget, "sql_reads", 0), work)
        held.attach(budget)
        with patch.object(source.time, "monotonic_ns", return_value=20), \
                patch.object(source.clock, "_check_on_work", return_value=10020):
            with self.assertRaises(ValueError):
                held.check()
        self.assertTrue(held._failed)
        budget.sql_reads = True
        with self.assertRaises(ValueError):
            source._stamp(budget)

    def test_complete_setup_marker_schedule_and_exact_scalar_types(self):
        trace = source._SetupTrace()
        tx = {"profile": source.transaction_source._TRANSACTION_PROFILE, "rowLimit": 2}
        trace.read(source.transaction_source._TRANSACTION_TABLE, tx)
        for index, table in enumerate(source._CATALOG):
            trace.read(table, {"operation": source.acquisition.OPERATION, "setupOrdinal": index,
                "rowLimit": source._CATALOG_ROWS[index] + 1})
        for table in source._TABLES:
            trace.read(source.roots.PRIMARY_TABLE,
                {"profile": source._ROOT_PROFILE, "tableName": table, "rowLimit": 2})
        trace.read("pg_catalog.clock_timestamp", {"profile": source._CLOCK_PROFILE, "rowLimit": 2})
        for _ in range(3):
            trace.read(source.transaction_source._TRANSACTION_TABLE, tx)
        self.assertEqual(trace.ordinal, 14)
        with self.assertRaises(ValueError):
            trace.read(source.transaction_source._TRANSACTION_TABLE, tx)
        trace = source._SetupTrace()
        trace.ordinal = 1
        with self.assertRaises(ValueError):
            trace.read(source._CATALOG[0], {"operation": source.acquisition.OPERATION,
                "setupOrdinal": False, "rowLimit": 2})

    def test_actual_root_scalars_compare_independent_complete_inventory(self):
        call = fixture()
        cursor, trace, work, budget = root_capture(call)
        self.assertEqual(len(cursor.calls), 5)
        self.assertEqual(trace.ordinal, 10)
        self.assertEqual((budget.sql_reads, budget.returned_rows), (5, 5))
        self.assertGreater(budget.transport_bytes, 0)
        self.assertGreater(work.input_bytes, budget.transport_bytes)
        expected = tuple(copy.deepcopy(call["context"]["businessBeforeRoots"]))
        expected[0]["rootRevision"] += 1
        with self.assertRaises(ValueError):
            root_capture(call, expected)
        with self.assertRaises(ValueError):
            root_capture(call, expected[:-1])

    def test_cutoff_uses_original_epoch_and_does_not_renew_deadline(self):
        call = fixture()
        for cutoff, allowed in ((10, True), (11, False), (True, False)):
            cursor, trace, work = Cursor(call), source._SetupTrace(), meter()
            cursor.cutoff, trace.ordinal = cutoff, 10
            budget = source.reader._ReadAcquisitionBudget(cursor, trace, work=work, limits=source._SETUP_LIMITS)
            def run():
                with budget.read_phase(cursor, trace, work):
                    return source._cutoff(cursor, trace, budget, work, now=10000, deadline=11000, skew=0)
            if allowed:
                self.assertEqual(run().isoformat(), "1970-01-01T00:00:00.000010+00:00")
                self.assertEqual(budget.sql_reads, 1)
            else:
                with self.assertRaises(ValueError):
                    run()
                self.assertTrue(budget.failed)

    def test_two_actual_stage_counters_aggregate_once_without_new_work(self):
        work = meter()
        setup = source.reader._ReadAcquisitionBudget(object(), object(), work=work, limits=source._SETUP_LIMITS)
        proof = source.reader._ReadAcquisitionBudget(object(), object(), work=work)
        setup.sql_reads, setup.returned_rows, setup.parameter_bytes, setup.transport_bytes = 14, 16, 350, 12000
        proof.sql_reads, proof.returned_rows, proof.parameter_bytes, proof.transport_bytes = 67, 10, 11000, 95000
        self.assertEqual(source._physical_totals(setup, proof, work), (81, 26, 11350, 107000))
        self.assertGreater(work.input_bytes, 0)
        setup.returned_rows = 15
        with self.assertRaises(ValueError):
            source._physical_totals(setup, proof, work)
        with self.assertRaises(ValueError):
            source._physical_totals(proof, proof, work)

    def test_source_real_native_lifecycle_and_exact_four_probes(self):
        text = Path(source.__file__).read_text()
        tree = ast.parse(text)
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == "RecoveryInvalidationReadPlanner")
        acquire = next(node for node in owner.body if isinstance(node, ast.FunctionDef)
            and node.name == "acquire_originals")
        calls = [node for node in ast.walk(acquire) if isinstance(node, ast.Call)]
        attributes = [(node.lineno, node.func.attr) for node in calls if isinstance(node.func, ast.Attribute)]
        names = [(node.lineno, node.func.id) for node in calls if isinstance(node.func, ast.Name)]
        self.assertEqual(sum(name == "_transaction" for _, name in names), 4)
        self.assertEqual(sum(name == "_ReadAcquisitionBudget" for _, name in attributes), 2)
        self.assertEqual(sum(name == "_physical_totals" for _, name in names), 1)
        self.assertFalse(any(name in ("_ValidationWork", "_read_scope", "commit", "rollback")
            for _, name in (*attributes, *names)))
        first_sql = next(node for node in calls if isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute")
        self.assertEqual(ast.unparse(first_sql.args[0]), "physical._SET_TRANSACTION")
        self.assertLess(first_sql.lineno, min(line for line, name in names if name == "_transaction"))
        capture = next(line for line, name in attributes if name == "acquire_originals")
        self.assertLess(min(line for line, name in names if name == "_anchors"), capture)
        self.assertLess(min(line for line, name in names if name == "_cutoff"), capture)
        self.assertIn("transaction._outer_transaction is True", text)
        self.assertIn("transaction._stack_index == 0", text)
        self.assertIn("connection.closed is True", text)
        self.assertNotIn("trace.close(", text)


if __name__ == "__main__":
    unittest.main()
