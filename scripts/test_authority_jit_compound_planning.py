#!/usr/bin/env python3
"""UNRUN native-setup components/source controls, not PostgreSQL admission.

The cursor and clocks below are explicitly synthetic. No successful native
connection, witness, compound pass or authority result is simulated or claimed.
"""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_compound_planning as source
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits


def work():
    return _ValidationWork(QueryReadValidationLimits())


def digest(value):
    return "sha256:" + value * 64


def configuration():
    return dict(read_dsn="host=synthetic.invalid dbname=synthetic", connect_timeout_seconds=2,
        database_identity=("synthetic_planner", "CN=synthetic", "17", "CN=syntheticCA",
            digest("1"), digest("2"), digest("3")),
        assertion_policy={"rp_id": "synthetic.invalid", "origin": "https://synthetic.invalid",
            "maximum_assertion_age_seconds": 30})


def schedule(trace):
    transaction = (source.transaction_source._TRANSACTION_TABLE,
        {"profile": source.transaction_source._TRANSACTION_PROFILE, "rowLimit": 2})
    catalog = [(table, {"operation": source.OPERATION, "setupOrdinal": ordinal,
        "rowLimit": source.existing._CATALOG_ROWS[ordinal] + 1})
        for ordinal, table in enumerate(source.existing._CATALOG)]
    return [transaction, *catalog,
        (source.roots.PRIMARY_TABLE, {"profile": source._PRIMARY_PROFILE,
            "tableNames": list(trace.tables), "rowLimit": 9}),
        (source.heads.HEAD_TABLE, {"profile": source.heads.READ_PROFILE,
            "indexIds": list(trace.identities), "rowLimit": 13}),
        *[(table, {"profile": source._RBAC_PROFILE, "ordinal": ordinal,
            "rowLimit": source._RBAC_ROWS[ordinal] + 1})
            for ordinal, table in enumerate(source._RBAC_TABLES)],
        ("pg_catalog.clock_timestamp", {"profile": source._CLOCK_PROFILE, "rowLimit": 2}),
        transaction, transaction]


def trace():
    return source._SetupTrace(tuple(f"synthetic_table_{i}" for i in range(8)),
        tuple(f"synthetic_index_{i}" for i in range(12)))


class Cursor:
    """Only literal read/result framing; never a native connection double."""

    def __init__(self, responses):
        self.responses, self.executed, self.pending = list(responses), [], None

    def execute(self, sql, parameters):
        self.executed.append((sql, parameters))
        self.pending = self.responses.pop(0)
        return self

    def fetchmany(self, maximum):
        rows, self.pending = self.pending, None
        return rows[:maximum]


class JitCompoundPlanningControls(unittest.TestCase):
    def test_inert_configuration_is_owned_and_source_closed(self):
        args = configuration()
        with patch.object(source.physical, "_connect", side_effect=AssertionError("no native I/O")):
            planner = source.JitCompoundReadPlanner(**args)
        args["assertion_policy"]["rp_id"] = "changed.invalid"
        self.assertEqual(planner._configured[3][0], "synthetic.invalid")
        with self.assertRaises(FrozenInstanceError):
            planner._configured = ()
        for changes in (dict(connect_timeout_seconds=True), dict(connect_timeout_seconds=1),
                dict(connect_timeout_seconds=301), dict(read_dsn="host=x\nchanged=1"),
                dict(assertion_policy={**configuration()["assertion_policy"], "extra": 1}),
                dict(database_identity=(*configuration()["database_identity"][:6], "invalid"))):
            with self.subTest(fields=tuple(changes)), self.assertRaises(ValueError):
                source.JitCompoundReadPlanner(**{**configuration(), **changes})

    def test_exact_twelve_read_order_and_marker_types(self):
        held = trace()
        for table, key in schedule(held):
            held.read(table, key)
        self.assertEqual((held.position, held.catalog), (12, 4))
        with self.assertRaises(ValueError):
            held.read(*schedule(held)[-1])
        for ordinal in (0, 1, 5, 6, 7, 8, 9):
            held = trace()
            calls = schedule(held)
            for call in calls[:ordinal]:
                held.read(*call)
            with self.subTest(ordinal=ordinal), self.assertRaises(ValueError):
                held.read(*calls[ordinal + 1])
        held = trace()
        held.read(*schedule(held)[0])
        table, key = schedule(held)[1]
        key = {**key, "setupOrdinal": False}
        with self.assertRaises(ValueError):
            held.read(table, key)

    def test_actual_currentness_sql_is_retained_and_physically_accounted(self):
        module = Path(source.__file__).with_name("control_plane_rbac_currentness.py")
        tree = ast.parse(module.read_text())
        helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == "metadata_roots")
        actual = [node.args[0].value for node in ast.walk(helper)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute" and isinstance(node.args[0], ast.Constant)]
        self.assertEqual(tuple(actual), source._RBAC_SQL)
        rows = [{"table_name": name, "root_revision": 1, "root_digest": digest("4"), "leaf_count": 1}
            for name in ("rbac_authority_state", "rbac_role_bindings")]
        cursor = Cursor([[{"cluster_id": "17", "database": "synthetic"}], rows])
        meter, held = work(), trace()
        for call in schedule(held)[:7]:
            held.read(*call)
        collector = source.reader._ReadAcquisitionBudget(cursor, held, work=meter, limits=source._SETUP_LIMITS)
        with collector.read_phase(cursor, held, meter):
            adapter = source._RbacCursor(cursor, held, collector, meter)
            self.assertEqual(adapter.execute(source._RBAC_SQL[0]).fetchone()["cluster_id"], "17")
            retained = adapter.execute(source._RBAC_SQL[1]).fetchall()
            self.assertEqual(retained, rows)
            self.assertIsNot(retained[0], rows[0])
            self.assertEqual((adapter.ordinal, adapter.pending), (2, None))
        self.assertEqual((collector.sql_reads, collector.returned_rows), (2, 3))
        self.assertGreater(collector.transport_bytes, 0)
        self.assertGreater(meter.input_bytes, collector.transport_bytes)
        self.assertEqual(cursor.executed, [(sql, ()) for sql in source._RBAC_SQL])

    def test_rbac_extra_row_and_alternative_query_refuse(self):
        for extra, changed_sql in ((True, False), (False, True)):
            meter, held = work(), trace()
            for call in schedule(held)[:7]:
                held.read(*call)
            row = {"cluster_id": "17", "database": "synthetic"}
            cursor = Cursor([[row, row] if extra else [row]])
            collector = source.reader._ReadAcquisitionBudget(cursor, held, work=meter, limits=source._SETUP_LIMITS)
            with self.assertRaises(ValueError):
                with collector.read_phase(cursor, held, meter):
                    adapter = source._RbacCursor(cursor, held, collector, meter)
                    adapter.execute("SELECT true" if changed_sql else source._RBAC_SQL[0])
            self.assertEqual(len(cursor.executed), 0 if changed_sql else 1)

    def test_cutoff_and_transaction_tuple_cannot_be_replaced_or_aliased(self):
        self.assertEqual(source._cutoff_value({"cutoff_us": 100}, 100000, 101000, 0), 100)
        for value, now, deadline, skew in ((True, 100000, 101000, 0),
                (100, 100000, 100000, 0), (100, 100002, 101000, 1),
                (0, 100000, 101000, 100000)):
            with self.subTest(value=value, deadline=deadline), self.assertRaises(ValueError):
                source._cutoff_value({"cutoff_us": value}, now, deadline, skew)
        original = (160000, 17, "4/7", "serializable", "on", "on", "0", "0", "0")
        source._same_transaction(original, original)
        for position, value in ((0, 160000.0), (1, True), (2, "4/8"), (4, "off")):
            changed = (*original[:position], value, *original[position + 1:])
            with self.subTest(position=position), self.assertRaises(ValueError):
                source._same_transaction(changed, original)

    def test_original_parent_clock_and_callback_cancellation_remain_neutral(self):
        planner = source.JitCompoundReadPlanner(**configuration())
        meter = work()
        window = (10000, 10, 11, 11000, 1010, 1000, 0)
        with patch.object(source.existing.time, "monotonic_ns", return_value=20), \
                patch.object(source.existing.clock, "_check_on_work", return_value=10020):
            held = source.existing._Guard(planner, planner._configured, window, 10000, 10900,
                lambda: None, meter)
            before = meter.metrics
            held.check()
            self.assertEqual(before, meter.metrics)
            class Cancel(BaseException):
                pass
            error = Cancel()
            def cancel():
                raise error
            held = source.existing._Guard(planner, planner._configured, window, 10000, 10900,
                cancel, meter)
            with self.assertRaises(Cancel) as caught:
                held.check()
            self.assertIs(caught.exception, error)
            self.assertTrue(held._failed)

    def test_source_calls_genuine_pass_and_closes_before_output(self):
        tree = ast.parse(Path(source.__file__).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == "JitCompoundReadPlanner")
        acquire = next(node for node in owner.body if isinstance(node, ast.FunctionDef)
            and node.name == "acquire_pass")
        text = ast.unparse(acquire)
        self.assertIn("wrapped.execute(physical._SET_TRANSACTION)", text)
        self.assertLess(text.index("wrapped.execute(physical._SET_TRANSACTION)"),
            text.index("original_transaction ="))
        self.assertIn("rbac.require_roots(business_wire", text)
        self.assertIn("rbac_cursor.ordinal == 2", text)
        self.assertIn("roots._callback(work, compound.run_pass", text)
        self.assertIn("read_original=None", text)
        self.assertIn("type(result) is compound.JitPassObservation", text)
        self.assertLess(text.index("connection.closed is True"), text.index("return result"))
        self.assertIn("physical._close_after_failure(connection)", text)
        self.assertNotIn("_acquire_on_work", text)
        self.assertNotIn("_ValidationWork(", text)
        self.assertNotIn(".commit(", text)
        self.assertEqual(text.count("existing._transaction("), 3)


if __name__ == "__main__":
    unittest.main()
