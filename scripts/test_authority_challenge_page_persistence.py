"""Pure owner/cleanup controls and actual source joins, not PostgreSQL success.

The explicit opener double exercises only acquisition/cleanup of a returned
handle. No writer admission, SQL result, TLS identity, successful store or proof
verdict is substituted. Native transaction/ACL behavior needs separate coverage.
"""
from __future__ import annotations

import ast
import copy
from dataclasses import FrozenInstanceError
import inspect
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_page_persistence as persistence
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_challenge_page_binding import arguments, descriptor


IDENTITY = ("catchplate_policy_authority_planner_writer", "CN=synthetic-writer", "01", "CN=synthetic-ca")


def owner(**changes):
    values = dict(writer_dsn="host=synthetic.invalid dbname=synthetic",
        connect_timeout_seconds=2, database_identity=IDENTITY)
    values.update(changes)
    return persistence.MaintenancePagePersistence(**values)


def meter():
    return _ValidationWork(QueryReadValidationLimits())


def active_guard(*, check=lambda: None, work=None):
    endpoint = owner()
    object.__setattr__(endpoint, "_active", True)
    current = meter() if work is None else work
    return endpoint, current, persistence._guard(endpoint, endpoint._configured,
        original_deadline_ns=1000, check=check, work=current)


class ChallengePagePersistenceControls(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(persistence.time, "monotonic_ns", return_value=10)
        self.clock = patcher.start()
        self.addCleanup(patcher.stop)

    def test_inert_exact_immutable_endpoint_and_planner_writer_identity(self):
        endpoint = owner()
        self.assertEqual(endpoint._configured[1:], (2, IDENTITY))
        self.assertFalse(endpoint._active)
        with self.assertRaises(FrozenInstanceError):
            endpoint._configured = ()
        for change in (dict(writer_dsn=""), dict(writer_dsn="host=x\nuser=y"),
                dict(writer_dsn="host=x\x00"), dict(connect_timeout_seconds=True),
                dict(connect_timeout_seconds=2.0), dict(connect_timeout_seconds=1),
                dict(connect_timeout_seconds=301), dict(database_identity=list(IDENTITY)),
                dict(database_identity=IDENTITY[:3]),
                dict(database_identity=("caller_role", *IDENTITY[1:]))):
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                owner(**change)
        tree = ast.parse(inspect.getsource(persistence.MaintenancePagePersistence.__init__).lstrip())
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "connect" for node in ast.walk(tree)))

    def test_context_descriptor_and_deadline_owned_before_open(self):
        values = arguments()
        work = values.pop("work")
        raw = b'{"synthetic":"original body"}'
        values.update(body_bytes=raw, descriptor=descriptor(raw))
        original = copy.deepcopy(values)
        held = persistence._owned_arguments(values, persist=True, work=work)
        values["context"]["indexHeads"].clear()
        values["descriptor"]["byteCount"] = 0
        self.assertEqual(held, original)
        self.assertIs(held["body_bytes"], raw)
        for changes in (dict(original_deadline_ns=1001), dict(original_deadline_ns=True),
                dict(phase_ordinal=8), dict(page_kind="caller-kind"),
                dict(body_bytes=bytearray(raw)), dict(descriptor={**descriptor(raw), "accepted": True})):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                persistence._owned_arguments({**original, **changes}, persist=True, work=meter())

    def test_original_clock_native_owner_and_work_cannot_be_replaced(self):
        for invalid_time in (1000, 1001, True, 9):
            self.clock.return_value = 10
            endpoint, work, guard = active_guard()
            guard()
            self.clock.return_value = invalid_time
            with self.subTest(time=invalid_time), self.assertRaises(ValueError):
                guard()
            self.assertTrue(endpoint._failed)
        self.clock.return_value = 10
        for change in (lambda endpoint, work: setattr(work, "input_bytes", 0),
                lambda endpoint, work: setattr(work, "limits", QueryReadValidationLimits()),
                lambda endpoint, work: object.__setattr__(endpoint, "_configured", tuple(list(endpoint._configured))),
                lambda endpoint, work: object.__setattr__(endpoint, "_active", False)):
            work = meter()
            work.charge(input_bytes=10)
            endpoint, _, guard = active_guard(work=work)
            guard()
            change(endpoint, work)
            with self.assertRaises(ValueError):
                guard()
        endpoint, work, guard = active_guard()
        with mock.patch.object(persistence.os, "getpid", return_value=-1), self.assertRaises(ValueError):
            guard()

    def test_external_check_none_no_spending_no_reentry_and_failure_poison(self):
        endpoint, work, guard = active_guard()
        guard()
        work.charge(input_bytes=3)  # Legitimate store work may spend between checks.
        guard()
        for callback in (lambda: True, lambda: work.charge(input_bytes=1)):
            endpoint, _, guard = active_guard(work=work, check=callback)
            with self.assertRaises(ValueError):
                guard()
            self.assertTrue(endpoint._failed)
        def interrupted():
            raise KeyboardInterrupt("synthetic first failure")
        endpoint, _, guard = active_guard(check=interrupted)
        with self.assertRaises(KeyboardInterrupt):
            guard()
        self.assertTrue(endpoint._failed)
        held = {}
        def reenter():
            with self.assertRaises(ValueError):
                held["guard"]()
        endpoint, _, guard = active_guard(check=reenter)
        held["guard"] = guard
        with self.assertRaises(ValueError):
            guard()
        selected = arguments()
        with self.assertRaises(ValueError):
            endpoint.read(**selected, check=lambda: None)

    def test_post_open_failure_closes_actual_returned_handle_preserving_first_failure(self):
        events = []
        class Handle:
            closed = False
            def close(self):
                events.append("close")
                raise RuntimeError("synthetic cleanup failure")
        returned = Handle()
        class Opener:
            def connect(self, dsn, **kwargs):
                events.append(("open", kwargs))
                return returned
        calls = 0
        original = KeyboardInterrupt("synthetic post-open deadline failure")
        def check():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise original
        row_factory = object()
        with self.assertRaises(KeyboardInterrupt) as caught:
            persistence._connect(owner()._configured, check=check, work=meter(),
                psycopg=Opener(), dict_row=row_factory)
        self.assertIs(caught.exception, original)
        self.assertEqual(events, [("open", {"row_factory": row_factory, "connect_timeout": 2,
            "autocommit": False, "options": "-c search_path=pg_catalog"}), "close"])

    def test_fixed_binding_and_real_writer_own_serializable_admission_exit_and_close(self):
        tree = ast.parse(inspect.getsource(persistence))
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_run")
        calls = [ast.unparse(node.func) for node in ast.walk(run) if isinstance(node, ast.Call)]
        self.assertIn("writer._run_on_connection", calls)
        self.assertNotIn("commit", calls)
        self.assertIn("binding.retain_original if persist else binding.read_original", ast.unparse(run))
        run_source = ast.unparse(run)
        self.assertLess(run_source.index("writer._run_on_connection"), run_source.rindex("check()"))
        writer_source = inspect.getsource(persistence.writer._run_on_connection)
        self.assertLess(writer_source.index("cursor.execute(_SET_TRANSACTION)"),
            writer_source.index("cursor.execute(_IDENTITY_SQL)"))
        self.assertIn("planner_writer_privilege_check", writer_source)
        self.assertIn("db.PostgresMetadataConnection(guarded)", writer_source)
        self.assertLess(writer_source.index("connection.closed"), writer_source.index("return result"))
        self.assertEqual(persistence.writer._SET_TRANSACTION,
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE")
        store_source = inspect.getsource(persistence.binding.store)
        self.assertIn("lifecycle._admit(connection, work)", store_source)
        for method in (persistence.MaintenancePagePersistence.persist, persistence.MaintenancePagePersistence.read):
            parameters = inspect.signature(method).parameters
            self.assertFalse({"connection", "operation", "sql", "opener"} & set(parameters))


if __name__ == "__main__":
    unittest.main()
