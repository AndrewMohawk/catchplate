"""Fixed owner/cleanup controls only; no PostgreSQL acceptance is simulated."""
from __future__ import annotations

import ast
import copy
from dataclasses import FrozenInstanceError
import inspect
import unittest
from unittest import mock

from catchplate import authority_jit_original_persistence as persistence
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_jit_original_pages import binding


IDENTITY = ("catchplate_policy_authority_planner_writer", "CN=synthetic-writer", "01", "CN=synthetic-ca")


def owner(**changes):
    values = dict(writer_dsn="host=synthetic.invalid dbname=synthetic",
        connect_timeout_seconds=2, database_identity=IDENTITY)
    values.update(changes)
    return persistence.JitOriginalPersistence(**values)


def meter():
    return _ValidationWork(QueryReadValidationLimits())


def context():
    values = binding()
    return {name: values[name] for name in persistence.store.CONTEXT_FIELDS}


def active_guard(*, check=lambda: None, work=None):
    endpoint = owner()
    object.__setattr__(endpoint, "_active", True)
    current = meter() if work is None else work
    return endpoint, current, persistence._guard(endpoint, endpoint._configured,
        original_deadline_ns=1000, check=check, work=current)


class JitOriginalPersistenceControls(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(persistence.time, "monotonic_ns", return_value=10)
        self.clock = patcher.start()
        self.addCleanup(patcher.stop)

    def test_fixed_immutable_configuration_is_inert_and_writer_only(self):
        endpoint = owner()
        self.assertEqual(endpoint._configured[1:], (2, IDENTITY))
        with self.assertRaises(FrozenInstanceError):
            endpoint._configured = ()
        for changed in (dict(writer_dsn=""), dict(writer_dsn="host=x\nuser=y"),
                dict(writer_dsn="host=x\x00"), dict(connect_timeout_seconds=True),
                dict(connect_timeout_seconds=1), dict(connect_timeout_seconds=301),
                dict(database_identity=list(IDENTITY)),
                dict(database_identity=("caller_role", *IDENTITY[1:]))):
            with self.subTest(fields=list(changed)), self.assertRaises(ValueError):
                owner(**changed)
        text = inspect.getsource(persistence.JitOriginalPersistence.__init__)
        self.assertNotIn("connect(", text)
        self.assertNotIn("time.", text)

    def test_exact_context_and_actual_body_hash_are_owned_before_callbacks(self):
        original = context()
        raw = b"[]"
        desc = {"digest": binding(raw)["body_digest"], "byteCount": len(raw)}
        held, body = persistence._inputs(context=original, body_bytes=raw, descriptor=desc,
            persist=True, original_deadline_ns=1000, work=meter())
        expected = copy.deepcopy(held)
        original["page_kind"] = "caller"
        desc["byteCount"] = 0
        self.assertEqual(held, expected)
        self.assertIs(body, raw)
        for changes in (dict(original_deadline_ns=True), dict(body_bytes=bytearray(raw)),
                dict(descriptor={"digest": "sha256:" + "0" * 64, "byteCount": 2}),
                dict(descriptor={"digest": expected["body_digest"], "byteCount": 2, "accepted": True}),
                dict(context={**context(), "operation": "jit.decide"})):
            args = dict(context=context(), body_bytes=raw,
                descriptor={"digest": expected["body_digest"], "byteCount": 2},
                persist=True, original_deadline_ns=1000, work=meter())
            args.update(changes)
            with self.subTest(fields=list(changes)), self.assertRaises(ValueError):
                persistence._inputs(**args)
        read_context, no_body = persistence._inputs(context=context(), body_bytes=None,
            descriptor=None, persist=False, original_deadline_ns=1000, work=meter())
        self.assertEqual(read_context, context())
        self.assertIsNone(no_body)

    def test_guard_retains_clock_process_limits_and_monotone_original_work(self):
        for invalid in (1000, True, 9):
            self.clock.return_value = 10
            endpoint, work, guard = active_guard()
            guard()
            self.clock.return_value = invalid
            with self.assertRaises(ValueError):
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

    def test_external_check_is_neutral_none_and_poisoned_on_cancellation_or_reentry(self):
        work = meter()
        for check in (lambda: True, lambda: work.charge(input_bytes=1)):
            endpoint, _, guard = active_guard(work=work, check=check)
            with self.assertRaises(ValueError):
                guard()
            self.assertTrue(endpoint._failed)
        cancelled = KeyboardInterrupt("synthetic original cancellation")
        def cancel():
            raise cancelled
        endpoint, _, guard = active_guard(check=cancel)
        with self.assertRaises(KeyboardInterrupt) as caught:
            guard()
        self.assertIs(caught.exception, cancelled)
        self.assertTrue(endpoint._failed)
        held = {}
        def reenter():
            with self.assertRaises(ValueError):
                held["guard"]()
        endpoint, _, guard = active_guard(check=reenter)
        held["guard"] = guard
        with self.assertRaises(ValueError):
            guard()
        with mock.patch.object(persistence, "_run") as native:
            with self.assertRaises(ValueError):
                endpoint.read(context=context(), original_deadline_ns=1000, check=lambda: None, work=meter())
            native.assert_not_called()

    def test_post_open_failure_closes_returned_handle_and_preserves_first_failure(self):
        events = []
        class Handle:
            def close(self):
                events.append("close")
                raise RuntimeError("synthetic cleanup failure")
        returned = Handle()
        class Opener:
            def connect(self, dsn, **kwargs):
                events.append(("open", kwargs))
                return returned
        first = KeyboardInterrupt("synthetic post-open deadline refusal")
        calls = 0
        def check():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise first
        row_factory = object()
        with self.assertRaises(KeyboardInterrupt) as caught:
            persistence._connect(owner()._configured, check=check, work=meter(),
                psycopg=Opener(), dict_row=row_factory)
        self.assertIs(caught.exception, first)
        self.assertEqual(events, [("open", {"row_factory": row_factory, "connect_timeout": 2,
            "autocommit": False, "options": "-c search_path=pg_catalog"}), "close"])

    def test_source_calls_real_fixed_store_and_writer_and_checks_after_normal_close(self):
        tree = ast.parse(inspect.getsource(persistence))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        for name in ("store.persist_page", "store.read_original", "writer._run_on_connection",
                "store.lifecycle._guard", "reader._close_after_failure"):
            self.assertIn(name, calls)
        self.assertNotIn("_ValidationWork", calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in {"commit", "rollback", "sleep"} for name in calls))
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_run")
        body = ast.unparse(run)
        self.assertLess(body.index("writer._run_on_connection"), body.rindex("check()"))
        invoke = inspect.getsource(persistence._invoke)
        self.assertLess(invoke.index("_inputs("), invoke.index("guard()"))
        self.assertLess(invoke.index("guard()"), invoke.index("_run("))
        self.assertIn("_failed", invoke)


if __name__ == "__main__":
    unittest.main()
