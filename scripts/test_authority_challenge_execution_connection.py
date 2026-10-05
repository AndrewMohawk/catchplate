"""Pure/source native-owner controls; no PostgreSQL or successful proof double.

Clock doubles exercise only local allowance/lifetime checks. The cleanup double
exercises the real existing context wrapper's first-failure rule, not native
transaction admission. SQL/TLS/catalog/commit still require independent native
coverage; these controls make no database or authority claim.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_execution_connection as source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


DIGEST = "sha256:" + "1" * 64
OTHER = "sha256:" + "2" * 64
WINDOW = (100, 10, 10, 1100, 1010, 1000, 0)


def meter():
    return _ValidationWork(QueryReadValidationLimits())


def configuration(role=source.contract.ISSUER_ROLE):
    return ("host=synthetic.invalid dbname=synthetic", 2, role,
        "CN=synthetic-issuer", "01", "CN=synthetic-ca", DIGEST, OTHER)


def guard(work=None, check=lambda work: None, **changes):
    values = dict(purpose="issue", live_window=WINDOW, original_deadline_ns=510,
        work=meter() if work is None else work, check=check)
    values.update(changes)
    return source._Guard(configuration(), **values)


def transaction_row(**changes):
    result = dict(server_version_num=160000, backend_pid=42, virtual_transaction="12/34",
        transaction_isolation="serializable", transaction_read_only="off", transaction_deferrable="off",
        statement_timeout="500ms", lock_timeout="500ms", idle_in_transaction_session_timeout="500ms")
    result.update(changes)
    return result


def step_arguments(**changes):
    body = b'{"synthetic":"raw original, not a proof"}'
    values = dict(pending_decision_digest=DIGEST, ordinal=0, body_bytes=body,
        descriptor=dict(kind="phase-before", phaseOrdinal=0, rowOrdinal=0,
            byteCount=len(body), digest="sha256:" + hashlib.sha256(body).hexdigest()),
        deadline=600, work=meter())
    values.update(changes)
    return values


class ChallengeExecutionConnectionControls(unittest.TestCase):
    def setUp(self):
        # No DB or proof admission is patched. These are only local guard tests.
        self.epoch = mock.patch.object(source.clock, "_check_on_work", return_value=101).start()
        self.monotonic = mock.patch.object(source.time, "monotonic_ns", return_value=11).start()
        self.addCleanup(mock.patch.stopall)

    def test_exact_configuration_purpose_and_original_derived_deadlines(self):
        selected = guard()
        self.assertEqual((selected.bound, selected.epoch_bound), (510, 600))
        self.assertIs(selected.window, WINDOW)
        selected.check(selected.parent)
        for changes in (dict(purpose="read"), dict(purpose=True), dict(purpose="execute"),
                dict(original_deadline_ns=True), dict(original_deadline_ns=0),
                dict(live_window=list(WINDOW))):
            with self.subTest(changes=list(changes)), self.assertRaises((ValueError, RuntimeError)):
                guard(**changes)
        for config in (list(configuration()), configuration()[:7],
                (*configuration()[:2], "caller-role", *configuration()[3:])):
            with self.assertRaises((ValueError, RuntimeError)):
                source._Guard(config, purpose="issue", live_window=WINDOW,
                    original_deadline_ns=510, work=meter(), check=lambda work: None)
        self.monotonic.return_value = 510
        with self.assertRaises(ValueError):
            selected.check(selected.parent)
        self.assertTrue(selected.failed)

    def test_active_child_and_suspended_parent_callbacks_are_neutral_and_poison(self):
        for target in ("child", "parent"):
            parent, child = meter(), meter()
            selected = guard(parent)
            def spend():
                (child if target == "child" else parent).charge(input_bytes=1)
            with self.subTest(target=target), self.assertRaises(ValueError):
                selected.callback(child, spend)
            self.assertTrue(selected.failed)
        selected = guard(check=lambda work: True)
        with self.assertRaises(ValueError):
            selected.check(selected.parent)
        self.assertTrue(selected.failed)
        held = {}
        def reenter(work):
            try:
                held["guard"].check(work)
            except ValueError:
                pass
        selected = guard(check=reenter)
        held["guard"] = selected
        with self.assertRaises(ValueError):
            selected.check(selected.parent)
        self.assertTrue(selected.failed)

    def test_limits_counters_process_and_clock_cannot_reset(self):
        for change in (lambda selected: setattr(selected.parent, "input_bytes", 0),
                lambda selected: setattr(selected.parent, "limits", QueryReadValidationLimits()),
                lambda selected: setattr(selected, "configured", tuple(list(selected.configured))),
                lambda selected: setattr(selected, "process", (-1, -1))):
            work = meter()
            work.charge(input_bytes=10)
            selected = guard(work)
            selected.check(work)
            change(selected)
            with self.assertRaises(ValueError):
                selected.check(work)
            self.assertTrue(selected.failed)
        for epoch, monotonic in ((100, 11), (101, 10), (600, 11), (101, 510)):
            self.epoch.return_value, self.monotonic.return_value = 101, 11
            selected = guard()
            selected.check(selected.parent)
            self.epoch.return_value, self.monotonic.return_value = epoch, monotonic
            with self.subTest(epoch=epoch, monotonic=monotonic), self.assertRaises(ValueError):
                selected.check(selected.parent)

    def test_actual_transaction_scalars_are_closed_bounded_and_metered(self):
        work = meter()
        actual = source._transaction_row(transaction_row(), work)
        self.assertEqual(actual, tuple(transaction_row()[name] for name in source.observation._TRANSACTION_FIELDS))
        self.assertGreater(work.input_bytes, 0)
        self.assertGreater(work.json_nodes, 0)
        for changes in (dict(server_version_num=True), dict(server_version_num=170000),
                dict(backend_pid=0), dict(virtual_transaction="0/1"),
                dict(transaction_read_only="on"), dict(transaction_deferrable="on"),
                dict(transaction_isolation="read committed"), dict(lock_timeout="x" * 65),
                dict(statement_timeout="\x00"), dict(accepted=True)):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                source._transaction_row(transaction_row(**changes), meter())
        with self.assertRaises(ValueError):
            source._same(actual, source._transaction_row(transaction_row(virtual_transaction="12/35"), meter()), meter())

    def test_actual_body_descriptor_and_seal_readback_cannot_be_supplied_verdicts(self):
        values = step_arguments()
        parameters = source._step_arguments(**values)
        self.assertEqual(parameters[0:2], (DIGEST, 0))
        self.assertEqual(parameters[3].encode("ascii"), values["body_bytes"])
        self.assertEqual(json.loads(parameters[2]), values["descriptor"])
        self.assertEqual(parameters[4], 600)
        self.assertGreater(values["work"].hash_work, 0)
        for change in (dict(ordinal=True), dict(ordinal=1548), dict(body_bytes=bytearray(b"{}")),
                dict(descriptor={**values["descriptor"], "accepted": True}),
                dict(descriptor={**values["descriptor"], "digest": OTHER}),
                dict(descriptor={**values["descriptor"], "rowOrdinal": True}),
                dict(descriptor={**values["descriptor"], "phaseOrdinal": 3})):
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                source._step_arguments(**step_arguments(**change))
        expected = dict(pending_decision_digest=DIGEST, packet_digest=OTHER,
            issued_at_epoch_ns=1, expires_at_epoch_ns=2)
        source._seal_readback(expected.copy(), expected, meter())
        for changed in ({**expected, "issued_at_epoch_ns": True}, {**expected, "packet_digest": DIGEST},
                {**expected, "accepted": True}):
            with self.assertRaises(ValueError):
                source._seal_readback(changed, expected, meter())

    def test_marker_is_exact_maintenance_not_aggregate_operation(self):
        fields = source.existing.markers
        value = {name: DIGEST for name in fields.FIELDS}
        value.update(source_revision=source.existing.authority.SOURCE_REVISION,
            operation=source.contract.OPERATION, database_id="synthetic-db", predecessor_sequence=0,
            pending_sequence=1, fence=1)
        def encoded(row):
            return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.assertEqual(source._marker(encoded(value), DIGEST, meter()), encoded(value).encode("ascii"))
        for changes in (dict(operation="webauthn.registration.finalize"), dict(pending_sequence=2),
                dict(fence=True), dict(pending_decision_digest=OTHER), dict(accepted=True)):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                source._marker(encoded({**value, **changes}), DIGEST, meter())

    def test_native_source_joins_one_transaction_fixed_functions_and_normal_exit(self):
        text = inspect.getsource(source._run_on_configuration)
        tree = ast.parse(text)
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual(calls.count("psycopg.connect"), 1)
        self.assertIn("connection.transaction", text)
        self.assertIn("native._context(transaction, work)", text)
        self.assertLess(text.index("cursor.execute(existing._SET_TRANSACTION)"), text.index("session.check(work)"))
        self.assertLess(text.index("admit()\n                    parent"), text.index("result = operation(session)"))
        self.assertLess(text.index("result = operation(session)"), text.rindex("admit()"))
        self.assertLess(text.index("connection.closed is True"), text.index("return result"))
        for needle in ("challenge_execution_privilege_check", "_policy_candidate_authority_structure_manifest",
                "_policy_candidate_authority_manifest_digest", "configured[7]", "configured[6]",
                "row_factory=dict_row", "autocommit=False", "native._close_after_failure(connection)"):
            self.assertIn(needle, text)
        self.assertNotIn(".commit(", text)
        self.assertNotIn("_open_on_work", text)
        self.assertEqual((source._STEP_SQL.count("%s"), source._SEAL_SQL.count("%s"),
            source._EXECUTE_SQL.count("%s")), (5, 3, 2))
        native_text = inspect.getsource(source._Session._native)
        for needle in ("psycopg.Connection", "psycopg.Cursor", "psycopg.transaction.Transaction",
                "transaction._entered is True", "transaction._exited is False", "_outer_transaction is True",
                "transaction._stack_index == 0", "connection._num_transactions == 1"):
            self.assertIn(needle, native_text)

    def test_cleanup_preserves_first_base_exception(self):
        first = KeyboardInterrupt("synthetic first failure")
        events = []
        class Context:
            def __enter__(self):
                events.append("enter")
                return self
            def __exit__(self, kind, error, trace):
                events.append((kind, error))
                raise RuntimeError("synthetic cleanup failure")
        with self.assertRaises(KeyboardInterrupt) as caught:
            with source.native._context(Context(), meter()):
                raise first
        self.assertIs(caught.exception, first)
        self.assertEqual(events, ["enter", (KeyboardInterrupt, first)])


if __name__ == "__main__":
    unittest.main()
