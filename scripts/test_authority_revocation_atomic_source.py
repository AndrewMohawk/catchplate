#!/usr/bin/env python3
"""Nonimporting linkage for atomic original-byte retention and reservation.

These bounded source controls do not execute extracted code, import the active
database/service/registry, or prove PostgreSQL admission, replay or rollback.
The real two store calls and their original-byte verification remain required;
neither a retention receipt nor a reserved row is a successful-proof input.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, keywords, source


class RevocationAtomicSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.persistence = source("serverware/authority_revocation_persistence.py", 64 * 1024)
        cls.owner = definition(cls.persistence, "RevocationPlannerPersistence")
        cls.method = definition(cls.owner, "persist_and_reserve_execution")
        cls.operation = definition(cls.persistence, "_persist_and_reserve_on_connection")
        _, cls.store = source("serverware/authority_store/revocation_retention.py", 64 * 1024)
        _, cls.execution = source("serverware/authority_store/revocation_execution.py", 64 * 1024)

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_public_entry_snapshots_then_binds_bounded_originals_and_independent_id_before_one_runner(self):
        method = self.method
        self.assertEqual([item.arg for item in method.args.args], ["self"])
        self.assertEqual([item.arg for item in method.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "planned_at_epoch_ns",
            "envelope_id", "planner_transaction_id", "work"])
        self.assertTrue(all(value is None for value in method.args.kw_defaults))
        self.assertEqual(method.args.kwarg.arg, "expectations")
        self.assertIsNone(method.args.vararg)
        self.shape(method.body[1].value, "self._snapshot_configuration()")
        self.assertIs(assigned(method, "configuration"), method.body[1].value)
        originals = method.body[2]
        self.assertIsInstance(originals, ast.For)
        self.assertEqual([item.id for item in originals.target.elts], ["raw", "maximum"])
        self.shape(originals.iter, '''((envelope_bytes, retention.plan.contract.MAX_PAYLOAD_BYTES),
            (evaluation_context_bytes, retention.MAX_CONTEXT_BYTES))''')
        self.shape(originals.body[0].test, "type(raw) is not bytes or not 2 <= len(raw) <= maximum")
        self.assertIsInstance(originals.body[0].body[0], ast.Raise)
        self.shape(method.body[3].test,
                   "type(planned_at_epoch_ns) is not int or not 1 <= planned_at_epoch_ns <= 2**63 - 1")
        digests = calls(method, "retention.plan.contract._digest")
        self.assertEqual([ast.unparse(node.args[0]) for node in digests],
                         ["envelope_id", "planner_transaction_id", "expected_planner_transaction_id"])
        closed = method.body[6]
        self.shape(closed.test, '''len(expectations) != len(_CALL_INPUTS)
            or any(type(name) is not str for name in expectations) or set(expectations) != _CALL_INPUTS''')
        self.shape(assigned(method, "expected_planner_transaction_id"), 'expectations["expected_planner_transaction_id"]')
        ledger = call(method, "retention.capture._SharedLedger")
        self.shape(ledger, "retention.capture._SharedLedger(work)")
        joined = call(method, "retention.plan._same")
        self.shape(joined, '''retention.plan._same(planner_transaction_id, expected_planner_transaction_id, work,
            "atomic revocation planner transaction differs from its independent expectation")''')
        runner = call(method, "_run_on_configuration")
        self.shape(runner, '''_run_on_configuration(configuration, _persist_and_reserve_on_connection,
            {"envelope_bytes": envelope_bytes, "evaluation_context_bytes": evaluation_context_bytes,
             "planned_at_epoch_ns": planned_at_epoch_ns, "envelope_id": envelope_id,
             "planner_transaction_id": planner_transaction_id}, expectations, work)''')
        self.assertIs(method.body[-1].value, runner)
        order = (method.body[1], originals, method.body[3], *digests[:2], closed,
                 assigned(method, "expected_planner_transaction_id"), digests[2], ledger, joined, runner)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        self.assertEqual([ast.unparse(node) for node in ast.walk(method)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "self"], ["self._snapshot_configuration"])
        for spelling in ("self._run", "self.persist", "self.reserve_execution", "_connect",
                "store._callback", "store._owned_expectations", "retention._verify_record_on_work"):
            self.assertFalse(calls(method, spelling))
        # This is the actual charged canonical join, not scalar Python == or
        # a new ledger allowance. Two digest strings add 0H / 438B / 4N.
        _, plan = source("serverware/authority_revocation_plan.py", 256 * 1024)
        self.shape(definition(plan, "_same").body[0].value,
                   "semantics._canonical_equal(left, right, work=work, label=label)")
        _, semantics = source("serverware/authority_revocation_semantics.py", 64 * 1024)
        equal = definition(semantics, "_canonical_equal")
        self.assertEqual([ast.unparse(node) for node in calls(equal, "work.prepare_encoding")],
                         ["work.prepare_encoding(left)", "work.prepare_encoding(right)"])
        self.shape(call(equal, "work.charge"), "work.charge(input_bytes=len(left_wire) + len(right_wire))")
        self.shape(equal.body[-1].test, "left_wire != right_wire")

    def test_fixed_operation_admits_actual_facade_and_contains_both_stores_in_one_common_savepoint(self):
        operation = self.operation
        self.assertEqual(operation.args.args, [])
        self.assertEqual([item.arg for item in operation.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "planned_at_epoch_ns", "envelope_id",
            "planner_transaction_id", "connection", "work"])
        self.assertTrue(all(value is None for value in operation.args.kw_defaults))
        self.assertEqual(operation.args.kwarg.arg, "expectations")
        self.assertIsNone(operation.args.vararg)
        self.assertEqual([(node.module, tuple(item.name for item in node.names))
            for node in operation.body if isinstance(node, ast.ImportFrom)],
            [("serverware.authority_store", ("revocation_execution",))])
        self.shape(operation.body[2].value, "store._callback(work, store._transaction_connection, connection)")
        self.shape(assigned(operation, "raw"), "store._callback(work, store._require_planner_writer, connection)")
        common, = [node for node in ast.walk(operation) if isinstance(node, ast.With)]
        self.assertEqual(len(common.items), 1)
        self.shape(common.items[0].context_expr, "store._context(store._callback(work, raw.transaction), work)")
        self.assertIsNone(common.items[0].optional_vars)
        self.assertEqual(len(common.body), 5)
        continuity = "store._callback(work, revocation_execution._same_connection, connection, raw)"
        for index in (0, 2, 4):
            self.shape(common.body[index].value, continuity)
        persist = call(operation, "store.persist_revocation_planner_record")
        reserve = call(operation, "revocation_execution.reserve_revocation_execution_envelope")
        self.assertIs(common.body[1].value, persist)
        self.assertIs(common.body[3].value, reserve)
        self.shape(persist, '''store.persist_revocation_planner_record(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planned_at_epoch_ns=planned_at_epoch_ns, connection=connection, work=work, **expectations)''')
        self.shape(reserve, '''revocation_execution.reserve_revocation_execution_envelope(
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
            connection=connection, work=work, **expectations)''')
        self.shape(operation.body[-2].value, continuity)
        self.shape(operation.body[-1].value, "(retained_receipt, execution_reservation)")
        self.assertLess(common.end_lineno, operation.body[-2].lineno)
        self.assertEqual([node.id for node in ast.walk(operation)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
            and node.id == "retained_receipt"], ["retained_receipt"])
        self.assertFalse(any(isinstance(node, (ast.Try, ast.ExceptHandler)) for node in ast.walk(operation)))
        same = definition(self.execution, "_same_connection")
        self.shape(same.body[0].value, "store._transaction_connection(connection)")
        self.shape(same.body[1].test, "store._require_postgres_connection(connection) is not raw")
        transaction = definition(self.store, "_transaction_connection")
        self.shape(transaction.body[0].value, "_require_postgres_connection(connection)")
        self.shape(transaction.body[1].test, "connection.in_transaction is not True")
        _, connection = source("serverware/authority_store/planner_connection.py", 64 * 1024)
        gate = definition(connection, "_require_planner_writer")
        self.shape(call(gate, "_require_serializable"), "_require_serializable(raw)")
        self.shape(call(gate, "_require_database_role"),
                   "_require_database_role(raw, _db_value('_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE'))")

    def test_one_owned_runner_keeps_four_real_transaction_managers_and_returns_only_after_outer_exit(self):
        runner = definition(self.persistence, "_run_on_configuration")
        capture = call(runner, "_inputs_from_configuration")
        self.shape(capture, "_inputs_from_configuration(configuration, expectations, work)")
        opening = call(runner, "_connect")
        delegated = call(runner, "writer_connection._run_on_connection")
        self.shape(delegated, '''writer_connection._run_on_connection(connection,
            database_identity=configuration[6], work=work, operation=operation,
            arguments=arguments, expectations=owned)''')
        self.assertLess(capture.lineno, opening.lineno)
        self.assertLess(opening.lineno, delegated.lineno)
        self.assertIs(runner.body[-1].value, delegated)
        self.assertFalse(calls(runner, "operation"))
        _, writer = source("serverware/authority_revocation_writer_connection.py", 64 * 1024)
        owner = definition(writer, "_run_on_connection")
        guarded, = [node for node in owner.body if isinstance(node, ast.Try)]
        connection_scope, = [node for node in guarded.body if isinstance(node, ast.With)]
        self.shape(connection_scope.items[0].context_expr, "reader._context(connection, work)")
        self.shape(assigned(owner, "transaction"), "_callback(work, lambda: connection.transaction())")
        outer, = [node for node in connection_scope.body if isinstance(node, ast.With)]
        self.shape(outer.items[0].context_expr, "reader._context(transaction, work)")
        actual = call(owner, "operation")
        self.shape(actual, '''operation(connection=db.PostgresMetadataConnection(guarded),
            work=work, **arguments, **expectations)''')
        self.assertIn(actual, list(ast.walk(outer)))
        self.assertLess(call(owner, "_admit_identity").lineno, actual.lineno)
        self.assertLess(call(owner, "planner_writer_privilege_check").lineno, actual.lineno)
        self.shape(connection_scope.body[-1].value,
                   "_callback(work, reader._require_connection, connection, original, 0)")
        self.shape(guarded.body[-2].test, "_callback(work, lambda: connection.closed) is not True")
        self.shape(guarded.body[-1].value, "result")
        self.assertLess(outer.end_lineno, connection_scope.body[-1].lineno)
        self.assertLess(connection_scope.end_lineno, guarded.body[-2].lineno)
        # Each existing store retains its own actual savepoint inside the
        # common savepoint. Together with the writer outer transaction these
        # are four transaction managers, not four connection/cursor contexts.
        for function, prefix in ((self.operation, "store."),
                (definition(self.store, "persist_revocation_planner_record"), ""),
                (definition(self.execution, "reserve_revocation_execution_envelope"), "store.")):
            transactions = [node for node in ast.walk(function) if isinstance(node, ast.With)
                and ast.unparse(node.items[0].context_expr)
                    == prefix + "_context(" + prefix + "_callback(work, raw.transaction), work)"]
            self.assertEqual(len(transactions), 1)
            self.assertLess(transactions[0].end_lineno, function.body[-1].lineno)
        for function in (self.method, self.operation, runner):
            self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in {
                "commit", "rollback", "sign", "verify", "time_ns", "monotonic_ns"} for node in ast.walk(function)))
            for spelling in ("_ValidationWork", "QueryReadValidationLimits", "retention.capture._PackagingLedger"):
                self.assertFalse(calls(function, spelling))

    def test_reservation_reloads_and_verifies_original_stored_bytes_with_independent_planner_id(self):
        reserve = definition(self.execution, "reserve_revocation_execution_envelope")
        captured = call(reserve, "store._owned_expectations")
        self.shape(captured, "store._owned_expectations(expectations, work)")
        reread = call(reserve, "store._read_revocation_record_on_work")
        self.shape(reread, '''store._read_revocation_record_on_work(
            planner_transaction_id=planner_transaction_id, connection=connection,
            work=work, _expected_raw=raw, expectations=owned)''')
        self.assertLess(captured.lineno, reread.lineno)
        parent_guard, = [node for node in ast.walk(reserve) if isinstance(node, ast.If)
                         and ast.unparse(node.test) == "parent['status'] != 'planned'"]
        reconstruction = call(reserve, "_expected_reservation")
        self.shape(reconstruction, "_expected_reservation(envelope_id, record, parent, work)")
        self.assertLess(reread.lineno, parent_guard.lineno)
        self.assertLess(parent_guard.lineno, reconstruction.lineno)
        reader = definition(self.store, "_read_revocation_record_on_work")
        self.shape(call(reader, "work.prepare_comparison"),
                   'work.prepare_comparison(planner_transaction_id, expectations["expected_planner_transaction_id"])')
        id_guard, = [node for node in reader.body if isinstance(node, ast.If)
                    and ast.unparse(node.test) == "planner_transaction_id != expectations['expected_planner_transaction_id']"]
        reads = calls(reader, "_read")
        self.assertEqual(len(reads), 2)
        self.assertLess(id_guard.lineno, reads[0].lineno)
        self.shape(reads[0], "_read(cursor, _SELECT_PARENT, identity, work)")
        self.shape(reads[1], "_read(cursor, _SELECT_RECORD, identity, work)")
        self.shape(assigned(reader, "envelope"), '''_decode(stored["exact_envelope_base64url"],
            stored["exact_envelope_byte_count"], retention.plan.contract.MAX_PAYLOAD_BYTES, work)''')
        self.shape(assigned(reader, "context"), '''_decode(stored["evaluation_context_base64url"],
            stored["evaluation_context_byte_count"], retention.MAX_CONTEXT_BYTES, work)''')
        verified = call(reader, "retention._verify_record_on_work")
        self.shape(verified, '''retention._verify_record_on_work(envelope_bytes=envelope,
            evaluation_context_bytes=context, work=work, **expectations)''')
        self.assertLess(reads[1].lineno, verified.lineno)
        self.assertEqual([ast.unparse(node) for node in calls(reader, "_match")],
                         ["_match(row, reservation, work)", "_match(row, planned, work)", "_match(stored, sidecar, work)"])
        persist = definition(self.store, "persist_revocation_planner_record")
        self.shape(call(persist, "retention._verify_record_on_work"), '''retention._verify_record_on_work(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            work=work, **expectations)''')
        self.assertFalse(calls(reserve, "store._receipt"))

    def test_retry_preserves_original_planned_timestamp_and_requires_live_unconsumed_reservation(self):
        persist = definition(self.store, "persist_revocation_planner_record")
        times = calls(persist, "_planned_time")
        self.assertEqual([ast.unparse(node) for node in times],
                         ["_planned_time(planned_at_epoch_ns, reservation)", "_planned_time(row['planned_at_epoch_ns'], reservation)"])
        fresh = next(node for node in ast.walk(persist) if isinstance(node, ast.If)
                     and ast.unparse(node.test) == "row['status'] == 'reserved'")
        retry, = fresh.orelse
        self.assertIsInstance(retry, ast.If)
        self.shape(retry.test, 'row["status"] in {"planned", "consumed"}')
        self.assertEqual([ast.unparse(node.func) for node in calls(retry, "_check_authorization_rows")],
                         ["_check_authorization_rows"])
        self.assertFalse(calls(retry, "cursor.execute"))
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == "planned_at_epoch_ns" for node in ast.walk(retry)))
        self.shape(persist.body[-1].value, "_receipt(record, row)")
        receipt = definition(self.store, "_receipt")
        value = receipt.body[0].value
        fields = {key.value: value for key, value in zip(value.keys, value.values)}
        self.shape(fields["plannedAtEpochNs"], 'row["planned_at_epoch_ns"]')
        self.shape(definition(self.store, "_planned_time").body[0].test,
                   'type(value) is not int or not reservation["reserved_at_epoch_ns"] <= value < reservation["deadline_epoch_ns"]')
        reserve = definition(self.execution, "reserve_revocation_execution_envelope")
        fresh_checks = [node for node in calls(reserve, "store._callback")
                        if len(node.args) > 1 and ast.unparse(node.args[1]) == "store._fresh"]
        self.assertEqual([ast.unparse(node) for node in fresh_checks], ["store._callback(work, store._fresh, parent)"] * 2)
        insert = next(node for node in calls(reserve, "store._callback")
                      if len(node.args) > 2 and ast.unparse(node.args[2]) == "_INSERT")
        match = call(reserve, "store._match")
        self.shape(match, "store._match(row, expected, work)")
        self.assertLess(fresh_checks[0].lineno, insert.lineno)
        self.assertLess(insert.lineno, match.lineno)
        self.assertLess(match.lineno, fresh_checks[1].lineno)

    def test_atomic_owner_does_not_activate_service_actions_transport_or_widen_writer_peers(self):
        _, service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        process = definition(service, "AuthorityProcess")
        factory = definition(process, "_revocation_planner_persistence")
        self.assertEqual([item.arg for item in factory.args.args], ["self"])
        self.assertEqual([item.arg for item in factory.args.kwonlyargs], ["work"])
        self.assertIsNone(factory.args.kwarg)
        self.assertIsNone(factory.args.vararg)
        self.assertFalse(calls(service, "self._revocation_planner_persistence"))
        # Preserve this historical ID: the private action now deliberately
        # composes the owner, while public service dispatch stays unchanged.
        action = definition(process, "_persist_and_reserve_revocation_plan")
        atomic_calls = [node for node in ast.walk(service) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "persist_and_reserve_execution"]
        self.assertEqual(len(atomic_calls), 1)
        self.assertIn(atomic_calls[0], list(ast.walk(action)))
        handle = definition(process, "handle")
        writer, = [node for node in ast.walk(handle) if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "self.role_name == 'planner-writer'"]
        self.shape(keywords(call(writer, "self._verify_internal_envelope"))["allowed_purposes"],
                   "{'persist-measured-plan', 'read-persisted-plan', 'reserve-execution-envelope'}")
        self.assertEqual({node.func.attr for node in ast.walk(writer)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "self"},
            {"_verify_internal_envelope", "_handle_read_persisted_plan",
             "_handle_reserve_execution_envelope", "_handle_persist_measured_plan"})
        serve = definition(definition(service, "AuthorityServer"), "_serve_connection")
        peer, = [node for node in ast.walk(serve) if isinstance(node, ast.If)
                 and ast.unparse(node.test) == "uid != self.peer_uid or gid != self.peer_gid"]
        self.assertLess(peer.lineno, call(serve, "self.process.handle").lineno)
        topology = definition(definition(service, "MeasuredConfiguration"), "_verify_role_topology")
        joined = ast.parse('''((int(planner_writer.get("peerUid", -1)), int(planner_writer.get("peerGid", -1)))
            != (int(planner["serviceUid"]), int(planner["serviceGid"])))''', mode="eval").body
        self.assertEqual(sum(ast.dump(node) == ast.dump(joined)
            for node in ast.walk(topology) if isinstance(node, ast.Compare)), 1)
        for function in (handle, serve, factory):
            for spelling in ("persist_and_reserve_execution", "_persist_and_reserve_on_connection",
                    "_persist_and_reserve_revocation_plan"):
                self.assertNotIn(spelling, ast.unparse(function))
        for function in (self.method, self.operation):
            for spelling in ("_socket_request", "_socket_request_bytes", "_socket_request_revocation_bytes",
                    "_recv_message", "_recv_revocation_invocation_bytes", "time.time_ns", "time.monotonic_ns"):
                self.assertFalse(calls(function, spelling))
        _, registry = source("serverware/authority_transition_registry.py")
        self.shape(assigned(registry, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        closed, = [node for node in registry.body if isinstance(node, ast.If)]
        self.shape(closed.test, "_CLOSURE_ERRORS")
        self.assertIsInstance(closed.body[0], ast.Raise)


if __name__ == "__main__":
    unittest.main()
