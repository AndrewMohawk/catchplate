#!/usr/bin/env python3
"""Nonimporting source contracts for the private retention coordinator.

These bounded AST checks do not import the coordinator, planner, store, service
or registry and never execute extracted code. They establish source linkage,
not database transactions, signatures, rollback, currentness or activation.
The separate store fixture exercises real verification with a SQL recorder.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONFIGURED = frozenset({"planner_public_key", "verifier_public_key",
    "expected_planner_identity", "expected_verifier_identity"})
IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")


def source(relative, maximum):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("source exceeds its explicit fixture bound")
    text = path.read_text(encoding="utf-8")
    return text, ast.parse(text, filename=relative)


def definition(tree, name, owner=None):
    nodes = tree.body if owner is None else definition(tree, owner).body
    matches = [node for node in nodes if isinstance(node, (ast.ClassDef, ast.FunctionDef))
               and node.name == name]
    if len(matches) != 1:
        raise AssertionError("source definition is not unique: " + name)
    return matches[0]


def calls(node, spelling):
    return [item for item in ast.walk(node) if isinstance(item, ast.Call)
            and ast.unparse(item.func) == spelling]


class RevocationCoordinatorSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("serverware/authority_revocation_persistence.py", 64 * 1024)
        cls.owner = definition(cls.tree, "RevocationPlannerPersistence")

    def method(self, name):
        return definition(self.tree, name, "RevocationPlannerPersistence")

    def assert_shape(self, actual, expected):
        self.assertEqual(ast.dump(actual, include_attributes=False),
                         ast.dump(ast.parse(expected, mode="eval").body, include_attributes=False))

    def test_import_closure_is_registry_free_and_configuration_is_frozen(self):
        imports = [(node.module, tuple((item.name, item.asname) for item in node.names))
                   for node in self.tree.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, [
            ("__future__", (("annotations", None),)),
            ("dataclasses", (("dataclass", None),)),
            ("cryptography.hazmat.primitives.asymmetric.ed25519", (("Ed25519PublicKey", None),)),
            ("serverware", (("authority_revocation_retention", "retention"),)),
            ("serverware.authority_store", (("revocation_retention", "store"),)),
        ])
        self.assertEqual([node for node in self.tree.body if isinstance(node, ast.Import)], [])
        self.assertEqual(len(self.owner.decorator_list), 1)
        self.assert_shape(self.owner.decorator_list[0],
                         "dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)")
        self.assertEqual({node.name for node in self.owner.body if isinstance(node, ast.FunctionDef)},
                         {"__init__", "_snapshot_configuration", "_inputs", "_run", "persist", "read", "reserve_execution"})

    def test_constructor_pins_real_keys_and_copies_exact_identity_scalars(self):
        constructor = self.method("__init__")
        self.assert_shape(constructor.body[0].test,
            "type(persistence_dsn) is not str or not 1 <= len(persistence_dsn) <= 65536 "
            "or type(connect_timeout_seconds) is not int or not 1 <= connect_timeout_seconds <= 300 "
            "or not isinstance(planner_public_key, Ed25519PublicKey) "
            "or not isinstance(verifier_public_key, Ed25519PublicKey)")
        validation = calls(constructor, "retention.plan.contract.validate_identity_shape")
        self.assertEqual([ast.unparse(item.args[0]) for item in validation],
                         ["expected_planner_identity", "expected_verifier_identity"])
        loop = constructor.body[-1]
        self.assertIsInstance(loop, ast.For)
        bindings = {item.elts[0].value: item.elts[1] for item in loop.iter.elts}
        self.assertEqual(set(bindings), {"persistence_dsn", "connect_timeout_seconds",
            "planner_public_key", "verifier_public_key", "_planner_identity", "_verifier_identity"})
        for name in ("persistence_dsn", "connect_timeout_seconds", "planner_public_key", "verifier_public_key"):
            self.assert_shape(bindings[name], name)
        self.assert_shape(bindings["_planner_identity"],
                         "tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS)")
        self.assert_shape(bindings["_verifier_identity"],
                         "tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS)")
        self.assertEqual(len(calls(constructor, "object.__setattr__")), 1)
        self.assertTrue(all(item.lineno < loop.lineno for item in validation))

    def test_exact_fifteen_call_inputs_cannot_replace_configured_pins(self):
        assignments = {node.targets[0].id: node.value for node in self.tree.body
                       if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
        configured = assignments["_CONFIGURED"]
        self.assert_shape(configured.func, "frozenset")
        self.assertEqual({node.value for node in configured.args[0].elts}, CONFIGURED)
        self.assert_shape(assignments["_CALL_INPUTS"], "retention.wire._EXPECTATIONS - _CONFIGURED")
        self.assertEqual(tuple(item.value for item in assignments["_IDENTITY_FIELDS"].elts), IDENTITY_FIELDS)
        inputs = definition(self.tree, "_inputs_from_configuration")
        self.assert_shape(inputs.body[0].value, "_validate_configuration(configuration)")
        self.assert_shape(inputs.body[1].test,
                         "len(expectations) != len(_CALL_INPUTS) or set(expectations) != _CALL_INPUTS")
        pins = inputs.body[3].value
        self.assert_shape(pins, '{"planner_public_key": planner_key, '
            '"verifier_public_key": verifier_key, '
            '"expected_planner_identity": dict(zip(_IDENTITY_FIELDS, planner_identity)), '
            '"expected_verifier_identity": dict(zip(_IDENTITY_FIELDS, verifier_identity))}')
        owned = calls(inputs, "store._owned_expectations")
        self.assertEqual(len(owned), 1)
        self.assert_shape(owned[0], "store._owned_expectations({**expectations, **pins}, work)")
        facade = self.method("_inputs")
        self.assertEqual(len(facade.body), 1)
        self.assert_shape(facade.body[0].value,
            "_inputs_from_configuration(self._snapshot_configuration(), expectations, work)")
        # Pin the actual decoder/verifier inventory, not just a subtraction.
        _, plan_tree = source("serverware/authority_revocation_plan.py", 256 * 1024)
        inventory = next(node.value for node in plan_tree.body if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == "_VERIFICATION_INPUTS"
                                 for target in node.targets))
        fields = {node.value for node in inventory.args[0].elts} - {"envelope"} - CONFIGURED
        self.assertEqual(fields, {"expected_request", "expected_capability_id", "expected_planner_transaction_id",
            "expected_fence", "reserved_at_epoch_ns", "deadline_epoch_ns", "deadline_monotonic_ns",
            "now_epoch_ns", "now_monotonic_ns", "database_now", "maximum_assertion_age_ns",
            "maximum_plan_age_ns", "maximum_clock_skew_ns", "expected_before", "expected_approver_policy_digest"})

    def test_capture_precedes_real_connect_and_transaction_mode_is_literal(self):
        facade = self.method("_run")
        self.assertEqual(len(facade.body), 1)
        self.assert_shape(facade.body[0].value,
            "_run_on_configuration(self._snapshot_configuration(), operation, arguments, expectations, work)")
        run = definition(self.tree, "_run_on_configuration")
        self.assert_shape(run.body[1].value, "configuration[:2]")
        owned = calls(run, "_inputs_from_configuration")
        connect = calls(run, "psycopg.connect")
        self.assertEqual((len(owned), len(connect)), (1, 1))
        self.assertLess(owned[0].lineno, connect[0].lineno)
        self.assert_shape(owned[0], "_inputs_from_configuration(configuration, expectations, work)")
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == "self" for node in ast.walk(run)))
        self.assert_shape(connect[0], 'psycopg.connect(dsn, row_factory=dict_row, '
            'connect_timeout=timeout, options="-c search_path=pg_catalog")')
        opening = calls(run, "_connect")
        self.assertEqual(len(opening), 1)
        self.assert_shape(opening[0].args[0], "work")
        self.assert_shape(opening[0].args[1], 'lambda: psycopg.connect(dsn, row_factory=dict_row, '
            'connect_timeout=timeout, options="-c search_path=pg_catalog")')
        callbacks = calls(run, "store._callback")
        self.assertEqual(len(callbacks), 3)
        for callback in callbacks:
            self.assert_shape(callback.args[0], "work")
        execution = next(item for item in callbacks if isinstance(item.args[1], ast.Attribute)
                         and item.args[1].attr == "execute")
        self.assert_shape(execution, 'store._callback(work, active.execute, '
            '"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE")')
        contexts = calls(run, "store._context")
        self.assertEqual({ast.unparse(item) for item in contexts}, {
            "store._context(connection, work)", "store._context(transaction, work)",
            "store._context(cursor, work)"})
        operation = calls(run, "operation")
        self.assertEqual(len(operation), 1)
        self.assert_shape(operation[0], "operation(connection=db.PostgresMetadataConnection(connection), "
                          "work=work, **arguments, **owned)")
        self.assertLess(execution.lineno, operation[0].lineno)

    def test_raw_public_methods_target_only_the_genuine_store_and_same_work(self):
        persist, read = self.method("persist"), self.method("read")
        self.assert_shape(persist.body[0].test,
            "type(envelope_bytes) is not bytes or type(evaluation_context_bytes) is not bytes")
        self.assert_shape(persist.body[1].test,
            "type(planned_at_epoch_ns) is not int or not 1 <= planned_at_epoch_ns <= 2**63 - 1")
        self.assertEqual(len(calls(persist, "self._run")), 1)
        self.assert_shape(calls(persist, "self._run")[0],
            'self._run(store.persist_revocation_planner_record, {"envelope_bytes": envelope_bytes, '
            '"evaluation_context_bytes": evaluation_context_bytes, "planned_at_epoch_ns": planned_at_epoch_ns}, '
            'expectations, work)')
        self.assert_shape(read.body[0].value, "retention.plan.contract._digest(planner_transaction_id)")
        self.assertEqual(len(calls(read, "self._run")), 1)
        self.assert_shape(calls(read, "self._run")[0],
            'self._run(store.read_revocation_planner_record, {"planner_transaction_id": planner_transaction_id}, '
            'expectations, work)')
        for method in (persist, read):
            self.assertEqual(method.args.kwarg.arg, "expectations")
            self.assertIn("work", {argument.arg for argument in method.args.kwonlyargs})

    def test_no_new_allowance_parser_clock_signature_or_success_token_route(self):
        forbidden = {"_ValidationWork", "QueryReadValidationLimits", "_PackagingLedger",
            "json", "base64", "hashlib", "time", "datetime", "authority_transition_registry"}
        names = {node.id for node in ast.walk(self.tree) if isinstance(node, ast.Name)}
        self.assertTrue(names.isdisjoint(forbidden))
        attributes = {node.attr for node in ast.walk(self.tree) if isinstance(node, ast.Attribute)}
        self.assertTrue(attributes.isdisjoint({"sign", "verify", "loads", "dumps", "now", "time_ns",
                                               "monotonic_ns", "commit", "derive"}))
        run = definition(self.tree, "_run_on_configuration")
        self.assert_shape(run.body[-1].value, "result")
        self.assertEqual(len(calls(run, "operation")), 1)

    def test_reservation_targets_one_real_store_call_without_a_separate_read(self):
        reserve = self.method("reserve_execution")
        self.assertEqual([argument.arg for argument in reserve.args.kwonlyargs],
                         ["envelope_id", "planner_transaction_id", "work"])
        self.assertEqual(reserve.args.kwarg.arg, "expectations")
        imports = [(node.module, tuple(item.name for item in node.names))
                   for node in reserve.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, [("serverware.authority_store", ("revocation_execution",))])
        guards = calls(reserve, "retention.plan.contract._digest")
        self.assertEqual([ast.unparse(call.args[0]) for call in guards],
                         ["envelope_id", "planner_transaction_id"])
        operations = calls(reserve, "self._run")
        self.assertEqual(len(operations), 1)
        self.assert_shape(operations[0],
            'self._run(revocation_execution.reserve_revocation_execution_envelope, '
            '{"envelope_id": envelope_id, "planner_transaction_id": planner_transaction_id}, expectations, work)')
        self.assertTrue(all(guard.lineno < operations[0].lineno for guard in guards))
        self.assertFalse(calls(reserve, "self.read"))
        self.assertFalse(calls(reserve, "store.read_revocation_planner_record"))

    def test_invocation_snapshot_admits_all_six_values_before_callback_free_handoff(self):
        snapshot = self.method("_snapshot_configuration")
        self.assert_shape(snapshot.body[0].test, "type(self) is not RevocationPlannerPersistence")
        self.assert_shape(snapshot.body[1].value,
            "(self.persistence_dsn, self.connect_timeout_seconds, self.planner_public_key, "
            "self.verifier_public_key, self._planner_identity, self._verifier_identity)")
        self.assert_shape(snapshot.body[2].value, "_validate_configuration(configuration)")
        self.assert_shape(snapshot.body[3].value, "configuration")
        validation = definition(self.tree, "_validate_configuration")
        self.assert_shape(validation.body[1].test,
                         "type(configuration) is not tuple or len(configuration) != 6")
        self.assert_shape(validation.body[3].test,
            "type(dsn) is not str or not 1 <= len(dsn) <= 65536 "
            "or type(timeout) is not int or not 1 <= timeout <= 300 "
            "or not isinstance(planner_key, Ed25519PublicKey) "
            "or not isinstance(verifier_key, Ed25519PublicKey)")
        identities = validation.body[4]
        self.assert_shape(identities.iter, "(planner_identity, verifier_identity)")
        self.assert_shape(identities.body[0].test,
                         "type(identity) is not tuple or len(identity) != 3")
        self.assert_shape(calls(identities, "retention.plan.contract._digest")[0],
                         "retention.plan.contract._digest(digest)")
        for function in (snapshot, validation):
            attributes = {node.attr for node in ast.walk(function) if isinstance(node, ast.Attribute)}
            self.assertTrue(attributes.isdisjoint({"verify", "public_bytes", "public_bytes_raw", "connect"}))
        for name in ("_inputs_from_configuration", "_run_on_configuration"):
            function = definition(self.tree, name)
            self.assertFalse(any(isinstance(node, ast.Name) and node.id == "self"
                                 for node in ast.walk(function)))

    def test_connect_guard_owns_returned_handle_and_closes_without_requiring_valid_work(self):
        connect = definition(self.tree, "_connect")
        opened = definition(connect, "open_connection")
        self.assertIsInstance(opened.body[0], ast.Nonlocal)
        self.assertEqual(opened.body[0].names, ["connection"])
        self.assert_shape(opened.body[1].value, "opener()")
        self.assert_shape(opened.body[2].value, "connection")
        guarded, = [node for node in connect.body if isinstance(node, ast.Try)]
        self.assert_shape(guarded.body[0].value, "store._callback(work, open_connection)")
        self.assertEqual(len(guarded.handlers), 1)
        self.assert_shape(guarded.handlers[0].type, "BaseException")
        cleanup = guarded.handlers[0].body
        self.assert_shape(cleanup[0].test, "connection is not None")
        attempted = cleanup[0].body[0]
        self.assertIsInstance(attempted, ast.Try)
        self.assert_shape(attempted.body[0].value, "connection.close()")
        self.assert_shape(attempted.handlers[0].type, "BaseException")
        self.assertIsInstance(attempted.handlers[0].body[0], ast.Pass)
        self.assertIsInstance(cleanup[-1], ast.Raise)
        self.assertIsNone(cleanup[-1].exc)
        self.assertEqual(len(calls(connect, "store._callback")), 1)
        self.assertFalse(calls(connect, "_ValidationWork"))

    def test_legacy_v3_and_service_routes_do_not_activate_the_new_coordinator(self):
        service, _ = source("serverware/authority_service.py", 2 * 1024 * 1024)
        planner, planner_tree = source("serverware/authority_planner.py", 2 * 1024 * 1024)
        for text in (service, planner):
            self.assertNotIn("authority_revocation_persistence", text)
            self.assertNotIn("RevocationPlannerPersistence", text)
        legacy = definition(planner_tree, "persist", "PlannerPersistence")
        legacy_source = ast.get_source_segment(planner, legacy)
        self.assertIn('envelope.get("schema") != SIGNED_MEASURED_PLAN_SCHEMA', legacy_source)
        self.assertNotIn("persist_revocation_planner_record", legacy_source)
        schema = next(node.value for node in planner_tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "SIGNED_MEASURED_PLAN_SCHEMA"
                              for target in node.targets))
        self.assertEqual(schema.value, "serverware.signedPolicyAuthorityMeasuredPlan/v3")


if __name__ == "__main__":
    unittest.main()
