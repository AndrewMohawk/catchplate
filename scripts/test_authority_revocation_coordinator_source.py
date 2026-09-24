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
                         {"__init__", "_inputs", "_run", "persist", "read"})

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
        inputs = self.method("_inputs")
        self.assert_shape(inputs.body[0].test,
                         "len(expectations) != len(_CALL_INPUTS) or set(expectations) != _CALL_INPUTS")
        pins = inputs.body[1].value
        self.assert_shape(pins, '{"planner_public_key": self.planner_public_key, '
            '"verifier_public_key": self.verifier_public_key, '
            '"expected_planner_identity": dict(zip(_IDENTITY_FIELDS, self._planner_identity)), '
            '"expected_verifier_identity": dict(zip(_IDENTITY_FIELDS, self._verifier_identity))}')
        owned = calls(inputs, "store._owned_expectations")
        self.assertEqual(len(owned), 1)
        self.assert_shape(owned[0], "store._owned_expectations({**expectations, **pins}, work)")
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
        run = self.method("_run")
        self.assert_shape(run.body[0].value, "(self.persistence_dsn, self.connect_timeout_seconds)")
        owned = calls(run, "self._inputs")
        connect = calls(run, "psycopg.connect")
        self.assertEqual((len(owned), len(connect)), (1, 1))
        self.assertLess(owned[0].lineno, connect[0].lineno)
        self.assert_shape(owned[0], "self._inputs(expectations, work)")
        self.assert_shape(connect[0], 'psycopg.connect(dsn, row_factory=dict_row, '
            'connect_timeout=timeout, options="-c search_path=pg_catalog")')
        callbacks = calls(run, "store._callback")
        self.assertEqual(len(callbacks), 4)
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
        run = self.method("_run")
        self.assert_shape(run.body[-1].value, "result")
        self.assertEqual(len(calls(run, "operation")), 1)

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
