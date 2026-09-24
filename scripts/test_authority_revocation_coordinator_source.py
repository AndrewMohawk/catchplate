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
            ("serverware", (("authority_revocation_writer_connection", "writer_connection"),)),
            ("serverware.authority_store", (("revocation_retention", "store"),)),
        ])
        self.assertEqual([node for node in self.tree.body if isinstance(node, ast.Import)], [])
        self.assertEqual(len(self.owner.decorator_list), 1)
        self.assert_shape(self.owner.decorator_list[0],
                         "dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)")
        self.assertEqual({node.name for node in self.owner.body if isinstance(node, ast.FunctionDef)},
                         {"__init__", "_snapshot_configuration", "_inputs", "_run", "persist", "read",
                          "reserve_execution", "persist_and_reserve_execution"})

    def test_constructor_pins_real_keys_and_copies_exact_identity_scalars(self):
        constructor = self.method("__init__")
        self.assertEqual([item.arg for item in constructor.args.kwonlyargs],
            ["persistence_dsn", "connect_timeout_seconds", "planner_public_key", "verifier_public_key",
             "expected_planner_identity", "expected_verifier_identity", "writer_database_identity"])
        self.assertTrue(all(value is None for value in constructor.args.kw_defaults))
        validation = calls(constructor, "retention.plan.contract.validate_identity_shape")
        self.assertEqual([ast.unparse(item.args[0]) for item in validation],
                         ["expected_planner_identity", "expected_verifier_identity"])
        self.assert_shape(constructor.body[2].value,
            "(persistence_dsn, connect_timeout_seconds, planner_public_key, verifier_public_key, "
            "tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS), "
            "tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS), writer_database_identity)")
        self.assert_shape(constructor.body[3].value, "_validate_configuration(configuration)")
        loop = constructor.body[-1]
        self.assertIsInstance(loop, ast.For)
        bindings = {item.elts[0].value: item.elts[1] for item in loop.iter.elts}
        self.assertEqual(set(bindings), {"persistence_dsn", "connect_timeout_seconds",
            "planner_public_key", "verifier_public_key", "_planner_identity", "_verifier_identity", "_database_identity"})
        for index, name in enumerate(("persistence_dsn", "connect_timeout_seconds", "planner_public_key",
                "verifier_public_key", "_planner_identity", "_verifier_identity", "_database_identity")):
            self.assert_shape(bindings[name], f"configuration[{index}]")
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
        self.assert_shape(inputs.body[2].value, "configuration[:6]")
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
            'connect_timeout=timeout, autocommit=False, options="-c search_path=pg_catalog")')
        opening = calls(run, "_connect")
        self.assertEqual(len(opening), 1)
        self.assert_shape(opening[0].args[0], "work")
        self.assert_shape(opening[0].args[1], 'lambda: psycopg.connect(dsn, row_factory=dict_row, '
            'connect_timeout=timeout, autocommit=False, options="-c search_path=pg_catalog")')
        imported_db, = [node for node in run.body if isinstance(node, ast.ImportFrom)
            and node.module == "serverware" and [(item.name, item.asname) for item in node.names] == [("db", None)]]
        self.assertLess(owned[0].lineno, imported_db.lineno)
        self.assertLess(imported_db.lineno, opening[0].lineno)
        role_guard, = [node for node in run.body if isinstance(node, ast.If)]
        self.assert_shape(role_guard.test,
            "configuration[6][0] != db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE")
        self.assert_shape(role_guard.body[0].exc,
            "ValueError('revocation writer role differs from the actual database contract')")
        self.assertLess(imported_db.lineno, role_guard.lineno)
        self.assertLess(role_guard.end_lineno, opening[0].lineno)
        delegated, = calls(run, "writer_connection._run_on_connection")
        self.assert_shape(delegated, "writer_connection._run_on_connection(connection, "
            "database_identity=configuration[6], work=work, operation=operation, arguments=arguments, expectations=owned)")
        self.assertLess(opening[0].lineno, delegated.lineno)
        self.assertFalse(calls(run, "operation"))
        self.assertFalse(calls(run, "store._context"))
        _, writer = source("serverware/authority_revocation_writer_connection.py", 128 * 1024)
        mode = next(node.value for node in writer.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "_SET_TRANSACTION" for target in node.targets))
        self.assertEqual(mode.value, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE")

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
        self.assert_shape(run.body[-1].value, "writer_connection._run_on_connection(connection, "
            "database_identity=configuration[6], work=work, operation=operation, arguments=arguments, expectations=owned)")
        self.assertFalse(calls(run, "operation"))
        self.assertEqual(len(calls(run, "writer_connection._run_on_connection")), 1)

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
        # Preserve the historical six-value method ID. The seventh item is
        # now mandatory independent writer-role/TLS configuration, never an
        # optional admission flag or a pin recovered from a stored record.
        snapshot = self.method("_snapshot_configuration")
        self.assert_shape(snapshot.body[0].test, "type(self) is not RevocationPlannerPersistence")
        self.assert_shape(snapshot.body[1].value,
            "(self.persistence_dsn, self.connect_timeout_seconds, self.planner_public_key, "
            "self.verifier_public_key, self._planner_identity, self._verifier_identity, self._database_identity)")
        self.assert_shape(snapshot.body[2].value, "_validate_configuration(configuration)")
        self.assert_shape(snapshot.body[3].value, "configuration")
        validation = definition(self.tree, "_validate_configuration")
        self.assert_shape(validation.body[1].test,
                         "type(configuration) is not tuple or len(configuration) != 7")
        self.assert_shape(validation.body[3].test,
            "type(dsn) is not str or not 1 <= len(dsn) <= 65536 "
            r"or any(character in dsn for character in ('\x00', '\n', '\r')) "
            "or type(timeout) is not int or not 2 <= timeout <= 300 "
            "or not isinstance(planner_key, Ed25519PublicKey) "
            "or not isinstance(verifier_key, Ed25519PublicKey)")
        encoded = validation.body[4]
        self.assertIsInstance(encoded, ast.Try)
        self.assert_shape(encoded.body[0].test, "len(dsn.encode('utf-8')) > 65536")
        self.assert_shape(encoded.handlers[0].type, "UnicodeError")
        identities = validation.body[5]
        self.assert_shape(identities.iter, "(planner_identity, verifier_identity)")
        self.assert_shape(identities.body[0].test,
                         "type(identity) is not tuple or len(identity) != 3")
        self.assert_shape(calls(identities, "retention.plan.contract._digest")[0],
                         "retention.plan.contract._digest(digest)")
        self.assert_shape(validation.body[6].value, "writer_connection._validate_database_identity(database_identity)")
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

    def test_observed_entry_owns_twelve_context_fields_and_inventory_before_read_callbacks(self):
        _, tree = source("serverware/authority_revocation_coordinator.py", 64 * 1024)
        owner = definition(tree, "RevocationPlanningCoordinator")
        method = definition(owner, "produce_observed_and_persist_with_cutoff")
        self.assertEqual([argument.arg for argument in method.args.kwonlyargs],
            ["request", "evidence", "context", "root_inventory", "planned_at_epoch_ns", "work"])
        self.assertIsNone(method.args.kwarg)
        self.assertTrue(all(value is None for value in method.args.kw_defaults))
        assignments = {node.targets[0].id: node.value for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
        self.assert_shape(assignments["_CALL_CONTEXT"],
            'retention.production._CONTEXT_FIELDS - {"expectedPlannerIdentity", "expectedVerifierIdentity"}')
        self.assert_shape(assignments["_OBSERVED_CALL_CONTEXT"], '_CALL_CONTEXT - {"expectedBefore"}')
        _, production = source("serverware/authority_revocation_plan_production.py", 64 * 1024)
        fields = next(node.value for node in production.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "_CONTEXT_FIELDS" for target in node.targets))
        self.assertEqual({item.value for item in fields.args[0].elts}
            - {"expectedPlannerIdentity", "expectedVerifierIdentity", "expectedBefore"},
            {"expectedCapabilityId", "expectedPlannerTransactionId", "expectedFence",
             "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs", "nowEpochNs",
             "nowMonotonicNs", "maximumAssertionAgeNs", "maximumPlanAgeNs", "maximumClockSkewNs",
             "expectedApproverPolicyDigest"})
        for expression in ("type(context) is not dict", "set(context) != _OBSERVED_CALL_CONTEXT",
                "len(context) != len(_OBSERVED_CALL_CONTEXT)", "type(planned_at_epoch_ns) is not int"):
            self.assertIn(expression, ast.unparse(method))
        read_snapshot, = calls(method, "self._snapshot_configuration")
        pins, = calls(method, "persistence._snapshot_configuration")
        ledger, = calls(method, "retention.capture._SharedLedger")
        copied = sorted(calls(method, "authority_query_reads._CopyBudget(work).copy"), key=lambda node: node.lineno)
        inventory, = calls(method, "observed._capture_root_inventory")
        validated, = calls(method, "observed._validate_partial_context")
        read, = calls(method, "_produce_on_read_configuration")
        self.assertEqual(len(copied), 3)
        self.assert_shape(copied[0],
            'authority_query_reads._CopyBudget(work).copy({"request": request, "evidence": evidence, "context": context})')
        self.assert_shape(inventory, "observed._capture_root_inventory(root_inventory, work=work)")
        self.assert_shape(validated, "observed._validate_partial_context(actual_context, work)")
        ordered = [read_snapshot, pins, ledger, copied[0], inventory, validated, read]
        self.assertEqual([item.lineno for item in ordered], sorted(item.lineno for item in ordered))
        self.assert_shape(read, "_produce_on_read_configuration(read_configuration, configured, "
            "owned=owned, actual_context=actual_context, work=work, root_inventory=inventory)")
        context = next(node.value for node in ast.walk(method) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "actual_context" for target in node.targets))
        self.assert_shape(context, '{**owned["context"], "expectedPlannerIdentity": '
            'dict(zip(persistence_module._IDENTITY_FIELDS, configured[4])), "expectedVerifierIdentity": '
            'dict(zip(persistence_module._IDENTITY_FIELDS, configured[5]))}')
        self.assertIn("identity[4:] != configured[4]", ast.unparse(method))

    def test_shared_read_body_selects_real_producer_and_owns_projected_context_before_exit(self):
        _, coordinator = source("serverware/authority_revocation_coordinator.py", 64 * 1024)
        facade = definition(coordinator, "_produce_on_read_configuration")
        delegated, = calls(facade, "planning._produce_on_read_configuration")
        self.assert_shape(delegated, "planning._produce_on_read_configuration(read_configuration[:4], "
            "planner_public_key=configured[2], verifier_public_key=configured[3], "
            "owned=owned, actual_context=actual_context, work=work, root_inventory=root_inventory)")
        caught, = [node for node in ast.walk(facade) if isinstance(node, ast.ExceptHandler)]
        self.assert_shape(caught.type, "planning.reader.roots.RevocationRootReadError")
        self.assert_shape(caught.body[-1].exc, "persistence_module.store._error(str(exc))")
        self.assert_shape(caught.body[-1].cause, "exc")
        _, tree = source("serverware/authority_revocation_planning.py", 64 * 1024)
        helper = definition(tree, "_produce_on_read_configuration")
        legacy, = calls(helper, "program._produce_revocation_plan")
        observed, = calls(helper, "program._produce_observed_revocation_plan")
        branch, = [node for node in ast.walk(helper) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "root_inventory is None"]
        self.assertIn(legacy, list(ast.walk(branch.body[0])))
        self.assertIn(observed, list(ast.walk(branch.orelse[0])))
        for call in (legacy, observed):
            self.assertEqual([ast.unparse(argument) for argument in call.args], ["guarded"])
            keywords = {item.arg: ast.unparse(item.value) for item in call.keywords}
            for name, value in {"request": "owned['request']", "evidence": "owned['evidence']",
                    "context": "actual_context", "manifest": "manifest + authorization",
                    "verifier_public_key": "verifier_public_key", "planner_private_key": "private_key",
                    "planner_public_key": "planner_public_key", "query_work": "work", "trace": "trace"}.items():
                self.assertEqual(keywords[name], value)
        self.assertEqual({item.arg: ast.unparse(item.value) for item in observed.keywords}["root_inventory"], "root_inventory")
        copied, = calls(helper, "authority_query_reads._CopyBudget(work).copy")
        self.assert_shape(copied, "authority_query_reads._CopyBudget(work).copy(produced.expected_context)")
        validated, = calls(helper, "retention.production._validate_context")
        self.assert_shape(validated, "retention.production._validate_context(expected_context, work)")
        bound, = calls(helper, "retention.plan.semantics._canonical_equal")
        self.assert_shape(bound, 'retention.plan.semantics._canonical_equal('
            '{name: expected_context[name] for name in actual_context}, actual_context, '
            'work=work, label="observed producer changed independent context pins")')
        self.assertLess(observed.lineno, copied.lineno)
        self.assertLess(copied.lineno, validated.lineno)
        self.assertLess(validated.lineno, bound.lineno)
        scopes = [node for node in ast.walk(helper) if isinstance(node, ast.With)]
        self.assertEqual(len(scopes), 3)
        captures = [node for node in ast.walk(helper) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id in
                {"envelope_bytes", "context_bytes", "database_now"} for target in node.targets)]
        self.assertEqual(len(captures), 3)
        for scope in scopes:
            for item in (legacy, observed, copied, validated, bound, *captures):
                self.assertIn(item, list(ast.walk(scope)))
        self.assertFalse(calls(helper, "persistence_module._run_on_configuration"))
        returned, = [node for node in ast.walk(helper) if isinstance(node, ast.Return)]
        self.assert_shape(returned.value, "(envelope_bytes, context_bytes, database_now, expected_context)")
        for scope in scopes:
            self.assertNotIn(returned, list(ast.walk(scope)))
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "json.loads", "time.time_ns", "time.monotonic_ns"):
            self.assertFalse(calls(helper, forbidden))

    def test_observed_writer_uses_detached_projected_expectations_and_returns_independent_history(self):
        _, tree = source("serverware/authority_revocation_coordinator.py", 64 * 1024)
        method = definition(tree, "produce_observed_and_persist_with_cutoff", "RevocationPlanningCoordinator")
        read, = calls(method, "_produce_on_read_configuration")
        copied = sorted(calls(method, "authority_query_reads._CopyBudget(work).copy"), key=lambda node: node.lineno)
        self.assert_shape(copied[1], "authority_query_reads._CopyBudget(work).copy({"
            "argument: expected_context[name] for name, argument in retention._CONTEXT_PAIRS if name in _CALL_CONTEXT})")
        self.assert_shape(copied[2], 'authority_query_reads._CopyBudget(work).copy(owned["request"])')
        persisted, = calls(method, "persistence_module._run_on_configuration")
        self.assertLess(read.lineno, copied[1].lineno)
        self.assertLess(copied[1].lineno, copied[2].lineno)
        self.assertLess(copied[2].lineno, persisted.lineno)
        self.assert_shape(persisted, 'persistence_module._run_on_configuration(configured, '
            'store.persist_revocation_planner_record, {"envelope_bytes": envelope_bytes, '
            '"evaluation_context_bytes": context_bytes, "planned_at_epoch_ns": planned_at_epoch_ns}, expectations, work)')
        self.assertNotIn("owned['context'][name]", ast.unparse(method))
        self.assertEqual(len(calls(method, "_PersistedObservedRevocationPlan")), 1)
        self.assert_shape(method.body[-1].value, "_PersistedObservedRevocationPlan(retained, database_now, expected_context)")
        carrier = definition(tree, "_PersistedObservedRevocationPlan")
        self.assert_shape(carrier.decorator_list[0], "dataclass(frozen=True, slots=True)")
        self.assertEqual([node.target.id for node in carrier.body if isinstance(node, ast.AnnAssign)],
            ["retained", "database_now", "expected_context"])
        legacy = definition(tree, "produce_and_persist_with_cutoff", "RevocationPlanningCoordinator")
        self.assert_shape(legacy.body[-1].value, "(retained, database_now)")
        exact_read, = calls(legacy, "_produce_on_read_configuration")
        self.assertNotIn("root_inventory", {item.arg for item in exact_read.keywords})
        # The real persistence runner still owns inputs and invokes the actual
        # raw-record store. Neither the returned carrier nor its context is a
        # successful-verification argument accepted by that API.
        runner = definition(self.tree, "_run_on_configuration")
        self.assertEqual(len(calls(runner, "_inputs_from_configuration")), 1)
        self.assertEqual(len(calls(runner, "writer_connection._run_on_connection")), 1)
        self.assertFalse(calls(runner, "operation"))
        service, _ = source("serverware/authority_service.py", 2 * 1024 * 1024)
        self.assertNotIn("produce_observed_and_persist_with_cutoff", service)

    def test_shared_read_driver_getters_and_bindings_are_guarded_without_extra_allowance(self):
        _, tree = source("serverware/authority_revocation_planning.py", 64 * 1024)
        fetched = definition(tree, "_call", "_ReadResult")
        executed = definition(tree, "execute", "_ReadCursor")
        guarded_fetch, = calls(fetched, "cursor._call")
        guarded_execute, = calls(executed, "self._call")
        self.assert_shape(guarded_fetch, "cursor._call(lambda: getattr(result, method)(*args))")
        self.assert_shape(guarded_execute, "self._call(lambda: cursor.execute(*arguments))")
        for expression in ("self._identity is not identity", "self._result is not result", "self._cursor is not cursor"):
            self.assertIn(expression, ast.unparse(fetched))
        cursor_call = definition(tree, "_call", "_ReadCursor")
        required = definition(tree, "_require", "_ReadCursor")
        self.assertIn("self._identity is not identity", ast.unparse(required))
        self.assert_shape(calls(required, "zip")[0].args[0],
            "(self._cursor, self._connection, self._raw, self._work)")
        self.assert_shape(calls(required, "zip")[0].args[1], "identity")
        invoke = next(node for node in cursor_call.body if isinstance(node, ast.FunctionDef) and node.name == "invoke")
        self.assertEqual(len(calls(invoke, "self._require")), 4)
        self.assertEqual([ast.unparse(item) for item in calls(invoke, "reader.roots._callback")], [
            "reader.roots._callback(work, reader._require_connection, connection, raw, 2)",
            "reader.roots._callback(work, reader._require_connection, connection, raw, 2)"])
        self.assert_shape(cursor_call.body[-1].value, "reader.roots._callback(work, invoke)")
        for body in (fetched, executed, cursor_call, required):
            self.assertFalse(calls(body, "_ValidationWork"))
        helper = definition(tree, "_produce_on_read_configuration")
        callbacks = calls(helper, "reader.roots._callback")
        for expression in ("reader.roots._callback(work, lambda: connection.transaction())",
                "reader.roots._callback(work, lambda: connection.cursor())"):
            self.assertIn(expression, {ast.unparse(item) for item in callbacks})
        connected, = calls(helper, "psycopg.connect")
        self.assert_shape(connected, 'psycopg.connect(read_dsn, row_factory=dict_row, '
            'connect_timeout=timeout, options="-c search_path=pg_catalog")')
        self.assertEqual({ast.unparse(item) for item in calls(helper, "reader._context")}, {
            "reader._context(connection, work)", "reader._context(transaction, work)", "reader._context(cursor, work)"})


if __name__ == "__main__":
    unittest.main()
