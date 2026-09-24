#!/usr/bin/env python3
"""Nonimporting linkage checks for the configured original-byte issuer.

These authored AST controls do not import db, service, planner or registry;
they do not execute extracted code, connect, prove ACL/mTLS admission or native
transaction outcomes. The separate genuine replay fixture models the explicit
private admitted-opener seam, not successful execution of this real connector.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_FIELDS = {"expected_request", "expected_capability_id", "expected_planner_transaction_id",
    "expected_fence", "reserved_at_epoch_ns", "deadline_epoch_ns", "deadline_monotonic_ns", "now_epoch_ns",
    "now_monotonic_ns", "database_now", "maximum_assertion_age_ns", "maximum_plan_age_ns",
    "maximum_clock_skew_ns", "expected_before", "expected_approver_policy_digest"}


def read(relative, maximum=256 * 1024):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("configured issuer source exceeds its explicit bound")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=relative)


def definition(tree, name):
    matches = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name]
    if len(matches) != 1:
        raise AssertionError("configured issuer source definition is not unique: " + name)
    return matches[0]


def assignment(tree, name):
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(matches) != 1:
        raise AssertionError("configured issuer source assignment is not unique: " + name)
    return matches[0]


def calls(tree, spelling):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == spelling), key=lambda node: (node.lineno, node.col_offset))


class RevocationIssuerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source, cls.tree = read("serverware/authority_revocation_issuance.py")
        cls.owner = definition(cls.tree, "RevocationCapabilityIssuer")
        cls.db_source, cls.db = read("serverware/db.py", 16 * 1024 * 1024)
        cls.cap_source, cls.cap = read("serverware/authority_revocation_capability.py")
        cls.persistence_source, cls.persistence = read("serverware/authority_revocation_persistence.py")
        cls.store_source, cls.store = read("serverware/authority_store/revocation_retention.py")
        cls.issuance_source, cls.issuance = read("serverware/authority_store/revocation_capability.py")

    def assert_shape(self, actual, expression):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expression.strip() + ")", mode="eval").body))

    def test_module_is_registry_free_and_exposes_only_the_fixed_frozen_configuration(self):
        imports = [(node.module, tuple((alias.name, alias.asname) for alias in node.names))
            for node in self.tree.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, [("__future__", (("annotations", None),)),
            ("dataclasses", (("dataclass", None),)),
            ("cryptography.hazmat.primitives.asymmetric.ed25519", (("Ed25519PublicKey", None),)),
            ("serverware", (("authority_revocation_capability", "capability"),)),
            ("serverware", (("authority_revocation_invocation", "invocation"),)),
            ("serverware", (("authority_revocation_persistence", "persistence"),)),
            ("serverware.authority_store", (("revocation_capability", "issuance"),))])
        self.assertEqual([tuple((alias.name, alias.asname) for alias in node.names)
            for node in self.tree.body if isinstance(node, ast.Import)], [(('time', None),)])
        self.assert_shape(self.owner.decorator_list[0],
            "dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)")
        self.assertEqual([node.target.id for node in self.owner.body if isinstance(node, ast.AnnAssign)], ["_configuration"])
        self.assertEqual({node.name for node in self.owner.body if isinstance(node, ast.FunctionDef)},
            {"__init__", "_snapshot_configuration", "issue", "issue_authenticated"})
        self.assertNotIn("private_key", self.source)
        self.assertNotIn("authority_transition_registry", self.source)

    def test_constructor_captures_three_keys_two_identity_triples_and_five_policy_pins(self):
        constructor = definition(self.owner, "__init__")
        self.assertEqual([argument.arg for argument in constructor.args.kwonlyargs], [
            "planner_public_key", "verifier_public_key", "witness_public_key", "expected_planner_identity",
            "expected_verifier_identity", "expected_issuer_session_identity_digest", "issuer_pins",
            "expected_configuration_digest", "expected_witness_identity_digest", "expected_generation_sequence",
            "expected_generation_digest"])
        self.assert_shape(assignment(constructor, "configuration").value, """(
            planner_public_key, verifier_public_key, witness_public_key,
            tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS),
            tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS),
            expected_issuer_session_identity_digest, tuple(issuer_pins[name] for name in _PIN_FIELDS),
            expected_configuration_digest, expected_witness_identity_digest,
            expected_generation_sequence, expected_generation_digest)""")
        identities = calls(constructor, "capability.shape.validate_identity_shape")
        self.assertEqual([ast.unparse(call.args[0]) for call in identities],
            ["expected_planner_identity", "expected_verifier_identity"])
        self.assert_shape(calls(constructor, "issuance._closed")[0], "issuance._closed(issuer_pins, _PIN_FIELDS)")
        validate, publish = calls(constructor, "_validate_configuration"), calls(constructor, "object.__setattr__")
        self.assertEqual((len(validate), len(publish)), (1, 1))
        self.assertLess(validate[0].lineno, publish[0].lineno)
        self.assert_shape(publish[0], 'object.__setattr__(self, "_configuration", configuration)')
        self.assertFalse(calls(constructor, "public_bytes"))
        snapshot = definition(self.owner, "_snapshot_configuration")
        self.assert_shape(snapshot.body[0].test, "type(self) is not RevocationCapabilityIssuer")
        self.assert_shape(assignment(snapshot, "configuration").value, "self._configuration")
        self.assert_shape(snapshot.body[-1].value, "configuration")
        validation = definition(self.tree, "_validate_configuration")
        self.assert_shape(validation.body[1].test, "type(configuration) is not tuple or len(configuration) != 11")
        self.assertIn("len(identity) != 3", ast.get_source_segment(self.source, validation))
        self.assertIn("len(pins) != 5", ast.get_source_segment(self.source, validation))

    def test_exact_fifteen_historical_inputs_cannot_replace_role_bound_signer_or_pins(self):
        self.assert_shape(assignment(self.tree, "_CALL_INPUTS").value, "capability.wire._EXPECTATIONS - _CONFIGURED")
        self.assert_shape(assignment(self.tree, "_CONFIGURED").value, """frozenset({
            "planner_public_key", "verifier_public_key", "expected_planner_identity", "expected_verifier_identity"})""")
        _, plan = read("serverware/authority_revocation_plan.py")
        inventory = assignment(plan, "_VERIFICATION_INPUTS").value.args[0]
        self.assertEqual({item.value for item in inventory.elts} - {"envelope", "planner_public_key", "verifier_public_key",
            "expected_planner_identity", "expected_verifier_identity"}, HISTORICAL_FIELDS)
        inputs = definition(self.tree, "_inputs_from_configuration")
        self.assert_shape(inputs.body[1].test, """type(expectations) is not dict or len(expectations) != len(_CALL_INPUTS)
            or any(type(name) is not str for name in expectations) or set(expectations) != _CALL_INPUTS""")
        handles = assignment(inputs, "handles").value
        self.assert_shape(handles, '{"planner_public_key": planner_key, "verifier_public_key": verifier_key, "database_now": expectations["database_now"]}')
        capture = calls(inputs, "capability._capture_expectations")
        self.assertEqual(len(capture), 1)
        keywords = {keyword.arg: keyword.value for keyword in capture[0].keywords}
        self.assert_shape(keywords["expected_signer_identity"], "dict(zip(_IDENTITY_FIELDS, verifier_identity))")
        self.assert_shape(keywords["expected_execution_envelope_id"], "execution_id")
        self.assert_shape(keywords["expected_witness_receipt_digest"], "receipt_id")
        result = inputs.body[-1].value
        mapping = {key.value: value for key, value in zip(result.keys, result.values)}
        self.assert_shape(mapping["signer_public_key"], "verifier_key")
        self.assert_shape(mapping["witness_public_key"], "witness_key")
        self.assert_shape(mapping["retention_expectations"], '{**owned["retention"], **handles}')
        self.assert_shape(assignment(inputs, "pins").value,
            "capability.capture._JSONCapture(ledger).visit(dict(zip(_PIN_FIELDS, issuer_pins)), depth=0)")
        shared = definition(self.cap, "_capture_expectations")
        body = ast.get_source_segment(self.cap_source, shared)
        self.assertIn('"expectedExecutionEnvelopeId"', body)
        self.assertIn('"expectedWitnessReceiptDigest"', body)
        self.assertIn("shape._digest(owned[name])", body)

    def test_private_worker_owns_inputs_before_connect_and_delegates_once_on_original_work(self):
        run = definition(self.tree, "_run_on_configuration")
        self.assertIsNone(run.args.kwarg)
        self.assertEqual([argument.arg for argument in run.args.kwonlyargs], ["envelope_bytes", "witness_request_bytes",
            "expected_execution_envelope_id", "expected_witness_receipt_digest", "expectations", "work", "opener"])
        self.assertEqual([argument.arg for argument in run.args.args], ["configuration"])
        guards = calls(run, "capability.capture._SharedLedger")
        capture, connect, store = (calls(run, name) for name in (
            "_inputs_from_configuration", "persistence._connect", "issuance._issue_on_connection"))
        self.assertEqual(tuple(map(len, (guards, capture, connect, store))), (1, 1, 1, 1))
        self.assertLess(guards[0].lineno, capture[0].lineno)
        self.assertLess(capture[0].lineno, connect[0].lineno)
        self.assertLess(connect[0].lineno, store[0].lineno)
        self.assert_shape(connect[0], "persistence._connect(work, opener)")
        self.assert_shape(store[0], """issuance._issue_on_connection(connection=connection, work=work,
            envelope_bytes=envelope_bytes, witness_request_bytes=witness_request_bytes, **inputs)""")
        scopes = [node for node in ast.walk(run) if isinstance(node, ast.With)]
        self.assertEqual(len(scopes), 1)
        self.assert_shape(scopes[0].items[0].context_expr, "persistence.store._context(connection, work)")
        self.assertIn(store[0], tuple(ast.walk(scopes[0])))
        check = [node for node in ast.walk(run) if isinstance(node, ast.If)
            and "type(raw)" in ast.unparse(node.test)]
        self.assertEqual(len(check), 1)
        self.assertLess(check[0].lineno, connect[0].lineno)
        self.assertFalse(calls(run, "operation"))
        self.assertFalse(calls(run, "connection.commit"))
        self.assertFalse(calls(run, "connection.close"))

    def test_result_is_copied_closed_and_bound_before_the_outer_context_exits(self):
        run = definition(self.tree, "_run_on_configuration")
        owned = calls(run, "issuance._row")
        matched = calls(run, "persistence.store._match")
        self.assertEqual((len(owned), len(matched)), (1, 1))
        self.assert_shape(owned[0], "issuance._row(result, issuance._IDENTITY_FIELDS, work)")
        self.assert_shape(matched[0], 'persistence.store._match(result, {"capabilityId": inputs["retention_expectations"]["expected_capability_id"]}, work)')
        active = calls(run, "issuance._call")
        self.assertEqual(len(active), 2)
        self.assertLess(active[0].lineno, calls(run, "issuance._issue_on_connection")[0].lineno)
        self.assertLess(owned[0].lineno, matched[0].lineno)
        self.assertLess(matched[0].lineno, active[1].lineno)
        context = next(node for node in run.body if isinstance(node, ast.With))
        for node in (owned[0], matched[0], active[1]):
            self.assertIn(node, tuple(ast.walk(context)))
        self.assert_shape(run.body[-1].value, "result")
        self.assertEqual(len(calls(run, "capability.shape._digest")), 1)
        names = {node.id for node in ast.walk(self.tree) if isinstance(node, ast.Name)}
        self.assertTrue(names.isdisjoint({"_ValidationWork", "QueryReadValidationLimits", "_PackagingLedger",
            "json", "base64", "hashlib", "datetime"}))
        attributes = {node.attr for node in ast.walk(self.tree) if isinstance(node, ast.Attribute)}
        self.assertTrue(attributes.isdisjoint({"sign", "verify", "loads", "dumps", "now"}))
        # The original historical entry remains clock-free. Only the separate
        # authenticated invocation prefix may sample its guarded live clocks.
        legacy_attributes = {node.attr for node in ast.walk(run) if isinstance(node, ast.Attribute)}
        self.assertTrue(legacy_attributes.isdisjoint({"time_ns", "monotonic_ns"}))

    def test_public_method_lazy_binds_only_the_real_issuer_connector_after_snapshot(self):
        issue = definition(self.owner, "issue")
        self.assertEqual([argument.arg for argument in issue.args.kwonlyargs], ["envelope_bytes", "witness_request_bytes",
            "expected_execution_envelope_id", "expected_witness_receipt_digest", "work"])
        self.assertEqual(issue.args.kwarg.arg, "expectations")
        self.assert_shape(assignment(issue, "configuration").value, "self._snapshot_configuration()")
        opener = definition(issue, "open_issuer")
        self.assertEqual(len(opener.body), 2)
        self.assertIsInstance(opener.body[0], ast.ImportFrom)
        self.assertEqual((opener.body[0].module, tuple(alias.name for alias in opener.body[0].names)), ("serverware", ("db",)))
        self.assert_shape(opener.body[1].value, "db._policy_authority_capability_issuer_pg_connect_raw()")
        run = calls(issue, "_run_on_configuration")
        self.assertEqual(len(run), 1)
        self.assert_shape(run[0], """_run_on_configuration(configuration, envelope_bytes=envelope_bytes,
            witness_request_bytes=witness_request_bytes, expected_execution_envelope_id=expected_execution_envelope_id,
            expected_witness_receipt_digest=expected_witness_receipt_digest, expectations=expectations, work=work, opener=open_issuer)""")
        self.assertFalse(calls(issue, "open_issuer"))
        self.assertLess(assignment(issue, "configuration").lineno, opener.lineno)
        self.assertNotIn("dsn", ast.get_source_segment(self.source, issue).lower().split("return _run_on_configuration", 1)[1])
        for module in ("serverware/authority_service.py", "serverware/authority_store/executor_v9.py"):
            source, _tree = read(module, 2 * 1024 * 1024)
            self.assertNotIn("RevocationCapabilityIssuer", source)
            self.assertNotIn("authority_revocation_issuance", source)

    def test_linked_real_connector_starts_the_exact_transaction_and_preserves_caller_ownership(self):
        connector = definition(self.db, "_policy_authority_capability_issuer_pg_connect_raw")
        connection = calls(connector, "psycopg.connect")
        self.assertEqual(len(connection), 1)
        kwargs = {keyword.arg: keyword.value for keyword in connection[0].keywords}
        self.assert_shape(kwargs["autocommit"], "False")
        statements = calls(connector, "cur.execute")
        self.assertEqual(len(statements), 5)
        self.assertEqual(statements[0].args[0].value,
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE")
        self.assertEqual(statements[1].args[0].value,
            "SET search_path TO serverware_metadata, pg_catalog, pg_temp")
        source = ast.get_source_segment(self.db_source, connector)
        for clause in ("transaction_isolation", "transaction_read_only", "transaction_deferrable",
                '"serializable"', '"off"'):
            self.assertIn(clause, source)
        returns = [node for node in ast.walk(connector) if isinstance(node, ast.Return)]
        self.assertEqual(len(returns), 1)
        self.assert_shape(returns[0].value, "conn")
        self.assertFalse(calls(connector, "conn.commit"))
        self.assertFalse(calls(connector, "conn.rollback"))
        cleanup = [node for node in ast.walk(connector) if isinstance(node, ast.ExceptHandler)
            and isinstance(node.type, ast.Name) and node.type.id == "BaseException"]
        self.assertTrue(any(calls(node, "conn.close") for node in cleanup))
        self.assertEqual(len(calls(connector, "conn.close")), 1)

    def test_shared_connection_helpers_close_returned_handles_and_do_not_retry_commit_exit(self):
        connect = definition(self.persistence, "_connect")
        self.assertEqual(len(calls(connect, "store._callback")), 1)
        self.assertEqual(len(calls(connect, "connection.close")), 1)
        self.assertIn("except BaseException", ast.get_source_segment(self.persistence_source, connect))
        context = definition(self.store, "_context")
        source = ast.get_source_segment(self.store_source, context)
        self.assertIn("entered = False", source)
        self.assertIn("entered = True", source)
        self.assertIn("manager.__exit__(type(exc), exc, exc.__traceback__)", source)
        # The successful exit callback is guarded once; an error after that
        # driver's commit cannot safely cause a second rollback/exit attempt.
        self.assertEqual(len(calls(context, "_callback")), 2)
        self.assert_shape(calls(context, "_callback")[-1], "_callback(work, leave)")
        leave = [node for node in ast.walk(context) if isinstance(node, ast.FunctionDef) and node.name == "leave"]
        self.assertEqual(len(leave), 1)
        self.assert_shape(assignment(leave[0], "exited").value, "True")
        self.assert_shape(leave[0].body[-1].value, "manager.__exit__(None, None, None)")
        self.assertLess(assignment(leave[0], "exited").lineno, leave[0].body[-1].lineno)
        retry = [node for node in ast.walk(context) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "not exited"]
        self.assertEqual(len(retry), 1)
        self.assertEqual(len(calls(retry[0], "manager.__exit__")), 1)
        self.assert_shape(calls(retry[0], "manager.__exit__")[0], "manager.__exit__(type(exc), exc, exc.__traceback__)")
        worker = definition(self.issuance, "_issue_on_connection")
        self.assertEqual(len(calls(worker, "capability._verify_signed_capability_on_work")), 1)
        self.assertEqual(len(calls(worker, "_fresh")), 2)
        self.assertEqual(len(calls(worker, "_load")), 2)
        self.assertFalse(calls(worker, "connection.commit"))

    def test_authenticated_worker_bounds_original_bytes_and_snapshots_pins_before_live_clocks(self):
        worker = definition(self.tree, "_issue_invocation_on_configuration")
        self.assertEqual([argument.arg for argument in worker.args.args], ["configuration"])
        self.assertEqual([argument.arg for argument in worker.args.kwonlyargs],
            ["envelope_bytes", "work", "opener"])
        self.assertIsNone(worker.args.kwarg)
        validated, measured = calls(worker, "_validate_configuration"), calls(worker, "capability.capture._SharedLedger")
        self.assertEqual((len(validated), len(measured)), (1, 1))
        self.assert_shape(validated[0], "_validate_configuration(configuration)")
        self.assert_shape(measured[0], "capability.capture._SharedLedger(work)")
        bounds = [node for node in worker.body if isinstance(node, ast.If)]
        self.assertEqual(len(bounds), 1)
        self.assert_shape(bounds[0].test, """type(envelope_bytes) is not bytes
            or not 2 <= len(envelope_bytes) <= capability.authority.MAX_REQUEST_BYTES""")
        clocks = calls(worker, "persistence.store._callback")
        self.assertEqual(len(clocks), 2)
        self.assert_shape(clocks[0], "persistence.store._callback(work, time.monotonic_ns)")
        self.assert_shape(clocks[1], "persistence.store._callback(work, time.time_ns)")
        self.assertLess(validated[0].lineno, measured[0].lineno)
        self.assertLess(measured[0].lineno, bounds[0].lineno)
        bindings = {ast.unparse(node.targets[0]): node for node in worker.body
            if isinstance(node, ast.Assign) and len(node.targets) == 1}
        for target, expected in {
            "verifier_key": "configuration[1]", "configuration_digest": "configuration[7]",
            "(generation_sequence, generation_digest)": "configuration[9:11]",
            "(maximum_age_ns, maximum_clock_skew_ns)": "configuration[6][3:5]",
        }.items():
            self.assert_shape(bindings[target].value, expected)
            self.assertLess(bounds[0].lineno, bindings[target].lineno)
            self.assertLess(bindings[target].lineno, clocks[0].lineno)
        self.assert_shape(bindings["now_monotonic_ns"].value, "persistence.store._callback(work, time.monotonic_ns)")
        self.assert_shape(bindings["now_epoch_ns"].value, "persistence.store._callback(work, time.time_ns)")
        all_clocks = [node for node in ast.walk(self.tree) if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "time"]
        self.assertEqual({node.attr for node in all_clocks}, {"time_ns", "monotonic_ns"})
        self.assertEqual(len(all_clocks), 2)
        self.assertTrue(all(node in tuple(ast.walk(worker)) for node in all_clocks))

    def test_authenticated_prefix_verifies_raw_originals_before_the_unchanged_issuer_runner(self):
        worker = definition(self.tree, "_issue_invocation_on_configuration")
        verified = calls(worker, "invocation._verify_invocation_on_work")
        delegated = calls(worker, "_run_on_configuration")
        self.assertEqual((len(verified), len(delegated)), (1, 1))
        self.assert_shape(verified[0], """invocation._verify_invocation_on_work(
            envelope_bytes=envelope_bytes, verifier_public_key=verifier_key,
            expected_configuration_digest=configuration_digest,
            expected_generation_sequence=generation_sequence, expected_generation_digest=generation_digest,
            now_epoch_ns=now_epoch_ns, now_monotonic_ns=now_monotonic_ns,
            maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)""")
        self.assertIs(assignment(worker, "received").value, verified[0])
        self.assertLess(calls(worker, "persistence.store._callback")[-1].lineno, verified[0].lineno)
        self.assertLess(verified[0].lineno, delegated[0].lineno)
        self.assert_shape(delegated[0], """_run_on_configuration(configuration,
            envelope_bytes=received.capability_bytes, witness_request_bytes=received.witness_request_bytes,
            expected_execution_envelope_id=received.execution_envelope_id,
            expected_witness_receipt_digest=received.witness_receipt_digest,
            expectations=received.historical_expectations, work=work, opener=opener)""")
        self.assertIs(worker.body[-1].value, delegated[0])
        for forbidden in ("opener", "persistence._connect", "issuance._issue_on_connection",
                "self.issue", "self._snapshot_configuration", "json.loads", "_ValidationWork"):
            self.assertFalse(calls(worker, forbidden))
        # Publication still crosses the actual old runner, whose own capture,
        # connection context and genuine store calls the retained tests pin.
        runner = definition(self.tree, "_run_on_configuration")
        self.assertEqual(len(calls(runner, "_inputs_from_configuration")), 1)
        self.assertEqual(len(calls(runner, "persistence._connect")), 1)
        self.assertEqual(len(calls(runner, "issuance._issue_on_connection")), 1)

    def test_authenticated_method_owns_one_snapshot_and_lazy_real_connector_without_service_activation(self):
        method = definition(self.owner, "issue_authenticated")
        self.assertEqual([argument.arg for argument in method.args.kwonlyargs], ["envelope_bytes", "work"])
        self.assertIsNone(method.args.kwarg)
        snapshot = calls(method, "self._snapshot_configuration")
        self.assertEqual(len(snapshot), 1)
        self.assertIs(assignment(method, "configuration").value, snapshot[0])
        opener = definition(method, "open_issuer")
        self.assertEqual(len(opener.body), 2)
        self.assertIsInstance(opener.body[0], ast.ImportFrom)
        self.assertEqual((opener.body[0].module, tuple(alias.name for alias in opener.body[0].names)),
            ("serverware", ("db",)))
        self.assert_shape(opener.body[1].value, "db._policy_authority_capability_issuer_pg_connect_raw()")
        delegated = calls(method, "_issue_invocation_on_configuration")
        self.assertEqual(len(delegated), 1)
        self.assert_shape(delegated[0], """_issue_invocation_on_configuration(configuration,
            envelope_bytes=envelope_bytes, work=work, opener=open_issuer)""")
        self.assertLess(snapshot[0].lineno, opener.lineno)
        self.assertLess(opener.lineno, delegated[0].lineno)
        self.assertIs(method.body[-1].value, delegated[0])
        for forbidden in ("open_issuer", "self.issue", "_run_on_configuration", "issuance._issue_on_connection"):
            self.assertFalse(calls(method, forbidden))
        for module in ("serverware/authority_service.py", "serverware/authority_store/executor_v9.py"):
            source, _tree = read(module, 2 * 1024 * 1024)
            self.assertNotIn("RevocationCapabilityIssuer", source)
            self.assertNotIn("authority_revocation_issuance", source)
            self.assertNotIn("issue_authenticated", source)


if __name__ == "__main__":
    unittest.main()
