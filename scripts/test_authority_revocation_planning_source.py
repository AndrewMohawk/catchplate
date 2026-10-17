#!/usr/bin/env python3
"""Nonimporting linkage for the planner-only original-byte read owner.

Bounded source checks do not execute an extracted producer, replace the active
registry, or establish PostgreSQL, signature, transaction or launch admission.
The genuine planner remains a lazy dependency with its existing closed gate;
the new owner has no writer credential, persistence or public dispatch route.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(path, maximum=256 * 1024):
    target = ROOT / path
    if target.stat().st_size > maximum:
        raise AssertionError("revocation planning source exceeds its inspection bound")
    text = target.read_text(encoding="utf-8")
    return text, ast.parse(text, filename=path)


def definition(tree, name):
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
             and node.name == name]
    if len(nodes) != 1:
        raise AssertionError("revocation planning definition is not unique: " + name)
    return nodes[0]


def calls(tree, name):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == name), key=lambda node: (node.lineno, node.col_offset))


def call(tree, name):
    nodes = calls(tree, name)
    if len(nodes) != 1:
        raise AssertionError("revocation planning call is not unique: " + name)
    return nodes[0]


def assigned(tree, name):
    nodes = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(nodes) != 1:
        raise AssertionError("revocation planning assignment is not unique: " + name)
    return nodes[0]


def keywords(node):
    if any(item.arg is None for item in node.keywords):
        raise AssertionError("revocation planning call has open keyword expansion")
    return {item.arg: item.value for item in node.keywords}


class RevocationPlanningSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("catchplate/authority_revocation_planning.py", 64 * 1024)
        cls.owner = definition(cls.tree, "RevocationObservedPlanner")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_closed_owner_configuration_and_call_accept_no_writer_or_producer_override(self):
        constructor = definition(self.owner, "__init__")
        self.assertEqual([item.arg for item in constructor.args.args], ["self"])
        self.assertEqual([item.arg for item in constructor.args.kwonlyargs], [
            "read_dsn", "connect_timeout_seconds", "database_identity", "planner_private_key",
            "planner_public_key", "verifier_public_key", "expected_verifier_identity",
            "maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns"])
        self.assertIsNone(constructor.args.kwarg)
        self.assertIsNone(constructor.args.vararg)
        produce = definition(self.owner, "produce_observed")
        self.assertEqual([item.arg for item in produce.args.args], ["self"])
        self.assertEqual([item.arg for item in produce.args.kwonlyargs],
            ["request", "evidence", "context", "root_inventory", "work"])
        self.assertTrue(all(value is None for value in produce.args.kw_defaults))
        self.assertIsNone(produce.args.kwarg)
        self.assertIsNone(produce.args.vararg)
        carrier = definition(self.tree, "_ProducedObservedPlanBytes")
        self.assertEqual([node.target.id for node in carrier.body if isinstance(node, ast.AnnAssign)],
            ["envelope_bytes", "evaluation_context_bytes", "database_now", "expected_context"])
        for forbidden in ("authority_revocation_persistence", "authority_store.revocation_retention",
                "RevocationPlannerPersistence", "persist_revocation_planner_record", "persistence_dsn",
                "authority_service", "authority_transition_registry"):
            self.assertNotIn(forbidden, self.text)

    def test_private_owner_has_no_service_dispatch_or_expanded_database_credentials(self):
        service_text, service = source("catchplate/authority_service.py", 2 * 1024 * 1024)
        process = definition(service, "AuthorityProcess")
        handle = definition(process, "handle")
        admissions = calls(handle, "self._verify_internal_envelope")
        self.assertEqual(len(admissions), 3)
        self.shape(keywords(admissions[0])["allowed_purposes"], '{"plan-operation"}')
        self.shape(keywords(admissions[1])["allowed_purposes"], '''{
            "persist-measured-plan", "read-persisted-plan", "reserve-execution-envelope"}''')
        self.shape(keywords(admissions[2])["allowed_purposes"], '''
            {"issue-capability", "record-witness-receipt"} if self.role_name == "issuer" else {"execute-v9"}''')
        # Private measured construction is allowed; the public parser and
        # legacy purpose dispatch still cannot activate the successor owner.
        server = definition(service, "AuthorityServer")
        serve = definition(server, "_serve_connection")
        for public in (handle, serve):
            for forbidden in ("authority_revocation_planning", "RevocationObservedPlanner",
                    "_produce_revocation_observed_plan", "_planner_from_configuration_on_work"):
                self.assertNotIn(forbidden, ast.unparse(public))
        credentials = definition(process, "_reject_wrong_credentials")
        self.shape(assigned(credentials, "allowed"), '''{
            "verifier": {"CATCHPLATE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD"},
            "planner": {"CATCHPLATE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD"},
            "planner-writer": {"CATCHPLATE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD"},
            "issuer": {"CATCHPLATE_POLICY_AUTHORITY_CAPABILITY_ISSUER_POSTGRES_DSN_FD"},
            "executor": {"CATCHPLATE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD"}}[self.role_name]''')
        registry, tree = source("catchplate/authority_transition_registry.py")
        self.assertNotIn("authority_revocation_planning", registry)
        self.shape(assigned(tree, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        guards = [node for node in tree.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 1)
        self.shape(guards[0].test, "_CLOSURE_ERRORS")
        self.assertIsInstance(guards[0].body[0], ast.Raise)

    def test_fixed_ten_settings_are_revalidated_without_tightening_legacy_read_policy(self):
        constructor = definition(self.owner, "__init__")
        self.shape(assigned(constructor, "configuration"), '''(
            read_dsn, connect_timeout_seconds, database_identity, planner_private_key,
            planner_public_key, verifier_public_key,
            tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS),
            maximum_assertion_age_ns, maximum_plan_age_ns, maximum_clock_skew_ns)''')
        identity = call(constructor, "retention.plan.contract.validate_identity_shape")
        validate = call(constructor, "_validate_configuration")
        stored = call(constructor, "object.__setattr__")
        self.assertLess(identity.lineno, validate.lineno)
        self.assertLess(validate.lineno, stored.lineno)
        self.shape(stored, 'object.__setattr__(self, "_configuration", configuration)')
        snapshot = definition(self.owner, "_snapshot_configuration")
        self.shape(snapshot.body[0].test, "type(self) is not RevocationObservedPlanner")
        self.shape(assigned(snapshot, "configuration"), "self._configuration")
        self.shape(call(snapshot, "_validate_configuration"), "_validate_configuration(configuration)")
        self.shape(snapshot.body[-1].value, "configuration")
        configured = definition(self.tree, "_validate_configuration")
        read = definition(self.tree, "_validate_read_configuration")
        scope_configuration = definition(self.tree, "_validate_read_scope_configuration")
        self.shape(call(configured, "_validate_read_configuration"), "_validate_read_configuration(configuration[:4])")
        self.shape(call(read, "_validate_read_scope_configuration"), "_validate_read_scope_configuration(configuration[:3])")
        for expression in ("type(configuration) is not tuple", "len(configuration) != 10",
                "configuration[1] < 2", "configuration[8] > authority.VERIFIER_RESPONSE_MAX_AGE_NS",
                "configuration[9] != authority.VERIFIER_MAX_CLOCK_SKEW_NS"):
            self.assertIn(expression, ast.unparse(configured))
        for expression in ("len(configuration) != 4", "not isinstance(configuration[3], Ed25519PrivateKey)"):
            self.assertIn(expression, ast.unparse(read))
        for expression in ("len(configuration) != 3", "type(timeout) is not int",
                "not 1 <= timeout <= 300", "type(identity) is not tuple", "len(identity) != 7"):
            self.assertIn(expression, ast.unparse(scope_configuration))
        self.assertIn("not isinstance(key, Ed25519PublicKey)", ast.unparse(configured))
        self.assertIn("len(identity) != 3", ast.unparse(configured))
        body = definition(self.tree, "_produce_on_read_configuration")
        self.assertFalse(calls(body, "_validate_configuration"))
        self.assertFalse(calls(body, "_capture_planning_inputs"))
        self.assertFalse(calls(body, "observed._validate_partial_context"))

    def test_closed_nine_field_graph_and_full_inventory_are_owned_before_lazy_read(self):
        self.shape(assigned(self.tree, "_CONFIGURED_CONTEXT"), '''frozenset({
            "expectedPlannerIdentity", "expectedVerifierIdentity", "maximumAssertionAgeNs",
            "maximumPlanAgeNs", "maximumClockSkewNs"})''')
        self.shape(assigned(self.tree, "_CALL_CONTEXT"),
            'retention.production._CONTEXT_FIELDS - _CONFIGURED_CONTEXT - {"expectedBefore"}')
        _, production = source("catchplate/authority_revocation_plan_production.py")
        fields = assigned(production, "_CONTEXT_FIELDS")
        self.assertEqual({item.value for item in fields.args[0].elts} - {
            "expectedPlannerIdentity", "expectedVerifierIdentity", "expectedBefore",
            "maximumAssertionAgeNs", "maximumPlanAgeNs", "maximumClockSkewNs"}, {
            "expectedCapabilityId", "expectedPlannerTransactionId", "expectedFence",
            "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs", "nowEpochNs",
            "nowMonotonicNs", "expectedApproverPolicyDigest"})
        raw = definition(self.tree, "_capture_planning_call_inputs")
        self.assertEqual([item.arg for item in raw.args.kwonlyargs],
            ["request", "evidence", "context", "root_inventory", "work"])
        self.assertIsNone(raw.args.kwarg)
        self.assertIsNone(raw.args.vararg)
        sequence = [call(raw, name) for name in (
            "retention.capture._SharedLedger", "retention.plan.contract._object",
            "authority_query_reads._CopyBudget(work).copy", "observed._capture_root_inventory")]
        self.assertEqual([node.lineno for node in sequence], sorted(node.lineno for node in sequence))
        self.shape(sequence[0], "retention.capture._SharedLedger(work)")
        self.shape(sequence[1], 'retention.plan.contract._object(context, _CALL_CONTEXT, "observed planner caller context")')
        self.shape(sequence[2], '''authority_query_reads._CopyBudget(work).copy(
            {"request": request, "evidence": evidence, "context": context})''')
        self.shape(sequence[3], "observed._capture_root_inventory(root_inventory, work=work)")
        guards = [node for node in raw.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 1)
        self.shape(guards[0].test, "type(request) is not dict or type(evidence) is not dict")
        self.shape(raw.body[-1].value, "(owned, inventory)")
        capture = definition(self.tree, "_capture_planning_inputs")
        sequence = [call(capture, name) for name in (
            "_validate_configuration", "_capture_planning_call_inputs",
            "retention.plan.contract._request", "observed._validate_partial_context")]
        self.assertEqual([node.lineno for node in sequence], sorted(node.lineno for node in sequence))
        self.shape(sequence[0], "_validate_configuration(configuration)")
        self.shape(sequence[1], '''_capture_planning_call_inputs(request=request, evidence=evidence,
            context=context, root_inventory=root_inventory, work=work)''')
        self.shape(assigned(capture, "actual_context"), '''{**owned["context"],
            "expectedPlannerIdentity": dict(zip(_IDENTITY_FIELDS, configuration[2][4:])),
            "expectedVerifierIdentity": dict(zip(_IDENTITY_FIELDS, configuration[6])),
            "maximumAssertionAgeNs": configuration[7], "maximumPlanAgeNs": configuration[8],
            "maximumClockSkewNs": configuration[9]}''')
        self.shape(capture.body[-1].value, "(owned, actual_context, inventory)")
        method = definition(self.owner, "produce_observed")
        snapshot = call(method, "self._snapshot_configuration")
        owned = call(method, "_capture_planning_inputs")
        read = call(method, "_produce_on_read_configuration")
        self.assertLess(snapshot.lineno, owned.lineno)
        self.assertLess(owned.lineno, read.lineno)
        self.shape(read, '''_produce_on_read_configuration(configuration[:4],
            planner_public_key=configuration[4], verifier_public_key=configuration[5],
            owned=owned, actual_context=actual_context, work=work, root_inventory=inventory)''')
        self.shape(method.body[-1].value,
            "_ProducedObservedPlanBytes(envelope, context_bytes, database_now, expected_context)")
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "json.loads", "time.time_ns", "time.monotonic_ns"):
            self.assertFalse(calls(self.tree, forbidden))

    def test_real_program_and_manifest_trace_stay_inside_three_lazy_read_scopes(self):
        body = definition(self.tree, "_produce_on_read_configuration")
        read = definition(self.tree, "_read_scope")
        eager = [node for node in self.tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any("authority_planner" in ast.unparse(node) or "psycopg" in ast.unparse(node)
            for node in eager))
        lazy = [node for node in body.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual([ast.unparse(node) for node in lazy], ["from catchplate import authority_planner as planner"])
        lazy = [node for node in read.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual([ast.unparse(node) for node in lazy], [
            "from catchplate import authority_planner as planner", "import psycopg",
            "from psycopg.rows import dict_row"])
        self.shape(read.decorator_list[0], "contextmanager")
        self.shape(assigned(self.tree, "_READ_OPERATIONS"), '''frozenset({"webauthn.credential.revoke",
            "webauthn.registration.evidence.admit", "webauthn.trust.installation.admit"})''')
        self.assertIn("type(operation) is not str or operation not in _READ_OPERATIONS", ast.unparse(read))
        self.shape(assigned(body, "operation"), "planner.authority_transition_webauthn.OPERATION")
        self.shape(call(body, "planner.TypedTransitionPlanningProgram"),
            "planner.TypedTransitionPlanningProgram(operation=operation, handler=kernel.handler, kernel=kernel)")
        self.shape(call(read, "planner.PlannerTrace"), '''planner.PlannerTrace(operation=operation,
            _complete_queries=operation == planner.authority_transition_webauthn.OPERATION)''')
        self.shape(call(read, "planner.PlannerIdentity"), "planner.PlannerIdentity(*identity)")
        scopes = [node for node in ast.walk(read) if isinstance(node, ast.With)]
        self.assertEqual(len(scopes), 3)
        self.assertEqual({ast.unparse(node.items[0].context_expr) for node in scopes}, {
            "reader._context(connection, work)", "reader._context(transaction, work)", "reader._context(cursor, work)"})
        mode = call(read, "guarded.execute")
        self.shape(mode, 'guarded.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE")')
        yielded, = [node for node in ast.walk(read) if isinstance(node, ast.Yield)]
        self.shape(yielded.value, "(guarded, manifest + authorization, trace)")
        ordered = [mode, call(read, "planner._validate_database_identity"),
            call(read, "planner._load_manifest"), call(read, "planner._load_authorization_manifest"), yielded]
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        for scope in scopes:
            for node in ordered:
                self.assertIn(node, list(ast.walk(scope)))
        for name in ("planner._load_manifest", "planner._load_authorization_manifest"):
            self.shape(call(read, name), name + "(guarded, operation=operation, trace=trace)")
        delegated, = [node for node in ast.walk(body) if isinstance(node, ast.With)]
        self.shape(delegated.items[0].context_expr,
            "_read_scope(read_configuration[:3], operation=operation, work=work)")
        self.assertEqual([node.id for node in delegated.items[0].optional_vars.elts], ["guarded", "manifest", "trace"])
        for name in ("program._produce_revocation_plan", "program._produce_observed_revocation_plan"):
            self.assertIn(call(body, name), list(ast.walk(delegated)))
        self.shape(call(body, "program._produce_observed_revocation_plan"), '''program._produce_observed_revocation_plan(
            guarded, request=owned["request"], evidence=owned["evidence"], context=actual_context,
            root_inventory=root_inventory, manifest=manifest,
            verifier_public_key=verifier_public_key, planner_private_key=private_key,
            planner_public_key=planner_public_key, query_work=work, trace=trace)''')
        for forbidden in ("planner.MeasuredPlanner", "planner.validate_planner_request", "planner._read_root_set",
                "retention._verify_record_on_work"):
            self.assertFalse(calls(body, forbidden))
            self.assertFalse(calls(read, forbidden))

    def test_raw_connection_transaction_and_cursor_are_checked_through_cleanup(self):
        producer = definition(self.tree, "_produce_on_read_configuration")
        self.shape(call(producer, "_read_scope"), "_read_scope(read_configuration[:3], operation=operation, work=work)")
        body = definition(self.tree, "_read_scope")
        self.shape(call(body, "reader._connect"), '''reader._connect(work, lambda: psycopg.connect(read_dsn,
            row_factory=dict_row, connect_timeout=timeout, options="-c search_path=pg_catalog"))''')
        self.shape(assigned(body, "raw"), "reader.roots._callback(work, reader._connection_identity, connection, 0)")
        self.shape(assigned(body, "transaction"), "reader.roots._callback(work, lambda: connection.transaction())")
        self.shape(assigned(body, "cursor"), "reader.roots._callback(work, lambda: connection.cursor())")
        self.shape(assigned(body, "guarded"), "_ReadCursor(active, connection, raw, work)")
        for expression in ("active_connection is not connection", "active is not cursor",
                "reader.roots._callback(work, lambda: connection.closed) is not True"):
            self.assertIn(expression, ast.unparse(body))
        requirements = [node for node in calls(body, "reader.roots._callback")
            if len(node.args) > 1 and ast.unparse(node.args[1]) == "reader._require_connection"]
        self.assertEqual([ast.unparse(node.args[-1]) for node in requirements], ["0", "0", "2", "2", "2", "2", "0"])
        guarded, = [node for node in body.body if isinstance(node, ast.Try)]
        self.assertEqual(len(guarded.handlers), 1)
        self.shape(guarded.handlers[0].type, "BaseException")
        self.shape(call(guarded.handlers[0], "reader._close_after_failure"), "reader._close_after_failure(connection)")
        self.assertIsInstance(guarded.handlers[0].body[-1], ast.Raise)
        self.assertIsNone(guarded.handlers[0].body[-1].exc)
        _, lifecycle = source("catchplate/authority_revocation_root_reader.py")
        connect = definition(lifecycle, "_connect")
        self.shape(call(connect, "roots._callback"), "roots._callback(work, open_connection)")
        self.shape(call(connect, "_close_after_failure"), "_close_after_failure(connection)")
        context = definition(lifecycle, "_context")
        enter = definition(context, "enter")
        self.assertLess(call(enter, "manager.__enter__").lineno, next(node.lineno for node in enter.body
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "entered" for target in node.targets)))
        branch, = [node for node in context.body if isinstance(node, ast.Try)]
        leave = next(node for node in branch.orelse if isinstance(node, ast.FunctionDef) and node.name == "leave")
        self.assertLess(next(node.lineno for node in leave.body if isinstance(node, ast.Assign)),
            call(leave, "manager.__exit__").lineno)
        self.assertIn("if not exited:", ast.unparse(context))
        self.assertIn("manager.__exit__(type(exc), exc, exc.__traceback__)", ast.unparse(context))

    def test_original_outputs_and_projected_independent_history_are_captured_before_exit(self):
        body = definition(self.tree, "_produce_on_read_configuration")
        produced = call(body, "program._produce_observed_revocation_plan")
        copied = call(body, "authority_query_reads._CopyBudget(work).copy")
        validated = call(body, "retention.production._validate_context")
        compared = call(body, "retention.plan.semantics._canonical_equal")
        self.shape(copied, "authority_query_reads._CopyBudget(work).copy(produced.expected_context)")
        self.shape(validated, "retention.production._validate_context(expected_context, work)")
        self.shape(compared, '''retention.plan.semantics._canonical_equal(
            {name: expected_context[name] for name in actual_context}, actual_context,
            work=work, label="observed producer changed independent context pins")''')
        self.assertEqual([node.lineno for node in (produced, copied, validated, compared)],
            sorted(node.lineno for node in (produced, copied, validated, compared)))
        captures = [node for node in ast.walk(body) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id in
                {"envelope_bytes", "context_bytes", "database_now"} for target in node.targets)]
        self.assertEqual(len(captures), 3)
        for name, value in {"envelope_bytes": "produced.signed.envelope_bytes",
                "context_bytes": "produced.evaluation_context_bytes", "database_now": "produced.database_now"}.items():
            self.shape(assigned(body, name), value)
        returned, = [node for node in ast.walk(body) if isinstance(node, ast.Return)]
        self.shape(returned.value, "(envelope_bytes, context_bytes, database_now, expected_context)")
        scopes = [node for node in ast.walk(body) if isinstance(node, ast.With)]
        self.assertEqual(len(scopes), 1)
        self.shape(scopes[0].items[0].context_expr, "_read_scope(read_configuration[:3], operation=operation, work=work)")
        for scope in scopes:
            for node in (copied, validated, compared, *captures):
                self.assertIn(node, list(ast.walk(scope)))
            self.assertNotIn(returned, list(ast.walk(scope)))
            self.assertLess(scope.end_lineno, returned.lineno)
        self.shape(call(body, "retention.plan._verification_types"),
            "retention.plan._verification_types(planner_public_key, verifier_public_key, database_now)")
        self.assertIn("type(envelope_bytes) is not bytes or type(context_bytes) is not bytes", ast.unparse(body))


if __name__ == "__main__":
    unittest.main()
