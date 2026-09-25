#!/usr/bin/env python3
"""Nonimporting linkage for the private original-byte writer action.

These bounded source controls do not import the active service or database,
execute extracted functions, enroll configuration, or prove transport, PG16,
TLS/ACL admission, signatures or rollback. Input custody and a measured policy
join do not authenticate the caller's historical claims. Public routes and
peer permissions remain separate, unchanged gates.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, keywords, source


EXTERNAL_FIELDS = frozenset({
    "expected_request", "expected_capability_id", "expected_planner_transaction_id", "expected_fence",
    "reserved_at_epoch_ns", "deadline_epoch_ns", "deadline_monotonic_ns", "now_epoch_ns", "now_monotonic_ns",
    "database_now", "maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns",
    "expected_before", "expected_approver_policy_digest"})


class RevocationWriterActionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("serverware/authority_revocation_writer_action.py", 64 * 1024)
        _, cls.service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        cls.process = definition(cls.service, "AuthorityProcess")
        cls.action = definition(cls.process, "_persist_and_reserve_revocation_plan")
        cls.continuation = definition(cls.service, "_revocation_writer_from_owned_configuration")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_key_independent_input_boundary_owns_fourteen_json_fields_and_pins_exact_original_utc(self):
        imports = [(node.module, tuple((item.name, item.asname) for item in node.names))
            for node in self.tree.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, [("__future__", (("annotations", None),)),
            ("datetime", (("datetime", None), ("timezone", None))),
            ("serverware", (("authority_contract", "authority"),)),
            ("serverware", (("authority_revocation_retention", "retention"),))])
        self.assertFalse(any(isinstance(node, ast.Import) for node in self.tree.body))
        self.shape(assigned(self.tree, "_EXTERNAL_FIELDS"), '''retention.wire._EXPECTATIONS - {
            "planner_public_key", "verifier_public_key", "expected_planner_identity", "expected_verifier_identity"}''')
        _, plan = source("serverware/authority_revocation_plan.py", 256 * 1024)
        fields = assigned(plan, "_VERIFICATION_INPUTS").args[0]
        self.assertEqual({item.value for item in fields.elts} - {"envelope", "planner_public_key",
            "verifier_public_key", "expected_planner_identity", "expected_verifier_identity"}, EXTERNAL_FIELDS)
        capture = definition(self.tree, "_capture_action_inputs")
        self.assertEqual(capture.args.args, [])
        self.assertEqual([item.arg for item in capture.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "planned_at_epoch_ns",
            "envelope_id", "planner_transaction_id", "work"])
        self.assertEqual(capture.args.kwarg.arg, "expectations")
        self.assertIsNone(capture.args.vararg)
        self.assertTrue(all(value is None for value in capture.args.kw_defaults))
        body, = [node for node in capture.body if isinstance(node, ast.Try)]
        self.shape(body.body[0].value, "retention.capture._SharedLedger(work)")
        originals = body.body[1]
        self.assertIsInstance(originals, ast.For)
        self.shape(originals.iter, '''((envelope_bytes, retention.plan.contract.MAX_PAYLOAD_BYTES),
            (evaluation_context_bytes, retention.MAX_CONTEXT_BYTES))''')
        self.shape(originals.body[0].test, "type(raw) is not bytes or not 2 <= len(raw) <= maximum")
        self.shape(body.body[2].value, "retention.plan.contract._integer(planned_at_epoch_ns, minimum=1)")
        self.shape(body.body[3].value, "retention.plan.contract._digest(envelope_id)")
        self.shape(body.body[4].value, "retention.plan.contract._digest(planner_transaction_id)")
        self.shape(body.body[5].test, '''type(expectations) is not dict or len(expectations) != len(_EXTERNAL_FIELDS)
            or any(type(name) is not str for name in expectations) or set(expectations) != _EXTERNAL_FIELDS''')
        self.shape(assigned(capture, "database_now"), 'expectations["database_now"]')
        utc = body.body[7]
        self.shape(utc.test, "type(database_now) is not datetime or database_now.tzinfo is not timezone.utc")
        copied = assigned(capture, "owned")
        self.shape(copied, '''retention.capture._JSONCapture(ledger).visit({
            name: value for name, value in expectations.items() if name != "database_now"})''')
        self.assertEqual(len(calls(capture, "retention.capture._JSONCapture")), 1)
        reattached, = [node for node in ast.walk(capture) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Subscript) for target in node.targets)]
        self.assertEqual(ast.unparse(reattached.targets[0]), "owned['database_now']")
        self.shape(reattached.value, "database_now")
        self.assertLess(utc.lineno, copied.lineno)
        self.assertLess(copied.lineno, reattached.lineno)
        self.shape(assigned(capture, "arguments"), '''{"envelope_bytes": envelope_bytes,
            "evaluation_context_bytes": evaluation_context_bytes, "planned_at_epoch_ns": planned_at_epoch_ns,
            "envelope_id": envelope_id, "planner_transaction_id": planner_transaction_id}''')
        self.shape(body.body[-1].value, "(arguments, owned)")
        for spelling in ("retention.plan._verification_types", "retention._verify_record_on_work",
                "datetime.now", "datetime.fromtimestamp", "database_now.timestamp", "database_now.astimezone"):
            self.assertFalse(calls(capture, spelling))

    def test_captured_shapes_and_independent_planner_join_keep_real_shared_work_and_no_proof_token(self):
        capture = definition(self.tree, "_capture_action_inputs")
        owned = assigned(capture, "owned")
        request = call(capture, "retention.plan.contract._request")
        roots = call(capture, "retention.plan.semantics._expected_before")
        joined = call(capture, "retention.plan._same")
        self.shape(request, 'retention.plan.contract._request(owned["expected_request"])')
        self.shape(roots, 'retention.plan.semantics._expected_before(owned["expected_before"])')
        self.shape(joined, '''retention.plan._same(planner_transaction_id, owned["expected_planner_transaction_id"], work,
            "revocation writer action planner ID differs from its independent expectation")''')
        positive, = [node for node in ast.walk(capture) if isinstance(node, ast.For)
            and any(isinstance(item, ast.Constant) and item.value == "expected_fence" for item in ast.walk(node.iter))]
        self.shape(positive.iter, '''("expected_fence", "reserved_at_epoch_ns", "deadline_epoch_ns",
            "deadline_monotonic_ns", "now_epoch_ns", "now_monotonic_ns",
            "maximum_assertion_age_ns", "maximum_plan_age_ns")''')
        self.shape(positive.body[0].value, "retention.plan.contract._integer(owned[name], minimum=1)")
        skew, = [node for node in calls(capture, "retention.plan.contract._integer")
                 if ast.unparse(node.args[0]) == "owned['maximum_clock_skew_ns']"]
        self.shape(skew, 'retention.plan.contract._integer(owned["maximum_clock_skew_ns"])')
        self.assertEqual([node.lineno for node in (owned, request, positive, skew, roots, joined)],
                         sorted(node.lineno for node in (owned, request, positive, skew, roots, joined)))
        _, contract = source("serverware/authority_revocation_plan_contract.py", 64 * 1024)
        integer = definition(contract, "_integer")
        self.shape(integer.body[0].test, "type(value) is not int or not minimum <= value <= maximum")
        _, plan = source("serverware/authority_revocation_plan.py", 256 * 1024)
        self.shape(definition(plan, "_same").body[0].value,
                   "semantics._canonical_equal(left, right, work=work, label=label)")
        forbidden = {"_ValidationWork", "QueryReadValidationLimits", "_PackagingLedger", "Ed25519PublicKey",
                     "Ed25519PrivateKey", "store", "db", "psycopg", "json", "base64", "hashlib", "time"}
        self.assertTrue({node.id for node in ast.walk(self.tree) if isinstance(node, ast.Name)}.isdisjoint(forbidden))
        self.assertTrue({node.attr for node in ast.walk(self.tree) if isinstance(node, ast.Attribute)}.isdisjoint({
            "loads", "dumps", "sign", "verify", "connect", "execute", "timestamp", "now", "time_ns", "monotonic_ns"}))

    def test_policy_is_an_exact_comparison_with_measured_verifier_ages_without_caller_overwrite(self):
        policy = definition(self.tree, "_assert_policy_on_work")
        self.assertEqual([item.arg for item in policy.args.args], ["payload", "expectations", "work"])
        self.assertEqual(policy.args.kwonlyargs, [])
        self.assertIsNone(policy.args.kwarg)
        self.assertIsNone(policy.args.vararg)
        self.shape(assigned(self.tree, "_AGE_FIELDS"),
                   '("maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns")')
        self.shape(call(policy, "retention.capture._SharedLedger"), "retention.capture._SharedLedger(work)")
        self.shape(assigned(policy, "assertion_age"), 'payload["webauthn"]["maximumChallengeAgeNs"]')
        self.shape(assigned(policy, "verifier_age"), 'payload["roles"]["verifier"]["maximumInternalAgeNs"]')
        self.shape(assigned(policy, "supplied"), "tuple(expectations[name] for name in _AGE_FIELDS)")
        self.shape(assigned(policy, "measured"), '''(assertion_age,
            min(verifier_age, authority.VERIFIER_RESPONSE_MAX_AGE_NS), authority.VERIFIER_MAX_CLOCK_SKEW_NS)''')
        self.assertEqual([ast.unparse(node) for node in calls(policy, "retention.plan.contract._integer")], [
            "retention.plan.contract._integer(assertion_age, minimum=1)",
            "retention.plan.contract._integer(verifier_age, minimum=1)",
            "retention.plan.contract._integer(value, minimum=1)",
            "retention.plan.contract._integer(supplied[2])"])
        compared = call(policy, "retention.plan._same")
        self.shape(compared, '''retention.plan._same(supplied, measured, work,
            "revocation writer action policy differs from its measured configuration")''')
        self.assertLess(assigned(policy, "measured").lineno, compared.lineno)
        self.assertFalse(any(isinstance(node, (ast.Subscript, ast.Attribute))
            and isinstance(node.ctx, ast.Store) for node in ast.walk(policy)))
        self.assertFalse(any(isinstance(node, ast.Return) for node in ast.walk(policy)))
        self.assertFalse(calls(policy, "retention.capture._JSONCapture"))
        self.assertNotIn("planner-writer", ast.unparse(policy))
        _, authority = source("serverware/authority_contract.py", 512 * 1024)
        self.shape(assigned(authority, "VERIFIER_RESPONSE_MAX_AGE_NS"), "30 * 1_000_000_000")
        self.shape(assigned(authority, "VERIFIER_MAX_CLOCK_SKEW_NS"), "5 * 1_000_000_000")

    def test_private_process_owns_inputs_and_one_full_configuration_before_policy_and_callbacks(self):
        action = self.action
        self.assertEqual([item.arg for item in action.args.args], ["self"])
        self.assertEqual([item.arg for item in action.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "planned_at_epoch_ns", "envelope_id",
            "planner_transaction_id", "work"])
        self.assertEqual(action.args.kwarg.arg, "expectations")
        self.assertIsNone(action.args.vararg)
        self.shape(action.body[1].test, '''self.role_name != "planner-writer"
            or self.process_mode != "policy-authority-planner-writer"
            or type(self.configuration) is not MeasuredConfiguration''')
        self.shape(assigned(action, "configuration"), "self.configuration")
        self.shape(action.body[3].value, "(configuration.payload, configuration.digest)")
        capture = call(action, "authority_revocation_writer_action._capture_action_inputs")
        self.shape(capture, '''authority_revocation_writer_action._capture_action_inputs(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id, work=work, **expectations)''')
        paired, = [node for node in action.body if isinstance(node, ast.Assign) and node.value is capture]
        self.assertEqual([item.id for item in paired.targets[0].elts], ["arguments", "owned"])
        full = assigned(action, "owned_payload")
        self.shape(full, '''authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)''')
        self.shape(assigned(action, "ledger"), "authority_revocation_configuration.capability.capture._SharedLedger(work)")
        self.shape(call(action, "authority_revocation_configuration.capability.shape._digest"),
                   "authority_revocation_configuration.capability.shape._digest(configuration_digest)")
        policy = call(action, "authority_revocation_writer_action._assert_policy_on_work")
        self.shape(policy, "authority_revocation_writer_action._assert_policy_on_work(owned_payload, owned, work)")
        continuation = call(action, "_revocation_writer_from_owned_configuration")
        self.shape(continuation, '''_revocation_writer_from_owned_configuration(
            owned_payload=owned_payload, configuration_digest=configuration_digest, work=work)''')
        pair, = [node for node in action.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Tuple) and [ast.unparse(item) for item in target.elts]
                    == ["persistence", "_held_launch"] for target in node.targets)]
        self.assertIs(pair.value, continuation)
        atomic = call(action, "persistence.persist_and_reserve_execution")
        self.shape(atomic, "persistence.persist_and_reserve_execution(**arguments, work=work, **owned)")
        self.assertIs(action.body[-1].value, atomic)
        ordered = (action.body[1], assigned(action, "configuration"), action.body[3], capture, full,
                   policy, continuation, atomic)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        self.assertEqual([node.attr for node in sorted((node for node in ast.walk(action)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self"),
            key=lambda node: (node.lineno, node.col_offset))], ["role_name", "process_mode", "configuration", "configuration"])
        self.assertFalse(calls(action, "authority_revocation_configuration.production._callback"))
        self.assertFalse(calls(action, "self._revocation_planner_persistence"))

    def test_fixed_continuation_retains_launch_descriptor_generation_order_and_actual_key_mapper(self):
        continuation = self.continuation
        self.assertEqual(continuation.args.args, [])
        self.assertEqual([item.arg for item in continuation.args.kwonlyargs],
                         ["owned_payload", "configuration_digest", "work"])
        self.assertTrue(all(value is None for value in continuation.args.kw_defaults))
        self.assertIsNone(continuation.args.kwarg)
        self.assertIsNone(continuation.args.vararg)
        callbacks = calls(continuation, "authority_revocation_configuration.production._callback")
        self.assertEqual(len(callbacks), 3)
        for actual, expected in zip(callbacks, (
                'authority_revocation_configuration.production._callback(work, lambda: authority_launch_guard.require_active("planner-writer"))',
                '''authority_revocation_configuration.production._callback(work,
                    lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"))''',
                'authority_revocation_configuration.production._callback(work, lambda: dict(authority_launch_guard.generation()))')):
            self.shape(actual, expected)
        mapped = call(continuation, "authority_revocation_writer_configuration._persistence_from_configuration_on_work")
        self.shape(mapped, '''authority_revocation_writer_configuration._persistence_from_configuration_on_work(
            payload=owned_payload, configuration_digest=configuration_digest, generation=generation,
            persistence_dsn=persistence_dsn, work=work)''')
        self.assertIs(assigned(continuation, "persistence"), mapped)
        held = assigned(continuation, "held_launch")
        self.shape(held, '(generation["sequence"], generation["digest"])')
        self.shape(continuation.body[-1].value, "(persistence, held_launch)")
        self.assertLess(callbacks[2].lineno, held.lineno)
        self.assertLess(held.lineno, mapped.lineno)
        self.assertFalse(any(isinstance(node, ast.Name) and node.id in {"self", "opener", "operation"}
                             for node in ast.walk(continuation)))
        _, mapper = source("serverware/authority_revocation_writer_configuration.py", 64 * 1024)
        factory = definition(mapper, "_persistence_from_configuration_on_work")
        recapture = call(factory, "configuration._capture_configuration_on_work")
        self.shape(recapture, '''configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)''')
        keys = calls(factory, "configuration._key")
        self.assertEqual(len(keys), 2)
        actual_owner = call(factory, "persistence.RevocationPlannerPersistence")
        self.assertEqual([node.lineno for node in (recapture, *keys, actual_owner)],
                         sorted(node.lineno for node in (recapture, *keys, actual_owner)))

    def test_action_suffix_keeps_genuine_atomic_capture_and_two_original_byte_replays(self):
        _, persistence = source("serverware/authority_revocation_persistence.py", 64 * 1024)
        atomic = definition(definition(persistence, "RevocationPlannerPersistence"), "persist_and_reserve_execution")
        self.shape(call(atomic, "_persist_and_reserve_on_configuration"),
            '''_persist_and_reserve_on_configuration(configuration,
                envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
                planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
                planner_transaction_id=planner_transaction_id, work=work, **expectations)''')
        fixed = definition(persistence, "_persist_and_reserve_on_configuration")
        runner = call(fixed, "_run_on_configuration")
        self.shape(runner.args[1], "_persist_and_reserve_on_connection")
        self.shape(runner.args[-2], "expectations")
        self.shape(runner.args[-1], "work")
        capture = call(definition(persistence, "_inputs_from_configuration"), "store._owned_expectations")
        self.shape(capture, "store._owned_expectations({**expectations, **pins}, work)")
        operation = definition(persistence, "_persist_and_reserve_on_connection")
        common, = [node for node in ast.walk(operation) if isinstance(node, ast.With)]
        self.shape(common.items[0].context_expr, "store._context(store._callback(work, raw.transaction), work)")
        self.shape(call(common, "_retain_and_reserve_in_common"), '''_retain_and_reserve_in_common(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id, connection=connection, raw=raw,
            work=work, **expectations)''')
        inner = definition(persistence, "_retain_and_reserve_in_common")
        retained = call(inner, "store.persist_revocation_planner_record")
        reserved = call(inner, "revocation_execution.reserve_revocation_execution_envelope")
        self.assertLess(retained.lineno, reserved.lineno)
        self.shape(reserved, '''revocation_execution.reserve_revocation_execution_envelope(
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
            connection=connection, work=work, **expectations)''')
        self.shape(operation.body[-1].value, "result")
        self.shape(inner.body[-1].value, "(retained_receipt, execution_reservation)")
        _, store = source("serverware/authority_store/revocation_retention.py", 64 * 1024)
        initial = definition(store, "persist_revocation_planner_record")
        replay = definition(store, "_read_revocation_record_on_work")
        self.shape(call(initial, "retention._verify_record_on_work"), '''retention._verify_record_on_work(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes, work=work, **expectations)''')
        self.shape(call(replay, "retention._verify_record_on_work"), '''retention._verify_record_on_work(
            envelope_bytes=envelope, evaluation_context_bytes=context, work=work, **expectations)''')
        _, execution = source("serverware/authority_store/revocation_execution.py", 64 * 1024)
        reserved_read = call(definition(execution, "reserve_revocation_execution_envelope"), "store._read_revocation_record_on_work")
        self.shape(reserved_read, '''store._read_revocation_record_on_work(planner_transaction_id=planner_transaction_id,
            connection=connection, work=work, _expected_raw=raw, expectations=owned)''')

    def test_private_action_preserves_real_loader_and_closed_public_writer_dispatch(self):
        measured = definition(self.service, "MeasuredConfiguration")
        load = definition(measured, "load")
        signature = call(load, "root_key.verify")
        self.shape(signature, '''root_key.verify(_b64url_decode(envelope["signature"], size=64),
            _domain_digest(SIGNED_CONFIG_SCHEMA, payload_bytes).encode("ascii"))''')
        checks = [call(load, "configuration." + name) for name in
                  ("_verify_generation_binding", "_verify_role_topology", "_verify_runtime_closure", "_verify_attestation")]
        self.assertEqual([node.lineno for node in (signature, *checks)],
                         sorted(node.lineno for node in (signature, *checks)))
        handle = definition(self.process, "handle")
        writer, = [node for node in ast.walk(handle) if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "self.role_name == 'planner-writer'"]
        self.shape(keywords(call(writer, "self._verify_internal_envelope"))["allowed_purposes"],
                   "{'persist-measured-plan', 'read-persisted-plan', 'reserve-execution-envelope'}")
        served = definition(definition(self.service, "AuthorityServer"), "_serve_connection")
        for public in (handle, served):
            for spelling in ("_persist_and_reserve_revocation_plan", "_revocation_writer_from_owned_configuration",
                    "authority_revocation_writer_action", "persist_and_reserve_execution"):
                self.assertNotIn(spelling, ast.unparse(public))
        peer, = [node for node in ast.walk(served) if isinstance(node, ast.If)
                 and ast.unparse(node.test) == "uid != self.peer_uid or gid != self.peer_gid"]
        self.assertLess(peer.lineno, call(served, "self.process.handle").lineno)
        self.assertFalse(calls(self.service, "self._persist_and_reserve_revocation_plan"))
        self.assertFalse(calls(self.service, "self._revocation_planner_persistence"))
        _, registry = source("serverware/authority_transition_registry.py")
        self.shape(assigned(registry, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        closed, = [node for node in registry.body if isinstance(node, ast.If)]
        self.shape(closed.test, "_CLOSURE_ERRORS")
        self.assertIsInstance(closed.body[0], ast.Raise)


if __name__ == "__main__":
    unittest.main()
