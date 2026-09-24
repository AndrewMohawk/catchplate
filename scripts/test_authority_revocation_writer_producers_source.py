#!/usr/bin/env python3
"""Nonimporting linkage for configured verifier intent and planner relay.

These authored controls inspect source only in the future verification lane.
They do not fabricate a measured process, independent database acquisition,
launch admission, registry closure, or completed public request flow.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, source


class RevocationWriterProducersSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        cls.process = definition(cls.service, "AuthorityProcess")
        cls.intent = definition(cls.process, "_produce_revocation_writer_intent")
        cls.relay = definition(cls.process, "_produce_revocation_writer_relay")
        cls.text, cls.producers = source("serverware/authority_revocation_writer_producers.py", 64 * 1024)
        cls.intent_worker = definition(cls.producers, "_produce_intent_on_configuration")
        cls.relay_worker = definition(cls.producers, "_produce_relay_on_configuration")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_verifier_service_accepts_no_inventory_handoff_key_clock_or_callback(self):
        self.assertEqual([item.arg for item in self.intent.args.args], ["self"])
        self.assertEqual([item.arg for item in self.intent.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "expected_request", "context",
            "planned_at_epoch_ns", "envelope_id", "planner_transaction_id", "work"])
        self.assertTrue(all(value is None for value in self.intent.args.kw_defaults))
        self.assertIsNone(self.intent.args.kwarg)
        self.assertIsNone(self.intent.args.vararg)
        guard, = [node for node in self.intent.body if isinstance(node, ast.If)
            and "self.role_name" in ast.unparse(node.test)]
        self.shape(guard.test, '''self.role_name != "verifier"
            or self.process_mode != "policy-authority-verifier"
            or type(self.configuration) is not MeasuredConfiguration''')
        self.assertIsInstance(guard.body[0], ast.Raise)
        self.shape(assigned(self.intent, "configuration"), "self.configuration")
        self.shape(assigned(self.intent, "verifier_private_key"), "self.signing_key")
        owned = call(self.intent, "authority_revocation_writer_producers._capture_intent_call_inputs")
        self.shape(owned, '''authority_revocation_writer_producers._capture_intent_call_inputs(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            expected_request=expected_request, context=context, planned_at_epoch_ns=planned_at_epoch_ns,
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id, work=work)''')
        self.assertLess(assigned(self.intent, "verifier_private_key").lineno, owned.lineno)
        self.assertLess(owned.lineno, assigned(self.intent, "owned_payload").lineno)

    def test_full_owned_config_and_six_read_pins_precede_actual_descriptor_and_database(self):
        owned = assigned(self.intent, "owned_payload")
        self.shape(owned, '''authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)''')
        self.shape(assigned(self.intent, "role"), 'owned_payload["roles"]["verifier"]')
        self.shape(assigned(self.intent, "pins"), '''(int(timeout), role["databaseRole"],
            role["tlsClientDn"], role["tlsClientSerial"], role["tlsIssuerDn"], owned_payload["queryManifestDigest"])''')
        guard, = [node for node in ast.walk(self.intent) if isinstance(node, ast.If)
            and "type(timeout)" in ast.unparse(node.test)]
        self.shape(guard.test, "type(timeout) not in (int, float) or not 2 <= timeout <= 300")
        self.assertIsInstance(guard.body[0], ast.Raise)
        admitted = call(self.intent, "authority_revocation_root_reader._validate_pins")
        self.shape(admitted, "authority_revocation_root_reader._validate_pins(pins)")
        callbacks = calls(self.intent, "authority_revocation_configuration.production._callback")
        self.assertEqual(len(callbacks), 3)
        self.shape(callbacks[0], '''authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("verifier"))''')
        self.shape(callbacks[1], '''authority_revocation_configuration.production._callback(
            work, lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"))''')
        reader = assigned(self.intent, "reader")
        self.shape(reader, '''authority_revocation_root_reader.RevocationRootReader(
            dsn=dsn, connect_timeout_seconds=pins[0], database_role=pins[1],
            tls_client_dn=pins[2], tls_client_serial=pins[3], tls_issuer_dn=pins[4],
            query_manifest_digest=pins[5])''')
        self.assertEqual([owned.lineno, admitted.lineno, callbacks[0].lineno, callbacks[1].lineno, reader.lineno],
            sorted([owned.lineno, admitted.lineno, callbacks[0].lineno, callbacks[1].lineno, reader.lineno]))

    def test_real_read_is_recaptured_before_generation_last_and_direct_fixed_producer(self):
        read = assigned(self.intent, "observed_inventory")
        self.shape(read, "reader.read(work=work)")
        inventory = assigned(self.intent, "inventory")
        self.shape(inventory, "authority_revocation_observed._capture_root_inventory(observed_inventory, work=work)")
        generation = assigned(self.intent, "generation")
        self.shape(generation, '''authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))''')
        produced = call(self.intent, "authority_revocation_writer_producers._produce_intent_on_configuration")
        self.shape(produced, '''authority_revocation_writer_producers._produce_intent_on_configuration(
            payload=owned_payload, configuration_digest=configuration_digest, generation=generation,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            expected_request=owned_request, context=owned_context, root_inventory=inventory,
            planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id,
            verifier_private_key=verifier_private_key, work=work)''')
        self.assertEqual([read.lineno, inventory.lineno, generation.lineno, produced.lineno],
            sorted([read.lineno, inventory.lineno, generation.lineno, produced.lineno]))
        self.assertIsInstance(self.intent.body[-1], ast.Return)
        self.assertIs(self.intent.body[-1].value, produced)
        _, reader = source("serverware/authority_revocation_root_reader.py", 64 * 1024)
        actual = definition(reader, "_read_on_configuration")
        self.assertEqual(len(calls(actual, "_context")), 2)
        self.assertEqual(len(calls(actual, "roots._read_revocation_root_inventory_on_work")), 1)
        closed, = [node for node in ast.walk(actual) if isinstance(node, ast.If)
            and "lambda: connection.closed" in ast.unparse(node.test)]
        self.assertIsInstance(closed.body[0], ast.Raise)
        returned, = [node for node in ast.walk(actual) if isinstance(node, ast.Return)]
        self.shape(returned.value, "result")
        self.assertLess(closed.lineno, returned.lineno)
        self.shape(assigned(reader, "_SET_TRANSACTION"),
            '"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE"')

    def test_planner_relay_holds_signer_config_and_raws_before_launch_without_sending(self):
        self.assertEqual([item.arg for item in self.relay.args.kwonlyargs], [
            "intent_bytes", "envelope_bytes", "evaluation_context_bytes", "historical_expectations_bytes", "work"])
        self.assertIsNone(self.relay.args.kwarg)
        self.assertIsNone(self.relay.args.vararg)
        guard, = [node for node in self.relay.body if isinstance(node, ast.If)
            and "self.role_name" in ast.unparse(node.test)]
        self.shape(guard.test, '''self.role_name != "planner"
            or self.process_mode != "policy-authority-planner"
            or type(self.configuration) is not MeasuredConfiguration''')
        self.shape(assigned(self.relay, "planner_private_key"), "self.signing_key")
        raw = call(self.relay, "authority_revocation_writer_commitment._body_bounds")
        self.shape(raw, '''authority_revocation_writer_commitment._body_bounds(
            envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)''')
        owned = assigned(self.relay, "owned_payload")
        self.shape(owned, '''authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)''')
        callbacks = calls(self.relay, "authority_revocation_configuration.production._callback")
        self.assertEqual(len(callbacks), 2)
        self.shape(callbacks[0], '''authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("planner"))''')
        self.shape(callbacks[1], '''authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))''')
        produced = call(self.relay, "authority_revocation_writer_producers._produce_relay_on_configuration")
        self.shape(produced, '''authority_revocation_writer_producers._produce_relay_on_configuration(
            payload=owned_payload, configuration_digest=configuration_digest, generation=generation,
            intent_bytes=intent_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_private_key=planner_private_key, work=work)''')
        self.assertEqual([raw.lineno, owned.lineno, callbacks[0].lineno, callbacks[1].lineno, produced.lineno],
            sorted([raw.lineno, owned.lineno, callbacks[0].lineno, callbacks[1].lineno, produced.lineno]))
        self.assertIsInstance(self.relay.body[-1], ast.Return)
        self.assertIs(self.relay.body[-1].value, produced)
        for adapter in (self.intent, self.relay):
            for forbidden in ("self._read_revocation_root_observations", "self._verify_revocation_plan_handoff",
                    "self._send_revocation_writer_commitments", "_ValidationWork", "QueryReadValidationLimits",
                    "_socket_request", "_sign_internal", "_verify_internal_envelope"):
                self.assertFalse(calls(adapter, forbidden), forbidden)

    def test_root_signed_startup_and_registry_remain_real_and_public_dispatch_unchanged(self):
        main = definition(self.service, "main")
        self.assertLess(call(main, "MeasuredConfiguration.load").lineno,
                        call(main, "AuthorityProcess").lineno)
        handle = definition(self.process, "handle")
        served = definition(definition(self.service, "AuthorityServer"), "_serve_connection")
        for dispatcher in (handle, served):
            self.assertNotIn("_produce_revocation_writer_intent", ast.unparse(dispatcher))
            self.assertNotIn("_produce_revocation_writer_relay", ast.unparse(dispatcher))
        _, registry = source("serverware/authority_transition_registry.py")
        self.shape(assigned(registry, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        guard, = [node for node in registry.body if isinstance(node, ast.If)]
        self.shape(guard.test, "_CLOSURE_ERRORS")
        self.assertIsInstance(guard.body[0], ast.Raise)

    def test_actual_intent_capture_owns_closed_context_and_joins_independent_planner_id(self):
        captured = definition(self.producers, "_capture_intent_call_inputs")
        self.assertEqual([item.arg for item in captured.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "expected_request", "context",
            "planned_at_epoch_ns", "envelope_id", "planner_transaction_id", "work"])
        self.shape(call(captured, "plan.contract._object"), '''plan.contract._object(
            context, verifier._CALL_CONTEXT_FIELDS, "writer intent historical context")''')
        owned = assigned(captured, "owned")
        self.shape(owned, '''verifier.handoff.observed.reads._CopyBudget(work).copy(
            {"expectedRequest": expected_request, "context": context})''')
        joined = call(captured, "plan._same")
        self.shape(joined, '''plan._same(planner_transaction_id, historical["expectedPlannerTransactionId"],
            work, "writer intent planner ID differs from its independent expectation")''')
        self.assertLess(owned.lineno, joined.lineno)
        for forbidden in ("_capture_payload", "configuration.production._callback",
                "verifier._verifier_from_configuration_on_work", "owner.verify_handoff"):
            self.assertFalse(calls(captured, forbidden))
        _, configured = source("serverware/authority_revocation_verifier.py", 64 * 1024)
        self.shape(assigned(configured, "_CALL_CONTEXT_FIELDS"),
            'handoff.retention.production._CONTEXT_FIELDS - _CONFIGURED_CONTEXT_FIELDS - {"expectedBefore"}')

    def test_same_intent_invocation_owns_inputs_and_replays_before_deriving_historical_claims(self):
        worker = self.intent_worker
        self.assertEqual([item.arg for item in worker.args.kwonlyargs], [
            "payload", "configuration_digest", "generation", "envelope_bytes", "evaluation_context_bytes",
            "expected_request", "context", "root_inventory", "planned_at_epoch_ns", "envelope_id",
            "planner_transaction_id", "verifier_private_key", "work"])
        self.assertIsNone(worker.args.kwarg)
        self.assertIsNone(worker.args.vararg)
        captured = call(worker, "_capture_intent_call_inputs")
        inventory = call(worker, "verifier.handoff.observed._capture_root_inventory")
        self.shape(inventory, "verifier.handoff.observed._capture_root_inventory(root_inventory, work=work)")
        payload = call(worker, "_capture_payload")
        self.shape(payload, '_capture_payload(payload, ("verifier", "planner", "planner-writer"), work)')
        mapper = call(worker, "verifier._verifier_from_configuration_on_work")
        self.shape(mapper, '''verifier._verifier_from_configuration_on_work(payload=owned_payload,
            configuration_digest=configuration_digest, generation=generation, work=work)''')
        fixed = assigned(worker, "fixed")
        self.shape(fixed, "owner._snapshot_configuration()")
        verified = assigned(worker, "verified")
        self.shape(verified, '''owner.verify_handoff(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=request,
            context=historical, root_inventory=inventory, work=work)''')
        expectations = assigned(worker, "expectations")
        self.shape(expectations, '''{argument: verified.expected_context[name]
            for name, argument in commitment.retention._CONTEXT_PAIRS
            if argument not in ("expected_planner_identity", "expected_verifier_identity")}''')
        recaptured = call(worker, "commitment.action._capture_action_inputs")
        self.shape(recaptured, '''commitment.action._capture_action_inputs(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=planned_at_epoch_ns,
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
            expected_request=request, database_now=verified.database_now, work=work, **expectations)''')
        ordered = [captured, inventory, payload, mapper, fixed, verified, expectations, recaptured]
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        _, configured = source("serverware/authority_revocation_verifier.py", 64 * 1024)
        actual = definition(definition(configured, "RevocationPlanVerifier"), "verify_handoff")
        self.assertEqual(len(calls(actual, "handoff._verify_observed_plan_handoff_on_work")), 1)
        _, handoff = source("serverware/authority_revocation_handoff.py", 64 * 1024)
        actual_handoff = definition(handoff, "_verify_observed_plan_handoff_on_work")
        self.assertEqual(len(calls(actual_handoff, "retention._verify_record_on_work")), 1)

    def test_owned_history_precedes_real_clocks_and_freshness_without_retiming_original_plan(self):
        worker = self.intent_worker
        callbacks = calls(worker, "configuration.production._callback")
        self.assertEqual(len(callbacks), 2)
        self.shape(callbacks[0], "configuration.production._callback(work, time.monotonic_ns)")
        self.shape(callbacks[1], "configuration.production._callback(work, time.time_ns)")
        admitted = call(worker, "commitment._current")
        self.shape(admitted, "commitment._current(now_epoch, now_monotonic, maximum_age, fixed[6])")
        fresh = call(worker, "commitment._fresh")
        self.shape(fresh, '''commitment._fresh({"issuedAtEpochNs": owned["now_epoch_ns"],
            "issuedMonotonicNs": owned["now_monotonic_ns"],
            "deadlineMonotonicNs": owned["deadline_monotonic_ns"]}, owned,
            now_epoch, now_monotonic, maximum_age, fixed[6])''')
        produced = assigned(worker, "produced")
        self.shape(produced, '''commitment._produce_intent_on_work(**arguments,
            verifier_private_key=verifier_private_key, verifier_public_key=fixed[1],
            planner_public_key=fixed[0], configuration_digest=fixed[7],
            generation_sequence=fixed[8], generation_digest=fixed[9],
            issued_at_epoch_ns=now_epoch, issued_monotonic_ns=now_monotonic, work=work, **owned)''')
        returned, = [node for node in ast.walk(worker) if isinstance(node, ast.Return)]
        self.shape(returned.value, "(produced.intent_bytes, produced.historical_expectations_bytes)")
        ordered = [call(worker, "commitment.action._capture_action_inputs"), *callbacks, admitted, fresh, produced, returned]
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        payload = definition(self.producers, "_capture_payload")
        self.shape(assigned(payload, "owned"), '''configuration._ConfigurationCapture(capture._SharedLedger(work),
            maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)''')
        self.shape(call(payload, "plan.contract._integer"),
            'plan.contract._integer(role["maximumInternalAgeNs"], minimum=1)')
        result, = [node for node in ast.walk(payload) if isinstance(node, ast.Return)]
        self.shape(result.value, "(owned, min(ages))")

    def test_relay_uses_bound_keys_actual_intent_authentication_and_no_send_or_new_allowance(self):
        worker = self.relay_worker
        self.assertEqual([item.arg for item in worker.args.kwonlyargs], [
            "payload", "configuration_digest", "generation", "intent_bytes", "envelope_bytes",
            "evaluation_context_bytes", "historical_expectations_bytes", "planner_private_key", "work"])
        self.assertIsNone(worker.args.kwarg)
        self.assertIsNone(worker.args.vararg)
        payload = call(worker, "_capture_payload")
        self.shape(payload, '_capture_payload(payload, ("planner", "planner-writer"), work)')
        fixed = assigned(worker, "fixed")
        self.shape(fixed, "owner._snapshot_configuration()")
        callbacks = calls(worker, "configuration.production._callback")
        self.assertEqual(len(callbacks), 2)
        self.shape(callbacks[0], "configuration.production._callback(work, time.monotonic_ns)")
        self.shape(callbacks[1], "configuration.production._callback(work, time.time_ns)")
        produced = assigned(worker, "produced")
        self.shape(produced, '''commitment._produce_relay_on_work(intent_bytes=intent_bytes,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_private_key=planner_private_key, planner_public_key=fixed[0], verifier_public_key=fixed[1],
            expected_configuration_digest=fixed[7], expected_generation_sequence=fixed[8],
            expected_generation_digest=fixed[9], now_epoch_ns=now_epoch,
            now_monotonic_ns=now_monotonic, maximum_age_ns=maximum_age,
            maximum_clock_skew_ns=fixed[6], work=work)''')
        ordered = [payload, fixed, *callbacks, produced]
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        returned, = [node for node in ast.walk(worker) if isinstance(node, ast.Return)]
        self.shape(returned.value, "produced.relay_bytes")
        _, controls = source("serverware/authority_revocation_writer_commitment.py", 64 * 1024)
        for name in ("_produce_intent_on_work", "_produce_relay_on_work"):
            actual = definition(controls, name)
            self.assertLess(call(actual, "production._key_binding").lineno, call(actual, "_sign_wire").lineno)
        actual_relay = definition(controls, "_produce_relay_on_work")
        self.assertLess(call(actual_relay, "capability._signature").lineno, call(actual_relay, "_sign_wire").lineno)
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "_socket_request", "psycopg.connect",
                "_persist_and_reserve_request_on_configuration", "_send_on_configuration", "_sign_internal"):
            self.assertFalse(calls(self.producers, forbidden), forbidden)
        for imported in (node for node in self.producers.body if isinstance(node, (ast.Import, ast.ImportFrom))):
            for forbidden in ("authority_service", "authority_transition_registry", "psycopg"):
                self.assertNotIn(forbidden, ast.unparse(imported))
        self.assertFalse(any(isinstance(node, ast.While) for node in ast.walk(self.producers)))


if __name__ == "__main__":
    unittest.main()
