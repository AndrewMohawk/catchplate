#!/usr/bin/env python3
"""Bounded linkage, not extracted execution or measured-client admission.

These authored controls inspect source only in the future verification lane.
The actual service/registry graph is never imported, patched or bypassed here.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, keywords, source


ORIGINALS = ["intent_bytes", "relay_bytes", "envelope_bytes", "evaluation_context_bytes",
             "historical_expectations_bytes"]


class RevocationWriterClientSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("serverware/authority_revocation_writer_client.py", 64 * 1024)
        cls.client = definition(cls.tree, "_send_on_configuration")
        _, cls.service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        cls.process = definition(cls.service, "AuthorityProcess")
        cls.adapter = definition(cls.process, "_send_revocation_writer_commitments")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_actual_planner_adapter_owns_full_configuration_before_launch_and_generation_last(self):
        self.assertEqual([item.arg for item in self.adapter.args.args], ["self"])
        self.assertEqual([item.arg for item in self.adapter.args.kwonlyargs], ORIGINALS + ["work"])
        self.assertIsNone(self.adapter.args.kwarg)
        self.assertIsNone(self.adapter.args.vararg)
        guards = [node for node in self.adapter.body if isinstance(node, ast.If)]
        self.shape(guards[0].test, '''self.role_name != "planner"
            or self.process_mode != "policy-authority-planner"
            or type(self.configuration) is not MeasuredConfiguration''')
        self.assertIsInstance(guards[0].body[0], ast.Raise)
        self.shape(assigned(self.adapter, "configuration"), "self.configuration")
        owned = assigned(self.adapter, "owned_payload")
        self.shape(owned, '''authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)''')
        aggregate = call(self.adapter, "writer_transport._validate_lengths")
        self.shape(aggregate, '''writer_transport._validate_lengths((len(intent_bytes), len(relay_bytes),
            len(envelope_bytes), len(evaluation_context_bytes), len(historical_expectations_bytes)))''')
        callbacks = calls(self.adapter, "authority_revocation_configuration.production._callback")
        self.assertEqual(len(callbacks), 2)
        self.shape(callbacks[0], '''authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("planner"))''')
        self.shape(callbacks[1], '''authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))''')
        delegated = call(self.adapter, "authority_revocation_writer_client._send_on_configuration")
        self.shape(delegated, '''authority_revocation_writer_client._send_on_configuration(
            payload=owned_payload, configuration_digest=configuration_digest, generation=generation,
            intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes, work=work)''')
        self.assertEqual([aggregate.lineno, owned.lineno, callbacks[0].lineno,
            callbacks[1].lineno, delegated.lineno], sorted([aggregate.lineno, owned.lineno,
            callbacks[0].lineno, callbacks[1].lineno, delegated.lineno]))
        self.assertIsInstance(self.adapter.body[-1], ast.Return)
        self.assertIs(self.adapter.body[-1].value, delegated)
        for forbidden in ("_read_dsn_descriptor", "_ValidationWork", "QueryReadValidationLimits",
                          "_socket_request", "_sign_internal", "_verify_internal_envelope"):
            self.assertFalse(calls(self.adapter, forbidden))

    def test_client_captures_full_payload_and_endpoint_key_age_scalars_before_mapper_callbacks(self):
        self.assertEqual([item.arg for item in self.client.args.kwonlyargs],
                         ["payload", "configuration_digest", "generation", *ORIGINALS, "work"])
        self.assertIsNone(self.client.args.kwarg)
        self.assertIsNone(self.client.args.vararg)
        self.shape(assigned(self.client, "owned"), '''configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)''')
        mapper = call(self.client, "verifier._verifier_from_configuration_on_work")
        self.shape(mapper, '''verifier._verifier_from_configuration_on_work(payload=owned,
            configuration_digest=configuration_digest, generation=generation, work=work)''')
        for name, expression in (("path", 'writer["socketPath"]'),
                ("timeout_seconds", 'min(planner["requestTimeoutSeconds"], writer["requestTimeoutSeconds"])'),
                ("maximum_age_ns", 'min(planner["maximumInternalAgeNs"], writer["maximumInternalAgeNs"])'),
                ("writer_key_bytes", 'writer["responseSigningPublicKeyBase64Url"]'),
                ("writer_pin", 'writer["responseSigningSpkiDigest"]')):
            value = assigned(self.client, name)
            self.shape(value, expression)
            self.assertLess(value.lineno, mapper.lineno)
        self.assertLess(call(self.client, "transport._validate_lengths").lineno, mapper.lineno)
        topology = call(self.client, "commitment.plan._same")
        self.shape(topology.args[0], '(writer["peerUid"], writer["peerGid"])')
        self.shape(topology.args[1], '(planner["serviceUid"], planner["serviceGid"])')
        self.assertLess(topology.lineno, mapper.lineno)

    def test_actual_mapper_snapshot_and_independent_writer_key_precede_real_clock_samples(self):
        fixed = assigned(self.client, "fixed")
        self.shape(fixed, "owner._snapshot_configuration()")
        key = call(self.client, "configuration._key")
        self.shape(key, "configuration._key(writer_key_bytes, work, expected_spki=writer_pin)")
        callbacks = calls(self.client, "configuration.production._callback")
        self.assertEqual(len(callbacks), 3)
        self.shape(callbacks[0], "configuration.production._callback(work, time.monotonic_ns)")
        self.shape(callbacks[1], "configuration.production._callback(work, time.time_ns)")
        self.assertLess(fixed.lineno, key.lineno)
        self.assertLess(key.lineno, callbacks[0].lineno)
        self.assertLess(callbacks[0].lineno, callbacks[1].lineno)
        _, mapper = source("serverware/authority_revocation_verifier.py", 64 * 1024)
        actual = definition(mapper, "_verifier_from_configuration_on_work")
        capture = call(actual, "configuration._capture_configuration_on_work")
        for decoded in calls(actual, "configuration._key"):
            self.assertLess(capture.lineno, decoded.lineno)
        snapshot = definition(definition(mapper, "RevocationPlanVerifier"), "_snapshot_configuration")
        self.assertEqual(len(calls(snapshot, "_validate_configuration")), 1)

    def test_originals_and_configured_expectations_replay_before_guarded_transport_and_ack_verification(self):
        expected = call(self.client, "expectation._expected_ack_request_on_work")
        arguments = keywords(expected)
        self.assertEqual(set(arguments), {*ORIGINALS, "planner_public_key", "verifier_public_key",
            "expected_planner_identity", "expected_verifier_identity", "expected_configuration_digest",
            "expected_generation_sequence", "expected_generation_digest", "now_epoch_ns", "now_monotonic_ns",
            "maximum_age_ns", "maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns", "work"})
        for name in ORIGINALS + ["work", "now_epoch_ns", "now_monotonic_ns", "maximum_age_ns"]:
            self.shape(arguments[name], name)
        for name, index in (("planner_public_key", 0), ("verifier_public_key", 1),
                ("maximum_assertion_age_ns", 4), ("maximum_plan_age_ns", 5), ("maximum_clock_skew_ns", 6),
                ("expected_configuration_digest", 7), ("expected_generation_sequence", 8),
                ("expected_generation_digest", 9)):
            self.shape(arguments[name], f"fixed[{index}]")
        self.shape(arguments["expected_planner_identity"], "dict(zip(_IDENTITY_FIELDS, fixed[2]))")
        self.shape(arguments["expected_verifier_identity"], "dict(zip(_IDENTITY_FIELDS, fixed[3]))")
        received = assigned(self.client, "acknowledgment_bytes")
        self.shape(received, '''configuration.production._callback(work, lambda: transport._socket_request(
            path, intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes, timeout_seconds=timeout_seconds,
            expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))''')
        verified = call(self.client, "acknowledgment._verify_on_work")
        self.shape(verified, '''acknowledgment._verify_on_work(acknowledgment_bytes=acknowledgment_bytes,
            request_fields=request_fields, writer_public_key=writer_public_key,
            expected_writer_spki_digest=writer_pin, work=work)''')
        self.assertLess(expected.lineno, received.lineno)
        self.assertLess(received.lineno, verified.lineno)
        result, = [node for node in ast.walk(self.client) if isinstance(node, ast.Return)]
        self.shape(result.value, "acknowledgment_bytes")
        self.assertLess(verified.lineno, result.lineno)
        self.assertEqual(len(calls(self.client, "transport._socket_request")), 1)

    def test_no_alternate_authority_dsn_allowance_response_key_or_success_token_is_introduced(self):
        for imported in (node for node in self.tree.body if isinstance(node, (ast.Import, ast.ImportFrom))):
            for forbidden in ("authority_service", "authority_transition_registry", "psycopg", "import db"):
                self.assertNotIn(forbidden, ast.unparse(imported))
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "_PackagingLedger",
                "_connect", "_canonical", "json.loads", "_sign_on_work", "_sign_internal",
                "_persist_and_reserve_request_on_configuration"):
            self.assertFalse(calls(self.client, forbidden))
        for node in ast.walk(self.client):
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                self.assertNotIn(node.value.id, {"acknowledgment_bytes", "response", "ack"})
        self.assertFalse(any(isinstance(node, (ast.While, ast.ClassDef)) for node in ast.walk(self.client)))
        self.assertNotIn("private_key", self.text)
        self.assertNotIn("persistence_dsn", self.text)

    def test_real_root_and_registry_admission_stay_required_and_no_public_producer_is_fabricated(self):
        main = definition(self.service, "main")
        self.assertLess(call(main, "MeasuredConfiguration.load").lineno,
                        call(main, "AuthorityProcess").lineno)
        handle = definition(self.process, "handle")
        served = definition(definition(self.service, "AuthorityServer"), "_serve_connection")
        for dispatcher in (handle, served):
            self.assertNotIn("_send_revocation_writer_commitments", ast.unparse(dispatcher))
        self.assertFalse(calls(self.service, "self._send_revocation_writer_commitments"))
        self.assertFalse(calls(self.service, "commitment._produce_intent_on_work"))
        self.assertFalse(calls(self.service, "commitment._produce_relay_on_work"))
        _, registry = source("serverware/authority_transition_registry.py")
        self.shape(assigned(registry, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        guard, = [node for node in registry.body if isinstance(node, ast.If)]
        self.shape(guard.test, "_CLOSURE_ERRORS")
        self.assertIsInstance(guard.body[0], ast.Raise)


if __name__ == "__main__":
    unittest.main()
