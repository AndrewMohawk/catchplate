#!/usr/bin/env python3
"""Bounded, nonimporting linkage for original-byte ACK expectation derivation.

These authored controls parse source only in the future verification lane.
They do not execute an extracted helper, replace a proof or registry, admit
configuration, sample an authenticated clock, or establish custody/execution.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, source


class RevocationWriterAckExpectationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("catchplate/authority_revocation_writer_ack_expectation.py", 64 * 1024)
        cls.worker = definition(cls.tree, "_expected_ack_request_and_freshness_on_work")
        cls.compatibility = definition(cls.tree, "_expected_ack_request_on_work")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def tuple_assignment(self, names):
        found = [node for node in ast.walk(self.worker) if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Tuple)
            and all(isinstance(item, ast.Name) for item in node.targets[0].elts)
            and [item.id for item in node.targets[0].elts] == names]
        self.assertEqual(len(found), 1)
        return found[0]

    def test_closed_original_byte_and_configured_input_surface_has_only_inert_dependencies(self):
        self.assertEqual(self.worker.args.args, [])
        self.assertEqual([item.arg for item in self.worker.args.kwonlyargs], [
            "intent_bytes", "relay_bytes", "envelope_bytes", "evaluation_context_bytes",
            "historical_expectations_bytes", "planner_public_key", "verifier_public_key",
            "expected_planner_identity", "expected_verifier_identity",
            "expected_configuration_digest", "expected_generation_sequence", "expected_generation_digest",
            "now_epoch_ns", "now_monotonic_ns", "maximum_age_ns", "maximum_clock_skew_ns",
            "maximum_assertion_age_ns", "maximum_plan_age_ns", "work"])
        self.assertTrue(all(item is None for item in self.worker.args.kw_defaults))
        self.assertIsNone(self.worker.args.vararg)
        self.assertIsNone(self.worker.args.kwarg)
        self.assertEqual(ast.dump(self.compatibility.args), ast.dump(self.worker.args))
        forwarded = call(self.compatibility, "_expected_ack_request_and_freshness_on_work")
        self.assertEqual(forwarded.args, [])
        self.assertEqual([(item.arg, ast.unparse(item.value)) for item in forwarded.keywords],
                         [(item.arg, item.arg) for item in self.worker.args.kwonlyargs])
        self.assertEqual(len(self.compatibility.body), 3)
        captured = self.compatibility.body[1]
        self.assertIsInstance(captured, ast.Assign)
        self.assertIs(captured.value, forwarded)
        self.assertEqual(len(captured.targets), 1)
        self.assertIsInstance(captured.targets[0], ast.Tuple)
        self.assertEqual([item.id for item in captured.targets[0].elts], ["request", "_freshness_pins"])
        self.assertIsInstance(self.compatibility.body[-1], ast.Return)
        self.shape(self.compatibility.body[-1].value, "request")
        imports = [(node.module, [(item.name, item.asname) for item in node.names])
            for node in self.tree.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, [("__future__", [("annotations", None)]),
            ("catchplate", [("authority_contract", "authority")]),
            ("catchplate", [("authority_revocation_retention", "retention")]),
            ("catchplate", [("authority_revocation_writer_acknowledgment", "acknowledgment")]),
            ("catchplate", [("authority_revocation_writer_commitment", "commitment")])])
        self.assertFalse(any(isinstance(node, ast.Import) for node in ast.walk(self.tree)))
        self.assertEqual([node.name for node in self.tree.body if isinstance(node, ast.FunctionDef)],
                         ["_expected_ack_request_and_freshness_on_work", "_expected_ack_request_on_work"])
        error = definition(self.tree, "RevocationWriterAckExpectationError")
        self.assertEqual(len(error.bases), 1)
        self.shape(error.bases[0], "ValueError")

    def test_independent_identity_capture_and_shapes_precede_genuine_receiver_key_callbacks(self):
        self.shape(assigned(self.worker, "ledger"), "capture._SharedLedger(work)")
        identities = assigned(self.worker, "identities")
        self.shape(identities, '''capture._JSONCapture(ledger).visit({
            "expectedPlannerIdentity": expected_planner_identity,
            "expectedVerifierIdentity": expected_verifier_identity})''')
        self.assertEqual(len(calls(self.worker, "capture._JSONCapture")), 1)
        checks = calls(self.worker, "plan.contract.validate_identity_shape")
        self.assertEqual(len(checks), 2)
        for checked, spelling in zip(checks, ("expected_planner_identity", "expected_verifier_identity")):
            self.shape(checked, "plan.contract.validate_identity_shape(" + spelling + ")")
            self.assertLess(checked.lineno, identities.lineno)
        limits = calls(self.worker, "plan.contract._integer")
        self.assertEqual(len(limits), 2)
        self.shape(limits[0], "plan.contract._integer(maximum_assertion_age_ns, minimum=1)")
        self.shape(limits[1], '''plan.contract._integer(maximum_plan_age_ns,
            authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)''')
        for name in ("commitment._body_bounds", "commitment._pins", "commitment._current",
                     "commitment._public_keys"):
            self.assertLess(call(self.worker, name).lineno, identities.lineno)
        self.shape(call(self.worker, "commitment._body_bounds"),
                   "commitment._body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)")
        self.shape(call(self.worker, "commitment._current"),
                   "commitment._current(now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)")
        receiver = call(self.worker, "commitment._verify_commitments_on_work")
        self.shape(receiver, '''commitment._verify_commitments_on_work(
            intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_public_key=planner_public_key, verifier_public_key=verifier_public_key,
            expected_configuration_digest=expected_configuration_digest,
            expected_generation_sequence=expected_generation_sequence,
            expected_generation_digest=expected_generation_digest,
            now_epoch_ns=now_epoch_ns, now_monotonic_ns=now_monotonic_ns,
            maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)''')
        self.assertIs(assigned(self.worker, "received"), receiver)
        self.assertLess(identities.end_lineno, receiver.lineno)
        _, controls = source("catchplate/authority_revocation_writer_commitment.py", 64 * 1024)
        current = definition(controls, "_current")
        skew, = [node for node in current.body if isinstance(node, ast.If)]
        self.shape(skew.test, "skew != authority.VERIFIER_MAX_CLOCK_SKEW_NS")
        self.assertIsInstance(skew.body[0], ast.Raise)

    def test_checked_scalar_links_and_exact_policy_join_precede_closed_nineteen_expectation_replay(self):
        receiver = call(self.worker, "commitment._verify_commitments_on_work")
        freshness = assigned(self.worker, "freshness_pins")
        self.shape(freshness, '''(received.intent_envelope["issuedAtEpochNs"],
            received.intent_envelope["issuedMonotonicNs"], received.relay_envelope["issuedAtEpochNs"],
            received.relay_envelope["issuedMonotonicNs"], received.expectations["deadline_epoch_ns"],
            received.expectations["deadline_monotonic_ns"])''')
        identities = self.tuple_assignment(["intent_id", "relay_id"])
        arguments = self.tuple_assignment(["execution_id", "planner_id", "planned_at"])
        self.shape(identities.value, '(received.intent_envelope["envelopeId"], received.relay_envelope["envelopeId"])')
        self.shape(arguments.value, '''(received.arguments[name] for name in
            ("envelope_id", "planner_transaction_id", "planned_at_epoch_ns"))''')
        self.shape(assigned(self.tree, "_AGE_FIELDS"),
                   '("maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns")')
        policy = call(self.worker, "plan._same")
        self.shape(policy, '''plan._same(tuple(received.expectations[name] for name in _AGE_FIELDS),
            (maximum_assertion_age_ns, maximum_plan_age_ns, maximum_clock_skew_ns), work,
            "writer ACK history policy differs from independently configured policy")''')
        replay = call(self.worker, "retention._verify_record_on_work")
        self.shape(replay, '''retention._verify_record_on_work(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planner_public_key=planner_public_key, verifier_public_key=verifier_public_key,
            expected_planner_identity=identities["expectedPlannerIdentity"],
            expected_verifier_identity=identities["expectedVerifierIdentity"],
            work=work, **received.expectations)''')
        self.assertIs(assigned(self.worker, "record"), replay)
        self.assertEqual([receiver.lineno, freshness.lineno, identities.lineno, arguments.lineno,
            policy.lineno, replay.lineno], sorted([receiver.lineno, freshness.lineno, identities.lineno,
            arguments.lineno, policy.lineno, replay.lineno]))
        # Current clocks are used by receiver freshness, never substituted for
        # the signed historical clocks carried in its closed fifteen fields.
        self.assertNotIn("now_epoch_ns", [item.arg for item in replay.keywords])
        self.assertNotIn("now_monotonic_ns", [item.arg for item in replay.keywords])
        _, plan_source = source("catchplate/authority_revocation_plan.py", 256 * 1024)
        fields = {item.value for item in assigned(plan_source, "_VERIFICATION_INPUTS").args[0].elts}
        self.assertEqual(fields - {"envelope"}, {
            "expected_request", "expected_planner_identity", "planner_public_key",
            "expected_verifier_identity", "verifier_public_key", "expected_capability_id",
            "expected_planner_transaction_id", "expected_fence", "reserved_at_epoch_ns",
            "deadline_epoch_ns", "deadline_monotonic_ns", "now_epoch_ns", "now_monotonic_ns",
            "database_now", "maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns",
            "expected_before", "expected_approver_policy_digest"})
        _, wire = source("catchplate/authority_revocation_wire.py", 64 * 1024)
        self.shape(assigned(wire, "_EXPECTATIONS"), 'plan._VERIFICATION_INPUTS - {"envelope"}')
        _, action = source("catchplate/authority_revocation_writer_action.py", 64 * 1024)
        self.shape(assigned(action, "_EXTERNAL_FIELDS"), '''retention.wire._EXPECTATIONS - {
            "planner_public_key", "verifier_public_key", "expected_planner_identity", "expected_verifier_identity"}''')

    def test_closed_scalar_result_uses_original_hashes_and_only_this_replays_record_key_digests(self):
        request = assigned(self.worker, "request")
        self.shape(request, '''{
            "intent_envelope_id": intent_id, "relay_envelope_id": relay_id,
            "execution_envelope_id": execution_id, "planner_transaction_id": planner_id,
            "plan_protocol": retention.PLAN_PROTOCOL, "retained_record_digest": record.record_digest,
            "configuration_digest": expected_configuration_digest,
            "generation_sequence": expected_generation_sequence, "generation_digest": expected_generation_digest,
            "planner_key_digest": record.planner_key_digest, "verifier_key_digest": record.verifier_key_digest,
            "planned_at_epoch_ns": planned_at, "source_revision": authority.SOURCE_REVISION}''')
        loop, = [node for node in ast.walk(self.worker) if isinstance(node, ast.For)]
        self.shape(loop.iter, '''(("exact_intent", intent_bytes), ("exact_relay", relay_bytes),
            ("historical_expectations", historical_expectations_bytes))''')
        self.assertEqual(len(loop.body), 2)
        self.assertEqual(ast.unparse(loop.body[0].targets[0]), "request[name + '_bytes_digest']")
        self.shape(loop.body[0].value, "retention._bytes_digest(raw, work)")
        self.assertEqual(ast.unparse(loop.body[1].targets[0]), "request[name + '_byte_count']")
        self.shape(loop.body[1].value, "len(raw)")
        closed = call(self.worker, "acknowledgment._request_shape")
        self.shape(closed, "acknowledgment._request_shape(request)")
        returned, = [node for node in ast.walk(self.worker) if isinstance(node, ast.Return)]
        self.shape(returned.value, "(request, freshness_pins)")
        replay = call(self.worker, "retention._verify_record_on_work")
        self.assertEqual([replay.lineno, request.lineno, loop.lineno, closed.lineno, returned.lineno],
            sorted([replay.lineno, request.lineno, loop.lineno, closed.lineno, returned.lineno]))
        _, ack = source("catchplate/authority_revocation_writer_acknowledgment.py", 64 * 1024)
        expected = {item.value for item in assigned(ack, "REQUEST_FIELDS").args[0].elts}
        self.assertEqual({item.value for item in request.keys} | {
            "exact_intent_bytes_digest", "exact_intent_byte_count", "exact_relay_bytes_digest",
            "exact_relay_byte_count", "historical_expectations_bytes_digest",
            "historical_expectations_byte_count"}, expected)
        self.assertEqual(len(expected), 19)

    def test_genuine_workers_remain_linked_without_database_clock_signing_or_allowance_substitutes(self):
        _, controls = source("catchplate/authority_revocation_writer_commitment.py", 64 * 1024)
        receiver = definition(controls, "_verify_commitments_on_work")
        self.assertEqual(len(calls(receiver, "capability._signature")), 2)
        self.assertEqual(len(calls(receiver, "_bind_intent")), 1)
        _, retained = source("catchplate/authority_revocation_retention.py", 64 * 1024)
        replay = definition(retained, "_verify_record_on_work")
        actual = call(replay, "plan._verify_signed_revocation_plan_on_work")
        self.assertEqual([item.value.id for item in actual.keywords if item.arg == "work"], ["work"])
        _, record_type = source("catchplate/authority_revocation_plan.py", 256 * 1024)
        signed = definition(record_type, "_verify_signed_revocation_plan_on_work")
        self.assertTrue(calls(signed, "_verify_on_ledger"))
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "psycopg.connect",
                "_connect", "time.time_ns", "time.monotonic_ns", "datetime.now",
                "base64.urlsafe_b64encode", "commitment._intent_id", "commitment._relay_id",
                "acknowledgment._verify_on_work", "acknowledgment._sign_on_work"):
            self.assertFalse(calls(self.worker, forbidden), forbidden)
        self.assertFalse(any(isinstance(node, (ast.With, ast.AsyncWith)) for node in ast.walk(self.worker)))
        self.assertFalse(any(isinstance(node, ast.Name) and node.id in {
            "acknowledgment_bytes", "connection", "operation", "opener", "limits"}
            for node in ast.walk(self.worker)))
        for node in ast.walk(self.worker):
            if isinstance(node, ast.Assign):
                self.assertFalse(any(isinstance(target, ast.Name) and target.id == "work" for target in node.targets))


if __name__ == "__main__":
    unittest.main()
