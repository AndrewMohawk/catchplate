#!/usr/bin/env python3
"""Nonimporting linkage of the private authenticated invocation contract.

These source controls do not open service dispatch or registry gates, import
the active service, prove PostgreSQL admission, or promote sender-authenticated
historical claims into current root, witness or clock-provenance evidence.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
OUTER_FIELDS = {"schema", "envelopeId", "parentEnvelopeId", "purpose", "configurationDigest",
    "issuedAtEpochNs", "issuedMonotonicNs", "deadlineMonotonicNs", "fence", "payload", "signature"}
PAYLOAD_FIELDS = {"schema", "sourceRevision", "generationSequence", "generationDigest", "executionEnvelopeId",
    "witnessReceiptDigest", "capabilityBase64Url", "capabilityByteCount", "witnessRequestBase64Url",
    "witnessRequestByteCount", "historicalExpectations"}
HISTORICAL_FIELDS = {"expectedRequest", "expectedCapabilityId", "expectedPlannerTransactionId", "expectedFence",
    "reservedAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs", "nowEpochNs", "nowMonotonicNs",
    "databaseCutoffUs", "maximumAssertionAgeNs", "maximumPlanAgeNs", "maximumClockSkewNs",
    "expectedBefore", "expectedApproverPolicyDigest"}


def read(relative, maximum=256 * 1024):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("invocation source exceeds its explicit inspection bound")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=relative)


def definition(tree, name):
    matches = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name]
    if len(matches) != 1:
        raise AssertionError("invocation source definition is not unique: " + name)
    return matches[0]


def calls(tree, spelling):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == spelling), key=lambda node: (node.lineno, node.col_offset))


def assigned(tree, name):
    values = [node.value for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(values) != 1:
        raise AssertionError("invocation source assignment is not unique: " + name)
    return values[0]


class RevocationInvocationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source, cls.tree = read("serverware/authority_revocation_invocation.py")
        cls.owner_source, cls.owner_tree = read("serverware/authority_revocation_issuance.py")
        cls.service_source, cls.service = read("serverware/authority_service.py", 2 * 1024 * 1024)

    def assert_shape(self, actual, expression):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expression.strip() + ")", mode="eval").body))

    def test_fixed_producer_and_receiver_apis_have_no_successful_observation_input(self):
        producer = definition(self.tree, "_produce_invocation_on_work")
        receiver = definition(self.tree, "_verify_invocation_on_work")
        self.assertEqual([arg.arg for arg in producer.args.kwonlyargs], ["capability_bytes", "witness_request_bytes",
            "execution_envelope_id", "witness_receipt_digest", "historical_expectations", "signer_private_key",
            "signer_public_key", "configuration_digest", "generation_sequence", "generation_digest",
            "issued_at_epoch_ns", "issued_monotonic_ns", "work"])
        self.assertEqual([arg.arg for arg in receiver.args.kwonlyargs], ["envelope_bytes", "verifier_public_key",
            "expected_configuration_digest", "expected_generation_sequence", "expected_generation_digest",
            "now_epoch_ns", "now_monotonic_ns", "maximum_age_ns", "maximum_clock_skew_ns", "work"])
        for function in (producer, receiver):
            self.assertIsNone(function.args.kwarg)
            self.assertIsNone(function.args.vararg)
            self.assertEqual(function.args.args, [])

    def test_composition_uses_captured_configuration_and_independent_current_clocks_before_opening(self):
        run = definition(self.owner_tree, "_issue_invocation_on_configuration")
        self.assertEqual([arg.arg for arg in run.args.args], ["configuration"])
        self.assertEqual([arg.arg for arg in run.args.kwonlyargs], ["envelope_bytes", "work", "opener"])
        self.assertIsNone(run.args.kwarg)
        clocks = calls(run, "persistence.store._callback")
        self.assertEqual([ast.unparse(call.args[1]) for call in clocks], ["time.monotonic_ns", "time.time_ns"])
        receiver = calls(run, "invocation._verify_invocation_on_work")
        downstream = calls(run, "_run_on_configuration")
        self.assertEqual((len(receiver), len(downstream)), (1, 1))
        self.assertLess(clocks[-1].lineno, receiver[0].lineno)
        self.assertLess(receiver[0].lineno, downstream[0].lineno)
        self.assert_shape(receiver[0], """invocation._verify_invocation_on_work(envelope_bytes=envelope_bytes,
            verifier_public_key=verifier_key, expected_configuration_digest=configuration_digest,
            expected_generation_sequence=generation_sequence, expected_generation_digest=generation_digest,
            now_epoch_ns=now_epoch_ns, now_monotonic_ns=now_monotonic_ns,
            maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)""")
        self.assert_shape(downstream[0], """_run_on_configuration(configuration, envelope_bytes=received.capability_bytes,
            witness_request_bytes=received.witness_request_bytes,
            expected_execution_envelope_id=received.execution_envelope_id,
            expected_witness_receipt_digest=received.witness_receipt_digest,
            expectations=received.historical_expectations, work=work, opener=opener)""")
        self.assertFalse(calls(run, "opener"))
        self.assertFalse(calls(run, "_ValidationWork"))

    def test_successor_purpose_is_not_added_to_actual_legacy_dispatch_or_registry(self):
        self.assertNotIn("issue-revocation-capability", self.service_source)
        self.assertNotIn("issue_authenticated", self.service_source)
        self.assertNotIn("authority_revocation_invocation", self.service_source)
        imports = [node for node in self.tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any("authority_service" in ast.unparse(node) or "authority_transition_registry" in ast.unparse(node)
            or "serverware import db" in ast.unparse(node) for node in imports))
        source, _tree = read("serverware/authority_transition_registry.py")
        self.assertNotIn("issue-revocation-capability", source)
        self.assertNotIn("issue_authenticated", source)

    def test_full_wrapper_limits_and_depth_two_history_are_source_closed_and_frozen(self):
        self.assertEqual(ast.literal_eval(assigned(self.tree, "SCHEMA")),
            "serverware.policyAuthorityRevocationIssuanceInvocation/v1")
        self.assertEqual(ast.literal_eval(assigned(self.tree, "PURPOSE")), "issue-revocation-capability")
        for name, expected in (("ENVELOPE_FIELDS", OUTER_FIELDS), ("PAYLOAD_FIELDS", PAYLOAD_FIELDS)):
            value = assigned(self.tree, name)
            self.assertIsInstance(value, ast.Call)
            self.assertEqual(ast.unparse(value.func), "frozenset")
            self.assertEqual(ast.literal_eval(value.args[0]), expected)
        for name, expression in (("ENVELOPE_SCHEMA", "capability.authority.INTERNAL_ENVELOPE_SCHEMA"),
                ("MAX_ENVELOPE_BYTES", "capability.authority.MAX_REQUEST_BYTES"),
                ("MAX_JSON_NODES", "capability.MAX_JSON_NODES"),
                ("MAX_JSON_DEPTH", "capability.shape.MAX_JSON_DEPTH")):
            self.assert_shape(assigned(self.tree, name), expression)
        _source, authority = read("serverware/authority_contract.py")
        self.assert_shape(assigned(authority, "MAX_REQUEST_BYTES"), "4 * 1024 * 1024")
        self.assertEqual(ast.literal_eval(assigned(authority, "INTERNAL_ENVELOPE_SCHEMA")),
            "serverware.policyAuthorityInternalEnvelope/v3")
        _source, capability = read("serverware/authority_revocation_capability.py")
        self.assertEqual(ast.literal_eval(assigned(capability, "MAX_JSON_NODES")), 4096)
        self.assert_shape(assigned(capability, "shape"), "plan.contract")
        _source, plan = read("serverware/authority_revocation_plan.py")
        self.assertIn("from serverware import authority_revocation_plan_contract as contract", ast.unparse(plan))
        _source, shape = read("serverware/authority_revocation_plan_contract.py")
        self.assertEqual(ast.literal_eval(assigned(shape, "MAX_JSON_DEPTH")), 128)
        self.assert_shape(assigned(self.tree, "_HISTORICAL_PAIRS"), '''(("expectedRequest", "expected_request"),
            *(pair for pair in capability.retention._CONTEXT_PAIRS
              if pair[0] not in {"expectedPlannerIdentity", "expectedVerifierIdentity"}))''')
        self.assert_shape(assigned(self.tree, "HISTORICAL_FIELDS"),
            'frozenset({"databaseCutoffUs", *(name for name, _ in _HISTORICAL_PAIRS)})')
        _source, retention = read("serverware/authority_revocation_retention.py")
        pairs = ast.literal_eval(assigned(retention, "_CONTEXT_PAIRS"))
        actual_history = {name for name, _argument in pairs} - {"expectedPlannerIdentity", "expectedVerifierIdentity"}
        self.assertEqual(actual_history | {"expectedRequest", "databaseCutoffUs"}, HISTORICAL_FIELDS)
        capture = definition(self.tree, "_capture_history")
        self.assert_shape(assigned(capture, "owned"), "capability.capture._JSONCapture(ledger).visit(document, depth=2)")
        self.assert_shape(assigned(capture, "instant"), 'expectations["database_now"]')
        guards = [node for node in capture.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 1)
        self.assert_shape(guards[0].test, "type(instant) is not datetime or instant.tzinfo is not timezone.utc")
        self.assert_shape(assigned(capture, "document"),
            "{name: expectations[argument] for name, argument in _HISTORICAL_PAIRS}")
        cutoff = calls(capture, "capability.plan.semantics.complete.cutoff_microseconds")
        self.assertEqual(len(cutoff), 1)
        self.assert_shape(cutoff[0], "capability.plan.semantics.complete.cutoff_microseconds(instant)")
        history = definition(self.tree, "_history_shape")
        self.assert_shape(assigned(history, "instant"), "_EPOCH + timedelta(microseconds=cutoff)")
        self.assertIn("capability.plan.semantics.complete.cutoff_microseconds(instant) != cutoff", ast.unparse(history))

        # This is a source-inventory assertion, not native execution evidence.
        makefile = ROOT / "Makefile"
        self.assertLess(makefile.stat().st_size, 2 * 1024 * 1024)
        make_source = makefile.read_text(encoding="utf-8")
        closure = make_source.split("override CODER_COUNTED_NATIVE_SOURCE_DEPENDENCIES :=", 1)[1].split("CODER_TIMEOUT ?=", 1)[0]
        paths = {token for token in closure.split() if token != "\\"}
        self.assertTrue({"serverware/authority_revocation_invocation.py", "serverware/authority_revocation_issuance.py",
            "serverware/authority_revocation_capability.py", "serverware/authority_revocation_capability_production.py",
            "serverware/authority_revocation_plan.py", "serverware/authority_revocation_retention.py"} <= paths)

    def test_producer_owns_claims_and_reserves_complete_three_encoder_output_before_signing(self):
        producer = definition(self.tree, "_produce_invocation_on_work")
        capture = calls(producer, "_capture_history")
        encodes = calls(producer, "_encode")
        callbacks = calls(producer, "production._callback")
        signer = calls(producer, "_sign_wire")
        self.assertEqual((len(capture), len(encodes), len(callbacks), len(signer)), (1, 2, 3, 1))
        self.assert_shape(capture[0], "_capture_history(historical_expectations, ledger)")
        self.assert_shape(encodes[0], "_encode(capability_bytes, work)")
        self.assert_shape(encodes[1], "_encode(witness_request_bytes, work)")
        self.assertLess(capture[0].lineno, encodes[0].lineno)
        self.assertLess(encodes[-1].lineno, callbacks[0].lineno)
        self.assertLess(callbacks[-1].lineno, signer[0].lineno)
        self.assert_shape(calls(producer, "work.charge")[0], "work.charge(input_bytes=2 * 32 + 2 * 32)")
        self.assert_shape(signer[0], "_sign_wire(unsigned, signer_private_key, signer_public_key, work)")
        for callback in callbacks:
            self.assert_shape(callback.args[0], "work")
        self.assertFalse(calls(producer, "_ValidationWork"))
        sign_wire = definition(self.tree, "_sign_wire")
        measurements = calls(sign_wire, "work.measure")
        encoders = calls(sign_wire, "capability.plan.core.canonical_bytes")
        actual_sign = calls(sign_wire, "production._sign_and_verify")
        self.assertEqual((len(measurements), len(encoders), len(actual_sign)), (3, 3, 1))
        self.assert_shape(calls(sign_wire, "work.charge")[0], '''work.charge(
            input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=2 * unsigned_nodes + envelope_nodes)''')
        guards = [node for node in sign_wire.body if isinstance(node, ast.If)]
        self.assert_shape(guards[0].test, '''max(unsigned_size, envelope_size) > MAX_ENVELOPE_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_JSON_NODES''')
        self.assert_shape(guards[1].test, '''work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes''')
        self.assertLess(measurements[1].lineno, guards[1].lineno)
        self.assertLess(guards[1].lineno, encoders[0].lineno)
        self.assertLess(encoders[0].lineno, actual_sign[0].lineno)
        self.assertLess(actual_sign[0].lineno, measurements[2].lineno)
        self.assertLess(measurements[2].lineno, encoders[1].lineno)
        self.assertLess(encoders[1].lineno, encoders[2].lineno)
        self.assert_shape(actual_sign[0], "production._sign_and_verify(private_key, public_key, message, work)")
        self.assertIn("current_wire != unsigned_wire", ast.unparse(sign_wire))

    def test_receiver_authenticates_original_wire_before_header_joins_freshness_and_decoding(self):
        receiver = definition(self.tree, "_verify_invocation_on_work")
        spellings = ("capability.wire._decode_object", "_shape", "capability._canonical", "work.prepare_copy",
            "capability._wire", "capability._signature", "_bind", "_fresh")
        phases = [calls(receiver, spelling) for spelling in spellings]
        self.assertEqual([len(phase) for phase in phases], [1] * len(spellings))
        self.assertEqual([phase[0].lineno for phase in phases], sorted(phase[0].lineno for phase in phases))
        self.assert_shape(phases[0][0], '''capability.wire._decode_object(envelope_bytes, work=work,
            maximum_bytes=MAX_ENVELOPE_BYTES, maximum_nodes=MAX_JSON_NODES, maximum_depth=MAX_JSON_DEPTH)''')
        self.assert_shape(phases[2][0], "capability._canonical(envelope_bytes, envelope, ledger, MAX_ENVELOPE_BYTES, MAX_JSON_NODES)")
        self.assert_shape(phases[5][0], "capability._signature(verifier_public_key, signature, ENVELOPE_SCHEMA, unsigned_wire, ledger)")
        self.assert_shape(phases[6][0], "_bind(envelope, expected_configuration_digest, expected_generation_sequence, expected_generation_digest, work)")
        self.assert_shape(phases[7][0], "_fresh(envelope, now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)")
        decodes = calls(receiver, "_decode")
        self.assertEqual(len(decodes), 2)
        self.assertLess(phases[-1][0].lineno, decodes[0].lineno)
        self.assert_shape(decodes[0], '_decode(payload["capabilityBase64Url"], payload["capabilityByteCount"], capability.MAX_CAPABILITY_BYTES, work)')
        self.assert_shape(decodes[1], '_decode(payload["witnessRequestBase64Url"], payload["witnessRequestByteCount"], capability.MAX_WITNESS_REQUEST_BYTES, work)')
        bind = definition(self.tree, "_bind")
        comparison = calls(bind, "capability.plan._same")
        self.assertEqual(len(comparison), 1)
        self.assert_shape(comparison[0].args[0], '''(envelope["configurationDigest"], payload["generationSequence"], payload["generationDigest"],
            envelope["envelopeId"], envelope["parentEnvelopeId"], envelope["fence"], envelope["deadlineMonotonicNs"])''')
        self.assert_shape(comparison[0].args[1], '''(configuration, sequence, generation, historical["expectedCapabilityId"],
            historical["expectedPlannerTransactionId"], historical["expectedFence"], historical["deadlineMonotonicNs"])''')
        self.assert_shape(comparison[0].args[2], "work")
        guarded = [node for node in receiver.body if isinstance(node, ast.Try)]
        self.assertEqual(len(guarded), 1)
        self.assert_shape(assigned(guarded[0], "historical"),
            '{argument: payload["historicalExpectations"][name] for name, argument in _HISTORICAL_PAIRS}')
        observation = calls(receiver, "_AuthenticatedInvocation")
        self.assertEqual(len(observation), 1)
        self.assertEqual([ast.unparse(argument) for argument in observation[0].args[:4]],
            ["envelope", "envelope_bytes", "original_capability", "original_request"])
        self.assertFalse(calls(self.tree, "_ValidationWork"))
        self.assertFalse(calls(self.tree, "capability._verify_signed_capability_on_work"))
        self.assertFalse(calls(self.tree, "capability.retention._verify_record_on_work"))


if __name__ == "__main__":
    unittest.main()
