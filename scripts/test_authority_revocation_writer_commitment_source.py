#!/usr/bin/env python3
"""Nonimporting linkage for detached verifier intent and planner relay.

Source controls neither execute extracted functions nor establish transport,
key provisioning, database custody, current roots, policy admission or genuine
plan replay. Authenticated sender claims remain inputs to those separate real
boundaries; no ordinary carrier becomes a successful-proof or durable ACK token.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import ROOT, assigned, call, calls, definition, keywords, source


OUTER_FIELDS = frozenset({
    "schema", "envelopeId", "parentEnvelopeId", "purpose", "configurationDigest",
    "issuedAtEpochNs", "issuedMonotonicNs", "deadlineMonotonicNs", "fence", "payload", "signature"})
INTENT_FIELDS = frozenset({
    "schema", "sourceRevision", "generationSequence", "generationDigest", "capabilityId",
    "plannerTransactionId", "executionEnvelopeId", "plannedAtEpochNs", "databaseCutoffUs",
    "planEnvelopeDigest", "planEnvelopeByteCount", "evaluationContextDigest", "evaluationContextByteCount",
    "historicalExpectationsDigest", "historicalExpectationsByteCount"})
RELAY_FIELDS = frozenset({
    "schema", "sourceRevision", "generationSequence", "generationDigest",
    "verifierIntentDigest", "verifierIntentByteCount"})
HISTORY_FIELDS = frozenset({
    "expected_request", "expected_capability_id", "expected_planner_transaction_id", "expected_fence",
    "reserved_at_epoch_ns", "deadline_epoch_ns", "deadline_monotonic_ns", "now_epoch_ns", "now_monotonic_ns",
    "maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns",
    "expected_before", "expected_approver_policy_digest"})


class RevocationWriterCommitmentSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("serverware/authority_revocation_writer_commitment.py", 128 * 1024)

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_original_byte_apis_accept_no_verified_object_or_operation_override(self):
        intent = definition(self.tree, "_produce_intent_on_work")
        relay = definition(self.tree, "_produce_relay_on_work")
        receiver = definition(self.tree, "_verify_commitments_on_work")
        self.assertEqual([item.arg for item in intent.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "planned_at_epoch_ns", "envelope_id",
            "planner_transaction_id", "verifier_private_key", "verifier_public_key", "planner_public_key",
            "configuration_digest", "generation_sequence", "generation_digest", "issued_at_epoch_ns",
            "issued_monotonic_ns", "work"])
        self.assertEqual(intent.args.kwarg.arg, "expectations")
        relay_fields = ["intent_bytes", "envelope_bytes", "evaluation_context_bytes", "historical_expectations_bytes",
            "planner_private_key", "planner_public_key", "verifier_public_key", "expected_configuration_digest",
            "expected_generation_sequence", "expected_generation_digest", "now_epoch_ns", "now_monotonic_ns",
            "maximum_age_ns", "maximum_clock_skew_ns", "work"]
        self.assertEqual([item.arg for item in relay.args.kwonlyargs], relay_fields)
        self.assertEqual([item.arg for item in receiver.args.kwonlyargs],
                         ["intent_bytes", "relay_bytes", *(field for field in relay_fields[1:]
                                                             if field != "planner_private_key")])
        for function in (intent, relay, receiver):
            self.assertEqual(function.args.args, [])
            self.assertIsNone(function.args.vararg)
            self.assertTrue(all(value is None for value in function.args.kw_defaults))
        self.assertIsNone(relay.args.kwarg)
        self.assertIsNone(receiver.args.kwarg)
        imports = [ast.unparse(node) for node in self.tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        for forbidden in ("authority_service", "authority_transport", "authority_transition_registry",
                          "authority_revocation_persistence", "authority_store", "psycopg", "socket", "import db"):
            self.assertFalse(any(forbidden in item for item in imports))
        self.assertEqual([node.target.id for node in definition(self.tree, "_AuthenticatedCommitments").body
                          if isinstance(node, ast.AnnAssign)], ["intent_envelope", "relay_envelope", "intent_bytes",
            "relay_bytes", "envelope_bytes", "evaluation_context_bytes", "historical_expectations_bytes",
            "arguments", "expectations", "metrics"])

    def test_closed_controls_detach_source_bounded_history_without_widening_shared_work(self):
        literals = {
            "INTENT_SCHEMA": "serverware.policyAuthorityRevocationWriterIntent/v1",
            "RELAY_SCHEMA": "serverware.policyAuthorityRevocationWriterRelay/v1",
            "INTENT_PURPOSE": "authorize-revocation-writer-custody",
            "RELAY_PURPOSE": "relay-revocation-writer-custody",
            "INTENT_ID_DOMAIN": "serverware.policyAuthorityRevocationWriterIntentEnvelope/v1",
            "RELAY_ID_DOMAIN": "serverware.policyAuthorityRevocationWriterRelayEnvelope/v1",
            "MAX_CONTROL_NODES": 4096, "MAX_CONTROL_DEPTH": 2}
        for name, value in literals.items():
            self.assertEqual(ast.literal_eval(assigned(self.tree, name)), value)
        for name, expected in (("ENVELOPE_FIELDS", OUTER_FIELDS), ("INTENT_FIELDS", INTENT_FIELDS),
                               ("RELAY_FIELDS", RELAY_FIELDS)):
            actual = assigned(self.tree, name)
            self.assertEqual(ast.unparse(actual.func), "frozenset")
            self.assertEqual(ast.literal_eval(actual.args[0]), expected)
        shape = definition(self.tree, "_shape")
        self.assertEqual([ast.unparse(node) for node in calls(shape, "shape._object")], [
            "shape._object(envelope, ENVELOPE_FIELDS, 'writer commitment envelope')",
            "shape._object(payload, RELAY_FIELDS if relay else INTENT_FIELDS, 'writer commitment payload')"])
        self.assertEqual([ast.unparse(node) for node in calls(shape, "shape._literal")], [
            "shape._literal(envelope['schema'], ENVELOPE_SCHEMA)",
            "shape._literal(envelope['purpose'], RELAY_PURPOSE if relay else INTENT_PURPOSE)",
            "shape._literal(payload['schema'], RELAY_SCHEMA if relay else INTENT_SCHEMA)",
            "shape._literal(payload['sourceRevision'], authority.SOURCE_REVISION)"])
        for name, expression in (("ENVELOPE_SCHEMA", "authority.INTERNAL_ENVELOPE_SCHEMA"),
                ("MAX_CONTROL_BYTES", "authority.MAX_REQUEST_BYTES"),
                ("MAX_HISTORY_BYTES", "capture.MAX_TOTAL_INPUT_BYTES"),
                ("MAX_HISTORY_NODES", "capture.MAX_TOTAL_JSON_NODES"),
                ("MAX_HISTORY_DEPTH", "capture.MAX_JSON_DEPTH"),
                ("HISTORY_FIELDS", "action._EXTERNAL_FIELDS - {'database_now'}")):
            self.shape(assigned(self.tree, name), expression)
        _, plan = source("serverware/authority_revocation_plan.py", 256 * 1024)
        self.assertEqual(ast.literal_eval(assigned(plan, "_VERIFICATION_INPUTS").args[0]) - {
            "envelope", "planner_public_key", "verifier_public_key", "expected_planner_identity",
            "expected_verifier_identity", "database_now"}, HISTORY_FIELDS)
        _, authority = source("serverware/authority_contract.py", 512 * 1024)
        self.shape(assigned(authority, "MAX_REQUEST_BYTES"), "4 * 1024 * 1024")
        self.assertEqual(ast.literal_eval(assigned(authority, "INTERNAL_ENVELOPE_SCHEMA")),
                         "serverware.policyAuthorityInternalEnvelope/v3")
        _, accounting = source("serverware/authority_query_read_work.py", 64 * 1024)
        _, capture = source("serverware/authority_complete_query_batch.py", 128 * 1024)
        for tree, byte_name, node_name in ((accounting, "MAX_INPUT_BYTES", "MAX_JSON_NODES"),
                                         (capture, "MAX_TOTAL_INPUT_BYTES", "MAX_TOTAL_JSON_NODES")):
            self.shape(assigned(tree, byte_name), "64 * 1024 * 1024")
            self.assertEqual(ast.literal_eval(assigned(tree, node_name)), 1_000_000)
            self.assertEqual(ast.literal_eval(assigned(tree, "MAX_JSON_DEPTH")), 128)
        self.assertFalse(calls(self.tree, "_ValidationWork"))
        self.assertFalse(calls(self.tree, "QueryReadValidationLimits"))
        self.assertFalse(any(isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
            and node.attr in {"limits", "hash_work", "input_bytes", "json_nodes"} for node in ast.walk(self.tree)))
        bounds = definition(self.tree, "_body_bounds")
        self.assertEqual([ast.unparse(node) for node in calls(bounds, "_raw")], [
            "_raw(envelope_bytes, plan.contract.MAX_PAYLOAD_BYTES)",
            "_raw(evaluation_context_bytes, retention.MAX_CONTEXT_BYTES)",
            "_raw(historical_expectations_bytes, MAX_HISTORY_BYTES)"])

    def test_stable_purpose_ids_and_signed_utc_do_not_retime_or_recapture_history(self):
        self.shape(call(definition(self.tree, "_intent_id"), "plan._frame"),
            "plan._frame(INTENT_ID_DOMAIN, (plan._ascii(execution_id, work), plan._ascii(planner_id, work)), work)")
        self.shape(call(definition(self.tree, "_relay_id"), "plan._frame"),
            "plan._frame(RELAY_ID_DOMAIN, (plan._ascii(intent_id, work),), work)")
        utc = definition(self.tree, "_utc")
        scalar = definition(self.tree, "_signed_cutoff")
        self.shape(scalar.body[0].test, "type(cutoff) is not int or not -(2**63) <= cutoff < 2**63")
        self.shape(utc.body[0].value, "_signed_cutoff(cutoff)")
        self.shape(assigned(utc, "instant"), "_EPOCH + timedelta(microseconds=cutoff)")
        self.shape(utc.body[2].test, "plan.semantics.complete.cutoff_microseconds(instant) != cutoff")
        self.shape(utc.body[-1].value, "instant")
        shape = definition(self.tree, "_shape")
        self.shape(call(shape, "_signed_cutoff"), '_signed_cutoff(payload["databaseCutoffUs"])')
        self.assertFalse(calls(shape, "_utc"))
        self.assertEqual(len(calls(self.tree, "_utc")), 1)
        self.assertEqual(call(self.tree, "_utc"), call(definition(self.tree, "_bind_intent"), "_utc"))
        self.shape(assigned(self.tree, "_EPOCH"), "datetime(1970, 1, 1, tzinfo=timezone.utc)")
        for spelling in ("datetime.now", "datetime.fromtimestamp", "time.time_ns", "time.monotonic_ns"):
            self.assertFalse(calls(self.tree, spelling))
        _, action = source("serverware/authority_revocation_writer_action.py", 64 * 1024)
        captured = definition(action, "_capture_action_inputs")
        self.shape(assigned(captured, "database_now"), 'expectations["database_now"]')
        self.assertIn("type(database_now) is not datetime or database_now.tzinfo is not timezone.utc", ast.unparse(captured))
        self.shape(assigned(captured, "owned"), """retention.capture._JSONCapture(ledger).visit({
            name: value for name, value in expectations.items() if name != "database_now"})""")
        _, capture = source("serverware/authority_complete_query_batch.py", 128 * 1024)
        visit = definition(definition(capture, "_JSONCapture"), "visit")
        self.assertEqual([item.arg for item in visit.args.args[:3]], ["self", "value", "depth"])
        self.assertEqual(ast.literal_eval(visit.args.defaults[0]), 0)

    def test_original_controls_and_history_are_parsed_but_plan_and_context_are_only_committed(self):
        decoded = definition(self.tree, "_read_control")
        self.shape(call(decoded, "wire._decode_object"), """wire._decode_object(raw, work=ledger.work,
            maximum_bytes=MAX_CONTROL_BYTES, maximum_nodes=MAX_CONTROL_NODES, maximum_depth=MAX_CONTROL_DEPTH)""")
        validated = call(decoded, "_shape")
        self.shape(validated, "_shape(value, relay=relay)")
        canonical = call(decoded, "capability._canonical")
        copied = call(decoded, "ledger.work.prepare_copy")
        unsigned = assigned(decoded, "unsigned")
        emitted = call(decoded, "capability._wire")
        self.assertEqual([node.lineno for node in (canonical, copied, unsigned, emitted)],
                         sorted(node.lineno for node in (canonical, copied, unsigned, emitted)))
        self.assertLess(validated.lineno, canonical.lineno)
        self.shape(canonical, "capability._canonical(raw, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)")
        self.shape(copied, "ledger.work.prepare_copy(value)")
        self.shape(unsigned, "value.copy()")
        self.shape(decoded.body[-1].value, "(value, signature, unsigned_wire)")
        binding = definition(self.tree, "_bind_intent")
        body_hash_loop, = [node for node in binding.body if isinstance(node, ast.For)]
        self.shape(body_hash_loop.iter, """(
            (envelope_bytes, "planEnvelopeDigest", "planEnvelopeByteCount"),
            (evaluation_context_bytes, "evaluationContextDigest", "evaluationContextByteCount"),
            (historical_expectations_bytes, "historicalExpectationsDigest", "historicalExpectationsByteCount"))""")
        self.shape(call(body_hash_loop, "plan._same"), """plan._same((retention._bytes_digest(raw, work), len(raw)),
            (payload[digest_name], payload[count_name]), work, "writer commitment detached original body changed")""")
        history = call(binding, "wire._decode_object")
        self.shape(history, """wire._decode_object(historical_expectations_bytes, work=work,
            maximum_bytes=MAX_HISTORY_BYTES, maximum_nodes=MAX_HISTORY_NODES, maximum_depth=MAX_HISTORY_DEPTH)""")
        self.shape(call(binding, "plan.contract._object"),
                   'plan.contract._object(history, HISTORY_FIELDS, "writer commitment detached history")')
        self.shape(call(binding, "capability._canonical"), """capability._canonical(
            historical_expectations_bytes, history, ledger, MAX_HISTORY_BYTES, MAX_HISTORY_NODES)""")
        capture = call(binding, "action._capture_action_inputs")
        self.shape(capture, """action._capture_action_inputs(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=payload["plannedAtEpochNs"],
            envelope_id=payload["executionEnvelopeId"], planner_transaction_id=payload["plannerTransactionId"],
            work=work, database_now=_utc(payload["databaseCutoffUs"]), **history)""")
        self.assertLess(body_hash_loop.lineno, history.lineno)
        self.assertLess(history.lineno, capture.lineno)
        self.assertEqual([ast.unparse(node.args[0]) for node in calls(self.tree, "wire._decode_object")],
                         ["raw", "historical_expectations_bytes"])
        for spelling in ("wire._decode_envelope", "retention._verify_record_on_work", "action._assert_policy_on_work",
                "plan._verify_signed_revocation_plan_on_work", "plan.mixed._verify"):
            self.assertFalse(calls(self.tree, spelling))
        _, wire = source("serverware/authority_revocation_wire.py", 64 * 1024)
        loader = call(definition(wire, "_decode_object"), "json.loads")
        self.shape(keywords(loader)["object_pairs_hook"], "_unique_object")
        self.shape(keywords(loader)["parse_float"], "_reject_number")
        self.shape(keywords(loader)["parse_constant"], "_reject_number")

    def test_actual_key_separation_and_complete_output_reservations_precede_signing(self):
        distinct = definition(self.tree, "_distinct_public_keys")
        self.shape(call(distinct, "work.charge"), "work.charge(input_bytes=2 * 32 + 2 * 32)")
        exports = calls(distinct, "production._callback")
        self.assertEqual(len(exports), 2)
        self.shape(exports[0], "production._callback(work, lambda: planner_key.public_bytes(Encoding.Raw, PublicFormat.Raw))")
        self.shape(exports[1], "production._callback(work, lambda: verifier_key.public_bytes(Encoding.Raw, PublicFormat.Raw))")
        self.shape(distinct.body[-1].test,
            "any(type(raw) is not bytes or len(raw) != 32 for raw in (planner, verifier)) or planner == verifier")
        signed = definition(self.tree, "_sign_wire")
        measures = calls(signed, "work.measure")
        encoders = calls(signed, "plan.core.canonical_bytes")
        actual = call(signed, "production._sign_and_verify")
        self.assertEqual((len(measures), len(encoders)), (3, 3))
        self.shape(call(signed, "work.charge"), """work.charge(
            input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=2 * unsigned_nodes + envelope_nodes)""")
        guards = [node for node in signed.body if isinstance(node, ast.If)]
        self.shape(guards[0].test, "max(unsigned_size, envelope_size) > MAX_CONTROL_BYTES or "
                   "max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES")
        self.shape(guards[1].test, """work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes""")
        self.assertLess(measures[1].lineno, guards[1].lineno)
        self.assertLess(guards[1].lineno, encoders[0].lineno)
        self.assertLess(encoders[0].lineno, actual.lineno)
        self.assertLess(actual.lineno, measures[2].lineno)
        self.assertLess(measures[2].lineno, encoders[1].lineno)
        self.assertLess(encoders[1].lineno, encoders[2].lineno)
        self.shape(actual, "production._sign_and_verify(private_key, public_key, message, work)")
        self.shape(guards[3].test, "work.measure(unsigned) != (unsigned_size, unsigned_nodes)")
        self.shape(guards[4].test, "plan.core.canonical_bytes(unsigned) != original")
        self.shape(guards[5].test, "len(result) != envelope_size")
        _, production = source("serverware/authority_revocation_capability_production.py", 64 * 1024)
        key_binding = definition(production, "_key_binding")
        self.shape(call(key_binding, "work.charge"), "work.charge(input_bytes=3 * 32 + 2 * 64)")
        self.assertEqual(len(calls(key_binding, "_callback")), 4)
        self.assertIn("actual != expected", ast.unparse(key_binding))
        self.assertIn("expected == witness", ast.unparse(key_binding))
        paired = definition(production, "_sign_and_verify")
        self.shape(calls(paired, "_callback")[0], "_callback(work, lambda: private_key.sign(message))")
        self.shape(calls(paired, "_callback")[1], "_callback(work, lambda: public_key.verify(signature, message))")

    def test_two_role_authentication_precedes_full_header_binding_and_independent_freshness(self):
        intent = definition(self.tree, "_produce_intent_on_work")
        owned = call(intent, "action._capture_action_inputs")
        emitted = call(intent, "capability._wire")
        key = call(intent, "production._key_binding")
        signed = call(intent, "_sign_wire")
        self.shape(emitted, "capability._wire(history, ledger, MAX_HISTORY_BYTES, MAX_HISTORY_NODES)")
        self.shape(key, "production._key_binding(verifier_private_key, verifier_public_key, planner_public_key, work)")
        self.shape(signed, "_sign_wire(unsigned, verifier_private_key, verifier_public_key, work, relay=False)")
        self.assertEqual([node.lineno for node in (owned, emitted, key, signed)],
                         sorted(node.lineno for node in (owned, emitted, key, signed)))
        self.assertEqual([ast.unparse(node.args[0]) for node in calls(intent, "retention._bytes_digest")],
                         ["envelope_bytes", "evaluation_context_bytes", "historical_bytes"])
        relay = definition(self.tree, "_produce_relay_on_work")
        sequence = [call(relay, name) for name in ("_read_control", "production._key_binding",
                    "capability._signature", "_bind_intent", "_sign_wire")]
        self.assertEqual([node.lineno for node in sequence], sorted(node.lineno for node in sequence))
        self.shape(sequence[1], "production._key_binding(planner_private_key, planner_public_key, verifier_public_key, work)")
        self.shape(sequence[2], "capability._signature(verifier_public_key, signature, ENVELOPE_SCHEMA, unsigned_wire, ledger)")
        self.shape(sequence[4], "_sign_wire(unsigned, planner_private_key, planner_public_key, work, relay=True)")
        self.shape(call(relay, "retention._bytes_digest"), "retention._bytes_digest(intent_bytes, work)")
        receiver = definition(self.tree, "_verify_commitments_on_work")
        controls = calls(receiver, "_read_control")
        signatures = calls(receiver, "capability._signature")
        binding = call(receiver, "_bind_intent")
        fresh = call(receiver, "_fresh")
        self.assertEqual([ast.unparse(node) for node in controls], [
            "_read_control(relay_bytes, ledger, relay=True)", "_read_control(intent_bytes, ledger, relay=False)"])
        self.assertEqual([ast.unparse(node) for node in signatures], [
            "capability._signature(planner_public_key, relay_signature, ENVELOPE_SCHEMA, relay_unsigned, ledger)",
            "capability._signature(verifier_public_key, intent_signature, ENVELOPE_SCHEMA, intent_unsigned, ledger)"])
        separation = call(receiver, "_distinct_public_keys")
        self.assertEqual([node.lineno for node in (*controls, separation, *signatures, binding, fresh)],
                         sorted(node.lineno for node in (*controls, separation, *signatures, binding, fresh)))
        self.shape(binding, """_bind_intent(intent, envelope_bytes, evaluation_context_bytes,
            historical_expectations_bytes, expected_configuration_digest, expected_generation_sequence,
            expected_generation_digest, now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns, ledger)""")
        comparisons = calls(receiver, "plan._same")
        self.assertEqual(len(comparisons), 2)
        self.shape(comparisons[0], """plan._same((retention._bytes_digest(intent_bytes, work), len(intent_bytes)),
            (payload["verifierIntentDigest"], payload["verifierIntentByteCount"]), work,
            "writer relay does not commit to the original verifier intent")""")
        self.shape(comparisons[1], """plan._same(
            (relay["envelopeId"], relay["parentEnvelopeId"], relay["fence"], relay["deadlineMonotonicNs"]),
            (_relay_id(intent["envelopeId"], work), intent["envelopeId"], history["expected_fence"],
             history["deadline_monotonic_ns"]), work, "writer relay header differs from its original intent")""")
        intent_binding = definition(self.tree, "_bind_intent")
        self.shape(calls(intent_binding, "plan._same")[-1], """plan._same(
            (intent["envelopeId"], intent["parentEnvelopeId"], intent["fence"], intent["deadlineMonotonicNs"],
             payload["capabilityId"], payload["plannerTransactionId"]),
            (expected_id, owned["expected_planner_transaction_id"], owned["expected_fence"],
             owned["deadline_monotonic_ns"], owned["expected_capability_id"], owned["expected_planner_transaction_id"]),
            work, "writer intent header differs from its detached historical bindings")""")
        self.shape(call(definition(self.tree, "_bind_configuration"), "plan._same"), """plan._same(
            (envelope["configurationDigest"], payload["generationSequence"], payload["generationDigest"]),
            (configuration, sequence, generation), work,
            "writer commitment differs from independent configuration or generation")""")
        self.shape(call(intent_binding, "_fresh"), "_fresh(intent, owned, now_epoch, now_monotonic, age, skew)")
        self.shape(fresh, "_fresh(relay, history, now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)")
        for function in (relay, receiver):
            self.shape(call(function, "_current"),
                "_current(now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)")
        self.assertIn("skew != authority.VERIFIER_MAX_CLOCK_SKEW_NS", ast.unparse(definition(self.tree, "_current")))
        freshness = definition(self.tree, "_fresh")
        self.shape(assigned(freshness, "remaining_mono"), 'envelope["deadlineMonotonicNs"] - now_monotonic')
        self.shape(assigned(freshness, "remaining_epoch"), 'history["deadline_epoch_ns"] - now_epoch')
        self.shape(freshness.body[2].test, """envelope["issuedMonotonicNs"] > now_monotonic
            or now_monotonic - envelope["issuedMonotonicNs"] > age
            or envelope["issuedAtEpochNs"] > now_epoch + skew
            or now_epoch - envelope["issuedAtEpochNs"] > age
            or remaining_mono <= 0 or remaining_epoch <= 0
            or remaining_mono > age or remaining_epoch > age + skew
            or abs(remaining_epoch - remaining_mono) > skew""")
        self.shape(call(receiver, "_AuthenticatedCommitments"), """_AuthenticatedCommitments(
            intent, relay, intent_bytes, relay_bytes, envelope_bytes, evaluation_context_bytes,
            historical_expectations_bytes, arguments, history, _metrics(phases, 0, 2, work))""")

    def test_measured_policy_and_both_genuine_replays_remain_separate_required_boundaries(self):
        _, service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        action = definition(definition(service, "AuthorityProcess"), "_persist_and_reserve_revocation_plan")
        capture = call(action, "authority_revocation_writer_action._capture_action_inputs")
        policy = call(action, "authority_revocation_writer_action._assert_policy_on_work")
        factory = call(action, "_revocation_writer_from_owned_configuration")
        atomic = call(action, "persistence.persist_and_reserve_execution")
        self.shape(policy, "authority_revocation_writer_action._assert_policy_on_work(owned_payload, owned, work)")
        self.shape(factory, """_revocation_writer_from_owned_configuration(owned_payload=owned_payload,
            configuration_digest=configuration_digest, work=work)""")
        self.shape(atomic, "persistence.persist_and_reserve_execution(**arguments, work=work, **owned)")
        self.assertEqual([node.lineno for node in (capture, policy, factory, atomic)],
                         sorted(node.lineno for node in (capture, policy, factory, atomic)))
        self.assertNotIn("authority_revocation_writer_commitment", ast.unparse(action))
        _, action_tree = source("serverware/authority_revocation_writer_action.py", 64 * 1024)
        check = definition(action_tree, "_assert_policy_on_work")
        self.shape(assigned(check, "assertion_age"), 'payload["webauthn"]["maximumChallengeAgeNs"]')
        self.shape(assigned(check, "verifier_age"), 'payload["roles"]["verifier"]["maximumInternalAgeNs"]')
        self.shape(assigned(check, "measured"), """(assertion_age,
            min(verifier_age, authority.VERIFIER_RESPONSE_MAX_AGE_NS), authority.VERIFIER_MAX_CLOCK_SKEW_NS)""")
        self.assertFalse(any(isinstance(node, (ast.Attribute, ast.Subscript))
            and isinstance(node.ctx, ast.Store) for node in ast.walk(check)))
        _, persistence = source("serverware/authority_revocation_persistence.py", 64 * 1024)
        operation = definition(persistence, "_persist_and_reserve_on_connection")
        retained = call(operation, "store.persist_revocation_planner_record")
        reserved = call(operation, "revocation_execution.reserve_revocation_execution_envelope")
        common, = [node for node in ast.walk(operation) if isinstance(node, ast.With)]
        self.assertIn(retained, list(ast.walk(common)))
        self.assertIn(reserved, list(ast.walk(common)))
        self.assertLess(retained.lineno, reserved.lineno)
        self.shape(reserved, """revocation_execution.reserve_revocation_execution_envelope(
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
            connection=connection, work=work, **expectations)""")
        _, store = source("serverware/authority_store/revocation_retention.py", 64 * 1024)
        self.shape(call(definition(store, "persist_revocation_planner_record"), "retention._verify_record_on_work"),
            """retention._verify_record_on_work(envelope_bytes=envelope_bytes,
                evaluation_context_bytes=evaluation_context_bytes, work=work, **expectations)""")
        self.shape(call(definition(store, "_read_revocation_record_on_work"), "retention._verify_record_on_work"),
            """retention._verify_record_on_work(envelope_bytes=envelope,
                evaluation_context_bytes=context, work=work, **expectations)""")
        _, execution = source("serverware/authority_store/revocation_execution.py", 64 * 1024)
        self.shape(call(definition(execution, "reserve_revocation_execution_envelope"),
            "store._read_revocation_record_on_work"), """store._read_revocation_record_on_work(
                planner_transaction_id=planner_transaction_id, connection=connection,
                work=work, _expected_raw=raw, expectations=owned)""")

    def test_controls_do_not_open_public_routes_peer_topology_or_registry(self):
        service_text, service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        process = definition(service, "AuthorityProcess")
        handle = definition(process, "handle")
        served = definition(definition(service, "AuthorityServer"), "_serve_connection")
        writer, = [node for node in ast.walk(handle) if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "self.role_name == 'planner-writer'"]
        self.shape(keywords(call(writer, "self._verify_internal_envelope"))["allowed_purposes"],
                   "{'persist-measured-plan', 'read-persisted-plan', 'reserve-execution-envelope'}")
        for dispatcher in (handle, served):
            for forbidden in ("authorize-revocation-writer-custody", "relay-revocation-writer-custody",
                    "authority_revocation_writer_commitment", "_verify_commitments_on_work",
                    "_persist_and_reserve_revocation_plan", "_recv_revocation_invocation_bytes"):
                self.assertNotIn(forbidden, ast.unparse(dispatcher))
        self.assertNotIn("authority_revocation_writer_commitment", service_text)
        peer, = [node for node in ast.walk(served) if isinstance(node, ast.If)
                 and ast.unparse(node.test) == "uid != self.peer_uid or gid != self.peer_gid"]
        self.assertLess(peer.lineno, call(served, "self.process.handle").lineno)
        topology = ast.unparse(definition(definition(service, "MeasuredConfiguration"), "_verify_role_topology"))
        self.assertIn("(int(planner_writer.get('peerUid', -1)), int(planner_writer.get('peerGid', -1))) != "
                      "(int(planner['serviceUid']), int(planner['serviceGid']))", topology)
        registry_text, registry = source("serverware/authority_transition_registry.py")
        self.shape(assigned(registry, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        guard, = [node for node in registry.body if isinstance(node, ast.If)]
        self.shape(guard.test, "_CLOSURE_ERRORS")
        self.assertIsInstance(guard.body[0], ast.Raise)
        self.assertNotIn("authorize-revocation-writer-custody", registry_text)
        self.assertNotIn("relay-revocation-writer-custody", registry_text)
        makefile = ROOT / "Makefile"
        self.assertLess(makefile.stat().st_size, 2 * 1024 * 1024)
        closure = makefile.read_text(encoding="utf-8").split(
            "override CODER_COUNTED_NATIVE_SOURCE_DEPENDENCIES :=", 1)[1].split("CODER_TIMEOUT ?=", 1)[0]
        paths = {item for item in closure.split() if item != "\\"}
        self.assertTrue({"serverware/authority_revocation_writer_commitment.py",
            "serverware/authority_revocation_writer_action.py", "serverware/authority_revocation_persistence.py",
            "serverware/authority_store/revocation_retention.py", "serverware/authority_store/revocation_execution.py",
            "serverware/authority_revocation_capability_production.py"} <= paths)


if __name__ == "__main__":
    unittest.main()
