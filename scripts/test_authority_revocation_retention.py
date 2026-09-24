#!/usr/bin/env python3
"""Original retention bytes with independent commitments and work oracles.

Synthetic roots, clocks and keys exercise genuine signatures and proof replay.
These fixtures establish neither deployed PostgreSQL behavior nor currentness.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_retention as retention
from serverware import authority_revocation_persistence as coordinator
from serverware import authority_revocation_wire as reader
import test_authority_revocation_plan as oracle
import test_authority_revocation_wire as wire_oracle


CONTEXT_SCHEMA = "serverware.policyAuthorityRevocationEvaluationContext/v1"
RECORD_SCHEMA = "serverware.policyAuthorityRevocationRetainedPlan/v1"


def record_context(fixture):
    return {"schema": CONTEXT_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
        "databaseCutoffUs": fixture.semantic.cutoff_us, **oracle.production_context(fixture)}


def record_header(fixture, raw, context_raw):
    measured = fixture.payload["measuredPlan"]
    return {"schema": RECORD_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
        "planProtocol": "revocation-v4", "plannerTransactionId": fixture.planner_transaction_id,
        "operationId": measured["operationId"], "requestDigest": measured["requestDigest"],
        "capabilityId": measured["capabilityId"],
        "plannerKeyDigest": oracle.sha(fixture.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "verifierKeyDigest": oracle.sha(fixture.semantic.receipt.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "envelopeDigest": oracle.sha(raw), "envelopeByteCount": len(raw),
        "contextDigest": oracle.sha(context_raw), "contextByteCount": len(context_raw)}


def independent_record_metrics(fixture):
    """Closed passes over fixture inputs, never production-returned counters."""
    context = record_context(fixture)
    raw, context_raw = oracle.wire(fixture.envelope), oracle.wire(context)
    prefix = oracle.add(
        oracle.graph_cost({"expectedRequest": fixture.semantic.request, "context": context}, 1, 1),
        wire_oracle.decoder_units(context_raw, context), oracle.graph_cost(context),
        (0, 2 * len(context_raw), 0), oracle.canonical_comparison(context, context),
        wire_oracle.decoder_units(raw, fixture.envelope), (0, 2 * len(raw), 0))
    phases = oracle.independent_metrics(fixture)
    tail = oracle.add((5, 128 + len(raw) + len(context_raw) + len(oracle.wire(fixture.payload)), 0),
        oracle.json_digest_cost(RECORD_SCHEMA, record_header(fixture, raw, context_raw)))
    total = oracle.add(prefix, phases["total"], tail)
    replay_peak = oracle.add(prefix, phases["admission"])
    return {"prefix": prefix, "tail": tail, "total": total,
        "admission": tuple(max(left, right) for left, right in zip(replay_peak, total))}


class _SerializationCallbackKey(oracle._CallbackPublicKey):
    def public_bytes(self, encoding, format):
        raw = self.key.public_bytes(encoding, format)
        self.callback()
        return raw

    def verify(self, signature, data):
        self.key.verify(signature, data)
        self.calls += 1


class RevocationRetentionTests(unittest.TestCase):
    def fixture(self):
        return oracle.PlanFixture(approval=False, include_audit=False)

    def verify(self, fixture, work=None, **changes):
        supplied = {"envelope_bytes": oracle.wire(fixture.envelope),
            "evaluation_context_bytes": oracle.wire(record_context(fixture)),
            "work": work or accounting._ValidationWork(accounting.QueryReadValidationLimits()),
            **wire_oracle.expectations(fixture)}
        supplied.update(changes)
        return retention._verify_record_on_work(**supplied)

    def test_original_bytes_keys_header_and_genuine_replay_match_independent_oracles(self):
        fixture = self.fixture()
        raw, context_raw = oracle.wire(fixture.envelope), oracle.wire(record_context(fixture))
        expected = independent_record_metrics(fixture)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*expected["admission"]))
        with patch.object(retention.plan, "_verify_signed_revocation_plan_on_work",
                wraps=retention.plan._verify_signed_revocation_plan_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            actual = self.verify(fixture, work, envelope_bytes=raw, evaluation_context_bytes=context_raw)
        self.assertEqual((replay.call_count, proof.call_count), (1, 1))
        self.assertIs(replay.call_args.kwargs["work"], work)
        self.assertIs(replay.call_args.kwargs["original_envelope_bytes"], raw)
        self.assertIs(actual.envelope_bytes, raw)
        self.assertIs(actual.context_bytes, context_raw)
        self.assertEqual(actual.payload_bytes, oracle.wire(fixture.payload))
        header = record_header(fixture, raw, context_raw)
        self.assertEqual((len(actual.context), len(actual.header)), (18, 13))
        self.assertEqual(actual.header, header)
        self.assertEqual(actual.record_digest, oracle.framed(RECORD_SCHEMA, oracle.wire(header)))
        self.assertEqual(actual.payload_digest, oracle.sha(oracle.wire(fixture.payload)))
        self.assertEqual(actual.verification.semantics.mutations, fixture.semantic.final_mutations)
        self.assertEqual(oracle.units(actual.metrics), expected["total"])
        self.assertEqual(actual.metrics, work.metrics)

    def test_preconsumed_exact_peak_and_each_minus_one_never_create_allowance(self):
        fixture, prior = self.fixture(), (3, 31, 5)
        expected = independent_record_metrics(fixture)
        for dimension in (None, 0, 1, 2):
            limits = list(oracle.add(prior, expected["admission"]))
            if dimension is not None:
                limits[dimension] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = work.limits
            with self.subTest(dimension=dimension), patch.object(retention.plan.retained._PackagingLedger,
                    "__init__", side_effect=AssertionError("fresh outer allowance")):
                if dimension is None:
                    self.verify(fixture, work)
                    self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
                else:
                    with self.assertRaises(retention.RevocationRetentionError):
                        self.verify(fixture, work)
                    self.assertTrue(all(start <= used <= limit for start, used, limit
                        in zip(prior, oracle.units(work.metrics), limits)))
            self.assertIs(work.limits, entering)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_historical_context_is_closed_and_compared_before_signed_replay(self):
        fixture = self.fixture()
        context = record_context(fixture)
        variants = []
        for field in ("databaseCutoffUs", "nowEpochNs", "expectedFence", "maximumPlanAgeNs"):
            changed = copy.deepcopy(context)
            changed[field] += 1
            variants.append(changed)
        variants.extend(({name: value for name, value in context.items() if name != "expectedBefore"},
                         {**context, "currentAuthority": True}, {**context, "sourceRevision": "old"}))
        for changed in variants:
            with self.subTest(changed=tuple(changed)), patch.object(retention.plan,
                    "_verify_signed_revocation_plan_on_work", wraps=retention.plan._verify_signed_revocation_plan_on_work) as replay:
                with self.assertRaises(retention.RevocationRetentionError):
                    self.verify(fixture, evaluation_context_bytes=oracle.wire(changed))
            self.assertEqual(replay.call_count, 0)

    def test_noncanonical_context_bytes_are_not_normalized_into_a_new_record(self):
        fixture = self.fixture()
        raw = oracle.wire(record_context(fixture))
        for changed in (b" " + raw, raw + b"\n", raw.replace(b'"schema":', b'"\\u0073chema":', 1)):
            with self.subTest(length=len(changed)), patch.object(retention.plan,
                    "_verify_signed_revocation_plan_on_work", wraps=retention.plan._verify_signed_revocation_plan_on_work) as replay:
                with self.assertRaises(retention.RevocationRetentionError):
                    self.verify(fixture, evaluation_context_bytes=changed)
            self.assertEqual(replay.call_count, 0)

    def test_external_request_and_key_are_never_enrolled_from_stored_material(self):
        fixture = self.fixture()
        request = copy.deepcopy(fixture.semantic.request)
        request["arguments"]["reason"] = "different admitted request"
        for changes in ({"expected_request": request}, {"planner_public_key": fixture.other_key.public_key()},
                        {"verifier_public_key": fixture.other_key.public_key()}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(retention.RevocationRetentionError):
                self.verify(fixture, **changes)

    def test_original_envelope_and_false_signature_still_use_actual_verifier(self):
        fixture = self.fixture()
        envelope = copy.deepcopy(fixture.envelope)
        envelope["signatureBase64Url"] = "A" * 86
        for raw in (b" " + oracle.wire(fixture.envelope), oracle.wire(envelope)):
            with self.subTest(length=len(raw)), patch.object(retention.plan,
                    "_verify_signed_revocation_plan_on_work", wraps=retention.plan._verify_signed_revocation_plan_on_work) as replay:
                with self.assertRaises(retention.RevocationRetentionError):
                    self.verify(fixture, envelope_bytes=raw)
            self.assertEqual(replay.call_count, 1)

    def test_external_graphs_are_owned_before_actual_key_callbacks(self):
        fixture = self.fixture()
        pins = wire_oracle.expectations(fixture)
        def mutate():
            pins["expected_request"]["arguments"]["reason"] = "caller mutated after capture"
            pins["expected_planner_identity"].clear()
            pins["expected_before"].clear()
        key = oracle._CallbackPublicKey(fixture.key.public_key(), mutate)
        pins["planner_public_key"] = key
        actual = self.verify(fixture, **pins)
        self.assertEqual(key.calls, 1)
        self.assertEqual(actual.context, record_context(fixture))
        self.assertEqual(actual.payload, fixture.payload)

    def test_key_serialization_cannot_refund_or_spend_the_shared_work(self):
        fixture = self.fixture()
        for mutate in (lambda work: setattr(work, "input_bytes", work.input_bytes - 1),
                       lambda work: work.charge(input_bytes=1)):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            key = _SerializationCallbackKey(fixture.key.public_key(), lambda: mutate(work))
            with self.assertRaisesRegex(retention.RevocationRetentionError, "key serialization"):
                self.verify(fixture, work, planner_public_key=key)
            self.assertEqual(key.calls, 1)

    def test_missing_extra_or_success_token_expectations_deny_before_decode(self):
        fixture = self.fixture()
        pins = wire_oracle.expectations(fixture)
        for changed in ({key: value for key, value in pins.items() if key != "expected_request"},
                        {**pins, "verified_record": {}}, {**pins, "limits": accounting.QueryReadValidationLimits()}):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with patch.object(reader, "_decode_object", wraps=reader._decode_object) as decode:
                with self.assertRaises(retention.RevocationRetentionError):
                    retention._verify_record_on_work(envelope_bytes=oracle.wire(fixture.envelope),
                        evaluation_context_bytes=oracle.wire(record_context(fixture)), work=work, **changed)
            self.assertEqual((decode.call_count, oracle.units(work.metrics)), (0, (0, 0, 0)))

    def test_context_parser_bounds_precede_decode_without_changing_parser_cost(self):
        self.assertEqual((retention.MAX_CONTEXT_BYTES, retention.MAX_CONTEXT_NODES,
                          retention.MAX_CONTEXT_DEPTH), (524288, 4096, 8))
        value = {"a": [1, 2]}
        raw = oracle.wire(value)
        nodes = wire_oracle.counts(value)[0]
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        self.assertEqual(reader._decode_object(raw, work=work, maximum_bytes=len(raw),
            maximum_nodes=nodes, maximum_depth=3), value)
        self.assertEqual(oracle.units(work.metrics), wire_oracle.decoder_units(raw, value))
        for changes in ({"maximum_bytes": len(raw) - 1}, {"maximum_nodes": nodes - 1},
                        {"maximum_depth": 1}, {"maximum_nodes": True}, {"maximum_bytes": 2**64}):
            with self.subTest(changes=changes), patch.object(reader.json, "loads", wraps=reader.json.loads) as decode:
                with self.assertRaises(ValueError):
                    reader._decode_object(raw, work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **changes)
            self.assertEqual(decode.call_count, 0)

        boundary_inputs = (b'{"a":"' + b'x' * 524288 + b'"}',
            oracle.wire({str(index): None for index in range(2048)}),
            b'{"a":' * 9 + b'0' + b'}' * 9)
        for bounded in boundary_inputs:
            with self.subTest(size=len(bounded)), patch.object(reader.json, "loads", wraps=reader.json.loads) as decode:
                with self.assertRaises(ValueError):
                    reader._decode_object(bounded,
                        work=accounting._ValidationWork(accounting.QueryReadValidationLimits()),
                        maximum_bytes=524288, maximum_nodes=4096, maximum_depth=8)
            self.assertEqual(decode.call_count, 0)

    def test_configured_coordinator_owns_identity_pins_and_external_request_before_io(self):
        fixture = self.fixture()
        planner_identity = copy.deepcopy(fixture.identity)
        verifier_identity = copy.deepcopy(fixture.semantic.receipt.identity)
        planner_key, verifier_key = fixture.key.public_key(), fixture.semantic.receipt.key.public_key()
        configured = coordinator.RevocationPlannerPersistence(persistence_dsn="postgresql://synthetic.invalid/example",
            connect_timeout_seconds=5, planner_public_key=planner_key, verifier_public_key=verifier_key,
            expected_planner_identity=planner_identity, expected_verifier_identity=verifier_identity)
        planner_identity.clear()
        verifier_identity.clear()
        pins = wire_oracle.expectations(fixture)
        for name in ("planner_public_key", "verifier_public_key", "expected_planner_identity", "expected_verifier_identity"):
            pins.pop(name)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        owned = configured._inputs(pins, work)
        pins["expected_request"]["arguments"]["reason"] = "changed after admission"
        pins["expected_before"].clear()
        self.assertIs(owned["planner_public_key"], planner_key)
        self.assertIs(owned["verifier_public_key"], verifier_key)
        self.assertEqual(owned["expected_planner_identity"], fixture.identity)
        self.assertEqual(owned["expected_verifier_identity"], fixture.semantic.receipt.identity)
        self.assertEqual(owned["expected_request"], fixture.semantic.request)
        self.assertEqual(owned["expected_before"], fixture.semantic.expected_before)
        graph = {name: value for name, value in owned.items()
            if name not in {"planner_public_key", "verifier_public_key", "database_now"}}
        self.assertEqual(oracle.units(work.metrics), oracle.graph_cost(graph, 1, 1))
        self.assertNotIn("postgresql", repr(configured))

    def test_coordinator_rejects_per_call_configured_pin_overrides_before_io(self):
        fixture = self.fixture()
        configured = coordinator.RevocationPlannerPersistence(persistence_dsn="postgresql://synthetic.invalid/example",
            connect_timeout_seconds=5, planner_public_key=fixture.key.public_key(),
            verifier_public_key=fixture.semantic.receipt.key.public_key(),
            expected_planner_identity=fixture.identity, expected_verifier_identity=fixture.semantic.receipt.identity)
        pins = wire_oracle.expectations(fixture)
        for name in ("planner_public_key", "verifier_public_key", "expected_planner_identity", "expected_verifier_identity"):
            pins.pop(name)
        variants = ({**pins, "planner_public_key": fixture.other_key.public_key()},
            {**pins, "expected_verifier_identity": fixture.identity},
            {name: value for name, value in pins.items() if name != "expected_request"})
        for changed in variants:
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.assertRaises(ValueError):
                configured._inputs(changed, work)
            self.assertEqual(oracle.units(work.metrics), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
