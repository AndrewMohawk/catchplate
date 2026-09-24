#!/usr/bin/env python3
"""Original retention bytes with independent commitments and work oracles.

Synthetic roots, clocks and keys exercise genuine signatures and proof replay.
These fixtures establish neither deployed PostgreSQL behavior nor currentness.
"""
from __future__ import annotations

import copy
from datetime import timedelta, timezone
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
from serverware.authority_store import planner_connection as admission
import test_authority_revocation_plan as oracle
import test_authority_revocation_wire as wire_oracle


CONTEXT_SCHEMA = "serverware.policyAuthorityRevocationEvaluationContext/v1"
RECORD_SCHEMA = "serverware.policyAuthorityRevocationRetainedPlan/v1"
WRITER_DATABASE_IDENTITY = ("serverware_policy_authority_planner_writer",
    "CN=synthetic-writer", "23", "CN=synthetic-writer-issuer")


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

    def coordinator_fixture(self, fixture, *, planner_key=None, verifier_key=None):
        configured = coordinator.RevocationPlannerPersistence(
            persistence_dsn="postgresql://synthetic.invalid/example", connect_timeout_seconds=5,
            planner_public_key=fixture.key.public_key() if planner_key is None else planner_key,
            verifier_public_key=fixture.semantic.receipt.key.public_key() if verifier_key is None else verifier_key,
            expected_planner_identity=fixture.identity,
            expected_verifier_identity=fixture.semantic.receipt.identity,
            writer_database_identity=WRITER_DATABASE_IDENTITY)
        expectations = wire_oracle.expectations(fixture)
        for name in ("planner_public_key", "verifier_public_key",
                     "expected_planner_identity", "expected_verifier_identity"):
            expectations.pop(name)
        return configured, expectations

    def verify(self, fixture, work=None, **changes):
        supplied = {"envelope_bytes": oracle.wire(fixture.envelope),
            "evaluation_context_bytes": oracle.wire(record_context(fixture)),
            "work": work or accounting._ValidationWork(accounting.QueryReadValidationLimits()),
            **wire_oracle.expectations(fixture)}
        supplied.update(changes)
        return retention._verify_record_on_work(**supplied)

    def test_producer_context_original_bytes_exact_work_and_ownership(self):
        fixture, prior = self.fixture(), (1, 7, 5)
        context, document = oracle.production_context(fixture), record_context(fixture)
        raw, expected = oracle.wire(document), oracle.graph_cost(document)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*oracle.add(prior, expected)))
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        limits = work.limits
        # All hash allowance is already spent. The real encoder needs neither
        # hashing, a parser nor a replacement work object to produce context.
        with patch.object(retention.plan.core, "canonical_bytes",
                wraps=retention.plan.core.canonical_bytes) as encode, \
                patch.object(reader.json, "loads", side_effect=AssertionError("context reparsed")), \
                patch.object(accounting._ValidationWork, "__init__",
                             side_effect=AssertionError("fresh allowance")):
            actual = retention._encode_context_on_work(context,
                database_now=fixture.semantic.database_now, work=work)
        self.assertIs(type(actual), bytes)
        self.assertEqual(actual, raw)
        self.assertEqual(encode.call_count, 1)
        self.assertEqual(encode.call_args.args[0], document)
        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected))
        self.assertIs(work.limits, limits)
        context["expectedBefore"].clear()
        context["expectedPlannerIdentity"].clear()
        self.assertEqual(actual, raw)
        self.assertEqual(reader._decode_object(actual,
            work=accounting._ValidationWork(accounting.QueryReadValidationLimits()),
            maximum_bytes=524288, maximum_nodes=4096, maximum_depth=8), document)

    def test_producer_context_each_short_remaining_budget_denies_before_encoding(self):
        fixture, prior = self.fixture(), (1, 7, 5)
        context, document = oracle.production_context(fixture), record_context(fixture)
        required = oracle.add(prior, oracle.graph_cost(document))
        for dimension in (1, 2):
            limits = list(required)
            limits[dimension] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = work.limits
            with self.subTest(dimension=dimension), patch.object(retention.plan.core,
                    "canonical_bytes", wraps=retention.plan.core.canonical_bytes) as encode:
                with self.assertRaises(retention.RevocationRetentionError) as raised:
                    retention._encode_context_on_work(context,
                        database_now=fixture.semantic.database_now, work=work)
            self.assertIsInstance(raised.exception.__cause__, accounting.QueryReadWorkError)
            self.assertEqual(encode.call_count, 0)
            # The genuine first measurement remains spent; reservation of
            # the actual encoder's entire second pass fails atomically.
            self.assertEqual(oracle.units(work.metrics),
                oracle.add(prior, oracle.graph_cost(document, 1, 1)))
            self.assertIs(work.limits, entering)

    def test_producer_context_local_exact_and_short_bounds_precede_encoding(self):
        fixture = self.fixture()
        context, document = oracle.production_context(fixture), record_context(fixture)
        _, length, nodes = oracle.graph_cost(document, 1, 1)
        for byte_bound, node_bound in ((length, nodes), (length - 1, nodes), (length, nodes - 1)):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(byte_bound=byte_bound, node_bound=node_bound), \
                    patch.object(retention, "MAX_CONTEXT_BYTES", byte_bound), \
                    patch.object(retention, "MAX_CONTEXT_NODES", node_bound), \
                    patch.object(retention.plan.core, "canonical_bytes",
                                 wraps=retention.plan.core.canonical_bytes) as encode:
                if (byte_bound, node_bound) == (length, nodes):
                    self.assertEqual(retention._encode_context_on_work(context,
                        database_now=fixture.semantic.database_now, work=work), oracle.wire(document))
                    self.assertEqual((encode.call_count, oracle.units(work.metrics)),
                        (1, (0, 2 * length, 2 * nodes)))
                else:
                    with self.assertRaises(retention.RevocationRetentionError):
                        retention._encode_context_on_work(context,
                            database_now=fixture.semantic.database_now, work=work)
                    self.assertEqual((encode.call_count, oracle.units(work.metrics)), (0, (0, length, nodes)))

    def test_producer_context_closed_shape_and_exact_utc_instant_precede_encoding(self):
        fixture = self.fixture()
        context = oracle.production_context(fixture)
        malformed = [
            {name: value for name, value in context.items() if name != "expectedBefore"},
            {**context, "verified_record": {}}, {**context, "expectedFence": True},
        ]
        nested = copy.deepcopy(context)
        nested["expectedBefore"]["businessBeforeRoots"][0]["table"] = {"nested": "not a scalar"}
        malformed.append(nested)
        invalid_instants = (fixture.semantic.database_now.replace(tzinfo=None),
            fixture.semantic.database_now.astimezone(timezone(timedelta(hours=1))),
            fixture.semantic.cutoff_us)
        cases = [(changed, fixture.semantic.database_now) for changed in malformed]
        cases.extend((context, instant) for instant in invalid_instants)
        for ordinal, (changed, instant) in enumerate(cases):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(ordinal=ordinal), patch.object(retention.plan.core,
                    "canonical_bytes", wraps=retention.plan.core.canonical_bytes) as encode:
                with self.assertRaises(retention.RevocationRetentionError):
                    retention._encode_context_on_work(changed, database_now=instant, work=work)
            self.assertEqual((encode.call_count, oracle.units(work.metrics)), (0, (0, 0, 0)))

    def test_producer_context_identifier_nul_denies_and_other_unicode_round_trips(self):
        fixture = self.fixture()
        for field, name in (("businessBeforeRoots", "table"),
                            ("authorizationBeforeRoots", "table"),
                            ("indexBeforeHeads", "indexId")):
            context = oracle.production_context(fixture)
            self.assertTrue(context["expectedBefore"][field])
            context["expectedBefore"][field][0][name] += "\x00"
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(field=field), patch.object(retention.plan.core,
                    "canonical_bytes", wraps=retention.plan.core.canonical_bytes) as encode:
                with self.assertRaisesRegex(retention.RevocationRetentionError, "NUL"):
                    retention._encode_context_on_work(context,
                        database_now=fixture.semantic.database_now, work=work)
            self.assertEqual((encode.call_count, oracle.units(work.metrics)), (0, (0, 0, 0)))

        # These identifiers have only transport-shape validity here. They do
        # not claim a real source table, index, root or planner admission.
        context = oracle.production_context(fixture)
        context["expectedBefore"]["businessBeforeRoots"][0]["table"] = 'table-\u00e9\U0001f600\n"\\'
        context["expectedBefore"]["indexBeforeHeads"][0]["indexId"] = 'index-\u00e9\t'
        document = {**record_context(fixture), **context}
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        actual = retention._encode_context_on_work(context, database_now=fixture.semantic.database_now, work=work)
        self.assertEqual(actual, oracle.wire(document))
        self.assertEqual(oracle.units(work.metrics), oracle.graph_cost(document))
        self.assertEqual(reader._decode_object(actual,
            work=accounting._ValidationWork(accounting.QueryReadValidationLimits()),
            maximum_bytes=524288, maximum_nodes=4096, maximum_depth=8), document)

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
            expected_planner_identity=planner_identity, expected_verifier_identity=verifier_identity,
            writer_database_identity=WRITER_DATABASE_IDENTITY)
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
        self.assertEqual(configured._snapshot_configuration()[6], WRITER_DATABASE_IDENTITY)
        self.assertNotEqual(configured._snapshot_configuration()[6][:3],
                            configured._snapshot_configuration()[4])
        self.assertNotIn("writer_database_identity", owned)
        graph = {name: value for name, value in owned.items()
            if name not in {"planner_public_key", "verifier_public_key", "database_now"}}
        self.assertEqual(oracle.units(work.metrics), oracle.graph_cost(graph, 1, 1))
        self.assertNotIn("postgresql", repr(configured))

    def test_coordinator_rejects_per_call_configured_pin_overrides_before_io(self):
        fixture = self.fixture()
        configured = coordinator.RevocationPlannerPersistence(persistence_dsn="postgresql://synthetic.invalid/example",
            connect_timeout_seconds=5, planner_public_key=fixture.key.public_key(),
            verifier_public_key=fixture.semantic.receipt.key.public_key(),
            expected_planner_identity=fixture.identity, expected_verifier_identity=fixture.semantic.receipt.identity,
            writer_database_identity=WRITER_DATABASE_IDENTITY)
        pins = wire_oracle.expectations(fixture)
        for name in ("planner_public_key", "verifier_public_key", "expected_planner_identity", "expected_verifier_identity"):
            pins.pop(name)
        variants = ({**pins, "planner_public_key": fixture.other_key.public_key()},
            {**pins, "expected_verifier_identity": fixture.identity},
            {**pins, "writer_database_identity": WRITER_DATABASE_IDENTITY},
            {name: value for name, value in pins.items() if name != "expected_request"})
        for changed in variants:
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.assertRaises(ValueError):
                configured._inputs(changed, work)
            self.assertEqual(oracle.units(work.metrics), (0, 0, 0))

    def test_invocation_configuration_rejects_corrupted_slots_before_capture(self):
        fixture = self.fixture()
        identity = tuple(fixture.identity[name] for name in coordinator._IDENTITY_FIELDS)

        class TupleSubclass(tuple):
            def __iter__(self):
                raise AssertionError("foreign identity iteration")

        variants = [("persistence_dsn", value) for value in (
            None, "", "x" * 65537, "\u00e9" * 32769, "\ud800", "dsn\x00suffix", "dsn\nsuffix", "dsn\rsuffix")]
        variants.extend(("connect_timeout_seconds", value) for value in (True, 5.0, 0, 1, 301))
        variants.extend((name, object()) for name in ("planner_public_key", "verifier_public_key"))
        for name in ("_planner_identity", "_verifier_identity"):
            variants.extend((name, value) for value in (
                list(identity), TupleSubclass(identity), identity[:2], identity + (identity[0],),
                (True, *identity[1:]), ("sha256:" + "G" * 64, *identity[1:]),
                (identity[0] + "0", *identity[1:])))
        database_identity = WRITER_DATABASE_IDENTITY
        variants.extend(("_database_identity", value) for value in (
            None, list(database_identity), TupleSubclass(database_identity),
            database_identity[:3], database_identity + ("extra",),
            ("different-writer", *database_identity[1:]),
            (True, *database_identity[1:]),
        ))
        for index in (1, 2, 3):
            for value in (None, False, "", "embedded\x00nul", "\ud800", "x" * 4097, "\u00e9" * 2049):
                changed = list(database_identity)
                changed[index] = value
                variants.append(("_database_identity", tuple(changed)))
        for name, value in variants:
            configured, expectations = self.coordinator_fixture(fixture)
            object.__setattr__(configured, name, value)
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(name=name, kind=type(value).__name__), \
                    patch.object(coordinator.store, "_owned_expectations",
                                 side_effect=AssertionError("capture before configuration admission")) as capture, \
                    patch.object(coordinator, "_run_on_configuration",
                                 side_effect=AssertionError("connection before configuration admission")) as run:
                with self.assertRaises(ValueError):
                    configured._snapshot_configuration()
                with self.assertRaises(ValueError):
                    configured._inputs(expectations, work)
                with self.assertRaises(ValueError):
                    configured._run(None, {}, expectations, work)
            self.assertEqual((capture.call_count, run.call_count, oracle.units(work.metrics)),
                             (0, 0, (0, 0, 0)))

    def test_invocation_configuration_requires_exact_owner_and_closed_tuple(self):
        fixture = self.fixture()
        configured, expectations = self.coordinator_fixture(fixture)
        configuration = configured._snapshot_configuration()
        self.assertIs(type(configuration), tuple)
        self.assertEqual(len(configuration), 7)
        self.assertEqual(configuration[6], WRITER_DATABASE_IDENTITY)
        for timeout in (2, 300):
            self.assertIsNone(coordinator._validate_configuration((configuration[0], timeout, *configuration[2:])))
        with self.assertRaises(TypeError):
            configuration[0] = "replacement"

        class ForeignOwner(coordinator.RevocationPlannerPersistence):
            def __getattribute__(self, name):
                if name in {"persistence_dsn", "connect_timeout_seconds", "planner_public_key",
                            "verifier_public_key", "_planner_identity", "_verifier_identity", "_database_identity"}:
                    raise AssertionError("foreign configured-owner attribute callback")
                return super().__getattribute__(name)

        foreign = object.__new__(ForeignOwner)
        with self.assertRaises(ValueError):
            coordinator.RevocationPlannerPersistence._snapshot_configuration(foreign)

        class TupleSubclass(tuple):
            def __iter__(self):
                raise AssertionError("foreign configuration iteration")

        for changed in (object(), list(configuration), configuration[:-1],
                        configuration + (None,), TupleSubclass(configuration)):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(kind=type(changed).__name__), \
                    patch.object(coordinator.store, "_owned_expectations",
                                 side_effect=AssertionError("invalid tuple reached capture")) as capture:
                with self.assertRaises(ValueError):
                    coordinator._inputs_from_configuration(changed, expectations, work)
                with self.assertRaises(ValueError):
                    coordinator._run_on_configuration(changed, None, {}, expectations, work)
            self.assertEqual((capture.call_count, oracle.units(work.metrics)), (0, (0, 0, 0)))

    def test_configuration_handoff_preserves_exact_and_preconsumed_capture_work(self):
        fixture, prior = self.fixture(), (1, 7, 5)
        configured, expectations = self.coordinator_fixture(fixture)
        configuration = configured._snapshot_configuration()
        independent = wire_oracle.expectations(fixture)
        graph = {name: value for name, value in independent.items()
                 if name not in {"planner_public_key", "verifier_public_key", "database_now"}}
        expected = oracle.graph_cost(graph, 1, 1)
        for route in ("facade", "snapshot"):
            for deficient in (None, 1, 2):
                maximum = list(oracle.add(prior, expected))
                if deficient is not None:
                    maximum[deficient] -= 1
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*maximum))
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                entering = work.limits
                with self.subTest(route=route, deficient=deficient), \
                        patch.object(accounting._ValidationWork, "__init__",
                                     side_effect=AssertionError("fresh configuration allowance")):
                    def capture():
                        if route == "facade":
                            return configured._inputs(expectations, work)
                        return coordinator._inputs_from_configuration(configuration, expectations, work)

                    if deficient is None:
                        owned = capture()
                        self.assertEqual(owned["expected_request"], fixture.semantic.request)
                        self.assertEqual(owned["expected_before"], fixture.semantic.expected_before)
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected))
                    else:
                        with self.assertRaises(accounting.QueryReadWorkError):
                            capture()
                        self.assertTrue(all(start <= used <= limit for start, used, limit
                            in zip(prior, oracle.units(work.metrics), maximum)))
                self.assertEqual(work.hash_work, prior[0])
                self.assertIs(work.limits, entering)

    def test_configuration_snapshot_survives_genuine_key_callback_and_later_capture(self):
        fixture, prior = self.fixture(), (3, 31, 5)
        raw, context_raw = oracle.wire(fixture.envelope), oracle.wire(record_context(fixture))
        independent = wire_oracle.expectations(fixture)
        graph = {name: value for name, value in independent.items()
                 if name not in {"planner_public_key", "verifier_public_key", "database_now"}}
        captured = oracle.graph_cost(graph, 1, 1)
        record = independent_record_metrics(fixture)
        final = oracle.add(prior, captured, record["total"], captured)
        held = oracle.add(prior, captured, record["admission"])
        maximum = tuple(max(total, peak) for total, peak in zip(final, held))
        fields = ("persistence_dsn", "connect_timeout_seconds", "planner_public_key",
                  "verifier_public_key", "_planner_identity", "_verifier_identity", "_database_identity")
        replacement = ("postgresql://different.invalid/later", 300,
            fixture.other_key.public_key(), fixture.other_key.public_key(),
            ("sha256:" + "a" * 64,) * 3, ("sha256:" + "b" * 64,) * 3,
            (WRITER_DATABASE_IDENTITY[0], "CN=later-writer", "29", "CN=later-issuer"))
        for phase in ("planner", "verifier"):
            changed = []

            def mutate():
                self.assertEqual(changed, [])
                for name, value in zip(fields, replacement):
                    object.__setattr__(configured, name, value)
                expectations["expected_request"]["arguments"]["reason"] = "changed during signature"
                expectations["expected_before"].clear()
                changed.append(phase)

            key = oracle._CallbackPublicKey((fixture.key if phase == "planner"
                else fixture.semantic.receipt.key).public_key(), mutate)
            configured, expectations = self.coordinator_fixture(fixture,
                **{phase + "_key": key})
            configuration = configured._snapshot_configuration()
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*maximum))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = work.limits
            owned = coordinator._inputs_from_configuration(configuration, expectations, work)
            with self.subTest(phase=phase), patch.object(retention.plan.semantics.mixed, "_verify",
                    wraps=retention.plan.semantics.mixed._verify) as mixed, \
                    patch.object(retention.plan.retained._PackagingLedger, "__init__",
                                 side_effect=AssertionError("fresh outer configuration allowance")):
                actual = retention._verify_record_on_work(envelope_bytes=raw,
                    evaluation_context_bytes=context_raw, work=work, **owned)
                # This is a second genuine input capture using the same local
                # configuration and previously owned expectations, not SQL or
                # a successful-record token passed to persistence.
                later = coordinator._inputs_from_configuration(configuration,
                    {name: owned[name] for name in coordinator._CALL_INPUTS}, work)
            self.assertEqual((changed, key.calls, mixed.call_count), ([phase], 1, 1))
            self.assertEqual(configured._snapshot_configuration(), replacement)
            self.assertEqual(configuration[:2], ("postgresql://synthetic.invalid/example", 5))
            self.assertEqual(configuration[6], WRITER_DATABASE_IDENTITY)
            self.assertEqual(actual.envelope_bytes, raw)
            self.assertEqual(actual.context_bytes, context_raw)
            self.assertEqual(actual.payload, fixture.payload)
            for name in ("planner_public_key", "verifier_public_key"):
                self.assertIs(later[name], owned[name])
            self.assertEqual(later["expected_planner_identity"], fixture.identity)
            self.assertEqual(later["expected_verifier_identity"], fixture.semantic.receipt.identity)
            self.assertEqual(later["expected_request"], fixture.semantic.request)
            self.assertEqual(later["expected_before"], fixture.semantic.expected_before)
            self.assertIs(later["database_now"], fixture.semantic.database_now)
            self.assertEqual(oracle.units(work.metrics), final)
            self.assertIs(work.limits, entering)

    def test_atomic_custody_rejects_raw_shapes_closed_inputs_and_independent_ids_before_runner(self):
        fixture = self.fixture()
        configured, expectations = self.coordinator_fixture(fixture)
        original = {"envelope_bytes": oracle.wire(fixture.envelope),
            "evaluation_context_bytes": oracle.wire(record_context(fixture)),
            "planned_at_epoch_ns": fixture.now_epoch_ns,
            "envelope_id": oracle.sha(b"atomic independent execution id"),
            "planner_transaction_id": fixture.planner_transaction_id, **expectations}
        variants = [({name: value}, (0, 0, 0)) for name, value in (
            ("envelope_bytes", bytearray(original["envelope_bytes"])),
            ("envelope_bytes", b"x"), ("evaluation_context_bytes", memoryview(b"{}")),
            ("evaluation_context_bytes", b""), ("planned_at_epoch_ns", True),
            ("planned_at_epoch_ns", 0), ("planned_at_epoch_ns", 2**63),
            ("envelope_id", True), ("envelope_id", "SHA256:" + "a" * 64),
            ("planner_transaction_id", None), ("expected_planner_transaction_id", False),
            ("planner_public_key", fixture.other_key.public_key()),
            ("writer_database_identity", WRITER_DATABASE_IDENTITY), ("verified_record", {}))]
        other = oracle.sha(b"different independent planner transaction")
        variants.extend((({"planner_transaction_id": other},
                          oracle.canonical_comparison(other, fixture.planner_transaction_id)),
                         ({"expected_planner_transaction_id": other},
                          oracle.canonical_comparison(fixture.planner_transaction_id, other))))
        for changed, spent in variants:
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(fields=tuple(changed)), \
                    patch.object(coordinator, "_run_on_configuration",
                                 side_effect=AssertionError("invalid atomic inputs reached runner")) as run:
                with self.assertRaises(ValueError):
                    configured.persist_and_reserve_execution(**{**original, **changed}, work=work)
            self.assertEqual(run.call_count, 0)
            self.assertEqual(oracle.units(work.metrics), spent)
        for missing in ("expected_request", "database_now"):
            with self.subTest(missing=missing), patch.object(coordinator, "_run_on_configuration",
                    side_effect=AssertionError("open input closure reached runner")) as run:
                with self.assertRaises(ValueError):
                    configured.persist_and_reserve_execution(
                        **{name: value for name, value in original.items() if name != missing},
                        work=accounting._ValidationWork(accounting.QueryReadValidationLimits()))
            self.assertEqual(run.call_count, 0)
        for target, field, attribute in ((retention.plan.contract, "envelope_bytes", "MAX_PAYLOAD_BYTES"),
                                          (retention, "evaluation_context_bytes", "MAX_CONTEXT_BYTES")):
            with self.subTest(bound=attribute), patch.object(target, attribute, len(original[field]) - 1), \
                    patch.object(coordinator, "_run_on_configuration",
                                 side_effect=AssertionError("oversize original reached runner")) as run:
                with self.assertRaises(ValueError):
                    configured.persist_and_reserve_execution(**original,
                        work=accounting._ValidationWork(accounting.QueryReadValidationLimits()))
            self.assertEqual(run.call_count, 0)

    def test_atomic_preconnection_join_is_metered_without_fresh_allowance_or_success_stub(self):
        fixture = self.fixture()
        configured, expectations = self.coordinator_fixture(fixture)
        supplied = {"envelope_bytes": oracle.wire(fixture.envelope),
            "evaluation_context_bytes": oracle.wire(record_context(fixture)),
            "planned_at_epoch_ns": fixture.now_epoch_ns,
            "envelope_id": oracle.sha(b"atomic independent execution id"),
            "planner_transaction_id": fixture.planner_transaction_id, **expectations}
        prior, joined = (1, 7, 5), oracle.canonical_comparison(
            fixture.planner_transaction_id, fixture.planner_transaction_id)
        self.assertEqual(joined, (0, 438, 4))
        stopped = RuntimeError("intentional negative stop at actual runner boundary")
        for dimension in (None, 1, 2):
            limits = list(oracle.add(prior, joined))
            if dimension is not None:
                limits[dimension] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = work.limits
            # This never returns a fake connection or successful authority.
            # The exact case proves only preflight arrival; startup owns the
            # genuine writer/two-replay positive and complete H/B/N oracle.
            with self.subTest(dimension=dimension), patch.object(coordinator, "_run_on_configuration",
                    side_effect=stopped) as run, patch.object(accounting._ValidationWork, "__init__",
                    side_effect=AssertionError("preflight replaced caller work")):
                with self.assertRaises(RuntimeError if dimension is None else ValueError) as raised:
                    configured.persist_and_reserve_execution(**supplied, work=work)
            self.assertEqual(run.call_count, 1 if dimension is None else 0)
            if dimension is None:
                self.assertIs(raised.exception, stopped)
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, joined))
                self.assertIs(run.call_args.args[0][6], WRITER_DATABASE_IDENTITY)
                self.assertIs(run.call_args.args[-1], work)
            else:
                self.assertTrue(all(start <= used <= maximum for start, used, maximum
                    in zip(prior, oracle.units(work.metrics), limits)))
            self.assertIs(work.limits, entering)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_connect_meter_failure_closes_returned_connection_without_repair_or_error_replacement(self):
        class StoreError(ValueError):
            pass

        class Connection:
            def __init__(self, cleanup_error=False):
                self.closed = 0
                self.cleanup_error = cleanup_error

            def close(self):
                self.closed += 1
                if self.cleanup_error:
                    raise RuntimeError("cleanup cannot replace the original failure")

        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        connection = Connection()
        self.assertIs(coordinator._connect(work, lambda: connection), connection)
        self.assertEqual((connection.closed, oracle.units(work.metrics)), (0, (0, 0, 0)))
        for changed in ("spend", "refund", "counter_float", "limit_float", "replacement"):
            for cleanup_error in (False, True):
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
                work.charge(hashes=1, input_bytes=7, json_nodes=5)
                connection, observed = Connection(cleanup_error), []

                def opener():
                    if changed == "spend":
                        work.charge(input_bytes=1)
                    elif changed == "refund":
                        work.input_bytes -= 1
                    elif changed == "counter_float":
                        work.json_nodes = float(work.json_nodes)
                    elif changed == "limit_float":
                        object.__setattr__(work.limits, "max_hashes", float(work.limits.max_hashes))
                    else:
                        work.limits = accounting.QueryReadValidationLimits()
                    observed.append((work.limits, work.metrics))
                    return connection

                # This binds only the real callback guard's exception class;
                # no database, successful verification or connection is faked
                # into an authority result. Connection is a cleanup recorder.
                with self.subTest(changed=changed, cleanup_error=cleanup_error), \
                        patch.object(admission, "_DB_GLOBALS", {"MetadataStoreError": StoreError}):
                    with self.assertRaises(ValueError) as caught:
                        coordinator._connect(work, opener)
                self.assertEqual((connection.closed, len(observed)), (1, 1))
                self.assertNotIn("cleanup cannot", str(caught.exception))
                self.assertIs(work.limits, observed[0][0])
                self.assertEqual(work.metrics, observed[0][1])
                if changed == "counter_float":
                    self.assertIs(type(work.json_nodes), float)
                if changed == "limit_float":
                    self.assertIs(type(work.limits.max_hashes), float)

        first = ValueError("opener failed without returning a connection")

        def unopened():
            raise first

        with self.assertRaises(ValueError) as caught:
            coordinator._connect(accounting._ValidationWork(accounting.QueryReadValidationLimits()), unopened)
        self.assertIs(caught.exception, first)
        with patch.object(coordinator.store, "_callback", wraps=coordinator.store._callback), \
                patch.object(Connection, "__init__", side_effect=AssertionError("invalid work opened a connection")):
            with self.assertRaises(ValueError):
                coordinator._connect(None, Connection)


if __name__ == "__main__":
    unittest.main()
