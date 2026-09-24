#!/usr/bin/env python3
"""Genuine signed invocation claims and private configured-owner composition.

Independent original documents and real Ed25519 keys exercise the raw producer
and receiver. Sender authentication does not prove current roots, physical
clock custody, witness currentness, ACL admission or execution authority. The
composed path uses the existing admitted-connection recorder solely as a SQL/
transaction model and retains genuine capability, witness and retained replay.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_invocation as invocation
from serverware import authority_revocation_issuance as configured
from serverware import authority_revocation_retention as retention
from serverware.authority_store import planner_connection as admission
from serverware.authority_store import revocation_capability as issuance
import test_authority_revocation_capability as capability_oracle
import test_authority_revocation_capability_producer as signer_oracle
import test_authority_revocation_issuer as issuer_oracle
import test_authority_revocation_issuance as issuance_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_wire as wire_oracle


OUTER_SCHEMA = "serverware.policyAuthorityInternalEnvelope/v3"
PAYLOAD_SCHEMA = "serverware.policyAuthorityRevocationIssuanceInvocation/v1"
PURPOSE = "issue-revocation-capability"
HISTORICAL_PAIRS = (
    ("expectedRequest", "expected_request"), ("expectedCapabilityId", "expected_capability_id"),
    ("expectedPlannerTransactionId", "expected_planner_transaction_id"), ("expectedFence", "expected_fence"),
    ("reservedAtEpochNs", "reserved_at_epoch_ns"), ("deadlineEpochNs", "deadline_epoch_ns"),
    ("deadlineMonotonicNs", "deadline_monotonic_ns"), ("nowEpochNs", "now_epoch_ns"),
    ("nowMonotonicNs", "now_monotonic_ns"), ("databaseCutoffUs", "database_now"),
    ("maximumAssertionAgeNs", "maximum_assertion_age_ns"), ("maximumPlanAgeNs", "maximum_plan_age_ns"),
    ("maximumClockSkewNs", "maximum_clock_skew_ns"), ("expectedBefore", "expected_before"),
    ("expectedApproverPolicyDigest", "expected_approver_policy_digest"),
)


def cutoff_us(value):
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def independent_invocation_work(fixture):
    """Literal passes over independent original graphs, never result metrics."""
    add, graph = oracle.add, oracle.graph_cost
    unsigned = {name: value for name, value in fixture.envelope.items() if name != "signature"}
    cap, request = fixture.capability.raw, oracle.wire(fixture.capability.witness_request)
    signing = add(graph(unsigned, 6, 4), graph(fixture.envelope), (0, 566, 0),
        oracle.frame_cost(OUTER_SCHEMA, (oracle.wire(unsigned),)), (0, 142, 2))
    produced = {"capture": graph(fixture.envelope["payload"]["historicalExpectations"], 1, 1),
        "transport": add(*(issuance_oracle.persistence_oracle.codec_encode(raw) for raw in (cap, request))),
        "key_binding": (0, 128, 0), "signing": signing}
    produced["total"] = add(*(produced[name] for name in ("capture", "transport", "key_binding", "signing")))
    joined = (fixture.capability.configuration_digest, fixture.capability.generation_sequence,
        fixture.capability.generation_digest, fixture.historical["expected_capability_id"],
        fixture.historical["expected_planner_transaction_id"], fixture.historical["expected_fence"],
        fixture.historical["deadline_monotonic_ns"])
    consumed = {"transport": add(wire_oracle.decoder_units(fixture.raw, fixture.envelope),
        graph(fixture.envelope, 4, 4), (0, 2 * len(fixture.raw), 0), graph(unsigned)),
        "authentication": capability_oracle.signature_work(OUTER_SCHEMA, unsigned),
        "bindings": add(oracle.canonical_comparison(joined, joined),
            *(issuance_oracle.persistence_oracle.codec_decode(raw) for raw in (cap, request)))}
    consumed["total"] = add(*(consumed[name] for name in ("transport", "authentication", "bindings")))
    owner = issuer_oracle.independent_owner_work(fixture.capability, fixture.pins)
    composed = {"total": add(consumed["total"], owner["total"]),
        "admission": add(consumed["total"], owner["admission"])}
    return {"producer": produced, "receiver": consumed, "composed": composed}


class InvocationFixture:
    def __init__(self):
        self.capability = issuer_oracle.role_bound_fixture()
        self.pins = issuance_oracle.issuer_pins()
        supplied = issuer_oracle.call_inputs(self.capability)
        self.historical = {name: value for name, value in supplied.items() if name in issuer_oracle.HISTORICAL_FIELDS}
        self.issued_epoch = self.capability.plan.now_epoch_ns
        self.issued_mono = self.capability.plan.now_monotonic_ns
        self.rebuild()

    def rebuild(self):
        fixture = self.capability
        history = {wire: cutoff_us(self.historical[api]) if api == "database_now"
            else copy.deepcopy(self.historical[api]) for wire, api in HISTORICAL_PAIRS}
        self.payload = {"schema": PAYLOAD_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
            "generationSequence": fixture.generation_sequence, "generationDigest": fixture.generation_digest,
            "executionEnvelopeId": fixture.execution_envelope_id, "witnessReceiptDigest": fixture.witness_receipt_digest,
            "capabilityBase64Url": oracle.encoded(fixture.raw), "capabilityByteCount": len(fixture.raw),
            "witnessRequestBase64Url": oracle.encoded(oracle.wire(fixture.witness_request)),
            "witnessRequestByteCount": len(oracle.wire(fixture.witness_request)), "historicalExpectations": history}
        self.envelope = {"schema": OUTER_SCHEMA, "envelopeId": self.historical["expected_capability_id"],
            "parentEnvelopeId": self.historical["expected_planner_transaction_id"], "purpose": PURPOSE,
            "configurationDigest": fixture.configuration_digest, "issuedAtEpochNs": self.issued_epoch,
            "issuedMonotonicNs": self.issued_mono, "deadlineMonotonicNs": self.historical["deadline_monotonic_ns"],
            "fence": self.historical["expected_fence"], "payload": copy.deepcopy(self.payload)}
        self.resign()

    def resign(self, key=None):
        unsigned = {name: value for name, value in self.envelope.items() if name != "signature"}
        self.envelope = {**unsigned, "signature": oracle.encoded((self.capability.key if key is None else key).sign(
            oracle.framed(OUTER_SCHEMA, oracle.wire(unsigned)).encode("ascii")))}
        self.raw = oracle.wire(self.envelope)

    def produce_arguments(self):
        fixture = self.capability
        return {"capability_bytes": fixture.raw, "witness_request_bytes": oracle.wire(fixture.witness_request),
            "execution_envelope_id": fixture.execution_envelope_id, "witness_receipt_digest": fixture.witness_receipt_digest,
            "historical_expectations": copy.deepcopy(self.historical), "signer_private_key": fixture.key,
            "signer_public_key": fixture.key.public_key(), "configuration_digest": fixture.configuration_digest,
            "generation_sequence": fixture.generation_sequence, "generation_digest": fixture.generation_digest,
            "issued_at_epoch_ns": self.issued_epoch, "issued_monotonic_ns": self.issued_mono}

    def verify_arguments(self):
        fixture = self.capability
        return {"envelope_bytes": self.raw, "verifier_public_key": fixture.key.public_key(),
            "expected_configuration_digest": fixture.configuration_digest,
            "expected_generation_sequence": fixture.generation_sequence,
            "expected_generation_digest": fixture.generation_digest,
            "now_epoch_ns": fixture.plan.now_epoch_ns, "now_monotonic_ns": fixture.plan.now_monotonic_ns,
            "maximum_age_ns": self.pins["maximumAgeNs"], "maximum_clock_skew_ns": self.pins["maximumClockSkewNs"]}


class RevocationInvocationTests(unittest.TestCase):
    def setUp(self):
        self.old_namespace = admission._DB_GLOBALS
        admission.bind_db_globals({"MetadataStoreError": issuance_oracle.persistence_oracle.StoreError})

    def tearDown(self):
        admission._DB_GLOBALS = self.old_namespace

    def work(self, limits=None):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))

    def produce(self, fixture, work=None, **changes):
        return invocation._produce_invocation_on_work(work=self.work() if work is None else work,
            **{**fixture.produce_arguments(), **changes})

    def verify(self, fixture, work=None, **changes):
        return invocation._verify_invocation_on_work(work=self.work() if work is None else work,
            **{**fixture.verify_arguments(), **changes})

    def issue(self, fixture, connection, work=None, *, owner=None, opener=None, raw=None):
        cap = fixture.capability
        owner = configured.RevocationCapabilityIssuer(**issuer_oracle.constructor_inputs(cap, fixture.pins)) if owner is None else owner
        def open_connection():
            connection.event("open")
            return connection
        with patch.object(configured.time, "monotonic_ns", return_value=cap.plan.now_monotonic_ns), \
                patch.object(configured.time, "time_ns", return_value=cap.plan.now_epoch_ns):
            return configured._issue_invocation_on_configuration(owner._snapshot_configuration(),
                envelope_bytes=fixture.raw if raw is None else raw, work=self.work() if work is None else work,
                opener=open_connection if opener is None else opener)

    def test_genuine_producer_matches_independent_original_outer_and_receiver_preserves_it(self):
        fixture = InvocationFixture()
        expected = independent_invocation_work(fixture)
        work = self.work(oracle.add(expected["producer"]["total"], expected["receiver"]["total"]))
        produced = self.produce(fixture, work)
        self.assertEqual(produced.envelope_bytes, fixture.raw)
        self.assertEqual(oracle.units(work.metrics), expected["producer"]["total"])
        for phase in ("capture", "transport", "key_binding", "signing"):
            self.assertEqual(oracle.units(getattr(produced.metrics, phase)), expected["producer"][phase])
        self.assertEqual((produced.metrics.signing_attempts, produced.metrics.signature_verifications), (1, 1))
        attempts = []
        key = oracle._CallbackPublicKey(fixture.capability.key.public_key(), lambda: attempts.append("outer"))
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            received = self.verify(fixture, work, verifier_public_key=key)
        self.assertEqual(attempts, ["outer"])
        self.assertEqual(replay.call_count, 0)
        self.assertEqual(oracle.units(work.metrics), oracle.add(expected["producer"]["total"], expected["receiver"]["total"]))
        for phase in ("transport", "authentication", "bindings"):
            self.assertEqual(oracle.units(getattr(received.metrics, phase)), expected["receiver"][phase])
        self.assertEqual(received.metrics.signature_attempts, 1)
        self.assertEqual((received.metrics.total_hashes, received.metrics.total_input_bytes,
            received.metrics.total_json_nodes), oracle.units(work.metrics))
        self.assertEqual(received.envelope, fixture.envelope)
        self.assertEqual(received.envelope_bytes, fixture.raw)
        self.assertEqual(received.capability_bytes, fixture.capability.raw)
        self.assertEqual(received.witness_request_bytes, oracle.wire(fixture.capability.witness_request))
        self.assertEqual(received.execution_envelope_id, fixture.capability.execution_envelope_id)
        self.assertEqual(received.witness_receipt_digest, fixture.capability.witness_receipt_digest)
        self.assertEqual(received.historical_expectations, fixture.historical)
        self.assertIs(type(received.historical_expectations["database_now"]), datetime)
        self.assertIs(received.historical_expectations["database_now"].tzinfo, timezone.utc)
        self.assertEqual(tuple(map(len, (received.envelope, received.envelope["payload"], received.historical_expectations))), (11, 11, 15))

    def test_genuinely_signed_outer_joins_cannot_diverge_from_authenticated_history(self):
        for field, value in (("envelopeId", oracle.sha(b"other capability")),
                ("parentEnvelopeId", oracle.sha(b"other planner")), ("fence", 8),
                ("deadlineMonotonicNs", 127_999_999_999)):
            fixture = InvocationFixture()
            fixture.envelope[field] = value
            fixture.resign()
            key = oracle._CallbackPublicKey(fixture.capability.key.public_key(), lambda: None)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(fixture, verifier_public_key=key)
            self.assertEqual(key.calls, 1)

    def test_original_canonical_aliases_and_closed_shapes_are_not_normalized(self):
        fixture = InvocationFixture()
        for raw in (b" " + fixture.raw, fixture.raw.replace(b'"schema":', b'"schema" :', 1),
                fixture.raw[:-1] + b',"schema":"duplicate"}', fixture.raw.replace(b'"fence":7', b'"fence":7.0', 1)):
            self.assertNotEqual(raw, fixture.raw)
            key = oracle._CallbackPublicKey(fixture.capability.key.public_key(), lambda: None)
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                self.verify(fixture, envelope_bytes=raw, verifier_public_key=key)
            self.assertEqual(key.calls, 0)
        for part in ("outer", "payload", "historical"):
            for mode in ("missing", "extra"):
                changed = InvocationFixture()
                value = changed.envelope if part == "outer" else changed.envelope["payload"]
                if part == "historical":
                    value = value["historicalExpectations"]
                if mode == "missing":
                    value.pop(next(iter(value)))
                else:
                    value["successfulProof"] = True
                changed.resign()
                with self.subTest(part=part, mode=mode), self.assertRaises(ValueError):
                    self.verify(changed)

    def test_configuration_generation_key_and_purpose_are_independent_receiver_pins(self):
        fixture = InvocationFixture()
        for field, value in (("verifier_public_key", fixture.capability.other_key.public_key()),
                ("expected_configuration_digest", oracle.sha(b"other configuration")),
                ("expected_generation_sequence", fixture.capability.generation_sequence + 1),
                ("expected_generation_digest", oracle.sha(b"other generation"))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(fixture, **{field: value})
        for field, value in (("purpose", "issue-capability"), ("schema", "serverware.policyAuthorityInternalEnvelope/v4")):
            changed = InvocationFixture()
            changed.envelope[field] = value
            changed.resign()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(changed)
        fixture.resign(key=fixture.capability.plan.key)
        with self.assertRaises(ValueError):
            self.verify(fixture)

    def test_cutoff_roundtrip_is_exact_and_never_recovered_from_retained_context(self):
        fixture = InvocationFixture()
        for micros in (0, 1, 999999):
            changed = InvocationFixture()
            changed.historical["database_now"] = changed.historical["database_now"].replace(microsecond=micros)
            changed.rebuild()
            produced = self.produce(changed)
            received = self.verify(changed, envelope_bytes=produced.envelope_bytes)
            self.assertEqual(received.historical_expectations["database_now"], changed.historical["database_now"])
            self.assertEqual(cutoff_us(received.historical_expectations["database_now"]),
                changed.envelope["payload"]["historicalExpectations"]["databaseCutoffUs"])
        for value in (True, "1", 2**63 - 1):
            changed = InvocationFixture()
            changed.envelope["payload"]["historicalExpectations"]["databaseCutoffUs"] = value
            changed.resign()
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.verify(changed)
        for value in (fixture.historical["database_now"].replace(tzinfo=None),
                fixture.historical["database_now"].astimezone(timezone(timedelta(hours=1))), True):
            historical = {**fixture.historical, "database_now": value}
            with self.subTest(type=type(value).__name__), self.assertRaises(ValueError):
                self.produce(fixture, historical_expectations=historical)

    def test_authenticated_claims_are_not_current_root_or_retained_proof_authority(self):
        fixture = InvocationFixture()
        original_retained = fixture.capability.retained_bytes
        fixture.historical["expected_before"]["indexBeforeHeads"][0]["rootDigest"] = oracle.sha(b"signed but false root claim")
        fixture.rebuild()
        # This exact sender really signed the claim. The transport boundary
        # admits its provenance, not the truth of a live root or stored proof.
        received = self.verify(fixture)
        self.assertEqual(received.historical_expectations["expected_before"], fixture.historical["expected_before"])
        self.assertEqual(fixture.capability.retained_bytes, original_retained)
        connection = issuer_oracle.Connection(fixture.capability, fixture.pins)
        before = connection.snapshot()
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                self.assertRaises(ValueError):
            self.issue(fixture, connection)
        self.assertEqual(replay.call_count, 1)
        self.assertEqual(connection.stores, 0)
        self.assertEqual(connection.snapshot(), before)
        self.assertEqual((connection.outer_commits, connection.outer_rollbacks, connection.closes), (0, 1, 1))

    def test_composed_original_invocation_reaches_actual_issuer_and_genuine_replay_once(self):
        fixture = InvocationFixture()
        connection = issuer_oracle.Connection(fixture.capability, fixture.pins)
        expected = independent_invocation_work(fixture)
        work = self.work(oracle.add(expected["producer"]["total"], expected["composed"]["admission"]))
        produced = self.produce(fixture, work)
        with patch.object(invocation, "_verify_invocation_on_work", wraps=invocation._verify_invocation_on_work) as outer, \
                patch.object(issuance, "_issue_on_connection", wraps=issuance._issue_on_connection) as issued, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            result = self.issue(fixture, connection, work, raw=produced.envelope_bytes)
        self.assertEqual((outer.call_count, issued.call_count, replay.call_count, proof.call_count), (1, 1, 1, 1))
        self.assertEqual(oracle.units(work.metrics), oracle.add(expected["producer"]["total"], expected["composed"]["total"]))
        self.assertIs(outer.call_args.kwargs["work"], issued.call_args.kwargs["work"])
        self.assertEqual(issued.call_args.kwargs["envelope_bytes"], fixture.capability.raw)
        self.assertEqual(issued.call_args.kwargs["witness_request_bytes"], oracle.wire(fixture.capability.witness_request))
        self.assertEqual(issued.call_args.kwargs["retention_expectations"]["expected_request"], fixture.historical["expected_request"])
        self.assertEqual(issued.call_args.kwargs["retention_expectations"]["database_now"], fixture.historical["database_now"])
        self.assertEqual(result, issuance_oracle.expected_receipt(fixture.capability))
        self.assertEqual(connection.rows(), issuance_oracle.expected_load(fixture.capability, fixture.pins, issued=True))
        self.assertEqual((connection.outer_commits, connection.outer_rollbacks, connection.closes), (1, 0, 1))

    def test_outer_signature_failure_denies_before_open_but_inner_failure_rolls_back(self):
        for part in ("outer", "capability", "witness"):
            fixture = InvocationFixture()
            if part == "outer":
                fixture.resign(key=fixture.capability.other_key)
            elif part == "capability":
                fixture.capability.resign(key=fixture.capability.other_key)
                fixture.rebuild()
            else:
                fixture.capability.sign_receipt(key=fixture.capability.other_key)
                fixture.capability.rebuild()
                fixture.rebuild()
            connection = issuer_oracle.Connection(fixture.capability, fixture.pins)
            before = connection.snapshot()
            with self.subTest(part=part), self.assertRaises(ValueError):
                self.issue(fixture, connection)
            self.assertEqual(connection.snapshot(), before)
            self.assertEqual(connection.stores, 0)
            self.assertEqual(connection.outer_commits, 0)
            if part == "outer":
                self.assertEqual((connection.events, connection.closes), ([], 0))
            else:
                self.assertEqual((connection.outer_rollbacks, connection.closes), (1, 1))

    def test_sender_input_ownership_precedes_real_key_and_signing_callbacks(self):
        fixture = InvocationFixture()
        for phase in ("key", "sign"):
            supplied = fixture.produce_arguments()
            callbacks = []
            def mutate():
                callbacks.append(phase)
                supplied["historical_expectations"]["expected_request"]["arguments"]["actor_id"] = "late actor"
                supplied["historical_expectations"]["expected_before"]["indexBeforeHeads"][0]["rootDigest"] = oracle.sha(b"late root")
                supplied["historical_expectations"]["database_now"] += timedelta(microseconds=1)
            key = signer_oracle._ObservedPrivateKey(fixture.capability.key,
                callback=mutate if phase == "sign" else lambda: None,
                public_callback=mutate if phase == "key" else lambda: None)
            supplied["signer_private_key"] = key
            with self.subTest(phase=phase):
                produced = invocation._produce_invocation_on_work(work=self.work(), **supplied)
            self.assertTrue(callbacks)
            self.assertEqual(key.calls, 1)
            self.assertEqual(produced.envelope_bytes, fixture.raw)
            self.assertEqual(self.verify(fixture, envelope_bytes=produced.envelope_bytes).historical_expectations, fixture.historical)

    def test_mismatched_signing_keys_and_real_callback_meter_corruption_deny(self):
        fixture = InvocationFixture()
        key = signer_oracle._ObservedPrivateKey(fixture.capability.other_key)
        with self.assertRaises(ValueError):
            self.produce(fixture, signer_private_key=key)
        self.assertEqual(key.calls, 0)
        key = signer_oracle._ObservedPrivateKey(fixture.capability.key, signing_key=fixture.capability.other_key)
        with self.assertRaises(ValueError):
            self.produce(fixture, signer_private_key=key)
        self.assertEqual(key.calls, 1)
        for phase in ("key", "sign", "paired", "receiver"):
            for corruption in ("spend", "refund", "float", "limits"):
                work, changed = self.work(), []
                def corrupt():
                    if corruption == "spend":
                        work.charge(input_bytes=1)
                    elif corruption == "refund":
                        work.input_bytes -= 1
                    elif corruption == "float":
                        work.input_bytes = float(work.input_bytes)
                    else:
                        work.limits = accounting.QueryReadValidationLimits()
                    changed.append((work.hash_work, work.input_bytes, work.json_nodes, work.limits))
                key = signer_oracle._ObservedPrivateKey(fixture.capability.key,
                    callback=corrupt if phase == "sign" else lambda: None,
                    public_callback=corrupt if phase == "key" else lambda: None)
                public = oracle._CallbackPublicKey(fixture.capability.key.public_key(), corrupt)
                with self.subTest(phase=phase, corruption=corruption), self.assertRaises(ValueError):
                    if phase == "receiver":
                        self.verify(fixture, work, verifier_public_key=public)
                    else:
                        self.produce(fixture, work, signer_private_key=key,
                            signer_public_key=public if phase == "paired" else fixture.capability.key.public_key())
                self.assertEqual(len(changed), 1)
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), changed[0][:3])
                self.assertIs(work.limits, changed[0][3])
                if phase != "receiver":
                    self.assertEqual(key.calls, int(phase in ("sign", "paired")))

    def test_embedded_original_base64_and_counts_are_exact_after_real_outer_authentication(self):
        for stem in ("capability", "witnessRequest"):
            for mutation in ("alphabet", "padding", "count", "bool"):
                fixture = InvocationFixture()
                value = fixture.envelope["payload"]
                if mutation == "alphabet":
                    value[stem + "Base64Url"] = "!" + value[stem + "Base64Url"][1:]
                elif mutation == "padding":
                    value[stem + "Base64Url"] += "="
                elif mutation == "bool":
                    value[stem + "ByteCount"] = True
                else:
                    value[stem + "ByteCount"] += 1
                fixture.resign()
                with self.subTest(transport=stem, mutation=mutation), self.assertRaises(ValueError):
                    self.verify(fixture)

    def test_current_receiver_clocks_do_not_come_from_signed_historical_now(self):
        fixture = InvocationFixture()
        for name, value in (("now_monotonic_ns", fixture.historical["deadline_monotonic_ns"]),
                ("now_epoch_ns", fixture.issued_epoch + fixture.pins["maximumAgeNs"] + 1),
                ("now_monotonic_ns", True), ("now_epoch_ns", True)):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                self.verify(fixture, **{name: value})
        # Altering a historical scalar is a sender claim, not a way to replace
        # the separately supplied current clock in the receiver's admission.
        changed = InvocationFixture()
        changed.historical["now_epoch_ns"] -= 1
        changed.rebuild()
        with self.assertRaises(ValueError):
            self.verify(changed, now_epoch_ns=fixture.issued_epoch + fixture.pins["maximumAgeNs"] + 1)

    def test_independent_exact_preconsumed_and_minus_one_pure_work_has_no_new_allowance(self):
        fixture = InvocationFixture()
        expected = independent_invocation_work(fixture)
        for route, action in (("producer", self.produce), ("receiver", self.verify)):
            total = expected[route]["total"]
            self.assertEqual(total[0], 1)
            for prior in ((0, 0, 0), (1, 17, 3)):
                maximum = oracle.add(prior, total)
                work = self.work(maximum)
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                entering = work.limits
                with self.subTest(route=route, prior=prior), patch.object(accounting._ValidationWork,
                        "__init__", side_effect=AssertionError("new invocation allowance")):
                    action(fixture, work)
                self.assertEqual(oracle.units(work.metrics), maximum)
                self.assertIs(work.limits, entering)
                # Limits are positive by source contract. The legitimate prior
                # hash case below tests zero remaining hashes, not a fake zero
                # absolute ceiling which the actual limit constructor rejects.
                for axis in ((1, 2) if prior[0] == 0 else (0, 1, 2)):
                    limits = list(maximum)
                    limits[axis] -= 1
                    work = self.work(tuple(limits))
                    work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                    entering = work.limits
                    with self.subTest(route=route, prior=prior, axis=axis), self.assertRaises(ValueError):
                        action(fixture, work)
                    self.assertIs(work.limits, entering)
                    self.assertTrue(all(spent <= limit for spent, limit in zip(oracle.units(work.metrics), limits)))

    def test_composed_exact_prior_and_minus_one_admission_includes_the_real_retained_peak(self):
        fixture = InvocationFixture()
        expected = independent_invocation_work(fixture)["composed"]
        for prior in ((0, 0, 0), (1, 19, 5)):
            maximum = oracle.add(prior, expected["admission"])
            work, connection = self.work(maximum), issuer_oracle.Connection(fixture.capability, fixture.pins)
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = work.limits
            self.assertEqual(self.issue(fixture, connection, work), issuance_oracle.expected_receipt(fixture.capability))
            self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
            self.assertIs(work.limits, entering)
            for axis in range(3):
                limits = list(maximum)
                limits[axis] -= 1
                work, connection = self.work(tuple(limits)), issuer_oracle.Connection(fixture.capability, fixture.pins)
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                entering, before = work.limits, connection.snapshot()
                with self.subTest(prior=prior, axis=axis), self.assertRaises(ValueError):
                    self.issue(fixture, connection, work)
                self.assertEqual(connection.snapshot(), before)
                self.assertEqual(connection.outer_commits, 0)
                self.assertIs(work.limits, entering)
                self.assertTrue(all(spent <= limit for spent, limit in zip(oracle.units(work.metrics), limits)))

    def test_repeated_authenticated_issuance_repeats_outer_and_retained_verification_on_remaining_work(self):
        fixture = InvocationFixture()
        independent = independent_invocation_work(fixture)
        first = independent["composed"]
        inner_retry = issuer_oracle.independent_owner_work(fixture.capability, fixture.pins, issued=True)
        second = {name: oracle.add(independent["receiver"]["total"], inner_retry[name])
            for name in ("total", "admission")}
        limits = tuple(max(a, b) for a, b in zip(first["admission"], oracle.add(first["total"], second["admission"])))
        work = self.work(limits)
        one = issuer_oracle.Connection(fixture.capability, fixture.pins)
        two = issuer_oracle.Connection(fixture.capability, fixture.pins, issued=True)
        entering = work.limits
        with patch.object(invocation, "_verify_invocation_on_work", wraps=invocation._verify_invocation_on_work) as outer, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            self.issue(fixture, one, work)
            self.assertEqual(one.snapshot(), two.snapshot())
            self.issue(fixture, two, work)
        self.assertEqual((outer.call_count, replay.call_count), (2, 2))
        self.assertEqual(oracle.units(work.metrics), oracle.add(first["total"], second["total"]))
        self.assertIs(work.limits, entering)
        three = issuer_oracle.Connection(fixture.capability, fixture.pins, issued=True)
        with self.assertRaises(ValueError):
            self.issue(fixture, three, work)
        self.assertEqual(three.outer_commits, 0)
        self.assertIs(work.limits, entering)

    def test_complete_signing_reservation_and_local_wrapper_bound_precede_real_sign(self):
        fixture = InvocationFixture()
        expected = independent_invocation_work(fixture)["producer"]
        prior = (1, 0, 0)
        for deficient in (None, 0, 1, 2):
            maximum = list(oracle.add(prior, expected["total"]))
            if deficient is not None:
                maximum[deficient] -= 1
            work = self.work(tuple(maximum))
            work.charge(hashes=1)
            key = signer_oracle._ObservedPrivateKey(fixture.capability.key)
            with self.subTest(deficient=deficient), patch.object(invocation.capability.plan.core, "canonical_bytes",
                    wraps=invocation.capability.plan.core.canonical_bytes) as encoders:
                if deficient is None:
                    self.assertEqual(self.produce(fixture, work, signer_private_key=key).envelope_bytes, fixture.raw)
                else:
                    with self.assertRaises(ValueError):
                        self.produce(fixture, work, signer_private_key=key)
            self.assertEqual((key.calls, encoders.call_count), (1, 3) if deficient is None else (0, 0))
        # Lower only this private wrapper lookup, never a global request cap or
        # the underlying capability/retention policy, and allocate no huge data.
        for maximum in (len(fixture.raw), len(fixture.raw) - 1):
            key = signer_oracle._ObservedPrivateKey(fixture.capability.key)
            with self.subTest(maximum=maximum), patch.object(invocation, "MAX_ENVELOPE_BYTES", maximum):
                if maximum == len(fixture.raw):
                    self.assertEqual(self.produce(fixture, signer_private_key=key).envelope_bytes, fixture.raw)
                    self.assertEqual(self.verify(fixture).envelope_bytes, fixture.raw)
                else:
                    with self.assertRaises(ValueError):
                        self.produce(fixture, signer_private_key=key)
                    with self.assertRaises(ValueError):
                        self.verify(fixture)
            self.assertEqual(key.calls, int(maximum == len(fixture.raw)))

    def test_composed_clock_callback_cannot_retarget_snapshot_or_spend_shared_work(self):
        for mutation in ("configuration", "work"):
            fixture = InvocationFixture()
            owner = configured.RevocationCapabilityIssuer(**issuer_oracle.constructor_inputs(fixture.capability, fixture.pins))
            snapshot = owner._snapshot_configuration()
            connection, work = issuer_oracle.Connection(fixture.capability, fixture.pins), self.work()
            calls = []
            def monotonic():
                if not calls:
                    calls.append(mutation)
                    if mutation == "work":
                        work.charge(input_bytes=1)
                    else:
                        changed = list(snapshot)
                        changed[:3] = [fixture.capability.other_key.public_key()] * 3
                        changed[5] = changed[7] = changed[8] = changed[10] = oracle.sha(b"late configured pin")
                        changed[6] = changed[6][:3] + (1, 0)
                        changed[9] += 1
                        object.__setattr__(owner, "_configuration", tuple(changed))
                return fixture.capability.plan.now_monotonic_ns
            def opener():
                connection.event("open")
                return connection
            with self.subTest(mutation=mutation), patch.object(configured.time, "monotonic_ns", side_effect=monotonic), \
                    patch.object(configured.time, "time_ns", return_value=fixture.capability.plan.now_epoch_ns):
                if mutation == "work":
                    with self.assertRaises(ValueError):
                        configured._issue_invocation_on_configuration(snapshot, envelope_bytes=fixture.raw, work=work, opener=opener)
                else:
                    result = configured._issue_invocation_on_configuration(snapshot, envelope_bytes=fixture.raw, work=work, opener=opener)
                    self.assertEqual(result, issuance_oracle.expected_receipt(fixture.capability))
            self.assertEqual(calls, [mutation])
            if mutation == "work":
                self.assertEqual(connection.events, [])
                self.assertEqual(oracle.units(work.metrics), (0, 1, 0))
            else:
                self.assertEqual(connection.rows(), issuance_oracle.expected_load(fixture.capability, fixture.pins, issued=True))
                self.assertEqual(connection.outer_commits, 1)


if __name__ == "__main__":
    unittest.main()
